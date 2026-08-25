//! Public ingress and authenticated reverse-tunnel runtime.

mod broker;
mod claims;
mod forwarding;
mod host;
mod session;
mod websocket;

use std::{
    future::{Future, IntoFuture as _},
    io,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use axum::{
    Router,
    body::Body,
    extract::{ConnectInfo, FromRequestParts as _, Request, State, WebSocketUpgrade},
    http::{
        HeaderMap, HeaderValue, Response, StatusCode,
        header::{AUTHORIZATION, CONTENT_TYPE, HOST, WWW_AUTHENTICATE},
    },
    routing::any,
};
use sink_protocol::{CONTROL_PATH, MAX_TRANSPORT_MESSAGE_BYTES};
use thiserror::Error;
use tokio::{
    net::TcpListener,
    sync::{Notify, oneshot, watch},
    time::timeout,
};

use crate::db::Database;

use self::{
    claims::{ClaimLookup, ClaimRegistry},
    forwarding::{ForwardingContext, forward_request},
    host::{HostRoute, classify_host},
    session::run_control_socket,
};

pub const AUTHENTICATION_CHECK_INTERVAL: Duration = Duration::from_millis(250);

const ROOT_BODY: &str = "sink\n";
const NOT_FOUND_BODY: &str = "tunnel not found\n";
const UNAVAILABLE_BODY: &str = "tunnel unavailable\n";
const AUTHENTICATION_FAILED_BODY: &str = "authentication failed\n";
const INVALID_CONTROL_REQUEST_BODY: &str = "invalid control request\n";

/// Shared state for the single Traefik-facing Axum listener.
#[derive(Clone)]
pub struct RuntimeState {
    pub(crate) database: Database,
    pub(crate) public_base_domain: Arc<str>,
    pub(crate) claims: ClaimRegistry,
    shutdown: watch::Sender<bool>,
    sessions: Arc<SessionTracker>,
}

impl RuntimeState {
    pub fn new(
        database: Database,
        public_base_domain: impl AsRef<str>,
    ) -> Result<Self, RuntimeBuildError> {
        let public_base_domain = normalize_base_domain(public_base_domain.as_ref())
            .ok_or(RuntimeBuildError::InvalidPublicBaseDomain)?;
        let (shutdown, _) = watch::channel(false);
        Ok(Self {
            database,
            public_base_domain: Arc::from(public_base_domain),
            claims: ClaimRegistry::default(),
            shutdown,
            sessions: Arc::new(SessionTracker::default()),
        })
    }

    #[must_use]
    pub fn public_base_domain(&self) -> &str {
        &self.public_base_domain
    }

    #[must_use]
    pub fn is_shutting_down(&self) -> bool {
        *self.shutdown.borrow()
    }

    /// Stop new tunnel work, close live sessions, and immediately release all
    /// claims. Existing Axum requests are drained by [`serve`] for its bounded
    /// graceful-shutdown interval.
    pub fn initiate_shutdown(&self) {
        let already_shutting_down = self.shutdown.send_replace(true);
        if !already_shutting_down {
            self.claims.shutdown_all();
        }
    }

    /// Initiate shutdown and wait up to `drain_timeout` for control sessions.
    /// Returns `true` when every session ended inside the bound.
    pub async fn shutdown_and_drain(&self, drain_timeout: Duration) -> bool {
        self.initiate_shutdown();
        timeout(drain_timeout, self.sessions.wait_until_empty())
            .await
            .is_ok()
    }

    pub(crate) fn subscribe_shutdown(&self) -> watch::Receiver<bool> {
        self.shutdown.subscribe()
    }

    fn session_guard(&self) -> SessionGuard {
        self.sessions.active.fetch_add(1, Ordering::AcqRel);
        SessionGuard {
            sessions: Arc::clone(&self.sessions),
        }
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum RuntimeBuildError {
    #[error("public base domain must be a valid DNS name without a scheme, port, or wildcard")]
    InvalidPublicBaseDomain,
}

/// Build the complete ingress router. The exact control host/path and public
/// tunnel traffic share this one router and listener.
pub fn router(state: RuntimeState) -> Router {
    Router::new()
        .route(CONTROL_PATH, any(control_path_ingress))
        .fallback(any(public_ingress))
        .with_state(state)
}

/// Serve the runtime with a bounded graceful drain. When `shutdown` resolves,
/// new work stops, all claims are released, and Axum is allowed at most
/// `drain_timeout` to finish active public/control connections.
pub async fn serve<F>(
    listener: TcpListener,
    state: RuntimeState,
    shutdown: F,
    drain_timeout: Duration,
) -> io::Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    let shutdown_state = state.clone();
    let (shutdown_started, shutdown_observed) = oneshot::channel();
    let server = axum::serve(
        listener,
        router(state.clone()).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        shutdown.await;
        shutdown_state.initiate_shutdown();
        let _ = shutdown_started.send(());
    })
    .into_future();
    tokio::pin!(server);
    tokio::pin!(shutdown_observed);

    tokio::select! {
        result = &mut server => {
            state.initiate_shutdown();
            result
        }
        _ = &mut shutdown_observed => {
            match timeout(drain_timeout, &mut server).await {
                Ok(result) => result,
                Err(_) => {
                    tracing::warn!(
                        drain_timeout_ms = drain_timeout.as_millis(),
                        "server graceful drain timed out"
                    );
                    Ok(())
                }
            }
        }
    }
}

async fn control_path_ingress(
    State(state): State<RuntimeState>,
    request: Request,
) -> Response<Body> {
    match route_for_request(request.headers(), &state.public_base_domain) {
        HostRoute::Control => control_upgrade(state, request).await,
        HostRoute::Invalid if has_loopback_host(request.headers()) => {
            control_upgrade(state, request).await
        }
        HostRoute::Base | HostRoute::Tunnel(_) | HostRoute::Invalid => {
            public_request(state, request).await
        }
    }
}

async fn public_ingress(State(state): State<RuntimeState>, request: Request) -> Response<Body> {
    public_request(state, request).await
}

async fn control_upgrade(state: RuntimeState, request: Request) -> Response<Body> {
    if state.is_shutting_down() {
        return unavailable_response();
    }

    let token = match bearer_token(request.headers()) {
        Some(token) => token,
        None => {
            tracing::warn!("control authentication failed");
            return authentication_failed_response();
        }
    };
    let authenticated = match state.database.authenticate(token).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            tracing::warn!("control authentication failed");
            return authentication_failed_response();
        }
        Err(error) => {
            tracing::error!(%error, "control authentication lookup failed");
            return unavailable_response();
        }
    };

    let (mut parts, _) = request.into_parts();
    let upgrade = match WebSocketUpgrade::from_request_parts(&mut parts, &state).await {
        Ok(upgrade) => upgrade,
        Err(_) => return fixed_response(StatusCode::BAD_REQUEST, INVALID_CONTROL_REQUEST_BODY),
    };
    let session_state = state.clone();
    upgrade
        .max_message_size(MAX_TRANSPORT_MESSAGE_BYTES)
        .max_frame_size(MAX_TRANSPORT_MESSAGE_BYTES)
        .on_upgrade(move |socket| async move {
            let _session = session_state.session_guard();
            run_control_socket(socket, session_state, authenticated).await;
        })
}

async fn public_request(state: RuntimeState, request: Request) -> Response<Body> {
    let route = route_for_request(request.headers(), &state.public_base_domain);
    match route {
        HostRoute::Base => fixed_response(StatusCode::OK, ROOT_BODY),
        HostRoute::Control | HostRoute::Invalid => not_found_response(),
        HostRoute::Tunnel(subdomain) => {
            let broker = match state.claims.lookup(&subdomain, Instant::now()) {
                ClaimLookup::Active(broker) => broker,
                ClaimLookup::Disconnected => return unavailable_response(),
                ClaimLookup::Unknown => return not_found_response(),
            };
            let peer_ip = request
                .extensions()
                .get::<ConnectInfo<SocketAddr>>()
                .map(|peer| peer.0.ip());
            let public_host = format!("{subdomain}.{}", state.public_base_domain);
            match forward_request(
                broker,
                request,
                ForwardingContext {
                    public_host,
                    peer_ip,
                },
            )
            .await
            {
                Ok(response) => response,
                Err(error) => {
                    tracing::warn!(subdomain = %subdomain, %error, "public request forwarding failed");
                    unavailable_response()
                }
            }
        }
    }
}

fn route_for_request(headers: &HeaderMap, base_domain: &str) -> HostRoute {
    let mut hosts = headers.get_all(HOST).iter();
    let Some(host) = hosts.next() else {
        return HostRoute::Invalid;
    };
    if hosts.next().is_some() {
        return HostRoute::Invalid;
    }
    host.to_str()
        .ok()
        .map_or(HostRoute::Invalid, |host| classify_host(host, base_domain))
}

/// Explicit plaintext development connections commonly dial the loopback
/// listener directly instead of resolving `connect.<base-domain>`. Only the
/// reserved control path calls this helper, and bearer authentication remains
/// mandatory.
fn has_loopback_host(headers: &HeaderMap) -> bool {
    let mut hosts = headers.get_all(HOST).iter();
    let Some(host) = hosts.next().and_then(|value| value.to_str().ok()) else {
        return false;
    };
    if hosts.next().is_some() {
        return false;
    }
    let Ok(authority) = host.parse::<http::uri::Authority>() else {
        return false;
    };
    let host = authority
        .host()
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or_else(|| authority.host());
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let mut authorizations = headers.get_all(AUTHORIZATION).iter();
    let authorization = authorizations.next()?.to_str().ok()?;
    if authorizations.next().is_some() {
        return None;
    }
    let mut parts = authorization.split(' ');
    let scheme = parts.next()?;
    let token = parts.next()?;
    if !scheme.eq_ignore_ascii_case("bearer")
        || token.is_empty()
        || parts.next().is_some()
        || token.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return None;
    }
    Some(token)
}

fn fixed_response(status: StatusCode, body: &'static str) -> Response<Body> {
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
}

fn not_found_response() -> Response<Body> {
    fixed_response(StatusCode::NOT_FOUND, NOT_FOUND_BODY)
}

fn unavailable_response() -> Response<Body> {
    fixed_response(StatusCode::SERVICE_UNAVAILABLE, UNAVAILABLE_BODY)
}

fn authentication_failed_response() -> Response<Body> {
    let mut response = fixed_response(StatusCode::UNAUTHORIZED, AUTHENTICATION_FAILED_BODY);
    response
        .headers_mut()
        .insert(WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    response
}

fn normalize_base_domain(value: &str) -> Option<String> {
    let domain = value.trim().trim_end_matches('.').to_ascii_lowercase();
    let valid = !domain.is_empty()
        && domain.len() <= 253
        && domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        });
    valid.then_some(domain)
}

#[derive(Debug, Default)]
struct SessionTracker {
    active: AtomicUsize,
    empty: Notify,
}

impl SessionTracker {
    async fn wait_until_empty(&self) {
        loop {
            let notified = self.empty.notified();
            if self.active.load(Ordering::Acquire) == 0 {
                return;
            }
            notified.await;
        }
    }
}

#[derive(Debug)]
struct SessionGuard {
    sessions: Arc<SessionTracker>,
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        if self.sessions.active.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.sessions.empty.notify_waiters();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use http_body_util::BodyExt as _;
    use sink_protocol::Subdomain;
    use tower::ServiceExt as _;
    use uuid::Uuid;

    use super::*;
    use crate::runtime::{broker::StreamBroker, claims::ClaimOwner};

    #[test]
    fn bearer_parser_rejects_missing_ambiguous_and_malformed_values() {
        let mut headers = HeaderMap::new();
        assert_eq!(bearer_token(&headers), None);
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Basic value"));
        assert_eq!(bearer_token(&headers), None);
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer "));
        assert_eq!(bearer_token(&headers), None);
        headers.insert(AUTHORIZATION, HeaderValue::from_static("bearer secret"));
        assert_eq!(bearer_token(&headers), Some("secret"));
        headers.append(AUTHORIZATION, HeaderValue::from_static("Bearer second"));
        assert_eq!(bearer_token(&headers), None);
    }

    #[test]
    fn local_development_control_hosts_are_loopback_only() {
        for host in ["localhost:8080", "127.0.0.1:8080", "[::1]:8080"] {
            let mut headers = HeaderMap::new();
            headers.insert(HOST, HeaderValue::from_str(host).expect("test Host"));
            assert!(has_loopback_host(&headers), "{host}");
        }
        for host in ["192.0.2.1:8080", "connect.example.test", "attacker.test"] {
            let mut headers = HeaderMap::new();
            headers.insert(HOST, HeaderValue::from_str(host).expect("test Host"));
            assert!(!has_loopback_host(&headers), "{host}");
        }
    }

    #[tokio::test]
    async fn fixed_responses_are_safe_and_stable() {
        for (response, status, body) in [
            (
                fixed_response(StatusCode::OK, ROOT_BODY),
                StatusCode::OK,
                ROOT_BODY,
            ),
            (not_found_response(), StatusCode::NOT_FOUND, NOT_FOUND_BODY),
            (
                unavailable_response(),
                StatusCode::SERVICE_UNAVAILABLE,
                UNAVAILABLE_BODY,
            ),
            (
                authentication_failed_response(),
                StatusCode::UNAUTHORIZED,
                AUTHENTICATION_FAILED_BODY,
            ),
        ] {
            assert_eq!(response.status(), status);
            assert_eq!(
                response.headers()[CONTENT_TYPE],
                "text/plain; charset=utf-8"
            );
            let bytes = response
                .into_body()
                .collect()
                .await
                .expect("fixed body")
                .to_bytes();
            assert_eq!(bytes, body.as_bytes());
            let text = String::from_utf8_lossy(&bytes);
            assert!(!text.contains("sqlite"));
            assert!(!text.contains("token"));
            assert!(!text.contains("user"));
        }
    }

    #[test]
    fn runtime_base_domain_is_normalized_and_validated() {
        assert_eq!(
            normalize_base_domain(" Example.Test. ").as_deref(),
            Some("example.test")
        );
        for invalid in [
            "",
            "https://example.test",
            "*.example.test",
            "bad_name.test",
        ] {
            assert!(normalize_base_domain(invalid).is_none());
        }
    }

    #[tokio::test]
    async fn router_applies_exact_control_root_unknown_and_disconnected_responses()
    -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let database = Database::open(directory.path().join("router.sqlite3")).await?;
        let state = RuntimeState::new(database, "example.test")?;
        let app = router(state.clone());

        let root = app
            .clone()
            .oneshot(test_request("example.test", "/anything"))
            .await?;
        assert_eq!(root.status(), StatusCode::OK);

        let unknown = app
            .clone()
            .oneshot(test_request("unknown.example.test", "/"))
            .await?;
        assert_eq!(unknown.status(), StatusCode::NOT_FOUND);

        let wrong_control_path = app
            .clone()
            .oneshot(test_request("connect.example.test", "/not-control"))
            .await?;
        assert_eq!(wrong_control_path.status(), StatusCode::NOT_FOUND);

        let unauthenticated_control = app
            .clone()
            .oneshot(test_request("connect.example.test", CONTROL_PATH))
            .await?;
        assert_eq!(unauthenticated_control.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            unauthenticated_control.headers()[WWW_AUTHENTICATE],
            "Bearer"
        );

        let subdomain = Subdomain::parse("offline")?;
        let (broker, _requests) = StreamBroker::channel();
        let lease = state
            .claims
            .acquire(
                ClaimOwner {
                    user_id: 1,
                    session_id: Uuid::from_u128(1),
                },
                Some(subdomain),
                broker,
                Instant::now(),
            )
            .map_err(|error| std::io::Error::other(format!("claim setup failed: {error:?}")))?;
        state
            .claims
            .disconnect(&lease, Instant::now())
            .ok_or("claim did not disconnect")?;
        let unavailable = app
            .oneshot(test_request("offline.example.test", "/stream"))
            .await?;
        assert_eq!(unavailable.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = unavailable.into_body().collect().await?.to_bytes();
        assert_eq!(body, UNAVAILABLE_BODY.as_bytes());
        Ok(())
    }

    fn test_request(host: &'static str, path: &'static str) -> Request {
        Request::builder()
            .uri(path)
            .header(HOST, host)
            .body(Body::empty())
            .expect("valid test request")
    }
}
