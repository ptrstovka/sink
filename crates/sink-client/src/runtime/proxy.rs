use std::{
    convert::Infallible,
    error::Error as StdError,
    fmt,
    future::Future,
    io,
    net::IpAddr,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant, SystemTime},
};

use bytes::Bytes;
use http::{
    HeaderMap, HeaderValue, Method, Request, Response, StatusCode, Uri,
    header::{CONNECTION, CONTENT_TYPE, HOST, HeaderName, UPGRADE},
    uri::{Authority, PathAndQuery},
};
use http_body_util::{BodyExt, Full, combinators::UnsyncBoxBody};
use hyper::{
    body::{Body, Frame, Incoming, SizeHint},
    client::conn::http1,
    service::service_fn,
    upgrade::{self, OnUpgrade, Upgraded},
};
use hyper_util::rt::TokioIo;
use rustls::{
    ClientConfig, DigitallySignedStruct, Error as TlsError, RootCertStore, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{
        CryptoProvider, WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature,
    },
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
    sync::broadcast,
    time::timeout,
};
use tokio_rustls::TlsConnector;
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tracing::warn;
use uuid::Uuid;

use crate::{
    inspection::{
        BodyConstraints, BodyContentKind, CaptureDecision, HeaderSnapshots, InspectionStore,
        RequestSnapshot, ResponseSnapshot, TransactionId, TransactionOrigin,
    },
    replay::{
        ReplayRequestBody, ReplayResponseBody, ReplayTransport, ReplayTransportError,
        ReplayTransportFuture,
    },
    target::LocalTarget,
};

const LOCAL_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const SERVICE_UNAVAILABLE_BODY: &str = "local service unavailable\n";
const X_FORWARDED_HOST: HeaderName = HeaderName::from_static("x-forwarded-host");
const X_FORWARDED_PROTO: HeaderName = HeaderName::from_static("x-forwarded-proto");
const REQUEST_BODY_FAILURE: &str = "request body transfer failed";
const RESPONSE_BODY_FAILURE: &str = "response body transfer failed";

pub(crate) type BoxError = Box<dyn StdError + Send + Sync>;
pub(crate) type ProxyBody = UnsyncBoxBody<Bytes, BoxError>;

#[derive(Clone, Copy, Debug)]
struct LocalResponseTimings {
    connect: Duration,
    http_handshake: Duration,
    response_head: Duration,
}

#[derive(Debug)]
struct LocalResponse {
    response: Response<Incoming>,
    timings: LocalResponseTimings,
}

#[derive(Clone, Copy, Debug)]
struct TunnelRequestTiming {
    session_id: Uuid,
    stream_id: u32,
    accepted_at: Instant,
    request_head_at: Instant,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestSummary {
    pub method: Method,
    pub path_and_query: String,
    pub status: StatusCode,
    pub duration: Duration,
    pub request_bytes: u64,
    pub response_bytes: u64,
}

#[derive(Clone)]
pub(crate) struct LocalProxy {
    target: LocalTarget,
    tls: Option<TlsConnector>,
    summaries: broadcast::Sender<RequestSummary>,
    inspection: Option<InspectionStore>,
    connect_timeout: Duration,
}

impl fmt::Debug for LocalProxy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalProxy")
            .field("target", &self.target)
            .field("uses_tls", &self.tls.is_some())
            .field("inspection_enabled", &self.inspection.is_some())
            .field("connect_timeout", &self.connect_timeout)
            .finish_non_exhaustive()
    }
}

impl LocalProxy {
    pub(crate) fn new(
        target: LocalTarget,
        local_tls_insecure: bool,
        summaries: broadcast::Sender<RequestSummary>,
    ) -> Result<Self, ProxySetupError> {
        Self::new_with_inspection(target, local_tls_insecure, summaries, None)
    }

    /// Optional-store constructor for the runtime wiring layer. A missing
    /// store is exactly the legacy counting-only behavior.
    pub(crate) fn new_with_inspection(
        target: LocalTarget,
        local_tls_insecure: bool,
        summaries: broadcast::Sender<RequestSummary>,
        inspection: Option<InspectionStore>,
    ) -> Result<Self, ProxySetupError> {
        ensure_crypto_provider()?;
        let tls = target
            .uses_tls()
            .then(|| local_tls_connector(local_tls_insecure))
            .transpose()?;
        Ok(Self {
            target,
            tls,
            summaries,
            inspection,
            connect_timeout: LOCAL_CONNECT_TIMEOUT,
        })
    }

    pub(crate) fn for_connection(
        &self,
        tasks: TaskTracker,
        force_shutdown: CancellationToken,
    ) -> ExchangeProxy {
        ExchangeProxy {
            inner: self.clone(),
            tasks,
            force_shutdown,
        }
    }

    async fn send_local<B, Spawn>(
        &self,
        mut request: Request<B>,
        spawn_connection: Spawn,
    ) -> Result<LocalResponse, ReplayTransportError>
    where
        B: Body<Data = Bytes> + Send + 'static,
        B::Error: Into<BoxError>,
        Spawn: FnOnce(Pin<Box<dyn Future<Output = ()> + Send + 'static>>),
    {
        if rewrite_local_request(&mut request, &self.target).is_err() {
            return Err(ReplayTransportError::Rewrite);
        }

        let connect_started_at = Instant::now();
        let io = match self.connect_local().await {
            Ok(io) => io,
            Err(error) => {
                warn!(target = %self.target, error = %error, "local service connection failed");
                return Err(ReplayTransportError::Connect);
            }
        };
        let connect = connect_started_at.elapsed();
        let handshake_started_at = Instant::now();
        let handshake = timeout(
            self.connect_timeout,
            http1::handshake::<_, B>(TokioIo::new(io)),
        )
        .await;
        let (mut sender, connection) = match handshake {
            Ok(Ok(parts)) => parts,
            Ok(Err(_)) | Err(_) => {
                warn!(target = %self.target, "local HTTP handshake failed");
                return Err(ReplayTransportError::Handshake);
            }
        };
        let http_handshake = handshake_started_at.elapsed();

        spawn_connection(Box::pin(async move {
            if connection.with_upgrades().await.is_err() {
                // The response path reports failures. Do not retain or log
                // Hyper diagnostics that could contain request material.
                tracing::debug!("local HTTP connection ended with an error");
            }
        }));

        let response_head_started_at = Instant::now();
        let response = sender.send_request(request).await.map_err(|_| {
            warn!(target = %self.target, "local HTTP request failed");
            ReplayTransportError::Request
        })?;
        Ok(LocalResponse {
            response,
            timings: LocalResponseTimings {
                connect,
                http_handshake,
                response_head: response_head_started_at.elapsed(),
            },
        })
    }

    async fn connect_local(&self) -> Result<BoxedLocalIo, LocalConnectError> {
        let host = self
            .target
            .base_url()
            .host_str()
            .ok_or(LocalConnectError::InvalidTarget)?
            .to_owned();
        let port = self
            .target
            .base_url()
            .port_or_known_default()
            .ok_or(LocalConnectError::InvalidTarget)?;
        let tls = self.tls.clone();

        timeout(self.connect_timeout, async move {
            let tcp = TcpStream::connect((host.as_str(), port))
                .await
                .map_err(|_| LocalConnectError::Unavailable)?;
            let _ = tcp.set_nodelay(true);
            if let Some(connector) = tls {
                let server_name = server_name(&host)?;
                let stream = connector
                    .connect(server_name, tcp)
                    .await
                    .map_err(|_| LocalConnectError::Tls)?;
                Ok::<BoxedLocalIo, LocalConnectError>(Box::new(stream))
            } else {
                Ok::<BoxedLocalIo, LocalConnectError>(Box::new(tcp))
            }
        })
        .await
        .map_err(|_| LocalConnectError::Timeout)?
    }
}

impl ReplayTransport for LocalProxy {
    fn send(&self, request: Request<ReplayRequestBody>) -> ReplayTransportFuture {
        let proxy = self.clone();
        Box::pin(async move {
            proxy
                .send_local(request, |connection| {
                    drop(tokio::spawn(connection));
                })
                .await
                .map(|local| local.response.map(boxed_body) as Response<ReplayResponseBody>)
        })
    }
}

#[derive(Clone)]
pub(crate) struct ExchangeProxy {
    inner: LocalProxy,
    tasks: TaskTracker,
    force_shutdown: CancellationToken,
}

impl ExchangeProxy {
    #[cfg(test)]
    pub(crate) async fn forward<B>(&self, request: Request<B>) -> Response<ProxyBody>
    where
        B: Body<Data = Bytes> + Send + 'static,
        B::Error: Into<BoxError>,
    {
        self.forward_inner(request, None).await
    }

    async fn forward_tunnel<B>(
        &self,
        request: Request<B>,
        timing: TunnelRequestTiming,
    ) -> Response<ProxyBody>
    where
        B: Body<Data = Bytes> + Send + 'static,
        B::Error: Into<BoxError>,
    {
        self.forward_inner(request, Some(timing)).await
    }

    async fn forward_inner<B>(
        &self,
        mut request: Request<B>,
        tunnel_timing: Option<TunnelRequestTiming>,
    ) -> Response<ProxyBody>
    where
        B: Body<Data = Bytes> + Send + 'static,
        B::Error: Into<BoxError>,
    {
        let received_at = SystemTime::now();
        let method = request.method().clone();
        let original_path = request
            .uri()
            .path_and_query()
            .map_or_else(|| "/".to_owned(), ToString::to_string);
        let stats = Arc::new(RequestStats::new(
            method.clone(),
            original_path,
            self.inner.summaries.clone(),
        ));
        let wants_upgrade = request_wants_upgrade(&request);
        let inspection = self.inner.inspection.as_ref().and_then(|store| {
            InspectionCapture::begin(store, &request, received_at, stats.started, wants_upgrade)
        });
        let mut inspection_guard = InspectionGuard::new(inspection.clone());
        let public_upgrade = wants_upgrade.then(|| upgrade::on(&mut request));

        let request = request.map(|body| {
            ForwardBody::new(
                body,
                stats.request_bytes.clone(),
                inspection.clone(),
                CaptureDirection::Request,
            )
        });
        let tasks = self.tasks.clone();
        let force_shutdown = self.force_shutdown.clone();
        let response = self
            .inner
            .send_local(request, move |connection| {
                tasks.spawn(async move {
                    tokio::select! {
                        () = connection => {}
                        () = force_shutdown.cancelled() => {}
                    }
                });
            })
            .await;
        let local = match response {
            Ok(local) => local,
            Err(error) => {
                if let Some(timing) = tunnel_timing {
                    tracing::info!(
                        tunnel_session_id = %timing.session_id,
                        stream_id = timing.stream_id,
                        stage = "local_response_failed",
                        accept_to_failure_us = duration_micros(timing.accepted_at.elapsed()),
                        request_to_failure_us = duration_micros(timing.request_head_at.elapsed()),
                        error = %error,
                        "tunneled request stage latency"
                    );
                }
                inspection_guard.fail(error.capture_message());
                return service_unavailable(stats);
            }
        };
        if let Some(timing) = tunnel_timing {
            tracing::info!(
                tunnel_session_id = %timing.session_id,
                stream_id = timing.stream_id,
                stage = "local_response_head",
                status = local.response.status().as_u16(),
                accept_to_response_head_us = duration_micros(timing.accepted_at.elapsed()),
                request_to_response_head_us = duration_micros(timing.request_head_at.elapsed()),
                local_connect_us = duration_micros(local.timings.connect),
                local_http_handshake_us = duration_micros(local.timings.http_handshake),
                local_response_head_us = duration_micros(local.timings.response_head),
                "tunneled request stage latency"
            );
        }
        let response = self.prepare_response(local.response, public_upgrade, stats, inspection);
        inspection_guard.disarm();
        response
    }

    fn prepare_response(
        &self,
        mut response: Response<Incoming>,
        public_upgrade: Option<OnUpgrade>,
        stats: Arc<RequestStats>,
        inspection: Option<InspectionCapture>,
    ) -> Response<ProxyBody> {
        let status = response.status();
        let upgraded = public_upgrade.is_some()
            && (status == StatusCode::SWITCHING_PROTOCOLS
                || (stats.method == Method::CONNECT && status.is_success()));
        if let Some(capture) = &inspection {
            capture.start_response(&response, upgraded);
        }

        if upgraded {
            if let Some(capture) = &inspection {
                capture.upgrade();
            }
            let local_upgrade = upgrade::on(&mut response);
            let Some(public_upgrade) = public_upgrade else {
                return response.map(boxed_body);
            };
            let force_shutdown = self.force_shutdown.clone();
            let upgrade_stats = stats.clone();
            self.tasks.spawn(async move {
                let result = tokio::select! {
                    result = bridge_upgrades(public_upgrade, local_upgrade) => Some(result),
                    () = force_shutdown.cancelled() => None,
                };
                if let Some(Ok((request_bytes, response_bytes))) = result {
                    add_bytes(&upgrade_stats.request_bytes, request_bytes);
                    add_bytes(&upgrade_stats.response_bytes, response_bytes);
                }
                upgrade_stats.emit(status);
            });
            return response.map(boxed_body);
        }

        response.map(|body| {
            let forwarded = ForwardBody::new(
                body,
                stats.response_bytes.clone(),
                inspection,
                CaptureDirection::Response,
            );
            CompletionBody::new(forwarded, stats, status)
                .map_err(|error| -> BoxError { Box::new(error) })
                .boxed_unsync()
        })
    }
}

pub(crate) async fn serve_stream<S>(
    stream: S,
    proxy: ExchangeProxy,
    force_shutdown: CancellationToken,
    session_id: Uuid,
    stream_id: u32,
    accepted_at: Instant,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let service = service_fn(move |request| {
        let proxy = proxy.clone();
        async move {
            let request_head_at = Instant::now();
            tracing::info!(
                tunnel_session_id = %session_id,
                stream_id,
                stage = "request_head",
                accept_to_request_head_us = duration_micros(
                    request_head_at.saturating_duration_since(accepted_at)
                ),
                "tunneled request stage latency"
            );
            let timing = TunnelRequestTiming {
                session_id,
                stream_id,
                accepted_at,
                request_head_at,
            };
            Ok::<_, Infallible>(proxy.forward_tunnel(request, timing).await)
        }
    });
    // Keep Hyper's HTTP/1 upgrade handling enabled. Forcing keep-alive off
    // rewrites a valid `Connection: upgrade` response to `Connection: close`.
    // The server side still limits this yamux stream to one exchange by
    // dropping its request sender after the response arrives.
    let connection = hyper::server::conn::http1::Builder::new()
        .serve_connection(TokioIo::new(stream), service)
        .with_upgrades();
    tokio::select! {
        result = connection => {
            if result.is_err() {
                tracing::debug!(
                    tunnel_session_id = %session_id,
                    stream_id,
                    accepted_for_us = duration_micros(accepted_at.elapsed()),
                    "tunnel HTTP exchange ended with an error"
                );
            }
        }
        () = force_shutdown.cancelled() => {}
    }
}

pub fn resolve_local_uri(target: &LocalTarget, incoming: &Uri) -> Result<Uri, ProxySetupError> {
    let base_path = target.base_uri().path();
    let incoming_path = incoming.path();
    let joined_path = if base_path == "/" {
        incoming_path.to_owned()
    } else {
        let base = base_path.trim_end_matches('/');
        if incoming_path == "/" {
            format!("{base}/")
        } else {
            format!("{base}{incoming_path}")
        }
    };
    let path_and_query = match incoming.query() {
        Some(query) => format!("{joined_path}?{query}"),
        None => joined_path,
    }
    .parse::<PathAndQuery>()?;

    Uri::builder()
        .scheme(
            target
                .origin()
                .scheme()
                .cloned()
                .ok_or(ProxySetupError::InvalidLocalTarget)?,
        )
        .authority(
            target
                .origin()
                .authority()
                .cloned()
                .ok_or(ProxySetupError::InvalidLocalTarget)?,
        )
        .path_and_query(path_and_query)
        .build()
        .map_err(ProxySetupError::from)
}

pub fn rewrite_local_request<B>(
    request: &mut Request<B>,
    target: &LocalTarget,
) -> Result<(), ProxySetupError> {
    *request.uri_mut() = resolve_local_uri(target, request.uri())?;
    let authority = target
        .origin()
        .authority()
        .ok_or(ProxySetupError::InvalidLocalTarget)?;
    let host = HeaderValue::from_str(authority.as_str())?;
    request.headers_mut().insert(HOST, host);
    Ok(())
}

fn request_wants_upgrade<B>(request: &Request<B>) -> bool {
    if request.method() == Method::CONNECT {
        return true;
    }
    request.headers().contains_key(UPGRADE)
        && request
            .headers()
            .get_all(CONNECTION)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(','))
            .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
}

fn public_request_uri<B>(request: &Request<B>) -> Option<Uri> {
    let forwarded_scheme = header_text(request.headers(), &X_FORWARDED_PROTO)?;
    let scheme = forwarded_scheme
        .or_else(|| request.uri().scheme_str())
        .unwrap_or("http")
        .parse::<http::uri::Scheme>()
        .ok()?;
    if scheme != http::uri::Scheme::HTTP && scheme != http::uri::Scheme::HTTPS {
        return None;
    }

    let forwarded_host = header_text(request.headers(), &X_FORWARDED_HOST)?;
    let public_host = match forwarded_host {
        Some(host) => Some(host),
        None => header_text(request.headers(), &HOST)?,
    };
    let authority = public_host
        .map(str::parse::<Authority>)
        .transpose()
        .ok()?
        .or_else(|| request.uri().authority().cloned())?;
    let path_and_query = request
        .uri()
        .path_and_query()
        .cloned()
        .unwrap_or_else(|| PathAndQuery::from_static("/"));

    Uri::builder()
        .scheme(scheme)
        .authority(authority)
        .path_and_query(path_and_query)
        .build()
        .ok()
}

/// Return `None` for an absent header and fail the outer option for malformed
/// metadata. The forwarding server replaces these headers with normalized
/// singleton values, so malformed values must disable capture rather than
/// falling back to untrusted metadata.
fn header_text<'a>(headers: &'a HeaderMap, name: &HeaderName) -> Option<Option<&'a str>> {
    headers
        .get(name)
        .map_or(Some(None), |value| value.to_str().ok().map(Some))
}

fn body_content_kind(headers: &HeaderMap) -> BodyContentKind {
    BodyContentKind::from_content_type(headers.get(CONTENT_TYPE))
}

fn is_server_sent_events(headers: &HeaderMap) -> bool {
    headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("text/event-stream"))
}

fn body_constraints<B>(body: &B, headers: &HeaderMap, websocket_upgrade: bool) -> BodyConstraints
where
    B: Body,
{
    let server_sent_events = is_server_sent_events(headers);
    let streaming =
        server_sent_events || (!body.is_end_stream() && body.size_hint().exact().is_none());
    BodyConstraints::new(streaming, server_sent_events, websocket_upgrade)
}

const BODY_IN_PROGRESS: u8 = 0;
const BODY_COMPLETE: u8 = 1;
const BODY_INCOMPLETE: u8 = 2;
const BODY_UPDATING: u8 = 3;

#[derive(Clone)]
struct InspectionCapture {
    shared: Arc<InspectionCaptureState>,
}

struct InspectionCaptureState {
    store: InspectionStore,
    id: TransactionId,
    started: Instant,
    request_body: AtomicU8,
    response_body: AtomicU8,
    terminal: AtomicBool,
}

impl InspectionCapture {
    fn begin<B>(
        store: &InspectionStore,
        request: &Request<B>,
        received_at: SystemTime,
        started: Instant,
        websocket_upgrade: bool,
    ) -> Option<Self>
    where
        B: Body,
    {
        let public_uri = public_request_uri(request)?;
        let body = store.body_preview(
            body_content_kind(request.headers()),
            body_constraints(request.body(), request.headers(), websocket_upgrade),
        );
        let snapshot = RequestSnapshot::new(
            request.method().clone(),
            public_uri,
            request.version(),
            HeaderSnapshots::capture(request.headers()),
            body,
        )
        .ok()?;
        let CaptureDecision::Captured(id) =
            store.capture_at(TransactionOrigin::Original, snapshot, received_at)
        else {
            return None;
        };
        Some(Self {
            shared: Arc::new(InspectionCaptureState {
                store: store.clone(),
                id,
                started,
                request_body: AtomicU8::new(BODY_IN_PROGRESS),
                response_body: AtomicU8::new(BODY_IN_PROGRESS),
                terminal: AtomicBool::new(false),
            }),
        })
    }

    fn start_response<B>(&self, response: &Response<B>, websocket_upgrade: bool)
    where
        B: Body,
    {
        if self.is_terminal() {
            return;
        }
        let body = self.shared.store.body_preview(
            body_content_kind(response.headers()),
            body_constraints(response.body(), response.headers(), websocket_upgrade),
        );
        let snapshot = ResponseSnapshot::new(
            response.status(),
            response.version(),
            HeaderSnapshots::capture(response.headers()),
            body,
        );
        let _ = self
            .shared
            .store
            .start_response(self.shared.id, snapshot, self.elapsed());
    }

    fn record_body_chunk(&self, direction: CaptureDirection, chunk: &[u8]) {
        if self.is_terminal() {
            return;
        }
        match direction {
            CaptureDirection::Request => {
                let _ = self
                    .shared
                    .store
                    .record_request_body_chunk(self.shared.id, chunk);
            }
            CaptureDirection::Response => {
                let _ = self
                    .shared
                    .store
                    .record_response_body_chunk(self.shared.id, chunk);
            }
        }
    }

    fn finish_body(&self, direction: CaptureDirection) {
        if self.is_terminal() {
            return;
        }
        let state = self.body_state(direction);
        if state
            .compare_exchange(
                BODY_IN_PROGRESS,
                BODY_UPDATING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return;
        }
        match direction {
            CaptureDirection::Request => {
                let _ = self.shared.store.finish_request_body(self.shared.id);
            }
            CaptureDirection::Response => {
                let _ = self.shared.store.finish_response_body(self.shared.id);
            }
        }
        state.store(BODY_COMPLETE, Ordering::Release);
        self.finish_transaction_if_ready();
    }

    fn body_failed(&self, direction: CaptureDirection) {
        self.mark_body_incomplete(direction);
        self.fail(match direction {
            CaptureDirection::Request => REQUEST_BODY_FAILURE,
            CaptureDirection::Response => RESPONSE_BODY_FAILURE,
        });
    }

    fn body_dropped(&self, direction: CaptureDirection) {
        self.mark_body_incomplete(direction);
        if direction == CaptureDirection::Response {
            self.cancel();
        } else {
            self.finish_transaction_if_ready();
        }
    }

    fn fail(&self, message: &'static str) {
        if self.claim_terminal() {
            let _ = self
                .shared
                .store
                .fail(self.shared.id, self.elapsed(), message);
        }
    }

    fn cancel(&self) {
        if self.claim_terminal() {
            let _ = self.shared.store.cancel(self.shared.id, self.elapsed());
        }
    }

    fn upgrade(&self) {
        if self.claim_terminal() {
            let _ = self.shared.store.upgrade(self.shared.id, self.elapsed());
        }
    }

    #[cfg(test)]
    fn id(&self) -> TransactionId {
        self.shared.id
    }

    fn mark_body_incomplete(&self, direction: CaptureDirection) {
        if self.is_terminal() {
            return;
        }
        let state = self.body_state(direction);
        if state
            .compare_exchange(
                BODY_IN_PROGRESS,
                BODY_UPDATING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return;
        }
        match direction {
            CaptureDirection::Request => {
                let _ = self
                    .shared
                    .store
                    .mark_request_body_incomplete(self.shared.id);
            }
            CaptureDirection::Response => {
                let _ = self
                    .shared
                    .store
                    .mark_response_body_incomplete(self.shared.id);
            }
        }
        state.store(BODY_INCOMPLETE, Ordering::Release);
    }

    fn finish_transaction_if_ready(&self) {
        let request = self.shared.request_body.load(Ordering::Acquire);
        let response = self.shared.response_body.load(Ordering::Acquire);
        if request == BODY_COMPLETE && response == BODY_COMPLETE {
            if self.claim_terminal() {
                let _ = self.shared.store.complete(self.shared.id, self.elapsed());
            }
        } else if response == BODY_INCOMPLETE
            || (request == BODY_INCOMPLETE && response == BODY_COMPLETE)
        {
            self.cancel();
        }
    }

    fn body_state(&self, direction: CaptureDirection) -> &AtomicU8 {
        match direction {
            CaptureDirection::Request => &self.shared.request_body,
            CaptureDirection::Response => &self.shared.response_body,
        }
    }

    fn claim_terminal(&self) -> bool {
        self.shared
            .terminal
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    fn is_terminal(&self) -> bool {
        self.shared.terminal.load(Ordering::Acquire)
    }

    fn elapsed(&self) -> Duration {
        self.shared.started.elapsed()
    }
}

struct InspectionGuard {
    capture: Option<InspectionCapture>,
}

impl InspectionGuard {
    fn new(capture: Option<InspectionCapture>) -> Self {
        Self { capture }
    }

    fn fail(&mut self, message: &'static str) {
        if let Some(capture) = self.capture.take() {
            capture.fail(message);
        }
    }

    fn disarm(&mut self) {
        self.capture = None;
    }
}

impl Drop for InspectionGuard {
    fn drop(&mut self) {
        if let Some(capture) = self.capture.take() {
            capture.cancel();
        }
    }
}

fn service_unavailable(stats: Arc<RequestStats>) -> Response<ProxyBody> {
    let status = StatusCode::SERVICE_UNAVAILABLE;
    let body = Full::new(Bytes::from_static(SERVICE_UNAVAILABLE_BODY.as_bytes()));
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(
            CompletionBody::new(
                CountedBody::new(body, stats.response_bytes.clone()),
                stats,
                status,
            )
            .map_err(|never| match never {})
            .boxed_unsync(),
        )
        .unwrap_or_else(|_| Response::new(empty_body()))
}

fn boxed_body(body: Incoming) -> ProxyBody {
    body.map_err(|error| -> BoxError { Box::new(error) })
        .boxed_unsync()
}

fn empty_body() -> ProxyBody {
    Full::new(Bytes::new())
        .map_err(|never| match never {})
        .boxed_unsync()
}

struct RequestStats {
    method: Method,
    path_and_query: String,
    started: Instant,
    request_bytes: Arc<AtomicU64>,
    response_bytes: Arc<AtomicU64>,
    emitted: AtomicBool,
    summaries: broadcast::Sender<RequestSummary>,
}

impl RequestStats {
    fn new(
        method: Method,
        path_and_query: String,
        summaries: broadcast::Sender<RequestSummary>,
    ) -> Self {
        Self {
            method,
            path_and_query,
            started: Instant::now(),
            request_bytes: Arc::new(AtomicU64::new(0)),
            response_bytes: Arc::new(AtomicU64::new(0)),
            emitted: AtomicBool::new(false),
            summaries,
        }
    }

    fn emit(&self, status: StatusCode) {
        if self.emitted.swap(true, Ordering::AcqRel) {
            return;
        }
        let summary = RequestSummary {
            method: self.method.clone(),
            path_and_query: self.path_and_query.clone(),
            status,
            duration: self.started.elapsed(),
            request_bytes: self.request_bytes.load(Ordering::Relaxed),
            response_bytes: self.response_bytes.load(Ordering::Relaxed),
        };
        tracing::info!(
            method = %summary.method,
            path = %summary.path_and_query,
            status = summary.status.as_u16(),
            duration_ms = summary.duration.as_millis(),
            request_bytes = summary.request_bytes,
            response_bytes = summary.response_bytes,
            "request complete"
        );
        let _ = self.summaries.send(summary);
    }
}

struct CountedBody<B> {
    inner: Pin<Box<B>>,
    transferred: Arc<AtomicU64>,
}

impl<B> CountedBody<B> {
    fn new(inner: B, transferred: Arc<AtomicU64>) -> Self {
        Self {
            inner: Box::pin(inner),
            transferred,
        }
    }
}

impl<B> Body for CountedBody<B>
where
    B: Body<Data = Bytes>,
{
    type Data = Bytes;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        match this.inner.as_mut().poll_frame(context) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    add_bytes(&this.transferred, data.len() as u64);
                }
                Poll::Ready(Some(Ok(frame)))
            }
            other => other,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CaptureDirection {
    Request,
    Response,
}

struct CapturedBody<B> {
    inner: Pin<Box<B>>,
    transferred: Arc<AtomicU64>,
    capture: InspectionCapture,
    direction: CaptureDirection,
    finished: bool,
}

impl<B> CapturedBody<B>
where
    B: Body,
{
    fn new(
        inner: B,
        transferred: Arc<AtomicU64>,
        capture: InspectionCapture,
        direction: CaptureDirection,
    ) -> Self {
        let finished = inner.is_end_stream();
        if finished {
            capture.finish_body(direction);
        }
        Self {
            inner: Box::pin(inner),
            transferred,
            capture,
            direction,
            finished,
        }
    }
}

impl<B> CapturedBody<B> {
    fn finish(&mut self) {
        if self.finished {
            return;
        }
        self.finished = true;
        self.capture.finish_body(self.direction);
    }
}

impl<B> Body for CapturedBody<B>
where
    B: Body<Data = Bytes>,
{
    type Data = Bytes;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        let polled = this.inner.as_mut().poll_frame(context);
        match &polled {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    add_bytes(&this.transferred, data.len() as u64);
                    this.capture.record_body_chunk(this.direction, data);
                }
                if this.inner.is_end_stream() {
                    this.finish();
                }
            }
            Poll::Ready(Some(Err(_))) => {
                if !this.finished {
                    this.finished = true;
                    this.capture.body_failed(this.direction);
                }
            }
            Poll::Ready(None) => this.finish(),
            Poll::Pending => {}
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        self.finished || self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

impl<B> Drop for CapturedBody<B> {
    fn drop(&mut self) {
        if !self.finished {
            self.finished = true;
            self.capture.body_dropped(self.direction);
        }
    }
}

enum ForwardBody<B> {
    Counted(CountedBody<B>),
    Captured(CapturedBody<B>),
}

impl<B> ForwardBody<B>
where
    B: Body,
{
    fn new(
        inner: B,
        transferred: Arc<AtomicU64>,
        capture: Option<InspectionCapture>,
        direction: CaptureDirection,
    ) -> Self {
        match capture {
            Some(capture) => {
                Self::Captured(CapturedBody::new(inner, transferred, capture, direction))
            }
            None => Self::Counted(CountedBody::new(inner, transferred)),
        }
    }
}

impl<B> Body for ForwardBody<B>
where
    B: Body<Data = Bytes>,
{
    type Data = Bytes;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.get_mut() {
            Self::Counted(body) => Pin::new(body).poll_frame(context),
            Self::Captured(body) => Pin::new(body).poll_frame(context),
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            Self::Counted(body) => body.is_end_stream(),
            Self::Captured(body) => body.is_end_stream(),
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            Self::Counted(body) => body.size_hint(),
            Self::Captured(body) => body.size_hint(),
        }
    }
}

struct CompletionBody<B> {
    inner: Pin<Box<B>>,
    stats: Arc<RequestStats>,
    status: StatusCode,
    complete: bool,
}

impl<B> CompletionBody<B>
where
    B: Body,
{
    fn new(inner: B, stats: Arc<RequestStats>, status: StatusCode) -> Self {
        let complete = inner.is_end_stream();
        if complete {
            stats.emit(status);
        }
        Self {
            inner: Box::pin(inner),
            stats,
            status,
            complete,
        }
    }
}

impl<B> Body for CompletionBody<B>
where
    B: Body<Data = Bytes>,
{
    type Data = Bytes;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        let polled = this.inner.as_mut().poll_frame(context);
        let terminal = matches!(polled, Poll::Ready(None | Some(Err(_))))
            || matches!(polled, Poll::Ready(Some(Ok(_)))) && this.inner.is_end_stream();
        if terminal && !this.complete {
            this.complete = true;
            this.stats.emit(this.status);
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        self.complete || self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

impl<B> Drop for CompletionBody<B> {
    fn drop(&mut self) {
        if !self.complete {
            self.complete = true;
            self.stats.emit(self.status);
        }
    }
}

fn add_bytes(counter: &AtomicU64, amount: u64) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
        Some(value.saturating_add(amount))
    });
}

fn duration_micros(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

trait LocalIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T> LocalIo for T where T: AsyncRead + AsyncWrite + Unpin + Send {}
type BoxedLocalIo = Box<dyn LocalIo>;

fn ensure_crypto_provider() -> Result<(), ProxySetupError> {
    if CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }
    CryptoProvider::get_default()
        .map(|_| ())
        .ok_or(ProxySetupError::MissingTlsProvider)
}

fn local_tls_connector(insecure: bool) -> Result<TlsConnector, ProxySetupError> {
    let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    if insecure {
        let supported = CryptoProvider::get_default()
            .ok_or(ProxySetupError::MissingTlsProvider)?
            .signature_verification_algorithms;
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(DevelopmentOnlyVerifier { supported }));
    }
    Ok(TlsConnector::from(Arc::new(config)))
}

fn server_name(host: &str) -> Result<ServerName<'static>, LocalConnectError> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ServerName::IpAddress(ip.into()));
    }
    ServerName::try_from(host.to_owned()).map_err(|_| LocalConnectError::InvalidTarget)
}

#[derive(Debug)]
struct DevelopmentOnlyVerifier {
    supported: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for DevelopmentOnlyVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls12_signature(message, cert, signature, &self.supported)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls13_signature(message, cert, signature, &self.supported)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported.supported_schemes()
    }
}

async fn bridge_upgrades(public: OnUpgrade, local: OnUpgrade) -> io::Result<(u64, u64)> {
    let (public, local) = tokio::try_join!(upgrade_io(public), upgrade_io(local))?;
    bridge_io(TokioIo::new(public), TokioIo::new(local)).await
}

async fn upgrade_io(upgrade: OnUpgrade) -> io::Result<Upgraded> {
    upgrade
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::ConnectionAborted, "HTTP upgrade failed"))
}

async fn bridge_io<A, B>(mut public: A, mut local: B) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    tokio::io::copy_bidirectional(&mut public, &mut local).await
}

#[derive(Debug, thiserror::Error)]
pub enum ProxySetupError {
    #[error("local target cannot be represented as an HTTP request URI")]
    InvalidLocalTarget,
    #[error("local request URI is invalid")]
    InvalidUri(#[from] http::Error),
    #[error("local request path is invalid")]
    InvalidPath(#[from] http::uri::InvalidUri),
    #[error("local target authority is invalid")]
    InvalidAuthority(#[from] http::header::InvalidHeaderValue),
    #[error("no rustls cryptographic provider is installed")]
    MissingTlsProvider,
}

#[derive(Clone, Copy, Debug, thiserror::Error)]
enum LocalConnectError {
    #[error("invalid local target")]
    InvalidTarget,
    #[error("local target is unavailable")]
    Unavailable,
    #[error("local target connection timed out")]
    Timeout,
    #[error("local TLS certificate or hostname validation failed")]
    Tls,
}

#[cfg(test)]
mod tests {
    use std::{
        convert::Infallible,
        str::FromStr,
        sync::atomic::{AtomicUsize, Ordering},
    };

    use futures::{StreamExt as _, future::join_all, stream};
    use http_body_util::{Empty, StreamBody};
    use hyper::service::service_fn;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::inspection::{
        BodyCompletion, BodyRetention, FailureKind, HeaderSnapshot, InspectionLimits,
        TransactionLifecycle,
    };
    use crate::replay::ReplayService;

    fn capture_request<B>(
        store: &InspectionStore,
        request: &Request<B>,
        websocket_upgrade: bool,
    ) -> InspectionCapture
    where
        B: Body,
    {
        InspectionCapture::begin(
            store,
            request,
            SystemTime::now(),
            Instant::now(),
            websocket_upgrade,
        )
        .expect("test request should be captured")
    }

    fn public_request<B>(body: B) -> Result<Request<B>, http::Error> {
        Request::builder()
            .uri("/capture?from=test")
            .header(HOST, "fallback.example.test")
            .header(X_FORWARDED_HOST, "public.example.test")
            .header(X_FORWARDED_PROTO, "https")
            .body(body)
    }

    #[test]
    fn crypto_provider_initialization_is_idempotent() -> Result<(), ProxySetupError> {
        ensure_crypto_provider()?;
        ensure_crypto_provider()?;
        assert!(CryptoProvider::get_default().is_some());
        Ok(())
    }

    #[test]
    fn resolves_base_path_and_rewrites_host_without_touching_other_headers()
    -> Result<(), Box<dyn StdError>> {
        let target = LocalTarget::from_str("http://local.example:8080/api/v1/")?;
        let mut request = Request::builder()
            .uri("/users/%2Fraw?active=true")
            .header(HOST, "public.example.com")
            .header("x-forwarded-host", "public.example.com")
            .body(())?;
        rewrite_local_request(&mut request, &target)?;
        assert_eq!(
            request.uri().to_string(),
            "http://local.example:8080/api/v1/users/%2Fraw?active=true"
        );
        assert_eq!(request.headers()[HOST], "local.example:8080");
        assert_eq!(request.headers()["x-forwarded-host"], "public.example.com");
        Ok(())
    }

    #[test]
    fn root_target_preserves_incoming_path_and_query() -> Result<(), Box<dyn StdError>> {
        let target = LocalTarget::from_str("http://localhost:3000/")?;
        let incoming = Uri::from_static("/events?cursor=42");
        assert_eq!(
            resolve_local_uri(&target, &incoming)?.to_string(),
            "http://localhost:3000/events?cursor=42"
        );
        Ok(())
    }

    #[test]
    fn captures_public_metadata_before_local_rewrite() -> Result<(), Box<dyn StdError>> {
        let store = InspectionStore::new(InspectionLimits::new(4, 64)?);
        let before = SystemTime::now();
        let mut request = Request::builder()
            .method(Method::PATCH)
            .version(http::Version::HTTP_2)
            .uri("http://untrusted.invalid/widgets/%2Fraw?draft=true")
            .header(HOST, "fallback.invalid")
            .header(X_FORWARDED_HOST, "public.example.test:8443")
            .header(X_FORWARDED_PROTO, "https")
            .header("x-application-header", "preserved")
            .header("x-sink-inspector-token", "reserved-control-value")
            .body(Empty::<Bytes>::new())?;
        let capture = InspectionCapture::begin(&store, &request, before, Instant::now(), false)
            .ok_or("request was not captured")?;
        let target = LocalTarget::from_str("http://127.0.0.1:8080/base")?;
        rewrite_local_request(&mut request, &target)?;

        let transaction = store.get(capture.id()).ok_or("capture missing")?;
        assert_eq!(transaction.received_at(), before);
        assert_eq!(transaction.request().method(), Method::PATCH);
        assert_eq!(transaction.request().version(), http::Version::HTTP_2);
        assert_eq!(
            transaction.request().public_uri().to_string(),
            "https://public.example.test:8443/widgets/%2Fraw?draft=true"
        );
        assert!(transaction.request().headers().iter().any(|header| {
            header.name().as_str() == "x-application-header" && header.value() == "preserved"
        }));
        assert!(
            transaction
                .request()
                .headers()
                .iter()
                .all(|header| !crate::inspection::is_sink_control_header(header.name()))
        );
        assert_eq!(
            request.uri().to_string(),
            "http://127.0.0.1:8080/base/widgets/%2Fraw?draft=true"
        );
        assert_eq!(request.headers()[HOST], "127.0.0.1:8080");
        assert!(request.headers()["x-sink-inspector-token"] == "reserved-control-value");
        Ok(())
    }

    #[test]
    fn invalid_public_metadata_disables_only_capture() -> Result<(), Box<dyn StdError>> {
        let store = InspectionStore::new(InspectionLimits::new(4, 64)?);
        let mut request = Request::builder()
            .uri("/safe-forwarding")
            .header(HOST, "public.example.test")
            .header(X_FORWARDED_HOST, "/not-an-authority")
            .header(X_FORWARDED_PROTO, "https")
            .body(Empty::<Bytes>::new())?;

        assert!(
            InspectionCapture::begin(&store, &request, SystemTime::now(), Instant::now(), false,)
                .is_none()
        );
        rewrite_local_request(
            &mut request,
            &LocalTarget::from_str("http://127.0.0.1:8080")?,
        )?;
        assert_eq!(
            request.uri().to_string(),
            "http://127.0.0.1:8080/safe-forwarding"
        );
        assert!(store.is_empty());
        Ok(())
    }

    #[test]
    fn disabled_and_paused_inspection_do_not_capture() -> Result<(), Box<dyn StdError>> {
        let (summary_tx, _) = broadcast::channel(4);
        let proxy = LocalProxy::new(
            LocalTarget::from_str("http://127.0.0.1:8080")?,
            false,
            summary_tx,
        )?;
        assert!(proxy.inspection.is_none());

        let store = InspectionStore::new(InspectionLimits::new(4, 64)?);
        store.pause();
        let request = public_request(Empty::<Bytes>::new())?;
        assert!(
            InspectionCapture::begin(&store, &request, SystemTime::now(), Instant::now(), false,)
                .is_none()
        );
        assert!(store.is_empty());

        let (summary_tx, _) = broadcast::channel(4);
        let configured = LocalProxy::new_with_inspection(
            LocalTarget::from_str("http://127.0.0.1:8080")?,
            false,
            summary_tx,
            Some(store.clone()),
        )?;
        assert!(configured.inspection.is_some());
        Ok(())
    }

    #[tokio::test]
    async fn local_connection_failure_returns_safe_quick_503_and_keeps_summary_safe()
    -> Result<(), BoxError> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        drop(listener);

        let store = InspectionStore::new(InspectionLimits::new(4, 64)?);
        let (summary_tx, mut summary_rx) = broadcast::channel(4);
        let proxy = LocalProxy::new_with_inspection(
            format!("http://127.0.0.1:{port}").parse()?,
            false,
            summary_tx,
            Some(store.clone()),
        )?
        .for_connection(TaskTracker::new(), CancellationToken::new());
        let response = proxy
            .forward(
                Request::builder()
                    .method(Method::POST)
                    .uri("/upload?kind=test")
                    .header(HOST, "public.example.test")
                    .header(X_FORWARDED_HOST, "public.example.test")
                    .header(X_FORWARDED_PROTO, "https")
                    .body(Empty::<Bytes>::new())?,
            )
            .await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = response.into_body().collect().await?.to_bytes();
        assert_eq!(body, SERVICE_UNAVAILABLE_BODY);
        let summary = summary_rx.recv().await?;
        assert_eq!(summary.method, Method::POST);
        assert_eq!(summary.path_and_query, "/upload?kind=test");
        assert_eq!(summary.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(summary.response_bytes, body.len() as u64);
        let transaction = store
            .list()
            .pop()
            .ok_or_else(|| -> BoxError { Box::new(io::Error::other("capture missing")) })?;
        assert!(matches!(
            transaction.lifecycle(),
            TransactionLifecycle::FailedOrCancelled(failure)
                if failure.kind() == FailureKind::Failed
                    && failure.message()
                        == Some(ReplayTransportError::Connect.capture_message())
        ));
        Ok(())
    }

    #[tokio::test]
    async fn upgrade_bridge_is_full_duplex_and_counts_both_directions()
    -> Result<(), Box<dyn StdError>> {
        let (mut public_peer, public_bridge) = tokio::io::duplex(64);
        let (local_bridge, mut local_peer) = tokio::io::duplex(64);
        let bridge = tokio::spawn(bridge_io(public_bridge, local_bridge));

        public_peer.write_all(b"visitor-to-local").await?;
        let mut at_local = vec![0; 16];
        local_peer.read_exact(&mut at_local).await?;
        assert_eq!(at_local, b"visitor-to-local");

        local_peer.write_all(b"local-to-visitor").await?;
        let mut at_public = vec![0; 16];
        public_peer.read_exact(&mut at_public).await?;
        assert_eq!(at_public, b"local-to-visitor");

        public_peer.shutdown().await?;
        local_peer.shutdown().await?;
        drop(public_peer);
        drop(local_peer);
        assert_eq!(bridge.await??, (16, 16));
        Ok(())
    }

    #[tokio::test]
    async fn captured_body_forwards_first_frame_before_later_frames()
    -> Result<(), Box<dyn StdError>> {
        let store = InspectionStore::new(InspectionLimits::new(4, 64)?);
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let first =
            stream::once(async { Ok::<_, Infallible>(Frame::data(Bytes::from_static(b"first"))) });
        let second = stream::once(async move {
            let _ = release_rx.await;
            Ok::<_, Infallible>(Frame::data(Bytes::from_static(b"second")))
        });
        let request = public_request(StreamBody::new(first.chain(second)))?;
        let capture = capture_request(&store, &request, false);
        let counter = Arc::new(AtomicU64::new(0));
        let mut body = CapturedBody::new(
            request.into_body(),
            counter.clone(),
            capture.clone(),
            CaptureDirection::Request,
        );

        let first = timeout(Duration::from_millis(100), body.frame())
            .await?
            .ok_or("missing first frame")??;
        assert_eq!(first.data_ref(), Some(&Bytes::from_static(b"first")));
        assert_eq!(
            store
                .get(capture.id())
                .ok_or("capture missing")?
                .request()
                .body()
                .retained_bytes(),
            b"first"
        );
        assert_eq!(counter.load(Ordering::Relaxed), 5);

        let _ = release_tx.send(());
        let second = body.frame().await.ok_or("missing second frame")??;
        assert_eq!(second.data_ref(), Some(&Bytes::from_static(b"second")));
        assert!(body.frame().await.is_none());
        let body = store
            .get(capture.id())
            .ok_or("capture missing")?
            .request()
            .body()
            .clone();
        assert_eq!(body.retained_bytes(), b"firstsecond");
        assert_eq!(body.total_bytes(), 11);
        assert_eq!(body.completion(), BodyCompletion::Complete);
        assert_eq!(counter.load(Ordering::Relaxed), 11);
        Ok(())
    }

    #[tokio::test]
    async fn captured_body_preserves_trailers_and_size_hint() -> Result<(), Box<dyn StdError>> {
        let store = InspectionStore::new(InspectionLimits::new(4, 64)?);
        let mut trailers = HeaderMap::new();
        trailers.insert("x-checksum", HeaderValue::from_static("final"));
        let frames = stream::iter(vec![
            Ok::<_, Infallible>(Frame::data(Bytes::from_static(b"data"))),
            Ok(Frame::trailers(trailers)),
        ]);
        let request = public_request(StreamBody::new(frames))?;
        let capture = capture_request(&store, &request, false);
        let original_hint = request.body().size_hint();
        let mut body = CapturedBody::new(
            request.into_body(),
            Arc::new(AtomicU64::new(0)),
            capture,
            CaptureDirection::Request,
        );
        assert_eq!(body.size_hint().lower(), original_hint.lower());
        assert_eq!(body.size_hint().upper(), original_hint.upper());

        let data = body.frame().await.ok_or("missing data frame")??;
        assert_eq!(data.data_ref(), Some(&Bytes::from_static(b"data")));
        let trailers = body.frame().await.ok_or("missing trailer frame")??;
        assert_eq!(
            trailers
                .trailers_ref()
                .and_then(|headers| headers.get("x-checksum")),
            Some(&HeaderValue::from_static("final"))
        );
        assert!(body.frame().await.is_none());
        assert!(body.is_end_stream());
        Ok(())
    }

    #[tokio::test]
    async fn preview_truncates_without_losing_actual_byte_count() -> Result<(), Box<dyn StdError>> {
        let store = InspectionStore::new(InspectionLimits::new(4, 5)?);
        let request = Request::builder()
            .uri("/text")
            .header(HOST, "public.example.test")
            .header(X_FORWARDED_HOST, "public.example.test")
            .header(X_FORWARDED_PROTO, "https")
            .header(CONTENT_TYPE, "text/plain")
            .body(Full::new(Bytes::from_static(b"abcdefghij")))?;
        let capture = capture_request(&store, &request, false);
        let counter = Arc::new(AtomicU64::new(0));
        let body = CapturedBody::new(
            request.into_body(),
            counter.clone(),
            capture.clone(),
            CaptureDirection::Request,
        );
        body.collect().await?;

        let transaction = store.get(capture.id()).ok_or("capture missing")?;
        let preview = transaction.request().body();
        assert_eq!(preview.retained_bytes(), b"abcde");
        assert_eq!(preview.total_bytes(), 10);
        assert_eq!(preview.retention(), BodyRetention::Truncated);
        assert_eq!(preview.completion(), BodyCompletion::Complete);
        assert_eq!(counter.load(Ordering::Relaxed), 10);
        Ok(())
    }

    #[tokio::test]
    async fn binary_preview_counts_but_omits_bytes() -> Result<(), Box<dyn StdError>> {
        let store = InspectionStore::new(InspectionLimits::new(4, 64)?);
        let request = Request::builder()
            .uri("/image")
            .header(HOST, "public.example.test")
            .header(X_FORWARDED_HOST, "public.example.test")
            .header(X_FORWARDED_PROTO, "https")
            .header(CONTENT_TYPE, "image/png")
            .body(Full::new(Bytes::from_static(b"\x89PNGbinary")))?;
        let capture = capture_request(&store, &request, false);
        CapturedBody::new(
            request.into_body(),
            Arc::new(AtomicU64::new(0)),
            capture.clone(),
            CaptureDirection::Request,
        )
        .collect()
        .await?;

        let transaction = store.get(capture.id()).ok_or("capture missing")?;
        let preview = transaction.request().body();
        assert_eq!(preview.content_kind(), BodyContentKind::Binary);
        assert_eq!(preview.total_bytes(), 10);
        assert!(preview.retained_bytes().is_empty());
        assert_eq!(preview.retention(), BodyRetention::OmittedBinary);
        Ok(())
    }

    #[test]
    fn response_headers_classify_sse_before_body_polling() -> Result<(), Box<dyn StdError>> {
        let store = InspectionStore::new(InspectionLimits::new(4, 64)?);
        let request = public_request(Empty::<Bytes>::new())?;
        let capture = capture_request(&store, &request, false);
        CapturedBody::new(
            request.into_body(),
            Arc::new(AtomicU64::new(0)),
            capture.clone(),
            CaptureDirection::Request,
        );
        let response = Response::builder()
            .status(StatusCode::OK)
            .version(http::Version::HTTP_11)
            .header(CONTENT_TYPE, "text/event-stream; charset=utf-8")
            .header("x-response", "available-now")
            .body(StreamBody::new(stream::pending::<
                Result<Frame<Bytes>, Infallible>,
            >()))?;
        capture.start_response(&response, false);

        let transaction = store.get(capture.id()).ok_or("capture missing")?;
        let response = transaction.response().ok_or("response missing")?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.version(), http::Version::HTTP_11);
        assert_eq!(response.body().content_kind(), BodyContentKind::Text);
        assert!(response.body().constraints().is_server_sent_events());
        assert!(response.body().constraints().is_streaming());
        assert!(response.headers().iter().any(|header| {
            header.name().as_str() == "x-response" && header.value() == "available-now"
        }));
        Ok(())
    }

    #[test]
    fn dropping_response_body_marks_capture_cancelled() -> Result<(), Box<dyn StdError>> {
        let store = InspectionStore::new(InspectionLimits::new(4, 64)?);
        let request = public_request(Empty::<Bytes>::new())?;
        let capture = capture_request(&store, &request, false);
        drop(CapturedBody::new(
            request.into_body(),
            Arc::new(AtomicU64::new(0)),
            capture.clone(),
            CaptureDirection::Request,
        ));
        let response = Response::builder()
            .status(StatusCode::OK)
            .body(StreamBody::new(stream::pending::<
                Result<Frame<Bytes>, Infallible>,
            >()))?;
        capture.start_response(&response, false);
        drop(CapturedBody::new(
            response.into_body(),
            Arc::new(AtomicU64::new(0)),
            capture.clone(),
            CaptureDirection::Response,
        ));

        let transaction = store.get(capture.id()).ok_or("capture missing")?;
        assert!(matches!(
            transaction.lifecycle(),
            TransactionLifecycle::FailedOrCancelled(failure)
                if failure.kind() == FailureKind::Cancelled
        ));
        assert_eq!(
            transaction
                .response()
                .ok_or("response missing")?
                .body()
                .completion(),
            BodyCompletion::Incomplete
        );
        Ok(())
    }

    #[test]
    fn upgrade_capture_is_handshake_only() -> Result<(), Box<dyn StdError>> {
        let store = InspectionStore::new(InspectionLimits::new(4, 64)?);
        let request = Request::builder()
            .uri("/socket")
            .header(HOST, "public.example.test")
            .header(X_FORWARDED_HOST, "public.example.test")
            .header(X_FORWARDED_PROTO, "https")
            .header(CONNECTION, "upgrade")
            .header(UPGRADE, "websocket")
            .body(Empty::<Bytes>::new())?;
        assert!(request_wants_upgrade(&request));
        let capture = capture_request(&store, &request, true);
        drop(CapturedBody::new(
            request.into_body(),
            Arc::new(AtomicU64::new(0)),
            capture.clone(),
            CaptureDirection::Request,
        ));
        let response = Response::builder()
            .status(StatusCode::SWITCHING_PROTOCOLS)
            .header(CONNECTION, "upgrade")
            .header(UPGRADE, "websocket")
            .body(Empty::<Bytes>::new())?;
        capture.start_response(&response, true);
        capture.upgrade();
        capture.record_body_chunk(CaptureDirection::Request, b"websocket-request-frame");
        capture.record_body_chunk(CaptureDirection::Response, b"websocket-response-frame");

        let transaction = store.get(capture.id()).ok_or("capture missing")?;
        assert_eq!(transaction.lifecycle(), &TransactionLifecycle::Upgraded);
        assert!(
            transaction
                .request()
                .body()
                .constraints()
                .is_websocket_upgrade()
        );
        assert!(
            transaction
                .response()
                .ok_or("response missing")?
                .body()
                .constraints()
                .is_websocket_upgrade()
        );
        assert_eq!(transaction.request().body().total_bytes(), 0);
        assert_eq!(
            transaction
                .response()
                .ok_or("response missing")?
                .body()
                .total_bytes(),
            0
        );

        let connect = Request::builder()
            .method(Method::CONNECT)
            .uri("/connect")
            .body(Empty::<Bytes>::new())?;
        assert!(request_wants_upgrade(&connect));
        Ok(())
    }

    #[tokio::test]
    async fn request_and_response_are_streamed_without_whole_body_buffering() -> Result<(), BoxError>
    {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await?;
            let service = service_fn(|mut request: Request<Incoming>| async move {
                let first = request.body_mut().frame().await;
                let received_first_chunk = matches!(
                    first,
                    Some(Ok(frame)) if frame.data_ref().is_some_and(|data| data == "first-chunk")
                );
                let status = if received_first_chunk {
                    StatusCode::OK
                } else {
                    StatusCode::BAD_REQUEST
                };
                Ok::<_, Infallible>(
                    Response::builder()
                        .status(status)
                        .body(Full::new(Bytes::from_static(b"early-response")))
                        .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))),
                )
            });
            hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(socket), service)
                .await
                .map_err(io::Error::other)
        });

        let (summary_tx, _) = broadcast::channel(4);
        let tasks = TaskTracker::new();
        let proxy = LocalProxy::new(
            format!("http://127.0.0.1:{port}").parse()?,
            false,
            summary_tx,
        )?
        .for_connection(tasks.clone(), CancellationToken::new());

        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let first = stream::once(async {
            Ok::<_, Infallible>(Frame::data(Bytes::from_static(b"first-chunk")))
        });
        let second = stream::once(async move {
            let _ = release_rx.await;
            Ok::<_, Infallible>(Frame::data(Bytes::from_static(b"second-chunk")))
        });
        let request = Request::builder()
            .method(Method::POST)
            .uri("/stream")
            .body(StreamBody::new(first.chain(second)))?;
        let request_head_at = Instant::now();
        let response = timeout(
            Duration::from_secs(1),
            proxy.forward_tunnel(
                request,
                TunnelRequestTiming {
                    session_id: Uuid::from_u128(42),
                    stream_id: 2,
                    accepted_at: request_head_at,
                    request_head_at,
                },
            ),
        )
        .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let _ = release_tx.send(());
        assert_eq!(
            response.into_body().collect().await?.to_bytes(),
            "early-response"
        );

        tasks.close();
        let _ = timeout(Duration::from_secs(1), tasks.wait()).await;
        server.await??;
        Ok(())
    }

    #[tokio::test]
    async fn captured_exchange_preserves_terminal_summary_byte_counts() -> Result<(), BoxError> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await?;
            let service = service_fn(|request: Request<Incoming>| async move {
                let request_body = request.into_body().collect().await?.to_bytes();
                let status = if request_body == "request-body" {
                    StatusCode::CREATED
                } else {
                    StatusCode::BAD_REQUEST
                };
                Ok::<_, hyper::Error>(
                    Response::builder()
                        .status(status)
                        .header(CONTENT_TYPE, "text/plain")
                        .body(Full::new(Bytes::from_static(b"response!")))
                        .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))),
                )
            });
            hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(socket), service)
                .await
                .map_err(io::Error::other)
        });

        let store = InspectionStore::new(
            InspectionLimits::new(4, 64).map_err(|error| -> BoxError { Box::new(error) })?,
        );
        let (summary_tx, mut summary_rx) = broadcast::channel(4);
        let tasks = TaskTracker::new();
        let proxy = LocalProxy::new_with_inspection(
            format!("http://127.0.0.1:{port}").parse()?,
            false,
            summary_tx,
            Some(store.clone()),
        )?
        .for_connection(tasks.clone(), CancellationToken::new());
        let response = proxy
            .forward(
                Request::builder()
                    .method(Method::POST)
                    .uri("/counted")
                    .header(HOST, "public.example.test")
                    .header(X_FORWARDED_HOST, "public.example.test")
                    .header(X_FORWARDED_PROTO, "https")
                    .header(CONTENT_TYPE, "application/json")
                    .body(Full::new(Bytes::from_static(b"request-body")))?,
            )
            .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(
            response.into_body().collect().await?.to_bytes(),
            "response!"
        );

        let summary = timeout(Duration::from_secs(1), summary_rx.recv()).await??;
        assert_eq!(summary.status, StatusCode::CREATED);
        assert_eq!(summary.request_bytes, 12);
        assert_eq!(summary.response_bytes, 9);
        let transaction = store
            .list()
            .pop()
            .ok_or_else(|| -> BoxError { Box::new(io::Error::other("capture missing")) })?;
        assert_eq!(transaction.lifecycle(), &TransactionLifecycle::Completed);
        assert_eq!(transaction.request().body().total_bytes(), 12);
        assert_eq!(
            transaction
                .response()
                .ok_or_else(|| -> BoxError { Box::new(io::Error::other("response missing")) })?
                .body()
                .total_bytes(),
            9
        );

        tasks.close();
        let _ = timeout(Duration::from_secs(1), tasks.wait()).await;
        server.await??;
        Ok(())
    }

    #[tokio::test]
    async fn exact_replay_routes_directly_with_base_path_host_headers_body_and_terminal_capture()
    -> Result<(), BoxError> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let (observed_tx, observed_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await?;
            let observed_tx = Arc::new(std::sync::Mutex::new(Some(observed_tx)));
            let service = service_fn(move |request: Request<Incoming>| {
                let observed_tx = observed_tx.clone();
                async move {
                    let method = request.method().clone();
                    let version = request.version();
                    let uri = request.uri().clone();
                    let host = request.headers().get(HOST).cloned();
                    let repeated = request
                        .headers()
                        .get_all("x-repeat")
                        .iter()
                        .cloned()
                        .collect::<Vec<_>>();
                    let authorization = request.headers().get("authorization").cloned();
                    let sink_header = request.headers().get("x-sink-inspector-token").cloned();
                    let body = request.into_body().collect().await?.to_bytes();
                    if let Some(sender) = observed_tx
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .take()
                    {
                        let _ = sender.send((
                            method,
                            version,
                            uri,
                            host,
                            repeated,
                            authorization,
                            sink_header,
                            body,
                        ));
                    }
                    Ok::<_, hyper::Error>(
                        Response::builder()
                            .status(StatusCode::ACCEPTED)
                            .header(CONTENT_TYPE, "text/plain; charset=utf-8")
                            .header("x-local-response", "captured")
                            .body(Full::new(Bytes::from_static(b"response-preview")))
                            .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))),
                    )
                }
            });
            hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(socket), service)
                .await
                .map_err(io::Error::other)
        });

        let store = InspectionStore::new(InspectionLimits::new(8, 8)?);
        let mut request_body =
            store.body_preview(BodyContentKind::Json, BodyConstraints::ordinary());
        request_body.record_chunk(b"secret")?;
        request_body.finish()?;
        let source = RequestSnapshot::new(
            Method::PATCH,
            "https://public.invalid/orders/%2Fraw?draft=true".parse()?,
            http::Version::HTTP_11,
            HeaderSnapshots::from_entries([
                HeaderSnapshot::new(HOST, HeaderValue::from_static("public.invalid")),
                HeaderSnapshot::new(
                    HeaderName::from_static("x-repeat"),
                    HeaderValue::from_static("first"),
                ),
                HeaderSnapshot::new(
                    HeaderName::from_static("x-repeat"),
                    HeaderValue::from_static("second"),
                ),
                HeaderSnapshot::new(
                    HeaderName::from_static("authorization"),
                    HeaderValue::from_static("Bearer retained-application-secret"),
                ),
                HeaderSnapshot::new(
                    HeaderName::from_static("x-sink-inspector-token"),
                    HeaderValue::from_static("must-not-replay"),
                ),
                HeaderSnapshot::new(CONTENT_TYPE, HeaderValue::from_static("application/json")),
            ]),
            request_body,
        )?;
        let source_id = store
            .capture(TransactionOrigin::Original, source)
            .captured_id()
            .ok_or_else(|| -> BoxError {
                Box::new(io::Error::other("source capture unexpectedly paused"))
            })?;
        let (summary_tx, _) = broadcast::channel(4);
        let proxy = LocalProxy::new(
            format!("http://127.0.0.1:{port}/base/").parse()?,
            false,
            summary_tx,
        )?;
        let replay = ReplayService::new(store.clone(), Arc::new(proxy));
        let replay_id = replay.replay(source_id)?;

        let (method, version, uri, host, repeated, authorization, sink_header, body) =
            timeout(Duration::from_secs(1), observed_rx).await??;
        assert_eq!(method, Method::PATCH);
        assert_eq!(version, http::Version::HTTP_11);
        assert_eq!(
            uri.path_and_query().map(http::uri::PathAndQuery::as_str),
            Some("/base/orders/%2Fraw?draft=true")
        );
        assert_eq!(
            host,
            Some(HeaderValue::from_str(&format!("127.0.0.1:{port}"))?)
        );
        assert_eq!(
            repeated,
            [
                HeaderValue::from_static("first"),
                HeaderValue::from_static("second")
            ]
        );
        assert_eq!(
            authorization,
            Some(HeaderValue::from_static(
                "Bearer retained-application-secret"
            ))
        );
        assert_eq!(sink_header, None);
        assert_eq!(body, b"secret".as_slice());

        let replayed = timeout(Duration::from_secs(1), async {
            loop {
                if let Some(transaction) = store.get(replay_id)
                    && transaction.lifecycle().is_terminal()
                {
                    return transaction;
                }
                tokio::task::yield_now().await;
            }
        })
        .await?;
        assert_eq!(replayed.origin(), TransactionOrigin::replay(source_id));
        assert_eq!(replayed.lifecycle(), &TransactionLifecycle::Completed);
        let response = replayed
            .response()
            .ok_or_else(|| -> BoxError { Box::new(io::Error::other("replay response missing")) })?;
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        assert_eq!(response.body().retained_bytes(), b"response");
        assert_eq!(response.body().total_bytes(), 16);
        assert_eq!(response.body().retention(), BodyRetention::Truncated);
        server.await??;
        Ok(())
    }

    #[tokio::test]
    async fn replay_local_outage_returns_id_and_records_linked_terminal_failure()
    -> Result<(), BoxError> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        drop(listener);

        let store = InspectionStore::new(InspectionLimits::new(4, 64)?);
        let mut request_body =
            store.body_preview(BodyContentKind::Unknown, BodyConstraints::ordinary());
        request_body.finish()?;
        let source_id = store
            .capture(
                TransactionOrigin::Original,
                RequestSnapshot::new(
                    Method::GET,
                    "https://public.invalid/outage".parse()?,
                    http::Version::HTTP_11,
                    HeaderSnapshots::default(),
                    request_body,
                )?,
            )
            .captured_id()
            .ok_or_else(|| -> BoxError {
                Box::new(io::Error::other("source capture unexpectedly paused"))
            })?;
        let (summary_tx, _) = broadcast::channel(4);
        let proxy = LocalProxy::new(
            format!("http://127.0.0.1:{port}").parse()?,
            false,
            summary_tx,
        )?;
        let replay = ReplayService::new(store.clone(), Arc::new(proxy));
        let replay_id = replay.replay(source_id)?;
        let replayed = timeout(Duration::from_secs(1), async {
            loop {
                if let Some(transaction) = store.get(replay_id)
                    && transaction.lifecycle().is_terminal()
                {
                    return transaction;
                }
                tokio::task::yield_now().await;
            }
        })
        .await?;
        assert_eq!(replayed.origin(), TransactionOrigin::replay(source_id));
        assert!(matches!(
            replayed.lifecycle(),
            TransactionLifecycle::FailedOrCancelled(failure)
                if failure.kind() == FailureKind::Failed
                    && failure.message()
                        == Some(ReplayTransportError::Connect.capture_message())
        ));
        assert!(replayed.response().is_none());
        Ok(())
    }

    #[test]
    fn replay_reuses_secure_by_default_and_explicit_insecure_tls_connector_configuration()
    -> Result<(), Box<dyn StdError>> {
        let (summary_tx, _) = broadcast::channel(4);
        let secure = LocalProxy::new("https://localhost:443".parse()?, false, summary_tx.clone())?;
        let insecure = LocalProxy::new("https://localhost:443".parse()?, true, summary_tx.clone())?;
        let plaintext = LocalProxy::new("http://localhost:80".parse()?, false, summary_tx)?;
        assert!(secure.tls.is_some());
        assert!(insecure.tls.is_some());
        assert!(plaintext.tls.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn concurrent_exchanges_are_not_serialized() -> Result<(), BoxError> {
        const REQUESTS: usize = 32;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let stop = CancellationToken::new();
        let server_stop = stop.clone();
        let current = Arc::new(AtomicUsize::new(0));
        let maximum = Arc::new(AtomicUsize::new(0));
        let server_current = current.clone();
        let server_maximum = maximum.clone();
        let server = tokio::spawn(async move {
            loop {
                let accepted = tokio::select! {
                    () = server_stop.cancelled() => return,
                    accepted = listener.accept() => accepted,
                };
                let Ok((socket, _)) = accepted else {
                    return;
                };
                let current = server_current.clone();
                let maximum = server_maximum.clone();
                tokio::spawn(async move {
                    let service = service_fn(move |_request: Request<Incoming>| {
                        let current = current.clone();
                        let maximum = maximum.clone();
                        async move {
                            let active = current.fetch_add(1, Ordering::SeqCst) + 1;
                            maximum.fetch_max(active, Ordering::SeqCst);
                            tokio::time::sleep(Duration::from_millis(30)).await;
                            current.fetch_sub(1, Ordering::SeqCst);
                            Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"ok"))))
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(socket), service)
                        .await;
                });
            }
        });

        let (summary_tx, _) = broadcast::channel(REQUESTS);
        let tasks = TaskTracker::new();
        let proxy = LocalProxy::new(
            format!("http://127.0.0.1:{port}").parse()?,
            false,
            summary_tx,
        )?
        .for_connection(tasks.clone(), CancellationToken::new());
        let responses = join_all((0..REQUESTS).map(|index| {
            let proxy = proxy.clone();
            async move {
                proxy
                    .forward(
                        Request::builder()
                            .uri(format!("/request/{index}"))
                            .body(Empty::<Bytes>::new())
                            .unwrap_or_else(|_| Request::new(Empty::new())),
                    )
                    .await
            }
        }))
        .await;
        for response in responses {
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response.into_body().collect().await?.to_bytes(), "ok");
        }
        assert!(maximum.load(Ordering::SeqCst) > 1);

        tasks.close();
        let _ = timeout(Duration::from_secs(1), tasks.wait()).await;
        stop.cancel();
        server.await?;
        Ok(())
    }
}
