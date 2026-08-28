//! Loopback-only dashboard asset service and versioned inspection API.

mod assets;

pub use assets::{ProductionAssets, production_assets};

use std::{
    borrow::Cow,
    convert::Infallible,
    fmt,
    io::{self, Read as _},
    net::{Ipv4Addr, SocketAddr},
    num::NonZeroU16,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{
    Json, Router,
    body::Body,
    extract::{Path, State},
    http::{
        HeaderValue, Method, Request, StatusCode, Version,
        header::{
            CACHE_CONTROL, CONTENT_ENCODING, CONTENT_SECURITY_POLICY, CONTENT_TYPE, HOST, ORIGIN,
            PRAGMA, REFERRER_POLICY, X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS,
        },
    },
    middleware::{self, Next},
    response::{IntoResponse, Response, Sse, sse::Event},
    routing::{get, post},
};
use bytes::Bytes;
use flate2::read::{DeflateDecoder, GzDecoder, ZlibDecoder};
use futures::{StreamExt, stream};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::{net::TcpListener, sync::broadcast};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::curl::{
    CurlGenerationError, CurlGenerationOutcome, CurlService, CurlServiceError,
    SensitiveHeaderConsent,
};
use crate::inspection::{
    BodyCompletion, BodyConstraints, BodyContentKind, BodyPreview, BodyRetention, FailureKind,
    HeaderSensitivity, HeaderSnapshot, HeaderSnapshots, InspectionEvent, InspectionEventKind,
    InspectionStore, RemovalCause, ReplayEligibility, RequestSnapshot, ResponseSnapshot,
    SensitiveHeaderKind, Transaction, TransactionId, TransactionLifecycle, TransactionOrigin,
};
use crate::replay::{ReplayError, ReplayService};

/// The preferred dashboard port when the user did not request one explicitly.
pub const DEFAULT_DASHBOARD_PORT: u16 = 4040;

/// Custom request header required for reveal and every modifying API operation.
pub const INSPECTOR_TOKEN_HEADER: &str = "x-sink-inspector-token";

const INDEX_PATH: &str = "/index.html";
const CURL_REQUEST_BODY_LIMIT: usize = 256;
// Reka Select emits one static viewport stylesheet. Pin its exact hash instead of
// allowing arbitrary inline styles so the shadcn primitive works under the dashboard CSP.
const CONTENT_SECURITY_POLICY_VALUE: &str = "default-src 'self'; script-src 'self'; style-src 'self' 'sha256-60LHlRjW/B3CtzIoE/Lf1/NEDvko9efWMFaGVhHu/cs='; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'";

/// Port selection exposed to runtime integration.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum DashboardPort {
    /// Prefer 4040 and scan upward only when an address is already occupied.
    #[default]
    Automatic,
    /// Attempt exactly one validated, non-zero user-requested port.
    Explicit(NonZeroU16),
}

#[derive(Clone, Copy, Debug)]
enum BindMode {
    Automatic,
    Explicit(NonZeroU16),
    #[cfg(test)]
    Ephemeral,
}

/// One immutable asset that is already embedded in process memory.
#[derive(Clone)]
pub struct EmbeddedAsset {
    body: Bytes,
    content_type: HeaderValue,
}

impl EmbeddedAsset {
    /// Construct an embedded asset with an explicit MIME type.
    pub fn new(
        body: impl Into<Bytes>,
        content_type: &str,
    ) -> Result<Self, axum::http::header::InvalidHeaderValue> {
        Ok(Self {
            body: body.into(),
            content_type: HeaderValue::from_str(content_type)?,
        })
    }

    #[must_use]
    pub fn body(&self) -> &Bytes {
        &self.body
    }

    #[must_use]
    pub fn content_type(&self) -> &HeaderValue {
        &self.content_type
    }
}

impl fmt::Debug for EmbeddedAsset {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EmbeddedAsset")
            .field("body_len", &self.body.len())
            .field("content_type", &self.content_type)
            .finish()
    }
}

/// Injected source for production assets embedded into the executable.
///
/// Build integration can implement this trait with generated static byte slices.
/// The service itself never opens files or contacts a CDN.
pub trait EmbeddedAssetSource: Send + Sync + 'static {
    /// Fetch an asset by its absolute URL path (for example `/assets/app.js`).
    fn get(&self, path: &str) -> Option<EmbeddedAsset>;
}

/// An inspector token whose debug representation cannot expose the token value.
#[derive(Clone, PartialEq, Eq)]
pub struct InspectorToken(Arc<str>);

impl InspectorToken {
    fn generate() -> Self {
        let first = Uuid::new_v4().simple();
        let second = Uuid::new_v4().simple();
        Self(Arc::from(format!("{first}{second}")))
    }

    /// Expose the token for explicit API-client integration.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for InspectorToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InspectorToken([REDACTED])")
    }
}

/// A bound dashboard server that the runtime can supervise independently.
pub struct DashboardService {
    listener: TcpListener,
    router: Router,
    address: SocketAddr,
    url: String,
    inspector_token: InspectorToken,
    shutdown: CancellationToken,
}

impl DashboardService {
    /// Bind a loopback dashboard according to the user-facing port contract.
    pub async fn bind(
        store: InspectionStore,
        assets: Arc<dyn EmbeddedAssetSource>,
        port: DashboardPort,
    ) -> Result<Self, DashboardBindError> {
        let bind_mode = match port {
            DashboardPort::Automatic => BindMode::Automatic,
            DashboardPort::Explicit(port) => BindMode::Explicit(port),
        };
        Self::bind_mode(store, assets, bind_mode, None, None).await
    }

    /// Bind with the direct-local replay dependency configured by the runtime.
    #[allow(dead_code)] // Lead-owned lifecycle wiring consumes this additive seam.
    pub(crate) async fn bind_with_replay(
        store: InspectionStore,
        assets: Arc<dyn EmbeddedAssetSource>,
        port: DashboardPort,
        replay: ReplayService,
    ) -> Result<Self, DashboardBindError> {
        let bind_mode = match port {
            DashboardPort::Automatic => BindMode::Automatic,
            DashboardPort::Explicit(port) => BindMode::Explicit(port),
        };
        Self::bind_mode(store, assets, bind_mode, Some(replay), None).await
    }

    /// Bind with all direct-local production actions configured by the runtime.
    pub async fn bind_with_actions(
        store: InspectionStore,
        assets: Arc<dyn EmbeddedAssetSource>,
        port: DashboardPort,
        replay: ReplayService,
        curl: CurlService,
    ) -> Result<Self, DashboardBindError> {
        let bind_mode = match port {
            DashboardPort::Automatic => BindMode::Automatic,
            DashboardPort::Explicit(port) => BindMode::Explicit(port),
        };
        Self::bind_mode(store, assets, bind_mode, Some(replay), Some(curl)).await
    }

    #[cfg(test)]
    async fn bind_ephemeral(
        store: InspectionStore,
        assets: Arc<dyn EmbeddedAssetSource>,
    ) -> Result<Self, DashboardBindError> {
        Self::bind_mode(store, assets, BindMode::Ephemeral, None, None).await
    }

    #[cfg(test)]
    async fn bind_ephemeral_with_replay(
        store: InspectionStore,
        assets: Arc<dyn EmbeddedAssetSource>,
        replay: ReplayService,
    ) -> Result<Self, DashboardBindError> {
        Self::bind_mode(store, assets, BindMode::Ephemeral, Some(replay), None).await
    }

    #[cfg(test)]
    async fn bind_ephemeral_with_curl(
        store: InspectionStore,
        assets: Arc<dyn EmbeddedAssetSource>,
        curl: CurlService,
    ) -> Result<Self, DashboardBindError> {
        Self::bind_mode(store, assets, BindMode::Ephemeral, None, Some(curl)).await
    }

    async fn bind_mode(
        store: InspectionStore,
        assets: Arc<dyn EmbeddedAssetSource>,
        bind_mode: BindMode,
        replay: Option<ReplayService>,
        curl: Option<CurlService>,
    ) -> Result<Self, DashboardBindError> {
        let listener = bind_listener(bind_mode).await?;
        let address = listener
            .local_addr()
            .map_err(DashboardBindError::ReadLocalAddress)?;
        debug_assert_eq!(address.ip(), Ipv4Addr::LOCALHOST);
        let url = dashboard_url(address);
        let inspector_token = InspectorToken::generate();
        let shutdown = CancellationToken::new();
        let state = Arc::new(DashboardState {
            store,
            assets,
            expected_host: Arc::from(dashboard_host(address)),
            expected_origin: Arc::from(url.clone()),
            inspector_token: inspector_token.clone(),
            replay,
            curl,
            shutdown: shutdown.clone(),
        });
        let router = dashboard_router(state);

        Ok(Self {
            listener,
            router,
            address,
            url,
            inspector_token,
            shutdown,
        })
    }

    /// The exact IPv4 loopback socket selected during binding.
    #[must_use]
    pub const fn address(&self) -> SocketAddr {
        self.address
    }

    /// The same-origin dashboard URL, without a trailing slash.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    /// The token accepted in [`INSPECTOR_TOKEN_HEADER`].
    #[must_use]
    pub const fn inspector_token(&self) -> &InspectorToken {
        &self.inspector_token
    }

    /// Run the already-bound server until it fails or its supervising task is stopped.
    ///
    /// This future has no tunnel shutdown token and never owns or cancels tunnel lifecycle.
    pub async fn run(self) -> io::Result<()> {
        axum::serve(self.listener, self.router).await
    }

    /// Run the server until its independent lifecycle supervisor requests shutdown.
    pub async fn run_until_cancelled(self, shutdown: CancellationToken) -> io::Result<()> {
        let close_event_streams = self.shutdown;
        axum::serve(self.listener, self.router)
            .with_graceful_shutdown(async move {
                shutdown.cancelled_owned().await;
                close_event_streams.cancel();
            })
            .await
    }
}

impl fmt::Debug for DashboardService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DashboardService")
            .field("address", &self.address)
            .field("url", &self.url)
            .field("inspector_token", &self.inspector_token)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Error)]
pub enum DashboardBindError {
    #[error(
        "dashboard address {address} is already in use; choose another port with --dashboard-port <PORT>"
    )]
    ExplicitAddressInUse {
        address: SocketAddr,
        #[source]
        source: io::Error,
    },
    #[error("could not bind dashboard address {address}: {source}")]
    BindAddress {
        address: SocketAddr,
        #[source]
        source: io::Error,
    },
    #[error("no free loopback dashboard port was found at or above {DEFAULT_DASHBOARD_PORT}")]
    AutomaticPortsExhausted,
    #[error("could not read the bound dashboard address: {0}")]
    ReadLocalAddress(#[source] io::Error),
}

async fn bind_listener(bind_mode: BindMode) -> Result<TcpListener, DashboardBindError> {
    match bind_mode {
        BindMode::Automatic => {
            for port in DEFAULT_DASHBOARD_PORT..=u16::MAX {
                let address = loopback_address(port);
                match TcpListener::bind(address).await {
                    Ok(listener) => return Ok(listener),
                    Err(error) if error.kind() == io::ErrorKind::AddrInUse => {}
                    Err(source) => {
                        return Err(DashboardBindError::BindAddress { address, source });
                    }
                }
            }
            Err(DashboardBindError::AutomaticPortsExhausted)
        }
        BindMode::Explicit(port) => {
            let address = loopback_address(port.get());
            match TcpListener::bind(address).await {
                Ok(listener) => Ok(listener),
                Err(source) if source.kind() == io::ErrorKind::AddrInUse => {
                    Err(DashboardBindError::ExplicitAddressInUse { address, source })
                }
                Err(source) => Err(DashboardBindError::BindAddress { address, source }),
            }
        }
        #[cfg(test)]
        BindMode::Ephemeral => {
            let address = loopback_address(0);
            TcpListener::bind(address)
                .await
                .map_err(|source| DashboardBindError::BindAddress { address, source })
        }
    }
}

const fn loopback_address(port: u16) -> SocketAddr {
    SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST), port)
}

fn dashboard_host(address: SocketAddr) -> String {
    if address.port() == 80 {
        address.ip().to_string()
    } else {
        address.to_string()
    }
}

fn dashboard_url(address: SocketAddr) -> String {
    format!("http://{}", dashboard_host(address))
}

struct DashboardState {
    store: InspectionStore,
    assets: Arc<dyn EmbeddedAssetSource>,
    expected_host: Arc<str>,
    expected_origin: Arc<str>,
    inspector_token: InspectorToken,
    replay: Option<ReplayService>,
    curl: Option<CurlService>,
    shutdown: CancellationToken,
}

fn dashboard_router(state: Arc<DashboardState>) -> Router {
    Router::new()
        .route("/api/v1/session", get(session))
        .route(
            "/api/v1/transactions",
            get(list_transactions).delete(clear_transactions),
        )
        .route(
            "/api/v1/transactions/{id}",
            get(transaction_detail).delete(delete_transaction),
        )
        .route(
            "/api/v1/transactions/{id}/headers/{side}/{index}/reveal",
            post(reveal_header),
        )
        .route("/api/v1/transactions/{id}/replay", post(replay_transaction))
        .route("/api/v1/transactions/{id}/curl", post(curl_transaction))
        .route("/api/v1/events", get(live_events))
        .route("/api/v1/capture/pause", post(pause_capture))
        .route("/api/v1/capture/resume", post(resume_capture))
        .method_not_allowed_fallback(method_not_allowed)
        .fallback(asset_or_api_not_found)
        .layer(middleware::from_fn_with_state(state.clone(), request_guard))
        .with_state(state)
}

async fn request_guard(
    State(state): State<Arc<DashboardState>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let path = request.uri().path().to_owned();
    let method = request.method().clone();
    let rejection = validate_request(&state, &request);
    let mut response = match rejection {
        Some(rejection) => rejection.into_response(),
        None => next.run(request).await,
    };
    apply_security_headers(&mut response, path == "/api" || path.starts_with("/api/"));
    if method == Method::HEAD {
        response.headers_mut().remove("content-length");
    }
    response
}

fn validate_request(state: &DashboardState, request: &Request<Body>) -> Option<RequestRejection> {
    if request.method() == Method::OPTIONS {
        return Some(RequestRejection::new(
            StatusCode::FORBIDDEN,
            "cross_origin_preflight_rejected",
            "cross-origin preflight requests are not accepted",
        ));
    }

    let host_values = request.headers().get_all(HOST);
    let mut hosts = host_values.iter();
    let host = hosts.next();
    if host.is_none() || hosts.next().is_some() {
        return Some(RequestRejection::new(
            StatusCode::BAD_REQUEST,
            "invalid_host",
            "exactly one loopback Host header is required",
        ));
    }
    if host.is_none_or(|value| value.as_bytes() != state.expected_host.as_bytes()) {
        return Some(RequestRejection::new(
            StatusCode::MISDIRECTED_REQUEST,
            "invalid_host",
            "the Host header does not match this dashboard address",
        ));
    }

    let origin_values = request.headers().get_all(ORIGIN);
    let mut origins = origin_values.iter();
    if let Some(origin) = origins.next()
        && (origins.next().is_some() || origin.as_bytes() != state.expected_origin.as_bytes())
    {
        return Some(RequestRejection::new(
            StatusCode::FORBIDDEN,
            "invalid_origin",
            "the Origin header does not match this dashboard origin",
        ));
    }

    if is_modifying_method(request.method()) {
        let token_values = request.headers().get_all(INSPECTOR_TOKEN_HEADER);
        let mut tokens = token_values.iter();
        let token = tokens.next();
        if token.is_none()
            || tokens.next().is_some()
            || token
                .is_none_or(|value| value.as_bytes() != state.inspector_token.expose().as_bytes())
        {
            return Some(RequestRejection::new(
                StatusCode::FORBIDDEN,
                "invalid_inspector_token",
                "a valid inspector token header is required",
            ));
        }
    }

    None
}

fn is_modifying_method(method: &Method) -> bool {
    *method == Method::POST
        || *method == Method::PUT
        || *method == Method::PATCH
        || *method == Method::DELETE
}

fn apply_security_headers(response: &mut Response, api_path: bool) {
    let headers = response.headers_mut();
    headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    headers.insert(
        CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CONTENT_SECURITY_POLICY_VALUE),
    );
    headers.insert(REFERRER_POLICY, HeaderValue::from_static("same-origin"));
    headers.insert(X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        "permissions-policy",
        HeaderValue::from_static("camera=(), microphone=(), geolocation=()"),
    );
    headers.insert(
        "cross-origin-opener-policy",
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        "cross-origin-resource-policy",
        HeaderValue::from_static("same-origin"),
    );

    let is_html = headers
        .get(CONTENT_TYPE)
        .is_some_and(|value| value.as_bytes().starts_with(b"text/html"));
    if api_path || is_html {
        headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
        headers.insert(PRAGMA, HeaderValue::from_static("no-cache"));
    }
}

struct RequestRejection {
    status: StatusCode,
    code: &'static str,
    message: &'static str,
}

impl RequestRejection {
    const fn new(status: StatusCode, code: &'static str, message: &'static str) -> Self {
        Self {
            status,
            code,
            message,
        }
    }

    fn into_response(self) -> Response {
        error_response(self.status, self.code, self.message)
    }
}

#[derive(Serialize)]
struct ErrorEnvelope {
    error: ApiError,
}

#[derive(Serialize)]
struct ApiError {
    code: &'static str,
    message: &'static str,
}

fn error_response(status: StatusCode, code: &'static str, message: &'static str) -> Response {
    (
        status,
        Json(ErrorEnvelope {
            error: ApiError { code, message },
        }),
    )
        .into_response()
}

async fn session(State(state): State<Arc<DashboardState>>) -> Json<SessionDto> {
    Json(SessionDto {
        api_version: "v1",
        inspector_token: state.inspector_token.expose().to_owned(),
        capture: CaptureStateDto {
            paused: state.store.is_paused(),
        },
        events_url: "/api/v1/events",
    })
}

async fn list_transactions(State(state): State<Arc<DashboardState>>) -> Json<TransactionListDto> {
    let transactions = state
        .store
        .list_ids_newest_first()
        .into_iter()
        .filter_map(|id| {
            state
                .store
                .inspect(id, TransactionSummaryDto::from_transaction)
        })
        .collect();
    Json(TransactionListDto {
        transactions,
        capture: CaptureStateDto {
            paused: state.store.is_paused(),
        },
    })
}

async fn transaction_detail(
    State(state): State<Arc<DashboardState>>,
    Path(id): Path<String>,
) -> Response {
    let Some(id) = parse_transaction_id(&id) else {
        return invalid_transaction_id();
    };
    match state.store.get(id) {
        Some(transaction) => {
            Json(TransactionDetailDto::from_transaction(&transaction)).into_response()
        }
        None => transaction_not_found(),
    }
}

async fn replay_transaction(
    State(state): State<Arc<DashboardState>>,
    Path(id): Path<String>,
) -> Response {
    let Some(source_id) = parse_transaction_id(&id) else {
        return invalid_transaction_id();
    };
    let Some(replay) = state.replay.as_ref() else {
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "replay_unavailable",
            "replay is not configured for this dashboard",
        );
    };
    match replay.replay(source_id) {
        Ok(transaction_id) => (
            StatusCode::ACCEPTED,
            Json(ReplayTransactionDto { transaction_id }),
        )
            .into_response(),
        Err(ReplayError::SourceNotFound) => transaction_not_found(),
        Err(ReplayError::CapturePaused) => error_response(
            StatusCode::CONFLICT,
            ReplayError::CapturePaused.code(),
            "capture must be resumed before replay",
        ),
        Err(ReplayError::Ineligible(reason)) => error_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            reason.code(),
            "the retained request is not eligible for replay",
        ),
    }
}

async fn curl_transaction(
    State(state): State<Arc<DashboardState>>,
    Path(id): Path<String>,
    request: Request<Body>,
) -> Response {
    let Some(source_id) = parse_transaction_id(&id) else {
        return invalid_transaction_id();
    };
    if state.store.get(source_id).is_none() {
        return transaction_not_found();
    }
    let Some(curl) = state.curl.as_ref() else {
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "curl_unavailable",
            "cURL generation is not configured for this dashboard",
        );
    };
    let Ok(body) = axum::body::to_bytes(request.into_body(), CURL_REQUEST_BODY_LIMIT).await else {
        return error_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            "request_too_large",
            "the API request body exceeds its limit",
        );
    };
    let Ok(request) = serde_json::from_slice::<CurlTransactionRequest>(&body) else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "cURL generation requires a JSON includeSensitiveHeaders boolean",
        );
    };
    let consent = if request.include_sensitive_headers {
        SensitiveHeaderConsent::Granted
    } else {
        SensitiveHeaderConsent::NotGranted
    };
    match curl.generate(source_id, consent) {
        Ok(CurlGenerationOutcome::ConfirmationRequired(confirmation)) => (
            StatusCode::CONFLICT,
            Json(CurlConfirmationRequiredDto {
                status: "confirmation_required",
                header_names: confirmation.header_names().to_vec(),
            }),
        )
            .into_response(),
        Ok(CurlGenerationOutcome::Generated(command)) => Json(CurlGeneratedDto {
            status: "generated",
            command: command.command().to_owned(),
            contains_secrets: command.contains_secrets(),
        })
        .into_response(),
        Err(CurlServiceError::SourceNotFound) => transaction_not_found(),
        Err(CurlServiceError::Generation(error)) => curl_generation_error_response(error),
    }
}

fn curl_generation_error_response(error: CurlGenerationError) -> Response {
    match error {
        CurlGenerationError::Ineligible(reason) => error_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            reason.code(),
            "the retained request is not eligible for replay",
        ),
        CurlGenerationError::InvalidLocalUri => error_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            error.code(),
            "the retained request URI cannot be resolved against the current local target",
        ),
    }
}

async fn pause_capture(State(state): State<Arc<DashboardState>>) -> Json<CaptureStateDto> {
    state.store.pause();
    Json(CaptureStateDto { paused: true })
}

async fn resume_capture(State(state): State<Arc<DashboardState>>) -> Json<CaptureStateDto> {
    state.store.resume();
    Json(CaptureStateDto { paused: false })
}

async fn delete_transaction(
    State(state): State<Arc<DashboardState>>,
    Path(id): Path<String>,
) -> Response {
    let Some(id) = parse_transaction_id(&id) else {
        return invalid_transaction_id();
    };
    if state.store.delete(id) {
        Json(DeleteTransactionDto { id, deleted: true }).into_response()
    } else {
        transaction_not_found()
    }
}

async fn clear_transactions(
    State(state): State<Arc<DashboardState>>,
    request: Request<Body>,
) -> Response {
    let Ok(body) = axum::body::to_bytes(request.into_body(), 1024).await else {
        return error_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            "request_too_large",
            "the API request body exceeds its limit",
        );
    };
    let Ok(request) = serde_json::from_slice::<ClearTransactionsRequest>(&body) else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "clear all requires a JSON confirmation payload",
        );
    };
    if !request.confirm {
        return error_response(
            StatusCode::BAD_REQUEST,
            "confirmation_required",
            "clear all requires an explicit confirmation",
        );
    }
    Json(ClearTransactionsDto {
        removed: state.store.clear(),
    })
    .into_response()
}

async fn reveal_header(
    State(state): State<Arc<DashboardState>>,
    Path((id, side, index)): Path<(String, String, String)>,
) -> Response {
    let Some(id) = parse_transaction_id(&id) else {
        return invalid_transaction_id();
    };
    let Some(side) = HeaderSide::parse(&side) else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_header_side",
            "header side must be request or response",
        );
    };
    let Ok(index) = index.parse::<usize>() else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_header_index",
            "header index must be a non-negative integer",
        );
    };
    let lookup = state.store.inspect(id, |transaction| {
        let Some(header) = header_at(transaction, side, index) else {
            return HeaderRevealLookup::NotFound;
        };
        if !header.sensitivity().should_mask() {
            return HeaderRevealLookup::NotSensitive;
        }
        match header.value().to_str() {
            Ok(value) => HeaderRevealLookup::Value(value.to_owned()),
            Err(_) => HeaderRevealLookup::NotText,
        }
    });
    match lookup {
        None => transaction_not_found(),
        Some(HeaderRevealLookup::NotFound) => error_response(
            StatusCode::NOT_FOUND,
            "header_not_found",
            "the identified header is no longer retained",
        ),
        Some(HeaderRevealLookup::NotSensitive) => error_response(
            StatusCode::BAD_REQUEST,
            "header_not_sensitive",
            "public header values are already present in transaction detail",
        ),
        Some(HeaderRevealLookup::NotText) => error_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            "header_value_not_text",
            "the header value cannot be represented as text",
        ),
        Some(HeaderRevealLookup::Value(value)) => Json(RevealedHeaderDto { value }).into_response(),
    }
}

fn parse_transaction_id(value: &str) -> Option<TransactionId> {
    value.parse().ok()
}

fn invalid_transaction_id() -> Response {
    error_response(
        StatusCode::BAD_REQUEST,
        "invalid_transaction_id",
        "transaction id must be a UUID",
    )
}

fn transaction_not_found() -> Response {
    error_response(
        StatusCode::NOT_FOUND,
        "transaction_not_found",
        "the transaction is no longer retained",
    )
}

async fn asset_or_api_not_found(
    State(state): State<Arc<DashboardState>>,
    request: Request<Body>,
) -> Response {
    if request.uri().path() == "/api" || request.uri().path().starts_with("/api/") {
        return error_response(
            StatusCode::NOT_FOUND,
            "api_route_not_found",
            "the requested API route does not exist",
        );
    }
    if request.method() != Method::GET && request.method() != Method::HEAD {
        return error_response(
            StatusCode::METHOD_NOT_ALLOWED,
            "method_not_allowed",
            "this dashboard route does not accept the request method",
        );
    }

    let requested_path = if request.uri().path() == "/" {
        INDEX_PATH
    } else {
        request.uri().path()
    };
    let asset = state.assets.get(requested_path).or_else(|| {
        is_spa_route(requested_path)
            .then(|| state.assets.get(INDEX_PATH))
            .flatten()
    });
    let Some(asset) = asset else {
        return error_response(
            StatusCode::NOT_FOUND,
            "dashboard_asset_not_found",
            "the embedded dashboard index is unavailable",
        );
    };

    let body = if request.method() == Method::HEAD {
        Bytes::new()
    } else {
        asset.body.clone()
    };
    let mut response = (StatusCode::OK, body).into_response();
    response
        .headers_mut()
        .insert(CONTENT_TYPE, asset.content_type.clone());
    response
}

fn is_spa_route(path: &str) -> bool {
    !path.starts_with("/assets/")
        && (path == "/"
            || path
                .rsplit_once('/')
                .is_none_or(|(_, final_segment)| !final_segment.contains('.')))
}

async fn method_not_allowed() -> Response {
    error_response(
        StatusCode::METHOD_NOT_ALLOWED,
        "method_not_allowed",
        "the API route does not accept the request method",
    )
}

async fn live_events(
    State(state): State<Arc<DashboardState>>,
) -> Sse<impl futures::Stream<Item = Result<Event, Infallible>>> {
    let receiver = state.store.subscribe();
    let initial = stream::once(async {
        LiveEventDto::ResyncRequired {
            skipped: 0,
            reason: ResyncReasonDto::ConnectionOpened,
        }
    });
    let live = stream::unfold(receiver, |mut receiver| async move {
        let event = receive_live_event(&mut receiver).await?;
        Some((event, receiver))
    });
    let events = initial
        .chain(live)
        .map(|live_event| {
            let event_name = live_event.event_name();
            let sequence = live_event.sequence();
            let data = serde_json::to_string(&live_event).unwrap_or_else(|_| {
                "{\"kind\":\"resync_required\",\"skipped\":0,\"reason\":\"connection_opened\"}"
                    .to_owned()
            });
            let mut event = Event::default().event(event_name).data(data);
            if let Some(sequence) = sequence {
                event = event.id(sequence.to_string());
            }
            Ok(event)
        })
        .take_until(state.shutdown.clone().cancelled_owned());
    Sse::new(events).keep_alive(
        axum::response::sse::KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keep-alive"),
    )
}

async fn receive_live_event(
    receiver: &mut broadcast::Receiver<InspectionEvent>,
) -> Option<LiveEventDto> {
    match receiver.recv().await {
        Ok(event) => Some(LiveEventDto::from_inspection_event(event)),
        Err(broadcast::error::RecvError::Lagged(skipped)) => Some(LiveEventDto::ResyncRequired {
            skipped,
            reason: ResyncReasonDto::Lagged,
        }),
        Err(broadcast::error::RecvError::Closed) => None,
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SessionDto {
    api_version: &'static str,
    inspector_token: String,
    capture: CaptureStateDto,
    events_url: &'static str,
}

#[derive(Clone, Copy, Serialize)]
struct CaptureStateDto {
    paused: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TransactionListDto {
    transactions: Vec<TransactionSummaryDto>,
    capture: CaptureStateDto,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TransactionSummaryDto {
    id: TransactionId,
    received_at_unix_ms: u64,
    method: String,
    url: String,
    path: String,
    origin: TransactionOriginDto,
    #[serde(skip_serializing_if = "Option::is_none")]
    replay_source_id: Option<TransactionId>,
    state: TransactionStateDto,
    status: Option<u16>,
    error: Option<String>,
    duration_ms: Option<u64>,
    request_bytes: u64,
    response_bytes: Option<u64>,
    replay: ReplayEligibilityDto,
}

impl TransactionSummaryDto {
    fn from_transaction(transaction: &Transaction) -> Self {
        let request = transaction.request();
        let response = transaction.response();
        let (origin, replay_source_id) = transaction_origin(transaction.origin());
        Self {
            id: transaction.id(),
            received_at_unix_ms: unix_millis(transaction.received_at()),
            method: request.method().as_str().to_owned(),
            url: request.public_uri().to_string(),
            path: request
                .public_uri()
                .path_and_query()
                .map_or_else(|| "/".to_owned(), ToString::to_string),
            origin,
            replay_source_id,
            state: transaction_state(transaction.lifecycle()),
            status: response.map(|response| response.status().as_u16()),
            error: sanitized_failure_message(transaction),
            duration_ms: transaction.duration().map(duration_millis),
            request_bytes: request.body().total_bytes(),
            response_bytes: response.map(|response| response.body().total_bytes()),
            replay: ReplayEligibilityDto::from(transaction.replay_eligibility()),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TransactionDetailDto {
    #[serde(flatten)]
    summary: TransactionSummaryDto,
    lifecycle: TransactionLifecycleDto,
    response_started_after_ms: Option<u64>,
    request: RequestDetailDto,
    response: Option<ResponseDetailDto>,
}

impl TransactionDetailDto {
    fn from_transaction(transaction: &Transaction) -> Self {
        Self {
            summary: TransactionSummaryDto::from_transaction(transaction),
            lifecycle: TransactionLifecycleDto::from(transaction.lifecycle()),
            response_started_after_ms: transaction.response_started_after().map(duration_millis),
            request: RequestDetailDto::from_snapshot(transaction.request()),
            response: transaction.response().map(ResponseDetailDto::from_snapshot),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum TransactionOriginDto {
    Original,
    Replay,
}

fn transaction_origin(origin: TransactionOrigin) -> (TransactionOriginDto, Option<TransactionId>) {
    match origin {
        TransactionOrigin::Original => (TransactionOriginDto::Original, None),
        TransactionOrigin::Replay { source } => (TransactionOriginDto::Replay, source),
    }
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum TransactionStateDto {
    Pending,
    Complete,
    Failed,
}

fn transaction_state(lifecycle: &TransactionLifecycle) -> TransactionStateDto {
    match lifecycle {
        TransactionLifecycle::Received | TransactionLifecycle::ResponseStarted => {
            TransactionStateDto::Pending
        }
        TransactionLifecycle::Completed | TransactionLifecycle::Upgraded => {
            TransactionStateDto::Complete
        }
        TransactionLifecycle::FailedOrCancelled(_) => TransactionStateDto::Failed,
    }
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case", tag = "state")]
enum TransactionLifecycleDto {
    Received,
    ResponseStarted,
    Completed,
    FailedOrCancelled { kind: FailureKind },
    Upgraded,
}

impl From<&TransactionLifecycle> for TransactionLifecycleDto {
    fn from(lifecycle: &TransactionLifecycle) -> Self {
        match lifecycle {
            TransactionLifecycle::Received => Self::Received,
            TransactionLifecycle::ResponseStarted => Self::ResponseStarted,
            TransactionLifecycle::Completed => Self::Completed,
            TransactionLifecycle::FailedOrCancelled(failure) => Self::FailedOrCancelled {
                kind: failure.kind(),
            },
            TransactionLifecycle::Upgraded => Self::Upgraded,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReplayEligibilityDto {
    eligible: bool,
    reason_code: Option<&'static str>,
    reason: Option<String>,
}

impl From<ReplayEligibility> for ReplayEligibilityDto {
    fn from(eligibility: ReplayEligibility) -> Self {
        let reason = eligibility.reason();
        Self {
            eligible: eligibility.is_eligible(),
            reason_code: reason.map(|reason| reason.code()),
            reason: reason.map(|reason| reason.to_string()),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RequestDetailDto {
    method: String,
    url: String,
    version: &'static str,
    headers: Vec<HeaderDto>,
    body: BodyDto,
}

impl RequestDetailDto {
    fn from_snapshot(request: &RequestSnapshot) -> Self {
        Self {
            method: request.method().as_str().to_owned(),
            url: request.public_uri().to_string(),
            version: http_version(request.version()),
            headers: headers_dto(HeaderSide::Request, request.headers()),
            body: BodyDto::from_preview(request.body(), request.headers()),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ResponseDetailDto {
    status: u16,
    version: &'static str,
    headers: Vec<HeaderDto>,
    body: BodyDto,
}

impl ResponseDetailDto {
    fn from_snapshot(response: &ResponseSnapshot) -> Self {
        Self {
            status: response.status().as_u16(),
            version: http_version(response.version()),
            headers: headers_dto(HeaderSide::Response, response.headers()),
            body: BodyDto::from_preview(response.body(), response.headers()),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HeaderDto {
    id: String,
    name: String,
    sensitive: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    value_state: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sensitivity: Option<SensitiveHeaderKind>,
}

fn headers_dto(side: HeaderSide, headers: &HeaderSnapshots) -> Vec<HeaderDto> {
    headers
        .iter()
        .enumerate()
        .map(|(index, header)| {
            let sensitivity = header.sensitivity();
            let sensitive_kind = match sensitivity {
                HeaderSensitivity::Public => None,
                HeaderSensitivity::Sensitive(kind) => Some(kind),
            };
            HeaderDto {
                id: format!("{}:{index}", side.as_str()),
                name: header.name().as_str().to_owned(),
                sensitive: sensitivity.should_mask(),
                value: (!sensitivity.should_mask())
                    .then(|| String::from_utf8_lossy(header.value().as_bytes()).into_owned()),
                value_state: sensitivity.should_mask().then_some("masked"),
                sensitivity: sensitive_kind,
            }
        })
        .collect()
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BodyDto {
    kind: PayloadKindDto,
    content_type: Option<String>,
    text: Option<String>,
    transferred_bytes: u64,
    retained_bytes: u64,
    truncated: bool,
    completion: BodyCompletion,
    retention: BodyRetention,
    constraints: BodyConstraintsDto,
}

impl BodyDto {
    fn from_preview(preview: &BodyPreview, headers: &HeaderSnapshots) -> Self {
        let presentation = BodyPresentation::new(preview, headers);
        let kind = payload_kind(preview, &presentation);
        let text = if matches!(kind, PayloadKindDto::Binary | PayloadKindDto::Empty) {
            None
        } else {
            presentation
                .bytes
                .as_deref()
                .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
        };
        Self {
            kind,
            content_type: content_type(headers),
            text,
            transferred_bytes: preview.total_bytes(),
            retained_bytes: presentation
                .bytes
                .as_deref()
                .map_or(0, |bytes| u64::try_from(bytes.len()).unwrap_or(u64::MAX)),
            truncated: presentation.truncated,
            completion: preview.completion(),
            retention: presentation.retention,
            constraints: BodyConstraintsDto::from(preview.constraints()),
        }
    }
}

struct BodyPresentation<'a> {
    bytes: Option<Cow<'a, [u8]>>,
    retention: BodyRetention,
    truncated: bool,
}

impl<'a> BodyPresentation<'a> {
    fn new(preview: &'a BodyPreview, headers: &HeaderSnapshots) -> Self {
        let codings = match content_codings(headers) {
            Ok(codings) => codings,
            Err(()) => return Self::encoded_unavailable(),
        };
        if codings.is_empty() {
            return Self {
                bytes: (preview.content_kind() != BodyContentKind::Binary)
                    .then(|| Cow::Borrowed(preview.retained_bytes())),
                retention: preview.retention(),
                truncated: preview.is_truncated(),
            };
        }
        if preview.content_kind() == BodyContentKind::Binary
            || preview.completion() != BodyCompletion::Complete
            || !preview.is_fully_retained()
        {
            return Self::encoded_unavailable();
        }

        match decode_content(preview.retained_bytes(), &codings, preview.limit()) {
            Ok(decoded) => Self {
                bytes: Some(Cow::Owned(decoded.bytes)),
                retention: if decoded.truncated {
                    BodyRetention::Truncated
                } else {
                    BodyRetention::Retained
                },
                truncated: decoded.truncated,
            },
            Err(()) => Self::encoded_unavailable(),
        }
    }

    fn encoded_unavailable() -> Self {
        Self {
            bytes: None,
            retention: BodyRetention::OmittedBinary,
            truncated: false,
        }
    }
}

#[derive(Clone, Copy)]
enum ContentCoding {
    Gzip,
    Deflate,
    Brotli,
}

fn content_codings(headers: &HeaderSnapshots) -> Result<Vec<ContentCoding>, ()> {
    let mut codings = Vec::new();
    for header in headers
        .iter()
        .filter(|header| header.name() == CONTENT_ENCODING)
    {
        let value = header.value().to_str().map_err(|_| ())?;
        for token in value
            .split(',')
            .map(str::trim)
            .filter(|token| !token.is_empty())
        {
            if token.eq_ignore_ascii_case("identity") {
                continue;
            }
            let coding =
                if token.eq_ignore_ascii_case("gzip") || token.eq_ignore_ascii_case("x-gzip") {
                    ContentCoding::Gzip
                } else if token.eq_ignore_ascii_case("deflate") {
                    ContentCoding::Deflate
                } else if token.eq_ignore_ascii_case("br") {
                    ContentCoding::Brotli
                } else {
                    return Err(());
                };
            codings.push(coding);
        }
    }
    Ok(codings)
}

struct DecodedBody {
    bytes: Vec<u8>,
    truncated: bool,
}

fn decode_content(
    encoded: &[u8],
    codings: &[ContentCoding],
    limit: usize,
) -> Result<DecodedBody, ()> {
    let mut bytes = encoded.to_vec();
    for (index, coding) in codings.iter().rev().enumerate() {
        let decoded = decode_layer(*coding, &bytes, limit).map_err(|_| ())?;
        let is_final_layer = index + 1 == codings.len();
        if decoded.truncated && !is_final_layer {
            return Err(());
        }
        bytes = decoded.bytes;
        if is_final_layer {
            return Ok(DecodedBody {
                bytes,
                truncated: decoded.truncated,
            });
        }
    }
    Err(())
}

fn decode_layer(coding: ContentCoding, encoded: &[u8], limit: usize) -> io::Result<DecodedBody> {
    match coding {
        ContentCoding::Gzip => read_bounded(GzDecoder::new(encoded), limit),
        ContentCoding::Deflate => read_bounded(ZlibDecoder::new(encoded), limit)
            .or_else(|_| read_bounded(DeflateDecoder::new(encoded), limit)),
        ContentCoding::Brotli => read_bounded(brotli::Decompressor::new(encoded, 4_096), limit),
    }
}

fn read_bounded(reader: impl io::Read, limit: usize) -> io::Result<DecodedBody> {
    let mut bytes = Vec::new();
    let maximum = u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1);
    reader.take(maximum).read_to_end(&mut bytes)?;
    let truncated = bytes.len() > limit;
    bytes.truncate(limit);
    Ok(DecodedBody { bytes, truncated })
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum PayloadKindDto {
    Json,
    Text,
    Binary,
    Stream,
    Empty,
}

fn payload_kind(preview: &BodyPreview, presentation: &BodyPresentation<'_>) -> PayloadKindDto {
    if presentation.bytes.is_none() || preview.content_kind() == BodyContentKind::Binary {
        PayloadKindDto::Binary
    } else if presentation.bytes.as_deref().is_some_and(<[u8]>::is_empty) {
        PayloadKindDto::Empty
    } else if preview.constraints().is_server_sent_events() {
        PayloadKindDto::Stream
    } else if preview.content_kind() == BodyContentKind::Json {
        PayloadKindDto::Json
    } else if preview.constraints().is_streaming() {
        PayloadKindDto::Stream
    } else {
        PayloadKindDto::Text
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BodyConstraintsDto {
    streaming: bool,
    server_sent_events: bool,
    websocket_upgrade: bool,
}

impl From<BodyConstraints> for BodyConstraintsDto {
    fn from(constraints: BodyConstraints) -> Self {
        Self {
            streaming: constraints.is_streaming(),
            server_sent_events: constraints.is_server_sent_events(),
            websocket_upgrade: constraints.is_websocket_upgrade(),
        }
    }
}

fn content_type(headers: &HeaderSnapshots) -> Option<String> {
    headers
        .iter()
        .find(|header| header.name() == CONTENT_TYPE)
        .and_then(|header| header.value().to_str().ok())
        .map(ToOwned::to_owned)
}

fn header_at(transaction: &Transaction, side: HeaderSide, index: usize) -> Option<&HeaderSnapshot> {
    match side {
        HeaderSide::Request => transaction.request().headers().as_slice().get(index),
        HeaderSide::Response => transaction
            .response()
            .and_then(|response| response.headers().as_slice().get(index)),
    }
}

#[derive(Clone, Copy)]
enum HeaderSide {
    Request,
    Response,
}

impl HeaderSide {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "request" => Some(Self::Request),
            "response" => Some(Self::Response),
            _ => None,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::Response => "response",
        }
    }
}

#[derive(Deserialize)]
struct ClearTransactionsRequest {
    confirm: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CurlTransactionRequest {
    include_sensitive_headers: bool,
}

#[derive(Serialize)]
struct DeleteTransactionDto {
    id: TransactionId,
    deleted: bool,
}

#[derive(Serialize)]
struct ClearTransactionsDto {
    removed: usize,
}

#[derive(Serialize)]
struct RevealedHeaderDto {
    value: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReplayTransactionDto {
    transaction_id: TransactionId,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CurlConfirmationRequiredDto {
    status: &'static str,
    header_names: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CurlGeneratedDto {
    status: &'static str,
    command: String,
    contains_secrets: bool,
}

enum HeaderRevealLookup {
    Value(String),
    NotFound,
    NotSensitive,
    NotText,
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", tag = "kind")]
enum LiveEventDto {
    TransactionCreated {
        sequence: u64,
        id: TransactionId,
    },
    TransactionUpdated {
        sequence: u64,
        id: TransactionId,
    },
    TransactionRemoved {
        sequence: u64,
        id: TransactionId,
        cause: RemovalCauseDto,
    },
    Cleared {
        sequence: u64,
        removed: usize,
    },
    CaptureStateChanged {
        sequence: u64,
        paused: bool,
    },
    ResyncRequired {
        skipped: u64,
        reason: ResyncReasonDto,
    },
}

impl LiveEventDto {
    fn from_inspection_event(event: InspectionEvent) -> Self {
        let sequence = event.sequence();
        match event.kind() {
            InspectionEventKind::TransactionCreated(id) => {
                Self::TransactionCreated { sequence, id }
            }
            InspectionEventKind::TransactionUpdated(id) => {
                Self::TransactionUpdated { sequence, id }
            }
            InspectionEventKind::TransactionRemoved { id, cause } => Self::TransactionRemoved {
                sequence,
                id,
                cause: cause.into(),
            },
            InspectionEventKind::Cleared { removed } => Self::Cleared { sequence, removed },
            InspectionEventKind::CaptureStateChanged { paused } => {
                Self::CaptureStateChanged { sequence, paused }
            }
        }
    }

    const fn event_name(self) -> &'static str {
        match self {
            Self::ResyncRequired { .. } => "resync",
            _ => "inspection",
        }
    }

    const fn sequence(self) -> Option<u64> {
        match self {
            Self::TransactionCreated { sequence, .. }
            | Self::TransactionUpdated { sequence, .. }
            | Self::TransactionRemoved { sequence, .. }
            | Self::Cleared { sequence, .. }
            | Self::CaptureStateChanged { sequence, .. } => Some(sequence),
            Self::ResyncRequired { .. } => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum RemovalCauseDto {
    Deleted,
    Evicted,
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ResyncReasonDto {
    ConnectionOpened,
    Lagged,
}

impl From<RemovalCause> for RemovalCauseDto {
    fn from(cause: RemovalCause) -> Self {
        match cause {
            RemovalCause::Deleted => Self::Deleted,
            RemovalCause::Evicted => Self::Evicted,
        }
    }
}

fn sanitized_failure_message(transaction: &Transaction) -> Option<String> {
    let TransactionLifecycle::FailedOrCancelled(failure) = transaction.lifecycle() else {
        return None;
    };
    let mut message = failure.message()?.to_owned();
    for header in transaction.request().headers().iter().chain(
        transaction
            .response()
            .into_iter()
            .flat_map(|response| response.headers().iter()),
    ) {
        if header.sensitivity().should_mask()
            && let Ok(value) = header.value().to_str()
            && !value.is_empty()
        {
            message = message.replace(value, "[MASKED]");
        }
    }
    Some(message)
}

fn unix_millis(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map(duration_millis)
        .unwrap_or(0)
}

fn duration_millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn http_version(version: Version) -> &'static str {
    match version {
        Version::HTTP_09 => "HTTP/0.9",
        Version::HTTP_10 => "HTTP/1.0",
        Version::HTTP_11 => "HTTP/1.1",
        Version::HTTP_2 => "HTTP/2",
        Version::HTTP_3 => "HTTP/3",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests;
