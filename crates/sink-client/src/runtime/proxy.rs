use std::{
    convert::Infallible,
    error::Error as StdError,
    fmt, io,
    net::IpAddr,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

use bytes::Bytes;
use http::{
    HeaderValue, Method, Request, Response, StatusCode, Uri,
    header::{CONNECTION, CONTENT_TYPE, HOST, UPGRADE},
    uri::PathAndQuery,
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

use crate::target::LocalTarget;

const LOCAL_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const SERVICE_UNAVAILABLE_BODY: &str = "local service unavailable\n";

pub(crate) type BoxError = Box<dyn StdError + Send + Sync>;
pub(crate) type ProxyBody = UnsyncBoxBody<Bytes, BoxError>;

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
    connect_timeout: Duration,
}

impl fmt::Debug for LocalProxy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalProxy")
            .field("target", &self.target)
            .field("uses_tls", &self.tls.is_some())
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
        ensure_crypto_provider()?;
        let tls = target
            .uses_tls()
            .then(|| local_tls_connector(local_tls_insecure))
            .transpose()?;
        Ok(Self {
            target,
            tls,
            summaries,
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
}

#[derive(Clone)]
pub(crate) struct ExchangeProxy {
    inner: LocalProxy,
    tasks: TaskTracker,
    force_shutdown: CancellationToken,
}

impl ExchangeProxy {
    pub(crate) async fn forward<B>(&self, mut request: Request<B>) -> Response<ProxyBody>
    where
        B: Body<Data = Bytes> + Send + 'static,
        B::Error: Into<BoxError>,
    {
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
        let public_upgrade = wants_upgrade.then(|| upgrade::on(&mut request));

        if rewrite_local_request(&mut request, &self.inner.target).is_err() {
            return service_unavailable(stats);
        }

        let io = match self.connect_local().await {
            Ok(io) => io,
            Err(error) => {
                warn!(target = %self.inner.target, error = %error, "local service connection failed");
                return service_unavailable(stats);
            }
        };

        let request = request.map(|body| CountedBody::new(body, stats.request_bytes.clone()));
        let handshake = timeout(
            self.inner.connect_timeout,
            http1::handshake::<_, CountedBody<B>>(TokioIo::new(io)),
        )
        .await;
        let (mut sender, connection) = match handshake {
            Ok(Ok(parts)) => parts,
            Ok(Err(_)) | Err(_) => {
                warn!(target = %self.inner.target, "local HTTP handshake failed");
                return service_unavailable(stats);
            }
        };

        let force_shutdown = self.force_shutdown.clone();
        self.tasks.spawn(async move {
            tokio::select! {
                result = connection.with_upgrades() => {
                    if result.is_err() {
                        // The public response path reports failures; avoid logging
                        // body/header material from Hyper's diagnostic error.
                        tracing::debug!("local HTTP connection ended with an error");
                    }
                }
                () = force_shutdown.cancelled() => {}
            }
        });

        let response = match sender.send_request(request).await {
            Ok(response) => response,
            Err(_) => {
                warn!(target = %self.inner.target, "local HTTP request failed");
                return service_unavailable(stats);
            }
        };
        self.prepare_response(response, public_upgrade, stats)
    }

    async fn connect_local(&self) -> Result<BoxedLocalIo, LocalConnectError> {
        let host = self
            .inner
            .target
            .base_url()
            .host_str()
            .ok_or(LocalConnectError::InvalidTarget)?
            .to_owned();
        let port = self
            .inner
            .target
            .base_url()
            .port_or_known_default()
            .ok_or(LocalConnectError::InvalidTarget)?;
        let tls = self.inner.tls.clone();

        timeout(self.inner.connect_timeout, async move {
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

    fn prepare_response(
        &self,
        mut response: Response<Incoming>,
        public_upgrade: Option<OnUpgrade>,
        stats: Arc<RequestStats>,
    ) -> Response<ProxyBody> {
        let status = response.status();
        let upgraded = public_upgrade.is_some()
            && (status == StatusCode::SWITCHING_PROTOCOLS
                || (stats.method == Method::CONNECT && status.is_success()));

        if upgraded {
            let local_upgrade = upgrade::on(&mut response);
            let Some(public_upgrade) = public_upgrade else {
                return response.map(boxed_body);
            };
            let force_shutdown = self.force_shutdown.clone();
            let upgrade_stats = stats.clone();
            self.tasks.spawn(async move {
                let result = tokio::select! {
                    result = bridge_upgrades(public_upgrade, local_upgrade) => result,
                    () = force_shutdown.cancelled() => return,
                };
                if let Ok((request_bytes, response_bytes)) = result {
                    add_bytes(&upgrade_stats.request_bytes, request_bytes);
                    add_bytes(&upgrade_stats.response_bytes, response_bytes);
                    upgrade_stats.emit(status);
                }
            });
            return response.map(boxed_body);
        }

        response.map(|body| {
            let counted = CountedBody::new(body, stats.response_bytes.clone());
            CompletionBody::new(counted, stats, status)
                .map_err(|error| -> BoxError { Box::new(error) })
                .boxed_unsync()
        })
    }
}

pub(crate) async fn serve_stream<S>(
    stream: S,
    proxy: ExchangeProxy,
    force_shutdown: CancellationToken,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let service = service_fn(move |request| {
        let proxy = proxy.clone();
        async move { Ok::<_, Infallible>(proxy.forward(request).await) }
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
                tracing::debug!("tunnel HTTP exchange ended with an error");
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
        if matches!(polled, Poll::Ready(None)) && !this.complete {
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

fn add_bytes(counter: &AtomicU64, amount: u64) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
        Some(value.saturating_add(amount))
    });
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

    #[tokio::test]
    async fn local_connection_failure_returns_safe_quick_503_and_keeps_summary_safe()
    -> Result<(), BoxError> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        drop(listener);

        let (summary_tx, mut summary_rx) = broadcast::channel(4);
        let proxy = LocalProxy::new(
            format!("http://127.0.0.1:{port}").parse()?,
            false,
            summary_tx,
        )?
        .for_connection(TaskTracker::new(), CancellationToken::new());
        let response = proxy
            .forward(
                Request::builder()
                    .method(Method::POST)
                    .uri("/upload?kind=test")
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
        let response = timeout(Duration::from_secs(1), proxy.forward(request)).await?;
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
