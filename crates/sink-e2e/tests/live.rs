use std::{
    collections::{HashMap, HashSet},
    convert::Infallible,
    error::Error,
    future::Future,
    io,
    net::SocketAddr,
    num::NonZeroUsize,
    path::{Path as FsPath, PathBuf},
    pin::Pin,
    process::Stdio,
    str::FromStr as _,
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use axum::{
    Router,
    body::Body,
    extract::{Path, State, WebSocketUpgrade, ws::Message as AxumMessage},
    http::{
        HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode, Uri,
        header::{AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, FORWARDED, HOST, LOCATION},
    },
    routing::{any, get, post},
};
use bytes::Bytes;
use futures::{SinkExt as _, StreamExt as _, future::BoxFuture, stream};
use http_body_util::BodyExt as _;
use hyper::{body::Incoming, client::conn::http1};
use hyper_util::rt::TokioIo;
use sha2::{Digest as _, Sha256};
use sink_client::{
    cli::HttpArgs,
    config::{AuthToken, RunOverrides, SavedConfig},
    inspection::{BodyCompletion, DEFAULT_BODY_PREVIEW_LIMIT, DEFAULT_TRANSACTION_LIMIT},
    runtime::{
        ConnectionInfo, FailureDisposition, RuntimeError, RuntimeHandle, TunnelPhase, TunnelRuntime,
    },
    target::{LocalTarget, PublicUrl},
};
use sink_protocol::{
    MAX_PROXY_V2_HEADER_BYTES, NAMESPACE_COLLECTION_PATH, PROXY_V2_PREFIX_BYTES, ProxyV2Header,
    parse_proxy_v2,
};
use sink_server::{
    certificates::{
        CertificateIndexReloader, CertificateMaterial, CertificateProviderKind, CertificateRecord,
        CertificateState, CertificateStorage, CertificateTarget, Hostname, SecretBytes,
        SqliteCertificateStorage, Timestamp,
    },
    config::{ConfiguredDomain, ConfiguredDomains, HttpsProxyConfig},
    db::Database,
    namespace_control::{
        NamespaceCertificateError, NamespaceCertificateProvisioner, NamespaceCertificateRequest,
        NamespaceCertificateStatus,
    },
    runtime::{
        DynamicTlsCertificateResolver, RuntimeSniAuthorization, RuntimeState, TlsListener,
        build_tls_server_config, default_crypto_provider,
    },
};
use tempfile::TempDir;
use tokio::{
    io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, ReadBuf},
    net::{TcpListener, TcpStream},
    process::{Child, ChildStdin, ChildStdout, Command},
    sync::{Notify, oneshot, watch},
    task::JoinHandle,
    time::{sleep, timeout},
};
use tokio_tungstenite::{
    WebSocketStream, client_async,
    tungstenite::{Message, client::IntoClientRequest as _},
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

type TestError = Box<dyn Error + Send + Sync>;
type TestResult<T = ()> = Result<T, TestError>;

const TEST_BOUND: Duration = Duration::from_secs(20);
const PUBLIC_BASE_DOMAIN: &str = "e2e.test";
const STREAM_BYTES: usize = 2 * 1024 * 1024;
const ORDINARY_REQUESTS: usize = 100;
// The low-buffer shaped control link keeps both directions backpressured past
// yamux's 10-second RTT ping and the server WebSocket's 15-second heartbeat.
// Server-to-client traffic carries the upload and new-stream SYN frames. The
// larger reverse-direction download keeps both directions busy through the
// final upload checkpoint without delaying upload window updates artificially.
const PRESSURE_UPLOAD_BYTES: usize = 7 * 1024 * 1024;
const PRESSURE_DOWNLOAD_BYTES: usize = 40 * 1024 * 1024;
const PRESSURE_CHUNK_BYTES: usize = 16 * 1024;
const PRESSURE_TO_CLIENT_BYTES_PER_SECOND: usize = 384 * 1024;
const PRESSURE_TO_SERVER_BYTES_PER_SECOND: usize = 2 * 1024 * 1024;
const PRESSURE_FIXTURE_BYTES_PER_SECOND: usize = 24 * 1024 * 1024;
const PRESSURE_CHECKPOINTS: [usize; 4] = [
    768 * 1024,
    3 * 1024 * 1024,
    5 * 1024 * 1024,
    6 * 1024 * 1024,
];
const HEALTH_LATENCY_BOUND: Duration = Duration::from_secs(2);
const HEALTH_PROBES_PER_BATCH: usize = 4;
const HEALTH_BATCH_INTERVAL: Duration = Duration::from_millis(250);
const PRESSURE_SCENARIO_BOUND: Duration = Duration::from_secs(45);
const SEQUENTIAL_DOWNLOAD_BYTES: usize = 16 * 1024 * 1024;
const SEQUENTIAL_ORDINARY_REQUESTS: usize = 10;
const SEQUENTIAL_SCENARIO_BOUND: Duration = Duration::from_secs(60);

#[derive(Clone)]
struct FixtureState {
    download_chunks: Arc<Vec<Bytes>>,
    ordinary_active: Arc<AtomicUsize>,
    ordinary_max_active: Arc<AtomicUsize>,
    slow_active: Arc<AtomicUsize>,
    pressure_active: Arc<AtomicUsize>,
    pressure_bytes: Arc<AtomicUsize>,
    pressure_download_active: Arc<AtomicUsize>,
    pressure_download_bytes: Arc<AtomicUsize>,
    sse_events: Arc<AtomicUsize>,
    health_arrivals: Arc<Mutex<HashMap<usize, Instant>>>,
    side_effects: Arc<AtomicUsize>,
    side_effect_started: Arc<Notify>,
}

impl FixtureState {
    fn new(payload: &Bytes) -> Self {
        let download_chunks = payload
            .chunks(16 * 1024)
            .map(Bytes::copy_from_slice)
            .collect();
        Self {
            download_chunks: Arc::new(download_chunks),
            ordinary_active: Arc::new(AtomicUsize::new(0)),
            ordinary_max_active: Arc::new(AtomicUsize::new(0)),
            slow_active: Arc::new(AtomicUsize::new(0)),
            pressure_active: Arc::new(AtomicUsize::new(0)),
            pressure_bytes: Arc::new(AtomicUsize::new(0)),
            pressure_download_active: Arc::new(AtomicUsize::new(0)),
            pressure_download_bytes: Arc::new(AtomicUsize::new(0)),
            sse_events: Arc::new(AtomicUsize::new(0)),
            health_arrivals: Arc::new(Mutex::new(HashMap::new())),
            side_effects: Arc::new(AtomicUsize::new(0)),
            side_effect_started: Arc::new(Notify::new()),
        }
    }
}

struct ActivityGuard {
    active: Arc<AtomicUsize>,
}

impl ActivityGuard {
    fn new(active: Arc<AtomicUsize>, maximum: Option<&AtomicUsize>) -> Self {
        let current = active.fetch_add(1, Ordering::AcqRel) + 1;
        if let Some(maximum) = maximum {
            maximum.fetch_max(current, Ordering::AcqRel);
        }
        Self { active }
    }
}

impl Drop for ActivityGuard {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
    }
}

struct FixtureHarness {
    addr: SocketAddr,
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<io::Result<()>>>,
}

impl FixtureHarness {
    async fn start(state: FixtureState) -> TestResult<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        Self::from_listener(listener, state).await
    }

    async fn start_on(addr: SocketAddr, state: FixtureState) -> TestResult<Self> {
        let listener = TcpListener::bind(addr).await?;
        Self::from_listener(listener, state).await
    }

    async fn from_listener(listener: TcpListener, state: FixtureState) -> TestResult<Self> {
        let addr = listener.local_addr()?;
        let (shutdown, stopped) = oneshot::channel();
        let app = fixture_router(state);
        let task = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = stopped.await;
                })
                .await
        });
        Ok(Self {
            addr,
            shutdown: Some(shutdown),
            task: Some(task),
        })
    }

    async fn stop(mut self) -> TestResult<()> {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let task = self
            .task
            .take()
            .ok_or_else(|| io::Error::other("fixture task already consumed"))?;
        bounded("fixture shutdown", task).await???;
        Ok(())
    }
}

impl Drop for FixtureHarness {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(task) = self.task.as_ref() {
            task.abort();
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct EdgeTlsObservation {
    proxy: ProxyV2Header,
    proxy_wire: Vec<u8>,
    tls_wire: Vec<u8>,
}

struct EdgeTlsFixture {
    addr: SocketAddr,
    certificate_path: PathBuf,
    private_key_path: PathBuf,
    tls_addr: SocketAddr,
    observations: Arc<Mutex<Vec<EdgeTlsObservation>>>,
    observation_ready: Arc<Notify>,
    shutdown: CancellationToken,
    task: Option<JoinHandle<io::Result<()>>>,
    child: Option<Child>,
}

impl EdgeTlsFixture {
    async fn start(directory: &FsPath, hostname: &str) -> TestResult<Self> {
        let (_, certificate_path) = local_certificate(directory, hostname).await?;
        let private_key_path =
            directory.join(format!("{}-private-key.pem", hostname.replace('.', "-")));
        let observations = Arc::new(Mutex::new(Vec::new()));
        let observation_ready = Arc::new(Notify::new());
        let reserved_tls = TcpListener::bind("127.0.0.1:0").await?;
        let tls_addr = reserved_tls.local_addr()?;
        drop(reserved_tls);
        let mut child = spawn_openssl_edge(tls_addr, &certificate_path, &private_key_path)?;
        wait_for_openssl_edge(tls_addr, &mut child).await?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let shutdown = CancellationToken::new();
        let task = Some(Self::spawn(
            listener,
            tls_addr,
            Arc::clone(&observations),
            Arc::clone(&observation_ready),
            shutdown.clone(),
        ));
        Ok(Self {
            addr,
            certificate_path,
            private_key_path,
            tls_addr,
            observations,
            observation_ready,
            shutdown,
            task,
            child: Some(child),
        })
    }

    fn spawn(
        listener: TcpListener,
        tls_addr: SocketAddr,
        observations: Arc<Mutex<Vec<EdgeTlsObservation>>>,
        observation_ready: Arc<Notify>,
        shutdown: CancellationToken,
    ) -> JoinHandle<io::Result<()>> {
        tokio::spawn(async move {
            let connections = TaskTracker::new();
            loop {
                tokio::select! {
                    () = shutdown.cancelled() => break,
                    accepted = listener.accept() => {
                        let (stream, _) = accepted?;
                        let observations = Arc::clone(&observations);
                        let observation_ready = Arc::clone(&observation_ready);
                        connections.spawn(async move {
                            let _ = serve_edge_tls_connection(
                                stream,
                                tls_addr,
                                observations,
                                observation_ready,
                            )
                            .await;
                        });
                    }
                }
            }
            connections.close();
            connections.wait().await;
            Ok(())
        })
    }

    fn certificate_path(&self) -> &FsPath {
        &self.certificate_path
    }

    fn observation_count(&self) -> usize {
        self.observations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }

    async fn observation(&self, index: usize) -> TestResult<EdgeTlsObservation> {
        bounded("Edge TLS observation", async {
            loop {
                let notified = self.observation_ready.notified();
                if let Some(observation) = self
                    .observations
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .get(index)
                    .cloned()
                {
                    return observation;
                }
                notified.await;
            }
        })
        .await
    }

    async fn stop(&mut self) -> TestResult<()> {
        self.shutdown.cancel();
        let task = self
            .task
            .take()
            .ok_or_else(|| io::Error::other("Edge TLS fixture is not running"))?;
        bounded("Edge TLS fixture shutdown", task).await???;
        let mut child = self
            .child
            .take()
            .ok_or_else(|| io::Error::other("Edge TLS child is not running"))?;
        if child.try_wait()?.is_none() {
            child.kill().await?;
        }
        let _ = bounded("Edge TLS child shutdown", child.wait()).await??;
        Ok(())
    }

    async fn restart(&mut self) -> TestResult<()> {
        if self.task.is_some() || self.child.is_some() {
            return Err(io::Error::other("Edge TLS fixture is already running").into());
        }
        let mut child = spawn_openssl_edge(
            self.tls_addr,
            &self.certificate_path,
            &self.private_key_path,
        )?;
        wait_for_openssl_edge(self.tls_addr, &mut child).await?;
        let listener = TcpListener::bind(self.addr).await?;
        self.shutdown = CancellationToken::new();
        self.task = Some(Self::spawn(
            listener,
            self.tls_addr,
            Arc::clone(&self.observations),
            Arc::clone(&self.observation_ready),
            self.shutdown.clone(),
        ));
        self.child = Some(child);
        Ok(())
    }
}

impl Drop for EdgeTlsFixture {
    fn drop(&mut self) {
        self.shutdown.cancel();
        if let Some(task) = self.task.as_ref() {
            task.abort();
        }
        if let Some(child) = self.child.as_mut() {
            let _ = child.start_kill();
        }
    }
}

fn spawn_openssl_edge(
    addr: SocketAddr,
    certificate_path: &FsPath,
    private_key_path: &FsPath,
) -> TestResult<Child> {
    let child = Command::new("openssl")
        .args(["s_server", "-quiet", "-accept", &addr.to_string(), "-cert"])
        .arg(certificate_path)
        .arg("-key")
        .arg(private_key_path)
        .arg("-www")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    Ok(child)
}

async fn wait_for_openssl_edge(addr: SocketAddr, child: &mut Child) -> TestResult<()> {
    bounded("Edge OpenSSL readiness", async {
        loop {
            if let Some(status) = child.try_wait()? {
                return Err(io::Error::other(format!(
                    "Edge OpenSSL fixture exited early with {status}"
                ))
                .into());
            }
            if TcpStream::connect(addr).await.is_ok() {
                return Ok(());
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await?
}

async fn serve_edge_tls_connection(
    mut stream: TcpStream,
    tls_addr: SocketAddr,
    observations: Arc<Mutex<Vec<EdgeTlsObservation>>>,
    observation_ready: Arc<Notify>,
) -> TestResult<()> {
    let (proxy_wire, proxy) = read_proxy_v2_wire(&mut stream).await?;
    let tls_wire = Arc::new(Mutex::new(Vec::new()));
    let mut upstream = bounded("Edge OpenSSL connect", TcpStream::connect(tls_addr)).await??;
    let (mut stream_read, mut stream_write) = stream.split();
    let (mut upstream_read, mut upstream_write) = upstream.split();
    let to_edge = copy_recorded(&mut stream_read, &mut upstream_write, Arc::clone(&tls_wire));
    let from_edge = copy_and_shutdown(&mut upstream_read, &mut stream_write);
    let _ = bounded("Edge TLS relay", async {
        let (to_edge, from_edge) = tokio::join!(to_edge, from_edge);
        to_edge.and(from_edge)
    })
    .await??;
    observations
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(EdgeTlsObservation {
            proxy,
            proxy_wire,
            tls_wire: tls_wire
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone(),
        });
    observation_ready.notify_waiters();
    Ok(())
}

async fn read_proxy_v2_wire(stream: &mut TcpStream) -> TestResult<(Vec<u8>, ProxyV2Header)> {
    let mut wire = vec![0_u8; PROXY_V2_PREFIX_BYTES];
    stream.read_exact(&mut wire).await?;
    let payload_bytes = usize::from(u16::from_be_bytes([
        wire[PROXY_V2_PREFIX_BYTES - 2],
        wire[PROXY_V2_PREFIX_BYTES - 1],
    ]));
    let total_bytes = PROXY_V2_PREFIX_BYTES.saturating_add(payload_bytes);
    if total_bytes > MAX_PROXY_V2_HEADER_BYTES {
        return Err(io::Error::other("Edge received oversized PROXY v2 header").into());
    }
    wire.resize(total_bytes, 0);
    stream
        .read_exact(&mut wire[PROXY_V2_PREFIX_BYTES..])
        .await?;
    let proxy = parse_proxy_v2(&wire)?.header;
    Ok((wire, proxy))
}

struct PrefixProxy {
    addr: SocketAddr,
    recordings: Arc<Mutex<Vec<Vec<u8>>>>,
    recording_ready: Arc<Notify>,
    shutdown: CancellationToken,
    task: Option<JoinHandle<io::Result<()>>>,
}

impl PrefixProxy {
    async fn start(upstream: SocketAddr, prefix: Vec<u8>) -> TestResult<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let recordings = Arc::new(Mutex::new(Vec::new()));
        let recording_ready = Arc::new(Notify::new());
        let shutdown = CancellationToken::new();
        let task_recordings = Arc::clone(&recordings);
        let task_recording_ready = Arc::clone(&recording_ready);
        let task_shutdown = shutdown.clone();
        let task = tokio::spawn(async move {
            let connections = TaskTracker::new();
            loop {
                tokio::select! {
                    () = task_shutdown.cancelled() => break,
                    accepted = listener.accept() => {
                        let (downstream, _) = accepted?;
                        let prefix = prefix.clone();
                        let recordings = Arc::clone(&task_recordings);
                        let recording_ready = Arc::clone(&task_recording_ready);
                        let connection_shutdown = task_shutdown.clone();
                        connections.spawn(async move {
                            let Ok(mut upstream_stream) = TcpStream::connect(upstream).await else {
                                return;
                            };
                            if upstream_stream.write_all(&prefix).await.is_err() {
                                return;
                            }
                            let mut downstream = downstream;
                            let (mut downstream_read, mut downstream_write) = downstream.split();
                            let (mut upstream_read, mut upstream_write) = upstream_stream.split();
                            let captured = Arc::new(Mutex::new(Vec::new()));
                            let to_upstream = copy_recorded(
                                &mut downstream_read,
                                &mut upstream_write,
                                Arc::clone(&captured),
                            );
                            let to_downstream =
                                copy_and_shutdown(&mut upstream_read, &mut downstream_write);
                            tokio::select! {
                                _ = async { let _ = tokio::join!(to_upstream, to_downstream); } => {}
                                () = connection_shutdown.cancelled() => {}
                            }
                            recordings
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner)
                                .push(
                                    captured
                                        .lock()
                                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                                        .clone(),
                                );
                            recording_ready.notify_waiters();
                        });
                    }
                }
            }
            connections.close();
            connections.wait().await;
            Ok(())
        });
        Ok(Self {
            addr,
            recordings,
            recording_ready,
            shutdown,
            task: Some(task),
        })
    }

    async fn recording(&self, index: usize) -> TestResult<Vec<u8>> {
        bounded("prefixed proxy recording", async {
            loop {
                let notified = self.recording_ready.notified();
                if let Some(recording) = self
                    .recordings
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .get(index)
                    .cloned()
                {
                    return recording;
                }
                notified.await;
            }
        })
        .await
    }

    async fn stop(mut self) -> TestResult<()> {
        self.shutdown.cancel();
        let task = self
            .task
            .take()
            .ok_or_else(|| io::Error::other("prefixed proxy task already consumed"))?;
        bounded("prefixed proxy shutdown", task).await???;
        Ok(())
    }
}

impl Drop for PrefixProxy {
    fn drop(&mut self) {
        self.shutdown.cancel();
        if let Some(task) = self.task.as_ref() {
            task.abort();
        }
    }
}

async fn copy_recorded<R, W>(
    mut reader: R,
    mut writer: W,
    captured: Arc<Mutex<Vec<u8>>>,
) -> io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut copied = 0_u64;
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            writer.shutdown().await?;
            return Ok(copied);
        }
        captured
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend_from_slice(&buffer[..read]);
        writer.write_all(&buffer[..read]).await?;
        copied = copied.saturating_add(read as u64);
    }
}

async fn copy_and_shutdown<R, W>(mut reader: R, mut writer: W) -> io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let copied = tokio::io::copy(&mut reader, &mut writer).await?;
    writer.shutdown().await?;
    Ok(copied)
}

fn fixture_router(state: FixtureState) -> Router {
    Router::new()
        .route("/inspect", any(inspect_request))
        .route("/inspect/{*tail}", any(inspect_request))
        .route("/health", get(health))
        .route("/upload", any(hash_upload))
        .route("/backpressured-upload", any(backpressured_upload))
        .route("/pressure-download", get(pressure_download))
        .route("/sequential-download", get(sequential_download))
        .route("/download", get(stream_download))
        .route("/sse", get(sse))
        .route("/ws", get(websocket_echo))
        .route("/ordinary/{id}", any(ordinary))
        .route("/side-effect", post(side_effect))
        .with_state(state)
}

async fn health(State(state): State<FixtureState>, headers: HeaderMap) -> Response<Body> {
    if let Some(probe) = headers
        .get("x-e2e-health-probe")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
    {
        state
            .health_arrivals
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(probe, Instant::now());
    }
    Response::new(Body::from("ok\n"))
}

async fn inspect_request(
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Body,
) -> Response<Body> {
    let body = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => return fixed_response(StatusCode::BAD_REQUEST, "invalid body\n"),
    };
    let body = String::from_utf8_lossy(&body);
    let path_and_query = uri
        .path_and_query()
        .map_or_else(|| "/".to_owned(), ToString::to_string);
    let observed = format!(
        "method={method}\npath_query={path_and_query}\nhost={}\nauthorization={}\nforwarded={}\n\
         x-forwarded-for={}\nx-forwarded-host={}\nx-forwarded-proto={}\nx-e2e-request={}\nbody={body}",
        header_text(&headers, HOST),
        header_text(&headers, AUTHORIZATION),
        header_text(&headers, FORWARDED),
        header_text(&headers, HeaderName::from_static("x-forwarded-for")),
        header_text(&headers, HeaderName::from_static("x-forwarded-host")),
        header_text(&headers, HeaderName::from_static("x-forwarded-proto")),
        header_text(&headers, HeaderName::from_static("x-e2e-request")),
    );
    let mut response = Response::new(Body::from(observed));
    *response.status_mut() = StatusCode::CREATED;
    response.headers_mut().insert(
        HeaderName::from_static("x-e2e-response"),
        HeaderValue::from_static("preserved"),
    );
    response
}

async fn hash_upload(body: Body) -> Response<Body> {
    let mut body = body;
    let mut hasher = Sha256::new();
    let mut bytes = 0_u64;
    while let Some(frame) = body.frame().await {
        let frame = match frame {
            Ok(frame) => frame,
            Err(_) => return fixed_response(StatusCode::BAD_REQUEST, "invalid body\n"),
        };
        if let Ok(data) = frame.into_data() {
            hasher.update(&data);
            bytes = bytes.saturating_add(data.len() as u64);
        }
    }
    Response::new(Body::from(format!(
        "bytes={bytes}\nsha256={}\n",
        digest_hex(&hasher.finalize())
    )))
}

async fn backpressured_upload(State(state): State<FixtureState>, body: Body) -> Response<Body> {
    let _activity = ActivityGuard::new(Arc::clone(&state.pressure_active), None);
    let started = Instant::now();
    let mut body = body;
    let mut bytes = 0_usize;
    while let Some(frame) = body.frame().await {
        let frame = match frame {
            Ok(frame) => frame,
            Err(_) => return fixed_response(StatusCode::BAD_REQUEST, "invalid body\n"),
        };
        if let Ok(data) = frame.into_data() {
            bytes = bytes.saturating_add(data.len());
            state.pressure_bytes.store(bytes, Ordering::Release);

            let expected_nanos =
                (bytes as u128 * 1_000_000_000_u128) / PRESSURE_FIXTURE_BYTES_PER_SECOND as u128;
            let expected_elapsed =
                Duration::from_nanos(u64::try_from(expected_nanos).unwrap_or(u64::MAX));
            if let Some(delay) = expected_elapsed.checked_sub(started.elapsed()) {
                sleep(delay).await;
            }
        }
    }
    Response::new(Body::from(format!("bytes={bytes}\n")))
}

async fn pressure_download(State(state): State<FixtureState>) -> Response<Body> {
    generated_download(state, PRESSURE_DOWNLOAD_BYTES)
}

async fn sequential_download(State(state): State<FixtureState>) -> Response<Body> {
    generated_download(state, SEQUENTIAL_DOWNLOAD_BYTES)
}

fn generated_download(state: FixtureState, total_bytes: usize) -> Response<Body> {
    let activity = ActivityGuard::new(Arc::clone(&state.pressure_download_active), None);
    let chunk = Bytes::from(vec![0x5a; PRESSURE_CHUNK_BYTES]);
    let emitted = Arc::clone(&state.pressure_download_bytes);
    let chunks = stream::unfold(
        (0_usize, chunk, emitted, activity),
        move |(sent, chunk, emitted, activity)| async move {
            if sent >= total_bytes {
                return None;
            }
            let length = (total_bytes - sent).min(chunk.len());
            let data = chunk.slice(..length);
            let sent = sent.saturating_add(length);
            emitted.store(sent, Ordering::Release);
            Some((
                Ok::<Bytes, Infallible>(data),
                (sent, chunk, emitted, activity),
            ))
        },
    );
    let mut response = Response::new(Body::from_stream(chunks));
    if let Ok(content_length) = HeaderValue::from_str(&total_bytes.to_string()) {
        response
            .headers_mut()
            .insert(CONTENT_LENGTH, content_length);
    }
    response
}

async fn stream_download(State(state): State<FixtureState>) -> Response<Body> {
    let chunks = state.download_chunks.as_ref().clone();
    let stream = tokio_stream::iter(chunks.into_iter().map(Ok::<Bytes, Infallible>));
    Response::new(Body::from_stream(stream))
}

async fn sse(State(state): State<FixtureState>) -> Response<Body> {
    let events = stream::unfold(
        (0_usize, Arc::clone(&state.sse_events)),
        |(sequence, emitted)| async move {
            if sequence > 0 {
                sleep(Duration::from_millis(25)).await;
            }
            emitted.store(sequence.saturating_add(1), Ordering::Release);
            let event = Bytes::from(format!("event: progress\ndata: {sequence}\n\n"));
            Some((
                Ok::<Bytes, Infallible>(event),
                (sequence.wrapping_add(1), emitted),
            ))
        },
    );
    let mut response = Response::new(Body::from_stream(events));
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("text/event-stream"));
    response
}

async fn websocket_echo(upgrade: WebSocketUpgrade) -> impl axum::response::IntoResponse {
    upgrade.on_upgrade(|mut socket| async move {
        while let Some(Ok(message)) = socket.recv().await {
            match message {
                AxumMessage::Text(_) | AxumMessage::Binary(_) | AxumMessage::Pong(_) => {
                    if socket.send(message).await.is_err() {
                        break;
                    }
                }
                AxumMessage::Ping(payload) => {
                    if socket.send(AxumMessage::Pong(payload)).await.is_err() {
                        break;
                    }
                }
                AxumMessage::Close(_) => break,
            }
        }
    })
}

async fn ordinary(State(state): State<FixtureState>, Path(id): Path<usize>) -> Response<Body> {
    let _activity = ActivityGuard::new(
        Arc::clone(&state.ordinary_active),
        Some(&state.ordinary_max_active),
    );
    sleep(Duration::from_millis(10)).await;
    let mut response = Response::new(Body::from(format!("ordinary-{id}")));
    response.headers_mut().insert(
        HeaderName::from_static("x-ordinary-id"),
        HeaderValue::from_str(&id.to_string()).unwrap_or_else(|_| HeaderValue::from_static("bad")),
    );
    response
}

async fn side_effect(State(state): State<FixtureState>) -> Response<Body> {
    state.side_effects.fetch_add(1, Ordering::AcqRel);
    state.side_effect_started.notify_waiters();
    let activity = ActivityGuard::new(Arc::clone(&state.slow_active), None);
    let delayed = stream::once(async move {
        sleep(Duration::from_secs(5)).await;
        drop(activity);
        Ok::<Bytes, Infallible>(Bytes::from_static(b"side-effect-complete"))
    });
    Response::new(Body::from_stream(delayed))
}

fn fixed_response(status: StatusCode, body: &'static str) -> Response<Body> {
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    response
}

fn header_text(headers: &HeaderMap, name: impl axum::http::header::AsHeaderName) -> &str {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("<missing>")
}

fn digest_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn deterministic_payload(size: usize) -> Bytes {
    let mut payload = Vec::with_capacity(size);
    for index in 0..size {
        payload.push(((index.wrapping_mul(31).wrapping_add(index / 251)) % 256) as u8);
    }
    Bytes::from(payload)
}

fn generated_upload_body(total_bytes: usize) -> Body {
    let chunk = Bytes::from(vec![0xa5; PRESSURE_CHUNK_BYTES]);
    let chunks = stream::unfold((0_usize, chunk), move |(sent, chunk)| async move {
        if sent >= total_bytes {
            return None;
        }
        let length = (total_bytes - sent).min(chunk.len());
        let data = chunk.slice(..length);
        Some((
            Ok::<Bytes, Infallible>(data),
            (sent.saturating_add(length), chunk),
        ))
    });
    Body::from_stream(chunks)
}

struct AbortOnDropTask<T> {
    task: Option<JoinHandle<T>>,
}

impl<T> AbortOnDropTask<T> {
    fn new(task: JoinHandle<T>) -> Self {
        Self { task: Some(task) }
    }

    async fn join(&mut self, label: &'static str) -> TestResult<T> {
        let task = self
            .task
            .as_mut()
            .ok_or_else(|| io::Error::other("task already consumed"))?;
        let result = bounded(label, task).await?;
        let _ = self.task.take();
        Ok(result?)
    }

    fn is_finished(&self) -> bool {
        self.task.as_ref().is_some_and(JoinHandle::is_finished)
    }

    async fn abort(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
            let _ = timeout(HEALTH_LATENCY_BOUND, task).await;
        }
    }
}

impl<T> Drop for AbortOnDropTask<T> {
    fn drop(&mut self) {
        if let Some(task) = self.task.as_ref() {
            task.abort();
        }
    }
}

#[derive(Clone, Copy)]
struct LinkState {
    generation: u64,
    enabled: bool,
}

#[derive(Clone, Copy)]
struct LinkRateLimits {
    to_server_bytes_per_second: usize,
    to_client_bytes_per_second: usize,
}

struct LinkProxy {
    addr: SocketAddr,
    state: watch::Sender<LinkState>,
    shutdown: CancellationToken,
    task: Option<JoinHandle<io::Result<()>>>,
}

impl LinkProxy {
    async fn start(upstream: SocketAddr) -> TestResult<Self> {
        Self::start_with_rate_limit(upstream, None).await
    }

    async fn start_rate_limited(upstream: SocketAddr, limits: LinkRateLimits) -> TestResult<Self> {
        Self::start_with_rate_limit(upstream, Some(limits)).await
    }

    async fn start_with_rate_limit(
        upstream: SocketAddr,
        limits: Option<LinkRateLimits>,
    ) -> TestResult<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let (state, _) = watch::channel(LinkState {
            generation: 0,
            enabled: true,
        });
        let shutdown = CancellationToken::new();
        let task_state = state.clone();
        let task_shutdown = shutdown.clone();
        let task = tokio::spawn(async move {
            let connections = TaskTracker::new();
            loop {
                tokio::select! {
                    () = task_shutdown.cancelled() => break,
                    accepted = listener.accept() => {
                        let (downstream, _) = accepted?;
                        let mut state = task_state.subscribe();
                        let snapshot = *state.borrow();
                        if !snapshot.enabled {
                            drop(downstream);
                            continue;
                        }
                        let connection_shutdown = task_shutdown.clone();
                        connections.spawn(async move {
                            let upstream_stream = TcpStream::connect(upstream).await;
                            let Ok(mut upstream_stream) = upstream_stream else {
                                return;
                            };
                            let mut downstream = downstream;
                            tokio::select! {
                                _ = copy_link(&mut downstream, &mut upstream_stream, limits) => {}
                                _ = state.wait_for(|current| {
                                    !current.enabled || current.generation != snapshot.generation
                                }) => {}
                                () = connection_shutdown.cancelled() => {}
                            }
                            let _ = downstream.shutdown().await;
                            let _ = upstream_stream.shutdown().await;
                        });
                    }
                }
            }
            connections.close();
            connections.wait().await;
            Ok(())
        });
        Ok(Self {
            addr,
            state,
            shutdown,
            task: Some(task),
        })
    }

    fn cut(&self) {
        let mut state = *self.state.borrow();
        state.enabled = false;
        state.generation = state.generation.wrapping_add(1);
        self.state.send_replace(state);
    }

    fn resume(&self) {
        let mut state = *self.state.borrow();
        state.enabled = true;
        state.generation = state.generation.wrapping_add(1);
        self.state.send_replace(state);
    }

    async fn stop(mut self) -> TestResult<()> {
        self.shutdown.cancel();
        let task = self
            .task
            .take()
            .ok_or_else(|| io::Error::other("link proxy task already consumed"))?;
        bounded("link proxy shutdown", task).await???;
        Ok(())
    }
}

async fn copy_link(
    downstream: &mut TcpStream,
    upstream: &mut TcpStream,
    limits: Option<LinkRateLimits>,
) -> io::Result<()> {
    let Some(limits) = limits else {
        tokio::io::copy_bidirectional(downstream, upstream).await?;
        return Ok(());
    };

    let (downstream_read, downstream_write) = downstream.split();
    let (upstream_read, upstream_write) = upstream.split();
    tokio::try_join!(
        copy_rate_limited(
            downstream_read,
            upstream_write,
            limits.to_server_bytes_per_second,
        ),
        copy_rate_limited(
            upstream_read,
            downstream_write,
            limits.to_client_bytes_per_second,
        ),
    )?;
    Ok(())
}

async fn copy_rate_limited<R, W>(
    mut reader: R,
    mut writer: W,
    bytes_per_second: usize,
) -> io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let started = Instant::now();
    let mut copied = 0_u64;
    let mut buffer = vec![0_u8; PRESSURE_CHUNK_BYTES];
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            writer.shutdown().await?;
            return Ok(copied);
        }
        writer.write_all(&buffer[..read]).await?;
        copied = copied.saturating_add(read as u64);

        let expected_nanos = (u128::from(copied) * 1_000_000_000_u128) / bytes_per_second as u128;
        let expected_elapsed =
            Duration::from_nanos(u64::try_from(expected_nanos).unwrap_or(u64::MAX));
        if let Some(delay) = expected_elapsed.checked_sub(started.elapsed()) {
            sleep(delay).await;
        }
    }
}

impl Drop for LinkProxy {
    fn drop(&mut self) {
        self.shutdown.cancel();
        if let Some(task) = self.task.as_ref() {
            task.abort();
        }
    }
}

struct ServerHarness {
    addr: SocketAddr,
    state: RuntimeState,
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<io::Result<()>>>,
}

impl ServerHarness {
    async fn start(database: Database) -> TestResult<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let state = RuntimeState::new(database, PUBLIC_BASE_DOMAIN)?;
        let runtime_state = state.clone();
        let (shutdown, stopped) = oneshot::channel();
        let task = tokio::spawn(async move {
            sink_server::runtime::serve(
                listener,
                runtime_state,
                async move {
                    let _ = stopped.await;
                },
                Duration::from_secs(3),
            )
            .await
        });
        Ok(Self {
            addr,
            state,
            shutdown: Some(shutdown),
            task: Some(task),
        })
    }

    async fn stop(mut self) -> TestResult<()> {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let task = self
            .task
            .take()
            .ok_or_else(|| io::Error::other("server task already consumed"))?;
        bounded("sink server shutdown", task).await???;
        Ok(())
    }
}

impl Drop for ServerHarness {
    fn drop(&mut self) {
        self.state.initiate_shutdown();
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(task) = self.task.as_ref() {
            task.abort();
        }
    }
}

struct LiveStack {
    _temp: TempDir,
    database: Database,
    server: ServerHarness,
    link: LinkProxy,
}

impl LiveStack {
    async fn start() -> TestResult<Self> {
        Self::start_with_link_rate_limit(None).await
    }

    async fn start_with_link_rate_limit(limits: Option<LinkRateLimits>) -> TestResult<Self> {
        let temp = tempfile::tempdir()?;
        let database = Database::open(temp.path().join("sink.sqlite3")).await?;
        let server = ServerHarness::start(database.clone()).await?;
        let link = match limits {
            Some(limits) => LinkProxy::start_rate_limited(server.addr, limits).await?,
            None => LinkProxy::start(server.addr).await?,
        };
        Ok(Self {
            _temp: temp,
            database,
            server,
            link,
        })
    }

    async fn stop(self) -> TestResult<()> {
        let Self {
            _temp,
            database,
            server,
            link,
        } = self;
        link.stop().await?;
        server.stop().await?;
        database.close().await;
        drop(_temp);
        Ok(())
    }
}

type TestTlsResolver =
    DynamicTlsCertificateResolver<SqliteCertificateStorage, RuntimeSniAuthorization>;

#[derive(Clone)]
struct LocalCertificateProvisioner {
    storage: Arc<SqliteCertificateStorage>,
    certificate_directory: Arc<PathBuf>,
    reloader: Arc<RwLock<Option<Arc<dyn CertificateIndexReloader>>>>,
    pending: Arc<Mutex<HashSet<String>>>,
    certificate_paths: Arc<Mutex<HashMap<String, PathBuf>>>,
}

impl LocalCertificateProvisioner {
    fn new(
        storage: Arc<SqliteCertificateStorage>,
        certificate_directory: PathBuf,
        base_hostname: &str,
        base_certificate_path: PathBuf,
    ) -> Self {
        Self {
            storage,
            certificate_directory: Arc::new(certificate_directory),
            reloader: Arc::new(RwLock::new(None)),
            pending: Arc::new(Mutex::new(HashSet::new())),
            certificate_paths: Arc::new(Mutex::new(HashMap::from([(
                base_hostname.to_owned(),
                base_certificate_path,
            )]))),
        }
    }

    fn attach_reloader(&self, reloader: Arc<dyn CertificateIndexReloader>) {
        *self
            .reloader
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(reloader);
    }

    fn set_pending(&self, hostname: &str) {
        self.pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(hostname.to_owned());
    }

    fn certificate_for(&self, hostname: &str) -> TestResult<PathBuf> {
        self.certificate_paths
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(hostname)
            .cloned()
            .ok_or_else(|| io::Error::other(format!("no local certificate for {hostname}")).into())
    }

    fn reloader(&self) -> Result<Arc<dyn CertificateIndexReloader>, NamespaceCertificateError> {
        self.reloader
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
            .ok_or(NamespaceCertificateError)
    }
}

impl NamespaceCertificateProvisioner for LocalCertificateProvisioner {
    fn provision(
        &self,
        request: NamespaceCertificateRequest,
    ) -> BoxFuture<'_, Result<NamespaceCertificateStatus, NamespaceCertificateError>> {
        Box::pin(async move {
            let target = CertificateTarget::namespace(request.hostname.clone());
            let is_pending = self
                .pending
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .contains(request.hostname.as_str());
            if is_pending {
                self.storage
                    .store_certificate(CertificateRecord::pending(
                        target,
                        request.provider,
                        request.now,
                    ))
                    .await
                    .map_err(|_| NamespaceCertificateError)?;
                self.reloader()?
                    .refresh(request.now)
                    .await
                    .map_err(|_| NamespaceCertificateError)?;
                return Ok(NamespaceCertificateStatus::Pending);
            }

            let (material, certificate_path) = local_certificate(
                self.certificate_directory.as_ref(),
                request.hostname.as_str(),
            )
            .await
            .map_err(|_| NamespaceCertificateError)?;
            self.storage
                .store_certificate(CertificateRecord::ready(
                    target,
                    request.provider,
                    material,
                    request.now,
                ))
                .await
                .map_err(|_| NamespaceCertificateError)?;
            self.certificate_paths
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(request.hostname.to_string(), certificate_path);
            self.reloader()?
                .refresh(request.now)
                .await
                .map_err(|_| NamespaceCertificateError)?;
            Ok(NamespaceCertificateStatus::Ready)
        })
    }

    fn release(
        &self,
        hostname: Hostname,
        provider: CertificateProviderKind,
        now: Timestamp,
    ) -> BoxFuture<'_, Result<(), NamespaceCertificateError>> {
        Box::pin(async move {
            let target = CertificateTarget::namespace(hostname.clone());
            let retained = self
                .storage
                .load_certificate(&target)
                .await
                .map_err(|_| NamespaceCertificateError)?
                .and_then(|certificate| match certificate.state {
                    CertificateState::Ready(material) => Some(CertificateRecord::retained(
                        target.clone(),
                        provider,
                        material,
                        now,
                    )),
                    CertificateState::Pending
                    | CertificateState::RetryScheduled { .. }
                    | CertificateState::Failed
                    | CertificateState::Retained(_) => None,
                });
            self.storage
                .retire_order_cycle(target, provider, retained)
                .await
                .map_err(|_| NamespaceCertificateError)?;
            self.reloader()?
                .refresh(now)
                .await
                .map_err(|_| NamespaceCertificateError)?;
            Ok(())
        })
    }
}

struct ManagedTlsServerHarness {
    http_addr: SocketAddr,
    https_addr: SocketAddr,
    state: RuntimeState,
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<io::Result<()>>>,
}

impl ManagedTlsServerHarness {
    async fn start(
        database: Database,
        storage: Arc<SqliteCertificateStorage>,
        certificates: Arc<LocalCertificateProvisioner>,
    ) -> TestResult<Self> {
        Self::start_on(database, storage, certificates, None, None).await
    }

    async fn start_on(
        database: Database,
        storage: Arc<SqliteCertificateStorage>,
        certificates: Arc<LocalCertificateProvisioner>,
        addresses: Option<(SocketAddr, SocketAddr)>,
        https_proxy: Option<HttpsProxyConfig>,
    ) -> TestResult<Self> {
        let base_hostname = Hostname::parse(PUBLIC_BASE_DOMAIN)?;
        let crypto_provider = default_crypto_provider();
        let authorization = Arc::new(RuntimeSniAuthorization::new(base_hostname.clone()));
        let resolver = Arc::new(TestTlsResolver::new(
            storage,
            authorization.clone(),
            crypto_provider.clone(),
        ));
        certificates.attach_reloader(resolver.clone());
        resolver.refresh(test_timestamp()).await?;

        let domains = ConfiguredDomains::new(vec![ConfiguredDomain::new(
            base_hostname,
            2,
            CertificateProviderKind::Cloudflare,
        )?])?;
        let state = RuntimeState::with_namespace_control(
            database,
            PUBLIC_BASE_DOMAIN,
            domains,
            certificates,
        )?;
        state.attach_sni_authorization(&authorization)?;
        state.refresh_sni_namespace_boundaries().await?;

        let tls_config = build_tls_server_config(resolver, crypto_provider)?;
        let (http_bind, https_bind) = match addresses {
            Some(addresses) => addresses,
            None => ("127.0.0.1:0".parse()?, "127.0.0.1:0".parse()?),
        };
        let http_listener = TcpListener::bind(http_bind).await?;
        let http_addr = http_listener.local_addr()?;
        let https_socket = TcpListener::bind(https_bind).await?;
        let https_addr = https_socket.local_addr()?;
        let https_listener = match https_proxy {
            Some(proxy) => {
                TlsListener::with_passthrough(https_socket, tls_config, state.clone(), proxy)
            }
            None => TlsListener::new(https_socket, tls_config),
        };
        let runtime_state = state.clone();
        let (shutdown, stopped) = oneshot::channel();
        let task = tokio::spawn(async move {
            sink_server::runtime::serve_http_and_https(
                http_listener,
                https_listener,
                runtime_state,
                async move {
                    let _ = stopped.await;
                },
                Duration::from_secs(3),
            )
            .await
        });
        Ok(Self {
            http_addr,
            https_addr,
            state,
            shutdown: Some(shutdown),
            task: Some(task),
        })
    }

    async fn stop(mut self) -> TestResult<()> {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let task = self
            .task
            .take()
            .ok_or_else(|| io::Error::other("managed server task already consumed"))?;
        bounded("managed server shutdown", task).await???;
        Ok(())
    }
}

impl Drop for ManagedTlsServerHarness {
    fn drop(&mut self) {
        self.state.initiate_shutdown();
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(task) = self.task.as_ref() {
            task.abort();
        }
    }
}

struct ManagedTlsStack {
    _temp: TempDir,
    database: Database,
    storage: Arc<SqliteCertificateStorage>,
    certificates: Arc<LocalCertificateProvisioner>,
    https_proxy: Option<HttpsProxyConfig>,
    server: Option<ManagedTlsServerHarness>,
}

impl ManagedTlsStack {
    async fn start() -> TestResult<Self> {
        Self::start_with_https_proxy(None).await
    }

    async fn start_with_https_proxy(https_proxy: Option<HttpsProxyConfig>) -> TestResult<Self> {
        let temp = tempfile::tempdir()?;
        let database_path = temp.path().join("sink.sqlite3");
        let database = Database::open(&database_path).await?;
        let storage = Arc::new(SqliteCertificateStorage::connect(&database_path).await?);
        let certificate_directory = temp.path().join("certificates");
        tokio::fs::create_dir(&certificate_directory).await?;
        let base_hostname = Hostname::parse(PUBLIC_BASE_DOMAIN)?;
        let (base_material, base_certificate_path) =
            local_certificate(&certificate_directory, PUBLIC_BASE_DOMAIN).await?;
        storage
            .store_certificate(CertificateRecord::ready(
                CertificateTarget::base_domain(base_hostname),
                CertificateProviderKind::Cloudflare,
                base_material,
                test_timestamp(),
            ))
            .await?;
        let certificates = Arc::new(LocalCertificateProvisioner::new(
            storage.clone(),
            certificate_directory,
            PUBLIC_BASE_DOMAIN,
            base_certificate_path,
        ));
        let server = match https_proxy.clone() {
            Some(proxy) => {
                ManagedTlsServerHarness::start_on(
                    database.clone(),
                    storage.clone(),
                    certificates.clone(),
                    None,
                    Some(proxy),
                )
                .await?
            }
            None => {
                ManagedTlsServerHarness::start(
                    database.clone(),
                    storage.clone(),
                    certificates.clone(),
                )
                .await?
            }
        };
        Ok(Self {
            _temp: temp,
            database,
            storage,
            certificates,
            https_proxy,
            server: Some(server),
        })
    }

    fn server(&self) -> TestResult<&ManagedTlsServerHarness> {
        self.server
            .as_ref()
            .ok_or_else(|| io::Error::other("managed server is not running").into())
    }

    async fn restart_server(&mut self) -> TestResult<()> {
        let old = self
            .server
            .take()
            .ok_or_else(|| io::Error::other("managed server is not running"))?;
        let addresses = (old.http_addr, old.https_addr);
        old.stop().await?;
        self.server = Some(
            ManagedTlsServerHarness::start_on(
                self.database.clone(),
                self.storage.clone(),
                self.certificates.clone(),
                Some(addresses),
                self.https_proxy.clone(),
            )
            .await?,
        );
        Ok(())
    }

    async fn stop(mut self) -> TestResult<()> {
        if let Some(server) = self.server.take() {
            server.stop().await?;
        }
        self.storage.close().await;
        self.database.close().await;
        Ok(())
    }
}

async fn local_certificate(
    directory: &FsPath,
    hostname: &str,
) -> TestResult<(CertificateMaterial, PathBuf)> {
    let stem = hostname.replace('.', "-");
    let certificate_path = directory.join(format!("{stem}-certificate.pem"));
    let private_key_path = directory.join(format!("{stem}-private-key.pem"));
    let subject = format!("/CN={hostname}");
    let alternative_names = format!("subjectAltName=DNS:{hostname},DNS:*.{hostname}");
    let output = bounded(
        "local certificate generation",
        Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-sha256",
                "-nodes",
                "-days",
                "2",
                "-subj",
                &subject,
                "-addext",
                &alternative_names,
                "-keyout",
            ])
            .arg(&private_key_path)
            .arg("-out")
            .arg(&certificate_path)
            .output(),
    )
    .await??;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "openssl certificate generation failed with {}",
            output.status
        ))
        .into());
    }
    let certificate_chain_pem = tokio::fs::read(&certificate_path).await?;
    let private_key_pem = tokio::fs::read(&private_key_path).await?;
    let material = CertificateMaterial {
        certificate_chain_pem,
        private_key_pem: SecretBytes::new(private_key_pem),
        not_before: Timestamp::from_unix_seconds(0),
        not_after: test_timestamp().saturating_add(Duration::from_secs(48 * 60 * 60)),
    };
    Ok((material, certificate_path))
}

fn test_timestamp() -> Timestamp {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    Timestamp::from_unix_seconds(seconds)
}

struct ClientHarness {
    handle: RuntimeHandle,
    task: Option<JoinHandle<Result<(), RuntimeError>>>,
}

impl ClientHarness {
    fn start(runtime: TunnelRuntime) -> Self {
        let handle = runtime.handle();
        let task = tokio::spawn(runtime.run());
        Self {
            handle,
            task: Some(task),
        }
    }

    async fn connected(&self) -> TestResult<ConnectionInfo> {
        wait_connected(self.handle.subscribe_state()).await
    }

    async fn finish(mut self) -> TestResult<Result<(), RuntimeError>> {
        let task = self
            .task
            .take()
            .ok_or_else(|| io::Error::other("client task already consumed"))?;
        let joined = bounded("client runtime exit", task).await?;
        Ok(joined?)
    }

    async fn stop(mut self) -> TestResult<()> {
        self.handle.begin_graceful_shutdown();
        let task = self
            .task
            .take()
            .ok_or_else(|| io::Error::other("client task already consumed"))?;
        let result = bounded("client graceful shutdown", task).await??;
        result?;
        Ok(())
    }
}

impl Drop for ClientHarness {
    fn drop(&mut self) {
        self.handle.begin_graceful_shutdown();
        if let Some(task) = self.task.as_ref() {
            task.abort();
        }
    }
}

struct MultiConnectProcess {
    child: Child,
}

impl MultiConnectProcess {
    fn start(
        config: &std::path::Path,
        config_home: &std::path::Path,
        token: &str,
        server_addr: SocketAddr,
    ) -> TestResult<Self> {
        let mut command = Command::new(env!("CARGO_BIN_EXE_multi-connect-fixture"));
        command
            .env("SINK_E2E_CONNECT_CONFIG", config)
            .env("SINK_E2E_AUTHTOKEN", token)
            .env("SINK_E2E_SERVER_ADDR", format!("http://{server_addr}"))
            .env("XDG_CONFIG_HOME", config_home)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        Ok(Self {
            child: command.spawn()?,
        })
    }

    fn assert_running(&mut self) -> TestResult<()> {
        if let Some(status) = self.child.try_wait()? {
            return Err(io::Error::other(format!(
                "multi-connect process exited unexpectedly with {status}"
            ))
            .into());
        }
        Ok(())
    }

    async fn stop(mut self) -> TestResult<()> {
        if self.child.try_wait()?.is_none() {
            self.child.kill().await?;
        }
        let _ = bounded("multi-connect process exit", self.child.wait()).await??;
        Ok(())
    }

    async fn stop_gracefully(mut self) -> TestResult<()> {
        let pid = self
            .child
            .id()
            .ok_or_else(|| io::Error::other("multi-connect process has no PID"))?;
        let status = bounded(
            "multi-connect termination signal",
            Command::new("kill")
                .arg("-TERM")
                .arg(pid.to_string())
                .status(),
        )
        .await??;
        if !status.success() {
            return Err(io::Error::other(format!(
                "could not terminate multi-connect process: {status}"
            ))
            .into());
        }
        let status = bounded("multi-connect graceful exit", self.child.wait()).await??;
        if !status.success() {
            return Err(io::Error::other(format!(
                "multi-connect process did not exit cleanly: {status}"
            ))
            .into());
        }
        Ok(())
    }
}

fn client_runtime(
    token: &str,
    control_addr: SocketAddr,
    target_addr: SocketAddr,
    requested_hostname: Option<&str>,
) -> TestResult<TunnelRuntime> {
    client_runtime_with_cors(
        token,
        control_addr,
        target_addr,
        requested_hostname,
        &[],
        false,
    )
}

fn client_runtime_with_cors(
    token: &str,
    control_addr: SocketAddr,
    target_addr: SocketAddr,
    requested_hostname: Option<&str>,
    origins: &[&str],
    credentials: bool,
) -> TestResult<TunnelRuntime> {
    let config = SavedConfig::default().resolve(RunOverrides {
        authtoken: Some(AuthToken::new(token.to_owned())?),
        server_addr: Some(format!("http://{control_addr}").parse()?),
        allow_plaintext_control: true,
    })?;
    let target = LocalTarget::from_str(&format!("http://{target_addr}"))?;
    let public_url = requested_hostname
        .map(|hostname| PublicUrl::from_str(&format!("https://{hostname}")))
        .transpose()?;
    let runtime = TunnelRuntime::from_http(
        &HttpArgs {
            cors_allow_origin: origins
                .iter()
                .map(|origin| origin.parse())
                .collect::<Result<_, _>>()?,
            cors_allow_credentials: credentials,
            target,
            url: public_url,
            authtoken: None,
            server_addr: None,
            local_tls_insecure: false,
            allow_plaintext_control: false,
            inspect: true,
            dashboard_port: None,
            inspect_request_limit: NonZeroUsize::new(DEFAULT_TRANSACTION_LIMIT)
                .ok_or_else(|| io::Error::other("default transaction limit must be non-zero"))?,
            inspect_body_limit: NonZeroUsize::new(DEFAULT_BODY_PREVIEW_LIMIT)
                .ok_or_else(|| io::Error::other("default body limit must be non-zero"))?,
        },
        config,
    )?;
    if runtime.handle().inspection_store().is_none() {
        return Err(io::Error::other("live e2e runtime did not enable inspection").into());
    }
    Ok(runtime)
}

async fn wait_connected(
    mut state: watch::Receiver<sink_client::runtime::TunnelState>,
) -> TestResult<ConnectionInfo> {
    bounded("client connection", async move {
        loop {
            let phase = state.borrow().phase.clone();
            match phase {
                TunnelPhase::Connected(info) => return Ok(info),
                TunnelPhase::Stopped => {
                    return Err(io::Error::other("client stopped before connecting").into());
                }
                TunnelPhase::Reconnecting { .. } | TunnelPhase::Draining => {}
            }
            state
                .changed()
                .await
                .map_err(|_| TestError::from(io::Error::other("client state channel closed")))?;
        }
    })
    .await?
}

async fn bounded<T>(label: &'static str, future: impl Future<Output = T>) -> TestResult<T> {
    timeout(TEST_BOUND, future)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, format!("timed out: {label}")).into())
}

async fn public_send(
    addr: SocketAddr,
    hostname: &str,
    mut request: Request<Body>,
) -> TestResult<Response<Incoming>> {
    request
        .headers_mut()
        .insert(HOST, HeaderValue::from_str(hostname)?);
    let stream = bounded("public TCP connect", TcpStream::connect(addr)).await??;
    let (mut sender, connection) = bounded(
        "public HTTP handshake",
        http1::handshake(TokioIo::new(stream)),
    )
    .await??;
    tokio::spawn(async move {
        let _ = connection.with_upgrades().await;
    });
    let response = bounded("public HTTP response", sender.send_request(request)).await??;
    Ok(response)
}

async fn public_call(
    addr: SocketAddr,
    hostname: &str,
    method: Method,
    path: &str,
    headers: HeaderMap,
    body: Body,
) -> TestResult<(StatusCode, HeaderMap, Bytes)> {
    let mut request = Request::builder().method(method).uri(path).body(body)?;
    *request.headers_mut() = headers;
    let response = public_send(addr, hostname, request).await?;
    let status = response.status();
    let headers = response.headers().clone();
    let body = bounded("public response body", response.into_body().collect()).await??;
    Ok((status, headers, body.to_bytes()))
}

struct OpenSslDuplex {
    _child: Child,
    reader: ChildStdout,
    writer: ChildStdin,
}

impl AsyncRead for OpenSslDuplex {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.reader).poll_read(context, buffer)
    }
}

impl AsyncWrite for OpenSslDuplex {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.writer).poll_write(context, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.writer).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.writer).poll_shutdown(context)
    }
}

fn public_tls_stream(
    addr: SocketAddr,
    sni: &str,
    certificate_authority: &FsPath,
) -> TestResult<OpenSslDuplex> {
    let address = addr.to_string();
    let mut child = Command::new("openssl")
        .args([
            "s_client",
            "-quiet",
            "-verify_return_error",
            "-verify_hostname",
            sni,
            "-servername",
            sni,
            "-connect",
            &address,
            "-CAfile",
        ])
        .arg(certificate_authority)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    let reader = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("openssl stdout was not piped"))?;
    let writer = child
        .stdin
        .take()
        .ok_or_else(|| io::Error::other("openssl stdin was not piped"))?;
    Ok(OpenSslDuplex {
        _child: child,
        reader,
        writer,
    })
}

async fn public_tls_send(
    addr: SocketAddr,
    sni: &str,
    host: &str,
    certificate_authority: &FsPath,
    mut request: Request<Body>,
) -> TestResult<Response<Incoming>> {
    request
        .headers_mut()
        .insert(HOST, HeaderValue::from_str(host)?);
    let stream = public_tls_stream(addr, sni, certificate_authority)?;
    let (mut sender, connection) = bounded(
        "public HTTPS handshake",
        http1::handshake(TokioIo::new(stream)),
    )
    .await??;
    tokio::spawn(async move {
        let _ = connection.with_upgrades().await;
    });
    let response = bounded("public HTTPS response", sender.send_request(request)).await??;
    Ok(response)
}

async fn public_tls_call(
    addr: SocketAddr,
    sni: &str,
    host: &str,
    certificate_authority: &FsPath,
    method: Method,
    path: &str,
    body: Body,
) -> TestResult<(StatusCode, HeaderMap, Bytes)> {
    let request = Request::builder().method(method).uri(path).body(body)?;
    let response = public_tls_send(addr, sni, host, certificate_authority, request).await?;
    let status = response.status();
    let headers = response.headers().clone();
    let body = bounded("public HTTPS response body", response.into_body().collect()).await??;
    Ok((status, headers, body.to_bytes()))
}

async fn assert_tls_handshake_rejected(
    addr: SocketAddr,
    sni: &str,
    certificate_authority: &FsPath,
) -> TestResult<()> {
    let address = addr.to_string();
    let mut child = Command::new("openssl")
        .args([
            "s_client",
            "-quiet",
            "-verify_return_error",
            "-verify_hostname",
            sni,
            "-servername",
            sni,
            "-connect",
            &address,
            "-CAfile",
        ])
        .arg(certificate_authority)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| io::Error::other("openssl stdin was not piped"))?;
    let request = format!("GET / HTTP/1.1\r\nHost: {sni}\r\nConnection: close\r\n\r\n");
    if let Err(error) = stdin.write_all(request.as_bytes()).await
        && !matches!(
            error.kind(),
            io::ErrorKind::BrokenPipe
                | io::ErrorKind::ConnectionAborted
                | io::ErrorKind::ConnectionReset
        )
    {
        return Err(error.into());
    }
    let _ = stdin.shutdown().await;
    drop(stdin);
    let status = timeout(Duration::from_secs(6), child.wait())
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                format!("TLS rejection timed out for {sni}"),
            )
        })??;
    if status.success() {
        return Err(
            io::Error::other(format!("TLS handshake unexpectedly succeeded for {sni}")).into(),
        );
    }
    Ok(())
}

fn required_v2_proxy(trusted_cidr: &str) -> TestResult<HttpsProxyConfig> {
    Ok(HttpsProxyConfig::RequiredV2 {
        trusted_peer_cidrs: vec![trusted_cidr.parse()?],
    })
}

fn proxy_v2_with_test_tlv(source: SocketAddr, destination: SocketAddr) -> TestResult<Vec<u8>> {
    let mut wire = ProxyV2Header::proxied(source, destination)?.encode()?;
    let payload_bytes = u16::from_be_bytes([
        wire[PROXY_V2_PREFIX_BYTES - 2],
        wire[PROXY_V2_PREFIX_BYTES - 1],
    ]);
    let extended = payload_bytes
        .checked_add(4)
        .ok_or_else(|| io::Error::other("test PROXY v2 payload overflow"))?;
    wire[PROXY_V2_PREFIX_BYTES - 2..PROXY_V2_PREFIX_BYTES].copy_from_slice(&extended.to_be_bytes());
    wire.extend_from_slice(&[0xea, 0, 1, 0xab]);
    Ok(wire)
}

fn oversized_proxy_v2_prefix() -> Vec<u8> {
    let mut wire = sink_protocol::PROXY_V2_SIGNATURE.to_vec();
    wire.push(0x21);
    wire.push(0x11);
    let payload_bytes =
        u16::try_from(MAX_PROXY_V2_HEADER_BYTES - PROXY_V2_PREFIX_BYTES + 1).unwrap_or(u16::MAX);
    wire.extend_from_slice(&payload_bytes.to_be_bytes());
    wire
}

async fn assert_prefixed_tls_handshake_rejected(
    server_addr: SocketAddr,
    prefix: Vec<u8>,
    sni: &str,
    certificate_authority: &FsPath,
) -> TestResult<()> {
    let proxy = PrefixProxy::start(server_addr, prefix).await?;
    assert_tls_handshake_rejected(proxy.addr, sni, certificate_authority).await?;
    proxy.stop().await
}

async fn assert_raw_connection_rejected(addr: SocketAddr, payload: &[u8]) -> TestResult<()> {
    let mut stream = bounded("rejected TCP connect", TcpStream::connect(addr)).await??;
    stream.write_all(payload).await?;
    stream.shutdown().await?;
    let mut response = [0_u8; 1];
    match timeout(Duration::from_secs(3), stream.read(&mut response)).await {
        Ok(Ok(0) | Err(_)) => Ok(()),
        Ok(Ok(_)) => Err(io::Error::other("rejected TCP connection returned data").into()),
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "rejected TCP connection remained open",
        )
        .into()),
    }
}

async fn edge_tls_round_trip(
    server_addr: SocketAddr,
    prefix: Vec<u8>,
    sni: &str,
    certificate_authority: &FsPath,
) -> TestResult<Vec<u8>> {
    let proxy = PrefixProxy::start(server_addr, prefix).await?;
    let (status, _, body) = public_tls_call(
        proxy.addr,
        sni,
        sni,
        certificate_authority,
        Method::GET,
        "/edge",
        Body::empty(),
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    assert!(!body.is_empty());
    let recording = proxy.recording(0).await?;
    proxy.stop().await?;
    Ok(recording)
}

async fn claim_namespace(
    addr: SocketAddr,
    token: &str,
    hostname: &str,
) -> TestResult<(StatusCode, Bytes)> {
    namespace_request(
        addr,
        token,
        Method::POST,
        NAMESPACE_COLLECTION_PATH,
        Body::from(format!(r#"{{"hostname":"{hostname}"}}"#)),
    )
    .await
}

async fn claim_passthrough_namespace(
    addr: SocketAddr,
    token: &str,
    hostname: &str,
) -> TestResult<(StatusCode, Bytes)> {
    namespace_request(
        addr,
        token,
        Method::POST,
        NAMESPACE_COLLECTION_PATH,
        Body::from(format!(
            r#"{{"hostname":"{hostname}","tls_mode":"passthrough"}}"#
        )),
    )
    .await
}

async fn namespace_request(
    addr: SocketAddr,
    token: &str,
    method: Method,
    path: &str,
    body: Body,
) -> TestResult<(StatusCode, Bytes)> {
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {token}"))?,
    );
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    let (status, _, body) = public_call(addr, "127.0.0.1", method, path, headers, body).await?;
    Ok((status, body))
}

async fn list_namespaces(addr: SocketAddr, token: &str) -> TestResult<Bytes> {
    let (status, body) = namespace_request(
        addr,
        token,
        Method::GET,
        NAMESPACE_COLLECTION_PATH,
        Body::empty(),
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    Ok(body)
}

async fn namespace_status(
    addr: SocketAddr,
    token: &str,
    hostname: &str,
) -> TestResult<(StatusCode, Bytes)> {
    namespace_request(
        addr,
        token,
        Method::GET,
        &format!("{NAMESPACE_COLLECTION_PATH}/{hostname}"),
        Body::empty(),
    )
    .await
}

async fn release_namespace(
    addr: SocketAddr,
    token: &str,
    hostname: &str,
) -> TestResult<(StatusCode, Bytes)> {
    namespace_request(
        addr,
        token,
        Method::DELETE,
        &format!("{NAMESPACE_COLLECTION_PATH}/{hostname}"),
        Body::empty(),
    )
    .await
}

fn management_error_code(body: &[u8]) -> TestResult<String> {
    let body = std::str::from_utf8(body)?;
    let (_, tail) = body
        .split_once(r#""code":""#)
        .ok_or_else(|| io::Error::other("management error response has no code"))?;
    let (code, _) = tail
        .split_once('"')
        .ok_or_else(|| io::Error::other("management error code is not terminated"))?;
    Ok(code.to_owned())
}

fn passthrough_namespace(body: &[u8], hostname: &str, depth: u32) -> TestResult<()> {
    active_namespace(body, hostname, depth)?;
    assert!(std::str::from_utf8(body)?.contains(r#""tls_mode":"passthrough""#));
    Ok(())
}

fn active_namespace(body: &[u8], hostname: &str, depth: u32) -> TestResult<()> {
    let response = std::str::from_utf8(body)?;
    assert!(response.contains(&format!(r#""hostname":"{hostname}""#)));
    assert!(response.contains(&format!(r#""depth":{depth}"#)));
    assert!(response.contains(r#""state":"active""#));
    Ok(())
}

async fn wait_for_public_status(
    stage: &'static str,
    addr: SocketAddr,
    hostname: &str,
    expected: StatusCode,
) -> TestResult<()> {
    wait_for_public_status_within(TEST_BOUND, stage, addr, hostname, expected).await
}

async fn wait_for_public_status_within(
    bound: Duration,
    stage: &'static str,
    addr: SocketAddr,
    hostname: &str,
    expected: StatusCode,
) -> TestResult<()> {
    timeout(bound, async move {
        loop {
            let result = public_call(
                addr,
                hostname,
                Method::GET,
                "/ordinary/999",
                HeaderMap::new(),
                Body::empty(),
            )
            .await;
            if result
                .as_ref()
                .is_ok_and(|(status, _, _)| *status == expected)
            {
                return Ok(());
            }
            sleep(Duration::from_millis(40)).await;
        }
    })
    .await
    .map_err(|_| -> TestError {
        Box::new(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("timed out: {stage}"),
        ))
    })?
}

async fn wait_for_public_body(
    stage: &'static str,
    addr: SocketAddr,
    hostname: &str,
    path: &str,
    expected: &Bytes,
) -> TestResult<()> {
    timeout(TEST_BOUND, async move {
        loop {
            let result = public_call(
                addr,
                hostname,
                Method::GET,
                path,
                HeaderMap::new(),
                Body::empty(),
            )
            .await;
            if result
                .as_ref()
                .is_ok_and(|(status, _, body)| *status == StatusCode::OK && body == expected)
            {
                return Ok(());
            }
            sleep(Duration::from_millis(40)).await;
        }
    })
    .await
    .map_err(|_| -> TestError {
        Box::new(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("timed out: {stage}"),
        ))
    })?
}

async fn wait_for_counter(counter: &AtomicUsize, expected: usize) -> TestResult<()> {
    bounded("fixture counter", async move {
        while counter.load(Ordering::Acquire) != expected {
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
}

async fn wait_for_counter_at_least(
    counter: &AtomicUsize,
    expected: usize,
    bound: Duration,
    label: &str,
) -> TestResult<()> {
    timeout(bound, async move {
        while counter.load(Ordering::Acquire) < expected {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            format!(
                "timed out: {label}; expected at least {expected} bytes, observed {}",
                counter.load(Ordering::Acquire)
            ),
        )
        .into()
    })
}

struct SseProbe {
    body: Incoming,
    buffered: Vec<u8>,
}

impl SseProbe {
    fn new(body: Incoming) -> Self {
        Self {
            body,
            buffered: Vec::new(),
        }
    }

    async fn sequence_at_least(&mut self, minimum: u64) -> TestResult<u64> {
        timeout(HEALTH_LATENCY_BOUND, async {
            loop {
                while let Some(offset) = self.buffered.windows(2).position(|pair| pair == b"\n\n") {
                    let event = self.buffered.drain(..offset + 2).collect::<Vec<_>>();
                    for line in String::from_utf8_lossy(&event).lines() {
                        let Some(value) = line.strip_prefix("data:") else {
                            continue;
                        };
                        let sequence = value.trim().parse::<u64>()?;
                        if sequence >= minimum {
                            return Ok::<_, TestError>(sequence);
                        }
                    }
                }

                let frame = self
                    .body
                    .frame()
                    .await
                    .ok_or_else(|| io::Error::other("SSE ended before making progress"))??;
                if let Ok(data) = frame.into_data() {
                    self.buffered.extend_from_slice(&data);
                    if self.buffered.len() > 16 * 1024 {
                        return Err(io::Error::other("SSE event exceeded 16 KiB").into());
                    }
                }
            }
        })
        .await
        .map_err(|_| -> TestError {
            Box::new(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("SSE did not deliver sequence {minimum} or newer within 2 seconds"),
            ))
        })?
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct HealthProbeStages {
    tcp_connected: Option<Duration>,
    http_ready: Option<Duration>,
    response_head: Option<Duration>,
    response_body: Option<Duration>,
}

#[derive(Clone, Copy, Debug)]
struct HealthObservation {
    stages: HealthProbeStages,
    fixture_arrival: Duration,
    total: Duration,
}

#[derive(Debug, Default)]
struct HealthReport {
    batches: usize,
    tunneled_probes: usize,
    direct_probes: usize,
    max_tunneled_total: Duration,
    max_direct_total: Duration,
    max_tunneled_tcp_connect: Duration,
    max_tunneled_http_ready: Duration,
    max_tunneled_response_head: Duration,
    max_tunneled_response_body: Duration,
    max_tunneled_to_fixture: Duration,
    max_tunneled_from_fixture: Duration,
}

impl HealthReport {
    fn observe_tunneled(&mut self, observation: HealthObservation) {
        self.tunneled_probes = self.tunneled_probes.saturating_add(1);
        self.max_tunneled_total = self.max_tunneled_total.max(observation.total);
        self.max_tunneled_tcp_connect = self
            .max_tunneled_tcp_connect
            .max(observation.stages.tcp_connected.unwrap_or_default());
        self.max_tunneled_http_ready = self
            .max_tunneled_http_ready
            .max(observation.stages.http_ready.unwrap_or_default());
        self.max_tunneled_response_head = self
            .max_tunneled_response_head
            .max(observation.stages.response_head.unwrap_or_default());
        self.max_tunneled_response_body = self
            .max_tunneled_response_body
            .max(observation.stages.response_body.unwrap_or_default());
        self.max_tunneled_to_fixture = self
            .max_tunneled_to_fixture
            .max(observation.fixture_arrival);
        self.max_tunneled_from_fixture = self.max_tunneled_from_fixture.max(
            observation
                .total
                .saturating_sub(observation.fixture_arrival),
        );
    }

    fn observe_direct(&mut self, observation: HealthObservation) {
        self.direct_probes = self.direct_probes.saturating_add(1);
        self.max_direct_total = self.max_direct_total.max(observation.total);
    }
}

async fn timed_health_probe(
    addr: SocketAddr,
    hostname: String,
    fixture_state: FixtureState,
    probe_id: usize,
    kind: &'static str,
) -> TestResult<HealthObservation> {
    // These timestamps separate public-listener/harness latency from time spent
    // crossing the tunnel. The fixture arrival marker further divides the
    // tunneled request and response directions without runtime instrumentation.
    let started = Instant::now();
    let stages = Arc::new(Mutex::new(HealthProbeStages::default()));
    let measured_stages = Arc::clone(&stages);
    let probe = async move {
        let mut request = Request::builder()
            .method(Method::GET)
            .uri("/health")
            .body(Body::empty())?;
        request
            .headers_mut()
            .insert(HOST, HeaderValue::from_str(&hostname)?);
        request.headers_mut().insert(
            HeaderName::from_static("x-e2e-health-probe"),
            HeaderValue::from_str(&probe_id.to_string())?,
        );

        let stream = TcpStream::connect(addr).await?;
        measured_stages
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .tcp_connected = Some(started.elapsed());
        let (mut sender, connection) = http1::handshake(TokioIo::new(stream)).await?;
        measured_stages
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .http_ready = Some(started.elapsed());
        tokio::spawn(async move {
            let _ = connection.with_upgrades().await;
        });

        let response = sender.send_request(request).await?;
        measured_stages
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .response_head = Some(started.elapsed());
        let status = response.status();
        let body = response.into_body().collect().await?.to_bytes();
        measured_stages
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .response_body = Some(started.elapsed());
        if status != StatusCode::OK || body != Bytes::from_static(b"ok\n") {
            return Err(io::Error::other(format!(
                "{kind} health probe {probe_id} returned {status} with {body:?}"
            ))
            .into());
        }
        Ok::<(), TestError>(())
    };

    timeout(HEALTH_LATENCY_BOUND, probe).await.map_err(|_| {
        let stages = *stages
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let fixture_arrival = fixture_state
            .health_arrivals
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&probe_id)
            .and_then(|arrival| arrival.checked_duration_since(started));
        io::Error::new(
            io::ErrorKind::TimedOut,
            format!(
                "{kind} health probe {probe_id} exceeded 2 seconds; stages={stages:?}; \
                     fixture_arrival={fixture_arrival:?}"
            ),
        )
    })??;

    let stages = *stages
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let fixture_arrival = fixture_state
        .health_arrivals
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .remove(&probe_id)
        .and_then(|arrival| arrival.checked_duration_since(started))
        .ok_or_else(|| {
            io::Error::other(format!("fixture did not record health probe {probe_id}"))
        })?;
    let total = started.elapsed();
    if total >= HEALTH_LATENCY_BOUND {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("{kind} health probe {probe_id} took {total:?}; stages={stages:?}"),
        )
        .into());
    }
    Ok(HealthObservation {
        stages,
        fixture_arrival,
        total,
    })
}

async fn health_probe_batch(
    addr: SocketAddr,
    fixture_addr: SocketAddr,
    hostname: &str,
    fixture_state: &FixtureState,
    first_probe_id: usize,
) -> TestResult<HealthReport> {
    let tunneled = async {
        let mut pending = stream::FuturesUnordered::new();
        for probe in 0..HEALTH_PROBES_PER_BATCH {
            pending.push(timed_health_probe(
                addr,
                hostname.to_owned(),
                fixture_state.clone(),
                first_probe_id.saturating_add(probe),
                "tunneled",
            ));
        }
        let mut observations = Vec::with_capacity(HEALTH_PROBES_PER_BATCH);
        while let Some(result) = pending.next().await {
            observations.push(result?);
        }
        Ok::<_, TestError>(observations)
    };
    let direct = timed_health_probe(
        fixture_addr,
        hostname.to_owned(),
        fixture_state.clone(),
        first_probe_id.saturating_add(HEALTH_PROBES_PER_BATCH),
        "direct fixture",
    );
    let (tunneled, direct) = tokio::join!(tunneled, direct);

    let mut report = HealthReport {
        batches: 1,
        ..HealthReport::default()
    };
    for observation in tunneled? {
        report.observe_tunneled(observation);
    }
    report.observe_direct(direct?);
    Ok(report)
}

async fn monitor_health(
    addr: SocketAddr,
    fixture_addr: SocketAddr,
    hostname: &str,
    fixture_state: &FixtureState,
    stop: CancellationToken,
) -> TestResult<HealthReport> {
    let mut report = HealthReport::default();
    let mut first_probe_id = 0_usize;
    loop {
        let batch = tokio::select! {
            () = stop.cancelled() => break,
            result = health_probe_batch(
                addr,
                fixture_addr,
                hostname,
                fixture_state,
                first_probe_id,
            ) => result?,
        };
        first_probe_id = first_probe_id
            .saturating_add(HEALTH_PROBES_PER_BATCH)
            .saturating_add(1);
        report.batches = report.batches.saturating_add(batch.batches);
        report.tunneled_probes = report.tunneled_probes.saturating_add(batch.tunneled_probes);
        report.direct_probes = report.direct_probes.saturating_add(batch.direct_probes);
        report.max_tunneled_total = report.max_tunneled_total.max(batch.max_tunneled_total);
        report.max_direct_total = report.max_direct_total.max(batch.max_direct_total);
        report.max_tunneled_tcp_connect = report
            .max_tunneled_tcp_connect
            .max(batch.max_tunneled_tcp_connect);
        report.max_tunneled_http_ready = report
            .max_tunneled_http_ready
            .max(batch.max_tunneled_http_ready);
        report.max_tunneled_response_head = report
            .max_tunneled_response_head
            .max(batch.max_tunneled_response_head);
        report.max_tunneled_response_body = report
            .max_tunneled_response_body
            .max(batch.max_tunneled_response_body);
        report.max_tunneled_to_fixture = report
            .max_tunneled_to_fixture
            .max(batch.max_tunneled_to_fixture);
        report.max_tunneled_from_fixture = report
            .max_tunneled_from_fixture
            .max(batch.max_tunneled_from_fixture);

        tokio::select! {
            () = stop.cancelled() => break,
            () = sleep(HEALTH_BATCH_INTERVAL) => {}
        }
    }
    Ok(report)
}

async fn public_websocket(
    addr: SocketAddr,
    hostname: &str,
) -> TestResult<WebSocketStream<TcpStream>> {
    let mut request = format!("ws://{hostname}/ws").into_client_request()?;
    request
        .headers_mut()
        .insert(HOST, HeaderValue::from_str(hostname)?);
    let stream = bounded("public WebSocket TCP connect", TcpStream::connect(addr)).await??;
    let (websocket, response) =
        bounded("public WebSocket upgrade", client_async(request, stream)).await??;
    if response.status() != StatusCode::SWITCHING_PROTOCOLS {
        return Err(
            io::Error::other(format!("WebSocket upgrade returned {}", response.status())).into(),
        );
    }
    Ok(websocket)
}

async fn public_tls_websocket(
    addr: SocketAddr,
    hostname: &str,
    certificate_authority: &FsPath,
) -> TestResult<WebSocketStream<OpenSslDuplex>> {
    let mut request = format!("wss://{hostname}/ws").into_client_request()?;
    request
        .headers_mut()
        .insert(HOST, HeaderValue::from_str(hostname)?);
    let stream = public_tls_stream(addr, hostname, certificate_authority)?;
    let (websocket, response) = bounded(
        "public HTTPS WebSocket upgrade",
        client_async(request, stream),
    )
    .await??;
    if response.status() != StatusCode::SWITCHING_PROTOCOLS {
        return Err(io::Error::other(format!(
            "HTTPS WebSocket upgrade returned {}",
            response.status()
        ))
        .into());
    }
    Ok(websocket)
}

async fn websocket_echo_progress<S>(
    websocket: &mut WebSocketStream<S>,
    payload: Bytes,
) -> TestResult<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    timeout(HEALTH_LATENCY_BOUND, async {
        websocket.send(Message::Binary(payload.clone())).await?;
        let echoed = websocket
            .next()
            .await
            .ok_or_else(|| io::Error::other("WebSocket ended before echo"))??;
        if echoed != Message::Binary(payload) {
            return Err(io::Error::other(format!(
                "unexpected WebSocket message while waiting for echo: {echoed:?}"
            ))
            .into());
        }
        Ok::<(), TestError>(())
    })
    .await
    .map_err(|_| -> TestError {
        Box::new(io::Error::new(
            io::ErrorKind::TimedOut,
            "WebSocket echo exceeded 2 seconds",
        ))
    })?
}

async fn websocket_round_trip(addr: SocketAddr, hostname: &str, payload: Bytes) -> TestResult<()> {
    let mut websocket = public_websocket(addr, hostname).await?;
    websocket_echo_progress(&mut websocket, payload).await?;
    bounded("public WebSocket close", websocket.close(None)).await??;
    Ok(())
}

async fn complete_generated_upload(addr: SocketAddr, hostname: &str) -> TestResult<()> {
    let mut headers = HeaderMap::new();
    headers.insert(
        CONTENT_LENGTH,
        HeaderValue::from_str(&PRESSURE_UPLOAD_BYTES.to_string())?,
    );
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    let (status, _, response_body) = public_call(
        addr,
        hostname,
        Method::PUT,
        "/backpressured-upload",
        headers,
        generated_upload_body(PRESSURE_UPLOAD_BYTES),
    )
    .await?;
    if status != StatusCode::OK {
        return Err(io::Error::other(format!("sequential upload returned {status}")).into());
    }
    let expected_body = Bytes::from(format!("bytes={PRESSURE_UPLOAD_BYTES}\n"));
    if response_body != expected_body {
        return Err(io::Error::other(format!(
            "unexpected sequential upload response: {response_body:?}"
        ))
        .into());
    }
    Ok(())
}

async fn complete_generated_download(addr: SocketAddr, hostname: &str) -> TestResult<()> {
    let request = Request::builder()
        .method(Method::GET)
        .uri("/sequential-download")
        .body(Body::empty())?;
    let response = public_send(addr, hostname, request).await?;
    if response.status() != StatusCode::OK {
        return Err(io::Error::other(format!(
            "sequential download returned {}",
            response.status()
        ))
        .into());
    }
    let mut body = response.into_body();
    let received = bounded("sequential download body", async {
        let mut received = 0_usize;
        while let Some(frame) = body.frame().await {
            if let Ok(data) = frame?.into_data() {
                received = received.saturating_add(data.len());
            }
        }
        Ok::<usize, TestError>(received)
    })
    .await??;
    if received != SEQUENTIAL_DOWNLOAD_BYTES {
        return Err(io::Error::other("sequential download returned the wrong byte count").into());
    }
    Ok(())
}

async fn require_long_lived_progress(
    sse_events: &AtomicUsize,
    websocket_echoes: &AtomicUsize,
    before: (usize, usize),
    stage: &str,
) -> TestResult<()> {
    tokio::try_join!(
        wait_for_counter_at_least(
            sse_events,
            before.0.saturating_add(1),
            HEALTH_LATENCY_BOUND,
            stage,
        ),
        wait_for_counter_at_least(
            websocket_echoes,
            before.1.saturating_add(1),
            HEALTH_LATENCY_BOUND,
            stage,
        ),
    )?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn generated_tunnel_preserves_and_streams_mixed_traffic() -> TestResult<()> {
    let payload = deterministic_payload(STREAM_BYTES);
    let fixture_state = FixtureState::new(&payload);
    let fixture = FixtureHarness::start(fixture_state.clone()).await?;
    let stack = LiveStack::start().await?;
    let issued = stack.database.create_user("generated-e2e").await?;
    let token = issued.token.expose_secret().to_owned();
    let client = ClientHarness::start(client_runtime(&token, stack.link.addr, fixture.addr, None)?);
    let inspection = client
        .handle
        .inspection_store()
        .ok_or_else(|| io::Error::other("inspection store unavailable"))?;
    let info = client.connected().await?;
    assert!(info.hostname.ends_with(".e2e.test"));

    let mut request_headers = HeaderMap::new();
    request_headers.insert(
        HeaderName::from_static("x-e2e-request"),
        HeaderValue::from_static("preserved"),
    );
    request_headers.insert(
        AUTHORIZATION,
        HeaderValue::from_static("Visitor public-credential"),
    );
    request_headers.insert(
        HeaderName::from_static("x-forwarded-for"),
        HeaderValue::from_static("203.0.113.9, 127.0.0.1"),
    );
    request_headers.insert(
        HeaderName::from_static("x-forwarded-proto"),
        HeaderValue::from_static("https"),
    );
    request_headers.insert(
        FORWARDED,
        HeaderValue::from_static("for=untrusted;host=untrusted"),
    );
    let (status, headers, observed) = public_call(
        stack.server.addr,
        &info.hostname,
        Method::PATCH,
        "/inspect/deep/path?alpha=one&alpha=two",
        request_headers,
        Body::from("request-body"),
    )
    .await?;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(headers["x-e2e-response"], "preserved");
    let observed = String::from_utf8(observed.to_vec())?;
    assert!(!observed.contains(&token));
    assert!(observed.contains("method=PATCH"));
    assert!(
        observed.contains("path_query=/inspect/deep/path?alpha=one&alpha=two"),
        "unexpected safe fixture observation: {observed}"
    );
    assert!(observed.contains(&format!("host={}", fixture.addr)));
    assert!(observed.contains("authorization=Visitor public-credential"));
    assert!(observed.contains(&format!(
        "forwarded=for=203.0.113.9;host={};proto=http",
        info.hostname
    )));
    assert!(observed.contains("x-forwarded-for=203.0.113.9"));
    assert!(observed.contains(&format!("x-forwarded-host={}", info.hostname)));
    assert!(observed.contains("x-forwarded-proto=http"));
    assert!(observed.contains("x-e2e-request=preserved"));
    assert!(observed.ends_with("body=request-body"));

    let upload_chunks: Vec<Bytes> = payload
        .chunks(8 * 1024)
        .map(Bytes::copy_from_slice)
        .collect();
    let upload_body = Body::from_stream(tokio_stream::iter(
        upload_chunks.into_iter().map(Ok::<Bytes, Infallible>),
    ));
    let (status, _, upload_result) = public_call(
        stack.server.addr,
        &info.hostname,
        Method::PUT,
        "/upload",
        HeaderMap::new(),
        upload_body,
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    let expected_digest = digest_hex(&Sha256::digest(&payload));
    let upload_result = String::from_utf8(upload_result.to_vec())?;
    assert!(upload_result.contains(&format!("bytes={STREAM_BYTES}")));
    assert!(upload_result.contains(&format!("sha256={expected_digest}")));

    let (status, _, download) = public_call(
        stack.server.addr,
        &info.hostname,
        Method::GET,
        "/download",
        HeaderMap::new(),
        Body::empty(),
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(download.len(), STREAM_BYTES);
    assert_eq!(digest_hex(&Sha256::digest(&download)), expected_digest);

    let request = Request::builder()
        .method(Method::GET)
        .uri("/sse")
        .body(Body::empty())?;
    let mut sse_response = public_send(stack.server.addr, &info.hostname, request).await?;
    assert_eq!(sse_response.status(), StatusCode::OK);
    assert_eq!(sse_response.headers()[CONTENT_TYPE], "text/event-stream");
    let mut sse_bytes = Vec::new();
    bounded("SSE progress", async {
        while !String::from_utf8_lossy(&sse_bytes).contains("data: 2") {
            let frame = sse_response
                .body_mut()
                .frame()
                .await
                .ok_or_else(|| io::Error::other("SSE ended early"))??;
            if let Ok(data) = frame.into_data() {
                sse_bytes.extend_from_slice(&data);
            }
        }
        Ok::<(), TestError>(())
    })
    .await??;

    let addr = stack.server.addr;
    let hostname = info.hostname.clone();
    let results = bounded(
        "100 concurrent ordinary requests",
        stream::iter(0..ORDINARY_REQUESTS)
            .map(|id| {
                let hostname = hostname.clone();
                async move {
                    let result = public_call(
                        addr,
                        &hostname,
                        Method::GET,
                        &format!("/ordinary/{id}"),
                        HeaderMap::new(),
                        Body::empty(),
                    )
                    .await?;
                    Ok::<_, TestError>((id, result))
                }
            })
            .buffer_unordered(25)
            .collect::<Vec<_>>(),
    )
    .await?;
    assert_eq!(results.len(), ORDINARY_REQUESTS);
    for result in results {
        let (id, (status, headers, body)) = result?;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers["x-ordinary-id"], id.to_string());
        assert_eq!(body, Bytes::from(format!("ordinary-{id}")));
    }
    assert!(fixture_state.ordinary_max_active.load(Ordering::Acquire) > 1);
    assert_eq!(inspection.len(), DEFAULT_TRANSACTION_LIMIT);

    drop(sse_response);

    client.stop().await?;
    stack.stop().await?;
    fixture.stop().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bidirectional_bulk_does_not_starve_health_sse_or_websocket() -> TestResult<()> {
    let fixture_payload = Bytes::new();
    let fixture_state = FixtureState::new(&fixture_payload);
    let fixture = FixtureHarness::start(fixture_state.clone()).await?;
    let stack = LiveStack::start_with_link_rate_limit(Some(LinkRateLimits {
        to_server_bytes_per_second: PRESSURE_TO_SERVER_BYTES_PER_SECOND,
        to_client_bytes_per_second: PRESSURE_TO_CLIENT_BYTES_PER_SECOND,
    }))
    .await?;
    let issued = stack.database.create_user("fairness-e2e").await?;
    let token = issued.token.expose_secret().to_owned();
    let hostname = "fairness.e2e.test";
    let client = ClientHarness::start(client_runtime(
        &token,
        stack.link.addr,
        fixture.addr,
        Some(hostname),
    )?);
    assert_eq!(client.connected().await?.hostname, hostname);

    let sse_request = Request::builder()
        .method(Method::GET)
        .uri("/sse")
        .body(Body::empty())?;
    let sse_response = public_send(stack.server.addr, hostname, sse_request).await?;
    assert_eq!(sse_response.status(), StatusCode::OK);
    assert_eq!(sse_response.headers()[CONTENT_TYPE], "text/event-stream");
    let mut sse = SseProbe::new(sse_response.into_body());
    let initial_sequence = sse.sequence_at_least(0).await?;
    let mut sse_sequence = sse
        .sequence_at_least(initial_sequence.saturating_add(1))
        .await?;

    let mut websocket = public_websocket(stack.server.addr, hostname).await?;
    websocket_echo_progress(&mut websocket, Bytes::from_static(b"before-pressure")).await?;
    let baseline_health =
        health_probe_batch(stack.server.addr, fixture.addr, hostname, &fixture_state, 0).await?;

    let upload_addr = stack.server.addr;
    let upload_hostname = hostname.to_owned();
    let mut upload = AbortOnDropTask::new(tokio::spawn(async move {
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_LENGTH,
            HeaderValue::from_str(&PRESSURE_UPLOAD_BYTES.to_string())?,
        );
        public_call(
            upload_addr,
            &upload_hostname,
            Method::PUT,
            "/backpressured-upload",
            headers,
            generated_upload_body(PRESSURE_UPLOAD_BYTES),
        )
        .await
    }));

    let download_addr = stack.server.addr;
    let download_hostname = hostname.to_owned();
    let download_received = Arc::new(AtomicUsize::new(0));
    let download_progress = Arc::clone(&download_received);
    let mut download = AbortOnDropTask::new(tokio::spawn(async move {
        let request = Request::builder()
            .method(Method::GET)
            .uri("/pressure-download")
            .body(Body::empty())?;
        let response = public_send(download_addr, &download_hostname, request).await?;
        if response.status() != StatusCode::OK {
            return Err(io::Error::other(format!(
                "pressure download returned {}",
                response.status()
            ))
            .into());
        }
        let mut body = response.into_body();
        let mut received = 0_usize;
        while let Some(frame) = body.frame().await {
            if let Ok(data) = frame?.into_data() {
                received = received.saturating_add(data.len());
                download_progress.store(received, Ordering::Release);
            }
        }
        Ok::<usize, TestError>(received)
    }));

    wait_for_counter(&fixture_state.pressure_active, 1).await?;
    wait_for_counter(&fixture_state.pressure_download_active, 1).await?;

    let health_stop = CancellationToken::new();
    let health_addr = stack.server.addr;
    let health_fixture_addr = fixture.addr;
    let health_hostname = hostname.to_owned();
    let health_fixture_state = fixture_state.clone();
    let health_task_stop = health_stop.clone();
    let mut health = AbortOnDropTask::new(tokio::spawn(async move {
        monitor_health(
            health_addr,
            health_fixture_addr,
            &health_hostname,
            &health_fixture_state,
            health_task_stop,
        )
        .await
    }));

    let scenario_result: TestResult<HealthReport> = timeout(PRESSURE_SCENARIO_BOUND, async {
        wait_for_counter(&fixture_state.pressure_active, 1).await?;
        for (checkpoint, expected_bytes) in PRESSURE_CHECKPOINTS.into_iter().enumerate() {
            let download_before_checkpoint = download_received.load(Ordering::Acquire);
            wait_for_counter_at_least(
                &fixture_state.pressure_bytes,
                expected_bytes,
                TEST_BOUND,
                "backpressured upload checkpoint",
            )
            .await?;
            wait_for_counter_at_least(
                &download_received,
                download_before_checkpoint.saturating_add(PRESSURE_CHUNK_BYTES),
                HEALTH_LATENCY_BOUND,
                "pressure download checkpoint",
            )
            .await?;
            if fixture_state.pressure_active.load(Ordering::Acquire) != 1 {
                return Err(io::Error::other(format!(
                    "backpressured upload ended before checkpoint {checkpoint}"
                ))
                .into());
            }
            if download.is_finished() {
                return Err(io::Error::other(format!(
                    "pressure download ended before checkpoint {checkpoint}"
                ))
                .into());
            }
            if health.is_finished() {
                health.join("health monitor early exit").await??;
                return Err(io::Error::other("health monitor ended before bulk traffic").into());
            }

            let upload_before_checks = fixture_state.pressure_bytes.load(Ordering::Acquire);
            let download_before_checks = download_received.load(Ordering::Acquire);
            let emitted_before = u64::try_from(fixture_state.sse_events.load(Ordering::Acquire))?;
            let sse_progress =
                sse.sequence_at_least(emitted_before.max(sse_sequence.saturating_add(1)));
            let websocket_progress = websocket_echo_progress(
                &mut websocket,
                Bytes::from(format!("during-pressure-{checkpoint}")),
            );
            let (next_sequence, ()) = tokio::try_join!(sse_progress, websocket_progress)?;
            sse_sequence = next_sequence;

            wait_for_counter_at_least(
                &fixture_state.pressure_bytes,
                upload_before_checks.saturating_add(PRESSURE_CHUNK_BYTES),
                HEALTH_LATENCY_BOUND,
                "backpressured upload forward progress",
            )
            .await?;
            wait_for_counter_at_least(
                &download_received,
                download_before_checks.saturating_add(PRESSURE_CHUNK_BYTES),
                HEALTH_LATENCY_BOUND,
                "pressure download forward progress",
            )
            .await?;
            if fixture_state.pressure_active.load(Ordering::Acquire) != 1 {
                return Err(io::Error::other(format!(
                    "backpressured upload was not active after checkpoint {checkpoint}"
                ))
                .into());
            }
        }

        let (status, _, response_body) = upload.join("backpressured upload completion").await??;
        if status != StatusCode::OK {
            return Err(io::Error::other(format!("backpressured upload returned {status}")).into());
        }
        let expected_body = Bytes::from(format!("bytes={PRESSURE_UPLOAD_BYTES}\n"));
        if response_body != expected_body {
            return Err(io::Error::other(format!(
                "unexpected backpressured upload response: {response_body:?}"
            ))
            .into());
        }
        let downloaded = download.join("pressure download completion").await??;
        if downloaded != PRESSURE_DOWNLOAD_BYTES {
            return Err(io::Error::other(format!(
                "public caller received {downloaded} of {PRESSURE_DOWNLOAD_BYTES} download bytes"
            ))
            .into());
        }
        wait_for_counter(&fixture_state.pressure_active, 0).await?;
        wait_for_counter(&fixture_state.pressure_download_active, 0).await?;
        if fixture_state.pressure_bytes.load(Ordering::Acquire) != PRESSURE_UPLOAD_BYTES {
            return Err(io::Error::other(format!(
                "fixture received {} of {PRESSURE_UPLOAD_BYTES} upload bytes",
                fixture_state.pressure_bytes.load(Ordering::Acquire)
            ))
            .into());
        }
        if fixture_state
            .pressure_download_bytes
            .load(Ordering::Acquire)
            != PRESSURE_DOWNLOAD_BYTES
        {
            return Err(io::Error::other(format!(
                "fixture emitted {} of {PRESSURE_DOWNLOAD_BYTES} download bytes",
                fixture_state
                    .pressure_download_bytes
                    .load(Ordering::Acquire)
            ))
            .into());
        }

        health_stop.cancel();
        let health_report = health.join("health monitor completion").await??;
        if health_report.batches < 20 {
            return Err(io::Error::other(format!(
                "health monitor completed only {} batches during bulk traffic",
                health_report.batches
            ))
            .into());
        }
        Ok(health_report)
    })
    .await
    .map_err(|_| -> TestError {
        Box::new(io::Error::new(
            io::ErrorKind::TimedOut,
            "bidirectional pressure scenario exceeded 45 seconds",
        ))
    })?;

    if scenario_result.is_err() {
        health_stop.cancel();
        upload.abort().await;
        download.abort().await;
        health.abort().await;
    }
    let websocket_shutdown = timeout(HEALTH_LATENCY_BOUND, websocket.close(None)).await;
    drop(sse);
    let client_shutdown = client.stop().await;
    let stack_shutdown = stack.stop().await;
    let fixture_shutdown = fixture.stop().await;

    let health_report = scenario_result?;
    websocket_shutdown.map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "WebSocket close exceeded 2 seconds",
        )
    })??;
    client_shutdown?;
    stack_shutdown?;
    fixture_shutdown?;
    eprintln!(
        "bidirectional fairness: baseline_tunnel_max={:?} baseline_direct_max={:?} \
         pressure_batches={} pressure_tunnel_probes={} pressure_direct_probes={} \
         pressure_tunnel_max={:?} pressure_direct_max={:?} tcp_connect_max={:?} \
         http_ready_max={:?} response_head_max={:?} response_body_max={:?} \
         to_fixture_max={:?} from_fixture_max={:?}",
        baseline_health.max_tunneled_total,
        baseline_health.max_direct_total,
        health_report.batches,
        health_report.tunneled_probes,
        health_report.direct_probes,
        health_report.max_tunneled_total,
        health_report.max_direct_total,
        health_report.max_tunneled_tcp_connect,
        health_report.max_tunneled_http_ready,
        health_report.max_tunneled_response_head,
        health_report.max_tunneled_response_body,
        health_report.max_tunneled_to_fixture,
        health_report.max_tunneled_from_fixture,
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sequential_bulk_cycle_allows_a_second_upload_with_active_streams() -> TestResult<()> {
    let fixture_state = FixtureState::new(&Bytes::new());
    let fixture = FixtureHarness::start(fixture_state.clone()).await?;
    let stack = LiveStack::start_with_link_rate_limit(Some(LinkRateLimits {
        to_server_bytes_per_second: PRESSURE_TO_SERVER_BYTES_PER_SECOND,
        to_client_bytes_per_second: PRESSURE_TO_CLIENT_BYTES_PER_SECOND,
    }))
    .await?;
    let issued = stack.database.create_user("sequential-bulk-e2e").await?;
    let token = issued.token.expose_secret().to_owned();
    let hostname = "sequential-bulk.e2e.test";
    let client = ClientHarness::start(client_runtime(
        &token,
        stack.link.addr,
        fixture.addr,
        Some(hostname),
    )?);
    let inspection = client
        .handle
        .inspection_store()
        .ok_or_else(|| io::Error::other("inspection store unavailable"))?;
    assert_eq!(
        inspection.limits().body_preview_limit(),
        DEFAULT_BODY_PREVIEW_LIMIT
    );
    assert_eq!(client.connected().await?.hostname, hostname);
    let session_id = client.handle.session_id();

    let sse_request = Request::builder()
        .method(Method::GET)
        .uri("/sse")
        .body(Body::empty())?;
    let sse_response = public_send(stack.server.addr, hostname, sse_request).await?;
    if sse_response.status() != StatusCode::OK {
        return Err(
            io::Error::other(format!("sequential SSE returned {}", sse_response.status())).into(),
        );
    }
    let mut sse = SseProbe::new(sse_response.into_body());
    let websocket = public_websocket(stack.server.addr, hostname).await?;
    let activity_stop = CancellationToken::new();
    let sse_received = Arc::new(AtomicUsize::new(0));
    let websocket_echoes = Arc::new(AtomicUsize::new(0));

    let sse_task_stop = activity_stop.clone();
    let sse_task_received = Arc::clone(&sse_received);
    let mut sse_activity = AbortOnDropTask::new(tokio::spawn(async move {
        let mut minimum = 0_u64;
        loop {
            let sequence = tokio::select! {
                () = sse_task_stop.cancelled() => break,
                result = sse.sequence_at_least(minimum) => result?,
            };
            minimum = sequence.saturating_add(1);
            sse_task_received.fetch_add(1, Ordering::AcqRel);
        }
        Ok::<usize, TestError>(sse_task_received.load(Ordering::Acquire))
    }));

    let websocket_task_stop = activity_stop.clone();
    let websocket_task_echoes = Arc::clone(&websocket_echoes);
    let mut websocket_activity = AbortOnDropTask::new(tokio::spawn(async move {
        let mut websocket = websocket;
        loop {
            let echo = websocket_echo_progress(
                &mut websocket,
                Bytes::from_static(b"sequential-stream-activity"),
            );
            tokio::select! {
                () = websocket_task_stop.cancelled() => break,
                result = echo => result?,
            }
            websocket_task_echoes.fetch_add(1, Ordering::AcqRel);
            tokio::select! {
                () = websocket_task_stop.cancelled() => break,
                () = sleep(Duration::from_millis(100)) => {}
            }
        }
        timeout(HEALTH_LATENCY_BOUND, websocket.close(None))
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "WebSocket close exceeded 2 seconds",
                )
            })??;
        Ok::<usize, TestError>(websocket_task_echoes.load(Ordering::Acquire))
    }));

    tokio::try_join!(
        wait_for_counter_at_least(
            &sse_received,
            2,
            HEALTH_LATENCY_BOUND,
            "initial sequential SSE progress",
        ),
        wait_for_counter_at_least(
            &websocket_echoes,
            2,
            HEALTH_LATENCY_BOUND,
            "initial sequential WebSocket progress",
        ),
    )?;

    let scenario_result = timeout(SEQUENTIAL_SCENARIO_BOUND, async {
        let before = (
            sse_received.load(Ordering::Acquire),
            websocket_echoes.load(Ordering::Acquire),
        );
        complete_generated_upload(stack.server.addr, hostname).await?;
        require_long_lived_progress(
            &sse_received,
            &websocket_echoes,
            before,
            "long-lived streams during first upload",
        )
        .await?;

        let before = (
            sse_received.load(Ordering::Acquire),
            websocket_echoes.load(Ordering::Acquire),
        );
        complete_generated_download(stack.server.addr, hostname).await?;
        require_long_lived_progress(
            &sse_received,
            &websocket_echoes,
            before,
            "long-lived streams during download",
        )
        .await?;

        let before = (
            sse_received.load(Ordering::Acquire),
            websocket_echoes.load(Ordering::Acquire),
        );
        for id in 0..SEQUENTIAL_ORDINARY_REQUESTS {
            let (status, headers, body) = public_call(
                stack.server.addr,
                hostname,
                Method::GET,
                &format!("/ordinary/{id}"),
                HeaderMap::new(),
                Body::empty(),
            )
            .await?;
            let expected_id = id.to_string();
            let expected_body = format!("ordinary-{id}");
            if status != StatusCode::OK
                || headers
                    .get("x-ordinary-id")
                    .and_then(|value| value.to_str().ok())
                    != Some(expected_id.as_str())
                || body.as_ref() != expected_body.as_bytes()
            {
                return Err(io::Error::other(format!(
                    "ordinary request {id} returned an unexpected response"
                ))
                .into());
            }
        }
        require_long_lived_progress(
            &sse_received,
            &websocket_echoes,
            before,
            "long-lived streams during ordinary requests",
        )
        .await?;

        let before = (
            sse_received.load(Ordering::Acquire),
            websocket_echoes.load(Ordering::Acquire),
        );
        complete_generated_upload(stack.server.addr, hostname).await?;
        require_long_lived_progress(
            &sse_received,
            &websocket_echoes,
            before,
            "long-lived streams during second upload",
        )
        .await?;

        if client.handle.session_id() != session_id {
            return Err(
                io::Error::other("client session changed during sequential bulk cycle").into(),
            );
        }
        let uploads = inspection
            .list()
            .into_iter()
            .filter(|transaction| {
                transaction.request().method() == Method::PUT
                    && transaction.request().public_uri().path() == "/backpressured-upload"
            })
            .collect::<Vec<_>>();
        if uploads.len() != 2 {
            return Err(io::Error::other(format!(
                "inspection retained {} sequential uploads instead of 2",
                uploads.len()
            ))
            .into());
        }
        for upload in uploads {
            if upload.request().body().total_bytes() != PRESSURE_UPLOAD_BYTES as u64
                || upload.request().body().completion() != BodyCompletion::Complete
                || upload.response().map(|response| response.status()) != Some(StatusCode::OK)
                || upload.duration().is_none()
            {
                return Err(io::Error::other(format!(
                    "inspection did not retain a completed {PRESSURE_UPLOAD_BYTES}-byte upload"
                ))
                .into());
            }
        }
        Ok::<(), TestError>(())
    })
    .await
    .map_err(|_| -> TestError {
        Box::new(io::Error::new(
            io::ErrorKind::TimedOut,
            "sequential bulk scenario exceeded 60 seconds",
        ))
    })?;

    activity_stop.cancel();
    let sse_result = sse_activity.join("sequential SSE shutdown").await;
    let websocket_result = websocket_activity
        .join("sequential WebSocket shutdown")
        .await;
    let client_result = client.stop().await;
    let stack_result = stack.stop().await;
    let fixture_result = fixture.stop().await;

    scenario_result?;
    let received_events = sse_result??;
    let completed_echoes = websocket_result??;
    client_result?;
    stack_result?;
    fixture_result?;
    eprintln!(
        "sequential bulk: upload_bytes={PRESSURE_UPLOAD_BYTES} download_bytes={SEQUENTIAL_DOWNLOAD_BYTES} \
         ordinary_requests={SEQUENTIAL_ORDINARY_REQUESTS} sse_events={received_events} \
         websocket_echoes={completed_echoes} inspection_entries={}",
        inspection.len(),
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn outage_conflict_reclaim_and_interruption_do_not_replay() -> TestResult<()> {
    let payload = deterministic_payload(256 * 1024);
    let fixture_state = FixtureState::new(&payload);
    let fixture = FixtureHarness::start(fixture_state.clone()).await?;
    let fixture_addr = fixture.addr;
    let stack = LiveStack::start().await?;
    let issued = stack.database.create_user("reconnect-e2e").await?;
    let token = issued.token.expose_secret().to_owned();
    let hostname = "chosen.e2e.test";
    let client = ClientHarness::start(client_runtime(
        &token,
        stack.link.addr,
        fixture_addr,
        Some(hostname),
    )?);
    let session_id = client.handle.session_id();
    let first_info = client.connected().await?;
    assert_eq!(first_info.hostname, hostname);

    let unknown = public_call(
        stack.server.addr,
        "unknown.e2e.test",
        Method::GET,
        "/",
        HeaderMap::new(),
        Body::empty(),
    )
    .await?;
    assert_eq!(unknown.0, StatusCode::NOT_FOUND);

    let mut conflicting = client_runtime(&token, stack.link.addr, fixture_addr, Some(hostname))?;
    let conflict = bounded("custom hostname conflict", conflicting.run_one_connection())
        .await?
        .expect_err("the second active custom claim must conflict");
    assert!(matches!(
        conflict,
        RuntimeError::Rejected {
            code: sink_protocol::RejectCode::SubdomainConflict
        }
    ));
    assert_eq!(conflict.disposition(), FailureDisposition::Permanent);

    fixture.stop().await?;
    let outage_started = Instant::now();
    let unavailable = public_call(
        stack.server.addr,
        hostname,
        Method::GET,
        "/ordinary/1",
        HeaderMap::new(),
        Body::empty(),
    )
    .await?;
    assert_eq!(unavailable.0, StatusCode::SERVICE_UNAVAILABLE);
    assert!(outage_started.elapsed() < Duration::from_secs(4));

    let fixture = FixtureHarness::start_on(fixture_addr, fixture_state.clone()).await?;
    wait_for_public_status(
        "local target recovery",
        stack.server.addr,
        hostname,
        StatusCode::OK,
    )
    .await?;

    let cancellation_started = fixture_state.side_effect_started.notified();
    let cancel_addr = stack.server.addr;
    let cancel_host = hostname.to_owned();
    let cancelled_request = tokio::spawn(async move {
        public_call(
            cancel_addr,
            &cancel_host,
            Method::POST,
            "/side-effect",
            HeaderMap::new(),
            Body::empty(),
        )
        .await
    });
    bounded("local side effect start", cancellation_started).await?;
    wait_for_counter(&fixture_state.side_effects, 1).await?;
    cancelled_request.abort();
    let _ = cancelled_request.await;
    wait_for_counter(&fixture_state.slow_active, 0).await?;
    assert_eq!(fixture_state.side_effects.load(Ordering::Acquire), 1);

    let interruption_started = fixture_state.side_effect_started.notified();
    let interrupted_addr = stack.server.addr;
    let interrupted_host = hostname.to_owned();
    let interrupted_request = tokio::spawn(async move {
        public_call(
            interrupted_addr,
            &interrupted_host,
            Method::POST,
            "/side-effect",
            HeaderMap::new(),
            Body::empty(),
        )
        .await
    });
    bounded("interrupted side effect start", interruption_started).await?;
    wait_for_counter(&fixture_state.side_effects, 2).await?;
    stack.link.cut();
    wait_for_public_status(
        "known disconnected response",
        stack.server.addr,
        hostname,
        StatusCode::SERVICE_UNAVAILABLE,
    )
    .await?;
    let interrupted_result = bounded("interrupted request failure", interrupted_request).await??;
    assert!(match interrupted_result.as_ref() {
        Ok((status, _, _)) => *status == StatusCode::SERVICE_UNAVAILABLE,
        Err(_) => true,
    });
    wait_for_counter(&fixture_state.slow_active, 0).await?;
    sleep(Duration::from_millis(300)).await;
    assert_eq!(fixture_state.side_effects.load(Ordering::Acquire), 2);

    stack.link.resume();
    wait_for_public_status(
        "same-run reclaim",
        stack.server.addr,
        hostname,
        StatusCode::OK,
    )
    .await?;
    let reclaimed = client.connected().await?;
    assert_eq!(reclaimed.hostname, first_info.hostname);
    assert_eq!(client.handle.session_id(), session_id);
    assert_eq!(fixture_state.side_effects.load(Ordering::Acquire), 2);

    client.stop().await?;

    stack.stop().await?;
    fixture.stop().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rotation_and_disable_close_tunnels_and_credentials_fail_permanently() -> TestResult<()> {
    let payload = deterministic_payload(64 * 1024);
    let fixture_state = FixtureState::new(&payload);
    let fixture = FixtureHarness::start(fixture_state).await?;
    let stack = LiveStack::start().await?;
    let issued = stack.database.create_user("revocation-e2e").await?;
    let old_token = issued.token.expose_secret().to_owned();
    let hostname = "revoked.e2e.test";

    let old_client = ClientHarness::start(client_runtime(
        &old_token,
        stack.server.addr,
        fixture.addr,
        Some(hostname),
    )?);
    assert_eq!(old_client.connected().await?.hostname, hostname);

    let rotated = stack.database.rotate_token("revocation-e2e").await?;
    let new_token = rotated.token.expose_secret().to_owned();
    let old_result = old_client.finish().await?;
    let old_error = old_result.expect_err("rotated credential must stop reconnecting");
    assert_eq!(old_error.disposition(), FailureDisposition::Permanent);
    wait_for_public_status(
        "rotation claim release",
        stack.server.addr,
        hostname,
        StatusCode::NOT_FOUND,
    )
    .await?;

    let mut rejected_old =
        client_runtime(&old_token, stack.server.addr, fixture.addr, Some(hostname))?;
    let old_rejection = bounded("old token rejection", rejected_old.run_one_connection())
        .await?
        .expect_err("old credential must remain invalid");
    assert_eq!(old_rejection.disposition(), FailureDisposition::Permanent);

    let enabled_client = ClientHarness::start(client_runtime(
        &new_token,
        stack.server.addr,
        fixture.addr,
        Some(hostname),
    )?);
    assert_eq!(enabled_client.connected().await?.hostname, hostname);
    stack.database.disable_user("revocation-e2e").await?;
    let disabled_result = enabled_client.finish().await?;
    let disabled_error = disabled_result.expect_err("disabled user must stop reconnecting");
    assert_eq!(disabled_error.disposition(), FailureDisposition::Permanent);
    wait_for_public_status(
        "disable claim release",
        stack.server.addr,
        hostname,
        StatusCode::NOT_FOUND,
    )
    .await?;

    stack.database.enable_user("revocation-e2e").await?;
    let recovered_client = ClientHarness::start(client_runtime(
        &new_token,
        stack.server.addr,
        fixture.addr,
        Some(hostname),
    )?);
    assert_eq!(recovered_client.connected().await?.hostname, hostname);
    wait_for_public_status(
        "enabled credential recovery",
        stack.server.addr,
        hostname,
        StatusCode::OK,
    )
    .await?;
    recovered_client.stop().await?;

    stack.stop().await?;
    fixture.stop().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn clean_shutdown_releases_custom_claim_immediately() -> TestResult<()> {
    let payload = deterministic_payload(1024);
    let fixture = FixtureHarness::start(FixtureState::new(&payload)).await?;
    let stack = LiveStack::start().await?;
    let issued = stack.database.create_user("clean-release-e2e").await?;
    let token = issued.token.expose_secret().to_owned();
    let hostname = "clean-release.e2e.test";
    let client = ClientHarness::start(client_runtime(
        &token,
        stack.server.addr,
        fixture.addr,
        Some(hostname),
    )?);
    assert_eq!(client.connected().await?.hostname, hostname);

    client.stop().await?;
    wait_for_public_status_within(
        Duration::from_secs(2),
        "clean shutdown claim release",
        stack.server.addr,
        hostname,
        StatusCode::NOT_FOUND,
    )
    .await?;

    stack.stop().await?;
    fixture.stop().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn single_route_http_compatibility_serves_root_pool_http_and_https() -> TestResult<()> {
    let payload = deterministic_payload(256 * 1024);
    let fixture = FixtureHarness::start(FixtureState::new(&payload)).await?;
    let stack = ManagedTlsStack::start().await?;
    let issued = stack.database.create_user("managed-root-e2e").await?;
    let token = issued.token.expose_secret().to_owned();
    let server = stack.server()?;
    let client = ClientHarness::start(client_runtime(
        &token,
        server.http_addr,
        fixture.addr,
        None,
    )?);
    let info = client.connected().await?;
    assert_eq!(
        Hostname::parse(&info.hostname)?.depth_below(&Hostname::parse(PUBLIC_BASE_DOMAIN)?),
        Some(1),
        "generated sink http route must stay in the root pool"
    );

    let (http_status, http_headers, http_body) = public_call(
        server.http_addr,
        &info.hostname,
        Method::GET,
        "/inspect/root-pool?transport=http",
        HeaderMap::new(),
        Body::empty(),
    )
    .await?;
    assert_eq!(http_status, StatusCode::CREATED);
    assert!(!http_status.is_redirection());
    assert!(!http_headers.contains_key(LOCATION));
    assert!(String::from_utf8(http_body.to_vec())?.contains("x-forwarded-proto=http"));

    let base_certificate = stack.certificates.certificate_for(PUBLIC_BASE_DOMAIN)?;
    let (https_status, https_headers, https_body) = public_tls_call(
        server.https_addr,
        &info.hostname,
        &info.hostname,
        &base_certificate,
        Method::GET,
        "/inspect/root-pool?transport=https",
        Body::empty(),
    )
    .await?;
    assert_eq!(https_status, StatusCode::CREATED);
    assert!(!https_status.is_redirection());
    assert!(!https_headers.contains_key(LOCATION));
    assert!(String::from_utf8(https_body.to_vec())?.contains("x-forwarded-proto=https"));

    let upload_chunks: Vec<Bytes> = payload
        .chunks(8 * 1024)
        .map(Bytes::copy_from_slice)
        .collect();
    let (upload_status, _, upload_body) = public_tls_call(
        server.https_addr,
        &info.hostname,
        &info.hostname,
        &base_certificate,
        Method::PUT,
        "/upload",
        Body::from_stream(tokio_stream::iter(
            upload_chunks.into_iter().map(Ok::<Bytes, Infallible>),
        )),
    )
    .await?;
    assert_eq!(upload_status, StatusCode::OK);
    let upload_body = String::from_utf8(upload_body.to_vec())?;
    assert!(upload_body.contains("bytes=262144"));
    assert!(upload_body.contains(&format!("sha256={}", digest_hex(&Sha256::digest(&payload)))));

    let (download_status, _, download) = public_tls_call(
        server.https_addr,
        &info.hostname,
        &info.hostname,
        &base_certificate,
        Method::GET,
        "/download",
        Body::empty(),
    )
    .await?;
    assert_eq!(download_status, StatusCode::OK);
    assert_eq!(download, payload);

    let mut websocket =
        public_tls_websocket(server.https_addr, &info.hostname, &base_certificate).await?;
    websocket_echo_progress(&mut websocket, Bytes::from_static(b"https-full-duplex-one")).await?;
    websocket_echo_progress(&mut websocket, Bytes::from_static(b"https-full-duplex-two")).await?;
    bounded("HTTPS WebSocket close", websocket.close(None)).await??;

    client.stop().await?;
    stack.stop().await?;
    fixture.stop().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn passthrough_namespace_management_is_immediate_durable_and_conflict_safe() -> TestResult<()>
{
    let payload = Bytes::from_static(b"passthrough-management-route");
    let fixture = FixtureHarness::start(FixtureState::new(&payload)).await?;
    let mut stack =
        ManagedTlsStack::start_with_https_proxy(Some(required_v2_proxy("127.0.0.0/8")?)).await?;
    let owner = stack.database.create_user("passthrough-owner-e2e").await?;
    let intruder = stack
        .database
        .create_user("passthrough-intruder-e2e")
        .await?;
    let owner_token = owner.token.expose_secret().to_owned();
    let intruder_token = intruder.token.expose_secret().to_owned();
    let namespace = "edge.e2e.test";

    let (status, created) =
        claim_passthrough_namespace(stack.server()?.http_addr, &owner_token, namespace).await?;
    assert_eq!(status, StatusCode::CREATED);
    passthrough_namespace(&created, namespace, 1)?;

    let (status, idempotent) =
        claim_passthrough_namespace(stack.server()?.http_addr, &owner_token, namespace).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(idempotent, created);

    let listed = list_namespaces(stack.server()?.http_addr, &owner_token).await?;
    passthrough_namespace(&listed, namespace, 1)?;
    assert_eq!(
        String::from_utf8_lossy(&listed)
            .matches(r#""hostname":"#)
            .count(),
        1
    );
    let (status, body) =
        namespace_status(stack.server()?.http_addr, &owner_token, namespace).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, created);

    let (status, body) = namespace_request(
        stack.server()?.http_addr,
        &intruder_token,
        Method::POST,
        NAMESPACE_COLLECTION_PATH,
        Body::from(format!(
            r#"{{"hostname":"{namespace}","tls_mode":"passthrough"}}"#
        )),
    )
    .await?;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(management_error_code(&body)?, "namespace_unavailable");

    let (status, body) = namespace_request(
        stack.server()?.http_addr,
        &owner_token,
        Method::POST,
        NAMESPACE_COLLECTION_PATH,
        Body::from(format!(r#"{{"hostname":"{namespace}"}}"#)),
    )
    .await?;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(management_error_code(&body)?, "namespace_mode_conflict");

    let child = "api.edge.e2e.test";
    let child_body = format!(r#"{{"hostname":"{child}","tls_mode":"passthrough"}}"#);
    let (status, body) = namespace_request(
        stack.server()?.http_addr,
        &intruder_token,
        Method::POST,
        NAMESPACE_COLLECTION_PATH,
        Body::from(child_body.clone()),
    )
    .await?;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(
        management_error_code(&body)?,
        "parent_namespace_unavailable"
    );
    let (status, body) = namespace_request(
        stack.server()?.http_addr,
        &owner_token,
        Method::POST,
        NAMESPACE_COLLECTION_PATH,
        Body::from(child_body),
    )
    .await?;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(management_error_code(&body)?, "wildcard_conflict");

    let exact_hostname = "preexisting.e2e.test";
    let exact = ClientHarness::start(client_runtime(
        &owner_token,
        stack.server()?.http_addr,
        fixture.addr,
        Some(exact_hostname),
    )?);
    assert_eq!(exact.connected().await?.hostname, exact_hostname);
    let exact_body = format!(r#"{{"hostname":"{exact_hostname}","tls_mode":"passthrough"}}"#);
    let (status, body) = namespace_request(
        stack.server()?.http_addr,
        &owner_token,
        Method::POST,
        NAMESPACE_COLLECTION_PATH,
        Body::from(exact_body.clone()),
    )
    .await?;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(management_error_code(&body)?, "wildcard_conflict");
    exact.stop().await?;
    wait_for_public_status(
        "preexisting exact release",
        stack.server()?.http_addr,
        exact_hostname,
        StatusCode::NOT_FOUND,
    )
    .await?;
    let (status, body) = namespace_request(
        stack.server()?.http_addr,
        &owner_token,
        Method::POST,
        NAMESPACE_COLLECTION_PATH,
        Body::from(exact_body),
    )
    .await?;
    assert_eq!(status, StatusCode::CREATED);
    passthrough_namespace(&body, exact_hostname, 1)?;

    for invalid_body in [
        r#"{"hostname":"invalid.e2e.test","tls_mode":"edge"}"#,
        r#"{"hostname":"too.deep.invalid.e2e.test","tls_mode":"passthrough"}"#,
    ] {
        let (status, body) = namespace_request(
            stack.server()?.http_addr,
            &owner_token,
            Method::POST,
            NAMESPACE_COLLECTION_PATH,
            Body::from(invalid_body),
        )
        .await?;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(matches!(
            management_error_code(&body)?.as_str(),
            "invalid_tls_mode" | "invalid_hostname"
        ));
    }

    stack.restart_server().await?;
    let listed = list_namespaces(stack.server()?.http_addr, &owner_token).await?;
    assert_eq!(
        String::from_utf8_lossy(&listed)
            .matches(r#""hostname":"#)
            .count(),
        2
    );
    passthrough_namespace(&listed, namespace, 1)?;
    passthrough_namespace(&listed, exact_hostname, 1)?;
    let (status, body) =
        namespace_status(stack.server()?.http_addr, &owner_token, namespace).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, created);

    for hostname in [namespace, exact_hostname] {
        let (status, body) =
            release_namespace(stack.server()?.http_addr, &owner_token, hostname).await?;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert!(body.is_empty());
        let (status, _) =
            namespace_status(stack.server()?.http_addr, &owner_token, hostname).await?;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }
    assert_eq!(
        list_namespaces(stack.server()?.http_addr, &owner_token).await?,
        r#"{"namespaces":[]}"#
    );

    stack.stop().await?;
    fixture.stop().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn passthrough_route_preserves_http_tls_proxy_metadata_and_restart_isolation()
-> TestResult<()> {
    let payload = deterministic_payload(512 * 1024);
    let fixture_state = FixtureState::new(&payload);
    let fixture = FixtureHarness::start(fixture_state).await?;
    let process_files = tempfile::tempdir()?;
    let namespace = "edge.e2e.test";
    let child = "api.edge.e2e.test";
    let deep = "deep.api.edge.e2e.test";
    let mut edge = EdgeTlsFixture::start(process_files.path(), namespace).await?;
    let mut stack =
        ManagedTlsStack::start_with_https_proxy(Some(required_v2_proxy("127.0.0.0/8")?)).await?;
    let issued = stack.database.create_user("passthrough-route-e2e").await?;
    let token = issued.token.expose_secret().to_owned();
    let (status, claim) =
        claim_passthrough_namespace(stack.server()?.http_addr, &token, namespace).await?;
    assert_eq!(status, StatusCode::CREATED);
    passthrough_namespace(&claim, namespace, 1)?;

    let config_path = process_files.path().join("passthrough-routes.toml");
    std::fs::write(
        &config_path,
        format!(
            r#"
[[routes]]
name = "edge"
url = "https://{namespace}"
target = "http://{}"
tls_target = "tcp://{}"
proxy_protocol = "v2"
inspect = false
"#,
            fixture.addr, edge.addr
        ),
    )?;
    let mut process = MultiConnectProcess::start(
        &config_path,
        &process_files.path().join("config-home"),
        &token,
        stack.server()?.http_addr,
    )?;

    wait_for_public_body(
        "passthrough apex HTTP",
        stack.server()?.http_addr,
        namespace,
        "/download",
        &payload,
    )
    .await?;
    wait_for_public_body(
        "passthrough direct-child HTTP",
        stack.server()?.http_addr,
        child,
        "/download",
        &payload,
    )
    .await?;
    let (status, _, body) = public_call(
        stack.server()?.http_addr,
        deep,
        Method::GET,
        "/download",
        HeaderMap::new(),
        Body::empty(),
    )
    .await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body, "tunnel not found\n");

    let mut exact_override =
        client_runtime(&token, stack.server()?.http_addr, fixture.addr, Some(child))?;
    let error = bounded(
        "passthrough exact-route override rejection",
        exact_override.run_one_connection(),
    )
    .await?
    .expect_err("an exact route must not shadow passthrough ownership");
    assert!(matches!(
        error,
        RuntimeError::Rejected {
            code: sink_protocol::RejectCode::InvalidSubdomain
        }
    ));
    assert_eq!(error.disposition(), FailureDisposition::Permanent);

    websocket_round_trip(
        stack.server()?.http_addr,
        child,
        Bytes::from_static(b"passthrough-http-websocket"),
    )
    .await?;
    let sse_request = Request::builder()
        .method(Method::GET)
        .uri("/sse")
        .body(Body::empty())?;
    let sse_response = public_send(stack.server()?.http_addr, namespace, sse_request).await?;
    assert_eq!(sse_response.status(), StatusCode::OK);
    let mut sse = SseProbe::new(sse_response.into_body());
    assert!(sse.sequence_at_least(2).await? >= 2);
    drop(sse);

    let ipv4_source: SocketAddr = "198.51.100.27:43111".parse()?;
    let ipv4_destination: SocketAddr = "203.0.113.8:443".parse()?;
    let incoming_v4 = proxy_v2_with_test_tlv(ipv4_source, ipv4_destination)?;
    let observation_index = edge.observation_count();
    let client_wire = edge_tls_round_trip(
        stack.server()?.https_addr,
        incoming_v4.clone(),
        child,
        edge.certificate_path(),
    )
    .await?;
    let observed = edge.observation(observation_index).await?;
    let expected_v4 = ProxyV2Header::proxied(ipv4_source, ipv4_destination)?;
    assert_eq!(observed.proxy, expected_v4);
    assert_eq!(observed.proxy_wire, expected_v4.encode()?);
    assert_ne!(observed.proxy_wire, incoming_v4);
    assert!(!observed.tls_wire.is_empty());
    assert_eq!(client_wire, observed.tls_wire);

    let ipv6_source: SocketAddr = "[2001:db8:1::27]:53111".parse()?;
    let ipv6_destination: SocketAddr = "[2001:db8:2::8]:443".parse()?;
    let incoming_v6 = proxy_v2_with_test_tlv(ipv6_source, ipv6_destination)?;
    let observation_index = edge.observation_count();
    let client_wire = edge_tls_round_trip(
        stack.server()?.https_addr,
        incoming_v6.clone(),
        namespace,
        edge.certificate_path(),
    )
    .await?;
    let observed = edge.observation(observation_index).await?;
    let expected_v6 = ProxyV2Header::proxied(ipv6_source, ipv6_destination)?;
    assert_eq!(observed.proxy, expected_v6);
    assert_eq!(observed.proxy_wire, expected_v6.encode()?);
    assert_ne!(observed.proxy_wire, incoming_v6);
    assert!(!observed.tls_wire.is_empty());
    assert_eq!(client_wire, observed.tls_wire);

    let successful_observations = edge.observation_count();
    for unsupported in ["unsupported.e2e.test", deep] {
        assert_prefixed_tls_handshake_rejected(
            stack.server()?.https_addr,
            ProxyV2Header::proxied(ipv4_source, ipv4_destination)?.encode()?,
            unsupported,
            edge.certificate_path(),
        )
        .await?;
    }
    assert_eq!(edge.observation_count(), successful_observations);

    edge.stop().await?;
    assert_prefixed_tls_handshake_rejected(
        stack.server()?.https_addr,
        ProxyV2Header::proxied(ipv4_source, ipv4_destination)?.encode()?,
        child,
        edge.certificate_path(),
    )
    .await?;
    wait_for_public_body(
        "HTTP remains healthy during raw target outage",
        stack.server()?.http_addr,
        child,
        "/download",
        &payload,
    )
    .await?;
    process.assert_running()?;
    edge.restart().await?;
    let observation_index = edge.observation_count();
    edge_tls_round_trip(
        stack.server()?.https_addr,
        ProxyV2Header::proxied(ipv4_source, ipv4_destination)?.encode()?,
        child,
        edge.certificate_path(),
    )
    .await?;
    edge.observation(observation_index).await?;

    process.stop_gracefully().await?;
    wait_for_public_status(
        "durable disconnected passthrough HTTP",
        stack.server()?.http_addr,
        child,
        StatusCode::SERVICE_UNAVAILABLE,
    )
    .await?;
    assert_prefixed_tls_handshake_rejected(
        stack.server()?.https_addr,
        ProxyV2Header::proxied(ipv4_source, ipv4_destination)?.encode()?,
        child,
        edge.certificate_path(),
    )
    .await?;

    process = MultiConnectProcess::start(
        &config_path,
        &process_files.path().join("config-home-reconnect"),
        &token,
        stack.server()?.http_addr,
    )?;
    wait_for_public_body(
        "passthrough client reconnect",
        stack.server()?.http_addr,
        child,
        "/download",
        &payload,
    )
    .await?;
    let observation_index = edge.observation_count();
    edge_tls_round_trip(
        stack.server()?.https_addr,
        ProxyV2Header::proxied(ipv6_source, ipv6_destination)?.encode()?,
        namespace,
        edge.certificate_path(),
    )
    .await?;
    edge.observation(observation_index).await?;

    stack.restart_server().await?;
    wait_for_public_body(
        "passthrough route after server restart",
        stack.server()?.http_addr,
        namespace,
        "/download",
        &payload,
    )
    .await?;
    let persisted = list_namespaces(stack.server()?.http_addr, &token).await?;
    passthrough_namespace(&persisted, namespace, 1)?;
    assert_eq!(
        String::from_utf8_lossy(&persisted)
            .matches(r#""hostname":"#)
            .count(),
        1
    );
    let observation_index = edge.observation_count();
    edge_tls_round_trip(
        stack.server()?.https_addr,
        ProxyV2Header::proxied(ipv4_source, ipv4_destination)?.encode()?,
        child,
        edge.certificate_path(),
    )
    .await?;
    edge.observation(observation_index).await?;
    process.assert_running()?;

    process.stop().await?;
    stack.stop().await?;
    edge.stop().await?;
    fixture.stop().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn required_proxy_v2_ingress_rejects_missing_malformed_oversized_local_and_untrusted()
-> TestResult<()> {
    let stack =
        ManagedTlsStack::start_with_https_proxy(Some(required_v2_proxy("127.0.0.0/8")?)).await?;
    let https_addr = stack.server()?.https_addr;

    let mut missing = vec![0_u8; PROXY_V2_PREFIX_BYTES];
    missing[..5].copy_from_slice(&[0x16, 0x03, 0x03, 0, 11]);
    assert_raw_connection_rejected(https_addr, &missing).await?;
    assert_raw_connection_rejected(https_addr, &[0_u8; PROXY_V2_PREFIX_BYTES]).await?;
    assert_raw_connection_rejected(https_addr, &oversized_proxy_v2_prefix()).await?;
    assert_raw_connection_rejected(https_addr, &ProxyV2Header::local().encode()?).await?;
    stack.stop().await?;

    let untrusted =
        ManagedTlsStack::start_with_https_proxy(Some(required_v2_proxy("192.0.2.0/24")?)).await?;
    assert_raw_connection_rejected(
        untrusted.server()?.https_addr,
        &ProxyV2Header::proxied("198.51.100.40:50000".parse()?, "203.0.113.9:443".parse()?)?
            .encode()?,
    )
    .await?;
    untrusted.stop().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn persistent_nested_namespace_owns_routing_and_most_specific_tls() -> TestResult<()> {
    let payload = Bytes::from_static(b"nested-namespace-response");
    let fixture = FixtureHarness::start(FixtureState::new(&payload)).await?;
    let mut stack = ManagedTlsStack::start().await?;
    let owner = stack.database.create_user("namespace-owner-e2e").await?;
    let intruder = stack.database.create_user("namespace-intruder-e2e").await?;
    let owner_token = owner.token.expose_secret().to_owned();
    let intruder_token = intruder.token.expose_secret().to_owned();
    let parent = "team.e2e.test";
    let child = "edge.team.e2e.test";

    let (status, body) = claim_namespace(stack.server()?.http_addr, &owner_token, parent).await?;
    assert_eq!(status, StatusCode::CREATED);
    active_namespace(&body, parent, 1)?;

    let (status, body) = claim_namespace(stack.server()?.http_addr, &intruder_token, child).await?;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(
        std::str::from_utf8(&body)?.contains("parent_namespace_unavailable"),
        "unexpected adjacent-parent rejection: {}",
        String::from_utf8_lossy(&body)
    );

    let (status, body) = claim_namespace(stack.server()?.http_addr, &owner_token, child).await?;
    assert_eq!(status, StatusCode::CREATED);
    active_namespace(&body, child, 2)?;

    stack.restart_server().await?;
    let server = stack.server()?;
    let route = "api.edge.team.e2e.test";
    let client = ClientHarness::start(client_runtime(
        &owner_token,
        server.http_addr,
        fixture.addr,
        Some(route),
    )?);
    assert_eq!(client.connected().await?.hostname, route);

    let (http_status, _, http_body) = public_call(
        server.http_addr,
        route,
        Method::GET,
        "/download",
        HeaderMap::new(),
        Body::empty(),
    )
    .await?;
    assert_eq!(http_status, StatusCode::OK);
    assert_eq!(http_body, payload);

    let child_certificate = stack.certificates.certificate_for(child)?;
    let (https_status, _, https_body) = public_tls_call(
        server.https_addr,
        route,
        route,
        &child_certificate,
        Method::GET,
        "/download",
        Body::empty(),
    )
    .await?;
    assert_eq!(https_status, StatusCode::OK);
    assert_eq!(https_body, payload);

    let (mismatch_status, _, mismatch_body) = public_tls_call(
        server.https_addr,
        route,
        "other.edge.team.e2e.test",
        &child_certificate,
        Method::GET,
        "/download",
        Body::empty(),
    )
    .await?;
    assert_eq!(mismatch_status, StatusCode::MISDIRECTED_REQUEST);
    assert_eq!(mismatch_body, "TLS SNI and HTTP Host do not match\n");

    assert_tls_handshake_rejected(
        server.https_addr,
        "unused.edge.team.e2e.test",
        &child_certificate,
    )
    .await?;

    let mut unauthorized =
        client_runtime(&intruder_token, server.http_addr, fixture.addr, Some(route))?;
    let error = bounded(
        "nested namespace route ownership rejection",
        unauthorized.run_one_connection(),
    )
    .await?
    .expect_err("an adjacent-parent outsider must not route inside the namespace");
    assert!(matches!(
        error,
        RuntimeError::Rejected {
            code: sink_protocol::RejectCode::InvalidSubdomain
        }
    ));
    assert_eq!(error.disposition(), FailureDisposition::Permanent);

    client.stop().await?;
    stack.stop().await?;
    fixture.stop().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pending_child_boundary_blocks_parent_wildcard_fallback() -> TestResult<()> {
    let payload = Bytes::from_static(b"pending-boundary-route");
    let fixture = FixtureHarness::start(FixtureState::new(&payload)).await?;
    let stack = ManagedTlsStack::start().await?;
    let issued = stack.database.create_user("pending-boundary-e2e").await?;
    let token = issued.token.expose_secret().to_owned();
    let parent = "pending.e2e.test";
    let child = "api.pending.e2e.test";

    let (status, body) = claim_namespace(stack.server()?.http_addr, &token, parent).await?;
    assert_eq!(status, StatusCode::CREATED);
    active_namespace(&body, parent, 1)?;

    let server = stack.server()?;
    let client = ClientHarness::start(client_runtime(
        &token,
        server.http_addr,
        fixture.addr,
        Some(child),
    )?);
    assert_eq!(client.connected().await?.hostname, child);
    let parent_certificate = stack.certificates.certificate_for(parent)?;
    let (status, _, body) = public_tls_call(
        server.https_addr,
        child,
        child,
        &parent_certificate,
        Method::GET,
        "/download",
        Body::empty(),
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, payload);

    stack.certificates.set_pending(child);
    let (status, body) = claim_namespace(server.http_addr, &token, child).await?;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert!(std::str::from_utf8(&body)?.contains(r#""state":"pending""#));

    let (http_status, _, http_body) = public_call(
        server.http_addr,
        child,
        Method::GET,
        "/download",
        HeaderMap::new(),
        Body::empty(),
    )
    .await?;
    assert_eq!(http_status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(http_body, "tunnel unavailable\n");
    assert_tls_handshake_rejected(server.https_addr, child, &parent_certificate).await?;

    client.stop().await?;
    stack.stop().await?;
    fixture.stop().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn multi_connect_route_failure_and_reconnect_preserve_healthy_sibling() -> TestResult<()> {
    let healthy_payload = Bytes::from_static(b"healthy-route");
    let incumbent_payload = Bytes::from_static(b"incumbent-route");
    let recovered_payload = Bytes::from_static(b"recovered-route");
    let healthy_fixture = FixtureHarness::start(FixtureState::new(&healthy_payload)).await?;
    let incumbent_fixture = FixtureHarness::start(FixtureState::new(&incumbent_payload)).await?;
    let recovered_fixture = FixtureHarness::start(FixtureState::new(&recovered_payload)).await?;
    let stack = LiveStack::start().await?;
    let issued = stack.database.create_user("multi-connect-live-e2e").await?;
    let token = issued.token.expose_secret().to_owned();
    let healthy_hostname = "healthy-multi.e2e.test";
    let flaky_hostname = "flaky-multi.e2e.test";

    let incumbent = ClientHarness::start(client_runtime(
        &token,
        stack.server.addr,
        incumbent_fixture.addr,
        Some(flaky_hostname),
    )?);
    assert_eq!(incumbent.connected().await?.hostname, flaky_hostname);

    let process_files = tempfile::tempdir()?;
    let config_path = process_files.path().join("routes.toml");
    std::fs::write(
        &config_path,
        format!(
            r#"
[[routes]]
name = "healthy"
url = "https://{healthy_hostname}"
target = "http://{}"
inspect = false

[[routes]]
name = "flaky"
url = "https://{flaky_hostname}"
target = "http://{}"
inspect = false
"#,
            healthy_fixture.addr, recovered_fixture.addr
        ),
    )?;
    let mut process = MultiConnectProcess::start(
        &config_path,
        &process_files.path().join("config-home"),
        &token,
        stack.server.addr,
    )?;

    wait_for_public_body(
        "healthy multi-connect sibling",
        stack.server.addr,
        healthy_hostname,
        "/download",
        &healthy_payload,
    )
    .await?;
    wait_for_public_body(
        "incumbent conflicting route",
        stack.server.addr,
        flaky_hostname,
        "/download",
        &incumbent_payload,
    )
    .await?;
    process.assert_running()?;

    incumbent.stop().await?;
    wait_for_public_body(
        "failed route independent retry",
        stack.server.addr,
        flaky_hostname,
        "/download",
        &recovered_payload,
    )
    .await?;
    wait_for_public_body(
        "healthy sibling after route recovery",
        stack.server.addr,
        healthy_hostname,
        "/download",
        &healthy_payload,
    )
    .await?;
    process.assert_running()?;

    process.stop().await?;
    stack.stop().await?;
    healthy_fixture.stop().await?;
    incumbent_fixture.stop().await?;
    recovered_fixture.stop().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn websocket_upgrade_is_full_duplex() -> TestResult<()> {
    let payload = deterministic_payload(1024);
    let fixture = FixtureHarness::start(FixtureState::new(&payload)).await?;
    let stack = LiveStack::start().await?;
    let issued = stack.database.create_user("websocket-e2e").await?;
    let token = issued.token.expose_secret().to_owned();
    let hostname = "websocket.e2e.test";
    let client = ClientHarness::start(client_runtime(
        &token,
        stack.server.addr,
        fixture.addr,
        Some(hostname),
    )?);
    assert_eq!(client.connected().await?.hostname, hostname);

    websocket_round_trip(
        stack.server.addr,
        hostname,
        Bytes::from_static(b"full-duplex-through-yamux"),
    )
    .await?;

    client.stop().await?;
    stack.stop().await?;
    fixture.stop().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cors_policy_survives_the_tunnel_and_captures_preflight() -> TestResult<()> {
    use axum::http::header::*;
    let stack = LiveStack::start().await?;
    let token = stack
        .database
        .create_user("cors-user")
        .await?
        .token
        .expose_secret()
        .to_owned();
    for (origins, credentials) in [(vec!["https://app.example.com"], true), (vec!["*"], false)] {
        let fixture = FixtureHarness::start(FixtureState::new(&Bytes::new())).await?;
        let client = ClientHarness::start(client_runtime_with_cors(
            &token,
            stack.link.addr,
            fixture.addr,
            None,
            &origins,
            credentials,
        )?);
        let info = client.connected().await?;
        let store = client
            .handle
            .inspection_store()
            .ok_or_else(|| io::Error::other("store missing"))?;
        let mut summaries = client.handle.subscribe_requests();
        let expected_origin = if credentials {
            "https://app.example.com"
        } else {
            "*"
        };
        let mut headers = HeaderMap::new();
        headers.insert(ORIGIN, HeaderValue::from_static("https://app.example.com"));
        headers.insert(
            ACCESS_CONTROL_REQUEST_METHOD,
            HeaderValue::from_static("PATCH"),
        );
        headers.insert(
            ACCESS_CONTROL_REQUEST_HEADERS,
            HeaderValue::from_static("Authorization, X-App"),
        );
        // This nonexistent endpoint proves the client handles preflight, not upstream.
        let (status, response_headers, body) = public_call(
            stack.server.addr,
            &info.hostname,
            Method::OPTIONS,
            "/cors-preflight",
            headers.clone(),
            Body::empty(),
        )
        .await?;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let summary = bounded("preflight summary", summaries.recv()).await??;
        assert_eq!(summary.status, StatusCode::NO_CONTENT);
        assert_eq!(summary.method, Method::OPTIONS);
        assert_eq!(summary.response_bytes, 0);
        assert!(body.is_empty());
        assert_eq!(
            response_headers[ACCESS_CONTROL_ALLOW_ORIGIN],
            expected_origin
        );
        assert_eq!(
            response_headers[ACCESS_CONTROL_ALLOW_HEADERS],
            "authorization, x-app"
        );
        assert_eq!(response_headers[ACCESS_CONTROL_ALLOW_METHODS], "PATCH");
        assert_eq!(
            response_headers.contains_key(ACCESS_CONTROL_ALLOW_CREDENTIALS),
            credentials
        );
        let captured = store
            .list()
            .into_iter()
            .find(|transaction| transaction.request().public_uri().path() == "/cors-preflight")
            .ok_or_else(|| io::Error::other("preflight missing"))?;
        assert!(captured.lifecycle().is_terminal());
        let snapshot = captured
            .response()
            .ok_or_else(|| io::Error::other("response missing"))?;
        assert_eq!(snapshot.status(), StatusCode::NO_CONTENT);
        assert!(
            snapshot
                .headers()
                .iter()
                .any(|header| header.name() == ACCESS_CONTROL_ALLOW_ORIGIN)
        );

        headers.remove(ACCESS_CONTROL_REQUEST_METHOD);
        headers.remove(ACCESS_CONTROL_REQUEST_HEADERS);
        headers.insert(COOKIE, HeaderValue::from_static("session=test"));
        let (status, response_headers, _) = public_call(
            stack.server.addr,
            &info.hostname,
            Method::GET,
            "/health",
            headers.clone(),
            Body::empty(),
        )
        .await?;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            response_headers[ACCESS_CONTROL_ALLOW_ORIGIN],
            expected_origin
        );
        let (status, _, _) = public_call(
            stack.server.addr,
            &info.hostname,
            Method::OPTIONS,
            "/cors-preflight",
            headers.clone(),
            Body::empty(),
        )
        .await?;
        assert_eq!(status, StatusCode::NOT_FOUND);
        headers.insert(ORIGIN, HeaderValue::from_static("https://other.test"));
        let (_, response_headers, _) = public_call(
            stack.server.addr,
            &info.hostname,
            Method::GET,
            "/health",
            headers.clone(),
            Body::empty(),
        )
        .await?;
        assert_eq!(
            response_headers.contains_key(ACCESS_CONTROL_ALLOW_ORIGIN),
            !credentials
        );
        websocket_round_trip(
            stack.server.addr,
            &info.hostname,
            Bytes::from_static(b"cors-upgrade"),
        )
        .await?;
        complete_generated_download(stack.server.addr, &info.hostname).await?;
        fixture.stop().await?;
        headers.insert(ORIGIN, HeaderValue::from_static("https://app.example.com"));
        let (status, response_headers, _) = public_call(
            stack.server.addr,
            &info.hostname,
            Method::GET,
            "/health",
            headers,
            Body::empty(),
        )
        .await?;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            response_headers[ACCESS_CONTROL_ALLOW_ORIGIN],
            expected_origin
        );
        client.stop().await?;
    }
    stack.stop().await?;
    Ok(())
}
