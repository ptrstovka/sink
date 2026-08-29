use std::{
    collections::HashMap,
    convert::Infallible,
    error::Error,
    future::Future,
    io,
    net::SocketAddr,
    num::NonZeroUsize,
    str::FromStr as _,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use axum::{
    Router,
    body::Body,
    extract::{Path, State, WebSocketUpgrade, ws::Message as AxumMessage},
    http::{
        HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode, Uri,
        header::{AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, FORWARDED, HOST},
    },
    routing::{any, get, post},
};
use bytes::Bytes;
use futures::{SinkExt as _, StreamExt as _, stream};
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
use sink_server::{db::Database, runtime::RuntimeState};
use tempfile::TempDir;
use tokio::{
    io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _},
    net::{TcpListener, TcpStream},
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

fn client_runtime(
    token: &str,
    control_addr: SocketAddr,
    target_addr: SocketAddr,
    requested_hostname: Option<&str>,
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

async fn websocket_echo_progress(
    websocket: &mut WebSocketStream<TcpStream>,
    payload: Bytes,
) -> TestResult<()> {
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
        "forwarded=for=203.0.113.9;host={};proto=https",
        info.hostname
    )));
    assert!(observed.contains("x-forwarded-for=203.0.113.9"));
    assert!(observed.contains(&format!("x-forwarded-host={}", info.hostname)));
    assert!(observed.contains("x-forwarded-proto=https"));
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
