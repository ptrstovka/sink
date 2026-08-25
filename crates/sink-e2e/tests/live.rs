use std::{
    convert::Infallible,
    error::Error,
    future::Future,
    io,
    net::SocketAddr,
    str::FromStr as _,
    sync::{
        Arc,
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
        header::{AUTHORIZATION, CONTENT_TYPE, FORWARDED, HOST},
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
    config::{AuthToken, RunOverrides, SavedConfig, ServerAddressFallback},
    runtime::{
        ConnectionInfo, FailureDisposition, RuntimeError, RuntimeHandle, TunnelPhase, TunnelRuntime,
    },
    target::{LocalTarget, PublicUrl},
};
use sink_server::{db::Database, runtime::RuntimeState};
use tempfile::TempDir;
use tokio::{
    io::AsyncWriteExt as _,
    net::{TcpListener, TcpStream},
    sync::{Notify, oneshot, watch},
    task::JoinHandle,
    time::{sleep, timeout},
};
use tokio_tungstenite::{
    client_async,
    tungstenite::{Message, client::IntoClientRequest as _},
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

type TestError = Box<dyn Error + Send + Sync>;
type TestResult<T = ()> = Result<T, TestError>;

const TEST_BOUND: Duration = Duration::from_secs(20);
const PUBLIC_BASE_DOMAIN: &str = "e2e.test";
const STREAM_BYTES: usize = 2 * 1024 * 1024;
const ORDINARY_REQUESTS: usize = 100;

#[derive(Clone)]
struct FixtureState {
    download_chunks: Arc<Vec<Bytes>>,
    ordinary_active: Arc<AtomicUsize>,
    ordinary_max_active: Arc<AtomicUsize>,
    slow_active: Arc<AtomicUsize>,
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
        .route("/upload", any(hash_upload))
        .route("/download", get(stream_download))
        .route("/sse", get(sse))
        .route("/ws", get(websocket_echo))
        .route("/ordinary/{id}", any(ordinary))
        .route("/side-effect", post(side_effect))
        .with_state(state)
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

async fn stream_download(State(state): State<FixtureState>) -> Response<Body> {
    let chunks = state.download_chunks.as_ref().clone();
    let stream = tokio_stream::iter(chunks.into_iter().map(Ok::<Bytes, Infallible>));
    Response::new(Body::from_stream(stream))
}

async fn sse() -> Response<Body> {
    let events = stream::unfold(0_u64, |sequence| async move {
        if sequence > 0 {
            sleep(Duration::from_millis(25)).await;
        }
        let event = Bytes::from(format!("event: progress\ndata: {sequence}\n\n"));
        Some((Ok::<Bytes, Infallible>(event), sequence.wrapping_add(1)))
    });
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

#[derive(Clone, Copy)]
struct LinkState {
    generation: u64,
    enabled: bool,
}

struct LinkProxy {
    addr: SocketAddr,
    state: watch::Sender<LinkState>,
    shutdown: CancellationToken,
    task: Option<JoinHandle<io::Result<()>>>,
}

impl LinkProxy {
    async fn start(upstream: SocketAddr) -> TestResult<Self> {
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
                                _ = tokio::io::copy_bidirectional(&mut downstream, &mut upstream_stream) => {}
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
        let temp = tempfile::tempdir()?;
        let database = Database::open(temp.path().join("sink.sqlite3")).await?;
        let server = ServerHarness::start(database.clone()).await?;
        let link = LinkProxy::start(server.addr).await?;
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
    let config = SavedConfig::default().resolve(
        RunOverrides {
            authtoken: Some(AuthToken::new(token.to_owned())?),
            server_addr: Some(format!("http://{control_addr}").parse()?),
            allow_plaintext_control: true,
        },
        ServerAddressFallback::RequireConfigured,
    )?;
    let target = LocalTarget::from_str(&format!("http://{target_addr}"))?;
    let public_url = requested_hostname
        .map(|hostname| PublicUrl::from_str(&format!("https://{hostname}")))
        .transpose()?;
    Ok(TunnelRuntime::new(config, target, public_url, false)?)
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

async fn websocket_round_trip(addr: SocketAddr, hostname: &str, payload: Bytes) -> TestResult<()> {
    let mut request = format!("ws://{hostname}/ws").into_client_request()?;
    request
        .headers_mut()
        .insert(HOST, HeaderValue::from_str(hostname)?);
    let stream = bounded("public WebSocket TCP connect", TcpStream::connect(addr)).await??;
    let (mut websocket, response) =
        bounded("public WebSocket upgrade", client_async(request, stream)).await??;
    assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
    websocket.send(Message::Binary(payload.clone())).await?;
    let echoed = bounded("public WebSocket echo", websocket.next())
        .await?
        .ok_or_else(|| io::Error::other("WebSocket ended before echo"))??;
    assert_eq!(echoed, Message::Binary(payload));
    websocket.close(None).await?;
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

    drop(sse_response);

    client.stop().await?;
    stack.stop().await?;
    fixture.stop().await?;
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
