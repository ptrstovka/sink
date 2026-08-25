//! Manual-only local HTTP fixture used by `scripts/acceptance`.

use std::{
    convert::Infallible,
    env,
    error::Error,
    io,
    net::SocketAddr,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use axum::{
    Router,
    body::Body,
    extract::{Path, State, WebSocketUpgrade, ws::Message},
    http::{HeaderValue, Response, StatusCode, header::CONTENT_TYPE},
    routing::{any, get, post, put},
};
use bytes::Bytes;
use futures::stream;
use http_body_util::BodyExt as _;
use sha2::{Digest as _, Sha256};
use tokio::{fs::File, net::TcpListener, time::sleep};
use tokio_util::io::ReaderStream;

type AppError = Box<dyn Error + Send + Sync>;

#[derive(Clone)]
struct FixtureState {
    download_file: Arc<PathBuf>,
    active_streams: Arc<AtomicUsize>,
    side_effects: Arc<AtomicUsize>,
}

struct ActiveStream(Arc<AtomicUsize>);

impl ActiveStream {
    fn new(counter: Arc<AtomicUsize>) -> Self {
        counter.fetch_add(1, Ordering::AcqRel);
        Self(counter)
    }
}

impl Drop for ActiveStream {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

#[tokio::main]
async fn main() -> Result<(), AppError> {
    let confirmation = env::var("SINK_ACCEPTANCE_CONFIRM").unwrap_or_default();
    if confirmation != "I_UNDERSTAND" {
        return Err(io::Error::other(
            "set SINK_ACCEPTANCE_CONFIRM=I_UNDERSTAND for the manual fixture",
        )
        .into());
    }
    let listen: SocketAddr = env::var("SINK_ACCEPTANCE_FIXTURE_LISTEN")
        .unwrap_or_else(|_| "127.0.0.1:3000".to_owned())
        .parse()?;
    if !listen.ip().is_loopback() {
        return Err(io::Error::other("the manual fixture must bind a loopback address").into());
    }
    let download_file = PathBuf::from(env::var("SINK_ACCEPTANCE_DOWNLOAD_FILE").map_err(|_| {
        io::Error::other("SINK_ACCEPTANCE_DOWNLOAD_FILE must name the generated test payload")
    })?);
    if !download_file.is_file() {
        return Err(io::Error::other("the configured download payload is not a file").into());
    }

    let state = FixtureState {
        download_file: Arc::new(download_file),
        active_streams: Arc::new(AtomicUsize::new(0)),
        side_effects: Arc::new(AtomicUsize::new(0)),
    };
    let app = Router::new()
        .route("/health", get(|| async { "ok\n" }))
        .route("/ordinary/{id}", any(ordinary))
        .route("/upload", put(upload))
        .route("/download", get(download))
        .route("/sse", get(sse))
        .route("/ws", get(websocket))
        .route("/side-effect", post(side_effect))
        .route("/stats", get(stats))
        .with_state(state);
    let listener = TcpListener::bind(listen).await?;
    let bound = listener.local_addr()?;
    println!("acceptance fixture listening on http://{bound}");
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}

async fn ordinary(Path(id): Path<String>) -> String {
    format!("ordinary-{id}\n")
}

async fn upload(body: Body) -> Response<Body> {
    let mut body = body;
    let mut hasher = Sha256::new();
    let mut count = 0_u64;
    while let Some(frame) = body.frame().await {
        let frame = match frame {
            Ok(frame) => frame,
            Err(_) => return response(StatusCode::BAD_REQUEST, "invalid upload\n"),
        };
        if let Ok(data) = frame.into_data() {
            count = count.saturating_add(data.len() as u64);
            hasher.update(data);
        }
    }
    response(
        StatusCode::OK,
        format!("bytes={count}\nsha256={}\n", hex(&hasher.finalize())),
    )
}

async fn download(State(state): State<FixtureState>) -> Response<Body> {
    let file = match File::open(state.download_file.as_ref()).await {
        Ok(file) => file,
        Err(_) => return response(StatusCode::SERVICE_UNAVAILABLE, "download unavailable\n"),
    };
    Response::new(Body::from_stream(ReaderStream::new(file)))
}

async fn sse() -> Response<Body> {
    let events = stream::unfold(0_u64, |sequence| async move {
        if sequence > 0 {
            sleep(Duration::from_secs(1)).await;
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

async fn websocket(upgrade: WebSocketUpgrade) -> impl axum::response::IntoResponse {
    upgrade.on_upgrade(|mut socket| async move {
        while let Some(Ok(message)) = socket.recv().await {
            match message {
                Message::Text(_) | Message::Binary(_) | Message::Pong(_) => {
                    if socket.send(message).await.is_err() {
                        break;
                    }
                }
                Message::Ping(payload) => {
                    if socket.send(Message::Pong(payload)).await.is_err() {
                        break;
                    }
                }
                Message::Close(_) => break,
            }
        }
    })
}

async fn side_effect(State(state): State<FixtureState>) -> Response<Body> {
    state.side_effects.fetch_add(1, Ordering::AcqRel);
    let active = ActiveStream::new(Arc::clone(&state.active_streams));
    let delayed = stream::once(async move {
        sleep(Duration::from_secs(60)).await;
        drop(active);
        Ok::<Bytes, Infallible>(Bytes::from_static(b"side-effect-complete\n"))
    });
    Response::new(Body::from_stream(delayed))
}

async fn stats(State(state): State<FixtureState>) -> String {
    format!(
        "active_streams={}\nside_effects={}\n",
        state.active_streams.load(Ordering::Acquire),
        state.side_effects.load(Ordering::Acquire)
    )
}

fn response(status: StatusCode, body: impl Into<Body>) -> Response<Body> {
    let mut response = Response::new(body.into());
    *response.status_mut() = status;
    response
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
