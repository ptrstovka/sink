use std::{
    collections::VecDeque,
    sync::{Arc, Mutex, MutexGuard},
    task::Poll,
    time::{Duration, Instant},
};

use futures::{AsyncRead, AsyncWrite, future::poll_fn};
use thiserror::Error;
use tokio::{
    sync::{mpsc, oneshot},
    time::timeout,
};
use uuid::Uuid;
use yamux::{Config, Connection, ConnectionError, DEFAULT_CREDIT, Mode, Stream};

const COMMANDS_PER_POLL: usize = 256;
const STREAM_OPEN_TIMEOUT: Duration = Duration::from_secs(1);
const YAMUX_MAX_STREAMS: usize = 512;
// yamux 0.13 draws auto-tuned per-stream credit from the aggregate receive
// window's surplus. Reserving exactly the 256 KiB minimum for every stream
// leaves no surplus for bulk streams to queue ahead of later SYN frames.
const YAMUX_MAX_CONNECTION_RECEIVE_WINDOW_BYTES: usize =
    YAMUX_MAX_STREAMS * DEFAULT_CREDIT as usize;

fn yamux_config() -> Config {
    let mut config = Config::default();
    config
        .set_max_num_streams(YAMUX_MAX_STREAMS)
        .set_max_connection_receive_window(Some(YAMUX_MAX_CONNECTION_RECEIVE_WINDOW_BYTES));
    config
}

type OpenReply = oneshot::Sender<Result<ObservedStream, BrokerError>>;

#[derive(Debug)]
struct OpenRequest {
    session_id: Uuid,
    enqueued_at: Instant,
    reply: OpenReply,
}

#[derive(Debug)]
struct PendingOpen {
    session_id: Uuid,
    broker_queue: Duration,
    yamux_open_started_at: Instant,
    reply: OpenReply,
}

#[derive(Debug)]
pub(crate) struct ObservedStream {
    pub(crate) stream: Stream,
    pub(crate) session_id: Uuid,
    pub(crate) broker_queue: Duration,
    pub(crate) yamux_open: Duration,
}

#[derive(Debug)]
enum DriverCommand {
    Open(OpenRequest),
    Shutdown,
    Replace,
}

#[derive(Clone, Debug)]
pub(crate) struct StreamBroker {
    commands: mpsc::UnboundedSender<DriverCommand>,
    liveness: ControlLinkLiveness,
    open_timeout: Duration,
    session_id: Uuid,
}

impl StreamBroker {
    #[cfg(test)]
    pub(crate) fn channel() -> (Self, StreamRequests) {
        Self::channel_for_session(Uuid::nil())
    }

    pub(crate) fn channel_for_session(session_id: Uuid) -> (Self, StreamRequests) {
        Self::channel_with_open_timeout(session_id, STREAM_OPEN_TIMEOUT)
    }

    fn channel_with_open_timeout(
        session_id: Uuid,
        open_timeout: Duration,
    ) -> (Self, StreamRequests) {
        let (commands, requests) = mpsc::unbounded_channel();
        (
            Self {
                commands,
                liveness: ControlLinkLiveness::default(),
                open_timeout,
                session_id,
            },
            StreamRequests { requests },
        )
    }

    #[cfg(test)]
    pub(crate) async fn open_stream(&self) -> Result<Stream, BrokerError> {
        self.open_stream_observed()
            .await
            .map(|opened| opened.stream)
    }

    pub(crate) async fn open_stream_observed(&self) -> Result<ObservedStream, BrokerError> {
        self.liveness.record_public_stream_request();
        let (reply, response) = oneshot::channel();
        self.commands
            .send(DriverCommand::Open(OpenRequest {
                session_id: self.session_id,
                enqueued_at: Instant::now(),
                reply,
            }))
            .map_err(|_| BrokerError::Unavailable)?;
        match timeout(self.open_timeout, response).await {
            Ok(Ok(Ok(opened))) => {
                self.liveness.record_public_stream_opened();
                Ok(opened)
            }
            Ok(Ok(Err(error))) => Err(error),
            Ok(Err(_)) => Err(BrokerError::Unavailable),
            Err(_) => {
                self.liveness.record_public_stream_open_timeout();
                Err(BrokerError::TimedOut)
            }
        }
    }

    pub(crate) fn is_available(&self) -> bool {
        !self.commands.is_closed()
    }

    pub(crate) fn liveness(&self) -> ControlLinkLiveness {
        self.liveness.clone()
    }

    pub(crate) fn liveness_snapshot(&self, now: Instant) -> ControlLinkSnapshot {
        self.liveness.snapshot(now)
    }

    pub(crate) fn session_id(&self) -> Uuid {
        self.session_id
    }

    pub(crate) fn shutdown(&self) {
        let _ = self.commands.send(DriverCommand::Shutdown);
    }

    /// Stop this driver immediately because a newer control link for the same
    /// authenticated client run has taken ownership of its claim.
    pub(crate) fn replace(&self) {
        let _ = self.commands.send(DriverCommand::Replace);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ControlInboundKind {
    Binary,
    Ping,
    Pong,
}

impl ControlInboundKind {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Binary => "binary",
            Self::Ping => "ping",
            Self::Pong => "pong",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ControlLinkSnapshot {
    pub(crate) client_version: Option<Arc<str>>,
    pub(crate) connected_for: Duration,
    pub(crate) last_inbound_ago: Option<Duration>,
    pub(crate) last_inbound_kind: Option<ControlInboundKind>,
    pub(crate) last_ping_sent_ago: Option<Duration>,
    pub(crate) last_pong_received_ago: Option<Duration>,
    pub(crate) heartbeat_pings_sent: u64,
    pub(crate) heartbeat_pongs_received: u64,
    pub(crate) heartbeat_timeouts: u64,
    pub(crate) binary_messages_received: u64,
    pub(crate) public_stream_requests: u64,
    pub(crate) public_streams_opened: u64,
    pub(crate) public_stream_open_timeouts: u64,
}

#[derive(Clone, Debug)]
pub(crate) struct ControlLinkLiveness {
    inner: Arc<Mutex<ControlLinkLivenessInner>>,
}

#[derive(Debug)]
struct ControlLinkLivenessInner {
    created_at: Instant,
    client_version: Option<Arc<str>>,
    last_inbound_at: Option<Instant>,
    last_inbound_kind: Option<ControlInboundKind>,
    last_ping_sent_at: Option<Instant>,
    last_pong_received_at: Option<Instant>,
    heartbeat_pings_sent: u64,
    heartbeat_pongs_received: u64,
    heartbeat_timeouts: u64,
    binary_messages_received: u64,
    public_stream_requests: u64,
    public_streams_opened: u64,
    public_stream_open_timeouts: u64,
}

impl Default for ControlLinkLiveness {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(ControlLinkLivenessInner {
                created_at: Instant::now(),
                client_version: None,
                last_inbound_at: None,
                last_inbound_kind: None,
                last_ping_sent_at: None,
                last_pong_received_at: None,
                heartbeat_pings_sent: 0,
                heartbeat_pongs_received: 0,
                heartbeat_timeouts: 0,
                binary_messages_received: 0,
                public_stream_requests: 0,
                public_streams_opened: 0,
                public_stream_open_timeouts: 0,
            })),
        }
    }
}

impl ControlLinkLiveness {
    pub(crate) fn set_client_version(&self, client_version: impl AsRef<str>) {
        self.lock().client_version = Some(Arc::from(client_version.as_ref()));
    }

    pub(crate) fn record_inbound(&self, kind: ControlInboundKind) {
        let now = Instant::now();
        let mut inner = self.lock();
        inner.last_inbound_at = Some(now);
        inner.last_inbound_kind = Some(kind);
        match kind {
            ControlInboundKind::Binary => {
                inner.binary_messages_received = inner.binary_messages_received.saturating_add(1);
            }
            ControlInboundKind::Pong => {
                inner.last_pong_received_at = Some(now);
                inner.heartbeat_pongs_received = inner.heartbeat_pongs_received.saturating_add(1);
            }
            ControlInboundKind::Ping => {}
        }
    }

    pub(crate) fn record_heartbeat_ping(&self) {
        let mut inner = self.lock();
        inner.last_ping_sent_at = Some(Instant::now());
        inner.heartbeat_pings_sent = inner.heartbeat_pings_sent.saturating_add(1);
    }

    pub(crate) fn record_heartbeat_timeout(&self) {
        let mut inner = self.lock();
        inner.heartbeat_timeouts = inner.heartbeat_timeouts.saturating_add(1);
    }

    fn record_public_stream_request(&self) {
        let mut inner = self.lock();
        inner.public_stream_requests = inner.public_stream_requests.saturating_add(1);
    }

    fn record_public_stream_opened(&self) {
        let mut inner = self.lock();
        inner.public_streams_opened = inner.public_streams_opened.saturating_add(1);
    }

    fn record_public_stream_open_timeout(&self) {
        let mut inner = self.lock();
        inner.public_stream_open_timeouts = inner.public_stream_open_timeouts.saturating_add(1);
    }

    pub(crate) fn snapshot(&self, now: Instant) -> ControlLinkSnapshot {
        let inner = self.lock();
        ControlLinkSnapshot {
            client_version: inner.client_version.clone(),
            connected_for: now.saturating_duration_since(inner.created_at),
            last_inbound_ago: inner
                .last_inbound_at
                .map(|at| now.saturating_duration_since(at)),
            last_inbound_kind: inner.last_inbound_kind,
            last_ping_sent_ago: inner
                .last_ping_sent_at
                .map(|at| now.saturating_duration_since(at)),
            last_pong_received_ago: inner
                .last_pong_received_at
                .map(|at| now.saturating_duration_since(at)),
            heartbeat_pings_sent: inner.heartbeat_pings_sent,
            heartbeat_pongs_received: inner.heartbeat_pongs_received,
            heartbeat_timeouts: inner.heartbeat_timeouts,
            binary_messages_received: inner.binary_messages_received,
            public_stream_requests: inner.public_stream_requests,
            public_streams_opened: inner.public_streams_opened,
            public_stream_open_timeouts: inner.public_stream_open_timeouts,
        }
    }

    fn lock(&self) -> MutexGuard<'_, ControlLinkLivenessInner> {
        match self.inner.lock() {
            Ok(inner) => inner,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

#[derive(Debug)]
pub(crate) struct StreamRequests {
    requests: mpsc::UnboundedReceiver<DriverCommand>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DriverExit {
    Shutdown,
    Replaced,
    TransportClosed,
    TransportError,
    UnexpectedInboundStream,
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub(crate) enum BrokerError {
    #[error("tunnel stream unavailable")]
    Unavailable,
    #[error("tunnel stream open timed out")]
    TimedOut,
}

pub(crate) async fn drive_yamux<IO>(io: IO, requests: StreamRequests) -> DriverExit
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let mut connection = Connection::new(io, yamux_config(), Mode::Server);
    let mut requests = requests.requests;
    let mut pending = VecDeque::<PendingOpen>::new();
    let mut shutdown = false;

    poll_fn(move |context| {
        match connection.poll_next_inbound(context) {
            Poll::Ready(Some(Ok(stream))) => {
                tracing::warn!(stream_id = %stream.id(), "client opened a disallowed yamux stream");
                drop(stream);
                fail_pending(&mut pending);
                return Poll::Ready(DriverExit::UnexpectedInboundStream);
            }
            Poll::Ready(Some(Err(error))) => {
                tracing::warn!(%error, "yamux control connection failed");
                fail_pending(&mut pending);
                return Poll::Ready(DriverExit::TransportError);
            }
            Poll::Ready(None) => {
                fail_pending(&mut pending);
                return Poll::Ready(DriverExit::TransportClosed);
            }
            Poll::Pending => {}
        }

        let mut command_limit_reached = true;
        for _ in 0..COMMANDS_PER_POLL {
            match requests.poll_recv(context) {
                Poll::Ready(Some(DriverCommand::Open(request))) if !shutdown => {
                    let now = Instant::now();
                    pending.push_back(PendingOpen {
                        session_id: request.session_id,
                        broker_queue: now.saturating_duration_since(request.enqueued_at),
                        yamux_open_started_at: now,
                        reply: request.reply,
                    });
                }
                Poll::Ready(Some(DriverCommand::Open(request))) => {
                    let _ = request.reply.send(Err(BrokerError::Unavailable));
                }
                Poll::Ready(Some(DriverCommand::Shutdown)) | Poll::Ready(None) => {
                    shutdown = true;
                }
                Poll::Ready(Some(DriverCommand::Replace)) => {
                    fail_pending(&mut pending);
                    return Poll::Ready(DriverExit::Replaced);
                }
                Poll::Pending => {
                    command_limit_reached = false;
                    break;
                }
            }
        }

        if command_limit_reached {
            context.waker().wake_by_ref();
        }

        if shutdown {
            fail_pending(&mut pending);
            return match connection.poll_close(context) {
                Poll::Ready(_) => Poll::Ready(DriverExit::Shutdown),
                Poll::Pending => Poll::Pending,
            };
        }

        while let Some(open) = pending.pop_front() {
            if open.reply.is_closed() {
                continue;
            }
            match connection.poll_new_outbound(context) {
                Poll::Ready(Ok(stream)) => {
                    let observed = ObservedStream {
                        stream,
                        session_id: open.session_id,
                        broker_queue: open.broker_queue,
                        yamux_open: open.yamux_open_started_at.elapsed(),
                    };
                    let _ = open.reply.send(Ok(observed));
                }
                Poll::Ready(Err(error)) => {
                    let _ = open.reply.send(Err(BrokerError::Unavailable));
                    fail_pending(&mut pending);
                    if matches!(error, ConnectionError::Closed) {
                        return Poll::Ready(DriverExit::TransportClosed);
                    }
                    tracing::warn!(%error, "yamux could not open an outbound stream");
                    return Poll::Ready(DriverExit::TransportError);
                }
                Poll::Pending => {
                    pending.push_front(open);
                    break;
                }
            }
        }

        Poll::Pending
    })
    .await
}

fn fail_pending(pending: &mut VecDeque<PendingOpen>) {
    for open in pending.drain(..) {
        let _ = open.reply.send(Err(BrokerError::Unavailable));
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::VecDeque, io, pin::Pin, sync::Arc, task::Context, time::Duration};

    use axum::extract::ws::Message;
    use bytes::Bytes;
    use futures::{Sink, Stream, future::poll_fn};
    use sink_protocol::MessageIo;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        sync::Barrier,
    };
    use tokio_util::compat::{FuturesAsyncReadCompatExt as _, TokioAsyncReadCompatExt as _};

    use super::*;
    use crate::runtime::websocket::AxumMessageAdapter;

    const CONCURRENT_STREAMS: usize = 128;

    #[tokio::test]
    async fn peer_close_racing_outbound_open_is_classified_as_closed() -> Result<(), io::Error> {
        let socket = ClosingWebSocket {
            incoming: VecDeque::from([
                Ok(Message::Binary(Bytes::from_static(&[
                    0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                ]))),
                Ok(Message::Close(None)),
            ]),
        };
        let (adapter, _) = AxumMessageAdapter::new(socket, ControlLinkLiveness::default());
        let server_io = MessageIo::new(adapter);

        let (broker, requests) = StreamBroker::channel();
        let mut open_request = Box::pin(broker.open_stream());
        assert!(matches!(
            futures::poll!(open_request.as_mut()),
            std::task::Poll::Pending
        ));

        let exit = tokio::time::timeout(Duration::from_secs(1), drive_yamux(server_io, requests))
            .await
            .map_err(|_| io::Error::other("peer-close race test timed out"))?;
        assert_eq!(exit, DriverExit::TransportClosed);
        assert!(matches!(open_request.await, Err(BrokerError::Unavailable)));
        Ok(())
    }

    struct ClosingWebSocket {
        incoming: VecDeque<Result<Message, axum::Error>>,
    }

    #[tokio::test]
    async fn blocked_control_writes_do_not_stop_inbound_progress() -> Result<(), io::Error> {
        let messages = BackpressuredMessages {
            incoming: VecDeque::from([
                Ok(Bytes::copy_from_slice(&yamux_header(2, 1, 0, 42))),
                Ok(Bytes::copy_from_slice(&yamux_header(0, 1, 1, 0))),
            ]),
        };
        let (broker, requests) = StreamBroker::channel();

        let exit = tokio::time::timeout(
            Duration::from_secs(1),
            drive_yamux(MessageIo::new(messages), requests),
        )
        .await
        .map_err(|_| io::Error::other("yamux stopped reading behind a blocked Pong"))?;

        assert_eq!(exit, DriverExit::UnexpectedInboundStream);
        drop(broker);
        Ok(())
    }

    struct BackpressuredMessages {
        incoming: VecDeque<io::Result<Bytes>>,
    }

    impl Stream for BackpressuredMessages {
        type Item = io::Result<Bytes>;

        fn poll_next(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Option<Self::Item>> {
            self.incoming
                .pop_front()
                .map_or(Poll::Pending, |message| Poll::Ready(Some(message)))
        }
    }

    impl Sink<Bytes> for BackpressuredMessages {
        type Error = io::Error;

        fn poll_ready(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Pending
        }

        fn start_send(self: Pin<&mut Self>, _message: Bytes) -> Result<(), Self::Error> {
            Err(io::Error::other("message sent without sink readiness"))
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Pending
        }

        fn poll_close(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Pending
        }
    }

    fn yamux_header(tag: u8, flags: u16, stream_id: u32, length: u32) -> [u8; 12] {
        let mut header = [0_u8; 12];
        header[1] = tag;
        header[2..4].copy_from_slice(&flags.to_be_bytes());
        header[4..8].copy_from_slice(&stream_id.to_be_bytes());
        header[8..12].copy_from_slice(&length.to_be_bytes());
        header
    }

    impl Stream for ClosingWebSocket {
        type Item = Result<Message, axum::Error>;

        fn poll_next(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Option<Self::Item>> {
            Poll::Ready(self.incoming.pop_front())
        }
    }

    impl Sink<Message> for ClosingWebSocket {
        type Error = axum::Error;

        fn poll_ready(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Err(broken_pipe()))
        }

        fn start_send(self: Pin<&mut Self>, _message: Message) -> Result<(), Self::Error> {
            Err(broken_pipe())
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Err(broken_pipe()))
        }

        fn poll_close(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Err(broken_pipe()))
        }
    }

    fn broken_pipe() -> axum::Error {
        axum::Error::new(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "peer closed before server write",
        ))
    }

    #[tokio::test]
    async fn replacement_stops_a_half_open_driver_immediately() -> Result<(), io::Error> {
        let (server_io, _silent_peer) = tokio::io::duplex(1024);
        let (broker, requests) = StreamBroker::channel();
        let driver = tokio::spawn(drive_yamux(server_io.compat(), requests));

        tokio::task::yield_now().await;
        broker.replace();

        let exit = tokio::time::timeout(Duration::from_secs(1), driver)
            .await
            .map_err(|_| io::Error::other("replacement did not stop the old driver"))?
            .map_err(io::Error::other)?;
        assert_eq!(exit, DriverExit::Replaced);
        Ok(())
    }

    #[tokio::test]
    async fn stream_open_wait_is_bounded_and_reported() -> Result<(), io::Error> {
        let (broker, _undriven_requests) =
            StreamBroker::channel_with_open_timeout(Uuid::nil(), Duration::from_millis(10));

        let result = tokio::time::timeout(Duration::from_secs(1), broker.open_stream())
            .await
            .map_err(|_| io::Error::other("broker did not enforce its stream-open deadline"))?;
        assert!(matches!(result, Err(BrokerError::TimedOut)));

        let snapshot = broker.liveness_snapshot(Instant::now());
        assert_eq!(snapshot.public_stream_requests, 1);
        assert_eq!(snapshot.public_streams_opened, 0);
        assert_eq!(snapshot.public_stream_open_timeouts, 1);
        Ok(())
    }

    #[tokio::test]
    async fn broker_opens_many_streaming_exchanges_concurrently() -> Result<(), io::Error> {
        let (server_io, client_io) = tokio::io::duplex(2 * 1024 * 1024);
        let session_id = Uuid::from_u128(42);
        let (broker, requests) = StreamBroker::channel_for_session(session_id);
        let server_driver = tokio::spawn(drive_yamux(server_io.compat(), requests));
        let barrier = Arc::new(Barrier::new(CONCURRENT_STREAMS));

        let client_driver = tokio::spawn({
            let barrier = Arc::clone(&barrier);
            async move {
                let mut connection =
                    Connection::new(client_io.compat(), Config::default(), Mode::Client);
                loop {
                    match poll_fn(|context| connection.poll_next_inbound(context)).await {
                        Some(Ok(stream)) => {
                            let barrier = Arc::clone(&barrier);
                            tokio::spawn(async move {
                                let mut stream = stream.compat();
                                let mut payload = [0_u8; 1024];
                                stream.read_exact(&mut payload).await?;
                                barrier.wait().await;
                                stream.write_all(&payload).await?;
                                stream.shutdown().await
                            });
                        }
                        Some(Err(error)) => {
                            return Err(io::Error::other(error));
                        }
                        None => return Ok(()),
                    }
                }
            }
        });

        let exchanges = (0..CONCURRENT_STREAMS).map(|index| {
            let broker = broker.clone();
            async move {
                let opened = broker
                    .open_stream_observed()
                    .await
                    .map_err(io::Error::other)?;
                if opened.session_id != session_id
                    || opened.broker_queue > Duration::from_secs(10)
                    || opened.yamux_open > Duration::from_secs(10)
                {
                    return Err(io::Error::other(
                        "stream-open observation was missing or out of bounds",
                    ));
                }
                let mut stream = opened.stream.compat();
                let payload = [index as u8; 1024];
                stream.write_all(&payload).await?;
                let mut echoed = [0_u8; 1024];
                stream.read_exact(&mut echoed).await?;
                if echoed != payload {
                    return Err(io::Error::other("echoed stream payload was corrupted"));
                }
                Ok(())
            }
        });

        tokio::time::timeout(
            Duration::from_secs(10),
            futures::future::try_join_all(exchanges),
        )
        .await
        .map_err(|_| io::Error::other("concurrent stream test timed out"))??;

        broker.shutdown();
        let exit = server_driver.await.map_err(io::Error::other)?;
        assert_eq!(exit, DriverExit::Shutdown);
        client_driver.await.map_err(io::Error::other)??;
        Ok(())
    }
}
