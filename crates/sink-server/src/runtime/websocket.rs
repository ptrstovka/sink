use std::{
    collections::VecDeque,
    future::Future as _,
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, ready},
    time::Duration,
};

use axum::extract::ws::Message;
use bytes::Bytes;
use futures::{Sink, Stream};
use rand::RngCore as _;
use sink_protocol::MAX_TRANSPORT_MESSAGE_BYTES;
use tokio::time::{Instant, Sleep, sleep};

use super::broker::{ControlInboundKind, ControlLinkLiveness};

const CONTROL_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);
const CONTROL_HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(10);

/// Axum WebSocket adapter consumed by `sink_protocol::MessageIo` after the
/// JSON handshake. It exposes binary messages only and chunks large yamux
/// writes so no WebSocket message exceeds the shared transport bound.
pub(crate) struct AxumMessageAdapter<S> {
    socket: S,
    incoming: VecDeque<io::Result<Bytes>>,
    incoming_closed: bool,
    outgoing: VecDeque<Bytes>,
    clean_close: Arc<AtomicBool>,
    heartbeat: Heartbeat,
    liveness: ControlLinkLiveness,
}

impl<S> AxumMessageAdapter<S> {
    pub(crate) fn new(socket: S, liveness: ControlLinkLiveness) -> (Self, CleanClose) {
        Self::with_heartbeat(
            socket,
            CONTROL_HEARTBEAT_INTERVAL,
            CONTROL_HEARTBEAT_TIMEOUT,
            liveness,
        )
    }

    fn with_heartbeat(
        socket: S,
        heartbeat_interval: Duration,
        heartbeat_timeout: Duration,
        liveness: ControlLinkLiveness,
    ) -> (Self, CleanClose) {
        let clean_close = Arc::new(AtomicBool::new(false));
        (
            Self {
                socket,
                incoming: VecDeque::new(),
                incoming_closed: false,
                outgoing: VecDeque::new(),
                clean_close: Arc::clone(&clean_close),
                heartbeat: Heartbeat::new(heartbeat_interval, heartbeat_timeout),
                liveness,
            },
            CleanClose { clean_close },
        )
    }

    fn prefetch_incoming(&mut self, context: &mut Context<'_>) -> bool
    where
        S: Stream<Item = Result<Message, axum::Error>> + Sink<Message, Error = axum::Error> + Unpin,
    {
        if !self.incoming.is_empty() || self.incoming_closed {
            return true;
        }
        loop {
            if let Err(error) = self.poll_control_outgoing(context) {
                self.incoming.push_back(Err(error));
                return true;
            }
            match Pin::new(&mut self.socket).poll_next(context) {
                Poll::Ready(Some(Ok(Message::Binary(bytes))))
                    if bytes.len() <= MAX_TRANSPORT_MESSAGE_BYTES =>
                {
                    self.liveness.record_inbound(ControlInboundKind::Binary);
                    self.heartbeat.observe_activity();
                    self.incoming.push_back(Ok(bytes));
                    return true;
                }
                Poll::Ready(Some(Ok(Message::Binary(_)))) => {
                    self.incoming.push_back(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "binary WebSocket message exceeds the transport limit",
                    )));
                    return true;
                }
                Poll::Ready(Some(Ok(Message::Text(_)))) => {
                    self.incoming.push_back(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "text WebSocket message after handshake",
                    )));
                    return true;
                }
                Poll::Ready(Some(Ok(Message::Close(_)))) => {
                    self.clean_close.store(true, Ordering::Release);
                    self.incoming_closed = true;
                    return true;
                }
                Poll::Ready(Some(Ok(Message::Ping(_)))) => {
                    // Tungstenite queued the mandatory pong while reading.
                    self.liveness.record_inbound(ControlInboundKind::Ping);
                    self.heartbeat.observe_activity();
                    self.heartbeat.needs_flush = true;
                }
                Poll::Ready(Some(Ok(Message::Pong(_)))) => {
                    self.liveness.record_inbound(ControlInboundKind::Pong);
                    self.heartbeat.observe_activity();
                }
                Poll::Ready(Some(Err(error))) => {
                    self.incoming.push_back(Err(websocket_error(error)));
                    return true;
                }
                Poll::Ready(None) => {
                    self.incoming_closed = true;
                    return true;
                }
                Poll::Pending => match self.heartbeat.poll_timers(context) {
                    Ok(()) => {
                        if let Err(error) = self.poll_control_outgoing(context) {
                            self.incoming.push_back(Err(error));
                            return true;
                        }
                        return false;
                    }
                    Err(error) => {
                        if error.kind() == io::ErrorKind::TimedOut {
                            self.liveness.record_heartbeat_timeout();
                        }
                        self.incoming.push_back(Err(error));
                        return true;
                    }
                },
            }
        }
    }

    fn poll_control_outgoing(&mut self, context: &mut Context<'_>) -> io::Result<()>
    where
        S: Sink<Message, Error = axum::Error> + Unpin,
    {
        if self.heartbeat.pending_ping.is_some() {
            match Pin::new(&mut self.socket).poll_ready(context) {
                Poll::Ready(Ok(())) => {
                    let Some(payload) = self.heartbeat.pending_ping.take() else {
                        return Ok(());
                    };
                    Pin::new(&mut self.socket)
                        .start_send(Message::Ping(payload))
                        .map_err(websocket_error)?;
                    self.liveness.record_heartbeat_ping();
                    self.heartbeat.ping_sent();
                }
                Poll::Ready(Err(error)) => return Err(websocket_error(error)),
                Poll::Pending => return Ok(()),
            }
        }

        if self.heartbeat.needs_flush {
            match Pin::new(&mut self.socket).poll_flush(context) {
                Poll::Ready(Ok(())) => self.heartbeat.needs_flush = false,
                Poll::Ready(Err(error)) => return Err(websocket_error(error)),
                Poll::Pending => {}
            }
        }
        Ok(())
    }

    fn poll_drain_outgoing(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<io::Result<()>>
    where
        S: Sink<Message, Error = axum::Error> + Unpin,
    {
        while let Some(chunk) = self.outgoing.pop_front() {
            match Pin::new(&mut self.socket).poll_ready(context) {
                Poll::Ready(Ok(())) => {
                    if let Err(error) =
                        Pin::new(&mut self.socket).start_send(Message::Binary(chunk))
                    {
                        return Poll::Ready(Err(websocket_error(error)));
                    }
                }
                Poll::Ready(Err(error)) => {
                    self.outgoing.push_front(chunk);
                    return Poll::Ready(Err(websocket_error(error)));
                }
                Poll::Pending => {
                    self.outgoing.push_front(chunk);
                    return Poll::Pending;
                }
            }
        }
        Poll::Ready(Ok(()))
    }
}

struct Heartbeat {
    interval: Duration,
    timeout: Duration,
    next_ping: Pin<Box<Sleep>>,
    deadline: Option<Pin<Box<Sleep>>>,
    pending_ping: Option<Bytes>,
    awaiting_activity: bool,
    needs_flush: bool,
}

impl Heartbeat {
    fn new(interval: Duration, timeout: Duration) -> Self {
        Self {
            interval,
            timeout,
            next_ping: Box::pin(sleep(interval)),
            deadline: None,
            pending_ping: None,
            awaiting_activity: false,
            needs_flush: false,
        }
    }

    fn poll_timers(&mut self, context: &mut Context<'_>) -> io::Result<()> {
        if self
            .deadline
            .as_mut()
            .is_some_and(|deadline| deadline.as_mut().poll(context).is_ready())
        {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "control WebSocket heartbeat timed out",
            ));
        }

        if !self.awaiting_activity
            && self.pending_ping.is_none()
            && self.next_ping.as_mut().poll(context).is_ready()
        {
            let nonce = rand::rng().next_u64().to_be_bytes();
            self.pending_ping = Some(Bytes::copy_from_slice(&nonce));
            self.awaiting_activity = true;
            self.deadline = Some(Box::pin(sleep(self.timeout)));
            if let Some(deadline) = self.deadline.as_mut() {
                let _ = deadline.as_mut().poll(context);
            }
        }
        Ok(())
    }

    fn ping_sent(&mut self) {
        self.needs_flush = true;
    }

    fn observe_activity(&mut self) {
        self.pending_ping = None;
        self.awaiting_activity = false;
        self.deadline = None;
        self.next_ping
            .as_mut()
            .reset(Instant::now() + self.interval);
    }
}

#[derive(Clone, Debug)]
pub(crate) struct CleanClose {
    clean_close: Arc<AtomicBool>,
}

impl CleanClose {
    pub(crate) fn received(&self) -> bool {
        self.clean_close.load(Ordering::Acquire)
    }
}

impl<S> Stream for AxumMessageAdapter<S>
where
    S: Stream<Item = Result<Message, axum::Error>> + Sink<Message, Error = axum::Error> + Unpin,
{
    type Item = io::Result<Bytes>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if let Some(incoming) = self.incoming.pop_front() {
            return Poll::Ready(Some(incoming));
        }
        if self.incoming_closed {
            return Poll::Ready(None);
        }
        if !self.prefetch_incoming(context) {
            return Poll::Pending;
        }
        if let Some(incoming) = self.incoming.pop_front() {
            Poll::Ready(Some(incoming))
        } else {
            Poll::Ready(None)
        }
    }
}

impl<S> Sink<Bytes> for AxumMessageAdapter<S>
where
    S: Stream<Item = Result<Message, axum::Error>> + Sink<Message, Error = axum::Error> + Unpin,
{
    type Error = io::Error;

    fn poll_ready(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.prefetch_incoming(context) {
            context.waker().wake_by_ref();
            return Poll::Pending;
        }
        ready!(self.as_mut().poll_drain_outgoing(context))?;
        Pin::new(&mut self.socket)
            .poll_ready(context)
            .map_err(websocket_error)
    }

    fn start_send(mut self: Pin<&mut Self>, mut item: Bytes) -> io::Result<()> {
        if item.is_empty() {
            return Ok(());
        }

        let first_len = item.len().min(MAX_TRANSPORT_MESSAGE_BYTES);
        let first = item.split_to(first_len);
        Pin::new(&mut self.socket)
            .start_send(Message::Binary(first))
            .map_err(websocket_error)?;
        while !item.is_empty() {
            let length = item.len().min(MAX_TRANSPORT_MESSAGE_BYTES);
            self.outgoing.push_back(item.split_to(length));
        }
        Ok(())
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.prefetch_incoming(context) {
            context.waker().wake_by_ref();
            return Poll::Pending;
        }
        ready!(self.as_mut().poll_drain_outgoing(context))?;
        Pin::new(&mut self.socket)
            .poll_flush(context)
            .map_err(websocket_error)
    }

    fn poll_close(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.as_mut().poll_drain_outgoing(context))?;
        Pin::new(&mut self.socket)
            .poll_close(context)
            .map_err(websocket_error)
    }
}

fn websocket_error(error: axum::Error) -> io::Error {
    io::Error::other(error)
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{Arc, Mutex, MutexGuard},
        task::Waker,
    };

    use futures::StreamExt as _;

    use super::*;

    #[tokio::test]
    async fn silent_websocket_fails_after_the_heartbeat_deadline() -> io::Result<()> {
        let socket = MockWebSocket::new(false);
        let state = Arc::clone(&socket.state);
        let liveness = ControlLinkLiveness::default();
        let (mut adapter, _) = AxumMessageAdapter::with_heartbeat(
            socket,
            Duration::from_millis(10),
            Duration::from_millis(10),
            liveness.clone(),
        );

        let incoming = tokio::time::timeout(Duration::from_millis(250), adapter.next())
            .await
            .map_err(|_| io::Error::other("heartbeat test timed out"))?
            .ok_or_else(|| io::Error::other("adapter closed without heartbeat error"))?;
        let error = incoming.expect_err("silent peer must fail its heartbeat");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(
            lock_state(&state)
                .outgoing
                .iter()
                .any(|message| matches!(message, Message::Ping(_)))
        );
        let snapshot = liveness.snapshot(std::time::Instant::now());
        assert_eq!(snapshot.heartbeat_pings_sent, 1);
        assert_eq!(snapshot.heartbeat_pongs_received, 0);
        assert_eq!(snapshot.heartbeat_timeouts, 1);
        Ok(())
    }

    #[tokio::test]
    async fn heartbeat_pongs_keep_an_idle_websocket_alive() -> io::Result<()> {
        let socket = MockWebSocket::new(true);
        let state = Arc::clone(&socket.state);
        let liveness = ControlLinkLiveness::default();
        let (mut adapter, _) = AxumMessageAdapter::with_heartbeat(
            socket,
            Duration::from_millis(10),
            Duration::from_millis(20),
            liveness.clone(),
        );

        let result = tokio::time::timeout(Duration::from_millis(100), adapter.next()).await;
        assert!(
            result.is_err(),
            "responsive idle peer must remain connected"
        );
        let ping_count = lock_state(&state)
            .outgoing
            .iter()
            .filter(|message| matches!(message, Message::Ping(_)))
            .count();
        assert!(ping_count >= 2, "expected repeated heartbeat pings");
        let snapshot = liveness.snapshot(std::time::Instant::now());
        assert_eq!(snapshot.heartbeat_pings_sent, ping_count as u64);
        let outstanding_pings = snapshot
            .heartbeat_pings_sent
            .checked_sub(snapshot.heartbeat_pongs_received)
            .expect("heartbeat pong count must not exceed the ping count");
        assert!(
            outstanding_pings <= 1,
            "at most one heartbeat ping may be awaiting its pong"
        );
        assert_eq!(snapshot.heartbeat_timeouts, 0);
        assert_eq!(snapshot.last_inbound_kind, Some(ControlInboundKind::Pong));
        assert!(snapshot.last_pong_received_ago.is_some());
        Ok(())
    }

    #[tokio::test]
    async fn heartbeat_deadline_also_bounds_a_blocked_ping_write() -> io::Result<()> {
        let socket = MockWebSocket::new_with_write_readiness(false, false);
        let liveness = ControlLinkLiveness::default();
        let (mut adapter, _) = AxumMessageAdapter::with_heartbeat(
            socket,
            Duration::from_millis(10),
            Duration::from_millis(10),
            liveness.clone(),
        );

        let incoming = tokio::time::timeout(Duration::from_millis(250), adapter.next())
            .await
            .map_err(|_| io::Error::other("blocked heartbeat test timed out"))?
            .ok_or_else(|| io::Error::other("adapter closed without heartbeat error"))?;
        let error = incoming.expect_err("blocked heartbeat write must time out");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        let snapshot = liveness.snapshot(std::time::Instant::now());
        assert_eq!(snapshot.heartbeat_pings_sent, 0);
        assert_eq!(snapshot.heartbeat_timeouts, 1);
        Ok(())
    }

    struct MockWebSocket {
        state: Arc<Mutex<MockState>>,
    }

    struct MockState {
        auto_pong: bool,
        write_ready: bool,
        incoming: VecDeque<Message>,
        outgoing: Vec<Message>,
        reader: Option<Waker>,
    }

    impl MockWebSocket {
        fn new(auto_pong: bool) -> Self {
            Self::new_with_write_readiness(auto_pong, true)
        }

        fn new_with_write_readiness(auto_pong: bool, write_ready: bool) -> Self {
            Self {
                state: Arc::new(Mutex::new(MockState {
                    auto_pong,
                    write_ready,
                    incoming: VecDeque::new(),
                    outgoing: Vec::new(),
                    reader: None,
                })),
            }
        }
    }

    fn lock_state(state: &Mutex<MockState>) -> MutexGuard<'_, MockState> {
        match state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    impl Stream for MockWebSocket {
        type Item = Result<Message, axum::Error>;

        fn poll_next(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            let mut state = lock_state(&self.state);
            match state.incoming.pop_front() {
                Some(message) => Poll::Ready(Some(Ok(message))),
                None => {
                    state.reader = Some(context.waker().clone());
                    Poll::Pending
                }
            }
        }
    }

    impl Sink<Message> for MockWebSocket {
        type Error = axum::Error;

        fn poll_ready(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            if lock_state(&self.state).write_ready {
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            }
        }

        fn start_send(self: Pin<&mut Self>, message: Message) -> Result<(), Self::Error> {
            let mut state = lock_state(&self.state);
            if state.auto_pong
                && let Message::Ping(payload) = &message
            {
                state.incoming.push_back(Message::Pong(payload.clone()));
                if let Some(reader) = state.reader.take() {
                    reader.wake();
                }
            }
            state.outgoing.push(message);
            Ok(())
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
    }
}
