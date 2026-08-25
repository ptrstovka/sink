use std::{
    collections::VecDeque,
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, ready},
};

use axum::extract::ws::Message;
use bytes::Bytes;
use futures::{Sink, Stream};
use sink_protocol::MAX_TRANSPORT_MESSAGE_BYTES;

/// Axum WebSocket adapter consumed by `sink_protocol::MessageIo` after the
/// JSON handshake. It exposes binary messages only and chunks large yamux
/// writes so no WebSocket message exceeds the shared transport bound.
pub(crate) struct AxumMessageAdapter<S> {
    socket: S,
    incoming: VecDeque<io::Result<Bytes>>,
    incoming_closed: bool,
    outgoing: VecDeque<Bytes>,
    clean_close: Arc<AtomicBool>,
}

impl<S> AxumMessageAdapter<S> {
    pub(crate) fn new(socket: S) -> (Self, CleanClose) {
        let clean_close = Arc::new(AtomicBool::new(false));
        (
            Self {
                socket,
                incoming: VecDeque::new(),
                incoming_closed: false,
                outgoing: VecDeque::new(),
                clean_close: Arc::clone(&clean_close),
            },
            CleanClose { clean_close },
        )
    }

    fn prefetch_incoming(&mut self, context: &mut Context<'_>) -> bool
    where
        S: Stream<Item = Result<Message, axum::Error>> + Unpin,
    {
        if !self.incoming.is_empty() || self.incoming_closed {
            return true;
        }
        loop {
            match Pin::new(&mut self.socket).poll_next(context) {
                Poll::Ready(Some(Ok(Message::Binary(bytes))))
                    if bytes.len() <= MAX_TRANSPORT_MESSAGE_BYTES =>
                {
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
                Poll::Ready(Some(Ok(Message::Ping(_) | Message::Pong(_)))) => {}
                Poll::Ready(Some(Err(error))) => {
                    self.incoming.push_back(Err(websocket_error(error)));
                    return true;
                }
                Poll::Ready(None) => {
                    self.incoming_closed = true;
                    return true;
                }
                Poll::Pending => return false,
            }
        }
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
    S: Stream<Item = Result<Message, axum::Error>> + Unpin,
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
