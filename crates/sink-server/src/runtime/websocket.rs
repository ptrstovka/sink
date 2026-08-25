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

use axum::extract::ws::{Message, WebSocket};
use bytes::Bytes;
use futures::{Sink, Stream};
use sink_protocol::MAX_TRANSPORT_MESSAGE_BYTES;

/// Axum WebSocket adapter consumed by `sink_protocol::MessageIo` after the
/// JSON handshake. It exposes binary messages only and chunks large yamux
/// writes so no WebSocket message exceeds the shared transport bound.
pub(crate) struct AxumMessageAdapter {
    socket: WebSocket,
    outgoing: VecDeque<Bytes>,
    clean_close: Arc<AtomicBool>,
}

impl AxumMessageAdapter {
    pub(crate) fn new(socket: WebSocket) -> (Self, CleanClose) {
        let clean_close = Arc::new(AtomicBool::new(false));
        (
            Self {
                socket,
                outgoing: VecDeque::new(),
                clean_close: Arc::clone(&clean_close),
            },
            CleanClose { clean_close },
        )
    }

    fn poll_drain_outgoing(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
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

impl Stream for AxumMessageAdapter {
    type Item = io::Result<Bytes>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            match ready!(Pin::new(&mut self.socket).poll_next(context)) {
                Some(Ok(Message::Binary(bytes))) if bytes.len() <= MAX_TRANSPORT_MESSAGE_BYTES => {
                    return Poll::Ready(Some(Ok(bytes)));
                }
                Some(Ok(Message::Binary(_))) => {
                    return Poll::Ready(Some(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "binary WebSocket message exceeds the transport limit",
                    ))));
                }
                Some(Ok(Message::Text(_))) => {
                    return Poll::Ready(Some(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "text WebSocket message after handshake",
                    ))));
                }
                Some(Ok(Message::Close(_))) => {
                    self.clean_close.store(true, Ordering::Release);
                    return Poll::Ready(None);
                }
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                Some(Err(error)) => {
                    return Poll::Ready(Some(Err(websocket_error(error))));
                }
                None => return Poll::Ready(None),
            }
        }
    }
}

impl Sink<Bytes> for AxumMessageAdapter {
    type Error = io::Error;

    fn poll_ready(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
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
