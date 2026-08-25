use std::{
    collections::VecDeque,
    io,
    pin::Pin,
    task::{Context, Poll, ready},
};

use bytes::Bytes;
use futures::{Sink, Stream};
use sink_protocol::MAX_TRANSPORT_MESSAGE_BYTES;
use tokio_tungstenite::tungstenite::{Error as WebSocketError, Message};

/// Maps only WebSocket binary messages into the byte-message transport used by
/// `sink_protocol::MessageIo`. WebSocket control frames remain at this layer.
#[derive(Debug)]
pub(crate) struct WebSocketBinary<S> {
    inner: S,
    outgoing: VecDeque<Bytes>,
    needs_flush: bool,
}

impl<S> WebSocketBinary<S> {
    pub(crate) fn new(inner: S) -> Self {
        Self {
            inner,
            outgoing: VecDeque::new(),
            needs_flush: false,
        }
    }

    fn poll_drain_outgoing(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<io::Result<()>>
    where
        S: Sink<Message, Error = WebSocketError> + Unpin,
    {
        while let Some(chunk) = self.outgoing.pop_front() {
            match Pin::new(&mut self.inner).poll_ready(context) {
                Poll::Ready(Ok(())) => {
                    if Pin::new(&mut self.inner)
                        .start_send(Message::Binary(chunk))
                        .is_err()
                    {
                        return Poll::Ready(Err(control_io_error()));
                    }
                }
                Poll::Ready(Err(_)) => {
                    self.outgoing.push_front(chunk);
                    return Poll::Ready(Err(control_io_error()));
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

impl<S> Stream for WebSocketBinary<S>
where
    S: Stream<Item = Result<Message, WebSocketError>>
        + Sink<Message, Error = WebSocketError>
        + Unpin,
{
    type Item = io::Result<Bytes>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            if self.needs_flush {
                match Pin::new(&mut self.inner).poll_flush(context) {
                    Poll::Ready(Ok(())) => self.needs_flush = false,
                    Poll::Ready(Err(_)) => {
                        return Poll::Ready(Some(Err(control_io_error())));
                    }
                    Poll::Pending => return Poll::Pending,
                }
            }

            match Pin::new(&mut self.inner).poll_next(context) {
                Poll::Ready(Some(Ok(Message::Binary(bytes)))) => {
                    if bytes.len() > MAX_TRANSPORT_MESSAGE_BYTES {
                        return Poll::Ready(Some(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "control WebSocket binary message exceeds the protocol limit",
                        ))));
                    }
                    return Poll::Ready(Some(Ok(bytes)));
                }
                Poll::Ready(Some(Ok(Message::Ping(_) | Message::Pong(_)))) => {
                    // Tungstenite queues the mandatory pong automatically. A flush
                    // here ensures it is sent even when yamux has no bytes to write.
                    self.needs_flush = true;
                }
                Poll::Ready(Some(Ok(Message::Close(_)))) | Poll::Ready(None) => {
                    return Poll::Ready(None);
                }
                Poll::Ready(Some(Ok(Message::Text(_) | Message::Frame(_)))) => {
                    return Poll::Ready(Some(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "unexpected non-binary message after the control handshake",
                    ))));
                }
                Poll::Ready(Some(Err(_))) => {
                    return Poll::Ready(Some(Err(control_io_error())));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S> Sink<Bytes> for WebSocketBinary<S>
where
    S: Stream<Item = Result<Message, WebSocketError>>
        + Sink<Message, Error = WebSocketError>
        + Unpin,
{
    type Error = io::Error;

    fn poll_ready(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        ready!(self.as_mut().poll_drain_outgoing(context))?;
        Pin::new(&mut self.inner)
            .poll_ready(context)
            .map_err(|_| control_io_error())
    }

    fn start_send(mut self: Pin<&mut Self>, mut bytes: Bytes) -> Result<(), Self::Error> {
        if bytes.is_empty() {
            return Ok(());
        }

        let first_length = bytes.len().min(MAX_TRANSPORT_MESSAGE_BYTES);
        let first = bytes.split_to(first_length);
        Pin::new(&mut self.inner)
            .start_send(Message::Binary(first))
            .map_err(|_| control_io_error())?;
        while !bytes.is_empty() {
            let length = bytes.len().min(MAX_TRANSPORT_MESSAGE_BYTES);
            self.outgoing.push_back(bytes.split_to(length));
        }
        Ok(())
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        ready!(self.as_mut().poll_drain_outgoing(context))?;
        Pin::new(&mut self.inner)
            .poll_flush(context)
            .map_err(|_| control_io_error())
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        ready!(self.as_mut().poll_drain_outgoing(context))?;
        Pin::new(&mut self.inner)
            .poll_close(context)
            .map_err(|_| control_io_error())
    }
}

fn control_io_error() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, "control WebSocket closed")
}

#[cfg(test)]
mod tests {
    use futures::SinkExt as _;

    use super::*;

    #[derive(Debug, Default)]
    struct MockWebSocket {
        outgoing: Vec<Message>,
        ready_calls: usize,
        pending_on_ready_call: Option<usize>,
        pending_was_returned: bool,
        flushes: usize,
        closes: usize,
    }

    impl Stream for MockWebSocket {
        type Item = Result<Message, WebSocketError>;

        fn poll_next(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            Poll::Pending
        }
    }

    impl Sink<Message> for MockWebSocket {
        type Error = WebSocketError;

        fn poll_ready(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            self.ready_calls += 1;
            if self.pending_on_ready_call == Some(self.ready_calls) && !self.pending_was_returned {
                self.pending_was_returned = true;
                context.waker().wake_by_ref();
                return Poll::Pending;
            }
            Poll::Ready(Ok(()))
        }

        fn start_send(mut self: Pin<&mut Self>, item: Message) -> Result<(), Self::Error> {
            self.outgoing.push(item);
            Ok(())
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            self.flushes += 1;
            Poll::Ready(Ok(()))
        }

        fn poll_close(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            self.closes += 1;
            Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn large_write_becomes_ordered_bounded_messages_and_reconstructs_exactly() -> io::Result<()> {
        let length = MAX_TRANSPORT_MESSAGE_BYTES * 2 + 137;
        let original = Bytes::from(
            (0..length)
                .map(|index| (index % 251) as u8)
                .collect::<Vec<_>>(),
        );
        let mut adapter = WebSocketBinary::new(MockWebSocket::default());
        futures::executor::block_on(adapter.send(original.clone()))?;

        assert_eq!(adapter.inner.outgoing.len(), 3);
        let mut reconstructed = Vec::with_capacity(length);
        for message in &adapter.inner.outgoing {
            let Message::Binary(chunk) = message else {
                return Err(io::Error::other("adapter emitted a non-binary message"));
            };
            assert!(!chunk.is_empty());
            assert!(chunk.len() <= MAX_TRANSPORT_MESSAGE_BYTES);
            reconstructed.extend_from_slice(chunk);
        }
        assert_eq!(reconstructed, original);
        assert_eq!(adapter.inner.flushes, 1);
        Ok(())
    }

    #[test]
    fn flush_and_close_drain_chunks_through_pending_readiness() -> io::Result<()> {
        let length = MAX_TRANSPORT_MESSAGE_BYTES * 2 + 1;
        let socket = MockWebSocket {
            // The first readiness poll admits the input; the second happens
            // while draining its first queued remainder.
            pending_on_ready_call: Some(2),
            ..MockWebSocket::default()
        };
        let mut adapter = WebSocketBinary::new(socket);
        futures::executor::block_on(async {
            adapter.feed(Bytes::from(vec![7_u8; length])).await?;
            adapter.flush().await?;
            adapter.close().await
        })?;

        assert!(adapter.inner.pending_was_returned);
        assert_eq!(adapter.inner.outgoing.len(), 3);
        assert_eq!(adapter.inner.flushes, 1);
        assert_eq!(adapter.inner.closes, 1);
        assert!(adapter.outgoing.is_empty());
        Ok(())
    }
}
