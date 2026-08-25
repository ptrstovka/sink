use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Buf, Bytes};
use futures::{AsyncRead, AsyncWrite, Sink, Stream};

/// Adapts a message-oriented binary transport into the byte stream expected by yamux.
///
/// Runtime crates map their WebSocket implementation to a `Stream<Item =
/// io::Result<Bytes>> + Sink<Bytes, Error = io::Error>` before constructing this
/// adapter. Text/control messages remain part of the handshake/runtime layer.
#[derive(Debug)]
pub struct MessageIo<S> {
    inner: S,
    read_chunk: Bytes,
}

impl<S> MessageIo<S> {
    #[must_use]
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            read_chunk: Bytes::new(),
        }
    }

    #[must_use]
    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S> AsyncRead for MessageIo<S>
where
    S: Stream<Item = io::Result<Bytes>> + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        output: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if output.is_empty() {
            return Poll::Ready(Ok(0));
        }

        loop {
            if self.read_chunk.has_remaining() {
                let count = output.len().min(self.read_chunk.remaining());
                self.read_chunk.copy_to_slice(&mut output[..count]);
                return Poll::Ready(Ok(count));
            }

            match Pin::new(&mut self.inner).poll_next(context) {
                Poll::Ready(Some(Ok(chunk))) if chunk.is_empty() => {}
                Poll::Ready(Some(Ok(chunk))) => self.read_chunk = chunk,
                Poll::Ready(Some(Err(error))) => return Poll::Ready(Err(error)),
                Poll::Ready(None) => return Poll::Ready(Ok(0)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S> AsyncWrite for MessageIo<S>
where
    S: Stream<Item = io::Result<Bytes>> + Sink<Bytes, Error = io::Error> + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        if input.is_empty() {
            return Poll::Ready(Ok(0));
        }
        match Pin::new(&mut self.inner).poll_ready(context) {
            Poll::Ready(Ok(())) => {
                Pin::new(&mut self.inner).start_send(Bytes::copy_from_slice(input))?;
                Poll::Ready(Ok(input.len()))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_close(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_close(context)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use futures::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    #[derive(Debug, Default)]
    struct MockMessages {
        incoming: VecDeque<io::Result<Bytes>>,
        outgoing: Vec<Bytes>,
    }

    impl Stream for MockMessages {
        type Item = io::Result<Bytes>;

        fn poll_next(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Option<Self::Item>> {
            Poll::Ready(self.incoming.pop_front())
        }
    }

    impl Sink<Bytes> for MockMessages {
        type Error = io::Error;

        fn poll_ready(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn start_send(mut self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
            self.outgoing.push(item);
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

    #[test]
    fn reads_across_message_boundaries_and_partial_buffers() -> io::Result<()> {
        let mock = MockMessages {
            incoming: VecDeque::from([
                Ok(Bytes::from_static(b"abc")),
                Ok(Bytes::new()),
                Ok(Bytes::from_static(b"defgh")),
            ]),
            outgoing: Vec::new(),
        };
        let mut io = MessageIo::new(mock);
        let mut output = [0_u8; 8];
        futures::executor::block_on(io.read_exact(&mut output))?;
        assert_eq!(&output, b"abcdefgh");
        Ok(())
    }

    #[test]
    fn each_write_becomes_one_binary_message() -> io::Result<()> {
        let mut io = MessageIo::new(MockMessages::default());
        futures::executor::block_on(async {
            io.write_all(b"one").await?;
            io.write_all(b"two").await?;
            io.flush().await
        })?;
        let mock = io.into_inner();
        assert_eq!(
            mock.outgoing,
            [Bytes::from_static(b"one"), Bytes::from_static(b"two")]
        );
        Ok(())
    }
}
