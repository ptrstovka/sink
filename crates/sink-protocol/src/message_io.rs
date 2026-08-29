use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Buf, Bytes, BytesMut};
use futures::{AsyncRead, AsyncWrite, Sink, Stream};

const YAMUX_HEADER_BYTES: usize = 12;
const YAMUX_DATA_TAG: u8 = 0;
const YAMUX_PING_TAG: u8 = 2;
const YAMUX_ACK_FLAG: u16 = 2;
const YAMUX_CONNECTION_STREAM_ID: [u8; 4] = [0; 4];

#[cfg(test)]
const YAMUX_SYN_FLAG: u16 = 1;

#[derive(Debug)]
enum ReadTerminal {
    Error(io::Error),
    Eof,
}

/// Adapts a message-oriented binary transport into the byte stream expected by yamux.
///
/// Runtime crates map their WebSocket implementation to a `Stream<Item =
/// io::Result<Bytes>> + Sink<Bytes, Error = io::Error>` before constructing this
/// adapter. Text/control messages remain part of the handshake/runtime layer.
#[derive(Debug)]
pub struct MessageIo<S> {
    inner: S,
    incoming_chunk: Bytes,
    read_chunk: Bytes,
    header: [u8; YAMUX_HEADER_BYTES],
    header_len: usize,
    body_remaining: usize,
    read_terminal: Option<ReadTerminal>,
    pending_pong: Option<Bytes>,
    outgoing_frame: Option<Bytes>,
    write_buffer: BytesMut,
    write_frame_bytes: Option<usize>,
    outgoing_needs_flush: bool,
}

impl<S> MessageIo<S> {
    #[must_use]
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            incoming_chunk: Bytes::new(),
            read_chunk: Bytes::new(),
            header: [0; YAMUX_HEADER_BYTES],
            header_len: 0,
            body_remaining: 0,
            read_terminal: None,
            pending_pong: None,
            outgoing_frame: None,
            write_buffer: BytesMut::with_capacity(YAMUX_HEADER_BYTES),
            write_frame_bytes: None,
            outgoing_needs_flush: false,
        }
    }

    #[must_use]
    pub fn into_inner(self) -> S {
        self.inner
    }

    /// Send a coalesced connection-level yamux Pong ahead of ordinary writes.
    ///
    /// yamux 0.13 stops reading its transport while a Pong is waiting for a
    /// blocked write. Two busy peers can therefore stop reading each other
    /// permanently. Keeping the reply at this full-duplex boundary lets reads
    /// continue while the WebSocket sink is backpressured.
    fn poll_outgoing(&mut self, context: &mut Context<'_>) -> Poll<io::Result<()>>
    where
        S: Sink<Bytes, Error = io::Error> + Unpin,
    {
        if let Some(pong) = self.pending_pong.take() {
            match Pin::new(&mut self.inner).poll_ready(context) {
                Poll::Ready(Ok(())) => {
                    Pin::new(&mut self.inner).start_send(pong)?;
                    self.outgoing_needs_flush = true;
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => {
                    self.pending_pong = Some(pong);
                    return Poll::Pending;
                }
            }
        }

        if let Some(frame) = self.outgoing_frame.take() {
            match Pin::new(&mut self.inner).poll_ready(context) {
                Poll::Ready(Ok(())) => {
                    Pin::new(&mut self.inner).start_send(frame)?;
                    self.outgoing_needs_flush = true;
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => {
                    self.outgoing_frame = Some(frame);
                    return Poll::Pending;
                }
            }
        }

        if self.outgoing_needs_flush {
            match Pin::new(&mut self.inner).poll_flush(context) {
                Poll::Ready(Ok(())) => self.outgoing_needs_flush = false,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }

        Poll::Ready(Ok(()))
    }

    fn decode_header(&mut self) -> Option<Bytes> {
        debug_assert_eq!(self.header_len, YAMUX_HEADER_BYTES);
        self.header_len = 0;

        let flags = u16::from_be_bytes([self.header[2], self.header[3]]);
        let is_connection_ping = self.header[0] == 0
            && self.header[1] == YAMUX_PING_TAG
            && flags & YAMUX_ACK_FLAG == 0
            && self.header[4..8] == YAMUX_CONNECTION_STREAM_ID;
        if is_connection_ping {
            let mut pong = self.header;
            // yamux's RTT Ping carries SYN, while its Pong carries ACK only.
            // Do not echo arbitrary request flags into the response.
            pong[2..4].copy_from_slice(&YAMUX_ACK_FLAG.to_be_bytes());
            // An honest yamux peer has at most one outstanding RTT Ping. Keep
            // only the newest reply so a malformed peer cannot grow memory.
            self.pending_pong = Some(Bytes::copy_from_slice(&pong));
            return None;
        }

        if self.header[0] == 0 && self.header[1] == YAMUX_DATA_TAG {
            self.body_remaining = u32::from_be_bytes([
                self.header[8],
                self.header[9],
                self.header[10],
                self.header[11],
            ]) as usize;
        }
        Some(Bytes::copy_from_slice(&self.header))
    }

    fn buffer_write(&mut self, input: &[u8]) -> usize {
        let remaining = match self.write_frame_bytes {
            Some(frame_bytes) => frame_bytes.saturating_sub(self.write_buffer.len()),
            None => YAMUX_HEADER_BYTES.saturating_sub(self.write_buffer.len()),
        };
        let count = remaining.min(input.len());
        self.write_buffer.extend_from_slice(&input[..count]);

        if self.write_frame_bytes.is_none() && self.write_buffer.len() == YAMUX_HEADER_BYTES {
            let body_bytes = if self.write_buffer[0] == 0 && self.write_buffer[1] == YAMUX_DATA_TAG
            {
                u32::from_be_bytes([
                    self.write_buffer[8],
                    self.write_buffer[9],
                    self.write_buffer[10],
                    self.write_buffer[11],
                ]) as usize
            } else {
                0
            };
            self.write_frame_bytes = Some(YAMUX_HEADER_BYTES.saturating_add(body_bytes));
        }

        if self.write_frame_bytes == Some(self.write_buffer.len()) {
            self.outgoing_frame = Some(self.write_buffer.split().freeze());
            self.write_frame_bytes = None;
        }
        count
    }
}

impl<S> AsyncRead for MessageIo<S>
where
    S: Stream<Item = io::Result<Bytes>> + Sink<Bytes, Error = io::Error> + Unpin,
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
            // A blocked Pong must never prevent the read half from draining.
            // `poll_outgoing` registers the write waker; the read poll below
            // independently registers the read waker before returning Pending.
            if let Poll::Ready(Err(error)) = self.poll_outgoing(context) {
                return Poll::Ready(Err(error));
            }

            if self.read_chunk.has_remaining() {
                let count = output.len().min(self.read_chunk.remaining());
                self.read_chunk.copy_to_slice(&mut output[..count]);
                return Poll::Ready(Ok(count));
            }

            if self.body_remaining > 0 && self.incoming_chunk.has_remaining() {
                let count = self.body_remaining.min(self.incoming_chunk.remaining());
                self.body_remaining -= count;
                self.read_chunk = self.incoming_chunk.split_to(count);
                continue;
            }

            if self.body_remaining == 0 && self.header_len == YAMUX_HEADER_BYTES {
                if let Some(header) = self.decode_header() {
                    self.read_chunk = header;
                }
                continue;
            }

            if self.body_remaining == 0 && self.incoming_chunk.has_remaining() {
                let count =
                    (YAMUX_HEADER_BYTES - self.header_len).min(self.incoming_chunk.remaining());
                let start = self.header_len;
                let end = self.header_len + count;
                let incoming = self.incoming_chunk.split_to(count);
                self.header[start..end].copy_from_slice(&incoming);
                self.header_len = end;
                continue;
            }

            if let Some(terminal) = self.read_terminal.take() {
                if self.header_len > 0 {
                    self.read_chunk = Bytes::copy_from_slice(&self.header[..self.header_len]);
                    self.header_len = 0;
                    self.read_terminal = Some(terminal);
                    continue;
                }
                return match terminal {
                    ReadTerminal::Error(error) => Poll::Ready(Err(error)),
                    ReadTerminal::Eof => Poll::Ready(Ok(0)),
                };
            }

            match Pin::new(&mut self.inner).poll_next(context) {
                Poll::Ready(Some(Ok(chunk))) if chunk.is_empty() => {}
                Poll::Ready(Some(Ok(chunk))) => self.incoming_chunk = chunk,
                Poll::Ready(Some(Err(error))) => {
                    self.read_terminal = Some(ReadTerminal::Error(error));
                }
                Poll::Ready(None) => self.read_terminal = Some(ReadTerminal::Eof),
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
        match self.poll_outgoing(context) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }
        Poll::Ready(Ok(self.buffer_write(input)))
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.poll_outgoing(context) {
            Poll::Ready(Ok(())) => {}
            other => return other,
        }
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_close(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.poll_outgoing(context) {
            Poll::Ready(Ok(())) => {}
            other => return other,
        }
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
    fn each_yamux_frame_becomes_one_binary_message() -> io::Result<()> {
        let mut io = MessageIo::new(MockMessages::default());
        let first = yamux_header(YAMUX_DATA_TAG, 0, 1, 3);
        let second = yamux_header(YAMUX_DATA_TAG, 0, 3, 3);
        futures::executor::block_on(async {
            io.write_all(&first).await?;
            io.write_all(b"one").await?;
            io.write_all(&second).await?;
            io.write_all(b"two").await?;
            io.flush().await
        })?;
        let mock = io.into_inner();
        assert_eq!(
            mock.outgoing,
            [
                Bytes::from([first.as_slice(), b"one"].concat()),
                Bytes::from([second.as_slice(), b"two"].concat()),
            ]
        );
        Ok(())
    }

    #[test]
    fn connection_ping_is_answered_below_yamux_and_following_data_is_read() -> io::Result<()> {
        let ping = yamux_header(YAMUX_PING_TAG, YAMUX_SYN_FLAG, 0, 42);
        let data = yamux_header(YAMUX_DATA_TAG, 1, 1, 5);
        let mock = MockMessages {
            incoming: VecDeque::from([
                Ok(Bytes::copy_from_slice(&ping[..7])),
                Ok(Bytes::copy_from_slice(&ping[7..])),
                Ok(Bytes::copy_from_slice(&data)),
                Ok(Bytes::from_static(b"hello")),
            ]),
            outgoing: Vec::new(),
        };
        let mut io = MessageIo::new(mock);
        let mut output = [0_u8; YAMUX_HEADER_BYTES + 5];
        futures::executor::block_on(io.read_exact(&mut output))?;

        assert_eq!(&output[..YAMUX_HEADER_BYTES], &data);
        assert_eq!(&output[YAMUX_HEADER_BYTES..], b"hello");
        let mock = io.into_inner();
        assert_eq!(
            mock.outgoing,
            [Bytes::copy_from_slice(&yamux_header(
                YAMUX_PING_TAG,
                YAMUX_ACK_FLAG,
                0,
                42,
            ))]
        );
        Ok(())
    }

    #[test]
    fn data_body_that_looks_like_ping_is_not_intercepted() -> io::Result<()> {
        let data = yamux_header(YAMUX_DATA_TAG, 0, 1, YAMUX_HEADER_BYTES as u32);
        let ping_shaped_body = yamux_header(YAMUX_PING_TAG, YAMUX_SYN_FLAG, 0, 7);
        let mock = MockMessages {
            incoming: VecDeque::from([
                Ok(Bytes::copy_from_slice(&data)),
                Ok(Bytes::copy_from_slice(&ping_shaped_body)),
            ]),
            outgoing: Vec::new(),
        };
        let mut io = MessageIo::new(mock);
        let mut output = [0_u8; YAMUX_HEADER_BYTES * 2];
        futures::executor::block_on(io.read_exact(&mut output))?;

        assert_eq!(&output[..YAMUX_HEADER_BYTES], &data);
        assert_eq!(&output[YAMUX_HEADER_BYTES..], &ping_shaped_body);
        assert!(io.into_inner().outgoing.is_empty());
        Ok(())
    }

    #[test]
    fn pong_is_never_inserted_between_a_data_header_and_body() -> io::Result<()> {
        let data = yamux_header(YAMUX_DATA_TAG, 0, 1, 3);
        let ping = yamux_header(YAMUX_PING_TAG, YAMUX_SYN_FLAG, 0, 99);
        let mock = MockMessages {
            incoming: VecDeque::from([Ok(Bytes::copy_from_slice(&ping))]),
            outgoing: Vec::new(),
        };
        let mut io = MessageIo::new(mock);

        futures::executor::block_on(async {
            // yamux writes a frame header and body separately. Keep the
            // incomplete data frame private while an inbound Ping is handled.
            io.write_all(&data).await?;
            let mut ignored = [0_u8; 1];
            assert_eq!(io.read(&mut ignored).await?, 0);
            io.write_all(b"one").await?;
            io.flush().await
        })?;

        let mock = io.into_inner();
        assert_eq!(
            mock.outgoing,
            [
                Bytes::copy_from_slice(&yamux_header(YAMUX_PING_TAG, YAMUX_ACK_FLAG, 0, 99,)),
                Bytes::from([data.as_slice(), b"one"].concat()),
            ]
        );
        Ok(())
    }

    fn yamux_header(tag: u8, flags: u16, stream_id: u32, length: u32) -> [u8; 12] {
        let mut header = [0_u8; 12];
        header[1] = tag;
        header[2..4].copy_from_slice(&flags.to_be_bytes());
        header[4..8].copy_from_slice(&stream_id.to_be_bytes());
        header[8..12].copy_from_slice(&length.to_be_bytes());
        header
    }
}
