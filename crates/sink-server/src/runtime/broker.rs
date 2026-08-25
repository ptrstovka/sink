use std::{collections::VecDeque, task::Poll};

use futures::{AsyncRead, AsyncWrite, future::poll_fn};
use thiserror::Error;
use tokio::sync::{mpsc, oneshot};
use yamux::{Config, Connection, ConnectionError, Mode, Stream};

const COMMANDS_PER_POLL: usize = 256;

type OpenReply = oneshot::Sender<Result<Stream, BrokerError>>;

#[derive(Debug)]
enum DriverCommand {
    Open(OpenReply),
    Shutdown,
}

#[derive(Clone, Debug)]
pub(crate) struct StreamBroker {
    commands: mpsc::UnboundedSender<DriverCommand>,
}

impl StreamBroker {
    pub(crate) fn channel() -> (Self, StreamRequests) {
        let (commands, requests) = mpsc::unbounded_channel();
        (Self { commands }, StreamRequests { requests })
    }

    pub(crate) async fn open_stream(&self) -> Result<Stream, BrokerError> {
        let (reply, response) = oneshot::channel();
        self.commands
            .send(DriverCommand::Open(reply))
            .map_err(|_| BrokerError::Unavailable)?;
        response.await.unwrap_or(Err(BrokerError::Unavailable))
    }

    pub(crate) fn is_available(&self) -> bool {
        !self.commands.is_closed()
    }

    pub(crate) fn shutdown(&self) {
        let _ = self.commands.send(DriverCommand::Shutdown);
    }
}

#[derive(Debug)]
pub(crate) struct StreamRequests {
    requests: mpsc::UnboundedReceiver<DriverCommand>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DriverExit {
    Shutdown,
    TransportClosed,
    TransportError,
    UnexpectedInboundStream,
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[error("tunnel stream unavailable")]
pub(crate) enum BrokerError {
    Unavailable,
}

pub(crate) async fn drive_yamux<IO>(io: IO, requests: StreamRequests) -> DriverExit
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let mut connection = Connection::new(io, Config::default(), Mode::Server);
    let mut requests = requests.requests;
    let mut pending = VecDeque::<OpenReply>::new();
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
                Poll::Ready(Some(DriverCommand::Open(reply))) if !shutdown => {
                    pending.push_back(reply);
                }
                Poll::Ready(Some(DriverCommand::Open(reply))) => {
                    let _ = reply.send(Err(BrokerError::Unavailable));
                }
                Poll::Ready(Some(DriverCommand::Shutdown)) | Poll::Ready(None) => {
                    shutdown = true;
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

        while let Some(reply) = pending.pop_front() {
            match connection.poll_new_outbound(context) {
                Poll::Ready(Ok(stream)) => {
                    let _ = reply.send(Ok(stream));
                }
                Poll::Ready(Err(error)) => {
                    let _ = reply.send(Err(BrokerError::Unavailable));
                    fail_pending(&mut pending);
                    if matches!(error, ConnectionError::Closed) {
                        return Poll::Ready(DriverExit::TransportClosed);
                    }
                    tracing::warn!(%error, "yamux could not open an outbound stream");
                    return Poll::Ready(DriverExit::TransportError);
                }
                Poll::Pending => {
                    pending.push_front(reply);
                    break;
                }
            }
        }

        Poll::Pending
    })
    .await
}

fn fail_pending(pending: &mut VecDeque<OpenReply>) {
    for reply in pending.drain(..) {
        let _ = reply.send(Err(BrokerError::Unavailable));
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
        let (adapter, _) = AxumMessageAdapter::new(socket);
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
    async fn broker_opens_many_streaming_exchanges_concurrently() -> Result<(), io::Error> {
        let (server_io, client_io) = tokio::io::duplex(2 * 1024 * 1024);
        let (broker, requests) = StreamBroker::channel();
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
                let mut stream = broker
                    .open_stream()
                    .await
                    .map_err(io::Error::other)?
                    .compat();
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
