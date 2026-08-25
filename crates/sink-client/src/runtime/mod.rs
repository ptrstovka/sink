//! Reconnecting control client and streaming local HTTP(S) proxy runtime.

mod backoff;
mod control;
mod proxy;
mod websocket_io;

use std::{fmt, future::poll_fn, time::Duration};

use futures::{AsyncRead, AsyncWrite};
use sink_protocol::{ClientHello, MessageIo, RejectCode, Subdomain};
use tokio::{
    sync::{broadcast, watch},
    time::timeout,
};
use tokio_util::{compat::FuturesAsyncReadCompatExt, sync::CancellationToken, task::TaskTracker};
use uuid::Uuid;
use yamux::{Config as YamuxConfig, Connection, Mode};

use crate::{
    cli::{CliValidationError, HttpArgs},
    config::ResolvedConfig,
    target::{LocalTarget, PublicUrl},
};

use backoff::ReconnectBackoff;
use control::EstablishedControl;
use proxy::LocalProxy;
use websocket_io::WebSocketBinary;

pub use proxy::{ProxySetupError, RequestSummary, resolve_local_uri, rewrite_local_request};

const REQUEST_SUMMARY_CAPACITY: usize = 512;
const DEFAULT_DRAIN_TIMEOUT: Duration = Duration::from_secs(10);
const FORCED_TASK_CLEANUP_TIMEOUT: Duration = Duration::from_secs(1);
const CONTROL_CLOSE_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectionInfo {
    pub hostname: String,
    pub subdomain: Subdomain,
    pub public_http_url: String,
    pub public_https_url: String,
    pub reconnect_grace_seconds: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TunnelPhase {
    Reconnecting {
        attempt: u32,
        retry_in: Option<Duration>,
        last_error: Option<String>,
    },
    Connected(ConnectionInfo),
    Draining,
    Stopped,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TunnelState {
    pub session_id: Uuid,
    pub phase: TunnelPhase,
}

#[derive(Clone)]
pub struct RuntimeHandle {
    session_id: Uuid,
    shutdown: CancellationToken,
    state: watch::Receiver<TunnelState>,
    summaries: broadcast::Sender<RequestSummary>,
}

impl fmt::Debug for RuntimeHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeHandle")
            .field("session_id", &self.session_id)
            .field("state", &self.state.borrow().clone())
            .finish_non_exhaustive()
    }
}

impl RuntimeHandle {
    #[must_use]
    pub fn session_id(&self) -> Uuid {
        self.session_id
    }

    #[must_use]
    pub fn current_state(&self) -> TunnelState {
        self.state.borrow().clone()
    }

    #[must_use]
    pub fn subscribe_state(&self) -> watch::Receiver<TunnelState> {
        self.state.clone()
    }

    #[must_use]
    pub fn subscribe_requests(&self) -> broadcast::Receiver<RequestSummary> {
        self.summaries.subscribe()
    }

    /// Stop accepting new tunnel streams and give active exchanges a bounded
    /// drain opportunity. Repeated forced termination remains binary-owned.
    pub fn begin_graceful_shutdown(&self) {
        self.shutdown.cancel();
    }
}

pub struct TunnelRuntime {
    config: ResolvedConfig,
    local_proxy: LocalProxy,
    session_id: Uuid,
    initial_requested_hostname: Option<String>,
    accepted: Option<ConnectionInfo>,
    shutdown: CancellationToken,
    state: watch::Sender<TunnelState>,
    summaries: broadcast::Sender<RequestSummary>,
    drain_timeout: Duration,
}

impl fmt::Debug for TunnelRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TunnelRuntime")
            .field("config", &self.config)
            .field("local_proxy", &self.local_proxy)
            .field("session_id", &self.session_id)
            .field(
                "initial_requested_hostname",
                &self.initial_requested_hostname,
            )
            .field("accepted", &self.accepted)
            .field("drain_timeout", &self.drain_timeout)
            .finish_non_exhaustive()
    }
}

impl TunnelRuntime {
    /// Build the runtime directly from the lead-owned CLI/config wiring types.
    pub fn from_http(args: &HttpArgs, config: ResolvedConfig) -> Result<Self, RuntimeError> {
        args.validate()?;
        Self::new(
            config,
            args.target.clone(),
            args.url.clone(),
            args.local_tls_insecure,
        )
    }

    pub fn new(
        config: ResolvedConfig,
        target: LocalTarget,
        requested_public_url: Option<PublicUrl>,
        local_tls_insecure: bool,
    ) -> Result<Self, RuntimeError> {
        let session_id = Uuid::new_v4();
        let initial_requested_hostname =
            requested_public_url.map(|public| public.requested_hostname().to_owned());
        let shutdown = CancellationToken::new();
        let initial_state = TunnelState {
            session_id,
            phase: TunnelPhase::Reconnecting {
                attempt: 0,
                retry_in: None,
                last_error: None,
            },
        };
        let (state, _) = watch::channel(initial_state);
        let (summaries, _) = broadcast::channel(REQUEST_SUMMARY_CAPACITY);
        let local_proxy = LocalProxy::new(target, local_tls_insecure, summaries.clone())?;
        Ok(Self {
            config,
            local_proxy,
            session_id,
            initial_requested_hostname,
            accepted: None,
            shutdown,
            state,
            summaries,
            drain_timeout: DEFAULT_DRAIN_TIMEOUT,
        })
    }

    #[must_use]
    pub fn handle(&self) -> RuntimeHandle {
        RuntimeHandle {
            session_id: self.session_id,
            shutdown: self.shutdown.clone(),
            state: self.state.subscribe(),
            summaries: self.summaries.clone(),
        }
    }

    #[must_use]
    pub fn session_id(&self) -> Uuid {
        self.session_id
    }

    #[must_use]
    pub fn client_hello(&self) -> ClientHello {
        ClientHello::new(
            self.session_id,
            self.expected_hostname().map(ToOwned::to_owned),
            env!("CARGO_PKG_VERSION"),
        )
    }

    #[must_use]
    pub fn accepted_connection(&self) -> Option<&ConnectionInfo> {
        self.accepted.as_ref()
    }

    /// Run one control connection through handshake and binary yamux mode.
    /// Transient errors are returned to [`Self::run`] for reconnect handling;
    /// application requests are never retained or replayed across this call.
    pub async fn run_one_connection(&mut self) -> Result<ConnectionEnd, RuntimeError> {
        let hello = self.client_hello();
        let expected_hostname = self.expected_hostname().map(ToOwned::to_owned);
        let EstablishedControl { websocket, info } = {
            let establish = control::establish(
                &self.config,
                &hello,
                expected_hostname.as_deref(),
                self.accepted.as_ref(),
            );
            tokio::pin!(establish);
            tokio::select! {
                () = self.shutdown.cancelled() => return Ok(ConnectionEnd::Shutdown),
                result = &mut establish => result?,
            }
        };

        self.accepted = Some(info.clone());
        self.publish(TunnelPhase::Connected(info));
        let bytes = WebSocketBinary::new(websocket);
        let io = MessageIo::new(bytes);
        let connection = Connection::new(io, YamuxConfig::default(), Mode::Client);
        self.drive_connection(connection).await
    }

    /// Retry transient failures for the lifetime of the process while keeping
    /// the same UUID and, after first acceptance, the same assigned hostname.
    pub async fn run(mut self) -> Result<(), RuntimeError> {
        let mut backoff = ReconnectBackoff::default();
        let mut attempt = 0_u32;

        loop {
            if self.shutdown.is_cancelled() {
                self.publish(TunnelPhase::Stopped);
                return Ok(());
            }
            self.publish(TunnelPhase::Reconnecting {
                attempt,
                retry_in: None,
                last_error: None,
            });

            let result = self.run_one_connection().await;
            let failure = match result {
                Ok(ConnectionEnd::Shutdown) => {
                    self.publish(TunnelPhase::Stopped);
                    return Ok(());
                }
                Ok(ConnectionEnd::Disconnected) => {
                    backoff.reset();
                    RuntimeError::TunnelDisconnected
                }
                Err(error) if error.disposition() == FailureDisposition::Permanent => {
                    self.publish(TunnelPhase::Stopped);
                    return Err(error);
                }
                Err(error) => error,
            };

            let delay = backoff.next_delay(self.session_id);
            attempt = attempt.saturating_add(1);
            self.publish(TunnelPhase::Reconnecting {
                attempt,
                retry_in: Some(delay),
                last_error: Some(failure.to_string()),
            });
            tokio::select! {
                () = self.shutdown.cancelled() => {
                    self.publish(TunnelPhase::Stopped);
                    return Ok(());
                }
                () = tokio::time::sleep(delay) => {}
            }
        }
    }

    async fn drive_connection<T>(
        &mut self,
        mut connection: Connection<T>,
    ) -> Result<ConnectionEnd, RuntimeError>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let tasks = TaskTracker::new();
        let force_shutdown = CancellationToken::new();
        let exchange_proxy = self
            .local_proxy
            .for_connection(tasks.clone(), force_shutdown.clone());

        loop {
            tokio::select! {
                () = self.shutdown.cancelled() => {
                    self.publish(TunnelPhase::Draining);
                    self.drain_connection(&mut connection, &tasks, &force_shutdown).await;
                    return Ok(ConnectionEnd::Shutdown);
                }
                inbound = poll_fn(|context| connection.poll_next_inbound(context)) => {
                    match inbound {
                        Some(Ok(stream)) => {
                            let proxy = exchange_proxy.clone();
                            let force = force_shutdown.clone();
                            tasks.spawn(proxy::serve_stream(stream.compat(), proxy, force));
                        }
                        Some(Err(_)) | None => {
                            cleanup_tasks(&tasks, &force_shutdown).await;
                            return Ok(ConnectionEnd::Disconnected);
                        }
                    }
                }
            }
        }
    }

    async fn drain_connection<T>(
        &self,
        connection: &mut Connection<T>,
        tasks: &TaskTracker,
        force_shutdown: &CancellationToken,
    ) where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        tasks.close();
        let wait = tasks.wait();
        tokio::pin!(wait);
        let deadline = tokio::time::sleep(self.drain_timeout);
        tokio::pin!(deadline);

        loop {
            tokio::select! {
                () = &mut wait => break,
                inbound = poll_fn(|context| connection.poll_next_inbound(context)) => {
                    match inbound {
                        Some(Ok(stream)) => drop(stream),
                        Some(Err(_)) | None => {
                            force_shutdown.cancel();
                            let _ = timeout(FORCED_TASK_CLEANUP_TIMEOUT, tasks.wait()).await;
                            return;
                        }
                    }
                }
                () = &mut deadline => {
                    force_shutdown.cancel();
                    let _ = timeout(FORCED_TASK_CLEANUP_TIMEOUT, tasks.wait()).await;
                    return;
                }
            }
        }

        let _ = timeout(
            CONTROL_CLOSE_TIMEOUT,
            poll_fn(|context| connection.poll_close(context)),
        )
        .await;
    }

    fn expected_hostname(&self) -> Option<&str> {
        self.accepted
            .as_ref()
            .map(|info| info.hostname.as_str())
            .or(self.initial_requested_hostname.as_deref())
    }

    fn publish(&self, phase: TunnelPhase) {
        self.state.send_replace(TunnelState {
            session_id: self.session_id,
            phase,
        });
    }
}

async fn cleanup_tasks(tasks: &TaskTracker, force_shutdown: &CancellationToken) {
    force_shutdown.cancel();
    tasks.close();
    let _ = timeout(FORCED_TASK_CLEANUP_TIMEOUT, tasks.wait()).await;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectionEnd {
    Shutdown,
    Disconnected,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailureDisposition {
    Permanent,
    Transient,
}

#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    #[error("invalid tunnel command: {0}")]
    ClientArguments(#[from] CliValidationError),
    #[error("the control server address cannot be converted to a WebSocket endpoint")]
    InvalidControlAddress,
    #[error("the authentication token cannot be represented as a Bearer credential")]
    InvalidAuthenticationToken,
    #[error("the control server is temporarily unavailable")]
    ControlUnavailable,
    #[error(
        "the control server rejected the WebSocket upgrade with HTTP {status}; check the token, server address, and client/server versions"
    )]
    UpgradeRejected { status: http::StatusCode },
    #[error(
        "the control server rejected the tunnel ({code:?}); check the token, user state, client/server versions, and requested hostname"
    )]
    Rejected { code: RejectCode },
    #[error("the control server returned an invalid or mismatched protocol handshake")]
    ProtocolViolation,
    #[error("the tunnel control connection was interrupted")]
    TunnelDisconnected,
    #[error("could not configure the local HTTP(S) proxy: {0}")]
    LocalProxySetup(#[from] ProxySetupError),
}

impl RuntimeError {
    #[must_use]
    pub fn disposition(&self) -> FailureDisposition {
        match self {
            Self::ControlUnavailable | Self::TunnelDisconnected => FailureDisposition::Transient,
            Self::ClientArguments(_)
            | Self::InvalidControlAddress
            | Self::InvalidAuthenticationToken
            | Self::UpgradeRejected { .. }
            | Self::Rejected { .. }
            | Self::ProtocolViolation
            | Self::LocalProxySetup(_) => FailureDisposition::Permanent,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bytes::Bytes;
    use futures::future::join_all;
    use http::{Request, StatusCode};
    use http_body_util::{BodyExt, Empty};
    use hyper::client::conn::http1;
    use hyper_util::rt::TokioIo;
    use sink_protocol::{SessionAccepted, Subdomain};
    use tokio_util::compat::TokioAsyncReadCompatExt;

    use crate::config::{AuthToken, RunOverrides, SavedConfig};

    use super::*;

    fn resolved_config() -> Result<ResolvedConfig, proxy::BoxError> {
        Ok(SavedConfig::default().resolve_for_http(RunOverrides {
            authtoken: Some(AuthToken::new("runtime-test-token")?),
            server_addr: Some("https://connect.example.test".parse()?),
            allow_plaintext_control: false,
        })?)
    }

    #[test]
    fn one_run_uuid_and_requested_hostname_are_stable_across_reconnects()
    -> Result<(), proxy::BoxError> {
        let mut runtime = TunnelRuntime::new(
            resolved_config()?,
            LocalTarget::from_str("http://localhost:3000")?,
            None,
            false,
        )?;
        let session = runtime.session_id();
        assert_eq!(runtime.client_hello().session_id, session);
        assert_eq!(runtime.client_hello().requested_hostname, None);

        let accepted = SessionAccepted::new(
            session,
            Subdomain::parse("generated-42")?,
            "http://generated-42.serus.eu",
            "https://generated-42.serus.eu",
            30,
        );
        runtime.accepted = Some(control::validate_acceptance(accepted, session, None, None)?);
        for _ in 0..3 {
            let hello = runtime.client_hello();
            assert_eq!(hello.session_id, session);
            assert_eq!(
                hello.requested_hostname.as_deref(),
                Some("generated-42.serus.eu")
            );
        }
        Ok(())
    }

    #[test]
    fn custom_hostname_is_sent_exactly_before_first_acceptance() -> Result<(), proxy::BoxError> {
        let runtime = TunnelRuntime::new(
            resolved_config()?,
            "3000".parse()?,
            Some("https://Demo.serus.eu".parse()?),
            false,
        )?;
        assert_eq!(
            runtime.client_hello().requested_hostname.as_deref(),
            Some("demo.serus.eu")
        );
        Ok(())
    }

    #[test]
    fn permanent_and_transient_errors_are_explicit() {
        assert_eq!(
            RuntimeError::ControlUnavailable.disposition(),
            FailureDisposition::Transient
        );
        assert_eq!(
            RuntimeError::Rejected {
                code: RejectCode::AuthenticationFailed
            }
            .disposition(),
            FailureDisposition::Permanent
        );
        assert_eq!(
            RuntimeError::ProtocolViolation.disposition(),
            FailureDisposition::Permanent
        );
    }

    #[tokio::test]
    async fn yamux_accepts_concurrent_independent_http_streams() -> Result<(), proxy::BoxError> {
        const STREAMS: usize = 16;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let unused_port = listener.local_addr()?.port();
        drop(listener);

        let mut runtime = TunnelRuntime::new(
            resolved_config()?,
            format!("http://127.0.0.1:{unused_port}").parse()?,
            None,
            false,
        )?;
        runtime.drain_timeout = Duration::from_secs(1);
        let handle = runtime.handle();
        let (client_transport, server_transport) = tokio::io::duplex(1024 * 1024);
        let client_connection = Connection::new(
            client_transport.compat(),
            YamuxConfig::default(),
            Mode::Client,
        );
        let mut server_connection = Connection::new(
            server_transport.compat(),
            YamuxConfig::default(),
            Mode::Server,
        );
        let runtime_task =
            tokio::spawn(async move { runtime.drive_connection(client_connection).await });

        let mut streams = Vec::with_capacity(STREAMS);
        for _ in 0..STREAMS {
            streams.push(poll_fn(|context| server_connection.poll_new_outbound(context)).await?);
        }
        let server_driver = tokio::spawn(async move {
            while let Some(inbound) =
                poll_fn(|context| server_connection.poll_next_inbound(context)).await
            {
                if inbound.is_err() {
                    break;
                }
            }
        });

        let statuses = join_all(
            streams
                .into_iter()
                .enumerate()
                .map(|(index, stream)| request_status(stream, index)),
        )
        .await;
        for status in statuses {
            assert_eq!(status?, StatusCode::SERVICE_UNAVAILABLE);
        }

        handle.begin_graceful_shutdown();
        assert_eq!(runtime_task.await??, ConnectionEnd::Shutdown);
        server_driver.await?;
        Ok(())
    }

    async fn request_status(
        stream: yamux::Stream,
        index: usize,
    ) -> Result<StatusCode, proxy::BoxError> {
        let (mut sender, connection) =
            http1::handshake::<_, Empty<Bytes>>(TokioIo::new(stream.compat())).await?;
        let driver = tokio::spawn(connection);
        let response = sender
            .send_request(
                Request::builder()
                    .uri(format!("/stream/{index}"))
                    .body(Empty::new())?,
            )
            .await?;
        let status = response.status();
        let _ = response.into_body().collect().await?;
        drop(sender);
        timeout(Duration::from_secs(1), driver).await???;
        Ok(status)
    }
}
