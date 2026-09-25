//! Client-side commands for Sink's authenticated namespace management API.

use std::{future::Future, io, net::IpAddr, sync::Arc, time::Duration};

use bytes::Bytes;
use http::{
    HeaderValue, Method, Request, StatusCode, Uri,
    header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, HOST},
};
use http_body_util::{BodyExt as _, Full, Limited};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use rustls::{ClientConfig, RootCertStore, crypto::CryptoProvider, pki_types::ServerName};
use serde::de::DeserializeOwned;
use sink_protocol::{
    ManagementErrorCode, ManagementErrorResponse, NAMESPACE_COLLECTION_PATH, Namespace,
    NamespaceClaimRequest, NamespaceListResponse, NamespaceResponse, NamespaceState,
    NamespaceTlsMode,
};
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
    time::{Instant, sleep_until, timeout, timeout_at},
};
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;
use url::Url;
use zeroize::Zeroizing;

use crate::{
    cli::{NamespaceArgs, NamespaceCommand},
    config::{ConfigError, ConfigStore, ResolvedConfig},
};

const MAX_RESPONSE_BODY_BYTES: usize = 64 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const INITIAL_POLL_DELAY: Duration = Duration::from_millis(250);
const MAX_POLL_DELAY: Duration = Duration::from_secs(2);

trait ControlIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T> ControlIo for T where T: AsyncRead + AsyncWrite + Unpin + Send {}
type BoxedControlIo = Box<dyn ControlIo>;

/// Successful output from one namespace command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NamespaceCommandOutput {
    /// One or more namespace state records. An empty vector is a successful empty list.
    Namespaces(Vec<Namespace>),
    /// Confirmation that the named namespace was released.
    Released(String),
}

impl NamespaceCommandOutput {
    /// Write the stable, line-oriented command output.
    pub fn write_to(&self, writer: &mut impl io::Write) -> io::Result<()> {
        match self {
            Self::Namespaces(namespaces) if namespaces.is_empty() => {
                writeln!(writer, "no namespaces")
            }
            Self::Namespaces(namespaces) => {
                for namespace in namespaces {
                    writeln!(
                        writer,
                        "namespace {}: {}{}",
                        namespace.hostname,
                        namespace_state_name(namespace.state),
                        namespace_mode_suffix(namespace.tls_mode)
                    )?;
                }
                Ok(())
            }
            Self::Released(hostname) => writeln!(writer, "namespace {hostname}: released"),
        }
    }
}

/// Namespace command failures. Authentication credentials are never retained in an error.
#[derive(Debug, Error)]
pub enum NamespaceError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error("the authentication token cannot be represented as a Bearer credential")]
    InvalidAuthenticationToken,
    #[error("the configured control-server address cannot be used for namespace management")]
    InvalidControlAddress,
    #[error("could not initialize TLS for the namespace control server")]
    TlsSetup,
    #[error("could not connect to the namespace control server")]
    Connect(#[source] io::Error),
    #[error("could not establish TLS with the namespace control server")]
    Tls(#[source] io::Error),
    #[error("could not encode the namespace request")]
    RequestEncode(#[source] serde_json::Error),
    #[error("could not build the namespace request")]
    RequestBuild,
    #[error("the namespace API request timed out")]
    RequestTimeout,
    #[error("the namespace API HTTP exchange failed")]
    Http(#[source] hyper::Error),
    #[error("the namespace control server closed the connection before responding")]
    ConnectionClosed,
    #[error("the namespace API returned an invalid or oversized response body")]
    ResponseBody,
    #[error("the namespace API returned invalid JSON with HTTP {status}")]
    ResponseDecode {
        status: StatusCode,
        #[source]
        source: serde_json::Error,
    },
    #[error("namespace API error `{code}` (HTTP {status}): {message}")]
    Api {
        status: StatusCode,
        code: &'static str,
        message: String,
    },
    #[error("the namespace API returned unexpected HTTP {status}")]
    UnexpectedStatus { status: StatusCode },
    #[error("namespace `{hostname}` entered the failed state")]
    ClaimFailed { hostname: String },
    #[error("namespace `{hostname}` is being released and cannot become active")]
    ClaimReleasing { hostname: String },
    #[error(
        "timed out after {timeout_seconds}s waiting for namespace `{hostname}` to become active (last state: {last_state})"
    )]
    ClaimTimeout {
        hostname: String,
        timeout_seconds: u64,
        last_state: &'static str,
    },
    #[error("namespace operation cancelled")]
    Cancelled,
}

/// Run one namespace command using saved configuration plus its one-run overrides.
pub async fn run(
    arguments: NamespaceArgs,
    cancellation: CancellationToken,
) -> Result<NamespaceCommandOutput, NamespaceError> {
    let saved = ConfigStore::platform()?.load()?;
    let resolved = arguments.command.control().resolve_config(&saved)?;
    execute(
        arguments.command,
        resolved,
        cancellation,
        NamespaceSettings::production(),
    )
    .await
}

async fn execute(
    command: NamespaceCommand,
    config: ResolvedConfig,
    cancellation: CancellationToken,
    settings: NamespaceSettings,
) -> Result<NamespaceCommandOutput, NamespaceError> {
    let claim_wait = match &command {
        NamespaceCommand::Claim(arguments) if !arguments.no_wait => {
            Some(ClaimWait::new(Duration::from_secs(arguments.timeout)))
        }
        _ => None,
    };
    let request_timeout = command_request_timeout(&command, settings.request_timeout);
    let api = NamespaceApiClient::new(config, request_timeout)?;
    match command {
        NamespaceCommand::Claim(arguments) => {
            let mut namespace = if let Some(wait) = claim_wait {
                match timeout_at(
                    wait.deadline,
                    api.claim(&arguments.hostname, arguments.passthrough, &cancellation),
                )
                .await
                {
                    Ok(result) => result?,
                    Err(_) => {
                        return Err(NamespaceError::ClaimTimeout {
                            hostname: arguments.hostname,
                            timeout_seconds: wait.timeout_seconds,
                            last_state: "unknown",
                        });
                    }
                }
            } else {
                api.claim(&arguments.hostname, arguments.passthrough, &cancellation)
                    .await?
            };
            if arguments.no_wait {
                ensure_claim_can_succeed(&namespace)?;
            } else if namespace.state != NamespaceState::Active {
                ensure_claim_can_succeed(&namespace)?;
                eprintln!(
                    "waiting for namespace {} to become active (current state: {}, timeout: {}s)",
                    namespace.hostname,
                    namespace_state_name(namespace.state),
                    arguments.timeout
                );
                let hostname = namespace.hostname.clone();
                namespace = wait_for_active(
                    namespace,
                    claim_wait.expect("waiting claims have a deadline"),
                    settings.poll_policy,
                    &cancellation,
                    || api.status(&hostname, &cancellation),
                )
                .await?;
            }
            Ok(NamespaceCommandOutput::Namespaces(vec![namespace]))
        }
        NamespaceCommand::List(_) => {
            let namespaces = api.list(&cancellation).await?;
            Ok(NamespaceCommandOutput::Namespaces(namespaces))
        }
        NamespaceCommand::Status(arguments) => {
            let namespace = api.status(&arguments.hostname, &cancellation).await?;
            Ok(NamespaceCommandOutput::Namespaces(vec![namespace]))
        }
        NamespaceCommand::Release(arguments) => {
            api.release(&arguments.hostname, &cancellation).await?;
            Ok(NamespaceCommandOutput::Released(arguments.hostname))
        }
    }
}

fn command_request_timeout(command: &NamespaceCommand, default: Duration) -> Duration {
    match command {
        // A waited claim may legitimately keep its initial POST open while
        // issuance completes, but ClaimWait still caps the whole POST + poll
        // sequence. --no-wait has no activation budget and keeps the normal
        // bounded request timeout.
        NamespaceCommand::Claim(arguments) if !arguments.no_wait => {
            default.max(Duration::from_secs(arguments.timeout))
        }
        NamespaceCommand::Claim(_)
        | NamespaceCommand::List(_)
        | NamespaceCommand::Status(_)
        | NamespaceCommand::Release(_) => default,
    }
}

#[derive(Clone, Copy, Debug)]
struct ClaimWait {
    deadline: Instant,
    timeout_seconds: u64,
}

impl ClaimWait {
    fn new(duration: Duration) -> Self {
        Self {
            deadline: Instant::now() + duration,
            timeout_seconds: duration.as_secs(),
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct NamespaceSettings {
    request_timeout: Duration,
    poll_policy: PollPolicy,
}

impl NamespaceSettings {
    const fn production() -> Self {
        Self {
            request_timeout: REQUEST_TIMEOUT,
            poll_policy: PollPolicy {
                initial_delay: INITIAL_POLL_DELAY,
                max_delay: MAX_POLL_DELAY,
            },
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct PollPolicy {
    initial_delay: Duration,
    max_delay: Duration,
}

struct NamespaceApiClient {
    config: ResolvedConfig,
    tls: TlsConnector,
    request_timeout: Duration,
}

impl NamespaceApiClient {
    fn new(config: ResolvedConfig, request_timeout: Duration) -> Result<Self, NamespaceError> {
        if CryptoProvider::get_default().is_none() {
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        }
        if CryptoProvider::get_default().is_none() {
            return Err(NamespaceError::TlsSetup);
        }
        let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let tls = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(Self {
            config,
            tls: TlsConnector::from(Arc::new(tls)),
            request_timeout,
        })
    }

    async fn claim(
        &self,
        hostname: &str,
        passthrough: bool,
        cancellation: &CancellationToken,
    ) -> Result<Namespace, NamespaceError> {
        let body = if passthrough {
            serde_json::to_vec(&NamespaceClaimRequest::passthrough(hostname))
        } else {
            serde_json::to_vec(&NamespaceClaimRequest::managed(hostname))
        }
        .map_err(NamespaceError::RequestEncode)?;
        let (status, body) = self
            .send(
                Method::POST,
                collection_url(self.config.server_addr().as_url()),
                Some(body),
                cancellation,
            )
            .await?;
        if !matches!(
            status,
            StatusCode::OK | StatusCode::CREATED | StatusCode::ACCEPTED
        ) {
            return Err(response_error(status, &body));
        }
        decode_json::<NamespaceResponse>(status, &body).map(|response| response.namespace)
    }

    async fn list(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<Vec<Namespace>, NamespaceError> {
        let (status, body) = self
            .send(
                Method::GET,
                collection_url(self.config.server_addr().as_url()),
                None,
                cancellation,
            )
            .await?;
        if status != StatusCode::OK {
            return Err(response_error(status, &body));
        }
        decode_json::<NamespaceListResponse>(status, &body).map(|response| response.namespaces)
    }

    async fn status(
        &self,
        hostname: &str,
        cancellation: &CancellationToken,
    ) -> Result<Namespace, NamespaceError> {
        let (status, body) = self
            .send(
                Method::GET,
                item_url(self.config.server_addr().as_url(), hostname)?,
                None,
                cancellation,
            )
            .await?;
        if status != StatusCode::OK {
            return Err(response_error(status, &body));
        }
        decode_json::<NamespaceResponse>(status, &body).map(|response| response.namespace)
    }

    async fn release(
        &self,
        hostname: &str,
        cancellation: &CancellationToken,
    ) -> Result<(), NamespaceError> {
        let (status, body) = self
            .send(
                Method::DELETE,
                item_url(self.config.server_addr().as_url(), hostname)?,
                None,
                cancellation,
            )
            .await?;
        if status == StatusCode::NO_CONTENT {
            Ok(())
        } else {
            Err(response_error(status, &body))
        }
    }

    async fn send(
        &self,
        method: Method,
        url: Url,
        body: Option<Vec<u8>>,
        cancellation: &CancellationToken,
    ) -> Result<(StatusCode, Bytes), NamespaceError> {
        let uri = url
            .as_str()
            .parse::<Uri>()
            .map_err(|_| NamespaceError::InvalidControlAddress)?;
        let authority = uri
            .authority()
            .ok_or(NamespaceError::InvalidControlAddress)?
            .as_str()
            .to_owned();
        let bearer = Zeroizing::new(format!(
            "Bearer {}",
            self.config.auth_token().expose_secret()
        ));
        let mut authorization = HeaderValue::from_str(bearer.as_str())
            .map_err(|_| NamespaceError::InvalidAuthenticationToken)?;
        authorization.set_sensitive(true);

        let mut request = Request::builder()
            .method(method)
            .uri(uri)
            .header(ACCEPT, "application/json")
            .header(HOST, authority)
            .header(AUTHORIZATION, authorization);
        let body = match body {
            Some(body) => {
                request = request.header(CONTENT_TYPE, "application/json");
                Full::new(Bytes::from(body))
            }
            None => Full::new(Bytes::new()),
        };
        let request = request
            .body(body)
            .map_err(|_| NamespaceError::RequestBuild)?;

        let exchange = async {
            let io = self.connect(&url).await?;
            let (mut sender, connection) = http1::handshake::<_, Full<Bytes>>(TokioIo::new(io))
                .await
                .map_err(NamespaceError::Http)?;
            let response_exchange = async {
                let response = sender
                    .send_request(request)
                    .await
                    .map_err(NamespaceError::Http)?;
                let status = response.status();
                let body = Limited::new(response.into_body(), MAX_RESPONSE_BODY_BYTES)
                    .collect()
                    .await
                    .map_err(|_| NamespaceError::ResponseBody)?
                    .to_bytes();
                Ok((status, body))
            };
            tokio::pin!(connection);
            tokio::pin!(response_exchange);
            tokio::select! {
                biased;
                result = &mut response_exchange => result,
                result = &mut connection => match result {
                    Ok(()) => Err(NamespaceError::ConnectionClosed),
                    Err(error) => Err(NamespaceError::Http(error)),
                },
            }
        };

        tokio::select! {
            biased;
            () = cancellation.cancelled() => Err(NamespaceError::Cancelled),
            result = timeout(self.request_timeout, exchange) => {
                result.map_err(|_| NamespaceError::RequestTimeout)?
            }
        }
    }

    async fn connect(&self, url: &Url) -> Result<BoxedControlIo, NamespaceError> {
        let host = url
            .host_str()
            .ok_or(NamespaceError::InvalidControlAddress)?
            .to_owned();
        let port = url
            .port_or_known_default()
            .ok_or(NamespaceError::InvalidControlAddress)?;
        let tcp = TcpStream::connect((host.as_str(), port))
            .await
            .map_err(NamespaceError::Connect)?;
        let _ = tcp.set_nodelay(true);

        match url.scheme() {
            "http" => Ok(Box::new(tcp)),
            "https" => {
                let server_name = server_name(&host)?;
                let tls = self
                    .tls
                    .connect(server_name, tcp)
                    .await
                    .map_err(NamespaceError::Tls)?;
                Ok(Box::new(tls))
            }
            _ => Err(NamespaceError::InvalidControlAddress),
        }
    }
}

fn server_name(host: &str) -> Result<ServerName<'static>, NamespaceError> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ServerName::IpAddress(ip.into()));
    }
    ServerName::try_from(host.to_owned()).map_err(|_| NamespaceError::InvalidControlAddress)
}

fn collection_url(origin: &Url) -> Url {
    let mut url = origin.clone();
    url.set_path(NAMESPACE_COLLECTION_PATH);
    url.set_query(None);
    url.set_fragment(None);
    url
}

fn item_url(origin: &Url, hostname: &str) -> Result<Url, NamespaceError> {
    let mut url = collection_url(origin);
    url.path_segments_mut()
        .map_err(|()| NamespaceError::InvalidControlAddress)?
        .push(hostname);
    Ok(url)
}

fn decode_json<T: DeserializeOwned>(status: StatusCode, body: &[u8]) -> Result<T, NamespaceError> {
    serde_json::from_slice(body).map_err(|source| NamespaceError::ResponseDecode { status, source })
}

fn response_error(status: StatusCode, body: &[u8]) -> NamespaceError {
    match serde_json::from_slice::<ManagementErrorResponse>(body) {
        Ok(response) => NamespaceError::Api {
            status,
            code: management_error_code_name(response.error.code),
            message: response.error.message,
        },
        Err(_) => NamespaceError::UnexpectedStatus { status },
    }
}

fn ensure_claim_can_succeed(namespace: &Namespace) -> Result<(), NamespaceError> {
    match namespace.state {
        NamespaceState::Failed => Err(NamespaceError::ClaimFailed {
            hostname: namespace.hostname.clone(),
        }),
        NamespaceState::Releasing => Err(NamespaceError::ClaimReleasing {
            hostname: namespace.hostname.clone(),
        }),
        NamespaceState::Pending | NamespaceState::Active | NamespaceState::Retrying => Ok(()),
    }
}

async fn wait_for_active<P, F>(
    mut namespace: Namespace,
    wait: ClaimWait,
    policy: PollPolicy,
    cancellation: &CancellationToken,
    mut poll: P,
) -> Result<Namespace, NamespaceError>
where
    P: FnMut() -> F,
    F: Future<Output = Result<Namespace, NamespaceError>>,
{
    let deadline = wait.deadline;
    let timeout_seconds = wait.timeout_seconds;
    let mut delay = policy.initial_delay;

    loop {
        match namespace.state {
            NamespaceState::Active => return Ok(namespace),
            NamespaceState::Failed | NamespaceState::Releasing => {
                ensure_claim_can_succeed(&namespace)?;
            }
            NamespaceState::Pending | NamespaceState::Retrying => {}
        }

        let wake_at = std::cmp::min(Instant::now() + delay, deadline);
        tokio::select! {
            biased;
            () = cancellation.cancelled() => return Err(NamespaceError::Cancelled),
            () = sleep_until(wake_at) => {}
        }
        if Instant::now() >= deadline {
            return Err(NamespaceError::ClaimTimeout {
                hostname: namespace.hostname,
                timeout_seconds,
                last_state: namespace_state_name(namespace.state),
            });
        }

        namespace = tokio::select! {
            biased;
            () = cancellation.cancelled() => return Err(NamespaceError::Cancelled),
            result = timeout_at(deadline, poll()) => match result {
                Ok(result) => result?,
                Err(_) => return Err(NamespaceError::ClaimTimeout {
                    hostname: namespace.hostname,
                    timeout_seconds,
                    last_state: namespace_state_name(namespace.state),
                }),
            }
        };
        delay = std::cmp::min(delay.saturating_mul(2), policy.max_delay);
    }
}

const fn namespace_state_name(state: NamespaceState) -> &'static str {
    match state {
        NamespaceState::Pending => "pending",
        NamespaceState::Active => "active",
        NamespaceState::Failed => "failed",
        NamespaceState::Retrying => "retrying",
        NamespaceState::Releasing => "releasing",
    }
}

const fn namespace_mode_suffix(mode: NamespaceTlsMode) -> &'static str {
    match mode {
        NamespaceTlsMode::Managed => "",
        NamespaceTlsMode::Passthrough => " (passthrough)",
    }
}

const fn management_error_code_name(code: ManagementErrorCode) -> &'static str {
    match code {
        ManagementErrorCode::AuthenticationRequired => "authentication_required",
        ManagementErrorCode::InvalidRequest => "invalid_request",
        ManagementErrorCode::InvalidHostname => "invalid_hostname",
        ManagementErrorCode::ReservedHostname => "reserved_hostname",
        ManagementErrorCode::NamespaceUnavailable => "namespace_unavailable",
        ManagementErrorCode::ParentNamespaceUnavailable => "parent_namespace_unavailable",
        ManagementErrorCode::NamespaceNotFound => "namespace_not_found",
        ManagementErrorCode::NamespaceHasChildren => "namespace_has_children",
        ManagementErrorCode::NamespaceInUse => "namespace_in_use",
        ManagementErrorCode::CertificateUnavailable => "certificate_unavailable",
        ManagementErrorCode::ServiceUnavailable => "service_unavailable",
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        convert::Infallible,
        error::Error,
        sync::{Arc, Mutex},
    };

    use axum::{Router, body::Body, extract::State};
    use clap::Parser as _;
    use http::{Response, header::AUTHORIZATION};
    use tokio::{net::TcpListener, task::JoinHandle};

    use crate::{
        cli::{Cli, SinkCommand},
        config::{AuthToken, RunOverrides, SavedConfig},
    };

    use super::*;

    #[derive(Clone, Debug)]
    struct FakeResponse {
        status: StatusCode,
        body: String,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct RecordedRequest {
        method: Method,
        path: String,
        authorization_count: usize,
        authorization: Option<String>,
        body: Vec<u8>,
    }

    #[derive(Clone, Default)]
    struct FakeState {
        responses: Arc<Mutex<VecDeque<FakeResponse>>>,
        response_delays: Arc<Mutex<VecDeque<Duration>>>,
        requests: Arc<Mutex<Vec<RecordedRequest>>>,
    }

    async fn fake_management(
        State(state): State<FakeState>,
        request: axum::extract::Request,
    ) -> Result<Response<Body>, Infallible> {
        let method = request.method().clone();
        let path = request.uri().path().to_owned();
        let authorization_count = request.headers().get_all(AUTHORIZATION).iter().count();
        let authorization = request
            .headers()
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let body = match axum::body::to_bytes(request.into_body(), 16 * 1024).await {
            Ok(body) => body.to_vec(),
            Err(_) => Vec::new(),
        };
        if let Ok(mut requests) = state.requests.lock() {
            requests.push(RecordedRequest {
                method,
                path,
                authorization_count,
                authorization,
                body,
            });
        }
        let response = state
            .responses
            .lock()
            .ok()
            .and_then(|mut responses| responses.pop_front())
            .unwrap_or(FakeResponse {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                body:
                    r#"{"error":{"code":"service_unavailable","message":"missing fake response"}}"#
                        .to_owned(),
            });
        let delay = state
            .response_delays
            .lock()
            .ok()
            .and_then(|mut delays| delays.pop_front())
            .unwrap_or_default();
        tokio::time::sleep(delay).await;
        let built = Response::builder()
            .status(response.status)
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(response.body));
        Ok(built.unwrap_or_else(|_| Response::new(Body::empty())))
    }

    async fn fake_server(
        responses: Vec<FakeResponse>,
    ) -> Result<(String, FakeState, JoinHandle<()>), Box<dyn Error>> {
        fake_server_with_delays(responses, Vec::new()).await
    }

    async fn fake_server_with_delays(
        responses: Vec<FakeResponse>,
        response_delays: Vec<Duration>,
    ) -> Result<(String, FakeState, JoinHandle<()>), Box<dyn Error>> {
        let state = FakeState {
            responses: Arc::new(Mutex::new(responses.into())),
            response_delays: Arc::new(Mutex::new(response_delays.into())),
            requests: Arc::default(),
        };
        let router = Router::new()
            .fallback(fake_management)
            .with_state(state.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        Ok((format!("http://{address}"), state, task))
    }

    fn namespace_with_mode(
        hostname: &str,
        state: NamespaceState,
        tls_mode: NamespaceTlsMode,
    ) -> Namespace {
        Namespace {
            hostname: hostname.to_owned(),
            depth: 1,
            tls_mode,
            state,
            created_at: 10,
            updated_at: 20,
        }
    }

    fn namespace(hostname: &str, state: NamespaceState) -> Namespace {
        namespace_with_mode(hostname, state, NamespaceTlsMode::Managed)
    }

    fn namespace_json(hostname: &str, state: NamespaceState) -> Result<String, serde_json::Error> {
        serde_json::to_string(&NamespaceResponse {
            namespace: namespace(hostname, state),
        })
    }

    fn namespace_json_with_mode(
        hostname: &str,
        state: NamespaceState,
        tls_mode: NamespaceTlsMode,
    ) -> Result<String, serde_json::Error> {
        serde_json::to_string(&NamespaceResponse {
            namespace: namespace_with_mode(hostname, state, tls_mode),
        })
    }

    fn resolved(server: &str, token: &str) -> Result<ResolvedConfig, Box<dyn Error>> {
        Ok(SavedConfig::default().resolve(RunOverrides {
            authtoken: Some(AuthToken::new(token)?),
            server_addr: Some(server.parse()?),
            allow_plaintext_control: true,
        })?)
    }

    fn test_settings() -> NamespaceSettings {
        NamespaceSettings {
            request_timeout: Duration::from_secs(1),
            poll_policy: PollPolicy {
                initial_delay: Duration::from_millis(1),
                max_delay: Duration::from_millis(1),
            },
        }
    }

    #[test]
    fn claim_request_timeout_distinguishes_wait_and_no_wait() -> Result<(), Box<dyn Error>> {
        for (arguments, expected) in [
            (
                vec!["sink", "namespace", "claim", "cloud.example.test"],
                300,
            ),
            (
                vec![
                    "sink",
                    "namespace",
                    "claim",
                    "cloud.example.test",
                    "--passthrough",
                    "--timeout",
                    "45",
                ],
                45,
            ),
            (
                vec![
                    "sink",
                    "namespace",
                    "claim",
                    "cloud.example.test",
                    "--timeout",
                    "5",
                ],
                10,
            ),
            (
                vec![
                    "sink",
                    "namespace",
                    "claim",
                    "cloud.example.test",
                    "--no-wait",
                ],
                10,
            ),
        ] {
            let cli = Cli::try_parse_from(arguments)?;
            let SinkCommand::Namespace(arguments) = cli.command else {
                return Err("expected namespace command".into());
            };
            assert_eq!(
                command_request_timeout(&arguments.command, REQUEST_TIMEOUT),
                Duration::from_secs(expected)
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn no_wait_claim_keeps_the_normal_request_bound() -> Result<(), Box<dyn Error>> {
        let hostname = "cloud.example.test";
        let (server, _state, task) = fake_server_with_delays(
            vec![FakeResponse {
                status: StatusCode::CREATED,
                body: namespace_json(hostname, NamespaceState::Active)?,
            }],
            vec![Duration::from_millis(100)],
        )
        .await?;
        let cli = Cli::try_parse_from(["sink", "namespace", "claim", hostname, "--no-wait"])?;
        let SinkCommand::Namespace(arguments) = cli.command else {
            return Err("expected namespace command".into());
        };
        let settings = NamespaceSettings {
            request_timeout: Duration::from_millis(20),
            poll_policy: test_settings().poll_policy,
        };

        let error = execute(
            arguments.command,
            resolved(&server, "test-only-secret")?,
            CancellationToken::new(),
            settings,
        )
        .await
        .expect_err("no-wait request should retain the normal request timeout");
        assert!(matches!(error, NamespaceError::RequestTimeout));
        task.abort();
        Ok(())
    }

    #[tokio::test]
    async fn activation_timeout_is_one_budget_for_claim_and_polling() -> Result<(), Box<dyn Error>>
    {
        let hostname = "cloud.example.test";
        let (server, _state, task) = fake_server_with_delays(
            vec![
                FakeResponse {
                    status: StatusCode::ACCEPTED,
                    body: namespace_json(hostname, NamespaceState::Pending)?,
                },
                FakeResponse {
                    status: StatusCode::OK,
                    body: namespace_json(hostname, NamespaceState::Active)?,
                },
            ],
            vec![Duration::from_millis(700), Duration::from_millis(700)],
        )
        .await?;
        let cli = Cli::try_parse_from(["sink", "namespace", "claim", hostname, "--timeout", "1"])?;
        let SinkCommand::Namespace(arguments) = cli.command else {
            return Err("expected namespace command".into());
        };

        let error = execute(
            arguments.command,
            resolved(&server, "test-only-secret")?,
            CancellationToken::new(),
            test_settings(),
        )
        .await
        .expect_err("claim and polling must share the selected activation timeout");
        assert!(matches!(
            error,
            NamespaceError::ClaimTimeout {
                timeout_seconds: 1,
                last_state: "pending",
                ..
            }
        ));
        task.abort();
        Ok(())
    }

    #[tokio::test]
    async fn claim_posts_once_and_polls_until_active_with_one_bearer_header()
    -> Result<(), Box<dyn Error>> {
        let hostname = "cloud.example.test";
        let (server, state, task) = fake_server(vec![
            FakeResponse {
                status: StatusCode::ACCEPTED,
                body: namespace_json(hostname, NamespaceState::Pending)?,
            },
            FakeResponse {
                status: StatusCode::OK,
                body: namespace_json(hostname, NamespaceState::Retrying)?,
            },
            FakeResponse {
                status: StatusCode::OK,
                body: namespace_json(hostname, NamespaceState::Active)?,
            },
        ])
        .await?;
        let cli = Cli::try_parse_from(["sink", "namespace", "claim", hostname, "--timeout", "1"])?;
        let SinkCommand::Namespace(arguments) = cli.command else {
            return Err("expected namespace command".into());
        };

        let result = execute(
            arguments.command,
            resolved(&server, "test-only-secret")?,
            CancellationToken::new(),
            test_settings(),
        )
        .await?;
        assert_eq!(
            result,
            NamespaceCommandOutput::Namespaces(vec![namespace(hostname, NamespaceState::Active)])
        );

        let requests = state
            .requests
            .lock()
            .map_err(|_| "fake request lock poisoned")?
            .clone();
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[0].method, Method::POST);
        assert_eq!(requests[0].path, NAMESPACE_COLLECTION_PATH);
        assert_eq!(requests[0].authorization_count, 1);
        assert_eq!(
            requests[0].authorization.as_deref(),
            Some("Bearer test-only-secret")
        );
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&requests[0].body)?,
            serde_json::json!({"hostname": hostname})
        );
        assert_eq!(
            serde_json::from_slice::<NamespaceClaimRequest>(&requests[0].body)?,
            NamespaceClaimRequest::managed(hostname)
        );
        for request in &requests[1..] {
            assert_eq!(request.method, Method::GET);
            assert_eq!(request.path, "/_sink/api/v1/namespaces/cloud.example.test");
            assert_eq!(request.authorization_count, 1);
        }
        task.abort();
        Ok(())
    }

    #[tokio::test]
    async fn passthrough_claim_posts_mode_and_accepts_immediate_active_response()
    -> Result<(), Box<dyn Error>> {
        let hostname = "edge.example.test";
        let expected = namespace_with_mode(
            hostname,
            NamespaceState::Active,
            NamespaceTlsMode::Passthrough,
        );
        let (server, state, task) = fake_server(vec![FakeResponse {
            status: StatusCode::CREATED,
            body: namespace_json_with_mode(
                hostname,
                NamespaceState::Active,
                NamespaceTlsMode::Passthrough,
            )?,
        }])
        .await?;
        let cli = Cli::try_parse_from([
            "sink",
            "namespace",
            "claim",
            hostname,
            "--passthrough",
            "--timeout",
            "1",
        ])?;
        let SinkCommand::Namespace(arguments) = cli.command else {
            return Err("expected namespace command".into());
        };

        let result = execute(
            arguments.command,
            resolved(&server, "test-only-secret")?,
            CancellationToken::new(),
            test_settings(),
        )
        .await?;
        assert_eq!(result, NamespaceCommandOutput::Namespaces(vec![expected]));

        let requests = state
            .requests
            .lock()
            .map_err(|_| "fake request lock poisoned")?
            .clone();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method, Method::POST);
        assert_eq!(requests[0].path, NAMESPACE_COLLECTION_PATH);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&requests[0].body)?,
            serde_json::json!({
                "hostname": hostname,
                "tls_mode": "passthrough"
            })
        );
        task.abort();
        Ok(())
    }

    #[tokio::test]
    async fn list_status_and_release_follow_the_management_contract() -> Result<(), Box<dyn Error>>
    {
        let hostname = "cloud.example.test";
        let passthrough_hostname = "edge.example.test";
        let passthrough = namespace_with_mode(
            passthrough_hostname,
            NamespaceState::Active,
            NamespaceTlsMode::Passthrough,
        );
        let (server, state, task) = fake_server(vec![
            FakeResponse {
                status: StatusCode::OK,
                body: serde_json::to_string(&NamespaceListResponse {
                    namespaces: vec![
                        namespace(hostname, NamespaceState::Active),
                        passthrough.clone(),
                    ],
                })?,
            },
            FakeResponse {
                status: StatusCode::OK,
                body: namespace_json_with_mode(
                    passthrough_hostname,
                    NamespaceState::Active,
                    NamespaceTlsMode::Passthrough,
                )?,
            },
            FakeResponse {
                status: StatusCode::NO_CONTENT,
                body: String::new(),
            },
        ])
        .await?;
        let api = NamespaceApiClient::new(
            resolved(&server, "test-only-secret")?,
            Duration::from_secs(1),
        )?;
        let cancellation = CancellationToken::new();

        assert_eq!(
            api.list(&cancellation).await?,
            vec![
                namespace(hostname, NamespaceState::Active),
                passthrough.clone()
            ]
        );
        assert_eq!(
            api.status(passthrough_hostname, &cancellation).await?,
            passthrough
        );
        api.release(passthrough_hostname, &cancellation).await?;

        let requests = state
            .requests
            .lock()
            .map_err(|_| "fake request lock poisoned")?
            .clone();
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[0].method, Method::GET);
        assert_eq!(requests[0].path, NAMESPACE_COLLECTION_PATH);
        assert_eq!(requests[1].method, Method::GET);
        assert_eq!(requests[2].method, Method::DELETE);
        assert_eq!(requests[1].path, requests[2].path);
        assert!(
            requests
                .iter()
                .all(|request| request.authorization_count == 1)
        );
        task.abort();
        Ok(())
    }

    #[tokio::test]
    async fn invalid_namespace_mode_response_is_rejected() -> Result<(), Box<dyn Error>> {
        let hostname = "edge.example.test";
        let (server, _state, task) = fake_server(vec![FakeResponse {
            status: StatusCode::OK,
            body: format!(
                r#"{{"namespace":{{"hostname":"{hostname}","depth":1,"tls_mode":"invalid","state":"active","created_at":10,"updated_at":20}}}}"#
            ),
        }])
        .await?;
        let api = NamespaceApiClient::new(
            resolved(&server, "test-only-secret")?,
            Duration::from_secs(1),
        )?;

        let error = api
            .status(hostname, &CancellationToken::new())
            .await
            .expect_err("unknown namespace modes must fail decoding");
        assert!(matches!(
            error,
            NamespaceError::ResponseDecode {
                status: StatusCode::OK,
                ..
            }
        ));
        task.abort();
        Ok(())
    }

    #[tokio::test]
    async fn stable_api_error_is_clear_and_does_not_expose_the_token() -> Result<(), Box<dyn Error>>
    {
        let (server, _state, task) = fake_server(vec![FakeResponse {
            status: StatusCode::CONFLICT,
            body:
                r#"{"error":{"code":"namespace_in_use","message":"namespace has active routes"}}"#
                    .to_owned(),
        }])
        .await?;
        let api = NamespaceApiClient::new(
            resolved(&server, "never-print-this-secret")?,
            Duration::from_secs(1),
        )?;
        let error = api
            .release("cloud.example.test", &CancellationToken::new())
            .await
            .expect_err("release should fail");
        let displayed = error.to_string();
        let debugged = format!("{error:?}");
        assert!(displayed.contains("namespace_in_use"));
        assert!(displayed.contains("HTTP 409 Conflict"));
        assert!(displayed.contains("namespace has active routes"));
        assert!(!displayed.contains("never-print-this-secret"));
        assert!(!debugged.contains("never-print-this-secret"));
        task.abort();
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn polling_backoff_is_deterministic() -> Result<(), Box<dyn Error>> {
        let started = Instant::now();
        let states = Arc::new(Mutex::new(VecDeque::from([
            namespace("cloud.example.test", NamespaceState::Retrying),
            namespace("cloud.example.test", NamespaceState::Active),
        ])));
        let result = wait_for_active(
            namespace("cloud.example.test", NamespaceState::Pending),
            ClaimWait::new(Duration::from_secs(10)),
            PollPolicy {
                initial_delay: Duration::from_millis(250),
                max_delay: Duration::from_secs(2),
            },
            &CancellationToken::new(),
            || {
                let state = states
                    .lock()
                    .map_err(|_| NamespaceError::ResponseBody)
                    .and_then(|mut states| states.pop_front().ok_or(NamespaceError::ResponseBody));
                std::future::ready(state)
            },
        )
        .await?;
        assert_eq!(result.state, NamespaceState::Active);
        assert_eq!(Instant::now() - started, Duration::from_millis(750));
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn polling_timeout_and_cancellation_are_terminal() -> Result<(), Box<dyn Error>> {
        let cancellation = CancellationToken::new();
        let timeout_error = wait_for_active(
            namespace("cloud.example.test", NamespaceState::Pending),
            ClaimWait::new(Duration::from_millis(600)),
            PollPolicy {
                initial_delay: Duration::from_millis(250),
                max_delay: Duration::from_millis(500),
            },
            &cancellation,
            || std::future::ready(Ok(namespace("cloud.example.test", NamespaceState::Pending))),
        )
        .await
        .expect_err("pending claim should time out");
        assert!(matches!(timeout_error, NamespaceError::ClaimTimeout { .. }));

        cancellation.cancel();
        let cancelled = wait_for_active(
            namespace("cloud.example.test", NamespaceState::Pending),
            ClaimWait::new(Duration::from_secs(1)),
            PollPolicy {
                initial_delay: Duration::from_millis(1),
                max_delay: Duration::from_millis(1),
            },
            &cancellation,
            || std::future::ready(Err(NamespaceError::ResponseBody)),
        )
        .await
        .expect_err("cancelled claim should stop");
        assert!(matches!(cancelled, NamespaceError::Cancelled));
        Ok(())
    }

    #[test]
    fn output_is_stable_and_line_oriented() -> Result<(), Box<dyn Error>> {
        let output = NamespaceCommandOutput::Namespaces(vec![
            namespace("cloud.example.test", NamespaceState::Active),
            namespace_with_mode(
                "edge.cloud.example.test",
                NamespaceState::Retrying,
                NamespaceTlsMode::Passthrough,
            ),
        ]);
        let mut rendered = Vec::new();
        output.write_to(&mut rendered)?;
        assert_eq!(
            String::from_utf8(rendered)?,
            "namespace cloud.example.test: active\nnamespace edge.cloud.example.test: retrying (passthrough)\n"
        );

        let mut empty = Vec::new();
        NamespaceCommandOutput::Namespaces(Vec::new()).write_to(&mut empty)?;
        assert_eq!(String::from_utf8(empty)?, "no namespaces\n");
        Ok(())
    }
}
