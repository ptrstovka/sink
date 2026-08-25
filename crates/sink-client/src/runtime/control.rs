use std::time::Duration;

use futures::{SinkExt, StreamExt};
use http::{HeaderValue, Request, StatusCode, header::AUTHORIZATION};
use sink_protocol::{
    CONTROL_PATH, ClientHello, MAX_HANDSHAKE_BYTES, MAX_TRANSPORT_MESSAGE_BYTES, PROTOCOL_VERSION,
    RejectCode, ServerHello, SessionAccepted, SessionRejected,
};
use tokio::{net::TcpStream, time::timeout};
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream, connect_async_with_config,
    tungstenite::{
        Error as WebSocketError, Message, client::IntoClientRequest, protocol::WebSocketConfig,
    },
};
use url::{Host, Url};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::config::ResolvedConfig;

use super::{ConnectionInfo, RuntimeError};

const CONTROL_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const CONTROL_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

pub(crate) type ControlWebSocket = WebSocketStream<MaybeTlsStream<TcpStream>>;

pub(crate) struct EstablishedControl {
    pub(crate) websocket: ControlWebSocket,
    pub(crate) info: ConnectionInfo,
}

pub(crate) async fn establish(
    config: &ResolvedConfig,
    hello: &ClientHello,
    expected_hostname: Option<&str>,
    prior: Option<&ConnectionInfo>,
) -> Result<EstablishedControl, RuntimeError> {
    let request = control_upgrade_request(config)?;
    let websocket_config = WebSocketConfig::default()
        .max_message_size(Some(MAX_TRANSPORT_MESSAGE_BYTES))
        .max_frame_size(Some(MAX_TRANSPORT_MESSAGE_BYTES));

    let connect = timeout(
        CONTROL_CONNECT_TIMEOUT,
        connect_async_with_config(request, Some(websocket_config), true),
    )
    .await
    .map_err(|_| RuntimeError::ControlUnavailable)?;
    let (mut websocket, _) = connect.map_err(classify_upgrade_error)?;

    let handshake = timeout(
        CONTROL_HANDSHAKE_TIMEOUT,
        exchange_hello(&mut websocket, hello),
    )
    .await
    .map_err(|_| RuntimeError::ControlUnavailable)??;

    let accepted = match handshake {
        ServerHello::Accepted(accepted) => accepted,
        ServerHello::Rejected(rejected) => return Err(classify_rejection(rejected)),
    };
    let info = validate_acceptance(accepted, hello.session_id, expected_hostname, prior)?;
    Ok(EstablishedControl { websocket, info })
}

pub(crate) fn control_websocket_url(config: &ResolvedConfig) -> Result<Url, RuntimeError> {
    let mut url = config.server_addr().as_url().clone();
    let websocket_scheme = if config.server_addr().is_plaintext() {
        "ws"
    } else {
        "wss"
    };
    url.set_scheme(websocket_scheme)
        .map_err(|()| RuntimeError::InvalidControlAddress)?;
    url.set_path(CONTROL_PATH);
    url.set_query(None);
    url.set_fragment(None);
    Ok(url)
}

fn control_upgrade_request(config: &ResolvedConfig) -> Result<Request<()>, RuntimeError> {
    let url = control_websocket_url(config)?;
    let mut request = url
        .as_str()
        .into_client_request()
        .map_err(|_| RuntimeError::InvalidControlAddress)?;
    let bearer = Zeroizing::new(format!("Bearer {}", config.auth_token().expose_secret()));
    let bearer = HeaderValue::from_str(bearer.as_str())
        .map_err(|_| RuntimeError::InvalidAuthenticationToken)?;
    request.headers_mut().insert(AUTHORIZATION, bearer);
    Ok(request)
}

async fn exchange_hello(
    websocket: &mut ControlWebSocket,
    hello: &ClientHello,
) -> Result<ServerHello, RuntimeError> {
    hello
        .validate()
        .map_err(|_| RuntimeError::ProtocolViolation)?;
    let encoded = serde_json::to_string(hello).map_err(|_| RuntimeError::ProtocolViolation)?;
    if encoded.len() > MAX_HANDSHAKE_BYTES {
        return Err(RuntimeError::ProtocolViolation);
    }
    websocket
        .send(Message::Text(encoded.into()))
        .await
        .map_err(|_| RuntimeError::ControlUnavailable)?;

    loop {
        match websocket.next().await {
            Some(Ok(Message::Text(text))) if text.len() <= MAX_HANDSHAKE_BYTES => {
                return serde_json::from_str(text.as_str())
                    .map_err(|_| RuntimeError::ProtocolViolation);
            }
            Some(Ok(Message::Ping(_) | Message::Pong(_))) => {
                // Tungstenite queues pongs while reading. Flush so a quiet peer
                // receives them even before yamux starts writing.
                websocket
                    .flush()
                    .await
                    .map_err(|_| RuntimeError::ControlUnavailable)?;
            }
            Some(Ok(Message::Close(_))) | None => return Err(RuntimeError::ControlUnavailable),
            Some(Err(_)) => return Err(RuntimeError::ControlUnavailable),
            Some(Ok(Message::Text(_) | Message::Binary(_) | Message::Frame(_))) => {
                return Err(RuntimeError::ProtocolViolation);
            }
        }
    }
}

fn classify_upgrade_error(error: WebSocketError) -> RuntimeError {
    match error {
        WebSocketError::Http(response) if permanent_upgrade_status(response.status()) => {
            RuntimeError::UpgradeRejected {
                status: response.status(),
            }
        }
        _ => RuntimeError::ControlUnavailable,
    }
}

fn permanent_upgrade_status(status: StatusCode) -> bool {
    status.is_client_error()
        && !matches!(
            status,
            StatusCode::REQUEST_TIMEOUT | StatusCode::TOO_EARLY | StatusCode::TOO_MANY_REQUESTS
        )
}

fn classify_rejection(rejected: SessionRejected) -> RuntimeError {
    if rejected.permanent || reject_code_is_permanent(rejected.code) {
        RuntimeError::Rejected {
            code: rejected.code,
        }
    } else {
        RuntimeError::ControlUnavailable
    }
}

pub(crate) fn reject_code_is_permanent(code: RejectCode) -> bool {
    !matches!(code, RejectCode::ServerUnavailable)
}

pub(crate) fn validate_acceptance(
    accepted: SessionAccepted,
    session_id: Uuid,
    expected_hostname: Option<&str>,
    prior: Option<&ConnectionInfo>,
) -> Result<ConnectionInfo, RuntimeError> {
    if accepted.protocol_version != PROTOCOL_VERSION || accepted.session_id != session_id {
        return Err(RuntimeError::ProtocolViolation);
    }

    let http = parse_assigned_url(&accepted.public_http_url, "http")?;
    let https = parse_assigned_url(&accepted.public_https_url, "https")?;
    let http_hostname = http.host_str().ok_or(RuntimeError::ProtocolViolation)?;
    let https_hostname = https.host_str().ok_or(RuntimeError::ProtocolViolation)?;
    if http_hostname != https_hostname {
        return Err(RuntimeError::ProtocolViolation);
    }

    let (claim, _) = https_hostname
        .split_once('.')
        .ok_or(RuntimeError::ProtocolViolation)?;
    if claim != accepted.subdomain.as_str()
        || expected_hostname.is_some_and(|expected| expected != https_hostname)
    {
        return Err(RuntimeError::ProtocolViolation);
    }

    let info = ConnectionInfo {
        hostname: https_hostname.to_owned(),
        subdomain: accepted.subdomain,
        public_http_url: http.to_string(),
        public_https_url: https.to_string(),
        reconnect_grace_seconds: accepted.reconnect_grace_seconds,
    };

    if let Some(prior) = prior
        && (prior.hostname != info.hostname
            || prior.subdomain != info.subdomain
            || prior.public_http_url != info.public_http_url
            || prior.public_https_url != info.public_https_url)
    {
        return Err(RuntimeError::ProtocolViolation);
    }
    Ok(info)
}

fn parse_assigned_url(raw: &str, scheme: &str) -> Result<Url, RuntimeError> {
    let url = Url::parse(raw).map_err(|_| RuntimeError::ProtocolViolation)?;
    if url.scheme() != scheme
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.host(), Some(Host::Domain(_)))
    {
        return Err(RuntimeError::ProtocolViolation);
    }
    Ok(url)
}

#[cfg(test)]
mod tests {
    use sink_protocol::{RejectCode, SessionAccepted, SessionRejected, Subdomain};

    use crate::config::{AuthToken, RunOverrides, SavedConfig};

    use super::*;

    fn resolved(server: &str, token: &str) -> Result<ResolvedConfig, Box<dyn std::error::Error>> {
        Ok(SavedConfig::default().resolve_for_http(RunOverrides {
            authtoken: Some(AuthToken::new(token)?),
            server_addr: Some(server.parse()?),
            allow_plaintext_control: server.starts_with("http://"),
        })?)
    }

    #[test]
    fn control_url_and_authorization_are_exact_and_do_not_embed_the_token()
    -> Result<(), Box<dyn std::error::Error>> {
        let token = "test-only-super-secret";
        let secure = resolved("https://connect.example.test:8443", token)?;
        let request = control_upgrade_request(&secure)?;
        assert_eq!(
            request.uri().to_string(),
            "wss://connect.example.test:8443/_sink/connect"
        );
        assert_eq!(
            request.headers()[AUTHORIZATION],
            "Bearer test-only-super-secret"
        );
        assert!(!request.uri().to_string().contains(token));
        assert!(request.headers().get("cookie").is_none());

        let plaintext = resolved("http://127.0.0.1:8080", token)?;
        assert_eq!(
            control_websocket_url(&plaintext)?.as_str(),
            "ws://127.0.0.1:8080/_sink/connect"
        );
        Ok(())
    }

    #[test]
    fn operational_errors_never_format_the_token() -> Result<(), Box<dyn std::error::Error>> {
        let token = "format-me-never";
        let config = resolved("https://connect.example.test", token)?;
        let error = control_upgrade_request(&config)
            .and_then(|_| Err::<Request<()>, _>(RuntimeError::ControlUnavailable))
            .expect_err("synthetic failure");
        for output in [format!("{error}"), format!("{error:?}")] {
            assert!(!output.contains(token));
        }
        Ok(())
    }

    #[test]
    fn accepted_session_hostname_and_urls_must_match() -> Result<(), Box<dyn std::error::Error>> {
        let session = Uuid::from_u128(42);
        let accepted = SessionAccepted::new(
            session,
            Subdomain::parse("demo")?,
            "http://demo.serus.eu",
            "https://demo.serus.eu",
            30,
        );
        let info = validate_acceptance(accepted.clone(), session, Some("demo.serus.eu"), None)?;
        assert_eq!(info.hostname, "demo.serus.eu");

        let wrong_session = validate_acceptance(accepted.clone(), Uuid::from_u128(43), None, None);
        assert!(matches!(
            wrong_session,
            Err(RuntimeError::ProtocolViolation)
        ));
        let wrong_request =
            validate_acceptance(accepted.clone(), session, Some("other.serus.eu"), None);
        assert!(matches!(
            wrong_request,
            Err(RuntimeError::ProtocolViolation)
        ));

        let mut wrong_url = accepted;
        wrong_url.public_http_url = "http://other.serus.eu".to_owned();
        assert!(matches!(
            validate_acceptance(wrong_url, session, None, None),
            Err(RuntimeError::ProtocolViolation)
        ));
        Ok(())
    }

    #[test]
    fn rejection_classification_treats_only_server_unavailable_as_transient() {
        for code in [
            RejectCode::AuthenticationFailed,
            RejectCode::UserDisabled,
            RejectCode::UnsupportedProtocol,
            RejectCode::InvalidRequest,
            RejectCode::InvalidSubdomain,
            RejectCode::SubdomainConflict,
        ] {
            assert!(reject_code_is_permanent(code));
            assert!(matches!(
                classify_rejection(SessionRejected::transient(code, "ignored")),
                RuntimeError::Rejected { .. }
            ));
        }
        assert!(matches!(
            classify_rejection(SessionRejected::transient(
                RejectCode::ServerUnavailable,
                "ignored"
            )),
            RuntimeError::ControlUnavailable
        ));
        assert!(matches!(
            classify_rejection(SessionRejected::permanent(
                RejectCode::ServerUnavailable,
                "ignored"
            )),
            RuntimeError::Rejected { .. }
        ));
    }
}
