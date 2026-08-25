use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::{PROTOCOL_VERSION, Subdomain};

/// First control message sent by a client after the authenticated WebSocket upgrade.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientHello {
    pub protocol_version: u16,
    pub session_id: Uuid,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_hostname: Option<String>,
    pub client_version: String,
}

impl ClientHello {
    #[must_use]
    pub fn new(
        session_id: Uuid,
        requested_hostname: Option<String>,
        client_version: impl Into<String>,
    ) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            session_id,
            requested_hostname,
            client_version: client_version.into(),
        }
    }

    pub fn validate(&self) -> Result<(), HandshakeError> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(HandshakeError::UnsupportedVersion {
                received: self.protocol_version,
                supported: PROTOCOL_VERSION,
            });
        }
        if self.session_id.is_nil() {
            return Err(HandshakeError::NilSessionId);
        }
        if self.client_version.trim().is_empty() {
            return Err(HandshakeError::MissingClientVersion);
        }
        if self.requested_hostname.as_ref().is_some_and(|hostname| {
            hostname.is_empty()
                || hostname.len() > 253
                || !hostname.is_ascii()
                || hostname.bytes().any(|byte| byte.is_ascii_whitespace())
        }) {
            return Err(HandshakeError::InvalidRequestedHostname);
        }
        Ok(())
    }
}

/// First control message returned by the server.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ServerHello {
    Accepted(SessionAccepted),
    Rejected(SessionRejected),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionAccepted {
    pub protocol_version: u16,
    pub session_id: Uuid,
    pub subdomain: Subdomain,
    pub public_http_url: String,
    pub public_https_url: String,
    pub reconnect_grace_seconds: u64,
}

impl SessionAccepted {
    #[must_use]
    pub fn new(
        session_id: Uuid,
        subdomain: Subdomain,
        public_http_url: impl Into<String>,
        public_https_url: impl Into<String>,
        reconnect_grace_seconds: u64,
    ) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            session_id,
            subdomain,
            public_http_url: public_http_url.into(),
            public_https_url: public_https_url.into(),
            reconnect_grace_seconds,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionRejected {
    pub code: RejectCode,
    pub message: String,
    /// Permanent rejections stop the client's reconnect loop.
    pub permanent: bool,
}

impl SessionRejected {
    #[must_use]
    pub fn permanent(code: RejectCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            permanent: true,
        }
    }

    #[must_use]
    pub fn transient(code: RejectCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            permanent: false,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectCode {
    AuthenticationFailed,
    UserDisabled,
    UnsupportedProtocol,
    InvalidRequest,
    InvalidSubdomain,
    SubdomainConflict,
    ServerUnavailable,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum HandshakeError {
    #[error("unsupported protocol version {received}; this server supports version {supported}")]
    UnsupportedVersion { received: u16, supported: u16 },
    #[error("session id must not be nil")]
    NilSessionId,
    #[error("client version must not be empty")]
    MissingClientVersion,
    #[error("requested public hostname is invalid")]
    InvalidRequestedHostname,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_round_trips_without_token_material() -> Result<(), Box<dyn std::error::Error>> {
        let hello = ClientHello::new(
            Uuid::parse_str("f3ebc60f-6e4f-45b9-836e-3d1ed9c76e58")?,
            Some("demo.serus.eu".to_owned()),
            "0.1.0",
        );
        let json = serde_json::to_string(&hello)?;
        assert!(!json.contains("token"));
        assert_eq!(serde_json::from_str::<ClientHello>(&json)?, hello);
        Ok(())
    }

    #[test]
    fn incompatible_versions_are_rejected() {
        let mut hello = ClientHello::new(Uuid::new_v4(), None, "0.1.0");
        hello.protocol_version = PROTOCOL_VERSION + 1;
        assert!(matches!(
            hello.validate(),
            Err(HandshakeError::UnsupportedVersion { .. })
        ));
    }

    #[test]
    fn rejection_serialization_is_stable() -> Result<(), serde_json::Error> {
        let response = ServerHello::Rejected(SessionRejected::permanent(
            RejectCode::AuthenticationFailed,
            "credential rejected",
        ));
        let json = serde_json::to_value(response)?;
        assert_eq!(json["status"], "rejected");
        assert_eq!(json["code"], "authentication_failed");
        assert_eq!(json["permanent"], true);
        Ok(())
    }
}
