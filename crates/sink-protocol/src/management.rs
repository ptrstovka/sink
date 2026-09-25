use serde::{Deserialize, Serialize};

/// Versioned namespace-management collection endpoint on the Sink control host.
pub const NAMESPACE_COLLECTION_PATH: &str = "/_sink/api/v1/namespaces";

/// Versioned namespace-management item endpoint pattern on the Sink control host.
pub const NAMESPACE_ITEM_PATH: &str = "/_sink/api/v1/namespaces/{hostname}";

/// TLS handling selected for one persistent namespace.
///
/// Managed TLS is the backward-compatible default and is omitted from JSON.
/// Passthrough is always explicit on both claims and namespace responses.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NamespaceTlsMode {
    #[default]
    Managed,
    Passthrough,
}

impl NamespaceTlsMode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Managed => "managed",
            Self::Passthrough => "passthrough",
        }
    }

    fn is_managed(&self) -> bool {
        *self == Self::Managed
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamespaceClaimRequest {
    pub hostname: String,
}

impl NamespaceClaimRequest {
    pub const MANAGED_TLS_MODE: &'static str = "managed";
    pub const PASSTHROUGH_TLS_MODE: &'static str = "passthrough";

    #[must_use]
    pub fn managed(hostname: impl Into<String>) -> Self {
        Self {
            hostname: hostname.into(),
        }
    }

    /// Build the opt-in passthrough request shape without changing the legacy
    /// managed request type or its serialized form.
    #[must_use]
    pub fn passthrough(hostname: impl Into<String>) -> impl Serialize {
        NamespaceClaimWithModeRequest {
            hostname: hostname.into(),
            tls_mode: NamespaceTlsMode::Passthrough,
        }
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct NamespaceClaimWithModeRequest {
    hostname: String,
    tls_mode: NamespaceTlsMode,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NamespaceState {
    Pending,
    Active,
    Failed,
    Retrying,
    Releasing,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Namespace {
    pub hostname: String,
    pub depth: u32,
    #[serde(default, skip_serializing_if = "NamespaceTlsMode::is_managed")]
    pub tls_mode: NamespaceTlsMode,
    pub state: NamespaceState,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamespaceResponse {
    pub namespace: Namespace,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamespaceListResponse {
    pub namespaces: Vec<Namespace>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagementErrorCode {
    AuthenticationRequired,
    InvalidRequest,
    InvalidHostname,
    ReservedHostname,
    NamespaceUnavailable,
    ParentNamespaceUnavailable,
    NamespaceNotFound,
    NamespaceHasChildren,
    NamespaceInUse,
    CertificateUnavailable,
    ServiceUnavailable,
}

impl ManagementErrorCode {
    pub const INVALID_TLS_MODE_CODE: &'static str = "invalid_tls_mode";
    pub const NAMESPACE_MODE_CONFLICT_CODE: &'static str = "namespace_mode_conflict";
    pub const WILDCARD_CONFLICT_CODE: &'static str = "wildcard_conflict";
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagementError {
    pub code: ManagementErrorCode,
    pub message: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagementErrorResponse {
    pub error: ManagementError,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespace_contract_serialization_is_stable() -> Result<(), serde_json::Error> {
        let response = NamespaceResponse {
            namespace: Namespace {
                hostname: "cloud.example.test".to_owned(),
                depth: 1,
                tls_mode: NamespaceTlsMode::Managed,
                state: NamespaceState::Retrying,
                created_at: 10,
                updated_at: 20,
            },
        };

        let json = serde_json::to_value(&response)?;
        assert_eq!(json["namespace"]["hostname"], "cloud.example.test");
        assert!(json["namespace"].get("tls_mode").is_none());
        assert_eq!(json["namespace"]["state"], "retrying");
        assert_eq!(serde_json::from_value::<NamespaceResponse>(json)?, response);
        Ok(())
    }

    #[test]
    fn managed_mode_is_the_backward_compatible_request_default() -> Result<(), serde_json::Error> {
        let legacy =
            serde_json::from_str::<NamespaceClaimRequest>(r#"{"hostname":"cloud.example.test"}"#)?;
        assert_eq!(legacy, NamespaceClaimRequest::managed("cloud.example.test"));

        let serialized = serde_json::to_value(&legacy)?;
        assert_eq!(
            serialized,
            serde_json::json!({"hostname": "cloud.example.test"})
        );
        Ok(())
    }

    #[test]
    fn passthrough_mode_has_stable_opt_in_serialization() -> Result<(), serde_json::Error> {
        let request = NamespaceClaimRequest::passthrough("cloud.example.test");
        let serialized = serde_json::to_value(&request)?;
        assert_eq!(
            serialized,
            serde_json::json!({
                "hostname": "cloud.example.test",
                "tls_mode": "passthrough"
            })
        );
        assert!(
            serde_json::from_value::<NamespaceClaimRequest>(serialized).is_err(),
            "the legacy managed request must retain its deny-unknown shape"
        );
        Ok(())
    }

    #[test]
    fn namespace_response_defaults_managed_and_round_trips_passthrough()
    -> Result<(), serde_json::Error> {
        let managed: NamespaceResponse = serde_json::from_str(
            r#"{"namespace":{"hostname":"cloud.example.test","depth":1,"state":"active","created_at":10,"updated_at":20}}"#,
        )?;
        assert_eq!(managed.namespace.tls_mode, NamespaceTlsMode::Managed);
        assert!(
            serde_json::to_value(&managed)?["namespace"]
                .get("tls_mode")
                .is_none()
        );

        let passthrough_json = serde_json::json!({
            "namespace": {
                "hostname": "edge.example.test",
                "depth": 1,
                "tls_mode": "passthrough",
                "state": "active",
                "created_at": 30,
                "updated_at": 40
            }
        });
        let passthrough: NamespaceResponse = serde_json::from_value(passthrough_json.clone())?;
        assert_eq!(
            passthrough.namespace.tls_mode,
            NamespaceTlsMode::Passthrough
        );
        assert_eq!(serde_json::to_value(passthrough)?, passthrough_json);
        Ok(())
    }

    #[test]
    fn invalid_namespace_tls_mode_is_rejected() {
        let invalid = serde_json::from_str::<NamespaceResponse>(
            r#"{"namespace":{"hostname":"edge.example.test","depth":1,"tls_mode":"edge","state":"active","created_at":30,"updated_at":40}}"#,
        );
        assert!(invalid.is_err());
        assert_eq!(NamespaceTlsMode::Managed.as_str(), "managed");
        assert_eq!(NamespaceTlsMode::Passthrough.as_str(), "passthrough");
    }

    #[test]
    fn management_errors_have_machine_readable_codes() -> Result<(), serde_json::Error> {
        let response = ManagementErrorResponse {
            error: ManagementError {
                code: ManagementErrorCode::NamespaceInUse,
                message: "namespace has active routes".to_owned(),
            },
        };

        let json = serde_json::to_value(response)?;
        assert_eq!(json["error"]["code"], "namespace_in_use");
        assert_eq!(json["error"]["message"], "namespace has active routes");
        assert_eq!(
            ManagementErrorCode::INVALID_TLS_MODE_CODE,
            "invalid_tls_mode"
        );
        assert_eq!(
            ManagementErrorCode::NAMESPACE_MODE_CONFLICT_CODE,
            "namespace_mode_conflict"
        );
        assert_eq!(
            ManagementErrorCode::WILDCARD_CONFLICT_CODE,
            "wildcard_conflict"
        );
        Ok(())
    }
}
