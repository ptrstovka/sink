use serde::{Deserialize, Serialize};

/// Versioned namespace-management collection endpoint on the Sink control host.
pub const NAMESPACE_COLLECTION_PATH: &str = "/_sink/api/v1/namespaces";

/// Versioned namespace-management item endpoint pattern on the Sink control host.
pub const NAMESPACE_ITEM_PATH: &str = "/_sink/api/v1/namespaces/{hostname}";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamespaceClaimRequest {
    pub hostname: String,
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
                state: NamespaceState::Retrying,
                created_at: 10,
                updated_at: 20,
            },
        };

        let json = serde_json::to_value(&response)?;
        assert_eq!(json["namespace"]["hostname"], "cloud.example.test");
        assert_eq!(json["namespace"]["state"], "retrying");
        assert_eq!(serde_json::from_value::<NamespaceResponse>(json)?, response);
        Ok(())
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
        Ok(())
    }
}
