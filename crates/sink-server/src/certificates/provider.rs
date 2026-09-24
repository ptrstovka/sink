use std::{fmt, str::FromStr};

use futures::future::BoxFuture;
use thiserror::Error;

use super::{AccountRecord, CertificateIdentifiers, CertificateMaterial};

/// Selects the provider adapter for a configured domain. Cloudflare is the
/// only accepted initial value; adding another adapter does not change the
/// configured-domain or certificate storage contracts.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CertificateProviderKind {
    Cloudflare,
}

impl CertificateProviderKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cloudflare => "cloudflare",
        }
    }
}

impl fmt::Display for CertificateProviderKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for CertificateProviderKind {
    type Err = UnsupportedCertificateProvider;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "cloudflare" => Ok(Self::Cloudflare),
            _ => Err(UnsupportedCertificateProvider(value.to_owned())),
        }
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
#[error("unsupported certificate provider `{0}`; supported providers: cloudflare")]
pub struct UnsupportedCertificateProvider(pub String);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderErrorKind {
    Retryable,
    Permanent,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
#[error("certificate provider error: {message}")]
pub struct ProviderError {
    pub kind: ProviderErrorKind,
    /// Sanitized operational context only; adapters must not include API,
    /// ACME-account, challenge, or private-key secrets.
    pub message: String,
}

impl ProviderError {
    pub fn retryable(message: impl Into<String>) -> Self {
        Self {
            kind: ProviderErrorKind::Retryable,
            message: message.into(),
        }
    }

    pub fn permanent(message: impl Into<String>) -> Self {
        Self {
            kind: ProviderErrorKind::Permanent,
            message: message.into(),
        }
    }
}

/// Boundary for future ACME account and DNS-01 implementations. Provider
/// adapters receive only opaque persisted account state and exact identifiers;
/// they do not decide claim ownership or which hostnames may be served.
pub trait CertificateProvider: Send + Sync {
    fn kind(&self) -> CertificateProviderKind;

    /// Non-secret durable account realm, normally the validated ACME directory
    /// URL. Accounts from different realms must never be interchanged.
    fn account_scope(&self) -> &str;

    fn provision_account<'a>(
        &'a self,
        persisted: Option<&'a AccountRecord>,
    ) -> BoxFuture<'a, Result<AccountRecord, ProviderError>>;

    fn issue<'a>(
        &'a self,
        account: &'a AccountRecord,
        identifiers: &'a CertificateIdentifiers,
    ) -> BoxFuture<'a, Result<CertificateMaterial, ProviderError>>;
}
