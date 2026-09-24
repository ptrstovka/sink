//! Durable certificate lifecycle, ACME DNS-01, and fail-closed selection.
//!
//! This module deliberately contains no public listener or namespace HTTP
//! wiring. Network adapters stay behind deterministic ACME, DNS, and HTTP
//! boundaries so automated tests never contact public infrastructure.

mod acme;
mod cloudflare;
mod fake;
mod instant;
mod manager;
mod names;
mod policy;
mod provider;
mod resolver;
mod state;
mod storage;

pub use acme::{
    AcmeClient, AcmeOrder, CloudflareAcmeProvider, DnsChallenge, DnsChallengeProvider, DnsRecord,
};
pub use cloudflare::{
    CloudflareDnsProvider, CloudflareHttpClient, CloudflareHttpRequest, CloudflareHttpResponse,
    HttpMethod, ReqwestCloudflareHttpClient,
};
pub use fake::{FakeCertificateProvider, FakeCertificateStorage};
pub use instant::InstantAcmeClient;
pub use manager::{CertificateManager, ManagerError, ProvisionOutcome};
pub use names::{CertificateIdentifiers, CertificateTarget, Hostname, HostnameError};
pub use policy::{
    InvalidSafetyLimits, IssuancePolicy, LimitExceeded, OrderPlan, QuotaSnapshot, RetryPolicy,
    SafetyLimits,
};
pub use provider::{
    CertificateProvider, CertificateProviderKind, ProviderError, ProviderErrorKind,
    UnsupportedCertificateProvider,
};
pub use resolver::{
    AuthorizedHostnames, CertificateIndexReloader, CertificateReloadError, IndexError,
    ResolveError, ResolvedCertificate, SniAuthorization, SniCertificateIndex,
};
pub use state::{
    AccountRecord, CertificateMaterial, CertificateRecord, CertificateState, IssuanceReason,
    IssuanceRequest, OrderOwner, OrderRecord, OrderState, SecretBytes, Timestamp,
};
pub use storage::{CertificateStorage, SqliteCertificateStorage, StorageError};
