//! Certificate lifecycle foundations.
//!
//! This module deliberately contains no public listener, rustls, Cloudflare,
//! or ACME network wiring. It defines the normalized identifiers, provider and
//! persistence boundaries, policy/scheduling primitives, and fail-closed SNI
//! selection those later integrations use.

mod fake;
mod manager;
mod names;
mod policy;
mod provider;
mod resolver;
mod state;
mod storage;

pub use fake::{FakeCertificateProvider, FakeCertificateStorage};
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
    AuthorizedHostnames, IndexError, ResolveError, ResolvedCertificate, SniAuthorization,
    SniCertificateIndex,
};
pub use state::{
    AccountRecord, CertificateMaterial, CertificateRecord, CertificateState, IssuanceReason,
    IssuanceRequest, OrderOwner, OrderRecord, OrderState, SecretBytes, Timestamp,
};
pub use storage::{CertificateStorage, StorageError};
