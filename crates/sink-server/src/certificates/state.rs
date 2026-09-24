use std::{fmt, time::Duration};

use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{CertificateProviderKind, CertificateTarget};

/// Wall-clock time represented as Unix seconds for straightforward durable
/// storage and deterministic scheduling tests.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct Timestamp(u64);

impl Timestamp {
    pub const fn from_unix_seconds(seconds: u64) -> Self {
        Self(seconds)
    }

    pub const fn unix_seconds(self) -> u64 {
        self.0
    }

    pub fn saturating_add(self, duration: Duration) -> Self {
        Self(self.0.saturating_add(duration.as_secs()))
    }
}

/// Secret account or key material. Debug output is always redacted and the
/// allocation is zeroed when dropped.
#[derive(Clone, Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    pub fn expose_secret(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretBytes([REDACTED])")
    }
}

/// Persisted ACME/provider account state. The opaque secret is owned by the
/// provider adapter and must never be logged or returned to clients.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountRecord {
    pub provider: CertificateProviderKind,
    pub external_account_id: String,
    pub private_state: SecretBytes,
}

/// Certificate and private key returned by a provider.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertificateMaterial {
    pub certificate_chain_pem: Vec<u8>,
    pub private_key_pem: SecretBytes,
    pub not_before: Timestamp,
    pub not_after: Timestamp,
}

impl CertificateMaterial {
    pub fn is_valid_at(&self, now: Timestamp) -> bool {
        self.not_before <= now && now < self.not_after
    }
}

/// Durable serving/provisioning state for a managed certificate target.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CertificateState {
    Pending,
    Ready(CertificateMaterial),
    RetryScheduled {
        retry_at: Timestamp,
        cooldown_until: Option<Timestamp>,
    },
    Failed,
    /// Valid material retained after a namespace release. It is never served,
    /// but can be promoted without a new order after an authorized reclaim.
    Retained(CertificateMaterial),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertificateRecord {
    pub target: CertificateTarget,
    pub provider: CertificateProviderKind,
    pub state: CertificateState,
    pub updated_at: Timestamp,
}

impl CertificateRecord {
    pub fn pending(
        target: CertificateTarget,
        provider: CertificateProviderKind,
        now: Timestamp,
    ) -> Self {
        Self {
            target,
            provider,
            state: CertificateState::Pending,
            updated_at: now,
        }
    }

    pub fn ready(
        target: CertificateTarget,
        provider: CertificateProviderKind,
        material: CertificateMaterial,
        now: Timestamp,
    ) -> Self {
        Self {
            target,
            provider,
            state: CertificateState::Ready(material),
            updated_at: now,
        }
    }

    pub fn retained(
        target: CertificateTarget,
        provider: CertificateProviderKind,
        material: CertificateMaterial,
        now: Timestamp,
    ) -> Self {
        Self {
            target,
            provider,
            state: CertificateState::Retained(material),
            updated_at: now,
        }
    }

    pub fn reusable_material(&self, now: Timestamp) -> Option<&CertificateMaterial> {
        match &self.state {
            CertificateState::Ready(material) | CertificateState::Retained(material)
                if material.is_valid_at(now) =>
            {
                Some(material)
            }
            _ => None,
        }
    }

    pub fn active_material(&self, now: Timestamp) -> Option<&CertificateMaterial> {
        match &self.state {
            CertificateState::Ready(material) if material.is_valid_at(now) => Some(material),
            _ => None,
        }
    }

    pub fn promote_reusable(&mut self, now: Timestamp) -> bool {
        let CertificateState::Retained(material) = &self.state else {
            return self.active_material(now).is_some();
        };
        if !material.is_valid_at(now) {
            return false;
        }

        self.state = CertificateState::Ready(material.clone());
        self.updated_at = now;
        true
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OrderOwner {
    Platform,
    User(String),
}

impl OrderOwner {
    pub fn user_id(&self) -> Option<&str> {
        match self {
            Self::Platform => None,
            Self::User(user_id) => Some(user_id),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IssuanceReason {
    BaseProvisioning,
    NamespaceClaim,
    Renewal,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuanceRequest {
    pub target: CertificateTarget,
    pub provider: CertificateProviderKind,
    pub owner: OrderOwner,
    pub reason: IssuanceReason,
}

impl IssuanceRequest {
    pub fn validates_ownership_shape(&self) -> bool {
        matches!(
            (&self.target, &self.owner, self.reason),
            (
                CertificateTarget::BaseDomain(_),
                OrderOwner::Platform,
                IssuanceReason::BaseProvisioning | IssuanceReason::Renewal
            ) | (
                CertificateTarget::Namespace(_),
                OrderOwner::User(_),
                IssuanceReason::NamespaceClaim | IssuanceReason::Renewal
            )
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OrderState {
    Queued,
    InProgress,
    RetryScheduled { retry_at: Timestamp },
    Succeeded,
    Failed,
}

impl OrderState {
    pub fn is_pending(&self) -> bool {
        matches!(
            self,
            Self::Queued | Self::InProgress | Self::RetryScheduled { .. }
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrderRecord {
    pub request: IssuanceRequest,
    pub state: OrderState,
    pub attempts: u32,
    pub consecutive_failures: u32,
    pub cooldown_until: Option<Timestamp>,
    pub last_error: Option<String>,
    pub updated_at: Timestamp,
}

impl OrderRecord {
    pub fn queued(request: IssuanceRequest, now: Timestamp) -> Self {
        Self {
            request,
            state: OrderState::Queued,
            attempts: 0,
            consecutive_failures: 0,
            cooldown_until: None,
            last_error: None,
            updated_at: now,
        }
    }

    pub fn start(&mut self, now: Timestamp) {
        self.attempts = self.attempts.saturating_add(1);
        self.state = OrderState::InProgress;
        self.updated_at = now;
    }

    pub fn succeed(&mut self, now: Timestamp) {
        self.state = OrderState::Succeeded;
        self.consecutive_failures = 0;
        self.cooldown_until = None;
        self.last_error = None;
        self.updated_at = now;
    }

    pub fn fail_permanently(&mut self, message: String, now: Timestamp) {
        self.state = OrderState::Failed;
        self.last_error = Some(message);
        self.updated_at = now;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_debug_output_is_always_redacted() {
        let secret = SecretBytes::new(b"never-print-this".to_vec());
        let rendered = format!("{secret:?}");

        assert_eq!(rendered, "SecretBytes([REDACTED])");
        assert!(!rendered.contains("never-print-this"));
    }
}
