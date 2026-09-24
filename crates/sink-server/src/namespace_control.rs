//! Certificate lifecycle boundary used by the authenticated namespace control plane.

use std::sync::Arc;

use futures::future::BoxFuture;
use thiserror::Error;

use crate::certificates::{
    CertificateManager, CertificateProvider, CertificateProviderKind, CertificateRecord,
    CertificateState, CertificateStorage, CertificateTarget, Hostname, IssuancePolicy,
    IssuanceReason, IssuanceRequest, OrderOwner, OrderState, ProvisionOutcome, QuotaSnapshot,
    StorageError, Timestamp,
};

#[derive(Clone, Debug)]
pub struct NamespaceCertificateRequest {
    pub hostname: Hostname,
    pub user_id: i64,
    pub provider: CertificateProviderKind,
    pub quota: QuotaSnapshot,
    pub now: Timestamp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NamespaceCertificateStatus {
    Pending,
    Ready,
    Retrying,
    Failed,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
#[error("namespace certificate operation is unavailable")]
pub struct NamespaceCertificateError;

/// Injectable boundary between namespace ownership and certificate lifecycle.
///
/// `Ready` is a strong result: implementations may return it only after usable
/// certificate material has been durably persisted. Errors must not contain
/// provider, account, challenge, or private-key secrets.
pub trait NamespaceCertificateProvisioner: Send + Sync {
    fn provision(
        &self,
        request: NamespaceCertificateRequest,
    ) -> BoxFuture<'_, Result<NamespaceCertificateStatus, NamespaceCertificateError>>;

    /// Stop future certificate use/renewal for a released namespace and retain
    /// reusable material according to the backend policy.
    fn release(
        &self,
        hostname: Hostname,
        provider: CertificateProviderKind,
        now: Timestamp,
    ) -> BoxFuture<'_, Result<(), NamespaceCertificateError>>;
}

/// Safe placeholder used until the durable certificate backend is injected by
/// the listener/backend integration lane. It never marks a claim active.
#[derive(Clone, Copy, Debug, Default)]
pub struct DeferredNamespaceCertificates;

impl NamespaceCertificateProvisioner for DeferredNamespaceCertificates {
    fn provision(
        &self,
        _request: NamespaceCertificateRequest,
    ) -> BoxFuture<'_, Result<NamespaceCertificateStatus, NamespaceCertificateError>> {
        Box::pin(async { Ok(NamespaceCertificateStatus::Pending) })
    }

    fn release(
        &self,
        _hostname: Hostname,
        _provider: CertificateProviderKind,
        _now: Timestamp,
    ) -> BoxFuture<'_, Result<(), NamespaceCertificateError>> {
        Box::pin(async { Ok(()) })
    }
}

/// Adapter from the certificate-manager foundation to the control-plane
/// boundary. The storage handle is retained so release can demote ready
/// material to retained material without exposing keys to the control plane.
pub struct ManagedNamespaceCertificates<P, S> {
    manager: CertificateManager<P, S>,
    storage: Arc<S>,
}

impl<P, S> ManagedNamespaceCertificates<P, S>
where
    P: CertificateProvider,
    S: CertificateStorage,
{
    pub fn new(provider: Arc<P>, storage: Arc<S>, policy: IssuancePolicy) -> Self {
        Self {
            manager: CertificateManager::new(provider, Arc::clone(&storage), policy),
            storage,
        }
    }
}

impl<P, S> NamespaceCertificateProvisioner for ManagedNamespaceCertificates<P, S>
where
    P: CertificateProvider + 'static,
    S: CertificateStorage + 'static,
{
    fn provision(
        &self,
        request: NamespaceCertificateRequest,
    ) -> BoxFuture<'_, Result<NamespaceCertificateStatus, NamespaceCertificateError>> {
        Box::pin(async move {
            let target = CertificateTarget::namespace(request.hostname);
            let outcome = self
                .manager
                .provision(
                    IssuanceRequest {
                        target: target.clone(),
                        provider: request.provider,
                        owner: OrderOwner::User(request.user_id.to_string()),
                        reason: IssuanceReason::NamespaceClaim,
                    },
                    request.quota,
                    request.now,
                )
                .await
                .map_err(|_| NamespaceCertificateError)?;

            let status = match outcome {
                ProvisionOutcome::Issued(record) | ProvisionOutcome::Reused(record) => {
                    if record.active_material(request.now).is_none() {
                        return Err(NamespaceCertificateError);
                    }
                    NamespaceCertificateStatus::Ready
                }
                ProvisionOutcome::Deduplicated(OrderState::RetryScheduled { .. })
                | ProvisionOutcome::RetryNotDue { .. }
                | ProvisionOutcome::RetryScheduled { .. } => NamespaceCertificateStatus::Retrying,
                ProvisionOutcome::Deduplicated(OrderState::Queued | OrderState::InProgress)
                | ProvisionOutcome::Rejected(_) => NamespaceCertificateStatus::Pending,
                ProvisionOutcome::Deduplicated(OrderState::Succeeded) => {
                    let certificate = self
                        .storage
                        .load_certificate(&target)
                        .await
                        .map_err(map_storage_error)?;
                    if certificate
                        .as_ref()
                        .and_then(|record| record.active_material(request.now))
                        .is_some()
                    {
                        NamespaceCertificateStatus::Ready
                    } else {
                        return Err(NamespaceCertificateError);
                    }
                }
                ProvisionOutcome::Deduplicated(OrderState::Failed)
                | ProvisionOutcome::PermanentlyFailed => NamespaceCertificateStatus::Failed,
            };
            Ok(status)
        })
    }

    fn release(
        &self,
        hostname: Hostname,
        provider: CertificateProviderKind,
        now: Timestamp,
    ) -> BoxFuture<'_, Result<(), NamespaceCertificateError>> {
        Box::pin(async move {
            let target = CertificateTarget::namespace(hostname);
            let Some(certificate) = self
                .storage
                .load_certificate(&target)
                .await
                .map_err(map_storage_error)?
            else {
                return Ok(());
            };

            if certificate.provider != provider {
                return Err(NamespaceCertificateError);
            }
            if let CertificateState::Ready(material) = certificate.state {
                self.storage
                    .store_certificate(CertificateRecord::retained(target, provider, material, now))
                    .await
                    .map_err(map_storage_error)?;
            }
            Ok(())
        })
    }
}

fn map_storage_error(_error: StorageError) -> NamespaceCertificateError {
    NamespaceCertificateError
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certificates::{
        CertificateMaterial, FakeCertificateProvider, FakeCertificateStorage, SecretBytes,
    };

    #[tokio::test]
    async fn manager_adapter_only_reports_ready_after_persistence() {
        let material = CertificateMaterial {
            certificate_chain_pem: b"certificate".to_vec(),
            private_key_pem: SecretBytes::new(b"private key".to_vec()),
            not_before: Timestamp::from_unix_seconds(10),
            not_after: Timestamp::from_unix_seconds(1_000),
        };
        let provider = Arc::new(FakeCertificateProvider::succeeding(material));
        let storage = Arc::new(FakeCertificateStorage::default());
        let certificates = ManagedNamespaceCertificates::new(
            provider,
            Arc::clone(&storage),
            IssuancePolicy::default(),
        );
        let hostname = Hostname::parse("cloud.example.test").expect("valid hostname");

        let status = certificates
            .provision(NamespaceCertificateRequest {
                hostname: hostname.clone(),
                user_id: 7,
                provider: CertificateProviderKind::Cloudflare,
                quota: QuotaSnapshot::default(),
                now: Timestamp::from_unix_seconds(100),
            })
            .await
            .expect("provisioning succeeds");

        assert_eq!(status, NamespaceCertificateStatus::Ready);
        assert!(matches!(
            storage
                .certificate(&CertificateTarget::namespace(hostname))
                .map(|record| record.state),
            Some(CertificateState::Ready(_))
        ));
    }
}
