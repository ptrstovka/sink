//! Certificate lifecycle boundary used by the authenticated namespace control plane.

use std::sync::Arc;

use futures::future::BoxFuture;
use thiserror::Error;

use crate::certificates::{
    CertificateIndexReloader, CertificateManager, CertificateProvider, CertificateProviderKind,
    CertificateRecord, CertificateState, CertificateStorage, CertificateTarget, Hostname,
    IssuancePolicy, IssuanceReason, IssuanceRequest, OrderOwner, OrderState, ProvisionOutcome,
    QuotaSnapshot, StorageError, Timestamp,
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
    reloader: Option<Arc<dyn CertificateIndexReloader>>,
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
            reloader: None,
        }
    }

    pub fn from_manager(
        manager: CertificateManager<P, S>,
        storage: Arc<S>,
        reloader: Arc<dyn CertificateIndexReloader>,
    ) -> Self {
        Self {
            manager,
            storage,
            reloader: Some(reloader),
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
            if status == NamespaceCertificateStatus::Ready
                && let Some(reloader) = &self.reloader
            {
                reloader
                    .refresh(request.now)
                    .await
                    .map_err(|_| NamespaceCertificateError)?;
            }
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
            let certificate = self
                .storage
                .load_certificate(&target)
                .await
                .map_err(map_storage_error)?;
            if certificate
                .as_ref()
                .is_some_and(|certificate| certificate.provider != provider)
            {
                return Err(NamespaceCertificateError);
            }
            let retained = certificate.and_then(|certificate| match certificate.state {
                CertificateState::Ready(material) => Some(CertificateRecord::retained(
                    target.clone(),
                    provider,
                    material,
                    now,
                )),
                CertificateState::Pending
                | CertificateState::RetryScheduled { .. }
                | CertificateState::Failed
                | CertificateState::Retained(_) => None,
            });
            self.storage
                .retire_order_cycle(target, provider, retained)
                .await
                .map_err(map_storage_error)?;
            if let Some(reloader) = &self.reloader {
                reloader
                    .refresh(now)
                    .await
                    .map_err(|_| NamespaceCertificateError)?;
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
    use tempfile::NamedTempFile;

    use super::*;
    use crate::certificates::{
        AuthorizedHostnames, CertificateMaterial, FakeCertificateProvider, FakeCertificateStorage,
        ProviderError, SecretBytes, SniCertificateIndex, SqliteCertificateStorage,
    };

    fn material(not_after: u64) -> CertificateMaterial {
        CertificateMaterial {
            certificate_chain_pem: b"certificate".to_vec(),
            private_key_pem: SecretBytes::new(b"private key".to_vec()),
            not_before: Timestamp::from_unix_seconds(10),
            not_after: Timestamp::from_unix_seconds(not_after),
        }
    }

    async fn sqlite_storage() -> (NamedTempFile, Arc<SqliteCertificateStorage>) {
        let file = NamedTempFile::new().expect("temporary database");
        let storage = Arc::new(
            SqliteCertificateStorage::connect(file.path())
                .await
                .expect("open certificate storage"),
        );
        (file, storage)
    }

    #[tokio::test]
    async fn manager_adapter_only_reports_ready_after_persistence() {
        let provider = Arc::new(FakeCertificateProvider::succeeding(material(1_000)));
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

    #[tokio::test]
    async fn sqlite_release_preserves_retained_reuse_then_allows_fresh_owner_cycle() {
        let (_file, storage) = sqlite_storage().await;
        let provider = Arc::new(FakeCertificateProvider::succeeding(material(1_500)));
        let certificates = ManagedNamespaceCertificates::new(
            provider.clone(),
            storage.clone(),
            IssuancePolicy::default(),
        );
        let hostname = Hostname::parse("cloud.example.test").expect("valid hostname");
        let request = |user_id, now| NamespaceCertificateRequest {
            hostname: hostname.clone(),
            user_id,
            provider: CertificateProviderKind::Cloudflare,
            quota: QuotaSnapshot::default(),
            now: Timestamp::from_unix_seconds(now),
        };

        assert_eq!(
            certificates
                .provision(request(7, 100))
                .await
                .expect("initial issuance"),
            NamespaceCertificateStatus::Ready
        );
        certificates
            .release(
                hostname.clone(),
                CertificateProviderKind::Cloudflare,
                Timestamp::from_unix_seconds(200),
            )
            .await
            .expect("release namespace cycle");
        let target = CertificateTarget::namespace(hostname.clone());
        assert!(
            storage
                .load_order(&target)
                .await
                .expect("load retired order")
                .is_none()
        );
        assert!(matches!(
            storage
                .load_certificate(&target)
                .await
                .expect("load retained material")
                .map(|certificate| certificate.state),
            Some(CertificateState::Retained(_))
        ));
        certificates
            .release(
                hostname.clone(),
                CertificateProviderKind::Cloudflare,
                Timestamp::from_unix_seconds(201),
            )
            .await
            .expect("idempotent release retry");
        assert!(matches!(
            storage
                .load_certificate(&target)
                .await
                .expect("load retained material after retry")
                .map(|certificate| certificate.state),
            Some(CertificateState::Retained(_))
        ));

        assert_eq!(
            certificates
                .provision(request(8, 300))
                .await
                .expect("new owner reuses retained material"),
            NamespaceCertificateStatus::Ready
        );
        assert_eq!(provider.issue_count(), 1);
        assert!(
            storage
                .load_order(&target)
                .await
                .expect("load reused cycle")
                .is_none()
        );
        certificates
            .release(
                hostname.clone(),
                CertificateProviderKind::Cloudflare,
                Timestamp::from_unix_seconds(400),
            )
            .await
            .expect("release reused material");

        provider.set_issue_result(Ok(material(10_000)));
        assert_eq!(
            certificates
                .provision(request(9, 2_000))
                .await
                .expect("fresh owner issues after retained material expires"),
            NamespaceCertificateStatus::Ready
        );
        let order = storage
            .load_order(&target)
            .await
            .expect("load fresh owner order")
            .expect("fresh owner order exists");
        assert_eq!(order.request.owner, OrderOwner::User("9".to_owned()));
        assert_eq!(order.request.reason, IssuanceReason::NamespaceClaim);
        assert_eq!(provider.issue_count(), 2);
    }

    #[tokio::test]
    async fn sqlite_release_retires_retry_cycle_before_new_owner_reclaims() {
        let (_file, storage) = sqlite_storage().await;
        let provider = Arc::new(FakeCertificateProvider::failing(ProviderError::retryable(
            "local retryable failure",
        )));
        let base_target = CertificateTarget::base_domain(
            Hostname::parse("example.test").expect("valid hostname"),
        );
        storage
            .store_certificate(CertificateRecord::ready(
                base_target.clone(),
                CertificateProviderKind::Cloudflare,
                material(10_000),
                Timestamp::from_unix_seconds(10),
            ))
            .await
            .expect("store base certificate");
        let certificates = ManagedNamespaceCertificates::new(
            provider.clone(),
            storage.clone(),
            IssuancePolicy::default(),
        );
        let hostname = Hostname::parse("cloud.example.test").expect("valid hostname");
        let request = |user_id, now| NamespaceCertificateRequest {
            hostname: hostname.clone(),
            user_id,
            provider: CertificateProviderKind::Cloudflare,
            quota: QuotaSnapshot::default(),
            now: Timestamp::from_unix_seconds(now),
        };

        assert_eq!(
            certificates
                .provision(request(7, 100))
                .await
                .expect("persist scheduled retry"),
            NamespaceCertificateStatus::Retrying
        );
        certificates
            .release(
                hostname.clone(),
                CertificateProviderKind::Cloudflare,
                Timestamp::from_unix_seconds(101),
            )
            .await
            .expect("release retrying namespace");
        let target = CertificateTarget::namespace(hostname.clone());
        assert!(
            storage
                .load_order(&target)
                .await
                .expect("load retired retry order")
                .is_none()
        );
        assert!(
            storage
                .load_certificate(&target)
                .await
                .expect("load retired retry certificate")
                .is_none()
        );
        let index = SniCertificateIndex::new(
            storage
                .load_certificates()
                .await
                .expect("load released certificate snapshot"),
        )
        .expect("valid released certificate snapshot");
        let authorized = AuthorizedHostnames::new([hostname.clone()]);
        assert_eq!(
            index
                .resolve(
                    hostname.as_str(),
                    Timestamp::from_unix_seconds(102),
                    &authorized,
                )
                .expect("released child falls back to base certificate")
                .target,
            &base_target
        );

        provider.set_issue_result(Ok(material(10_000)));
        assert_eq!(
            certificates
                .provision(request(8, 102))
                .await
                .expect("new owner starts without stale backoff"),
            NamespaceCertificateStatus::Ready
        );
        let order = storage
            .load_order(&target)
            .await
            .expect("load replacement order")
            .expect("replacement order exists");
        assert_eq!(order.request.owner, OrderOwner::User("8".to_owned()));
        assert_eq!(order.state, OrderState::Succeeded);
        assert_eq!(provider.issue_count(), 2);
    }
}
