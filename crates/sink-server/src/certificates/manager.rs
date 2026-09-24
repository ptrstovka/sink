use std::sync::Arc;

use thiserror::Error;
use tokio::sync::{Mutex, Semaphore};

use super::{
    CertificateProvider, CertificateRecord, CertificateState, CertificateStorage, IssuancePolicy,
    IssuanceRequest, LimitExceeded, OrderPlan, OrderRecord, OrderState, ProviderError,
    ProviderErrorKind, QuotaSnapshot, StorageError, Timestamp,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProvisionOutcome {
    Issued(CertificateRecord),
    Reused(CertificateRecord),
    Deduplicated(OrderState),
    RetryNotDue { retry_at: Timestamp },
    RetryScheduled { retry_at: Timestamp },
    PermanentlyFailed,
    Rejected(LimitExceeded),
}

/// Coordinates durable lifecycle transitions around a provider call. Claim
/// ownership and database transactions remain outside this type; the caller
/// supplies their already-computed quota snapshot.
pub struct CertificateManager<P, S> {
    provider: Arc<P>,
    storage: Arc<S>,
    policy: IssuancePolicy,
    admission_lock: Mutex<()>,
    provider_slots: Arc<Semaphore>,
}

impl<P, S> CertificateManager<P, S>
where
    P: CertificateProvider,
    S: CertificateStorage,
{
    pub fn new(provider: Arc<P>, storage: Arc<S>, policy: IssuancePolicy) -> Self {
        let provider_slots = Arc::new(Semaphore::new(policy.limits().max_concurrent_orders()));
        Self {
            provider,
            storage,
            policy,
            admission_lock: Mutex::new(()),
            provider_slots,
        }
    }

    /// Reconcile orders that were executing when the previous process stopped.
    /// Call this once during backend startup before accepting provisioning
    /// work; the storage operation is transactional and idempotent.
    pub async fn reconcile_after_restart(&self, now: Timestamp) -> Result<u64, ManagerError> {
        self.storage
            .reconcile_in_progress(self.policy.limits().retry(), now)
            .await
            .map_err(Into::into)
    }

    pub async fn provision(
        &self,
        request: IssuanceRequest,
        quota: QuotaSnapshot,
        now: Timestamp,
    ) -> Result<ProvisionOutcome, ManagerError> {
        if request.provider != self.provider.kind() {
            return Err(ManagerError::ProviderMismatch);
        }

        let admission_guard = self.admission_lock.lock().await;
        let mut certificate = self.storage.load_certificate(&request.target).await?;
        let persisted_order = self.storage.load_order(&request.target).await?;
        let plan = self.policy.plan(
            &request,
            quota,
            certificate.as_ref(),
            persisted_order.as_ref(),
            now,
        );

        match plan {
            OrderPlan::ReuseValidCertificate => {
                let mut reusable = certificate.ok_or(ManagerError::InconsistentStorage)?;
                if !reusable.promote_reusable(now) {
                    return Err(ManagerError::InconsistentStorage);
                }
                self.storage.store_certificate(reusable.clone()).await?;
                return Ok(ProvisionOutcome::Reused(reusable));
            }
            OrderPlan::Deduplicated(state) => {
                return Ok(ProvisionOutcome::Deduplicated(state));
            }
            OrderPlan::RetryNotDue { retry_at } => {
                return Ok(ProvisionOutcome::RetryNotDue { retry_at });
            }
            OrderPlan::PermanentlyFailed => return Ok(ProvisionOutcome::PermanentlyFailed),
            OrderPlan::Rejected(limit) => return Ok(ProvisionOutcome::Rejected(limit)),
            OrderPlan::InvalidRequest => return Err(ManagerError::InvalidRequest),
            OrderPlan::Start => {}
        }

        let Ok(permit) = self.provider_slots.clone().try_acquire_owned() else {
            return Ok(ProvisionOutcome::Rejected(
                LimitExceeded::ConcurrentGlobalOrders,
            ));
        };

        let mut order = match persisted_order {
            Some(existing) if matches!(existing.state, OrderState::RetryScheduled { .. }) => {
                existing
            }
            _ => OrderRecord::queued(request.clone(), now),
        };
        order.start(now);
        let pending = if certificate
            .as_ref()
            .and_then(|record| record.active_material(now))
            .is_none()
        {
            let pending = CertificateRecord::pending(request.target.clone(), request.provider, now);
            certificate = Some(pending.clone());
            Some(pending)
        } else {
            None
        };
        self.storage.store_lifecycle(order.clone(), pending).await?;
        drop(admission_guard);

        let result = self.issue(&request).await;
        drop(permit);

        match result {
            Ok(material) => {
                if material.not_before >= material.not_after || material.not_after <= now {
                    return self
                        .record_provider_failure(
                            &mut order,
                            certificate,
                            ProviderError::permanent(
                                "provider returned an invalid certificate validity interval",
                            ),
                            now,
                        )
                        .await;
                }

                let ready =
                    CertificateRecord::ready(request.target, request.provider, material, now);
                order.succeed(now);
                self.storage
                    .store_lifecycle(order, Some(ready.clone()))
                    .await?;
                Ok(ProvisionOutcome::Issued(ready))
            }
            Err(error) => {
                let outcome = self
                    .record_provider_failure(&mut order, certificate, error, now)
                    .await?;
                Ok(outcome)
            }
        }
    }

    async fn issue(
        &self,
        request: &IssuanceRequest,
    ) -> Result<super::CertificateMaterial, ProviderError> {
        let persisted = self
            .storage
            .load_account(request.provider, self.provider.account_scope())
            .await
            .map_err(|error| {
                ProviderError::retryable(format!("account storage unavailable: {error}"))
            })?;
        let account = self.provider.provision_account(persisted.as_ref()).await?;
        if account.provider != request.provider {
            return Err(ProviderError::permanent(
                "provider returned an account for a different adapter",
            ));
        }
        self.storage
            .store_account(account.clone())
            .await
            .map_err(|error| {
                ProviderError::retryable(format!("account storage unavailable: {error}"))
            })?;
        self.provider
            .issue(&account, &request.target.identifiers())
            .await
    }

    async fn record_provider_failure(
        &self,
        order: &mut OrderRecord,
        existing_certificate: Option<CertificateRecord>,
        error: ProviderError,
        now: Timestamp,
    ) -> Result<ProvisionOutcome, ManagerError> {
        match error.kind {
            ProviderErrorKind::Retryable => {
                let retry_at =
                    self.policy
                        .limits()
                        .retry()
                        .schedule_retry(order, error.message, now);
                let certificate = if existing_certificate
                    .as_ref()
                    .and_then(|record| record.active_material(now))
                    .is_none()
                {
                    Some(CertificateRecord {
                        target: order.request.target.clone(),
                        provider: order.request.provider,
                        state: CertificateState::RetryScheduled {
                            retry_at,
                            cooldown_until: order.cooldown_until,
                        },
                        updated_at: now,
                    })
                } else {
                    None
                };
                self.storage
                    .store_lifecycle(order.clone(), certificate)
                    .await?;
                Ok(ProvisionOutcome::RetryScheduled { retry_at })
            }
            ProviderErrorKind::Permanent => {
                order.fail_permanently(error.message, now);
                let certificate = if existing_certificate
                    .as_ref()
                    .and_then(|record| record.active_material(now))
                    .is_none()
                {
                    Some(CertificateRecord {
                        target: order.request.target.clone(),
                        provider: order.request.provider,
                        state: CertificateState::Failed,
                        updated_at: now,
                    })
                } else {
                    None
                };
                self.storage
                    .store_lifecycle(order.clone(), certificate)
                    .await?;
                Ok(ProvisionOutcome::PermanentlyFailed)
            }
        }
    }
}

#[derive(Debug, Error)]
pub enum ManagerError {
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error("issuance request does not match the configured provider")]
    ProviderMismatch,
    #[error("issuance request target, owner, and reason are inconsistent")]
    InvalidRequest,
    #[error("certificate storage returned inconsistent state")]
    InconsistentStorage,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certificates::{
        CertificateMaterial, CertificateProviderKind, CertificateTarget, FakeCertificateProvider,
        FakeCertificateStorage, Hostname, IssuanceReason, OrderOwner, SecretBytes,
    };

    fn request() -> IssuanceRequest {
        IssuanceRequest {
            target: CertificateTarget::namespace(
                Hostname::parse("cloud.example.test").expect("valid hostname"),
            ),
            provider: CertificateProviderKind::Cloudflare,
            owner: OrderOwner::User("user-1".to_owned()),
            reason: IssuanceReason::NamespaceClaim,
        }
    }

    fn material() -> CertificateMaterial {
        CertificateMaterial {
            certificate_chain_pem: b"certificate chain".to_vec(),
            private_key_pem: SecretBytes::new(b"private key".to_vec()),
            not_before: Timestamp::from_unix_seconds(900),
            not_after: Timestamp::from_unix_seconds(10_000),
        }
    }

    #[tokio::test]
    async fn issues_and_persists_account_certificate_and_completed_order() {
        let provider = Arc::new(FakeCertificateProvider::succeeding(material()));
        let storage = Arc::new(FakeCertificateStorage::default());
        let manager =
            CertificateManager::new(provider.clone(), storage.clone(), IssuancePolicy::default());

        let outcome = manager
            .provision(
                request(),
                QuotaSnapshot::default(),
                Timestamp::from_unix_seconds(1_000),
            )
            .await
            .expect("issuance succeeds");

        assert!(matches!(outcome, ProvisionOutcome::Issued(_)));
        assert_eq!(provider.issue_count(), 1);
        assert!(
            storage
                .account(CertificateProviderKind::Cloudflare)
                .is_some()
        );
        assert!(matches!(
            storage
                .certificate(&request().target)
                .map(|record| record.state),
            Some(CertificateState::Ready(_))
        ));
        assert!(matches!(
            storage.order(&request().target).map(|record| record.state),
            Some(OrderState::Succeeded)
        ));
    }

    #[tokio::test]
    async fn reuses_retained_valid_material_without_calling_the_provider() {
        let provider = Arc::new(FakeCertificateProvider::succeeding(material()));
        let storage = Arc::new(FakeCertificateStorage::default());
        storage.insert_certificate(CertificateRecord::retained(
            request().target,
            CertificateProviderKind::Cloudflare,
            material(),
            Timestamp::from_unix_seconds(900),
        ));
        let manager = CertificateManager::new(provider.clone(), storage, IssuancePolicy::default());

        let outcome = manager
            .provision(
                request(),
                QuotaSnapshot::default(),
                Timestamp::from_unix_seconds(1_000),
            )
            .await
            .expect("reuse succeeds");

        assert!(matches!(outcome, ProvisionOutcome::Reused(_)));
        assert_eq!(provider.issue_count(), 0);
    }

    #[tokio::test]
    async fn retryable_failure_is_persisted_with_deterministic_backoff() {
        let provider = Arc::new(FakeCertificateProvider::failing(ProviderError::retryable(
            "temporary DNS failure",
        )));
        let storage = Arc::new(FakeCertificateStorage::default());
        let manager = CertificateManager::new(provider, storage.clone(), IssuancePolicy::default());

        let outcome = manager
            .provision(
                request(),
                QuotaSnapshot::default(),
                Timestamp::from_unix_seconds(1_000),
            )
            .await
            .expect("failure becomes schedule state");

        assert_eq!(
            outcome,
            ProvisionOutcome::RetryScheduled {
                retry_at: Timestamp::from_unix_seconds(1_060)
            }
        );
        assert!(matches!(
            storage.order(&request().target).map(|record| record.state),
            Some(OrderState::RetryScheduled { retry_at })
                if retry_at == Timestamp::from_unix_seconds(1_060)
        ));
    }

    #[tokio::test]
    async fn renewal_failure_keeps_the_still_valid_active_certificate() {
        let provider = Arc::new(FakeCertificateProvider::failing(ProviderError::retryable(
            "temporary CA failure",
        )));
        let storage = Arc::new(FakeCertificateStorage::default());
        let mut renewal = request();
        renewal.reason = IssuanceReason::Renewal;
        storage.insert_certificate(CertificateRecord::ready(
            renewal.target.clone(),
            CertificateProviderKind::Cloudflare,
            material(),
            Timestamp::from_unix_seconds(900),
        ));
        let manager = CertificateManager::new(provider, storage.clone(), IssuancePolicy::default());

        let outcome = manager
            .provision(
                renewal.clone(),
                QuotaSnapshot::default(),
                Timestamp::from_unix_seconds(1_000),
            )
            .await
            .expect("renewal failure becomes retry state");

        assert!(matches!(outcome, ProvisionOutcome::RetryScheduled { .. }));
        assert!(matches!(
            storage
                .certificate(&renewal.target)
                .map(|record| record.state),
            Some(CertificateState::Ready(_))
        ));
    }

    #[tokio::test]
    async fn restart_reconciliation_releases_deduplication_after_backoff() {
        let provider = Arc::new(FakeCertificateProvider::succeeding(material()));
        let storage = Arc::new(FakeCertificateStorage::default());
        let now = Timestamp::from_unix_seconds(1_000);
        let mut interrupted = OrderRecord::queued(request(), now);
        interrupted.start(now);
        storage.insert_order(interrupted);
        storage.insert_certificate(CertificateRecord::pending(
            request().target,
            CertificateProviderKind::Cloudflare,
            now,
        ));
        let manager =
            CertificateManager::new(provider.clone(), storage.clone(), IssuancePolicy::default());

        assert_eq!(
            manager
                .reconcile_after_restart(now)
                .await
                .expect("reconcile interrupted order"),
            1
        );
        assert_eq!(
            manager
                .provision(request(), QuotaSnapshot::default(), now)
                .await
                .expect("retry is delayed"),
            ProvisionOutcome::RetryNotDue {
                retry_at: Timestamp::from_unix_seconds(1_060)
            }
        );
        assert!(matches!(
            manager
                .provision(
                    request(),
                    QuotaSnapshot::default(),
                    Timestamp::from_unix_seconds(1_060),
                )
                .await
                .expect("retry starts when due"),
            ProvisionOutcome::Issued(_)
        ));
        assert_eq!(provider.issue_count(), 1);
    }
}
