use std::{sync::Arc, time::Duration};

use thiserror::Error;

use crate::{
    certificates::{
        CertificateIndexReloader, CertificateManager, CertificateProvider, CertificateState,
        CertificateStorage, CertificateTarget, Hostname, IssuanceReason, IssuanceRequest,
        ManagerError, OrderOwner, OrderState, ProvisionOutcome, QuotaSnapshot, StorageError,
        Timestamp,
    },
    config::ConfiguredDomains,
    db::{DbError, NamespaceClaim, NamespaceClaimState},
};

use super::{RuntimeState, listeners::now_timestamp};

pub const DEFAULT_LIFECYCLE_INTERVAL: Duration = Duration::from_secs(30);
pub const DEFAULT_RENEW_BEFORE: Duration = Duration::from_secs(30 * 24 * 60 * 60);

#[derive(Debug, Error)]
pub enum LifecycleError {
    #[error(transparent)]
    Manager(#[from] ManagerError),
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error(transparent)]
    Database(#[from] DbError),
    #[error("managed TLS certificate index refresh failed")]
    Refresh,
    #[error("the configured base-domain certificate is not ready")]
    BaseCertificateUnavailable,
}

/// Provision or reuse every configured platform certificate before either
/// listener starts accepting traffic. A retry outcome is acceptable only when
/// a still-valid certificate remains available.
pub async fn provision_base_certificates<P, S>(
    manager: &CertificateManager<P, S>,
    storage: &Arc<S>,
    domains: &ConfiguredDomains,
    reloader: &Arc<dyn CertificateIndexReloader>,
    now: Timestamp,
) -> Result<(), LifecycleError>
where
    P: CertificateProvider,
    S: CertificateStorage,
{
    for domain in domains.as_slice() {
        manager
            .provision(
                IssuanceRequest {
                    target: CertificateTarget::base_domain(domain.hostname.clone()),
                    provider: domain.certificate_provider,
                    owner: OrderOwner::Platform,
                    reason: IssuanceReason::BaseProvisioning,
                },
                QuotaSnapshot::default(),
                now,
            )
            .await?;
        let target = CertificateTarget::base_domain(domain.hostname.clone());
        let ready = storage
            .load_certificate(&target)
            .await?
            .and_then(|record| record.active_material(now).cloned())
            .is_some();
        if !ready {
            return Err(LifecycleError::BaseCertificateUnavailable);
        }
    }
    reloader
        .refresh(now)
        .await
        .map_err(|_| LifecycleError::Refresh)
}

/// Durable retry and renewal executor. It derives work from persistent claims
/// and certificate state on every pass; no in-memory queue or repeated user
/// request is required for progress.
pub struct CertificateLifecycle<P, S> {
    manager: CertificateManager<P, S>,
    storage: Arc<S>,
    reloader: Arc<dyn CertificateIndexReloader>,
    state: RuntimeState,
    interval: Duration,
    renew_before: Duration,
}

impl<P, S> CertificateLifecycle<P, S>
where
    P: CertificateProvider + 'static,
    S: CertificateStorage + 'static,
{
    pub fn new(
        manager: CertificateManager<P, S>,
        storage: Arc<S>,
        reloader: Arc<dyn CertificateIndexReloader>,
        state: RuntimeState,
    ) -> Self {
        Self {
            manager,
            storage,
            reloader,
            state,
            interval: DEFAULT_LIFECYCLE_INTERVAL,
            renew_before: DEFAULT_RENEW_BEFORE,
        }
    }

    #[cfg(test)]
    fn with_schedule(mut self, interval: Duration, renew_before: Duration) -> Self {
        self.interval = interval;
        self.renew_before = renew_before;
        self
    }

    pub async fn run(self) {
        let mut shutdown = self.state.subscribe_shutdown();
        if *shutdown.borrow() {
            return;
        }
        let mut interval = tokio::time::interval(self.interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                biased;
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        return;
                    }
                }
                _ = interval.tick() => {
                    if let Err(error) = self.run_once(now_timestamp()).await {
                        tracing::error!(%error, "certificate lifecycle pass failed");
                    }
                }
            }
        }
    }

    pub async fn run_once(&self, now: Timestamp) -> Result<(), LifecycleError> {
        self.renew_base_certificates(now).await;

        let users = self.state.database.list_users().await?;
        for user in users {
            let claims = self.state.database.list_namespace_claims(user.id).await?;
            for claim in claims.clone() {
                if matches!(
                    claim.state,
                    NamespaceClaimState::Releasing | NamespaceClaimState::Failed
                ) {
                    continue;
                }
                self.progress_namespace(claim, &claims, now).await;
            }
        }
        Ok(())
    }

    async fn renew_base_certificates(&self, now: Timestamp) {
        for domain in self.state.domains.as_slice() {
            let target = CertificateTarget::base_domain(domain.hostname.clone());
            let certificate = match self.storage.load_certificate(&target).await {
                Ok(certificate) => certificate,
                Err(error) => {
                    tracing::error!(hostname = %domain.hostname, %error, "base certificate lookup failed");
                    continue;
                }
            };
            if !needs_renewal(certificate.as_ref(), now, self.renew_before) {
                continue;
            }
            let result = self
                .manager
                .provision(
                    IssuanceRequest {
                        target,
                        provider: domain.certificate_provider,
                        owner: OrderOwner::Platform,
                        reason: IssuanceReason::Renewal,
                    },
                    QuotaSnapshot::default(),
                    now,
                )
                .await;
            if let Err(error) = result {
                tracing::error!(hostname = %domain.hostname, %error, "base certificate renewal failed");
                continue;
            }
            if self.reloader.refresh(now).await.is_err() {
                tracing::error!(hostname = %domain.hostname, "base certificate reload failed");
            }
        }
    }

    async fn progress_namespace(
        &self,
        observed: NamespaceClaim,
        user_claims: &[NamespaceClaim],
        now: Timestamp,
    ) {
        let Ok(hostname) = Hostname::parse(&observed.fqdn) else {
            tracing::error!(
                claim_id = observed.id,
                "persisted namespace hostname is invalid"
            );
            return;
        };
        let Some(domain) = self.state.domains.most_specific_match(&hostname).cloned() else {
            tracing::error!(hostname = %hostname, "persisted namespace has no configured base domain");
            return;
        };
        let _mutation = self.state.namespace_mutations.lock(&hostname).await;
        let current = match self.state.database.namespace_claim(hostname.as_str()).await {
            Ok(Some(claim)) if claim.user_id == observed.user_id => claim,
            Ok(Some(_) | None) => return,
            Err(error) => {
                tracing::error!(hostname = %hostname, %error, "namespace lifecycle lookup failed");
                return;
            }
        };
        if matches!(
            current.state,
            NamespaceClaimState::Releasing | NamespaceClaimState::Failed
        ) {
            return;
        }

        let target = CertificateTarget::namespace(hostname.clone());
        if current.state != NamespaceClaimState::Active {
            match self.storage.load_order(&target).await {
                Ok(Some(order)) if order.state == OrderState::Failed => {
                    let _admission = self.state.admission_gate.lock().await;
                    if let Err(error) = self
                        .state
                        .database
                        .transition_namespace_claim(
                            current.user_id,
                            &current.fqdn,
                            current.state,
                            NamespaceClaimState::Failed,
                        )
                        .await
                    {
                        tracing::debug!(hostname = %hostname, %error, "namespace permanent-failure transition raced");
                    }
                    return;
                }
                Ok(_) => {}
                Err(error) => {
                    tracing::error!(hostname = %hostname, %error, "namespace order lookup failed");
                    return;
                }
            }
        }
        if current.state == NamespaceClaimState::Active {
            let certificate = match self.storage.load_certificate(&target).await {
                Ok(certificate) => certificate,
                Err(error) => {
                    tracing::error!(hostname = %hostname, %error, "namespace certificate lookup failed");
                    return;
                }
            };
            if !needs_renewal(certificate.as_ref(), now, self.renew_before) {
                return;
            }
        }

        let reason = if current.state == NamespaceClaimState::Active {
            IssuanceReason::Renewal
        } else {
            IssuanceReason::NamespaceClaim
        };
        let outcome = match self
            .manager
            .provision(
                IssuanceRequest {
                    target: target.clone(),
                    provider: domain.certificate_provider,
                    owner: OrderOwner::User(current.user_id.to_string()),
                    reason,
                },
                quota_snapshot(user_claims, current.id),
                now,
            )
            .await
        {
            Ok(outcome) => outcome,
            Err(error) => {
                tracing::error!(hostname = %hostname, %error, "namespace certificate lifecycle failed");
                return;
            }
        };

        if self.reloader.refresh(now).await.is_err() {
            tracing::error!(hostname = %hostname, "namespace certificate reload failed");
            return;
        }
        let active_material = match self.storage.load_certificate(&target).await {
            Ok(record) => record
                .as_ref()
                .and_then(|record| record.active_material(now))
                .is_some(),
            Err(error) => {
                tracing::error!(hostname = %hostname, %error, "namespace certificate verification failed");
                return;
            }
        };
        let desired = namespace_state(&outcome, active_material, current.state);
        if desired == current.state {
            return;
        }

        let _admission = self.state.admission_gate.lock().await;
        if let Err(error) = self
            .state
            .database
            .transition_namespace_claim(current.user_id, &current.fqdn, current.state, desired)
            .await
        {
            tracing::debug!(hostname = %hostname, %error, "namespace lifecycle transition raced");
        }
    }
}

fn needs_renewal(
    certificate: Option<&crate::certificates::CertificateRecord>,
    now: Timestamp,
    renew_before: Duration,
) -> bool {
    match certificate.map(|record| &record.state) {
        Some(CertificateState::Ready(material)) => {
            material.not_after <= now.saturating_add(renew_before)
        }
        _ => true,
    }
}

fn namespace_state(
    outcome: &ProvisionOutcome,
    active_material: bool,
    previous: NamespaceClaimState,
) -> NamespaceClaimState {
    if active_material {
        return NamespaceClaimState::Active;
    }
    match outcome {
        ProvisionOutcome::Deduplicated(OrderState::Failed)
        | ProvisionOutcome::PermanentlyFailed => NamespaceClaimState::Failed,
        ProvisionOutcome::Deduplicated(OrderState::RetryScheduled { .. })
        | ProvisionOutcome::RetryNotDue { .. }
        | ProvisionOutcome::RetryScheduled { .. } => NamespaceClaimState::Retrying,
        ProvisionOutcome::Issued(_)
        | ProvisionOutcome::Reused(_)
        | ProvisionOutcome::Deduplicated(OrderState::Succeeded) => NamespaceClaimState::Retrying,
        ProvisionOutcome::Deduplicated(OrderState::Queued | OrderState::InProgress)
        | ProvisionOutcome::Rejected(_) => {
            if previous == NamespaceClaimState::Active {
                NamespaceClaimState::Retrying
            } else {
                NamespaceClaimState::Pending
            }
        }
    }
}

fn quota_snapshot(claims: &[NamespaceClaim], target_id: i64) -> QuotaSnapshot {
    let active_claims_for_user = claims
        .iter()
        .filter(|claim| claim.state == NamespaceClaimState::Active)
        .count()
        .try_into()
        .unwrap_or(u32::MAX);
    let other_pending_orders_for_user = claims
        .iter()
        .filter(|claim| {
            claim.id != target_id
                && matches!(
                    claim.state,
                    NamespaceClaimState::Pending | NamespaceClaimState::Retrying
                )
        })
        .count()
        .try_into()
        .unwrap_or(u32::MAX);
    QuotaSnapshot {
        active_claims_for_user,
        other_pending_orders_for_user,
        concurrent_orders: 0,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use futures::future::BoxFuture;
    use tempfile::tempdir;

    use super::*;
    use crate::{
        certificates::{
            CertificateMaterial, CertificateProviderKind, CertificateRecord,
            FakeCertificateProvider, FakeCertificateStorage, IssuancePolicy, ProviderError,
            SecretBytes,
        },
        config::ConfiguredDomain,
        db::Database,
        namespace_control::DeferredNamespaceCertificates,
    };

    #[derive(Default)]
    struct RecordingReloader {
        refreshes: AtomicUsize,
    }

    impl CertificateIndexReloader for RecordingReloader {
        fn refresh(
            &self,
            _now: Timestamp,
        ) -> BoxFuture<'_, Result<(), crate::certificates::CertificateReloadError>> {
            self.refreshes.fetch_add(1, Ordering::Relaxed);
            Box::pin(async { Ok(()) })
        }
    }

    fn material(not_after: u64) -> CertificateMaterial {
        CertificateMaterial {
            certificate_chain_pem: b"test certificate".to_vec(),
            private_key_pem: SecretBytes::new(b"test private key".to_vec()),
            not_before: Timestamp::from_unix_seconds(100),
            not_after: Timestamp::from_unix_seconds(not_after),
        }
    }

    fn domains() -> ConfiguredDomains {
        ConfiguredDomains::new(vec![
            ConfiguredDomain::new(
                Hostname::parse("example.test").expect("valid hostname"),
                2,
                CertificateProviderKind::Cloudflare,
            )
            .expect("valid domain"),
        ])
        .expect("configured domains")
    }

    async fn state(database: Database, domains: ConfiguredDomains) -> RuntimeState {
        RuntimeState::with_namespace_control(
            database,
            "example.test",
            domains,
            Arc::new(DeferredNamespaceCertificates),
        )
        .expect("runtime state")
    }

    #[tokio::test]
    async fn background_pass_progresses_a_persisted_pending_claim_without_another_post() {
        let directory = tempdir().expect("temporary directory");
        let database = Database::open(directory.path().join("sink.sqlite3"))
            .await
            .expect("database");
        let user = database.create_user("alice").await.expect("create user");
        let claim = database
            .create_namespace_claim(user.user.id, "cloud.example.test", "example.test", 2)
            .await
            .expect("create claim");
        let storage = Arc::new(FakeCertificateStorage::default());
        storage.insert_certificate(CertificateRecord::ready(
            CertificateTarget::base_domain(
                Hostname::parse("example.test").expect("valid hostname"),
            ),
            CertificateProviderKind::Cloudflare,
            material(10_000_000),
            Timestamp::from_unix_seconds(100),
        ));
        let provider = Arc::new(FakeCertificateProvider::succeeding(material(100_000)));
        let manager =
            CertificateManager::new(provider.clone(), storage.clone(), IssuancePolicy::default());
        let reloader = Arc::new(RecordingReloader::default());
        let lifecycle = CertificateLifecycle::new(
            manager,
            storage,
            reloader.clone(),
            state(database.clone(), domains()).await,
        )
        .with_schedule(Duration::from_millis(10), Duration::from_secs(500));

        lifecycle
            .run_once(Timestamp::from_unix_seconds(1_000))
            .await
            .expect("lifecycle pass");

        let updated = database
            .namespace_claim(&claim.fqdn)
            .await
            .expect("claim lookup")
            .expect("claim remains");
        assert_eq!(updated.state, NamespaceClaimState::Active);
        assert_eq!(provider.issue_count(), 1);
        assert_eq!(reloader.refreshes.load(Ordering::Relaxed), 1);
        database.close().await;
    }

    #[tokio::test]
    async fn renewal_failure_preserves_a_still_valid_namespace_certificate() {
        let directory = tempdir().expect("temporary directory");
        let database = Database::open(directory.path().join("sink.sqlite3"))
            .await
            .expect("database");
        let user = database.create_user("alice").await.expect("create user");
        let claim = database
            .create_namespace_claim(user.user.id, "cloud.example.test", "example.test", 2)
            .await
            .expect("create claim");
        database
            .transition_namespace_claim(
                user.user.id,
                &claim.fqdn,
                NamespaceClaimState::Pending,
                NamespaceClaimState::Active,
            )
            .await
            .expect("activate claim");

        let storage = Arc::new(FakeCertificateStorage::default());
        storage.insert_certificate(CertificateRecord::ready(
            CertificateTarget::base_domain(
                Hostname::parse("example.test").expect("valid hostname"),
            ),
            CertificateProviderKind::Cloudflare,
            material(100_000),
            Timestamp::from_unix_seconds(100),
        ));
        let namespace_target = CertificateTarget::namespace(
            Hostname::parse("cloud.example.test").expect("valid hostname"),
        );
        storage.insert_certificate(CertificateRecord::ready(
            namespace_target.clone(),
            CertificateProviderKind::Cloudflare,
            material(1_200),
            Timestamp::from_unix_seconds(100),
        ));
        let provider = Arc::new(FakeCertificateProvider::failing(ProviderError::retryable(
            "local fake failure",
        )));
        let manager = CertificateManager::new(provider, storage.clone(), IssuancePolicy::default());
        let lifecycle = CertificateLifecycle::new(
            manager,
            storage.clone(),
            Arc::new(RecordingReloader::default()),
            state(database.clone(), domains()).await,
        )
        .with_schedule(Duration::from_millis(10), Duration::from_secs(500));

        lifecycle
            .run_once(Timestamp::from_unix_seconds(1_000))
            .await
            .expect("lifecycle pass");

        assert!(matches!(
            storage
                .certificate(&namespace_target)
                .map(|record| record.state),
            Some(CertificateState::Ready(_))
        ));
        let updated = database
            .namespace_claim(&claim.fqdn)
            .await
            .expect("claim lookup")
            .expect("claim remains");
        assert_eq!(updated.state, NamespaceClaimState::Active);
        database.close().await;
    }

    #[tokio::test]
    async fn background_pass_does_not_restart_a_permanently_failed_claim_cycle() {
        let directory = tempdir().expect("temporary directory");
        let database = Database::open(directory.path().join("sink.sqlite3"))
            .await
            .expect("database");
        let user = database.create_user("alice").await.expect("create user");
        let claim = database
            .create_namespace_claim(user.user.id, "cloud.example.test", "example.test", 2)
            .await
            .expect("create claim");
        let storage = Arc::new(FakeCertificateStorage::default());
        storage.insert_certificate(CertificateRecord::ready(
            CertificateTarget::base_domain(
                Hostname::parse("example.test").expect("valid hostname"),
            ),
            CertificateProviderKind::Cloudflare,
            material(10_000_000),
            Timestamp::from_unix_seconds(100),
        ));
        let target = CertificateTarget::namespace(
            Hostname::parse("cloud.example.test").expect("valid hostname"),
        );
        storage.insert_certificate(CertificateRecord {
            target: target.clone(),
            provider: CertificateProviderKind::Cloudflare,
            state: CertificateState::Failed,
            updated_at: Timestamp::from_unix_seconds(1_000),
        });
        let mut order = crate::certificates::OrderRecord::queued(
            IssuanceRequest {
                target,
                provider: CertificateProviderKind::Cloudflare,
                owner: OrderOwner::User(user.user.id.to_string()),
                reason: IssuanceReason::NamespaceClaim,
            },
            Timestamp::from_unix_seconds(1_000),
        );
        order.fail_permanently(
            "operator remediation required".to_owned(),
            Timestamp::from_unix_seconds(1_000),
        );
        storage.insert_order(order);
        let provider = Arc::new(FakeCertificateProvider::succeeding(material(100_000)));
        let manager =
            CertificateManager::new(provider.clone(), storage.clone(), IssuancePolicy::default());
        let lifecycle = CertificateLifecycle::new(
            manager,
            storage,
            Arc::new(RecordingReloader::default()),
            state(database.clone(), domains()).await,
        );

        lifecycle
            .run_once(Timestamp::from_unix_seconds(1_030))
            .await
            .expect("lifecycle pass");

        let updated = database
            .namespace_claim(&claim.fqdn)
            .await
            .expect("claim lookup")
            .expect("claim remains");
        assert_eq!(updated.state, NamespaceClaimState::Failed);
        assert_eq!(provider.issue_count(), 0);
        database.close().await;
    }

    #[tokio::test]
    async fn startup_fails_closed_when_the_base_certificate_is_unavailable() {
        let storage = Arc::new(FakeCertificateStorage::default());
        let provider = Arc::new(FakeCertificateProvider::failing(ProviderError::retryable(
            "local fake failure",
        )));
        let manager = CertificateManager::new(provider, storage.clone(), IssuancePolicy::default());
        let reloader: Arc<dyn CertificateIndexReloader> = Arc::new(RecordingReloader::default());

        let result = provision_base_certificates(
            &manager,
            &storage,
            &domains(),
            &reloader,
            Timestamp::from_unix_seconds(1_000),
        )
        .await;

        assert!(matches!(
            result,
            Err(LifecycleError::BaseCertificateUnavailable)
        ));
    }

    #[tokio::test]
    async fn lifecycle_stops_promptly_with_the_runtime() {
        let directory = tempdir().expect("temporary directory");
        let database = Database::open(directory.path().join("sink.sqlite3"))
            .await
            .expect("database");
        let runtime = state(database.clone(), domains()).await;
        let storage = Arc::new(FakeCertificateStorage::default());
        storage.insert_certificate(CertificateRecord::ready(
            CertificateTarget::base_domain(
                Hostname::parse("example.test").expect("valid hostname"),
            ),
            CertificateProviderKind::Cloudflare,
            material(100_000),
            Timestamp::from_unix_seconds(100),
        ));
        let manager = CertificateManager::new(
            Arc::new(FakeCertificateProvider::succeeding(material(100_000))),
            storage.clone(),
            IssuancePolicy::default(),
        );
        let lifecycle = CertificateLifecycle::new(
            manager,
            storage,
            Arc::new(RecordingReloader::default()),
            runtime.clone(),
        )
        .with_schedule(Duration::from_secs(60), Duration::from_secs(500));
        let task = tokio::spawn(lifecycle.run());

        runtime.initiate_shutdown();
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("lifecycle shutdown timeout")
            .expect("lifecycle task");
        database.close().await;
    }
}
