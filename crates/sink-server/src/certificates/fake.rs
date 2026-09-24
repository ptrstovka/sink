//! Deterministic, in-memory provider and storage adapters for certificate
//! manager tests. They never perform DNS, ACME, filesystem, or network I/O.

use std::{
    collections::BTreeMap,
    sync::{Mutex, MutexGuard},
};

use futures::future::BoxFuture;

use super::{
    AccountRecord, CertificateIdentifiers, CertificateMaterial, CertificateProvider,
    CertificateProviderKind, CertificateRecord, CertificateState, CertificateStorage,
    CertificateTarget, OrderRecord, OrderState, ProviderError, RetryPolicy, SecretBytes,
    StorageError, Timestamp,
};

pub struct FakeCertificateProvider {
    issue_result: Mutex<Result<CertificateMaterial, ProviderError>>,
    issued_identifiers: Mutex<Vec<CertificateIdentifiers>>,
}

impl FakeCertificateProvider {
    pub fn succeeding(material: CertificateMaterial) -> Self {
        Self {
            issue_result: Mutex::new(Ok(material)),
            issued_identifiers: Mutex::new(Vec::new()),
        }
    }

    pub fn failing(error: ProviderError) -> Self {
        Self {
            issue_result: Mutex::new(Err(error)),
            issued_identifiers: Mutex::new(Vec::new()),
        }
    }

    pub fn set_issue_result(&self, result: Result<CertificateMaterial, ProviderError>) {
        *lock(&self.issue_result) = result;
    }

    pub fn issue_count(&self) -> usize {
        lock(&self.issued_identifiers).len()
    }

    pub fn issued_identifiers(&self) -> Vec<CertificateIdentifiers> {
        lock(&self.issued_identifiers).clone()
    }
}

impl CertificateProvider for FakeCertificateProvider {
    fn kind(&self) -> CertificateProviderKind {
        CertificateProviderKind::Cloudflare
    }

    fn account_scope(&self) -> &str {
        "fake-acme-directory"
    }

    fn provision_account<'a>(
        &'a self,
        persisted: Option<&'a AccountRecord>,
    ) -> BoxFuture<'a, Result<AccountRecord, ProviderError>> {
        Box::pin(async move {
            Ok(persisted.cloned().unwrap_or_else(|| AccountRecord {
                provider: CertificateProviderKind::Cloudflare,
                account_scope: "fake-acme-directory".to_owned(),
                external_account_id: "fake-account".to_owned(),
                private_state: SecretBytes::new(b"fake-account-private-state".to_vec()),
            }))
        })
    }

    fn issue<'a>(
        &'a self,
        _account: &'a AccountRecord,
        identifiers: &'a CertificateIdentifiers,
    ) -> BoxFuture<'a, Result<CertificateMaterial, ProviderError>> {
        Box::pin(async move {
            lock(&self.issued_identifiers).push(identifiers.clone());
            lock(&self.issue_result).clone()
        })
    }
}

#[derive(Default)]
struct FakeStorageState {
    accounts: BTreeMap<(CertificateProviderKind, String), AccountRecord>,
    certificates: BTreeMap<CertificateTarget, CertificateRecord>,
    orders: BTreeMap<CertificateTarget, OrderRecord>,
}

#[derive(Default)]
pub struct FakeCertificateStorage {
    state: Mutex<FakeStorageState>,
}

impl FakeCertificateStorage {
    pub fn account(&self, provider: CertificateProviderKind) -> Option<AccountRecord> {
        lock(&self.state)
            .accounts
            .iter()
            .find_map(|((kind, _), account)| (*kind == provider).then(|| account.clone()))
    }

    pub fn certificate(&self, target: &CertificateTarget) -> Option<CertificateRecord> {
        lock(&self.state).certificates.get(target).cloned()
    }

    pub fn order(&self, target: &CertificateTarget) -> Option<OrderRecord> {
        lock(&self.state).orders.get(target).cloned()
    }

    pub fn insert_certificate(&self, certificate: CertificateRecord) {
        lock(&self.state)
            .certificates
            .insert(certificate.target.clone(), certificate);
    }

    pub fn insert_order(&self, order: OrderRecord) {
        lock(&self.state)
            .orders
            .insert(order.request.target.clone(), order);
    }
}

impl CertificateStorage for FakeCertificateStorage {
    fn load_account<'a>(
        &'a self,
        provider: CertificateProviderKind,
        account_scope: &'a str,
    ) -> BoxFuture<'a, Result<Option<AccountRecord>, StorageError>> {
        Box::pin(async move {
            Ok(lock(&self.state)
                .accounts
                .get(&(provider, account_scope.to_owned()))
                .cloned())
        })
    }

    fn store_account(&self, account: AccountRecord) -> BoxFuture<'_, Result<(), StorageError>> {
        Box::pin(async move {
            lock(&self.state)
                .accounts
                .insert((account.provider, account.account_scope.clone()), account);
            Ok(())
        })
    }

    fn load_certificate<'a>(
        &'a self,
        target: &'a CertificateTarget,
    ) -> BoxFuture<'a, Result<Option<CertificateRecord>, StorageError>> {
        Box::pin(async move { Ok(self.certificate(target)) })
    }

    fn store_certificate(
        &self,
        certificate: CertificateRecord,
    ) -> BoxFuture<'_, Result<(), StorageError>> {
        Box::pin(async move {
            self.insert_certificate(certificate);
            Ok(())
        })
    }

    fn load_certificates(&self) -> BoxFuture<'_, Result<Vec<CertificateRecord>, StorageError>> {
        Box::pin(async move { Ok(lock(&self.state).certificates.values().cloned().collect()) })
    }

    fn load_order<'a>(
        &'a self,
        target: &'a CertificateTarget,
    ) -> BoxFuture<'a, Result<Option<OrderRecord>, StorageError>> {
        Box::pin(async move { Ok(self.order(target)) })
    }

    fn store_order(&self, order: OrderRecord) -> BoxFuture<'_, Result<(), StorageError>> {
        Box::pin(async move {
            self.insert_order(order);
            Ok(())
        })
    }

    fn store_lifecycle(
        &self,
        order: OrderRecord,
        certificate: Option<CertificateRecord>,
    ) -> BoxFuture<'_, Result<(), StorageError>> {
        Box::pin(async move {
            let mut state = lock(&self.state);
            if let Some(certificate) = certificate {
                state
                    .certificates
                    .insert(certificate.target.clone(), certificate);
            }
            state.orders.insert(order.request.target.clone(), order);
            Ok(())
        })
    }

    fn reconcile_in_progress<'a>(
        &'a self,
        retry: &'a RetryPolicy,
        now: Timestamp,
    ) -> BoxFuture<'a, Result<u64, StorageError>> {
        Box::pin(async move {
            let mut state = lock(&self.state);
            let targets = state
                .orders
                .iter()
                .filter(|(_, order)| matches!(order.state, OrderState::InProgress))
                .map(|(target, _)| target.clone())
                .collect::<Vec<_>>();
            for target in &targets {
                let (provider, retry_at, cooldown_until) = {
                    let Some(order) = state.orders.get_mut(target) else {
                        continue;
                    };
                    let retry_at = retry.schedule_retry(
                        order,
                        "issuance interrupted by server restart".to_owned(),
                        now,
                    );
                    (order.request.provider, retry_at, order.cooldown_until)
                };
                let needs_retry_state = state
                    .certificates
                    .get(target)
                    .is_none_or(|certificate| certificate.active_material(now).is_none());
                if needs_retry_state {
                    state.certificates.insert(
                        target.clone(),
                        CertificateRecord {
                            target: target.clone(),
                            provider,
                            state: CertificateState::RetryScheduled {
                                retry_at,
                                cooldown_until,
                            },
                            updated_at: now,
                        },
                    );
                }
            }
            Ok(targets.len() as u64)
        })
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}
