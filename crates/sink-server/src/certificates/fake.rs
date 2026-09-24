//! Deterministic, in-memory provider and storage adapters for certificate
//! manager tests. They never perform DNS, ACME, filesystem, or network I/O.

use std::{
    collections::BTreeMap,
    sync::{Mutex, MutexGuard},
};

use futures::future::BoxFuture;

use super::{
    AccountRecord, CertificateIdentifiers, CertificateMaterial, CertificateProvider,
    CertificateProviderKind, CertificateRecord, CertificateStorage, CertificateTarget, OrderRecord,
    ProviderError, SecretBytes, StorageError,
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

    fn provision_account<'a>(
        &'a self,
        persisted: Option<&'a AccountRecord>,
    ) -> BoxFuture<'a, Result<AccountRecord, ProviderError>> {
        Box::pin(async move {
            Ok(persisted.cloned().unwrap_or_else(|| AccountRecord {
                provider: CertificateProviderKind::Cloudflare,
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
pub struct FakeCertificateStorage {
    accounts: Mutex<BTreeMap<CertificateProviderKind, AccountRecord>>,
    certificates: Mutex<BTreeMap<CertificateTarget, CertificateRecord>>,
    orders: Mutex<BTreeMap<CertificateTarget, OrderRecord>>,
}

impl FakeCertificateStorage {
    pub fn account(&self, provider: CertificateProviderKind) -> Option<AccountRecord> {
        lock(&self.accounts).get(&provider).cloned()
    }

    pub fn certificate(&self, target: &CertificateTarget) -> Option<CertificateRecord> {
        lock(&self.certificates).get(target).cloned()
    }

    pub fn order(&self, target: &CertificateTarget) -> Option<OrderRecord> {
        lock(&self.orders).get(target).cloned()
    }

    pub fn insert_certificate(&self, certificate: CertificateRecord) {
        lock(&self.certificates).insert(certificate.target.clone(), certificate);
    }

    pub fn insert_order(&self, order: OrderRecord) {
        lock(&self.orders).insert(order.request.target.clone(), order);
    }
}

impl CertificateStorage for FakeCertificateStorage {
    fn load_account(
        &self,
        provider: CertificateProviderKind,
    ) -> BoxFuture<'_, Result<Option<AccountRecord>, StorageError>> {
        Box::pin(async move { Ok(self.account(provider)) })
    }

    fn store_account(&self, account: AccountRecord) -> BoxFuture<'_, Result<(), StorageError>> {
        Box::pin(async move {
            lock(&self.accounts).insert(account.provider, account);
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
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}
