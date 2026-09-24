use futures::future::BoxFuture;
use thiserror::Error;

use super::{
    AccountRecord, CertificateProviderKind, CertificateRecord, CertificateTarget, OrderRecord,
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
#[error("certificate storage error: {message}")]
pub struct StorageError {
    pub message: String,
}

impl StorageError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// Persistence boundary for provider accounts, certificate/key material, and
/// order scheduling state.
///
/// Implementations must make each `store_*` operation atomic. A later database
/// adapter can use the surrounding control-plane transaction for ownership and
/// quota checks without coupling this module to `db.rs`.
pub trait CertificateStorage: Send + Sync {
    fn load_account(
        &self,
        provider: CertificateProviderKind,
    ) -> BoxFuture<'_, Result<Option<AccountRecord>, StorageError>>;

    fn store_account(&self, account: AccountRecord) -> BoxFuture<'_, Result<(), StorageError>>;

    fn load_certificate<'a>(
        &'a self,
        target: &'a CertificateTarget,
    ) -> BoxFuture<'a, Result<Option<CertificateRecord>, StorageError>>;

    fn store_certificate(
        &self,
        certificate: CertificateRecord,
    ) -> BoxFuture<'_, Result<(), StorageError>>;

    fn load_order<'a>(
        &'a self,
        target: &'a CertificateTarget,
    ) -> BoxFuture<'a, Result<Option<OrderRecord>, StorageError>>;

    fn store_order(&self, order: OrderRecord) -> BoxFuture<'_, Result<(), StorageError>>;
}
