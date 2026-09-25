use std::{fmt, mem, sync::Arc};

use async_trait::async_trait;
use futures::future::BoxFuture;

use super::{
    AccountRecord, CertificateIdentifiers, CertificateMaterial, CertificateProvider,
    CertificateProviderKind, ProviderError, SecretBytes,
};

/// One DNS-01 response. The TXT value is secret-bearing transient material and
/// is redacted from Debug output.
#[derive(Clone, Eq, PartialEq)]
pub struct DnsChallenge {
    record_name: String,
    value: SecretBytes,
}

impl DnsChallenge {
    pub fn new(record_name: impl Into<String>, value: SecretBytes) -> Self {
        Self {
            record_name: record_name.into(),
            value,
        }
    }

    pub fn record_name(&self) -> &str {
        &self.record_name
    }

    pub fn value(&self) -> &SecretBytes {
        &self.value
    }
}

impl fmt::Debug for DnsChallenge {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DnsChallenge")
            .field("record_name", &self.record_name)
            .field("value", &"[REDACTED]")
            .finish()
    }
}

/// Opaque handle for a TXT record created by the DNS provider. It deliberately
/// contains no challenge value so cleanup and errors cannot expose one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsRecord {
    pub record_id: String,
    pub record_name: String,
}

#[async_trait]
pub trait DnsChallengeProvider: Send + Sync {
    async fn create_txt(&self, challenge: &DnsChallenge) -> Result<DnsRecord, ProviderError>;

    async fn wait_propagated(&self, records: &[DnsRecord]) -> Result<(), ProviderError>;

    async fn delete_txt(&self, record: &DnsRecord) -> Result<(), ProviderError>;
}

#[async_trait]
pub trait AcmeClient: Send + Sync {
    fn account_scope(&self) -> &str;

    async fn provision_account(
        &self,
        persisted: Option<&AccountRecord>,
    ) -> Result<AccountRecord, ProviderError>;

    async fn start_order(
        &self,
        account: &AccountRecord,
        identifiers: &CertificateIdentifiers,
    ) -> Result<Box<dyn AcmeOrder>, ProviderError>;
}

#[async_trait]
pub trait AcmeOrder: Send {
    async fn dns_challenges(&mut self) -> Result<Vec<DnsChallenge>, ProviderError>;

    /// Notify the CA that all DNS records are ready and wait for every
    /// authorization plus the order itself to become ready.
    async fn authorize(&mut self) -> Result<(), ProviderError>;

    /// Finalize the order, wait for certificate issuance, and convert the
    /// resulting chain/key into durable material.
    async fn finalize(&mut self) -> Result<CertificateMaterial, ProviderError>;
}

/// Domain-generic ACME DNS-01 orchestration. Cloudflare is selected only by
/// the DNS implementation and provider kind; no production domain is embedded
/// in this adapter.
pub struct CloudflareAcmeProvider<A, D> {
    acme: Arc<A>,
    dns: Arc<D>,
}

impl<A, D> CloudflareAcmeProvider<A, D> {
    pub fn new(acme: Arc<A>, dns: Arc<D>) -> Self {
        Self { acme, dns }
    }
}

impl<A, D> CertificateProvider for CloudflareAcmeProvider<A, D>
where
    A: AcmeClient + 'static,
    D: DnsChallengeProvider + 'static,
{
    fn kind(&self) -> CertificateProviderKind {
        CertificateProviderKind::Cloudflare
    }

    fn account_scope(&self) -> &str {
        self.acme.account_scope()
    }

    fn provision_account<'a>(
        &'a self,
        persisted: Option<&'a AccountRecord>,
    ) -> BoxFuture<'a, Result<AccountRecord, ProviderError>> {
        Box::pin(async move { self.acme.provision_account(persisted).await })
    }

    fn issue<'a>(
        &'a self,
        account: &'a AccountRecord,
        identifiers: &'a CertificateIdentifiers,
    ) -> BoxFuture<'a, Result<CertificateMaterial, ProviderError>> {
        Box::pin(async move {
            let mut order = self.acme.start_order(account, identifiers).await?;
            let challenges = order.dns_challenges().await?;
            let mut cleanup = DnsCleanupGuard::new(Arc::clone(&self.dns), challenges.len());

            for challenge in &challenges {
                match self.dns.create_txt(challenge).await {
                    Ok(record) => cleanup.records.push(record),
                    Err(error) => {
                        let records = cleanup.disarm();
                        cleanup_records(self.dns.as_ref(), &records).await;
                        return Err(error);
                    }
                }
            }

            let result = async {
                if !cleanup.records.is_empty() {
                    self.dns.wait_propagated(&cleanup.records).await?;
                }
                order.authorize().await?;
                order.finalize().await
            }
            .await;
            let records = cleanup.disarm();
            let cleanup_failed = cleanup_records(self.dns.as_ref(), &records).await;

            match (result, cleanup_failed) {
                (Ok(_), true) => Err(ProviderError::retryable(
                    "Cloudflare DNS challenge cleanup failed",
                )),
                (result, _) => result,
            }
        })
    }
}

struct DnsCleanupGuard<D>
where
    D: DnsChallengeProvider + 'static,
{
    provider: Arc<D>,
    records: Vec<DnsRecord>,
}

impl<D> DnsCleanupGuard<D>
where
    D: DnsChallengeProvider + 'static,
{
    fn new(provider: Arc<D>, capacity: usize) -> Self {
        Self {
            provider,
            records: Vec::with_capacity(capacity),
        }
    }

    fn disarm(mut self) -> Vec<DnsRecord> {
        mem::take(&mut self.records)
    }
}

impl<D> Drop for DnsCleanupGuard<D>
where
    D: DnsChallengeProvider + 'static,
{
    fn drop(&mut self) {
        if self.records.is_empty() {
            return;
        }
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let provider = Arc::clone(&self.provider);
        let records = mem::take(&mut self.records);
        drop(runtime.spawn(async move {
            cleanup_records(provider.as_ref(), &records).await;
        }));
    }
}

async fn cleanup_records(provider: &impl DnsChallengeProvider, records: &[DnsRecord]) -> bool {
    let mut failed = false;
    for record in records.iter().rev() {
        if provider.delete_txt(record).await.is_err() {
            failed = true;
        }
    }
    failed
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{Mutex, MutexGuard},
        time::Duration,
    };

    use super::*;
    use crate::certificates::{Hostname, Timestamp};

    fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
        mutex
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn material() -> CertificateMaterial {
        CertificateMaterial {
            certificate_chain_pem: b"certificate chain".to_vec(),
            private_key_pem: SecretBytes::new(b"private key".to_vec()),
            not_before: Timestamp::from_unix_seconds(900),
            not_after: Timestamp::from_unix_seconds(10_000),
        }
    }

    fn identifiers() -> CertificateIdentifiers {
        super::super::CertificateTarget::namespace(
            Hostname::parse("cloud.example.test").expect("valid hostname"),
        )
        .identifiers()
    }

    struct FakeAcme {
        events: Arc<Mutex<Vec<String>>>,
        fail_authorization: bool,
        saw_persisted_account: Mutex<bool>,
        issued_identifiers: Mutex<Vec<(String, String)>>,
    }

    impl FakeAcme {
        fn new(events: Arc<Mutex<Vec<String>>>, fail_authorization: bool) -> Self {
            Self {
                events,
                fail_authorization,
                saw_persisted_account: Mutex::new(false),
                issued_identifiers: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl AcmeClient for FakeAcme {
        fn account_scope(&self) -> &str {
            "https://acme.example/directory"
        }

        async fn provision_account(
            &self,
            persisted: Option<&AccountRecord>,
        ) -> Result<AccountRecord, ProviderError> {
            *lock(&self.saw_persisted_account) = persisted.is_some();
            Ok(persisted.cloned().unwrap_or_else(|| AccountRecord {
                provider: CertificateProviderKind::Cloudflare,
                account_scope: self.account_scope().to_owned(),
                external_account_id: "account-1".to_owned(),
                private_state: SecretBytes::new(b"account state".to_vec()),
            }))
        }

        async fn start_order(
            &self,
            _account: &AccountRecord,
            identifiers: &CertificateIdentifiers,
        ) -> Result<Box<dyn AcmeOrder>, ProviderError> {
            lock(&self.issued_identifiers).push((
                identifiers.apex().to_string(),
                identifiers.wildcard().to_owned(),
            ));
            Ok(Box::new(FakeOrder {
                events: self.events.clone(),
                fail_authorization: self.fail_authorization,
            }))
        }
    }

    struct FakeOrder {
        events: Arc<Mutex<Vec<String>>>,
        fail_authorization: bool,
    }

    #[async_trait]
    impl AcmeOrder for FakeOrder {
        async fn dns_challenges(&mut self) -> Result<Vec<DnsChallenge>, ProviderError> {
            lock(&self.events).push("acme:challenges".to_owned());
            Ok(vec![
                DnsChallenge::new(
                    "_acme-challenge.cloud.example.test",
                    SecretBytes::new(b"apex challenge".to_vec()),
                ),
                DnsChallenge::new(
                    "_acme-challenge.cloud.example.test",
                    SecretBytes::new(b"wildcard challenge".to_vec()),
                ),
            ])
        }

        async fn authorize(&mut self) -> Result<(), ProviderError> {
            lock(&self.events).push("acme:authorize".to_owned());
            if self.fail_authorization {
                Err(ProviderError::retryable("ACME authorization failed"))
            } else {
                Ok(())
            }
        }

        async fn finalize(&mut self) -> Result<CertificateMaterial, ProviderError> {
            lock(&self.events).push("acme:finalize".to_owned());
            Ok(material())
        }
    }

    struct FakeDns {
        events: Arc<Mutex<Vec<String>>>,
    }

    #[async_trait]
    impl DnsChallengeProvider for FakeDns {
        async fn create_txt(&self, challenge: &DnsChallenge) -> Result<DnsRecord, ProviderError> {
            let index = lock(&self.events)
                .iter()
                .filter(|event| event.starts_with("dns:create"))
                .count();
            lock(&self.events).push(format!("dns:create:{index}"));
            Ok(DnsRecord {
                record_id: format!("record-{index}"),
                record_name: challenge.record_name().to_owned(),
            })
        }

        async fn wait_propagated(&self, records: &[DnsRecord]) -> Result<(), ProviderError> {
            lock(&self.events).push(format!("dns:propagated:{}", records.len()));
            Ok(())
        }

        async fn delete_txt(&self, record: &DnsRecord) -> Result<(), ProviderError> {
            lock(&self.events).push(format!("dns:delete:{}", record.record_id));
            Ok(())
        }
    }

    struct BlockingDns {
        events: Arc<Mutex<Vec<String>>>,
        propagation_entered: Arc<tokio::sync::Notify>,
        release_propagation: Arc<tokio::sync::Notify>,
    }

    #[async_trait]
    impl DnsChallengeProvider for BlockingDns {
        async fn create_txt(&self, challenge: &DnsChallenge) -> Result<DnsRecord, ProviderError> {
            let index = lock(&self.events)
                .iter()
                .filter(|event| event.starts_with("dns:create"))
                .count();
            lock(&self.events).push(format!("dns:create:{index}"));
            Ok(DnsRecord {
                record_id: format!("record-{index}"),
                record_name: challenge.record_name().to_owned(),
            })
        }

        async fn wait_propagated(&self, records: &[DnsRecord]) -> Result<(), ProviderError> {
            lock(&self.events).push(format!("dns:propagated:{}", records.len()));
            self.propagation_entered.notify_waiters();
            self.release_propagation.notified().await;
            Ok(())
        }

        async fn delete_txt(&self, record: &DnsRecord) -> Result<(), ProviderError> {
            lock(&self.events).push(format!("dns:delete:{}", record.record_id));
            Ok(())
        }
    }

    fn account() -> AccountRecord {
        AccountRecord {
            provider: CertificateProviderKind::Cloudflare,
            account_scope: "https://acme.example/directory".to_owned(),
            external_account_id: "account-1".to_owned(),
            private_state: SecretBytes::new(b"account state".to_vec()),
        }
    }

    #[tokio::test]
    async fn apex_and_wildcard_flow_waits_then_authorizes_and_always_cleans_up() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let acme = Arc::new(FakeAcme::new(events.clone(), false));
        let dns = Arc::new(FakeDns {
            events: events.clone(),
        });
        let provider = CloudflareAcmeProvider::new(acme.clone(), dns);

        let issued = provider
            .issue(&account(), &identifiers())
            .await
            .expect("issue certificate");

        assert_eq!(issued, material());
        assert_eq!(
            lock(&acme.issued_identifiers).as_slice(),
            &[(
                "cloud.example.test".to_owned(),
                "*.cloud.example.test".to_owned()
            )]
        );
        assert_eq!(
            lock(&events).as_slice(),
            [
                "acme:challenges",
                "dns:create:0",
                "dns:create:1",
                "dns:propagated:2",
                "acme:authorize",
                "acme:finalize",
                "dns:delete:record-1",
                "dns:delete:record-0",
            ]
        );
    }

    #[tokio::test]
    async fn authorization_failure_still_cleans_up_every_record() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let provider = CloudflareAcmeProvider::new(
            Arc::new(FakeAcme::new(events.clone(), true)),
            Arc::new(FakeDns {
                events: events.clone(),
            }),
        );

        let error = provider
            .issue(&account(), &identifiers())
            .await
            .expect_err("authorization fails");

        assert_eq!(error.message, "ACME authorization failed");
        let events = lock(&events);
        assert!(events.contains(&"dns:delete:record-1".to_owned()));
        assert!(events.contains(&"dns:delete:record-0".to_owned()));
        assert!(!events.contains(&"acme:finalize".to_owned()));
    }

    #[tokio::test]
    async fn cancellation_still_cleans_up_every_created_record() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let propagation_entered = Arc::new(tokio::sync::Notify::new());
        let entered = Arc::clone(&propagation_entered).notified_owned();
        let provider = Arc::new(CloudflareAcmeProvider::new(
            Arc::new(FakeAcme::new(events.clone(), false)),
            Arc::new(BlockingDns {
                events: events.clone(),
                propagation_entered,
                release_propagation: Arc::new(tokio::sync::Notify::new()),
            }),
        ));
        let issue = tokio::spawn(async move { provider.issue(&account(), &identifiers()).await });

        entered.await;
        issue.abort();
        let _ = issue.await;
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let cleaned = {
                    let events = lock(&events);
                    events.contains(&"dns:delete:record-1".to_owned())
                        && events.contains(&"dns:delete:record-0".to_owned())
                };
                if cleaned {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cancellation cleanup completes");
    }

    #[tokio::test]
    async fn persisted_account_is_reused_and_challenge_debug_is_redacted() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let acme = Arc::new(FakeAcme::new(events, false));
        let provider = CloudflareAcmeProvider::new(
            acme.clone(),
            Arc::new(FakeDns {
                events: Arc::new(Mutex::new(Vec::new())),
            }),
        );

        assert_eq!(
            provider
                .provision_account(Some(&account()))
                .await
                .expect("reuse account"),
            account()
        );
        assert!(*lock(&acme.saw_persisted_account));

        let challenge = DnsChallenge::new(
            "_acme-challenge.example.test",
            SecretBytes::new(b"never-print-challenge".to_vec()),
        );
        let rendered = format!("{challenge:?}");
        assert!(!rendered.contains("never-print-challenge"));
        assert!(rendered.contains("[REDACTED]"));
    }
}
