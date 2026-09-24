use std::{io::Cursor, time::Duration};

use async_trait::async_trait;
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, NewAccount,
    NewOrder, Order, OrderStatus, RetryPolicy as AcmeRetryPolicy,
};
use x509_parser::parse_x509_certificate;

use super::{
    AccountRecord, AcmeClient, AcmeOrder, CertificateIdentifiers, CertificateMaterial,
    CertificateProviderKind, DnsChallenge, ProviderError, SecretBytes, Timestamp,
};

const DEFAULT_AUTHORIZATION_TIMEOUT: Duration = Duration::from_secs(120);
const DEFAULT_CERTIFICATE_TIMEOUT: Duration = Duration::from_secs(120);

/// Production ACME protocol adapter backed by `instant-acme`. The adapter
/// deliberately turns dependency errors into static operational messages so
/// server error paths cannot reflect account keys or challenge material.
pub struct InstantAcmeClient {
    directory_url: String,
    contacts: Vec<String>,
    authorization_retry: AcmeRetryPolicy,
    certificate_retry: AcmeRetryPolicy,
}

impl InstantAcmeClient {
    pub fn new(
        directory_url: impl Into<String>,
        contacts: Vec<String>,
    ) -> Result<Self, ProviderError> {
        let directory_url = directory_url.into();
        let parsed_directory = url::Url::parse(&directory_url)
            .map_err(|_| ProviderError::permanent("invalid ACME client configuration"))?;
        if parsed_directory.scheme() != "https"
            || parsed_directory.host_str().is_none()
            || parsed_directory.cannot_be_a_base()
            || parsed_directory.username() != ""
            || parsed_directory.password().is_some()
            || directory_url.len() > 2048
            || contacts.is_empty()
            || contacts.iter().any(|contact| {
                !contact.starts_with("mailto:")
                    || !contact.contains('@')
                    || contact.chars().any(char::is_whitespace)
            })
        {
            return Err(ProviderError::permanent(
                "invalid ACME client configuration",
            ));
        }
        Ok(Self {
            directory_url: parsed_directory.to_string(),
            contacts,
            authorization_retry: AcmeRetryPolicy::new()
                .initial_delay(Duration::from_millis(500))
                .timeout(DEFAULT_AUTHORIZATION_TIMEOUT),
            certificate_retry: AcmeRetryPolicy::new()
                .initial_delay(Duration::from_millis(500))
                .timeout(DEFAULT_CERTIFICATE_TIMEOUT),
        })
    }

    async fn restore_account(&self, record: &AccountRecord) -> Result<Account, ProviderError> {
        if record.provider != CertificateProviderKind::Cloudflare
            || record.account_scope != self.directory_url
        {
            return Err(ProviderError::permanent(
                "stored ACME account belongs to a different account realm",
            ));
        }
        let credentials: AccountCredentials =
            serde_json::from_slice(record.private_state.expose_secret())
                .map_err(|_| ProviderError::permanent("stored ACME account state is malformed"))?;
        let builder = Account::builder()
            .map_err(|_| ProviderError::retryable("ACME HTTP client initialization failed"))?;
        let account = builder
            .from_credentials(credentials)
            .await
            .map_err(|_| ProviderError::retryable("stored ACME account could not be restored"))?;
        if account.id() != record.external_account_id {
            return Err(ProviderError::permanent(
                "stored ACME account identity is malformed",
            ));
        }
        Ok(account)
    }
}

#[async_trait]
impl AcmeClient for InstantAcmeClient {
    fn account_scope(&self) -> &str {
        &self.directory_url
    }

    async fn provision_account(
        &self,
        persisted: Option<&AccountRecord>,
    ) -> Result<AccountRecord, ProviderError> {
        if let Some(persisted) = persisted {
            // Parse now so malformed durable state fails before an order starts.
            let _: AccountCredentials =
                serde_json::from_slice(persisted.private_state.expose_secret()).map_err(|_| {
                    ProviderError::permanent("stored ACME account state is malformed")
                })?;
            if persisted.provider != CertificateProviderKind::Cloudflare
                || persisted.account_scope != self.directory_url
            {
                return Err(ProviderError::permanent(
                    "stored ACME account belongs to a different account realm",
                ));
            }
            return Ok(persisted.clone());
        }

        let contacts = self.contacts.iter().map(String::as_str).collect::<Vec<_>>();
        let builder = Account::builder()
            .map_err(|_| ProviderError::retryable("ACME HTTP client initialization failed"))?;
        let (account, credentials) = builder
            .create(
                &NewAccount {
                    contact: &contacts,
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                },
                self.directory_url.clone(),
                None,
            )
            .await
            .map_err(|_| ProviderError::retryable("ACME account provisioning failed"))?;
        let private_state = serde_json::to_vec(&credentials)
            .map_err(|_| ProviderError::permanent("ACME account serialization failed"))?;
        Ok(AccountRecord {
            provider: CertificateProviderKind::Cloudflare,
            account_scope: self.directory_url.clone(),
            external_account_id: account.id().to_owned(),
            private_state: SecretBytes::new(private_state),
        })
    }

    async fn start_order(
        &self,
        account: &AccountRecord,
        identifiers: &CertificateIdentifiers,
    ) -> Result<Box<dyn AcmeOrder>, ProviderError> {
        let account = self.restore_account(account).await?;
        let identifiers = [
            Identifier::Dns(identifiers.apex().to_string()),
            Identifier::Dns(identifiers.wildcard().to_owned()),
        ];
        let order = account
            .new_order(&NewOrder::new(&identifiers))
            .await
            .map_err(|_| ProviderError::retryable("ACME order creation failed"))?;
        Ok(Box::new(InstantOrder {
            order,
            authorization_retry: self.authorization_retry,
            certificate_retry: self.certificate_retry,
        }))
    }
}

struct InstantOrder {
    order: Order,
    authorization_retry: AcmeRetryPolicy,
    certificate_retry: AcmeRetryPolicy,
}

#[async_trait]
impl AcmeOrder for InstantOrder {
    async fn dns_challenges(&mut self) -> Result<Vec<DnsChallenge>, ProviderError> {
        let mut result = Vec::new();
        let mut authorizations = self.order.authorizations();
        while let Some(authorization) = authorizations.next().await {
            let mut authorization = authorization
                .map_err(|_| ProviderError::retryable("ACME authorization retrieval failed"))?;
            match authorization.status {
                AuthorizationStatus::Valid => continue,
                AuthorizationStatus::Pending => {}
                _ => {
                    return Err(ProviderError::permanent(
                        "ACME authorization is not pending",
                    ));
                }
            }
            let challenge = authorization
                .challenge(ChallengeType::Dns01)
                .ok_or_else(|| ProviderError::permanent("ACME DNS-01 challenge is unavailable"))?;
            let identifier = challenge.identifier().to_string();
            let identifier = identifier.strip_prefix("*.").unwrap_or(&identifier);
            let hostname = super::Hostname::parse(identifier)
                .map_err(|_| ProviderError::permanent("ACME returned an invalid DNS identifier"))?;
            result.push(DnsChallenge::new(
                format!("_acme-challenge.{hostname}"),
                SecretBytes::new(challenge.key_authorization().dns_value().into_bytes()),
            ));
        }
        Ok(result)
    }

    async fn authorize(&mut self) -> Result<(), ProviderError> {
        let mut authorizations = self.order.authorizations();
        while let Some(authorization) = authorizations.next().await {
            let mut authorization = authorization
                .map_err(|_| ProviderError::retryable("ACME authorization retrieval failed"))?;
            match authorization.status {
                AuthorizationStatus::Valid => continue,
                AuthorizationStatus::Pending => {}
                _ => {
                    return Err(ProviderError::permanent(
                        "ACME authorization is not pending",
                    ));
                }
            }
            let mut challenge = authorization
                .challenge(ChallengeType::Dns01)
                .ok_or_else(|| ProviderError::permanent("ACME DNS-01 challenge is unavailable"))?;
            challenge
                .set_ready()
                .await
                .map_err(|_| ProviderError::retryable("ACME challenge readiness failed"))?;
        }
        let status = self
            .order
            .poll_ready(&self.authorization_retry)
            .await
            .map_err(|_| ProviderError::retryable("ACME authorization polling failed"))?;
        if status != OrderStatus::Ready {
            return Err(ProviderError::permanent("ACME authorization was rejected"));
        }
        Ok(())
    }

    async fn finalize(&mut self) -> Result<CertificateMaterial, ProviderError> {
        let private_key_pem = self
            .order
            .finalize()
            .await
            .map_err(|_| ProviderError::retryable("ACME order finalization failed"))?;
        let certificate_chain_pem = self
            .order
            .poll_certificate(&self.certificate_retry)
            .await
            .map_err(|_| ProviderError::retryable("ACME certificate retrieval failed"))?;
        material_from_pem(certificate_chain_pem, private_key_pem)
    }
}

fn material_from_pem(
    certificate_chain_pem: String,
    private_key_pem: String,
) -> Result<CertificateMaterial, ProviderError> {
    let mut cursor = Cursor::new(certificate_chain_pem.as_bytes());
    let first = rustls_pemfile::certs(&mut cursor)
        .next()
        .transpose()
        .map_err(|_| ProviderError::permanent("ACME certificate chain is malformed"))?
        .ok_or_else(|| ProviderError::permanent("ACME certificate chain is empty"))?;
    let (_, certificate) = parse_x509_certificate(first.as_ref())
        .map_err(|_| ProviderError::permanent("ACME leaf certificate is malformed"))?;
    let not_before = u64::try_from(certificate.validity().not_before.timestamp())
        .map(Timestamp::from_unix_seconds)
        .map_err(|_| ProviderError::permanent("ACME certificate validity is unsupported"))?;
    let not_after = u64::try_from(certificate.validity().not_after.timestamp())
        .map(Timestamp::from_unix_seconds)
        .map_err(|_| ProviderError::permanent("ACME certificate validity is unsupported"))?;
    if not_before >= not_after || private_key_pem.is_empty() {
        return Err(ProviderError::permanent(
            "ACME certificate material is invalid",
        ));
    }
    Ok(CertificateMaterial {
        certificate_chain_pem: certificate_chain_pem.into_bytes(),
        private_key_pem: SecretBytes::new(private_key_pem.into_bytes()),
        not_before,
        not_after,
    })
}

#[cfg(test)]
mod tests {
    use rcgen::{CertifiedKey, generate_simple_self_signed};

    use super::*;

    #[test]
    fn converts_pem_material_and_keeps_the_private_key_redacted() {
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["example.test".to_owned()])
                .expect("generate certificate");
        let private_key = signing_key.serialize_pem();
        let material = material_from_pem(cert.pem(), private_key.clone())
            .expect("convert certificate material");

        assert!(material.not_before < material.not_after);
        assert_eq!(
            material.private_key_pem.expose_secret(),
            private_key.as_bytes()
        );
        assert!(!format!("{material:?}").contains(&private_key));
    }

    #[test]
    fn rejects_unsafe_acme_configuration_without_reflecting_it() {
        let error = match InstantAcmeClient::new(
            "http://acme.invalid/directory?secret=never-print",
            vec!["admin@example.test".to_owned()],
        ) {
            Ok(_) => panic!("unsafe configuration accepted"),
            Err(error) => error,
        };
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains("never-print"));
        assert_eq!(error.message, "invalid ACME client configuration");
    }
}
