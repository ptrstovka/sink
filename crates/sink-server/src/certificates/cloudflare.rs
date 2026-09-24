use std::{fmt, sync::Arc, time::Duration};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use super::{
    DnsChallenge, DnsChallengeProvider, DnsRecord, Hostname, ProviderError, ProviderErrorKind,
    SecretBytes,
};

const CLOUDFLARE_API_BASE: &str = "https://api.cloudflare.com/client/v4";
const DEFAULT_PROPAGATION_DELAY: Duration = Duration::from_secs(15);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpMethod {
    Get,
    Post,
    Delete,
}

/// Secret-safe HTTP boundary used by the Cloudflare adapter. Both the bearer
/// token and request body may contain secrets, so Debug prints neither.
pub struct CloudflareHttpRequest {
    pub method: HttpMethod,
    pub url: String,
    pub bearer_token: SecretBytes,
    pub body: Option<SecretBytes>,
}

impl fmt::Debug for CloudflareHttpRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CloudflareHttpRequest")
            .field("method", &self.method)
            .field("url", &self.url)
            .field("bearer_token", &"[REDACTED]")
            .field("body", &self.body.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

pub struct CloudflareHttpResponse {
    pub status: u16,
    pub body: SecretBytes,
}

impl fmt::Debug for CloudflareHttpResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CloudflareHttpResponse")
            .field("status", &self.status)
            .field("body", &"[REDACTED]")
            .finish()
    }
}

#[async_trait]
pub trait CloudflareHttpClient: Send + Sync {
    async fn execute(
        &self,
        request: CloudflareHttpRequest,
    ) -> Result<CloudflareHttpResponse, ProviderError>;
}

#[derive(Clone)]
pub struct ReqwestCloudflareHttpClient {
    client: reqwest::Client,
}

impl ReqwestCloudflareHttpClient {
    pub fn new() -> Result<Self, ProviderError> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|_| ProviderError::permanent("Cloudflare HTTP client setup failed"))?;
        Ok(Self { client })
    }
}

#[async_trait]
impl CloudflareHttpClient for ReqwestCloudflareHttpClient {
    async fn execute(
        &self,
        request: CloudflareHttpRequest,
    ) -> Result<CloudflareHttpResponse, ProviderError> {
        let token = std::str::from_utf8(request.bearer_token.expose_secret())
            .map_err(|_| ProviderError::permanent("Cloudflare API token is invalid"))?;
        let builder = match request.method {
            HttpMethod::Get => self.client.get(&request.url),
            HttpMethod::Post => self.client.post(&request.url),
            HttpMethod::Delete => self.client.delete(&request.url),
        }
        .bearer_auth(token)
        .header(reqwest::header::CONTENT_TYPE, "application/json");
        let builder = match request.body {
            Some(body) => builder.body(body.expose_secret().to_vec()),
            None => builder,
        };
        let response = builder
            .send()
            .await
            .map_err(|_| ProviderError::retryable("Cloudflare API request failed"))?;
        let status = response.status().as_u16();
        let body = response
            .bytes()
            .await
            .map_err(|_| ProviderError::retryable("Cloudflare API response failed"))?;
        Ok(CloudflareHttpResponse {
            status,
            body: SecretBytes::new(body.to_vec()),
        })
    }
}

pub struct CloudflareDnsProvider<C> {
    http: Arc<C>,
    api_base: String,
    zone_id: String,
    zone_hostname: Hostname,
    api_token: SecretBytes,
    propagation_delay: Duration,
}

impl<C> CloudflareDnsProvider<C>
where
    C: CloudflareHttpClient,
{
    pub fn new(
        http: Arc<C>,
        zone_id: impl Into<String>,
        zone_hostname: Hostname,
        api_token: SecretBytes,
    ) -> Result<Self, ProviderError> {
        Self::with_settings(
            http,
            CLOUDFLARE_API_BASE,
            zone_id,
            zone_hostname,
            api_token,
            DEFAULT_PROPAGATION_DELAY,
        )
    }

    pub fn with_settings(
        http: Arc<C>,
        api_base: impl Into<String>,
        zone_id: impl Into<String>,
        zone_hostname: Hostname,
        api_token: SecretBytes,
        propagation_delay: Duration,
    ) -> Result<Self, ProviderError> {
        let api_base = api_base.into();
        let zone_id = zone_id.into();
        let parsed_api_base = url::Url::parse(&api_base)
            .map_err(|_| ProviderError::permanent("invalid Cloudflare DNS configuration"))?;
        if parsed_api_base.scheme() != "https"
            || parsed_api_base.host_str().is_none()
            || parsed_api_base.cannot_be_a_base()
            || parsed_api_base.username() != ""
            || parsed_api_base.password().is_some()
            || parsed_api_base.query().is_some()
            || parsed_api_base.fragment().is_some()
            || api_base.ends_with('/')
            || zone_id.len() != 32
            || !zone_id.bytes().all(|byte| byte.is_ascii_hexdigit())
            || api_token.expose_secret().is_empty()
        {
            return Err(ProviderError::permanent(
                "invalid Cloudflare DNS configuration",
            ));
        }
        Ok(Self {
            http,
            api_base: parsed_api_base.to_string().trim_end_matches('/').to_owned(),
            zone_id,
            zone_hostname,
            api_token,
            propagation_delay,
        })
    }

    fn record_url(&self, record_id: Option<&str>) -> String {
        match record_id {
            Some(record_id) => format!(
                "{}/zones/{}/dns_records/{record_id}",
                self.api_base, self.zone_id
            ),
            None => format!("{}/zones/{}/dns_records", self.api_base, self.zone_id),
        }
    }

    fn request(
        &self,
        method: HttpMethod,
        url: String,
        body: Option<SecretBytes>,
    ) -> CloudflareHttpRequest {
        CloudflareHttpRequest {
            method,
            url,
            bearer_token: self.api_token.clone(),
            body,
        }
    }

    fn validate_record_name(&self, value: &str) -> Result<(), ProviderError> {
        let identifier = value
            .strip_prefix("_acme-challenge.")
            .ok_or_else(|| ProviderError::permanent("invalid DNS-01 challenge record name"))?;
        let identifier = Hostname::parse(identifier)
            .map_err(|_| ProviderError::permanent("invalid DNS-01 challenge record name"))?;
        if !identifier.is_same_or_below(&self.zone_hostname) {
            return Err(ProviderError::permanent(
                "DNS-01 challenge is outside the configured Cloudflare zone",
            ));
        }
        Ok(())
    }
}

#[async_trait]
impl<C> DnsChallengeProvider for CloudflareDnsProvider<C>
where
    C: CloudflareHttpClient,
{
    async fn create_txt(&self, challenge: &DnsChallenge) -> Result<DnsRecord, ProviderError> {
        self.validate_record_name(challenge.record_name())?;
        let content = std::str::from_utf8(challenge.value().expose_secret())
            .map_err(|_| ProviderError::permanent("invalid DNS-01 challenge value"))?;
        let body = serde_json::to_vec(&CreateDnsRecord {
            record_type: "TXT",
            name: challenge.record_name(),
            content,
            ttl: 60,
        })
        .map_err(|_| ProviderError::permanent("Cloudflare DNS request encoding failed"))?;
        let response = self
            .http
            .execute(self.request(
                HttpMethod::Post,
                self.record_url(None),
                Some(SecretBytes::new(body)),
            ))
            .await?;
        let response: CloudflareEnvelope<DnsRecordResponse> = parse_response(response)?;
        let result = response.result.ok_or_else(|| {
            ProviderError::retryable("Cloudflare DNS record creation returned no record")
        })?;
        if result.record_type != "TXT" || result.name != challenge.record_name() {
            return Err(ProviderError::permanent(
                "Cloudflare DNS record creation returned an unexpected record",
            ));
        }
        validate_record_id(&result.id)?;
        Ok(DnsRecord {
            record_id: result.id,
            record_name: result.name,
        })
    }

    async fn wait_propagated(&self, records: &[DnsRecord]) -> Result<(), ProviderError> {
        tokio::time::sleep(self.propagation_delay).await;
        for record in records {
            validate_record_id(&record.record_id)?;
            let response = self
                .http
                .execute(self.request(
                    HttpMethod::Get,
                    self.record_url(Some(&record.record_id)),
                    None,
                ))
                .await?;
            let response: CloudflareEnvelope<DnsRecordResponse> = parse_response(response)?;
            let result = response.result.ok_or_else(|| {
                ProviderError::retryable("Cloudflare DNS propagation check returned no record")
            })?;
            if result.id != record.record_id
                || result.record_type != "TXT"
                || result.name != record.record_name
            {
                return Err(ProviderError::retryable(
                    "Cloudflare DNS challenge is not yet propagated",
                ));
            }
        }
        Ok(())
    }

    async fn delete_txt(&self, record: &DnsRecord) -> Result<(), ProviderError> {
        validate_record_id(&record.record_id)?;
        let response = self
            .http
            .execute(self.request(
                HttpMethod::Delete,
                self.record_url(Some(&record.record_id)),
                None,
            ))
            .await?;
        if response.status == 404 {
            return Ok(());
        }
        let _: CloudflareEnvelope<serde_json::Value> = parse_response(response)?;
        Ok(())
    }
}

#[derive(Serialize)]
struct CreateDnsRecord<'a> {
    #[serde(rename = "type")]
    record_type: &'static str,
    name: &'a str,
    content: &'a str,
    ttl: u32,
}

#[derive(Deserialize)]
struct CloudflareEnvelope<T> {
    success: bool,
    result: Option<T>,
}

#[derive(Deserialize)]
struct DnsRecordResponse {
    id: String,
    name: String,
    #[serde(rename = "type")]
    record_type: String,
}

fn parse_response<T>(
    response: CloudflareHttpResponse,
) -> Result<CloudflareEnvelope<T>, ProviderError>
where
    T: for<'de> Deserialize<'de>,
{
    let kind = if response.status == 429 || response.status >= 500 {
        ProviderErrorKind::Retryable
    } else {
        ProviderErrorKind::Permanent
    };
    if !(200..300).contains(&response.status) {
        return Err(ProviderError {
            kind,
            message: "Cloudflare API rejected the DNS request".to_owned(),
        });
    }
    let envelope: CloudflareEnvelope<T> = serde_json::from_slice(response.body.expose_secret())
        .map_err(|_| ProviderError::retryable("Cloudflare API returned malformed JSON"))?;
    if !envelope.success {
        return Err(ProviderError::permanent(
            "Cloudflare API rejected the DNS request",
        ));
    }
    Ok(envelope)
}

fn validate_record_id(value: &str) -> Result<(), ProviderError> {
    if value.len() != 32 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ProviderError::permanent(
            "Cloudflare API returned an invalid DNS record identifier",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{collections::VecDeque, sync::Mutex};

    use super::*;

    const ZONE_ID: &str = "0123456789abcdef0123456789abcdef";
    const RECORD_ID: &str = "abcdef0123456789abcdef0123456789";
    type CapturedRequest = (HttpMethod, String, Option<Vec<u8>>, Vec<u8>);

    #[derive(Default)]
    struct FakeHttpClient {
        requests: Mutex<Vec<CloudflareHttpRequest>>,
        responses: Mutex<VecDeque<CloudflareHttpResponse>>,
    }

    impl FakeHttpClient {
        fn push(&self, status: u16, body: &str) {
            self.responses
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push_back(CloudflareHttpResponse {
                    status,
                    body: SecretBytes::new(body.as_bytes().to_vec()),
                });
        }

        fn requests(&self) -> Vec<CapturedRequest> {
            self.requests
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .iter()
                .map(|request| {
                    (
                        request.method,
                        request.url.clone(),
                        request
                            .body
                            .as_ref()
                            .map(|body| body.expose_secret().to_vec()),
                        request.bearer_token.expose_secret().to_vec(),
                    )
                })
                .collect()
        }
    }

    #[async_trait]
    impl CloudflareHttpClient for FakeHttpClient {
        async fn execute(
            &self,
            request: CloudflareHttpRequest,
        ) -> Result<CloudflareHttpResponse, ProviderError> {
            self.requests
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(request);
            self.responses
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .pop_front()
                .ok_or_else(|| ProviderError::permanent("fake HTTP response missing"))
        }
    }

    fn provider(http: Arc<FakeHttpClient>) -> CloudflareDnsProvider<FakeHttpClient> {
        CloudflareDnsProvider::with_settings(
            http,
            "https://api.cloudflare.test/client/v4",
            ZONE_ID,
            Hostname::parse("example.test").expect("valid zone"),
            SecretBytes::new(b"cloudflare-token-never-print".to_vec()),
            Duration::ZERO,
        )
        .expect("valid provider")
    }

    #[tokio::test]
    async fn create_wait_and_delete_use_expected_requests_without_network() {
        let http = Arc::new(FakeHttpClient::default());
        http.push(
            200,
            &format!(
                r#"{{"success":true,"result":{{"id":"{RECORD_ID}","name":"_acme-challenge.cloud.example.test","type":"TXT"}}}}"#
            ),
        );
        http.push(
            200,
            &format!(
                r#"{{"success":true,"result":{{"id":"{RECORD_ID}","name":"_acme-challenge.cloud.example.test","type":"TXT"}}}}"#
            ),
        );
        http.push(200, r#"{"success":true,"result":{"id":"deleted"}}"#);
        let provider = provider(http.clone());
        let challenge = DnsChallenge::new(
            "_acme-challenge.cloud.example.test",
            SecretBytes::new(b"dns-challenge-never-print".to_vec()),
        );

        let record = provider
            .create_txt(&challenge)
            .await
            .expect("create record");
        provider
            .wait_propagated(std::slice::from_ref(&record))
            .await
            .expect("propagation check");
        provider.delete_txt(&record).await.expect("delete record");

        let requests = http.requests();
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[0].0, HttpMethod::Post);
        assert_eq!(requests[1].0, HttpMethod::Get);
        assert_eq!(requests[2].0, HttpMethod::Delete);
        let body =
            String::from_utf8(requests[0].2.clone().expect("request body")).expect("UTF-8 body");
        assert!(body.contains("dns-challenge-never-print"));
        assert_eq!(requests[0].3, b"cloudflare-token-never-print");

        let debug = format!(
            "{:?}",
            http.requests
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())[0]
        );
        assert!(!debug.contains("dns-challenge-never-print"));
        assert!(!debug.contains("cloudflare-token-never-print"));
    }

    #[tokio::test]
    async fn rejects_out_of_zone_challenges_before_http() {
        let http = Arc::new(FakeHttpClient::default());
        let provider = provider(http.clone());
        let error = provider
            .create_txt(&DnsChallenge::new(
                "_acme-challenge.attacker.test",
                SecretBytes::new(b"secret".to_vec()),
            ))
            .await
            .expect_err("out of zone rejected");

        assert_eq!(
            error.message,
            "DNS-01 challenge is outside the configured Cloudflare zone"
        );
        assert!(http.requests().is_empty());
    }

    #[tokio::test]
    async fn api_errors_are_classified_without_echoing_response_secrets() {
        let http = Arc::new(FakeHttpClient::default());
        http.push(
            429,
            r#"{"success":false,"errors":[{"message":"dns-challenge-never-print"}]}"#,
        );
        let provider = provider(http);
        let error = provider
            .create_txt(&DnsChallenge::new(
                "_acme-challenge.example.test",
                SecretBytes::new(b"dns-challenge-never-print".to_vec()),
            ))
            .await
            .expect_err("rate limit returned");

        assert_eq!(error.kind, ProviderErrorKind::Retryable);
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains("dns-challenge-never-print"));
    }
}
