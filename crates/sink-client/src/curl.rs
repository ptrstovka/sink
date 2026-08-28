//! Deterministic, side-effect-free cURL generation for retained requests.

use std::{fmt, str};

use http::{HeaderName, header::CONNECTION};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    inspection::{
        HeaderSnapshot, InspectionStore, ReplayEligibility, ReplayIneligibilityReason, Transaction,
        TransactionId, is_sink_control_header,
    },
    runtime::resolve_local_uri,
    target::LocalTarget,
};

/// Whether a caller has deliberately consented to copying sensitive headers.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SensitiveHeaderConsent {
    NotGranted,
    Granted,
}

/// The result of attempting to generate a cURL command.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "status", content = "result")]
pub enum CurlGenerationOutcome {
    Generated(CurlCommand),
    ConfirmationRequired(SensitiveHeaderConfirmation),
}

/// Sensitive headers that require deliberate consent before command generation.
///
/// Only header names are exposed. Raw values remain confined to the retained
/// transaction until consent is granted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SensitiveHeaderConfirmation {
    header_names: Vec<String>,
}

impl SensitiveHeaderConfirmation {
    #[must_use]
    pub fn header_names(&self) -> &[String] {
        &self.header_names
    }
}

/// A generated command plus an explicit secret-exposure marker.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct CurlCommand {
    command: String,
    contains_secrets: bool,
}

impl CurlCommand {
    #[must_use]
    pub fn command(&self) -> &str {
        &self.command
    }

    #[must_use]
    pub const fn contains_secrets(&self) -> bool {
        self.contains_secrets
    }
}

impl fmt::Debug for CurlCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CurlCommand")
            .field("command", &"[REDACTED]")
            .field("contains_secrets", &self.contains_secrets)
            .finish()
    }
}

/// A stable cURL-generation failure that never embeds request data.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum CurlGenerationError {
    #[error("request is not eligible for replay: {}", .0.code())]
    Ineligible(ReplayIneligibilityReason),
    #[error("the request URI cannot be resolved against the current local target")]
    InvalidLocalUri,
}

impl CurlGenerationError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Ineligible(reason) => reason.code(),
            Self::InvalidLocalUri => "invalid_local_uri",
        }
    }

    #[must_use]
    pub const fn replay_reason(self) -> Option<ReplayIneligibilityReason> {
        match self {
            Self::Ineligible(reason) => Some(reason),
            Self::InvalidLocalUri => None,
        }
    }
}

/// Cloneable cURL dependency for the protected dashboard operation.
///
/// The service owns the current validated local target and the per-run TLS
/// setting so every generated command uses the same destination contract as
/// ordinary forwarding and replay.
#[derive(Clone)]
pub struct CurlService {
    store: InspectionStore,
    target: LocalTarget,
    local_tls_insecure: bool,
}

impl CurlService {
    /// Construct cURL generation from the runtime's current local target.
    pub(crate) fn new(
        store: InspectionStore,
        target: LocalTarget,
        local_tls_insecure: bool,
    ) -> Self {
        Self {
            store,
            target,
            local_tls_insecure,
        }
    }

    /// Generate from one retained transaction without exposing request data in
    /// lookup or eligibility failures.
    pub fn generate(
        &self,
        source_id: TransactionId,
        sensitive_header_consent: SensitiveHeaderConsent,
    ) -> Result<CurlGenerationOutcome, CurlServiceError> {
        let source = self
            .store
            .get(source_id)
            .ok_or(CurlServiceError::SourceNotFound)?;
        generate_curl_command(
            &source,
            &self.target,
            self.local_tls_insecure,
            sensitive_header_consent,
        )
        .map_err(CurlServiceError::Generation)
    }
}

impl fmt::Debug for CurlService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CurlService")
            .field("store", &self.store)
            .field("target", &self.target)
            .field("local_tls_insecure", &self.local_tls_insecure)
            .finish()
    }
}

/// A stable service-level failure that never embeds retained request data.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum CurlServiceError {
    #[error("the source transaction is no longer retained")]
    SourceNotFound,
    #[error(transparent)]
    Generation(#[from] CurlGenerationError),
}

impl CurlServiceError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::SourceNotFound => "transaction_not_found",
            Self::Generation(error) => error.code(),
        }
    }
}

/// Generate a shell-safe command that sends an eligible retained request
/// directly to the current local target.
///
/// The command uses a POSIX `printf %b` pipeline so the complete request body
/// remains byte-faithful even when it contains NUL or other control bytes.
pub fn generate_curl_command(
    transaction: &Transaction,
    target: &LocalTarget,
    local_tls_insecure: bool,
    sensitive_header_consent: SensitiveHeaderConsent,
) -> Result<CurlGenerationOutcome, CurlGenerationError> {
    if let ReplayEligibility::Ineligible(reason) = transaction.replay_eligibility() {
        return Err(CurlGenerationError::Ineligible(reason));
    }

    let connection_nominated = connection_nominated_headers(transaction);
    let included_headers = transaction
        .request()
        .headers()
        .iter()
        .filter(|header| !exclude_header(header.name(), &connection_nominated))
        .collect::<Vec<_>>();
    let sensitive_header_names = sensitive_header_names(&included_headers);

    if !sensitive_header_names.is_empty()
        && sensitive_header_consent == SensitiveHeaderConsent::NotGranted
    {
        return Ok(CurlGenerationOutcome::ConfirmationRequired(
            SensitiveHeaderConfirmation {
                header_names: sensitive_header_names,
            },
        ));
    }

    let local_uri = resolve_local_uri(target, transaction.request().public_uri())
        .map_err(|_| CurlGenerationError::InvalidLocalUri)?;
    let body = transaction.request().body().retained_bytes();
    let body_printf_operand = octal_printf_operand(body);

    let mut command = String::from("printf '%b' ");
    command.push_str(&shell_quote(&body_printf_operand));
    command.push_str(" | curl --globoff --path-as-is --request ");
    command.push_str(&shell_quote(transaction.request().method().as_str()));

    if target.uses_tls() && local_tls_insecure {
        command.push_str(" --insecure");
    }

    append_curl_default_suppressions(&mut command, &included_headers);
    for header in included_headers {
        command.push_str(" --header ");
        command.push_str(&shell_header(header));
    }

    command.push_str(" --data-binary @- --url ");
    command.push_str(&shell_quote(&local_uri.to_string()));

    Ok(CurlGenerationOutcome::Generated(CurlCommand {
        command,
        contains_secrets: !sensitive_header_names.is_empty(),
    }))
}

fn connection_nominated_headers(transaction: &Transaction) -> Vec<HeaderName> {
    let mut nominated = Vec::new();
    for header in transaction
        .request()
        .headers()
        .iter()
        .filter(|header| header.name() == CONNECTION)
    {
        for token in header.value().as_bytes().split(|byte| *byte == b',') {
            let token = trim_optional_whitespace(token);
            if let Ok(name) = HeaderName::from_bytes(token)
                && !nominated.contains(&name)
            {
                nominated.push(name);
            }
        }
    }
    nominated
}

fn trim_optional_whitespace(mut value: &[u8]) -> &[u8] {
    while value
        .first()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        value = &value[1..];
    }
    while value
        .last()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        value = &value[..value.len() - 1];
    }
    value
}

fn exclude_header(name: &HeaderName, connection_nominated: &[HeaderName]) -> bool {
    let name_text = name.as_str();
    connection_nominated.contains(name)
        || matches!(
            name_text,
            "host"
                | "connection"
                | "keep-alive"
                | "proxy-authenticate"
                | "proxy-authorization"
                | "proxy-connection"
                | "te"
                | "trailer"
                | "transfer-encoding"
                | "upgrade"
                | "forwarded"
                | "content-length"
        )
        || name_text == "x-forwarded"
        || name_text.starts_with("x-forwarded-")
        || is_sink_control_header(name)
}

fn sensitive_header_names(headers: &[&HeaderSnapshot]) -> Vec<String> {
    let mut names = Vec::new();
    for header in headers {
        if header.sensitivity().should_mask()
            && !names.iter().any(|name| name == header.name().as_str())
        {
            names.push(header.name().as_str().to_owned());
        }
    }
    names
}

fn append_curl_default_suppressions(command: &mut String, headers: &[&HeaderSnapshot]) {
    for name in ["accept", "content-type", "expect", "user-agent"] {
        if !headers.iter().any(|header| header.name().as_str() == name) {
            command.push_str(" --header ");
            command.push_str(&shell_quote(&format!("{name}:")));
        }
    }
}

fn shell_header(header: &HeaderSnapshot) -> String {
    let mut bytes =
        Vec::with_capacity(header.name().as_str().len() + header.value().as_bytes().len() + 1);
    bytes.extend_from_slice(header.name().as_str().as_bytes());
    if header.value().is_empty() {
        // cURL's semicolon form sends an empty header; `name:` removes it.
        bytes.push(b';');
    } else {
        bytes.push(b':');
        bytes.extend_from_slice(header.value().as_bytes());
    }
    shell_bytes(&bytes)
}

fn shell_bytes(bytes: &[u8]) -> String {
    match str::from_utf8(bytes) {
        Ok(value) => shell_quote(value),
        Err(_) => format!(
            "\"$(printf '%b' {})\"",
            shell_quote(&octal_printf_operand(bytes))
        ),
    }
}

fn shell_quote(value: &str) -> String {
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('\'');
    for character in value.chars() {
        if character == '\'' {
            quoted.push_str("'\"'\"'");
        } else {
            quoted.push(character);
        }
    }
    quoted.push('\'');
    quoted
}

fn octal_printf_operand(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut escaped = String::with_capacity(bytes.len().saturating_mul(5));
    for byte in bytes {
        write!(escaped, "\\0{byte:03o}").expect("writing to a String cannot fail");
    }
    escaped
}

#[cfg(test)]
mod tests {
    use std::{error::Error as StdError, str::FromStr, time::SystemTime};

    use http::{HeaderName, HeaderValue, Method, Uri, Version};

    use super::*;
    use crate::inspection::{
        BodyConstraints, BodyContentKind, BodyPreview, HeaderSnapshots, RequestSnapshot,
        TransactionId, TransactionOrigin,
    };

    const BODY_LIMIT: usize = 256;

    #[derive(Clone, Copy)]
    struct BodyFixture {
        content_kind: BodyContentKind,
        constraints: BodyConstraints,
        finish: bool,
        limit: usize,
    }

    fn transaction(
        method: Method,
        public_uri: Uri,
        headers: impl IntoIterator<Item = HeaderSnapshot>,
        body: &[u8],
        fixture: BodyFixture,
    ) -> Result<Transaction, Box<dyn StdError>> {
        let mut preview =
            BodyPreview::new(fixture.limit, fixture.content_kind, fixture.constraints)?;
        preview.record_chunk(body)?;
        if fixture.finish {
            preview.finish()?;
        }
        let request = RequestSnapshot::new(
            method,
            public_uri,
            Version::HTTP_11,
            HeaderSnapshots::from_entries(headers),
            preview,
        )?;
        Ok(Transaction::new(
            TransactionId::new(),
            TransactionOrigin::Original,
            SystemTime::UNIX_EPOCH,
            request,
        ))
    }

    fn eligible_transaction(
        method: Method,
        public_uri: Uri,
        headers: impl IntoIterator<Item = HeaderSnapshot>,
        body: &[u8],
    ) -> Result<Transaction, Box<dyn StdError>> {
        transaction(
            method,
            public_uri,
            headers,
            body,
            BodyFixture {
                content_kind: BodyContentKind::Text,
                constraints: BodyConstraints::ordinary(),
                finish: true,
                limit: BODY_LIMIT,
            },
        )
    }

    fn generated(
        transaction: &Transaction,
        target: &LocalTarget,
        insecure: bool,
        consent: SensitiveHeaderConsent,
    ) -> Result<CurlCommand, Box<dyn StdError>> {
        match generate_curl_command(transaction, target, insecure, consent)? {
            CurlGenerationOutcome::Generated(command) => Ok(command),
            CurlGenerationOutcome::ConfirmationRequired(_) => {
                Err("unexpected sensitive-header confirmation".into())
            }
        }
    }

    #[test]
    fn resolves_current_target_base_path_and_preserves_path_and_query()
    -> Result<(), Box<dyn StdError>> {
        let transaction = eligible_transaction(
            Method::GET,
            Uri::from_static("https://public.example.test/users/%2Fraw?active=true&order=desc"),
            [],
            b"",
        )?;
        let target = LocalTarget::from_str("http://localhost:3000/api/v1/")?;
        let command = generated(
            &transaction,
            &target,
            false,
            SensitiveHeaderConsent::NotGranted,
        )?;
        assert!(
            command.command().ends_with(
                "--url 'http://localhost:3000/api/v1/users/%2Fraw?active=true&order=desc'"
            )
        );
        assert!(!command.command().contains("public.example.test"));
        Ok(())
    }

    #[test]
    fn preserves_method_and_ordered_repeated_application_headers() -> Result<(), Box<dyn StdError>>
    {
        let transaction = eligible_transaction(
            Method::PATCH,
            Uri::from_static("https://public.example.test/items"),
            [
                HeaderSnapshot::new(
                    HeaderName::from_static("x-repeat"),
                    HeaderValue::from_static("first"),
                ),
                HeaderSnapshot::new(
                    HeaderName::from_static("content-type"),
                    HeaderValue::from_static("application/json"),
                ),
                HeaderSnapshot::new(
                    HeaderName::from_static("x-repeat"),
                    HeaderValue::from_bytes(b"second\x80")?,
                ),
            ],
            br#"{"exact":true}"#,
        )?;
        let target = LocalTarget::from_str("http://127.0.0.1:8080")?;
        let command = generated(
            &transaction,
            &target,
            false,
            SensitiveHeaderConsent::NotGranted,
        )?;

        assert!(command.command().contains("--request 'PATCH'"));
        let first = command
            .command()
            .find("--header 'x-repeat:first'")
            .ok_or("first repeated header missing")?;
        let content_type = command
            .command()
            .find("--header 'content-type:application/json'")
            .ok_or("content-type header missing")?;
        let second = command
            .command()
            .find("\"$(printf '%b' '\\0170\\0055\\0162")
            .ok_or("non-UTF-8 repeated header missing")?;
        assert!(first < content_type && content_type < second);
        #[cfg(unix)]
        {
            let (arguments, body) = run_with_fake_curl(command.command())?;
            let first = arguments
                .iter()
                .position(|argument| argument.as_slice() == b"x-repeat:first")
                .ok_or("first repeated argument missing")?;
            let content_type = arguments
                .iter()
                .position(|argument| argument.as_slice() == b"content-type:application/json")
                .ok_or("content-type argument missing")?;
            let second = arguments
                .iter()
                .position(|argument| argument.as_slice() == b"x-repeat:second\x80")
                .ok_or("second repeated argument missing")?;
            assert!(first < content_type && content_type < second);
            assert_eq!(body, br#"{"exact":true}"#);
        }
        Ok(())
    }

    #[test]
    fn excludes_transport_forwarding_control_and_connection_nominated_headers()
    -> Result<(), Box<dyn StdError>> {
        let excluded = [
            ("host", "public.example.test"),
            ("connection", "x-remove, Authorization"),
            ("x-remove", "nominated"),
            ("authorization", "nominated-secret"),
            ("keep-alive", "timeout=5"),
            ("proxy-authenticate", "Basic"),
            ("proxy-authorization", "proxy-secret"),
            ("proxy-connection", "keep-alive"),
            ("te", "trailers"),
            ("trailer", "x-checksum"),
            ("transfer-encoding", "chunked"),
            ("upgrade", "websocket"),
            ("forwarded", "for=192.0.2.1"),
            ("x-forwarded-for", "192.0.2.1"),
            ("content-length", "4"),
            ("x-sink-control", "never-copy"),
        ];
        let mut headers = excluded
            .iter()
            .map(|(name, value)| {
                Ok(HeaderSnapshot::new(
                    HeaderName::from_str(name)?,
                    HeaderValue::from_str(value)?,
                ))
            })
            .collect::<Result<Vec<_>, Box<dyn StdError>>>()?;
        headers.push(HeaderSnapshot::new(
            HeaderName::from_static("x-application"),
            HeaderValue::from_static("keep-me"),
        ));

        let transaction = eligible_transaction(
            Method::POST,
            Uri::from_static("https://public.example.test/items"),
            headers,
            b"body",
        )?;
        let target = LocalTarget::from_str("http://localhost:3000")?;
        let command = generated(
            &transaction,
            &target,
            false,
            SensitiveHeaderConsent::NotGranted,
        )?;

        assert!(
            command
                .command()
                .contains("--header 'x-application:keep-me'")
        );
        for (name, _) in excluded {
            assert!(
                !command.command().contains(&format!("--header '{name}:")),
                "included excluded header {name}"
            );
        }
        Ok(())
    }

    #[test]
    fn sensitive_headers_require_confirmation_and_debug_never_reveals_values()
    -> Result<(), Box<dyn StdError>> {
        let transaction = eligible_transaction(
            Method::GET,
            Uri::from_static("https://public.example.test/private"),
            [
                HeaderSnapshot::new(
                    HeaderName::from_static("authorization"),
                    HeaderValue::from_static("Bearer do-not-debug"),
                ),
                HeaderSnapshot::new(
                    HeaderName::from_static("cookie"),
                    HeaderValue::from_static("session=also-secret"),
                ),
                HeaderSnapshot::new(
                    HeaderName::from_static("proxy-authorization"),
                    HeaderValue::from_static("excluded-proxy-secret"),
                ),
            ],
            b"body-secret",
        )?;
        let target = LocalTarget::from_str("http://localhost:3000")?;

        let confirmation = generate_curl_command(
            &transaction,
            &target,
            false,
            SensitiveHeaderConsent::NotGranted,
        )?;
        let CurlGenerationOutcome::ConfirmationRequired(confirmation_details) = &confirmation
        else {
            return Err("confirmation was not required".into());
        };
        assert_eq!(
            confirmation_details.header_names(),
            &["authorization".to_owned(), "cookie".to_owned()]
        );
        let confirmation_debug = format!("{confirmation:?}");
        assert!(!confirmation_debug.contains("do-not-debug"));
        assert!(!confirmation_debug.contains("also-secret"));

        let command = generated(
            &transaction,
            &target,
            false,
            SensitiveHeaderConsent::Granted,
        )?;
        assert!(command.contains_secrets());
        assert!(command.command().contains("Bearer do-not-debug"));
        assert!(command.command().contains("session=also-secret"));
        assert!(!command.command().contains("excluded-proxy-secret"));
        let command_debug = format!("{command:?}");
        assert!(command_debug.contains("[REDACTED]"));
        assert!(!command_debug.contains("do-not-debug"));
        assert!(!command_debug.contains("also-secret"));
        assert!(!command_debug.contains("body-secret"));
        Ok(())
    }

    #[test]
    fn shell_quotes_metacharacters_and_apostrophes() -> Result<(), Box<dyn StdError>> {
        let public_uri =
            Uri::from_str("https://public.example.test/a'b?literal=$(touch%20never)&semi=;value")?;
        let transaction = eligible_transaction(
            Method::POST,
            public_uri,
            [HeaderSnapshot::new(
                HeaderName::from_static("x-shell"),
                HeaderValue::from_static("' $(touch never) ; & | `false`"),
            )],
            b"shell body",
        )?;
        let target = LocalTarget::from_str("http://localhost:3000/base'")?;
        let command = generated(
            &transaction,
            &target,
            false,
            SensitiveHeaderConsent::NotGranted,
        )?;

        assert!(command.command().contains("'\"'\"'"));
        assert!(
            command
                .command()
                .contains("--header 'x-shell:'\"'\"' $(touch never)")
        );
        assert!(
            command
                .command()
                .contains("literal=$(touch%20never)&semi=;value")
        );
        #[cfg(unix)]
        {
            let (arguments, body) = run_with_fake_curl(command.command())?;
            assert!(arguments.iter().any(|argument| {
                argument.as_slice() == b"x-shell:' $(touch never) ; & | `false`"
            }));
            assert!(arguments.iter().any(|argument| {
                argument.as_slice()
                    == b"http://localhost:3000/base'/a'b?literal=$(touch%20never)&semi=;value"
            }));
            assert_eq!(body, b"shell body");
        }
        Ok(())
    }

    #[test]
    fn body_octal_representation_is_exact_for_binary_and_control_bytes()
    -> Result<(), Box<dyn StdError>> {
        let body = [0, 1, 9, 10, 13, b'\'', b'\\', 127, 128, 255];
        let transaction = eligible_transaction(
            Method::POST,
            Uri::from_static("https://public.example.test/binary-looking-text"),
            [],
            &body,
        )?;
        assert_eq!(
            transaction.replay_eligibility(),
            ReplayEligibility::Eligible
        );
        let target = LocalTarget::from_str("http://localhost:3000")?;
        let command = generated(
            &transaction,
            &target,
            false,
            SensitiveHeaderConsent::NotGranted,
        )?;

        assert!(command.command().starts_with(
            "printf '%b' '\\0000\\0001\\0011\\0012\\0015\\0047\\0134\\0177\\0200\\0377' | curl"
        ));
        #[cfg(unix)]
        {
            let (_, captured_body) = run_with_fake_curl(command.command())?;
            assert_eq!(captured_body, body);
        }
        Ok(())
    }

    #[test]
    fn empty_body_uses_the_same_unambiguous_stdin_pipeline() -> Result<(), Box<dyn StdError>> {
        let transaction = transaction(
            Method::DELETE,
            Uri::from_static("https://public.example.test/items/42"),
            [],
            b"",
            BodyFixture {
                content_kind: BodyContentKind::Unknown,
                constraints: BodyConstraints::ordinary(),
                finish: true,
                limit: BODY_LIMIT,
            },
        )?;
        assert_eq!(
            transaction.replay_eligibility(),
            ReplayEligibility::Eligible
        );
        let target = LocalTarget::from_str("http://localhost:3000")?;
        let command = generated(
            &transaction,
            &target,
            false,
            SensitiveHeaderConsent::NotGranted,
        )?;
        assert!(command.command().starts_with("printf '%b' '' | curl"));
        assert!(command.command().contains("--data-binary @-"));
        #[cfg(unix)]
        {
            let (_, captured_body) = run_with_fake_curl(command.command())?;
            assert!(captured_body.is_empty());
        }
        Ok(())
    }

    #[test]
    fn insecure_flag_requires_both_https_target_and_insecure_setting()
    -> Result<(), Box<dyn StdError>> {
        let transaction = eligible_transaction(
            Method::GET,
            Uri::from_static("https://public.example.test/health"),
            [],
            b"",
        )?;
        let http = LocalTarget::from_str("http://localhost:3000")?;
        let https = LocalTarget::from_str("https://localhost:3443")?;

        assert!(
            !generated(
                &transaction,
                &http,
                true,
                SensitiveHeaderConsent::NotGranted,
            )?
            .command()
            .contains(" --insecure")
        );
        assert!(
            !generated(
                &transaction,
                &https,
                false,
                SensitiveHeaderConsent::NotGranted,
            )?
            .command()
            .contains(" --insecure")
        );
        assert!(
            generated(
                &transaction,
                &https,
                true,
                SensitiveHeaderConsent::NotGranted,
            )?
            .command()
            .contains(" --insecure")
        );
        Ok(())
    }

    #[test]
    fn returns_every_stable_replay_ineligibility_reason() -> Result<(), Box<dyn StdError>> {
        let target = LocalTarget::from_str("http://localhost:3000")?;
        let cases = [
            (
                BodyContentKind::Text,
                BodyConstraints::new(false, false, true),
                b"body".as_slice(),
                true,
                BODY_LIMIT,
                ReplayIneligibilityReason::WebSocketUpgrade,
            ),
            (
                BodyContentKind::Text,
                BodyConstraints::new(false, true, false),
                b"body".as_slice(),
                true,
                BODY_LIMIT,
                ReplayIneligibilityReason::ServerSentEvents,
            ),
            (
                BodyContentKind::Text,
                BodyConstraints::new(true, false, false),
                b"body".as_slice(),
                true,
                BODY_LIMIT,
                ReplayIneligibilityReason::StreamingRequest,
            ),
            (
                BodyContentKind::Binary,
                BodyConstraints::ordinary(),
                b"body".as_slice(),
                true,
                BODY_LIMIT,
                ReplayIneligibilityReason::BinaryRequestBody,
            ),
            (
                BodyContentKind::Unknown,
                BodyConstraints::ordinary(),
                b"body".as_slice(),
                true,
                BODY_LIMIT,
                ReplayIneligibilityReason::UnclassifiedRequestBody,
            ),
            (
                BodyContentKind::Text,
                BodyConstraints::ordinary(),
                b"body".as_slice(),
                false,
                BODY_LIMIT,
                ReplayIneligibilityReason::IncompleteRequestBody,
            ),
            (
                BodyContentKind::Text,
                BodyConstraints::ordinary(),
                b"body".as_slice(),
                true,
                2,
                ReplayIneligibilityReason::TruncatedRequestBody,
            ),
        ];

        for (content_kind, constraints, body, finish, limit, reason) in cases {
            let transaction = transaction(
                Method::POST,
                Uri::from_static("https://public.example.test/items"),
                [],
                body,
                BodyFixture {
                    content_kind,
                    constraints,
                    finish,
                    limit,
                },
            )?;
            let error = generate_curl_command(
                &transaction,
                &target,
                false,
                SensitiveHeaderConsent::Granted,
            )
            .expect_err("ineligible transaction must be rejected");
            assert_eq!(error, CurlGenerationError::Ineligible(reason));
            assert_eq!(error.code(), reason.code());
            assert_eq!(error.replay_reason(), Some(reason));
            assert!(error.to_string().contains(reason.code()));
        }
        Ok(())
    }

    #[cfg(unix)]
    type FakeCurlCapture = (Vec<Vec<u8>>, Vec<u8>);

    #[cfg(unix)]
    fn run_with_fake_curl(command: &str) -> Result<FakeCurlCapture, Box<dyn StdError>> {
        use std::{env, fs, os::unix::fs::PermissionsExt as _, process::Command};

        let directory = tempfile::tempdir()?;
        let curl_path = directory.path().join("curl");
        fs::write(
            &curl_path,
            "#!/bin/sh\nindex=0\nfor argument do\n  index=$((index + 1))\n  printf '%s' \"$argument\" > \"$CURL_CAPTURE_DIR/arg-$index\"\ndone\ncat > \"$CURL_CAPTURE_DIR/body\"\n",
        )?;
        let mut permissions = fs::metadata(&curl_path)?.permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&curl_path, permissions)?;

        let mut search_paths = vec![directory.path().to_owned()];
        if let Some(existing_path) = env::var_os("PATH") {
            search_paths.extend(env::split_paths(&existing_path));
        }
        let path = env::join_paths(search_paths)?;
        let status = Command::new("sh")
            .arg("-c")
            .arg(command)
            .env("PATH", path)
            .env("CURL_CAPTURE_DIR", directory.path())
            .current_dir(directory.path())
            .status()?;
        if !status.success() {
            return Err(format!("generated command exited with {status}").into());
        }
        if directory.path().join("never").exists() {
            return Err("shell metacharacters executed unexpectedly".into());
        }

        let mut arguments = Vec::new();
        for index in 1.. {
            let path = directory.path().join(format!("arg-{index}"));
            if !path.exists() {
                break;
            }
            arguments.push(fs::read(path)?);
        }
        let body = fs::read(directory.path().join("body"))?;
        Ok((arguments, body))
    }
}
