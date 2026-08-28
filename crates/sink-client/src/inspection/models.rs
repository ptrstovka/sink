//! Immutable inspection identities and bounded transaction snapshots.

use std::{
    fmt,
    num::NonZeroUsize,
    str::FromStr,
    time::{Duration, SystemTime},
};

use http::{
    HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri, Version,
    header::{AUTHORIZATION, COOKIE, PROXY_AUTHORIZATION, SET_COOKIE},
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

/// An immutable, process-local identity for one captured transaction.
#[derive(Clone, Copy, Debug, Deserialize, Hash, Ord, PartialEq, Eq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct TransactionId(Uuid);

impl TransactionId {
    /// Generate a new transaction identity.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    #[must_use]
    pub const fn from_uuid(value: Uuid) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn as_uuid(self) -> Uuid {
        self.0
    }
}

impl Default for TransactionId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for TransactionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for TransactionId {
    type Err = uuid::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(value).map(Self)
    }
}

/// Whether traffic originated at the public tunnel or from an explicit replay.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum TransactionOrigin {
    Original,
    Replay {
        /// The captured transaction replayed by the user, when it is still known.
        source: Option<TransactionId>,
    },
}

impl TransactionOrigin {
    #[must_use]
    pub const fn replay(source: TransactionId) -> Self {
        Self::Replay {
            source: Some(source),
        }
    }

    #[must_use]
    pub const fn unlinked_replay() -> Self {
        Self::Replay { source: None }
    }

    #[must_use]
    pub const fn source(self) -> Option<TransactionId> {
        match self {
            Self::Original => None,
            Self::Replay { source } => source,
        }
    }
}

/// Why a header is sensitive enough to mask by default.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SensitiveHeaderKind {
    Authorization,
    ProxyAuthorization,
    Cookie,
    SetCookie,
    ApiKey,
    AuthToken,
}

/// Explicit display policy attached to every captured application header.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "classification", content = "kind")]
pub enum HeaderSensitivity {
    Public,
    Sensitive(SensitiveHeaderKind),
}

impl HeaderSensitivity {
    #[must_use]
    pub const fn should_mask(self) -> bool {
        matches!(self, Self::Sensitive(_))
    }
}

/// A UI/API-safe choice between a masked marker and the preserved header value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeaderDisplayValue<'a> {
    Masked,
    Revealed(&'a HeaderValue),
}

/// One application header with exact value bytes and explicit masking metadata.
///
/// This type deliberately has no field for Sink control credentials. It must be
/// populated only from tunneled application requests or responses. Sensitive
/// raw values are private and are also redacted from `Debug` output.
#[derive(Clone, PartialEq, Eq)]
pub struct HeaderSnapshot {
    name: HeaderName,
    value: HeaderValue,
    sensitivity: HeaderSensitivity,
}

impl HeaderSnapshot {
    #[must_use]
    pub fn new(name: HeaderName, value: HeaderValue) -> Self {
        let sensitivity = classify_header_name(&name);
        Self {
            name,
            value,
            sensitivity,
        }
    }

    #[must_use]
    pub const fn with_sensitivity(
        name: HeaderName,
        value: HeaderValue,
        sensitivity: HeaderSensitivity,
    ) -> Self {
        Self {
            name,
            value,
            sensitivity,
        }
    }

    #[must_use]
    pub const fn name(&self) -> &HeaderName {
        &self.name
    }

    /// Return the exact value retained for a deliberate reveal or replay.
    #[must_use]
    pub const fn value(&self) -> &HeaderValue {
        &self.value
    }

    #[must_use]
    pub const fn sensitivity(&self) -> HeaderSensitivity {
        self.sensitivity
    }

    #[must_use]
    pub const fn display_value(&self, reveal_sensitive: bool) -> HeaderDisplayValue<'_> {
        if self.sensitivity.should_mask() && !reveal_sensitive {
            HeaderDisplayValue::Masked
        } else {
            HeaderDisplayValue::Revealed(&self.value)
        }
    }
}

impl fmt::Debug for HeaderSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut snapshot = formatter.debug_struct("HeaderSnapshot");
        snapshot.field("name", &self.name);
        if self.sensitivity.should_mask() || is_sink_control_header(&self.name) {
            snapshot.field("value", &"[MASKED]");
        } else {
            snapshot.field("value", &self.value);
        }
        snapshot.field("sensitivity", &self.sensitivity).finish()
    }
}

/// An ordered snapshot that preserves repeated application headers.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HeaderSnapshots(Vec<HeaderSnapshot>);

impl HeaderSnapshots {
    #[must_use]
    pub fn capture(headers: &HeaderMap) -> Self {
        Self::from_entries(
            headers
                .iter()
                .map(|(name, value)| HeaderSnapshot::new(name.clone(), value.clone())),
        )
    }

    #[must_use]
    pub fn from_entries(entries: impl IntoIterator<Item = HeaderSnapshot>) -> Self {
        Self(
            entries
                .into_iter()
                .filter(|header| !is_sink_control_header(header.name()))
                .collect(),
        )
    }

    #[must_use]
    pub fn as_slice(&self) -> &[HeaderSnapshot] {
        &self.0
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = &HeaderSnapshot> {
        self.0.iter()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl FromIterator<HeaderSnapshot> for HeaderSnapshots {
    fn from_iter<T: IntoIterator<Item = HeaderSnapshot>>(iter: T) -> Self {
        Self::from_entries(iter)
    }
}

/// Classify standard sensitive application header names without inspecting values.
#[must_use]
pub fn classify_header_name(name: &HeaderName) -> HeaderSensitivity {
    let name_text = name.as_str();
    if name == AUTHORIZATION {
        HeaderSensitivity::Sensitive(SensitiveHeaderKind::Authorization)
    } else if name == PROXY_AUTHORIZATION {
        HeaderSensitivity::Sensitive(SensitiveHeaderKind::ProxyAuthorization)
    } else if name == COOKIE {
        HeaderSensitivity::Sensitive(SensitiveHeaderKind::Cookie)
    } else if name == SET_COOKIE {
        HeaderSensitivity::Sensitive(SensitiveHeaderKind::SetCookie)
    } else if name_text == "x-api-key"
        || name_text == "api-key"
        || name_text == "apikey"
        || name_text.ends_with("-api-key")
        || name_text.ends_with("-apikey")
    {
        HeaderSensitivity::Sensitive(SensitiveHeaderKind::ApiKey)
    } else if matches!(
        name_text,
        "authentication-info" | "proxy-authentication-info"
    ) || name_text.split('-').any(|segment| {
        matches!(
            segment,
            "token" | "secret" | "credential" | "password" | "passwd" | "passphrase" | "signature"
        )
    }) {
        HeaderSensitivity::Sensitive(SensitiveHeaderKind::AuthToken)
    } else {
        HeaderSensitivity::Public
    }
}

/// Whether a header belongs to Sink's reserved control namespace.
///
/// These headers are not application traffic and are excluded at the capture
/// model boundary. Keeping this predicate here gives capture, replay, and cURL
/// one defensive policy without exposing any credential values.
#[must_use]
pub fn is_sink_control_header(name: &HeaderName) -> bool {
    let name = name.as_str();
    name == "x-sink" || name.starts_with("x-sink-")
}

/// Display-oriented classification for a body preview.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BodyContentKind {
    Unknown,
    Json,
    Text,
    Form,
    Xml,
    Binary,
}

impl BodyContentKind {
    /// Classify a Content-Type header without depending on a MIME parser.
    #[must_use]
    pub fn from_content_type(value: Option<&HeaderValue>) -> Self {
        let Some(value) = value.and_then(|value| value.to_str().ok()) else {
            return Self::Unknown;
        };
        let essence = value
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();

        if essence == "application/json" || essence.ends_with("+json") {
            Self::Json
        } else if matches!(essence.as_str(), "application/xml" | "text/xml")
            || essence.ends_with("+xml")
        {
            Self::Xml
        } else if essence.starts_with("text/")
            || matches!(
                essence.as_str(),
                "application/javascript" | "application/graphql" | "application/sql"
            )
        {
            Self::Text
        } else if essence == "application/x-www-form-urlencoded" {
            Self::Form
        } else if essence.starts_with("image/")
            || essence.starts_with("audio/")
            || essence.starts_with("video/")
            || essence.starts_with("font/")
            || matches!(
                essence.as_str(),
                "application/octet-stream"
                    | "application/pdf"
                    | "application/zip"
                    | "application/gzip"
            )
        {
            Self::Binary
        } else {
            Self::Unknown
        }
    }
}

/// Protocol/transfer properties that constrain display and replay behavior.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct BodyConstraints {
    streaming: bool,
    server_sent_events: bool,
    websocket_upgrade: bool,
}

impl BodyConstraints {
    #[must_use]
    pub const fn ordinary() -> Self {
        Self {
            streaming: false,
            server_sent_events: false,
            websocket_upgrade: false,
        }
    }

    #[must_use]
    pub const fn new(streaming: bool, server_sent_events: bool, websocket_upgrade: bool) -> Self {
        Self {
            streaming: streaming || server_sent_events,
            server_sent_events,
            websocket_upgrade,
        }
    }

    #[must_use]
    pub const fn is_streaming(self) -> bool {
        self.streaming
    }

    #[must_use]
    pub const fn is_server_sent_events(self) -> bool {
        self.server_sent_events
    }

    #[must_use]
    pub const fn is_websocket_upgrade(self) -> bool {
        self.websocket_upgrade
    }
}

/// Whether transfer of a body is ongoing, finished, or ended early.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BodyCompletion {
    InProgress,
    Complete,
    Incomplete,
}

/// Why retained bytes differ from the transferred body.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BodyRetention {
    Retained,
    Truncated,
    OmittedBinary,
}

/// A bounded body value plus transfer metadata.
#[derive(Clone, PartialEq, Eq)]
pub struct BodyPreview {
    retained: Vec<u8>,
    total_bytes: u64,
    limit: NonZeroUsize,
    content_kind: BodyContentKind,
    completion: BodyCompletion,
    constraints: BodyConstraints,
}

impl fmt::Debug for BodyPreview {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BodyPreview")
            .field("retained_bytes", &"[REDACTED]")
            .field("retained_len", &self.retained.len())
            .field("total_bytes", &self.total_bytes)
            .field("limit", &self.limit)
            .field("content_kind", &self.content_kind)
            .field("completion", &self.completion)
            .field("constraints", &self.constraints)
            .finish()
    }
}

impl BodyPreview {
    pub fn new(
        limit: usize,
        content_kind: BodyContentKind,
        constraints: BodyConstraints,
    ) -> Result<Self, BodyPreviewError> {
        let limit = NonZeroUsize::new(limit).ok_or(BodyPreviewError::ZeroLimit)?;
        Ok(Self::from_nonzero_limit(limit, content_kind, constraints))
    }

    pub fn completed_empty(
        limit: usize,
        content_kind: BodyContentKind,
        constraints: BodyConstraints,
    ) -> Result<Self, BodyPreviewError> {
        let mut preview = Self::new(limit, content_kind, constraints)?;
        preview.completion = BodyCompletion::Complete;
        Ok(preview)
    }

    pub(crate) fn from_nonzero_limit(
        limit: NonZeroUsize,
        content_kind: BodyContentKind,
        constraints: BodyConstraints,
    ) -> Self {
        Self {
            retained: Vec::new(),
            total_bytes: 0,
            limit,
            content_kind,
            completion: BodyCompletion::InProgress,
            constraints,
        }
    }

    pub fn record_chunk(&mut self, chunk: &[u8]) -> Result<(), BodyPreviewError> {
        self.ensure_in_progress()?;
        self.total_bytes = self
            .total_bytes
            .saturating_add(u64::try_from(chunk.len()).unwrap_or(u64::MAX));

        if self.content_kind != BodyContentKind::Binary {
            let remaining = self.limit.get().saturating_sub(self.retained.len());
            let copied = remaining.min(chunk.len());
            self.retained.extend_from_slice(&chunk[..copied]);
        }
        Ok(())
    }

    pub fn set_content_kind(
        &mut self,
        content_kind: BodyContentKind,
    ) -> Result<(), BodyPreviewError> {
        self.ensure_in_progress()?;
        self.content_kind = content_kind;
        if content_kind == BodyContentKind::Binary {
            self.retained.clear();
        }
        Ok(())
    }

    pub fn set_constraints(
        &mut self,
        constraints: BodyConstraints,
    ) -> Result<(), BodyPreviewError> {
        self.ensure_in_progress()?;
        self.constraints = constraints;
        Ok(())
    }

    pub fn finish(&mut self) -> Result<(), BodyPreviewError> {
        self.ensure_in_progress()?;
        self.completion = BodyCompletion::Complete;
        Ok(())
    }

    pub fn mark_incomplete(&mut self) -> Result<(), BodyPreviewError> {
        self.ensure_in_progress()?;
        self.completion = BodyCompletion::Incomplete;
        Ok(())
    }

    #[must_use]
    pub fn retained_bytes(&self) -> &[u8] {
        &self.retained
    }

    #[must_use]
    pub const fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    #[must_use]
    pub const fn limit(&self) -> usize {
        self.limit.get()
    }

    #[must_use]
    pub const fn content_kind(&self) -> BodyContentKind {
        self.content_kind
    }

    #[must_use]
    pub const fn completion(&self) -> BodyCompletion {
        self.completion
    }

    #[must_use]
    pub const fn constraints(&self) -> BodyConstraints {
        self.constraints
    }

    #[must_use]
    pub fn retention(&self) -> BodyRetention {
        if self.content_kind == BodyContentKind::Binary {
            BodyRetention::OmittedBinary
        } else if self.total_bytes > u64::try_from(self.retained.len()).unwrap_or(u64::MAX) {
            BodyRetention::Truncated
        } else {
            BodyRetention::Retained
        }
    }

    #[must_use]
    pub fn is_truncated(&self) -> bool {
        self.retention() == BodyRetention::Truncated
    }

    #[must_use]
    pub fn is_fully_retained(&self) -> bool {
        self.content_kind != BodyContentKind::Binary
            && self.total_bytes == u64::try_from(self.retained.len()).unwrap_or(u64::MAX)
    }

    pub(crate) fn clamp_limit(&mut self, maximum: NonZeroUsize) {
        if self.limit > maximum {
            self.limit = maximum;
            self.retained.truncate(maximum.get());
        }
    }

    fn ensure_in_progress(&self) -> Result<(), BodyPreviewError> {
        if self.completion == BodyCompletion::InProgress {
            Ok(())
        } else {
            Err(BodyPreviewError::AlreadyFinished)
        }
    }

    fn force_incomplete(&mut self) {
        if self.completion == BodyCompletion::InProgress {
            self.completion = BodyCompletion::Incomplete;
        }
    }
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum BodyPreviewError {
    #[error("body preview limit must be greater than zero")]
    ZeroLimit,
    #[error("body preview transfer has already finished")]
    AlreadyFinished,
}

/// Public request metadata captured before local-target rewriting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestSnapshot {
    method: Method,
    public_uri: Uri,
    version: Version,
    headers: HeaderSnapshots,
    body: BodyPreview,
}

impl RequestSnapshot {
    pub fn new(
        method: Method,
        public_uri: Uri,
        version: Version,
        headers: HeaderSnapshots,
        body: BodyPreview,
    ) -> Result<Self, RequestSnapshotError> {
        if public_uri.scheme().is_none() || public_uri.authority().is_none() {
            return Err(RequestSnapshotError::NonAbsolutePublicUri);
        }
        Ok(Self {
            method,
            public_uri,
            version,
            headers,
            body,
        })
    }

    #[must_use]
    pub const fn method(&self) -> &Method {
        &self.method
    }

    #[must_use]
    pub const fn public_uri(&self) -> &Uri {
        &self.public_uri
    }

    #[must_use]
    pub const fn version(&self) -> Version {
        self.version
    }

    #[must_use]
    pub const fn headers(&self) -> &HeaderSnapshots {
        &self.headers
    }

    #[must_use]
    pub const fn body(&self) -> &BodyPreview {
        &self.body
    }

    pub(crate) fn body_mut(&mut self) -> &mut BodyPreview {
        &mut self.body
    }
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum RequestSnapshotError {
    #[error("captured public request URI must include a scheme and authority")]
    NonAbsolutePublicUri,
}

/// Response metadata captured as soon as local response headers arrive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResponseSnapshot {
    status: StatusCode,
    version: Version,
    headers: HeaderSnapshots,
    body: BodyPreview,
}

impl ResponseSnapshot {
    #[must_use]
    pub const fn new(
        status: StatusCode,
        version: Version,
        headers: HeaderSnapshots,
        body: BodyPreview,
    ) -> Self {
        Self {
            status,
            version,
            headers,
            body,
        }
    }

    #[must_use]
    pub const fn status(&self) -> StatusCode {
        self.status
    }

    #[must_use]
    pub const fn version(&self) -> Version {
        self.version
    }

    #[must_use]
    pub const fn headers(&self) -> &HeaderSnapshots {
        &self.headers
    }

    #[must_use]
    pub const fn body(&self) -> &BodyPreview {
        &self.body
    }

    pub(crate) fn body_mut(&mut self) -> &mut BodyPreview {
        &mut self.body
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureKind {
    Failed,
    Cancelled,
}

#[derive(Clone, Deserialize, PartialEq, Eq, Serialize)]
pub struct TransactionFailure {
    kind: FailureKind,
    #[serde(default, skip_deserializing, skip_serializing)]
    message: Option<String>,
}

impl TransactionFailure {
    #[must_use]
    pub(crate) fn failed(message: &'static str) -> Self {
        Self {
            kind: FailureKind::Failed,
            message: Some(message.to_owned()),
        }
    }

    #[must_use]
    pub const fn cancelled() -> Self {
        Self {
            kind: FailureKind::Cancelled,
            message: None,
        }
    }

    #[must_use]
    pub const fn kind(&self) -> FailureKind {
        self.kind
    }

    #[must_use]
    pub fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }
}

impl fmt::Debug for TransactionFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransactionFailure")
            .field("kind", &self.kind)
            .field("message", &self.message.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

/// Explicit transaction lifecycle from receipt through one terminal outcome.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "state", content = "failure")]
pub enum TransactionLifecycle {
    Received,
    ResponseStarted,
    Completed,
    FailedOrCancelled(TransactionFailure),
    Upgraded,
}

impl TransactionLifecycle {
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Completed | Self::FailedOrCancelled(_) | Self::Upgraded
        )
    }
}

/// A stable explanation suitable for disabled replay controls and API responses.
#[derive(Clone, Copy, Debug, Deserialize, Error, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayIneligibilityReason {
    #[error("WebSocket upgrade transactions cannot be replayed")]
    WebSocketUpgrade,
    #[error("server-sent event transactions cannot be replayed")]
    ServerSentEvents,
    #[error("streaming request bodies cannot be replayed")]
    StreamingRequest,
    #[error("binary request bodies are not retained for replay")]
    BinaryRequestBody,
    #[error("the request body content kind is not known")]
    UnclassifiedRequestBody,
    #[error("the request body did not finish transferring")]
    IncompleteRequestBody,
    #[error("the request body preview was truncated")]
    TruncatedRequestBody,
}

impl ReplayIneligibilityReason {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::WebSocketUpgrade => "websocket_upgrade",
            Self::ServerSentEvents => "server_sent_events",
            Self::StreamingRequest => "streaming_request",
            Self::BinaryRequestBody => "binary_request_body",
            Self::UnclassifiedRequestBody => "unclassified_request_body",
            Self::IncompleteRequestBody => "incomplete_request_body",
            Self::TruncatedRequestBody => "truncated_request_body",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "status", content = "reason")]
pub enum ReplayEligibility {
    Eligible,
    Ineligible(ReplayIneligibilityReason),
}

impl ReplayEligibility {
    #[must_use]
    pub const fn is_eligible(self) -> bool {
        matches!(self, Self::Eligible)
    }

    #[must_use]
    pub const fn reason(self) -> Option<ReplayIneligibilityReason> {
        match self {
            Self::Eligible => None,
            Self::Ineligible(reason) => Some(reason),
        }
    }
}

/// A complete point-in-time inspection record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transaction {
    id: TransactionId,
    origin: TransactionOrigin,
    received_at: SystemTime,
    request: RequestSnapshot,
    response: Option<ResponseSnapshot>,
    lifecycle: TransactionLifecycle,
    response_started_after: Option<Duration>,
    duration: Option<Duration>,
}

impl Transaction {
    #[must_use]
    pub const fn new(
        id: TransactionId,
        origin: TransactionOrigin,
        received_at: SystemTime,
        request: RequestSnapshot,
    ) -> Self {
        Self {
            id,
            origin,
            received_at,
            request,
            response: None,
            lifecycle: TransactionLifecycle::Received,
            response_started_after: None,
            duration: None,
        }
    }

    #[must_use]
    pub const fn id(&self) -> TransactionId {
        self.id
    }

    #[must_use]
    pub const fn origin(&self) -> TransactionOrigin {
        self.origin
    }

    #[must_use]
    pub const fn received_at(&self) -> SystemTime {
        self.received_at
    }

    #[must_use]
    pub const fn request(&self) -> &RequestSnapshot {
        &self.request
    }

    #[must_use]
    pub const fn response(&self) -> Option<&ResponseSnapshot> {
        self.response.as_ref()
    }

    #[must_use]
    pub const fn lifecycle(&self) -> &TransactionLifecycle {
        &self.lifecycle
    }

    #[must_use]
    pub const fn response_started_after(&self) -> Option<Duration> {
        self.response_started_after
    }

    #[must_use]
    pub const fn duration(&self) -> Option<Duration> {
        self.duration
    }

    pub fn record_request_body_chunk(
        &mut self,
        chunk: &[u8],
    ) -> Result<(), TransactionUpdateError> {
        self.ensure_active()?;
        self.request.body_mut().record_chunk(chunk)?;
        Ok(())
    }

    pub fn set_request_body_content_kind(
        &mut self,
        content_kind: BodyContentKind,
    ) -> Result<(), TransactionUpdateError> {
        self.ensure_active()?;
        self.request.body_mut().set_content_kind(content_kind)?;
        Ok(())
    }

    pub fn set_request_body_constraints(
        &mut self,
        constraints: BodyConstraints,
    ) -> Result<(), TransactionUpdateError> {
        self.ensure_active()?;
        self.request.body_mut().set_constraints(constraints)?;
        Ok(())
    }

    pub fn finish_request_body(&mut self) -> Result<(), TransactionUpdateError> {
        self.ensure_active()?;
        self.request.body_mut().finish()?;
        Ok(())
    }

    pub fn mark_request_body_incomplete(&mut self) -> Result<(), TransactionUpdateError> {
        self.ensure_active()?;
        self.request.body_mut().mark_incomplete()?;
        Ok(())
    }

    pub fn start_response(
        &mut self,
        response: ResponseSnapshot,
        elapsed: Duration,
    ) -> Result<(), TransactionUpdateError> {
        if self.lifecycle != TransactionLifecycle::Received {
            return Err(TransactionUpdateError::InvalidLifecycleTransition);
        }
        self.response = Some(response);
        self.response_started_after = Some(elapsed);
        self.lifecycle = TransactionLifecycle::ResponseStarted;
        Ok(())
    }

    pub fn record_response_body_chunk(
        &mut self,
        chunk: &[u8],
    ) -> Result<(), TransactionUpdateError> {
        let response = self.active_response_mut()?;
        response.body_mut().record_chunk(chunk)?;
        Ok(())
    }

    pub fn set_response_body_content_kind(
        &mut self,
        content_kind: BodyContentKind,
    ) -> Result<(), TransactionUpdateError> {
        let response = self.active_response_mut()?;
        response.body_mut().set_content_kind(content_kind)?;
        Ok(())
    }

    pub fn set_response_body_constraints(
        &mut self,
        constraints: BodyConstraints,
    ) -> Result<(), TransactionUpdateError> {
        let response = self.active_response_mut()?;
        response.body_mut().set_constraints(constraints)?;
        Ok(())
    }

    pub fn finish_response_body(&mut self) -> Result<(), TransactionUpdateError> {
        let response = self.active_response_mut()?;
        response.body_mut().finish()?;
        Ok(())
    }

    pub fn mark_response_body_incomplete(&mut self) -> Result<(), TransactionUpdateError> {
        let response = self.active_response_mut()?;
        response.body_mut().mark_incomplete()?;
        Ok(())
    }

    pub fn complete(&mut self, duration: Duration) -> Result<(), TransactionUpdateError> {
        if self.lifecycle != TransactionLifecycle::ResponseStarted {
            return Err(TransactionUpdateError::InvalidLifecycleTransition);
        }
        let response = self
            .response
            .as_ref()
            .ok_or(TransactionUpdateError::ResponseNotStarted)?;
        if self.request.body.completion() != BodyCompletion::Complete
            || response.body.completion() != BodyCompletion::Complete
        {
            return Err(TransactionUpdateError::BodiesStillInProgress);
        }
        self.lifecycle = TransactionLifecycle::Completed;
        self.duration = Some(duration);
        Ok(())
    }

    pub(crate) fn fail(
        &mut self,
        duration: Duration,
        message: &'static str,
    ) -> Result<(), TransactionUpdateError> {
        self.finish_with_failure(duration, TransactionFailure::failed(message))
    }

    pub fn cancel(&mut self, duration: Duration) -> Result<(), TransactionUpdateError> {
        self.finish_with_failure(duration, TransactionFailure::cancelled())
    }

    pub fn upgrade(&mut self, duration: Duration) -> Result<(), TransactionUpdateError> {
        if self.lifecycle != TransactionLifecycle::ResponseStarted {
            return Err(TransactionUpdateError::InvalidLifecycleTransition);
        }
        self.request.body_mut().force_incomplete();
        if let Some(response) = self.response.as_mut() {
            response.body_mut().force_incomplete();
        }
        self.lifecycle = TransactionLifecycle::Upgraded;
        self.duration = Some(duration);
        Ok(())
    }

    #[must_use]
    pub fn replay_eligibility(&self) -> ReplayEligibility {
        let request_body = self.request.body();
        let request_constraints = request_body.constraints();
        let response_constraints = self
            .response
            .as_ref()
            .map(|response| response.body.constraints());

        if matches!(self.lifecycle, TransactionLifecycle::Upgraded)
            || request_constraints.is_websocket_upgrade()
            || response_constraints.is_some_and(BodyConstraints::is_websocket_upgrade)
        {
            return ReplayEligibility::Ineligible(ReplayIneligibilityReason::WebSocketUpgrade);
        }
        if request_constraints.is_server_sent_events()
            || response_constraints.is_some_and(BodyConstraints::is_server_sent_events)
        {
            return ReplayEligibility::Ineligible(ReplayIneligibilityReason::ServerSentEvents);
        }
        if request_constraints.is_streaming() {
            return ReplayEligibility::Ineligible(ReplayIneligibilityReason::StreamingRequest);
        }
        if request_body.content_kind() == BodyContentKind::Binary {
            return ReplayEligibility::Ineligible(ReplayIneligibilityReason::BinaryRequestBody);
        }
        if request_body.total_bytes() > 0 && request_body.content_kind() == BodyContentKind::Unknown
        {
            return ReplayEligibility::Ineligible(
                ReplayIneligibilityReason::UnclassifiedRequestBody,
            );
        }
        if request_body.completion() != BodyCompletion::Complete {
            return ReplayEligibility::Ineligible(ReplayIneligibilityReason::IncompleteRequestBody);
        }
        if !request_body.is_fully_retained() {
            return ReplayEligibility::Ineligible(ReplayIneligibilityReason::TruncatedRequestBody);
        }
        ReplayEligibility::Eligible
    }

    pub(crate) fn clamp_body_limits(&mut self, maximum: NonZeroUsize) {
        self.request.body_mut().clamp_limit(maximum);
        if let Some(response) = self.response.as_mut() {
            response.body_mut().clamp_limit(maximum);
        }
    }

    fn ensure_active(&self) -> Result<(), TransactionUpdateError> {
        if self.lifecycle.is_terminal() {
            Err(TransactionUpdateError::TransactionAlreadyTerminal)
        } else {
            Ok(())
        }
    }

    fn active_response_mut(&mut self) -> Result<&mut ResponseSnapshot, TransactionUpdateError> {
        if self.lifecycle != TransactionLifecycle::ResponseStarted {
            return Err(TransactionUpdateError::ResponseNotStarted);
        }
        self.response
            .as_mut()
            .ok_or(TransactionUpdateError::ResponseNotStarted)
    }

    fn finish_with_failure(
        &mut self,
        duration: Duration,
        failure: TransactionFailure,
    ) -> Result<(), TransactionUpdateError> {
        self.ensure_active()?;
        self.request.body_mut().force_incomplete();
        if let Some(response) = self.response.as_mut() {
            response.body_mut().force_incomplete();
        }
        self.lifecycle = TransactionLifecycle::FailedOrCancelled(failure);
        self.duration = Some(duration);
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum TransactionUpdateError {
    #[error("transaction lifecycle transition is not allowed")]
    InvalidLifecycleTransition,
    #[error("transaction has already reached a terminal state")]
    TransactionAlreadyTerminal,
    #[error("response metadata has not been captured")]
    ResponseNotStarted,
    #[error("request and response bodies must finish before completion")]
    BodiesStillInProgress,
    #[error(transparent)]
    Body(#[from] BodyPreviewError),
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIMIT: usize = 16;

    fn request_with_body(body: BodyPreview) -> Result<RequestSnapshot, RequestSnapshotError> {
        RequestSnapshot::new(
            Method::POST,
            Uri::from_static("https://public.example.test/widgets?draft=1"),
            Version::HTTP_11,
            HeaderSnapshots::default(),
            body,
        )
    }

    fn completed_empty_body() -> Result<BodyPreview, BodyPreviewError> {
        BodyPreview::completed_empty(LIMIT, BodyContentKind::Unknown, BodyConstraints::ordinary())
    }

    fn response(body: BodyPreview) -> ResponseSnapshot {
        ResponseSnapshot::new(
            StatusCode::OK,
            Version::HTTP_11,
            HeaderSnapshots::default(),
            body,
        )
    }

    #[test]
    fn header_masking_is_explicit_and_debug_safe() -> Result<(), http::header::InvalidHeaderValue> {
        let secret = HeaderValue::from_str("Bearer do-not-leak")?;
        let authorization = HeaderSnapshot::new(AUTHORIZATION, secret.clone());
        assert_eq!(
            authorization.sensitivity(),
            HeaderSensitivity::Sensitive(SensitiveHeaderKind::Authorization)
        );
        assert_eq!(authorization.value().as_bytes(), secret.as_bytes());
        assert_eq!(
            authorization.display_value(false),
            HeaderDisplayValue::Masked
        );
        assert_eq!(
            authorization.display_value(true),
            HeaderDisplayValue::Revealed(&secret)
        );
        let debug = format!("{authorization:?}");
        assert!(debug.contains("[MASKED]"));
        assert!(!debug.contains("do-not-leak"));

        for (name, kind) in [
            (PROXY_AUTHORIZATION, SensitiveHeaderKind::ProxyAuthorization),
            (COOKIE, SensitiveHeaderKind::Cookie),
            (SET_COOKIE, SensitiveHeaderKind::SetCookie),
            (
                HeaderName::from_static("x-api-key"),
                SensitiveHeaderKind::ApiKey,
            ),
            (
                HeaderName::from_static("x-auth-token"),
                SensitiveHeaderKind::AuthToken,
            ),
            (
                HeaderName::from_static("x-client-secret"),
                SensitiveHeaderKind::AuthToken,
            ),
            (
                HeaderName::from_static("x-webhook-signature"),
                SensitiveHeaderKind::AuthToken,
            ),
            (
                HeaderName::from_static("x-goog-api-key"),
                SensitiveHeaderKind::ApiKey,
            ),
        ] {
            assert_eq!(
                classify_header_name(&name),
                HeaderSensitivity::Sensitive(kind)
            );
        }
        assert_eq!(
            classify_header_name(&HeaderName::from_static("content-type")),
            HeaderSensitivity::Public
        );

        let reserved = HeaderSnapshot::with_sensitivity(
            HeaderName::from_static("x-sink-control"),
            HeaderValue::from_static("reserved-control-value"),
            HeaderSensitivity::Public,
        );
        let debug = format!("{reserved:?}");
        assert!(debug.contains("[MASKED]"));
        assert!(!debug.contains("reserved-control-value"));
        Ok(())
    }

    #[test]
    fn sink_control_headers_never_enter_snapshot_collections() {
        let mut headers = HeaderMap::new();
        headers.insert("x-public", HeaderValue::from_static("retained"));
        headers.insert("x-sink", HeaderValue::from_static("reserved-one"));
        headers.insert(
            "x-sink-inspector-token",
            HeaderValue::from_static("reserved-two"),
        );

        let captured = HeaderSnapshots::capture(&headers);
        assert_eq!(captured.len(), 1);
        assert_eq!(captured.as_slice()[0].name(), "x-public");

        let constructed = HeaderSnapshots::from_entries([
            HeaderSnapshot::new(
                HeaderName::from_static("x-sink-control"),
                HeaderValue::from_static("reserved-three"),
            ),
            HeaderSnapshot::new(
                HeaderName::from_static("x-application"),
                HeaderValue::from_static("retained"),
            ),
        ]);
        assert_eq!(constructed.len(), 1);
        assert_eq!(constructed.as_slice()[0].name(), "x-application");
    }

    #[test]
    fn repeated_header_values_preserve_exact_bytes() -> Result<(), http::header::InvalidHeaderValue>
    {
        let mut headers = HeaderMap::new();
        headers.append("x-example", HeaderValue::from_static("first"));
        headers.append("x-example", HeaderValue::from_bytes(b"second\x80")?);
        let snapshots = HeaderSnapshots::capture(&headers);
        assert_eq!(snapshots.len(), 2);
        assert_eq!(snapshots.as_slice()[0].value().as_bytes(), b"first");
        assert_eq!(snapshots.as_slice()[1].value().as_bytes(), b"second\x80");
        Ok(())
    }

    #[test]
    fn content_type_classification_covers_structured_text_and_binary() {
        assert_eq!(
            BodyContentKind::from_content_type(Some(&HeaderValue::from_static(
                "application/problem+json; charset=utf-8"
            ))),
            BodyContentKind::Json
        );
        assert_eq!(
            BodyContentKind::from_content_type(Some(&HeaderValue::from_static("text/xml"))),
            BodyContentKind::Xml
        );
        assert_eq!(
            BodyContentKind::from_content_type(Some(&HeaderValue::from_static("image/png"))),
            BodyContentKind::Binary
        );
        assert_eq!(
            BodyContentKind::from_content_type(None),
            BodyContentKind::Unknown
        );
    }

    #[test]
    fn preview_bounds_retained_bytes_but_counts_the_full_transfer() -> Result<(), BodyPreviewError>
    {
        assert_eq!(
            BodyPreview::new(0, BodyContentKind::Text, BodyConstraints::ordinary()),
            Err(BodyPreviewError::ZeroLimit)
        );
        let mut preview = BodyPreview::new(4, BodyContentKind::Text, BodyConstraints::ordinary())?;
        preview.record_chunk(b"abc")?;
        preview.record_chunk(b"defgh")?;
        preview.finish()?;
        assert_eq!(preview.retained_bytes(), b"abcd");
        assert_eq!(preview.total_bytes(), 8);
        assert_eq!(preview.retention(), BodyRetention::Truncated);
        assert_eq!(preview.completion(), BodyCompletion::Complete);
        assert_eq!(
            preview.record_chunk(b"later"),
            Err(BodyPreviewError::AlreadyFinished)
        );
        Ok(())
    }

    #[test]
    fn binary_reclassification_drops_previously_retained_bytes() -> Result<(), BodyPreviewError> {
        let mut preview =
            BodyPreview::new(LIMIT, BodyContentKind::Unknown, BodyConstraints::ordinary())?;
        preview.record_chunk(b"\0\x01opaque")?;
        preview.set_content_kind(BodyContentKind::Binary)?;
        preview.finish()?;
        assert!(preview.retained_bytes().is_empty());
        assert_eq!(preview.total_bytes(), 8);
        assert_eq!(preview.retention(), BodyRetention::OmittedBinary);
        Ok(())
    }

    #[test]
    fn body_and_failure_debug_and_serialization_do_not_expose_retained_text()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut preview =
            BodyPreview::new(LIMIT, BodyContentKind::Text, BodyConstraints::ordinary())?;
        preview.record_chunk(b"retained-debug-value")?;
        let debug = format!("{preview:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("retained-debug-value"));

        let failure = TransactionFailure::failed("failure-debug-value");
        let debug = format!("{failure:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("failure-debug-value"));
        let serialized = serde_json::to_string(&failure)?;
        assert!(!serialized.contains("failure-debug-value"));
        Ok(())
    }

    #[test]
    fn lifecycle_transitions_capture_response_and_terminal_outcomes()
    -> Result<(), Box<dyn std::error::Error>> {
        let request = request_with_body(completed_empty_body()?)?;
        let mut transaction = Transaction::new(
            TransactionId::new(),
            TransactionOrigin::Original,
            SystemTime::UNIX_EPOCH,
            request,
        );
        transaction.start_response(response(completed_empty_body()?), Duration::from_millis(5))?;
        transaction.complete(Duration::from_millis(8))?;
        assert_eq!(transaction.lifecycle(), &TransactionLifecycle::Completed);
        assert_eq!(
            transaction.response_started_after(),
            Some(Duration::from_millis(5))
        );
        assert_eq!(transaction.duration(), Some(Duration::from_millis(8)));
        assert_eq!(
            transaction.cancel(Duration::from_millis(9)),
            Err(TransactionUpdateError::TransactionAlreadyTerminal)
        );

        let request = request_with_body(BodyPreview::new(
            LIMIT,
            BodyContentKind::Text,
            BodyConstraints::ordinary(),
        )?)?;
        let mut cancelled = Transaction::new(
            TransactionId::new(),
            TransactionOrigin::Original,
            SystemTime::UNIX_EPOCH,
            request,
        );
        cancelled.cancel(Duration::from_secs(1))?;
        assert!(matches!(
            cancelled.lifecycle(),
            TransactionLifecycle::FailedOrCancelled(failure)
                if failure.kind() == FailureKind::Cancelled
        ));
        assert_eq!(
            cancelled.request().body().completion(),
            BodyCompletion::Incomplete
        );
        Ok(())
    }

    #[test]
    fn completion_requires_response_and_finished_bodies() -> Result<(), Box<dyn std::error::Error>>
    {
        let request = request_with_body(completed_empty_body()?)?;
        let mut transaction = Transaction::new(
            TransactionId::new(),
            TransactionOrigin::Original,
            SystemTime::UNIX_EPOCH,
            request,
        );
        assert_eq!(
            transaction.complete(Duration::ZERO),
            Err(TransactionUpdateError::InvalidLifecycleTransition)
        );
        transaction.start_response(
            response(BodyPreview::new(
                LIMIT,
                BodyContentKind::Text,
                BodyConstraints::ordinary(),
            )?),
            Duration::ZERO,
        )?;
        assert_eq!(
            transaction.complete(Duration::ZERO),
            Err(TransactionUpdateError::BodiesStillInProgress)
        );
        transaction.finish_response_body()?;
        transaction.complete(Duration::ZERO)?;
        Ok(())
    }

    #[test]
    fn replay_eligibility_has_stable_categorical_precedence()
    -> Result<(), Box<dyn std::error::Error>> {
        let eligible = Transaction::new(
            TransactionId::new(),
            TransactionOrigin::Original,
            SystemTime::UNIX_EPOCH,
            request_with_body(completed_empty_body()?)?,
        );
        assert_eq!(eligible.replay_eligibility(), ReplayEligibility::Eligible);

        let cases = [
            (
                BodyContentKind::Text,
                BodyConstraints::new(false, false, true),
                ReplayIneligibilityReason::WebSocketUpgrade,
            ),
            (
                BodyContentKind::Text,
                BodyConstraints::new(false, true, false),
                ReplayIneligibilityReason::ServerSentEvents,
            ),
            (
                BodyContentKind::Text,
                BodyConstraints::new(true, false, false),
                ReplayIneligibilityReason::StreamingRequest,
            ),
            (
                BodyContentKind::Binary,
                BodyConstraints::ordinary(),
                ReplayIneligibilityReason::BinaryRequestBody,
            ),
            (
                BodyContentKind::Unknown,
                BodyConstraints::ordinary(),
                ReplayIneligibilityReason::UnclassifiedRequestBody,
            ),
        ];

        for (content_kind, constraints, reason) in cases {
            let mut body = BodyPreview::new(LIMIT, content_kind, constraints)?;
            body.record_chunk(b"body")?;
            body.finish()?;
            let transaction = Transaction::new(
                TransactionId::new(),
                TransactionOrigin::Original,
                SystemTime::UNIX_EPOCH,
                request_with_body(body)?,
            );
            assert_eq!(
                transaction.replay_eligibility(),
                ReplayEligibility::Ineligible(reason)
            );
            assert!(!reason.code().is_empty());
        }

        let incomplete = Transaction::new(
            TransactionId::new(),
            TransactionOrigin::Original,
            SystemTime::UNIX_EPOCH,
            request_with_body(BodyPreview::new(
                LIMIT,
                BodyContentKind::Text,
                BodyConstraints::ordinary(),
            )?)?,
        );
        assert_eq!(
            incomplete.replay_eligibility(),
            ReplayEligibility::Ineligible(ReplayIneligibilityReason::IncompleteRequestBody)
        );

        let mut truncated_body =
            BodyPreview::new(2, BodyContentKind::Text, BodyConstraints::ordinary())?;
        truncated_body.record_chunk(b"long")?;
        truncated_body.finish()?;
        let truncated = Transaction::new(
            TransactionId::new(),
            TransactionOrigin::Original,
            SystemTime::UNIX_EPOCH,
            request_with_body(truncated_body)?,
        );
        assert_eq!(
            truncated.replay_eligibility(),
            ReplayEligibility::Ineligible(ReplayIneligibilityReason::TruncatedRequestBody)
        );
        Ok(())
    }

    #[test]
    fn response_sse_metadata_disables_replay() -> Result<(), Box<dyn std::error::Error>> {
        let request = request_with_body(completed_empty_body()?)?;
        let mut transaction = Transaction::new(
            TransactionId::new(),
            TransactionOrigin::Original,
            SystemTime::UNIX_EPOCH,
            request,
        );
        let response_body = BodyPreview::new(
            LIMIT,
            BodyContentKind::Text,
            BodyConstraints::new(false, true, false),
        )?;
        transaction.start_response(response(response_body), Duration::ZERO)?;
        assert_eq!(
            transaction.replay_eligibility(),
            ReplayEligibility::Ineligible(ReplayIneligibilityReason::ServerSentEvents)
        );
        Ok(())
    }

    #[test]
    fn public_request_uri_must_be_absolute() -> Result<(), BodyPreviewError> {
        let result = RequestSnapshot::new(
            Method::GET,
            Uri::from_static("/relative"),
            Version::HTTP_11,
            HeaderSnapshots::default(),
            completed_empty_body()?,
        );
        assert_eq!(result, Err(RequestSnapshotError::NonAbsolutePublicUri));
        Ok(())
    }
}
