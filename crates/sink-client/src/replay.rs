//! Explicit, exact replay of immutable retained HTTP requests.

use std::{
    error::Error as StdError,
    fmt,
    future::Future,
    pin::Pin,
    sync::Arc,
    time::{Instant, SystemTime},
};

use bytes::Bytes;
use http::{HeaderMap, Request, Response, header::CONTENT_TYPE};
use http_body_util::{BodyExt, Full, combinators::UnsyncBoxBody};
use hyper::body::Body as _;
use thiserror::Error;
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

use crate::inspection::{
    BodyConstraints, BodyContentKind, CaptureDecision, HeaderSnapshots, InspectionEventKind,
    InspectionStore, ReplayEligibility, ReplayIneligibilityReason, RequestSnapshot,
    ResponseSnapshot, Transaction, TransactionId, TransactionOrigin, is_sink_control_header,
};

const LOCAL_REWRITE_FAILURE: &str = "local request rewrite failed";
const LOCAL_CONNECT_FAILURE: &str = "local service connection failed";
const LOCAL_HANDSHAKE_FAILURE: &str = "local HTTP handshake failed";
const LOCAL_REQUEST_FAILURE: &str = "local HTTP request failed";
const RESPONSE_BODY_FAILURE: &str = "response body transfer failed";

pub(crate) type ReplayBodyError = Box<dyn StdError + Send + Sync>;
pub(crate) type ReplayRequestBody = Full<Bytes>;
pub(crate) type ReplayResponseBody = UnsyncBoxBody<Bytes, ReplayBodyError>;
pub(crate) type ReplayTransportFuture = Pin<
    Box<
        dyn Future<Output = Result<Response<ReplayResponseBody>, ReplayTransportError>>
            + Send
            + 'static,
    >,
>;

/// Direct-local request execution injected by the runtime's configured proxy.
///
/// The trait is crate-private so dashboard code cannot substitute a public
/// tunnel/control-plane transport. Its request and response types remain
/// streaming and do not require whole-body response buffering.
pub(crate) trait ReplayTransport: Send + Sync + 'static {
    fn send(&self, request: Request<ReplayRequestBody>) -> ReplayTransportFuture;
}

/// Stable local execution failures. These variants deliberately retain no
/// Hyper error or request material that could expose application secrets.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub(crate) enum ReplayTransportError {
    #[error("{LOCAL_REWRITE_FAILURE}")]
    Rewrite,
    #[error("{LOCAL_CONNECT_FAILURE}")]
    Connect,
    #[error("{LOCAL_HANDSHAKE_FAILURE}")]
    Handshake,
    #[error("{LOCAL_REQUEST_FAILURE}")]
    Request,
}

impl ReplayTransportError {
    pub(crate) const fn capture_message(self) -> &'static str {
        match self {
            Self::Rewrite => LOCAL_REWRITE_FAILURE,
            Self::Connect => LOCAL_CONNECT_FAILURE,
            Self::Handshake => LOCAL_HANDSHAKE_FAILURE,
            Self::Request => LOCAL_REQUEST_FAILURE,
        }
    }
}

/// Cloneable replay dependency for the protected dashboard mutation.
#[derive(Clone)]
pub struct ReplayService {
    store: InspectionStore,
    transport: Arc<dyn ReplayTransport>,
    tasks: Arc<ReplayTaskOwner>,
}

impl ReplayService {
    /// Construct replay from the same configured local proxy used for ordinary
    /// forwarding. Runtime integration supplies the proxy as the transport.
    #[allow(dead_code)] // Lead-owned runtime wiring consumes this crate-private seam.
    pub(crate) fn new(store: InspectionStore, transport: Arc<dyn ReplayTransport>) -> Self {
        Self {
            store,
            transport,
            tasks: Arc::new(ReplayTaskOwner {
                shutdown: CancellationToken::new(),
            }),
        }
    }

    /// Reserve a linked capture before scheduling any direct-local I/O.
    ///
    /// The explicit action is consent to resend retained application secrets.
    /// Execution and bounded response draining continue independently of the
    /// dashboard request task, so the API can return the new transaction ID
    /// without buffering a local response.
    pub fn replay(&self, source_id: TransactionId) -> Result<TransactionId, ReplayError> {
        let mut removals = self.store.subscribe();
        let source = self
            .store
            .get(source_id)
            .ok_or(ReplayError::SourceNotFound)?;
        if let ReplayEligibility::Ineligible(reason) = source.replay_eligibility() {
            return Err(ReplayError::Ineligible(reason));
        }

        let request_snapshot = replay_snapshot(&source);
        let request = replay_request(&source);
        let CaptureDecision::Captured(replay_id) = self.store.capture_at(
            TransactionOrigin::replay(source_id),
            request_snapshot,
            SystemTime::now(),
        ) else {
            return Err(ReplayError::CapturePaused);
        };

        let store = self.store.clone();
        let transport = self.transport.clone();
        let shutdown = self.tasks.shutdown.clone();
        drop(tokio::spawn(async move {
            execute_and_capture(
                store,
                transport,
                replay_id,
                request,
                shutdown,
                &mut removals,
            )
            .await;
        }));
        Ok(replay_id)
    }
}

struct ReplayTaskOwner {
    shutdown: CancellationToken,
}

impl Drop for ReplayTaskOwner {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

impl fmt::Debug for ReplayService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReplayService")
            .field("store", &self.store)
            .field("transport", &"[DIRECT LOCAL TRANSPORT]")
            .finish()
    }
}

/// A replay rejection that occurs before any local request is sent.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum ReplayError {
    #[error("the source transaction is no longer retained")]
    SourceNotFound,
    #[error("request is not eligible for replay: {}", .0.code())]
    Ineligible(ReplayIneligibilityReason),
    #[error("capture is paused; replay was not sent")]
    CapturePaused,
}

impl ReplayError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::SourceNotFound => "transaction_not_found",
            Self::Ineligible(reason) => reason.code(),
            Self::CapturePaused => "capture_paused",
        }
    }

    #[must_use]
    pub const fn replay_reason(self) -> Option<ReplayIneligibilityReason> {
        match self {
            Self::Ineligible(reason) => Some(reason),
            Self::SourceNotFound | Self::CapturePaused => None,
        }
    }
}

fn replay_snapshot(source: &Transaction) -> RequestSnapshot {
    RequestSnapshot::new(
        source.request().method().clone(),
        source.request().public_uri().clone(),
        source.request().version(),
        replay_headers(source),
        source.request().body().clone(),
    )
    .expect("a retained source already contains a validated absolute public URI")
}

fn replay_request(source: &Transaction) -> Request<ReplayRequestBody> {
    let mut request = Request::new(Full::new(Bytes::copy_from_slice(
        source.request().body().retained_bytes(),
    )));
    *request.method_mut() = source.request().method().clone();
    *request.uri_mut() = source.request().public_uri().clone();
    *request.version_mut() = source.request().version();
    for header in replay_headers(source).iter() {
        request
            .headers_mut()
            .append(header.name().clone(), header.value().clone());
    }
    request
}

fn replay_headers(source: &Transaction) -> HeaderSnapshots {
    source
        .request()
        .headers()
        .iter()
        .filter(|header| !is_sink_control_header(header.name()))
        .cloned()
        .collect()
}

async fn execute_and_capture(
    store: InspectionStore,
    transport: Arc<dyn ReplayTransport>,
    replay_id: TransactionId,
    request: Request<ReplayRequestBody>,
    shutdown: CancellationToken,
    removals: &mut broadcast::Receiver<crate::inspection::InspectionEvent>,
) {
    let started = Instant::now();
    let sent = tokio::select! {
        biased;
        () = shutdown.cancelled() => {
            let _ = store.cancel(replay_id, started.elapsed());
            return;
        }
        () = wait_until_removed(&store, removals, replay_id) => return,
        result = transport.send(request) => result,
    };
    let mut response = match sent {
        Ok(response) => response,
        Err(error) => {
            let _ = store.fail(replay_id, started.elapsed(), error.capture_message());
            return;
        }
    };

    let snapshot = response_snapshot(&store, &response);
    if store
        .start_response(replay_id, snapshot, started.elapsed())
        .is_err()
    {
        return;
    }
    loop {
        let frame = tokio::select! {
            biased;
            () = shutdown.cancelled() => {
                let _ = store.cancel(replay_id, started.elapsed());
                return;
            }
            () = wait_until_removed(&store, removals, replay_id) => return,
            frame = response.body_mut().frame() => frame,
        };
        let Some(frame) = frame else {
            break;
        };
        match frame {
            Ok(frame) => {
                if let Some(data) = frame.data_ref()
                    && store.record_response_body_chunk(replay_id, data).is_err()
                {
                    return;
                }
            }
            Err(_) => {
                let _ = store.mark_response_body_incomplete(replay_id);
                let _ = store.fail(replay_id, started.elapsed(), RESPONSE_BODY_FAILURE);
                return;
            }
        }
    }

    if store.finish_response_body(replay_id).is_ok() {
        let _ = store.complete(replay_id, started.elapsed());
    }
}

async fn wait_until_removed(
    store: &InspectionStore,
    removals: &mut broadcast::Receiver<crate::inspection::InspectionEvent>,
    replay_id: TransactionId,
) {
    loop {
        if store.inspect(replay_id, |_| ()).is_none() {
            return;
        }
        match removals.recv().await {
            Ok(event) => match event.kind() {
                InspectionEventKind::TransactionRemoved { id, .. } if id == replay_id => return,
                InspectionEventKind::Cleared { .. } => return,
                _ => {}
            },
            Err(broadcast::error::RecvError::Lagged(_)) => {}
            Err(broadcast::error::RecvError::Closed) => return,
        }
    }
}

fn response_snapshot(
    store: &InspectionStore,
    response: &Response<ReplayResponseBody>,
) -> ResponseSnapshot {
    let content_kind = BodyContentKind::from_content_type(response.headers().get(CONTENT_TYPE));
    let server_sent_events = is_server_sent_events(response.headers());
    let streaming = server_sent_events
        || (!response.body().is_end_stream() && response.body().size_hint().exact().is_none());
    let body = store.body_preview(
        content_kind,
        BodyConstraints::new(streaming, server_sent_events, false),
    );
    ResponseSnapshot::new(
        response.status(),
        response.version(),
        HeaderSnapshots::capture(response.headers()),
        body,
    )
}

fn is_server_sent_events(headers: &HeaderMap) -> bool {
    headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("text/event-stream"))
}

#[cfg(test)]
mod tests {
    use std::{
        convert::Infallible,
        future::pending,
        io,
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use futures::stream;
    use http::{HeaderName, HeaderValue, Method, StatusCode, Uri, Version, header::AUTHORIZATION};
    use http_body_util::{Empty, StreamBody};
    use hyper::body::Frame;
    use tokio::sync::Notify;
    use tokio::time::timeout;

    use super::*;
    use crate::inspection::{
        BodyCompletion, BodyRetention, HeaderSnapshot, InspectionLimits, TransactionLifecycle,
    };

    type TestResult<T = ()> = Result<T, Box<dyn StdError>>;

    #[derive(Default)]
    struct RecordingTransport {
        sends: Arc<AtomicUsize>,
        requests: Arc<Mutex<Vec<ObservedRequest>>>,
        failure: Option<ReplayTransportError>,
    }

    #[derive(Debug)]
    struct ObservedRequest {
        method: Method,
        uri: Uri,
        version: Version,
        headers: HeaderSnapshots,
        body: Bytes,
    }

    impl RecordingTransport {
        fn failing(failure: ReplayTransportError) -> Self {
            Self {
                failure: Some(failure),
                ..Self::default()
            }
        }
    }

    impl ReplayTransport for RecordingTransport {
        fn send(&self, request: Request<ReplayRequestBody>) -> ReplayTransportFuture {
            let sends = self.sends.clone();
            let requests = self.requests.clone();
            let failure = self.failure;
            Box::pin(async move {
                sends.fetch_add(1, Ordering::SeqCst);
                let (parts, body) = request.into_parts();
                let body = body
                    .collect()
                    .await
                    .map_err(|never| match never {})?
                    .to_bytes();
                requests
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(ObservedRequest {
                        method: parts.method,
                        uri: parts.uri,
                        version: parts.version,
                        headers: HeaderSnapshots::capture(&parts.headers),
                        body,
                    });
                if let Some(failure) = failure {
                    return Err(failure);
                }
                Ok(Response::builder()
                    .status(StatusCode::CREATED)
                    .header(CONTENT_TYPE, "text/plain")
                    .body(
                        Empty::<Bytes>::new()
                            .map_err(|never: Infallible| match never {})
                            .boxed_unsync(),
                    )
                    .unwrap_or_else(|_| {
                        Response::new(
                            Empty::new()
                                .map_err(|never: Infallible| match never {})
                                .boxed_unsync(),
                        )
                    }))
            })
        }
    }

    struct FailingResponseBodyTransport;

    impl ReplayTransport for FailingResponseBodyTransport {
        fn send(&self, _request: Request<ReplayRequestBody>) -> ReplayTransportFuture {
            Box::pin(async {
                let frames = stream::iter([
                    Ok(Frame::data(Bytes::from_static(b"partial"))),
                    Err(io::Error::other("body failed with secret-like diagnostics")),
                ]);
                let body: ReplayResponseBody = StreamBody::new(frames)
                    .map_err(|error| -> ReplayBodyError { Box::new(error) })
                    .boxed_unsync();
                Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header(CONTENT_TYPE, "text/plain")
                    .body(body)
                    .unwrap_or_else(|_| {
                        Response::new(
                            Empty::<Bytes>::new()
                                .map_err(|never: Infallible| match never {})
                                .boxed_unsync(),
                        )
                    }))
            })
        }
    }

    #[derive(Default)]
    struct PendingTransport {
        started: Notify,
        dropped: Arc<AtomicUsize>,
    }

    struct DropProbe(Arc<AtomicUsize>);

    impl Drop for DropProbe {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl ReplayTransport for PendingTransport {
        fn send(&self, request: Request<ReplayRequestBody>) -> ReplayTransportFuture {
            let drop_probe = DropProbe(self.dropped.clone());
            self.started.notify_one();
            Box::pin(async move {
                let _request = request;
                let _drop_probe = drop_probe;
                pending::<Result<Response<ReplayResponseBody>, ReplayTransportError>>().await
            })
        }
    }

    fn source_snapshot(
        store: &InspectionStore,
        content_kind: BodyContentKind,
        constraints: BodyConstraints,
        body_bytes: &[u8],
        complete: bool,
        headers: HeaderSnapshots,
    ) -> TestResult<RequestSnapshot> {
        let mut body = store.body_preview(content_kind, constraints);
        body.record_chunk(body_bytes)?;
        if complete {
            body.finish()?;
        }
        Ok(RequestSnapshot::new(
            Method::PATCH,
            "https://public.example.test/orders/%2Fraw?draft=true".parse()?,
            Version::HTTP_11,
            headers,
            body,
        )?)
    }

    fn capture_source(
        store: &InspectionStore,
        content_kind: BodyContentKind,
        constraints: BodyConstraints,
        body_bytes: &[u8],
        complete: bool,
    ) -> TestResult<TransactionId> {
        store
            .capture(
                TransactionOrigin::Original,
                source_snapshot(
                    store,
                    content_kind,
                    constraints,
                    body_bytes,
                    complete,
                    HeaderSnapshots::default(),
                )?,
            )
            .captured_id()
            .ok_or_else(|| io::Error::other("source capture unexpectedly paused").into())
    }

    async fn wait_terminal(store: &InspectionStore, id: TransactionId) -> TestResult<Transaction> {
        timeout(Duration::from_secs(1), async {
            loop {
                if let Some(transaction) = store.get(id)
                    && transaction.lifecycle().is_terminal()
                {
                    return transaction;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .map_err(Into::into)
    }

    async fn pending_replay(
        transaction_limit: usize,
    ) -> TestResult<(
        InspectionStore,
        ReplayService,
        TransactionId,
        Arc<PendingTransport>,
    )> {
        let store = InspectionStore::new(InspectionLimits::new(transaction_limit, 64)?);
        let source_id = capture_source(
            &store,
            BodyContentKind::Text,
            BodyConstraints::ordinary(),
            b"bounded-body",
            true,
        )?;
        let transport = Arc::new(PendingTransport::default());
        let replay = ReplayService::new(store.clone(), transport.clone());
        let replay_id = replay.replay(source_id)?;
        timeout(Duration::from_secs(1), transport.started.notified()).await?;
        Ok((store, replay, replay_id, transport))
    }

    async fn wait_for_pending_transport_drop(transport: &PendingTransport) -> TestResult {
        timeout(Duration::from_secs(1), async {
            while transport.dropped.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        Ok(())
    }

    #[tokio::test]
    async fn eligible_request_preserves_application_secrets_and_filters_sink_control_headers()
    -> TestResult {
        let store = InspectionStore::new(InspectionLimits::new(8, 1024)?);
        let headers = HeaderSnapshots::from_entries([
            HeaderSnapshot::new(AUTHORIZATION, HeaderValue::from_static("Bearer app-secret")),
            HeaderSnapshot::new(
                HeaderName::from_static("x-repeat"),
                HeaderValue::from_static("first"),
            ),
            HeaderSnapshot::new(
                HeaderName::from_static("x-repeat"),
                HeaderValue::from_static("second"),
            ),
            HeaderSnapshot::new(
                HeaderName::from_static("x-sink-inspector-token"),
                HeaderValue::from_static("must-not-send"),
            ),
        ]);
        let source_id = store
            .capture(
                TransactionOrigin::Original,
                source_snapshot(
                    &store,
                    BodyContentKind::Json,
                    BodyConstraints::ordinary(),
                    br#"{"exact":true}"#,
                    true,
                    headers,
                )?,
            )
            .captured_id()
            .ok_or_else(|| io::Error::other("source capture unexpectedly paused"))?;
        let transport = Arc::new(RecordingTransport::default());
        let replay = ReplayService::new(store.clone(), transport.clone());
        let replay_id = replay.replay(source_id)?;
        let transaction = wait_terminal(&store, replay_id).await?;

        assert_eq!(transaction.origin(), TransactionOrigin::replay(source_id));
        assert_eq!(transaction.lifecycle(), &TransactionLifecycle::Completed);
        assert_eq!(transport.sends.load(Ordering::SeqCst), 1);
        let requests = transport
            .requests
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let request = requests.first().ok_or("request was not observed")?;
        assert_eq!(request.method, Method::PATCH);
        assert_eq!(request.version, Version::HTTP_11);
        assert_eq!(
            request.uri,
            "https://public.example.test/orders/%2Fraw?draft=true"
        );
        assert_eq!(request.body, br#"{"exact":true}"#.as_slice());
        assert_eq!(
            request
                .headers
                .iter()
                .filter(|header| header.name() == "x-repeat")
                .map(|header| header.value())
                .collect::<Vec<_>>(),
            ["first", "second"]
        );
        assert_eq!(
            request
                .headers
                .iter()
                .find(|header| header.name() == AUTHORIZATION)
                .map(|header| header.value()),
            Some(&HeaderValue::from_static("Bearer app-secret"))
        );
        assert!(
            request
                .headers
                .iter()
                .all(|header| !is_sink_control_header(header.name()))
        );
        assert!(
            transaction
                .request()
                .headers()
                .iter()
                .all(|header| !is_sink_control_header(header.name()))
        );
        Ok(())
    }

    #[test]
    fn all_stable_ineligibility_reasons_reject_without_a_send() -> TestResult {
        let cases = [
            (
                BodyContentKind::Text,
                BodyConstraints::new(false, false, true),
                b"body".as_slice(),
                true,
                ReplayIneligibilityReason::WebSocketUpgrade,
            ),
            (
                BodyContentKind::Text,
                BodyConstraints::new(false, true, false),
                b"body".as_slice(),
                true,
                ReplayIneligibilityReason::ServerSentEvents,
            ),
            (
                BodyContentKind::Text,
                BodyConstraints::new(true, false, false),
                b"body".as_slice(),
                true,
                ReplayIneligibilityReason::StreamingRequest,
            ),
            (
                BodyContentKind::Binary,
                BodyConstraints::ordinary(),
                b"body".as_slice(),
                true,
                ReplayIneligibilityReason::BinaryRequestBody,
            ),
            (
                BodyContentKind::Unknown,
                BodyConstraints::ordinary(),
                b"body".as_slice(),
                true,
                ReplayIneligibilityReason::UnclassifiedRequestBody,
            ),
            (
                BodyContentKind::Text,
                BodyConstraints::ordinary(),
                b"body".as_slice(),
                false,
                ReplayIneligibilityReason::IncompleteRequestBody,
            ),
        ];

        for (content_kind, constraints, body, complete, expected) in cases {
            let store = InspectionStore::new(InspectionLimits::new(4, 64)?);
            let source_id = capture_source(&store, content_kind, constraints, body, complete)?;
            let transport = Arc::new(RecordingTransport::default());
            let replay = ReplayService::new(store.clone(), transport.clone());
            assert_eq!(
                replay.replay(source_id),
                Err(ReplayError::Ineligible(expected))
            );
            assert_eq!(expected.code(), ReplayError::Ineligible(expected).code());
            assert_eq!(transport.sends.load(Ordering::SeqCst), 0);
            assert_eq!(store.len(), 1);
        }

        let store = InspectionStore::new(InspectionLimits::new(4, 3)?);
        let source_id = capture_source(
            &store,
            BodyContentKind::Text,
            BodyConstraints::ordinary(),
            b"four",
            true,
        )?;
        let transport = Arc::new(RecordingTransport::default());
        let replay = ReplayService::new(store.clone(), transport.clone());
        assert_eq!(
            replay.replay(source_id),
            Err(ReplayError::Ineligible(
                ReplayIneligibilityReason::TruncatedRequestBody
            ))
        );
        assert_eq!(transport.sends.load(Ordering::SeqCst), 0);
        assert_eq!(store.len(), 1);
        Ok(())
    }

    #[test]
    fn missing_source_and_paused_capture_reject_before_sending() -> TestResult {
        let store = InspectionStore::new(InspectionLimits::new(4, 64)?);
        let transport = Arc::new(RecordingTransport::default());
        let replay = ReplayService::new(store.clone(), transport.clone());
        assert_eq!(
            replay.replay(TransactionId::new()),
            Err(ReplayError::SourceNotFound)
        );

        let source_id = capture_source(
            &store,
            BodyContentKind::Text,
            BodyConstraints::ordinary(),
            b"body",
            true,
        )?;
        store.pause();
        assert_eq!(replay.replay(source_id), Err(ReplayError::CapturePaused));
        assert_eq!(transport.sends.load(Ordering::SeqCst), 0);
        assert_eq!(store.len(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn local_failure_is_terminal_and_debug_error_paths_do_not_expose_secrets() -> TestResult {
        let store = InspectionStore::new(InspectionLimits::new(4, 64)?);
        let headers = HeaderSnapshots::from_entries([HeaderSnapshot::new(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer never-log-this"),
        )]);
        let source_id = store
            .capture(
                TransactionOrigin::Original,
                source_snapshot(
                    &store,
                    BodyContentKind::Text,
                    BodyConstraints::ordinary(),
                    b"body-secret",
                    true,
                    headers,
                )?,
            )
            .captured_id()
            .ok_or_else(|| io::Error::other("source capture unexpectedly paused"))?;
        let transport = Arc::new(RecordingTransport::failing(ReplayTransportError::Connect));
        let replay = ReplayService::new(store.clone(), transport);
        assert!(!format!("{replay:?}").contains("never-log-this"));
        let replay_id = replay.replay(source_id)?;
        let transaction = wait_terminal(&store, replay_id).await?;
        assert!(matches!(
            transaction.lifecycle(),
            TransactionLifecycle::FailedOrCancelled(failure)
                if failure.message() == Some(LOCAL_CONNECT_FAILURE)
        ));
        let debug = format!(
            "{transaction:?} {replay:?} {:?}",
            ReplayError::CapturePaused
        );
        assert!(!debug.contains("never-log-this"));
        assert!(!debug.contains("body-secret"));
        assert_eq!(
            transaction.request().body().completion(),
            BodyCompletion::Complete
        );
        assert_eq!(
            transaction.request().body().retention(),
            BodyRetention::Retained
        );
        Ok(())
    }

    #[tokio::test]
    async fn response_body_failure_keeps_bounded_preview_and_records_only_a_stable_error()
    -> TestResult {
        let store = InspectionStore::new(InspectionLimits::new(4, 4)?);
        let source_id = capture_source(
            &store,
            BodyContentKind::Text,
            BodyConstraints::ordinary(),
            b"body",
            true,
        )?;
        let replay = ReplayService::new(store.clone(), Arc::new(FailingResponseBodyTransport));
        let replay_id = replay.replay(source_id)?;
        let transaction = wait_terminal(&store, replay_id).await?;
        let response = transaction.response().ok_or("response metadata missing")?;
        assert_eq!(response.body().retained_bytes(), b"part");
        assert_eq!(response.body().total_bytes(), 7);
        assert_eq!(response.body().completion(), BodyCompletion::Incomplete);
        assert!(matches!(
            transaction.lifecycle(),
            TransactionLifecycle::FailedOrCancelled(failure)
                if failure.message() == Some(RESPONSE_BODY_FAILURE)
        ));
        let debug = format!("{transaction:?}");
        assert!(!debug.contains("secret-like diagnostics"));
        Ok(())
    }

    #[tokio::test]
    async fn delete_clear_eviction_and_service_drop_cancel_pending_replay_ownership() -> TestResult
    {
        let (store, _replay, replay_id, transport) = pending_replay(4).await?;
        assert!(store.delete(replay_id));
        wait_for_pending_transport_drop(&transport).await?;

        let (store, _replay, _replay_id, transport) = pending_replay(4).await?;
        assert!(store.clear() > 0);
        wait_for_pending_transport_drop(&transport).await?;

        let (store, _replay, replay_id, transport) = pending_replay(2).await?;
        let _ = capture_source(
            &store,
            BodyContentKind::Text,
            BodyConstraints::ordinary(),
            b"replacement-one",
            true,
        )?;
        let _ = capture_source(
            &store,
            BodyContentKind::Text,
            BodyConstraints::ordinary(),
            b"replacement-two",
            true,
        )?;
        assert!(store.get(replay_id).is_none());
        wait_for_pending_transport_drop(&transport).await?;

        let (store, replay, replay_id, transport) = pending_replay(4).await?;
        drop(replay);
        wait_for_pending_transport_drop(&transport).await?;
        let transaction = store
            .get(replay_id)
            .ok_or_else(|| io::Error::other("cancelled replay capture was not retained"))?;
        assert!(matches!(
            transaction.lifecycle(),
            TransactionLifecycle::FailedOrCancelled(failure)
                if failure.kind() == crate::inspection::FailureKind::Cancelled
        ));
        Ok(())
    }
}
