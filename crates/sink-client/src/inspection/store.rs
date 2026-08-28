//! Thread-safe, bounded in-memory retention for inspection transactions.

use std::{
    collections::{HashMap, VecDeque},
    num::NonZeroUsize,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, SystemTime},
};

use thiserror::Error;
use tokio::sync::broadcast;

use super::{
    BodyConstraints, BodyContentKind, BodyPreview, RequestSnapshot, ResponseSnapshot, Transaction,
    TransactionId, TransactionOrigin, TransactionUpdateError,
};

pub const DEFAULT_TRANSACTION_LIMIT: usize = 100;
pub const DEFAULT_BODY_PREVIEW_LIMIT: usize = 1024 * 1024;
pub const DEFAULT_EVENT_CAPACITY: usize = 256;

/// Validated process-local inspection retention limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InspectionLimits {
    transaction_limit: NonZeroUsize,
    body_preview_limit: NonZeroUsize,
    event_capacity: NonZeroUsize,
}

impl InspectionLimits {
    pub fn new(
        transaction_limit: usize,
        body_preview_limit: usize,
    ) -> Result<Self, InspectionLimitError> {
        Self::with_event_capacity(
            transaction_limit,
            body_preview_limit,
            DEFAULT_EVENT_CAPACITY,
        )
    }

    pub fn with_event_capacity(
        transaction_limit: usize,
        body_preview_limit: usize,
        event_capacity: usize,
    ) -> Result<Self, InspectionLimitError> {
        Ok(Self {
            transaction_limit: NonZeroUsize::new(transaction_limit)
                .ok_or(InspectionLimitError::ZeroTransactionLimit)?,
            body_preview_limit: NonZeroUsize::new(body_preview_limit)
                .ok_or(InspectionLimitError::ZeroBodyPreviewLimit)?,
            event_capacity: NonZeroUsize::new(event_capacity)
                .ok_or(InspectionLimitError::ZeroEventCapacity)?,
        })
    }

    #[must_use]
    pub const fn transaction_limit(self) -> usize {
        self.transaction_limit.get()
    }

    #[must_use]
    pub const fn body_preview_limit(self) -> usize {
        self.body_preview_limit.get()
    }

    #[must_use]
    pub const fn event_capacity(self) -> usize {
        self.event_capacity.get()
    }
}

impl Default for InspectionLimits {
    fn default() -> Self {
        match Self::new(DEFAULT_TRANSACTION_LIMIT, DEFAULT_BODY_PREVIEW_LIMIT) {
            Ok(limits) => limits,
            Err(_) => unreachable!("inspection defaults are non-zero constants"),
        }
    }
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum InspectionLimitError {
    #[error("inspection transaction limit must be greater than zero")]
    ZeroTransactionLimit,
    #[error("inspection body preview limit must be greater than zero")]
    ZeroBodyPreviewLimit,
    #[error("inspection event capacity must be greater than zero")]
    ZeroEventCapacity,
}

/// Why an entry left the retained transaction set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RemovalCause {
    Deleted,
    Evicted,
}

/// A compact event; consumers fetch current snapshots and recover from lag by listing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InspectionEvent {
    sequence: u64,
    kind: InspectionEventKind,
}

impl InspectionEvent {
    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub const fn kind(self) -> InspectionEventKind {
        self.kind
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InspectionEventKind {
    TransactionCreated(TransactionId),
    TransactionUpdated(TransactionId),
    TransactionRemoved {
        id: TransactionId,
        cause: RemovalCause,
    },
    Cleared {
        removed: usize,
    },
    CaptureStateChanged {
        paused: bool,
    },
}

/// Atomic result of attempting to begin capture for a received request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaptureDecision {
    Captured(TransactionId),
    Paused,
}

impl CaptureDecision {
    #[must_use]
    pub const fn captured_id(self) -> Option<TransactionId> {
        match self {
            Self::Captured(id) => Some(id),
            Self::Paused => None,
        }
    }
}

/// Cloneable access to a memory-only transaction store.
///
/// The event stream uses Tokio's bounded broadcast channel. Sending is
/// synchronous and never waits for receivers; lagged consumers receive a
/// `Lagged` error and can recover by calling [`Self::list`].
#[derive(Clone)]
pub struct InspectionStore {
    shared: Arc<Shared>,
}

impl std::fmt::Debug for InspectionStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let inner = self.lock_inner();
        formatter
            .debug_struct("InspectionStore")
            .field("limits", &self.shared.limits)
            .field("paused", &inner.paused)
            .field("len", &inner.transactions.len())
            .field("event_sequence", &inner.event_sequence)
            .finish()
    }
}

impl InspectionStore {
    #[must_use]
    pub fn new(limits: InspectionLimits) -> Self {
        let (events, _) = broadcast::channel(limits.event_capacity());
        Self {
            shared: Arc::new(Shared {
                limits,
                inner: Mutex::new(Inner::default()),
                events,
            }),
        }
    }

    #[must_use]
    pub fn limits(&self) -> InspectionLimits {
        self.shared.limits
    }

    /// Create an in-progress preview using this store's configured byte bound.
    #[must_use]
    pub fn body_preview(
        &self,
        content_kind: BodyContentKind,
        constraints: BodyConstraints,
    ) -> BodyPreview {
        BodyPreview::from_nonzero_limit(
            self.shared.limits.body_preview_limit,
            content_kind,
            constraints,
        )
    }

    /// Atomically check pause state and retain a newly received transaction.
    #[must_use]
    pub fn capture(&self, origin: TransactionOrigin, request: RequestSnapshot) -> CaptureDecision {
        self.capture_at(origin, request, SystemTime::now())
    }

    /// Variant of [`Self::capture`] for a timestamp taken at the proxy boundary.
    #[must_use]
    pub fn capture_at(
        &self,
        origin: TransactionOrigin,
        request: RequestSnapshot,
        received_at: SystemTime,
    ) -> CaptureDecision {
        let mut inner = self.lock_inner();
        if inner.paused {
            return CaptureDecision::Paused;
        }

        let id = TransactionId::new();
        let mut transaction = Transaction::new(id, origin, received_at, request);
        transaction.clamp_body_limits(self.shared.limits.body_preview_limit);
        inner.transactions.insert(id, transaction);
        inner.oldest_first.push_back(id);

        if inner.transactions.len() > self.shared.limits.transaction_limit()
            && let Some(evicted) = inner.oldest_first.pop_front()
        {
            inner.transactions.remove(&evicted);
            self.publish_locked(
                &mut inner,
                InspectionEventKind::TransactionRemoved {
                    id: evicted,
                    cause: RemovalCause::Evicted,
                },
            );
        }
        self.publish_locked(&mut inner, InspectionEventKind::TransactionCreated(id));
        CaptureDecision::Captured(id)
    }

    /// Return one current point-in-time snapshot.
    #[must_use]
    pub fn get(&self, id: TransactionId) -> Option<Transaction> {
        self.lock_inner().transactions.get(&id).cloned()
    }

    /// Return retained identities newest first without cloning transaction bodies.
    #[must_use]
    pub fn list_ids_newest_first(&self) -> Vec<TransactionId> {
        self.lock_inner()
            .oldest_first
            .iter()
            .rev()
            .copied()
            .collect()
    }

    /// Inspect one retained transaction while briefly holding the store lock.
    ///
    /// Callbacks must remain lightweight and must not call back into this store.
    /// This lets metadata consumers build summaries without cloning body previews.
    pub fn inspect<R>(
        &self,
        id: TransactionId,
        inspect: impl FnOnce(&Transaction) -> R,
    ) -> Option<R> {
        self.lock_inner().transactions.get(&id).map(inspect)
    }

    /// Return current snapshots newest first.
    #[must_use]
    pub fn list(&self) -> Vec<Transaction> {
        let inner = self.lock_inner();
        inner
            .oldest_first
            .iter()
            .rev()
            .filter_map(|id| inner.transactions.get(id).cloned())
            .collect()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.lock_inner().transactions.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.lock_inner().transactions.is_empty()
    }

    #[must_use]
    pub fn is_paused(&self) -> bool {
        self.lock_inner().paused
    }

    pub fn pause(&self) {
        self.set_paused(true);
    }

    pub fn resume(&self) {
        self.set_paused(false);
    }

    /// Delete one entry. Later updates return `TransactionNotFound` and cannot recreate it.
    pub fn delete(&self, id: TransactionId) -> bool {
        let mut inner = self.lock_inner();
        if inner.transactions.remove(&id).is_none() {
            return false;
        }
        if let Some(index) = inner
            .oldest_first
            .iter()
            .position(|candidate| *candidate == id)
        {
            inner.oldest_first.remove(index);
        }
        self.publish_locked(
            &mut inner,
            InspectionEventKind::TransactionRemoved {
                id,
                cause: RemovalCause::Deleted,
            },
        );
        true
    }

    /// Clear every retained entry and return the number released by the store.
    pub fn clear(&self) -> usize {
        let mut inner = self.lock_inner();
        let removed = inner.transactions.len();
        inner.transactions.clear();
        inner.oldest_first.clear();
        self.publish_locked(&mut inner, InspectionEventKind::Cleared { removed });
        removed
    }

    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<InspectionEvent> {
        self.shared.events.subscribe()
    }

    pub fn record_request_body_chunk(
        &self,
        id: TransactionId,
        chunk: &[u8],
    ) -> Result<(), StoreUpdateError> {
        self.mutate(id, |transaction| {
            transaction.record_request_body_chunk(chunk)
        })
    }

    pub fn set_request_body_content_kind(
        &self,
        id: TransactionId,
        content_kind: BodyContentKind,
    ) -> Result<(), StoreUpdateError> {
        self.mutate(id, |transaction| {
            transaction.set_request_body_content_kind(content_kind)
        })
    }

    pub fn set_request_body_constraints(
        &self,
        id: TransactionId,
        constraints: BodyConstraints,
    ) -> Result<(), StoreUpdateError> {
        self.mutate(id, |transaction| {
            transaction.set_request_body_constraints(constraints)
        })
    }

    pub fn finish_request_body(&self, id: TransactionId) -> Result<(), StoreUpdateError> {
        self.mutate(id, Transaction::finish_request_body)
    }

    pub fn mark_request_body_incomplete(&self, id: TransactionId) -> Result<(), StoreUpdateError> {
        self.mutate(id, Transaction::mark_request_body_incomplete)
    }

    pub fn start_response(
        &self,
        id: TransactionId,
        mut response: ResponseSnapshot,
        elapsed: Duration,
    ) -> Result<(), StoreUpdateError> {
        response
            .body_mut()
            .clamp_limit(self.shared.limits.body_preview_limit);
        self.mutate(id, move |transaction| {
            transaction.start_response(response, elapsed)
        })
    }

    pub fn record_response_body_chunk(
        &self,
        id: TransactionId,
        chunk: &[u8],
    ) -> Result<(), StoreUpdateError> {
        self.mutate(id, |transaction| {
            transaction.record_response_body_chunk(chunk)
        })
    }

    pub fn set_response_body_content_kind(
        &self,
        id: TransactionId,
        content_kind: BodyContentKind,
    ) -> Result<(), StoreUpdateError> {
        self.mutate(id, |transaction| {
            transaction.set_response_body_content_kind(content_kind)
        })
    }

    pub fn set_response_body_constraints(
        &self,
        id: TransactionId,
        constraints: BodyConstraints,
    ) -> Result<(), StoreUpdateError> {
        self.mutate(id, |transaction| {
            transaction.set_response_body_constraints(constraints)
        })
    }

    pub fn finish_response_body(&self, id: TransactionId) -> Result<(), StoreUpdateError> {
        self.mutate(id, Transaction::finish_response_body)
    }

    pub fn mark_response_body_incomplete(&self, id: TransactionId) -> Result<(), StoreUpdateError> {
        self.mutate(id, Transaction::mark_response_body_incomplete)
    }

    pub fn complete(&self, id: TransactionId, duration: Duration) -> Result<(), StoreUpdateError> {
        self.mutate(id, |transaction| transaction.complete(duration))
    }

    pub(crate) fn fail(
        &self,
        id: TransactionId,
        duration: Duration,
        message: &'static str,
    ) -> Result<(), StoreUpdateError> {
        self.mutate(id, move |transaction| transaction.fail(duration, message))
    }

    pub fn cancel(&self, id: TransactionId, duration: Duration) -> Result<(), StoreUpdateError> {
        self.mutate(id, |transaction| transaction.cancel(duration))
    }

    pub fn upgrade(&self, id: TransactionId, duration: Duration) -> Result<(), StoreUpdateError> {
        self.mutate(id, |transaction| transaction.upgrade(duration))
    }

    fn set_paused(&self, paused: bool) {
        let mut inner = self.lock_inner();
        if inner.paused == paused {
            return;
        }
        inner.paused = paused;
        self.publish_locked(
            &mut inner,
            InspectionEventKind::CaptureStateChanged { paused },
        );
    }

    fn mutate(
        &self,
        id: TransactionId,
        mutation: impl FnOnce(&mut Transaction) -> Result<(), TransactionUpdateError>,
    ) -> Result<(), StoreUpdateError> {
        let mut inner = self.lock_inner();
        let transaction = inner
            .transactions
            .get_mut(&id)
            .ok_or(StoreUpdateError::TransactionNotFound(id))?;
        mutation(transaction)?;
        self.publish_locked(&mut inner, InspectionEventKind::TransactionUpdated(id));
        Ok(())
    }

    fn publish_locked(&self, inner: &mut Inner, kind: InspectionEventKind) {
        inner.event_sequence = inner.event_sequence.saturating_add(1);
        let event = InspectionEvent {
            sequence: inner.event_sequence,
            kind,
        };
        drop(self.shared.events.send(event));
    }

    fn lock_inner(&self) -> MutexGuard<'_, Inner> {
        self.shared
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl Default for InspectionStore {
    fn default() -> Self {
        Self::new(InspectionLimits::default())
    }
}

struct Shared {
    limits: InspectionLimits,
    inner: Mutex<Inner>,
    events: broadcast::Sender<InspectionEvent>,
}

#[derive(Default)]
struct Inner {
    transactions: HashMap<TransactionId, Transaction>,
    oldest_first: VecDeque<TransactionId>,
    paused: bool,
    event_sequence: u64,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum StoreUpdateError {
    #[error("inspection transaction {0} is no longer retained")]
    TransactionNotFound(TransactionId),
    #[error(transparent)]
    InvalidUpdate(#[from] TransactionUpdateError),
}

#[cfg(test)]
mod tests {
    use std::{
        io,
        sync::{Arc, Barrier},
        thread,
    };

    use http::{Method, StatusCode, Uri, Version};
    use tokio::sync::broadcast::error::TryRecvError;

    use super::*;
    use crate::inspection::{
        BodyCompletion, HeaderSnapshots, RequestSnapshotError, TransactionLifecycle,
    };

    fn request(
        store: &InspectionStore,
        path: &str,
        body_complete: bool,
    ) -> Result<RequestSnapshot, Box<dyn std::error::Error>> {
        let mut body = store.body_preview(BodyContentKind::Text, BodyConstraints::ordinary());
        if body_complete {
            body.finish()?;
        }
        Ok(RequestSnapshot::new(
            Method::GET,
            format!("https://public.example.test{path}").parse::<Uri>()?,
            Version::HTTP_11,
            HeaderSnapshots::default(),
            body,
        )?)
    }

    fn captured_id(decision: CaptureDecision) -> Result<TransactionId, io::Error> {
        decision
            .captured_id()
            .ok_or_else(|| io::Error::other("capture was unexpectedly paused"))
    }

    fn response(store: &InspectionStore, body_complete: bool) -> ResponseSnapshot {
        let mut body = store.body_preview(BodyContentKind::Text, BodyConstraints::ordinary());
        if body_complete {
            let result = body.finish();
            debug_assert!(result.is_ok());
        }
        ResponseSnapshot::new(
            StatusCode::OK,
            Version::HTTP_11,
            HeaderSnapshots::default(),
            body,
        )
    }

    #[test]
    fn limits_validate_and_defaults_match_the_product_contract() {
        let defaults = InspectionLimits::default();
        assert_eq!(defaults.transaction_limit(), 100);
        assert_eq!(defaults.body_preview_limit(), 1024 * 1024);
        assert_eq!(
            InspectionLimits::new(0, 1),
            Err(InspectionLimitError::ZeroTransactionLimit)
        );
        assert_eq!(
            InspectionLimits::new(1, 0),
            Err(InspectionLimitError::ZeroBodyPreviewLimit)
        );
        assert_eq!(
            InspectionLimits::with_event_capacity(1, 1, 0),
            Err(InspectionLimitError::ZeroEventCapacity)
        );
    }

    #[test]
    fn newest_entries_are_listed_first_and_oldest_is_evicted()
    -> Result<(), Box<dyn std::error::Error>> {
        let store = InspectionStore::new(InspectionLimits::new(2, 32)?);
        let first = captured_id(store.capture(
            TransactionOrigin::Original,
            request(&store, "/first", true)?,
        ))?;
        let second = captured_id(store.capture(
            TransactionOrigin::Original,
            request(&store, "/second", true)?,
        ))?;
        let third = captured_id(store.capture(
            TransactionOrigin::Original,
            request(&store, "/third", true)?,
        ))?;

        assert!(store.get(first).is_none());
        assert_eq!(
            store.list().iter().map(Transaction::id).collect::<Vec<_>>(),
            [third, second]
        );
        assert_eq!(store.len(), 2);
        assert_eq!(store.list_ids_newest_first(), [third, second]);
        assert_eq!(
            store.inspect(second, |transaction| transaction
                .request()
                .public_uri()
                .clone()),
            Some(Uri::from_static("https://public.example.test/second"))
        );
        Ok(())
    }

    #[test]
    fn store_clamps_prebuilt_previews_to_its_own_limit() -> Result<(), Box<dyn std::error::Error>> {
        let store = InspectionStore::new(InspectionLimits::new(1, 4)?);
        let mut body = BodyPreview::new(64, BodyContentKind::Text, BodyConstraints::ordinary())?;
        body.record_chunk(b"abcdefgh")?;
        body.finish()?;
        let id = captured_id(store.capture(
            TransactionOrigin::Original,
            RequestSnapshot::new(
                Method::POST,
                Uri::from_static("https://public.example.test/upload"),
                Version::HTTP_11,
                HeaderSnapshots::default(),
                body,
            )?,
        ))?;
        let snapshot = store
            .get(id)
            .ok_or_else(|| io::Error::other("transaction was not retained"))?;
        assert_eq!(snapshot.request().body().limit(), 4);
        assert_eq!(snapshot.request().body().retained_bytes(), b"abcd");
        assert_eq!(snapshot.request().body().total_bytes(), 8);
        Ok(())
    }

    #[test]
    fn pause_skips_only_new_capture_and_existing_entries_can_finish()
    -> Result<(), Box<dyn std::error::Error>> {
        let store = InspectionStore::new(InspectionLimits::new(4, 32)?);
        let existing = captured_id(store.capture(
            TransactionOrigin::Original,
            request(&store, "/existing", false)?,
        ))?;
        store.pause();
        assert!(store.is_paused());
        assert_eq!(
            store.capture(
                TransactionOrigin::Original,
                request(&store, "/while-paused", true)?
            ),
            CaptureDecision::Paused
        );
        store.finish_request_body(existing)?;
        store.start_response(existing, response(&store, true), Duration::from_millis(1))?;
        store.complete(existing, Duration::from_millis(2))?;
        assert_eq!(
            store
                .get(existing)
                .ok_or_else(|| io::Error::other("existing transaction disappeared"))?
                .lifecycle(),
            &TransactionLifecycle::Completed
        );
        store.resume();
        assert!(!store.is_paused());
        assert!(matches!(
            store.capture(
                TransactionOrigin::Original,
                request(&store, "/after-resume", true)?
            ),
            CaptureDecision::Captured(_)
        ));
        Ok(())
    }

    #[test]
    fn delete_and_clear_prevent_resurrection() -> Result<(), Box<dyn std::error::Error>> {
        let store = InspectionStore::new(InspectionLimits::new(4, 32)?);
        let deleted = captured_id(store.capture(
            TransactionOrigin::Original,
            request(&store, "/deleted", false)?,
        ))?;
        assert!(store.delete(deleted));
        assert!(!store.delete(deleted));
        assert_eq!(
            store.record_request_body_chunk(deleted, b"late"),
            Err(StoreUpdateError::TransactionNotFound(deleted))
        );

        let cleared = captured_id(store.capture(
            TransactionOrigin::Original,
            request(&store, "/cleared", false)?,
        ))?;
        assert_eq!(store.clear(), 1);
        assert!(store.is_empty());
        assert_eq!(
            store.finish_request_body(cleared),
            Err(StoreUpdateError::TransactionNotFound(cleared))
        );
        Ok(())
    }

    #[test]
    fn lifecycle_updates_publish_in_sequence() -> Result<(), Box<dyn std::error::Error>> {
        let store = InspectionStore::new(InspectionLimits::new(4, 32)?);
        let mut events = store.subscribe();
        let id = captured_id(store.capture(
            TransactionOrigin::Original,
            request(&store, "/events", false)?,
        ))?;
        store.finish_request_body(id)?;
        store.start_response(id, response(&store, false), Duration::ZERO)?;
        store.finish_response_body(id)?;
        store.complete(id, Duration::from_millis(1))?;

        let mut prior = 0;
        for _ in 0..5 {
            let event = events.try_recv()?;
            assert!(event.sequence() > prior);
            prior = event.sequence();
        }
        Ok(())
    }

    #[test]
    fn lagging_or_absent_receivers_never_block_writers() -> Result<(), Box<dyn std::error::Error>> {
        let store = InspectionStore::new(InspectionLimits::with_event_capacity(16, 32, 2)?);
        let mut lagging = store.subscribe();
        for index in 0..8 {
            let path = format!("/{index}");
            let _ = store.capture(TransactionOrigin::Original, request(&store, &path, true)?);
        }
        assert!(matches!(lagging.try_recv(), Err(TryRecvError::Lagged(_))));
        drop(lagging);

        for index in 8..512 {
            let path = format!("/{index}");
            let _ = store.capture(TransactionOrigin::Original, request(&store, &path, true)?);
        }
        assert_eq!(store.len(), 16);
        Ok(())
    }

    #[test]
    fn concurrent_updates_are_serialized_without_losing_bytes()
    -> Result<(), Box<dyn std::error::Error>> {
        const THREADS: usize = 8;
        const CHUNKS_PER_THREAD: usize = 100;
        let store = InspectionStore::new(InspectionLimits::new(4, 4096)?);
        let id = captured_id(store.capture(
            TransactionOrigin::Original,
            request(&store, "/concurrent", false)?,
        ))?;
        let mut handles = Vec::new();
        for _ in 0..THREADS {
            let writer = store.clone();
            handles.push(thread::spawn(move || {
                for _ in 0..CHUNKS_PER_THREAD {
                    writer.record_request_body_chunk(id, b"x")?;
                }
                Ok::<_, StoreUpdateError>(())
            }));
        }
        for handle in handles {
            handle
                .join()
                .map_err(|_| io::Error::other("inspection writer thread panicked"))??;
        }
        store.finish_request_body(id)?;
        store.start_response(id, response(&store, true), Duration::ZERO)?;
        store.complete(id, Duration::from_millis(1))?;

        let snapshot = store
            .get(id)
            .ok_or_else(|| io::Error::other("transaction was not retained"))?;
        assert_eq!(
            snapshot.request().body().total_bytes(),
            u64::try_from(THREADS * CHUNKS_PER_THREAD)?
        );
        assert_eq!(
            snapshot.request().body().retained_bytes().len(),
            THREADS * CHUNKS_PER_THREAD
        );
        assert_eq!(
            snapshot.request().body().completion(),
            BodyCompletion::Complete
        );
        assert_eq!(snapshot.lifecycle(), &TransactionLifecycle::Completed);
        Ok(())
    }

    #[test]
    fn concurrent_terminal_updates_leave_exactly_one_terminal_outcome()
    -> Result<(), Box<dyn std::error::Error>> {
        let store = InspectionStore::new(InspectionLimits::new(2, 32)?);
        let id = captured_id(store.capture(
            TransactionOrigin::Original,
            request(&store, "/terminal-race", false)?,
        ))?;
        let barrier = Arc::new(Barrier::new(3));

        let failing_store = store.clone();
        let failing_barrier = barrier.clone();
        let fail = thread::spawn(move || {
            failing_barrier.wait();
            failing_store.fail(id, Duration::from_millis(2), "local failure")
        });

        let cancelling_store = store.clone();
        let cancelling_barrier = barrier.clone();
        let cancel = thread::spawn(move || {
            cancelling_barrier.wait();
            cancelling_store.cancel(id, Duration::from_millis(2))
        });

        barrier.wait();
        let fail = fail
            .join()
            .map_err(|_| io::Error::other("failure writer thread panicked"))?;
        let cancel = cancel
            .join()
            .map_err(|_| io::Error::other("cancellation writer thread panicked"))?;
        assert_eq!(usize::from(fail.is_ok()) + usize::from(cancel.is_ok()), 1);

        let snapshot = store
            .get(id)
            .ok_or_else(|| io::Error::other("transaction was not retained"))?;
        assert!(matches!(
            snapshot.lifecycle(),
            TransactionLifecycle::FailedOrCancelled(_)
        ));
        assert_eq!(
            snapshot.request().body().completion(),
            BodyCompletion::Incomplete
        );
        Ok(())
    }

    #[test]
    fn evicted_entry_cannot_be_updated_after_concurrent_replacement()
    -> Result<(), Box<dyn std::error::Error>> {
        let store = InspectionStore::new(InspectionLimits::new(1, 32)?);
        let evicted = captured_id(
            store.capture(TransactionOrigin::Original, request(&store, "/old", false)?),
        )?;
        let _replacement = captured_id(
            store.capture(TransactionOrigin::Original, request(&store, "/new", true)?),
        )?;
        assert_eq!(
            store.finish_request_body(evicted),
            Err(StoreUpdateError::TransactionNotFound(evicted))
        );
        Ok(())
    }

    #[test]
    fn request_validation_errors_remain_at_the_model_boundary()
    -> Result<(), Box<dyn std::error::Error>> {
        let store = InspectionStore::default();
        let relative = RequestSnapshot::new(
            Method::GET,
            Uri::from_static("/relative"),
            Version::HTTP_11,
            HeaderSnapshots::default(),
            store.body_preview(BodyContentKind::Unknown, BodyConstraints::ordinary()),
        );
        assert_eq!(relative, Err(RequestSnapshotError::NonAbsolutePublicUri));
        Ok(())
    }
}
