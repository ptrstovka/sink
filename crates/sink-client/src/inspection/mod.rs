//! Client-local, bounded HTTP inspection models and storage.
//!
//! This subsystem is intentionally separate from the terminal-oriented
//! `runtime::RequestSummary` contract. It stores application traffic only in
//! process memory and exposes no protocol or Sink-control credential types.

mod models;
mod store;

pub use models::{
    BodyCompletion, BodyConstraints, BodyContentKind, BodyPreview, BodyPreviewError, BodyRetention,
    FailureKind, HeaderDisplayValue, HeaderSensitivity, HeaderSnapshot, HeaderSnapshots,
    ReplayEligibility, ReplayIneligibilityReason, RequestSnapshot, RequestSnapshotError,
    ResponseSnapshot, SensitiveHeaderKind, Transaction, TransactionFailure, TransactionId,
    TransactionLifecycle, TransactionOrigin, TransactionUpdateError, classify_header_name,
    is_sink_control_header,
};
pub use store::{
    CaptureDecision, DEFAULT_BODY_PREVIEW_LIMIT, DEFAULT_EVENT_CAPACITY, DEFAULT_TRANSACTION_LIMIT,
    InspectionEvent, InspectionEventKind, InspectionLimitError, InspectionLimits, InspectionStore,
    RemovalCause, StoreUpdateError,
};
