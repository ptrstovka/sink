use std::{path::Path, time::Duration};

use futures::future::BoxFuture;
use sqlx::{
    FromRow, SqliteConnection, SqlitePool,
    migrate::{MigrateError, Migrator},
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
};
use thiserror::Error;

use super::{
    AccountRecord, CertificateMaterial, CertificateProviderKind, CertificateRecord,
    CertificateState, CertificateTarget, Hostname, IssuanceReason, IssuanceRequest, OrderOwner,
    OrderRecord, OrderState, RetryPolicy, SecretBytes, Timestamp,
};

static MIGRATOR: Migrator = sqlx::migrate!();

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

    fn database() -> Self {
        Self::new("durable certificate database operation failed")
    }

    fn malformed(kind: &'static str) -> Self {
        Self::new(format!("malformed durable certificate {kind}"))
    }
}

impl From<sqlx::Error> for StorageError {
    fn from(_: sqlx::Error) -> Self {
        Self::database()
    }
}

impl From<MigrateError> for StorageError {
    fn from(_: MigrateError) -> Self {
        Self::new("certificate database migration failed")
    }
}

/// Persistence boundary for provider accounts, certificate/key material, and
/// order scheduling state.
///
/// Implementations must make each `store_*` operation atomic. Lifecycle
/// transitions that change an order and certificate together use
/// `store_lifecycle`, which must commit both records or neither.
pub trait CertificateStorage: Send + Sync {
    fn load_account<'a>(
        &'a self,
        provider: CertificateProviderKind,
        account_scope: &'a str,
    ) -> BoxFuture<'a, Result<Option<AccountRecord>, StorageError>>;

    fn store_account(&self, account: AccountRecord) -> BoxFuture<'_, Result<(), StorageError>>;

    fn load_certificate<'a>(
        &'a self,
        target: &'a CertificateTarget,
    ) -> BoxFuture<'a, Result<Option<CertificateRecord>, StorageError>>;

    fn load_certificates(&self) -> BoxFuture<'_, Result<Vec<CertificateRecord>, StorageError>>;

    fn store_certificate(
        &self,
        certificate: CertificateRecord,
    ) -> BoxFuture<'_, Result<(), StorageError>>;

    fn load_order<'a>(
        &'a self,
        target: &'a CertificateTarget,
    ) -> BoxFuture<'a, Result<Option<OrderRecord>, StorageError>>;

    fn store_order(&self, order: OrderRecord) -> BoxFuture<'_, Result<(), StorageError>>;

    fn store_lifecycle(
        &self,
        order: OrderRecord,
        certificate: Option<CertificateRecord>,
    ) -> BoxFuture<'_, Result<(), StorageError>>;

    /// Convert every order left `InProgress` by a stopped process into a
    /// scheduled retry. Implementations must reconcile all matching orders in
    /// one transaction so startup cannot leave a partially recovered set.
    fn reconcile_in_progress<'a>(
        &'a self,
        retry: &'a RetryPolicy,
        now: Timestamp,
    ) -> BoxFuture<'a, Result<u64, StorageError>>;
}

/// SQLite-backed durable certificate state. It can be constructed from a
/// shared pool once the server database exposes one, or opened independently
/// against the same database path until that cross-boundary wiring lands.
#[derive(Clone)]
pub struct SqliteCertificateStorage {
    pool: SqlitePool,
}

impl SqliteCertificateStorage {
    pub async fn connect(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .foreign_keys(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Normal)
            .busy_timeout(Duration::from_secs(5));
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(options)
            .await?;
        MIGRATOR.run(&pool).await?;
        Ok(Self { pool })
    }

    pub fn from_pool(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    pub async fn close(&self) {
        self.pool.close().await;
    }
}

impl CertificateStorage for SqliteCertificateStorage {
    fn load_account<'a>(
        &'a self,
        provider: CertificateProviderKind,
        account_scope: &'a str,
    ) -> BoxFuture<'a, Result<Option<AccountRecord>, StorageError>> {
        Box::pin(async move {
            let row = sqlx::query_as::<_, AccountRow>(
                r#"
                SELECT provider, account_scope, external_account_id, private_state
                FROM certificate_accounts
                WHERE provider = ? AND account_scope = ?
                "#,
            )
            .bind(provider.as_str())
            .bind(account_scope)
            .fetch_optional(&self.pool)
            .await?;
            row.map(AccountRecord::try_from).transpose()
        })
    }

    fn store_account(&self, account: AccountRecord) -> BoxFuture<'_, Result<(), StorageError>> {
        Box::pin(async move {
            validate_account(&account)?;
            sqlx::query(
                r#"
                INSERT INTO certificate_accounts (
                    provider, account_scope, external_account_id, private_state, updated_at
                ) VALUES (?, ?, ?, ?, unixepoch())
                ON CONFLICT(provider, account_scope) DO UPDATE SET
                    external_account_id = excluded.external_account_id,
                    private_state = excluded.private_state,
                    updated_at = excluded.updated_at
                "#,
            )
            .bind(account.provider.as_str())
            .bind(&account.account_scope)
            .bind(&account.external_account_id)
            .bind(account.private_state.expose_secret())
            .execute(&self.pool)
            .await?;
            Ok(())
        })
    }

    fn load_certificate<'a>(
        &'a self,
        target: &'a CertificateTarget,
    ) -> BoxFuture<'a, Result<Option<CertificateRecord>, StorageError>> {
        Box::pin(async move {
            let row = sqlx::query_as::<_, CertificateRow>(&format!(
                "{} WHERE target = ?",
                CertificateRow::SELECT
            ))
            .bind(target.apex().as_str())
            .fetch_optional(&self.pool)
            .await?;
            row.map(CertificateRecord::try_from).transpose()
        })
    }

    fn load_certificates(&self) -> BoxFuture<'_, Result<Vec<CertificateRecord>, StorageError>> {
        Box::pin(async move {
            let rows = sqlx::query_as::<_, CertificateRow>(CertificateRow::SELECT)
                .fetch_all(&self.pool)
                .await?;
            rows.into_iter().map(CertificateRecord::try_from).collect()
        })
    }

    fn store_certificate(
        &self,
        certificate: CertificateRecord,
    ) -> BoxFuture<'_, Result<(), StorageError>> {
        Box::pin(async move {
            let encoded = EncodedCertificate::try_from(&certificate)?;
            let mut connection = self.pool.acquire().await?;
            upsert_certificate(&mut connection, &certificate, &encoded).await
        })
    }

    fn load_order<'a>(
        &'a self,
        target: &'a CertificateTarget,
    ) -> BoxFuture<'a, Result<Option<OrderRecord>, StorageError>> {
        Box::pin(async move {
            let row =
                sqlx::query_as::<_, OrderRow>(&format!("{} WHERE target = ?", OrderRow::SELECT))
                    .bind(target.apex().as_str())
                    .fetch_optional(&self.pool)
                    .await?;
            row.map(OrderRecord::try_from).transpose()
        })
    }

    fn store_order(&self, order: OrderRecord) -> BoxFuture<'_, Result<(), StorageError>> {
        Box::pin(async move {
            let encoded = EncodedOrder::try_from(&order)?;
            let mut connection = self.pool.acquire().await?;
            upsert_order(&mut connection, &order, &encoded).await
        })
    }

    fn store_lifecycle(
        &self,
        order: OrderRecord,
        certificate: Option<CertificateRecord>,
    ) -> BoxFuture<'_, Result<(), StorageError>> {
        Box::pin(async move {
            if let Some(certificate) = &certificate
                && (certificate.target != order.request.target
                    || certificate.provider != order.request.provider)
            {
                return Err(StorageError::malformed("lifecycle transition"));
            }
            let encoded_order = EncodedOrder::try_from(&order)?;
            let encoded_certificate = certificate
                .as_ref()
                .map(EncodedCertificate::try_from)
                .transpose()?;
            let mut transaction = self.pool.begin().await?;
            if let (Some(certificate), Some(encoded)) =
                (certificate.as_ref(), encoded_certificate.as_ref())
            {
                upsert_certificate(&mut transaction, certificate, encoded).await?;
            }
            upsert_order(&mut transaction, &order, &encoded_order).await?;
            transaction.commit().await?;
            Ok(())
        })
    }

    fn reconcile_in_progress<'a>(
        &'a self,
        retry: &'a RetryPolicy,
        now: Timestamp,
    ) -> BoxFuture<'a, Result<u64, StorageError>> {
        Box::pin(async move {
            let mut transaction = self.pool.begin().await?;
            let rows = sqlx::query_as::<_, OrderRow>(&format!(
                "{} WHERE order_state = 'in_progress' ORDER BY target",
                OrderRow::SELECT
            ))
            .fetch_all(&mut *transaction)
            .await?;
            let mut reconciled = 0_u64;

            for row in rows {
                let mut order = OrderRecord::try_from(row)?;
                let retry_at = retry.schedule_retry(
                    &mut order,
                    "issuance interrupted by server restart".to_owned(),
                    now,
                );
                let certificate_row = sqlx::query_as::<_, CertificateRow>(&format!(
                    "{} WHERE target = ?",
                    CertificateRow::SELECT
                ))
                .bind(order.request.target.apex().as_str())
                .fetch_optional(&mut *transaction)
                .await?
                .ok_or_else(|| StorageError::malformed("order reference"))?;
                let certificate = CertificateRecord::try_from(certificate_row)?;
                if certificate.active_material(now).is_none() {
                    let retrying = CertificateRecord {
                        target: order.request.target.clone(),
                        provider: order.request.provider,
                        state: CertificateState::RetryScheduled {
                            retry_at,
                            cooldown_until: order.cooldown_until,
                        },
                        updated_at: now,
                    };
                    let encoded = EncodedCertificate::try_from(&retrying)?;
                    upsert_certificate(&mut transaction, &retrying, &encoded).await?;
                }
                let encoded = EncodedOrder::try_from(&order)?;
                upsert_order(&mut transaction, &order, &encoded).await?;
                reconciled = reconciled.saturating_add(1);
            }

            transaction.commit().await?;
            Ok(reconciled)
        })
    }
}

#[derive(FromRow)]
struct AccountRow {
    provider: String,
    account_scope: String,
    external_account_id: String,
    private_state: Vec<u8>,
}

impl TryFrom<AccountRow> for AccountRecord {
    type Error = StorageError;

    fn try_from(row: AccountRow) -> Result<Self, Self::Error> {
        if row.account_scope.is_empty()
            || row.external_account_id.is_empty()
            || row.private_state.is_empty()
        {
            return Err(StorageError::malformed("account state"));
        }
        Ok(Self {
            provider: parse_provider(&row.provider)?,
            account_scope: row.account_scope,
            external_account_id: row.external_account_id,
            private_state: SecretBytes::new(row.private_state),
        })
    }
}

#[derive(FromRow)]
struct CertificateRow {
    target: String,
    target_kind: String,
    provider: String,
    lifecycle_state: String,
    certificate_chain_pem: Option<Vec<u8>>,
    private_key_pem: Option<Vec<u8>>,
    not_before: Option<i64>,
    not_after: Option<i64>,
    retry_at: Option<i64>,
    cooldown_until: Option<i64>,
    updated_at: i64,
}

impl CertificateRow {
    const SELECT: &'static str = r#"
        SELECT target, target_kind, provider, lifecycle_state,
               certificate_chain_pem, private_key_pem, not_before, not_after,
               retry_at, cooldown_until, updated_at
        FROM managed_certificates
    "#;
}

impl TryFrom<CertificateRow> for CertificateRecord {
    type Error = StorageError;

    fn try_from(row: CertificateRow) -> Result<Self, Self::Error> {
        let target = parse_target(&row.target, &row.target_kind)?;
        let provider = parse_provider(&row.provider)?;
        let updated_at = parse_timestamp(row.updated_at, "timestamp")?;
        let state = match row.lifecycle_state.as_str() {
            "pending"
                if row.certificate_chain_pem.is_none()
                    && row.private_key_pem.is_none()
                    && row.not_before.is_none()
                    && row.not_after.is_none()
                    && row.retry_at.is_none()
                    && row.cooldown_until.is_none() =>
            {
                CertificateState::Pending
            }
            "failed"
                if row.certificate_chain_pem.is_none()
                    && row.private_key_pem.is_none()
                    && row.not_before.is_none()
                    && row.not_after.is_none()
                    && row.retry_at.is_none()
                    && row.cooldown_until.is_none() =>
            {
                CertificateState::Failed
            }
            "retry_scheduled"
                if row.certificate_chain_pem.is_none()
                    && row.private_key_pem.is_none()
                    && row.not_before.is_none()
                    && row.not_after.is_none() =>
            {
                CertificateState::RetryScheduled {
                    retry_at: parse_optional_timestamp(row.retry_at, "retry state")?
                        .ok_or_else(|| StorageError::malformed("retry state"))?,
                    cooldown_until: parse_optional_timestamp(row.cooldown_until, "retry cooldown")?,
                }
            }
            "ready" | "retained" if row.retry_at.is_none() && row.cooldown_until.is_none() => {
                let material = CertificateMaterial {
                    certificate_chain_pem: row
                        .certificate_chain_pem
                        .filter(|value| !value.is_empty())
                        .ok_or_else(|| StorageError::malformed("material"))?,
                    private_key_pem: SecretBytes::new(
                        row.private_key_pem
                            .filter(|value| !value.is_empty())
                            .ok_or_else(|| StorageError::malformed("material"))?,
                    ),
                    not_before: parse_optional_timestamp(row.not_before, "validity")?
                        .ok_or_else(|| StorageError::malformed("validity"))?,
                    not_after: parse_optional_timestamp(row.not_after, "validity")?
                        .ok_or_else(|| StorageError::malformed("validity"))?,
                };
                if material.not_before >= material.not_after {
                    return Err(StorageError::malformed("validity"));
                }
                if row.lifecycle_state == "ready" {
                    CertificateState::Ready(material)
                } else {
                    CertificateState::Retained(material)
                }
            }
            _ => return Err(StorageError::malformed("lifecycle state")),
        };
        Ok(Self {
            target,
            provider,
            state,
            updated_at,
        })
    }
}

#[derive(FromRow)]
struct OrderRow {
    target: String,
    target_kind: String,
    provider: String,
    owner_kind: String,
    owner_id: Option<String>,
    reason: String,
    order_state: String,
    attempts: i64,
    consecutive_failures: i64,
    retry_at: Option<i64>,
    cooldown_until: Option<i64>,
    last_error: Option<String>,
    updated_at: i64,
}

impl OrderRow {
    const SELECT: &'static str = r#"
        SELECT target, target_kind, provider, owner_kind, owner_id, reason,
               order_state, attempts, consecutive_failures, retry_at,
               cooldown_until, last_error, updated_at
        FROM certificate_orders
    "#;
}

impl TryFrom<OrderRow> for OrderRecord {
    type Error = StorageError;

    fn try_from(row: OrderRow) -> Result<Self, Self::Error> {
        let target = parse_target(&row.target, &row.target_kind)?;
        let provider = parse_provider(&row.provider)?;
        let owner = match (row.owner_kind.as_str(), row.owner_id) {
            ("platform", None) => OrderOwner::Platform,
            ("user", Some(user_id)) if !user_id.is_empty() => OrderOwner::User(user_id),
            _ => return Err(StorageError::malformed("order owner")),
        };
        let reason = match row.reason.as_str() {
            "base_provisioning" => IssuanceReason::BaseProvisioning,
            "namespace_claim" => IssuanceReason::NamespaceClaim,
            "renewal" => IssuanceReason::Renewal,
            _ => return Err(StorageError::malformed("order reason")),
        };
        let request = IssuanceRequest {
            target,
            provider,
            owner,
            reason,
        };
        if !request.validates_ownership_shape() {
            return Err(StorageError::malformed("order request"));
        }
        let retry_at = parse_optional_timestamp(row.retry_at, "order retry")?;
        let state = match (row.order_state.as_str(), retry_at) {
            ("queued", None) => OrderState::Queued,
            ("in_progress", None) => OrderState::InProgress,
            ("retry_scheduled", Some(retry_at)) => OrderState::RetryScheduled { retry_at },
            ("succeeded", None) => OrderState::Succeeded,
            ("failed", None) => OrderState::Failed,
            _ => return Err(StorageError::malformed("order state")),
        };
        Ok(Self {
            request,
            state,
            attempts: parse_u32(row.attempts, "order attempts")?,
            consecutive_failures: parse_u32(row.consecutive_failures, "order failure count")?,
            cooldown_until: parse_optional_timestamp(row.cooldown_until, "order cooldown")?,
            last_error: row.last_error,
            updated_at: parse_timestamp(row.updated_at, "order timestamp")?,
        })
    }
}

struct EncodedCertificate {
    state: &'static str,
    certificate_chain_pem: Option<Vec<u8>>,
    private_key_pem: Option<Vec<u8>>,
    not_before: Option<i64>,
    not_after: Option<i64>,
    retry_at: Option<i64>,
    cooldown_until: Option<i64>,
    updated_at: i64,
}

impl TryFrom<&CertificateRecord> for EncodedCertificate {
    type Error = StorageError;

    fn try_from(record: &CertificateRecord) -> Result<Self, Self::Error> {
        let updated_at = encode_timestamp(record.updated_at)?;
        let (
            state,
            certificate_chain_pem,
            private_key_pem,
            not_before,
            not_after,
            retry_at,
            cooldown_until,
        ) = match &record.state {
            CertificateState::Pending => ("pending", None, None, None, None, None, None),
            CertificateState::Failed => ("failed", None, None, None, None, None, None),
            CertificateState::RetryScheduled {
                retry_at,
                cooldown_until,
            } => (
                "retry_scheduled",
                None,
                None,
                None,
                None,
                Some(encode_timestamp(*retry_at)?),
                cooldown_until.map(encode_timestamp).transpose()?,
            ),
            CertificateState::Ready(material) | CertificateState::Retained(material) => {
                if material.certificate_chain_pem.is_empty()
                    || material.private_key_pem.expose_secret().is_empty()
                    || material.not_before >= material.not_after
                {
                    return Err(StorageError::malformed("material"));
                }
                (
                    if matches!(record.state, CertificateState::Ready(_)) {
                        "ready"
                    } else {
                        "retained"
                    },
                    Some(material.certificate_chain_pem.clone()),
                    Some(material.private_key_pem.expose_secret().to_vec()),
                    Some(encode_timestamp(material.not_before)?),
                    Some(encode_timestamp(material.not_after)?),
                    None,
                    None,
                )
            }
        };
        Ok(Self {
            state,
            certificate_chain_pem,
            private_key_pem,
            not_before,
            not_after,
            retry_at,
            cooldown_until,
            updated_at,
        })
    }
}

struct EncodedOrder {
    target_kind: &'static str,
    owner_kind: &'static str,
    owner_id: Option<String>,
    reason: &'static str,
    state: &'static str,
    retry_at: Option<i64>,
    cooldown_until: Option<i64>,
    updated_at: i64,
}

impl TryFrom<&OrderRecord> for EncodedOrder {
    type Error = StorageError;

    fn try_from(order: &OrderRecord) -> Result<Self, Self::Error> {
        if !order.request.validates_ownership_shape()
            || order
                .last_error
                .as_ref()
                .is_some_and(|message| message.len() > 1024)
        {
            return Err(StorageError::malformed("order"));
        }
        let target_kind = target_kind(&order.request.target);
        let (owner_kind, owner_id) = match &order.request.owner {
            OrderOwner::Platform => ("platform", None),
            OrderOwner::User(user_id) if !user_id.is_empty() && user_id.len() <= 128 => {
                ("user", Some(user_id.clone()))
            }
            OrderOwner::User(_) => return Err(StorageError::malformed("order owner")),
        };
        let reason = match order.request.reason {
            IssuanceReason::BaseProvisioning => "base_provisioning",
            IssuanceReason::NamespaceClaim => "namespace_claim",
            IssuanceReason::Renewal => "renewal",
        };
        let (state, retry_at) = match order.state {
            OrderState::Queued => ("queued", None),
            OrderState::InProgress => ("in_progress", None),
            OrderState::RetryScheduled { retry_at } => {
                ("retry_scheduled", Some(encode_timestamp(retry_at)?))
            }
            OrderState::Succeeded => ("succeeded", None),
            OrderState::Failed => ("failed", None),
        };
        Ok(Self {
            target_kind,
            owner_kind,
            owner_id,
            reason,
            state,
            retry_at,
            cooldown_until: order.cooldown_until.map(encode_timestamp).transpose()?,
            updated_at: encode_timestamp(order.updated_at)?,
        })
    }
}

async fn upsert_certificate(
    connection: &mut SqliteConnection,
    certificate: &CertificateRecord,
    encoded: &EncodedCertificate,
) -> Result<(), StorageError> {
    let result = sqlx::query(
        r#"
        INSERT INTO managed_certificates (
            target, target_kind, provider, lifecycle_state,
            certificate_chain_pem, private_key_pem, not_before, not_after,
            retry_at, cooldown_until, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(target) DO UPDATE SET
            lifecycle_state = excluded.lifecycle_state,
            certificate_chain_pem = excluded.certificate_chain_pem,
            private_key_pem = excluded.private_key_pem,
            not_before = excluded.not_before,
            not_after = excluded.not_after,
            retry_at = excluded.retry_at,
            cooldown_until = excluded.cooldown_until,
            updated_at = excluded.updated_at
        WHERE managed_certificates.target_kind = excluded.target_kind
          AND managed_certificates.provider = excluded.provider
        "#,
    )
    .bind(certificate.target.apex().as_str())
    .bind(target_kind(&certificate.target))
    .bind(certificate.provider.as_str())
    .bind(encoded.state)
    .bind(&encoded.certificate_chain_pem)
    .bind(&encoded.private_key_pem)
    .bind(encoded.not_before)
    .bind(encoded.not_after)
    .bind(encoded.retry_at)
    .bind(encoded.cooldown_until)
    .bind(encoded.updated_at)
    .execute(connection)
    .await?;
    if result.rows_affected() != 1 {
        return Err(StorageError::malformed("certificate identity"));
    }
    Ok(())
}

async fn upsert_order(
    connection: &mut SqliteConnection,
    order: &OrderRecord,
    encoded: &EncodedOrder,
) -> Result<(), StorageError> {
    let result = sqlx::query(
        r#"
        INSERT INTO certificate_orders (
            target, target_kind, provider, owner_kind, owner_id, reason,
            order_state, attempts, consecutive_failures, retry_at,
            cooldown_until, last_error, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(target) DO UPDATE SET
            order_state = excluded.order_state,
            attempts = excluded.attempts,
            consecutive_failures = excluded.consecutive_failures,
            retry_at = excluded.retry_at,
            cooldown_until = excluded.cooldown_until,
            last_error = excluded.last_error,
            updated_at = excluded.updated_at
        WHERE certificate_orders.target_kind = excluded.target_kind
          AND certificate_orders.provider = excluded.provider
          AND certificate_orders.owner_kind = excluded.owner_kind
          AND certificate_orders.owner_id IS excluded.owner_id
          AND certificate_orders.reason = excluded.reason
        "#,
    )
    .bind(order.request.target.apex().as_str())
    .bind(encoded.target_kind)
    .bind(order.request.provider.as_str())
    .bind(encoded.owner_kind)
    .bind(&encoded.owner_id)
    .bind(encoded.reason)
    .bind(encoded.state)
    .bind(i64::from(order.attempts))
    .bind(i64::from(order.consecutive_failures))
    .bind(encoded.retry_at)
    .bind(encoded.cooldown_until)
    .bind(&order.last_error)
    .bind(encoded.updated_at)
    .execute(connection)
    .await?;
    if result.rows_affected() != 1 {
        return Err(StorageError::malformed("order identity"));
    }
    Ok(())
}

fn validate_account(account: &AccountRecord) -> Result<(), StorageError> {
    if account.account_scope.is_empty()
        || account.account_scope.len() > 2048
        || account.external_account_id.is_empty()
        || account.external_account_id.len() > 2048
        || account.private_state.expose_secret().is_empty()
    {
        return Err(StorageError::malformed("account state"));
    }
    Ok(())
}

fn parse_provider(value: &str) -> Result<CertificateProviderKind, StorageError> {
    value
        .parse()
        .map_err(|_| StorageError::malformed("provider"))
}

fn target_kind(target: &CertificateTarget) -> &'static str {
    match target {
        CertificateTarget::BaseDomain(_) => "base",
        CertificateTarget::Namespace(_) => "namespace",
    }
}

fn parse_target(value: &str, kind: &str) -> Result<CertificateTarget, StorageError> {
    let hostname = Hostname::parse(value).map_err(|_| StorageError::malformed("target"))?;
    match kind {
        "base" => Ok(CertificateTarget::base_domain(hostname)),
        "namespace" => Ok(CertificateTarget::namespace(hostname)),
        _ => Err(StorageError::malformed("target kind")),
    }
}

fn encode_timestamp(value: Timestamp) -> Result<i64, StorageError> {
    i64::try_from(value.unix_seconds()).map_err(|_| StorageError::malformed("timestamp"))
}

fn parse_timestamp(value: i64, kind: &'static str) -> Result<Timestamp, StorageError> {
    u64::try_from(value)
        .map(Timestamp::from_unix_seconds)
        .map_err(|_| StorageError::malformed(kind))
}

fn parse_optional_timestamp(
    value: Option<i64>,
    kind: &'static str,
) -> Result<Option<Timestamp>, StorageError> {
    value.map(|value| parse_timestamp(value, kind)).transpose()
}

fn parse_u32(value: i64, kind: &'static str) -> Result<u32, StorageError> {
    u32::try_from(value).map_err(|_| StorageError::malformed(kind))
}

#[cfg(test)]
mod tests {
    use tempfile::NamedTempFile;

    use super::*;

    fn target() -> CertificateTarget {
        CertificateTarget::namespace(Hostname::parse("cloud.example.test").expect("valid hostname"))
    }

    fn request() -> IssuanceRequest {
        IssuanceRequest {
            target: target(),
            provider: CertificateProviderKind::Cloudflare,
            owner: OrderOwner::User("user-1".to_owned()),
            reason: IssuanceReason::NamespaceClaim,
        }
    }

    fn material() -> CertificateMaterial {
        CertificateMaterial {
            certificate_chain_pem: b"certificate chain".to_vec(),
            private_key_pem: SecretBytes::new(b"private key".to_vec()),
            not_before: Timestamp::from_unix_seconds(900),
            not_after: Timestamp::from_unix_seconds(10_000),
        }
    }

    async fn storage() -> (NamedTempFile, SqliteCertificateStorage) {
        let file = NamedTempFile::new().expect("temporary database");
        let storage = SqliteCertificateStorage::connect(file.path())
            .await
            .expect("open certificate storage");
        (file, storage)
    }

    #[tokio::test]
    async fn account_and_certificate_secrets_round_trip_without_debug_disclosure() {
        let (_file, storage) = storage().await;
        let account = AccountRecord {
            provider: CertificateProviderKind::Cloudflare,
            account_scope: "https://acme.example/directory".to_owned(),
            external_account_id: "account-1".to_owned(),
            private_state: SecretBytes::new(b"account secret".to_vec()),
        };
        storage
            .store_account(account.clone())
            .await
            .expect("store account");
        let loaded = storage
            .load_account(account.provider, &account.account_scope)
            .await
            .expect("load account")
            .expect("stored account");
        assert_eq!(loaded, account);
        assert!(!format!("{loaded:?}").contains("account secret"));

        let certificate = CertificateRecord::ready(
            target(),
            CertificateProviderKind::Cloudflare,
            material(),
            Timestamp::from_unix_seconds(1_000),
        );
        storage
            .store_certificate(certificate.clone())
            .await
            .expect("store certificate");
        let loaded = storage
            .load_certificate(&target())
            .await
            .expect("load certificate")
            .expect("stored certificate");
        assert_eq!(loaded, certificate);
        assert!(!format!("{loaded:?}").contains("private key"));
    }

    #[tokio::test]
    async fn lifecycle_transitions_are_committed_together() {
        let (_file, storage) = storage().await;
        let now = Timestamp::from_unix_seconds(1_000);
        let mut order = OrderRecord::queued(request(), now);
        order.start(now);
        let pending =
            CertificateRecord::pending(target(), CertificateProviderKind::Cloudflare, now);
        storage
            .store_lifecycle(order.clone(), Some(pending))
            .await
            .expect("store start transition");

        order.succeed(Timestamp::from_unix_seconds(1_001));
        let ready = CertificateRecord::ready(
            target(),
            CertificateProviderKind::Cloudflare,
            material(),
            Timestamp::from_unix_seconds(1_001),
        );
        storage
            .store_lifecycle(order, Some(ready.clone()))
            .await
            .expect("store completion transition");

        assert_eq!(
            storage
                .load_certificate(&target())
                .await
                .expect("load certificate"),
            Some(ready)
        );
        assert!(matches!(
            storage
                .load_order(&target())
                .await
                .expect("load order")
                .map(|order| order.state),
            Some(OrderState::Succeeded)
        ));
    }

    #[tokio::test]
    async fn lifecycle_transaction_rolls_back_certificate_when_order_identity_conflicts() {
        let (_file, storage) = storage().await;
        let now = Timestamp::from_unix_seconds(1_000);
        let mut original = OrderRecord::queued(request(), now);
        original.start(now);
        storage
            .store_lifecycle(
                original,
                Some(CertificateRecord::pending(
                    target(),
                    CertificateProviderKind::Cloudflare,
                    now,
                )),
            )
            .await
            .expect("store original lifecycle");

        let mut conflicting_request = request();
        conflicting_request.owner = OrderOwner::User("different-user".to_owned());
        let mut conflicting = OrderRecord::queued(conflicting_request, now);
        conflicting.start(now);
        let failed = CertificateRecord {
            target: target(),
            provider: CertificateProviderKind::Cloudflare,
            state: CertificateState::Failed,
            updated_at: Timestamp::from_unix_seconds(1_001),
        };
        storage
            .store_lifecycle(conflicting, Some(failed))
            .await
            .expect_err("conflicting identity rejected");

        assert!(matches!(
            storage
                .load_certificate(&target())
                .await
                .expect("load certificate")
                .map(|certificate| certificate.state),
            Some(CertificateState::Pending)
        ));
        assert!(matches!(
            storage
                .load_order(&target())
                .await
                .expect("load order")
                .map(|order| order.request.owner),
            Some(OrderOwner::User(owner)) if owner == "user-1"
        ));
    }

    #[tokio::test]
    async fn restart_reconciliation_schedules_retry_and_is_idempotent() {
        let (file, storage) = storage().await;
        let now = Timestamp::from_unix_seconds(1_000);
        let mut order = OrderRecord::queued(request(), now);
        order.start(now);
        storage
            .store_lifecycle(
                order,
                Some(CertificateRecord::pending(
                    target(),
                    CertificateProviderKind::Cloudflare,
                    now,
                )),
            )
            .await
            .expect("store interrupted order");
        storage.close().await;

        let reopened = SqliteCertificateStorage::connect(file.path())
            .await
            .expect("reopen certificate storage");
        assert_eq!(
            reopened
                .reconcile_in_progress(&RetryPolicy::default(), now)
                .await
                .expect("reconcile"),
            1
        );
        assert_eq!(
            reopened
                .reconcile_in_progress(&RetryPolicy::default(), now)
                .await
                .expect("second reconcile"),
            0
        );
        let retry_at = Timestamp::from_unix_seconds(1_060);
        assert!(matches!(
            reopened
                .load_order(&target())
                .await
                .expect("load order")
                .map(|order| order.state),
            Some(OrderState::RetryScheduled { retry_at: stored }) if stored == retry_at
        ));
        assert!(matches!(
            reopened
                .load_certificate(&target())
                .await
                .expect("load certificate")
                .map(|certificate| certificate.state),
            Some(CertificateState::RetryScheduled { retry_at: stored, .. }) if stored == retry_at
        ));
    }

    #[tokio::test]
    async fn retained_material_survives_restart_and_can_be_promoted_for_reuse() {
        let (file, storage) = storage().await;
        storage
            .store_certificate(CertificateRecord::retained(
                target(),
                CertificateProviderKind::Cloudflare,
                material(),
                Timestamp::from_unix_seconds(900),
            ))
            .await
            .expect("store retained certificate");
        storage.close().await;

        let reopened = SqliteCertificateStorage::connect(file.path())
            .await
            .expect("reopen certificate storage");
        let mut retained = reopened
            .load_certificate(&target())
            .await
            .expect("load retained certificate")
            .expect("retained certificate exists");
        assert!(retained.promote_reusable(Timestamp::from_unix_seconds(1_000)));
        reopened
            .store_certificate(retained)
            .await
            .expect("promote retained certificate");
        assert!(matches!(
            reopened
                .load_certificate(&target())
                .await
                .expect("load promoted certificate")
                .map(|certificate| certificate.state),
            Some(CertificateState::Ready(_))
        ));
    }

    #[tokio::test]
    async fn malformed_durable_state_fails_closed_without_exposing_blob_content() {
        let (_file, storage) = storage().await;
        let mut connection = storage.pool().acquire().await.expect("database connection");
        sqlx::query("PRAGMA ignore_check_constraints = ON")
            .execute(&mut *connection)
            .await
            .expect("allow corruption for test");
        sqlx::query(
            r#"
            INSERT INTO managed_certificates (
                target, target_kind, provider, lifecycle_state,
                certificate_chain_pem, private_key_pem, not_before, not_after,
                retry_at, cooldown_until, updated_at
            ) VALUES (?, 'namespace', 'cloudflare', 'ready', ?, ?, NULL, NULL, NULL, NULL, 1000)
            "#,
        )
        .bind(target().apex().as_str())
        .bind(b"public certificate".as_slice())
        .bind(b"must-not-leak-private-key".as_slice())
        .execute(&mut *connection)
        .await
        .expect("insert malformed row");
        drop(connection);

        let error = storage
            .load_certificate(&target())
            .await
            .expect_err("malformed row rejected");
        let rendered = format!("{error:?} {error}");
        assert!(rendered.contains("malformed durable certificate"));
        assert!(!rendered.contains("must-not-leak-private-key"));
    }
}
