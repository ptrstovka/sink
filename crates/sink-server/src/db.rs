//! SQLite-backed users, authentication tokens, and namespace claims.

use std::{fmt, path::Path, time::Duration};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngCore as _;
use sha2::{Digest as _, Sha256};
use sqlx::{
    SqlitePool,
    migrate::{MigrateError, Migrator},
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
};
use thiserror::Error;
use zeroize::Zeroizing;

static MIGRATOR: Migrator = sqlx::migrate!();

pub const DEFAULT_TOKEN_NAME: &str = "default";

const TOKEN_RANDOM_BYTES: usize = 32;
const TOKEN_INSERT_ATTEMPTS: usize = 4;
const MAX_USERNAME_BYTES: usize = 128;
const MAX_TOKEN_NAME_BYTES: usize = 64;
const MAX_FQDN_BYTES: usize = 253;

#[derive(Clone)]
pub struct Database {
    pool: SqlitePool,
}

impl Database {
    /// Open (or create) a SQLite database and apply all embedded migrations.
    pub async fn open(path: impl AsRef<Path>) -> Result<Self, DbError> {
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

    /// Close all pool connections. Clones of this handle must also be dropped
    /// or closed before SQLx can finish the close operation.
    pub async fn close(&self) {
        self.pool.close().await;
    }

    /// Create a unique enabled user with its initial `default` token.
    ///
    /// This preserves the original user-creation contract while storing the
    /// token in the named-token table.
    pub async fn create_user(&self, username: &str) -> Result<IssuedUser, DbError> {
        let username = normalize_username(username)?;

        for _ in 0..TOKEN_INSERT_ATTEMPTS {
            let token = IssuedToken::generate();
            let digest = digest_token(token.expose_secret());
            let mut transaction = self.pool.begin().await?;
            let user = sqlx::query_as::<_, UserRow>(
                r#"
                INSERT INTO users (username)
                VALUES (?)
                RETURNING id, username, enabled, token_generation, auth_revision, created_at
                "#,
            )
            .bind(&username)
            .fetch_one(&mut *transaction)
            .await;

            let user = match user {
                Ok(row) => UserSummary::from(row),
                Err(error) if is_unique_violation(&error) => {
                    transaction.rollback().await?;
                    return Err(DbError::UserAlreadyExists { username });
                }
                Err(error) => return Err(error.into()),
            };

            let inserted = sqlx::query(
                r#"
                INSERT INTO user_tokens (user_id, name, token_digest)
                VALUES (?, ?, ?)
                "#,
            )
            .bind(user.id)
            .bind(DEFAULT_TOKEN_NAME)
            .bind(digest.to_vec())
            .execute(&mut *transaction)
            .await;

            match inserted {
                Ok(_) => {
                    transaction.commit().await?;
                    return Ok(IssuedUser { user, token });
                }
                Err(error) if is_unique_violation(&error) => {
                    transaction.rollback().await?;
                }
                Err(error) => return Err(error.into()),
            }
        }

        Err(DbError::TokenCollision)
    }

    /// Resolve any named bearer token to its enabled user. Token names are
    /// administration metadata and do not scope the user's capabilities.
    pub async fn authenticate(&self, token: &str) -> Result<Option<AuthenticatedUser>, DbError> {
        let digest = digest_token(token);
        let row = sqlx::query_as::<_, AuthenticationRow>(
            r#"
            SELECT users.id, users.username, users.token_generation, users.auth_revision
            FROM user_tokens
            JOIN users ON users.id = user_tokens.user_id
            WHERE user_tokens.token_digest = ? AND users.enabled = 1
            "#,
        )
        .bind(digest.to_vec())
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(Into::into))
    }

    /// Read the non-secret state a runtime watcher needs to revoke live
    /// sessions after token rotation/revocation or user disablement.
    pub async fn authentication_state(
        &self,
        user_id: i64,
    ) -> Result<Option<AuthenticationState>, DbError> {
        let row = sqlx::query_as::<_, AuthenticationStateRow>(
            r#"
            SELECT id, enabled, token_generation, auth_revision
            FROM users
            WHERE id = ?
            "#,
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(Into::into))
    }

    /// Compatibility wrapper which rotates the initial `default` token.
    pub async fn rotate_token(&self, username: &str) -> Result<IssuedUser, DbError> {
        let issued = self.rotate_user_token(username, DEFAULT_TOKEN_NAME).await?;
        Ok(IssuedUser {
            user: issued.user,
            token: issued.token,
        })
    }

    /// Create an additional named token. The secret is returned exactly once.
    pub async fn create_user_token(
        &self,
        username: &str,
        token_name: &str,
    ) -> Result<IssuedUserToken, DbError> {
        let username = normalize_username(username)?;
        let token_name = normalize_token_name(token_name)?;
        let user = self
            .find_user(&username)
            .await?
            .ok_or_else(|| DbError::UserNotFound {
                username: username.clone(),
            })?;

        for _ in 0..TOKEN_INSERT_ATTEMPTS {
            let token = IssuedToken::generate();
            let digest = digest_token(token.expose_secret());
            let result = sqlx::query_as::<_, UserTokenRow>(
                r#"
                INSERT INTO user_tokens (user_id, name, token_digest)
                VALUES (?, ?, ?)
                RETURNING id, user_id, name, generation, created_at, updated_at
                "#,
            )
            .bind(user.id)
            .bind(&token_name)
            .bind(digest.to_vec())
            .fetch_one(&self.pool)
            .await;

            match result {
                Ok(row) => {
                    return Ok(IssuedUserToken {
                        user,
                        details: row.into(),
                        token,
                    });
                }
                Err(error) if is_unique_violation(&error) => {
                    if self.find_user_token(user.id, &token_name).await?.is_some() {
                        return Err(DbError::TokenAlreadyExists {
                            username,
                            token_name,
                        });
                    }
                }
                Err(error) => return Err(error.into()),
            }
        }

        Err(DbError::TokenCollision)
    }

    /// Rotate one named token. Other named credentials remain valid. The
    /// user-level watcher revision is advanced so already-authenticated
    /// sessions are forced to reauthenticate against current token state.
    pub async fn rotate_user_token(
        &self,
        username: &str,
        token_name: &str,
    ) -> Result<IssuedUserToken, DbError> {
        let username = normalize_username(username)?;
        let token_name = normalize_token_name(token_name)?;

        for _ in 0..TOKEN_INSERT_ATTEMPTS {
            let token = IssuedToken::generate();
            let digest = digest_token(token.expose_secret());
            let mut transaction = self.pool.begin().await?;
            let user = find_user_in(&mut transaction, &username)
                .await?
                .ok_or_else(|| DbError::UserNotFound {
                    username: username.clone(),
                })?;

            let rotated = sqlx::query_as::<_, UserTokenRow>(
                r#"
                UPDATE user_tokens
                SET token_digest = ?, generation = generation + 1, updated_at = unixepoch()
                WHERE user_id = ? AND name = ? AND generation < 9223372036854775807
                RETURNING id, user_id, name, generation, created_at, updated_at
                "#,
            )
            .bind(digest.to_vec())
            .bind(user.id)
            .bind(&token_name)
            .fetch_optional(&mut *transaction)
            .await;

            let details = match rotated {
                Ok(Some(row)) => UserTokenSummary::from(row),
                Ok(None) => {
                    let existing =
                        find_user_token_in(&mut transaction, user.id, &token_name).await?;
                    transaction.rollback().await?;
                    return match existing {
                        Some(_) => Err(DbError::TokenGenerationExhausted {
                            username,
                            token_name,
                        }),
                        None => Err(DbError::TokenNotFound {
                            username,
                            token_name,
                        }),
                    };
                }
                Err(error) if is_unique_violation(&error) => {
                    transaction.rollback().await?;
                    continue;
                }
                Err(error) => return Err(error.into()),
            };

            let advanced = advance_authentication_revision(&mut transaction, &username).await?;
            let Some(user) = advanced else {
                transaction.rollback().await?;
                return Err(DbError::RevisionExhausted { username });
            };
            transaction.commit().await?;
            return Ok(IssuedUserToken {
                user,
                details,
                token,
            });
        }

        Err(DbError::TokenCollision)
    }

    /// Revoke one named token and return only its safe metadata.
    pub async fn revoke_user_token(
        &self,
        username: &str,
        token_name: &str,
    ) -> Result<RevokedUserToken, DbError> {
        let username = normalize_username(username)?;
        let token_name = normalize_token_name(token_name)?;
        let mut transaction = self.pool.begin().await?;
        let user = find_user_in(&mut transaction, &username)
            .await?
            .ok_or_else(|| DbError::UserNotFound {
                username: username.clone(),
            })?;
        let revoked = sqlx::query_as::<_, UserTokenRow>(
            r#"
            DELETE FROM user_tokens
            WHERE user_id = ? AND name = ?
            RETURNING id, user_id, name, generation, created_at, updated_at
            "#,
        )
        .bind(user.id)
        .bind(&token_name)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or_else(|| DbError::TokenNotFound {
            username: username.clone(),
            token_name: token_name.clone(),
        })?;

        let Some(user) = advance_authentication_revision(&mut transaction, &username).await? else {
            transaction.rollback().await?;
            return Err(DbError::RevisionExhausted { username });
        };
        transaction.commit().await?;
        Ok(RevokedUserToken {
            user,
            token: revoked.into(),
        })
    }

    /// List safe metadata for a user's active named tokens. Digests are never
    /// selected by this query.
    pub async fn list_user_tokens(&self, username: &str) -> Result<Vec<UserTokenSummary>, DbError> {
        let username = normalize_username(username)?;
        let user = self
            .find_user(&username)
            .await?
            .ok_or_else(|| DbError::UserNotFound {
                username: username.clone(),
            })?;
        let rows = sqlx::query_as::<_, UserTokenRow>(
            r#"
            SELECT id, user_id, name, generation, created_at, updated_at
            FROM user_tokens
            WHERE user_id = ?
            ORDER BY name COLLATE NOCASE, id
            "#,
        )
        .bind(user.id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    pub async fn disable_user(&self, username: &str) -> Result<UserStateChange, DbError> {
        self.set_enabled(username, false).await
    }

    pub async fn enable_user(&self, username: &str) -> Result<UserStateChange, DbError> {
        self.set_enabled(username, true).await
    }

    /// List only safe account metadata. The query intentionally never joins
    /// the token table or selects a digest.
    pub async fn list_users(&self) -> Result<Vec<UserSummary>, DbError> {
        let rows = sqlx::query_as::<_, UserRow>(
            r#"
            SELECT id, username, enabled, token_generation, auth_revision, created_at
            FROM users
            ORDER BY username COLLATE NOCASE, id
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(Into::into).collect())
    }

    /// Atomically reserve a normalized namespace under a caller-supplied base
    /// domain policy. Root claims are depth 1. Deeper claims require an
    /// immediately adjacent parent owned by the same user.
    pub async fn create_namespace_claim(
        &self,
        user_id: i64,
        fqdn: &str,
        base_domain: &str,
        max_depth: u32,
    ) -> Result<NamespaceClaim, DbError> {
        self.create_namespace_claim_with_tls_mode(
            user_id,
            fqdn,
            base_domain,
            max_depth,
            NamespaceTlsMode::Managed,
        )
        .await
    }

    /// Atomically reserve a normalized namespace with an explicit immutable
    /// TLS mode. Passthrough ownership is active immediately because it has no
    /// certificate-order prerequisite.
    pub async fn create_namespace_claim_with_tls_mode(
        &self,
        user_id: i64,
        fqdn: &str,
        base_domain: &str,
        max_depth: u32,
        tls_mode: NamespaceTlsMode,
    ) -> Result<NamespaceClaim, DbError> {
        let fqdn = normalize_fqdn(fqdn)?;
        let base_domain = normalize_fqdn(base_domain)?;
        let depth = namespace_depth(&fqdn, &base_domain)?;
        if depth > max_depth {
            return Err(DbError::NamespaceDepthExceeded {
                fqdn,
                depth,
                max_depth,
            });
        }
        if self.find_user_by_id(user_id).await?.is_none() {
            return Err(DbError::UserIdNotFound { user_id });
        }
        let initial_state = match tls_mode {
            NamespaceTlsMode::Managed => NamespaceClaimState::Pending,
            NamespaceTlsMode::Passthrough => NamespaceClaimState::Active,
        };

        let result = if depth == 1 {
            sqlx::query_as::<_, NamespaceClaimRow>(
                r#"
                INSERT INTO namespace_claims (user_id, fqdn, parent_id, depth, tls_mode, state)
                VALUES (?, ?, NULL, ?, ?, ?)
                RETURNING id, user_id, fqdn, parent_id, depth, tls_mode, state,
                          created_at, updated_at
                "#,
            )
            .bind(user_id)
            .bind(&fqdn)
            .bind(i64::from(depth))
            .bind(tls_mode.as_str())
            .bind(initial_state.as_str())
            .fetch_one(&self.pool)
            .await
        } else {
            let parent_fqdn =
                direct_parent(&fqdn).ok_or_else(|| DbError::InvalidFqdn { fqdn: fqdn.clone() })?;
            let inserted = sqlx::query_as::<_, NamespaceClaimRow>(
                r#"
                INSERT INTO namespace_claims (
                    user_id, fqdn, parent_id, depth, tls_mode, state
                )
                SELECT ?, ?, id, ?, ?, ?
                FROM namespace_claims
                WHERE fqdn = ? AND user_id = ? AND state <> 'releasing'
                RETURNING id, user_id, fqdn, parent_id, depth, tls_mode, state,
                          created_at, updated_at
                "#,
            )
            .bind(user_id)
            .bind(&fqdn)
            .bind(i64::from(depth))
            .bind(tls_mode.as_str())
            .bind(initial_state.as_str())
            .bind(parent_fqdn)
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await;

            match inserted {
                Ok(Some(row)) => Ok(row),
                Ok(None) => {
                    let parent = self.find_namespace_claim_normalized(parent_fqdn).await?;
                    return match parent {
                        None => Err(DbError::ParentNamespaceNotClaimed {
                            fqdn: parent_fqdn.to_owned(),
                        }),
                        Some(parent) if parent.user_id != user_id => {
                            Err(DbError::ParentNamespaceOwnedByAnotherUser { fqdn: parent.fqdn })
                        }
                        Some(parent) => {
                            Err(DbError::ParentNamespaceReleasing { fqdn: parent.fqdn })
                        }
                    };
                }
                Err(error) => Err(error),
            }
        };

        match result {
            Ok(row) => NamespaceClaim::try_from(row),
            Err(error) if is_passthrough_overlap_violation(&error) => {
                Err(DbError::PassthroughNamespaceOverlap { fqdn })
            }
            Err(error) if is_unique_violation(&error) => {
                let existing = self.find_namespace_claim_normalized(&fqdn).await?;
                if let Some(existing) = existing {
                    Err(DbError::NamespaceAlreadyClaimed {
                        fqdn,
                        owner_user_id: existing.user_id,
                    })
                } else {
                    Err(DbError::Sql(error))
                }
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Find an exact namespace claim after canonical FQDN normalization.
    pub async fn namespace_claim(&self, fqdn: &str) -> Result<Option<NamespaceClaim>, DbError> {
        let fqdn = normalize_fqdn(fqdn)?;
        self.find_namespace_claim_normalized(&fqdn).await
    }

    /// Return the most specific claim that can govern a route: an exact claim
    /// takes precedence, otherwise only the route's direct parent is eligible.
    /// The caller decides how lifecycle state affects admission.
    pub async fn namespace_claim_for_route(
        &self,
        hostname: &str,
    ) -> Result<Option<NamespaceClaim>, DbError> {
        let hostname = normalize_fqdn(hostname)?;
        if let Some(exact) = self.find_namespace_claim_normalized(&hostname).await? {
            return Ok(Some(exact));
        }
        let Some(parent) = direct_parent(&hostname) else {
            return Ok(None);
        };
        self.find_namespace_claim_normalized(parent).await
    }

    /// Return the active passthrough namespace whose wildcard covers this
    /// hostname. Coverage is deliberately limited to the apex and one label
    /// below it, even when a deeper managed namespace exists.
    pub async fn active_passthrough_claim_for_route(
        &self,
        hostname: &str,
    ) -> Result<Option<NamespaceClaim>, DbError> {
        let hostname = normalize_fqdn(hostname)?;
        if let Some(exact) = self.find_namespace_claim_normalized(&hostname).await?
            && exact.tls_mode == NamespaceTlsMode::Passthrough
            && exact.state == NamespaceClaimState::Active
        {
            return Ok(Some(exact));
        }
        let Some(parent) = direct_parent(&hostname) else {
            return Ok(None);
        };
        let claim = self.find_namespace_claim_normalized(parent).await?;
        Ok(claim.filter(|claim| {
            claim.tls_mode == NamespaceTlsMode::Passthrough
                && claim.state == NamespaceClaimState::Active
        }))
    }

    /// List managed-TLS claims only. Certificate lifecycle and TLS-boundary
    /// restart code intentionally use this view so passthrough namespaces can
    /// never schedule or require Sink certificate material.
    pub async fn list_namespace_claims(
        &self,
        user_id: i64,
    ) -> Result<Vec<NamespaceClaim>, DbError> {
        let rows = sqlx::query_as::<_, NamespaceClaimRow>(
            r#"
            SELECT id, user_id, fqdn, parent_id, depth, tls_mode, state,
                   created_at, updated_at
            FROM namespace_claims
            WHERE user_id = ? AND tls_mode = 'managed'
            ORDER BY depth, fqdn COLLATE NOCASE, id
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(NamespaceClaim::try_from).collect()
    }

    /// List every namespace mode for control-plane status, hierarchy, and
    /// release decisions.
    pub async fn list_all_namespace_claims(
        &self,
        user_id: i64,
    ) -> Result<Vec<NamespaceClaim>, DbError> {
        let rows = sqlx::query_as::<_, NamespaceClaimRow>(
            r#"
            SELECT id, user_id, fqdn, parent_id, depth, tls_mode, state,
                   created_at, updated_at
            FROM namespace_claims
            WHERE user_id = ?
            ORDER BY depth, fqdn COLLATE NOCASE, id
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(NamespaceClaim::try_from).collect()
    }

    /// Find a live passthrough wildcard whose apex is equal or immediately
    /// adjacent to `fqdn`. Such a claim would overlap a new wildcard.
    pub async fn overlapping_active_passthrough_claim(
        &self,
        fqdn: &str,
    ) -> Result<Option<NamespaceClaim>, DbError> {
        let fqdn = normalize_fqdn(fqdn)?;
        let rows = sqlx::query_as::<_, NamespaceClaimRow>(
            r#"
            SELECT id, user_id, fqdn, parent_id, depth, tls_mode, state,
                   created_at, updated_at
            FROM namespace_claims
            WHERE tls_mode = 'passthrough' AND state = 'active'
            ORDER BY depth DESC, fqdn COLLATE NOCASE, id
            "#,
        )
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(NamespaceClaim::try_from)
            .find_map(|claim| match claim {
                Ok(claim)
                    if claim.fqdn == fqdn
                        || direct_parent(&claim.fqdn) == Some(fqdn.as_str())
                        || direct_parent(&fqdn) == Some(claim.fqdn.as_str()) =>
                {
                    Some(Ok(claim))
                }
                Ok(_) => None,
                Err(error) => Some(Err(error)),
            })
            .transpose()
    }

    /// Compare-and-set a claim lifecycle state. This primitive lets the later
    /// control plane coordinate provisioning/retry/release without lost
    /// updates.
    pub async fn transition_namespace_claim(
        &self,
        user_id: i64,
        fqdn: &str,
        expected: NamespaceClaimState,
        next: NamespaceClaimState,
    ) -> Result<NamespaceClaim, DbError> {
        let fqdn = normalize_fqdn(fqdn)?;
        let updated = sqlx::query_as::<_, NamespaceClaimRow>(
            r#"
            UPDATE namespace_claims
            SET state = ?, updated_at = unixepoch()
            WHERE fqdn = ? AND user_id = ? AND state = ?
            RETURNING id, user_id, fqdn, parent_id, depth, tls_mode, state,
                      created_at, updated_at
            "#,
        )
        .bind(next.as_str())
        .bind(&fqdn)
        .bind(user_id)
        .bind(expected.as_str())
        .fetch_optional(&self.pool)
        .await?;
        if let Some(row) = updated {
            return NamespaceClaim::try_from(row);
        }
        let current = self
            .find_namespace_claim_normalized(&fqdn)
            .await?
            .ok_or_else(|| DbError::NamespaceNotFound { fqdn: fqdn.clone() })?;
        if current.user_id != user_id {
            return Err(DbError::NamespaceNotOwned { fqdn });
        }
        Err(DbError::NamespaceStateConflict {
            fqdn,
            expected,
            actual: current.state,
        })
    }

    /// Delete a released claim only after it has entered `releasing` and has
    /// no child claims. Active-route checks remain a later runtime concern.
    pub async fn delete_releasing_namespace_claim(
        &self,
        user_id: i64,
        fqdn: &str,
    ) -> Result<NamespaceClaim, DbError> {
        let fqdn = normalize_fqdn(fqdn)?;
        let deleted = sqlx::query_as::<_, NamespaceClaimRow>(
            r#"
            DELETE FROM namespace_claims
            WHERE fqdn = ?
              AND user_id = ?
              AND state = 'releasing'
              AND NOT EXISTS (
                  SELECT 1 FROM namespace_claims AS child
                  WHERE child.parent_id = namespace_claims.id
              )
            RETURNING id, user_id, fqdn, parent_id, depth, tls_mode, state,
                      created_at, updated_at
            "#,
        )
        .bind(&fqdn)
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;
        if let Some(row) = deleted {
            return NamespaceClaim::try_from(row);
        }
        let current = self
            .find_namespace_claim_normalized(&fqdn)
            .await?
            .ok_or_else(|| DbError::NamespaceNotFound { fqdn: fqdn.clone() })?;
        if current.user_id != user_id {
            return Err(DbError::NamespaceNotOwned { fqdn });
        }
        if current.state != NamespaceClaimState::Releasing {
            return Err(DbError::NamespaceStateConflict {
                fqdn,
                expected: NamespaceClaimState::Releasing,
                actual: current.state,
            });
        }
        Err(DbError::NamespaceHasChildren { fqdn })
    }

    async fn set_enabled(&self, username: &str, enabled: bool) -> Result<UserStateChange, DbError> {
        let username = normalize_username(username)?;
        let row = sqlx::query_as::<_, UserRow>(
            r#"
            UPDATE users
            SET enabled = ?, auth_revision = auth_revision + 1, updated_at = unixepoch()
            WHERE username = ?
              AND enabled <> ?
              AND auth_revision < 9223372036854775807
            RETURNING id, username, enabled, token_generation, auth_revision, created_at
            "#,
        )
        .bind(enabled)
        .bind(&username)
        .bind(enabled)
        .fetch_optional(&self.pool)
        .await?;

        if let Some(row) = row {
            return Ok(UserStateChange {
                user: row.into(),
                changed: true,
            });
        }

        let user = self
            .find_user(&username)
            .await?
            .ok_or_else(|| DbError::UserNotFound {
                username: username.clone(),
            })?;
        if user.enabled == enabled {
            Ok(UserStateChange {
                user,
                changed: false,
            })
        } else {
            Err(DbError::RevisionExhausted { username })
        }
    }

    async fn find_user(&self, username: &str) -> Result<Option<UserSummary>, DbError> {
        let row = sqlx::query_as::<_, UserRow>(
            r#"
            SELECT id, username, enabled, token_generation, auth_revision, created_at
            FROM users
            WHERE username = ?
            "#,
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(Into::into))
    }

    async fn find_user_by_id(&self, user_id: i64) -> Result<Option<UserSummary>, DbError> {
        let row = sqlx::query_as::<_, UserRow>(
            r#"
            SELECT id, username, enabled, token_generation, auth_revision, created_at
            FROM users
            WHERE id = ?
            "#,
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(Into::into))
    }

    async fn find_user_token(
        &self,
        user_id: i64,
        token_name: &str,
    ) -> Result<Option<UserTokenSummary>, DbError> {
        let row = sqlx::query_as::<_, UserTokenRow>(
            r#"
            SELECT id, user_id, name, generation, created_at, updated_at
            FROM user_tokens
            WHERE user_id = ? AND name = ?
            "#,
        )
        .bind(user_id)
        .bind(token_name)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(Into::into))
    }

    async fn find_namespace_claim_normalized(
        &self,
        fqdn: &str,
    ) -> Result<Option<NamespaceClaim>, DbError> {
        let row = sqlx::query_as::<_, NamespaceClaimRow>(
            r#"
            SELECT id, user_id, fqdn, parent_id, depth, tls_mode, state,
                   created_at, updated_at
            FROM namespace_claims
            WHERE fqdn = ?
            "#,
        )
        .bind(fqdn)
        .fetch_optional(&self.pool)
        .await?;
        row.map(NamespaceClaim::try_from).transpose()
    }
}

async fn find_user_in(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    username: &str,
) -> Result<Option<UserSummary>, sqlx::Error> {
    let row = sqlx::query_as::<_, UserRow>(
        r#"
        SELECT id, username, enabled, token_generation, auth_revision, created_at
        FROM users
        WHERE username = ?
        "#,
    )
    .bind(username)
    .fetch_optional(&mut **transaction)
    .await?;
    Ok(row.map(Into::into))
}

async fn find_user_token_in(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    user_id: i64,
    token_name: &str,
) -> Result<Option<UserTokenSummary>, sqlx::Error> {
    let row = sqlx::query_as::<_, UserTokenRow>(
        r#"
        SELECT id, user_id, name, generation, created_at, updated_at
        FROM user_tokens
        WHERE user_id = ? AND name = ?
        "#,
    )
    .bind(user_id)
    .bind(token_name)
    .fetch_optional(&mut **transaction)
    .await?;
    Ok(row.map(Into::into))
}

async fn advance_authentication_revision(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    username: &str,
) -> Result<Option<UserSummary>, sqlx::Error> {
    let row = sqlx::query_as::<_, UserRow>(
        r#"
        UPDATE users
        SET token_generation = token_generation + 1,
            auth_revision = auth_revision + 1,
            updated_at = unixepoch()
        WHERE username = ?
          AND token_generation < 9223372036854775807
          AND auth_revision < 9223372036854775807
        RETURNING id, username, enabled, token_generation, auth_revision, created_at
        "#,
    )
    .bind(username)
    .fetch_optional(&mut **transaction)
    .await?;
    Ok(row.map(Into::into))
}

/// A one-time bearer token. It is zeroized on drop, has redacted `Debug`, and
/// deliberately has no `Display` implementation. Callers must explicitly opt
/// into exposing it for creation/rotation output.
pub struct IssuedToken {
    value: Zeroizing<String>,
}

impl IssuedToken {
    fn generate() -> Self {
        let mut random = [0_u8; TOKEN_RANDOM_BYTES];
        rand::rng().fill_bytes(&mut random);
        let token = format!("sink_{}", URL_SAFE_NO_PAD.encode(random));
        Self {
            value: Zeroizing::new(token),
        }
    }

    pub fn expose_secret(&self) -> &str {
        self.value.as_str()
    }

    /// Construct the complete HTTP Authorization value. The returned string is
    /// also zeroized on drop.
    pub fn bearer_authorization(&self) -> Zeroizing<String> {
        Zeroizing::new(format!("Bearer {}", self.expose_secret()))
    }
}

impl fmt::Debug for IssuedToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("IssuedToken([REDACTED])")
    }
}

#[derive(Debug)]
pub struct IssuedUser {
    pub user: UserSummary,
    pub token: IssuedToken,
}

#[derive(Debug)]
pub struct IssuedUserToken {
    pub user: UserSummary,
    pub details: UserTokenSummary,
    pub token: IssuedToken,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevokedUserToken {
    pub user: UserSummary,
    pub token: UserTokenSummary,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UserTokenSummary {
    pub id: i64,
    pub user_id: i64,
    pub name: String,
    pub generation: i64,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UserSummary {
    pub id: i64,
    pub username: String,
    pub enabled: bool,
    /// Aggregate credential revision retained for runtime compatibility.
    pub token_generation: i64,
    pub auth_revision: i64,
    pub created_at: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedUser {
    pub id: i64,
    pub username: String,
    pub token_generation: i64,
    pub auth_revision: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthenticationState {
    pub user_id: i64,
    pub enabled: bool,
    pub token_generation: i64,
    pub auth_revision: i64,
}

impl AuthenticationState {
    /// Whether this state still authorizes a session created by `user`.
    pub fn still_authorizes(&self, user: &AuthenticatedUser) -> bool {
        self.user_id == user.id
            && self.enabled
            && self.token_generation == user.token_generation
            && self.auth_revision == user.auth_revision
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UserStateChange {
    pub user: UserSummary,
    pub changed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NamespaceClaimState {
    Pending,
    Active,
    Failed,
    Retrying,
    Releasing,
}

impl NamespaceClaimState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Failed => "failed",
            Self::Retrying => "retrying",
            Self::Releasing => "releasing",
        }
    }
}

impl fmt::Display for NamespaceClaimState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl TryFrom<&str> for NamespaceClaimState {
    type Error = DbError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "pending" => Ok(Self::Pending),
            "active" => Ok(Self::Active),
            "failed" => Ok(Self::Failed),
            "retrying" => Ok(Self::Retrying),
            "releasing" => Ok(Self::Releasing),
            other => Err(DbError::InvalidNamespaceState {
                state: other.to_owned(),
            }),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NamespaceTlsMode {
    Managed,
    Passthrough,
}

impl NamespaceTlsMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Managed => "managed",
            Self::Passthrough => "passthrough",
        }
    }
}

impl fmt::Display for NamespaceTlsMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl TryFrom<&str> for NamespaceTlsMode {
    type Error = DbError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "managed" => Ok(Self::Managed),
            "passthrough" => Ok(Self::Passthrough),
            other => Err(DbError::InvalidNamespaceTlsMode {
                tls_mode: other.to_owned(),
            }),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamespaceClaim {
    pub id: i64,
    pub user_id: i64,
    pub fqdn: String,
    pub parent_id: Option<i64>,
    pub depth: u32,
    pub tls_mode: NamespaceTlsMode,
    pub state: NamespaceClaimState,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Error)]
pub enum DbError {
    #[error("username cannot be empty")]
    EmptyUsername,
    #[error("username exceeds {MAX_USERNAME_BYTES} bytes")]
    UsernameTooLong,
    #[error("user `{username}` already exists")]
    UserAlreadyExists { username: String },
    #[error("user `{username}` was not found")]
    UserNotFound { username: String },
    #[error("user id {user_id} was not found")]
    UserIdNotFound { user_id: i64 },
    #[error("authentication revision exhausted for user `{username}`")]
    RevisionExhausted { username: String },
    #[error("token name cannot be empty")]
    EmptyTokenName,
    #[error("token name exceeds {MAX_TOKEN_NAME_BYTES} bytes")]
    TokenNameTooLong,
    #[error("token name `{token_name}` contains unsafe characters")]
    InvalidTokenName { token_name: String },
    #[error("token `{token_name}` already exists for user `{username}`")]
    TokenAlreadyExists {
        username: String,
        token_name: String,
    },
    #[error("token `{token_name}` was not found for user `{username}`")]
    TokenNotFound {
        username: String,
        token_name: String,
    },
    #[error("generation exhausted for token `{token_name}` of user `{username}`")]
    TokenGenerationExhausted {
        username: String,
        token_name: String,
    },
    #[error("could not generate a unique user token")]
    TokenCollision,
    #[error("hostname cannot be empty")]
    EmptyFqdn,
    #[error("hostname exceeds {MAX_FQDN_BYTES} bytes")]
    FqdnTooLong,
    #[error("hostname `{fqdn}` is not a normalized DNS name")]
    InvalidFqdn { fqdn: String },
    #[error("the base domain `{base_domain}` itself cannot be claimed")]
    CannotClaimBaseDomain { base_domain: String },
    #[error("namespace `{fqdn}` is not below base domain `{base_domain}`")]
    NamespaceOutsideBaseDomain { fqdn: String, base_domain: String },
    #[error("namespace `{fqdn}` depth {depth} exceeds configured maximum {max_depth}")]
    NamespaceDepthExceeded {
        fqdn: String,
        depth: u32,
        max_depth: u32,
    },
    #[error("namespace `{fqdn}` is already claimed by user id {owner_user_id}")]
    NamespaceAlreadyClaimed { fqdn: String, owner_user_id: i64 },
    #[error("passthrough namespace `{fqdn}` overlaps an active passthrough namespace")]
    PassthroughNamespaceOverlap { fqdn: String },
    #[error("parent namespace `{fqdn}` has not been claimed")]
    ParentNamespaceNotClaimed { fqdn: String },
    #[error("parent namespace `{fqdn}` belongs to another user")]
    ParentNamespaceOwnedByAnotherUser { fqdn: String },
    #[error("parent namespace `{fqdn}` is being released")]
    ParentNamespaceReleasing { fqdn: String },
    #[error("namespace `{fqdn}` was not found")]
    NamespaceNotFound { fqdn: String },
    #[error("namespace `{fqdn}` is not owned by this user")]
    NamespaceNotOwned { fqdn: String },
    #[error("namespace `{fqdn}` has child claims")]
    NamespaceHasChildren { fqdn: String },
    #[error("namespace `{fqdn}` state is `{actual}`, expected `{expected}`")]
    NamespaceStateConflict {
        fqdn: String,
        expected: NamespaceClaimState,
        actual: NamespaceClaimState,
    },
    #[error("database contained invalid namespace state `{state}`")]
    InvalidNamespaceState { state: String },
    #[error("database contained invalid namespace TLS mode `{tls_mode}`")]
    InvalidNamespaceTlsMode { tls_mode: String },
    #[error("database operation failed")]
    Sql(#[from] sqlx::Error),
    #[error("database migration failed")]
    Migration(#[from] MigrateError),
}

type UserRow = (i64, String, bool, i64, i64, i64);
type UserTokenRow = (i64, i64, String, i64, i64, i64);
type AuthenticationRow = (i64, String, i64, i64);
type AuthenticationStateRow = (i64, bool, i64, i64);
type NamespaceClaimRow = (i64, i64, String, Option<i64>, i64, String, String, i64, i64);

impl From<UserRow> for UserSummary {
    fn from((id, username, enabled, token_generation, auth_revision, created_at): UserRow) -> Self {
        Self {
            id,
            username,
            enabled,
            token_generation,
            auth_revision,
            created_at,
        }
    }
}

impl From<UserTokenRow> for UserTokenSummary {
    fn from((id, user_id, name, generation, created_at, updated_at): UserTokenRow) -> Self {
        Self {
            id,
            user_id,
            name,
            generation,
            created_at,
            updated_at,
        }
    }
}

impl From<AuthenticationRow> for AuthenticatedUser {
    fn from((id, username, token_generation, auth_revision): AuthenticationRow) -> Self {
        Self {
            id,
            username,
            token_generation,
            auth_revision,
        }
    }
}

impl From<AuthenticationStateRow> for AuthenticationState {
    fn from((user_id, enabled, token_generation, auth_revision): AuthenticationStateRow) -> Self {
        Self {
            user_id,
            enabled,
            token_generation,
            auth_revision,
        }
    }
}

impl TryFrom<NamespaceClaimRow> for NamespaceClaim {
    type Error = DbError;

    fn try_from(
        (
            id,
            user_id,
            fqdn,
            parent_id,
            depth,
            tls_mode,
            state,
            created_at,
            updated_at,
        ): NamespaceClaimRow,
    ) -> Result<Self, Self::Error> {
        let depth =
            u32::try_from(depth).map_err(|_| DbError::InvalidFqdn { fqdn: fqdn.clone() })?;
        Ok(Self {
            id,
            user_id,
            fqdn,
            parent_id,
            depth,
            tls_mode: NamespaceTlsMode::try_from(tls_mode.as_str())?,
            state: NamespaceClaimState::try_from(state.as_str())?,
            created_at,
            updated_at,
        })
    }
}

fn normalize_username(username: &str) -> Result<String, DbError> {
    let username = username.trim();
    if username.is_empty() {
        return Err(DbError::EmptyUsername);
    }
    if username.len() > MAX_USERNAME_BYTES {
        return Err(DbError::UsernameTooLong);
    }
    Ok(username.to_owned())
}

fn normalize_token_name(token_name: &str) -> Result<String, DbError> {
    let token_name = token_name.trim();
    if token_name.is_empty() {
        return Err(DbError::EmptyTokenName);
    }
    if token_name.len() > MAX_TOKEN_NAME_BYTES {
        return Err(DbError::TokenNameTooLong);
    }
    if !token_name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(DbError::InvalidTokenName {
            token_name: token_name.to_owned(),
        });
    }
    Ok(token_name.to_owned())
}

/// Normalize an ASCII FQDN to lowercase without a trailing root dot.
pub fn normalize_fqdn(fqdn: &str) -> Result<String, DbError> {
    if fqdn.trim() != fqdn {
        return Err(DbError::InvalidFqdn {
            fqdn: fqdn.to_owned(),
        });
    }
    let fqdn = fqdn.strip_suffix('.').unwrap_or(fqdn);
    if fqdn.is_empty() {
        return Err(DbError::EmptyFqdn);
    }
    if fqdn.len() > MAX_FQDN_BYTES {
        return Err(DbError::FqdnTooLong);
    }
    if !fqdn.is_ascii() {
        return Err(DbError::InvalidFqdn {
            fqdn: fqdn.to_owned(),
        });
    }
    let normalized = fqdn.to_ascii_lowercase();
    let valid = normalized.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    });
    if !valid {
        return Err(DbError::InvalidFqdn { fqdn: normalized });
    }
    Ok(normalized)
}

fn namespace_depth(fqdn: &str, base_domain: &str) -> Result<u32, DbError> {
    if fqdn == base_domain {
        return Err(DbError::CannotClaimBaseDomain {
            base_domain: base_domain.to_owned(),
        });
    }
    let suffix = format!(".{base_domain}");
    let relative =
        fqdn.strip_suffix(&suffix)
            .ok_or_else(|| DbError::NamespaceOutsideBaseDomain {
                fqdn: fqdn.to_owned(),
                base_domain: base_domain.to_owned(),
            })?;
    u32::try_from(relative.split('.').count()).map_err(|_| DbError::FqdnTooLong)
}

fn direct_parent(fqdn: &str) -> Option<&str> {
    fqdn.split_once('.').map(|(_, parent)| parent)
}

fn digest_token(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

fn is_unique_violation(error: &sqlx::Error) -> bool {
    matches!(error, sqlx::Error::Database(error) if error.is_unique_violation())
}

fn is_passthrough_overlap_violation(error: &sqlx::Error) -> bool {
    matches!(
        error,
        sqlx::Error::Database(error)
            if error.message().contains("overlapping passthrough namespace")
    )
}

#[cfg(test)]
mod tests {
    use std::{error::Error, fs};

    use sqlx::{Connection as _, Executor as _, SqliteConnection};
    use tempfile::TempDir;

    use super::*;

    async fn temporary_database() -> Result<(TempDir, std::path::PathBuf, Database), DbError> {
        let directory = tempfile::tempdir().map_err(sqlx::Error::Io)?;
        let path = directory.path().join("users.sqlite3");
        let database = Database::open(&path).await?;
        Ok((directory, path, database))
    }

    #[tokio::test]
    async fn legacy_token_migrates_and_remains_valid() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("legacy.sqlite3");
        let options = SqliteConnectOptions::new()
            .filename(&path)
            .create_if_missing(true)
            .foreign_keys(true);
        let mut connection = SqliteConnection::connect_with(&options).await?;
        connection
            .execute(sqlx::raw_sql(include_str!("../migrations/0001_users.sql")))
            .await?;
        let legacy_token = "sink_legacy-token";
        sqlx::query(
            r#"
            INSERT INTO users (username, token_digest, token_generation, auth_revision)
            VALUES ('legacy', ?, 7, 11)
            "#,
        )
        .bind(digest_token(legacy_token).to_vec())
        .execute(&mut connection)
        .await?;
        let mut migration = connection.begin().await?;
        (&mut *migration)
            .execute(sqlx::raw_sql(include_str!(
                "../migrations/0002_user_tokens_and_namespace_claims.sql"
            )))
            .await?;
        migration.commit().await?;
        connection.close().await?;

        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await?;
        let database = Database { pool };
        assert!(
            sqlx::query("SELECT token_digest FROM users")
                .execute(&database.pool)
                .await
                .is_err(),
            "the legacy digest column must not remain on users"
        );
        assert!(
            sqlx::query("PRAGMA foreign_key_check")
                .fetch_all(&database.pool)
                .await?
                .is_empty()
        );
        let authenticated = database
            .authenticate(legacy_token)
            .await?
            .ok_or("legacy token did not authenticate")?;
        assert_eq!(authenticated.username, "legacy");
        assert_eq!(authenticated.token_generation, 7);
        let tokens = database.list_user_tokens("legacy").await?;
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].name, DEFAULT_TOKEN_NAME);
        assert_eq!(tokens[0].generation, 7);
        Ok(())
    }

    #[tokio::test]
    async fn namespace_tls_mode_migration_backfills_managed_and_enforces_values()
    -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("namespace-mode-migration.sqlite3");
        let options = SqliteConnectOptions::new()
            .filename(&path)
            .create_if_missing(true)
            .foreign_keys(true);
        let mut connection = SqliteConnection::connect_with(&options).await?;
        connection
            .execute(sqlx::raw_sql(include_str!("../migrations/0001_users.sql")))
            .await?;
        sqlx::query(
            r#"
            INSERT INTO users (username, token_digest)
            VALUES ('legacy', zeroblob(32))
            "#,
        )
        .execute(&mut connection)
        .await?;
        connection
            .execute(sqlx::raw_sql(include_str!(
                "../migrations/0002_user_tokens_and_namespace_claims.sql"
            )))
            .await?;
        sqlx::query(
            r#"
            INSERT INTO namespace_claims (user_id, fqdn, depth, state)
            VALUES (1, 'cloud.example.test', 1, 'active')
            "#,
        )
        .execute(&mut connection)
        .await?;
        connection
            .execute(sqlx::raw_sql(include_str!(
                "../migrations/0004_namespace_tls_mode.sql"
            )))
            .await?;

        let mode: String = sqlx::query_scalar("SELECT tls_mode FROM namespace_claims WHERE id = 1")
            .fetch_one(&mut connection)
            .await?;
        assert_eq!(mode, "managed");
        assert!(
            sqlx::query("UPDATE namespace_claims SET tls_mode = 'passthrough' WHERE id = 1")
                .execute(&mut connection)
                .await
                .is_err()
        );
        assert!(
            sqlx::query(
                r#"
                INSERT INTO namespace_claims (user_id, fqdn, depth, tls_mode)
                VALUES (1, 'invalid.example.test', 1, 'invalid')
                "#,
            )
            .execute(&mut connection)
            .await
            .is_err()
        );
        connection.close().await?;
        Ok(())
    }

    #[tokio::test]
    async fn users_and_all_named_tokens_persist_across_reopen() -> Result<(), Box<dyn Error>> {
        let (_directory, path, database) = temporary_database().await?;
        let default = database.create_user("alice").await?;
        let cloud = database.create_user_token("alice", "cloud").await?;
        let user_id = default.user.id;
        database.close().await;

        let reopened = Database::open(path).await?;
        for secret in [default.token.expose_secret(), cloud.token.expose_secret()] {
            let authenticated = reopened
                .authenticate(secret)
                .await?
                .ok_or("persisted token did not authenticate")?;
            assert_eq!(authenticated.id, user_id);
        }
        Ok(())
    }

    #[tokio::test]
    async fn named_token_lifecycle_preserves_sibling_credentials() -> Result<(), Box<dyn Error>> {
        let (_directory, _path, database) = temporary_database().await?;
        let default = database.create_user("alice").await?;
        let cloud = database.create_user_token("alice", "cloud").await?;
        assert!(matches!(
            database.create_user_token("alice", "CLOUD").await,
            Err(DbError::TokenAlreadyExists { .. })
        ));

        let initial_auth = database
            .authenticate(cloud.token.expose_secret())
            .await?
            .ok_or("named token did not authenticate")?;
        let rotated = database.rotate_user_token("alice", "cloud").await?;
        assert_eq!(rotated.details.generation, 2);
        assert!(
            database
                .authenticate(cloud.token.expose_secret())
                .await?
                .is_none()
        );
        assert!(
            database
                .authenticate(rotated.token.expose_secret())
                .await?
                .is_some()
        );
        assert!(
            database
                .authenticate(default.token.expose_secret())
                .await?
                .is_some(),
            "rotating one token must not revoke its sibling"
        );
        let state = database
            .authentication_state(default.user.id)
            .await?
            .ok_or("user state disappeared")?;
        assert!(!state.still_authorizes(&initial_auth));

        database.revoke_user_token("alice", "cloud").await?;
        assert!(
            database
                .authenticate(rotated.token.expose_secret())
                .await?
                .is_none()
        );
        assert!(
            database
                .authenticate(default.token.expose_secret())
                .await?
                .is_some()
        );
        assert_eq!(database.list_user_tokens("alice").await?.len(), 1);
        assert!(matches!(
            database.rotate_user_token("alice", "cloud").await,
            Err(DbError::TokenNotFound { .. })
        ));
        Ok(())
    }

    #[tokio::test]
    async fn disable_enable_and_legacy_rotation_remain_compatible() -> Result<(), Box<dyn Error>> {
        let (_directory, _path, database) = temporary_database().await?;
        let created = database.create_user("alice").await?;
        database.disable_user("alice").await?;
        assert!(
            database
                .authenticate(created.token.expose_secret())
                .await?
                .is_none()
        );
        database.enable_user("alice").await?;
        let rotated = database.rotate_token("alice").await?;
        assert!(
            database
                .authenticate(created.token.expose_secret())
                .await?
                .is_none()
        );
        assert!(
            database
                .authenticate(rotated.token.expose_secret())
                .await?
                .is_some()
        );
        Ok(())
    }

    #[tokio::test]
    async fn safe_views_and_database_never_store_plaintext_tokens() -> Result<(), Box<dyn Error>> {
        let (_directory, path, database) = temporary_database().await?;
        let created = database.create_user("alice").await?;
        let named = database.create_user_token("alice", "automation").await?;
        let safe = format!(
            "{:?}{:?}",
            database.list_users().await?,
            database.list_user_tokens("alice").await?
        );
        assert!(!safe.contains(created.token.expose_secret()));
        assert!(!format!("{named:?}").contains(named.token.expose_secret()));

        database.close().await;
        let bytes = fs::read(path)?;
        for secret in [created.token.expose_secret(), named.token.expose_secret()] {
            assert!(
                !bytes
                    .windows(secret.len())
                    .any(|part| part == secret.as_bytes())
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn namespace_claims_enforce_depth_and_parent_ownership() -> Result<(), Box<dyn Error>> {
        let (_directory, _path, database) = temporary_database().await?;
        let alice = database.create_user("alice").await?;
        let bob = database.create_user("bob").await?;

        let root = database
            .create_namespace_claim(alice.user.id, "Cloud.Example.Test.", "example.test", 2)
            .await?;
        assert_eq!(root.fqdn, "cloud.example.test");
        assert_eq!((root.depth, root.parent_id), (1, None));
        assert!(matches!(
            database
                .create_namespace_claim(bob.user.id, "edge.cloud.example.test", "example.test", 2)
                .await,
            Err(DbError::ParentNamespaceOwnedByAnotherUser { .. })
        ));

        let child = database
            .create_namespace_claim(alice.user.id, "edge.cloud.example.test", "example.test", 2)
            .await?;
        assert_eq!((child.depth, child.parent_id), (2, Some(root.id)));
        assert_eq!(
            database
                .namespace_claim_for_route("api.edge.cloud.example.test")
                .await?
                .ok_or("direct child was not covered")?
                .id,
            child.id
        );
        assert!(
            database
                .namespace_claim_for_route("deep.api.edge.cloud.example.test")
                .await?
                .is_none(),
            "claims must not cover arbitrary descendant depth"
        );
        assert_eq!(
            database.list_namespace_claims(alice.user.id).await?.len(),
            2
        );
        assert!(matches!(
            database
                .create_namespace_claim(
                    alice.user.id,
                    "region.edge.cloud.example.test",
                    "example.test",
                    2,
                )
                .await,
            Err(DbError::NamespaceDepthExceeded { depth: 3, .. })
        ));
        assert!(matches!(
            database
                .create_namespace_claim(alice.user.id, "example.test", "example.test", 2)
                .await,
            Err(DbError::CannotClaimBaseDomain { .. })
        ));
        assert!(matches!(
            database
                .create_namespace_claim(alice.user.id, "other.test", "example.test", 2)
                .await,
            Err(DbError::NamespaceOutsideBaseDomain { .. })
        ));
        Ok(())
    }

    #[tokio::test]
    async fn passthrough_mode_is_active_persistent_and_excluded_from_managed_tls_views()
    -> Result<(), Box<dyn Error>> {
        let (directory, path, database) = temporary_database().await?;
        let alice = database.create_user("alice").await?;
        let claim = database
            .create_namespace_claim_with_tls_mode(
                alice.user.id,
                "cloud.example.test",
                "example.test",
                2,
                NamespaceTlsMode::Passthrough,
            )
            .await?;
        assert_eq!(claim.tls_mode, NamespaceTlsMode::Passthrough);
        assert_eq!(claim.state, NamespaceClaimState::Active);
        assert!(
            database
                .list_namespace_claims(alice.user.id)
                .await?
                .is_empty(),
            "passthrough claims must not enter managed certificate lifecycle views"
        );
        assert_eq!(
            database.list_all_namespace_claims(alice.user.id).await?,
            vec![claim.clone()]
        );

        database.close().await;
        let reopened = Database::open(&path).await?;
        let persisted = reopened
            .namespace_claim("cloud.example.test")
            .await?
            .ok_or("passthrough claim did not survive reopen")?;
        assert_eq!(persisted.tls_mode, NamespaceTlsMode::Passthrough);
        assert_eq!(persisted.state, NamespaceClaimState::Active);
        reopened.close().await;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn passthrough_wildcards_reject_overlap_and_cover_only_direct_children()
    -> Result<(), Box<dyn Error>> {
        let (_directory, _path, database) = temporary_database().await?;
        let alice = database.create_user("alice").await?;
        let bob = database.create_user("bob").await?;
        let root = database
            .create_namespace_claim_with_tls_mode(
                alice.user.id,
                "cloud.example.test",
                "example.test",
                2,
                NamespaceTlsMode::Passthrough,
            )
            .await?;

        for covered in ["cloud.example.test", "api.cloud.example.test"] {
            assert_eq!(
                database
                    .active_passthrough_claim_for_route(covered)
                    .await?
                    .ok_or("covered hostname had no passthrough owner")?
                    .id,
                root.id
            );
        }
        assert!(
            database
                .active_passthrough_claim_for_route("deep.api.cloud.example.test")
                .await?
                .is_none()
        );
        assert!(matches!(
            database
                .create_namespace_claim_with_tls_mode(
                    bob.user.id,
                    "edge.cloud.example.test",
                    "example.test",
                    2,
                    NamespaceTlsMode::Passthrough,
                )
                .await,
            Err(DbError::ParentNamespaceOwnedByAnotherUser { .. })
        ));
        assert!(matches!(
            database
                .create_namespace_claim_with_tls_mode(
                    alice.user.id,
                    "edge.cloud.example.test",
                    "example.test",
                    2,
                    NamespaceTlsMode::Passthrough,
                )
                .await,
            Err(DbError::PassthroughNamespaceOverlap { .. })
        ));
        Ok(())
    }

    #[tokio::test]
    async fn namespace_uniqueness_is_race_safe() -> Result<(), Box<dyn Error>> {
        let (_directory, _path, database) = temporary_database().await?;
        let alice = database.create_user("alice").await?;
        let bob = database.create_user("bob").await?;
        let first = database.clone();
        let second = database.clone();
        let (alice_result, bob_result) = tokio::join!(
            first.create_namespace_claim(alice.user.id, "cloud.example.test", "example.test", 2),
            second.create_namespace_claim(bob.user.id, "cloud.example.test", "example.test", 2)
        );
        assert_eq!(
            usize::from(alice_result.is_ok()) + usize::from(bob_result.is_ok()),
            1
        );
        let failure = alice_result
            .err()
            .or_else(|| bob_result.err())
            .ok_or("missing losing claim")?;
        assert!(matches!(failure, DbError::NamespaceAlreadyClaimed { .. }));
        Ok(())
    }

    #[tokio::test]
    async fn lifecycle_is_compare_and_set_and_release_is_child_safe() -> Result<(), Box<dyn Error>>
    {
        let (_directory, _path, database) = temporary_database().await?;
        let alice = database.create_user("alice").await?;
        let root = database
            .create_namespace_claim(alice.user.id, "cloud.example.test", "example.test", 2)
            .await?;
        let child = database
            .create_namespace_claim(alice.user.id, "edge.cloud.example.test", "example.test", 2)
            .await?;
        let root = database
            .transition_namespace_claim(
                alice.user.id,
                &root.fqdn,
                NamespaceClaimState::Pending,
                NamespaceClaimState::Active,
            )
            .await?;
        assert!(matches!(
            database
                .transition_namespace_claim(
                    alice.user.id,
                    &root.fqdn,
                    NamespaceClaimState::Pending,
                    NamespaceClaimState::Failed,
                )
                .await,
            Err(DbError::NamespaceStateConflict { .. })
        ));
        let root = database
            .transition_namespace_claim(
                alice.user.id,
                &root.fqdn,
                NamespaceClaimState::Active,
                NamespaceClaimState::Releasing,
            )
            .await?;
        assert!(matches!(
            database
                .delete_releasing_namespace_claim(alice.user.id, &root.fqdn)
                .await,
            Err(DbError::NamespaceHasChildren { .. })
        ));
        database
            .transition_namespace_claim(
                alice.user.id,
                &child.fqdn,
                NamespaceClaimState::Pending,
                NamespaceClaimState::Releasing,
            )
            .await?;
        database
            .delete_releasing_namespace_claim(alice.user.id, &child.fqdn)
            .await?;
        database
            .delete_releasing_namespace_claim(alice.user.id, &root.fqdn)
            .await?;
        Ok(())
    }

    #[tokio::test]
    async fn database_trigger_rejects_forged_parent_ownership() -> Result<(), Box<dyn Error>> {
        let (_directory, _path, database) = temporary_database().await?;
        let alice = database.create_user("alice").await?;
        let bob = database.create_user("bob").await?;
        let parent = database
            .create_namespace_claim(alice.user.id, "cloud.example.test", "example.test", 2)
            .await?;
        let forged = sqlx::query(
            r#"
            INSERT INTO namespace_claims (user_id, fqdn, parent_id, depth)
            VALUES (?, 'edge.cloud.example.test', ?, 2)
            "#,
        )
        .bind(bob.user.id)
        .bind(parent.id)
        .execute(&database.pool)
        .await;
        assert!(forged.is_err());
        Ok(())
    }

    #[test]
    fn validation_rejects_unsafe_names() {
        assert_eq!(
            normalize_fqdn("Api.Example.Test.").expect("valid hostname should normalize"),
            "api.example.test"
        );
        for fqdn in [
            "",
            ".",
            "bad..example",
            "-bad.example",
            "bad_.example",
            "é.example",
            " example.test",
            "example.test ",
        ] {
            assert!(normalize_fqdn(fqdn).is_err(), "accepted {fqdn:?}");
        }
        for name in ["", "has space", "line\nbreak", "token/tab"] {
            assert!(normalize_token_name(name).is_err(), "accepted {name:?}");
        }
    }

    #[test]
    fn issued_tokens_are_bearer_safe_and_high_entropy() {
        let token = IssuedToken::generate();
        let exposed = token.expose_secret();
        assert!(exposed.len() >= 43);
        assert!(
            exposed
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        );
        assert!(token.bearer_authorization().starts_with("Bearer sink_"));
    }
}
