//! SQLite-backed users and authentication state.

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

const TOKEN_RANDOM_BYTES: usize = 32;
const TOKEN_INSERT_ATTEMPTS: usize = 4;
const MAX_USERNAME_BYTES: usize = 128;

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

    /// Create a unique enabled user and return its bearer token exactly once.
    pub async fn create_user(&self, username: &str) -> Result<IssuedUser, DbError> {
        let username = normalize_username(username)?;

        for _ in 0..TOKEN_INSERT_ATTEMPTS {
            let token = IssuedToken::generate();
            let digest = digest_token(token.expose_secret());
            let result = sqlx::query_as::<_, UserRow>(
                r#"
                INSERT INTO users (username, token_digest)
                VALUES (?, ?)
                RETURNING id, username, enabled, token_generation, auth_revision, created_at
                "#,
            )
            .bind(&username)
            .bind(digest.to_vec())
            .fetch_one(&self.pool)
            .await;

            match result {
                Ok(row) => {
                    return Ok(IssuedUser {
                        user: row.into(),
                        token,
                    });
                }
                Err(error) if is_unique_violation(&error) => {
                    if self.find_user(&username).await?.is_some() {
                        return Err(DbError::UserAlreadyExists { username });
                    }
                }
                Err(error) => return Err(error.into()),
            }
        }

        Err(DbError::TokenCollision)
    }

    /// Resolve a bearer token to an enabled user. Disabled, rotated, malformed,
    /// and unknown credentials intentionally all return `None`.
    pub async fn authenticate(&self, token: &str) -> Result<Option<AuthenticatedUser>, DbError> {
        let digest = digest_token(token);
        let row = sqlx::query_as::<_, AuthenticationRow>(
            r#"
            SELECT id, username, token_generation, auth_revision
            FROM users
            WHERE token_digest = ? AND enabled = 1
            "#,
        )
        .bind(digest.to_vec())
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(Into::into))
    }

    /// Read the non-secret state a runtime watcher needs to revoke a live
    /// session after rotation or disablement.
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

    /// Issue a replacement token and atomically advance both the token
    /// generation and the general authentication revision.
    pub async fn rotate_token(&self, username: &str) -> Result<IssuedUser, DbError> {
        let username = normalize_username(username)?;

        for _ in 0..TOKEN_INSERT_ATTEMPTS {
            let token = IssuedToken::generate();
            let digest = digest_token(token.expose_secret());
            let result = sqlx::query_as::<_, UserRow>(
                r#"
                UPDATE users
                SET token_digest = ?,
                    token_generation = token_generation + 1,
                    auth_revision = auth_revision + 1,
                    updated_at = unixepoch()
                WHERE username = ?
                  AND token_generation < 9223372036854775807
                  AND auth_revision < 9223372036854775807
                RETURNING id, username, enabled, token_generation, auth_revision, created_at
                "#,
            )
            .bind(digest.to_vec())
            .bind(&username)
            .fetch_optional(&self.pool)
            .await;

            match result {
                Ok(Some(row)) => {
                    return Ok(IssuedUser {
                        user: row.into(),
                        token,
                    });
                }
                Ok(None) => return Err(self.missing_or_exhausted(&username).await?),
                Err(error) if is_unique_violation(&error) => {}
                Err(error) => return Err(error.into()),
            }
        }

        Err(DbError::TokenCollision)
    }

    pub async fn disable_user(&self, username: &str) -> Result<UserStateChange, DbError> {
        self.set_enabled(username, false).await
    }

    pub async fn enable_user(&self, username: &str) -> Result<UserStateChange, DbError> {
        self.set_enabled(username, true).await
    }

    /// List only operator-safe user metadata. The query intentionally never
    /// selects the token digest.
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

    async fn missing_or_exhausted(&self, username: &str) -> Result<DbError, DbError> {
        match self.find_user(username).await? {
            Some(_) => Ok(DbError::RevisionExhausted {
                username: username.to_owned(),
            }),
            None => Ok(DbError::UserNotFound {
                username: username.to_owned(),
            }),
        }
    }
}

/// A one-time bearer token. It is zeroized on drop, has redacted `Debug`, and
/// deliberately has no `Display` implementation. Callers must explicitly opt
/// into exposing it for the creation/rotation terminal response.
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UserSummary {
    pub id: i64,
    pub username: String,
    pub enabled: bool,
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

    #[error("authentication revision exhausted for user `{username}`")]
    RevisionExhausted { username: String },

    #[error("could not generate a unique user token")]
    TokenCollision,

    #[error("database operation failed")]
    Sql(#[from] sqlx::Error),

    #[error("database migration failed")]
    Migration(#[from] MigrateError),
}

type UserRow = (i64, String, bool, i64, i64, i64);
type AuthenticationRow = (i64, String, i64, i64);
type AuthenticationStateRow = (i64, bool, i64, i64);

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

fn digest_token(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

fn is_unique_violation(error: &sqlx::Error) -> bool {
    matches!(error, sqlx::Error::Database(error) if error.is_unique_violation())
}

#[cfg(test)]
mod tests {
    use std::{error::Error, fs};

    use tempfile::TempDir;

    use super::*;

    async fn temporary_database() -> Result<(TempDir, std::path::PathBuf, Database), DbError> {
        let directory = tempfile::tempdir().map_err(sqlx::Error::Io)?;
        let path = directory.path().join("users.sqlite3");
        let database = Database::open(&path).await?;
        Ok((directory, path, database))
    }

    #[tokio::test]
    async fn users_and_authentication_persist_across_reopen() -> Result<(), Box<dyn Error>> {
        let (_directory, path, database) = temporary_database().await?;
        let created = database.create_user("alice").await?;
        let expected_id = created.user.id;
        database.close().await;

        let reopened = Database::open(path).await?;
        let authenticated = reopened
            .authenticate(created.token.expose_secret())
            .await?
            .ok_or("created token did not authenticate after reopen")?;

        assert_eq!(authenticated.id, expected_id);
        assert_eq!(authenticated.username, "alice");
        Ok(())
    }

    #[tokio::test]
    async fn usernames_are_unique_and_tokens_are_isolated() -> Result<(), Box<dyn Error>> {
        let (_directory, _path, database) = temporary_database().await?;
        let alice = database.create_user("Alice").await?;
        let duplicate = database.create_user("alice").await;
        assert!(matches!(duplicate, Err(DbError::UserAlreadyExists { .. })));

        let bob = database.create_user("bob").await?;
        let alice_auth = database
            .authenticate(alice.token.expose_secret())
            .await?
            .ok_or("Alice token did not authenticate")?;
        let bob_auth = database
            .authenticate(bob.token.expose_secret())
            .await?
            .ok_or("Bob token did not authenticate")?;

        assert_eq!(alice_auth.id, alice.user.id);
        assert_eq!(bob_auth.id, bob.user.id);
        assert_ne!(alice_auth.id, bob_auth.id);
        assert!(database.authenticate("not-a-real-token").await?.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn rotation_revokes_old_token_and_advances_watch_state() -> Result<(), Box<dyn Error>> {
        let (_directory, _path, database) = temporary_database().await?;
        let created = database.create_user("alice").await?;
        let initial_auth = database
            .authenticate(created.token.expose_secret())
            .await?
            .ok_or("initial token did not authenticate")?;

        let rotated = database.rotate_token("alice").await?;
        assert_eq!(
            rotated.user.token_generation,
            initial_auth.token_generation + 1
        );
        assert!(
            rotated.user.auth_revision > initial_auth.auth_revision,
            "rotation must advance the watcher revision"
        );
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
        let current = database
            .authentication_state(created.user.id)
            .await?
            .ok_or("authentication state disappeared")?;
        assert!(!current.still_authorizes(&initial_auth));
        Ok(())
    }

    #[tokio::test]
    async fn disable_and_enable_are_visible_to_authentication() -> Result<(), Box<dyn Error>> {
        let (_directory, _path, database) = temporary_database().await?;
        let created = database.create_user("alice").await?;
        let authenticated = database
            .authenticate(created.token.expose_secret())
            .await?
            .ok_or("created token did not authenticate")?;

        let disabled = database.disable_user("alice").await?;
        assert!(disabled.changed);
        assert!(!disabled.user.enabled);
        assert!(
            database
                .authenticate(created.token.expose_secret())
                .await?
                .is_none()
        );
        let disabled_state = database
            .authentication_state(created.user.id)
            .await?
            .ok_or("disabled authentication state disappeared")?;
        assert!(!disabled_state.still_authorizes(&authenticated));

        let enabled = database.enable_user("alice").await?;
        assert!(enabled.changed);
        assert!(enabled.user.enabled);
        assert!(enabled.user.auth_revision > disabled.user.auth_revision);
        assert!(
            database
                .authenticate(created.token.expose_secret())
                .await?
                .is_some()
        );
        Ok(())
    }

    #[tokio::test]
    async fn listing_and_storage_do_not_expose_reusable_tokens() -> Result<(), Box<dyn Error>> {
        let (_directory, path, database) = temporary_database().await?;
        let created = database.create_user("alice").await?;
        let listing = database.list_users().await?;
        let debug_listing = format!("{listing:?}");
        assert!(!debug_listing.contains(created.token.expose_secret()));
        assert!(!format!("{created:?}").contains(created.token.expose_secret()));
        assert_eq!(listing.len(), 1);

        database.close().await;
        let database_bytes = fs::read(path)?;
        let secret = created.token.expose_secret().as_bytes();
        assert!(
            !database_bytes
                .windows(secret.len())
                .any(|part| part == secret)
        );
        Ok(())
    }

    #[test]
    fn issued_tokens_are_bearer_safe_and_high_entropy() {
        let token = IssuedToken::generate();
        let exposed = token.expose_secret();
        assert!(exposed.len() >= 43);
        assert!(
            exposed
                .bytes()
                .all(|byte| { byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-') })
        );
        assert!(token.bearer_authorization().starts_with("Bearer sink_"));
    }
}
