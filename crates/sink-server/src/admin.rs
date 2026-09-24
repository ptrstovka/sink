//! Clap command model and server administration command execution.

use std::io::{self, Write};

use clap::{Args, Parser, Subcommand};
use thiserror::Error;

use crate::{
    config::{ConfigError, DatabaseArgs, ServeArgs},
    db::{
        Database, DbError, IssuedUser, IssuedUserToken, RevokedUserToken, UserStateChange,
        UserSummary, UserTokenSummary,
    },
};

#[derive(Parser, Debug)]
#[command(
    name = "sink-server",
    version,
    about = "Run and administer the Sink tunnel server"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: ServerCommand,
}

#[derive(Subcommand, Debug)]
pub enum ServerCommand {
    /// Run the tunnel server.
    Serve(ServeArgs),
    /// Manage users and server-issued bearer tokens.
    User(UserArgs),
    /// Print the Sink server version.
    Version,
}

#[derive(Args, Debug)]
pub struct UserArgs {
    #[command(flatten)]
    pub database: DatabaseArgs,

    #[command(subcommand)]
    pub command: UserCommand,
}

#[derive(Subcommand, Debug)]
pub enum UserCommand {
    /// Create an enabled user and print a new token once.
    Create(UsernameArgs),
    /// List users without token secrets or digests.
    List,
    /// Rotate the compatibility `default` token.
    RotateToken(UsernameArgs),
    /// Manage a user's named bearer tokens.
    Token(UserTokenArgs),
    /// Revoke a user's ability to authenticate.
    Disable(UsernameArgs),
    /// Allow a disabled user to authenticate again.
    Enable(UsernameArgs),
}

#[derive(Args, Debug)]
pub struct UsernameArgs {
    pub username: String,
}

#[derive(Args, Debug)]
pub struct UserTokenArgs {
    #[command(subcommand)]
    pub command: UserTokenCommand,
}

#[derive(Subcommand, Debug)]
pub enum UserTokenCommand {
    /// Create a named token and print its secret once.
    Create(UserTokenNameArgs),
    /// List safe metadata for a user's active tokens.
    List(UsernameArgs),
    /// Rotate a named token and print its replacement secret once.
    Rotate(UserTokenNameArgs),
    /// Permanently revoke a named token.
    Revoke(UserTokenNameArgs),
}

#[derive(Args, Debug)]
pub struct UserTokenNameArgs {
    pub username: String,
    pub token_name: String,
}

/// Execute a parsed user command, including opening and migrating its selected
/// database. Runtime wiring only needs to explicitly print the returned value.
pub async fn execute(args: UserArgs) -> Result<AdminOutput, AdminError> {
    let path = args.database.resolve()?;
    let database = Database::open(path).await?;
    let output = execute_with_database(&database, args.command).await;
    database.close().await;
    output.map_err(Into::into)
}

/// Execute against an existing pool, useful for server integration and tests.
pub async fn execute_with_database(
    database: &Database,
    command: UserCommand,
) -> Result<AdminOutput, DbError> {
    match command {
        UserCommand::Create(args) => database
            .create_user(&args.username)
            .await
            .map(AdminOutput::Created),
        UserCommand::List => database.list_users().await.map(AdminOutput::Users),
        UserCommand::RotateToken(args) => database
            .rotate_token(&args.username)
            .await
            .map(AdminOutput::TokenRotated),
        UserCommand::Token(args) => {
            match args.command {
                UserTokenCommand::Create(args) => database
                    .create_user_token(&args.username, &args.token_name)
                    .await
                    .map(AdminOutput::NamedTokenCreated),
                UserTokenCommand::List(args) => database
                    .list_user_tokens(&args.username)
                    .await
                    .map(|tokens| AdminOutput::NamedTokens {
                        username: args.username,
                        tokens,
                    }),
                UserTokenCommand::Rotate(args) => database
                    .rotate_user_token(&args.username, &args.token_name)
                    .await
                    .map(AdminOutput::NamedTokenRotated),
                UserTokenCommand::Revoke(args) => database
                    .revoke_user_token(&args.username, &args.token_name)
                    .await
                    .map(AdminOutput::NamedTokenRevoked),
            }
        }
        UserCommand::Disable(args) => database
            .disable_user(&args.username)
            .await
            .map(AdminOutput::Disabled),
        UserCommand::Enable(args) => database
            .enable_user(&args.username)
            .await
            .map(AdminOutput::Enabled),
    }
}

/// Structured command output. Its `Debug` representation inherits token
/// redaction from [`crate::db::IssuedToken`]. It deliberately has no `Display`
/// implementation so token exposure happens only through `write_terminal`.
#[derive(Debug)]
pub enum AdminOutput {
    Created(IssuedUser),
    Users(Vec<UserSummary>),
    TokenRotated(IssuedUser),
    NamedTokenCreated(IssuedUserToken),
    NamedTokens {
        username: String,
        tokens: Vec<UserTokenSummary>,
    },
    NamedTokenRotated(IssuedUserToken),
    NamedTokenRevoked(RevokedUserToken),
    Disabled(UserStateChange),
    Enabled(UserStateChange),
}

impl AdminOutput {
    /// Write administration output. Creation and rotation are the only paths
    /// that intentionally reveal a reusable token.
    pub fn write_terminal(&self, mut writer: impl Write) -> io::Result<()> {
        match self {
            Self::Created(issued) => {
                writeln!(writer, "created user `{}`", issued.user.username)?;
                writeln!(writer, "token: {}", issued.token.expose_secret())?;
                writeln!(writer, "save this token now; it cannot be retrieved later")
            }
            Self::TokenRotated(issued) => {
                writeln!(
                    writer,
                    "rotated token for `{}` (generation {})",
                    issued.user.username, issued.user.token_generation
                )?;
                writeln!(writer, "token: {}", issued.token.expose_secret())?;
                writeln!(writer, "save this token now; it cannot be retrieved later")
            }
            Self::NamedTokenCreated(issued) => {
                writeln!(
                    writer,
                    "created token `{}` for user `{}` (generation {})",
                    issued.details.name, issued.user.username, issued.details.generation
                )?;
                writeln!(writer, "token: {}", issued.token.expose_secret())?;
                writeln!(writer, "save this token now; it cannot be retrieved later")
            }
            Self::NamedTokenRotated(issued) => {
                writeln!(
                    writer,
                    "rotated token `{}` for user `{}` (generation {})",
                    issued.details.name, issued.user.username, issued.details.generation
                )?;
                writeln!(writer, "token: {}", issued.token.expose_secret())?;
                writeln!(writer, "save this token now; it cannot be retrieved later")
            }
            Self::NamedTokens { username, tokens } => {
                writeln!(writer, "tokens for user `{username}`")?;
                writeln!(writer, "NAME\tGENERATION\tCREATED\tUPDATED")?;
                for token in tokens {
                    writeln!(
                        writer,
                        "{}\t{}\t{}\t{}",
                        token.name, token.generation, token.created_at, token.updated_at
                    )?;
                }
                Ok(())
            }
            Self::NamedTokenRevoked(revoked) => writeln!(
                writer,
                "revoked token `{}` for user `{}`",
                revoked.token.name, revoked.user.username
            ),
            Self::Users(users) => {
                writeln!(writer, "USERNAME\tSTATE\tTOKEN GENERATION")?;
                for user in users {
                    let state = if user.enabled { "enabled" } else { "disabled" };
                    writeln!(
                        writer,
                        "{}\t{}\t{}",
                        user.username, state, user.token_generation
                    )?;
                }
                Ok(())
            }
            Self::Disabled(change) => write_state_change(&mut writer, change, "disabled"),
            Self::Enabled(change) => write_state_change(&mut writer, change, "enabled"),
        }
    }
}

fn write_state_change(
    writer: &mut impl Write,
    change: &UserStateChange,
    state: &str,
) -> io::Result<()> {
    if change.changed {
        writeln!(writer, "{state} user `{}`", change.user.username)
    } else {
        writeln!(writer, "user `{}` is already {state}", change.user.username)
    }
}

#[derive(Debug, Error)]
pub enum AdminError {
    #[error(transparent)]
    Config(#[from] ConfigError),

    #[error(transparent)]
    Database(#[from] DbError),
}

#[cfg(test)]
mod tests {
    use std::{error::Error, path::PathBuf};

    use clap::Parser as _;

    use super::*;

    #[test]
    fn clap_models_serve_and_all_user_commands() -> Result<(), Box<dyn Error>> {
        let serve = Cli::try_parse_from([
            "sink-server",
            "serve",
            "--listen-address",
            "127.0.0.1:9090",
            "--public-base-domain",
            "example.test",
            "--sqlite-path",
            "serve.sqlite3",
            "--log-level",
            "debug",
        ])?;
        assert!(matches!(serve.command, ServerCommand::Serve(_)));
        assert!(Cli::try_parse_from(["sink-server", "serve"]).is_err());

        for command in ["create", "rotate-token", "disable", "enable"] {
            let parsed = Cli::try_parse_from([
                "sink-server",
                "user",
                command,
                "alice",
                "--sqlite-path",
                "admin.sqlite3",
            ])?;
            let ServerCommand::User(user) = parsed.command else {
                return Err("expected user command".into());
            };
            assert_eq!(
                user.database.sqlite_path,
                Some(PathBuf::from("admin.sqlite3"))
            );
        }

        let list = Cli::try_parse_from(["sink-server", "user", "list"])?;
        assert!(matches!(
            list.command,
            ServerCommand::User(UserArgs {
                command: UserCommand::List,
                ..
            })
        ));

        for command in ["create", "rotate", "revoke"] {
            let parsed = Cli::try_parse_from([
                "sink-server",
                "user",
                "token",
                command,
                "alice",
                "cloud",
                "--sqlite-path",
                "admin.sqlite3",
            ])?;
            let ServerCommand::User(user) = parsed.command else {
                return Err("expected user token command".into());
            };
            assert_eq!(
                user.database.sqlite_path,
                Some(PathBuf::from("admin.sqlite3"))
            );
        }
        let token_list = Cli::try_parse_from(["sink-server", "user", "token", "list", "alice"])?;
        assert!(matches!(
            token_list.command,
            ServerCommand::User(UserArgs {
                command: UserCommand::Token(UserTokenArgs {
                    command: UserTokenCommand::List(_),
                }),
                ..
            })
        ));

        let version = Cli::try_parse_from(["sink-server", "version"])?;
        assert!(matches!(version.command, ServerCommand::Version));
        Ok(())
    }

    #[tokio::test]
    async fn admin_listing_is_safe_and_stateful() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let database = Database::open(directory.path().join("admin.sqlite3")).await?;
        let created = database.create_user("alice").await?;
        database.disable_user("alice").await?;

        let output = execute_with_database(&database, UserCommand::List).await?;
        let mut rendered = Vec::new();
        output.write_terminal(&mut rendered)?;
        let rendered = String::from_utf8(rendered)?;

        assert!(rendered.contains("alice\tdisabled\t1"));
        assert!(!rendered.contains(created.token.expose_secret()));
        Ok(())
    }

    #[tokio::test]
    async fn named_token_admin_lifecycle_reveals_only_new_secrets() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let database = Database::open(directory.path().join("admin.sqlite3")).await?;
        database.create_user("alice").await?;

        let created = execute_with_database(
            &database,
            UserCommand::Token(UserTokenArgs {
                command: UserTokenCommand::Create(UserTokenNameArgs {
                    username: "alice".to_owned(),
                    token_name: "cloud".to_owned(),
                }),
            }),
        )
        .await?;
        let AdminOutput::NamedTokenCreated(created_token) = &created else {
            return Err("expected named token creation output".into());
        };
        let secret = created_token.token.expose_secret().to_owned();
        let mut rendered = Vec::new();
        created.write_terminal(&mut rendered)?;
        assert!(String::from_utf8(rendered)?.contains(&secret));

        let listing = execute_with_database(
            &database,
            UserCommand::Token(UserTokenArgs {
                command: UserTokenCommand::List(UsernameArgs {
                    username: "alice".to_owned(),
                }),
            }),
        )
        .await?;
        let mut rendered = Vec::new();
        listing.write_terminal(&mut rendered)?;
        let rendered = String::from_utf8(rendered)?;
        assert!(rendered.contains("cloud\t1"));
        assert!(!rendered.contains(&secret));

        let revoked = execute_with_database(
            &database,
            UserCommand::Token(UserTokenArgs {
                command: UserTokenCommand::Revoke(UserTokenNameArgs {
                    username: "alice".to_owned(),
                    token_name: "cloud".to_owned(),
                }),
            }),
        )
        .await?;
        let mut rendered = Vec::new();
        revoked.write_terminal(&mut rendered)?;
        assert!(!String::from_utf8(rendered)?.contains(&secret));
        Ok(())
    }
}
