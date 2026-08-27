//! Command-line and environment-backed server configuration.

use std::{env, ffi::OsString, net::SocketAddr, path::PathBuf};

use clap::Args;
use thiserror::Error;

pub const LISTEN_ADDRESS_ENV: &str = "SINK_SERVER_LISTEN_ADDRESS";
pub const PUBLIC_BASE_DOMAIN_ENV: &str = "SINK_SERVER_PUBLIC_BASE_DOMAIN";
pub const SQLITE_PATH_ENV: &str = "SINK_SERVER_SQLITE_PATH";
pub const LOG_LEVEL_ENV: &str = "SINK_SERVER_LOG_LEVEL";

pub const DEFAULT_LISTEN_ADDRESS: &str = "127.0.0.1:8080";
pub const DEFAULT_SQLITE_PATH: &str = "sink.sqlite3";
pub const DEFAULT_LOG_LEVEL: &str = "info";

/// Raw `serve` options. Every option can also be supplied by its documented
/// `SINK_SERVER_*` environment variable; Clap gives an explicit flag priority
/// over the environment value.
#[derive(Args, Clone, Debug, Default, Eq, PartialEq)]
pub struct ServeArgs {
    /// Address on which the server accepts Traefik-forwarded traffic.
    #[arg(long, value_name = "ADDRESS", env = "SINK_SERVER_LISTEN_ADDRESS")]
    pub listen_address: Option<SocketAddr>,

    /// Public DNS suffix used for tunnel and control hostnames.
    #[arg(
        long,
        value_name = "DOMAIN",
        env = "SINK_SERVER_PUBLIC_BASE_DOMAIN",
        required = true
    )]
    pub public_base_domain: Option<String>,

    #[command(flatten)]
    pub database: DatabaseArgs,

    /// Tracing filter, such as `info` or `info,sink_server=debug`.
    #[arg(long, value_name = "FILTER", env = "SINK_SERVER_LOG_LEVEL")]
    pub log_level: Option<String>,
}

/// SQLite location shared by `serve` and all administration commands.
#[derive(Args, Clone, Debug, Default, Eq, PartialEq)]
pub struct DatabaseArgs {
    /// SQLite database file. This option is global within `user`, so it may be
    /// written before or after the user subcommand.
    #[arg(
        long,
        global = true,
        value_name = "PATH",
        env = "SINK_SERVER_SQLITE_PATH"
    )]
    pub sqlite_path: Option<PathBuf>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServeConfig {
    pub listen_address: SocketAddr,
    pub public_base_domain: String,
    pub sqlite_path: PathBuf,
    pub log_level: String,
}

impl ServeConfig {
    /// Resolve parsed arguments against the current process environment.
    pub fn resolve(args: &ServeArgs) -> Result<Self, ConfigError> {
        Self::resolve_with(args, &ProcessEnvironment)
    }

    /// Resolve against an injected environment source. This is public so
    /// embedders can resolve configuration without mutating process-global
    /// environment state.
    pub fn resolve_with(
        args: &ServeArgs,
        environment: &impl Environment,
    ) -> Result<Self, ConfigError> {
        let listen_address = match args.listen_address {
            Some(address) => address,
            None => environment_string(environment, LISTEN_ADDRESS_ENV)?
                .unwrap_or_else(|| DEFAULT_LISTEN_ADDRESS.to_owned())
                .parse()
                .map_err(|source| ConfigError::InvalidListenAddress { source })?,
        };

        let configured_domain = match args.public_base_domain.as_deref() {
            Some(domain) => domain.to_owned(),
            None => environment_string(environment, PUBLIC_BASE_DOMAIN_ENV)?
                .ok_or(ConfigError::MissingPublicBaseDomain)?,
        };
        let public_base_domain = normalize_base_domain(&configured_domain)?;

        let sqlite_path = args.database.resolve_with(environment)?;

        let log_level = match args.log_level.as_deref() {
            Some(filter) => normalize_log_level(filter)?,
            None => normalize_log_level(
                environment_string(environment, LOG_LEVEL_ENV)?
                    .as_deref()
                    .unwrap_or(DEFAULT_LOG_LEVEL),
            )?,
        };

        Ok(Self {
            listen_address,
            public_base_domain,
            sqlite_path,
            log_level,
        })
    }
}

impl DatabaseArgs {
    pub fn resolve(&self) -> Result<PathBuf, ConfigError> {
        self.resolve_with(&ProcessEnvironment)
    }

    pub fn resolve_with(&self, environment: &impl Environment) -> Result<PathBuf, ConfigError> {
        let path = self
            .sqlite_path
            .clone()
            .or_else(|| environment.value(SQLITE_PATH_ENV).map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from(DEFAULT_SQLITE_PATH));

        if path.as_os_str().is_empty() {
            return Err(ConfigError::EmptySqlitePath);
        }

        Ok(path)
    }
}

/// Small abstraction over environment access used for deterministic config
/// resolution tests and embedding.
pub trait Environment {
    fn value(&self, name: &str) -> Option<OsString>;
}

impl<F> Environment for F
where
    F: Fn(&str) -> Option<OsString>,
{
    fn value(&self, name: &str) -> Option<OsString> {
        self(name)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ProcessEnvironment;

impl Environment for ProcessEnvironment {
    fn value(&self, name: &str) -> Option<OsString> {
        env::var_os(name)
    }
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("{variable} is not valid UTF-8")]
    NonUnicodeEnvironment { variable: &'static str },

    #[error("invalid listen address")]
    InvalidListenAddress {
        #[source]
        source: std::net::AddrParseError,
    },

    #[error("public base domain must be a valid DNS name without a scheme, port, or wildcard")]
    InvalidPublicBaseDomain,

    #[error(
        "public base domain is required; pass `--public-base-domain DOMAIN` or set SINK_SERVER_PUBLIC_BASE_DOMAIN"
    )]
    MissingPublicBaseDomain,

    #[error("SQLite database path cannot be empty")]
    EmptySqlitePath,

    #[error("log level/filter cannot be empty")]
    EmptyLogLevel,
}

fn environment_string(
    environment: &impl Environment,
    variable: &'static str,
) -> Result<Option<String>, ConfigError> {
    environment
        .value(variable)
        .map(|value| {
            value
                .into_string()
                .map_err(|_| ConfigError::NonUnicodeEnvironment { variable })
        })
        .transpose()
}

fn normalize_base_domain(value: &str) -> Result<String, ConfigError> {
    let domain = value.trim().trim_end_matches('.').to_ascii_lowercase();
    let valid = !domain.is_empty()
        && domain.len() <= 253
        && domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        });

    if valid {
        Ok(domain)
    } else {
        Err(ConfigError::InvalidPublicBaseDomain)
    }
}

fn normalize_log_level(value: &str) -> Result<String, ConfigError> {
    let value = value.trim();
    if value.is_empty() {
        Err(ConfigError::EmptyLogLevel)
    } else {
        Ok(value.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, ffi::OsString};

    use super::*;

    fn environment(values: &[(&str, &str)]) -> impl Environment {
        let values: HashMap<String, OsString> = values
            .iter()
            .map(|(key, value)| ((*key).to_owned(), OsString::from(value)))
            .collect();
        move |name: &str| values.get(name).cloned()
    }

    #[test]
    fn explicit_serve_arguments_override_environment() {
        let args = ServeArgs {
            listen_address: Some("127.0.0.1:9010".parse().expect("test address")),
            public_base_domain: Some("CLI.Example.".to_owned()),
            database: DatabaseArgs {
                sqlite_path: Some(PathBuf::from("cli.sqlite3")),
            },
            log_level: Some("debug".to_owned()),
        };
        let environment = environment(&[
            (LISTEN_ADDRESS_ENV, "127.0.0.1:9020"),
            (PUBLIC_BASE_DOMAIN_ENV, "env.example"),
            (SQLITE_PATH_ENV, "env.sqlite3"),
            (LOG_LEVEL_ENV, "warn"),
        ]);

        let resolved = ServeConfig::resolve_with(&args, &environment).expect("valid config");

        assert_eq!(
            resolved.listen_address,
            "127.0.0.1:9010".parse().expect("test address")
        );
        assert_eq!(resolved.public_base_domain, "cli.example");
        assert_eq!(resolved.sqlite_path, PathBuf::from("cli.sqlite3"));
        assert_eq!(resolved.log_level, "debug");
    }

    #[test]
    fn environment_overrides_defaults() {
        let environment = environment(&[
            (LISTEN_ADDRESS_ENV, "0.0.0.0:8088"),
            (PUBLIC_BASE_DOMAIN_ENV, "tunnels.example"),
            (SQLITE_PATH_ENV, "/var/lib/sink/users.sqlite3"),
            (LOG_LEVEL_ENV, "sink_server=trace"),
        ]);

        let resolved = ServeConfig::resolve_with(&ServeArgs::default(), &environment)
            .expect("valid environment config");

        assert_eq!(
            resolved.listen_address,
            "0.0.0.0:8088".parse().expect("test address")
        );
        assert_eq!(resolved.public_base_domain, "tunnels.example");
        assert_eq!(
            resolved.sqlite_path,
            PathBuf::from("/var/lib/sink/users.sqlite3")
        );
        assert_eq!(resolved.log_level, "sink_server=trace");
    }

    #[test]
    fn domain_is_required_while_other_settings_keep_defaults() {
        assert!(matches!(
            ServeConfig::resolve_with(&ServeArgs::default(), &environment(&[])),
            Err(ConfigError::MissingPublicBaseDomain)
        ));

        let resolved = ServeConfig::resolve_with(
            &ServeArgs {
                public_base_domain: Some("example.test".to_owned()),
                ..ServeArgs::default()
            },
            &environment(&[]),
        )
        .expect("valid required domain");

        assert_eq!(resolved.sqlite_path, PathBuf::from(DEFAULT_SQLITE_PATH));
        assert_eq!(resolved.log_level, DEFAULT_LOG_LEVEL);
    }
}
