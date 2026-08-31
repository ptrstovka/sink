use std::num::{NonZeroU16, NonZeroUsize};

use clap::{Args, Parser, Subcommand};
use thiserror::Error;

use crate::{
    config::{
        AuthToken, ConfigError, ConfigStore, ControlServerAddr, ResolvedConfig, RunOverrides,
        SavedConfig,
    },
    target::{LocalTarget, PublicUrl},
};

#[derive(Clone, Debug, Parser)]
#[command(
    name = "sink",
    version,
    about = "Expose a local web service through Sink"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: SinkCommand,
}

#[derive(Clone, Debug, Subcommand)]
pub enum SinkCommand {
    /// Expose a local HTTP or HTTPS service.
    Http(Box<HttpArgs>),
    /// Save client configuration.
    Config(ConfigArgs),
    /// Update the Sink client to the latest stable release.
    Update,
    /// Print the Sink client version.
    Version,
}

#[derive(Clone, Debug, Args)]
pub struct HttpArgs {
    /// Local port, host:port, or http(s) URL.
    pub target: LocalTarget,

    /// Request a specific public HTTPS hostname.
    #[arg(long, value_name = "HTTPS_URL")]
    pub url: Option<PublicUrl>,

    /// Use an authentication token for this run without saving it.
    #[arg(long, value_name = "TOKEN")]
    pub authtoken: Option<AuthToken>,

    /// Use a control-server origin for this run without saving it.
    #[arg(long, value_name = "SERVER")]
    pub server_addr: Option<ControlServerAddr>,

    /// Skip certificate verification for an HTTPS local target (development only).
    #[arg(long)]
    pub local_tls_insecure: bool,

    /// Permit an http:// control server for this run (local development only).
    #[arg(long)]
    pub allow_plaintext_control: bool,

    /// Enable the local request inspector and dashboard; use --inspect=false to disable.
    #[arg(
        long,
        default_value_t = true,
        action = clap::ArgAction::Set,
        require_equals = true,
        value_name = "BOOL"
    )]
    pub inspect: bool,

    /// Bind the inspection dashboard to this specific loopback TCP port.
    ///
    /// When omitted, the dashboard automatically searches from port 4040 upward.
    #[arg(long, value_name = "PORT")]
    pub dashboard_port: Option<NonZeroU16>,

    /// Maximum number of requests retained by the inspector.
    #[arg(long, default_value = "100", value_name = "COUNT")]
    pub inspect_request_limit: NonZeroUsize,

    /// Maximum bytes retained from each request or response body preview.
    #[arg(long, default_value = "1048576", value_name = "BYTES")]
    pub inspect_body_limit: NonZeroUsize,
}

impl HttpArgs {
    pub fn validate(&self) -> Result<(), CliValidationError> {
        if self.local_tls_insecure && !self.target.uses_tls() {
            return Err(CliValidationError::LocalTlsInsecureRequiresHttps);
        }
        Ok(())
    }

    #[must_use]
    pub fn run_overrides(&self) -> RunOverrides {
        RunOverrides {
            authtoken: self.authtoken.clone(),
            server_addr: self.server_addr.clone(),
            allow_plaintext_control: self.allow_plaintext_control,
        }
    }

    pub fn resolve_config(&self, saved: &SavedConfig) -> Result<ResolvedConfig, ConfigError> {
        saved.resolve(self.run_overrides())
    }
}

#[derive(Clone, Debug, Args)]
pub struct ConfigArgs {
    #[command(subcommand)]
    pub command: ConfigCommand,
}

#[derive(Clone, Debug, Subcommand)]
pub enum ConfigCommand {
    /// Save an authentication token.
    AddAuthtoken {
        #[arg(value_name = "TOKEN")]
        token: AuthToken,
    },
    /// Save the control-server address.
    AddServerAddr {
        #[arg(value_name = "SERVER")]
        server: ControlServerAddr,
    },
}

impl ConfigCommand {
    pub fn persist(self, store: &ConfigStore) -> Result<ConfigField, ConfigError> {
        match self {
            Self::AddAuthtoken { token } => {
                store.save_authtoken(token)?;
                Ok(ConfigField::AuthToken)
            }
            Self::AddServerAddr { server } => {
                store.save_server_addr(server)?;
                Ok(ConfigField::ServerAddress)
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigField {
    AuthToken,
    ServerAddress,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum CliValidationError {
    #[error("--local-tls-insecure requires an https:// local target")]
    LocalTlsInsecureRequiresHttps,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_http_command_and_all_run_overrides() -> Result<(), Box<dyn std::error::Error>> {
        let cli = Cli::try_parse_from([
            "sink",
            "http",
            "https://localhost:8443/base",
            "--url",
            "https://demo.example.com",
            "--authtoken",
            "one-run-secret",
            "--server-addr",
            "http://127.0.0.1:8080",
            "--local-tls-insecure",
            "--allow-plaintext-control",
            "--inspect=false",
            "--dashboard-port",
            "4042",
            "--inspect-request-limit",
            "25",
            "--inspect-body-limit",
            "65536",
        ])?;
        let SinkCommand::Http(args) = cli.command else {
            return Err("expected http command".into());
        };
        args.validate()?;
        assert_eq!(
            args.target.base_uri().to_string(),
            "https://localhost:8443/base"
        );
        assert_eq!(
            args.url.as_ref().map(PublicUrl::requested_hostname),
            Some("demo.example.com")
        );
        assert_eq!(
            args.authtoken.as_ref().map(AuthToken::expose_secret),
            Some("one-run-secret")
        );
        assert!(args.local_tls_insecure);
        assert!(args.allow_plaintext_control);
        assert!(!args.inspect);
        assert_eq!(args.dashboard_port.map(NonZeroU16::get), Some(4042));
        assert_eq!(args.inspect_request_limit.get(), 25);
        assert_eq!(args.inspect_body_limit.get(), 65_536);
        Ok(())
    }

    #[test]
    fn inspection_settings_use_approved_defaults() -> Result<(), Box<dyn std::error::Error>> {
        let cli = Cli::try_parse_from(["sink", "http", "3000"])?;
        let SinkCommand::Http(args) = cli.command else {
            return Err("expected http command".into());
        };

        assert!(args.inspect);
        assert_eq!(args.dashboard_port, None);
        assert_eq!(args.inspect_request_limit.get(), 100);
        assert_eq!(args.inspect_body_limit.get(), 1_048_576);
        Ok(())
    }

    #[test]
    fn rejects_zero_inspection_limits_and_dashboard_port() {
        for flag in [
            "--dashboard-port",
            "--inspect-request-limit",
            "--inspect-body-limit",
        ] {
            let result = Cli::try_parse_from(["sink", "http", "3000", flag, "0"]);
            assert!(result.is_err(), "{flag} accepted zero");
        }
    }

    #[test]
    fn parses_ngrok_shaped_config_commands() -> Result<(), Box<dyn std::error::Error>> {
        let token = Cli::try_parse_from(["sink", "config", "add-authtoken", "secret"])?;
        assert!(matches!(
            token.command,
            SinkCommand::Config(ConfigArgs {
                command: ConfigCommand::AddAuthtoken { .. }
            })
        ));

        let server = Cli::try_parse_from([
            "sink",
            "config",
            "add-server-addr",
            "https://connect.example.test",
        ])?;
        assert!(matches!(
            server.command,
            SinkCommand::Config(ConfigArgs {
                command: ConfigCommand::AddServerAddr { .. }
            })
        ));
        Ok(())
    }

    #[test]
    fn parses_version_command() -> Result<(), Box<dyn std::error::Error>> {
        let cli = Cli::try_parse_from(["sink", "version"])?;
        assert!(matches!(cli.command, SinkCommand::Version));
        Ok(())
    }

    #[test]
    fn parses_update_command_without_arguments() -> Result<(), Box<dyn std::error::Error>> {
        let cli = Cli::try_parse_from(["sink", "update"])?;
        assert!(matches!(cli.command, SinkCommand::Update));
        Ok(())
    }

    #[test]
    fn cli_debug_output_redacts_override_and_config_tokens()
    -> Result<(), Box<dyn std::error::Error>> {
        for arguments in [
            vec!["sink", "http", "3000", "--authtoken", "debug-secret"],
            vec!["sink", "config", "add-authtoken", "debug-secret"],
        ] {
            let cli = Cli::try_parse_from(arguments)?;
            let output = format!("{cli:?}");
            assert!(!output.contains("debug-secret"));
            assert!(output.contains("REDACTED"));
        }
        Ok(())
    }

    #[test]
    fn rejects_non_https_public_url_during_cli_parsing() {
        let error =
            Cli::try_parse_from(["sink", "http", "3000", "--url", "http://demo.example.com"]);
        assert!(error.is_err());
    }

    #[test]
    fn local_tls_insecure_is_scoped_to_https_targets() -> Result<(), Box<dyn std::error::Error>> {
        let cli = Cli::try_parse_from(["sink", "http", "3000", "--local-tls-insecure"])?;
        let SinkCommand::Http(args) = cli.command else {
            return Err("expected http command".into());
        };
        assert_eq!(
            args.validate(),
            Err(CliValidationError::LocalTlsInsecureRequiresHttps)
        );
        Ok(())
    }
}
