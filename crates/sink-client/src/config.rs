use std::{
    fmt, fs,
    io::{self, Write},
    path::{Path, PathBuf},
    str::FromStr,
};

use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;
use thiserror::Error;
use url::Url;
use zeroize::{Zeroize as _, Zeroizing};

pub const DEFAULT_SERVER_ADDR: &str = "https://connect.serus.eu";
pub const CONFIG_FILE_NAME: &str = "config.toml";

/// An authentication token whose debug representation is always redacted.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthToken(Zeroizing<String>);

impl AuthToken {
    pub fn new(value: impl Into<String>) -> Result<Self, AuthTokenError> {
        let value = value.into();
        if value.is_empty() {
            return Err(AuthTokenError::Empty);
        }
        Ok(Self(Zeroizing::new(value)))
    }

    /// Exposes the credential only to code that must authenticate the control
    /// connection. Do not include the returned value in logs or errors.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for AuthToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthToken([REDACTED])")
    }
}

impl FromStr for AuthToken {
    type Err = AuthTokenError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum AuthTokenError {
    #[error("authentication token cannot be empty")]
    Empty,
}

/// A syntactically valid HTTP(S) control-server origin.
///
/// Plain HTTP can be represented so local development addresses can be saved,
/// but resolution rejects it unless the run explicitly opts in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlServerAddr(Url);

impl ControlServerAddr {
    #[must_use]
    pub fn as_url(&self) -> &Url {
        &self.0
    }

    #[must_use]
    pub fn is_plaintext(&self) -> bool {
        self.0.scheme() == "http"
    }
}

impl fmt::Display for ControlServerAddr {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0.as_str())
    }
}

impl FromStr for ControlServerAddr {
    type Err = ControlServerAddrError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.is_empty() || value.trim() != value || value.chars().any(char::is_whitespace) {
            return Err(ControlServerAddrError::Invalid);
        }
        let mut url = Url::parse(value).map_err(|_| ControlServerAddrError::Invalid)?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(ControlServerAddrError::UnsupportedScheme);
        }
        if url.host().is_none() {
            return Err(ControlServerAddrError::MissingHost);
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(ControlServerAddrError::UserInfo);
        }
        if url.port() == Some(0) {
            return Err(ControlServerAddrError::ZeroPort);
        }
        if url.path() != "/" || url.query().is_some() || url.fragment().is_some() {
            return Err(ControlServerAddrError::OriginOnly);
        }
        url.set_path("/");
        Ok(Self(url))
    }
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ControlServerAddrError {
    #[error("server address must be a valid http:// or https:// URL")]
    Invalid,
    #[error("server address must use http:// or https://")]
    UnsupportedScheme,
    #[error("server address must include a host")]
    MissingHost,
    #[error("server address cannot contain a username or password")]
    UserInfo,
    #[error("server address port must be greater than zero")]
    ZeroPort,
    #[error("server address must be an origin without a path, query, or fragment")]
    OriginOnly,
}

#[derive(Clone, Default)]
pub struct SavedConfig {
    authtoken: Option<AuthToken>,
    server_addr: Option<ControlServerAddr>,
}

impl SavedConfig {
    #[must_use]
    pub fn authtoken(&self) -> Option<&AuthToken> {
        self.authtoken.as_ref()
    }

    #[must_use]
    pub fn server_addr(&self) -> Option<&ControlServerAddr> {
        self.server_addr.as_ref()
    }

    /// Resolves a normal `sink http` run using the intended production server
    /// when neither an override nor a saved address exists.
    pub fn resolve_for_http(&self, overrides: RunOverrides) -> Result<ResolvedConfig, ConfigError> {
        self.resolve(overrides, ServerAddressFallback::IntendedDefault)
    }

    /// Resolves run settings with explicit override > saved > fallback
    /// precedence. This method never writes to the config store.
    pub fn resolve(
        &self,
        overrides: RunOverrides,
        fallback: ServerAddressFallback,
    ) -> Result<ResolvedConfig, ConfigError> {
        let auth_token = overrides
            .authtoken
            .or_else(|| self.authtoken.clone())
            .ok_or(ConfigError::MissingAuthToken)?;
        let server_addr = overrides
            .server_addr
            .or_else(|| self.server_addr.clone())
            .map(Ok)
            .unwrap_or_else(|| match fallback {
                ServerAddressFallback::IntendedDefault => DEFAULT_SERVER_ADDR
                    .parse()
                    .map_err(|_| ConfigError::InvalidBuiltInServerAddress),
                ServerAddressFallback::RequireConfigured => Err(ConfigError::MissingServerAddress),
            })?;

        if server_addr.is_plaintext() && !overrides.allow_plaintext_control {
            return Err(ConfigError::PlaintextControlNotAllowed);
        }

        Ok(ResolvedConfig {
            auth_token,
            server_addr,
        })
    }
}

impl fmt::Debug for SavedConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SavedConfig")
            .field("authtoken", &self.authtoken.as_ref().map(|_| "[REDACTED]"))
            .field("server_addr", &self.server_addr)
            .finish()
    }
}

#[derive(Clone, Debug, Default)]
pub struct RunOverrides {
    pub authtoken: Option<AuthToken>,
    pub server_addr: Option<ControlServerAddr>,
    pub allow_plaintext_control: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ServerAddressFallback {
    #[default]
    IntendedDefault,
    RequireConfigured,
}

#[derive(Clone, Debug)]
pub struct ResolvedConfig {
    auth_token: AuthToken,
    server_addr: ControlServerAddr,
}

impl ResolvedConfig {
    #[must_use]
    pub fn auth_token(&self) -> &AuthToken {
        &self.auth_token
    }

    #[must_use]
    pub fn server_addr(&self) -> &ControlServerAddr {
        &self.server_addr
    }
}

/// File-backed client configuration with an injectable path for tests and
/// embedding.
#[derive(Clone, Debug)]
pub struct ConfigStore {
    path: PathBuf,
}

impl ConfigStore {
    pub fn platform() -> Result<Self, ConfigError> {
        let project_dirs = ProjectDirs::from("eu", "serus", "sink")
            .ok_or(ConfigError::PlatformConfigUnavailable)?;
        Ok(Self::new(project_dirs.config_dir().join(CONFIG_FILE_NAME)))
    }

    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn load(&self) -> Result<SavedConfig, ConfigError> {
        let contents = match fs::read_to_string(&self.path) {
            Ok(contents) => contents,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(SavedConfig::default());
            }
            Err(source) => {
                return Err(ConfigError::Read {
                    path: self.path.clone(),
                    source,
                });
            }
        };
        let contents = Zeroizing::new(contents);
        let mut disk: DiskConfig =
            toml::from_str(&contents).map_err(|_| ConfigError::InvalidFile {
                path: self.path.clone(),
            })?;

        let authtoken = disk
            .authtoken
            .take()
            .map(AuthToken::new)
            .transpose()
            .map_err(|_| ConfigError::InvalidFile {
                path: self.path.clone(),
            })?;
        let server_addr = disk
            .server_addr
            .take()
            .map(|value| value.parse::<ControlServerAddr>())
            .transpose()
            .map_err(|_| ConfigError::InvalidFile {
                path: self.path.clone(),
            })?;

        Ok(SavedConfig {
            authtoken,
            server_addr,
        })
    }

    pub fn save(&self, config: &SavedConfig) -> Result<(), ConfigError> {
        let disk = DiskConfig {
            authtoken: config
                .authtoken
                .as_ref()
                .map(|token| token.expose_secret().to_owned()),
            server_addr: config.server_addr.as_ref().map(ToString::to_string),
        };
        let encoded =
            Zeroizing::new(toml::to_string_pretty(&disk).map_err(|_| ConfigError::Serialize)?);
        self.atomic_write(encoded.as_bytes())
    }

    pub fn save_authtoken(&self, token: AuthToken) -> Result<(), ConfigError> {
        let mut config = self.load()?;
        config.authtoken = Some(token);
        self.save(&config)
    }

    pub fn save_server_addr(&self, server_addr: ControlServerAddr) -> Result<(), ConfigError> {
        let mut config = self.load()?;
        config.server_addr = Some(server_addr);
        self.save(&config)
    }

    fn atomic_write(&self, contents: &[u8]) -> Result<(), ConfigError> {
        let parent = self
            .path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent).map_err(|source| ConfigError::Write {
            path: self.path.clone(),
            source,
        })?;
        secure_directory_permissions(parent).map_err(|source| ConfigError::Write {
            path: self.path.clone(),
            source,
        })?;

        let mut temporary = NamedTempFile::new_in(parent).map_err(|source| ConfigError::Write {
            path: self.path.clone(),
            source,
        })?;
        secure_file_permissions(temporary.as_file()).map_err(|source| ConfigError::Write {
            path: self.path.clone(),
            source,
        })?;
        temporary
            .write_all(contents)
            .and_then(|()| temporary.as_file_mut().sync_all())
            .map_err(|source| ConfigError::Write {
                path: self.path.clone(),
                source,
            })?;
        temporary
            .persist(&self.path)
            .map_err(|error| ConfigError::Write {
                path: self.path.clone(),
                source: error.error,
            })?;
        sync_directory(parent).map_err(|source| ConfigError::Write {
            path: self.path.clone(),
            source,
        })?;
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DiskConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    authtoken: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    server_addr: Option<String>,
}

impl Drop for DiskConfig {
    fn drop(&mut self) {
        self.authtoken.zeroize();
    }
}

#[cfg(unix)]
fn secure_directory_permissions(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn secure_directory_permissions(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn secure_file_permissions(file: &fs::File) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    file.set_permissions(fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn secure_file_permissions(_file: &fs::File) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> io::Result<()> {
    fs::File::open(path)?.sync_all()
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("could not determine the platform configuration directory")]
    PlatformConfigUnavailable,
    #[error("could not read Sink configuration at {path}")]
    Read {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("Sink configuration at {path} is invalid; update it with `sink config` commands")]
    InvalidFile { path: PathBuf },
    #[error("could not serialize Sink configuration")]
    Serialize,
    #[error("could not securely write Sink configuration at {path}")]
    Write {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error(
        "no authentication token configured; run `sink config add-authtoken TOKEN` or pass `--authtoken TOKEN`"
    )]
    MissingAuthToken,
    #[error(
        "no server address configured; run `sink config add-server-addr SERVER` or pass `--server-addr SERVER`"
    )]
    MissingServerAddress,
    #[error("the built-in Sink server address is invalid")]
    InvalidBuiltInServerAddress,
    #[error(
        "refusing a plaintext control connection; use an https:// server or pass `--allow-plaintext-control` for local development"
    )]
    PlaintextControlNotAllowed,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_store(directory: &tempfile::TempDir) -> ConfigStore {
        ConfigStore::new(directory.path().join("nested").join(CONFIG_FILE_NAME))
    }

    #[test]
    fn saves_and_loads_both_configuration_values() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = test_store(&directory);
        store.save_authtoken(AuthToken::new("saved-secret")?)?;
        store.save_server_addr("https://connect.example.test".parse()?)?;

        let loaded = store.load()?;
        assert_eq!(
            loaded.authtoken().map(AuthToken::expose_secret),
            Some("saved-secret")
        );
        assert_eq!(
            loaded.server_addr().map(ToString::to_string),
            Some("https://connect.example.test/".to_owned())
        );
        Ok(())
    }

    #[test]
    fn run_overrides_win_without_changing_saved_values() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = test_store(&directory);
        store.save_authtoken(AuthToken::new("saved-secret")?)?;
        store.save_server_addr("https://saved.example.test".parse()?)?;

        let saved = store.load()?;
        let resolved = saved.resolve_for_http(RunOverrides {
            authtoken: Some(AuthToken::new("one-run-secret")?),
            server_addr: Some("https://override.example.test".parse()?),
            allow_plaintext_control: false,
        })?;
        assert_eq!(resolved.auth_token().expose_secret(), "one-run-secret");
        assert_eq!(
            resolved.server_addr().to_string(),
            "https://override.example.test/"
        );

        let reloaded = store.load()?;
        assert_eq!(
            reloaded.authtoken().map(AuthToken::expose_secret),
            Some("saved-secret")
        );
        assert_eq!(
            reloaded.server_addr().map(ToString::to_string),
            Some("https://saved.example.test/".to_owned())
        );
        Ok(())
    }

    #[test]
    fn resolution_uses_intended_default_and_has_actionable_missing_errors()
    -> Result<(), Box<dyn std::error::Error>> {
        let saved = SavedConfig::default();
        assert!(matches!(
            saved.resolve_for_http(RunOverrides::default()),
            Err(ConfigError::MissingAuthToken)
        ));

        let overrides = RunOverrides {
            authtoken: Some(AuthToken::new("secret")?),
            ..RunOverrides::default()
        };
        let resolved = saved.resolve_for_http(overrides.clone())?;
        assert_eq!(
            resolved.server_addr().to_string(),
            DEFAULT_SERVER_ADDR.to_owned() + "/"
        );
        assert!(matches!(
            saved.resolve(overrides, ServerAddressFallback::RequireConfigured),
            Err(ConfigError::MissingServerAddress)
        ));
        Ok(())
    }

    #[test]
    fn plaintext_control_requires_per_run_opt_in() -> Result<(), Box<dyn std::error::Error>> {
        let saved = SavedConfig {
            authtoken: Some(AuthToken::new("secret")?),
            server_addr: Some("http://127.0.0.1:8080".parse()?),
        };
        assert!(matches!(
            saved.resolve_for_http(RunOverrides::default()),
            Err(ConfigError::PlaintextControlNotAllowed)
        ));
        let resolved = saved.resolve_for_http(RunOverrides {
            allow_plaintext_control: true,
            ..RunOverrides::default()
        })?;
        assert!(resolved.server_addr().is_plaintext());
        Ok(())
    }

    #[test]
    fn debug_output_redacts_authentication_tokens() -> Result<(), AuthTokenError> {
        let token = AuthToken::new("do-not-print-this")?;
        let config = SavedConfig {
            authtoken: Some(token.clone()),
            server_addr: None,
        };
        let resolved = ResolvedConfig {
            auth_token: token.clone(),
            server_addr: DEFAULT_SERVER_ADDR
                .parse()
                .map_err(|_| AuthTokenError::Empty)?,
        };
        for output in [
            format!("{token:?}"),
            format!("{config:?}"),
            format!("{resolved:?}"),
        ] {
            assert!(!output.contains("do-not-print-this"));
            assert!(output.contains("REDACTED"));
        }
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn persisted_config_and_directory_are_owner_only() -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir()?;
        let store = test_store(&directory);
        store.save_authtoken(AuthToken::new("saved-secret")?)?;

        let file_mode = fs::metadata(store.path())?.permissions().mode() & 0o777;
        let directory_mode = fs::metadata(store.path().parent().ok_or("missing parent")?)?
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(file_mode, 0o600);
        assert_eq!(directory_mode, 0o700);
        Ok(())
    }

    #[test]
    fn malformed_config_errors_do_not_echo_file_contents() -> Result<(), Box<dyn std::error::Error>>
    {
        let directory = tempfile::tempdir()?;
        let store = test_store(&directory);
        fs::create_dir_all(store.path().parent().ok_or("missing parent")?)?;
        fs::write(store.path(), "authtoken = [\"secret-that-must-not-leak\"]")?;

        let error = store.load().expect_err("configuration should be rejected");
        let output = format!("{error:?} {error}");
        assert!(!output.contains("secret-that-must-not-leak"));
        Ok(())
    }
}
