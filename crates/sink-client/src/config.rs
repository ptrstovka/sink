use std::{
    collections::HashMap,
    fmt, fs,
    io::{self, Write},
    num::{NonZeroU16, NonZeroUsize},
    path::{Path, PathBuf},
    str::FromStr,
};

use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;
use thiserror::Error;
use url::Url;
use zeroize::{Zeroize as _, Zeroizing};

use crate::{
    cors::{CorsOrigin, CorsPolicy},
    target::{LocalTarget, PublicUrl},
};

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

    /// Resolves a normal `sink http` run. Both credentials and the server
    /// address must come from an explicit override or saved configuration.
    pub fn resolve_for_http(&self, overrides: RunOverrides) -> Result<ResolvedConfig, ConfigError> {
        self.resolve(overrides)
    }

    /// Resolves run settings with explicit override > saved precedence. This
    /// method never writes to the config store.
    pub fn resolve(&self, overrides: RunOverrides) -> Result<ResolvedConfig, ConfigError> {
        let auth_token = overrides
            .authtoken
            .or_else(|| self.authtoken.clone())
            .ok_or(ConfigError::MissingAuthToken)?;
        let server_addr = overrides
            .server_addr
            .or_else(|| self.server_addr.clone())
            .ok_or(ConfigError::MissingServerAddress)?;

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

const DEFAULT_INSPECT_REQUEST_LIMIT: u64 = 100;
const DEFAULT_INSPECT_BODY_LIMIT: u64 = 1_048_576;
const MAX_ROUTE_NAME_BYTES: usize = 64;

/// A completely parsed and semantically validated multi-connect file.
///
/// The file is TOML and uses one array-table per named route:
///
/// ```toml
/// [[routes]]
/// name = "api"
/// url = "https://api.example.com"
/// target = "localhost:3000"
/// dashboard_port = 4040 # optional; automatic when omitted
/// ```
///
/// `local_tls_insecure`, `cors_allow_origin`, `cors_allow_credentials`,
/// `inspect`, `inspect_request_limit`, and `inspect_body_limit` mirror the
/// existing `sink http` options. Authentication and the control-server address
/// are intentionally absent and continue to use the existing global settings.
#[derive(Clone, Debug)]
pub struct ConnectConfig {
    routes: Vec<ConnectRouteConfig>,
}

impl ConnectConfig {
    /// Read and validate every route before returning any runnable state.
    pub fn load(path: &Path) -> Result<Self, ConnectConfigError> {
        let contents = fs::read_to_string(path).map_err(|source| ConnectConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        let disk: DiskConnectConfig =
            toml::from_str(&contents).map_err(|source| ConnectConfigError::InvalidFile {
                path: path.to_path_buf(),
                detail: source.message().to_owned(),
            })?;
        Self::from_disk(disk)
    }

    fn from_disk(disk: DiskConnectConfig) -> Result<Self, ConnectConfigError> {
        if disk.routes.is_empty() {
            return Err(ConnectConfigError::NoRoutes);
        }

        let mut routes = Vec::with_capacity(disk.routes.len());
        let mut names = HashMap::<String, usize>::new();
        let mut hostnames = HashMap::<String, String>::new();
        let mut dashboard_ports = HashMap::<NonZeroU16, String>::new();

        for (index, raw) in disk.routes.into_iter().enumerate() {
            let route_number = index.saturating_add(1);
            validate_route_name(&raw.name, route_number)?;
            if let Some(first_index) = names.insert(raw.name.clone(), route_number) {
                return Err(ConnectConfigError::DuplicateRouteName {
                    name: raw.name,
                    first_index,
                    duplicate_index: route_number,
                });
            }

            let route = ConnectRouteConfig::from_disk(raw, route_number)?;
            let hostname = route.public_url.requested_hostname().to_owned();
            if let Some(first_route) = hostnames.insert(hostname.clone(), route.name.clone()) {
                return Err(ConnectConfigError::DuplicatePublicHostname {
                    hostname,
                    first_route,
                    duplicate_route: route.name,
                });
            }
            if let Some(port) = route.dashboard_port
                && let Some(first_route) = dashboard_ports.insert(port, route.name.clone())
            {
                return Err(ConnectConfigError::DuplicateDashboardPort {
                    port,
                    first_route,
                    duplicate_route: route.name,
                });
            }
            routes.push(route);
        }

        Ok(Self { routes })
    }

    #[must_use]
    pub fn routes(&self) -> &[ConnectRouteConfig] {
        &self.routes
    }

    #[must_use]
    pub fn into_routes(self) -> Vec<ConnectRouteConfig> {
        self.routes
    }
}

/// One independently supervised route from a validated multi-connect file.
#[derive(Clone, Debug)]
pub struct ConnectRouteConfig {
    pub(crate) name: String,
    pub(crate) public_url: PublicUrl,
    pub(crate) target: LocalTarget,
    pub(crate) local_tls_insecure: bool,
    pub(crate) cors_allow_origin: Vec<CorsOrigin>,
    pub(crate) cors_allow_credentials: bool,
    pub(crate) inspect: bool,
    pub(crate) dashboard_port: Option<NonZeroU16>,
    pub(crate) inspect_request_limit: NonZeroUsize,
    pub(crate) inspect_body_limit: NonZeroUsize,
}

impl ConnectRouteConfig {
    fn from_disk(raw: DiskConnectRoute, route_number: usize) -> Result<Self, ConnectConfigError> {
        let route = raw.name.clone();
        let public_url: PublicUrl = raw.url.parse().map_err(|error| {
            ConnectConfigError::invalid_route(route.clone(), route_number, "url", error)
        })?;
        let target: LocalTarget = raw.target.parse().map_err(|error| {
            ConnectConfigError::invalid_route(route.clone(), route_number, "target", error)
        })?;
        if raw.local_tls_insecure && !target.uses_tls() {
            return Err(ConnectConfigError::invalid_route(
                route,
                route_number,
                "local_tls_insecure",
                "may be true only for an https:// target",
            ));
        }

        let cors_allow_origin: Vec<CorsOrigin> = raw
            .cors_allow_origin
            .into_iter()
            .map(|origin| {
                origin.parse().map_err(|error| {
                    ConnectConfigError::invalid_route(
                        raw.name.clone(),
                        route_number,
                        "cors_allow_origin",
                        error,
                    )
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        CorsPolicy::new(cors_allow_origin.clone(), raw.cors_allow_credentials).map_err(
            |error| {
                ConnectConfigError::invalid_route(
                    raw.name.clone(),
                    route_number,
                    "cors_allow_origin",
                    error,
                )
            },
        )?;

        let dashboard_port = raw
            .dashboard_port
            .map(|port| nonzero_u16(port, &raw.name, route_number, "dashboard_port"))
            .transpose()?;
        if !raw.inspect && dashboard_port.is_some() {
            return Err(ConnectConfigError::invalid_route(
                raw.name,
                route_number,
                "dashboard_port",
                "requires inspect = true",
            ));
        }

        let inspect_request_limit = nonzero_usize(
            raw.inspect_request_limit,
            &raw.name,
            route_number,
            "inspect_request_limit",
        )?;
        let inspect_body_limit = nonzero_usize(
            raw.inspect_body_limit,
            &raw.name,
            route_number,
            "inspect_body_limit",
        )?;

        Ok(Self {
            name: raw.name,
            public_url,
            target,
            local_tls_insecure: raw.local_tls_insecure,
            cors_allow_origin,
            cors_allow_credentials: raw.cors_allow_credentials,
            inspect: raw.inspect,
            dashboard_port,
            inspect_request_limit,
            inspect_body_limit,
        })
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn public_url(&self) -> &PublicUrl {
        &self.public_url
    }

    #[must_use]
    pub fn target(&self) -> &LocalTarget {
        &self.target
    }

    #[must_use]
    pub fn dashboard_port(&self) -> Option<NonZeroU16> {
        self.dashboard_port
    }
}

fn validate_route_name(name: &str, route_number: usize) -> Result<(), ConnectConfigError> {
    if name.is_empty()
        || name.len() > MAX_ROUTE_NAME_BYTES
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(ConnectConfigError::InvalidRouteName {
            route_number,
            name: name.to_owned(),
        });
    }
    Ok(())
}

fn nonzero_u16(
    value: u64,
    route: &str,
    route_number: usize,
    field: &'static str,
) -> Result<NonZeroU16, ConnectConfigError> {
    u16::try_from(value)
        .ok()
        .and_then(NonZeroU16::new)
        .ok_or_else(|| {
            ConnectConfigError::invalid_route(
                route.to_owned(),
                route_number,
                field,
                "must be between 1 and 65535",
            )
        })
}

fn nonzero_usize(
    value: u64,
    route: &str,
    route_number: usize,
    field: &'static str,
) -> Result<NonZeroUsize, ConnectConfigError> {
    usize::try_from(value)
        .ok()
        .and_then(NonZeroUsize::new)
        .ok_or_else(|| {
            ConnectConfigError::invalid_route(
                route.to_owned(),
                route_number,
                field,
                "must be greater than zero and fit this platform",
            )
        })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DiskConnectConfig {
    routes: Vec<DiskConnectRoute>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DiskConnectRoute {
    name: String,
    url: String,
    target: String,
    #[serde(default)]
    local_tls_insecure: bool,
    #[serde(default)]
    cors_allow_origin: Vec<String>,
    #[serde(default)]
    cors_allow_credentials: bool,
    #[serde(default = "default_inspect")]
    inspect: bool,
    dashboard_port: Option<u64>,
    #[serde(default = "default_inspect_request_limit")]
    inspect_request_limit: u64,
    #[serde(default = "default_inspect_body_limit")]
    inspect_body_limit: u64,
}

const fn default_inspect() -> bool {
    true
}

const fn default_inspect_request_limit() -> u64 {
    DEFAULT_INSPECT_REQUEST_LIMIT
}

const fn default_inspect_body_limit() -> u64 {
    DEFAULT_INSPECT_BODY_LIMIT
}

#[derive(Debug, Error)]
pub enum ConnectConfigError {
    #[error("could not read multi-connect configuration at {path}")]
    Read {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("multi-connect configuration at {path} is invalid: {detail}")]
    InvalidFile { path: PathBuf, detail: String },
    #[error("multi-connect configuration must contain at least one [[routes]] entry")]
    NoRoutes,
    #[error(
        "route #{route_number} has invalid name `{name}`; use 1-64 ASCII letters, digits, '-' or '_'"
    )]
    InvalidRouteName { route_number: usize, name: String },
    #[error("duplicate route name `{name}` at routes #{first_index} and #{duplicate_index}")]
    DuplicateRouteName {
        name: String,
        first_index: usize,
        duplicate_index: usize,
    },
    #[error(
        "duplicate public hostname `{hostname}` in routes `{first_route}` and `{duplicate_route}`"
    )]
    DuplicatePublicHostname {
        hostname: String,
        first_route: String,
        duplicate_route: String,
    },
    #[error(
        "dashboard port {port} is explicitly assigned to both `{first_route}` and `{duplicate_route}`"
    )]
    DuplicateDashboardPort {
        port: NonZeroU16,
        first_route: String,
        duplicate_route: String,
    },
    #[error("route `{route}` (#{route_number}) has invalid {field}: {detail}")]
    InvalidRoute {
        route: String,
        route_number: usize,
        field: &'static str,
        detail: String,
    },
}

impl ConnectConfigError {
    fn invalid_route(
        route: String,
        route_number: usize,
        field: &'static str,
        detail: impl fmt::Display,
    ) -> Self {
        Self::InvalidRoute {
            route,
            route_number,
            field,
            detail: detail.to_string(),
        }
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
        let project_dirs =
            ProjectDirs::from("", "", "sink").ok_or(ConfigError::PlatformConfigUnavailable)?;
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
    fn resolution_requires_both_values_and_has_actionable_missing_errors()
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
        assert!(matches!(
            saved.resolve_for_http(overrides),
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
            server_addr: "https://connect.example.test"
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

    fn write_connect_config(
        directory: &tempfile::TempDir,
        contents: &str,
    ) -> Result<PathBuf, io::Error> {
        let path = directory.path().join("routes.toml");
        fs::write(&path, contents)?;
        Ok(path)
    }

    #[test]
    fn multi_connect_file_parses_current_route_conventions()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = write_connect_config(
            &directory,
            r#"
[[routes]]
name = "api"
url = "https://API.cloud.example.com"
target = "https://localhost:8443/base"
local_tls_insecure = true
cors_allow_origin = ["https://app.example.com"]
cors_allow_credentials = true
dashboard_port = 4042
inspect_request_limit = 25
inspect_body_limit = 65536

[[routes]]
name = "events"
url = "https://events.cloud.example.com"
target = "localhost:6001"
inspect = false
"#,
        )?;

        let config = ConnectConfig::load(&path)?;
        assert_eq!(config.routes().len(), 2);
        let api = &config.routes()[0];
        assert_eq!(api.name(), "api");
        assert_eq!(
            api.public_url().requested_hostname(),
            "api.cloud.example.com"
        );
        assert_eq!(api.target().to_string(), "https://localhost:8443/base");
        assert_eq!(api.dashboard_port().map(NonZeroU16::get), Some(4042));
        assert_eq!(api.inspect_request_limit.get(), 25);
        assert_eq!(api.inspect_body_limit.get(), 65_536);

        let events = &config.routes()[1];
        assert!(!events.inspect);
        assert_eq!(events.dashboard_port(), None);
        assert_eq!(events.inspect_request_limit.get(), 100);
        assert_eq!(events.inspect_body_limit.get(), 1_048_576);
        Ok(())
    }

    #[test]
    fn multi_connect_file_rejects_duplicate_names_hostnames_and_ports()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let duplicate_name = write_connect_config(
            &directory,
            r#"
[[routes]]
name = "api"
url = "https://api.example.com"
target = "3000"

[[routes]]
name = "api"
url = "https://events.example.com"
target = "3001"
"#,
        )?;
        assert!(matches!(
            ConnectConfig::load(&duplicate_name),
            Err(ConnectConfigError::DuplicateRouteName { .. })
        ));

        let duplicate_hostname = write_connect_config(
            &directory,
            r#"
[[routes]]
name = "first"
url = "https://API.example.com"
target = "3000"

[[routes]]
name = "second"
url = "https://api.example.com"
target = "3001"
"#,
        )?;
        assert!(matches!(
            ConnectConfig::load(&duplicate_hostname),
            Err(ConnectConfigError::DuplicatePublicHostname { .. })
        ));

        let duplicate_port = write_connect_config(
            &directory,
            r#"
[[routes]]
name = "first"
url = "https://first.example.com"
target = "3000"
dashboard_port = 4050

[[routes]]
name = "second"
url = "https://second.example.com"
target = "3001"
dashboard_port = 4050
"#,
        )?;
        assert!(matches!(
            ConnectConfig::load(&duplicate_port),
            Err(ConnectConfigError::DuplicateDashboardPort { .. })
        ));
        Ok(())
    }

    #[test]
    fn multi_connect_file_rejects_invalid_route_semantics_before_runtime_setup()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        for (contents, field) in [
            (
                r#"
[[routes]]
name = "api"
url = "https://api.example.com"
target = "localhost"
"#,
                "target",
            ),
            (
                r#"
[[routes]]
name = "api"
url = "https://api.example.com"
target = "3000"
local_tls_insecure = true
"#,
                "local_tls_insecure",
            ),
            (
                r#"
[[routes]]
name = "api"
url = "https://api.example.com"
target = "3000"
inspect = false
dashboard_port = 4040
"#,
                "dashboard_port",
            ),
            (
                r#"
[[routes]]
name = "api"
url = "https://api.example.com"
target = "3000"
inspect_request_limit = 0
"#,
                "inspect_request_limit",
            ),
        ] {
            let path = write_connect_config(&directory, contents)?;
            let error = ConnectConfig::load(&path).expect_err("route must be invalid");
            assert!(
                matches!(error, ConnectConfigError::InvalidRoute { field: actual, .. } if actual == field),
                "unexpected error for {field}: {error}"
            );
        }
        Ok(())
    }

    #[test]
    fn multi_connect_file_requires_routes_and_rejects_secret_fields_without_echoing_values()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let empty = write_connect_config(&directory, "routes = []")?;
        assert!(matches!(
            ConnectConfig::load(&empty),
            Err(ConnectConfigError::NoRoutes)
        ));

        let secret = "secret-that-must-stay-external";
        let path = write_connect_config(
            &directory,
            &format!(
                r#"
authtoken = "{secret}"

[[routes]]
name = "api"
url = "https://api.example.com"
target = "3000"
"#
            ),
        )?;
        let error = ConnectConfig::load(&path).expect_err("secret field must be rejected");
        let output = format!("{error:?} {error}");
        assert!(!output.contains(secret));
        assert!(output.contains("unknown field"));
        Ok(())
    }
}
