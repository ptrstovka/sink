//! Command-line and environment-backed server configuration.

use std::{
    env,
    ffi::OsString,
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::PathBuf,
    str::FromStr,
};

use clap::Args;
use thiserror::Error;

use crate::certificates::{
    CertificateProviderKind, Hostname, SecretBytes, UnsupportedCertificateProvider,
};

pub const LISTEN_ADDRESS_ENV: &str = "SINK_SERVER_LISTEN_ADDRESS";
pub const HTTP_LISTEN_ADDRESS_ENV: &str = "SINK_SERVER_HTTP_LISTEN_ADDRESS";
pub const HTTPS_LISTEN_ADDRESS_ENV: &str = "SINK_SERVER_HTTPS_LISTEN_ADDRESS";
pub const HTTPS_PROXY_PROTOCOL_ENV: &str = "SINK_SERVER_HTTPS_PROXY_PROTOCOL";
pub const HTTPS_PROXY_TRUSTED_PEER_CIDRS_ENV: &str = "SINK_SERVER_HTTPS_PROXY_TRUSTED_PEER_CIDRS";
pub const PUBLIC_BASE_DOMAIN_ENV: &str = "SINK_SERVER_PUBLIC_BASE_DOMAIN";
pub const MAX_NAMESPACE_DEPTH_ENV: &str = "SINK_SERVER_MAX_NAMESPACE_DEPTH";
pub const CERTIFICATE_PROVIDER_ENV: &str = "SINK_SERVER_CERTIFICATE_PROVIDER";
pub const CERTIFICATE_BACKEND_ENABLED_ENV: &str = "SINK_SERVER_CERTIFICATE_BACKEND_ENABLED";
pub const ACME_DIRECTORY_URL_ENV: &str = "SINK_SERVER_ACME_DIRECTORY_URL";
pub const ACME_CONTACT_ENV: &str = "SINK_SERVER_ACME_CONTACT";
pub const ACME_TERMS_AGREED_ENV: &str = "SINK_SERVER_ACME_TERMS_AGREED";
pub const CLOUDFLARE_ZONE_ID_ENV: &str = "SINK_SERVER_CLOUDFLARE_ZONE_ID";
pub const CLOUDFLARE_API_TOKEN_ENV: &str = "SINK_SERVER_CLOUDFLARE_API_TOKEN";
pub const SQLITE_PATH_ENV: &str = "SINK_SERVER_SQLITE_PATH";
pub const LOG_LEVEL_ENV: &str = "SINK_SERVER_LOG_LEVEL";

pub const DEFAULT_LISTEN_ADDRESS: &str = "127.0.0.1:8080";
pub const DEFAULT_SQLITE_PATH: &str = "sink.sqlite3";
pub const DEFAULT_LOG_LEVEL: &str = "info";
pub const DEFAULT_MAX_NAMESPACE_DEPTH: u8 = 2;
pub const DEFAULT_CERTIFICATE_PROVIDER: &str = "cloudflare";
pub const DEFAULT_HTTPS_PROXY_PROTOCOL: &str = "disabled";
pub const DEFAULT_ACME_DIRECTORY_URL: &str =
    "https://acme-staging-v02.api.letsencrypt.org/directory";

/// Raw `serve` options. Every option can also be supplied by its documented
/// `SINK_SERVER_*` environment variable; Clap gives an explicit flag priority
/// over the environment value.
#[derive(Args, Clone, Debug, Default, Eq, PartialEq)]
pub struct ServeArgs {
    /// Legacy alias for `--http-listen-address`.
    #[arg(long, value_name = "ADDRESS", env = "SINK_SERVER_LISTEN_ADDRESS")]
    pub listen_address: Option<SocketAddr>,

    /// Address on which Sink accepts plain HTTP traffic.
    #[arg(long, value_name = "ADDRESS", env = "SINK_SERVER_HTTP_LISTEN_ADDRESS")]
    pub http_listen_address: Option<SocketAddr>,

    /// Address on which Sink terminates HTTPS/TLS traffic. Required when the
    /// certificate backend is enabled and rejected when it is disabled.
    #[arg(long, value_name = "ADDRESS", env = "SINK_SERVER_HTTPS_LISTEN_ADDRESS")]
    pub https_listen_address: Option<SocketAddr>,

    #[command(flatten)]
    pub https_proxy: Box<HttpsProxyArgs>,

    /// Public DNS suffix used for tunnel and control hostnames.
    #[arg(
        long,
        value_name = "DOMAIN",
        env = "SINK_SERVER_PUBLIC_BASE_DOMAIN",
        required = true
    )]
    pub public_base_domain: Option<String>,

    /// Maximum persistent namespace-claim depth below the base domain.
    #[arg(long, value_name = "DEPTH", env = "SINK_SERVER_MAX_NAMESPACE_DEPTH")]
    pub max_namespace_depth: Option<u8>,

    /// DNS/certificate provider used for this domain.
    #[arg(
        long,
        value_name = "PROVIDER",
        env = "SINK_SERVER_CERTIFICATE_PROVIDER"
    )]
    pub certificate_provider: Option<String>,

    /// Enable the durable ACME backend and HTTPS listener. Existing plain HTTP
    /// behavior remains available with this disabled.
    #[arg(long, env = "SINK_SERVER_CERTIFICATE_BACKEND_ENABLED")]
    pub certificate_backend_enabled: Option<bool>,

    /// HTTPS ACME directory. The safe default is Let's Encrypt staging;
    /// production issuance must select the production directory explicitly.
    #[arg(long, value_name = "URL", env = "SINK_SERVER_ACME_DIRECTORY_URL")]
    pub acme_directory_url: Option<String>,

    /// ACME account contact in `mailto:user@example.com` form.
    #[arg(long, value_name = "MAILTO", env = "SINK_SERVER_ACME_CONTACT")]
    pub acme_contact: Option<String>,

    /// Explicitly agree to the configured ACME directory's terms of service.
    #[arg(long, env = "SINK_SERVER_ACME_TERMS_AGREED")]
    pub acme_terms_agreed: Option<bool>,

    /// Cloudflare zone identifier containing the configured base domain.
    #[arg(long, value_name = "ZONE_ID", env = "SINK_SERVER_CLOUDFLARE_ZONE_ID")]
    pub cloudflare_zone_id: Option<String>,

    #[command(flatten)]
    pub database: DatabaseArgs,

    /// Tracing filter, such as `info` or `info,sink_server=debug`.
    #[arg(long, value_name = "FILTER", env = "SINK_SERVER_LOG_LEVEL")]
    pub log_level: Option<String>,
}

#[derive(Args, Clone, Debug, Default, Eq, PartialEq)]
pub struct HttpsProxyArgs {
    /// HTTPS ingress PROXY protocol policy: `disabled` (the compatibility
    /// default) or `required-v2`.
    #[arg(
        long = "https-proxy-protocol",
        value_name = "MODE",
        env = "SINK_SERVER_HTTPS_PROXY_PROTOCOL"
    )]
    pub protocol: Option<String>,

    /// Comma-separated IPv4/IPv6 CIDRs allowed to supply required PROXY v2
    /// metadata. Valid only with `--https-proxy-protocol required-v2`.
    #[arg(
        long = "https-proxy-trusted-peer-cidrs",
        value_name = "CIDR,...",
        env = "SINK_SERVER_HTTPS_PROXY_TRUSTED_PEER_CIDRS"
    )]
    pub trusted_peer_cidrs: Option<String>,
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
    pub http_listen_address: SocketAddr,
    pub https_listen_address: Option<SocketAddr>,
    pub https_proxy: HttpsProxyConfig,
    /// Kept for the existing runtime until multi-domain listener wiring lands.
    pub public_base_domain: String,
    pub domains: ConfiguredDomains,
    pub certificate_backend: CertificateBackendConfig,
    pub sqlite_path: PathBuf,
    pub log_level: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HttpsProxyConfig {
    Disabled,
    RequiredV2 {
        trusted_peer_cidrs: Vec<TrustedPeerCidr>,
    },
}

impl HttpsProxyConfig {
    pub fn mode_name(&self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::RequiredV2 { .. } => "required-v2",
        }
    }

    pub fn trusted_peer_cidrs(&self) -> &[TrustedPeerCidr] {
        match self {
            Self::Disabled => &[],
            Self::RequiredV2 { trusted_peer_cidrs } => trusted_peer_cidrs,
        }
    }
}

/// A validated, canonical IPv4 or IPv6 network used only for ingress trust.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TrustedPeerCidr {
    network: IpAddr,
    prefix: u8,
}

impl TrustedPeerCidr {
    pub fn contains(self, address: IpAddr) -> bool {
        match (self.network, address) {
            (IpAddr::V4(network), IpAddr::V4(address)) => {
                let mask = ipv4_mask(self.prefix);
                u32::from(network) & mask == u32::from(address) & mask
            }
            (IpAddr::V6(network), IpAddr::V6(address)) => {
                let mask = ipv6_mask(self.prefix);
                u128::from(network) & mask == u128::from(address) & mask
            }
            (IpAddr::V4(_), IpAddr::V6(_)) | (IpAddr::V6(_), IpAddr::V4(_)) => false,
        }
    }
}

impl FromStr for TrustedPeerCidr {
    type Err = ConfigError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (address, prefix) = value
            .split_once('/')
            .ok_or(ConfigError::InvalidHttpsProxyTrustedPeerCidr)?;
        if address.is_empty() || prefix.is_empty() || prefix.contains('/') {
            return Err(ConfigError::InvalidHttpsProxyTrustedPeerCidr);
        }
        let address = address
            .parse::<IpAddr>()
            .map_err(|_| ConfigError::InvalidHttpsProxyTrustedPeerCidr)?;
        let prefix = prefix
            .parse::<u8>()
            .map_err(|_| ConfigError::InvalidHttpsProxyTrustedPeerCidr)?;
        let network = match address {
            IpAddr::V4(address) if prefix <= 32 => {
                IpAddr::V4(Ipv4Addr::from(u32::from(address) & ipv4_mask(prefix)))
            }
            IpAddr::V6(address) if prefix <= 128 => {
                IpAddr::V6(Ipv6Addr::from(u128::from(address) & ipv6_mask(prefix)))
            }
            IpAddr::V4(_) | IpAddr::V6(_) => {
                return Err(ConfigError::InvalidHttpsProxyTrustedPeerCidr);
            }
        };
        Ok(Self { network, prefix })
    }
}

impl fmt::Display for TrustedPeerCidr {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}/{}", self.network, self.prefix)
    }
}

const fn ipv4_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

const fn ipv6_mask(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CertificateBackendConfig {
    Disabled,
    Enabled(EnabledCertificateBackendConfig),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnabledCertificateBackendConfig {
    pub acme_directory_url: String,
    pub acme_contact: String,
    pub cloudflare_zone_id: String,
    pub cloudflare_zone_hostname: Hostname,
    pub cloudflare_api_token: CloudflareApiToken,
}

#[derive(Clone, Eq, PartialEq)]
pub struct CloudflareApiToken(SecretBytes);

impl CloudflareApiToken {
    pub fn new(value: impl Into<String>) -> Self {
        Self(SecretBytes::new(value.into().into_bytes()))
    }

    pub fn expose_secret(&self) -> &[u8] {
        self.0.expose_secret()
    }
}

impl fmt::Debug for CloudflareApiToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CloudflareApiToken([REDACTED])")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfiguredDomain {
    pub hostname: Hostname,
    pub max_namespace_depth: u8,
    pub certificate_provider: CertificateProviderKind,
}

impl ConfiguredDomain {
    pub fn new(
        hostname: Hostname,
        max_namespace_depth: u8,
        certificate_provider: CertificateProviderKind,
    ) -> Result<Self, ConfigError> {
        if max_namespace_depth == 0 {
            return Err(ConfigError::InvalidMaxNamespaceDepth);
        }
        Ok(Self {
            hostname,
            max_namespace_depth,
            certificate_provider,
        })
    }
}

/// Validated collection designed for multiple configured base domains even
/// though the current CLI resolves the existing single-domain option.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfiguredDomains(Vec<ConfiguredDomain>);

impl ConfiguredDomains {
    pub fn new(domains: Vec<ConfiguredDomain>) -> Result<Self, ConfigError> {
        if domains.is_empty() {
            return Err(ConfigError::MissingPublicBaseDomain);
        }
        for (index, domain) in domains.iter().enumerate() {
            if domains[..index]
                .iter()
                .any(|existing| existing.hostname == domain.hostname)
            {
                return Err(ConfigError::DuplicateBaseDomain(
                    domain.hostname.to_string(),
                ));
            }
        }
        Ok(Self(domains))
    }

    pub fn as_slice(&self) -> &[ConfiguredDomain] {
        &self.0
    }

    /// Resolve overlapping configured suffixes in favor of the most specific.
    pub fn most_specific_match(&self, hostname: &Hostname) -> Option<&ConfiguredDomain> {
        self.0
            .iter()
            .filter(|domain| hostname.is_same_or_below(&domain.hostname))
            .max_by_key(|domain| domain.hostname.label_count())
    }
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
        let http_listen_address = resolve_http_listen_address(args, environment)?;

        let configured_domain = match args.public_base_domain.as_deref() {
            Some(domain) => domain.to_owned(),
            None => environment_string(environment, PUBLIC_BASE_DOMAIN_ENV)?
                .ok_or(ConfigError::MissingPublicBaseDomain)?,
        };
        let public_base_domain = normalize_base_domain(&configured_domain)?;

        let max_namespace_depth = match args.max_namespace_depth {
            Some(depth) => depth,
            None => environment_string(environment, MAX_NAMESPACE_DEPTH_ENV)?
                .map(|value| {
                    value
                        .parse::<u8>()
                        .map_err(|_| ConfigError::InvalidMaxNamespaceDepth)
                })
                .transpose()?
                .unwrap_or(DEFAULT_MAX_NAMESPACE_DEPTH),
        };
        let configured_provider = match args.certificate_provider.as_deref() {
            Some(provider) => provider.to_owned(),
            None => environment_string(environment, CERTIFICATE_PROVIDER_ENV)?
                .unwrap_or_else(|| DEFAULT_CERTIFICATE_PROVIDER.to_owned()),
        };
        let certificate_provider = configured_provider.parse()?;
        let configured_domain = ConfiguredDomain::new(
            Hostname::parse(&public_base_domain)
                .map_err(|_| ConfigError::InvalidPublicBaseDomain)?,
            max_namespace_depth,
            certificate_provider,
        )?;
        let domains = ConfiguredDomains::new(vec![configured_domain])?;
        let certificate_backend =
            resolve_certificate_backend(args, environment, domains.as_slice()[0].hostname.clone())?;
        let https_listen_address = resolve_https_listen_address(
            args,
            environment,
            &certificate_backend,
            http_listen_address,
        )?;
        let https_proxy = resolve_https_proxy(args, environment, &certificate_backend)?;

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
            http_listen_address,
            https_listen_address,
            https_proxy,
            public_base_domain,
            domains,
            certificate_backend,
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

    #[error("legacy and HTTP listener addresses disagree")]
    ConflictingHttpListenAddresses,

    #[error(
        "HTTPS listen address is required when the certificate backend is enabled; pass `--https-listen-address ADDRESS` or set SINK_SERVER_HTTPS_LISTEN_ADDRESS"
    )]
    MissingHttpsListenAddress,

    #[error("HTTPS listen address requires the certificate backend to be enabled")]
    HttpsListenAddressWithoutCertificateBackend,

    #[error("HTTP and HTTPS listeners must use different addresses")]
    DuplicateListenAddresses,

    #[error("HTTPS PROXY protocol mode must be `disabled` or `required-v2`")]
    InvalidHttpsProxyProtocol,

    #[error("required PROXY v2 mode needs at least one trusted peer CIDR")]
    MissingHttpsProxyTrustedPeerCidrs,

    #[error("trusted PROXY peer CIDRs are valid only in `required-v2` mode")]
    HttpsProxyTrustedPeerCidrsWithoutRequiredV2,

    #[error("HTTPS PROXY protocol configuration requires the certificate backend")]
    HttpsProxyWithoutCertificateBackend,

    #[error("invalid HTTPS PROXY trusted peer CIDR")]
    InvalidHttpsProxyTrustedPeerCidr,

    #[error("public base domain must be a valid DNS name without a scheme, port, or wildcard")]
    InvalidPublicBaseDomain,

    #[error("maximum namespace depth must be an integer greater than zero")]
    InvalidMaxNamespaceDepth,

    #[error(transparent)]
    UnsupportedCertificateProvider(#[from] UnsupportedCertificateProvider),

    #[error("base domain `{0}` is configured more than once")]
    DuplicateBaseDomain(String),

    #[error(
        "public base domain is required; pass `--public-base-domain DOMAIN` or set SINK_SERVER_PUBLIC_BASE_DOMAIN"
    )]
    MissingPublicBaseDomain,

    #[error("SQLite database path cannot be empty")]
    EmptySqlitePath,

    #[error("log level/filter cannot be empty")]
    EmptyLogLevel,

    #[error("certificate backend enablement must be `true` or `false`")]
    InvalidCertificateBackendEnabled,

    #[error("ACME directory URL must be a valid HTTPS URL")]
    InvalidAcmeDirectoryUrl,

    #[error("ACME contact must use `mailto:user@example.com` form")]
    InvalidAcmeContact,

    #[error("certificate backend enablement requires explicit ACME terms agreement")]
    AcmeTermsNotAgreed,

    #[error("Cloudflare zone ID must contain exactly 32 hexadecimal characters")]
    InvalidCloudflareZoneId,

    #[error("Cloudflare API token is required when the certificate backend is enabled")]
    MissingCloudflareApiToken,
}

fn resolve_http_listen_address(
    args: &ServeArgs,
    environment: &impl Environment,
) -> Result<SocketAddr, ConfigError> {
    if let (Some(legacy), Some(http)) = (args.listen_address, args.http_listen_address) {
        if legacy != http {
            return Err(ConfigError::ConflictingHttpListenAddresses);
        }
        return Ok(http);
    }
    if let Some(address) = args.http_listen_address.or(args.listen_address) {
        return Ok(address);
    }

    let http = environment_string(environment, HTTP_LISTEN_ADDRESS_ENV)?;
    let legacy = environment_string(environment, LISTEN_ADDRESS_ENV)?;
    if let (Some(http), Some(legacy)) = (&http, &legacy)
        && http != legacy
    {
        return Err(ConfigError::ConflictingHttpListenAddresses);
    }
    http.or(legacy)
        .unwrap_or_else(|| DEFAULT_LISTEN_ADDRESS.to_owned())
        .parse()
        .map_err(|source| ConfigError::InvalidListenAddress { source })
}

fn resolve_https_listen_address(
    args: &ServeArgs,
    environment: &impl Environment,
    backend: &CertificateBackendConfig,
    http_listen_address: SocketAddr,
) -> Result<Option<SocketAddr>, ConfigError> {
    let configured = match args.https_listen_address {
        Some(address) => Some(address),
        None => environment_string(environment, HTTPS_LISTEN_ADDRESS_ENV)?
            .map(|value| {
                value
                    .parse()
                    .map_err(|source| ConfigError::InvalidListenAddress { source })
            })
            .transpose()?,
    };

    match (backend, configured) {
        (CertificateBackendConfig::Disabled, None) => Ok(None),
        (CertificateBackendConfig::Disabled, Some(_)) => {
            Err(ConfigError::HttpsListenAddressWithoutCertificateBackend)
        }
        (CertificateBackendConfig::Enabled(_), None) => Err(ConfigError::MissingHttpsListenAddress),
        (CertificateBackendConfig::Enabled(_), Some(address)) if address == http_listen_address => {
            Err(ConfigError::DuplicateListenAddresses)
        }
        (CertificateBackendConfig::Enabled(_), Some(address)) => Ok(Some(address)),
    }
}

fn resolve_https_proxy(
    args: &ServeArgs,
    environment: &impl Environment,
    backend: &CertificateBackendConfig,
) -> Result<HttpsProxyConfig, ConfigError> {
    let mode = args
        .https_proxy
        .protocol
        .clone()
        .or(environment_string(environment, HTTPS_PROXY_PROTOCOL_ENV)?)
        .unwrap_or_else(|| DEFAULT_HTTPS_PROXY_PROTOCOL.to_owned());
    let trusted = args
        .https_proxy
        .trusted_peer_cidrs
        .clone()
        .or(environment_string(
            environment,
            HTTPS_PROXY_TRUSTED_PEER_CIDRS_ENV,
        )?);

    let mode = mode.trim().to_ascii_lowercase();
    let config = match mode.as_str() {
        "disabled" => {
            if trusted
                .as_deref()
                .is_some_and(|value| !value.trim().is_empty())
            {
                return Err(ConfigError::HttpsProxyTrustedPeerCidrsWithoutRequiredV2);
            }
            HttpsProxyConfig::Disabled
        }
        "required-v2" => {
            let trusted = trusted.ok_or(ConfigError::MissingHttpsProxyTrustedPeerCidrs)?;
            let mut trusted_peer_cidrs = Vec::new();
            for value in trusted.split(',') {
                let value = value.trim();
                if value.is_empty() {
                    return Err(ConfigError::InvalidHttpsProxyTrustedPeerCidr);
                }
                let cidr = value.parse::<TrustedPeerCidr>()?;
                if !trusted_peer_cidrs.contains(&cidr) {
                    trusted_peer_cidrs.push(cidr);
                }
            }
            if trusted_peer_cidrs.is_empty() {
                return Err(ConfigError::MissingHttpsProxyTrustedPeerCidrs);
            }
            HttpsProxyConfig::RequiredV2 { trusted_peer_cidrs }
        }
        _ => return Err(ConfigError::InvalidHttpsProxyProtocol),
    };

    if !matches!(config, HttpsProxyConfig::Disabled)
        && matches!(backend, CertificateBackendConfig::Disabled)
    {
        return Err(ConfigError::HttpsProxyWithoutCertificateBackend);
    }
    Ok(config)
}

fn resolve_certificate_backend(
    args: &ServeArgs,
    environment: &impl Environment,
    zone_hostname: Hostname,
) -> Result<CertificateBackendConfig, ConfigError> {
    let enabled = match args.certificate_backend_enabled {
        Some(enabled) => enabled,
        None => environment_bool(environment, CERTIFICATE_BACKEND_ENABLED_ENV)?.unwrap_or(false),
    };
    if !enabled {
        return Ok(CertificateBackendConfig::Disabled);
    }

    let terms_agreed = match args.acme_terms_agreed {
        Some(agreed) => agreed,
        None => environment_bool(environment, ACME_TERMS_AGREED_ENV)?.unwrap_or(false),
    };
    if !terms_agreed {
        return Err(ConfigError::AcmeTermsNotAgreed);
    }

    let directory_url = args
        .acme_directory_url
        .clone()
        .or(environment_string(environment, ACME_DIRECTORY_URL_ENV)?)
        .unwrap_or_else(|| DEFAULT_ACME_DIRECTORY_URL.to_owned());
    let parsed_directory =
        url::Url::parse(&directory_url).map_err(|_| ConfigError::InvalidAcmeDirectoryUrl)?;
    if parsed_directory.scheme() != "https"
        || parsed_directory.host_str().is_none()
        || parsed_directory.cannot_be_a_base()
        || parsed_directory.username() != ""
        || parsed_directory.password().is_some()
    {
        return Err(ConfigError::InvalidAcmeDirectoryUrl);
    }

    let contact = args
        .acme_contact
        .clone()
        .or(environment_string(environment, ACME_CONTACT_ENV)?)
        .ok_or(ConfigError::InvalidAcmeContact)?;
    if !contact.starts_with("mailto:")
        || !contact["mailto:".len()..].contains('@')
        || contact.chars().any(char::is_whitespace)
    {
        return Err(ConfigError::InvalidAcmeContact);
    }

    let zone_id = args
        .cloudflare_zone_id
        .clone()
        .or(environment_string(environment, CLOUDFLARE_ZONE_ID_ENV)?)
        .ok_or(ConfigError::InvalidCloudflareZoneId)?;
    if zone_id.len() != 32 || !zone_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ConfigError::InvalidCloudflareZoneId);
    }

    // The credential is intentionally environment-only: accepting it as a
    // command-line value would expose it through the host process list.
    let api_token = environment
        .value(CLOUDFLARE_API_TOKEN_ENV)
        .map(|value| {
            value
                .into_string()
                .map(CloudflareApiToken::new)
                .map_err(|_| ConfigError::NonUnicodeEnvironment {
                    variable: CLOUDFLARE_API_TOKEN_ENV,
                })
        })
        .transpose()?
        .ok_or(ConfigError::MissingCloudflareApiToken)?;
    if api_token.expose_secret().is_empty() {
        return Err(ConfigError::MissingCloudflareApiToken);
    }

    Ok(CertificateBackendConfig::Enabled(
        EnabledCertificateBackendConfig {
            acme_directory_url: parsed_directory.to_string(),
            acme_contact: contact,
            cloudflare_zone_id: zone_id.to_ascii_lowercase(),
            cloudflare_zone_hostname: zone_hostname,
            cloudflare_api_token: api_token,
        },
    ))
}

fn environment_bool(
    environment: &impl Environment,
    variable: &'static str,
) -> Result<Option<bool>, ConfigError> {
    environment_string(environment, variable)?
        .map(|value| match value.trim().to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" => Ok(true),
            "false" | "0" | "no" => Ok(false),
            _ => Err(ConfigError::InvalidCertificateBackendEnabled),
        })
        .transpose()
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
    Hostname::parse(value.trim())
        .map(|hostname| hostname.to_string())
        .map_err(|_| ConfigError::InvalidPublicBaseDomain)
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

    use clap::{CommandFactory as _, Parser as _, error::ErrorKind};

    use super::*;
    use crate::admin::{Cli, ServerCommand};

    fn environment(values: &[(&str, &str)]) -> impl Environment {
        let values: HashMap<String, OsString> = values
            .iter()
            .map(|(key, value)| ((*key).to_owned(), OsString::from(value)))
            .collect();
        move |name: &str| values.get(name).cloned()
    }

    #[test]
    fn https_proxy_cli_uses_only_the_public_long_option_names() {
        let parsed = Cli::try_parse_from([
            "sink-server",
            "serve",
            "--public-base-domain",
            "example.test",
            "--https-proxy-protocol",
            "required-v2",
            "--https-proxy-trusted-peer-cidrs",
            "192.0.2.99/24,2001:db8:42::1/48",
        ])
        .expect("documented HTTPS PROXY options should parse");
        let ServerCommand::Serve(args) = parsed.command else {
            panic!("expected serve command");
        };
        assert_eq!(args.https_proxy.protocol.as_deref(), Some("required-v2"));
        assert_eq!(
            args.https_proxy.trusted_peer_cidrs.as_deref(),
            Some("192.0.2.99/24,2001:db8:42::1/48")
        );
        let resolved = ServeConfig::resolve_with(
            &args,
            &environment(&[
                (CERTIFICATE_BACKEND_ENABLED_ENV, "true"),
                (HTTPS_LISTEN_ADDRESS_ENV, "127.0.0.1:8443"),
                (ACME_TERMS_AGREED_ENV, "true"),
                (ACME_CONTACT_ENV, "mailto:admin@example.test"),
                (CLOUDFLARE_ZONE_ID_ENV, "0123456789abcdef0123456789abcdef"),
                (CLOUDFLARE_API_TOKEN_ENV, "token"),
                (HTTPS_PROXY_PROTOCOL_ENV, "disabled"),
                (HTTPS_PROXY_TRUSTED_PEER_CIDRS_ENV, "198.51.100.0/24"),
            ]),
        )
        .expect("explicit HTTPS PROXY options should override the environment");
        assert_eq!(resolved.https_proxy.mode_name(), "required-v2");
        assert_eq!(
            resolved
                .https_proxy
                .trusted_peer_cidrs()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            ["192.0.2.0/24", "2001:db8:42::/48"]
        );

        for accidental_name in ["--protocol", "--trusted-peer-cidrs"] {
            let error = Cli::try_parse_from([
                "sink-server",
                "serve",
                "--public-base-domain",
                "example.test",
                accidental_name,
                "value",
            ])
            .expect_err("accidental generic option name must be rejected");
            assert_eq!(
                error.kind(),
                ErrorKind::UnknownArgument,
                "{accidental_name}"
            );
        }
    }

    #[test]
    fn serve_help_exposes_the_https_proxy_contract() {
        let mut command = Cli::command();
        let serve = command
            .find_subcommand_mut("serve")
            .expect("serve subcommand");
        let help = serve.render_long_help().to_string();

        assert!(help.contains("--https-proxy-protocol <MODE>"));
        assert!(help.contains("SINK_SERVER_HTTPS_PROXY_PROTOCOL"));
        assert!(help.contains("--https-proxy-trusted-peer-cidrs <CIDR,...>"));
        assert!(help.contains("SINK_SERVER_HTTPS_PROXY_TRUSTED_PEER_CIDRS"));
        assert!(!help.lines().any(|line| {
            let option = line.trim_start();
            option.starts_with("--protocol ") || option.starts_with("--trusted-peer-cidrs ")
        }));
    }

    #[test]
    fn explicit_serve_arguments_override_environment() {
        let args = ServeArgs {
            listen_address: Some("127.0.0.1:9010".parse().expect("test address")),
            http_listen_address: None,
            https_listen_address: None,
            https_proxy: Box::default(),
            public_base_domain: Some("CLI.Example.".to_owned()),
            max_namespace_depth: Some(3),
            certificate_provider: Some("cloudflare".to_owned()),
            certificate_backend_enabled: Some(false),
            acme_directory_url: None,
            acme_contact: None,
            acme_terms_agreed: None,
            cloudflare_zone_id: None,
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
            resolved.http_listen_address,
            "127.0.0.1:9010".parse().expect("test address")
        );
        assert_eq!(resolved.public_base_domain, "cli.example");
        assert_eq!(resolved.domains.as_slice()[0].max_namespace_depth, 3);
        assert_eq!(
            resolved.domains.as_slice()[0].certificate_provider,
            CertificateProviderKind::Cloudflare
        );
        assert_eq!(resolved.sqlite_path, PathBuf::from("cli.sqlite3"));
        assert_eq!(resolved.log_level, "debug");
        assert_eq!(
            resolved.certificate_backend,
            CertificateBackendConfig::Disabled
        );
        assert_eq!(resolved.https_proxy, HttpsProxyConfig::Disabled);
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
            resolved.http_listen_address,
            "0.0.0.0:8088".parse().expect("test address")
        );
        assert_eq!(resolved.public_base_domain, "tunnels.example");
        assert_eq!(
            resolved.domains.as_slice()[0].max_namespace_depth,
            DEFAULT_MAX_NAMESPACE_DEPTH
        );
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

    #[test]
    fn domain_policy_can_be_supplied_from_the_environment() {
        let resolved = ServeConfig::resolve_with(
            &ServeArgs::default(),
            &environment(&[
                (PUBLIC_BASE_DOMAIN_ENV, "tunnels.example"),
                (MAX_NAMESPACE_DEPTH_ENV, "4"),
                (CERTIFICATE_PROVIDER_ENV, "CLOUDFLARE"),
            ]),
        )
        .expect("valid domain policy");

        let domain = &resolved.domains.as_slice()[0];
        assert_eq!(domain.hostname.as_str(), "tunnels.example");
        assert_eq!(domain.max_namespace_depth, 4);
        assert_eq!(
            domain.certificate_provider,
            CertificateProviderKind::Cloudflare
        );
    }

    #[test]
    fn invalid_domain_policy_is_rejected_clearly() {
        assert!(matches!(
            ServeConfig::resolve_with(
                &ServeArgs::default(),
                &environment(&[
                    (PUBLIC_BASE_DOMAIN_ENV, "example.test"),
                    (MAX_NAMESPACE_DEPTH_ENV, "0"),
                ]),
            ),
            Err(ConfigError::InvalidMaxNamespaceDepth)
        ));
        assert!(matches!(
            ServeConfig::resolve_with(
                &ServeArgs::default(),
                &environment(&[
                    (PUBLIC_BASE_DOMAIN_ENV, "example.test"),
                    (CERTIFICATE_PROVIDER_ENV, "unknown"),
                ]),
            ),
            Err(ConfigError::UnsupportedCertificateProvider(_))
        ));
        assert!(matches!(
            ServeConfig::resolve_with(
                &ServeArgs::default(),
                &environment(&[(PUBLIC_BASE_DOMAIN_ENV, "https://example.test")]),
            ),
            Err(ConfigError::InvalidPublicBaseDomain)
        ));
    }

    #[test]
    fn configured_domains_choose_the_most_specific_suffix() {
        let domains = ConfiguredDomains::new(vec![
            ConfiguredDomain::new(
                Hostname::parse("example.test").expect("valid hostname"),
                2,
                CertificateProviderKind::Cloudflare,
            )
            .expect("valid domain"),
            ConfiguredDomain::new(
                Hostname::parse("internal.example.test").expect("valid hostname"),
                1,
                CertificateProviderKind::Cloudflare,
            )
            .expect("valid domain"),
        ])
        .expect("valid domains");

        let selected = domains
            .most_specific_match(
                &Hostname::parse("api.internal.example.test").expect("valid hostname"),
            )
            .expect("configured suffix");
        assert_eq!(selected.hostname.as_str(), "internal.example.test");
    }

    #[test]
    fn disabled_backend_does_not_require_or_validate_live_credentials() {
        let resolved = ServeConfig::resolve_with(
            &ServeArgs::default(),
            &environment(&[
                (PUBLIC_BASE_DOMAIN_ENV, "example.test"),
                (CLOUDFLARE_ZONE_ID_ENV, "not-a-zone-id"),
                (CLOUDFLARE_API_TOKEN_ENV, ""),
                (ACME_DIRECTORY_URL_ENV, "http://unsafe.invalid"),
            ]),
        )
        .expect("disabled backend ignores inactive settings");

        assert_eq!(
            resolved.certificate_backend,
            CertificateBackendConfig::Disabled
        );
    }

    #[test]
    fn enabled_backend_uses_staging_default_and_redacts_token() {
        let resolved = ServeConfig::resolve_with(
            &ServeArgs::default(),
            &environment(&[
                (PUBLIC_BASE_DOMAIN_ENV, "example.test"),
                (CERTIFICATE_BACKEND_ENABLED_ENV, "true"),
                (HTTPS_LISTEN_ADDRESS_ENV, "127.0.0.1:8443"),
                (ACME_TERMS_AGREED_ENV, "true"),
                (ACME_CONTACT_ENV, "mailto:admin@example.test"),
                (CLOUDFLARE_ZONE_ID_ENV, "0123456789abcdef0123456789abcdef"),
                (CLOUDFLARE_API_TOKEN_ENV, "cloudflare-token-never-print"),
            ]),
        )
        .expect("valid enabled backend");

        let CertificateBackendConfig::Enabled(backend) = &resolved.certificate_backend else {
            panic!("backend should be enabled");
        };
        assert_eq!(backend.acme_directory_url, DEFAULT_ACME_DIRECTORY_URL);
        assert_eq!(backend.cloudflare_zone_hostname.as_str(), "example.test");
        let rendered = format!("{resolved:?}");
        assert!(!rendered.contains("cloudflare-token-never-print"));
        assert!(rendered.contains("[REDACTED]"));
    }

    #[test]
    fn enabled_backend_requires_terms_contact_zone_and_token() {
        let base = [
            (PUBLIC_BASE_DOMAIN_ENV, "example.test"),
            (CERTIFICATE_BACKEND_ENABLED_ENV, "true"),
        ];
        assert!(matches!(
            ServeConfig::resolve_with(&ServeArgs::default(), &environment(&base)),
            Err(ConfigError::AcmeTermsNotAgreed)
        ));

        let unsafe_directory = environment(&[
            (PUBLIC_BASE_DOMAIN_ENV, "example.test"),
            (CERTIFICATE_BACKEND_ENABLED_ENV, "true"),
            (ACME_TERMS_AGREED_ENV, "true"),
            (ACME_CONTACT_ENV, "mailto:admin@example.test"),
            (CLOUDFLARE_ZONE_ID_ENV, "0123456789abcdef0123456789abcdef"),
            (CLOUDFLARE_API_TOKEN_ENV, "token"),
            (ACME_DIRECTORY_URL_ENV, "http://acme.invalid/directory"),
        ]);
        assert!(matches!(
            ServeConfig::resolve_with(&ServeArgs::default(), &unsafe_directory),
            Err(ConfigError::InvalidAcmeDirectoryUrl)
        ));
    }

    #[test]
    fn listener_contract_is_explicit_and_fails_closed() {
        let disabled_with_https = environment(&[
            (PUBLIC_BASE_DOMAIN_ENV, "example.test"),
            (HTTPS_LISTEN_ADDRESS_ENV, "127.0.0.1:8443"),
        ]);
        assert!(matches!(
            ServeConfig::resolve_with(&ServeArgs::default(), &disabled_with_https),
            Err(ConfigError::HttpsListenAddressWithoutCertificateBackend)
        ));

        let enabled_without_https = environment(&[
            (PUBLIC_BASE_DOMAIN_ENV, "example.test"),
            (CERTIFICATE_BACKEND_ENABLED_ENV, "true"),
            (ACME_TERMS_AGREED_ENV, "true"),
            (ACME_CONTACT_ENV, "mailto:admin@example.test"),
            (CLOUDFLARE_ZONE_ID_ENV, "0123456789abcdef0123456789abcdef"),
            (CLOUDFLARE_API_TOKEN_ENV, "token"),
        ]);
        assert!(matches!(
            ServeConfig::resolve_with(&ServeArgs::default(), &enabled_without_https),
            Err(ConfigError::MissingHttpsListenAddress)
        ));

        let duplicate = environment(&[
            (PUBLIC_BASE_DOMAIN_ENV, "example.test"),
            (HTTP_LISTEN_ADDRESS_ENV, "127.0.0.1:8443"),
            (HTTPS_LISTEN_ADDRESS_ENV, "127.0.0.1:8443"),
            (CERTIFICATE_BACKEND_ENABLED_ENV, "true"),
            (ACME_TERMS_AGREED_ENV, "true"),
            (ACME_CONTACT_ENV, "mailto:admin@example.test"),
            (CLOUDFLARE_ZONE_ID_ENV, "0123456789abcdef0123456789abcdef"),
            (CLOUDFLARE_API_TOKEN_ENV, "token"),
        ]);
        assert!(matches!(
            ServeConfig::resolve_with(&ServeArgs::default(), &duplicate),
            Err(ConfigError::DuplicateListenAddresses)
        ));
    }

    #[test]
    fn trusted_peer_cidrs_are_canonical_and_cover_v4_and_v6() {
        let ipv4 = "192.0.2.99/24"
            .parse::<TrustedPeerCidr>()
            .expect("valid IPv4 CIDR");
        assert_eq!(ipv4.to_string(), "192.0.2.0/24");
        assert!(ipv4.contains("192.0.2.1".parse().expect("IPv4")));
        assert!(!ipv4.contains("192.0.3.1".parse().expect("IPv4")));

        let ipv6 = "2001:db8:42::99/48"
            .parse::<TrustedPeerCidr>()
            .expect("valid IPv6 CIDR");
        assert_eq!(ipv6.to_string(), "2001:db8:42::/48");
        assert!(ipv6.contains("2001:db8:42::1".parse().expect("IPv6")));
        assert!(!ipv6.contains("2001:db8:43::1".parse().expect("IPv6")));

        for invalid in ["192.0.2.1", "192.0.2.1/33", "2001:db8::1/129", "/24"] {
            assert!(invalid.parse::<TrustedPeerCidr>().is_err(), "{invalid}");
        }
    }

    #[test]
    fn required_proxy_v2_is_explicit_and_validation_safe() {
        let backend = [
            (PUBLIC_BASE_DOMAIN_ENV, "example.test"),
            (CERTIFICATE_BACKEND_ENABLED_ENV, "true"),
            (HTTPS_LISTEN_ADDRESS_ENV, "127.0.0.1:8443"),
            (ACME_TERMS_AGREED_ENV, "true"),
            (ACME_CONTACT_ENV, "mailto:admin@example.test"),
            (CLOUDFLARE_ZONE_ID_ENV, "0123456789abcdef0123456789abcdef"),
            (CLOUDFLARE_API_TOKEN_ENV, "token"),
        ];
        let mut required = backend.to_vec();
        required.extend([
            (HTTPS_PROXY_PROTOCOL_ENV, "required-v2"),
            (
                HTTPS_PROXY_TRUSTED_PEER_CIDRS_ENV,
                "192.0.2.99/24, 2001:db8:42::1/48",
            ),
        ]);
        let resolved = ServeConfig::resolve_with(&ServeArgs::default(), &environment(&required))
            .expect("valid required PROXY v2 config");
        assert_eq!(resolved.https_proxy.mode_name(), "required-v2");
        assert_eq!(
            resolved
                .https_proxy
                .trusted_peer_cidrs()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            ["192.0.2.0/24", "2001:db8:42::/48"]
        );

        let mut missing = backend.to_vec();
        missing.push((HTTPS_PROXY_PROTOCOL_ENV, "required-v2"));
        assert!(matches!(
            ServeConfig::resolve_with(&ServeArgs::default(), &environment(&missing)),
            Err(ConfigError::MissingHttpsProxyTrustedPeerCidrs)
        ));

        assert!(matches!(
            ServeConfig::resolve_with(
                &ServeArgs::default(),
                &environment(&[
                    (PUBLIC_BASE_DOMAIN_ENV, "example.test"),
                    (HTTPS_PROXY_TRUSTED_PEER_CIDRS_ENV, "127.0.0.1/32"),
                ]),
            ),
            Err(ConfigError::HttpsProxyTrustedPeerCidrsWithoutRequiredV2)
        ));

        assert!(matches!(
            ServeConfig::resolve_with(
                &ServeArgs::default(),
                &environment(&[
                    (PUBLIC_BASE_DOMAIN_ENV, "example.test"),
                    (HTTPS_PROXY_PROTOCOL_ENV, "required-v2"),
                    (HTTPS_PROXY_TRUSTED_PEER_CIDRS_ENV, "127.0.0.1/32"),
                ]),
            ),
            Err(ConfigError::HttpsProxyWithoutCertificateBackend)
        ));
    }
}
