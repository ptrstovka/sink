use std::{fmt, str::FromStr};

use http::Uri;
use sink_protocol::{Subdomain, SubdomainError};
use thiserror::Error;
use url::{Host, Url};

/// The application protocol used between the client and its local target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalScheme {
    Http,
    Https,
}

/// A validated local HTTP(S) target.
///
/// `base_uri` preserves an explicit path, while `origin` contains only the
/// scheme and authority. Runtimes can therefore choose whether to resolve
/// incoming request paths below a configured base path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalTarget {
    base_url: Url,
    base_uri: Uri,
    origin: Uri,
    scheme: LocalScheme,
}

impl LocalTarget {
    #[must_use]
    pub fn base_url(&self) -> &Url {
        &self.base_url
    }

    #[must_use]
    pub fn base_uri(&self) -> &Uri {
        &self.base_uri
    }

    #[must_use]
    pub fn origin(&self) -> &Uri {
        &self.origin
    }

    #[must_use]
    pub fn scheme(&self) -> LocalScheme {
        self.scheme
    }

    #[must_use]
    pub fn uses_tls(&self) -> bool {
        self.scheme == LocalScheme::Https
    }
}

impl fmt::Display for LocalTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.base_url.as_str())
    }
}

impl FromStr for LocalTarget {
    type Err = LocalTargetError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        if input.is_empty() {
            return Err(LocalTargetError::Empty);
        }
        if input.trim() != input || input.chars().any(char::is_whitespace) {
            return Err(LocalTargetError::Whitespace);
        }

        let explicit_scheme = input.contains("://");
        let candidate = if input.bytes().all(|byte| byte.is_ascii_digit()) {
            let port = input
                .parse::<u16>()
                .map_err(|_| LocalTargetError::InvalidPort)?;
            if port == 0 {
                return Err(LocalTargetError::ZeroPort);
            }
            format!("http://localhost:{port}/")
        } else if explicit_scheme {
            input.to_owned()
        } else {
            if !has_explicit_port(input) {
                return Err(LocalTargetError::MissingPort);
            }
            format!("http://{input}")
        };

        let parsed = Url::parse(&candidate).map_err(|_| LocalTargetError::InvalidUrl)?;
        let scheme = match parsed.scheme() {
            "http" => LocalScheme::Http,
            "https" => LocalScheme::Https,
            scheme => return Err(LocalTargetError::UnsupportedScheme(scheme.to_owned())),
        };
        if parsed.host().is_none() {
            return Err(LocalTargetError::MissingHost);
        }
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(LocalTargetError::UserInfo);
        }
        if parsed.port() == Some(0) {
            return Err(LocalTargetError::ZeroPort);
        }
        if parsed.query().is_some() {
            return Err(LocalTargetError::Query);
        }
        if parsed.fragment().is_some() {
            return Err(LocalTargetError::Fragment);
        }

        let base_uri = parsed
            .as_str()
            .parse::<Uri>()
            .map_err(|_| LocalTargetError::InvalidUrl)?;
        let origin = parsed
            .origin()
            .ascii_serialization()
            .parse::<Uri>()
            .map_err(|_| LocalTargetError::InvalidUrl)?;

        Ok(Self {
            base_url: parsed,
            base_uri,
            origin,
            scheme,
        })
    }
}

fn has_explicit_port(input: &str) -> bool {
    let authority = input.split('/').next().unwrap_or_default();
    if let Some(bracketed) = authority.strip_prefix('[') {
        return bracketed
            .split_once("]:")
            .is_some_and(|(_, port)| !port.is_empty());
    }
    authority
        .rsplit_once(':')
        .is_some_and(|(host, port)| !host.is_empty() && !port.is_empty())
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum LocalTargetError {
    #[error("local target cannot be empty")]
    Empty,
    #[error("local target cannot contain whitespace")]
    Whitespace,
    #[error("local target must be a port, host:port, or an http:// or https:// URL")]
    InvalidUrl,
    #[error("local target port must be between 1 and 65535")]
    InvalidPort,
    #[error("local target port must be greater than zero")]
    ZeroPort,
    #[error("a scheme-less local target must include a port (for example localhost:3000)")]
    MissingPort,
    #[error("local target URL must include a host")]
    MissingHost,
    #[error("unsupported local target scheme {0}; use http or https")]
    UnsupportedScheme(String),
    #[error("local target URL cannot contain a username or password")]
    UserInfo,
    #[error("local target URL cannot contain a query string")]
    Query,
    #[error("local target URL cannot contain a fragment")]
    Fragment,
}

/// A requested public HTTPS hostname and its validated claim label.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicUrl {
    url: Url,
    requested_hostname: String,
    subdomain: Subdomain,
}

impl PublicUrl {
    #[must_use]
    pub fn as_url(&self) -> &Url {
        &self.url
    }

    /// The complete normalized hostname to send in `ClientHello`.
    ///
    /// This deliberately preserves the configured base-domain suffix instead
    /// of sending only the first claim label.
    #[must_use]
    pub fn requested_hostname(&self) -> &str {
        &self.requested_hostname
    }

    #[must_use]
    pub fn subdomain(&self) -> &Subdomain {
        &self.subdomain
    }
}

impl fmt::Display for PublicUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.url.as_str())
    }
}

impl FromStr for PublicUrl {
    type Err = PublicUrlError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        if input.is_empty() {
            return Err(PublicUrlError::Empty);
        }
        if input.trim() != input || input.chars().any(char::is_whitespace) {
            return Err(PublicUrlError::Whitespace);
        }

        let parsed = Url::parse(input).map_err(|_| PublicUrlError::InvalidUrl)?;
        if parsed.scheme() != "https" {
            return Err(PublicUrlError::HttpsRequired);
        }
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(PublicUrlError::UserInfo);
        }
        if authority_has_port(input) || parsed.port().is_some() {
            return Err(PublicUrlError::Port);
        }
        if parsed.path() != "/" {
            return Err(PublicUrlError::Path);
        }
        if parsed.query().is_some() {
            return Err(PublicUrlError::Query);
        }
        if parsed.fragment().is_some() {
            return Err(PublicUrlError::Fragment);
        }

        let hostname = match parsed.host() {
            Some(Host::Domain(hostname)) => hostname.to_owned(),
            Some(Host::Ipv4(_) | Host::Ipv6(_)) => return Err(PublicUrlError::IpAddress),
            None => return Err(PublicUrlError::MissingHost),
        };
        if hostname.len() > 253 {
            return Err(PublicUrlError::HostnameTooLong);
        }
        let (claim, base_domain) = hostname
            .split_once('.')
            .ok_or(PublicUrlError::MissingBaseDomain)?;
        if !valid_domain_suffix(base_domain) {
            return Err(PublicUrlError::InvalidBaseDomain);
        }

        let subdomain = Subdomain::parse(claim).map_err(PublicUrlError::InvalidSubdomain)?;
        Ok(Self {
            url: parsed,
            requested_hostname: hostname,
            subdomain,
        })
    }
}

fn authority_has_port(input: &str) -> bool {
    let Some((_, remainder)) = input.split_once("://") else {
        return false;
    };
    let authority = remainder.split(['/', '?', '#']).next().unwrap_or_default();
    let host_and_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_, value)| value);
    host_and_port.contains(':')
}

fn valid_domain_suffix(value: &str) -> bool {
    !value.is_empty()
        && !value.ends_with('.')
        && value.len() <= 253
        && value.split('.').all(valid_dns_label)
}

fn valid_dns_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum PublicUrlError {
    #[error("public URL cannot be empty")]
    Empty,
    #[error("public URL cannot contain whitespace")]
    Whitespace,
    #[error("public URL must be a valid HTTPS URL")]
    InvalidUrl,
    #[error("public URL must use https://")]
    HttpsRequired,
    #[error("public URL must include a DNS hostname")]
    MissingHost,
    #[error("public URL must use a DNS hostname, not an IP address")]
    IpAddress,
    #[error("public hostname must be at most 253 characters")]
    HostnameTooLong,
    #[error("public URL cannot contain a username or password")]
    UserInfo,
    #[error("public URL cannot include a port")]
    Port,
    #[error("public URL must contain only a hostname, without a path")]
    Path,
    #[error("public URL cannot contain a query string")]
    Query,
    #[error("public URL cannot contain a fragment")]
    Fragment,
    #[error("public hostname must contain a claim label and a base domain")]
    MissingBaseDomain,
    #[error("public hostname has an invalid base domain")]
    InvalidBaseDomain,
    #[error("invalid public subdomain: {0}")]
    InvalidSubdomain(#[source] SubdomainError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_port_targets_localhost_http() -> Result<(), LocalTargetError> {
        let target = LocalTarget::from_str("3000")?;
        assert_eq!(
            target.base_uri(),
            &Uri::from_static("http://localhost:3000/")
        );
        assert_eq!(target.origin(), &Uri::from_static("http://localhost:3000"));
        assert_eq!(target.scheme(), LocalScheme::Http);
        Ok(())
    }

    #[test]
    fn scheme_less_host_and_path_default_to_http() -> Result<(), LocalTargetError> {
        let target = LocalTarget::from_str("host.local:3000/api/")?;
        assert_eq!(target.base_url().as_str(), "http://host.local:3000/api/");
        assert_eq!(target.origin().to_string(), "http://host.local:3000/");
        Ok(())
    }

    #[test]
    fn explicit_https_preserves_base_uri() -> Result<(), LocalTargetError> {
        let target = LocalTarget::from_str("https://localhost:8443/base")?;
        assert!(target.uses_tls());
        assert_eq!(target.base_uri().to_string(), "https://localhost:8443/base");
        assert_eq!(target.origin().to_string(), "https://localhost:8443/");
        Ok(())
    }

    #[test]
    fn local_target_rejects_bad_ports_and_schemes() {
        assert_eq!(LocalTarget::from_str("0"), Err(LocalTargetError::ZeroPort));
        assert_eq!(
            LocalTarget::from_str("70000"),
            Err(LocalTargetError::InvalidPort)
        );
        assert_eq!(
            LocalTarget::from_str("localhost"),
            Err(LocalTargetError::MissingPort)
        );
        assert_eq!(
            LocalTarget::from_str("ftp://localhost:21"),
            Err(LocalTargetError::UnsupportedScheme("ftp".to_owned()))
        );
    }

    #[test]
    fn public_url_keeps_full_hostname_and_validates_claim() -> Result<(), PublicUrlError> {
        let public = PublicUrl::from_str("https://Demo-42.serus.eu")?;
        assert_eq!(public.requested_hostname(), "demo-42.serus.eu");
        assert_eq!(public.subdomain().as_str(), "demo-42");
        assert_eq!(public.as_url().as_str(), "https://demo-42.serus.eu/");
        Ok(())
    }

    #[test]
    fn public_url_leaves_base_domain_authority_to_server() -> Result<(), PublicUrlError> {
        let public = PublicUrl::from_str("https://demo.tunnels.example")?;
        assert_eq!(public.requested_hostname(), "demo.tunnels.example");
        assert_eq!(public.subdomain().as_str(), "demo");
        Ok(())
    }

    #[test]
    fn public_url_requires_bare_https_dns_hostname() {
        assert_eq!(
            PublicUrl::from_str("http://demo.serus.eu"),
            Err(PublicUrlError::HttpsRequired)
        );
        assert_eq!(
            PublicUrl::from_str("https://127.0.0.1"),
            Err(PublicUrlError::IpAddress)
        );
        assert_eq!(
            PublicUrl::from_str("https://demo.serus.eu/path"),
            Err(PublicUrlError::Path)
        );
        assert_eq!(
            PublicUrl::from_str("https://demo.serus.eu:443"),
            Err(PublicUrlError::Port)
        );
    }

    #[test]
    fn public_url_rejects_reserved_connect_claim() {
        assert!(matches!(
            PublicUrl::from_str("https://connect.serus.eu"),
            Err(PublicUrlError::InvalidSubdomain(SubdomainError::Reserved))
        ));
    }
}
