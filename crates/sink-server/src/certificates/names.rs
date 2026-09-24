use std::{fmt, str::FromStr};

use thiserror::Error;

/// A normalized ASCII DNS hostname.
///
/// Hostnames are stored without a trailing root dot and in lowercase. The
/// parser intentionally does not perform IDNA conversion; callers must supply
/// an ASCII A-label so configuration, SNI, and persisted identifiers all use
/// one canonical representation.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Hostname(String);

impl Hostname {
    pub fn parse(value: &str) -> Result<Self, HostnameError> {
        if value.trim() != value {
            return Err(HostnameError);
        }

        let without_root_dot = value.strip_suffix('.').unwrap_or(value);
        if without_root_dot.ends_with('.') {
            return Err(HostnameError);
        }
        let normalized = without_root_dot.to_ascii_lowercase();
        let valid = !normalized.is_empty()
            && normalized.len() <= 253
            && normalized.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            });

        if valid {
            Ok(Self(normalized))
        } else {
            Err(HostnameError)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn label_count(&self) -> usize {
        self.0.split('.').count()
    }

    /// Returns the number of labels between this hostname and `suffix`.
    pub fn depth_below(&self, suffix: &Self) -> Option<usize> {
        if self == suffix {
            return Some(0);
        }

        let prefix = self.0.strip_suffix(suffix.as_str())?;
        let prefix = prefix.strip_suffix('.')?;
        Some(prefix.split('.').count())
    }

    pub fn is_same_or_below(&self, suffix: &Self) -> bool {
        self.depth_below(suffix).is_some()
    }
}

impl fmt::Debug for Hostname {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Hostname").field(&self.0).finish()
    }
}

impl fmt::Display for Hostname {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for Hostname {
    type Err = HostnameError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[error("hostname must be a valid ASCII DNS name without a scheme, port, or wildcard")]
pub struct HostnameError;

/// The persistent object for which Sink manages one apex-plus-wildcard
/// certificate.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CertificateTarget {
    BaseDomain(Hostname),
    Namespace(Hostname),
}

impl CertificateTarget {
    pub fn base_domain(hostname: Hostname) -> Self {
        Self::BaseDomain(hostname)
    }

    pub fn namespace(hostname: Hostname) -> Self {
        Self::Namespace(hostname)
    }

    pub fn apex(&self) -> &Hostname {
        match self {
            Self::BaseDomain(hostname) | Self::Namespace(hostname) => hostname,
        }
    }

    pub fn is_namespace(&self) -> bool {
        matches!(self, Self::Namespace(_))
    }

    pub fn identifiers(&self) -> CertificateIdentifiers {
        CertificateIdentifiers::new(self.apex().clone())
    }
}

/// The exact pair of DNS identifiers requested for every managed
/// certificate: the target apex and one wildcard immediately below it.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct CertificateIdentifiers {
    apex: Hostname,
    wildcard: String,
}

impl CertificateIdentifiers {
    fn new(apex: Hostname) -> Self {
        let wildcard = format!("*.{apex}");
        Self { apex, wildcard }
    }

    pub fn apex(&self) -> &Hostname {
        &self.apex
    }

    pub fn wildcard(&self) -> &str {
        &self.wildcard
    }

    /// Certificate wildcards cover exactly one label, never arbitrary depth.
    pub fn covers(&self, hostname: &Hostname) -> bool {
        matches!(hostname.depth_below(&self.apex), Some(0 | 1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostname_normalizes_case_and_a_root_dot() {
        let hostname = Hostname::parse("API.Example.COM.").expect("valid hostname");

        assert_eq!(hostname.as_str(), "api.example.com");
        assert_eq!(hostname.label_count(), 3);
    }

    #[test]
    fn hostname_rejects_ambiguous_or_non_dns_input() {
        for invalid in [
            " example.com",
            "example.com ",
            "*.example.com",
            "https://example.com",
            "-bad.example",
            "bad-.example",
            "example..com",
            "example.com..",
            "münchen.example",
        ] {
            assert!(Hostname::parse(invalid).is_err(), "accepted {invalid}");
        }
    }

    #[test]
    fn identifiers_cover_only_the_apex_and_one_child_label() {
        let target = CertificateTarget::namespace(
            Hostname::parse("cloud.example.com").expect("valid hostname"),
        );
        let identifiers = target.identifiers();

        assert_eq!(identifiers.apex().as_str(), "cloud.example.com");
        assert_eq!(identifiers.wildcard(), "*.cloud.example.com");
        assert!(identifiers.covers(&Hostname::parse("cloud.example.com").expect("valid hostname")));
        assert!(
            identifiers.covers(&Hostname::parse("api.cloud.example.com").expect("valid hostname"))
        );
        assert!(
            !identifiers
                .covers(&Hostname::parse("deep.api.cloud.example.com").expect("valid hostname"))
        );
        assert!(
            !identifiers.covers(&Hostname::parse("notcloud.example.com").expect("valid hostname"))
        );

        let base =
            CertificateTarget::base_domain(Hostname::parse("example.com").expect("valid hostname"));
        assert_eq!(base.identifiers().apex().as_str(), "example.com");
        assert_eq!(base.identifiers().wildcard(), "*.example.com");
    }
}
