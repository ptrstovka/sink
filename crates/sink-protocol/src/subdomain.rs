use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::RESERVED_CONNECT_SUBDOMAIN;

/// A normalized, claimable single DNS label.
#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Subdomain(String);

impl Subdomain {
    pub fn parse(value: &str) -> Result<Self, SubdomainError> {
        if value.is_empty() {
            return Err(SubdomainError::Empty);
        }
        if value.len() > 63 {
            return Err(SubdomainError::TooLong);
        }
        if value.starts_with('-') || value.ends_with('-') {
            return Err(SubdomainError::EdgeHyphen);
        }
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(SubdomainError::InvalidCharacter);
        }

        let normalized = value.to_ascii_lowercase();
        if normalized == RESERVED_CONNECT_SUBDOMAIN {
            return Err(SubdomainError::Reserved);
        }
        Ok(Self(normalized))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Subdomain {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for Subdomain {
    type Err = SubdomainError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl TryFrom<String> for Subdomain {
    type Error = SubdomainError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<Subdomain> for String {
    fn from(value: Subdomain) -> Self {
        value.0
    }
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum SubdomainError {
    #[error("subdomain cannot be empty")]
    Empty,
    #[error("subdomain must be at most 63 characters")]
    TooLong,
    #[error("subdomain may contain only ASCII letters, digits, and hyphens")]
    InvalidCharacter,
    #[error("subdomain cannot begin or end with a hyphen")]
    EdgeHyphen,
    #[error("the connect subdomain is reserved for Sink control traffic")]
    Reserved,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_and_normalizes_dns_labels() -> Result<(), SubdomainError> {
        assert_eq!(Subdomain::parse("Demo-42")?.as_str(), "demo-42");
        Ok(())
    }

    #[test]
    fn rejects_reserved_and_multi_label_names() {
        assert_eq!(Subdomain::parse("connect"), Err(SubdomainError::Reserved));
        assert_eq!(
            Subdomain::parse("demo.example.com"),
            Err(SubdomainError::InvalidCharacter)
        );
    }

    #[test]
    fn serde_cannot_bypass_validation() {
        let result = serde_json::from_str::<Subdomain>("\"-bad\"");
        assert!(result.is_err());
    }
}
