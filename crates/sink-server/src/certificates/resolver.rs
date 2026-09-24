use std::collections::HashSet;

use thiserror::Error;

use super::{
    CertificateMaterial, CertificateRecord, CertificateState, CertificateTarget, Hostname,
    Timestamp,
};

/// Authorization is deliberately separate from certificate coverage. The TLS
/// integration must consult current route/claim state and cannot turn a valid
/// wildcard into authorization for an otherwise unknown hostname.
pub trait SniAuthorization {
    fn is_authorized(&self, hostname: &Hostname) -> bool;
}

impl<F> SniAuthorization for F
where
    F: Fn(&Hostname) -> bool,
{
    fn is_authorized(&self, hostname: &Hostname) -> bool {
        self(hostname)
    }
}

#[derive(Clone, Debug, Default)]
pub struct AuthorizedHostnames {
    hostnames: HashSet<Hostname>,
}

impl AuthorizedHostnames {
    pub fn new(hostnames: impl IntoIterator<Item = Hostname>) -> Self {
        Self {
            hostnames: hostnames.into_iter().collect(),
        }
    }
}

impl SniAuthorization for AuthorizedHostnames {
    fn is_authorized(&self, hostname: &Hostname) -> bool {
        self.hostnames.contains(hostname)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResolvedCertificate<'a> {
    pub target: &'a CertificateTarget,
    pub material: &'a CertificateMaterial,
}

/// Immutable snapshot used by a future rustls resolver. Replacing the whole
/// index after an atomic storage update keeps handshakes free of partially
/// updated certificate/key pairs.
#[derive(Clone, Debug, Default)]
pub struct SniCertificateIndex {
    records: Vec<CertificateRecord>,
}

impl SniCertificateIndex {
    pub fn new(records: impl IntoIterator<Item = CertificateRecord>) -> Result<Self, IndexError> {
        let records: Vec<_> = records.into_iter().collect();
        let mut apexes = HashSet::new();
        for record in &records {
            if !apexes.insert(record.target.apex().clone()) {
                return Err(IndexError::DuplicateTarget(
                    record.target.apex().to_string(),
                ));
            }
        }
        Ok(Self { records })
    }

    pub fn resolve(
        &self,
        server_name: &str,
        now: Timestamp,
        authorization: &impl SniAuthorization,
    ) -> Result<ResolvedCertificate<'_>, ResolveError> {
        let hostname = Hostname::parse(server_name).map_err(|_| ResolveError::InvalidServerName)?;
        if !authorization.is_authorized(&hostname) {
            return Err(ResolveError::Unauthorized);
        }

        // Select by specificity before checking readiness. A pending child
        // namespace therefore cannot silently fall back to its parent's
        // wildcard certificate.
        let record = self
            .records
            .iter()
            .filter(|record| !matches!(record.state, CertificateState::Retained(_)))
            .filter(|record| record.target.identifiers().covers(&hostname))
            .max_by_key(|record| record.target.apex().label_count())
            .ok_or(ResolveError::Uncovered)?;

        let material = record.active_material(now).ok_or(ResolveError::NotReady)?;
        Ok(ResolvedCertificate {
            target: &record.target,
            material,
        })
    }

    pub fn records(&self) -> &[CertificateRecord] {
        &self.records
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum IndexError {
    #[error("multiple certificate records exist for `{0}`")]
    DuplicateTarget(String),
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ResolveError {
    #[error("SNI server name is not a valid normalized DNS hostname")]
    InvalidServerName,
    #[error("SNI server name is not currently authorized")]
    Unauthorized,
    #[error("no managed certificate covers the SNI server name")]
    Uncovered,
    #[error("the most-specific managed certificate is not ready or is expired")]
    NotReady,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certificates::{CertificateProviderKind, SecretBytes};

    fn hostname(value: &str) -> Hostname {
        Hostname::parse(value).expect("valid hostname")
    }

    fn material(not_after: u64) -> CertificateMaterial {
        CertificateMaterial {
            certificate_chain_pem: b"certificate".to_vec(),
            private_key_pem: SecretBytes::new(b"private key".to_vec()),
            not_before: Timestamp::from_unix_seconds(100),
            not_after: Timestamp::from_unix_seconds(not_after),
        }
    }

    fn ready(target: CertificateTarget) -> CertificateRecord {
        CertificateRecord::ready(
            target,
            CertificateProviderKind::Cloudflare,
            material(10_000),
            Timestamp::from_unix_seconds(100),
        )
    }

    #[test]
    fn resolves_the_most_specific_active_apex_or_wildcard() {
        let base = CertificateTarget::base_domain(hostname("example.test"));
        let cloud = CertificateTarget::namespace(hostname("cloud.example.test"));
        let edge = CertificateTarget::namespace(hostname("edge.cloud.example.test"));
        let index = SniCertificateIndex::new([
            ready(base.clone()),
            ready(cloud.clone()),
            ready(edge.clone()),
        ])
        .expect("valid index");
        let allowed = AuthorizedHostnames::new([
            hostname("api.example.test"),
            hostname("cloud.example.test"),
            hostname("api.cloud.example.test"),
            hostname("edge.cloud.example.test"),
            hostname("foo.edge.cloud.example.test"),
        ]);
        let now = Timestamp::from_unix_seconds(1_000);

        assert_eq!(
            index
                .resolve("API.EXAMPLE.TEST.", now, &allowed)
                .expect("base certificate")
                .target,
            &base
        );
        assert_eq!(
            index
                .resolve("cloud.example.test", now, &allowed)
                .expect("namespace apex")
                .target,
            &cloud
        );
        assert_eq!(
            index
                .resolve("api.cloud.example.test", now, &allowed)
                .expect("namespace wildcard")
                .target,
            &cloud
        );
        assert_eq!(
            index
                .resolve("edge.cloud.example.test", now, &allowed)
                .expect("nested namespace apex")
                .target,
            &edge
        );
        assert_eq!(
            index
                .resolve("foo.edge.cloud.example.test", now, &allowed)
                .expect("nested namespace wildcard")
                .target,
            &edge
        );
    }

    #[test]
    fn fails_closed_for_unauthorized_uncovered_and_expired_names() {
        let base = CertificateTarget::base_domain(hostname("example.test"));
        let expired = CertificateRecord::ready(
            base,
            CertificateProviderKind::Cloudflare,
            material(999),
            Timestamp::from_unix_seconds(100),
        );
        let index = SniCertificateIndex::new([expired]).expect("valid index");
        let allowed = AuthorizedHostnames::new([
            hostname("api.example.test"),
            hostname("deep.api.example.test"),
        ]);
        let now = Timestamp::from_unix_seconds(1_000);

        assert_eq!(
            index.resolve("unknown.example.test", now, &allowed),
            Err(ResolveError::Unauthorized)
        );
        assert_eq!(
            index.resolve("deep.api.example.test", now, &allowed),
            Err(ResolveError::Uncovered)
        );
        assert_eq!(
            index.resolve("api.example.test", now, &allowed),
            Err(ResolveError::NotReady)
        );
    }

    #[test]
    fn pending_child_namespace_blocks_parent_fallback() {
        let base = CertificateTarget::base_domain(hostname("example.test"));
        let cloud = CertificateTarget::namespace(hostname("cloud.example.test"));
        let pending = CertificateRecord::pending(
            cloud,
            CertificateProviderKind::Cloudflare,
            Timestamp::from_unix_seconds(900),
        );
        let index =
            SniCertificateIndex::new([ready(base), pending]).expect("valid certificate index");
        let allowed = AuthorizedHostnames::new([hostname("cloud.example.test")]);

        assert_eq!(
            index.resolve(
                "cloud.example.test",
                Timestamp::from_unix_seconds(1_000),
                &allowed,
            ),
            Err(ResolveError::NotReady)
        );
    }
}
