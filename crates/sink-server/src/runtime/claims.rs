use std::{
    collections::HashMap,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use rand::RngCore as _;
use sink_protocol::Subdomain;
use uuid::Uuid;

use super::broker::StreamBroker;

pub(crate) const RECONNECT_GRACE: Duration = Duration::from_secs(30);

const GENERATED_CLAIM_ATTEMPTS: usize = 64;

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub(crate) struct ClaimOwner {
    pub(crate) user_id: i64,
    pub(crate) session_id: Uuid,
}

#[derive(Clone, Debug)]
pub(crate) struct ClaimLease {
    pub(crate) subdomain: Subdomain,
    pub(crate) owner: ClaimOwner,
    pub(crate) lease_id: u64,
}

#[derive(Clone, Debug)]
pub(crate) enum ClaimLookup {
    Active(StreamBroker),
    Disconnected,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ClaimError {
    Conflict(ClaimConflict),
    GenerationExhausted,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ClaimConflict {
    pub(crate) subdomain: Subdomain,
    pub(crate) owner: ClaimOwner,
    pub(crate) status: ClaimStatusKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ClaimStatusKind {
    Active,
    Disconnected,
}

impl ClaimStatusKind {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Disconnected => "disconnected",
        }
    }
}

#[derive(Debug)]
enum ClaimStatus {
    Active { broker: StreamBroker, lease_id: u64 },
    Disconnected { expires_at: Instant, lease_id: u64 },
}

#[derive(Debug)]
struct Claim {
    owner: ClaimOwner,
    status: ClaimStatus,
}

#[derive(Debug, Default)]
struct ClaimsInner {
    by_subdomain: HashMap<Subdomain, Claim>,
    next_lease_id: u64,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct ClaimRegistry {
    inner: Arc<Mutex<ClaimsInner>>,
}

impl ClaimRegistry {
    pub(crate) fn acquire(
        &self,
        owner: ClaimOwner,
        requested: Option<Subdomain>,
        broker: StreamBroker,
        now: Instant,
    ) -> Result<ClaimLease, ClaimError> {
        let mut inner = self.lock();
        expire_locked(&mut inner, now);

        if let Some((subdomain, claim)) = inner
            .by_subdomain
            .iter()
            .find(|(_, claim)| claim.owner == owner)
        {
            let requested_matches = requested
                .as_ref()
                .is_none_or(|requested| requested == subdomain);
            if !requested_matches {
                return Err(ClaimError::Conflict(conflict(subdomain, claim)));
            }

            let subdomain = subdomain.clone();
            let replaced = match &claim.status {
                ClaimStatus::Active { broker, .. } => Some(broker.clone()),
                ClaimStatus::Disconnected { .. } => None,
            };
            let lease = activate_locked(&mut inner, subdomain, owner, broker);
            if let Some(replaced) = replaced {
                replaced.replace();
            }
            return Ok(lease);
        }

        let subdomain = match requested {
            Some(subdomain) => {
                if let Some(claim) = inner.by_subdomain.get(&subdomain) {
                    return Err(ClaimError::Conflict(conflict(&subdomain, claim)));
                }
                subdomain
            }
            None => generate_available_subdomain(&inner)?,
        };

        Ok(activate_locked(&mut inner, subdomain, owner, broker))
    }

    pub(crate) fn lookup(&self, subdomain: &Subdomain, now: Instant) -> ClaimLookup {
        let mut inner = self.lock();
        expire_locked(&mut inner, now);
        match inner.by_subdomain.get(subdomain) {
            Some(Claim {
                status: ClaimStatus::Active { broker, .. },
                ..
            }) if broker.is_available() => ClaimLookup::Active(broker.clone()),
            Some(Claim {
                status: ClaimStatus::Active { .. } | ClaimStatus::Disconnected { .. },
                ..
            }) => ClaimLookup::Disconnected,
            None => ClaimLookup::Unknown,
        }
    }

    /// Mark an unexpectedly lost control link as temporarily reclaimable.
    /// Returns the exact expiry deadline when this lease was still current.
    pub(crate) fn disconnect(&self, lease: &ClaimLease, now: Instant) -> Option<Instant> {
        let mut inner = self.lock();
        let claim = inner.by_subdomain.get_mut(&lease.subdomain)?;
        let current_lease = matches!(
            claim.status,
            ClaimStatus::Active { lease_id, .. } if lease_id == lease.lease_id
        );
        if claim.owner != lease.owner || !current_lease {
            return None;
        }

        let expires_at = now + RECONNECT_GRACE;
        claim.status = ClaimStatus::Disconnected {
            expires_at,
            lease_id: lease.lease_id,
        };
        Some(expires_at)
    }

    /// Immediately release a cleanly closed, revoked, or shutting-down lease.
    pub(crate) fn release(&self, lease: &ClaimLease) -> bool {
        let mut inner = self.lock();
        let current = inner
            .by_subdomain
            .get(&lease.subdomain)
            .is_some_and(|claim| {
                claim.owner == lease.owner
                    && match claim.status {
                        ClaimStatus::Active { lease_id, .. }
                        | ClaimStatus::Disconnected { lease_id, .. } => lease_id == lease.lease_id,
                    }
            });
        if current {
            inner.by_subdomain.remove(&lease.subdomain);
        }
        current
    }

    pub(crate) fn expire(&self, now: Instant) {
        expire_locked(&mut self.lock(), now);
    }

    pub(crate) fn shutdown_all(&self) {
        let mut inner = self.lock();
        for claim in inner.by_subdomain.values() {
            if let ClaimStatus::Active { broker, .. } = &claim.status {
                broker.shutdown();
            }
        }
        inner.by_subdomain.clear();
    }

    fn lock(&self) -> MutexGuard<'_, ClaimsInner> {
        match self.inner.lock() {
            Ok(inner) => inner,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

fn conflict(subdomain: &Subdomain, claim: &Claim) -> ClaimConflict {
    ClaimConflict {
        subdomain: subdomain.clone(),
        owner: claim.owner,
        status: match claim.status {
            ClaimStatus::Active { .. } => ClaimStatusKind::Active,
            ClaimStatus::Disconnected { .. } => ClaimStatusKind::Disconnected,
        },
    }
}

fn activate_locked(
    inner: &mut ClaimsInner,
    subdomain: Subdomain,
    owner: ClaimOwner,
    broker: StreamBroker,
) -> ClaimLease {
    inner.next_lease_id = inner.next_lease_id.wrapping_add(1).max(1);
    let lease_id = inner.next_lease_id;
    inner.by_subdomain.insert(
        subdomain.clone(),
        Claim {
            owner,
            status: ClaimStatus::Active { broker, lease_id },
        },
    );
    ClaimLease {
        subdomain,
        owner,
        lease_id,
    }
}

fn expire_locked(inner: &mut ClaimsInner, now: Instant) {
    inner.by_subdomain.retain(|_, claim| {
        !matches!(
            claim.status,
            ClaimStatus::Disconnected { expires_at, .. } if expires_at <= now
        )
    });
}

fn generate_available_subdomain(inner: &ClaimsInner) -> Result<Subdomain, ClaimError> {
    for _ in 0..GENERATED_CLAIM_ATTEMPTS {
        let random = rand::rng().next_u64();
        let value = format!("t{random:016x}");
        let subdomain = match Subdomain::parse(&value) {
            Ok(subdomain) => subdomain,
            Err(_) => continue,
        };
        if !inner.by_subdomain.contains_key(&subdomain) {
            return Ok(subdomain);
        }
    }
    Err(ClaimError::GenerationExhausted)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner(user_id: i64, session: u128) -> ClaimOwner {
        ClaimOwner {
            user_id,
            session_id: Uuid::from_u128(session),
        }
    }

    fn broker() -> StreamBroker {
        StreamBroker::channel().0
    }

    #[test]
    fn active_claim_conflicts_never_displace() {
        let registry = ClaimRegistry::default();
        let now = Instant::now();
        let subdomain = Subdomain::parse("demo").expect("valid test subdomain");
        let (active_broker, _active_requests) = StreamBroker::channel();
        let first = registry
            .acquire(owner(1, 1), Some(subdomain.clone()), active_broker, now)
            .expect("first claim");

        let conflict = registry
            .acquire(owner(2, 2), Some(subdomain.clone()), broker(), now)
            .expect_err("different owner must conflict");
        assert_eq!(
            conflict,
            ClaimError::Conflict(ClaimConflict {
                subdomain: subdomain.clone(),
                owner: owner(1, 1),
                status: ClaimStatusKind::Active,
            })
        );
        assert!(matches!(
            registry.lookup(&subdomain, now),
            ClaimLookup::Active(_)
        ));
        assert_eq!(first.owner, owner(1, 1));
    }

    #[test]
    fn same_active_owner_atomically_replaces_its_old_lease() {
        let registry = ClaimRegistry::default();
        let now = Instant::now();
        let subdomain = Subdomain::parse("demo").expect("valid test subdomain");
        let claim_owner = owner(1, 1);
        let first = registry
            .acquire(claim_owner, Some(subdomain.clone()), broker(), now)
            .expect("first claim");

        let (replacement_broker, _replacement_requests) = StreamBroker::channel();
        let replacement = registry
            .acquire(
                claim_owner,
                Some(subdomain.clone()),
                replacement_broker,
                now,
            )
            .expect("same run reconnect replaces its active socket");

        assert_ne!(replacement.lease_id, first.lease_id);
        assert!(!registry.release(&first));
        assert!(matches!(
            registry.lookup(&subdomain, now),
            ClaimLookup::Active(_)
        ));
        assert!(registry.release(&replacement));
    }

    #[test]
    fn only_the_same_user_and_session_can_reclaim_during_grace() {
        let registry = ClaimRegistry::default();
        let now = Instant::now();
        let subdomain = Subdomain::parse("demo").expect("valid test subdomain");
        let claim_owner = owner(1, 1);
        let lease = registry
            .acquire(claim_owner, Some(subdomain.clone()), broker(), now)
            .expect("initial claim");
        let deadline = registry
            .disconnect(&lease, now)
            .expect("current lease disconnects");

        assert_eq!(deadline, now + RECONNECT_GRACE);
        assert!(matches!(
            registry.lookup(&subdomain, now + Duration::from_secs(29)),
            ClaimLookup::Disconnected
        ));
        assert!(matches!(
            registry.acquire(
                owner(1, 2),
                Some(subdomain.clone()),
                broker(),
                now + Duration::from_secs(29)
            ),
            Err(ClaimError::Conflict(_))
        ));
        let reclaimed = registry
            .acquire(claim_owner, None, broker(), now + Duration::from_secs(29))
            .expect("same run reclaims generated or chosen name");
        assert_eq!(reclaimed.subdomain, subdomain);
        assert_ne!(reclaimed.lease_id, lease.lease_id);
    }

    #[test]
    fn grace_expires_at_exactly_thirty_seconds() {
        let registry = ClaimRegistry::default();
        let now = Instant::now();
        let subdomain = Subdomain::parse("demo").expect("valid test subdomain");
        let lease = registry
            .acquire(owner(1, 1), Some(subdomain.clone()), broker(), now)
            .expect("initial claim");
        registry.disconnect(&lease, now).expect("disconnect");

        let replacement = registry
            .acquire(
                owner(2, 2),
                Some(subdomain.clone()),
                broker(),
                now + RECONNECT_GRACE,
            )
            .expect("claim is free at the exact deadline");
        assert_eq!(replacement.subdomain, subdomain);
    }

    #[test]
    fn clean_release_is_immediate_and_stale_leases_are_harmless() {
        let registry = ClaimRegistry::default();
        let now = Instant::now();
        let subdomain = Subdomain::parse("demo").expect("valid test subdomain");
        let lease = registry
            .acquire(owner(1, 1), Some(subdomain.clone()), broker(), now)
            .expect("initial claim");
        assert!(registry.release(&lease));
        assert!(matches!(
            registry.lookup(&subdomain, now),
            ClaimLookup::Unknown
        ));

        let replacement = registry
            .acquire(owner(2, 2), Some(subdomain), broker(), now)
            .expect("immediate replacement");
        assert!(!registry.release(&lease));
        assert_eq!(replacement.owner, owner(2, 2));
    }
}
