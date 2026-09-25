use std::{
    collections::HashMap,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use rand::RngCore as _;
use uuid::Uuid;

use crate::certificates::Hostname;

use super::broker::{ControlLinkLiveness, ControlLinkSnapshot, StreamBroker};

pub(crate) const RECONNECT_GRACE: Duration = Duration::from_secs(30);

const GENERATED_CLAIM_ATTEMPTS: usize = 64;

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub(crate) struct ClaimOwner {
    pub(crate) user_id: i64,
    pub(crate) session_id: Uuid,
}

#[derive(Clone, Debug)]
pub(crate) struct ClaimLease {
    pub(crate) hostname: Hostname,
    #[allow(dead_code)] // Consumed by the Wave 2 raw-route session path.
    pub(crate) route_kind: RouteKind,
    pub(crate) owner: ClaimOwner,
    pub(crate) lease_id: u64,
}

/// A live control link either owns one exact HTTP route or one passthrough
/// wildcard. The wildcard covers its apex and direct children only.
#[derive(Clone, Debug, Hash, Eq, PartialEq)]
#[allow(dead_code)] // Passthrough variant is the Wave 2 listener contract.
pub(crate) enum RouteTarget {
    Exact(Hostname),
    PassthroughWildcard(Hostname),
}

impl RouteTarget {
    pub(crate) fn exact(hostname: Hostname) -> Self {
        Self::Exact(hostname)
    }

    #[allow(dead_code)] // Wave 2 listener/control-session integration contract.
    pub(crate) fn passthrough(namespace: Hostname) -> Self {
        Self::PassthroughWildcard(namespace)
    }

    pub(crate) fn hostname(&self) -> &Hostname {
        match self {
            Self::Exact(hostname) | Self::PassthroughWildcard(hostname) => hostname,
        }
    }

    pub(crate) fn kind(&self) -> RouteKind {
        match self {
            Self::Exact(_) => RouteKind::Exact,
            Self::PassthroughWildcard(_) => RouteKind::PassthroughWildcard,
        }
    }

    fn covers(&self, hostname: &Hostname) -> bool {
        match self {
            Self::Exact(exact) => exact == hostname,
            Self::PassthroughWildcard(namespace) => {
                matches!(hostname.depth_below(namespace), Some(0 | 1))
            }
        }
    }

    fn overlaps(&self, other: &Self) -> bool {
        self.covers(other.hostname()) || other.covers(self.hostname())
    }
}

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub(crate) enum RouteKind {
    Exact,
    PassthroughWildcard,
}

#[derive(Clone, Debug)]
pub(crate) enum ClaimLookup {
    Active {
        broker: StreamBroker,
        owner: ClaimOwner,
    },
    Disconnected,
    Unknown,
}

#[derive(Clone, Debug)]
#[allow(dead_code)] // Wave 2 listener consumes this resolved route shape.
pub(crate) enum RouteLookup {
    Active {
        target: RouteTarget,
        broker: StreamBroker,
        owner: ClaimOwner,
    },
    Disconnected {
        target: RouteTarget,
    },
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ClaimError {
    Conflict(Box<ClaimConflict>),
    GenerationExhausted,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ClaimConflict {
    pub(crate) hostname: Hostname,
    pub(crate) route_kind: RouteKind,
    pub(crate) owner: ClaimOwner,
    pub(crate) status: ClaimStatusKind,
    pub(crate) broker_available: bool,
    pub(crate) liveness: ControlLinkSnapshot,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RouteClaim {
    pub(crate) owner: ClaimOwner,
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
    target: RouteTarget,
    owner: ClaimOwner,
    liveness: ControlLinkLiveness,
    status: ClaimStatus,
}

#[derive(Debug, Default)]
struct ClaimsInner {
    by_hostname: HashMap<Hostname, Claim>,
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
        requested: Hostname,
        broker: StreamBroker,
        now: Instant,
    ) -> Result<ClaimLease, ClaimError> {
        self.acquire_route(owner, RouteTarget::exact(requested), broker, now)
    }

    #[allow(dead_code)] // Wave 2 control-session integration contract.
    pub(crate) fn acquire_passthrough(
        &self,
        owner: ClaimOwner,
        namespace: Hostname,
        broker: StreamBroker,
        now: Instant,
    ) -> Result<ClaimLease, ClaimError> {
        self.acquire_route(owner, RouteTarget::passthrough(namespace), broker, now)
    }

    /// Acquire a previously authorized route target. Exact targets may not
    /// shadow a passthrough wildcard, and passthrough wildcards may not overlap
    /// any live exact route or wildcard.
    pub(crate) fn acquire_route(
        &self,
        owner: ClaimOwner,
        requested: RouteTarget,
        broker: StreamBroker,
        now: Instant,
    ) -> Result<ClaimLease, ClaimError> {
        let mut inner = self.lock();
        expire_locked(&mut inner, now);

        if let Some((hostname, claim)) = inner
            .by_hostname
            .iter()
            .find(|(_, claim)| claim.owner == owner)
        {
            if requested != claim.target {
                return Err(ClaimError::Conflict(Box::new(conflict(
                    hostname, claim, now,
                ))));
            }

            let replaced = match &claim.status {
                ClaimStatus::Active { broker, .. } => Some(broker.clone()),
                ClaimStatus::Disconnected { .. } => None,
            };
            let lease = activate_locked(&mut inner, requested, owner, broker);
            if let Some(replaced) = replaced {
                replaced.replace();
            }
            return Ok(lease);
        }

        if let Some((hostname, claim)) = inner
            .by_hostname
            .iter()
            .find(|(_, claim)| requested.overlaps(&claim.target))
        {
            return Err(ClaimError::Conflict(Box::new(conflict(
                hostname, claim, now,
            ))));
        }

        Ok(activate_locked(&mut inner, requested, owner, broker))
    }

    pub(crate) fn generated_candidate(
        &self,
        base_domain: &Hostname,
        now: Instant,
    ) -> Result<Hostname, ClaimError> {
        let mut inner = self.lock();
        expire_locked(&mut inner, now);
        for _ in 0..GENERATED_CLAIM_ATTEMPTS {
            let random = rand::rng().next_u64();
            let value = format!("t{random:016x}.{base_domain}");
            let Ok(hostname) = Hostname::parse(&value) else {
                continue;
            };
            if !inner.by_hostname.contains_key(&hostname) {
                return Ok(hostname);
            }
        }
        Err(ClaimError::GenerationExhausted)
    }

    pub(crate) fn lookup(&self, hostname: &Hostname, now: Instant) -> ClaimLookup {
        let mut inner = self.lock();
        expire_locked(&mut inner, now);
        match inner.by_hostname.get(hostname) {
            Some(Claim {
                target: RouteTarget::Exact(_),
                owner,
                status: ClaimStatus::Active { broker, .. },
                ..
            }) if broker.is_available() => ClaimLookup::Active {
                broker: broker.clone(),
                owner: *owner,
            },
            Some(Claim {
                target: RouteTarget::Exact(_),
                status: ClaimStatus::Active { .. } | ClaimStatus::Disconnected { .. },
                ..
            }) => ClaimLookup::Disconnected,
            Some(_) | None => ClaimLookup::Unknown,
        }
    }

    /// Resolve an exact or passthrough route for the Wave 2 listener. Exact
    /// lookup wins defensively, although acquisition prevents overlap.
    #[allow(dead_code)] // Wave 2 listener integration contract.
    pub(crate) fn resolve_route(&self, hostname: &Hostname, now: Instant) -> RouteLookup {
        let mut inner = self.lock();
        expire_locked(&mut inner, now);
        let claim = inner
            .by_hostname
            .get(hostname)
            .filter(|claim| matches!(&claim.target, RouteTarget::Exact(_)))
            .or_else(|| {
                inner.by_hostname.values().find(|claim| {
                    matches!(&claim.target, RouteTarget::PassthroughWildcard(_))
                        && claim.target.covers(hostname)
                })
            });
        match claim {
            Some(Claim {
                target,
                owner,
                status: ClaimStatus::Active { broker, .. },
                ..
            }) if broker.is_available() => RouteLookup::Active {
                target: target.clone(),
                broker: broker.clone(),
                owner: *owner,
            },
            Some(Claim { target, .. }) => RouteLookup::Disconnected {
                target: target.clone(),
            },
            None => RouteLookup::Unknown,
        }
    }

    pub(crate) fn route_claim(&self, hostname: &Hostname, now: Instant) -> Option<RouteClaim> {
        let mut inner = self.lock();
        expire_locked(&mut inner, now);
        let claim = inner.by_hostname.get(hostname)?;
        if !matches!(&claim.target, RouteTarget::Exact(_)) {
            return None;
        }
        Some(RouteClaim { owner: claim.owner })
    }

    pub(crate) fn has_routes_covered_by(&self, namespace: &Hostname, now: Instant) -> bool {
        let mut inner = self.lock();
        expire_locked(&mut inner, now);
        inner
            .by_hostname
            .keys()
            .any(|hostname| matches!(hostname.depth_below(namespace), Some(0 | 1)))
    }

    /// Mark an unexpectedly lost control link as temporarily reclaimable.
    /// Returns the exact expiry deadline when this lease was still current.
    pub(crate) fn disconnect(&self, lease: &ClaimLease, now: Instant) -> Option<Instant> {
        let mut inner = self.lock();
        let claim = inner.by_hostname.get_mut(&lease.hostname)?;
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
        let current = inner.by_hostname.get(&lease.hostname).is_some_and(|claim| {
            claim.owner == lease.owner
                && match claim.status {
                    ClaimStatus::Active { lease_id, .. }
                    | ClaimStatus::Disconnected { lease_id, .. } => lease_id == lease.lease_id,
                }
        });
        if current {
            inner.by_hostname.remove(&lease.hostname);
        }
        current
    }

    pub(crate) fn expire(&self, now: Instant) {
        expire_locked(&mut self.lock(), now);
    }

    pub(crate) fn shutdown_all(&self) {
        let mut inner = self.lock();
        for claim in inner.by_hostname.values() {
            if let ClaimStatus::Active { broker, .. } = &claim.status {
                broker.shutdown();
            }
        }
        inner.by_hostname.clear();
    }

    fn lock(&self) -> MutexGuard<'_, ClaimsInner> {
        match self.inner.lock() {
            Ok(inner) => inner,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

fn conflict(hostname: &Hostname, claim: &Claim, now: Instant) -> ClaimConflict {
    let (status, broker_available) = match &claim.status {
        ClaimStatus::Active { broker, .. } => (ClaimStatusKind::Active, broker.is_available()),
        ClaimStatus::Disconnected { .. } => (ClaimStatusKind::Disconnected, false),
    };
    ClaimConflict {
        hostname: hostname.clone(),
        route_kind: claim.target.kind(),
        owner: claim.owner,
        status,
        broker_available,
        liveness: claim.liveness.snapshot(now),
    }
}

fn activate_locked(
    inner: &mut ClaimsInner,
    target: RouteTarget,
    owner: ClaimOwner,
    broker: StreamBroker,
) -> ClaimLease {
    inner.next_lease_id = inner.next_lease_id.wrapping_add(1).max(1);
    let lease_id = inner.next_lease_id;
    let liveness = broker.liveness();
    let hostname = target.hostname().clone();
    inner.by_hostname.insert(
        hostname.clone(),
        Claim {
            target: target.clone(),
            owner,
            liveness,
            status: ClaimStatus::Active { broker, lease_id },
        },
    );
    ClaimLease {
        hostname,
        route_kind: target.kind(),
        owner,
        lease_id,
    }
}

fn expire_locked(inner: &mut ClaimsInner, now: Instant) {
    inner.by_hostname.retain(|_, claim| {
        !matches!(
            claim.status,
            ClaimStatus::Disconnected { expires_at, .. } if expires_at <= now
        )
    });
}

#[cfg(test)]
mod tests {
    use crate::runtime::broker::ControlInboundKind;

    use super::*;

    fn owner(user_id: i64, session: u128) -> ClaimOwner {
        ClaimOwner {
            user_id,
            session_id: Uuid::from_u128(session),
        }
    }

    fn hostname(value: &str) -> Hostname {
        Hostname::parse(value).expect("valid test hostname")
    }

    fn broker() -> StreamBroker {
        StreamBroker::channel().0
    }

    #[test]
    fn active_claim_conflicts_never_displace() {
        let registry = ClaimRegistry::default();
        let now = Instant::now();
        let hostname = hostname("demo.example.test");
        let (active_broker, _active_requests) = StreamBroker::channel();
        let active_liveness = active_broker.liveness();
        active_liveness.set_client_version("0.0.3");
        active_liveness.record_heartbeat_ping();
        active_liveness.record_inbound(ControlInboundKind::Pong);
        let first = registry
            .acquire(owner(1, 1), hostname.clone(), active_broker, now)
            .expect("first claim");

        let conflict = registry
            .acquire(owner(2, 2), hostname.clone(), broker(), now)
            .expect_err("different owner must conflict");
        let ClaimError::Conflict(conflict) = conflict else {
            panic!("expected a claim conflict");
        };
        assert_eq!(conflict.hostname, hostname);
        assert_eq!(conflict.owner, owner(1, 1));
        assert_eq!(conflict.status, ClaimStatusKind::Active);
        assert!(conflict.broker_available);
        assert_eq!(conflict.liveness.client_version.as_deref(), Some("0.0.3"));
        assert_eq!(conflict.liveness.heartbeat_pings_sent, 1);
        assert_eq!(conflict.liveness.heartbeat_pongs_received, 1);
        assert_eq!(
            conflict.liveness.last_inbound_kind,
            Some(ControlInboundKind::Pong)
        );
        assert!(matches!(
            registry.lookup(&hostname, now),
            ClaimLookup::Active { .. }
        ));
        assert_eq!(first.owner, owner(1, 1));
    }

    #[test]
    fn same_active_owner_atomically_replaces_its_old_lease() {
        let registry = ClaimRegistry::default();
        let now = Instant::now();
        let hostname = hostname("demo.example.test");
        let claim_owner = owner(1, 1);
        let first = registry
            .acquire(claim_owner, hostname.clone(), broker(), now)
            .expect("first claim");

        let (replacement_broker, _replacement_requests) = StreamBroker::channel();
        let replacement = registry
            .acquire(claim_owner, hostname.clone(), replacement_broker, now)
            .expect("same run reconnect replaces its active socket");

        assert_ne!(replacement.lease_id, first.lease_id);
        assert!(!registry.release(&first));
        assert!(matches!(
            registry.lookup(&hostname, now),
            ClaimLookup::Active { .. }
        ));
        assert!(registry.release(&replacement));
    }

    #[test]
    fn only_the_same_user_and_session_can_reclaim_during_grace() {
        let registry = ClaimRegistry::default();
        let now = Instant::now();
        let hostname = hostname("demo.example.test");
        let claim_owner = owner(1, 1);
        let lease = registry
            .acquire(claim_owner, hostname.clone(), broker(), now)
            .expect("initial claim");
        let deadline = registry
            .disconnect(&lease, now)
            .expect("current lease disconnects");

        assert_eq!(deadline, now + RECONNECT_GRACE);
        assert!(matches!(
            registry.lookup(&hostname, now + Duration::from_secs(29)),
            ClaimLookup::Disconnected
        ));
        assert!(matches!(
            registry.acquire(
                owner(1, 2),
                hostname.clone(),
                broker(),
                now + Duration::from_secs(29)
            ),
            Err(ClaimError::Conflict(_))
        ));
        let reclaimed = registry
            .acquire(
                claim_owner,
                hostname.clone(),
                broker(),
                now + Duration::from_secs(29),
            )
            .expect("same run reclaims its chosen name");
        assert_eq!(reclaimed.hostname, hostname);
        assert_ne!(reclaimed.lease_id, lease.lease_id);
    }

    #[test]
    fn grace_expires_at_exactly_thirty_seconds() {
        let registry = ClaimRegistry::default();
        let now = Instant::now();
        let hostname = hostname("demo.example.test");
        let lease = registry
            .acquire(owner(1, 1), hostname.clone(), broker(), now)
            .expect("initial claim");
        registry.disconnect(&lease, now).expect("disconnect");

        let replacement = registry
            .acquire(
                owner(2, 2),
                hostname.clone(),
                broker(),
                now + RECONNECT_GRACE,
            )
            .expect("claim is free at the exact deadline");
        assert_eq!(replacement.hostname, hostname);
    }

    #[test]
    fn covered_route_checks_include_only_apex_and_direct_children() {
        let registry = ClaimRegistry::default();
        let now = Instant::now();
        let deep = hostname("foo.edge.cloud.example.test");
        registry
            .acquire(owner(1, 1), deep, broker(), now)
            .expect("route claim");

        assert!(registry.has_routes_covered_by(&hostname("edge.cloud.example.test"), now));
        assert!(!registry.has_routes_covered_by(&hostname("cloud.example.test"), now));
    }

    #[test]
    fn passthrough_wildcard_resolves_apex_and_direct_children_only() {
        let registry = ClaimRegistry::default();
        let now = Instant::now();
        let namespace = hostname("cloud.example.test");
        let (active_broker, _active_requests) = StreamBroker::channel();
        let lease = registry
            .acquire_passthrough(owner(1, 1), namespace.clone(), active_broker, now)
            .expect("passthrough wildcard");
        assert_eq!(lease.route_kind, RouteKind::PassthroughWildcard);

        for covered in [namespace.clone(), hostname("api.cloud.example.test")] {
            match registry.resolve_route(&covered, now) {
                RouteLookup::Active {
                    target,
                    owner: route_owner,
                    ..
                } => {
                    assert_eq!(target, RouteTarget::passthrough(namespace.clone()));
                    assert_eq!(route_owner, owner(1, 1));
                }
                other => panic!("expected active passthrough route, got {other:?}"),
            }
        }
        assert!(matches!(
            registry.resolve_route(&hostname("deep.api.cloud.example.test"), now),
            RouteLookup::Unknown
        ));
        assert!(matches!(
            registry.lookup(&namespace, now),
            ClaimLookup::Unknown
        ));
        assert!(registry.route_claim(&namespace, now).is_none());
    }

    #[test]
    fn exact_routes_and_overlapping_wildcards_conflict() {
        let registry = ClaimRegistry::default();
        let now = Instant::now();
        let namespace = hostname("cloud.example.test");
        registry
            .acquire_passthrough(owner(1, 1), namespace.clone(), broker(), now)
            .expect("passthrough wildcard");

        for exact in [namespace.clone(), hostname("api.cloud.example.test")] {
            let conflict = registry
                .acquire(owner(2, 2), exact, broker(), now)
                .expect_err("exact route must not shadow wildcard");
            let ClaimError::Conflict(conflict) = conflict else {
                panic!("expected conflict");
            };
            assert_eq!(conflict.route_kind, RouteKind::PassthroughWildcard);
        }
        assert!(matches!(
            registry.acquire_passthrough(
                owner(3, 3),
                hostname("edge.cloud.example.test"),
                broker(),
                now
            ),
            Err(ClaimError::Conflict(_))
        ));
        registry
            .acquire_passthrough(owner(4, 4), hostname("other.example.test"), broker(), now)
            .expect("disjoint wildcard");
    }

    #[test]
    fn passthrough_acquisition_rejects_preexisting_covered_exact_route() {
        let registry = ClaimRegistry::default();
        let now = Instant::now();
        registry
            .acquire(
                owner(1, 1),
                hostname("api.cloud.example.test"),
                broker(),
                now,
            )
            .expect("exact route");
        assert!(matches!(
            registry.acquire_passthrough(
                owner(2, 2),
                hostname("cloud.example.test"),
                broker(),
                now
            ),
            Err(ClaimError::Conflict(_))
        ));
    }

    #[test]
    fn passthrough_wildcard_reconnect_and_release_preserve_target_identity() {
        let registry = ClaimRegistry::default();
        let now = Instant::now();
        let namespace = hostname("cloud.example.test");
        let claim_owner = owner(1, 1);
        let first = registry
            .acquire_passthrough(claim_owner, namespace.clone(), broker(), now)
            .expect("passthrough wildcard");
        registry
            .disconnect(&first, now)
            .expect("passthrough lease disconnects");

        let (replacement_broker, _replacement_requests) = StreamBroker::channel();
        let replacement = registry
            .acquire_passthrough(
                claim_owner,
                namespace.clone(),
                replacement_broker,
                now + Duration::from_secs(29),
            )
            .expect("same session reclaims passthrough target");
        assert_eq!(replacement.route_kind, RouteKind::PassthroughWildcard);
        assert_ne!(replacement.lease_id, first.lease_id);
        assert!(!registry.release(&first));
        assert!(registry.release(&replacement));
        assert!(matches!(
            registry.resolve_route(&namespace, now + Duration::from_secs(29)),
            RouteLookup::Unknown
        ));
    }

    #[test]
    fn clean_release_is_immediate_and_stale_leases_are_harmless() {
        let registry = ClaimRegistry::default();
        let now = Instant::now();
        let hostname = hostname("demo.example.test");
        let lease = registry
            .acquire(owner(1, 1), hostname.clone(), broker(), now)
            .expect("initial claim");
        assert!(registry.release(&lease));
        assert!(matches!(
            registry.lookup(&hostname, now),
            ClaimLookup::Unknown
        ));

        let replacement = registry
            .acquire(owner(2, 2), hostname, broker(), now)
            .expect("immediate replacement");
        assert!(!registry.release(&lease));
        assert_eq!(replacement.owner, owner(2, 2));
    }
}
