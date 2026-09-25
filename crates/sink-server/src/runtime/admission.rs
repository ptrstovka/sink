use crate::{
    certificates::Hostname,
    db::{NamespaceClaimState, NamespaceTlsMode},
};

use super::{RuntimeState, claims::RouteTarget, host::is_reserved_hostname};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RouteAdmissionError {
    Unauthorized,
    NotReady,
    Unavailable,
}

/// Authorize one normalized tunnel hostname. The caller must hold the shared
/// admission gate until any corresponding in-memory route lease is acquired.
pub(crate) async fn authorize_hostname_locked(
    state: &RuntimeState,
    user_id: i64,
    hostname: &Hostname,
) -> Result<(), RouteAdmissionError> {
    let Some(domain) = state.domains.most_specific_match(hostname) else {
        return Err(RouteAdmissionError::Unauthorized);
    };
    if is_reserved_hostname(hostname, &domain.hostname) {
        return Err(RouteAdmissionError::Unauthorized);
    }
    let Some(depth) = hostname.depth_below(&domain.hostname) else {
        return Err(RouteAdmissionError::Unauthorized);
    };
    if depth == 0 || depth > usize::from(domain.max_namespace_depth) + 1 {
        return Err(RouteAdmissionError::Unauthorized);
    }

    // Exact routes may not shadow an active passthrough wildcard. This lookup
    // deliberately ignores a more-specific managed claim because the parent
    // wildcard still covers that claim's apex, but never deeper descendants.
    if state
        .database
        .active_passthrough_claim_for_route(hostname.as_str())
        .await
        .map_err(|error| {
            tracing::error!(%error, "passthrough route-conflict lookup failed");
            RouteAdmissionError::Unavailable
        })?
        .is_some()
    {
        return Err(RouteAdmissionError::Unauthorized);
    }

    let claim = if depth == 1 {
        state.database.namespace_claim(hostname.as_str()).await
    } else {
        state
            .database
            .namespace_claim_for_route(hostname.as_str())
            .await
    }
    .map_err(|error| {
        tracing::error!(%error, "namespace route authorization lookup failed");
        RouteAdmissionError::Unavailable
    })?;

    match claim {
        None if depth == 1 => Ok(()),
        Some(claim) if claim.user_id == user_id && claim.state == NamespaceClaimState::Active => {
            Ok(())
        }
        Some(claim) if claim.user_id == user_id => Err(RouteAdmissionError::NotReady),
        Some(_) | None => Err(RouteAdmissionError::Unauthorized),
    }
}

/// Authorize the one canonical wildcard route owned by a passthrough
/// namespace. Wave 2 should call this while holding the shared admission gate,
/// then pass the returned target directly to `ClaimRegistry::acquire_route`.
/// The target covers only its apex and direct child hostnames.
#[allow(dead_code)] // Wave 2 listener/control-session integration contract.
pub(crate) async fn authorize_passthrough_namespace_locked(
    state: &RuntimeState,
    user_id: i64,
    namespace: &Hostname,
) -> Result<RouteTarget, RouteAdmissionError> {
    let Some(domain) = state.domains.most_specific_match(namespace) else {
        return Err(RouteAdmissionError::Unauthorized);
    };
    if is_reserved_hostname(namespace, &domain.hostname) {
        return Err(RouteAdmissionError::Unauthorized);
    }
    let Some(depth) = namespace.depth_below(&domain.hostname) else {
        return Err(RouteAdmissionError::Unauthorized);
    };
    if depth == 0 || depth > usize::from(domain.max_namespace_depth) {
        return Err(RouteAdmissionError::Unauthorized);
    }

    let claim = state
        .database
        .namespace_claim(namespace.as_str())
        .await
        .map_err(|error| {
            tracing::error!(%error, "passthrough namespace authorization lookup failed");
            RouteAdmissionError::Unavailable
        })?;
    match claim {
        Some(claim)
            if claim.user_id == user_id
                && claim.tls_mode == NamespaceTlsMode::Passthrough
                && claim.state == NamespaceClaimState::Active =>
        {
            Ok(RouteTarget::passthrough(namespace.clone()))
        }
        Some(claim) if claim.user_id == user_id && claim.state != NamespaceClaimState::Active => {
            Err(RouteAdmissionError::NotReady)
        }
        Some(_) | None => Err(RouteAdmissionError::Unauthorized),
    }
}
