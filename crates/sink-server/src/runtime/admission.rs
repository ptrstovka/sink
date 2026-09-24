use crate::{certificates::Hostname, db::NamespaceClaimState};

use super::{RuntimeState, host::is_reserved_hostname};

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
