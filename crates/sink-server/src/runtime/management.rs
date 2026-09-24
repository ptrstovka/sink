use std::{
    collections::HashMap,
    sync::{Arc, Weak},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use axum::{
    body::{Body, to_bytes},
    extract::{Request, State},
    http::{
        HeaderValue, Method, Response, StatusCode,
        header::{CONTENT_TYPE, WWW_AUTHENTICATE},
    },
};
use sink_protocol::{
    ManagementError, ManagementErrorCode, ManagementErrorResponse, Namespace,
    NamespaceClaimRequest, NamespaceListResponse, NamespaceResponse,
};

use crate::{
    certificates::{Hostname, QuotaSnapshot, Timestamp},
    config::ConfiguredDomain,
    db::{AuthenticatedUser, DbError, NamespaceClaim, NamespaceClaimState},
    namespace_control::{NamespaceCertificateRequest, NamespaceCertificateStatus},
};

use super::{
    RuntimeState, bearer_token,
    host::{HostRoute, is_reserved_hostname},
    public_request,
};

#[derive(Clone, Debug, Default)]
pub(crate) struct NamespaceOperationLocks {
    inner: Arc<tokio::sync::Mutex<HashMap<String, Weak<tokio::sync::Mutex<()>>>>>,
}

impl NamespaceOperationLocks {
    async fn lock(&self, hostname: &Hostname) -> tokio::sync::OwnedMutexGuard<()> {
        let lock = {
            let mut locks = self.inner.lock().await;
            locks.retain(|_, lock| lock.strong_count() > 0);
            if let Some(lock) = locks.get(hostname.as_str()).and_then(Weak::upgrade) {
                lock
            } else {
                let lock = Arc::new(tokio::sync::Mutex::new(()));
                locks.insert(hostname.to_string(), Arc::downgrade(&lock));
                lock
            }
        };
        lock.lock_owned().await
    }
}

const MAX_MANAGEMENT_BODY_BYTES: usize = 16 * 1024;

pub(crate) async fn namespace_collection_ingress(
    State(state): State<RuntimeState>,
    request: Request,
) -> Response<Body> {
    if !is_management_request(&state, &request) {
        return public_request(state, request).await;
    }
    let token = bearer_token(request.headers()).map(str::to_owned);
    let user = match authenticate(&state, token).await {
        Ok(user) => user,
        Err(response) => return response,
    };

    match request.method().clone() {
        Method::GET => list_namespaces(&state, &user).await,
        Method::POST => claim_namespace(&state, &user, request).await,
        _ => management_error(
            StatusCode::METHOD_NOT_ALLOWED,
            ManagementErrorCode::InvalidRequest,
            "method is not allowed",
        ),
    }
}

pub(crate) async fn namespace_item_ingress(
    State(state): State<RuntimeState>,
    request: Request,
) -> Response<Body> {
    if !is_management_request(&state, &request) {
        return public_request(state, request).await;
    }
    let token = bearer_token(request.headers()).map(str::to_owned);
    let user = match authenticate(&state, token).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let Some(raw_hostname) = request
        .uri()
        .path()
        .strip_prefix("/_sink/api/v1/namespaces/")
    else {
        return invalid_request();
    };
    let (hostname, domain) = match validate_namespace(&state, raw_hostname) {
        Ok(validated) => validated,
        Err(response) => return *response,
    };

    match request.method().clone() {
        Method::GET => namespace_status(&state, &user, &hostname).await,
        Method::DELETE => release_namespace(&state, &user, hostname, domain).await,
        _ => management_error(
            StatusCode::METHOD_NOT_ALLOWED,
            ManagementErrorCode::InvalidRequest,
            "method is not allowed",
        ),
    }
}

fn is_management_request(state: &RuntimeState, request: &Request) -> bool {
    matches!(
        super::route_for_request(request.headers(), &state.public_base_domain),
        HostRoute::Control
    ) || super::has_loopback_host(request.headers())
}

async fn authenticate(
    state: &RuntimeState,
    token: Option<String>,
) -> Result<AuthenticatedUser, Response<Body>> {
    let Some(token) = token else {
        return Err(authentication_error());
    };
    match state.database.authenticate(&token).await {
        Ok(Some(user)) => Ok(user),
        Ok(None) => Err(authentication_error()),
        Err(error) => {
            tracing::error!(%error, "namespace management authentication failed");
            Err(service_unavailable())
        }
    }
}

async fn list_namespaces(state: &RuntimeState, user: &AuthenticatedUser) -> Response<Body> {
    match state.database.list_namespace_claims(user.id).await {
        Ok(claims) => json_response(
            StatusCode::OK,
            &NamespaceListResponse {
                namespaces: claims.into_iter().map(namespace_contract).collect(),
            },
        ),
        Err(error) => {
            tracing::error!(user_id = user.id, %error, "namespace list failed");
            service_unavailable()
        }
    }
}

async fn namespace_status(
    state: &RuntimeState,
    user: &AuthenticatedUser,
    hostname: &Hostname,
) -> Response<Body> {
    match state.database.namespace_claim(hostname.as_str()).await {
        Ok(Some(claim)) if claim.user_id == user.id => json_response(
            StatusCode::OK,
            &NamespaceResponse {
                namespace: namespace_contract(claim),
            },
        ),
        Ok(Some(_) | None) => namespace_not_found(),
        Err(error) => {
            tracing::error!(user_id = user.id, hostname = %hostname, %error, "namespace status failed");
            service_unavailable()
        }
    }
}

async fn claim_namespace(
    state: &RuntimeState,
    user: &AuthenticatedUser,
    request: Request,
) -> Response<Body> {
    let bytes = match to_bytes(request.into_body(), MAX_MANAGEMENT_BODY_BYTES).await {
        Ok(bytes) => bytes,
        Err(_) => return invalid_request(),
    };
    let request = match serde_json::from_slice::<NamespaceClaimRequest>(&bytes) {
        Ok(request) => request,
        Err(_) => return invalid_request(),
    };
    let (hostname, domain) = match validate_namespace(state, &request.hostname) {
        Ok(validated) => validated,
        Err(response) => return *response,
    };

    let _mutation = state.namespace_mutations.lock(&hostname).await;
    let (claim, created) = {
        let _admission = state.admission_gate.lock().await;
        match prepare_claim(state, user.id, &hostname, &domain).await {
            Ok(prepared) => prepared,
            Err(response) => return response,
        }
    };

    if claim.state == NamespaceClaimState::Active {
        return claim_response(StatusCode::OK, claim);
    }

    let claims = match state.database.list_namespace_claims(user.id).await {
        Ok(claims) => claims,
        Err(error) => {
            tracing::error!(user_id = user.id, %error, "namespace quota lookup failed");
            return service_unavailable();
        }
    };
    let quota = quota_snapshot(&claims, claim.id);
    let certificate_status = state
        .certificates
        .provision(NamespaceCertificateRequest {
            hostname: hostname.clone(),
            user_id: user.id,
            provider: domain.certificate_provider,
            quota,
            now: now_timestamp(),
        })
        .await;
    let target_state = match certificate_status {
        Ok(NamespaceCertificateStatus::Ready) => NamespaceClaimState::Active,
        Ok(NamespaceCertificateStatus::Pending) => NamespaceClaimState::Pending,
        Ok(NamespaceCertificateStatus::Retrying) | Err(_) => NamespaceClaimState::Retrying,
        Ok(NamespaceCertificateStatus::Failed) => NamespaceClaimState::Failed,
    };
    let claim = match set_claim_state(state, user.id, claim, target_state).await {
        Ok(claim) => claim,
        Err(response) => return response,
    };
    let status = if claim.state == NamespaceClaimState::Active {
        if created {
            StatusCode::CREATED
        } else {
            StatusCode::OK
        }
    } else {
        StatusCode::ACCEPTED
    };
    claim_response(status, claim)
}

async fn prepare_claim(
    state: &RuntimeState,
    user_id: i64,
    hostname: &Hostname,
    domain: &ConfiguredDomain,
) -> Result<(NamespaceClaim, bool), Response<Body>> {
    match state.database.namespace_claim(hostname.as_str()).await {
        Ok(Some(claim)) if claim.user_id != user_id => return Err(namespace_unavailable()),
        Ok(Some(claim)) if claim.state == NamespaceClaimState::Releasing => {
            return Err(namespace_unavailable());
        }
        Ok(Some(claim)) => return Ok((claim, false)),
        Ok(None) => {}
        Err(error) => {
            tracing::error!(user_id, hostname = %hostname, %error, "namespace lookup failed");
            return Err(service_unavailable());
        }
    }

    if state
        .claims
        .route_claim(hostname, Instant::now())
        .is_some_and(|claim| claim.owner.user_id != user_id)
    {
        return Err(namespace_unavailable());
    }

    let depth = hostname
        .depth_below(&domain.hostname)
        .and_then(|depth| u32::try_from(depth).ok())
        .ok_or_else(invalid_hostname)?;
    if depth > 1 {
        let Some((_, parent)) = hostname.as_str().split_once('.') else {
            return Err(parent_namespace_unavailable());
        };
        match state.database.namespace_claim(parent).await {
            Ok(Some(parent_claim))
                if parent_claim.user_id == user_id
                    && parent_claim.state == NamespaceClaimState::Active => {}
            Ok(Some(_) | None) => return Err(parent_namespace_unavailable()),
            Err(error) => {
                tracing::error!(user_id, hostname = %hostname, %error, "parent namespace lookup failed");
                return Err(service_unavailable());
            }
        }
    }

    state
        .database
        .create_namespace_claim(
            user_id,
            hostname.as_str(),
            domain.hostname.as_str(),
            u32::from(domain.max_namespace_depth),
        )
        .await
        .map(|claim| (claim, true))
        .map_err(|error| map_claim_error(user_id, hostname, error))
}

async fn set_claim_state(
    state: &RuntimeState,
    user_id: i64,
    claim: NamespaceClaim,
    target: NamespaceClaimState,
) -> Result<NamespaceClaim, Response<Body>> {
    if claim.state == target {
        return Ok(claim);
    }
    state
        .database
        .transition_namespace_claim(user_id, &claim.fqdn, claim.state, target)
        .await
        .map_err(|error| {
            tracing::error!(user_id, hostname = claim.fqdn, %error, "namespace state transition failed");
            service_unavailable()
        })
}

async fn release_namespace(
    state: &RuntimeState,
    user: &AuthenticatedUser,
    hostname: Hostname,
    domain: ConfiguredDomain,
) -> Response<Body> {
    let _mutation = state.namespace_mutations.lock(&hostname).await;
    {
        let _admission = state.admission_gate.lock().await;
        let claim = match state.database.namespace_claim(hostname.as_str()).await {
            Ok(Some(claim)) if claim.user_id == user.id => claim,
            Ok(Some(_) | None) => return namespace_not_found(),
            Err(error) => {
                tracing::error!(user_id = user.id, hostname = %hostname, %error, "namespace release lookup failed");
                return service_unavailable();
            }
        };
        let owned_claims = match state.database.list_namespace_claims(user.id).await {
            Ok(claims) => claims,
            Err(error) => {
                tracing::error!(user_id = user.id, %error, "namespace child lookup failed");
                return service_unavailable();
            }
        };
        if owned_claims
            .iter()
            .any(|candidate| candidate.parent_id == Some(claim.id))
        {
            return management_error(
                StatusCode::CONFLICT,
                ManagementErrorCode::NamespaceHasChildren,
                "namespace has child claims",
            );
        }
        if state
            .claims
            .has_routes_covered_by(&hostname, Instant::now())
        {
            return management_error(
                StatusCode::CONFLICT,
                ManagementErrorCode::NamespaceInUse,
                "namespace has active or reconnecting routes",
            );
        }
        if claim.state != NamespaceClaimState::Releasing
            && let Err(error) = state
                .database
                .transition_namespace_claim(
                    user.id,
                    hostname.as_str(),
                    claim.state,
                    NamespaceClaimState::Releasing,
                )
                .await
        {
            tracing::error!(user_id = user.id, hostname = %hostname, %error, "namespace release transition failed");
            return service_unavailable();
        }
    }

    if state
        .certificates
        .release(
            hostname.clone(),
            domain.certificate_provider,
            now_timestamp(),
        )
        .await
        .is_err()
    {
        tracing::error!(user_id = user.id, hostname = %hostname, "namespace certificate release failed");
        return management_error(
            StatusCode::SERVICE_UNAVAILABLE,
            ManagementErrorCode::CertificateUnavailable,
            "certificate release is unavailable",
        );
    }

    let _admission = state.admission_gate.lock().await;
    match state
        .database
        .delete_releasing_namespace_claim(user.id, hostname.as_str())
        .await
    {
        Ok(_) => empty_response(StatusCode::NO_CONTENT),
        Err(DbError::NamespaceHasChildren { .. }) => management_error(
            StatusCode::CONFLICT,
            ManagementErrorCode::NamespaceHasChildren,
            "namespace has child claims",
        ),
        Err(error) => {
            tracing::error!(user_id = user.id, hostname = %hostname, %error, "namespace release delete failed");
            service_unavailable()
        }
    }
}

fn validate_namespace(
    state: &RuntimeState,
    raw_hostname: &str,
) -> Result<(Hostname, ConfiguredDomain), Box<Response<Body>>> {
    let hostname = Hostname::parse(raw_hostname).map_err(|_| Box::new(invalid_hostname()))?;
    let Some(domain) = state.domains.most_specific_match(&hostname).cloned() else {
        return Err(Box::new(invalid_hostname()));
    };
    let Some(depth) = hostname.depth_below(&domain.hostname) else {
        return Err(Box::new(invalid_hostname()));
    };
    if depth == 0 || depth > usize::from(domain.max_namespace_depth) {
        return Err(Box::new(invalid_hostname()));
    }
    if is_reserved_hostname(&hostname, &domain.hostname) {
        return Err(Box::new(management_error(
            StatusCode::CONFLICT,
            ManagementErrorCode::ReservedHostname,
            "hostname is reserved by Sink",
        )));
    }
    Ok((hostname, domain))
}

fn quota_snapshot(claims: &[NamespaceClaim], target_id: i64) -> QuotaSnapshot {
    let active_claims_for_user = claims
        .iter()
        .filter(|claim| claim.state == NamespaceClaimState::Active)
        .count()
        .try_into()
        .unwrap_or(u32::MAX);
    let other_pending_orders_for_user = claims
        .iter()
        .filter(|claim| {
            claim.id != target_id
                && matches!(
                    claim.state,
                    NamespaceClaimState::Pending | NamespaceClaimState::Retrying
                )
        })
        .count()
        .try_into()
        .unwrap_or(u32::MAX);
    QuotaSnapshot {
        active_claims_for_user,
        other_pending_orders_for_user,
        concurrent_orders: 0,
    }
}

fn now_timestamp() -> Timestamp {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    Timestamp::from_unix_seconds(seconds)
}

fn namespace_contract(claim: NamespaceClaim) -> Namespace {
    Namespace {
        hostname: claim.fqdn,
        depth: claim.depth,
        state: match claim.state {
            NamespaceClaimState::Pending => sink_protocol::NamespaceState::Pending,
            NamespaceClaimState::Active => sink_protocol::NamespaceState::Active,
            NamespaceClaimState::Failed => sink_protocol::NamespaceState::Failed,
            NamespaceClaimState::Retrying => sink_protocol::NamespaceState::Retrying,
            NamespaceClaimState::Releasing => sink_protocol::NamespaceState::Releasing,
        },
        created_at: claim.created_at,
        updated_at: claim.updated_at,
    }
}

fn claim_response(status: StatusCode, claim: NamespaceClaim) -> Response<Body> {
    json_response(
        status,
        &NamespaceResponse {
            namespace: namespace_contract(claim),
        },
    )
}

fn map_claim_error(user_id: i64, hostname: &Hostname, error: DbError) -> Response<Body> {
    match error {
        DbError::NamespaceAlreadyClaimed { .. } => namespace_unavailable(),
        DbError::ParentNamespaceNotClaimed { .. }
        | DbError::ParentNamespaceOwnedByAnotherUser { .. }
        | DbError::ParentNamespaceReleasing { .. } => parent_namespace_unavailable(),
        DbError::CannotClaimBaseDomain { .. }
        | DbError::NamespaceOutsideBaseDomain { .. }
        | DbError::NamespaceDepthExceeded { .. }
        | DbError::EmptyFqdn
        | DbError::FqdnTooLong
        | DbError::InvalidFqdn { .. } => invalid_hostname(),
        other => {
            tracing::error!(user_id, hostname = %hostname, error = %other, "namespace creation failed");
            service_unavailable()
        }
    }
}

fn json_response(status: StatusCode, value: &impl serde::Serialize) -> Response<Body> {
    let body = match serde_json::to_vec(value) {
        Ok(body) => Body::from(body),
        Err(_) => Body::from(
            r#"{"error":{"code":"service_unavailable","message":"service is unavailable"}}"#,
        ),
    };
    let mut response = Response::new(body);
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
}

fn empty_response(status: StatusCode) -> Response<Body> {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = status;
    response
}

fn management_error(
    status: StatusCode,
    code: ManagementErrorCode,
    message: &'static str,
) -> Response<Body> {
    json_response(
        status,
        &ManagementErrorResponse {
            error: ManagementError {
                code,
                message: message.to_owned(),
            },
        },
    )
}

fn authentication_error() -> Response<Body> {
    let mut response = management_error(
        StatusCode::UNAUTHORIZED,
        ManagementErrorCode::AuthenticationRequired,
        "authentication is required",
    );
    response
        .headers_mut()
        .insert(WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    response
}

fn invalid_request() -> Response<Body> {
    management_error(
        StatusCode::BAD_REQUEST,
        ManagementErrorCode::InvalidRequest,
        "request is invalid",
    )
}

fn invalid_hostname() -> Response<Body> {
    management_error(
        StatusCode::UNPROCESSABLE_ENTITY,
        ManagementErrorCode::InvalidHostname,
        "hostname is not a claimable namespace",
    )
}

fn namespace_unavailable() -> Response<Body> {
    management_error(
        StatusCode::CONFLICT,
        ManagementErrorCode::NamespaceUnavailable,
        "namespace is unavailable",
    )
}

fn parent_namespace_unavailable() -> Response<Body> {
    management_error(
        StatusCode::CONFLICT,
        ManagementErrorCode::ParentNamespaceUnavailable,
        "parent namespace is unavailable",
    )
}

fn namespace_not_found() -> Response<Body> {
    management_error(
        StatusCode::NOT_FOUND,
        ManagementErrorCode::NamespaceNotFound,
        "namespace was not found",
    )
}

fn service_unavailable() -> Response<Body> {
    management_error(
        StatusCode::SERVICE_UNAVAILABLE,
        ManagementErrorCode::ServiceUnavailable,
        "service is unavailable",
    )
}

#[cfg(test)]
mod tests {
    use std::{
        error::Error,
        sync::{Arc, Mutex as StdMutex},
    };

    use futures::future::BoxFuture;
    use http_body_util::BodyExt as _;
    use sink_protocol::{ManagementErrorResponse, NamespaceListResponse, NamespaceResponse};
    use tower::ServiceExt as _;
    use uuid::Uuid;

    use crate::{
        certificates::{CertificateProviderKind, Hostname},
        config::{ConfiguredDomain, ConfiguredDomains},
        namespace_control::{
            NamespaceCertificateError, NamespaceCertificateProvisioner, NamespaceCertificateRequest,
        },
        runtime::{
            admission::{RouteAdmissionError, authorize_hostname_locked},
            broker::StreamBroker,
            claims::ClaimOwner,
            router,
        },
    };

    use super::*;

    #[derive(Debug)]
    struct FakeCertificates {
        status: NamespaceCertificateStatus,
        release_fails: bool,
        provisioned: StdMutex<Vec<String>>,
        released: StdMutex<Vec<String>>,
    }

    impl FakeCertificates {
        fn new(status: NamespaceCertificateStatus) -> Self {
            Self {
                status,
                release_fails: false,
                provisioned: StdMutex::new(Vec::new()),
                released: StdMutex::new(Vec::new()),
            }
        }

        fn failing_release(status: NamespaceCertificateStatus) -> Self {
            Self {
                status,
                release_fails: true,
                provisioned: StdMutex::new(Vec::new()),
                released: StdMutex::new(Vec::new()),
            }
        }

        fn provision_count(&self) -> usize {
            self.provisioned
                .lock()
                .map_or(0, |hostnames| hostnames.len())
        }

        fn release_count(&self) -> usize {
            self.released.lock().map_or(0, |hostnames| hostnames.len())
        }
    }

    impl NamespaceCertificateProvisioner for FakeCertificates {
        fn provision(
            &self,
            request: NamespaceCertificateRequest,
        ) -> BoxFuture<'_, Result<NamespaceCertificateStatus, NamespaceCertificateError>> {
            if let Ok(mut provisioned) = self.provisioned.lock() {
                provisioned.push(request.hostname.to_string());
            }
            let status = self.status;
            Box::pin(async move { Ok(status) })
        }

        fn release(
            &self,
            hostname: Hostname,
            _provider: CertificateProviderKind,
            _now: Timestamp,
        ) -> BoxFuture<'_, Result<(), NamespaceCertificateError>> {
            if let Ok(mut released) = self.released.lock() {
                released.push(hostname.to_string());
            }
            let fails = self.release_fails;
            Box::pin(async move {
                if fails {
                    Err(NamespaceCertificateError)
                } else {
                    Ok(())
                }
            })
        }
    }

    async fn fixture(
        certificates: Arc<FakeCertificates>,
    ) -> Result<
        (
            tempfile::TempDir,
            RuntimeState,
            crate::db::IssuedUser,
            crate::db::IssuedUser,
        ),
        Box<dyn Error>,
    > {
        let directory = tempfile::tempdir()?;
        let database =
            crate::db::Database::open(directory.path().join("management.sqlite3")).await?;
        let alice = database.create_user("alice").await?;
        let bob = database.create_user("bob").await?;
        let domain = ConfiguredDomain::new(
            Hostname::parse("example.test")?,
            2,
            CertificateProviderKind::Cloudflare,
        )?;
        let state = RuntimeState::with_namespace_control(
            database,
            "example.test",
            ConfiguredDomains::new(vec![domain])?,
            certificates,
        )?;
        Ok((directory, state, alice, bob))
    }

    fn request(method: Method, path: &str, token: Option<&str>, body: Body) -> Request {
        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header("host", "connect.example.test");
        if let Some(token) = token {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        builder.body(body).expect("valid test request")
    }

    async fn json<T: serde::de::DeserializeOwned>(
        response: Response<Body>,
    ) -> Result<T, Box<dyn Error>> {
        let body = response.into_body().collect().await?.to_bytes();
        Ok(serde_json::from_slice(&body)?)
    }

    #[tokio::test]
    async fn authenticated_claim_list_and_status_contract_is_idempotent()
    -> Result<(), Box<dyn Error>> {
        let certificates = Arc::new(FakeCertificates::new(NamespaceCertificateStatus::Ready));
        let (_directory, state, alice, bob) = fixture(Arc::clone(&certificates)).await?;
        let app = router(state);
        let body = serde_json::to_vec(&NamespaceClaimRequest {
            hostname: "Cloud.Example.Test.".to_owned(),
        })?;

        let unauthenticated = app
            .clone()
            .oneshot(request(
                Method::POST,
                sink_protocol::NAMESPACE_COLLECTION_PATH,
                None,
                Body::from(body.clone()),
            ))
            .await?;
        assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(unauthenticated.headers()[WWW_AUTHENTICATE], "Bearer");
        let error: ManagementErrorResponse = json(unauthenticated).await?;
        assert_eq!(
            error.error.code,
            ManagementErrorCode::AuthenticationRequired
        );

        let created = app
            .clone()
            .oneshot(request(
                Method::POST,
                sink_protocol::NAMESPACE_COLLECTION_PATH,
                Some(alice.token.expose_secret()),
                Body::from(body.clone()),
            ))
            .await?;
        assert_eq!(created.status(), StatusCode::CREATED);
        let created: NamespaceResponse = json(created).await?;
        assert_eq!(created.namespace.hostname, "cloud.example.test");
        assert_eq!(
            created.namespace.state,
            sink_protocol::NamespaceState::Active
        );

        let idempotent = app
            .clone()
            .oneshot(request(
                Method::POST,
                sink_protocol::NAMESPACE_COLLECTION_PATH,
                Some(alice.token.expose_secret()),
                Body::from(body),
            ))
            .await?;
        assert_eq!(idempotent.status(), StatusCode::OK);
        assert_eq!(certificates.provision_count(), 1);

        let listed = app
            .clone()
            .oneshot(request(
                Method::GET,
                sink_protocol::NAMESPACE_COLLECTION_PATH,
                Some(alice.token.expose_secret()),
                Body::empty(),
            ))
            .await?;
        let listed: NamespaceListResponse = json(listed).await?;
        assert_eq!(listed.namespaces.len(), 1);
        assert_eq!(listed.namespaces[0].hostname, "cloud.example.test");

        let status = app
            .clone()
            .oneshot(request(
                Method::GET,
                "/_sink/api/v1/namespaces/cloud.example.test",
                Some(alice.token.expose_secret()),
                Body::empty(),
            ))
            .await?;
        assert_eq!(status.status(), StatusCode::OK);

        let hidden_from_foreign_user = app
            .oneshot(request(
                Method::GET,
                "/_sink/api/v1/namespaces/cloud.example.test",
                Some(bob.token.expose_secret()),
                Body::empty(),
            ))
            .await?;
        assert_eq!(hidden_from_foreign_user.status(), StatusCode::NOT_FOUND);
        Ok(())
    }

    #[tokio::test]
    async fn hierarchy_reserved_names_and_depth_are_enforced() -> Result<(), Box<dyn Error>> {
        let certificates = Arc::new(FakeCertificates::new(NamespaceCertificateStatus::Ready));
        let (_directory, state, alice, bob) = fixture(certificates).await?;
        let app = router(state);

        for hostname in ["cloud.example.test", "edge.cloud.example.test"] {
            let response = app
                .clone()
                .oneshot(request(
                    Method::POST,
                    sink_protocol::NAMESPACE_COLLECTION_PATH,
                    Some(alice.token.expose_secret()),
                    Body::from(serde_json::to_vec(&NamespaceClaimRequest {
                        hostname: hostname.to_owned(),
                    })?),
                ))
                .await?;
            assert_eq!(response.status(), StatusCode::CREATED, "{hostname}");
        }

        let foreign_child = app
            .clone()
            .oneshot(request(
                Method::POST,
                sink_protocol::NAMESPACE_COLLECTION_PATH,
                Some(bob.token.expose_secret()),
                Body::from(serde_json::to_vec(&NamespaceClaimRequest {
                    hostname: "other.cloud.example.test".to_owned(),
                })?),
            ))
            .await?;
        assert_eq!(foreign_child.status(), StatusCode::CONFLICT);
        let error: ManagementErrorResponse = json(foreign_child).await?;
        assert_eq!(
            error.error.code,
            ManagementErrorCode::ParentNamespaceUnavailable
        );

        for (hostname, expected_code) in [
            ("example.test", ManagementErrorCode::InvalidHostname),
            (
                "connect.example.test",
                ManagementErrorCode::ReservedHostname,
            ),
            (
                "region.edge.cloud.example.test",
                ManagementErrorCode::InvalidHostname,
            ),
        ] {
            let response = app
                .clone()
                .oneshot(request(
                    Method::POST,
                    sink_protocol::NAMESPACE_COLLECTION_PATH,
                    Some(alice.token.expose_secret()),
                    Body::from(serde_json::to_vec(&NamespaceClaimRequest {
                        hostname: hostname.to_owned(),
                    })?),
                ))
                .await?;
            let error: ManagementErrorResponse = json(response).await?;
            assert_eq!(error.error.code, expected_code, "{hostname}");
        }
        Ok(())
    }

    #[tokio::test]
    async fn release_rejects_children_and_directly_covered_route_leases()
    -> Result<(), Box<dyn Error>> {
        let certificates = Arc::new(FakeCertificates::new(NamespaceCertificateStatus::Ready));
        let (_directory, state, alice, _bob) = fixture(Arc::clone(&certificates)).await?;
        let app = router(state.clone());
        for hostname in [
            "cloud.example.test",
            "edge.cloud.example.test",
            "busy.example.test",
        ] {
            let response = app
                .clone()
                .oneshot(request(
                    Method::POST,
                    sink_protocol::NAMESPACE_COLLECTION_PATH,
                    Some(alice.token.expose_secret()),
                    Body::from(serde_json::to_vec(&NamespaceClaimRequest {
                        hostname: hostname.to_owned(),
                    })?),
                ))
                .await?;
            assert_eq!(response.status(), StatusCode::CREATED);
        }

        let parent_release = app
            .clone()
            .oneshot(request(
                Method::DELETE,
                "/_sink/api/v1/namespaces/cloud.example.test",
                Some(alice.token.expose_secret()),
                Body::empty(),
            ))
            .await?;
        assert_eq!(parent_release.status(), StatusCode::CONFLICT);
        let error: ManagementErrorResponse = json(parent_release).await?;
        assert_eq!(error.error.code, ManagementErrorCode::NamespaceHasChildren);

        let authenticated = state
            .database
            .authenticate(alice.token.expose_secret())
            .await?
            .ok_or("alice authentication missing")?;
        let (broker, _requests) = StreamBroker::channel();
        let lease = state
            .claims
            .acquire(
                ClaimOwner {
                    user_id: authenticated.id,
                    session_id: Uuid::new_v4(),
                },
                Hostname::parse("api.busy.example.test")?,
                broker,
                Instant::now(),
            )
            .map_err(|error| format!("route claim failed: {error:?}"))?;
        state
            .claims
            .disconnect(&lease, Instant::now())
            .ok_or("route did not enter reconnect lease")?;

        let busy_release = app
            .clone()
            .oneshot(request(
                Method::DELETE,
                "/_sink/api/v1/namespaces/busy.example.test",
                Some(alice.token.expose_secret()),
                Body::empty(),
            ))
            .await?;
        assert_eq!(busy_release.status(), StatusCode::CONFLICT);
        let error: ManagementErrorResponse = json(busy_release).await?;
        assert_eq!(error.error.code, ManagementErrorCode::NamespaceInUse);

        state.claims.release(&lease);
        for hostname in ["edge.cloud.example.test", "cloud.example.test"] {
            let released = app
                .clone()
                .oneshot(request(
                    Method::DELETE,
                    &format!("/_sink/api/v1/namespaces/{hostname}"),
                    Some(alice.token.expose_secret()),
                    Body::empty(),
                ))
                .await?;
            assert_eq!(released.status(), StatusCode::NO_CONTENT, "{hostname}");
        }
        assert_eq!(certificates.release_count(), 2);
        Ok(())
    }

    #[tokio::test]
    async fn pending_claims_fail_closed_for_route_authorization() -> Result<(), Box<dyn Error>> {
        let certificates = Arc::new(FakeCertificates::new(NamespaceCertificateStatus::Pending));
        let (_directory, state, alice, bob) = fixture(certificates).await?;
        let app = router(state.clone());
        let response = app
            .oneshot(request(
                Method::POST,
                sink_protocol::NAMESPACE_COLLECTION_PATH,
                Some(alice.token.expose_secret()),
                Body::from(serde_json::to_vec(&NamespaceClaimRequest {
                    hostname: "cloud.example.test".to_owned(),
                })?),
            ))
            .await?;
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let response: NamespaceResponse = json(response).await?;
        assert_eq!(
            response.namespace.state,
            sink_protocol::NamespaceState::Pending
        );

        let alice = state
            .database
            .authenticate(alice.token.expose_secret())
            .await?
            .ok_or("alice authentication missing")?;
        let bob = state
            .database
            .authenticate(bob.token.expose_secret())
            .await?
            .ok_or("bob authentication missing")?;
        let _admission = state.admission_gate.lock().await;
        assert_eq!(
            authorize_hostname_locked(&state, alice.id, &Hostname::parse("cloud.example.test")?)
                .await,
            Err(RouteAdmissionError::NotReady)
        );
        assert_eq!(
            authorize_hostname_locked(
                &state,
                alice.id,
                &Hostname::parse("api.cloud.example.test")?
            )
            .await,
            Err(RouteAdmissionError::NotReady)
        );
        assert_eq!(
            authorize_hostname_locked(&state, bob.id, &Hostname::parse("cloud.example.test")?)
                .await,
            Err(RouteAdmissionError::Unauthorized)
        );
        assert_eq!(
            authorize_hostname_locked(&state, bob.id, &Hostname::parse("free.example.test")?).await,
            Ok(())
        );
        assert_eq!(
            authorize_hostname_locked(&state, bob.id, &Hostname::parse("deep.free.example.test")?)
                .await,
            Err(RouteAdmissionError::Unauthorized)
        );
        Ok(())
    }

    #[tokio::test]
    async fn active_hierarchy_authorizes_only_owner_and_adjacent_children()
    -> Result<(), Box<dyn Error>> {
        let certificates = Arc::new(FakeCertificates::new(NamespaceCertificateStatus::Ready));
        let (_directory, state, alice, bob) = fixture(certificates).await?;
        let app = router(state.clone());
        for hostname in ["cloud.example.test", "edge.cloud.example.test"] {
            let response = app
                .clone()
                .oneshot(request(
                    Method::POST,
                    sink_protocol::NAMESPACE_COLLECTION_PATH,
                    Some(alice.token.expose_secret()),
                    Body::from(serde_json::to_vec(&NamespaceClaimRequest {
                        hostname: hostname.to_owned(),
                    })?),
                ))
                .await?;
            assert_eq!(response.status(), StatusCode::CREATED);
        }
        let alice = state
            .database
            .authenticate(alice.token.expose_secret())
            .await?
            .ok_or("alice authentication missing")?;
        let bob = state
            .database
            .authenticate(bob.token.expose_secret())
            .await?
            .ok_or("bob authentication missing")?;
        let _admission = state.admission_gate.lock().await;

        for hostname in [
            "cloud.example.test",
            "api.cloud.example.test",
            "edge.cloud.example.test",
            "foo.edge.cloud.example.test",
        ] {
            let hostname = Hostname::parse(hostname)?;
            assert_eq!(
                authorize_hostname_locked(&state, alice.id, &hostname).await,
                Ok(()),
                "{hostname}"
            );
            assert_eq!(
                authorize_hostname_locked(&state, bob.id, &hostname).await,
                Err(RouteAdmissionError::Unauthorized),
                "{hostname}"
            );
        }
        assert_eq!(
            authorize_hostname_locked(
                &state,
                alice.id,
                &Hostname::parse("deep.api.cloud.example.test")?
            )
            .await,
            Err(RouteAdmissionError::Unauthorized)
        );
        Ok(())
    }

    #[tokio::test]
    async fn namespace_claim_rejects_foreign_apex_route_but_allows_owner_conversion()
    -> Result<(), Box<dyn Error>> {
        let certificates = Arc::new(FakeCertificates::new(NamespaceCertificateStatus::Ready));
        let (_directory, state, alice, bob) = fixture(certificates).await?;
        let bob_auth = state
            .database
            .authenticate(bob.token.expose_secret())
            .await?
            .ok_or("bob authentication missing")?;
        let (broker, _requests) = StreamBroker::channel();
        state
            .claims
            .acquire(
                ClaimOwner {
                    user_id: bob_auth.id,
                    session_id: Uuid::new_v4(),
                },
                Hostname::parse("taken.example.test")?,
                broker,
                Instant::now(),
            )
            .map_err(|error| format!("route claim failed: {error:?}"))?;
        let app = router(state);
        let body = serde_json::to_vec(&NamespaceClaimRequest {
            hostname: "taken.example.test".to_owned(),
        })?;

        let foreign = app
            .clone()
            .oneshot(request(
                Method::POST,
                sink_protocol::NAMESPACE_COLLECTION_PATH,
                Some(alice.token.expose_secret()),
                Body::from(body.clone()),
            ))
            .await?;
        assert_eq!(foreign.status(), StatusCode::CONFLICT);

        let owner = app
            .oneshot(request(
                Method::POST,
                sink_protocol::NAMESPACE_COLLECTION_PATH,
                Some(bob.token.expose_secret()),
                Body::from(body),
            ))
            .await?;
        assert_eq!(owner.status(), StatusCode::CREATED);
        Ok(())
    }

    #[tokio::test]
    async fn certificate_release_failure_retains_releasing_ownership() -> Result<(), Box<dyn Error>>
    {
        let certificates = Arc::new(FakeCertificates::failing_release(
            NamespaceCertificateStatus::Ready,
        ));
        let (_directory, state, alice, _bob) = fixture(certificates).await?;
        let app = router(state.clone());
        let created = app
            .clone()
            .oneshot(request(
                Method::POST,
                sink_protocol::NAMESPACE_COLLECTION_PATH,
                Some(alice.token.expose_secret()),
                Body::from(serde_json::to_vec(&NamespaceClaimRequest {
                    hostname: "cloud.example.test".to_owned(),
                })?),
            ))
            .await?;
        assert_eq!(created.status(), StatusCode::CREATED);

        let release = app
            .oneshot(request(
                Method::DELETE,
                "/_sink/api/v1/namespaces/cloud.example.test",
                Some(alice.token.expose_secret()),
                Body::empty(),
            ))
            .await?;
        assert_eq!(release.status(), StatusCode::SERVICE_UNAVAILABLE);
        let error: ManagementErrorResponse = json(release).await?;
        assert_eq!(
            error.error.code,
            ManagementErrorCode::CertificateUnavailable
        );
        let retained = state
            .database
            .namespace_claim("cloud.example.test")
            .await?
            .ok_or("releasing claim was deleted")?;
        assert_eq!(retained.state, NamespaceClaimState::Releasing);
        Ok(())
    }
}
