//! Independent supervision for the routes in `sink connect --config <file>`.

use std::{
    future::{Future, pending},
    io,
    num::NonZeroU16,
    time::Duration,
};

use sink_protocol::RejectCode;
use thiserror::Error;
use tokio::{
    sync::broadcast,
    task::{JoinHandle, JoinSet},
    time::timeout,
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::{
    cli::{ConnectArgs, HttpArgs},
    config::{
        ConfigError, ConfigStore, ConnectConfig, ConnectConfigError, ConnectRouteConfig,
        ResolvedConfig,
    },
    dashboard::{DashboardBindError, DashboardPort, DashboardService, production_assets},
    runtime::{
        ConnectionEnd, RequestSummary, RuntimeError, RuntimeHandle, TunnelPhase, TunnelRuntime,
    },
    target::LocalTarget,
};

const INITIAL_RETRY_DELAY: Duration = Duration::from_millis(100);
const MAX_RETRY_DELAY: Duration = Duration::from_secs(2);
const DASHBOARD_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);

/// Load, validate, prepare, and supervise every configured route.
pub async fn run(arguments: ConnectArgs) -> Result<(), MultiConnectError> {
    // Route syntax and semantics are deliberately resolved before credentials,
    // runtime construction, dashboard binding, or task startup.
    let connect = ConnectConfig::load(&arguments.config)?;
    let saved = ConfigStore::platform()?.load()?;
    let resolved = arguments.resolve_config(&saved)?;
    let prepared = prepare_routes(connect, resolved).await?;
    supervise_routes(prepared).await
}

struct PreparedRoute {
    name: String,
    target: LocalTarget,
    runtime: TunnelRuntime,
    handle: RuntimeHandle,
    inspect: bool,
    dashboard_port: Option<NonZeroU16>,
    dashboard: Option<DashboardService>,
}

impl PreparedRoute {
    fn dashboard_binding(&self) -> Option<DashboardPort> {
        self.inspect.then(|| {
            self.dashboard_port
                .map_or(DashboardPort::Automatic, DashboardPort::Explicit)
        })
    }
}

async fn prepare_routes(
    connect: ConnectConfig,
    resolved: ResolvedConfig,
) -> Result<Vec<PreparedRoute>, MultiConnectError> {
    let mut prepared = Vec::with_capacity(connect.routes().len());
    for route in connect.into_routes() {
        let name = route.name.clone();
        let target = route.target.clone();
        let inspect = route.inspect;
        let dashboard_port = route.dashboard_port;
        let arguments = route_http_arguments(route);
        let runtime = TunnelRuntime::from_http(&arguments, resolved.clone()).map_err(|source| {
            MultiConnectError::RouteSetup {
                route: name.clone(),
                source,
            }
        })?;
        let handle = runtime.handle();
        prepared.push(PreparedRoute {
            name,
            target,
            runtime,
            handle,
            inspect,
            dashboard_port,
            dashboard: None,
        });
    }

    // Reserve stable explicit ports first so automatic allocation cannot take
    // one merely because an automatic route appeared earlier in the file.
    for route in &mut prepared {
        let Some(DashboardPort::Explicit(port)) = route.dashboard_binding() else {
            continue;
        };
        route.dashboard = route
            .handle
            .bind_dashboard(production_assets(), DashboardPort::Explicit(port))
            .await
            .map_err(|source| MultiConnectError::DashboardBind {
                route: route.name.clone(),
                source,
            })?;
    }

    for route in &mut prepared {
        if route.dashboard.is_some() || route.dashboard_binding() != Some(DashboardPort::Automatic)
        {
            continue;
        }
        match route
            .handle
            .bind_dashboard(production_assets(), DashboardPort::Automatic)
            .await
        {
            Ok(dashboard) => route.dashboard = dashboard,
            Err(error) => {
                tracing::error!(route = %route.name, %error, "inspection dashboard could not start; route will continue");
            }
        }
    }

    Ok(prepared)
}

fn route_http_arguments(route: ConnectRouteConfig) -> HttpArgs {
    HttpArgs {
        target: route.target,
        url: Some(route.public_url),
        authtoken: None,
        server_addr: None,
        local_tls_insecure: route.local_tls_insecure,
        cors_allow_origin: route.cors_allow_origin,
        cors_allow_credentials: route.cors_allow_credentials,
        allow_plaintext_control: false,
        inspect: route.inspect,
        dashboard_port: route.dashboard_port,
        inspect_request_limit: route.inspect_request_limit,
        inspect_body_limit: route.inspect_body_limit,
    }
}

async fn supervise_routes(prepared: Vec<PreparedRoute>) -> Result<(), MultiConnectError> {
    let shutdown = CancellationToken::new();
    let handles: Vec<_> = prepared.iter().map(|route| route.handle.clone()).collect();
    let mut tasks = JoinSet::new();

    for route in prepared {
        println!("[{}] local target: {}", route.name, route.target);
        if let Some(dashboard) = route.dashboard.as_ref() {
            println!("[{}] inspector dashboard: {}", route.name, dashboard.url());
        }
        tasks.spawn(run_route(route, shutdown.clone()));
    }

    let signal = termination_signal();
    tokio::pin!(signal);
    loop {
        tokio::select! {
            () = &mut signal => {
                eprintln!("shutting down all routes gracefully; send the signal again to force exit");
                begin_shutdown(&handles, &shutdown);
                arm_forced_exit();
                drain_route_tasks(&mut tasks).await;
                return Ok(());
            }
            joined = tasks.join_next() => {
                match joined {
                    Some(Ok(RouteExit::GlobalAuthentication { route, source })) => {
                        begin_shutdown(&handles, &shutdown);
                        drain_route_tasks(&mut tasks).await;
                        return Err(MultiConnectError::GlobalAuthentication { route, source });
                    }
                    Some(Ok(RouteExit::Shutdown { route })) => {
                        tracing::warn!(%route, "route supervisor stopped without a process shutdown");
                    }
                    Some(Err(error)) => {
                        tracing::error!(%error, "route supervisor task failed unexpectedly");
                    }
                    None => return Err(MultiConnectError::AllRoutesStopped),
                }
            }
        }
    }
}

fn begin_shutdown(handles: &[RuntimeHandle], shutdown: &CancellationToken) {
    for handle in handles {
        handle.begin_graceful_shutdown();
    }
    shutdown.cancel();
}

async fn drain_route_tasks(tasks: &mut JoinSet<RouteExit>) {
    while let Some(result) = tasks.join_next().await {
        if let Err(error) = result {
            tracing::error!(%error, "route supervisor task could not be joined cleanly");
        }
    }
}

enum RouteExit {
    Shutdown { route: String },
    GlobalAuthentication { route: String, source: RuntimeError },
}

async fn run_route(mut route: PreparedRoute, shutdown: CancellationToken) -> RouteExit {
    let dashboard_task = route.dashboard.take().map(DashboardTask::start);
    let state_task = tokio::spawn(print_state_changes(
        route.name.clone(),
        route.handle.subscribe_state(),
    ));
    let request_task = tokio::spawn(print_request_summaries(
        route.name.clone(),
        route.handle.subscribe_requests(),
    ));

    let outcome =
        supervise_runtime(&route.name, &mut route.runtime, &route.handle, &shutdown).await;

    stop_output_task(state_task).await;
    stop_output_task(request_task).await;
    if let Some(task) = dashboard_task {
        task.stop().await;
    }
    eprintln!("[{}] state: stopped", route.name);
    outcome
}

async fn supervise_runtime(
    route: &str,
    runtime: &mut TunnelRuntime,
    handle: &RuntimeHandle,
    shutdown: &CancellationToken,
) -> RouteExit {
    let mut backoff = RouteBackoff::default();
    let mut attempt = 0_u32;

    loop {
        if shutdown.is_cancelled() {
            return RouteExit::Shutdown {
                route: route.to_owned(),
            };
        }

        let failure = match runtime.run_one_connection().await {
            Ok(ConnectionEnd::Shutdown) => {
                return RouteExit::Shutdown {
                    route: route.to_owned(),
                };
            }
            Ok(ConnectionEnd::Disconnected) => {
                backoff.reset();
                RuntimeError::TunnelDisconnected
            }
            Err(error) if is_global_authentication_failure(&error) => {
                return RouteExit::GlobalAuthentication {
                    route: route.to_owned(),
                    source: error,
                };
            }
            Err(error) => error,
        };

        let delay = backoff.next_delay(handle.session_id());
        attempt = attempt.saturating_add(1);
        eprintln!(
            "[{route}] state: retrying (attempt {attempt}, retry in {} ms): {failure}",
            delay.as_millis()
        );
        tokio::select! {
            () = shutdown.cancelled() => {
                return RouteExit::Shutdown { route: route.to_owned() };
            }
            () = tokio::time::sleep(delay) => {}
        }
    }
}

/// The protocol provides exact authentication rejection codes after upgrade.
/// HTTP 401/403 are also treated as global authentication failures because a
/// proxy may reject the bearer credential before the protocol handshake.
fn is_global_authentication_failure(error: &RuntimeError) -> bool {
    match error {
        RuntimeError::InvalidAuthenticationToken
        | RuntimeError::Rejected {
            code: RejectCode::AuthenticationFailed | RejectCode::UserDisabled,
        } => true,
        RuntimeError::UpgradeRejected { status } => matches!(
            *status,
            http::StatusCode::UNAUTHORIZED | http::StatusCode::FORBIDDEN
        ),
        _ => false,
    }
}

#[derive(Debug, Default)]
struct RouteBackoff {
    failures: u32,
}

impl RouteBackoff {
    fn reset(&mut self) {
        self.failures = 0;
    }

    fn next_delay(&mut self, session_id: Uuid) -> Duration {
        let exponent = self.failures.min(31);
        self.failures = self.failures.saturating_add(1);

        let ceiling_ms = INITIAL_RETRY_DELAY
            .as_millis()
            .saturating_mul(1_u128 << exponent)
            .min(MAX_RETRY_DELAY.as_millis()) as u64;
        let floor_ms = ceiling_ms / 2;
        let jitter_span = ceiling_ms.saturating_sub(floor_ms).saturating_add(1);
        let jitter = stable_jitter(session_id, exponent) % jitter_span;
        Duration::from_millis(floor_ms + jitter)
    }
}

fn stable_jitter(session_id: Uuid, attempt: u32) -> u64 {
    let mut value = u64::from_le_bytes(session_id.as_bytes()[..8].try_into().unwrap_or([0_u8; 8]))
        ^ u64::from(attempt);
    value ^= value >> 12;
    value ^= value << 25;
    value ^= value >> 27;
    value.wrapping_mul(0x2545_f491_4f6c_dd1d)
}

async fn print_state_changes(
    route: String,
    mut states: tokio::sync::watch::Receiver<crate::runtime::TunnelState>,
) {
    while states.changed().await.is_ok() {
        match &states.borrow_and_update().phase {
            TunnelPhase::Connected(info) => {
                println!("[{route}] state: connected");
                println!("[{route}] public HTTP:  {}", info.public_http_url);
                println!("[{route}] public HTTPS: {}", info.public_https_url);
            }
            TunnelPhase::Reconnecting { .. } => {}
            TunnelPhase::Draining => eprintln!("[{route}] state: draining"),
            TunnelPhase::Stopped => eprintln!("[{route}] state: stopped"),
        }
    }
}

async fn print_request_summaries(
    route: String,
    mut summaries: broadcast::Receiver<RequestSummary>,
) {
    loop {
        match summaries.recv().await {
            Ok(summary) => println!(
                "[{route}] {} {} -> {}  {} ms  in={} B out={} B",
                summary.method,
                summary.path_and_query,
                summary.status.as_u16(),
                summary.duration.as_millis(),
                summary.request_bytes,
                summary.response_bytes
            ),
            Err(broadcast::error::RecvError::Lagged(skipped)) => {
                eprintln!("[{route}] request summary display skipped {skipped} entries");
            }
            Err(broadcast::error::RecvError::Closed) => return,
        }
    }
}

async fn stop_output_task(task: JoinHandle<()>) {
    task.abort();
    let _ = task.await;
}

struct DashboardTask {
    shutdown: CancellationToken,
    task: JoinHandle<()>,
}

impl DashboardTask {
    fn start(service: DashboardService) -> Self {
        let shutdown = CancellationToken::new();
        let run = service.run_until_cancelled(shutdown.clone());
        Self::spawn(shutdown, run)
    }

    fn spawn<F>(shutdown: CancellationToken, run: F) -> Self
    where
        F: Future<Output = io::Result<()>> + Send + 'static,
    {
        let task = tokio::spawn(async move {
            if let Err(error) = run.await {
                tracing::error!(%error, "inspection dashboard stopped unexpectedly; route remains active");
            }
        });
        Self { shutdown, task }
    }

    async fn stop(self) {
        self.shutdown.cancel();
        let mut task = self.task;
        match timeout(DASHBOARD_SHUTDOWN_TIMEOUT, &mut task).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                tracing::error!(%error, "inspection dashboard task could not be joined cleanly");
            }
            Err(_) => {
                tracing::warn!("inspection dashboard exceeded its shutdown deadline");
                task.abort();
                let _ = task.await;
            }
        }
    }
}

fn arm_forced_exit() {
    tokio::spawn(async {
        termination_signal().await;
        eprintln!("forcing immediate exit");
        std::process::exit(130);
    });
}

#[cfg(unix)]
async fn termination_signal() {
    use tokio::signal::unix::{SignalKind, signal};

    let mut terminate = match signal(SignalKind::terminate()) {
        Ok(signal) => signal,
        Err(error) => {
            tracing::error!(%error, "could not install SIGTERM handler");
            pending::<()>().await;
            return;
        }
    };
    tokio::select! {
        result = tokio::signal::ctrl_c() => {
            if let Err(error) = result {
                tracing::error!(%error, "could not listen for Ctrl-C");
                pending::<()>().await;
            }
        }
        _ = terminate.recv() => {}
    }
}

#[cfg(not(unix))]
async fn termination_signal() {
    if let Err(error) = tokio::signal::ctrl_c().await {
        tracing::error!(%error, "could not listen for Ctrl-C");
        pending::<()>().await;
    }
}

#[derive(Debug, Error)]
pub enum MultiConnectError {
    #[error(transparent)]
    RouteConfig(#[from] ConnectConfigError),
    #[error(transparent)]
    ClientConfig(#[from] ConfigError),
    #[error("route `{route}` could not be prepared: {source}")]
    RouteSetup {
        route: String,
        #[source]
        source: RuntimeError,
    },
    #[error("route `{route}` could not bind its explicit inspection dashboard: {source}")]
    DashboardBind {
        route: String,
        #[source]
        source: DashboardBindError,
    },
    #[error("global authentication failed while starting route `{route}`: {source}")]
    GlobalAuthentication {
        route: String,
        #[source]
        source: RuntimeError,
    },
    #[error("all route supervisors stopped unexpectedly")]
    AllRoutesStopped,
}

#[cfg(test)]
mod tests {
    use std::fs;

    use crate::config::{AuthToken, RunOverrides, SavedConfig};

    use super::*;

    fn resolved_config() -> Result<ResolvedConfig, Box<dyn std::error::Error>> {
        Ok(SavedConfig::default().resolve(RunOverrides {
            authtoken: Some(AuthToken::new("multi-connect-test-token")?),
            server_addr: Some("https://connect.example.test".parse()?),
            allow_plaintext_control: false,
        })?)
    }

    #[test]
    fn authentication_classification_is_narrow_and_process_global() {
        for error in [
            RuntimeError::InvalidAuthenticationToken,
            RuntimeError::Rejected {
                code: RejectCode::AuthenticationFailed,
            },
            RuntimeError::Rejected {
                code: RejectCode::UserDisabled,
            },
            RuntimeError::UpgradeRejected {
                status: http::StatusCode::UNAUTHORIZED,
            },
            RuntimeError::UpgradeRejected {
                status: http::StatusCode::FORBIDDEN,
            },
        ] {
            assert!(is_global_authentication_failure(&error), "{error:?}");
        }

        for error in [
            RuntimeError::Rejected {
                code: RejectCode::SubdomainConflict,
            },
            RuntimeError::Rejected {
                code: RejectCode::InvalidSubdomain,
            },
            RuntimeError::Rejected {
                code: RejectCode::UnsupportedProtocol,
            },
            RuntimeError::UpgradeRejected {
                status: http::StatusCode::NOT_FOUND,
            },
            RuntimeError::ProtocolViolation,
        ] {
            assert!(!is_global_authentication_failure(&error), "{error:?}");
        }
    }

    #[test]
    fn route_backoff_is_independent_deterministic_and_capped() {
        let first_session = Uuid::from_u128(0x1234_0000_0000_0000_0000_0000_0000_0000);
        let second_session = Uuid::from_u128(0x5678_0000_0000_0000_0000_0000_0000_0000);
        let mut first = RouteBackoff::default();
        let mut same = RouteBackoff::default();
        let mut second = RouteBackoff::default();

        let first_delays: Vec<_> = (0..20).map(|_| first.next_delay(first_session)).collect();
        let same_delays: Vec<_> = (0..20).map(|_| same.next_delay(first_session)).collect();
        let second_delays: Vec<_> = (0..20).map(|_| second.next_delay(second_session)).collect();

        assert_eq!(first_delays, same_delays);
        assert_ne!(first_delays, second_delays);
        assert!(first_delays.iter().all(|delay| *delay <= MAX_RETRY_DELAY));
        assert!(first_delays[0] >= INITIAL_RETRY_DELAY / 2);
        assert!(first_delays[10] >= MAX_RETRY_DELAY / 2);
    }

    #[tokio::test]
    async fn inspection_disabled_route_has_no_dashboard_binding_plan_or_service()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("routes.toml");
        fs::write(
            &path,
            r#"
[[routes]]
name = "api"
url = "https://api.example.com"
target = "3000"
inspect = false
"#,
        )?;

        let prepared = prepare_routes(ConnectConfig::load(&path)?, resolved_config()?).await?;
        assert_eq!(prepared.len(), 1);
        assert!(!prepared[0].inspect);
        assert_eq!(
            prepared[0].dashboard_binding(),
            None,
            "None is the gate that prevents any bind_dashboard call"
        );
        assert!(prepared[0].dashboard.is_none());
        assert!(prepared[0].handle.inspection_store().is_none());
        Ok(())
    }

    #[tokio::test]
    async fn automatic_inspectors_bind_distinct_ports_and_own_distinct_stores()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("routes.toml");
        fs::write(
            &path,
            r#"
[[routes]]
name = "api"
url = "https://api.example.com"
target = "3000"

[[routes]]
name = "events"
url = "https://events.example.com"
target = "6001"
"#,
        )?;

        let prepared = prepare_routes(ConnectConfig::load(&path)?, resolved_config()?).await?;
        let first_dashboard = prepared[0]
            .dashboard
            .as_ref()
            .ok_or("first dashboard was not bound")?;
        let second_dashboard = prepared[1]
            .dashboard
            .as_ref()
            .ok_or("second dashboard was not bound")?;
        assert_ne!(
            first_dashboard.address().port(),
            second_dashboard.address().port()
        );

        let first_store = prepared[0]
            .handle
            .inspection_store()
            .ok_or("first inspection store is missing")?;
        let second_store = prepared[1]
            .handle
            .inspection_store()
            .ok_or("second inspection store is missing")?;
        assert_eq!(first_store.limits().transaction_limit(), 100);
        assert_eq!(second_store.limits().transaction_limit(), 100);
        assert!(first_store.list_ids_newest_first().is_empty());
        assert!(second_store.list_ids_newest_first().is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn occupied_explicit_inspector_port_fails_before_route_tasks_start()
    -> Result<(), Box<dyn std::error::Error>> {
        let occupied = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let port = occupied.local_addr()?.port();
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("routes.toml");
        fs::write(
            &path,
            format!(
                r#"
[[routes]]
name = "api"
url = "https://api.example.com"
target = "3000"
dashboard_port = {port}
"#
            ),
        )?;

        let result = prepare_routes(ConnectConfig::load(&path)?, resolved_config()?).await;
        assert!(matches!(
            result,
            Err(MultiConnectError::DashboardBind {
                source: DashboardBindError::ExplicitAddressInUse { address, .. },
                ..
            }) if address.port() == port
        ));
        Ok(())
    }
}
