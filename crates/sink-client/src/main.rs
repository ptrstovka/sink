use std::{error::Error, future::Future, future::pending, io, process::ExitCode};

use clap::Parser as _;
use sink_client::{
    cli::{Cli, ConfigField, SinkCommand},
    config::ConfigStore,
    dashboard::{DashboardPort, DashboardService, production_assets},
    runtime::{RequestSummary, TunnelPhase, TunnelRuntime},
};
use tokio::time::{Duration, timeout};
use tokio::{sync::broadcast, task::JoinHandle};
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;

type BoxError = Box<dyn Error + Send + Sync>;

#[tokio::main]
async fn main() -> ExitCode {
    if let Err(error) = run().await {
        eprintln!("error: {error}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

async fn run() -> Result<(), BoxError> {
    initialize_tracing()?;
    let cli = Cli::parse();
    match cli.command {
        SinkCommand::Config(arguments) => {
            let field = arguments.command.persist(&ConfigStore::platform()?)?;
            match field {
                ConfigField::AuthToken => println!("authentication token saved"),
                ConfigField::ServerAddress => println!("server address saved"),
            }
            Ok(())
        }
        SinkCommand::Http(arguments) => run_tunnel(*arguments).await,
        SinkCommand::Version => {
            println!("sink {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
    }
}

async fn run_tunnel(arguments: sink_client::cli::HttpArgs) -> Result<(), BoxError> {
    let store = ConfigStore::platform()?;
    let saved = store.load()?;
    let resolved = arguments.resolve_config(&saved)?;
    let runtime = TunnelRuntime::from_http(&arguments, resolved)?;
    let handle = runtime.handle();

    let dashboard_port = arguments
        .dashboard_port
        .map_or(DashboardPort::Automatic, DashboardPort::Explicit);
    let dashboard = dashboard_bind_result(
        arguments.dashboard_port.is_some(),
        handle
            .bind_dashboard(production_assets(), dashboard_port)
            .await,
    )?;
    let dashboard_task = dashboard.map(|service| {
        println!("inspector dashboard: {}", service.url());
        DashboardTask::start(service)
    });

    println!("local target: {}", arguments.target);
    let state_task = tokio::spawn(print_state_changes(handle.subscribe_state()));
    let request_task = tokio::spawn(print_request_summaries(handle.subscribe_requests()));

    let run = runtime.run();
    tokio::pin!(run);
    let result = tokio::select! {
        result = &mut run => result,
        () = termination_signal() => {
            eprintln!("shutting down gracefully; send the signal again to force exit");
            handle.begin_graceful_shutdown();
            arm_forced_exit();
            run.await
        }
    };

    stop_output_task(state_task).await;
    stop_output_task(request_task).await;
    if let Some(task) = dashboard_task {
        task.stop().await;
    }
    result.map_err(Into::into)
}

fn dashboard_bind_result(
    explicit_port: bool,
    result: Result<Option<DashboardService>, sink_client::dashboard::DashboardBindError>,
) -> Result<Option<DashboardService>, sink_client::dashboard::DashboardBindError> {
    match result {
        Err(error) if !explicit_port => {
            tracing::error!(%error, "inspection dashboard could not start; tunnel will continue");
            Ok(None)
        }
        result => result,
    }
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
                tracing::error!(%error, "inspection dashboard stopped unexpectedly; tunnel remains active");
            }
        });
        Self { shutdown, task }
    }

    async fn stop(self) {
        self.shutdown.cancel();
        let mut task = self.task;
        match timeout(Duration::from_secs(2), &mut task).await {
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

async fn print_state_changes(
    mut states: tokio::sync::watch::Receiver<sink_client::runtime::TunnelState>,
) {
    while states.changed().await.is_ok() {
        match &states.borrow_and_update().phase {
            TunnelPhase::Connected(info) => {
                println!("state: connected");
                println!("public HTTP:  {}", info.public_http_url);
                println!("public HTTPS: {}", info.public_https_url);
            }
            TunnelPhase::Reconnecting {
                attempt,
                retry_in,
                last_error,
            } => {
                if *attempt > 0 {
                    let delay_ms = retry_in.map_or(0, |delay| delay.as_millis());
                    eprintln!(
                        "state: reconnecting (attempt {attempt}, retry in {delay_ms} ms): {}",
                        last_error.as_deref().unwrap_or("connection interrupted")
                    );
                }
            }
            TunnelPhase::Draining => eprintln!("state: draining"),
            TunnelPhase::Stopped => eprintln!("state: stopped"),
        }
    }
}

async fn print_request_summaries(mut summaries: broadcast::Receiver<RequestSummary>) {
    loop {
        match summaries.recv().await {
            Ok(summary) => println!(
                "{} {} -> {}  {} ms  in={} B out={} B",
                summary.method,
                summary.path_and_query,
                summary.status.as_u16(),
                summary.duration.as_millis(),
                summary.request_bytes,
                summary.response_bytes
            ),
            Err(broadcast::error::RecvError::Lagged(skipped)) => {
                eprintln!("request summary display skipped {skipped} entries");
            }
            Err(broadcast::error::RecvError::Closed) => return,
        }
    }
}

async fn stop_output_task(task: JoinHandle<()>) {
    task.abort();
    let _ = task.await;
}

fn initialize_tracing() -> Result<(), BoxError> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(io::stderr)
        .try_init()?;
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn dashboard_failure_does_not_cancel_tunnel_lifecycle() {
        let tunnel_shutdown = CancellationToken::new();
        let dashboard_shutdown = CancellationToken::new();
        let task = DashboardTask::spawn(dashboard_shutdown, async {
            Err(io::Error::other("simulated dashboard task failure"))
        });

        task.stop().await;
        assert!(!tunnel_shutdown.is_cancelled());
    }

    #[test]
    fn automatic_bind_failure_is_isolated_but_explicit_failure_remains_actionable() {
        let automatic = dashboard_bind_result(
            false,
            Err(sink_client::dashboard::DashboardBindError::AutomaticPortsExhausted),
        );
        assert!(matches!(automatic, Ok(None)));

        let explicit = dashboard_bind_result(
            true,
            Err(sink_client::dashboard::DashboardBindError::AutomaticPortsExhausted),
        );
        assert!(matches!(
            explicit,
            Err(sink_client::dashboard::DashboardBindError::AutomaticPortsExhausted)
        ));
    }
}

#[cfg(not(unix))]
async fn termination_signal() {
    if let Err(error) = tokio::signal::ctrl_c().await {
        tracing::error!(%error, "could not listen for Ctrl-C");
        pending::<()>().await;
    }
}
