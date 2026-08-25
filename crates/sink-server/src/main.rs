use std::{error::Error, future::pending, io, process::ExitCode, time::Duration};

use clap::Parser as _;
use sink_server::{
    admin::{self, Cli, ServerCommand},
    config::ServeConfig,
    db::Database,
    runtime::{self, RuntimeState},
};
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

const GRACEFUL_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);
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
    let cli = Cli::parse();
    match cli.command {
        ServerCommand::User(arguments) => {
            let output = admin::execute(arguments).await?;
            output.write_terminal(io::stdout().lock())?;
            Ok(())
        }
        ServerCommand::Serve(arguments) => serve(arguments).await,
    }
}

async fn serve(arguments: sink_server::config::ServeArgs) -> Result<(), BoxError> {
    let config = ServeConfig::resolve(&arguments)?;
    initialize_tracing(&config.log_level)?;
    let database = Database::open(&config.sqlite_path).await?;
    let listener = TcpListener::bind(config.listen_address).await?;
    let state = RuntimeState::new(database.clone(), &config.public_base_domain)?;

    tracing::info!(
        listen_address = %config.listen_address,
        public_base_domain = %config.public_base_domain,
        sqlite_path = %config.sqlite_path.display(),
        "sink server starting"
    );
    let result = runtime::serve(
        listener,
        state,
        first_termination_signal(),
        GRACEFUL_DRAIN_TIMEOUT,
    )
    .await;
    database.close().await;
    result?;
    tracing::info!("sink server stopped");
    Ok(())
}

fn initialize_tracing(filter: &str) -> Result<(), BoxError> {
    let filter = EnvFilter::try_new(filter)?;
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(io::stderr)
        .try_init()?;
    Ok(())
}

async fn first_termination_signal() {
    termination_signal().await;
    tracing::info!("shutdown requested; send the signal again to force exit");
    arm_forced_exit();
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
