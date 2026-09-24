use std::{
    error::Error,
    future::pending,
    io,
    process::ExitCode,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use clap::Parser as _;
use sink_server::{
    admin::{self, Cli, ServerCommand},
    certificates::{
        CertificateIndexReloader, CertificateManager, CloudflareAcmeProvider,
        CloudflareDnsProvider, InstantAcmeClient, IssuancePolicy, ReqwestCloudflareHttpClient,
        SecretBytes, SqliteCertificateStorage, Timestamp,
    },
    config::{CertificateBackendConfig, EnabledCertificateBackendConfig, ServeConfig},
    db::Database,
    namespace_control::{DeferredNamespaceCertificates, ManagedNamespaceCertificates},
    runtime::{
        self, CertificateLifecycle, DynamicTlsCertificateResolver, RuntimeSniAuthorization,
        RuntimeState, TlsListener,
    },
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
        ServerCommand::Version => {
            println!("sink-server {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
    }
}

async fn serve(arguments: sink_server::config::ServeArgs) -> Result<(), BoxError> {
    let config = ServeConfig::resolve(&arguments)?;
    initialize_tracing(&config.log_level)?;
    let database = Database::open(&config.sqlite_path).await?;
    let http_listener = TcpListener::bind(config.http_listen_address).await?;
    let result = match config.certificate_backend.clone() {
        CertificateBackendConfig::Disabled => {
            serve_plain_http(&config, database.clone(), http_listener).await
        }
        CertificateBackendConfig::Enabled(backend) => {
            let Some(https_address) = config.https_listen_address else {
                return Err(io::Error::other(
                    "enabled certificate backend has no HTTPS listener address",
                )
                .into());
            };
            let https_listener = TcpListener::bind(https_address).await?;
            serve_http_and_https(
                &config,
                backend,
                database.clone(),
                http_listener,
                https_listener,
            )
            .await
        }
    };
    database.close().await;
    result?;
    tracing::info!("sink server stopped");
    Ok(())
}

async fn serve_plain_http(
    config: &ServeConfig,
    database: Database,
    listener: TcpListener,
) -> Result<(), BoxError> {
    let state = RuntimeState::with_namespace_control(
        database,
        &config.public_base_domain,
        config.domains.clone(),
        Arc::new(DeferredNamespaceCertificates),
    )?;

    tracing::info!(
        http_listen_address = %config.http_listen_address,
        public_base_domain = %config.public_base_domain,
        sqlite_path = %config.sqlite_path.display(),
        certificate_backend = "disabled",
        "sink server ready"
    );
    runtime::serve(
        listener,
        state,
        first_termination_signal(),
        GRACEFUL_DRAIN_TIMEOUT,
    )
    .await?;
    Ok(())
}

async fn serve_http_and_https(
    config: &ServeConfig,
    backend: EnabledCertificateBackendConfig,
    database: Database,
    http_listener: TcpListener,
    https_listener: TcpListener,
) -> Result<(), BoxError> {
    let storage = Arc::new(SqliteCertificateStorage::connect(&config.sqlite_path).await?);
    let http = Arc::new(ReqwestCloudflareHttpClient::new()?);
    let dns = Arc::new(CloudflareDnsProvider::new(
        http,
        backend.cloudflare_zone_id,
        backend.cloudflare_zone_hostname,
        SecretBytes::new(backend.cloudflare_api_token.expose_secret().to_vec()),
    )?);
    let acme = Arc::new(InstantAcmeClient::new(
        backend.acme_directory_url,
        vec![backend.acme_contact],
    )?);
    let provider = Arc::new(CloudflareAcmeProvider::new(acme, dns));
    let manager =
        CertificateManager::new(provider.clone(), storage.clone(), IssuancePolicy::default());
    let now = now_timestamp();
    let reconciled = manager.reconcile_after_restart(now).await?;
    tracing::info!(
        reconciled_orders = reconciled,
        "certificate startup reconciliation complete"
    );

    let authorization = Arc::new(RuntimeSniAuthorization::new(
        config.domains.as_slice()[0].hostname.clone(),
    ));
    let crypto_provider = runtime::default_crypto_provider();
    let resolver = Arc::new(DynamicTlsCertificateResolver::new(
        storage.clone(),
        authorization.clone(),
        crypto_provider.clone(),
    ));
    let reloader: Arc<dyn CertificateIndexReloader> = resolver.clone();
    runtime::provision_base_certificates(&manager, &storage, &config.domains, &reloader, now)
        .await?;

    let certificates = Arc::new(ManagedNamespaceCertificates::from_manager(
        manager.clone(),
        storage.clone(),
        reloader.clone(),
    ));
    let state = RuntimeState::with_namespace_control(
        database,
        &config.public_base_domain,
        config.domains.clone(),
        certificates,
    )?;
    state.refresh_sni_namespace_boundaries().await?;
    state.attach_sni_authorization(&authorization)?;

    let tls_config = runtime::build_tls_server_config(resolver, crypto_provider)?;
    let tls_listener = TlsListener::new(https_listener, tls_config);
    let lifecycle = CertificateLifecycle::new(manager, storage.clone(), reloader, state.clone());
    let mut lifecycle_task = tokio::spawn(lifecycle.run());

    tracing::info!(
        http_listen_address = %config.http_listen_address,
        https_listen_address = ?config.https_listen_address,
        public_base_domain = %config.public_base_domain,
        sqlite_path = %config.sqlite_path.display(),
        certificate_backend = "cloudflare-acme",
        "sink server ready"
    );
    let serve_result = runtime::serve_http_and_https(
        http_listener,
        tls_listener,
        state,
        first_termination_signal(),
        GRACEFUL_DRAIN_TIMEOUT,
    )
    .await;
    let lifecycle_result = tokio::time::timeout(GRACEFUL_DRAIN_TIMEOUT, &mut lifecycle_task).await;
    if lifecycle_result.is_err() {
        lifecycle_task.abort();
        let _ = lifecycle_task.await;
    }
    storage.close().await;
    serve_result?;
    match lifecycle_result {
        Ok(joined) => joined?,
        Err(_) => {
            return Err(io::Error::other("certificate lifecycle shutdown timed out").into());
        }
    }
    Ok(())
}

fn now_timestamp() -> Timestamp {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    Timestamp::from_unix_seconds(seconds)
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
