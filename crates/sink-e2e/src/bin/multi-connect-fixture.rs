//! Test-only entry point for exercising the public multi-connect supervisor.

use std::{env, error::Error, io, path::PathBuf};

use sink_client::{
    cli::ConnectArgs,
    config::{AuthToken, ControlServerAddr},
};

type AppError = Box<dyn Error + Send + Sync>;

#[tokio::main]
async fn main() -> Result<(), AppError> {
    let config = required_path("SINK_E2E_CONNECT_CONFIG")?;
    let authtoken = AuthToken::new(required("SINK_E2E_AUTHTOKEN")?)?;
    let server_addr = required("SINK_E2E_SERVER_ADDR")?.parse::<ControlServerAddr>()?;

    sink_client::multi_connect::run(ConnectArgs {
        config,
        authtoken: Some(authtoken),
        server_addr: Some(server_addr),
        allow_plaintext_control: true,
    })
    .await?;
    Ok(())
}

fn required(name: &'static str) -> Result<String, io::Error> {
    env::var(name).map_err(|_| io::Error::other(format!("{name} is required")))
}

fn required_path(name: &'static str) -> Result<PathBuf, io::Error> {
    required(name).map(PathBuf::from)
}
