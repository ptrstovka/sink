use std::time::Instant;

use axum::extract::ws::{Message, WebSocket};
use sink_protocol::{
    ClientHello, HandshakeError, MAX_HANDSHAKE_BYTES, MessageIo, RejectCode, ServerHello,
    SessionAccepted, SessionRejected,
};
use tokio::time::{MissedTickBehavior, interval, sleep_until};

use crate::db::AuthenticatedUser;

use super::{
    AUTHENTICATION_CHECK_INTERVAL, RuntimeState,
    broker::{DriverExit, StreamBroker, drive_yamux},
    claims::{ClaimError, ClaimLease, ClaimOwner, RECONNECT_GRACE},
    host::requested_subdomain,
    websocket::AxumMessageAdapter,
};

pub(crate) async fn run_control_socket(
    mut socket: WebSocket,
    state: RuntimeState,
    user: AuthenticatedUser,
) {
    let hello = match receive_client_hello(&mut socket).await {
        Ok(Some(hello)) => hello,
        Ok(None) => return,
        Err(rejection) => {
            send_rejection(&mut socket, rejection).await;
            return;
        }
    };

    if state.is_shutting_down() {
        send_rejection(
            &mut socket,
            SessionRejected::transient(RejectCode::ServerUnavailable, "server is shutting down"),
        )
        .await;
        return;
    }

    let requested = match hello.requested_hostname.as_deref() {
        Some(hostname) => match requested_subdomain(hostname, &state.public_base_domain) {
            Some(subdomain) => Some(subdomain),
            None => {
                send_rejection(
                    &mut socket,
                    SessionRejected::permanent(
                        RejectCode::InvalidSubdomain,
                        "requested hostname is invalid",
                    ),
                )
                .await;
                return;
            }
        },
        None => None,
    };

    let (broker, requests) = StreamBroker::channel();
    let liveness = broker.liveness();
    liveness.set_client_version(&hello.client_version);
    let owner = ClaimOwner {
        user_id: user.id,
        session_id: hello.session_id,
    };
    let lease = match state
        .claims
        .acquire(owner, requested.clone(), broker.clone(), Instant::now())
    {
        Ok(lease) => lease,
        Err(ClaimError::Conflict(conflict)) => {
            let incumbent_client_version = conflict
                .liveness
                .client_version
                .as_deref()
                .unwrap_or("<unknown>");
            let incumbent_last_inbound_ago_ms = conflict
                .liveness
                .last_inbound_ago
                .map(|duration| duration.as_millis());
            let incumbent_last_inbound_kind = conflict
                .liveness
                .last_inbound_kind
                .map_or("<none>", |kind| kind.as_str());
            let incumbent_last_ping_sent_ago_ms = conflict
                .liveness
                .last_ping_sent_ago
                .map(|duration| duration.as_millis());
            let incumbent_last_pong_received_ago_ms = conflict
                .liveness
                .last_pong_received_ago
                .map(|duration| duration.as_millis());
            tracing::warn!(
                user_id = user.id,
                session_id = %hello.session_id,
                client_version = hello.client_version,
                requested_subdomain = requested.as_ref().map_or("<generated>", |value| value.as_str()),
                incumbent_subdomain = %conflict.subdomain,
                incumbent_user_id = conflict.owner.user_id,
                incumbent_session_id = %conflict.owner.session_id,
                incumbent_status = conflict.status.as_str(),
                incumbent_broker_available = conflict.broker_available,
                incumbent_client_version,
                incumbent_connected_for_ms = conflict.liveness.connected_for.as_millis(),
                incumbent_last_inbound_ago_ms = ?incumbent_last_inbound_ago_ms,
                incumbent_last_inbound_kind,
                incumbent_last_ping_sent_ago_ms = ?incumbent_last_ping_sent_ago_ms,
                incumbent_last_pong_received_ago_ms = ?incumbent_last_pong_received_ago_ms,
                incumbent_heartbeat_pings_sent = conflict.liveness.heartbeat_pings_sent,
                incumbent_heartbeat_pongs_received = conflict.liveness.heartbeat_pongs_received,
                incumbent_heartbeat_timeouts = conflict.liveness.heartbeat_timeouts,
                incumbent_binary_messages_received = conflict.liveness.binary_messages_received,
                incumbent_public_stream_requests = conflict.liveness.public_stream_requests,
                "tunnel hostname claim conflicted"
            );
            send_rejection(
                &mut socket,
                SessionRejected::transient(
                    RejectCode::SubdomainConflict,
                    "requested hostname is already in use",
                ),
            )
            .await;
            return;
        }
        Err(ClaimError::GenerationExhausted) => {
            tracing::error!("could not allocate a generated tunnel hostname");
            send_rejection(
                &mut socket,
                SessionRejected::transient(
                    RejectCode::ServerUnavailable,
                    "server could not allocate a tunnel hostname",
                ),
            )
            .await;
            return;
        }
    };

    let hostname = format!("{}.{}", lease.subdomain, state.public_base_domain);
    let accepted = ServerHello::Accepted(SessionAccepted::new(
        hello.session_id,
        lease.subdomain.clone(),
        format!("http://{hostname}"),
        format!("https://{hostname}"),
        RECONNECT_GRACE.as_secs(),
    ));
    if send_server_hello(&mut socket, &accepted).await.is_err() {
        tracing::warn!(
            user_id = user.id,
            session_id = %hello.session_id,
            client_version = hello.client_version,
            subdomain = %lease.subdomain,
            "control link was lost while accepting the tunnel"
        );
        disconnect_and_watch_grace(&state, &lease, &user);
        return;
    }

    tracing::info!(
        user_id = user.id,
        session_id = %hello.session_id,
        client_version = hello.client_version,
        subdomain = %lease.subdomain,
        "tunnel connected"
    );

    let (adapter, clean_close) = AxumMessageAdapter::new(socket, liveness);
    let io = MessageIo::new(adapter);
    let driver = drive_yamux(io, requests);
    tokio::pin!(driver);
    let authentication_watch = watch_authentication(state.database.clone(), user.clone());
    tokio::pin!(authentication_watch);
    let mut shutdown = state.subscribe_shutdown();

    let exit = loop {
        tokio::select! {
            driver_exit = &mut driver => break SessionExit::Driver(driver_exit),
            authentication_exit = &mut authentication_watch => break authentication_exit,
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break SessionExit::ServerShutdown;
                }
            }
        }
    };

    let final_liveness = broker.liveness_snapshot(Instant::now());
    match exit {
        SessionExit::Driver(DriverExit::TransportError) if !clean_close.received() => {
            disconnect_and_watch_grace(&state, &lease, &user);
            tracing::warn!(
                user_id = user.id,
                session_id = %hello.session_id,
                client_version = hello.client_version,
                subdomain = %lease.subdomain,
                driver_exit = ?DriverExit::TransportError,
                control_liveness = ?final_liveness,
                "tunnel disconnected unexpectedly; claim retained for reconnect grace"
            );
        }
        SessionExit::Driver(DriverExit::Replaced) => {
            state.claims.release(&lease);
            tracing::info!(
                user_id = user.id,
                session_id = %hello.session_id,
                client_version = hello.client_version,
                subdomain = %lease.subdomain,
                driver_exit = ?DriverExit::Replaced,
                control_liveness = ?final_liveness,
                "tunnel control link replaced by reconnect"
            );
        }
        SessionExit::Revoked => {
            state.claims.release(&lease);
            broker.shutdown();
            tracing::warn!(
                user_id = user.id,
                session_id = %hello.session_id,
                client_version = hello.client_version,
                subdomain = %lease.subdomain,
                control_liveness = ?final_liveness,
                "tunnel authorization was revoked"
            );
        }
        SessionExit::AuthenticationCheckFailed | SessionExit::ServerShutdown => {
            state.claims.release(&lease);
            broker.shutdown();
            tracing::info!(
                user_id = user.id,
                session_id = %hello.session_id,
                client_version = hello.client_version,
                subdomain = %lease.subdomain,
                server_close_reason = ?exit,
                control_liveness = ?final_liveness,
                "tunnel closed by server"
            );
        }
        SessionExit::Driver(driver_exit) => {
            state.claims.release(&lease);
            tracing::info!(
                user_id = user.id,
                session_id = %hello.session_id,
                client_version = hello.client_version,
                subdomain = %lease.subdomain,
                ?driver_exit,
                control_liveness = ?final_liveness,
                "tunnel closed"
            );
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum SessionExit {
    Driver(DriverExit),
    Revoked,
    AuthenticationCheckFailed,
    ServerShutdown,
}

async fn watch_authentication(
    database: crate::db::Database,
    user: AuthenticatedUser,
) -> SessionExit {
    let mut authentication_check = interval(AUTHENTICATION_CHECK_INTERVAL);
    authentication_check.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        authentication_check.tick().await;
        match database.authentication_state(user.id).await {
            Ok(Some(authentication)) if authentication.still_authorizes(&user) => {}
            Ok(_) => return SessionExit::Revoked,
            Err(error) => {
                tracing::error!(
                    user_id = user.id,
                    %error,
                    "authentication state check failed; closing tunnel"
                );
                return SessionExit::AuthenticationCheckFailed;
            }
        }
    }
}

async fn receive_client_hello(
    socket: &mut WebSocket,
) -> Result<Option<ClientHello>, SessionRejected> {
    loop {
        let message = match socket.recv().await {
            Some(Ok(message)) => message,
            Some(Err(_)) | None => return Ok(None),
        };
        let text = match message {
            Message::Text(text) => text,
            Message::Ping(_) | Message::Pong(_) => continue,
            Message::Close(_) => return Ok(None),
            Message::Binary(_) => {
                return Err(SessionRejected::permanent(
                    RejectCode::InvalidRequest,
                    "first control text message must be a client hello",
                ));
            }
        };
        if text.len() > MAX_HANDSHAKE_BYTES {
            return Err(SessionRejected::permanent(
                RejectCode::InvalidRequest,
                "client hello exceeds the handshake limit",
            ));
        }
        let hello: ClientHello = serde_json::from_slice(text.as_bytes()).map_err(|_| {
            SessionRejected::permanent(RejectCode::InvalidRequest, "client hello is invalid")
        })?;
        hello.validate().map_err(handshake_rejection)?;
        return Ok(Some(hello));
    }
}

fn handshake_rejection(error: HandshakeError) -> SessionRejected {
    match error {
        HandshakeError::UnsupportedVersion { .. } => SessionRejected::permanent(
            RejectCode::UnsupportedProtocol,
            "client protocol version is unsupported",
        ),
        HandshakeError::InvalidRequestedHostname => SessionRejected::permanent(
            RejectCode::InvalidSubdomain,
            "requested hostname is invalid",
        ),
        HandshakeError::NilSessionId | HandshakeError::MissingClientVersion => {
            SessionRejected::permanent(RejectCode::InvalidRequest, "client hello is invalid")
        }
    }
}

async fn send_rejection(socket: &mut WebSocket, rejection: SessionRejected) {
    let _ = send_server_hello(socket, &ServerHello::Rejected(rejection)).await;
    let _ = socket.send(Message::Close(None)).await;
}

async fn send_server_hello(socket: &mut WebSocket, hello: &ServerHello) -> Result<(), ()> {
    let json = serde_json::to_string(hello).map_err(|_| ())?;
    socket
        .send(Message::Text(json.into()))
        .await
        .map_err(|_| ())
}

fn disconnect_and_watch_grace(state: &RuntimeState, lease: &ClaimLease, user: &AuthenticatedUser) {
    let Some(deadline) = state.claims.disconnect(lease, Instant::now()) else {
        return;
    };
    let state = state.clone();
    let lease = lease.clone();
    let user = user.clone();
    tokio::spawn(async move {
        let deadline = sleep_until(deadline.into());
        tokio::pin!(deadline);
        let authentication_watch = watch_authentication(state.database.clone(), user);
        tokio::pin!(authentication_watch);
        tokio::select! {
            () = &mut deadline => {
                state.claims.expire(Instant::now());
            }
            _ = &mut authentication_watch => {
                state.claims.release(&lease);
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use std::{error::Error, time::Duration};

    use super::*;
    use crate::db::Database;

    #[tokio::test]
    async fn authentication_snapshot_detects_rotation_and_disablement() -> Result<(), Box<dyn Error>>
    {
        let directory = tempfile::tempdir()?;
        let database = Database::open(directory.path().join("runtime.sqlite3")).await?;
        let issued = database.create_user("runtime-test").await?;
        let authenticated = database
            .authenticate(issued.token.expose_secret())
            .await?
            .ok_or("issued credential did not authenticate")?;

        let current = database
            .authentication_state(authenticated.id)
            .await?
            .ok_or("authentication state missing")?;
        assert!(current.still_authorizes(&authenticated));

        let rotated_user = database.rotate_token("runtime-test").await?;
        let rotated = database
            .authentication_state(authenticated.id)
            .await?
            .ok_or("rotated authentication state missing")?;
        assert!(!rotated.still_authorizes(&authenticated));

        let new_auth = database
            .authenticate(rotated_user.token.expose_secret())
            .await?
            .ok_or("rotated credential did not authenticate")?;
        database.disable_user("runtime-test").await?;
        let watcher_exit = tokio::time::timeout(
            Duration::from_secs(1),
            watch_authentication(database.clone(), new_auth),
        )
        .await?;
        assert!(matches!(watcher_exit, SessionExit::Revoked));
        let disabled = database
            .authentication_state(authenticated.id)
            .await?
            .ok_or("disabled authentication state missing")?;
        assert!(!disabled.enabled);
        assert_eq!(AUTHENTICATION_CHECK_INTERVAL, Duration::from_millis(250));
        Ok(())
    }
}
