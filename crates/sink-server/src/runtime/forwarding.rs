use std::{
    net::IpAddr,
    str::FromStr as _,
    time::{Duration, Instant},
};

use axum::body::Body;
use http::{
    HeaderMap, HeaderValue, Request, Response, StatusCode,
    header::{
        CONNECTION, FORWARDED, HeaderName, PROXY_AUTHENTICATE, PROXY_AUTHORIZATION, TE, TRAILER,
        TRANSFER_ENCODING, UPGRADE,
    },
};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use thiserror::Error;
use tokio_util::compat::FuturesAsyncReadCompatExt as _;

use super::broker::{BrokerError, StreamBroker};

const X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");
const X_FORWARDED_HOST: HeaderName = HeaderName::from_static("x-forwarded-host");
const X_FORWARDED_PROTO: HeaderName = HeaderName::from_static("x-forwarded-proto");
const KEEP_ALIVE: HeaderName = HeaderName::from_static("keep-alive");
const PROXY_CONNECTION: HeaderName = HeaderName::from_static("proxy-connection");

#[derive(Clone, Debug)]
pub(crate) struct ForwardingContext {
    pub(crate) public_host: String,
    pub(crate) peer_ip: Option<IpAddr>,
}

#[derive(Debug, Error)]
pub(crate) enum ForwardError {
    #[error(transparent)]
    Broker(#[from] BrokerError),
    #[error("could not start an HTTP exchange on the tunnel stream")]
    Handshake(#[source] hyper::Error),
    #[error("the tunneled HTTP exchange failed")]
    Exchange(#[source] hyper::Error),
    #[error("could not construct forwarded request metadata")]
    InvalidForwardedMetadata,
}

pub(crate) async fn forward_request(
    broker: StreamBroker,
    mut request: Request<Body>,
    context: ForwardingContext,
) -> Result<Response<Body>, ForwardError> {
    let forwarding_started_at = Instant::now();
    let request_is_upgrade = is_generic_upgrade(request.headers());
    let public_upgrade = request_is_upgrade.then(|| hyper::upgrade::on(&mut request));
    prepare_request_headers(request.headers_mut(), &context, request_is_upgrade)?;

    let session_id = broker.session_id();
    let open_wait_started_at = Instant::now();
    let opened = match broker.open_stream_observed().await {
        Ok(opened) => opened,
        Err(error) => {
            tracing::info!(
                tunnel_session_id = %session_id,
                stage = "stream_open_failed",
                broker_wait_us = duration_micros(open_wait_started_at.elapsed()),
                total_us = duration_micros(forwarding_started_at.elapsed()),
                error = %error,
                "tunneled request stage latency"
            );
            return Err(ForwardError::Broker(error));
        }
    };
    let stream_id = opened.stream.id().val();
    tracing::info!(
        tunnel_session_id = %opened.session_id,
        stream_id,
        stage = "stream_opened",
        broker_queue_us = duration_micros(opened.broker_queue),
        yamux_open_us = duration_micros(opened.yamux_open),
        total_us = duration_micros(forwarding_started_at.elapsed()),
        "tunneled request stage latency"
    );

    let stream = opened.stream;
    let io = TokioIo::new(stream.compat());
    let handshake_started_at = Instant::now();
    let (mut sender, connection) = match http1::handshake(io).await {
        Ok(parts) => parts,
        Err(error) => {
            tracing::info!(
                tunnel_session_id = %session_id,
                stream_id,
                stage = "http_handshake_failed",
                http_handshake_us = duration_micros(handshake_started_at.elapsed()),
                total_us = duration_micros(forwarding_started_at.elapsed()),
                error = %error,
                "tunneled request stage latency"
            );
            return Err(ForwardError::Handshake(error));
        }
    };
    let http_handshake = handshake_started_at.elapsed();
    tokio::spawn(async move {
        if let Err(error) = connection.with_upgrades().await {
            tracing::debug!(
                tunnel_session_id = %session_id,
                stream_id,
                %error,
                "tunneled HTTP connection ended with an error"
            );
        }
    });

    let response_head_started_at = Instant::now();
    let mut response = match sender.send_request(request).await {
        Ok(response) => response,
        Err(error) => {
            tracing::info!(
                tunnel_session_id = %session_id,
                stream_id,
                stage = "response_head_failed",
                http_handshake_us = duration_micros(http_handshake),
                tunneled_response_head_us = duration_micros(response_head_started_at.elapsed()),
                total_us = duration_micros(forwarding_started_at.elapsed()),
                error = %error,
                "tunneled request stage latency"
            );
            return Err(ForwardError::Exchange(error));
        }
    };
    drop(sender);

    tracing::info!(
        tunnel_session_id = %session_id,
        stream_id,
        stage = "response_head",
        status = response.status().as_u16(),
        http_handshake_us = duration_micros(http_handshake),
        tunneled_response_head_us = duration_micros(response_head_started_at.elapsed()),
        total_us = duration_micros(forwarding_started_at.elapsed()),
        "tunneled request stage latency"
    );

    let response_is_upgrade = response.status() == StatusCode::SWITCHING_PROTOCOLS
        && is_generic_upgrade(response.headers());
    let remote_upgrade = response_is_upgrade.then(|| hyper::upgrade::on(&mut response));
    strip_hop_by_hop(response.headers_mut(), response_is_upgrade);

    if let (Some(public_upgrade), Some(remote_upgrade)) = (public_upgrade, remote_upgrade) {
        tokio::spawn(async move {
            let result = async {
                let (public, remote) = tokio::try_join!(public_upgrade, remote_upgrade)?;
                let mut public = TokioIo::new(public);
                let mut remote = TokioIo::new(remote);
                tokio::io::copy_bidirectional(&mut public, &mut remote).await?;
                Ok::<(), UpgradeBridgeError>(())
            }
            .await;
            if let Err(error) = result {
                tracing::debug!(%error, "tunneled upgraded connection ended");
            }
        });
    }

    let (parts, body) = response.into_parts();
    Ok(Response::from_parts(parts, Body::new(body)))
}

fn duration_micros(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

fn prepare_request_headers(
    headers: &mut HeaderMap,
    context: &ForwardingContext,
    preserve_upgrade: bool,
) -> Result<(), ForwardError> {
    let scheme = forwarded_scheme(headers);
    let visitor = forwarded_visitor(headers).or(context.peer_ip);
    strip_hop_by_hop(headers, preserve_upgrade);
    headers.remove(FORWARDED);
    headers.remove(&X_FORWARDED_FOR);
    headers.remove(&X_FORWARDED_HOST);
    headers.remove(&X_FORWARDED_PROTO);

    headers.insert(
        X_FORWARDED_HOST,
        HeaderValue::from_str(&context.public_host)
            .map_err(|_| ForwardError::InvalidForwardedMetadata)?,
    );
    headers.insert(X_FORWARDED_PROTO, HeaderValue::from_static(scheme));

    if let Some(visitor) = visitor {
        let visitor_value = visitor.to_string();
        headers.insert(
            X_FORWARDED_FOR,
            HeaderValue::from_str(&visitor_value)
                .map_err(|_| ForwardError::InvalidForwardedMetadata)?,
        );
        let forwarded = match visitor {
            IpAddr::V4(_) => format!("for={visitor};host={};proto={scheme}", context.public_host),
            IpAddr::V6(_) => format!(
                "for=\"[{visitor}]\";host={};proto={scheme}",
                context.public_host
            ),
        };
        headers.insert(
            FORWARDED,
            HeaderValue::from_str(&forwarded)
                .map_err(|_| ForwardError::InvalidForwardedMetadata)?,
        );
    } else {
        let forwarded = format!("host={};proto={scheme}", context.public_host);
        headers.insert(
            FORWARDED,
            HeaderValue::from_str(&forwarded)
                .map_err(|_| ForwardError::InvalidForwardedMetadata)?,
        );
    }
    Ok(())
}

fn forwarded_scheme(headers: &HeaderMap) -> &'static str {
    headers
        .get(&X_FORWARDED_PROTO)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .and_then(|value| {
            if value.eq_ignore_ascii_case("https") {
                Some("https")
            } else if value.eq_ignore_ascii_case("http") {
                Some("http")
            } else {
                None
            }
        })
        .unwrap_or("http")
}

fn forwarded_visitor(headers: &HeaderMap) -> Option<IpAddr> {
    headers
        .get(&X_FORWARDED_FOR)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .and_then(|value| IpAddr::from_str(value).ok())
}

fn is_generic_upgrade(headers: &HeaderMap) -> bool {
    let connection_has_upgrade = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|token| token.trim().eq_ignore_ascii_case("upgrade"));
    connection_has_upgrade
        && headers
            .get(UPGRADE)
            .is_some_and(|value| !value.as_bytes().is_empty())
}

fn strip_hop_by_hop(headers: &mut HeaderMap, preserve_upgrade: bool) {
    let upgrade = preserve_upgrade
        .then(|| headers.get(UPGRADE).cloned())
        .flatten();
    let connection_named: Vec<HeaderName> = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|token| HeaderName::from_bytes(token.trim().as_bytes()).ok())
        .collect();

    for name in connection_named {
        headers.remove(name);
    }
    for name in [
        CONNECTION,
        KEEP_ALIVE,
        PROXY_AUTHENTICATE,
        PROXY_AUTHORIZATION,
        TE,
        TRAILER,
        TRANSFER_ENCODING,
        UPGRADE,
        PROXY_CONNECTION,
    ] {
        headers.remove(name);
    }

    if let Some(upgrade) = upgrade {
        headers.insert(CONNECTION, HeaderValue::from_static("upgrade"));
        headers.insert(UPGRADE, upgrade);
    }
}

#[derive(Debug, Error)]
enum UpgradeBridgeError {
    #[error("HTTP upgrade failed")]
    Upgrade(#[from] hyper::Error),
    #[error("upgraded stream forwarding failed")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use std::{convert::Infallible, error::Error, io, time::Duration};

    use bytes::Bytes;
    use futures::future::poll_fn;
    use http::header::HOST;
    use http_body_util::{BodyExt as _, StreamBody};
    use hyper::{body::Frame, service::service_fn};
    use tokio_util::compat::{FuturesAsyncReadCompatExt as _, TokioAsyncReadCompatExt as _};
    use yamux::{Config, Connection, Mode};

    use super::*;
    use crate::runtime::broker::{DriverExit, StreamBroker, drive_yamux};

    #[test]
    fn forwarded_headers_are_replaced_and_hop_headers_are_stripped() {
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static("demo.example.test"));
        headers.insert(
            X_FORWARDED_FOR,
            HeaderValue::from_static("203.0.113.8, 10.0.0.2"),
        );
        headers.insert(X_FORWARDED_PROTO, HeaderValue::from_static("https"));
        headers.insert(
            CONNECTION,
            HeaderValue::from_static("keep-alive, x-remove-me"),
        );
        headers.insert(
            HeaderName::from_static("x-remove-me"),
            HeaderValue::from_static("secret-hop-value"),
        );
        headers.insert(
            FORWARDED,
            HeaderValue::from_static("for=untrusted;host=untrusted"),
        );

        prepare_request_headers(
            &mut headers,
            &ForwardingContext {
                public_host: "demo.example.test".to_owned(),
                peer_ip: None,
            },
            false,
        )
        .expect("safe metadata");

        assert_eq!(headers[HOST], "demo.example.test");
        assert_eq!(headers[X_FORWARDED_HOST], "demo.example.test");
        assert_eq!(headers[X_FORWARDED_PROTO], "https");
        assert_eq!(headers[X_FORWARDED_FOR], "203.0.113.8");
        assert_eq!(
            headers[FORWARDED],
            "for=203.0.113.8;host=demo.example.test;proto=https"
        );
        assert!(!headers.contains_key(CONNECTION));
        assert!(!headers.contains_key("x-remove-me"));
    }

    #[test]
    fn generic_upgrade_keeps_only_required_hop_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(CONNECTION, HeaderValue::from_static("upgrade, keep-alive"));
        headers.insert(UPGRADE, HeaderValue::from_static("example-protocol"));
        headers.insert(KEEP_ALIVE, HeaderValue::from_static("timeout=5"));

        strip_hop_by_hop(&mut headers, true);

        assert_eq!(headers[CONNECTION], "upgrade");
        assert_eq!(headers[UPGRADE], "example-protocol");
        assert!(!headers.contains_key(KEEP_ALIVE));
    }

    #[tokio::test]
    async fn http_exchange_preserves_fidelity_and_streams_bodies() -> Result<(), Box<dyn Error>> {
        let (server_io, client_io) = tokio::io::duplex(1024 * 1024);
        let (broker, requests) = StreamBroker::channel();
        let server_driver = tokio::spawn(drive_yamux(server_io.compat(), requests));
        let client_driver = tokio::spawn(async move {
            let mut connection =
                Connection::new(client_io.compat(), Config::default(), Mode::Client);
            loop {
                match poll_fn(|context| connection.poll_next_inbound(context)).await {
                    Some(Ok(stream)) => {
                        tokio::spawn(async move {
                            let service =
                                service_fn(|request: Request<hyper::body::Incoming>| async move {
                                    let method = request.method().clone();
                                    let uri = request.uri().clone();
                                    let forwarded = request
                                        .headers()
                                        .get(FORWARDED)
                                        .cloned()
                                        .unwrap_or_else(|| HeaderValue::from_static("missing"));
                                    let hop_header_present =
                                        request.headers().contains_key("x-hop");
                                    let body = request.into_body().collect().await?.to_bytes();
                                    let prefix =
                                        format!("{method} {uri} hop={hop_header_present} body=");
                                    let response_body = StreamBody::new(tokio_stream::iter([
                                        Ok::<Frame<Bytes>, Infallible>(Frame::data(Bytes::from(
                                            prefix,
                                        ))),
                                        Ok::<Frame<Bytes>, Infallible>(Frame::data(body)),
                                    ]));
                                    let mut response = Response::new(response_body);
                                    *response.status_mut() = StatusCode::PARTIAL_CONTENT;
                                    response.headers_mut().insert(
                                        HeaderName::from_static("x-seen-forwarded"),
                                        forwarded,
                                    );
                                    Ok::<_, hyper::Error>(response)
                                });
                            hyper::server::conn::http1::Builder::new()
                                .serve_connection(TokioIo::new(stream.compat()), service)
                                .await
                        });
                    }
                    Some(Err(error)) => return Err(io::Error::other(error)),
                    None => return Ok(()),
                }
            }
        });

        let chunks = tokio_stream::iter([
            Ok::<Bytes, io::Error>(Bytes::from_static(b"streamed-")),
            Ok::<Bytes, io::Error>(Bytes::from_static(b"request")),
        ]);
        let mut request = Request::builder()
            .method("PATCH")
            .uri("/upload?part=2")
            .header(HOST, "demo.example.test")
            .header(CONNECTION, "x-hop")
            .header("x-hop", "remove-me")
            .header(X_FORWARDED_PROTO, "https")
            .header(X_FORWARDED_FOR, "203.0.113.9")
            .body(Body::from_stream(chunks))?;
        request
            .headers_mut()
            .insert("x-end-to-end", HeaderValue::from_static("preserved"));

        let response = tokio::time::timeout(
            Duration::from_secs(5),
            forward_request(
                broker.clone(),
                request,
                ForwardingContext {
                    public_host: "demo.example.test".to_owned(),
                    peer_ip: None,
                },
            ),
        )
        .await
        .map_err(|_| io::Error::other("HTTP forwarding test timed out"))??;
        assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            response.headers()["x-seen-forwarded"],
            "for=203.0.113.9;host=demo.example.test;proto=https"
        );
        let body = response.into_body().collect().await?.to_bytes();
        assert_eq!(
            body,
            Bytes::from_static(b"PATCH /upload?part=2 hop=false body=streamed-request")
        );

        broker.shutdown();
        assert_eq!(server_driver.await?, DriverExit::Shutdown);
        client_driver.await??;
        Ok(())
    }
}
