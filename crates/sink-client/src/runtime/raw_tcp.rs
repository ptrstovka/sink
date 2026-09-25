//! Per-stream dispatch and raw TCP forwarding for passthrough namespaces.

use std::{
    fmt, io,
    pin::Pin,
    task::{Context, Poll},
    time::{Duration, Instant},
};

use sink_protocol::{
    ProxyV2Header, RAW_STREAM_OPEN_MAGIC, RawTcpStreamOpen, StreamOpenReadError,
    read_raw_stream_open,
};
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, ReadBuf},
    net::TcpStream,
    time::timeout,
};
use tokio_util::compat::TokioAsyncReadCompatExt as _;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::config::{OutgoingProxyProtocol, RawTcpTarget};

use super::proxy::{self, ExchangeProxy};

const STREAM_OPEN_TIMEOUT: Duration = Duration::from_secs(3);
const RAW_TARGET_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const PROXY_HEADER_WRITE_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Clone)]
pub(crate) struct RawTcpBridge {
    namespace_apex: String,
    target: RawTcpTarget,
    proxy_protocol: Option<OutgoingProxyProtocol>,
    connect_timeout: Duration,
}

impl fmt::Debug for RawTcpBridge {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RawTcpBridge")
            .field("namespace_apex", &self.namespace_apex)
            .field("target", &self.target)
            .field("proxy_protocol", &self.proxy_protocol)
            .field("connect_timeout", &self.connect_timeout)
            .finish()
    }
}

impl RawTcpBridge {
    pub(crate) fn new(
        namespace_apex: String,
        target: RawTcpTarget,
        proxy_protocol: Option<OutgoingProxyProtocol>,
    ) -> Self {
        Self {
            namespace_apex,
            target,
            proxy_protocol,
            connect_timeout: RAW_TARGET_CONNECT_TIMEOUT,
        }
    }

    async fn relay<S>(
        &self,
        mut tunnel: S,
        open: RawTcpStreamOpen,
        cancellation: &CancellationToken,
    ) -> Result<(u64, u64), RawTcpBridgeError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        if !hostname_is_covered(&self.namespace_apex, open.route_hostname()) {
            return Err(RawTcpBridgeError::RouteOutsideNamespace);
        }

        let connect = TcpStream::connect((self.target.host(), self.target.port()));
        tokio::pin!(connect);
        let mut upstream = tokio::select! {
            () = cancellation.cancelled() => return Err(RawTcpBridgeError::Cancelled),
            result = timeout(self.connect_timeout, &mut connect) => match result {
                Ok(Ok(stream)) => stream,
                Ok(Err(_)) => return Err(RawTcpBridgeError::TargetUnavailable),
                Err(_) => return Err(RawTcpBridgeError::ConnectTimeout),
            },
        };
        let _ = upstream.set_nodelay(true);

        if self.proxy_protocol == Some(OutgoingProxyProtocol::V2) {
            let header = ProxyV2Header::proxied(open.source(), open.destination())
                .and_then(|header| header.encode())
                .map_err(|_| RawTcpBridgeError::InvalidProxyMetadata)?;
            tokio::select! {
                () = cancellation.cancelled() => return Err(RawTcpBridgeError::Cancelled),
                result = timeout(PROXY_HEADER_WRITE_TIMEOUT, upstream.write_all(&header)) => {
                    match result {
                        Ok(Ok(())) => {}
                        Ok(Err(_)) => return Err(RawTcpBridgeError::ProxyHeaderWrite),
                        Err(_) => return Err(RawTcpBridgeError::ProxyHeaderWriteTimeout),
                    }
                }
            }
        }

        tokio::select! {
            () = cancellation.cancelled() => Err(RawTcpBridgeError::Cancelled),
            result = tokio::io::copy_bidirectional(&mut tunnel, &mut upstream) => {
                result.map_err(|_| RawTcpBridgeError::Relay)
            }
        }
    }
}

pub(crate) async fn dispatch_stream<S>(
    stream: S,
    http_proxy: ExchangeProxy,
    raw_bridge: Option<RawTcpBridge>,
    force_shutdown: CancellationToken,
    session_id: Uuid,
    stream_id: u32,
    accepted_at: Instant,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let detected = tokio::select! {
        () = force_shutdown.cancelled() => return,
        result = timeout(STREAM_OPEN_TIMEOUT, detect_stream(stream)) => match result {
            Ok(Ok(detected)) => detected,
            Ok(Err(error)) => {
                tracing::warn!(
                    tunnel_session_id = %session_id,
                    stream_id,
                    %error,
                    "tunnel stream preamble was rejected"
                );
                return;
            }
            Err(_) => {
                tracing::warn!(
                    tunnel_session_id = %session_id,
                    stream_id,
                    "tunnel stream preamble timed out"
                );
                return;
            }
        }
    };

    match detected {
        DetectedStream::LegacyHttp(stream) => {
            proxy::serve_stream(
                stream,
                http_proxy,
                force_shutdown,
                session_id,
                stream_id,
                accepted_at,
            )
            .await;
        }
        DetectedStream::RawTcp { stream, open } => {
            let Some(bridge) = raw_bridge else {
                tracing::warn!(
                    tunnel_session_id = %session_id,
                    stream_id,
                    route_hostname = open.route_hostname(),
                    "raw stream was rejected because this route has no TLS target"
                );
                return;
            };
            match bridge.relay(stream, open, &force_shutdown).await {
                Ok((tunnel_to_target_bytes, target_to_tunnel_bytes)) => {
                    tracing::debug!(
                        tunnel_session_id = %session_id,
                        stream_id,
                        tunnel_to_target_bytes,
                        target_to_tunnel_bytes,
                        "raw tunnel stream completed"
                    );
                }
                Err(RawTcpBridgeError::Cancelled) => {}
                Err(error) => {
                    tracing::warn!(
                        tunnel_session_id = %session_id,
                        stream_id,
                        %error,
                        "raw tunnel stream failed"
                    );
                }
            }
        }
    }
}

fn hostname_is_covered(namespace_apex: &str, actual: &str) -> bool {
    if actual.eq_ignore_ascii_case(namespace_apex) {
        return true;
    }
    let Some(prefix) = actual
        .get(..actual.len().saturating_sub(namespace_apex.len()))
        .and_then(|prefix| prefix.strip_suffix('.'))
    else {
        return false;
    };
    !prefix.is_empty()
        && !prefix.contains('.')
        && actual
            .get(actual.len().saturating_sub(namespace_apex.len())..)
            .is_some_and(|suffix| suffix.eq_ignore_ascii_case(namespace_apex))
}

enum DetectedStream<S> {
    LegacyHttp(PrefixedIo<S>),
    RawTcp { stream: S, open: RawTcpStreamOpen },
}

async fn detect_stream<S>(mut stream: S) -> Result<DetectedStream<S>, RawTcpBridgeError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut prefix = Vec::with_capacity(RAW_STREAM_OPEN_MAGIC.len());
    for expected in RAW_STREAM_OPEN_MAGIC {
        let mut byte = [0_u8; 1];
        let count = stream
            .read(&mut byte)
            .await
            .map_err(RawTcpBridgeError::PreambleRead)?;
        if count == 0 {
            return Ok(DetectedStream::LegacyHttp(PrefixedIo::new(stream, prefix)));
        }
        prefix.push(byte[0]);
        if byte[0] != expected {
            return Ok(DetectedStream::LegacyHttp(PrefixedIo::new(stream, prefix)));
        }
    }

    let framed = PrefixedIo::new(stream, prefix);
    let mut compatible = framed.compat();
    let open = read_raw_stream_open(&mut compatible)
        .await
        .map_err(RawTcpBridgeError::InvalidPreamble)?;
    Ok(DetectedStream::RawTcp {
        stream: compatible.into_inner().into_inner(),
        open,
    })
}

struct PrefixedIo<S> {
    inner: S,
    prefix: Vec<u8>,
    offset: usize,
}

impl<S> PrefixedIo<S> {
    fn new(inner: S, prefix: Vec<u8>) -> Self {
        Self {
            inner,
            prefix,
            offset: 0,
        }
    }

    fn into_inner(self) -> S {
        self.inner
    }
}

impl<S> AsyncRead for PrefixedIo<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.offset < self.prefix.len() && output.remaining() > 0 {
            let count = output
                .remaining()
                .min(self.prefix.len().saturating_sub(self.offset));
            let end = self.offset + count;
            output.put_slice(&self.prefix[self.offset..end]);
            self.offset = end;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(context, output)
    }
}

impl<S> AsyncWrite for PrefixedIo<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.inner).poll_write(context, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

#[derive(Debug, Error)]
enum RawTcpBridgeError {
    #[error("could not read tunnel stream preamble")]
    PreambleRead(#[source] io::Error),
    #[error("invalid raw tunnel stream preamble")]
    InvalidPreamble(#[source] StreamOpenReadError),
    #[error("raw route hostname is outside the configured namespace")]
    RouteOutsideNamespace,
    #[error("raw TLS target is unavailable")]
    TargetUnavailable,
    #[error("raw TLS target connection timed out")]
    ConnectTimeout,
    #[error("raw stream endpoint metadata is not valid for PROXY v2")]
    InvalidProxyMetadata,
    #[error("could not write outgoing PROXY v2 header")]
    ProxyHeaderWrite,
    #[error("outgoing PROXY v2 header write timed out")]
    ProxyHeaderWriteTimeout,
    #[error("raw byte relay failed")]
    Relay,
    #[error("raw byte relay was cancelled")]
    Cancelled,
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use sink_protocol::{StreamOpen, read_proxy_v2};
    use tokio::net::TcpListener;

    use super::*;

    #[tokio::test]
    async fn fragmented_detection_preserves_every_legacy_http_byte()
    -> Result<(), Box<dyn std::error::Error>> {
        let bytes = b"POST /stream HTTP/1.1\r\nHost: edge.example.test\r\n\r\nbody";
        let (mut writer, reader) = tokio::io::duplex(128);
        let write = tokio::spawn(async move {
            for chunk in bytes.chunks(2) {
                writer.write_all(chunk).await?;
                tokio::task::yield_now().await;
            }
            writer.shutdown().await
        });

        let DetectedStream::LegacyHttp(mut stream) = detect_stream(reader).await? else {
            return Err("legacy HTTP was classified as raw".into());
        };
        let mut actual = Vec::new();
        stream.read_to_end(&mut actual).await?;
        assert_eq!(actual, bytes);
        write.await??;
        Ok(())
    }

    #[tokio::test]
    async fn fragmented_raw_preamble_is_consumed_and_tls_tail_is_untouched()
    -> Result<(), Box<dyn std::error::Error>> {
        let open = RawTcpStreamOpen::new(
            "www.edge.example.test",
            "192.0.2.1:40000".parse()?,
            "198.51.100.1:443".parse()?,
        )?;
        let tls = b"\x16\x03\x01\x00\x05hello";
        let mut bytes = StreamOpen::RawTcp(open.clone()).encode()?;
        bytes.extend_from_slice(tls);
        let (mut writer, reader) = tokio::io::duplex(128);
        let write = tokio::spawn(async move {
            for byte in bytes {
                writer.write_all(&[byte]).await?;
                tokio::task::yield_now().await;
            }
            writer.shutdown().await
        });

        let DetectedStream::RawTcp {
            mut stream,
            open: decoded,
        } = detect_stream(reader).await?
        else {
            return Err("raw preamble was classified as HTTP".into());
        };
        assert_eq!(decoded, open);
        let mut actual = Vec::new();
        stream.read_to_end(&mut actual).await?;
        assert_eq!(actual, tls);
        write.await??;
        Ok(())
    }

    #[test]
    fn namespace_coverage_accepts_only_apex_and_one_direct_child() {
        for hostname in ["edge.example.test", "www.edge.example.test"] {
            assert!(hostname_is_covered("edge.example.test", hostname));
        }
        for hostname in [
            "deep.www.edge.example.test",
            "unrelated.example.test",
            "notedge.example.test",
            "xedge.example.test",
        ] {
            assert!(!hostname_is_covered("edge.example.test", hostname));
        }
        assert!(hostname_is_covered(
            "EDGE.example.test",
            "WWW.edge.example.test"
        ));
    }

    #[tokio::test]
    async fn outgoing_proxy_v2_ipv4_wire_is_fresh_and_tls_is_transparent()
    -> Result<(), Box<dyn std::error::Error>> {
        exercise_relay(
            Some(OutgoingProxyProtocol::V2),
            "192.0.2.10:40123".parse()?,
            "198.51.100.20:443".parse()?,
        )
        .await
    }

    #[tokio::test]
    async fn outgoing_proxy_v2_ipv6_wire_is_fresh_and_tls_is_transparent()
    -> Result<(), Box<dyn std::error::Error>> {
        exercise_relay(
            Some(OutgoingProxyProtocol::V2),
            "[2001:db8::10]:40123".parse()?,
            "[2001:db8::20]:443".parse()?,
        )
        .await
    }

    #[tokio::test]
    async fn proxy_disabled_starts_upstream_with_unchanged_tls_bytes()
    -> Result<(), Box<dyn std::error::Error>> {
        exercise_relay(
            None,
            "192.0.2.10:40123".parse()?,
            "198.51.100.20:443".parse()?,
        )
        .await
    }

    async fn exercise_relay(
        proxy_protocol: Option<OutgoingProxyProtocol>,
        source: SocketAddr,
        destination: SocketAddr,
    ) -> Result<(), Box<dyn std::error::Error>> {
        const TLS_BYTES: &[u8] = b"\x16\x03\x01\x00\x0bclienthello";
        const RESPONSE: &[u8] = b"\x16\x03\x03server-response";
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await?;
            let observed = if proxy_protocol.is_some() {
                let mut compatible = socket.compat();
                let header = read_proxy_v2(&mut compatible)
                    .await
                    .map_err(io::Error::other)?;
                socket = compatible.into_inner();
                Some(header)
            } else {
                None
            };
            let mut tls = Vec::new();
            socket.read_to_end(&mut tls).await?;
            socket.write_all(RESPONSE).await?;
            socket.shutdown().await?;
            Ok::<_, io::Error>((observed, tls))
        });

        let bridge = RawTcpBridge::new(
            "edge.example.test".to_owned(),
            format!("tcp://127.0.0.1:{port}").parse()?,
            proxy_protocol,
        );
        let open = RawTcpStreamOpen::new("www.edge.example.test", source, destination)?;
        let cancellation = CancellationToken::new();
        let (bridge_io, mut peer) = tokio::io::duplex(256);
        let relay = tokio::spawn(async move { bridge.relay(bridge_io, open, &cancellation).await });

        peer.write_all(TLS_BYTES).await?;
        peer.shutdown().await?;
        let mut response = Vec::new();
        peer.read_to_end(&mut response).await?;
        assert_eq!(response, RESPONSE);
        assert_eq!(
            relay.await??,
            (TLS_BYTES.len() as u64, RESPONSE.len() as u64)
        );
        let (observed, tls) = server.await??;
        assert_eq!(tls, TLS_BYTES);
        match (proxy_protocol, observed) {
            (Some(OutgoingProxyProtocol::V2), Some(header)) => {
                assert_eq!(header.source(), Some(source));
                assert_eq!(header.destination(), Some(destination));
                assert_eq!(
                    header.encode()?.len(),
                    if source.is_ipv4() { 28 } else { 52 }
                );
            }
            (None, None) => {}
            other => return Err(format!("unexpected PROXY observation: {other:?}").into()),
        }
        Ok(())
    }

    #[tokio::test]
    async fn target_failure_and_bad_actual_host_are_stream_local()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        drop(listener);
        let bridge = RawTcpBridge::new(
            "edge.example.test".to_owned(),
            format!("tcp://127.0.0.1:{port}").parse()?,
            None,
        );
        let cancellation = CancellationToken::new();
        let (stream, _peer) = tokio::io::duplex(64);
        let unavailable = bridge
            .relay(
                stream,
                RawTcpStreamOpen::new(
                    "edge.example.test",
                    "192.0.2.1:40000".parse()?,
                    "198.51.100.1:443".parse()?,
                )?,
                &cancellation,
            )
            .await;
        assert!(matches!(
            unavailable,
            Err(RawTcpBridgeError::TargetUnavailable)
        ));
        assert!(!cancellation.is_cancelled());

        let (stream, _peer) = tokio::io::duplex(64);
        let rejected = bridge
            .relay(
                stream,
                RawTcpStreamOpen::new(
                    "deep.www.edge.example.test",
                    "192.0.2.1:40000".parse()?,
                    "198.51.100.1:443".parse()?,
                )?,
                &cancellation,
            )
            .await;
        assert!(matches!(
            rejected,
            Err(RawTcpBridgeError::RouteOutsideNamespace)
        ));
        assert!(!cancellation.is_cancelled());
        Ok(())
    }

    #[tokio::test]
    async fn cancellation_ends_one_raw_relay_without_poisoning_route_state()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let server = tokio::spawn(async move {
            let (_socket, _) = listener.accept().await?;
            std::future::pending::<()>().await;
            #[allow(unreachable_code)]
            Ok::<_, io::Error>(())
        });
        let bridge = RawTcpBridge::new(
            "edge.example.test".to_owned(),
            format!("tcp://127.0.0.1:{port}").parse()?,
            None,
        );
        let cancellation = CancellationToken::new();
        let relay_cancellation = cancellation.clone();
        let (stream, _peer) = tokio::io::duplex(64);
        let relay = tokio::spawn(async move {
            bridge
                .relay(
                    stream,
                    RawTcpStreamOpen::new(
                        "edge.example.test",
                        "192.0.2.1:40000".parse().expect("source"),
                        "198.51.100.1:443".parse().expect("destination"),
                    )
                    .expect("open"),
                    &relay_cancellation,
                )
                .await
        });
        tokio::task::yield_now().await;
        cancellation.cancel();
        assert!(matches!(
            timeout(Duration::from_secs(1), relay).await??,
            Err(RawTcpBridgeError::Cancelled)
        ));
        server.abort();
        let _ = server.await;
        Ok(())
    }
}
