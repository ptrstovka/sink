use std::{
    collections::HashMap,
    fmt,
    io::{self, Cursor},
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, OnceLock, RwLock},
    task::{Context, Poll},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use axum::{
    extract::connect_info::Connected,
    serve::{IncomingStream, Listener},
};
use futures::{StreamExt as _, future::BoxFuture, stream::FuturesUnordered};
use rustls::{
    ServerConfig,
    crypto::CryptoProvider,
    server::{ClientHello as RustlsClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use sink_protocol::{ProxyV2Header, RawTcpStreamOpen, StreamOpen, read_proxy_v2};
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::watch,
    time::timeout,
};
use tokio_rustls::{TlsAcceptor, server::TlsStream};
use tokio_util::compat::{FuturesAsyncReadCompatExt as _, TokioAsyncReadCompatExt as _};

use crate::{
    certificates::{
        CertificateIndexReloader, CertificateReloadError, CertificateState, CertificateStorage,
        CertificateTarget, Hostname, SniAuthorization, SniCertificateIndex, Timestamp,
    },
    config::HttpsProxyConfig,
};

use super::{
    NamespaceTlsBoundaries, RuntimeState,
    claims::{ClaimRegistry, RouteLookup, RouteTarget},
    host::{HostRoute, classify_host},
};

const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const PROXY_HEADER_TIMEOUT: Duration = Duration::from_secs(2);
const CLIENT_HELLO_TIMEOUT: Duration = Duration::from_secs(5);
const RAW_STREAM_SETUP_TIMEOUT: Duration = Duration::from_secs(5);
const RAW_RELAY_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_PENDING_TLS_HANDSHAKES: usize = 256;
const MAX_CLIENT_HELLO_BYTES: usize = 64 * 1024;
const MAX_TLS_RECORD_PAYLOAD_BYTES: usize = (1 << 14) + 256;

type TlsHandshake = BoxFuture<'static, Option<(TlsStream<ReplayStream>, TlsConnectionAddress)>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PublicScheme {
    Http,
    Https,
}

impl PublicScheme {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PublicConnectionInfo {
    pub(crate) peer_addr: SocketAddr,
    pub(crate) scheme: PublicScheme,
    pub(crate) sni: Option<Hostname>,
}

impl Connected<IncomingStream<'_, TcpListener>> for PublicConnectionInfo {
    fn connect_info(stream: IncomingStream<'_, TcpListener>) -> Self {
        Self {
            peer_addr: *stream.remote_addr(),
            scheme: PublicScheme::Http,
            sni: None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct TlsConnectionAddress {
    peer_addr: SocketAddr,
    sni: Hostname,
}

/// TCP stream with a bounded prefix replayed before reading the live socket.
/// This lets managed rustls receive the byte-identical ClientHello inspected
/// by pre-dispatch.
pub struct ReplayStream {
    prefix: Cursor<Vec<u8>>,
    stream: TcpStream,
}

impl ReplayStream {
    fn new(prefix: Vec<u8>, stream: TcpStream) -> Self {
        Self {
            prefix: Cursor::new(prefix),
            stream,
        }
    }
}

impl AsyncRead for ReplayStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let position = usize::try_from(self.prefix.position()).unwrap_or(usize::MAX);
        let prefix = self.prefix.get_ref();
        if position < prefix.len() && buffer.remaining() > 0 {
            let available = &prefix[position..];
            let copied = available.len().min(buffer.remaining());
            buffer.put_slice(&available[..copied]);
            self.prefix.set_position((position + copied) as u64);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.stream).poll_read(context, buffer)
    }
}

impl AsyncWrite for ReplayStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.stream).poll_write(context, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.stream).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.stream).poll_shutdown(context)
    }
}

#[derive(Clone)]
struct TlsPredispatch {
    state: RuntimeState,
    proxy: HttpsProxyConfig,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TrustedConnectionEndpoints {
    source: SocketAddr,
    destination: SocketAddr,
}

/// Axum listener that completes rustls before handing a connection to the
/// shared HTTP router. Handshakes without an authorized, usable SNI
/// certificate never reach HTTP.
pub struct TlsListener {
    listener: TcpListener,
    acceptor: TlsAcceptor,
    predispatch: Option<TlsPredispatch>,
    handshakes: FuturesUnordered<TlsHandshake>,
}

impl TlsListener {
    pub fn new(listener: TcpListener, config: Arc<ServerConfig>) -> Self {
        Self {
            listener,
            acceptor: TlsAcceptor::from(config),
            predispatch: None,
            handshakes: FuturesUnordered::new(),
        }
    }

    /// Enable bounded ClientHello pre-dispatch and durable passthrough
    /// routing. The compatibility constructor remains managed-TLS-only for
    /// embedders; the server binary always uses this constructor.
    pub fn with_passthrough(
        listener: TcpListener,
        config: Arc<ServerConfig>,
        state: RuntimeState,
        proxy: HttpsProxyConfig,
    ) -> Self {
        Self {
            listener,
            acceptor: TlsAcceptor::from(config),
            predispatch: Some(TlsPredispatch { state, proxy }),
            handshakes: FuturesUnordered::new(),
        }
    }

    fn start_handshake(&mut self, stream: TcpStream, peer_addr: SocketAddr) {
        let acceptor = self.acceptor.clone();
        let predispatch = self.predispatch.clone();
        self.handshakes.push(Box::pin(async move {
            let local_addr = match stream.local_addr() {
                Ok(address) => address,
                Err(error) => {
                    tracing::debug!(%peer_addr, %error, "could not inspect HTTPS local address");
                    return None;
                }
            };
            let (stream, endpoints, expected_sni) = match predispatch {
                Some(predispatch) => {
                    match predispatch_connection(stream, peer_addr, local_addr, predispatch).await {
                        Ok(PredispatchOutcome::Managed {
                            stream,
                            endpoints,
                            sni,
                        }) => (stream, endpoints, Some(sni)),
                        Ok(PredispatchOutcome::Passthrough) => return None,
                        Err(error) => {
                            tracing::debug!(%peer_addr, %error, "HTTPS pre-dispatch rejected connection");
                            return None;
                        }
                    }
                }
                None => (
                    ReplayStream::new(Vec::new(), stream),
                    TrustedConnectionEndpoints {
                        source: peer_addr,
                        destination: local_addr,
                    },
                    None,
                ),
            };
            match timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
                Ok(Ok(stream)) => {
                    let Some(server_name) = stream.get_ref().1.server_name() else {
                        tracing::debug!(peer_addr = %endpoints.source, "TLS handshake completed without SNI");
                        return None;
                    };
                    let Ok(sni) = Hostname::parse(server_name) else {
                        tracing::debug!(peer_addr = %endpoints.source, "TLS handshake returned invalid SNI");
                        return None;
                    };
                    if expected_sni.as_ref().is_some_and(|expected| expected != &sni) {
                        tracing::debug!(peer_addr = %endpoints.source, %sni, "TLS handshake SNI changed after pre-dispatch");
                        return None;
                    }
                    Some((
                        stream,
                        TlsConnectionAddress {
                            peer_addr: endpoints.source,
                            sni,
                        },
                    ))
                }
                Ok(Err(error)) => {
                    tracing::debug!(peer_addr = %endpoints.source, %error, "TLS handshake rejected");
                    None
                }
                Err(_) => {
                    tracing::debug!(peer_addr = %endpoints.source, "TLS handshake timed out");
                    None
                }
            }
        }));
    }
}

enum PredispatchOutcome {
    Managed {
        stream: ReplayStream,
        endpoints: TrustedConnectionEndpoints,
        sni: Hostname,
    },
    Passthrough,
}

#[derive(Debug, Error)]
enum PredispatchError {
    #[error("accepted HTTPS peer is not trusted to supply PROXY metadata")]
    UntrustedProxyPeer,
    #[error("timed out while reading required PROXY v2 metadata")]
    ProxyTimeout,
    #[error("required PROXY v2 metadata is invalid")]
    InvalidProxy(#[source] sink_protocol::ProxyV2ReadError),
    #[error("PROXY v2 LOCAL is not accepted on required ingress")]
    ProxyLocal,
    #[error("unsupported PROXY v2 header")]
    UnsupportedProxyHeader,
    #[error("timed out while reading TLS ClientHello")]
    ClientHelloTimeout,
    #[error(transparent)]
    ClientHello(#[from] ClientHelloReadError),
    #[error("durable passthrough ownership lookup failed")]
    OwnershipLookup(#[source] crate::db::DbError),
    #[error("TLS SNI is not authorized")]
    UnauthorizedSni,
    #[error("durable passthrough ownership has no matching active wildcard broker")]
    PassthroughUnavailable,
    #[error("passthrough broker could not open a raw stream")]
    RawStreamOpen(#[source] super::broker::BrokerError),
    #[error("raw stream metadata could not be encoded")]
    RawStreamMetadata(#[source] sink_protocol::StreamOpenError),
}

#[derive(Debug, Error)]
enum ClientHelloReadError {
    #[error("TLS ClientHello I/O failed")]
    Io(#[source] io::Error),
    #[error("TLS record is not a bounded handshake record")]
    InvalidRecord,
    #[error("TLS ClientHello exceeds the configured byte limit")]
    TooLarge,
    #[error("first TLS handshake message is not ClientHello")]
    NotClientHello,
    #[error("TLS ClientHello structure is invalid")]
    InvalidStructure,
    #[error("TLS ClientHello has no single valid DNS SNI")]
    InvalidSni,
}

async fn predispatch_connection(
    mut stream: TcpStream,
    accepted_peer: SocketAddr,
    accepted_local: SocketAddr,
    predispatch: TlsPredispatch,
) -> Result<PredispatchOutcome, PredispatchError> {
    if predispatch.state.is_shutting_down() {
        return Err(PredispatchError::PassthroughUnavailable);
    }
    let endpoints = trusted_connection_endpoints(
        &mut stream,
        accepted_peer,
        accepted_local,
        &predispatch.proxy,
    )
    .await?;
    let (sni, buffered_tls) = timeout(CLIENT_HELLO_TIMEOUT, read_client_hello(&mut stream))
        .await
        .map_err(|_| PredispatchError::ClientHelloTimeout)??;

    let admission = predispatch.state.admission_gate.lock().await;
    let ownership = predispatch
        .state
        .database
        .active_passthrough_claim_for_route(sni.as_str())
        .await
        .map_err(PredispatchError::OwnershipLookup)?;
    let Some(ownership) = ownership else {
        if !managed_sni_authorized(&predispatch.state, &sni) {
            return Err(PredispatchError::UnauthorizedSni);
        }
        return Ok(PredispatchOutcome::Managed {
            stream: ReplayStream::new(buffered_tls, stream),
            endpoints,
            sni,
        });
    };

    let route = predispatch.state.claims.resolve_route(&sni, Instant::now());
    let broker = match route {
        RouteLookup::Active {
            target: RouteTarget::PassthroughWildcard(namespace),
            broker,
            owner,
        } if namespace.as_str() == ownership.fqdn && owner.user_id == ownership.user_id => broker,
        RouteLookup::Active { .. } | RouteLookup::Disconnected { .. } | RouteLookup::Unknown => {
            return Err(PredispatchError::PassthroughUnavailable);
        }
    };
    drop(admission);
    let opened = broker
        .open_stream_observed()
        .await
        .map_err(PredispatchError::RawStreamOpen)?;
    let open = RawTcpStreamOpen::new(sni.to_string(), endpoints.source, endpoints.destination)
        .map_err(PredispatchError::RawStreamMetadata)?;
    let preamble = StreamOpen::RawTcp(open)
        .encode()
        .map_err(PredispatchError::RawStreamMetadata)?;
    let shutdown = predispatch.state.subscribe_shutdown();
    tokio::spawn(relay_raw_stream(
        stream,
        opened.stream,
        preamble,
        buffered_tls,
        shutdown,
        sni,
    ));
    Ok(PredispatchOutcome::Passthrough)
}

async fn trusted_connection_endpoints(
    stream: &mut TcpStream,
    accepted_peer: SocketAddr,
    accepted_local: SocketAddr,
    proxy: &HttpsProxyConfig,
) -> Result<TrustedConnectionEndpoints, PredispatchError> {
    match proxy {
        HttpsProxyConfig::Disabled => Ok(TrustedConnectionEndpoints {
            source: accepted_peer,
            destination: accepted_local,
        }),
        HttpsProxyConfig::RequiredV2 { trusted_peer_cidrs } => {
            if !trusted_peer_cidrs
                .iter()
                .any(|network| network.contains(accepted_peer.ip()))
            {
                return Err(PredispatchError::UntrustedProxyPeer);
            }
            let header = timeout(PROXY_HEADER_TIMEOUT, async {
                let mut compatible = (&mut *stream).compat();
                read_proxy_v2(&mut compatible).await
            })
            .await
            .map_err(|_| PredispatchError::ProxyTimeout)?
            .map_err(PredispatchError::InvalidProxy)?;
            match header {
                ProxyV2Header::Proxy {
                    source,
                    destination,
                } => Ok(TrustedConnectionEndpoints {
                    source,
                    destination,
                }),
                ProxyV2Header::Local => Err(PredispatchError::ProxyLocal),
                _ => Err(PredispatchError::UnsupportedProxyHeader),
            }
        }
    }
}

fn managed_sni_authorized(state: &RuntimeState, sni: &Hostname) -> bool {
    match classify_host(sni.as_str(), &state.public_base_domain) {
        HostRoute::Base | HostRoute::Control => true,
        HostRoute::Tunnel(hostname) => state
            .claims
            .route_claim(&hostname, Instant::now())
            .is_some(),
        HostRoute::Invalid => false,
    }
}

async fn relay_raw_stream(
    mut public: TcpStream,
    tunnel: yamux::Stream,
    preamble: Vec<u8>,
    buffered_tls: Vec<u8>,
    mut shutdown: watch::Receiver<bool>,
    sni: Hostname,
) {
    let mut tunnel = tunnel.compat();
    let setup = async {
        tunnel.write_all(&preamble).await?;
        tunnel.write_all(&buffered_tls).await?;
        tunnel.flush().await
    };
    match timeout(RAW_STREAM_SETUP_TIMEOUT, setup).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            tracing::debug!(%sni, %error, "raw passthrough stream setup failed");
            return;
        }
        Err(_) => {
            tracing::debug!(%sni, "raw passthrough stream setup timed out");
            return;
        }
    }

    let relay_result = {
        let relay = tokio::io::copy_bidirectional(&mut public, &mut tunnel);
        tokio::pin!(relay);
        tokio::select! {
            result = &mut relay => Some(result),
            () = wait_for_raw_shutdown(&mut shutdown) => None,
        }
    };
    if let Some(Err(error)) = relay_result {
        tracing::debug!(%sni, %error, "raw passthrough relay ended with an error");
    } else if relay_result.is_none() {
        let graceful = async {
            let public_shutdown = public.shutdown();
            let tunnel_shutdown = tunnel.shutdown();
            let (public, tunnel) = tokio::join!(public_shutdown, tunnel_shutdown);
            public.and(tunnel)
        };
        match timeout(RAW_RELAY_SHUTDOWN_TIMEOUT, graceful).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                tracing::debug!(%sni, %error, "raw passthrough relay shutdown failed");
            }
            Err(_) => {
                tracing::debug!(%sni, "raw passthrough relay shutdown timed out");
            }
        }
    }
}

async fn wait_for_raw_shutdown(shutdown: &mut watch::Receiver<bool>) {
    if *shutdown.borrow() {
        return;
    }
    while shutdown.changed().await.is_ok() {
        if *shutdown.borrow() {
            return;
        }
    }
}

async fn read_client_hello<R>(reader: &mut R) -> Result<(Hostname, Vec<u8>), ClientHelloReadError>
where
    R: AsyncRead + Unpin,
{
    let mut wire = Vec::new();
    let mut handshake = Vec::new();
    let mut declared_handshake_bytes = None;
    loop {
        let mut header = [0_u8; 5];
        reader
            .read_exact(&mut header)
            .await
            .map_err(ClientHelloReadError::Io)?;
        if header[0] != 22 || header[1] != 3 {
            return Err(ClientHelloReadError::InvalidRecord);
        }
        let record_bytes = usize::from(u16::from_be_bytes([header[3], header[4]]));
        if record_bytes == 0 || record_bytes > MAX_TLS_RECORD_PAYLOAD_BYTES {
            return Err(ClientHelloReadError::InvalidRecord);
        }
        if wire
            .len()
            .saturating_add(header.len())
            .saturating_add(record_bytes)
            > MAX_CLIENT_HELLO_BYTES
        {
            return Err(ClientHelloReadError::TooLarge);
        }
        wire.extend_from_slice(&header);
        let payload_start = wire.len();
        wire.resize(payload_start + record_bytes, 0);
        reader
            .read_exact(&mut wire[payload_start..])
            .await
            .map_err(ClientHelloReadError::Io)?;
        handshake.extend_from_slice(&wire[payload_start..]);

        if handshake.len() >= 4 && declared_handshake_bytes.is_none() {
            if handshake[0] != 1 {
                return Err(ClientHelloReadError::NotClientHello);
            }
            let body_bytes = (usize::from(handshake[1]) << 16)
                | (usize::from(handshake[2]) << 8)
                | usize::from(handshake[3]);
            let complete = body_bytes.saturating_add(4);
            if complete > MAX_CLIENT_HELLO_BYTES {
                return Err(ClientHelloReadError::TooLarge);
            }
            declared_handshake_bytes = Some(complete);
        }
        if let Some(complete) = declared_handshake_bytes
            && handshake.len() >= complete
        {
            let sni = parse_client_hello_sni(&handshake[4..complete])?;
            return Ok((sni, wire));
        }
    }
}

fn parse_client_hello_sni(body: &[u8]) -> Result<Hostname, ClientHelloReadError> {
    let mut cursor = 0;
    take_client_hello(body, &mut cursor, 2 + 32)?;
    let session_bytes = usize::from(read_client_hello_u8(body, &mut cursor)?);
    take_client_hello(body, &mut cursor, session_bytes)?;
    let cipher_bytes = usize::from(read_client_hello_u16(body, &mut cursor)?);
    if cipher_bytes == 0 || cipher_bytes % 2 != 0 {
        return Err(ClientHelloReadError::InvalidStructure);
    }
    take_client_hello(body, &mut cursor, cipher_bytes)?;
    let compression_bytes = usize::from(read_client_hello_u8(body, &mut cursor)?);
    if compression_bytes == 0 {
        return Err(ClientHelloReadError::InvalidStructure);
    }
    take_client_hello(body, &mut cursor, compression_bytes)?;
    let extensions_bytes = usize::from(read_client_hello_u16(body, &mut cursor)?);
    let extensions = take_client_hello(body, &mut cursor, extensions_bytes)?;
    if cursor != body.len() {
        return Err(ClientHelloReadError::InvalidStructure);
    }

    let mut extension_cursor = 0;
    let mut sni = None;
    while extension_cursor < extensions.len() {
        let extension_type = read_client_hello_u16(extensions, &mut extension_cursor)?;
        let extension_bytes =
            usize::from(read_client_hello_u16(extensions, &mut extension_cursor)?);
        let extension = take_client_hello(extensions, &mut extension_cursor, extension_bytes)?;
        if extension_type == 0 {
            if sni.is_some() {
                return Err(ClientHelloReadError::InvalidSni);
            }
            sni = Some(parse_server_name_extension(extension)?);
        }
    }
    sni.ok_or(ClientHelloReadError::InvalidSni)
}

fn parse_server_name_extension(extension: &[u8]) -> Result<Hostname, ClientHelloReadError> {
    let mut cursor = 0;
    let list_bytes = usize::from(read_client_hello_u16(extension, &mut cursor)?);
    let names = take_client_hello(extension, &mut cursor, list_bytes)?;
    if cursor != extension.len() {
        return Err(ClientHelloReadError::InvalidSni);
    }
    let mut names_cursor = 0;
    let mut hostname = None;
    while names_cursor < names.len() {
        let name_type = read_client_hello_u8(names, &mut names_cursor)?;
        let name_bytes = usize::from(read_client_hello_u16(names, &mut names_cursor)?);
        let name = take_client_hello(names, &mut names_cursor, name_bytes)?;
        if name_type == 0 {
            if hostname.is_some() {
                return Err(ClientHelloReadError::InvalidSni);
            }
            let name = std::str::from_utf8(name).map_err(|_| ClientHelloReadError::InvalidSni)?;
            hostname = Some(Hostname::parse(name).map_err(|_| ClientHelloReadError::InvalidSni)?);
        }
    }
    hostname.ok_or(ClientHelloReadError::InvalidSni)
}

fn read_client_hello_u8(input: &[u8], cursor: &mut usize) -> Result<u8, ClientHelloReadError> {
    let byte = *input
        .get(*cursor)
        .ok_or(ClientHelloReadError::InvalidStructure)?;
    *cursor += 1;
    Ok(byte)
}

fn read_client_hello_u16(input: &[u8], cursor: &mut usize) -> Result<u16, ClientHelloReadError> {
    let bytes = take_client_hello(input, cursor, 2)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn take_client_hello<'a>(
    input: &'a [u8],
    cursor: &mut usize,
    bytes: usize,
) -> Result<&'a [u8], ClientHelloReadError> {
    let end = cursor
        .checked_add(bytes)
        .ok_or(ClientHelloReadError::InvalidStructure)?;
    let selected = input
        .get(*cursor..end)
        .ok_or(ClientHelloReadError::InvalidStructure)?;
    *cursor = end;
    Ok(selected)
}

impl Listener for TlsListener {
    type Io = TlsStream<ReplayStream>;
    type Addr = TlsConnectionAddress;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            if self.handshakes.is_empty() {
                match self.listener.accept().await {
                    Ok((stream, peer_addr)) => self.start_handshake(stream, peer_addr),
                    Err(error) => {
                        tracing::warn!(%error, "HTTPS listener accept failed");
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                }
                continue;
            }

            if self.handshakes.len() >= MAX_PENDING_TLS_HANDSHAKES {
                if let Some(Some(accepted)) = self.handshakes.next().await {
                    return accepted;
                }
                continue;
            }

            tokio::select! {
                accepted = self.handshakes.next() => {
                    if let Some(Some(accepted)) = accepted {
                        return accepted;
                    }
                }
                connection = self.listener.accept() => {
                    match connection {
                        Ok((stream, peer_addr)) => self.start_handshake(stream, peer_addr),
                        Err(error) => {
                            tracing::warn!(%error, "HTTPS listener accept failed");
                            tokio::time::sleep(Duration::from_secs(1)).await;
                        }
                    }
                }
            }
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        let peer_addr = self.listener.local_addr()?;
        // Axum only uses this for diagnostics. No connection exists yet, so a
        // synthetic, valid hostname is required by the listener trait's
        // address type and is never inserted into a request.
        let sni = Hostname::parse("listener.invalid")
            .map_err(|_| io::Error::other("could not construct TLS listener address"))?;
        Ok(TlsConnectionAddress { peer_addr, sni })
    }
}

impl Connected<IncomingStream<'_, TlsListener>> for PublicConnectionInfo {
    fn connect_info(stream: IncomingStream<'_, TlsListener>) -> Self {
        Self {
            peer_addr: stream.remote_addr().peer_addr,
            scheme: PublicScheme::Https,
            sni: Some(stream.remote_addr().sni.clone()),
        }
    }
}

#[derive(Default)]
struct TlsCertificateSnapshot {
    index: SniCertificateIndex,
    keys: HashMap<CertificateTarget, Arc<CertifiedKey>>,
}

/// Rustls resolver backed by whole-snapshot replacement. Durable records are
/// parsed before the write lock is taken, so handshakes see either the old
/// complete snapshot or the new complete snapshot.
pub struct DynamicTlsCertificateResolver<S, A: ?Sized> {
    storage: Arc<S>,
    authorization: Arc<A>,
    crypto_provider: Arc<CryptoProvider>,
    snapshot: RwLock<Arc<TlsCertificateSnapshot>>,
}

impl<S, A: ?Sized> DynamicTlsCertificateResolver<S, A> {
    pub fn new(
        storage: Arc<S>,
        authorization: Arc<A>,
        crypto_provider: Arc<CryptoProvider>,
    ) -> Self {
        Self {
            storage,
            authorization,
            crypto_provider,
            snapshot: RwLock::new(Arc::new(TlsCertificateSnapshot::default())),
        }
    }

    fn snapshot(&self) -> Arc<TlsCertificateSnapshot> {
        self.snapshot
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    #[cfg(test)]
    fn resolves_at(&self, server_name: &str, now: Timestamp) -> bool
    where
        A: SniAuthorization,
    {
        self.resolve_at(server_name, now).is_some()
    }

    fn resolve_at(&self, server_name: &str, now: Timestamp) -> Option<Arc<CertifiedKey>>
    where
        A: SniAuthorization,
    {
        let snapshot = self.snapshot();
        let selected = snapshot
            .index
            .resolve(server_name, now, self.authorization.as_ref())
            .ok()?;
        snapshot.keys.get(selected.target).cloned()
    }
}

impl<S, A: ?Sized> fmt::Debug for DynamicTlsCertificateResolver<S, A> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DynamicTlsCertificateResolver")
            .field("certificate_count", &self.snapshot().keys.len())
            .finish()
    }
}

impl<S, A> CertificateIndexReloader for DynamicTlsCertificateResolver<S, A>
where
    S: CertificateStorage + 'static,
    A: SniAuthorization + Send + Sync + ?Sized + 'static,
{
    fn refresh(&self, _now: Timestamp) -> BoxFuture<'_, Result<(), CertificateReloadError>> {
        Box::pin(async move {
            let records = self
                .storage
                .load_certificates()
                .await
                .map_err(|_| CertificateReloadError)?;
            let index =
                SniCertificateIndex::new(records.clone()).map_err(|_| CertificateReloadError)?;
            let mut keys = HashMap::new();
            for record in &records {
                let CertificateState::Ready(material) = &record.state else {
                    continue;
                };
                let key = certified_key(material, &self.crypto_provider)?;
                keys.insert(record.target.clone(), Arc::new(key));
            }
            let next = Arc::new(TlsCertificateSnapshot { index, keys });
            *self
                .snapshot
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = next;
            Ok(())
        })
    }
}

impl<S, A> ResolvesServerCert for DynamicTlsCertificateResolver<S, A>
where
    S: CertificateStorage + 'static,
    A: SniAuthorization + Send + Sync + ?Sized + 'static,
{
    fn resolve(&self, client_hello: RustlsClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.resolve_at(client_hello.server_name()?, now_timestamp())
    }
}

fn certified_key(
    material: &crate::certificates::CertificateMaterial,
    provider: &CryptoProvider,
) -> Result<CertifiedKey, CertificateReloadError> {
    let mut certificate_reader = Cursor::new(material.certificate_chain_pem.as_slice());
    let certificates = rustls_pemfile::certs(&mut certificate_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| CertificateReloadError)?;
    if certificates.is_empty() {
        return Err(CertificateReloadError);
    }

    let mut key_reader = Cursor::new(material.private_key_pem.expose_secret());
    let private_key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|_| CertificateReloadError)?
        .ok_or(CertificateReloadError)?;
    let signing_key = provider
        .key_provider
        .load_private_key(private_key)
        .map_err(|_| CertificateReloadError)?;
    let certified = CertifiedKey::new(certificates, signing_key);
    certified.keys_match().map_err(|_| CertificateReloadError)?;
    Ok(certified)
}

pub fn default_crypto_provider() -> Arc<CryptoProvider> {
    if let Some(provider) = CryptoProvider::get_default() {
        return Arc::clone(provider);
    }

    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    CryptoProvider::get_default().map_or_else(
        || Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
        Arc::clone,
    )
}

pub fn build_tls_server_config(
    resolver: Arc<dyn ResolvesServerCert>,
    crypto_provider: Arc<CryptoProvider>,
) -> Result<Arc<ServerConfig>, CertificateReloadError> {
    let mut config = ServerConfig::builder_with_provider(crypto_provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| CertificateReloadError)?
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// Live authorization for the configured platform names and current tunnel
/// leases. The claim registry is attached once after RuntimeState is built;
/// cloning it shares the same synchronized lease map without retaining the
/// whole runtime state.
pub struct RuntimeSniAuthorization {
    base_domain: Hostname,
    claims: OnceLock<ClaimRegistry>,
    boundaries: OnceLock<NamespaceTlsBoundaries>,
}

impl RuntimeSniAuthorization {
    pub fn new(base_domain: Hostname) -> Self {
        Self {
            base_domain,
            claims: OnceLock::new(),
            boundaries: OnceLock::new(),
        }
    }

    pub(crate) fn attach_runtime(
        &self,
        claims: ClaimRegistry,
        boundaries: NamespaceTlsBoundaries,
    ) -> bool {
        if self.claims.set(claims).is_err() {
            return false;
        }
        self.boundaries.set(boundaries).is_ok()
    }
}

impl SniAuthorization for RuntimeSniAuthorization {
    fn is_authorized(&self, hostname: &Hostname) -> bool {
        match classify_host(hostname.as_str(), self.base_domain.as_str()) {
            HostRoute::Base | HostRoute::Control => true,
            HostRoute::Tunnel(hostname) => self
                .claims
                .get()
                .and_then(|claims| claims.route_claim(&hostname, Instant::now()))
                .is_some(),
            HostRoute::Invalid => false,
        }
    }

    fn required_certificate_apex(&self, hostname: &Hostname) -> Option<Hostname> {
        self.boundaries
            .get()
            .and_then(|boundaries| boundaries.most_specific_for(hostname))
    }
}

pub(crate) fn now_timestamp() -> Timestamp {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    Timestamp::from_unix_seconds(seconds)
}

#[cfg(test)]
mod tests {
    use std::{error::Error, io};

    use futures::{AsyncReadExt as FuturesAsyncReadExt, future::poll_fn};
    use rcgen::{CertifiedKey as RcgenCertifiedKey, generate_simple_self_signed};
    use rustls::{ClientConfig, RootCertStore, pki_types::ServerName};
    use sink_protocol::{
        MAX_PROXY_V2_HEADER_BYTES, ProxyV2Header, RawTcpStreamOpen, read_raw_stream_open,
    };
    use tokio::{io::AsyncWriteExt as _, sync::mpsc, task::JoinHandle};
    use tokio_rustls::TlsConnector;
    use tokio_util::compat::TokioAsyncReadCompatExt as _;
    use uuid::Uuid;
    use yamux::{Config, Connection, Mode};

    use super::*;
    use crate::{
        certificates::{
            AuthorizedHostnames, CertificateMaterial, CertificateProviderKind, CertificateRecord,
            FakeCertificateStorage, SecretBytes,
        },
        config::TrustedPeerCidr,
        db::{Database, NamespaceTlsMode},
        runtime::{
            broker::{DriverExit, StreamBroker, drive_yamux},
            claims::ClaimOwner,
        },
    };

    type RawTunnelReceive = mpsc::UnboundedReceiver<Result<(RawTcpStreamOpen, Vec<u8>), io::Error>>;
    type RawTunnel = (
        StreamBroker,
        JoinHandle<DriverExit>,
        JoinHandle<Result<(), io::Error>>,
        RawTunnelReceive,
    );

    fn hostname(value: &str) -> Hostname {
        Hostname::parse(value).expect("valid hostname")
    }

    #[test]
    fn default_crypto_provider_is_installed_process_wide() {
        let selected = default_crypto_provider();
        let installed = CryptoProvider::get_default().expect("crypto provider installed");

        assert!(Arc::ptr_eq(&selected, installed));
    }

    #[tokio::test]
    async fn fragmented_client_hello_is_bounded_and_sni_is_canonical() -> Result<(), Box<dyn Error>>
    {
        let hello =
            fragment_handshake_across_records(&test_client_hello(Some("API.Cloud.Example.Test")));
        let expected = hello.clone();
        let (mut writer, mut reader) = tokio::io::duplex(hello.len() * 2);
        let send = tokio::spawn(async move {
            for byte in hello {
                writer.write_all(&[byte]).await?;
                tokio::task::yield_now().await;
            }
            Ok::<_, io::Error>(())
        });

        let (sni, buffered) = read_client_hello(&mut reader).await?;
        send.await??;
        assert_eq!(sni, hostname("api.cloud.example.test"));
        assert_eq!(buffered, expected);

        let missing_sni = test_client_hello(None);
        assert!(matches!(
            read_client_hello(&mut &missing_sni[..]).await,
            Err(ClientHelloReadError::InvalidSni)
        ));

        let mut oversized_record = vec![22, 0x03, 0x01];
        oversized_record
            .extend_from_slice(&((MAX_TLS_RECORD_PAYLOAD_BYTES + 1) as u16).to_be_bytes());
        assert!(matches!(
            read_client_hello(&mut &oversized_record[..]).await,
            Err(ClientHelloReadError::InvalidRecord)
        ));
        Ok(())
    }

    #[tokio::test]
    async fn proxy_policy_accepts_fragmented_trusted_v4_and_v6_headers()
    -> Result<(), Box<dyn Error>> {
        for (trusted_peer, cidr, source, destination) in [
            (
                "127.0.0.1:31000",
                "127.0.0.0/8",
                "192.0.2.10:41000",
                "198.51.100.20:443",
            ),
            (
                "[2001:db8:42::9]:31000",
                "2001:db8:42::/48",
                "[2001:db8:1::10]:41000",
                "[2001:db8:2::20]:443",
            ),
        ] {
            let source = source.parse::<SocketAddr>()?;
            let destination = destination.parse::<SocketAddr>()?;
            let encoded = ProxyV2Header::proxied(source, destination)?.encode()?;
            let (mut client, mut server, _, local) = tcp_pair().await?;
            let writer = tokio::spawn(async move {
                for chunk in encoded.chunks(3) {
                    client.write_all(chunk).await?;
                    tokio::task::yield_now().await;
                }
                Ok::<_, io::Error>(())
            });
            let endpoints = trusted_connection_endpoints(
                &mut server,
                trusted_peer.parse()?,
                local,
                &required_proxy(cidr),
            )
            .await?;
            writer.await??;
            assert_eq!(endpoints.source, source);
            assert_eq!(endpoints.destination, destination);
        }
        Ok(())
    }

    #[tokio::test]
    async fn proxy_policy_rejects_untrusted_missing_local_malformed_and_oversized()
    -> Result<(), Box<dyn Error>> {
        let (_client, mut server, peer, local) = tcp_pair().await?;
        assert!(matches!(
            trusted_connection_endpoints(
                &mut server,
                peer,
                local,
                &required_proxy("192.0.2.0/24"),
            )
            .await,
            Err(PredispatchError::UntrustedProxyPeer)
        ));

        let (client, mut server, peer, local) = tcp_pair().await?;
        drop(client);
        assert!(matches!(
            trusted_connection_endpoints(&mut server, peer, local, &required_proxy("127.0.0.0/8"),)
                .await,
            Err(PredispatchError::InvalidProxy(_))
        ));

        let (mut client, mut server, peer, local) = tcp_pair().await?;
        client.write_all(&ProxyV2Header::local().encode()?).await?;
        assert!(matches!(
            trusted_connection_endpoints(&mut server, peer, local, &required_proxy("127.0.0.0/8"),)
                .await,
            Err(PredispatchError::ProxyLocal)
        ));

        let (mut client, mut server, peer, local) = tcp_pair().await?;
        client.write_all(&[0_u8; 16]).await?;
        assert!(matches!(
            trusted_connection_endpoints(&mut server, peer, local, &required_proxy("127.0.0.0/8"),)
                .await,
            Err(PredispatchError::InvalidProxy(_))
        ));

        let (mut client, mut server, peer, local) = tcp_pair().await?;
        let mut oversized = sink_protocol::PROXY_V2_SIGNATURE.to_vec();
        oversized.extend_from_slice(&[0x21, 0x11]);
        oversized.extend_from_slice(
            &((MAX_PROXY_V2_HEADER_BYTES - sink_protocol::PROXY_V2_PREFIX_BYTES + 1) as u16)
                .to_be_bytes(),
        );
        client.write_all(&oversized).await?;
        assert!(matches!(
            trusted_connection_endpoints(&mut server, peer, local, &required_proxy("127.0.0.0/8"),)
                .await,
            Err(PredispatchError::InvalidProxy(_))
        ));
        Ok(())
    }

    #[tokio::test]
    async fn disabled_proxy_uses_socket_endpoints_and_proxy_bytes_fail_as_tls()
    -> Result<(), Box<dyn Error>> {
        let (mut client, mut server, peer, local) = tcp_pair().await?;
        let mut input =
            ProxyV2Header::proxied("192.0.2.1:41000".parse()?, "198.51.100.2:443".parse()?)?
                .encode()?;
        input.extend_from_slice(&test_client_hello(Some("example.test")));
        client.write_all(&input).await?;

        let endpoints =
            trusted_connection_endpoints(&mut server, peer, local, &HttpsProxyConfig::Disabled)
                .await?;
        assert_eq!(endpoints.source, peer);
        assert_eq!(endpoints.destination, local);
        assert!(matches!(
            read_client_hello(&mut server).await,
            Err(ClientHelloReadError::InvalidRecord)
        ));
        Ok(())
    }

    fn material(names: &[&str], not_after: u64) -> CertificateMaterial {
        let RcgenCertifiedKey { cert, signing_key } = generate_simple_self_signed(
            names
                .iter()
                .map(|name| (*name).to_owned())
                .collect::<Vec<_>>(),
        )
        .expect("generate local certificate");
        CertificateMaterial {
            certificate_chain_pem: cert.pem().into_bytes(),
            private_key_pem: SecretBytes::new(signing_key.serialize_pem().into_bytes()),
            not_before: Timestamp::from_unix_seconds(100),
            not_after: Timestamp::from_unix_seconds(not_after),
        }
    }

    fn test_client_hello(sni: Option<&str>) -> Vec<u8> {
        let mut extensions = Vec::new();
        if let Some(sni) = sni {
            let name = sni.as_bytes();
            let list_bytes = 1 + 2 + name.len();
            let extension_bytes = 2 + list_bytes;
            extensions.extend_from_slice(&0_u16.to_be_bytes());
            extensions.extend_from_slice(&(extension_bytes as u16).to_be_bytes());
            extensions.extend_from_slice(&(list_bytes as u16).to_be_bytes());
            extensions.push(0);
            extensions.extend_from_slice(&(name.len() as u16).to_be_bytes());
            extensions.extend_from_slice(name);
        }

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0x42; 32]);
        body.push(0);
        body.extend_from_slice(&2_u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(1);
        body.push(0);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut handshake = Vec::new();
        handshake.push(1);
        let body_bytes = body.len() as u32;
        handshake.extend_from_slice(&body_bytes.to_be_bytes()[1..]);
        handshake.extend_from_slice(&body);

        let mut record = vec![22, 0x03, 0x01];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    fn fragment_handshake_across_records(input: &[u8]) -> Vec<u8> {
        let payload_bytes = usize::from(u16::from_be_bytes([input[3], input[4]]));
        let payload = &input[5..5 + payload_bytes];
        let split = payload.len() / 2;
        let mut output = Vec::new();
        for part in [&payload[..split], &payload[split..]] {
            output.extend_from_slice(&input[..3]);
            output.extend_from_slice(&(part.len() as u16).to_be_bytes());
            output.extend_from_slice(part);
        }
        output.extend_from_slice(&input[5 + payload_bytes..]);
        output
    }

    async fn tcp_pair() -> io::Result<(TcpStream, TcpStream, SocketAddr, SocketAddr)> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let client = TcpStream::connect(address).await?;
        let (server, peer) = listener.accept().await?;
        let local = server.local_addr()?;
        Ok((client, server, peer, local))
    }

    fn required_proxy(cidr: &str) -> HttpsProxyConfig {
        HttpsProxyConfig::RequiredV2 {
            trusted_peer_cidrs: vec![cidr.parse::<TrustedPeerCidr>().expect("trusted CIDR")],
        }
    }

    #[tokio::test]
    async fn dynamic_resolver_refreshes_atomically_and_fails_closed() {
        let storage = Arc::new(FakeCertificateStorage::default());
        let base = CertificateTarget::base_domain(hostname("example.test"));
        storage.insert_certificate(CertificateRecord::ready(
            base,
            CertificateProviderKind::Cloudflare,
            material(&["example.test", "*.example.test"], 10_000),
            Timestamp::from_unix_seconds(100),
        ));
        let authorization = Arc::new(AuthorizedHostnames::new([
            hostname("example.test"),
            hostname("demo.example.test"),
            hostname("cloud.example.test"),
            hostname("api.cloud.example.test"),
        ]));
        let resolver = DynamicTlsCertificateResolver::new(
            storage.clone(),
            authorization,
            default_crypto_provider(),
        );
        resolver
            .refresh(Timestamp::from_unix_seconds(1_000))
            .await
            .expect("refresh base certificate");

        assert!(resolver.resolves_at("example.test", Timestamp::from_unix_seconds(1_000)));
        assert!(resolver.resolves_at("demo.example.test", Timestamp::from_unix_seconds(1_000)));
        assert!(!resolver.resolves_at("unknown.example.test", Timestamp::from_unix_seconds(1_000)));

        let cloud = CertificateTarget::namespace(hostname("cloud.example.test"));
        storage.insert_certificate(CertificateRecord::pending(
            cloud.clone(),
            CertificateProviderKind::Cloudflare,
            Timestamp::from_unix_seconds(1_000),
        ));
        resolver
            .refresh(Timestamp::from_unix_seconds(1_000))
            .await
            .expect("refresh pending child");
        assert!(!resolver.resolves_at("cloud.example.test", Timestamp::from_unix_seconds(1_000)));

        storage.insert_certificate(CertificateRecord::ready(
            cloud,
            CertificateProviderKind::Cloudflare,
            material(&["cloud.example.test", "*.cloud.example.test"], 10_000),
            Timestamp::from_unix_seconds(1_000),
        ));
        resolver
            .refresh(Timestamp::from_unix_seconds(1_000))
            .await
            .expect("refresh ready child");
        assert!(resolver.resolves_at(
            "api.cloud.example.test",
            Timestamp::from_unix_seconds(1_000)
        ));
        assert!(!resolver.resolves_at(
            "api.cloud.example.test",
            Timestamp::from_unix_seconds(10_000)
        ));
    }

    struct BoundaryAuthorization {
        hostname: Hostname,
        boundary: Hostname,
    }

    impl SniAuthorization for BoundaryAuthorization {
        fn is_authorized(&self, hostname: &Hostname) -> bool {
            hostname == &self.hostname
        }

        fn required_certificate_apex(&self, hostname: &Hostname) -> Option<Hostname> {
            (hostname == &self.hostname).then(|| self.boundary.clone())
        }
    }

    #[tokio::test]
    async fn a_persisted_claim_boundary_blocks_parent_fallback_without_a_child_record() {
        let storage = Arc::new(FakeCertificateStorage::default());
        storage.insert_certificate(CertificateRecord::ready(
            CertificateTarget::base_domain(hostname("example.test")),
            CertificateProviderKind::Cloudflare,
            material(&["example.test", "*.example.test"], 10_000),
            Timestamp::from_unix_seconds(100),
        ));
        let authorization = Arc::new(BoundaryAuthorization {
            hostname: hostname("cloud.example.test"),
            boundary: hostname("cloud.example.test"),
        });
        let resolver =
            DynamicTlsCertificateResolver::new(storage, authorization, default_crypto_provider());
        resolver
            .refresh(Timestamp::from_unix_seconds(1_000))
            .await
            .expect("refresh base certificate");

        assert!(!resolver.resolves_at("cloud.example.test", Timestamp::from_unix_seconds(1_000)));
    }

    #[tokio::test]
    async fn managed_fallback_replays_client_hello_and_unknown_sni_fails_closed()
    -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let database = Database::open(directory.path().join("managed-fallback.sqlite3")).await?;
        let state = RuntimeState::new(database, "example.test")?;
        let hello = test_client_hello(Some("example.test"));
        let (mut client, server, peer, local) = tcp_pair().await?;
        client.write_all(&hello).await?;
        let outcome = predispatch_connection(
            server,
            peer,
            local,
            TlsPredispatch {
                state: state.clone(),
                proxy: HttpsProxyConfig::Disabled,
            },
        )
        .await?;
        let PredispatchOutcome::Managed {
            mut stream,
            endpoints,
            sni,
        } = outcome
        else {
            return Err("managed base SNI entered passthrough".into());
        };
        assert_eq!(endpoints.source, peer);
        assert_eq!(sni, hostname("example.test"));
        let mut replayed = vec![0; hello.len()];
        stream.read_exact(&mut replayed).await?;
        assert_eq!(replayed, hello);

        let unknown = test_client_hello(Some("unknown.example.test"));
        let (mut client, server, peer, local) = tcp_pair().await?;
        client.write_all(&unknown).await?;
        assert!(matches!(
            predispatch_connection(
                server,
                peer,
                local,
                TlsPredispatch {
                    state,
                    proxy: HttpsProxyConfig::Disabled,
                },
            )
            .await,
            Err(PredispatchError::UnauthorizedSni)
        ));
        Ok(())
    }

    #[tokio::test]
    async fn durable_passthrough_apex_child_and_disconnected_routes_fail_closed_without_broker()
    -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let database = Database::open(directory.path().join("raw-fail-closed.sqlite3")).await?;
        let issued = database.create_user("raw-offline").await?;
        database
            .create_namespace_claim_with_tls_mode(
                issued.user.id,
                "cloud.example.test",
                "example.test",
                2,
                NamespaceTlsMode::Passthrough,
            )
            .await?;
        let state = RuntimeState::new(database, "example.test")?;

        for sni in ["cloud.example.test", "api.cloud.example.test"] {
            let hello = test_client_hello(Some(sni));
            let (mut client, server, peer, local) = tcp_pair().await?;
            client.write_all(&hello).await?;
            assert!(matches!(
                predispatch_connection(
                    server,
                    peer,
                    local,
                    TlsPredispatch {
                        state: state.clone(),
                        proxy: HttpsProxyConfig::Disabled,
                    },
                )
                .await,
                Err(PredispatchError::PassthroughUnavailable)
            ));
        }

        for sni in ["deep.api.cloud.example.test", "unknown.example.test"] {
            let hello = test_client_hello(Some(sni));
            let (mut client, server, peer, local) = tcp_pair().await?;
            client.write_all(&hello).await?;
            assert!(matches!(
                predispatch_connection(
                    server,
                    peer,
                    local,
                    TlsPredispatch {
                        state: state.clone(),
                        proxy: HttpsProxyConfig::Disabled,
                    },
                )
                .await,
                Err(PredispatchError::UnauthorizedSni)
            ));
        }

        let (broker, _requests) = StreamBroker::channel();
        let lease = state
            .claims
            .acquire_passthrough(
                ClaimOwner {
                    user_id: issued.user.id,
                    session_id: Uuid::from_u128(44),
                },
                hostname("cloud.example.test"),
                broker,
                Instant::now(),
            )
            .map_err(|error| io::Error::other(format!("wildcard claim failed: {error:?}")))?;
        state
            .claims
            .disconnect(&lease, Instant::now())
            .ok_or("wildcard did not disconnect")?;
        let hello = test_client_hello(Some("api.cloud.example.test"));
        let (mut client, server, peer, local) = tcp_pair().await?;
        client.write_all(&hello).await?;
        assert!(matches!(
            predispatch_connection(
                server,
                peer,
                local,
                TlsPredispatch {
                    state,
                    proxy: HttpsProxyConfig::Disabled,
                },
            )
            .await,
            Err(PredispatchError::PassthroughUnavailable)
        ));
        Ok(())
    }

    #[tokio::test]
    async fn raw_passthrough_preamble_uses_trusted_proxy_metadata_and_tls_bytes_are_exact()
    -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let database = Database::open(directory.path().join("raw-active.sqlite3")).await?;
        let issued = database.create_user("raw-active").await?;
        database
            .create_namespace_claim_with_tls_mode(
                issued.user.id,
                "cloud.example.test",
                "example.test",
                2,
                NamespaceTlsMode::Passthrough,
            )
            .await?;
        let state = RuntimeState::new(database, "example.test")?;
        let (broker, server_driver, client_driver, mut received) = raw_tunnel();
        state
            .claims
            .acquire_passthrough(
                ClaimOwner {
                    user_id: issued.user.id,
                    session_id: Uuid::from_u128(45),
                },
                hostname("cloud.example.test"),
                broker.clone(),
                Instant::now(),
            )
            .map_err(|error| io::Error::other(format!("wildcard claim failed: {error:?}")))?;

        for (index, requested_sni, canonical_sni) in [
            (0_u16, "Cloud.Example.Test", "cloud.example.test"),
            (1_u16, "API.Cloud.Example.Test", "api.cloud.example.test"),
        ] {
            let source = SocketAddr::new("192.0.2.10".parse()?, 41000 + index);
            let destination = "198.51.100.20:443".parse::<SocketAddr>()?;
            let proxy = ProxyV2Header::proxied(source, destination)?.encode()?;
            let hello = fragment_handshake_across_records(&test_client_hello(Some(requested_sni)));
            let tail = b"opaque-tls-after-client-hello";
            let mut expected_tls = hello.clone();
            expected_tls.extend_from_slice(tail);
            let (mut client, server, peer, local) = tcp_pair().await?;
            for chunk in proxy.chunks(2) {
                client.write_all(chunk).await?;
            }
            for chunk in hello.chunks(3) {
                client.write_all(chunk).await?;
            }
            client.write_all(tail).await?;
            client.shutdown().await?;

            assert!(matches!(
                predispatch_connection(
                    server,
                    peer,
                    local,
                    TlsPredispatch {
                        state: state.clone(),
                        proxy: required_proxy("127.0.0.0/8"),
                    },
                )
                .await?,
                PredispatchOutcome::Passthrough
            ));
            let (open, relayed_tls) = timeout(Duration::from_secs(2), received.recv())
                .await?
                .ok_or("raw stream receiver closed")??;
            assert_eq!(open.route_hostname(), canonical_sni);
            assert_eq!(open.source(), source);
            assert_eq!(open.destination(), destination);
            assert_eq!(relayed_tls, expected_tls);
        }

        broker.shutdown();
        assert_eq!(server_driver.await?, DriverExit::Shutdown);
        client_driver.await??;
        Ok(())
    }

    fn raw_tunnel() -> RawTunnel {
        let (server_io, client_io) = tokio::io::duplex(1024 * 1024);
        let (broker, requests) = StreamBroker::channel();
        let server_driver = tokio::spawn(drive_yamux(server_io.compat(), requests));
        let (received, receive) = mpsc::unbounded_channel();
        let client_driver = tokio::spawn(async move {
            let mut connection =
                Connection::new(client_io.compat(), Config::default(), Mode::Client);
            loop {
                match poll_fn(|context| connection.poll_next_inbound(context)).await {
                    Some(Ok(mut stream)) => {
                        let received = received.clone();
                        tokio::spawn(async move {
                            let result = async {
                                let open = read_raw_stream_open(&mut stream)
                                    .await
                                    .map_err(io::Error::other)?;
                                let mut tls = Vec::new();
                                FuturesAsyncReadExt::read_to_end(&mut stream, &mut tls).await?;
                                Ok((open, tls))
                            }
                            .await;
                            let _ = received.send(result);
                        });
                    }
                    Some(Err(error)) => return Err(io::Error::other(error)),
                    None => return Ok(()),
                }
            }
        });
        (broker, server_driver, client_driver, receive)
    }

    #[tokio::test]
    async fn tls_listener_rejects_unknown_sni_and_accepts_an_authorized_name() {
        let RcgenCertifiedKey { cert, signing_key } = generate_simple_self_signed(vec![
            "example.test".to_owned(),
            "*.example.test".to_owned(),
        ])
        .expect("generate local certificate");
        let root_certificate = cert.der().clone();
        let storage = Arc::new(FakeCertificateStorage::default());
        storage.insert_certificate(CertificateRecord::ready(
            CertificateTarget::base_domain(hostname("example.test")),
            CertificateProviderKind::Cloudflare,
            CertificateMaterial {
                certificate_chain_pem: cert.pem().into_bytes(),
                private_key_pem: SecretBytes::new(signing_key.serialize_pem().into_bytes()),
                not_before: Timestamp::from_unix_seconds(100),
                not_after: Timestamp::from_unix_seconds(u64::MAX),
            },
            Timestamp::from_unix_seconds(100),
        ));
        let authorization = Arc::new(AuthorizedHostnames::new([hostname("demo.example.test")]));
        let crypto_provider = default_crypto_provider();
        let resolver = Arc::new(DynamicTlsCertificateResolver::new(
            storage,
            authorization,
            crypto_provider.clone(),
        ));
        resolver
            .refresh(now_timestamp())
            .await
            .expect("refresh certificate");
        let server_config =
            build_tls_server_config(resolver, crypto_provider.clone()).expect("server TLS config");
        let tcp_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind local TLS listener");
        let address = tcp_listener.local_addr().expect("local address");
        let mut listener = TlsListener::new(tcp_listener, server_config);
        let accepted = tokio::spawn(async move { listener.accept().await });

        // A client that never sends ClientHello must not head-of-line block
        // subsequent handshakes.
        let stalled_tcp = TcpStream::connect(address)
            .await
            .expect("connect stalled TLS client");

        let mut roots = RootCertStore::empty();
        roots.add(root_certificate).expect("add local trust root");
        let client_config = ClientConfig::builder_with_provider(crypto_provider)
            .with_safe_default_protocol_versions()
            .expect("client protocol versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(client_config));

        let unknown_tcp = TcpStream::connect(address)
            .await
            .expect("connect unknown SNI");
        let unknown_name =
            ServerName::try_from("unknown.example.test".to_owned()).expect("valid server name");
        assert!(
            connector
                .clone()
                .connect(unknown_name, unknown_tcp)
                .await
                .is_err()
        );

        let known_tcp = TcpStream::connect(address)
            .await
            .expect("connect known SNI");
        let known_name =
            ServerName::try_from("demo.example.test".to_owned()).expect("valid server name");
        let client_stream = connector
            .connect(known_name, known_tcp)
            .await
            .expect("authorized TLS handshake");
        let (server_stream, connection) = accepted.await.expect("TLS accept task");
        assert_eq!(connection.sni, hostname("demo.example.test"));
        drop(stalled_tcp);
        drop(client_stream);
        drop(server_stream);
    }
}
