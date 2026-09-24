use std::{
    collections::HashMap,
    fmt,
    io::{self, Cursor},
    net::SocketAddr,
    sync::{Arc, OnceLock, RwLock},
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
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, server::TlsStream};

use crate::certificates::{
    CertificateIndexReloader, CertificateReloadError, CertificateState, CertificateStorage,
    CertificateTarget, Hostname, SniAuthorization, SniCertificateIndex, Timestamp,
};

use super::{
    NamespaceTlsBoundaries,
    claims::ClaimRegistry,
    host::{HostRoute, classify_host},
};

const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_PENDING_TLS_HANDSHAKES: usize = 256;

type TlsHandshake = BoxFuture<'static, Option<(TlsStream<TcpStream>, TlsConnectionAddress)>>;

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

/// Axum listener that completes rustls before handing a connection to the
/// shared HTTP router. Handshakes without an authorized, usable SNI
/// certificate never reach HTTP.
pub struct TlsListener {
    listener: TcpListener,
    acceptor: TlsAcceptor,
    handshakes: FuturesUnordered<TlsHandshake>,
}

impl TlsListener {
    pub fn new(listener: TcpListener, config: Arc<ServerConfig>) -> Self {
        Self {
            listener,
            acceptor: TlsAcceptor::from(config),
            handshakes: FuturesUnordered::new(),
        }
    }

    fn start_handshake(&mut self, stream: TcpStream, peer_addr: SocketAddr) {
        let acceptor = self.acceptor.clone();
        self.handshakes.push(Box::pin(async move {
            match tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
                Ok(Ok(stream)) => {
                    let Some(server_name) = stream.get_ref().1.server_name() else {
                        tracing::debug!(%peer_addr, "TLS handshake completed without SNI");
                        return None;
                    };
                    let Ok(sni) = Hostname::parse(server_name) else {
                        tracing::debug!(%peer_addr, "TLS handshake returned invalid SNI");
                        return None;
                    };
                    Some((stream, TlsConnectionAddress { peer_addr, sni }))
                }
                Ok(Err(error)) => {
                    tracing::debug!(%peer_addr, %error, "TLS handshake rejected");
                    None
                }
                Err(_) => {
                    tracing::debug!(%peer_addr, "TLS handshake timed out");
                    None
                }
            }
        }));
    }
}

impl Listener for TlsListener {
    type Io = TlsStream<TcpStream>;
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
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
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
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
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
    use rcgen::{CertifiedKey as RcgenCertifiedKey, generate_simple_self_signed};
    use rustls::{ClientConfig, RootCertStore, pki_types::ServerName};
    use tokio_rustls::TlsConnector;

    use super::*;
    use crate::certificates::{
        AuthorizedHostnames, CertificateMaterial, CertificateProviderKind, CertificateRecord,
        FakeCertificateStorage, SecretBytes,
    };

    fn hostname(value: &str) -> Hostname {
        Hostname::parse(value).expect("valid hostname")
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
