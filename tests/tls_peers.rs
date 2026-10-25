//! Plan task 14 criterion 8: one TLS listener + pin-gated `/_internal/peers/*`.
//!
//! Drives a real `rustls` client against the bound server:
//! (a) a pinned peer certificate is accepted on `POST /_internal/peers/hello`,
//! (b) an unpinned certificate is rejected there with 403,
//! (c) no client certificate still serves `GET /health` but is 403 on the
//!     peer route.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use cachette::config::ServerConfig;
use cachette::identity::{Identity, fingerprint_spki};
use cachette::routes;
use cachette::state::AppState;
use cachette::tls::{self, PeerCert, PeerPins};
use rustls::RootCertStore;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as RustlsError, SignatureScheme};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

/// Self-cleaning unique temp directory.
struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let unique = format!(
            "cachette-tls-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let path = std::env::temp_dir().join(unique);
        std::fs::create_dir_all(&path).expect("temp dir");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn mint(root: &Path, name: &str) -> Identity {
    Identity::load_or_generate(&root.join(name), Some(name), Some("127.0.0.1"))
        .expect("identity mints")
}

fn certs(identity: &Identity) -> Vec<CertificateDer<'static>> {
    let mut reader = std::io::BufReader::new(identity.cert_pem().as_bytes());
    rustls_pemfile::certs(&mut reader)
        .collect::<Result<_, _>>()
        .expect("identity PEM has certificates")
}

fn key(identity: &Identity) -> PrivateKeyDer<'static> {
    let mut reader = std::io::BufReader::new(identity.key_pem().as_bytes());
    rustls_pemfile::private_key(&mut reader)
        .expect("identity key parses")
        .expect("identity PEM has a key")
}

fn client_config(server: &Identity, client: Option<&Identity>) -> Arc<rustls::ClientConfig> {
    let mut roots = RootCertStore::empty();
    for cert in certs(server) {
        roots.add(cert).expect("anchor the server cert");
    }
    let builder = rustls::ClientConfig::builder().with_root_certificates(roots);
    let config = match client {
        Some(identity) => builder
            .with_client_auth_cert(certs(identity), key(identity))
            .expect("client cert/key match"),
        None => builder.with_no_client_auth(),
    };
    Arc::new(config)
}

/// Bind the TLS listener on an ephemeral port serving `server`'s identity and
/// pinning `pinned` peers, and serve the router on a task for the test's
/// lifetime. Returns the bound address.
async fn serve(server: &Identity, pinned: &[&Identity]) -> SocketAddr {
    let mut seed = BTreeMap::new();
    for (index, peer) in pinned.iter().enumerate() {
        seed.insert(format!("peer-{index}"), peer.fingerprint().to_owned());
    }
    let mut state = AppState::new();
    state.node_id = server.fingerprint().to_owned();
    state.peers = Arc::new(PeerPins::new(&seed, false));
    let section = ServerConfig {
        listen: String::from("127.0.0.1:0"),
        external_url: None,
        tls_cert: None,
        tls_key: None,
        max_chunk_bytes: 64 * 1024 * 1024,
        drain_grace_seconds: 30,
    };
    let config = tls::server_config(&section, server).expect("TLS config builds");
    let listener = tls::bind("127.0.0.1:0", config).await.expect("binds");
    let addr = listener.bind_addr().expect("bound addr");
    let app = routes::router(state);
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<PeerCert>(),
        )
        .await
        .expect("serve runs");
    });
    addr
}

/// Mint a fresh server identity and serve it (see [`serve`]).
async fn start_server(pinned: &[&Identity]) -> (SocketAddr, Identity) {
    let root = TestDir::new();
    let server = mint(root.path(), "server");
    let addr = serve(&server, pinned).await;
    (addr, server)
}

/// A peer-side verifier that trusts the server iff the certificate's SPKI
/// fingerprint is pinned, ignoring the validity window — the same trust
/// decision as production's `PinnedServerCert`, which a rotation must preserve.
#[derive(Debug)]
struct PinnedByFingerprint {
    pins: Arc<PeerPins>,
    algs: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for PinnedByFingerprint {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        let parsed = rustls::server::ParsedCertificate::try_from(end_entity)
            .map_err(|err| RustlsError::General(format!("peer certificate unusable: {err}")))?;
        let fingerprint = fingerprint_spki(parsed.subject_public_key_info().as_ref());
        if self.pins.authorize(&fingerprint) {
            return Ok(ServerCertVerified::assertion());
        }
        Err(RustlsError::General(format!(
            "peer certificate not pinned: {fingerprint}"
        )))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls12_signature(message, cert, dss, &self.algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

/// A client pinned to `pins` by SPKI fingerprint (no client certificate).
fn pinned_client(pins: Arc<PeerPins>) -> Arc<rustls::ClientConfig> {
    let algs = rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms;
    Arc::new(
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinnedByFingerprint { pins, algs }))
            .with_no_client_auth(),
    )
}

/// One HTTP/1.1 exchange over a fresh TLS connection; returns (status, text).
async fn request(
    addr: SocketAddr,
    config: Arc<rustls::ClientConfig>,
    method: &str,
    path: &str,
) -> (u16, String) {
    let tcp = TcpStream::connect(addr).await.expect("tcp connect");
    let server_name = ServerName::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST).into());
    let mut stream: TlsStream<TcpStream> = TlsConnector::from(config)
        .connect(server_name, tcp)
        .await
        .expect("TLS handshake");
    let head = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
    );
    stream
        .write_all(head.as_bytes())
        .await
        .expect("write request");
    let mut raw = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut raw))
        .await
        .expect("response before timeout")
        .expect("read response");
    let text = String::from_utf8_lossy(&raw).into_owned();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or_else(|| panic!("no HTTP status in response: {text:?}"));
    (status, text)
}

#[tokio::test]
async fn pinned_peer_cert_is_accepted_on_peer_hello() {
    let root = TestDir::new();
    let peer = mint(root.path(), "peer");
    let (addr, server) = start_server(&[&peer]).await;
    let (status, body) = request(
        addr,
        client_config(&server, Some(&peer)),
        "POST",
        "/_internal/peers/hello",
    )
    .await;
    assert_eq!(status, 200, "body: {body}");
    assert!(body.contains(r#""accepted":true"#), "body: {body}");
    assert!(
        body.contains(&format!(r#""node_id":"{}""#, server.fingerprint())),
        "body: {body}"
    );
}

#[tokio::test]
async fn unpinned_peer_cert_is_forbidden_on_peer_hello() {
    let root = TestDir::new();
    let pinned = mint(root.path(), "pinned");
    let rogue = mint(root.path(), "rogue");
    let (addr, server) = start_server(&[&pinned]).await;
    let (status, body) = request(
        addr,
        client_config(&server, Some(&rogue)),
        "POST",
        "/_internal/peers/hello",
    )
    .await;
    assert_eq!(status, 403, "body: {body}");
    assert!(body.contains("peer auth required"), "body: {body}");
}

#[tokio::test]
async fn no_client_cert_serves_health_but_not_peer_routes() {
    let root = TestDir::new();
    let pinned = mint(root.path(), "pinned");
    let (addr, server) = start_server(&[&pinned]).await;

    let (health_status, _) = request(addr, client_config(&server, None), "GET", "/health").await;
    assert_eq!(health_status, 200);

    let (peer_status, body) = request(
        addr,
        client_config(&server, None),
        "POST",
        "/_internal/peers/hello",
    )
    .await;
    assert_eq!(peer_status, 403, "body: {body}");
    assert!(body.contains("peer auth required"), "body: {body}");
}

/// Plan task 48: a peer that pinned the node BEFORE a certificate rotation
/// keeps accepting it. Renewal re-issues the certificate for the same key, so
/// the SPKI fingerprint — and every pin — is unchanged.
#[tokio::test]
async fn peer_pinned_to_old_fingerprint_accepts_a_renewed_certificate() {
    let root = TestDir::new();
    let dir = root.path().join("server");
    let server = Identity::load_or_generate(&dir, Some("server"), Some("127.0.0.1"))
        .expect("identity mints");
    let old_fingerprint = server.fingerprint().to_owned();
    // The peer's trust: a single pin collected (and seeded) BEFORE rotation.
    let pins = Arc::new(PeerPins::new(
        &BTreeMap::from([(String::from("server"), old_fingerprint.clone())]),
        false,
    ));

    // Baseline: the pinned peer completes a handshake with the original cert.
    let before = serve(&server, &[]).await;
    let (status, body) = request(before, pinned_client(pins.clone()), "GET", "/health").await;
    assert_eq!(status, 200, "baseline handshake: {body}");

    // Rotate in place: same key, fresh certificate on a refreshed window.
    let renewed = Identity::renew(&dir, Some("server"), Some("127.0.0.1")).expect("renew");
    assert_eq!(renewed.fingerprint(), old_fingerprint, "pin is invariant");
    assert_ne!(renewed.cert_pem(), server.cert_pem(), "certificate changed");

    // A server restarted with the renewed certificate: the peer still holds
    // ONLY the old pin and still completes the handshake — no re-seed, no
    // cluster coordination.
    let after = serve(&renewed, &[]).await;
    let (status, body) = request(after, pinned_client(pins), "GET", "/health").await;
    assert_eq!(
        status, 200,
        "pinned peer accepts the renewed certificate: {body}"
    );
}
