//! Plan task 17: auth x TLS integration matrix.
//!
//! Drives a *real* loopback TLS listener (the proven `tests/tls_peers.rs`
//! pattern) whose server certificate is signed by a test-only root CA, then
//! connects with a `rustls` client that anchors **only** that CA
//! (`RootCertStore::empty()` + `add(ca)`), using `ServerName::IpAddress` and a
//! `tokio-rustls` connector. Certificate verification is never disabled on the
//! client side — local-only trust comes from the test CA in the root store.
//!
//! The matrix is `{hmac, bearer, merge} x {artifactcache GET, mTLS peer} x
//! {runner-no-cert, peer-cert}`. Every cell below is asserted against a real
//! handshake.
//!
//! The artifactcache cells probe an **unmapped path under the guarded prefix**
//! (`/_apis/artifactcache/__matrix_probe`): it is covered by the path-scoped
//! `require_auth` gate but has no route in either state of the repo, so an
//! auth *pass* deterministically reaches the JSON 404 fallback while a
//! rejection is the 401 gate response — the same decisive "gate passed" signal
//! `tests/auth.rs` gets from its stub route, without adding a production route
//! (task 18 owns those).
//!
//! Asserted cells (17):
//!   C1  hmac   + artifactcache + no creds      + no cert   -> 401
//!   C2  hmac   + artifactcache + valid HMAC    + no cert   -> 404 (auth pass)
//!   C3  hmac   + artifactcache + valid HMAC    + peer cert -> 404 (auth pass)
//!   C4  hmac   + artifactcache + no creds      + peer cert -> 401 (cert != cred)
//!   C5  bearer + artifactcache + no creds      + no cert   -> 401
//!   C6  bearer + artifactcache + valid bearer  + no cert   -> 404 (auth pass)
//!   C7  bearer + artifactcache + valid bearer  + peer cert -> 404 (auth pass)
//!   C8  merge  + artifactcache + no creds      + no cert   -> 401
//!   C9  merge  + artifactcache + valid HMAC    + no cert   -> 404 (auth pass)
//!   C10 merge  + artifactcache + valid bearer  + no cert   -> 404 (auth pass, SAME server as C9)
//!   C11 merge  + artifactcache + wrong bearer  + no cert   -> 401
//!   C12 merge  + artifactcache + valid HMAC    + peer cert -> 404 (auth pass)
//!   C13 mTLS peer + no cert                                -> 403
//!   C14 mTLS peer + pinned peer cert                       -> 200
//!   C15 mTLS peer + CA-signed but unpinned rogue cert      -> 403
//!   C16 signed-url GET + minted params validate            -> Ok
//!   C17 signed-url GET + tampered mac                      -> Err
//!
//! C9 and C10 are the plan's "merge+hmac AND merge+bearer both succeed on the
//! SAME running server" requirement.

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cachette::auth::{self, AuthPolicy, TokenStore};
use cachette::config::{AuthMode, ServerConfig};
use cachette::identity::{Identity, fingerprint_spki};
use cachette::routes;
use cachette::state::AppState;
use cachette::tls::{self, PeerCert, PeerPins};
use hmac::{Hmac, KeyInit, Mac};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair,
};
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use sha2::Sha256;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

const SECRET: &str = "test-secret-0123456789abcdef";
const REPO: &str = "owner/cachette";
const RUN: &str = "1";
const ISOLATION: &str = "";
const STATIC_TOKEN: &str = "static-token-1";
/// Covered by the auth prefix, never routed: auth-pass => 404 fallback.
const ARTIFACTCACHE_PROBE: &str = "/_apis/artifactcache/__matrix_probe";
const PEER_HELLO: &str = "/_internal/peers/hello";

/// Self-cleaning unique temp directory (mirrors `tests/tls_peers.rs`).
struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let unique = format!(
            "cachette-auth-tls-{}-{}",
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

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_secs() as i64
}

/// Independent MAC computation (Forgejo runner `act/artifactcache/mac.go`):
/// `hex(HMAC-SHA256(secret, "<repo>><run>><ts>><isolation>"))`.
fn compute_mac(secret: &str, repo: &str, run: &str, ts: i64, isolation: &str) -> String {
    let payload = format!("{repo}>{run}>{ts}>{isolation}");
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("hmac key");
    mac.update(payload.as_bytes());
    mac.finalize()
        .into_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// A fresh, valid `Forgejo-Cache-*` header set.
fn hmac_headers() -> Vec<(String, String)> {
    let ts = now_secs();
    let mac = compute_mac(SECRET, REPO, RUN, ts, ISOLATION);
    vec![
        (String::from("forgejo-cache-repo"), String::from(REPO)),
        (String::from("forgejo-cache-runnumber"), String::from(RUN)),
        (String::from("forgejo-cache-timestamp"), ts.to_string()),
        (String::from("forgejo-cache-mac"), mac),
    ]
}

/// Borrowed view of owned header pairs for [`request`].
fn as_refs(headers: &[(String, String)]) -> Vec<(&str, &str)> {
    headers
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect()
}

/// Local-only PKI: one test root CA plus a CA-signed server cert and two
/// CA-signed client certs (one pinned peer, one unpinned rogue).
struct Pki {
    /// Root CA DER — the only thing the client trusts.
    ca: CertificateDer<'static>,
    server_cert_pem: String,
    server_key_pem: String,
    /// Pinned peer certificate + its key + its SPKI fingerprint.
    peer_cert: CertificateDer<'static>,
    peer_key: KeyPair,
    peer_fp: String,
    /// CA-signed but *unpinned* certificate — must still be rejected by the pin gate.
    rogue_cert: CertificateDer<'static>,
    rogue_key: KeyPair,
}

/// Generate a key and a CA-signed certificate for `cn` with optional SAN.
fn ca_signed(
    ca: &Certificate,
    ca_key: &KeyPair,
    cn: &str,
    san: Option<&str>,
) -> (Certificate, KeyPair) {
    let key = KeyPair::generate().expect("generate key");
    let subject_alt_names = san.map_or_else(Vec::new, |name| vec![name.to_owned()]);
    let mut params = CertificateParams::new(subject_alt_names).expect("cert params");
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, cn);
    params.distinguished_name = dn;
    let cert = params.signed_by(&key, ca, ca_key).expect("CA signs cert");
    (cert, key)
}

fn build_pki() -> Pki {
    let ca_key = KeyPair::generate().expect("ca key");
    let mut ca_params = CertificateParams::new(Vec::new()).expect("ca params");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let mut ca_dn = DistinguishedName::new();
    ca_dn.push(DnType::CommonName, "cachette test root CA");
    ca_params.distinguished_name = ca_dn;
    let ca = ca_params.self_signed(&ca_key).expect("self-signed CA");

    let (server, server_key) = ca_signed(&ca, &ca_key, "cachette test server", Some("127.0.0.1"));
    let (peer, peer_key) = ca_signed(&ca, &ca_key, "cachette test peer", None);
    let (rogue, rogue_key) = ca_signed(&ca, &ca_key, "cachette test rogue", None);
    Pki {
        ca: ca.der().clone(),
        server_cert_pem: server.pem(),
        server_key_pem: server_key.serialize_pem(),
        peer_fp: fingerprint_spki(&peer_key.public_key_der()),
        peer_cert: peer.der().clone(),
        peer_key,
        rogue_cert: rogue.der().clone(),
        rogue_key,
    }
}

/// Pin store seeded with the peer fingerprint (TOFU off, single-node default).
fn pinned(pki: &Pki) -> PeerPins {
    let seed = BTreeMap::from([(String::from("peer"), pki.peer_fp.clone())]);
    PeerPins::new(&seed, false)
}

/// Empty pin store: no cert can be authorized.
fn no_pins() -> PeerPins {
    PeerPins::new(&BTreeMap::new(), false)
}

fn key_der(pem: &str) -> PrivateKeyDer<'static> {
    let mut reader = std::io::BufReader::new(pem.as_bytes());
    rustls_pemfile::private_key(&mut reader)
        .expect("private key parses")
        .expect("PEM has a private key")
}

/// rustls client trusting ONLY the test root CA; optional client certificate.
fn client_config(
    pki: &Pki,
    client: Option<(&CertificateDer<'static>, &KeyPair)>,
) -> Arc<rustls::ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.add(pki.ca.clone()).expect("anchor the test root CA");
    let builder = rustls::ClientConfig::builder().with_root_certificates(roots);
    let config = match client {
        Some((cert, key)) => builder
            .with_client_auth_cert(vec![cert.clone()], key_der(&key.serialize_pem()))
            .expect("client cert/key match"),
        None => builder.with_no_client_auth(),
    };
    Arc::new(config)
}

/// Bind the loopback TLS listener and serve the real router on a task.
async fn start_server(root: &Path, mode: AuthMode, pki: &Pki, peers: PeerPins) -> SocketAddr {
    std::fs::write(root.join("server.crt"), &pki.server_cert_pem).expect("write server cert");
    std::fs::write(root.join("server.key"), &pki.server_key_pem).expect("write server key");
    // The identity is unused because tls_cert/tls_key are set (operator edge, M9).
    let identity = Identity::load_or_generate(
        &root.join("identity"),
        Some("test-server"),
        Some("127.0.0.1"),
    )
    .expect("server identity");
    let section = ServerConfig {
        listen: String::from("127.0.0.1:0"),
        external_url: None,
        tls_cert: Some(root.join("server.crt")),
        tls_key: Some(root.join("server.key")),
        max_chunk_bytes: 64 * 1024 * 1024,
        drain_grace_seconds: 30,
    };
    let config = tls::server_config(&section, &identity).expect("TLS config builds");
    let listener = tls::bind("127.0.0.1:0", config).await.expect("binds");
    let addr = listener.bind_addr().expect("bound addr");

    let mut state = AppState::new();
    state.node_id = String::from("test-node");
    state.tokens =
        Arc::new(TokenStore::open(&root.join("auth.sqlite3")).expect("token store opens"));
    state.set_auth(AuthPolicy {
        mode,
        secret: Some(SECRET.to_owned()),
        hmac_max_age_seconds: 600,
        static_tokens: vec![STATIC_TOKEN.to_owned()],
        cluster_enabled: false,
    });
    state.peers = Arc::new(peers);
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

/// One HTTP/1.1 exchange over a fresh TLS connection; returns (status, text).
async fn request(
    addr: SocketAddr,
    config: Arc<rustls::ClientConfig>,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
) -> (u16, String) {
    let tcp = TcpStream::connect(addr).await.expect("tcp connect");
    let server_name = ServerName::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST).into());
    let mut stream: TlsStream<TcpStream> = TlsConnector::from(config)
        .connect(server_name, tcp)
        .await
        .expect("TLS handshake");
    let mut head = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nContent-Length: 0\r\n"
    );
    for (name, value) in headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
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

/// Auth gate saw valid credentials: the request reached the 404 fallback.
fn assert_auth_passed(status: u16, body: &str, cell: &str) {
    assert_eq!(
        status, 404,
        "{cell}: expected auth pass-through, got {status}: {body}"
    );
}

/// Auth gate rejected the request with the opaque 401 body.
fn assert_auth_rejected(status: u16, body: &str, cell: &str) {
    assert_eq!(status, 401, "{cell}: {body}");
    assert!(body.contains("authentication required"), "{cell}: {body}");
}

/// hmac mode: HMAC authenticates; a bearer token and a client cert alone do not.
#[tokio::test]
async fn hmac_mode_gate_over_tls() {
    let root = TestDir::new();
    let pki = build_pki();
    let addr = start_server(root.path(), AuthMode::Hmac, &pki, no_pins()).await;
    let anon = client_config(&pki, None);
    let peer = client_config(&pki, Some((&pki.peer_cert, &pki.peer_key)));
    let hmac_owned = hmac_headers();
    let hmac = as_refs(&hmac_owned);

    // C1
    let (status, body) = request(addr, anon.clone(), "GET", ARTIFACTCACHE_PROBE, &[]).await;
    assert_auth_rejected(status, &body, "C1 hmac/no-creds");

    // C2
    let (status, body) = request(addr, anon.clone(), "GET", ARTIFACTCACHE_PROBE, &hmac).await;
    assert_auth_passed(status, &body, "C2 hmac/valid-hmac");

    // C3
    let (status, body) = request(addr, peer.clone(), "GET", ARTIFACTCACHE_PROBE, &hmac).await;
    assert_auth_passed(status, &body, "C3 hmac/valid-hmac+peer-cert");

    // C4 — a client certificate is not a v1 credential.
    let (status, body) = request(addr, peer, "GET", ARTIFACTCACHE_PROBE, &[]).await;
    assert_auth_rejected(status, &body, "C4 hmac/peer-cert-no-creds");

    // hmac mode rejects a bearer token.
    let (status, body) = request(
        addr,
        anon,
        "GET",
        ARTIFACTCACHE_PROBE,
        &[("authorization", "Bearer static-token-1")],
    )
    .await;
    assert_auth_rejected(status, &body, "hmac mode rejects bearer");
}

/// bearer mode: the static token authenticates; a valid HMAC does not.
#[tokio::test]
async fn bearer_mode_gate_over_tls() {
    let root = TestDir::new();
    let pki = build_pki();
    let addr = start_server(root.path(), AuthMode::Bearer, &pki, no_pins()).await;
    let anon = client_config(&pki, None);
    let peer = client_config(&pki, Some((&pki.peer_cert, &pki.peer_key)));
    let bearer = [("authorization", "Bearer static-token-1")];

    // C5
    let (status, body) = request(addr, anon.clone(), "GET", ARTIFACTCACHE_PROBE, &[]).await;
    assert_auth_rejected(status, &body, "C5 bearer/no-creds");

    // C6
    let (status, body) = request(addr, anon.clone(), "GET", ARTIFACTCACHE_PROBE, &bearer).await;
    assert_auth_passed(status, &body, "C6 bearer/valid-token");

    // C7
    let (status, body) = request(addr, peer, "GET", ARTIFACTCACHE_PROBE, &bearer).await;
    assert_auth_passed(status, &body, "C7 bearer/valid-token+peer-cert");

    // bearer mode rejects a valid HMAC.
    let hmac_owned = hmac_headers();
    let hmac = as_refs(&hmac_owned);
    let (status, body) = request(addr, anon, "GET", ARTIFACTCACHE_PROBE, &hmac).await;
    assert_auth_rejected(status, &body, "bearer mode rejects hmac");
}

/// merge mode: HMAC *and* bearer both succeed on the SAME running server.
#[tokio::test]
async fn merge_mode_accepts_hmac_and_bearer_on_one_server() {
    let root = TestDir::new();
    let pki = build_pki();
    let addr = start_server(root.path(), AuthMode::Merge, &pki, no_pins()).await;
    let anon = client_config(&pki, None);
    let peer = client_config(&pki, Some((&pki.peer_cert, &pki.peer_key)));
    let hmac_owned = hmac_headers();
    let hmac = as_refs(&hmac_owned);

    // C8
    let (status, body) = request(addr, anon.clone(), "GET", ARTIFACTCACHE_PROBE, &[]).await;
    assert_auth_rejected(status, &body, "C8 merge/no-creds");

    // C9 — HMAC pass on this server.
    let (status, body) = request(addr, anon.clone(), "GET", ARTIFACTCACHE_PROBE, &hmac).await;
    assert_auth_passed(status, &body, "C9 merge/valid-hmac");

    // C10 — bearer pass on the SAME server (the plan's key merge requirement).
    let (status, body) = request(
        addr,
        anon.clone(),
        "GET",
        ARTIFACTCACHE_PROBE,
        &[("authorization", "Bearer static-token-1")],
    )
    .await;
    assert_auth_passed(status, &body, "C10 merge/valid-bearer");

    // C11 — a wrong bearer token is still rejected.
    let (status, body) = request(
        addr,
        anon,
        "GET",
        ARTIFACTCACHE_PROBE,
        &[("authorization", "Bearer wrong-token")],
    )
    .await;
    assert_auth_rejected(status, &body, "C11 merge/wrong-bearer");

    // C12 — HMAC passes while presenting a peer certificate too.
    let (status, body) = request(addr, peer, "GET", ARTIFACTCACHE_PROBE, &hmac).await;
    assert_auth_passed(status, &body, "C12 merge/valid-hmac+peer-cert");
}

/// mTLS peer pin gate: pinned cert accepted, no cert / unpinned cert rejected.
#[tokio::test]
async fn peer_pin_gate_over_tls() {
    let root = TestDir::new();
    let pki = build_pki();
    let addr = start_server(root.path(), AuthMode::Merge, &pki, pinned(&pki)).await;

    // C13
    let (status, body) = request(addr, client_config(&pki, None), "POST", PEER_HELLO, &[]).await;
    assert_eq!(status, 403, "C13 peer/no-cert: {body}");
    assert!(body.contains("peer auth required"), "C13 body: {body}");

    // C14
    let (status, body) = request(
        addr,
        client_config(&pki, Some((&pki.peer_cert, &pki.peer_key))),
        "POST",
        PEER_HELLO,
        &[],
    )
    .await;
    assert_eq!(status, 200, "C14 peer/pinned-cert: {body}");
    assert!(body.contains(r#""accepted":true"#), "C14 body: {body}");

    // C15 — CA-signed but unpinned: the pin gate, not the CA, is the trust anchor.
    let (status, body) = request(
        addr,
        client_config(&pki, Some((&pki.rogue_cert, &pki.rogue_key))),
        "POST",
        PEER_HELLO,
        &[],
    )
    .await;
    assert_eq!(status, 403, "C15 peer/unpinned-cert: {body}");
}

/// signed-url GET: task-16's primitive validates a minted URL and rejects a
/// tampered one, exercised alongside a real TLS request carrying the query.
#[tokio::test]
async fn signed_url_primitive_over_tls() {
    let root = TestDir::new();
    let pki = build_pki();
    let addr = start_server(root.path(), AuthMode::Merge, &pki, no_pins()).await;
    let path = "/_apis/artifactcache/artifacts/42";
    let now = now_secs();
    let signed = auth::urls::mint(path, "42", SECRET, 900, now);

    // The minted query really travels the loopback TLS connection. The
    // artifact path is authorized by its signed URL alone (task 22), so a valid
    // signature passes the download gate and reaches the handler (this fixture
    // has no storage, so the handler reports 503); an unsigned request is still
    // rejected with 403 at the download gate.
    let url = format!("{path}{}", signed.query());
    let (status, body) = request(addr, client_config(&pki, None), "GET", &url, &[]).await;
    assert_eq!(
        status, 503,
        "signed-url GET over TLS must reach the download handler: {body}"
    );
    let (unsigned_status, unsigned_body) =
        request(addr, client_config(&pki, None), "GET", path, &[]).await;
    assert_eq!(
        unsigned_status, 403,
        "an unsigned artifact GET must be rejected by the download gate: {unsigned_body}"
    );

    // C16 — minted params validate against the exact bound path.
    let params = HashMap::from([
        (String::from("id"), signed.id.clone()),
        (String::from("exp"), signed.exp.to_string()),
        (String::from("mac"), signed.mac.clone()),
    ]);
    assert_eq!(
        auth::urls::validate(&params, path, SECRET, now),
        Ok(()),
        "C16 minted URL validates"
    );

    // C17 — flipping one MAC hex digit is rejected.
    let mut bytes = signed.mac.clone().into_bytes();
    bytes[0] = if bytes[0] == b'0' { b'1' } else { b'0' };
    let mut tampered = params.clone();
    tampered.insert(
        String::from("mac"),
        String::from_utf8(bytes).expect("hex is utf-8"),
    );
    assert!(
        auth::urls::validate(&tampered, path, SECRET, now).is_err(),
        "C17 tampered URL must reject"
    );
}
