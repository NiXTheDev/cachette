//! Plan task 47 acceptance: graceful drain on shutdown (in-process).
//!
//! A draining node must (1) advertise `draining` so peers stop selecting it
//! for NEW placements, (2) keep serving in-flight requests, and (3) refuse NEW
//! uploads with `503` + `Retry-After` while still serving downloads/finalize.
//!
//! Windows has no SIGTERM (there is no way to deliver the signal to a child in
//! CI without `GenerateConsoleCtrlEvent` against a shared console process
//! group), so — exactly like the `CACHETTE_TEST_SHUTDOWN_AFTER_MS` precedent in
//! `tests/shutdown.rs` — the drain is simulated by setting `state.draining`
//! directly. The real signal path lives in `main.rs::serve`.
//!
//! The node is served over a real ephemeral TLS listener (mirrors the
//! `tests/v1_relay.rs` harness) so the axum middleware ordering is exercised
//! end to end, not just in a bare router call.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use cachette::auth::AuthPolicy;
use cachette::config::{AuthMode, KeyCase, MinFree, ServerConfig};
use cachette::identity::Identity;
use cachette::routes;
use cachette::state::{AppState, CacheLimits};
use cachette::storage::MemoryStorage;
use cachette::tls::{self, PeerCert};
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

const TOKEN: &str = "drain-test-token";

/// Self-cleaning unique temp directory (no `tempfile` dependency).
struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let unique = format!(
            "cachette-drain-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let path = std::env::temp_dir().join(unique);
        let _ = std::fs::remove_dir_all(&path);
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

fn client_config(server: &Identity) -> Arc<rustls::ClientConfig> {
    let mut roots = RootCertStore::empty();
    for cert in certs(server) {
        roots.add(cert).expect("anchor the server cert");
    }
    Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

/// Build a node [`AppState`]: bearer-auth with [`TOKEN`], an in-memory storage
/// backend (so the request path is live), and `draining` pre-set.
fn state_with(identity: &Identity, storage: &Arc<MemoryStorage>, draining: bool) -> AppState {
    let mut state = AppState::new();
    state.node_id = identity.fingerprint().to_owned();
    state.peers = Arc::new(cachette::tls::PeerPins::new(&BTreeMap::new(), false));
    state.storage = Some(storage.clone());
    state.auth = Arc::new(AuthPolicy {
        mode: AuthMode::Bearer,
        secret: None,
        hmac_max_age_seconds: 600,
        static_tokens: vec![TOKEN.to_owned()],
        cluster_enabled: true,
    });
    state.cache = CacheLimits {
        max_size: 0,
        min_free: MinFree::Fraction(0.2),
        reservation_ttl_seconds: 3600,
        key_case: KeyCase::Preserve,
        signed_url_ttl_seconds: 900,
        max_chunk_bytes: 64 * 1024 * 1024,
    };
    state.draining.store(draining, Ordering::SeqCst);
    state
}

/// Bind a TLS listener on an ephemeral port and serve `state`'s router on a
/// task; returns the bound address, the live `draining` handle, and the task.
async fn serve(
    state: AppState,
    identity: &Identity,
) -> (SocketAddr, Arc<AtomicBool>, JoinHandle<()>) {
    let draining = state.draining.clone();
    let section = ServerConfig {
        listen: String::from("127.0.0.1:0"),
        external_url: None,
        tls_cert: None,
        tls_key: None,
        max_chunk_bytes: 64 * 1024 * 1024,
        drain_grace_seconds: 30,
    };
    let config = tls::server_config(&section, identity).expect("TLS config builds");
    let listener = tls::bind("127.0.0.1:0", config).await.expect("binds");
    let addr = listener.bind_addr().expect("bound addr");
    let app = routes::router(state);
    let handle = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<PeerCert>(),
        )
        .await
        .expect("serve runs");
    });
    (addr, draining, handle)
}

/// One HTTP/1.1 exchange over a fresh TLS connection; returns the status, the
/// response headers block, and the body text.
async fn http(
    addr: SocketAddr,
    config: Arc<rustls::ClientConfig>,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> (u16, String, String) {
    let tcp = TcpStream::connect(addr).await.expect("tcp connect");
    let server_name = ServerName::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST).into());
    let mut stream: TlsStream<TcpStream> = TlsConnector::from(config)
        .connect(server_name, tcp)
        .await
        .expect("TLS handshake");
    let mut head = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (name, value) in headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).await.expect("write head");
    stream.write_all(body).await.expect("write body");
    let mut raw = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut raw))
        .await
        .expect("response before timeout")
        .expect("read response");
    let text = String::from_utf8_lossy(&raw).into_owned();
    let (head, body) = text
        .split_once("\r\n\r\n")
        .map(|(head, body)| (head.to_owned(), body.to_owned()))
        .unwrap_or((text.clone(), String::new()));
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or_else(|| panic!("no HTTP status in response: {text:?}"));
    (status, head, body)
}

fn auth_header() -> String {
    format!("Bearer {TOKEN}")
}

#[tokio::test]
async fn draining_refuses_new_uploads_but_serves_in_flight_and_reports_readiness() {
    let root = TestDir::new();
    let node = mint(root.path(), "node");
    let storage = Arc::new(MemoryStorage::new());
    let state = state_with(&node, &storage, true);
    let (addr, draining, _handle) = serve(state, &node).await;
    let client = client_config(&node);
    let auth = auth_header();

    // (3) A NEW v1 reserve is refused with 503 + Retry-After while draining.
    let (status, head, body) = http(
        addr,
        client.clone(),
        "POST",
        "/_apis/artifactcache/caches",
        &[
            ("Authorization", auth.as_str()),
            ("Content-Type", "application/json"),
        ],
        br#"{"key":"drain-key","version":"v1"}"#,
    )
    .await;
    assert_eq!(status, 503, "new upload while draining: {body}");
    assert!(
        head.to_ascii_lowercase().contains("retry-after: 5"),
        "503 must carry Retry-After: {head}"
    );
    assert!(body.contains("draining"), "refusal body: {body}");

    // (2) An in-flight PATCH on a reservation that already exists is NOT
    // refused by the drain (any non-503 status is acceptable here — the
    // reservation is unknown in this fixture, so 404/400/409 all prove the
    // upload path is still served).
    let (status, _head, body) = http(
        addr,
        client.clone(),
        "PATCH",
        "/_apis/artifactcache/caches/123",
        &[
            ("Authorization", auth.as_str()),
            ("Content-Range", "bytes 0-3/*"),
        ],
        b"data",
    )
    .await;
    assert_ne!(status, 503, "in-flight chunk upload must be served: {body}");

    // (1)/(4) Readiness reports the drain; liveness stays up.
    let (status, _head, body) = http(addr, client.clone(), "GET", "/readyz", &[], &[]).await;
    assert_eq!(status, 503, "/readyz while draining: {body}");
    assert!(body.contains("draining"), "/readyz body: {body}");

    let (status, _head, body) = http(addr, client.clone(), "GET", "/healthz", &[], &[]).await;
    assert_eq!(status, 200, "/healthz stays live while draining: {body}");

    // A non-draining node is ready again.
    draining.store(false, Ordering::SeqCst);
    let (status, _head, body) = http(addr, client, "GET", "/readyz", &[], &[]).await;
    assert_eq!(status, 200, "/readyz once the drain clears: {body}");
    assert!(body.contains("ready"), "/readyz body: {body}");
}

#[tokio::test]
async fn non_draining_node_admits_uploads_and_reports_ready() {
    let root = TestDir::new();
    let node = mint(root.path(), "node");
    let storage = Arc::new(MemoryStorage::new());
    let state = state_with(&node, &storage, false);
    let (addr, _draining, _handle) = serve(state, &node).await;
    let client = client_config(&node);
    let auth = auth_header();

    let (status, _head, body) = http(
        addr,
        client.clone(),
        "POST",
        "/_apis/artifactcache/caches",
        &[
            ("Authorization", auth.as_str()),
            ("Content-Type", "application/json"),
        ],
        br#"{"key":"drain-key","version":"v1"}"#,
    )
    .await;
    assert_eq!(status, 200, "a healthy node reserves normally: {body}");

    let (status, _head, body) = http(addr, client, "GET", "/readyz", &[], &[]).await;
    assert_eq!(status, 200, "/readyz on a healthy node: {body}");
}

#[tokio::test]
async fn readyz_reports_starting_without_storage() {
    // No storage attached: readiness distinguishes `starting` from `draining`.
    let mut state = AppState::new();
    state.storage = None;
    let app = routes::router(state);
    let response = tower::ServiceExt::oneshot(
        app,
        axum::http::Request::builder()
            .method("GET")
            .uri("/readyz")
            .body(axum::body::Body::empty())
            .expect("request"),
    )
    .await
    .expect("router responds");
    assert_eq!(response.status(), 503);
    let bytes = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .expect("body");
    assert!(
        String::from_utf8_lossy(&bytes).contains("starting"),
        "body: {}",
        String::from_utf8_lossy(&bytes)
    );
}
