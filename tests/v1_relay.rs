//! Plan task 31: v1 relay from the entry node to the storage owner.
//!
//! In-process, real-TLS harness (mirrors `tests/tls_peers.rs`): node A serves
//! the v1 `/_apis/artifactcache` routes, node B (and, for the fallback case, a
//! second peer) serves the pin-gated `/_internal/peers/*` relay endpoints. A's
//! relay is built directly from a seeded [`PeerTable`] + [`Placement`], so the
//! tests exercise the real mTLS peer transport without a discovery runtime.
//!
//! Covered:
//! * happy path — reserve/PATCH/commit flow A→B, blob lands only on B, A holds
//!   only the session + owner record;
//! * cross-node duplicate reserve → GitHub 409 body;
//! * capacity fallback — B refuses (503) and A retries the next peer in the
//!   same request;
//! * owner death mid-upload → A answers 502 and marks the session failed;
//! * self-owner placement → the unchanged local path (no relay);
//! * B's peer endpoints directly — duplicate + idempotent repeat commit.
//!
//! Plan task 32 (find fan-out + owner-targeted v2 capability URLs) lives in
//! [`tests/v1_find_fanout.rs`](v1_find_fanout.rs).

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use cachette::auth::AuthPolicy;
use cachette::cluster::PeerTable;
use cachette::cluster::placement::Placement;
use cachette::cluster::relay::{ClusterRelay, RelayConfig};
use cachette::config::{AuthMode, KeyCase, MinFree, ServerConfig, Tiebreak};
use cachette::identity::Identity;
use cachette::routes;
use cachette::state::{AppState, CacheLimits};
use cachette::storage::{MemoryStorage, StorageBackend};
use cachette::tls::{self, PeerCert, PeerPins};
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

const TOKEN: &str = "relay-test-token";
const NOW: u64 = 1_700_000_000;

/// Self-cleaning unique temp directory (no `tempfile` dependency).
struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let unique = format!(
            "cachette-relay-{}-{}",
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

/// Build an [`AppState`] for one node: identity, pin seed, storage handle, auth
/// (static bearer), and cache knobs. Cluster-enabled so the `cluster_enabled`
/// flag matches a real deployment.
fn state_with(
    identity: &Identity,
    pins: &[&Identity],
    storage: &Arc<MemoryStorage>,
    max_size: u64,
    min_free: MinFree,
) -> AppState {
    let mut seed = BTreeMap::new();
    for (index, peer) in pins.iter().enumerate() {
        seed.insert(format!("peer-{index}"), peer.fingerprint().to_owned());
    }
    let mut state = AppState::new();
    state.node_id = identity.fingerprint().to_owned();
    state.peers = Arc::new(PeerPins::new(&seed, false));
    state.storage = Some(storage.clone());
    state.auth = Arc::new(AuthPolicy {
        mode: AuthMode::Bearer,
        secret: None,
        hmac_max_age_seconds: 600,
        static_tokens: vec![TOKEN.to_owned()],
        cluster_enabled: true,
    });
    state.cache = CacheLimits {
        max_size,
        min_free,
        reservation_ttl_seconds: 3600,
        key_case: KeyCase::Lower,
        signed_url_ttl_seconds: 900,
        max_chunk_bytes: 64 * 1024 * 1024,
    };
    state.capacity_total = max_size;
    state
}

/// Bind a TLS listener on an ephemeral port and serve `state`'s router on a
/// task; returns the bound address and the task handle (abortable to simulate
/// an owner crash).
async fn serve(state: AppState, identity: &Identity) -> (SocketAddr, JoinHandle<()>) {
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
    (addr, handle)
}

/// Publish one healthy peer into `table` with the given used/total bytes (the
/// heartbeat inputs placement reads).
fn publish(table: &PeerTable, identity: &Identity, addr: SocketAddr, used: u64, total: u64) {
    let fingerprint = identity.fingerprint();
    table.observe_discovered(fingerprint, fingerprint, &addr.to_string(), NOW);
    table.heartbeat(fingerprint, fingerprint, used, total, NOW, false);
}

/// Build A's relay from its identity + state + peer table.
fn build_relay(identity: &Identity, state: &AppState, table: Arc<PeerTable>) -> ClusterRelay {
    ClusterRelay::new(RelayConfig {
        node_id: identity.fingerprint().to_owned(),
        cert_pem: identity.cert_pem().to_owned(),
        key_pem: identity.key_pem().to_owned(),
        pins: state.peers.clone(),
        placement: Arc::new(Placement::with_seed(Tiebreak::Progressive, 7)),
        peer_table: table,
        min_free: state.cache.min_free,
        max_size: state.cache.max_size,
        reservation_ttl_seconds: state.cache.reservation_ttl_seconds,
    })
    .expect("relay builds")
}

/// One HTTP/1.1 exchange over a fresh TLS connection; returns the status and
/// the response body text.
async fn http(
    addr: SocketAddr,
    config: Arc<rustls::ClientConfig>,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> (u16, String) {
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
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or_else(|| panic!("no HTTP status in response: {text:?}"));
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_owned())
        .unwrap_or_default();
    (status, body)
}

fn auth_header() -> String {
    format!("Bearer {TOKEN}")
}

async fn read_all(storage: &MemoryStorage, key: &str, len: u64) -> Vec<u8> {
    let mut stream = storage
        .get_range(key, 0..len)
        .await
        .expect("entry is readable");
    let mut out = Vec::new();
    stream.read_to_end(&mut out).await.expect("read blob");
    out
}

#[tokio::test]
async fn relay_reserves_uploads_and_commits_on_remote_owner() {
    let root = TestDir::new();
    let a = mint(root.path(), "a");
    let b = mint(root.path(), "b");

    let b_storage = Arc::new(MemoryStorage::new());
    let b_state = state_with(&b, &[&a], &b_storage, 100, MinFree::Fraction(0.2));
    let (b_addr, _b_handle) = serve(b_state, &b).await;

    let a_storage = Arc::new(MemoryStorage::new());
    let mut a_state = state_with(&a, &[&b], &a_storage, 100, MinFree::Fraction(0.2));
    let table = Arc::new(PeerTable::new());
    publish(&table, &b, b_addr, 0, 100);
    a_state.peer_table = table.clone();
    let relay = Arc::new(build_relay(&a, &a_state, table));
    a_state.relay = Some(relay.clone());
    let (a_addr, _a_handle) = serve(a_state, &a).await;

    let client = client_config(&a, None);
    let auth = auth_header();

    // Reserve: placement picks B, which accepts and issues its own cacheId; the
    // client keeps A's id.
    let (status, body) = http(
        a_addr,
        client.clone(),
        "POST",
        "/_apis/artifactcache/caches",
        &[
            ("Authorization", auth.as_str()),
            ("Content-Type", "application/json"),
        ],
        br#"{"key":"relay-key","version":"v1"}"#,
    )
    .await;
    assert_eq!(status, 200, "reserve body: {body}");
    let cache_id = serde_json::from_str::<serde_json::Value>(&body)
        .expect("reserve JSON")
        .get("cacheId")
        .and_then(serde_json::Value::as_u64)
        .expect("cacheId is a number");

    // PATCH one chunk; A forwards it without buffering the whole blob.
    let payload = b"hello relay world";
    let (status, body) = http(
        a_addr,
        client.clone(),
        "PATCH",
        &format!("/_apis/artifactcache/caches/{cache_id}"),
        &[
            ("Authorization", auth.as_str()),
            ("Content-Range", &format!("bytes 0-{}/*", payload.len() - 1)),
        ],
        payload,
    )
    .await;
    assert_eq!(status, 204, "patch body: {body}");

    // Commit: A forwards; only after B publishes does A answer 204.
    let commit_body = format!("{{\"size\":{}}}", payload.len());
    let (status, body) = http(
        a_addr,
        client.clone(),
        "POST",
        &format!("/_apis/artifactcache/caches/{cache_id}"),
        &[
            ("Authorization", auth.as_str()),
            ("Content-Type", "application/json"),
        ],
        commit_body.as_bytes(),
    )
    .await;
    assert_eq!(status, 204, "commit body: {body}");

    // Blob bytes live only on B; A stored nothing.
    let stat = b_storage
        .stat("relay-key")
        .await
        .expect("stat")
        .expect("B holds the published entry");
    assert_eq!(stat.size, payload.len() as u64);
    assert_eq!(read_all(&b_storage, "relay-key", stat.size).await, payload);
    assert!(
        a_storage.stat("relay-key").await.expect("stat").is_none(),
        "A must not store the blob"
    );
    assert_eq!(a_storage.used_bytes().await.expect("used"), 0);

    // A records the owner for the task-32 find fan-out.
    let owner = relay.owner_for("relay-key").expect("owner recorded");
    assert_eq!(owner.node_id, b.fingerprint());
    assert_eq!(owner.addr, b_addr.to_string());
    assert_eq!(owner.size, payload.len() as u64);

    // A repeat reserve for the same (key, version) is a cross-node duplicate.
    let (status, body) = http(
        a_addr,
        client,
        "POST",
        "/_apis/artifactcache/caches",
        &[
            ("Authorization", auth.as_str()),
            ("Content-Type", "application/json"),
        ],
        br#"{"key":"relay-key","version":"v1"}"#,
    )
    .await;
    assert_eq!(status, 409, "duplicate body: {body}");
    assert!(
        body.contains("ArtifactCacheItemAlreadyExistsException"),
        "duplicate body: {body}"
    );
}

#[tokio::test]
async fn relay_falls_back_to_next_peer_when_owner_refuses_capacity() {
    let root = TestDir::new();
    let a = mint(root.path(), "a");
    let b = mint(root.path(), "b");
    let c = mint(root.path(), "c");

    // B's free-space floor (1000 bytes) exceeds its whole volume, so B refuses
    // every reservation with 503.
    let b_storage = Arc::new(MemoryStorage::new());
    let b_state = state_with(&b, &[&a], &b_storage, 100, MinFree::Bytes(1000));
    let (b_addr, _b_handle) = serve(b_state, &b).await;

    let c_storage = Arc::new(MemoryStorage::new());
    let c_state = state_with(&c, &[&a], &c_storage, 100, MinFree::Fraction(0.2));
    let (c_addr, _c_handle) = serve(c_state, &c).await;

    let a_storage = Arc::new(MemoryStorage::new());
    let mut a_state = state_with(&a, &[&b, &c], &a_storage, 100, MinFree::Fraction(0.2));
    let table = Arc::new(PeerTable::new());
    // A's placement sees a homogeneous cluster: B (50% full) is ranked before C
    // (0% full)... so B is tried first, refuses, and A retries C.
    publish(&table, &b, b_addr, 50, 100);
    publish(&table, &c, c_addr, 0, 100);
    a_state.peer_table = table.clone();
    let relay = Arc::new(build_relay(&a, &a_state, table));
    a_state.relay = Some(relay);
    let (a_addr, _a_handle) = serve(a_state, &a).await;

    let client = client_config(&a, None);
    let auth = auth_header();
    let (status, body) = http(
        a_addr,
        client.clone(),
        "POST",
        "/_apis/artifactcache/caches",
        &[
            ("Authorization", auth.as_str()),
            ("Content-Type", "application/json"),
        ],
        br#"{"key":"fallback-key","version":"v1"}"#,
    )
    .await;
    assert_eq!(status, 200, "reserve body: {body}");
    let cache_id = serde_json::from_str::<serde_json::Value>(&body)
        .expect("reserve JSON")
        .get("cacheId")
        .and_then(serde_json::Value::as_u64)
        .expect("cacheId is a number");

    let payload = b"fallback payload";
    let (status, body) = http(
        a_addr,
        client.clone(),
        "PATCH",
        &format!("/_apis/artifactcache/caches/{cache_id}"),
        &[
            ("Authorization", auth.as_str()),
            ("Content-Range", &format!("bytes 0-{}/*", payload.len() - 1)),
        ],
        payload,
    )
    .await;
    assert_eq!(status, 204, "patch body: {body}");

    let commit_body = format!("{{\"size\":{}}}", payload.len());
    let (status, body) = http(
        a_addr,
        client,
        "POST",
        &format!("/_apis/artifactcache/caches/{cache_id}"),
        &[
            ("Authorization", auth.as_str()),
            ("Content-Type", "application/json"),
        ],
        commit_body.as_bytes(),
    )
    .await;
    assert_eq!(status, 204, "commit body: {body}");

    // C ended up the owner; B never reserved anything.
    let stat = c_storage
        .stat("fallback-key")
        .await
        .expect("stat")
        .expect("C holds the published entry");
    assert_eq!(stat.size, payload.len() as u64);
    assert!(
        b_storage
            .stat("fallback-key")
            .await
            .expect("stat")
            .is_none(),
        "B never received the blob"
    );
    assert!(
        !b_storage
            .reservation_exists("fallback-key", NOW)
            .await
            .expect("reservation check"),
        "B refused before reserving"
    );
    assert_eq!(a_storage.used_bytes().await.expect("used"), 0);
}

#[tokio::test]
async fn relay_returns_bad_gateway_when_owner_dies_mid_upload() {
    let root = TestDir::new();
    let a = mint(root.path(), "a");
    let b = mint(root.path(), "b");

    let b_storage = Arc::new(MemoryStorage::new());
    let b_state = state_with(&b, &[&a], &b_storage, 100, MinFree::Fraction(0.2));
    let (b_addr, b_handle) = serve(b_state, &b).await;

    let a_storage = Arc::new(MemoryStorage::new());
    let mut a_state = state_with(&a, &[&b], &a_storage, 100, MinFree::Fraction(0.2));
    let table = Arc::new(PeerTable::new());
    publish(&table, &b, b_addr, 0, 100);
    a_state.peer_table = table.clone();
    a_state.relay = Some(Arc::new(build_relay(&a, &a_state, table)));
    let (a_addr, _a_handle) = serve(a_state, &a).await;

    let client = client_config(&a, None);
    let auth = auth_header();
    let (status, body) = http(
        a_addr,
        client.clone(),
        "POST",
        "/_apis/artifactcache/caches",
        &[
            ("Authorization", auth.as_str()),
            ("Content-Type", "application/json"),
        ],
        br#"{"key":"doomed-key","version":"v1"}"#,
    )
    .await;
    assert_eq!(status, 200, "reserve body: {body}");
    let cache_id = serde_json::from_str::<serde_json::Value>(&body)
        .expect("reserve JSON")
        .get("cacheId")
        .and_then(serde_json::Value::as_u64)
        .expect("cacheId is a number");

    // The owner dies before the chunk is forwarded.
    b_handle.abort();
    tokio::time::sleep(Duration::from_millis(100)).await;

    let payload = b"owner is gone";
    let (status, body) = http(
        a_addr,
        client,
        "PATCH",
        &format!("/_apis/artifactcache/caches/{cache_id}"),
        &[
            ("Authorization", auth.as_str()),
            ("Content-Range", &format!("bytes 0-{}/*", payload.len() - 1)),
        ],
        payload,
    )
    .await;
    assert_eq!(status, 502, "dead-owner patch body: {body}");
    assert!(
        body.contains("storage owner unreachable"),
        "dead-owner body: {body}"
    );
    assert!(
        a_storage.stat("doomed-key").await.expect("stat").is_none(),
        "A must never fall back to local storage"
    );
}

#[tokio::test]
async fn relay_self_owner_uses_the_unchanged_local_path() {
    let root = TestDir::new();
    let a = mint(root.path(), "a");

    let a_storage = Arc::new(MemoryStorage::new());
    let mut a_state = state_with(&a, &[], &a_storage, 100, MinFree::Fraction(0.2));
    let table = Arc::new(PeerTable::new());
    // The placement winner is this node itself.
    let self_addr: SocketAddr = "127.0.0.1:1".parse().expect("addr");
    publish(&table, &a, self_addr, 0, 100);
    a_state.peer_table = table.clone();
    a_state.relay = Some(Arc::new(build_relay(&a, &a_state, table)));
    let (a_addr, _a_handle) = serve(a_state, &a).await;

    let client = client_config(&a, None);
    let auth = auth_header();
    let (status, body) = http(
        a_addr,
        client.clone(),
        "POST",
        "/_apis/artifactcache/caches",
        &[
            ("Authorization", auth.as_str()),
            ("Content-Type", "application/json"),
        ],
        br#"{"key":"local-key","version":"v1"}"#,
    )
    .await;
    assert_eq!(status, 200, "reserve body: {body}");
    let cache_id = serde_json::from_str::<serde_json::Value>(&body)
        .expect("reserve JSON")
        .get("cacheId")
        .and_then(serde_json::Value::as_u64)
        .expect("cacheId is a number");

    let payload = b"stored locally";
    let (status, body) = http(
        a_addr,
        client.clone(),
        "PATCH",
        &format!("/_apis/artifactcache/caches/{cache_id}"),
        &[
            ("Authorization", auth.as_str()),
            ("Content-Range", &format!("bytes 0-{}/*", payload.len() - 1)),
        ],
        payload,
    )
    .await;
    assert_eq!(status, 204, "patch body: {body}");

    let commit_body = format!("{{\"size\":{}}}", payload.len());
    let (status, body) = http(
        a_addr,
        client,
        "POST",
        &format!("/_apis/artifactcache/caches/{cache_id}"),
        &[
            ("Authorization", auth.as_str()),
            ("Content-Type", "application/json"),
        ],
        commit_body.as_bytes(),
    )
    .await;
    assert_eq!(status, 204, "commit body: {body}");

    // The self-owner path published the entry into A's own storage.
    let stat = a_storage
        .stat("local-key")
        .await
        .expect("stat")
        .expect("A holds its own entry");
    assert_eq!(stat.size, payload.len() as u64);
}

#[tokio::test]
async fn owner_peer_endpoints_reject_duplicates_and_commit_idempotently() {
    let root = TestDir::new();
    let a = mint(root.path(), "a");
    let b = mint(root.path(), "b");

    let b_storage = Arc::new(MemoryStorage::new());
    let b_state = state_with(&b, &[&a], &b_storage, 100, MinFree::Fraction(0.2));
    let (b_addr, _b_handle) = serve(b_state, &b).await;

    // The relay is A; drive B's pin-gated endpoints directly as A.
    let client = client_config(&b, Some(&a));

    let (status, body) = http(
        b_addr,
        client.clone(),
        "POST",
        "/_internal/peers/reserve",
        &[("Content-Type", "application/json")],
        br#"{"key":"peer-key","version":"v1"}"#,
    )
    .await;
    assert_eq!(status, 200, "peer reserve body: {body}");
    let cache_id = serde_json::from_str::<serde_json::Value>(&body)
        .expect("reserve JSON")
        .get("cacheId")
        .and_then(serde_json::Value::as_u64)
        .expect("cacheId is a number");

    let payload = b"peer endpoint payload";
    let (status, body) = http(
        b_addr,
        client.clone(),
        "PUT",
        &format!("/_internal/peers/upload/{cache_id}?offset=0"),
        &[],
        payload,
    )
    .await;
    assert_eq!(status, 204, "peer upload body: {body}");

    let commit_body = format!("{{\"size\":{},\"key\":\"peer-key\"}}", payload.len());
    let (status, body) = http(
        b_addr,
        client.clone(),
        "POST",
        &format!("/_internal/peers/commit/{cache_id}"),
        &[("Content-Type", "application/json")],
        commit_body.as_bytes(),
    )
    .await;
    assert_eq!(status, 204, "peer commit body: {body}");

    // A repeat commit of a reservation B already published is an idempotent 204.
    let (status, body) = http(
        b_addr,
        client.clone(),
        "POST",
        &format!("/_internal/peers/commit/{cache_id}"),
        &[("Content-Type", "application/json")],
        commit_body.as_bytes(),
    )
    .await;
    assert_eq!(status, 204, "idempotent commit body: {body}");

    // A duplicate reserve surfaces the GitHub body.
    let (status, body) = http(
        b_addr,
        client,
        "POST",
        "/_internal/peers/reserve",
        &[("Content-Type", "application/json")],
        br#"{"key":"peer-key","version":"v1"}"#,
    )
    .await;
    assert_eq!(status, 409, "duplicate reserve body: {body}");
    assert!(
        body.contains("ArtifactCacheItemAlreadyExistsException"),
        "duplicate reserve body: {body}"
    );

    let stat = b_storage
        .stat("peer-key")
        .await
        .expect("stat")
        .expect("entry published");
    assert_eq!(stat.size, payload.len() as u64);
}

#[tokio::test]
async fn owner_peer_reserve_refuses_below_the_floor_with_503() {
    let root = TestDir::new();
    let a = mint(root.path(), "a");
    let b = mint(root.path(), "b");

    let b_storage = Arc::new(MemoryStorage::new());
    let b_state = state_with(&b, &[&a], &b_storage, 100, MinFree::Bytes(1000));
    let (b_addr, _b_handle) = serve(b_state, &b).await;

    let client = client_config(&b, Some(&a));
    let (status, body) = http(
        b_addr,
        client,
        "POST",
        "/_internal/peers/reserve",
        &[("Content-Type", "application/json")],
        br#"{"key":"no-room","version":"v1"}"#,
    )
    .await;
    assert_eq!(status, 503, "refusal body: {body}");
    assert_eq!(body.trim(), "{\"error\":\"insufficient capacity\"}");
    assert!(
        !b_storage
            .reservation_exists("no-room", NOW)
            .await
            .expect("reservation check"),
        "a refusal must not stage a reservation"
    );
}
