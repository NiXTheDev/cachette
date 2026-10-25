//! Plan task 32: v1 find fan-out + owner-targeted v2 capability URLs.
//!
//! In-process, real-TLS harness (same shape as `tests/v1_relay.rs`): node A
//! serves the v1 `/_apis/artifactcache` + `/twirp` routes, node B serves the
//! pin-gated `/_internal/peers/*` relay/find endpoints. A's relay is built
//! directly from a seeded [`PeerTable`] + [`Placement`], so the tests exercise
//! the real mTLS fan-out without a discovery runtime.
//!
//! Covered (acceptance for task 32):
//! * v1 `find` on A after a B-hosted save → `archiveLocation` hosts B, and a
//!   direct GET of that URL returns byte-identical bytes (A never proxies);
//! * dead owner at find → 204 miss, no hang (≤ the 1s fan-out budget);
//! * v2 `CreateCacheEntry` via A with B the owner → both capability URLs host B
//!   and B staged the reservation;
//! * v2 `GetCacheEntryDownloadURL` + `FinalizeCacheEntryUpload` via A → routed
//!   through the owner fan-out (plan QA line).

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

const TOKEN: &str = "fanout-test-token";
const NOW: u64 = 1_700_000_000;

/// Self-cleaning unique temp directory (no `tempfile` dependency).
struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let unique = format!(
            "cachette-fanout-{}-{}",
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
    state.set_auth(AuthPolicy {
        mode: AuthMode::Bearer,
        secret: None,
        hmac_max_age_seconds: 600,
        static_tokens: vec![TOKEN.to_owned()],
        cluster_enabled: true,
    });
    state.set_cache_limits(CacheLimits {
        max_size,
        min_free,
        reservation_ttl_seconds: 3600,
        key_case: KeyCase::Lower,
        signed_url_ttl_seconds: 900,
        max_chunk_bytes: 64 * 1024 * 1024,
    });
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
        metrics: state.metrics.clone(),
        min_free: state.cache_limits().min_free,
        max_size: state.cache_limits().max_size,
        reservation_ttl_seconds: state.cache_limits().reservation_ttl_seconds,
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

/// Reserve + upload one blob through A's relay so the owner holds a finalized
/// entry under `key` (task 31 harness reused by the task-32 fan-out tests).
async fn relay_put(
    a_addr: SocketAddr,
    client: &Arc<rustls::ClientConfig>,
    auth: &str,
    key: &str,
    version: &str,
    payload: &[u8],
) {
    let reserve_body = format!("{{\"key\":\"{key}\",\"version\":\"{version}\"}}");
    let (status, body) = http(
        a_addr,
        client.clone(),
        "POST",
        "/_apis/artifactcache/caches",
        &[
            ("Authorization", auth),
            ("Content-Type", "application/json"),
        ],
        reserve_body.as_bytes(),
    )
    .await;
    assert_eq!(status, 200, "reserve body: {body}");
    let cache_id = serde_json::from_str::<serde_json::Value>(&body)
        .expect("reserve JSON")
        .get("cacheId")
        .and_then(serde_json::Value::as_u64)
        .expect("cacheId is a number");
    let (status, body) = http(
        a_addr,
        client.clone(),
        "PATCH",
        &format!("/_apis/artifactcache/caches/{cache_id}"),
        &[
            ("Authorization", auth),
            ("Content-Range", &format!("bytes 0-{}/*", payload.len() - 1)),
        ],
        payload,
    )
    .await;
    assert_eq!(status, 204, "patch body: {body}");
    let commit_body = format!("{{\"size\":{}}}", payload.len());
    let (status, body) = http(
        a_addr,
        client.clone(),
        "POST",
        &format!("/_apis/artifactcache/caches/{cache_id}"),
        &[
            ("Authorization", auth),
            ("Content-Type", "application/json"),
        ],
        commit_body.as_bytes(),
    )
    .await;
    assert_eq!(status, 204, "commit body: {body}");
}

#[tokio::test]
async fn find_fan_out_mints_an_owner_hosted_download_url() {
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
    a_state.relay = Some(Arc::new(build_relay(&a, &a_state, table)));
    let (a_addr, _a_handle) = serve(a_state, &a).await;

    let client = client_config(&a, None);
    let auth = auth_header();

    // Save through A so only B holds the blob.
    let payload = b"find fan out payload";
    relay_put(a_addr, &client, &auth, "fanout-key", "v1", payload).await;

    // A has no local copy, so find resolves the owner via the peer fan-out and
    // mints a capability URL against B's host (M12 shared secret).
    let (status, body) = http(
        a_addr,
        client.clone(),
        "GET",
        "/_apis/artifactcache/cache?keys=fanout-key&version=v1",
        &[("Authorization", auth.as_str())],
        b"",
    )
    .await;
    assert_eq!(status, 200, "find body: {body}");
    let value: serde_json::Value = serde_json::from_str(&body).expect("find JSON");
    assert_eq!(
        value.get("result").and_then(serde_json::Value::as_str),
        Some("hit")
    );
    assert_eq!(
        value.get("cacheKey").and_then(serde_json::Value::as_str),
        Some("fanout-key")
    );
    let location = value
        .get("archiveLocation")
        .and_then(serde_json::Value::as_str)
        .expect("archiveLocation");
    // The capability URL must host B, never A — the runner downloads directly.
    let prefix = format!("http://{b_addr}/_apis/artifactcache/artifacts/fanout-key?");
    assert!(
        location.starts_with(&prefix),
        "owner-hosted url: {location} (expected prefix {prefix})"
    );

    // A direct GET of that URL against B returns byte-identical bytes: A never
    // proxies the download body.
    let path = location
        .strip_prefix(&format!("http://{b_addr}"))
        .expect("url hosts B");
    let b_client = client_config(&b, None);
    let (status, body) = http(b_addr, b_client, "GET", path, &[], b"").await;
    assert_eq!(status, 200, "owner download body: {body}");
    assert_eq!(body.as_bytes(), &payload[..]);
}

#[tokio::test]
async fn find_fan_out_degrades_to_a_miss_when_the_owner_is_dead() {
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

    // Save through A, then crash the owner.
    let payload = b"owner about to die";
    relay_put(a_addr, &client, &auth, "dead-owner-key", "v1", payload).await;
    b_handle.abort();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // The fan-out must not hang: a dead owner degrades to a 204 miss inside the
    // 1s FANOUT_TIMEOUT budget, and A must not fall back to serving stale bytes.
    let started = std::time::Instant::now();
    let (status, body) = http(
        a_addr,
        client,
        "GET",
        "/_apis/artifactcache/cache?keys=dead-owner-key&version=v1",
        &[("Authorization", auth.as_str())],
        b"",
    )
    .await;
    let elapsed = started.elapsed();
    assert_eq!(status, 204, "miss body: {body}");
    assert!(
        elapsed < Duration::from_millis(1500),
        "find must not hang past the fan-out budget: {elapsed:?}"
    );
}

#[tokio::test]
async fn v2_create_mints_capability_urls_on_the_remote_owner() {
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
    a_state.relay = Some(Arc::new(build_relay(&a, &a_state, table)));
    let (a_addr, _a_handle) = serve(a_state, &a).await;

    let client = client_config(&a, None);
    let auth = auth_header();

    let (status, body) = http(
        a_addr,
        client,
        "POST",
        "/twirp/github.actions.results.api.v1.CacheService/CreateCacheEntry",
        &[
            ("Authorization", auth.as_str()),
            ("Content-Type", "application/json"),
        ],
        br#"{"key":"v2-owner-key","version":"v2-ver"}"#,
    )
    .await;
    assert_eq!(status, 200, "create body: {body}");
    let value: serde_json::Value = serde_json::from_str(&body).expect("create JSON");
    assert_eq!(
        value.get("ok").and_then(serde_json::Value::as_bool),
        Some(true)
    );

    let upload = value
        .get("signed_upload_url")
        .and_then(serde_json::Value::as_str)
        .expect("signed_upload_url");
    let download = value
        .get("signed_download_url")
        .and_then(serde_json::Value::as_str)
        .expect("signed_download_url");
    // BOTH capability URLs must host the owner B (plan task 32 / QA line).
    assert!(
        upload.starts_with(&format!("http://{b_addr}/v2/upload/")),
        "upload url hosts owner: {upload}"
    );
    assert!(
        download.starts_with(&format!("http://{b_addr}/v2/artifacts/")),
        "download url hosts owner: {download}"
    );

    // The cache_id A minted is the id B staged the reservation under, so the
    // runner's direct upload to B finds B's local reservation.
    let cache_id = value
        .get("cache_id")
        .and_then(serde_json::Value::as_str)
        .expect("cache_id");
    assert!(
        upload.starts_with(&format!("http://{b_addr}/v2/upload/{cache_id}")),
        "upload path uses the minted cache_id: {upload}"
    );

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs();
    assert!(
        b_storage
            .stat("v2-owner-key")
            .await
            .expect("stat")
            .is_none(),
        "B stages a reservation, not a published entry"
    );
    assert!(
        b_storage
            .reservation_exists("v2-owner-key", now)
            .await
            .expect("reservation check"),
        "the owner must hold the reservation so the runner's direct upload lands"
    );
    assert!(
        !a_storage
            .reservation_exists("v2-owner-key", now)
            .await
            .expect("reservation check"),
        "the entry node must not stage a local reservation for a remote owner"
    );
}

#[tokio::test]
async fn v2_getdownloadurl_and_finalize_route_through_the_owner_fan_out() {
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
    a_state.relay = Some(Arc::new(build_relay(&a, &a_state, table)));
    let (a_addr, _a_handle) = serve(a_state, &a).await;

    let client = client_config(&a, None);
    let auth = auth_header();

    // Place a finalized entry on B (only) via the v1 relay.
    let payload = b"qa fan out entry";
    relay_put(a_addr, &client, &auth, "qa-key", "v1", payload).await;

    // GetCacheEntryDownloadURL: A has no local copy, so it fans out and mints a
    // download URL on the owner's host.
    let (status, body) = http(
        a_addr,
        client.clone(),
        "POST",
        "/twirp/github.actions.results.api.v1.CacheService/GetCacheEntryDownloadURL",
        &[
            ("Authorization", auth.as_str()),
            ("Content-Type", "application/json"),
        ],
        br#"{"key":"qa-key","version":"v1"}"#,
    )
    .await;
    assert_eq!(status, 200, "getdownloadurl body: {body}");
    let value: serde_json::Value = serde_json::from_str(&body).expect("getdownloadurl JSON");
    assert_eq!(
        value.get("ok").and_then(serde_json::Value::as_bool),
        Some(true)
    );
    let download = value
        .get("signed_download_url")
        .and_then(serde_json::Value::as_str)
        .expect("signed_download_url");
    assert!(
        download.starts_with(&format!("http://{b_addr}/v2/artifacts/qa-key?")),
        "download url hosts owner: {download}"
    );
    assert_eq!(
        value.get("matched_key").and_then(serde_json::Value::as_str),
        Some("qa-key")
    );

    // Finalize: A has no local copy, so it fans out and the owner verifies the
    // published entry (plan QA line: A→B finalize works).
    let finalize_body = format!(
        "{{\"key\":\"qa-key\",\"version\":\"v1\",\"size_bytes\":{}}}",
        payload.len()
    );
    let (status, body) = http(
        a_addr,
        client,
        "POST",
        "/twirp/github.actions.results.api.v1.CacheService/FinalizeCacheEntryUpload",
        &[
            ("Authorization", auth.as_str()),
            ("Content-Type", "application/json"),
        ],
        finalize_body.as_bytes(),
    )
    .await;
    assert_eq!(status, 200, "finalize body: {body}");
    let value: serde_json::Value = serde_json::from_str(&body).expect("finalize JSON");
    assert_eq!(
        value.get("ok").and_then(serde_json::Value::as_bool),
        Some(true)
    );
}
