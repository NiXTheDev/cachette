//! Plan task 28 acceptance (criterion 7): peer table + hello + mDNS + seeds.
//!
//! Covers the dedup contract (a seed-discovered node and its mDNS record are
//! ONE peer), the `mdns=false` seed-only mode, the no-network mDNS no-op, and
//! the `POST /_internal/peers/hello` upsert/refresh path through the router.
//!
//! Plan task 29 (M15) adds the heartbeat route (`POST /_internal/peers/
//! heartbeat`), the ±10s stale-timestamp rule, the `PeerTable::sweep_timeouts`
//! timeout sweep, and the heartbeat task's own-node registration.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use cachette::cluster::{self, PeerTable};
use cachette::config::ClusterConfig;
use cachette::identity::Identity;
use cachette::routes;
use cachette::state::AppState;
use cachette::tls::{PeerCert, PeerPins};
use serde_json::{Value, json};
use tower::ServiceExt;

/// Build a router whose peer pin store trusts `fingerprint` and whose peer
/// table is pre-seeded with `seed_addrs`.
fn router_with(fingerprint: &str, seed_addrs: &[&str]) -> AppState {
    let mut state = AppState::new();
    state.node_id = String::from("node-a");
    let mut pins = BTreeMap::new();
    pins.insert(String::from("peer"), fingerprint.to_owned());
    state.peers = Arc::new(PeerPins::new(&pins, false));
    for addr in seed_addrs {
        state.peer_table.observe_addr(addr);
    }
    state
}

/// Attach a pinned peer certificate to a request (the pin middleware reads it
/// from the extensions, exactly like `into_make_service_with_connect_info`).
fn pinned(request: Request<Body>, fingerprint: &str) -> Request<Body> {
    let mut request = request;
    request.extensions_mut().insert(ConnectInfo(PeerCert {
        remote: "127.0.0.1:5000".parse().expect("socket addr"),
        fingerprint: Some(fingerprint.to_owned()),
    }));
    request
}

fn hello_body(node_id: &str, fingerprint: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/_internal/peers/hello")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({ "node_id": node_id, "fingerprint": fingerprint }).to_string(),
        ))
        .expect("request")
}

fn get_peers() -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri("/_internal/peers")
        .body(Body::empty())
        .expect("request")
}

fn heartbeat_body(node_id: &str, used: u64, total: u64, ts: i64) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/_internal/peers/heartbeat")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "node_id": node_id,
                "used_bytes": used,
                "total_bytes": total,
                "ts": ts,
            })
            .to_string(),
        ))
        .expect("request")
}

/// Integration tests are an external crate, so the Unix clock is computed
/// locally (`auth::now_secs` is `pub(crate)`).
fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after 1970")
        .as_secs() as i64
}

async fn peers_json(state: &AppState) -> Value {
    let response = routes::router(state.clone())
        .oneshot(pinned(get_peers(), "FBBB"))
        .await
        .expect("router serves");
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("body");
    serde_json::from_slice(&bytes).expect("valid JSON")
}

#[tokio::test]
async fn seed_and_mdns_discovery_collapse_to_one_peer_record() {
    let state = router_with("FBBB", &["127.0.0.1:9001"]);
    // mDNS resolves node-b to the same address the seed already carries.
    state
        .peer_table
        .observe_discovered("node-b", "FBBB", "127.0.0.1:9001", 100);

    let body = peers_json(&state).await;
    let peers = body["peers"].as_array().expect("peers array");
    assert_eq!(peers.len(), 1, "{body}");
    assert_eq!(peers[0]["node_id"], "node-b");
    assert_eq!(peers[0]["fingerprint"], "FBBB");
    assert_eq!(peers[0]["addr"], "127.0.0.1:9001");
    assert_eq!(peers[0]["healthy"], true);
}

#[tokio::test]
async fn peer_list_shows_identity_and_health_for_all_peers() {
    let state = router_with("FBBB", &["127.0.0.1:9001", "127.0.0.1:9002"]);
    state
        .peer_table
        .observe_discovered("node-b", "FBBB", "127.0.0.1:9001", 100);
    state
        .peer_table
        .observe_discovered("node-c", "FCCC", "127.0.0.1:9002", 100);

    let body = peers_json(&state).await;
    let peers = body["peers"].as_array().expect("peers array");
    assert_eq!(peers.len(), 2, "{body}");
    let ids: Vec<&str> = peers
        .iter()
        .map(|peer| peer["node_id"].as_str().expect("node_id"))
        .collect();
    assert_eq!(ids, vec!["node-b", "node-c"]);
    for peer in peers {
        assert!(
            peer["fingerprint"]
                .as_str()
                .is_some_and(|fp| !fp.is_empty())
        );
        assert_eq!(peer["healthy"], true);
    }
}

#[tokio::test]
async fn hello_upserts_a_peer_and_refreshes_last_hello() {
    let state = router_with("FBBB", &[]);
    let app = routes::router(state.clone());

    let first = app
        .clone()
        .oneshot(pinned(hello_body("node-b", "FBBB"), "FBBB"))
        .await
        .expect("hello");
    assert_eq!(first.status(), StatusCode::OK);
    let first_bytes = axum::body::to_bytes(first.into_body(), 4096)
        .await
        .expect("body");
    let first_json: Value = serde_json::from_slice(&first_bytes).expect("JSON");
    assert_eq!(first_json["accepted"], true);
    assert_eq!(first_json["node_id"], "node-a");

    let before = peers_json(&state).await;
    let before_hello = before["peers"][0]["last_hello"]
        .as_u64()
        .expect("last_hello");

    // A second hello refreshes freshness without duplicating the record.
    let second = app
        .oneshot(pinned(hello_body("node-b", "FBBB"), "FBBB"))
        .await
        .expect("second hello");
    assert_eq!(second.status(), StatusCode::OK);

    let after = peers_json(&state).await;
    let peers = after["peers"].as_array().expect("peers array");
    assert_eq!(peers.len(), 1, "{after}");
    assert_eq!(peers[0]["node_id"], "node-b");
    assert_eq!(peers[0]["fingerprint"], "FBBB");
    let after_hello = peers[0]["last_hello"].as_u64().expect("last_hello");
    assert!(
        after_hello >= before_hello,
        "{before_hello} -> {after_hello}"
    );
}

#[tokio::test]
async fn hello_without_a_body_still_identifies_via_the_cert() {
    let state = router_with("FBBB", &[]);
    let request = Request::builder()
        .method("POST")
        .uri("/_internal/peers/hello")
        .body(Body::empty())
        .expect("request");
    let response = routes::router(state.clone())
        .oneshot(pinned(request, "FBBB"))
        .await
        .expect("hello");
    assert_eq!(response.status(), StatusCode::OK);

    let body = peers_json(&state).await;
    let peers = body["peers"].as_array().expect("peers array");
    assert_eq!(peers.len(), 1, "{body}");
    assert_eq!(peers[0]["fingerprint"], "FBBB");
}

#[tokio::test]
async fn unpinned_peer_cannot_read_the_peer_list() {
    let state = router_with("FBBB", &["127.0.0.1:9001"]);
    let response = routes::router(state)
        .oneshot(pinned(get_peers(), "ROGUE"))
        .await
        .expect("router serves");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[test]
fn mdns_disabled_registers_only_seeds() {
    let cluster = ClusterConfig {
        enabled: true,
        mdns: false,
        seeds: vec![String::from("cache-a"), String::from("cache-b:9002")],
        ..ClusterConfig::default()
    };
    let identity = Identity::load_or_generate(
        &std::env::temp_dir().join(format!("cachette-cluster-it-{}", std::process::id())),
        None,
        None,
    )
    .expect("identity");
    let runtime = cluster::start(&cluster, &identity, "0.0.0.0:8080");
    let peers = runtime.peer_table().snapshot();
    assert_eq!(peers.len(), 2, "{peers:?}");
    assert_eq!(peers[0].addr, "cache-a:8080");
    assert_eq!(peers[1].addr, "cache-b:9002");
    assert!(peers.iter().all(|peer| peer.fingerprint.is_empty()));
}

#[test]
fn mdns_on_with_no_network_boots_with_seeds_only() {
    let cluster = ClusterConfig {
        enabled: true,
        mdns: true,
        seeds: vec![String::from("cache-a:9001")],
        ..ClusterConfig::default()
    };
    let identity = Identity::load_or_generate(
        &std::env::temp_dir().join(format!("cachette-cluster-mdns-it-{}", std::process::id())),
        None,
        None,
    )
    .expect("identity");
    // Must not panic and must not treat a silent mDNS as an error.
    let runtime = cluster::start(&cluster, &identity, "127.0.0.1:8080");
    let peers = runtime.peer_table().snapshot();
    assert_eq!(peers.len(), 1, "{peers:?}");
    assert_eq!(peers[0].addr, "cache-a:9001");
}

#[test]
fn peer_table_dedup_contract_holds_directly() {
    let table = PeerTable::new();
    table.observe_addr("127.0.0.1:9001");
    table.observe_discovered("node-b", "FBBB", "127.0.0.1:9001", 1);
    assert_eq!(table.len(), 1);
    assert_eq!(table.snapshot()[0].node_id, "node-b");
}

#[tokio::test]
async fn heartbeat_refreshes_stats_and_freshness_through_the_router() {
    let state = router_with("FBBB", &[]);
    state
        .peer_table
        .observe_discovered("node-b", "FBBB", "127.0.0.1:9001", 100);
    let before = unix_now();

    let response = routes::router(state.clone())
        .oneshot(pinned(heartbeat_body("node-b", 40, 100, before), "FBBB"))
        .await
        .expect("heartbeat");
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .expect("body");
    let body: Value = serde_json::from_slice(&bytes).expect("JSON");
    assert_eq!(body["accepted"], true, "{body}");

    let peers = state.peer_table.snapshot();
    assert_eq!(peers.len(), 1, "{peers:?}");
    assert_eq!(peers[0].used_bytes, 40);
    assert_eq!(peers[0].total_bytes, 100);
    assert!(
        peers[0].last_hello >= before as u64,
        "last_hello {} must be at least the heartbeat ts {before}",
        peers[0].last_hello
    );
}

#[tokio::test]
async fn heartbeat_with_a_stale_timestamp_is_ignored() {
    let state = router_with("FBBB", &[]);
    state
        .peer_table
        .observe_discovered("node-b", "FBBB", "127.0.0.1:9001", 100);
    let stale = unix_now() + 30;

    let response = routes::router(state.clone())
        .oneshot(pinned(heartbeat_body("node-b", 99, 500, stale), "FBBB"))
        .await
        .expect("heartbeat");
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .expect("body");
    let body: Value = serde_json::from_slice(&bytes).expect("JSON");
    assert_eq!(body["accepted"], false, "{body}");

    let peers = state.peer_table.snapshot();
    assert_eq!(peers[0].used_bytes, 0, "stats must not move on a stale ts");
    assert_eq!(peers[0].total_bytes, 0);
    assert_eq!(peers[0].last_hello, 100, "freshness must not move");
}

#[tokio::test]
async fn unpinned_peer_cannot_send_a_heartbeat() {
    let state = router_with("FBBB", &["127.0.0.1:9001"]);
    let response = routes::router(state)
        .oneshot(pinned(heartbeat_body("node-b", 1, 1, unix_now()), "ROGUE"))
        .await
        .expect("router serves");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[test]
fn sweep_timeouts_marks_stale_peers_and_spares_fresh_and_seed_records() {
    let table = PeerTable::new();
    table.observe_discovered("node-b", "FBBB", "127.0.0.1:9001", 100);
    table.observe_addr("127.0.0.1:9009");

    assert_eq!(table.sweep_timeouts(114, 15), 0, "age 14 < timeout 15");
    assert_eq!(table.sweep_timeouts(115, 15), 1, "age 15 >= timeout 15");
    assert_eq!(table.sweep_timeouts(300, 15), 0, "not recounted");

    let peers = table.snapshot();
    let stale = peers
        .iter()
        .find(|peer| peer.node_id == "node-b")
        .expect("node-b record");
    assert!(!stale.healthy);
    let seed = peers
        .iter()
        .find(|peer| peer.addr == "127.0.0.1:9009")
        .expect("seed record");
    assert!(seed.healthy, "pre-hello seeds have no freshness yet");
}

#[test]
fn healthy_sorted_excludes_unhealthy_peers() {
    let table = PeerTable::new();
    table.observe_discovered("node-b", "FBBB", "127.0.0.1:9001", 1);
    table.observe_discovered("node-c", "FCCC", "127.0.0.1:9002", 1);
    assert!(table.mark_unhealthy("node-c", "FCCC"));
    let healthy = table.healthy_sorted();
    assert_eq!(healthy.len(), 1, "{healthy:?}");
    assert_eq!(healthy[0].node_id, "node-b");
}

#[tokio::test]
async fn a_restarted_peer_is_healthy_again_after_its_next_heartbeat() {
    let state = router_with("FBBB", &[]);
    state
        .peer_table
        .observe_discovered("node-b", "FBBB", "127.0.0.1:9001", 100);
    // C's heartbeats stop (killed): the sweep marks it unhealthy...
    assert_eq!(state.peer_table.sweep_timeouts(10_000, 15), 1);
    assert!(state.peer_table.healthy_sorted().is_empty());

    // ...then C restarts and heartbeats again — healthy within one interval.
    let response = routes::router(state.clone())
        .oneshot(pinned(
            heartbeat_body("node-b", 10, 100, unix_now()),
            "FBBB",
        ))
        .await
        .expect("heartbeat");
    assert_eq!(response.status(), StatusCode::OK);
    let healthy = state.peer_table.healthy_sorted();
    assert_eq!(healthy.len(), 1, "{:?}", state.peer_table.snapshot());
    assert_eq!(healthy[0].node_id, "node-b");
}

#[tokio::test]
async fn heartbeat_spawn_registers_the_own_node_immediately() {
    let table = Arc::new(PeerTable::new());
    let task = cachette::cluster::heartbeat::spawn(cachette::cluster::heartbeat::HeartbeatConfig {
        node_id: String::from("SELF"),
        cert_pem: String::new(),
        key_pem: String::new(),
        advertise_addr: String::from("127.0.0.1:8080"),
        peer_table: table.clone(),
        pins: Arc::new(PeerPins::new(&BTreeMap::new(), false)),
        storage: Arc::new(cachette::storage::MemoryStorage::new()),
        storage_path: std::env::temp_dir(),
        min_free: cachette::config::MinFree::Fraction(0.2),
        max_size: 0,
        interval: Duration::from_secs(3600),
        timeout: Duration::from_secs(7200),
    });
    // Registration is synchronous, so the record exists before any tick runs.
    let peers = table.snapshot();
    assert_eq!(peers.len(), 1, "{peers:?}");
    assert_eq!(peers[0].node_id, "SELF");
    assert_eq!(peers[0].fingerprint, "SELF");
    assert_eq!(peers[0].addr, "127.0.0.1:8080");
    assert!(peers[0].healthy);
    task.abort();
}
