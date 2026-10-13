//! Plan task 28 acceptance (criterion 7): peer table + hello + mDNS + seeds.
//!
//! Covers the dedup contract (a seed-discovered node and its mDNS record are
//! ONE peer), the `mdns=false` seed-only mode, the no-network mDNS no-op, and
//! the `POST /_internal/peers/hello` upsert/refresh path through the router.

use std::collections::BTreeMap;
use std::sync::Arc;

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
