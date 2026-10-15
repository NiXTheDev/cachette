//! Plan task 25 acceptance: Azure block-blob upload emulation
//! (`PUT /v2/upload/{entryId}`).
//!
//! Driven through the real router: a merge-mode `AppState` with an in-memory
//! backend mints a real signed capability URL via the Twirp `CreateCacheEntry`
//! method (task 24), then blocks are staged and a block list assembles them.
//!
//! Covered: 3 blocks (64-byte decoded ids, mixed alphabets) → blocklist →
//! 201 + non-empty `x-ms-request-id` + sha256 of the concatenation in listed
//! order; out-of-order `<Latest>` list reorders; 47/63-byte block id → 400;
//! unknown block in the list → 400; missing blocklist → 400; tampered/expired
//! URL → 403; unknown entryId → 404; `comp=must-ignore` with a body → 400.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
use cachette::auth::{AuthPolicy, urls};
use cachette::config::AuthMode;
use cachette::routes;
use cachette::state::AppState;
use cachette::storage::{MemoryStorage, StorageBackend};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;
use tower::ServiceExt;

const SECRET: &str = "test-secret-0123456789abcdef";
const STATIC_TOKEN: &str = "v2-upload-token";
const HOST: &str = "https://cache.example.com";
const SERVICE: &str = "/twirp/github.actions.results.api.v1.CacheService";

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_secs() as i64
}

fn state() -> (AppState, Arc<MemoryStorage>) {
    let storage = Arc::new(MemoryStorage::new());
    let mut state = AppState::new();
    state.storage = Some(storage.clone());
    state.external_url = Some(String::from(HOST));
    state.auth = Arc::new(AuthPolicy {
        mode: AuthMode::Merge,
        secret: Some(SECRET.to_owned()),
        hmac_max_age_seconds: 600,
        static_tokens: vec![STATIC_TOKEN.to_owned()],
        cluster_enabled: false,
    });
    (state, storage)
}

/// Captured response: status, headers and raw body.
struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}

/// Minimal `application/x-www-form-urlencoded` encoder for a query value.
fn encode_query_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*byte as char);
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

async fn send(app: Router, method: &str, uri: &str, body: Vec<u8>) -> Reply {
    let response = app
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .body(Body::from(body))
                .expect("valid request"),
        )
        .await
        .expect("router responds");
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = axum::body::to_bytes(response.into_body(), 4 * 1024 * 1024)
        .await
        .expect("response body");
    Reply {
        status,
        headers,
        body: bytes.to_vec(),
    }
}

/// Reserve a v2 entry through the real Twirp route and return the response.
async fn create_entry(app: Router, key: &str, version: &str) -> Value {
    let body = format!(r#"{{"key":"{key}","version":"{version}"}}"#);
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("{SERVICE}/CreateCacheEntry"))
                .header("authorization", format!("Bearer {STATIC_TOKEN}"))
                .header("content-type", "application/json")
                .body(Body::from(body))
                .expect("valid request"),
        )
        .await
        .expect("router responds");
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("response body");
    serde_json::from_slice(&bytes).expect("json response")
}

/// Mint an entry and return `(path_and_query, cache_id)` for the upload URL.
async fn signed_upload(app: Router, key: &str) -> (String, String) {
    let body = create_entry(app, key, "v1").await;
    assert_eq!(body["ok"], Value::Bool(true));
    let cache_id = body["cache_id"].as_str().expect("cache_id").to_owned();
    let upload = body["signed_upload_url"]
        .as_str()
        .expect("signed_upload_url");
    let path_and_query = upload.strip_prefix(HOST).expect("host-relative URL");
    (path_and_query.to_owned(), cache_id)
}

fn block_body(seed: u8) -> Vec<u8> {
    (0..64_u8).map(|index| seed.wrapping_add(index)).collect()
}

/// Build a `<BlockList>` document from `(tag, id)` pairs in document order.
fn block_list_xml(entries: &[(&str, &str)]) -> String {
    let mut xml = String::from("<BlockList>");
    for (tag, id) in entries {
        xml.push_str(&format!("<{tag}>{id}</{tag}>"));
    }
    xml.push_str("</BlockList>");
    xml
}

async fn read_blob(storage: &MemoryStorage, key: &str) -> Vec<u8> {
    let stat = storage
        .stat(key)
        .await
        .expect("stat")
        .expect("published entry");
    let mut stream = storage
        .get_range(key, 0..stat.size)
        .await
        .expect("get range");
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).await.expect("read");
    bytes
}

#[tokio::test]
async fn three_blocks_block_list_assembles_in_order_with_request_id() {
    let (state, storage) = state();
    let app = routes::router(state);
    let (upload, _cache_id) = signed_upload(app.clone(), "build-cache").await;

    let blocks = [block_body(0), block_body(100), block_body(200)];
    // Mixed alphabets/padding: URL-safe raw, URL-safe padded, standard padded.
    let ids = [
        URL_SAFE_NO_PAD.encode(&blocks[0]),
        URL_SAFE.encode(&blocks[1]),
        STANDARD.encode(&blocks[2]),
    ];

    for (block, id) in blocks.iter().zip(&ids) {
        let uri = format!("{upload}&comp=block&blockid={}", encode_query_value(id));
        let reply = send(app.clone(), "PUT", &uri, block.clone()).await;
        assert_eq!(reply.status, StatusCode::CREATED, "put block");
        assert!(reply.body.is_empty(), "put block body must be empty");
    }

    let xml = block_list_xml(&[
        ("Latest", &ids[0]),
        ("Latest", &ids[1]),
        ("Latest", &ids[2]),
    ]);
    let uri = format!(
        "{upload}&comp=blocklist&blocklist={}",
        encode_query_value(&xml)
    );
    let reply = send(app, "PUT", &uri, Vec::new()).await;
    assert_eq!(
        reply.status,
        StatusCode::CREATED,
        "body: {}",
        String::from_utf8_lossy(&reply.body)
    );
    assert!(reply.body.is_empty(), "block list body must be empty");

    let request_id = reply
        .headers
        .get("x-ms-request-id")
        .expect("x-ms-request-id present")
        .to_str()
        .expect("ascii header");
    assert!(!request_id.is_empty(), "x-ms-request-id must be non-empty");

    let expected: Vec<u8> = blocks.iter().flatten().copied().collect();
    let assembled = read_blob(&storage, "build-cache").await;
    assert_eq!(
        Sha256::digest(&assembled),
        Sha256::digest(&expected),
        "assembled sha256 must equal sha256 of the concatenation"
    );
    assert_eq!(assembled, expected);
}

#[tokio::test]
async fn out_of_order_block_list_reorders_per_document_order() {
    let (state, storage) = state();
    let app = routes::router(state);
    let (upload, _) = signed_upload(app.clone(), "reorder-cache").await;

    let blocks = [block_body(0), block_body(50), block_body(150)];
    let ids = [
        URL_SAFE_NO_PAD.encode(&blocks[0]),
        URL_SAFE_NO_PAD.encode(&blocks[1]),
        URL_SAFE_NO_PAD.encode(&blocks[2]),
    ];
    for (block, id) in blocks.iter().zip(&ids) {
        let uri = format!("{upload}&comp=block&blockid={}", encode_query_value(id));
        assert_eq!(
            send(app.clone(), "PUT", &uri, block.clone()).await.status,
            StatusCode::CREATED
        );
    }

    // Listed C, A, B — deliberately not upload order. `<Committed>` is accepted
    // alongside `<Latest>`.
    let xml = block_list_xml(&[
        ("Latest", &ids[2]),
        ("Committed", &ids[0]),
        ("Latest", &ids[1]),
    ]);
    let uri = format!(
        "{upload}&comp=blocklist&blocklist={}",
        encode_query_value(&xml)
    );
    let reply = send(app, "PUT", &uri, Vec::new()).await;
    assert_eq!(reply.status, StatusCode::CREATED);

    let expected: Vec<u8> = [&blocks[2], &blocks[0], &blocks[1]]
        .into_iter()
        .flatten()
        .copied()
        .collect();
    let assembled = read_blob(&storage, "reorder-cache").await;
    assert_eq!(
        Sha256::digest(&assembled),
        Sha256::digest(&expected),
        "sha256 must follow the XML order, not the upload order"
    );
}

#[tokio::test]
async fn block_id_with_wrong_decoded_length_is_400() {
    let (state, _storage) = state();
    let app = routes::router(state);
    let (upload, _) = signed_upload(app.clone(), "length-cache").await;

    for length in [47_usize, 63] {
        let bytes = vec![7_u8; length];
        let id = URL_SAFE_NO_PAD.encode(&bytes);
        let uri = format!("{upload}&comp=block&blockid={}", encode_query_value(&id));
        let reply = send(app.clone(), "PUT", &uri, bytes).await;
        assert_eq!(
            reply.status,
            StatusCode::BAD_REQUEST,
            "decoded length {length} must be 400"
        );
    }
}

#[tokio::test]
async fn block_list_referencing_an_unknown_block_is_400() {
    let (state, _storage) = state();
    let app = routes::router(state);
    let (upload, _) = signed_upload(app.clone(), "unknown-block-cache").await;

    let staged = block_body(0);
    let staged_id = URL_SAFE_NO_PAD.encode(&staged);
    let uri = format!(
        "{upload}&comp=block&blockid={}",
        encode_query_value(&staged_id)
    );
    assert_eq!(
        send(app.clone(), "PUT", &uri, staged).await.status,
        StatusCode::CREATED
    );

    let never_uploaded = URL_SAFE_NO_PAD.encode(block_body(9));
    let xml = block_list_xml(&[("Latest", &staged_id), ("Latest", &never_uploaded)]);
    let uri = format!(
        "{upload}&comp=blocklist&blocklist={}",
        encode_query_value(&xml)
    );
    let reply = send(app, "PUT", &uri, Vec::new()).await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn block_list_missing_parameter_is_400() {
    let (state, _storage) = state();
    let app = routes::router(state);
    let (upload, _) = signed_upload(app.clone(), "no-list-cache").await;
    let reply = send(app, "PUT", &format!("{upload}&comp=blocklist"), Vec::new()).await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn tampered_signed_url_is_403() {
    let (state, _storage) = state();
    let app = routes::router(state);
    let (upload, _) = signed_upload(app.clone(), "tamper-cache").await;

    // Flip a byte of the MAC.
    let tampered = {
        let mac_start = upload.find("&mac=").expect("mac present") + 5;
        let mut bytes = upload.clone().into_bytes();
        bytes[mac_start] = if bytes[mac_start] == b'0' { b'1' } else { b'0' };
        String::from_utf8(bytes).expect("utf-8")
    };
    let id = URL_SAFE_NO_PAD.encode(block_body(0));
    let uri = format!("{tampered}&comp=block&blockid={}", encode_query_value(&id));
    let reply = send(app, "PUT", &uri, block_body(0)).await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert_eq!(reply.body, br#"{"error":"invalid or expired url"}"#);
}

#[tokio::test]
async fn expired_signed_url_is_403() {
    let (state, _storage) = state();
    let app = routes::router(state);
    let cache_id = create_entry(app.clone(), "expired-cache", "v1").await["cache_id"]
        .as_str()
        .expect("cache_id")
        .to_owned();

    // A genuinely minted URL whose exp is one second in the past.
    let path = format!("/v2/upload/{cache_id}");
    let signed = urls::mint(&path, &cache_id, SECRET, 0, now_secs() - 1);
    let id = URL_SAFE_NO_PAD.encode(block_body(0));
    let uri = format!(
        "{path}{}&comp=block&blockid={}",
        signed.query(),
        encode_query_value(&id)
    );
    let reply = send(app, "PUT", &uri, block_body(0)).await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn unknown_entry_id_is_404() {
    let (state, _storage) = state();
    let app = routes::router(state);

    let unknown = "deadbeefdeadbeefdeadbeefdeadbeef";
    let path = format!("/v2/upload/{unknown}");
    let signed = urls::mint(&path, unknown, SECRET, 900, now_secs());
    let id = URL_SAFE_NO_PAD.encode(block_body(0));
    let uri = format!(
        "{path}{}&comp=block&blockid={}",
        signed.query(),
        encode_query_value(&id)
    );
    let reply = send(app, "PUT", &uri, block_body(0)).await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn unsupported_comp_with_body_is_400() {
    let (state, _storage) = state();
    let app = routes::router(state);
    let (upload, _) = signed_upload(app.clone(), "must-ignore-cache").await;
    let reply = send(
        app,
        "PUT",
        &format!("{upload}&comp=must-ignore"),
        b"ignored".to_vec(),
    )
    .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn unsupported_comp_without_body_is_201_noop() {
    // A bodyless unsupported comp is an accepted no-op.
    let (state, _storage) = state();
    let app = routes::router(state);
    let (upload, _) = signed_upload(app.clone(), "must-ignore-empty").await;
    let reply = send(
        app,
        "PUT",
        &format!("{upload}&comp=must-ignore"),
        Vec::new(),
    )
    .await;
    assert_eq!(reply.status, StatusCode::CREATED);
}

#[tokio::test]
async fn missing_signed_parameters_is_403() {
    let (state, _storage) = state();
    let app = routes::router(state);
    let (upload, cache_id) = signed_upload(app.clone(), "no-auth-cache").await;
    // Drop the whole query, including id/exp/mac.
    let reply = send(
        app.clone(),
        "PUT",
        &format!("/v2/upload/{cache_id}?comp=block"),
        block_body(0),
    )
    .await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);

    // A URL whose MAC binds a DIFFERENT entry path must not authorize this one,
    // even though the query carries syntactically valid id/exp/mac values.
    let query = upload
        .split_once('?')
        .map(|(_, query)| query)
        .expect("minted upload URL carries a query");
    let other = "00000000000000000000000000000000";
    assert_ne!(other, cache_id);
    let id = URL_SAFE_NO_PAD.encode(block_body(0));
    let reply = send(
        app,
        "PUT",
        &format!(
            "/v2/upload/{other}?{query}&comp=block&blockid={}",
            encode_query_value(&id)
        ),
        block_body(0),
    )
    .await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn auth_policy_secret_is_used_for_signed_urls() {
    // A URL minted with the configured secret validates; the fallback is never
    // used while a secret is configured (task 24 mint and task 25 validate
    // share `signing_secret`).
    let (state, _storage) = state();
    let app = routes::router(state);
    let (upload, _) = signed_upload(app.clone(), "secret-cache").await;
    let id = URL_SAFE_NO_PAD.encode(block_body(0));
    let reply = send(
        app,
        "PUT",
        &format!("{upload}&comp=block&blockid={}", encode_query_value(&id)),
        block_body(0),
    )
    .await;
    assert_eq!(reply.status, StatusCode::CREATED);
}
