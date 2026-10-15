//! Plan task 26 acceptance: v2 finalize / supersede / GetDownloadURL /
//! FindMissing + ranged artifact download.
//!
//! Driven through the real router with an in-memory backend. A full lifecycle
//! is exercised end to end: `CreateCacheEntry` → block upload + block list
//! (201) → `FinalizeCacheEntryUpload` (`ok:true`) → `GetCacheEntryDownloadURL`
//! (signed) → ranged `GET /v2/artifacts/{entryId}` (206 exact slice) →
//! `SupersedeCacheEntry` → the superseded URL 404s, the other 200s →
//! `FindMissingOrStaleCacheEntries` reports only the surviving entry.
//!
//! Failure cases covered: finalize with a wrong size is `ok:false` (NOT 500);
//! finalize with no published blob is 500 (never `ok:true`); an unknown entry
//! with a valid signature is 404; a missing/tampered signed URL is 403; a
//! download-URL miss is `{"ok":false,"signed_download_url":""}`.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use cachette::auth::{AuthPolicy, urls};
use cachette::config::AuthMode;
use cachette::routes;
use cachette::state::AppState;
use cachette::storage::{MemoryStorage, StorageBackend};
use serde_json::{Value, json};
use tower::ServiceExt;

const SECRET: &str = "test-secret-0123456789abcdef";
const STATIC_TOKEN: &str = "v2-download-token";
const HOST: &str = "https://cache.example.com";
const SERVICE: &str = "/twirp/github.actions.results.api.v1.CacheService";
const FINALIZE: &str = "FinalizeCacheEntryUpload";
const SUPERSEDE: &str = "SupersedeCacheEntry";
const DOWNLOAD_URL: &str = "GetCacheEntryDownloadURL";
const FIND: &str = "FindMissingOrStaleCacheEntries";

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

async fn send(
    app: Router,
    method: &str,
    uri: &str,
    headers: &[(&str, &str)],
    body: Vec<u8>,
) -> Reply {
    let mut builder = Request::builder().method(method).uri(uri);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let response = app
        .oneshot(builder.body(Body::from(body)).expect("valid request"))
        .await
        .expect("router responds");
    let status = response.status();
    let captured = response.headers().clone();
    let bytes = axum::body::to_bytes(response.into_body(), 8 * 1024 * 1024)
        .await
        .expect("response body");
    Reply {
        status,
        headers: captured,
        body: bytes.to_vec(),
    }
}

/// Drive one auth'd Twirp method and parse its JSON body.
async fn twirp(app: Router, method: &str, body: Value) -> (StatusCode, Value) {
    let auth = format!("Bearer {STATIC_TOKEN}");
    let reply = send(
        app,
        "POST",
        &format!("{SERVICE}/{method}"),
        &[
            ("authorization", auth.as_str()),
            ("content-type", "application/json"),
        ],
        body.to_string().into_bytes(),
    )
    .await;
    let value = serde_json::from_slice(&reply.body).expect("json response");
    (reply.status, value)
}

async fn create_entry(app: Router, key: &str, version: &str) -> Value {
    let (status, body) = twirp(
        app,
        "CreateCacheEntry",
        json!({"key": key, "version": version}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "create body: {body}");
    body
}

fn host_relative(url: &str) -> String {
    url.strip_prefix(HOST)
        .expect("URL uses the configured host")
        .to_owned()
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

fn block_body(seed: u8) -> Vec<u8> {
    (0..64_u8).map(|index| seed.wrapping_add(index)).collect()
}

/// Stage each block via `comp=block` then publish them via `comp=blocklist`,
/// returning the concatenated payload in document order.
async fn upload_and_commit(app: Router, upload: &str, blocks: &[Vec<u8>]) -> Vec<u8> {
    let ids: Vec<String> = blocks
        .iter()
        .map(|block| URL_SAFE_NO_PAD.encode(block))
        .collect();
    for (block, id) in blocks.iter().zip(&ids) {
        let uri = format!("{upload}&comp=block&blockid={}", encode_query_value(id));
        let reply = send(app.clone(), "PUT", &uri, &[], block.clone()).await;
        assert_eq!(reply.status, StatusCode::CREATED, "put block: {id}");
    }
    let mut xml = String::from("<BlockList>");
    for id in &ids {
        xml.push_str(&format!("<Latest>{id}</Latest>"));
    }
    xml.push_str("</BlockList>");
    let uri = format!(
        "{upload}&comp=blocklist&blocklist={}",
        encode_query_value(&xml)
    );
    let reply = send(app, "PUT", &uri, &[], Vec::new()).await;
    assert_eq!(
        reply.status,
        StatusCode::CREATED,
        "blocklist: {}",
        String::from_utf8_lossy(&reply.body)
    );
    blocks.iter().flatten().copied().collect()
}

async fn finalize(
    app: Router,
    key: &str,
    version: &str,
    cache_id: &str,
    size: Option<u64>,
) -> (StatusCode, Value) {
    let mut body = json!({"key": key, "version": version, "cache_id": cache_id});
    if let Some(size) = size {
        body["sizeBytes"] = json!(size);
    }
    twirp(app, FINALIZE, body).await
}

async fn get_download_url(
    app: Router,
    key: &str,
    version: &str,
    restore_keys: Option<&[&str]>,
) -> (StatusCode, Value) {
    let mut body = json!({"key": key, "version": version});
    if let Some(restore_keys) = restore_keys {
        body["restoreKeys"] = json!(restore_keys);
    }
    twirp(app, DOWNLOAD_URL, body).await
}

async fn find_missing(app: Router, pairs: &[(&str, &str)]) -> (StatusCode, Value) {
    let key_versions: Vec<Value> = pairs
        .iter()
        .map(|(key, version)| json!({"key": key, "version": version}))
        .collect();
    twirp(app, FIND, json!({"keyVersions": key_versions})).await
}

fn content_range(reply: &Reply) -> Option<String> {
    reply
        .headers
        .get(header::CONTENT_RANGE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

#[tokio::test]
async fn lifecycle_create_upload_finalize_download_supersede_findmissing() {
    let (state, storage) = state();
    let app = routes::router(state);

    // --- old entry: create → 3 blocks → blocklist → finalize -----------------
    let old = create_entry(app.clone(), "old-cache", "v1").await;
    let old_cache_id = old["cache_id"].as_str().expect("cache_id").to_owned();
    let old_upload = host_relative(
        old["signed_upload_url"]
            .as_str()
            .expect("signed_upload_url"),
    );
    let old_payload = upload_and_commit(
        app.clone(),
        &old_upload,
        &[block_body(0), block_body(64), block_body(128)],
    )
    .await;
    let (status, body) = finalize(
        app.clone(),
        "old-cache",
        "v1",
        &old_cache_id,
        Some(old_payload.len() as u64),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "finalize old: {body}");
    assert_eq!(body["ok"], json!(true), "finalize old: {body}");

    // --- new entry ----------------------------------------------------------
    let new = create_entry(app.clone(), "new-cache", "v1").await;
    let new_cache_id = new["cache_id"].as_str().expect("cache_id").to_owned();
    let new_upload = host_relative(
        new["signed_upload_url"]
            .as_str()
            .expect("signed_upload_url"),
    );
    let new_payload = upload_and_commit(
        app.clone(),
        &new_upload,
        &[block_body(200), block_body(10), block_body(90)],
    )
    .await;
    let (status, body) = finalize(
        app.clone(),
        "new-cache",
        "v1",
        &new_cache_id,
        Some(new_payload.len() as u64),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "finalize new: {body}");
    assert_eq!(body["ok"], json!(true));

    // --- GetCacheEntryDownloadURL mints a signed URL per entry --------------
    let (status, old_dl) = get_download_url(app.clone(), "old-cache", "v1", None).await;
    assert_eq!(status, StatusCode::OK, "old url: {old_dl}");
    assert_eq!(old_dl["ok"], json!(true));
    let old_url = old_dl["signed_download_url"]
        .as_str()
        .expect("signed_download_url");
    assert!(
        old_url.starts_with(&format!("{HOST}/v2/artifacts/old-cache?")),
        "{old_url}"
    );
    assert!(
        old_url.contains("&exp=") && old_url.contains("&mac="),
        "{old_url}"
    );
    assert_eq!(old_dl["matched_key"], json!("old-cache"));

    let (status, new_dl) = get_download_url(app.clone(), "new-cache", "v1", None).await;
    assert_eq!(status, StatusCode::OK, "new url: {new_dl}");
    assert_eq!(new_dl["ok"], json!(true));
    let new_url = new_dl["signed_download_url"]
        .as_str()
        .expect("signed_download_url");
    assert!(
        new_url.starts_with(&format!("{HOST}/v2/artifacts/new-cache?")),
        "{new_url}"
    );

    // --- ranged GET: 206 with the exact slice + Content-Range ---------------
    let old_path = host_relative(old_url);
    let reply = send(
        app.clone(),
        "GET",
        &old_path,
        &[("range", "bytes=10-19")],
        Vec::new(),
    )
    .await;
    assert_eq!(reply.status, StatusCode::PARTIAL_CONTENT, "ranged download");
    assert_eq!(
        content_range(&reply).as_deref(),
        Some(format!("bytes 10-19/{}", old_payload.len()).as_str())
    );
    assert_eq!(reply.body, old_payload[10..20].to_vec(), "exact slice");

    // --- full GET: 200 with the whole body ----------------------------------
    let new_path = host_relative(new_url);
    let reply = send(app.clone(), "GET", &new_path, &[], Vec::new()).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.body, new_payload);

    // --- supersede the old entry --------------------------------------------
    let (status, body) = twirp(
        app.clone(),
        SUPERSEDE,
        json!({"key": "old-cache", "version": "v1"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "supersede: {body}");
    assert_eq!(body["ok"], json!(true));

    let reply = send(app.clone(), "GET", &old_path, &[], Vec::new()).await;
    assert_eq!(
        reply.status,
        StatusCode::NOT_FOUND,
        "superseded entry is gone"
    );
    let reply = send(app.clone(), "GET", &new_path, &[], Vec::new()).await;
    assert_eq!(reply.status, StatusCode::OK, "survivor still downloads");

    // --- FindMissing reports only the surviving entry -----------------------
    let (status, body) =
        find_missing(app.clone(), &[("old-cache", "v1"), ("new-cache", "v1")]).await;
    assert_eq!(status, StatusCode::OK, "findmissing: {body}");
    let entries = body["cache_entries"]
        .as_array()
        .expect("cache_entries array");
    assert_eq!(entries.len(), 1, "only the new entry is present: {body}");
    assert_eq!(entries[0]["key"], json!("new-cache"));
    assert_eq!(entries[0]["version"], json!("v1"));
    assert_eq!(entries[0]["size"], json!(new_payload.len() as u64));
    assert!(
        entries[0]["creation_time"].as_u64().is_some(),
        "creation_time present: {body}"
    );

    // --- storage-level confirmation -----------------------------------------
    assert!(
        storage.stat("old-cache").await.expect("stat old").is_none(),
        "supersede deleted the entry"
    );
    assert!(storage.stat("new-cache").await.expect("stat new").is_some());
}

#[tokio::test]
async fn finalize_size_mismatch_is_ok_false_not_500() {
    let (state, _storage) = state();
    let app = routes::router(state);

    let created = create_entry(app.clone(), "size-cache", "v1").await;
    let cache_id = created["cache_id"].as_str().expect("cache_id").to_owned();
    let upload = host_relative(
        created["signed_upload_url"]
            .as_str()
            .expect("signed_upload_url"),
    );
    let payload = upload_and_commit(app.clone(), &upload, &[block_body(0)]).await;

    let (status, body) = finalize(
        app,
        "size-cache",
        "v1",
        &cache_id,
        Some(payload.len() as u64 + 1),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a size mismatch is a client error, not 500: {body}"
    );
    assert_eq!(body["ok"], json!(false));
}

#[tokio::test]
async fn finalize_missing_blob_is_500_and_never_ok_true() {
    let (state, _storage) = state();
    let app = routes::router(state);

    let (status, body) = finalize(app, "ghost-cache", "v1", "deadbeef", Some(1)).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "body: {body}");
    assert_eq!(body["ok"], json!(false));
}

#[tokio::test]
async fn download_unknown_entry_with_valid_signature_is_404() {
    let (state, _storage) = state();
    let app = routes::router(state);

    let path = "/v2/artifacts/ghost-cache";
    let signed = urls::mint(path, "ghost-cache", SECRET, 900, now_secs());
    let uri = format!("{path}{}", signed.query());
    let reply = send(app, "GET", &uri, &[], Vec::new()).await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn download_without_a_valid_signature_is_403() {
    let (state, _storage) = state();
    let app = routes::router(state);

    // No query at all.
    let reply = send(
        app.clone(),
        "GET",
        "/v2/artifacts/anything",
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert_eq!(reply.body, br#"{"error":"invalid or expired url"}"#);

    // A tampered MAC.
    let signed = urls::mint(
        "/v2/artifacts/anything",
        "anything",
        SECRET,
        900,
        now_secs(),
    );
    let mut mac = signed.mac.clone().into_bytes();
    mac[0] = if mac[0] == b'0' { b'1' } else { b'0' };
    let tampered = format!(
        "/v2/artifacts/anything?id={}&exp={}&mac={}",
        signed.id,
        signed.exp,
        String::from_utf8(mac).expect("hex is utf-8")
    );
    let reply = send(app.clone(), "GET", &tampered, &[], Vec::new()).await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);

    // A URL minted for a DIFFERENT path must not authorize this one.
    let other = urls::mint("/v2/artifacts/other", "other", SECRET, 900, now_secs());
    let uri = format!("/v2/artifacts/anything{}", other.query());
    let reply = send(app, "GET", &uri, &[], Vec::new()).await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn get_download_url_miss_is_ok_false_with_empty_url() {
    let (state, _storage) = state();
    let app = routes::router(state);

    let (status, body) = get_download_url(app, "no-such-cache", "v1", None).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["ok"], json!(false));
    assert_eq!(body["signed_download_url"], json!(""));
}

#[tokio::test]
async fn get_download_url_restore_key_prefix_fallback_hits() {
    let (state, _storage) = state();
    let app = routes::router(state);

    let created = create_entry(app.clone(), "prefix-cache-abc", "v1").await;
    let cache_id = created["cache_id"].as_str().expect("cache_id").to_owned();
    let upload = host_relative(
        created["signed_upload_url"]
            .as_str()
            .expect("signed_upload_url"),
    );
    let payload = upload_and_commit(app.clone(), &upload, &[block_body(5)]).await;
    let (_, body) = finalize(
        app.clone(),
        "prefix-cache-abc",
        "v1",
        &cache_id,
        Some(payload.len() as u64),
    )
    .await;
    assert_eq!(body["ok"], json!(true));

    // Exact first key misses; the restore key prefixes the stored entry.
    let (status, body) =
        get_download_url(app, "prefix-cache-xyz", "v1", Some(&["prefix-cache"])).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["ok"], json!(true), "body: {body}");
    assert_eq!(body["matched_key"], json!("prefix-cache-abc"));
    assert!(
        body["signed_download_url"]
            .as_str()
            .is_some_and(|url| url.starts_with(&format!("{HOST}/v2/artifacts/prefix-cache-abc?"))),
        "body: {body}"
    );
}

#[tokio::test]
async fn supersede_missing_key_is_idempotent_ok() {
    let (state, _storage) = state();
    let app = routes::router(state);

    let (status, body) = twirp(
        app,
        SUPERSEDE,
        json!({"key": "never-created", "version": "v1"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["ok"], json!(true));
}

#[tokio::test]
async fn supersede_allows_recreating_and_replacing_the_same_key() {
    let (state, storage) = state();
    let app = routes::router(state);

    // First generation.
    let first = create_entry(app.clone(), "rolling-cache", "v1").await;
    let first_cache_id = first["cache_id"].as_str().expect("cache_id").to_owned();
    let first_upload = host_relative(
        first["signed_upload_url"]
            .as_str()
            .expect("signed_upload_url"),
    );
    let first_payload = upload_and_commit(app.clone(), &first_upload, &[block_body(0)]).await;
    let (_, body) = finalize(
        app.clone(),
        "rolling-cache",
        "v1",
        &first_cache_id,
        Some(first_payload.len() as u64),
    )
    .await;
    assert_eq!(body["ok"], json!(true));

    // A same-key create is now a duplicate...
    let (_, duplicate) = twirp(
        app.clone(),
        "CreateCacheEntry",
        json!({"key": "rolling-cache", "version": "v1"}),
    )
    .await;
    assert_eq!(duplicate["ok"], json!(false));

    // ...until the runner supersedes the stale entry.
    let (_, body) = twirp(
        app.clone(),
        SUPERSEDE,
        json!({"key": "rolling-cache", "version": "v1"}),
    )
    .await;
    assert_eq!(body["ok"], json!(true));
    assert!(storage.stat("rolling-cache").await.expect("stat").is_none());

    // Second generation: create succeeds, upload replaces the content.
    let second = create_entry(app.clone(), "rolling-cache", "v1").await;
    assert_eq!(
        second["ok"],
        json!(true),
        "recreate after supersede: {second}"
    );
    let second_cache_id = second["cache_id"].as_str().expect("cache_id").to_owned();
    let second_upload = host_relative(
        second["signed_upload_url"]
            .as_str()
            .expect("signed_upload_url"),
    );
    let second_payload = upload_and_commit(
        app.clone(),
        &second_upload,
        &[block_body(200), block_body(1)],
    )
    .await;
    let (status, body) = finalize(
        app.clone(),
        "rolling-cache",
        "v1",
        &second_cache_id,
        Some(second_payload.len() as u64),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "finalize v2: {body}");
    assert_eq!(body["ok"], json!(true));
    assert_ne!(second_payload, first_payload);

    let (_, dl) = get_download_url(app.clone(), "rolling-cache", "v1", None).await;
    let url = host_relative(
        dl["signed_download_url"]
            .as_str()
            .expect("signed_download_url"),
    );
    let reply = send(app, "GET", &url, &[], Vec::new()).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(
        reply.body, second_payload,
        "download serves the new content"
    );
}

#[tokio::test]
async fn ranged_download_unsatisfiable_range_is_416() {
    let (state, _storage) = state();
    let app = routes::router(state);

    let created = create_entry(app.clone(), "range-cache", "v1").await;
    let cache_id = created["cache_id"].as_str().expect("cache_id").to_owned();
    let upload = host_relative(
        created["signed_upload_url"]
            .as_str()
            .expect("signed_upload_url"),
    );
    let payload = upload_and_commit(app.clone(), &upload, &[block_body(0)]).await;
    let (_, body) = finalize(
        app.clone(),
        "range-cache",
        "v1",
        &cache_id,
        Some(payload.len() as u64),
    )
    .await;
    assert_eq!(body["ok"], json!(true));

    let (_, dl) = get_download_url(app.clone(), "range-cache", "v1", None).await;
    let url = host_relative(
        dl["signed_download_url"]
            .as_str()
            .expect("signed_download_url"),
    );
    let reply = send(
        app,
        "GET",
        &url,
        &[("range", "bytes=100000-100001")],
        Vec::new(),
    )
    .await;
    assert_eq!(reply.status, StatusCode::RANGE_NOT_SATISFIABLE);
    assert_eq!(
        content_range(&reply).as_deref(),
        Some(format!("bytes */{}", payload.len()).as_str())
    );
}

#[tokio::test]
async fn find_missing_absent_pairs_report_nothing() {
    let (state, _storage) = state();
    let app = routes::router(state);

    let (status, body) = find_missing(app, &[("absent-a", "v1"), ("absent-b", "v2")]).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body, json!({"cache_entries": []}));
}
