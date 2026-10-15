//! Plan tasks 18/20/21 acceptance: the v1 artifactcache **status-code
//! contract** (criterion 1), driven in-process through the real router
//! (pattern from `tests/auth.rs`). Chunked uploads run against a real
//! `FsStorage` so commit assembles the on-disk parts; find/download fixtures
//! are seeded straight into `MemoryStorage`.
//!
//! Covered: find hit 200 (signed `archiveLocation`), find miss 204-empty,
//! reserve 200, duplicate reserve 409 (GitHub exception body), PATCH 204,
//! commit 204, commit size-mismatch 400 (+ reservation reaped), commit
//! supersede (one visible entry per key), download 200 full, download 206
//! slice + `Content-Range`, download incomplete 404, signed-URL gating
//! (bearer 403 without a URL, hmac single-node 200 bare, hmac cluster 403),
//! clean 200, unknown route 404 JSON, wrong method 405 JSON, auth 401.

use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode, header};
use cachette::auth::{AuthPolicy, urls};
use cachette::config::AuthMode;
use cachette::routes;
use cachette::state::AppState;
use cachette::storage::fs::FsStorage;
use cachette::storage::{ByteStream, MemoryStorage, StorageBackend};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use tower::ServiceExt;

const SECRET: &str = "test-secret-0123456789abcdef";
const TOKEN: &str = "v1-test-token";
const REPO: &str = "owner/cachette";
const RUN: &str = "1";
const FIXTURE_KEY: &str = "nginx-src-1.30.5";
const FIXTURE_BODY: &[u8] = b"the quick brown fox jumps over the lazy dog";

/// Captured response: status, headers and raw body.
struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}

fn json_body(value: serde_json::Value) -> Body {
    Body::from(value.to_string())
}

fn json_body_of(reply: &Reply) -> serde_json::Value {
    serde_json::from_slice(&reply.body).expect("response body is JSON")
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_secs() as i64
}

fn signed_url(key: &str) -> String {
    let path = format!("/_apis/artifactcache/artifacts/{key}");
    let signed = urls::mint(&path, key, SECRET, 900, now_secs());
    format!("{path}{}", signed.query())
}

fn compute_mac(ts: i64) -> String {
    let payload = format!("{REPO}>{RUN}>{ts}>");
    let mut mac = Hmac::<Sha256>::new_from_slice(SECRET.as_bytes()).expect("hmac key");
    mac.update(payload.as_bytes());
    mac.finalize()
        .into_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn hmac_headers(ts: i64) -> [(String, String); 4] {
    [
        (String::from("forgejo-cache-repo"), String::from(REPO)),
        (String::from("forgejo-cache-runnumber"), String::from(RUN)),
        (String::from("forgejo-cache-timestamp"), ts.to_string()),
        (String::from("forgejo-cache-mac"), compute_mac(ts)),
    ]
}

/// Seed a finalized, visible entry directly into storage (the fixture the
/// skeleton cannot create over HTTP until task 21 finalizes commits).
async fn seed(storage: &MemoryStorage, key: &str, body: &[u8]) {
    let stream: ByteStream<'static> = Box::pin(Cursor::new(body.to_vec()));
    storage.put_stream(key, stream).await.expect("seed put");
    storage.finalize(key).await.expect("seed finalize");
}

async fn fixture_state() -> AppState {
    let storage = Arc::new(MemoryStorage::new());
    seed(&storage, FIXTURE_KEY, FIXTURE_BODY).await;
    let mut state = AppState::new();
    state.storage = Some(storage);
    state.auth = Arc::new(AuthPolicy {
        mode: AuthMode::Bearer,
        secret: Some(SECRET.to_owned()),
        hmac_max_age_seconds: 600,
        static_tokens: vec![TOKEN.to_owned()],
        cluster_enabled: false,
    });
    state
}

/// Same as [`fixture_state`] but with a configured `cache.max_size` and the
/// storage handle returned so a test can seed entries mid-case.
async fn sized_state(max_size: u64) -> (AppState, Arc<MemoryStorage>) {
    let storage = Arc::new(MemoryStorage::new());
    seed(&storage, FIXTURE_KEY, FIXTURE_BODY).await;
    let mut state = AppState::new();
    state.cache.max_size = max_size;
    state.storage = Some(storage.clone());
    state.auth = Arc::new(AuthPolicy {
        mode: AuthMode::Bearer,
        secret: Some(SECRET.to_owned()),
        hmac_max_age_seconds: 600,
        static_tokens: vec![TOKEN.to_owned()],
        cluster_enabled: false,
    });
    (state, storage)
}

async fn hmac_state(cluster_enabled: bool) -> AppState {
    let storage = Arc::new(MemoryStorage::new());
    seed(&storage, FIXTURE_KEY, FIXTURE_BODY).await;
    let mut state = AppState::new();
    state.storage = Some(storage);
    state.auth = Arc::new(AuthPolicy {
        mode: AuthMode::Hmac,
        secret: Some(SECRET.to_owned()),
        hmac_max_age_seconds: 600,
        static_tokens: Vec::new(),
        cluster_enabled,
    });
    state
}

async fn call(
    app: &Router,
    method: &str,
    path: &str,
    token: Option<&str>,
    extra: &[(&str, &str)],
    body: Body,
) -> Reply {
    let mut builder = Request::builder().method(method).uri(path);
    if let Some(token) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    for (name, value) in extra {
        builder = builder.header(*name, *value);
    }
    let request = builder.body(body).expect("request builds");
    let response = app.clone().oneshot(request).await.expect("router responds");
    let status = response.status();
    let headers = response.headers().clone();
    let body = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("response body")
        .to_vec();
    Reply {
        status,
        headers,
        body,
    }
}

#[tokio::test]
async fn find_hit_returns_200_with_signed_archive_location() {
    let app = routes::router(fixture_state().await);
    let reply = call(
        &app,
        "GET",
        "/_apis/artifactcache/cache?keys=nginx-src-1.30.5&version=2",
        Some(TOKEN),
        &[],
        Body::empty(),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK);
    let body = json_body_of(&reply);
    assert_eq!(body["result"], "hit");
    assert_eq!(body["cacheKey"], FIXTURE_KEY);
    let location = body["archiveLocation"]
        .as_str()
        .expect("archiveLocation string");
    assert!(
        location.starts_with("/_apis/artifactcache/artifacts/nginx-src-1.30.5?id="),
        "location: {location}"
    );
    assert!(location.contains("&exp="), "location: {location}");
    assert!(location.contains("&mac="), "location: {location}");
}

#[tokio::test]
async fn find_miss_returns_empty_204_and_never_429() {
    let app = routes::router(fixture_state().await);
    let reply = call(
        &app,
        "GET",
        "/_apis/artifactcache/cache?keys=absent-key&version=2",
        Some(TOKEN),
        &[],
        Body::empty(),
    )
    .await;
    assert_eq!(reply.status, StatusCode::NO_CONTENT);
    assert_ne!(reply.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(reply.body.is_empty(), "204 must carry an empty body");
}

#[tokio::test]
async fn reserve_returns_200_with_fresh_cache_id_and_zero_size() {
    let app = routes::router(fixture_state().await);
    let reply = call(
        &app,
        "POST",
        "/_apis/artifactcache/caches",
        Some(TOKEN),
        &[("content-type", "application/json")],
        json_body(serde_json::json!({"key": "brand-new", "version": "2"})),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK);
    let body = json_body_of(&reply);
    let cache_id = body["cacheId"].as_u64().expect("cacheId number");
    assert!(cache_id > 0, "cacheId must be nonzero: {cache_id}");
    assert_eq!(body["cacheSize"], 0);
}

#[tokio::test]
async fn reserve_duplicate_returns_409_exception_body() {
    let app = routes::router(fixture_state().await);
    let reply = call(
        &app,
        "POST",
        "/_apis/artifactcache/caches",
        Some(TOKEN),
        &[("content-type", "application/json")],
        json_body(serde_json::json!({"key": FIXTURE_KEY, "version": "2"})),
    )
    .await;
    assert_eq!(reply.status, StatusCode::CONFLICT);
    let body = json_body_of(&reply);
    assert_eq!(body["error"], "ArtifactCacheItemAlreadyExistsException");
    assert_eq!(body["type"], "key");
    assert_eq!(body["key"], FIXTURE_KEY);
}

#[tokio::test]
async fn patch_chunk_returns_empty_204() {
    let (state, _dir) = fs_state().await;
    let app = routes::router(state);
    let cache_id = reserve_key(&app).await;
    let reply = call(
        &app,
        "PATCH",
        &format!("/_apis/artifactcache/caches/{cache_id}"),
        Some(TOKEN),
        &[("content-range", "bytes 0-9/*")],
        Body::from(vec![0_u8; 10]),
    )
    .await;
    assert_eq!(reply.status, StatusCode::NO_CONTENT);
    assert!(reply.body.is_empty(), "204 must carry an empty body");
}

#[tokio::test]
async fn commit_returns_empty_204() {
    let (state, _dir) = fs_state().await;
    let app = routes::router(state);
    let cache_id = reserve_key(&app).await;
    let staged = patch(&app, &cache_id, 0, 9, 10, 1).await;
    assert_eq!(staged.status, StatusCode::NO_CONTENT);
    let reply = commit(&app, &cache_id, 10).await;
    assert_eq!(reply.status, StatusCode::NO_CONTENT);
    assert!(reply.body.is_empty(), "204 must carry an empty body");
}

#[tokio::test]
async fn download_without_range_returns_200_full_body() {
    let app = routes::router(fixture_state().await);
    let reply = call(
        &app,
        "GET",
        &signed_url(FIXTURE_KEY),
        Some(TOKEN),
        &[],
        Body::empty(),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.body.as_slice(), FIXTURE_BODY);
    assert_eq!(
        reply
            .headers
            .get(header::ACCEPT_RANGES)
            .and_then(|value| value.to_str().ok()),
        Some("bytes"),
    );
}

#[tokio::test]
async fn download_with_range_returns_206_slice_and_content_range() {
    let app = routes::router(fixture_state().await);
    let reply = call(
        &app,
        "GET",
        &signed_url(FIXTURE_KEY),
        Some(TOKEN),
        &[("range", "bytes=4-8")],
        Body::empty(),
    )
    .await;
    assert_eq!(reply.status, StatusCode::PARTIAL_CONTENT);
    let content_range = reply
        .headers
        .get(header::CONTENT_RANGE)
        .and_then(|value| value.to_str().ok())
        .expect("Content-Range header");
    assert_eq!(content_range, format!("bytes 4-8/{}", FIXTURE_BODY.len()));
    assert_eq!(reply.body.as_slice(), &FIXTURE_BODY[4..=8]);
}

#[tokio::test]
async fn download_unknown_id_returns_404_json() {
    let app = routes::router(fixture_state().await);
    let reply = call(
        &app,
        "GET",
        &signed_url("missing"),
        Some(TOKEN),
        &[],
        Body::empty(),
    )
    .await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
    assert_eq!(json_body_of(&reply)["error"], "not found");
}

#[tokio::test]
async fn clean_returns_200() {
    let app = routes::router(fixture_state().await);
    let reply = call(
        &app,
        "POST",
        "/_apis/artifactcache/caches/clean",
        Some(TOKEN),
        &[],
        Body::empty(),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK);
}

#[tokio::test]
async fn unknown_route_returns_404_json() {
    let app = routes::router(fixture_state().await);
    let reply = call(&app, "GET", "/nope", None, &[], Body::empty()).await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
    assert_eq!(json_body_of(&reply)["error"], "not found");
}

#[tokio::test]
async fn wrong_method_returns_405_json() {
    let app = routes::router(fixture_state().await);
    let reply = call(
        &app,
        "POST",
        "/_apis/artifactcache/cache",
        Some(TOKEN),
        &[],
        Body::empty(),
    )
    .await;
    assert_eq!(reply.status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(json_body_of(&reply)["error"], "method not allowed");
}

#[tokio::test]
async fn artifactcache_route_requires_auth() {
    let app = routes::router(fixture_state().await);
    let reply = call(
        &app,
        "GET",
        "/_apis/artifactcache/cache?keys=x&version=2",
        None,
        &[],
        Body::empty(),
    )
    .await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn reserve_reports_max_size_minus_used_bytes() {
    let (state, _storage) = sized_state(1000).await;
    let app = routes::router(state);
    let reply = call(
        &app,
        "POST",
        "/_apis/artifactcache/caches",
        Some(TOKEN),
        &[("content-type", "application/json")],
        json_body(serde_json::json!({"key": "fresh-key", "version": "2"})),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK);
    let body = json_body_of(&reply);
    assert_eq!(body["cacheSize"], 1000 - FIXTURE_BODY.len() as u64);
    assert!(
        body.get("archiveLocation").is_none(),
        "reserve must not leak archiveLocation: {body}"
    );
}

#[tokio::test]
async fn reserve_clamps_cache_size_to_zero_when_over_quota() {
    let (state, _storage) = sized_state(10).await;
    let app = routes::router(state);
    let reply = call(
        &app,
        "POST",
        "/_apis/artifactcache/caches",
        Some(TOKEN),
        &[("content-type", "application/json")],
        json_body(serde_json::json!({"key": "over-quota", "version": "2"})),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_ne!(reply.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(json_body_of(&reply)["cacheSize"], 0);
}

#[tokio::test]
async fn reserve_of_incomplete_key_returns_200_not_409() {
    let app = routes::router(fixture_state().await);
    let request = || json_body(serde_json::json!({"key": "staged-key", "version": "2"}));
    let first = call(
        &app,
        "POST",
        "/_apis/artifactcache/caches",
        Some(TOKEN),
        &[("content-type", "application/json")],
        request(),
    )
    .await;
    let second = call(
        &app,
        "POST",
        "/_apis/artifactcache/caches",
        Some(TOKEN),
        &[("content-type", "application/json")],
        request(),
    )
    .await;
    assert_eq!(first.status, StatusCode::OK);
    assert_eq!(second.status, StatusCode::OK);
}

#[tokio::test]
async fn reserved_entry_is_invisible_to_find_until_commit() {
    let app = routes::router(fixture_state().await);
    let reserve = call(
        &app,
        "POST",
        "/_apis/artifactcache/caches",
        Some(TOKEN),
        &[("content-type", "application/json")],
        json_body(serde_json::json!({"key": "pending-key", "version": "2"})),
    )
    .await;
    assert_eq!(reserve.status, StatusCode::OK);
    let find = call(
        &app,
        "GET",
        "/_apis/artifactcache/cache?keys=pending-key&version=2",
        Some(TOKEN),
        &[],
        Body::empty(),
    )
    .await;
    assert_eq!(find.status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn reserve_repeat_after_completion_returns_409() {
    let (state, storage) = sized_state(0).await;
    let app = routes::router(state);
    let request = || json_body(serde_json::json!({"key": "repeat-key", "version": "2"}));
    let first = call(
        &app,
        "POST",
        "/_apis/artifactcache/caches",
        Some(TOKEN),
        &[("content-type", "application/json")],
        request(),
    )
    .await;
    assert_eq!(first.status, StatusCode::OK);
    seed(&storage, "repeat-key", b"payload").await;
    let second = call(
        &app,
        "POST",
        "/_apis/artifactcache/caches",
        Some(TOKEN),
        &[("content-type", "application/json")],
        request(),
    )
    .await;
    assert_eq!(second.status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn reserve_duplicate_detection_folds_key_case() {
    let app = routes::router(fixture_state().await);
    let requested = "NGINX-SRC-1.30.5";
    let reply = call(
        &app,
        "POST",
        "/_apis/artifactcache/caches",
        Some(TOKEN),
        &[("content-type", "application/json")],
        json_body(serde_json::json!({"key": requested, "version": "2"})),
    )
    .await;
    assert_eq!(reply.status, StatusCode::CONFLICT);
    assert_eq!(json_body_of(&reply)["key"], requested);
}

/// Temp dir removed on drop; unique per test so parallel runs never collide.
struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "cachette-t20-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).expect("temp dir");
        Self { path }
    }

    fn path(&self) -> &PathBuf {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// AppState backed by a real `FsStorage` on disk (chunk tests need the parts
/// directory layout). The `TempDir` must outlive the state.
async fn fs_state() -> (AppState, TempDir) {
    let dir = TempDir::new();
    let storage = Arc::new(FsStorage::open(dir.path()).expect("fs storage opens"));
    let mut state = AppState::new();
    state.storage = Some(storage);
    state.auth = Arc::new(AuthPolicy {
        mode: AuthMode::Bearer,
        secret: Some(SECRET.to_owned()),
        hmac_max_age_seconds: 600,
        static_tokens: vec![TOKEN.to_owned()],
        cluster_enabled: false,
    });
    (state, dir)
}

async fn fs_state_with_fs() -> (AppState, Arc<FsStorage>, TempDir) {
    let dir = TempDir::new();
    let storage = Arc::new(FsStorage::open(dir.path()).expect("fs storage opens"));
    let mut state = AppState::new();
    state.storage = Some(storage.clone());
    state.auth = Arc::new(AuthPolicy {
        mode: AuthMode::Bearer,
        secret: Some(SECRET.to_owned()),
        hmac_max_age_seconds: 600,
        static_tokens: vec![TOKEN.to_owned()],
        cluster_enabled: false,
    });
    (state, storage, dir)
}

/// Reserve a fresh cache entry over HTTP and return its `cacheId`.
async fn reserve_key(app: &Router) -> String {
    reserve(app, "chunked-key", "2").await
}

async fn reserve(app: &Router, key: &str, version: &str) -> String {
    let reply = call(
        app,
        "POST",
        "/_apis/artifactcache/caches",
        Some(TOKEN),
        &[("content-type", "application/json")],
        json_body(serde_json::json!({"key": key, "version": version})),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "reserve {key} v{version}");
    json_body_of(&reply)["cacheId"]
        .as_u64()
        .expect("cacheId number")
        .to_string()
}

async fn commit(app: &Router, cache_id: &str, size: u64) -> Reply {
    call(
        app,
        "POST",
        &format!("/_apis/artifactcache/caches/{cache_id}"),
        Some(TOKEN),
        &[("content-type", "application/json")],
        json_body(serde_json::json!({"size": size})),
    )
    .await
}

/// PATCH one chunk of `len` bytes at `start..=end` (inclusive), filled with
/// `fill` so distinct chunks are distinguishable on disk.
async fn patch(app: &Router, cache_id: &str, start: u64, end: u64, len: usize, fill: u8) -> Reply {
    call(
        app,
        "PATCH",
        &format!("/_apis/artifactcache/caches/{cache_id}"),
        Some(TOKEN),
        &[("content-range", &format!("bytes {start}-{end}/*"))],
        Body::from(vec![fill; len]),
    )
    .await
}

/// `parts/{cacheId}/{start}.part` file sizes, keyed by start offset.
fn chunk_sizes(dir: &Path, cache_id: &str) -> Vec<(u64, u64)> {
    let parts = dir.join("parts").join(cache_id);
    let mut sizes = Vec::new();
    for dirent in std::fs::read_dir(parts).expect("parts dir") {
        let dirent = dirent.expect("dirent");
        let name = dirent.file_name();
        let name = name.to_str().expect("utf8 name");
        let Some(stem) = name.strip_suffix(".part") else {
            continue;
        };
        let start = stem.parse::<u64>().expect("numeric start");
        sizes.push((start, dirent.metadata().expect("metadata").len()));
    }
    sizes.sort_unstable();
    sizes
}

#[tokio::test]
async fn patch_4mib_chunks_in_8_parts_stages_each_part_file() {
    let (state, dir) = fs_state().await;
    let app = routes::router(state);
    let cache_id = reserve_key(&app).await;
    let chunk = 4 * 1024 * 1024;
    for i in 0..8_u64 {
        let start = i * chunk;
        let reply = patch(
            &app,
            &cache_id,
            start,
            start + chunk - 1,
            chunk as usize,
            i as u8,
        )
        .await;
        assert_eq!(reply.status, StatusCode::NO_CONTENT, "chunk {i}");
    }
    let sizes = chunk_sizes(dir.path(), &cache_id);
    assert_eq!(sizes.len(), 8, "one part file per chunk: {sizes:?}");
    for (i, (start, len)) in sizes.iter().enumerate() {
        assert_eq!(*start, i as u64 * chunk, "offsets: {sizes:?}");
        assert_eq!(*len, chunk, "sizes: {sizes:?}");
    }
}

#[tokio::test]
async fn patch_32mib_chunks_in_4_parts_stages_each_part_file() {
    let (state, dir) = fs_state().await;
    let app = routes::router(state);
    let cache_id = reserve_key(&app).await;
    let chunk = 32 * 1024 * 1024;
    for i in 0..4_u64 {
        let start = i * chunk;
        let reply = patch(
            &app,
            &cache_id,
            start,
            start + chunk - 1,
            chunk as usize,
            i as u8,
        )
        .await;
        assert_eq!(reply.status, StatusCode::NO_CONTENT, "chunk {i}");
    }
    let sizes = chunk_sizes(dir.path(), &cache_id);
    assert_eq!(sizes.len(), 4, "one part file per chunk: {sizes:?}");
    for (i, (start, len)) in sizes.iter().enumerate() {
        assert_eq!(*start, i as u64 * chunk, "offsets: {sizes:?}");
        assert_eq!(*len, chunk, "sizes: {sizes:?}");
    }
}

#[tokio::test]
async fn patch_overlapping_range_returns_400() {
    let (state, _dir) = fs_state().await;
    let app = routes::router(state);
    let cache_id = reserve_key(&app).await;
    let first = patch(&app, &cache_id, 500, 599, 100, 1).await;
    assert_eq!(first.status, StatusCode::NO_CONTENT);
    let overlap = patch(&app, &cache_id, 400, 599, 200, 2).await;
    assert_eq!(overlap.status, StatusCode::BAD_REQUEST);
    let adjacent = patch(&app, &cache_id, 600, 699, 100, 3).await;
    assert_eq!(
        adjacent.status,
        StatusCode::NO_CONTENT,
        "adjacent ranges are fine"
    );
}

#[tokio::test]
async fn patch_unknown_cache_id_returns_404() {
    let (state, _dir) = fs_state().await;
    let app = routes::router(state);
    let reply = patch(&app, "deadbeefdeadbeefdeadbeefdeadbeef", 0, 9, 10, 1).await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
    assert_eq!(json_body_of(&reply)["error"], "not found");
}

#[tokio::test]
async fn patch_completed_entry_returns_409() {
    let (state, _dir) = fs_state().await;
    let storage = state.storage.as_ref().expect("storage configured").clone();
    let app = routes::router(state);
    let cache_id = reserve_key(&app).await;
    let reply = patch(&app, &cache_id, 0, 9, 10, 1).await;
    assert_eq!(reply.status, StatusCode::NO_CONTENT);
    storage.finalize(&cache_id).await.expect("finalize");
    let after = patch(&app, &cache_id, 10, 19, 10, 2).await;
    assert_eq!(after.status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn patch_repeat_of_received_range_is_idempotent_204() {
    let (state, dir) = fs_state().await;
    let app = routes::router(state);
    let cache_id = reserve_key(&app).await;
    let first = patch(&app, &cache_id, 0, 4_194_303, 4_194_304, 7).await;
    assert_eq!(first.status, StatusCode::NO_CONTENT);
    let second = patch(&app, &cache_id, 0, 4_194_303, 4_194_304, 7).await;
    assert_eq!(second.status, StatusCode::NO_CONTENT);
    let sizes = chunk_sizes(dir.path(), &cache_id);
    assert_eq!(
        sizes,
        vec![(0, 4_194_304)],
        "no duplicate part file: {sizes:?}"
    );
}

#[tokio::test]
async fn patch_malformed_content_range_returns_400() {
    let (state, _dir) = fs_state().await;
    let app = routes::router(state);
    let cache_id = reserve_key(&app).await;
    for bad in [
        "bytes 0-9",
        "bytes 0/*",
        "bytes a-b/*",
        "bytes 5-4/*",
        "items 0-1/*",
    ] {
        let reply = call(
            &app,
            "PATCH",
            &format!("/_apis/artifactcache/caches/{cache_id}"),
            Some(TOKEN),
            &[("content-range", bad)],
            Body::from(vec![0_u8; 10]),
        )
        .await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "header: {bad}");
    }
}

#[tokio::test]
async fn patch_cache_id_zero_returns_400() {
    let (state, _dir) = fs_state().await;
    let app = routes::router(state);
    let reply = patch(&app, "0", 0, 9, 10, 1).await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn patch_body_length_mismatch_returns_400() {
    let (state, _dir) = fs_state().await;
    let app = routes::router(state);
    let cache_id = reserve_key(&app).await;
    let reply = call(
        &app,
        "PATCH",
        &format!("/_apis/artifactcache/caches/{cache_id}"),
        Some(TOKEN),
        &[("content-range", "bytes 0-9/*")],
        Body::from(vec![0_u8; 5]),
    )
    .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn commit_then_find_and_download_round_trip() {
    let (state, _dir) = fs_state().await;
    let app = routes::router(state);
    let cache_id = reserve_key(&app).await;
    assert_eq!(
        patch(&app, &cache_id, 0, 4, 5, 0xAA).await.status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        patch(&app, &cache_id, 5, 9, 5, 0xBB).await.status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        commit(&app, &cache_id, 10).await.status,
        StatusCode::NO_CONTENT
    );

    let mut expected = vec![0xAA; 5];
    expected.extend(vec![0xBB; 5]);

    let find = call(
        &app,
        "GET",
        "/_apis/artifactcache/cache?keys=chunked-key&version=2",
        Some(TOKEN),
        &[],
        Body::empty(),
    )
    .await;
    assert_eq!(find.status, StatusCode::OK);
    let location = json_body_of(&find)["archiveLocation"]
        .as_str()
        .expect("archiveLocation string")
        .to_owned();

    let download = call(&app, "GET", &location, Some(TOKEN), &[], Body::empty()).await;
    assert_eq!(download.status, StatusCode::OK);
    assert_eq!(download.body, expected);

    let ranged = call(
        &app,
        "GET",
        &location,
        Some(TOKEN),
        &[("range", "bytes=4-7")],
        Body::empty(),
    )
    .await;
    assert_eq!(ranged.status, StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        ranged
            .headers
            .get(header::CONTENT_RANGE)
            .and_then(|value| value.to_str().ok()),
        Some("bytes 4-7/10"),
    );
    assert_eq!(ranged.body, vec![0xAA, 0xBB, 0xBB, 0xBB]);
}

#[tokio::test]
async fn commit_wrong_size_returns_400_and_reaps_reservation() {
    let (state, storage, _dir) = fs_state_with_fs().await;
    let app = routes::router(state);
    let cache_id = reserve_key(&app).await;
    assert_eq!(
        patch(&app, &cache_id, 0, 9, 10, 1).await.status,
        StatusCode::NO_CONTENT
    );

    let reply = commit(&app, &cache_id, 20).await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert!(
        json_body_of(&reply)["error"]
            .as_str()
            .expect("error string")
            .contains("does not match"),
    );

    let reaped = storage
        .reap_expired_reservations(now_secs() as u64)
        .await
        .expect("reap");
    assert_eq!(reaped, 1, "failed reservation is reclaimed");

    let download = call(
        &app,
        "GET",
        &signed_url("chunked-key"),
        Some(TOKEN),
        &[],
        Body::empty(),
    )
    .await;
    assert_eq!(download.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn commit_unknown_cache_id_returns_404() {
    let (state, _dir) = fs_state().await;
    let app = routes::router(state);
    let reply = commit(&app, "deadbeefdeadbeefdeadbeefdeadbeef", 10).await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn download_incomplete_reservation_returns_404() {
    let (state, _dir) = fs_state().await;
    let app = routes::router(state);
    let cache_id = reserve(&app, "pending-dl", "2").await;
    assert_eq!(
        patch(&app, &cache_id, 0, 4, 5, 1).await.status,
        StatusCode::NO_CONTENT
    );

    let download = call(
        &app,
        "GET",
        &signed_url("pending-dl"),
        Some(TOKEN),
        &[],
        Body::empty(),
    )
    .await;
    assert_eq!(download.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn commit_supersede_replaces_prior_same_key_version() {
    let (state, storage, _dir) = fs_state_with_fs().await;
    let app = routes::router(state);
    let v2 = reserve(&app, "super-key", "2").await;
    let v3 = reserve(&app, "super-key", "3").await;

    assert_eq!(
        patch(&app, &v2, 0, 2, 3, 0xC2).await.status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(commit(&app, &v2, 3).await.status, StatusCode::NO_CONTENT);
    assert_eq!(
        storage
            .stat("super-key")
            .await
            .expect("stat")
            .expect("v2 visible")
            .size,
        3
    );

    assert_eq!(
        patch(&app, &v3, 0, 3, 4, 0xC3).await.status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(commit(&app, &v3, 4).await.status, StatusCode::NO_CONTENT);

    let stat = storage
        .stat("super-key")
        .await
        .expect("stat")
        .expect("v3 visible");
    assert_eq!(stat.size, 4, "older version superseded");
    assert_eq!(
        storage.list().await.expect("list").len(),
        1,
        "one visible entry per key"
    );
    assert_eq!(
        storage.used_bytes().await.expect("used"),
        4,
        "superseded size subtracted from accounting"
    );

    let download = call(
        &app,
        "GET",
        &signed_url("super-key"),
        Some(TOKEN),
        &[],
        Body::empty(),
    )
    .await;
    assert_eq!(download.status, StatusCode::OK);
    assert_eq!(download.body, vec![0xC3; 4]);
}

#[tokio::test]
async fn download_requires_signed_url_in_bearer_mode() {
    let app = routes::router(fixture_state().await);
    let reply = call(
        &app,
        "GET",
        "/_apis/artifactcache/artifacts/nginx-src-1.30.5",
        Some(TOKEN),
        &[],
        Body::empty(),
    )
    .await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert_eq!(json_body_of(&reply)["error"], "invalid or expired url");
}

/// Task 22: a correctly signed artifact URL authorizes the download on its own
/// — real clients follow `archiveLocation` with no `Authorization` header, so
/// the HMAC/bearer gate must not reject it (the signed URL is the credential).
#[tokio::test]
async fn download_signed_url_authorizes_without_bearer() {
    let app = routes::router(fixture_state().await);
    let reply = call(
        &app,
        "GET",
        &signed_url(FIXTURE_KEY),
        None,
        &[],
        Body::empty(),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.body.as_slice(), FIXTURE_BODY);
}

/// Task 22: `find` returns an **absolute** `archiveLocation` once
/// `server.external_url` is configured (production always resolves it from
/// `listen`); clients `GET` the value verbatim.
#[tokio::test]
async fn find_returns_absolute_archive_location_when_external_url_configured() {
    let mut state = fixture_state().await;
    state.external_url = Some(String::from("https://cache.example.test"));
    let app = routes::router(state);
    let reply = call(
        &app,
        "GET",
        "/_apis/artifactcache/cache?keys=nginx-src-1.30.5&version=2",
        Some(TOKEN),
        &[],
        Body::empty(),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK);
    let location = json_body_of(&reply)["archiveLocation"]
        .as_str()
        .expect("archiveLocation string")
        .to_owned();
    assert!(
        location.starts_with(
            "https://cache.example.test/_apis/artifactcache/artifacts/nginx-src-1.30.5?id="
        ),
        "archiveLocation must be absolute: {location}"
    );
}

#[tokio::test]
async fn download_rejects_tampered_signed_url() {
    let app = routes::router(fixture_state().await);
    let path = format!("/_apis/artifactcache/artifacts/{FIXTURE_KEY}");
    let signed = urls::mint(&path, FIXTURE_KEY, SECRET, 900, now_secs());
    let mut mac = signed.mac.into_bytes();
    mac[0] = if mac[0] == b'0' { b'1' } else { b'0' };
    let damaged = format!(
        "{path}?id={}&exp={}&mac={}",
        signed.id,
        signed.exp,
        String::from_utf8(mac).expect("hex utf-8"),
    );
    let reply = call(&app, "GET", &damaged, Some(TOKEN), &[], Body::empty()).await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn download_allows_bare_get_in_hmac_single_node() {
    let app = routes::router(hmac_state(false).await);
    let headers = hmac_headers(now_secs());
    let extra: Vec<(&str, &str)> = headers
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();
    let reply = call(
        &app,
        "GET",
        "/_apis/artifactcache/artifacts/nginx-src-1.30.5",
        None,
        &extra,
        Body::empty(),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.body.as_slice(), FIXTURE_BODY);
}

#[tokio::test]
async fn download_requires_signed_url_in_hmac_cluster_mode() {
    let app = routes::router(hmac_state(true).await);
    let headers = hmac_headers(now_secs());
    let extra: Vec<(&str, &str)> = headers
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();

    let bare = call(
        &app,
        "GET",
        "/_apis/artifactcache/artifacts/nginx-src-1.30.5",
        None,
        &extra,
        Body::empty(),
    )
    .await;
    assert_eq!(bare.status, StatusCode::FORBIDDEN);

    let signed = call(
        &app,
        "GET",
        &signed_url(FIXTURE_KEY),
        None,
        &extra,
        Body::empty(),
    )
    .await;
    assert_eq!(signed.status, StatusCode::OK);
    assert_eq!(signed.body.as_slice(), FIXTURE_BODY);
}
