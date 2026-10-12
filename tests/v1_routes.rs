//! Plan task 18 acceptance: the v1 artifactcache **status-code contract**
//! (criterion 1), driven in-process through the real router (pattern from
//! `tests/auth.rs`). A fixture entry is seeded straight into `MemoryStorage`
//! because the skeleton reserves/stages (invisible) but does not finalize
//! until plan task 21.
//!
//! Covered: find hit 200 (signed `archiveLocation`), find miss 204-empty,
//! reserve 200, duplicate reserve 409 (GitHub exception body), PATCH 204,
//! commit 204, download 200 full, download 206 slice + `Content-Range`,
//! clean 200, unknown route 404 JSON, wrong method 405 JSON, auth 401, and
//! download-of-unknown 404.

use std::io::Cursor;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode, header};
use cachette::auth::AuthPolicy;
use cachette::config::AuthMode;
use cachette::routes;
use cachette::state::AppState;
use cachette::storage::{ByteStream, MemoryStorage, StorageBackend};
use tower::ServiceExt;

const SECRET: &str = "test-secret-0123456789abcdef";
const TOKEN: &str = "v1-test-token";
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
    let cache_id = body["cacheId"].as_str().expect("cacheId string");
    assert_eq!(cache_id.len(), 32, "cacheId: {cache_id}");
    assert!(
        cache_id.chars().all(|c| c.is_ascii_hexdigit()),
        "cacheId not hex: {cache_id}"
    );
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
    let app = routes::router(fixture_state().await);
    let reply = call(
        &app,
        "PATCH",
        "/_apis/artifactcache/caches/deadbeef",
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
    let app = routes::router(fixture_state().await);
    let reply = call(
        &app,
        "POST",
        "/_apis/artifactcache/caches/deadbeef",
        Some(TOKEN),
        &[("content-type", "application/json")],
        json_body(serde_json::json!({"size": 512})),
    )
    .await;
    assert_eq!(reply.status, StatusCode::NO_CONTENT);
    assert!(reply.body.is_empty(), "204 must carry an empty body");
}

#[tokio::test]
async fn download_without_range_returns_200_full_body() {
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
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.body.as_slice(), FIXTURE_BODY);
}

#[tokio::test]
async fn download_with_range_returns_206_slice_and_content_range() {
    let app = routes::router(fixture_state().await);
    let reply = call(
        &app,
        "GET",
        "/_apis/artifactcache/artifacts/nginx-src-1.30.5",
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
        "/_apis/artifactcache/artifacts/missing",
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
