//! Plan task 23 acceptance: Twirp JSON plumbing + per-mode auth on `/twirp/*`.
//!
//! Drives the full router in-process: the five `CacheService` methods answer
//! JSON, unknown methods get a `404 bad_route` envelope, malformed/mis-typed
//! bodies get `400 invalid_argument`, and the bearer/JWT matrix matches the v1
//! policy (static tokens everywhere, self-minted JWT only in `bearer`/`merge`).

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use cachette::auth::{self, AuthPolicy};
use cachette::config::AuthMode;
use cachette::routes;
use cachette::state::AppState;
use cachette::storage::{ByteStream, MemoryStorage, StorageBackend};
use hmac::{Hmac, KeyInit, Mac};
use serde_json::{Value, json};
use sha2::Sha256;
use tower::ServiceExt;

const SECRET: &str = "test-secret-0123456789abcdef";
const STATIC_TOKEN: &str = "static-token-1";
const REPO: &str = "owner/cachette";
const RUN: &str = "1";
const SERVICE: &str = "/twirp/github.actions.results.api.v1.CacheService";
const FIND: &str = "FindMissingOrStaleCacheEntries";
const CREATE: &str = "CreateCacheEntry";
const HOST: &str = "https://cache.example.com";

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_secs() as i64
}

fn state_with_mode(mode: AuthMode) -> AppState {
    let mut state = AppState::new();
    state.auth = Arc::new(AuthPolicy {
        mode,
        secret: Some(SECRET.to_owned()),
        hmac_max_age_seconds: 600,
        static_tokens: vec![STATIC_TOKEN.to_owned()],
        cluster_enabled: false,
    });
    state
}

/// A merge-mode state with an in-memory backend and a configured external host,
/// so `CreateCacheEntry` can reserve and mint absolute capability URLs.
fn state_with_storage(mode: AuthMode) -> AppState {
    let mut state = state_with_mode(mode);
    state.storage = Some(Arc::new(MemoryStorage::default()));
    state.external_url = Some(String::from(HOST));
    state
}

fn create_body(key: &str, version: &str) -> String {
    format!(r#"{{"key":"{key}","version":"{version}"}}"#)
}

/// Read a `GET` response from the router and return its status and JSON body.
async fn get(router: Router, uri: &str) -> (StatusCode, Value) {
    let response = router
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(uri)
                .body(Body::empty())
                .expect("request body"),
        )
        .await
        .expect("router responds");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("response body");
    let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, value)
}

fn json_ct() -> (String, String) {
    (
        String::from("content-type"),
        String::from("application/json"),
    )
}

fn content_type(value: &str) -> (String, String) {
    (String::from("content-type"), value.to_owned())
}

fn bearer(token: &str) -> (String, String) {
    (String::from("authorization"), format!("Bearer {token}"))
}

fn jwt_bearer() -> (String, String) {
    bearer(&auth::jwt::mint(SECRET, "write", 300, now_secs()))
}

/// Independent MAC (same formula as the Forgejo runner): `hex(HMAC-SHA256(
/// secret, "<repo>><run>><ts>><isolation>"))`.
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

fn forgejo_hmac_headers(ts: i64) -> Vec<(String, String)> {
    let mac = compute_mac(SECRET, REPO, RUN, ts, "");
    vec![
        (String::from("forgejo-cache-repo"), REPO.to_owned()),
        (String::from("forgejo-cache-runnumber"), RUN.to_owned()),
        (String::from("forgejo-cache-timestamp"), ts.to_string()),
        (String::from("forgejo-cache-mac"), mac),
        json_ct(),
    ]
}

async fn call(
    router: Router,
    method_path: &str,
    headers: &[(String, String)],
    body: &str,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method("POST")
        .uri(format!("{SERVICE}/{method_path}"));
    for (name, value) in headers {
        builder = builder.header(name, value);
    }
    let response = router
        .oneshot(
            builder
                .body(Body::from(body.to_owned()))
                .expect("request body"),
        )
        .await
        .expect("router responds");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("response body");
    let value = serde_json::from_slice(&bytes).expect("json response");
    (status, value)
}

#[tokio::test]
async fn find_missing_with_static_token_returns_empty_cache_entries() {
    let app = routes::router(state_with_mode(AuthMode::Merge));
    let headers = [bearer(STATIC_TOKEN), json_ct()];
    let (status, body) = call(app, FIND, &headers, r#"{"keyVersions":[]}"#).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body, json!({"cache_entries": []}));
}

#[tokio::test]
async fn all_five_methods_are_routed() {
    for method in [
        "CreateCacheEntry",
        "FinalizeCacheEntryUpload",
        "SupersedeCacheEntry",
        "GetCacheEntryDownloadURL",
        FIND,
    ] {
        let app = routes::router(state_with_storage(AuthMode::Merge));
        let headers = [bearer(STATIC_TOKEN), json_ct()];
        let (status, body) = call(app, method, &headers, "{}").await;
        assert_ne!(
            status,
            StatusCode::NOT_FOUND,
            "method {method} must be routed, body: {body}"
        );
    }
}

#[tokio::test]
async fn finalize_without_a_published_blob_is_500_not_ok() {
    // A routed-but-unknown finalize is a hard error: it must never answer
    // `ok:true` when the blob is absent (plan task 26).
    let app = routes::router(state_with_storage(AuthMode::Merge));
    let headers = [bearer(STATIC_TOKEN), json_ct()];
    let (status, body) = call(
        app,
        "FinalizeCacheEntryUpload",
        &headers,
        r#"{"key":"ghost-cache","version":"v1"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "body: {body}");
    assert_eq!(body["ok"], json!(false));
}

#[tokio::test]
async fn unknown_method_returns_404_bad_route_envelope() {
    let app = routes::router(state_with_mode(AuthMode::Merge));
    let headers = [bearer(STATIC_TOKEN), json_ct()];
    let (status, body) = call(app, "NoSuchMethod", &headers, "{}").await;
    assert_eq!(status, StatusCode::NOT_FOUND, "body: {body}");
    assert_eq!(body["code"], "bad_route");
    assert!(body["msg"].as_str().is_some(), "body: {body}");
}

#[tokio::test]
async fn text_json_content_type_is_accepted() {
    let app = routes::router(state_with_mode(AuthMode::Merge));
    let headers = [bearer(STATIC_TOKEN), content_type("text/json")];
    let (status, body) = call(app, FIND, &headers, r#"{"keyVersions":[]}"#).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
}

#[tokio::test]
async fn application_json_content_type_is_accepted() {
    let app = routes::router(state_with_mode(AuthMode::Merge));
    let headers = [
        bearer(STATIC_TOKEN),
        content_type("application/json; charset=utf-8"),
    ];
    let (status, body) = call(app, FIND, &headers, r#"{"keyVersions":[]}"#).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
}

#[tokio::test]
async fn missing_content_type_is_accepted() {
    let app = routes::router(state_with_mode(AuthMode::Merge));
    let headers = [bearer(STATIC_TOKEN)];
    let (status, body) = call(app, FIND, &headers, r#"{"keyVersions":[]}"#).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
}

#[tokio::test]
async fn wrong_content_type_returns_400_invalid_argument() {
    let app = routes::router(state_with_mode(AuthMode::Merge));
    let headers = [bearer(STATIC_TOKEN), content_type("application/xml")];
    let (status, body) = call(app, FIND, &headers, r#"{"keyVersions":[]}"#).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(body["code"], "invalid_argument");
}

#[tokio::test]
async fn malformed_json_returns_400_invalid_argument() {
    let app = routes::router(state_with_mode(AuthMode::Merge));
    let headers = [bearer(STATIC_TOKEN), json_ct()];
    let (status, body) = call(app, FIND, &headers, "{not json").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(body["code"], "invalid_argument");
}

#[tokio::test]
async fn unknown_json_fields_are_accepted_and_ignored() {
    let app = routes::router(state_with_mode(AuthMode::Merge));
    let headers = [bearer(STATIC_TOKEN), json_ct()];
    let body = r#"{"keyVersions":[],"request_id":"abc","github_actor_id":7,"nested":{"x":1}}"#;
    let (status, value) = call(app, FIND, &headers, body).await;
    assert_eq!(status, StatusCode::OK, "body: {value}");
    assert_eq!(value, json!({"cache_entries": []}));
}

#[tokio::test]
async fn hmac_mode_accepts_static_token() {
    let app = routes::router(state_with_mode(AuthMode::Hmac));
    let headers = [bearer(STATIC_TOKEN), json_ct()];
    let (status, body) = call(app, FIND, &headers, "{}").await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
}

#[tokio::test]
async fn hmac_mode_rejects_missing_token_with_401_unauthenticated() {
    let app = routes::router(state_with_mode(AuthMode::Hmac));
    let headers = [json_ct()];
    let (status, body) = call(app, FIND, &headers, "{}").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "body: {body}");
    assert_eq!(body["code"], "unauthenticated");
}

#[tokio::test]
async fn hmac_mode_rejects_self_minted_jwt() {
    let app = routes::router(state_with_mode(AuthMode::Hmac));
    let headers = [jwt_bearer(), json_ct()];
    let (status, body) = call(app, FIND, &headers, "{}").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "body: {body}");
    assert_eq!(body["code"], "unauthenticated");
}

#[tokio::test]
async fn hmac_headers_never_authenticate_twirp() {
    let app = routes::router(state_with_mode(AuthMode::Hmac));
    let mut headers = forgejo_hmac_headers(now_secs());
    headers.push(json_ct());
    let (status, body) = call(app, FIND, &headers, "{}").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "body: {body}");
    assert_eq!(body["code"], "unauthenticated");
}

#[tokio::test]
async fn bearer_mode_accepts_static_token_and_jwt() {
    let headers = [bearer(STATIC_TOKEN), json_ct()];
    let (status, body) = call(
        routes::router(state_with_mode(AuthMode::Bearer)),
        FIND,
        &headers,
        "{}",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "static token, body: {body}");

    let headers = [jwt_bearer(), json_ct()];
    let (status, body) = call(
        routes::router(state_with_mode(AuthMode::Bearer)),
        FIND,
        &headers,
        "{}",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "jwt, body: {body}");
}

#[tokio::test]
async fn bearer_mode_rejects_missing_token() {
    let app = routes::router(state_with_mode(AuthMode::Bearer));
    let (status, body) = call(app, FIND, &[json_ct()], "{}").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "body: {body}");
}

#[tokio::test]
async fn merge_mode_accepts_static_token_and_jwt() {
    let headers = [bearer(STATIC_TOKEN), json_ct()];
    let (status, body) = call(
        routes::router(state_with_mode(AuthMode::Merge)),
        FIND,
        &headers,
        "{}",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "static token, body: {body}");

    let headers = [jwt_bearer(), json_ct()];
    let (status, body) = call(
        routes::router(state_with_mode(AuthMode::Merge)),
        FIND,
        &headers,
        "{}",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "jwt, body: {body}");
}

#[tokio::test]
async fn unknown_twirp_path_still_returns_twirp_not_found_envelope() {
    let app = routes::router(state_with_mode(AuthMode::Merge));
    let mut builder = Request::builder()
        .method("POST")
        .uri("/twirp/github.actions.results.api.v1.OtherService/Ping");
    builder = builder.header("authorization", format!("Bearer {STATIC_TOKEN}"));
    builder = builder.header("content-type", "application/json");
    let response = app
        .oneshot(builder.body(Body::from("{}")).expect("request body"))
        .await
        .expect("router responds");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("response body");
    let value: Value = serde_json::from_slice(&bytes).expect("json response");
    assert_eq!(value["code"], "not_found");
}

#[tokio::test]
async fn create_cache_entry_returns_two_capability_urls_on_the_configured_host() {
    let app = routes::router(state_with_storage(AuthMode::Merge));
    let headers = [bearer(STATIC_TOKEN), json_ct()];
    let (status, body) = call(app, CREATE, &headers, &create_body("build-cache", "v1")).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["ok"], json!(true));

    let cache_id = body["cache_id"].as_str().expect("cache_id present");
    assert_eq!(cache_id.len(), 32, "cache_id is 32 hex chars: {cache_id}");
    let upload = body["signed_upload_url"]
        .as_str()
        .expect("signed_upload_url");
    let download = body["signed_download_url"]
        .as_str()
        .expect("signed_download_url");
    assert!(
        upload.starts_with("https://cache.example.com/v2/upload/"),
        "{upload}"
    );
    assert!(
        download.starts_with("https://cache.example.com/v2/artifacts/"),
        "{download}"
    );
    assert!(
        upload.contains(&format!("/v2/upload/{cache_id}?")),
        "{upload}"
    );
    assert!(
        download.contains(&format!("/v2/artifacts/{cache_id}?")),
        "{download}"
    );
    for url in [upload, download] {
        assert!(url.contains(&format!("id={cache_id}")), "id missing: {url}");
        assert!(url.contains("&exp="), "exp missing: {url}");
        assert!(url.contains("&mac="), "mac missing: {url}");
        assert!(!url.contains(SECRET), "secret leaked into URL: {url}");
    }
}

#[tokio::test]
async fn create_cache_entry_open_reservation_is_a_duplicate_without_upload_url() {
    let state = state_with_storage(AuthMode::Merge);
    let headers = [bearer(STATIC_TOKEN), json_ct()];
    let body = create_body("dup-cache", "v1");

    let (status, first) = call(routes::router(state.clone()), CREATE, &headers, &body).await;
    assert_eq!(status, StatusCode::OK, "body: {first}");
    assert_eq!(first["ok"], json!(true));

    let (status, second) = call(routes::router(state), CREATE, &headers, &body).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "duplicate is 200, not 400: {second}"
    );
    assert_eq!(second["ok"], json!(false));
    assert_eq!(second["otherFields"]["duplicateKey"], json!(true));
    assert!(
        second["reason"]
            .as_str()
            .is_some_and(|reason| !reason.is_empty()),
        "reason present: {second}"
    );
    assert!(
        second.get("signed_upload_url").is_none(),
        "duplicate must not carry an upload URL: {second}"
    );
    assert!(
        second.get("signed_download_url").is_none(),
        "no download URL: {second}"
    );
}

#[tokio::test]
async fn create_cache_entry_complete_entry_is_a_duplicate() {
    let storage = Arc::new(MemoryStorage::new());
    let stream: ByteStream<'static> = Box::pin(std::io::Cursor::new(b"data".to_vec()));
    storage
        .put_stream("done-cache", stream)
        .await
        .expect("seed put");
    storage.finalize("done-cache").await.expect("seed finalize");

    let mut state = state_with_mode(AuthMode::Merge);
    state.storage = Some(storage);
    state.external_url = Some(String::from(HOST));
    let headers = [bearer(STATIC_TOKEN), json_ct()];
    let (status, body) = call(
        routes::router(state),
        CREATE,
        &headers,
        &create_body("done-cache", "v1"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["ok"], json!(false));
    assert_eq!(body["otherFields"]["duplicateKey"], json!(true));
}

#[tokio::test]
async fn create_cache_entry_signed_download_url_404s_before_content() {
    let app = routes::router(state_with_storage(AuthMode::Merge));
    let headers = [bearer(STATIC_TOKEN), json_ct()];
    let (_, body) = call(
        app.clone(),
        CREATE,
        &headers,
        &create_body("pending-cache", "v1"),
    )
    .await;
    let download = body["signed_download_url"]
        .as_str()
        .expect("signed_download_url present");
    let path_and_query = download.strip_prefix(HOST).expect("URL uses the host");
    assert!(path_and_query.starts_with("/v2/artifacts/"), "{download}");

    let (status, _) = get(app, path_and_query).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "nothing uploaded yet, so the artifact path 404s"
    );
}

#[tokio::test]
async fn create_cache_entry_ignores_unknown_fields() {
    let app = routes::router(state_with_storage(AuthMode::Merge));
    let headers = [bearer(STATIC_TOKEN), json_ct()];
    let body = concat!(
        r#"{"key":"extra-cache","version":"v1","scope":"refs/heads/main","#,
        r#""metadata":{"repository_id":7,"scope":"refs/heads/main"},"#,
        r#""request_id":"abc","github_actor_id":9}"#,
    );
    let (status, value) = call(app, CREATE, &headers, body).await;
    assert_eq!(status, StatusCode::OK, "body: {value}");
    assert_eq!(value["ok"], json!(true));
    assert!(
        value["signed_upload_url"].as_str().is_some(),
        "body: {value}"
    );
}
