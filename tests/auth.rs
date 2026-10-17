//! Plan task 15 acceptance: per-request auth modes (hmac | bearer | merge)
//! and admin token register/revoke.
//!
//! Drives an in-process axum router (pattern from `tests/tls_peers.rs`):
//! (a) a correct Forgejo HMAC is accepted,
//! (b) a stale HMAC (> `hmac_max_age_seconds`) is rejected with 401,
//! (c) a future timestamp is rejected with 401,
//! (d) a correct static bearer token is accepted,
//! (e) a wrong token with no MAC is rejected with 401,
//! (f) `/_internal/register` mints a live token and `/_internal/revoke`
//!     makes it 401 again.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::middleware;
use axum::routing::get;
use cachette::auth::{self, AuthPolicy, TokenStore};
use cachette::config::AuthMode;
use cachette::routes;
use cachette::state::AppState;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use tower::ServiceExt;

const SECRET: &str = "test-secret-0123456789abcdef";
const REPO: &str = "owner/cachette";
const RUN: &str = "1";
const ISOLATION: &str = "";
const STATIC_TOKEN: &str = "static-token-1";

/// Self-cleaning unique temp directory (mirrors `tests/tls_peers.rs`).
struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let unique = format!(
            "cachette-auth-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let path = std::env::temp_dir().join(unique);
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

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_secs() as i64
}

/// Independent MAC computation (same formula as the Forgejo runner's
/// `mac.go`): `hex(HMAC-SHA256(secret, "<repo>><run>><ts>><isolation>"))`.
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

fn state_with(root: &Path) -> AppState {
    let mut state = AppState::new();
    state.tokens =
        Arc::new(TokenStore::open(&root.join("cachette.sqlite3")).expect("token store opens"));
    state.set_auth(AuthPolicy {
        mode: AuthMode::Merge,
        secret: Some(SECRET.to_owned()),
        hmac_max_age_seconds: 600,
        static_tokens: vec![STATIC_TOKEN.to_owned()],
        cluster_enabled: false,
    });
    state
}

/// Router with one real artifactcache route behind the auth gate.
fn protected_router(state: AppState) -> Router {
    Router::new()
        .route("/_apis/artifactcache/cache", get(|| async { "ok" }))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth::require_auth,
        ))
        .with_state(state)
}

async fn call(
    router: Router,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
) -> (StatusCode, String) {
    let mut builder = Request::builder().uri(path).method(method);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let response = router
        .oneshot(builder.body(Body::empty()).expect("request body"))
        .await
        .expect("router responds");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("response body");
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

/// Timestamp + MAC strings for a valid HMAC header set.
fn hmac_headers(ts: i64) -> (String, String) {
    (
        ts.to_string(),
        compute_mac(SECRET, REPO, RUN, ts, ISOLATION),
    )
}

#[tokio::test]
async fn valid_hmac_is_accepted() {
    let root = TestDir::new();
    let app = protected_router(state_with(root.path()));
    let (ts, mac) = hmac_headers(now_secs());
    let headers = [
        ("forgejo-cache-repo", REPO),
        ("forgejo-cache-runnumber", RUN),
        ("forgejo-cache-timestamp", ts.as_str()),
        ("forgejo-cache-mac", mac.as_str()),
    ];
    let (status, body) = call(app, "GET", "/_apis/artifactcache/cache", &headers).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
}

#[tokio::test]
async fn stale_hmac_is_rejected() {
    let root = TestDir::new();
    let app = protected_router(state_with(root.path()));
    let (ts, mac) = hmac_headers(now_secs() - 601);
    let headers = [
        ("forgejo-cache-repo", REPO),
        ("forgejo-cache-runnumber", RUN),
        ("forgejo-cache-timestamp", ts.as_str()),
        ("forgejo-cache-mac", mac.as_str()),
    ];
    let (status, body) = call(app, "GET", "/_apis/artifactcache/cache", &headers).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "body: {body}");
    assert!(body.contains("authentication required"), "body: {body}");
}

#[tokio::test]
async fn future_timestamp_is_rejected() {
    let root = TestDir::new();
    let app = protected_router(state_with(root.path()));
    let (ts, mac) = hmac_headers(now_secs() + 60);
    let headers = [
        ("forgejo-cache-repo", REPO),
        ("forgejo-cache-runnumber", RUN),
        ("forgejo-cache-timestamp", ts.as_str()),
        ("forgejo-cache-mac", mac.as_str()),
    ];
    let (status, body) = call(app, "GET", "/_apis/artifactcache/cache", &headers).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "body: {body}");
}

#[tokio::test]
async fn valid_static_bearer_token_is_accepted() {
    let root = TestDir::new();
    let app = protected_router(state_with(root.path()));
    let headers = [("authorization", "Bearer static-token-1")];
    let (status, body) = call(app, "GET", "/_apis/artifactcache/cache", &headers).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
}

#[tokio::test]
async fn wrong_token_without_mac_is_rejected() {
    let root = TestDir::new();
    let app = protected_router(state_with(root.path()));
    let headers = [("authorization", "Bearer wrong-token")];
    let (status, body) = call(app, "GET", "/_apis/artifactcache/cache", &headers).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "body: {body}");
    assert!(body.contains("authentication required"), "body: {body}");
}

#[tokio::test]
async fn register_then_revoke_controls_bearer_access() {
    let root = TestDir::new();
    let state = state_with(root.path());
    let app = routes::router(state.clone());
    let admin = [("authorization", "Bearer test-secret-0123456789abcdef")];
    let token = "dyn-token-abc123";

    let (status, body) = call(
        app.clone(),
        "POST",
        &format!("/_internal/register?token={token}"),
        &admin,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");

    let protected = protected_router(state.clone());
    let headers = [("authorization", "Bearer dyn-token-abc123")];
    let (status, body) = call(
        protected.clone(),
        "GET",
        "/_apis/artifactcache/cache",
        &headers,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");

    let (status, body) = call(
        app,
        "POST",
        &format!("/_internal/revoke?token={token}"),
        &admin,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");

    let (status, body) = call(protected, "GET", "/_apis/artifactcache/cache", &headers).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "body: {body}");
}

#[tokio::test]
async fn register_requires_admin_auth() {
    let root = TestDir::new();
    let state = state_with(root.path());
    let app = routes::router(state);
    let (status, body) = call(app, "POST", "/_internal/register?token=no-admin", &[]).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "body: {body}");
    assert!(body.contains("authentication required"), "body: {body}");
}
