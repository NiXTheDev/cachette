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
//!     makes it 401 again,
//! (g) a self-minted JWT verifies by signature — no `[auth] tokens` entry.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::middleware;
use axum::routing::get;
use axum::{Extension, Router};
use cachette::auth::{self, AuthPolicy, TokenStore};
use cachette::config::{AuthMode, Config, RuntimeForgeConfig};
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
        forge_hmac_secrets: Vec::new(),
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

/// `Authorization: Bearer <token>` pair as owned strings, for the minted-JWT
/// tests (`call` borrows `(name, value)` pairs of `&str`).
fn bearer_header(token: String) -> String {
    format!("Bearer {token}")
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
async fn self_minted_jwt_is_accepted_without_static_registration() {
    // The mint CLI signs `buildx-jwt` with `[auth].secret` and the server
    // holds that key, so the signature alone authorizes the v1 gate: no
    // listing in `[auth] tokens`, no TokenStore registration.
    let root = TestDir::new();
    let app = protected_router(state_with(root.path()));
    let bearer = bearer_header(cachette::auth::jwt::mint(SECRET, "[]", 300, now_secs()));
    let headers = [("authorization", bearer.as_str())];
    let (status, body) = call(app, "GET", "/_apis/artifactcache/cache", &headers).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
}

#[tokio::test]
async fn expired_self_minted_jwt_is_rejected() {
    let root = TestDir::new();
    let app = protected_router(state_with(root.path()));
    // Claims minted 400s ago with a 300s TTL put `exp` 100s in the past;
    // the gate's own `validate` catches the expiry.
    let bearer = bearer_header(cachette::auth::jwt::mint(
        SECRET,
        "[]",
        300,
        now_secs() - 400,
    ));
    let headers = [("authorization", bearer.as_str())];
    let (status, body) = call(app, "GET", "/_apis/artifactcache/cache", &headers).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "body: {body}");
}

#[tokio::test]
async fn jwt_signed_by_a_foreign_secret_is_rejected() {
    // Same shape, same claims, different key: this is the token class that
    // still needs an explicit `[auth] tokens` listing to work.
    let root = TestDir::new();
    let app = protected_router(state_with(root.path()));
    let bearer = bearer_header(cachette::auth::jwt::mint(
        "not-the-server-secret-0123456",
        "[]",
        300,
        now_secs(),
    ));
    let headers = [("authorization", bearer.as_str())];
    let (status, body) = call(app, "GET", "/_apis/artifactcache/cache", &headers).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "body: {body}");
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

/// Mint an HS256 runtime token (the shape a forge signs with its general
/// token signing secret).
fn mint_runtime_token(secret: &str, claims: &str) -> String {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
    let payload = URL_SAFE_NO_PAD.encode(claims.as_bytes());
    let signing_input = format!("{header}.{payload}");
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("hmac key");
    mac.update(signing_input.as_bytes());
    format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    )
}

/// v1.2 Plane B (`docs/shared-cache.md` §3): the boot installer reads each
/// enabled forge's signing-secret file, and a runtime token accepted by the
/// shared bearer chain resolves — through the real `require_auth` gate — to
/// `"<forge>|<tenant>"`. A token signed by another key stays unauthorized,
/// and an enabled block whose secret cannot be read is boot-fatal.
#[tokio::test]
async fn runtime_token_yields_its_forge_namespace() {
    let root = TestDir::new();
    let secret_path = root.path().join("forge-token-secret");
    std::fs::write(&secret_path, "forge-signing-secret\n").expect("secret file");

    let mut config = Config::default();
    config.auth.mode = AuthMode::Bearer;
    config.auth.runtime.insert(
        String::from("https://forge.example.org"),
        RuntimeForgeConfig {
            enabled: true,
            secret: secret_path,
            ..RuntimeForgeConfig::default()
        },
    );

    let state = AppState::new();
    state.set_auth(AuthPolicy::from_config(&config));
    cachette::auth::runtime::install(&state, &config).expect("runtime installs");
    assert!(
        state.runtime().is_some(),
        "boot install hangs the verifier on the state"
    );

    // Echo the namespace the gate inserted: the middleware path is the one
    // production requests take.
    let app = Router::new()
        .route(
            "/_apis/artifactcache/cache",
            get(|Extension(namespace): Extension<auth::Namespace>| async move { namespace.0 }),
        )
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth::require_auth,
        ))
        .with_state(state);

    let now = now_secs();
    let claims = format!(
        r#"{{"exp":{},"nbf":{},"scp":"repo:owner/cachette write:actions","oidc_extra":{{"repository":"owner/cachette"}}}}"#,
        now + 600,
        now - 10
    );
    let token = mint_runtime_token("forge-signing-secret", &claims);
    let bearer = bearer_header(token);
    let (status, body) = call(
        app.clone(),
        "GET",
        "/_apis/artifactcache/cache",
        &[("authorization", bearer.as_str())],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body, "https://forge.example.org|owner/cachette");

    // Same claims, foreign key: not this forge's credential.
    let foreign = bearer_header(mint_runtime_token("some-other-secret", &claims));
    let (status, body) = call(
        app,
        "GET",
        "/_apis/artifactcache/cache",
        &[("authorization", foreign.as_str())],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "body: {body}");

    // Enabled block with an unreadable secret file: boot-fatal.
    let mut broken = config;
    broken
        .auth
        .runtime
        .get_mut("https://forge.example.org")
        .expect("runtime block")
        .secret = root.path().join("absent-secret");
    let state = AppState::new();
    assert!(
        cachette::auth::runtime::install(&state, &broken).is_err(),
        "an unreadable signing secret must fail the boot"
    );
}
