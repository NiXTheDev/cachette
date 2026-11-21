//! Full-chain OIDC acceptance tests (v1.1 workstream A; docs/oidc.md is the
//! contract).
//!
//! Drives the same protected-router harness as `tests/auth.rs`, with a LIVE
//! TLS JWKS endpoint (rcgen leaf-as-CA, mirroring `tests/auth_tls.rs`) behind
//! `auth::oidc::install`, so the acceptance chain runs over real wire
//! traffic:
//!
//! * static tokens and registered TokenStore tokens keep winning (attempted
//!   before the OIDC verifier); unknown strings and garbage are 401,
//! * a conformant RS256 token from the configured IdP is accepted end to end,
//! * a `disabled`/absent `[auth.oidc]` table is behaviorally identical to
//!   v1.0 — OIDC-signed tokens are just unknown bearers — and never fetches,
//! * alg-confusion variants (`none`, `HS256`) are rejected, and a
//!   rogue-issuer token never triggers a fetch,
//! * kid rotation resolves through the real HTTP fetch (lazy singleflight),
//! * the default JWKS URL derives from the issuer when no override is set,
//! * the `[auth.oidc]` TOML surface roundtrips through serde.

use std::collections::BTreeMap;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{RSA_PKCS1_SHA256, RsaKeyPair};
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::middleware;
use axum::routing::get;
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use cachette::auth::{self, AuthPolicy, TokenStore};
use cachette::config::{AuthMode, Config, OidcConfig, OidcIssuerConfig};
use cachette::state::AppState;
use hmac::{Hmac, KeyInit, Mac};
use serde::Deserialize;
use serde_json::json;
use sha2::Sha256;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;
use tower::ServiceExt;

const STATIC_TOKEN: &str = "static-token-1";
const STORE_TOKEN: &str = "registered-store-token-1234";
const AUDIENCE: &str = "cachette";
const ROGUE_ISSUER: &str = "https://evil.example.org/rogue";
const RS256_HEADER: &str = r#"{"alg":"RS256","typ":"JWT","kid":"test-key-1"}"#;
const CACHE_PROBE: &str = "/_apis/artifactcache/cache";

/// Throwaway RSA fixture (`tests/fixtures/oidc-rsa.json`): tokens are minted
/// with its private half; the test IdP serves its public JWKS halves. It is
/// never trusted outside the `auth::oidc` unit tests and this file.
const FIXTURE_JSON: &str = include_str!("fixtures/oidc-rsa.json");

#[derive(Deserialize)]
struct RsaFixture {
    pkcs8: String,
    jwks_n: String,
    jwks_e: String,
    kid: String,
}

fn fixture() -> RsaFixture {
    serde_json::from_str(FIXTURE_JSON).expect("fixture parses")
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_secs() as i64
}

fn seg(json: &str) -> String {
    URL_SAFE_NO_PAD.encode(json.as_bytes())
}

/// Mint an RS256 token: PKCS#1 SHA-256 over `header_seg.payload_seg`.
fn sign_rs256(fx: &RsaFixture, header_seg: &str, payload_seg: &str) -> String {
    let der = STANDARD
        .decode(fx.pkcs8.as_bytes())
        .expect("fixture pkcs8 decodes");
    let key_pair = RsaKeyPair::from_pkcs8(&der).expect("pkcs8 loads");
    let mut signature = vec![0; key_pair.public_modulus_len()];
    let signing_input = format!("{header_seg}.{payload_seg}");
    key_pair
        .sign(
            &RSA_PKCS1_SHA256,
            &SystemRandom::new(),
            signing_input.as_bytes(),
            &mut signature,
        )
        .expect("signs");
    format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(&signature))
}

/// Conformant claims at the given mint time (exp +10 min, nbf -10s). Since
/// v1.2 the default `tenant_claim` is `repository`, so every conformant
/// token carries it (a token without it is a structural rejection).
const TENANT: &str = "NiXTheDev/cachette";

fn claims_json(issuer: &str, now: i64) -> String {
    json!({
        "iss": issuer,
        "aud": AUDIENCE,
        "sub": "ci-1",
        "repository": TENANT,
        "exp": now + 600,
        "nbf": now - 10,
    })
    .to_string()
}

fn expired_claims_json(issuer: &str, now: i64) -> String {
    json!({
        "iss": issuer,
        "aud": AUDIENCE,
        "sub": "ci-1",
        "repository": TENANT,
        "exp": now - 6000,
    })
    .to_string()
}

fn aud_claims_json(issuer: &str, now: i64, aud: &str) -> String {
    json!({
        "iss": issuer,
        "aud": aud,
        "sub": "ci-1",
        "repository": TENANT,
        "exp": now + 600,
        "nbf": now - 10,
    })
    .to_string()
}

/// Conformant RS256 fixture token, optionally under a specific kid.
fn oidc_token(fx: &RsaFixture, issuer: &str, kid: Option<&str>, now: i64) -> String {
    let header = match kid {
        Some(kid) => json!({ "alg": "RS256", "typ": "JWT", "kid": kid }).to_string(),
        None => String::from(RS256_HEADER),
    };
    sign_rs256(fx, &seg(&header), &seg(&claims_json(issuer, now)))
}

/// One-hour-stale RS256 token (leeway default is 30s).
fn expired_token(fx: &RsaFixture, issuer: &str, now: i64) -> String {
    sign_rs256(
        fx,
        &seg(RS256_HEADER),
        &seg(&expired_claims_json(issuer, now)),
    )
}

/// RS256 token whose `aud` is another app (claimed-gates coverage).
fn wrong_audience_token(fx: &RsaFixture, issuer: &str, now: i64) -> String {
    sign_rs256(
        fx,
        &seg(RS256_HEADER),
        &seg(&aud_claims_json(issuer, now, "other-app")),
    )
}

/// `alg: none` JOSE token (must die at the alg pin, no key consulted).
fn unsigned_token(issuer: &str, now: i64) -> String {
    let header = r#"{"alg":"none","typ":"JWT","kid":"test-key-1"}"#;
    format!("{}.{}.0", seg(header), seg(&claims_json(issuer, now)),)
}

/// `alg: HS256` JOSE token signed by an attacker-controlled HMAC secret
/// (symmetric-key confusion variant: the RSA material must never be fed).
fn hs256_token(issuer: &str, now: i64) -> String {
    let header = r#"{"alg":"HS256","typ":"JWT","kid":"test-key-1"}"#;
    let signing_input = format!("{}.{}", seg(header), seg(&claims_json(issuer, now)));
    let mut mac = Hmac::<Sha256>::new_from_slice(b"attacker-controlled-secret").expect("hmac key");
    mac.update(signing_input.as_bytes());
    format!(
        "{}.{}",
        signing_input,
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    )
}

/// Self-cleaning unique temp directory (mirrors `tests/auth.rs`).
struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "cachette-oidc-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
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

// ---------------------------------------------------------------------------
// Live TLS JWKS endpoint: self-signed leaf as its own CA (SAN 127.0.0.1),
// serving a mutable JWKS document at any recorded path.
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct ServerState {
    doc: Arc<StdMutex<String>>,
    hits: Arc<AtomicUsize>,
    paths: Arc<StdMutex<Vec<String>>>,
}

struct JwksServer {
    port: u16,
    state: ServerState,
    ca_pem_path: PathBuf,
}

impl JwksServer {
    /// A bare-hosts issuer pointing at the live endpoint; derived default
    /// JWKS URLs therefore target the recorded paths too.
    fn issuer(&self) -> String {
        format!("https://127.0.0.1:{}", self.port)
    }

    fn url(&self, path: &str) -> String {
        format!("https://127.0.0.1:{}{path}", self.port)
    }

    fn hits(&self) -> usize {
        self.state.hits.load(Ordering::SeqCst)
    }

    fn recorded_paths(&self) -> Vec<String> {
        self.state.paths.lock().unwrap().clone()
    }

    /// Swap the served document (the next connection sees it).
    fn set_doc(&self, doc: &str) {
        *self.state.doc.lock().unwrap() = doc.to_owned();
    }

    /// A JWKS doc serving the fixture key under each of `kids`.
    fn doc(&self, kids: &[&str]) -> String {
        let fx = fixture();
        let keys: Vec<_> = kids
            .iter()
            .map(|kid| json!({ "kty": "RSA", "kid": kid, "n": fx.jwks_n, "e": fx.jwks_e }))
            .collect();
        json!({ "keys": keys }).to_string()
    }
}

async fn spawn_jwks_server() -> JwksServer {
    // Leaf-as-CA with an IP SAN: webpki trusts it from the configured
    // bundle, matching the deployment shape with an IdP's own CA.
    let cert = rcgen::generate_simple_self_signed(vec![String::from("127.0.0.1")])
        .expect("test leaf cert");
    let cert_pem = cert.cert.pem();
    let key_pem = cert.signing_key.serialize_pem();

    // The CA bundle flows through a real FILE (install reads from disk).
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "cachette-jwks-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).expect("test dir");
    let ca_pem_path = dir.join("jwks-ca.pem");
    std::fs::write(&ca_pem_path, &cert_pem).expect("ca pem written");

    let mut reader = BufReader::new(key_pem.as_bytes());
    let key = rustls_pemfile::private_key(&mut reader)
        .expect("key parses")
        .expect("key present");
    let mut reader = BufReader::new(cert_pem.as_bytes());
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .expect("certs parse");
    let tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("server config");
    let acceptor = TlsAcceptor::from(Arc::new(tls));

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let port = listener.local_addr().expect("addr").port();

    let state = ServerState {
        doc: Arc::new(StdMutex::new(String::from("{}"))),
        hits: Arc::new(AtomicUsize::new(0)),
        paths: Arc::new(StdMutex::new(Vec::new())),
    };
    // The accept task is simply owned by the runtime; the server struct
    // carries no handle (tests never abort the loop — they just finish).
    tokio::spawn(accept_loop(listener, acceptor, state.clone()));
    JwksServer {
        port,
        state,
        ca_pem_path,
    }
}

/// Accept forever: each connection reads the request head (head-terminated —
/// the client never half-closes), records the path, and answers with
/// `Connection: close` + the currently-served document.
async fn accept_loop(listener: TcpListener, acceptor: TlsAcceptor, state: ServerState) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        let acceptor = acceptor.clone();
        let state = state.clone();
        tokio::spawn(async move {
            let Ok(mut tls) = acceptor.accept(stream).await else {
                return;
            };
            let Some(head) = read_head(&mut tls).await else {
                return;
            };
            let path = head
                .split_whitespace()
                .nth(1)
                .unwrap_or_default()
                .split('?')
                .next()
                .unwrap_or_default()
                .to_owned();
            state.hits.fetch_add(1, Ordering::SeqCst);
            state.paths.lock().unwrap().push(path);
            let body = state.doc.lock().unwrap().clone();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\
                 \r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = tls.write_all(response.as_bytes()).await;
            // Close cleanly (close_notify) like a well-behaved IdP pool.
            let _ = tls.shutdown().await;
            drop(tls);
        });
    }
}

/// Head-terminated server read (the empty line ends the request).
async fn read_head(tls: &mut TlsStream<tokio::net::TcpStream>) -> Option<String> {
    let mut buf = Vec::new();
    let mut scratch = [0u8; 2048];
    loop {
        let read = tls.read(&mut scratch).await.ok()?;
        if read == 0 {
            return None;
        }
        buf.extend_from_slice(&scratch[..read]);
        if buf.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
        if buf.len() > 16 * 1024 {
            return None;
        }
    }
    Some(String::from_utf8_lossy(&buf).into_owned())
}

// ---------------------------------------------------------------------------
// App assembly + request driving (tests/auth.rs harness)
// ---------------------------------------------------------------------------

/// Resolved config: bearer mode with one static token; `fields` shapes the
/// enabled OIDC table (the helper pre-inserts the `/_jwks` override so
/// tests can also clear it for the derived-URL path).
fn config(server: &JwksServer, fields: impl FnOnce(&mut OidcConfig)) -> Config {
    let mut config = Config::default();
    config.auth.mode = AuthMode::Bearer;
    config.auth.tokens = vec![STATIC_TOKEN.to_owned()];
    let mut oidc = OidcConfig {
        enabled: true,
        jwks_ca_pem: Some(server.ca_pem_path.clone()),
        ..OidcConfig::default()
    };
    oidc.issuers.insert(
        server.issuer(),
        OidcIssuerConfig {
            audiences: vec![AUDIENCE.to_owned()],
            jwks_url: Some(server.url("/_jwks")),
            ..OidcIssuerConfig::default()
        },
    );
    fields(&mut oidc);
    config.auth.oidc = Some(oidc);
    config
}

/// Disabled (or absent) `[auth.oidc]` table on the same endpoint; used by
/// the v1.0-parity test to prove no fetch happens either way.
fn disabled_config(server: &JwksServer, present: bool) -> Config {
    let mut config = Config::default();
    config.auth.mode = AuthMode::Bearer;
    config.auth.tokens = vec![STATIC_TOKEN.to_owned()];
    if present {
        let mut oidc = OidcConfig {
            enabled: false,
            jwks_ca_pem: Some(server.ca_pem_path.clone()),
            ..OidcConfig::default()
        };
        oidc.issuers.insert(
            server.issuer(),
            OidcIssuerConfig {
                audiences: vec![AUDIENCE.to_owned()],
                jwks_url: Some(server.url("/_jwks")),
                ..OidcIssuerConfig::default()
            },
        );
        config.auth.oidc = Some(oidc);
    }
    config
}

/// Protected router with one authenticated route plus its state handle; the
/// OIDC verifier is installed through `auth::oidc::install` exactly as
/// `serve()` does.
fn app(config: &Config, root: &Path) -> (Router, AppState) {
    let state = state_with(config, root);
    let router = Router::new()
        .route(CACHE_PROBE, get(|| async { "ok" }))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth::require_auth,
        ))
        .with_state(state.clone());
    (router, state)
}

/// State + token store + auth policy + boot install, mirroring `serve()`.
fn state_with(config: &Config, root: &Path) -> AppState {
    let mut state = AppState::new();
    state.tokens =
        Arc::new(TokenStore::open(&root.join("cachette.sqlite3")).expect("token store opens"));
    state.set_auth(AuthPolicy::from_config(config));
    auth::oidc::install(&state, config).expect("oidc installs");
    state
}

async fn register_store_token(state: &AppState) {
    state
        .tokens
        .register(STORE_TOKEN)
        .await
        .expect("register token");
}

async fn call(router: Router, method: &str, path: &str, headers: &[(&str, &str)]) -> StatusCode {
    let mut builder = Request::builder().uri(path).method(method);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let response = router
        .oneshot(builder.body(Body::empty()).expect("request body"))
        .await
        .expect("router responds");
    response.status()
}

async fn bearer_status(router: &Router, token: &str) -> StatusCode {
    call(
        router.clone(),
        "GET",
        CACHE_PROBE,
        &[("Authorization", &format!("Bearer {token}"))],
    )
    .await
}

/// Poll a token until it reaches `wanted` (the server boot-prefetch or a
/// lazy refresh has to land first) or panic once `timeout` elapses.
async fn eventually(router: &Router, token: &str, wanted: StatusCode, timeout: Duration) {
    let start = Instant::now();
    loop {
        let status = bearer_status(router, token).await;
        if status == wanted {
            return;
        }
        assert!(
            start.elapsed() < timeout,
            "token {token:?} never reached {wanted:?} within {timeout:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Give spawned background work (boot prefetch, lazy refresh) time to drain
/// before reading hit counters.
async fn quiesce() {
    tokio::time::sleep(Duration::from_millis(400)).await;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// The acceptance chain, in order: static token wins, registered store
/// token wins, then a real conformant RS256 token from the live IdP is
/// accepted; unknown strings and structural garbage are 401.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn static_store_then_oidc_chain() {
    let fx = fixture();
    let server = spawn_jwks_server().await;
    server.set_doc(&server.doc(&[fx.kid.as_str()]));
    let root = TestDir::new();
    {
        let (router, state) = app(&config(&server, |_| {}), root.path());
        register_store_token(&state).await;

        // Static token wins before anything OIDC.
        assert_eq!(
            bearer_status(&router, STATIC_TOKEN).await,
            StatusCode::OK,
            "static token must stay accepted"
        );
        // Registered TokenStore token wins before anything OIDC.
        assert_eq!(
            bearer_status(&router, STORE_TOKEN).await,
            StatusCode::OK,
            "registered store token must stay accepted"
        );
        // Conformant RS256 token is accepted through the real Wire chain
        // (boot prefetch over TLS, signature verify, claims gates).
        let token = oidc_token(&fx, &server.issuer(), None, now_secs());
        eventually(&router, &token, StatusCode::OK, Duration::from_secs(6)).await;
        // Unknown bearer strings are still 401.
        assert_eq!(
            bearer_status(&router, "unknown-static-token").await,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            bearer_status(&router, "not-a-token").await,
            StatusCode::UNAUTHORIZED
        );
    } // state + router dropped: the sqlite handle closes before cleanup.
    drop(root);
}

/// A `disabled` or absent `[auth.oidc]` table leaves v1.0 behavior
/// byte-identical — static tokens work, OIDC-signed tokens are just unknown
/// bearers — and never touches the IdP endpoint.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn disabled_or_absent_table_is_v1_behavior_and_never_fetches() {
    let fx = fixture();
    let server = spawn_jwks_server().await;
    server.set_doc(&server.doc(&[fx.kid.as_str()]));

    for present in [false, true] {
        let root = TestDir::new();
        {
            let (router, _state) = app(&disabled_config(&server, present), root.path());
            // Static tokens keep working.
            assert_eq!(bearer_status(&router, STATIC_TOKEN).await, StatusCode::OK);
            // A conformant OIDC token (freshly minted, would verify if OIDC
            // were on) is just an unknown bearer.
            let token = oidc_token(&fx, &server.issuer(), None, now_secs());
            assert_eq!(
                bearer_status(&router, &token).await,
                StatusCode::UNAUTHORIZED
            );
        } // state dropped before cleanup.
        drop(root);
    }
    // Both variants must have had ZERO fetches against the endpoint.
    assert_eq!(
        server.hits(),
        0,
        "an OIDC install must not happen for a disabled/absent table"
    );
}

/// Alg-confusion variants die at the alg pin, and a token issued by a
/// non-configured issuer dies without a single outbound fetch to the
/// (reachable!) endpoint — the `(issuer, kid)` cache never consults an
/// untrusted issuer index.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn alg_confusion_and_rogue_issuer_fail_without_fetching() {
    let fx = fixture();
    let server = spawn_jwks_server().await;
    server.set_doc(&server.doc(&[fx.kid.as_str()]));

    let root = TestDir::new();
    {
        let (router, _state) = app(&config(&server, |_| {}), root.path());

        // Warm: the fixture kid resolves through the boot prefetch.
        let warm = oidc_token(&fx, &server.issuer(), None, now_secs());
        eventually(&router, &warm, StatusCode::OK, Duration::from_secs(6)).await;
        quiesce().await;
        let hits_before = server.hits();

        let now = now_secs();
        // alg: none
        assert_eq!(
            bearer_status(&router, &unsigned_token(&server.issuer(), now)).await,
            StatusCode::UNAUTHORIZED,
            "alg none must die at the pin"
        );
        // alg: HS256 with attacker-chosen secret
        assert_eq!(
            bearer_status(&router, &hs256_token(&server.issuer(), now)).await,
            StatusCode::UNAUTHORIZED,
            "HS256 must die at the pin"
        );
        // RS256 token from a NON-configured issuer (same key, real kid, so
        // the lookup indices are the only untrusted difference).
        let rogue = oidc_token(&fx, ROGUE_ISSUER, Some("test-key-1"), now);
        assert_eq!(
            bearer_status(&router, &rogue).await,
            StatusCode::UNAUTHORIZED,
            "rogue issuer must fail closed"
        );

        // None of the three may have hit the endpoint.
        quiesce().await;
        assert_eq!(
            server.hits(),
            hits_before,
            "confusion variants / rogue issuer must not trigger a fetch"
        );
    } // state dropped before cleanup.
    drop(root);
}

/// Rotation: once the IdP rotates to a new kid, previously-unknown tokens
/// resolve through the real HTTP fetch (the lazy singleflight) while the
/// rotated-away kid stops verifying (replacement semantics).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kid_rotation_resolves_through_http() {
    let fx = fixture();
    let kid_a = fx.kid.clone();
    let server = spawn_jwks_server().await;
    server.set_doc(&server.doc(&[kid_a.as_str()]));

    let root = TestDir::new();
    {
        let (router, _state) = app(&config(&server, |_| {}), root.path());

        // Warm with kid_a.
        let warm = oidc_token(&fx, &server.issuer(), Some(&kid_a), now_secs());
        eventually(&router, &warm, StatusCode::OK, Duration::from_secs(6)).await;
        let warm_hits = server.hits();

        // Rotated: the endpoint now serves only kid_b.
        let kid_b = "rotated-kid-b";
        server.set_doc(&server.doc(&[kid_b]));

        // Before the refresh lands, the kid_b token is rejected...
        let rotated = oidc_token(&fx, &server.issuer(), Some(kid_b), now_secs());
        assert_eq!(
            bearer_status(&router, &rotated).await,
            StatusCode::UNAUTHORIZED,
            "unknown kid must fail closed before the refresh"
        );
        // ... and the lazy singleflight then resolves it through HTTP.
        eventually(&router, &rotated, StatusCode::OK, Duration::from_secs(6)).await;
        assert!(
            server.hits() > warm_hits,
            "the rotation must be resolved by a real fetch"
        );

        // Replacement semantics: the rotated-away kid no longer verifies.
        assert_eq!(
            bearer_status(&router, &warm).await,
            StatusCode::UNAUTHORIZED
        );
    } // state dropped before cleanup.
    drop(root);
}

/// Without a `jwks_urls` override the fetch derives the default
/// `{issuer}/.well-known/jwks.json` — asserted via the recorded request
/// paths on the live endpoint.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn default_jwks_url_derives_from_issuer() {
    let fx = fixture();
    let kid = fx.kid.clone();
    let server = spawn_jwks_server().await;
    server.set_doc(&server.doc(&[kid.as_str()]));

    let root = TestDir::new();
    {
        let (router, _state) = app(
            // Clear the override the helper pre-inserts: the fetch must
            // derive the default URL from the issuer itself.
            &config(&server, |oidc| {
                oidc.issuers
                    .get_mut(&server.issuer())
                    .expect("issuer block")
                    .jwks_url = None;
            }),
            root.path(),
        );

        let warm = oidc_token(&fx, &server.issuer(), None, now_secs());
        eventually(&router, &warm, StatusCode::OK, Duration::from_secs(6)).await;

        assert!(
            server
                .recorded_paths()
                .contains(&String::from("/.well-known/jwks.json")),
            "the default JWKS URL must be derived from the issuer; recorded: {:?}",
            server.recorded_paths()
        );
    } // state dropped before cleanup.
    drop(root);
}

/// A post-signature claims gate rejects: a stale token and a foreign
/// audience both 401 while a conformant token still 200s.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expired_and_wrong_audience_tokens_fail() {
    let fx = fixture();
    let server = spawn_jwks_server().await;
    server.set_doc(&server.doc(&[fx.kid.as_str()]));

    let root = TestDir::new();
    {
        let (router, _state) = app(&config(&server, |_| {}), root.path());

        let now = now_secs();
        let expired = expired_token(&fx, &server.issuer(), now);
        let wrong_aud = wrong_audience_token(&fx, &server.issuer(), now);
        let good = oidc_token(&fx, &server.issuer(), None, now);

        assert_eq!(
            bearer_status(&router, &expired).await,
            StatusCode::UNAUTHORIZED,
            "a 1-hour-stale token must be rejected"
        );
        assert_eq!(
            bearer_status(&router, &wrong_aud).await,
            StatusCode::UNAUTHORIZED,
            "a foreign audience must be rejected"
        );

        // And the good one still unlocks the route.
        eventually(&router, &good, StatusCode::OK, Duration::from_secs(6)).await;
    } // state dropped before cleanup.
    drop(root);
}

/// The `[auth.oidc]` TOML surface roundtrips through serde (v1.2 shape:
/// one block per issuer), and unknown keys are denied (operator-surface
/// guard).
#[test]
fn oidc_toml_surface_roundtrips() {
    let issuer = String::from("https://idp.example.org/realms/ci");
    let oidc = OidcConfig {
        enabled: true,
        jwks_refresh_seconds: 300,
        jwks_max_keys: 64,
        jwks_ca_pem: Some(PathBuf::from("/etc/cachette/idp-ca.pem")),
        issuers: BTreeMap::from([(
            issuer.clone(),
            OidcIssuerConfig {
                audiences: vec![String::from("cachette")],
                jwks_url: Some(String::from("https://idp.example.org/jwks.json")),
                tenant_claim: String::from("repository"),
                require: BTreeMap::from([(String::from("sub"), String::from("ci-"))]),
                leeway_seconds: 90,
                ca_pem: None,
            },
        )]),
        ..OidcConfig::default()
    };

    let rendered = toml::to_string(&oidc).expect("serializes");
    let roundtrip: OidcConfig = toml::from_str(&rendered).expect("parses back");

    assert!(roundtrip.enabled);
    assert_eq!(roundtrip.issuers.keys().collect::<Vec<_>>(), [&issuer]);
    let block = roundtrip.issuers.get(&issuer).expect("issuer block");
    assert_eq!(block.audiences, ["cachette"]);
    assert_eq!(
        block.jwks_url.as_deref(),
        Some("https://idp.example.org/jwks.json")
    );
    assert_eq!(block.require.get("sub").map(String::as_str), Some("ci-"));
    assert_eq!(block.tenant_claim, "repository");
    assert_eq!(block.leeway_seconds, 90);
    assert_eq!(roundtrip.jwks_refresh_seconds, 300);
    assert_eq!(roundtrip.jwks_max_keys, 64);
    assert_eq!(
        roundtrip.jwks_ca_pem.as_deref(),
        Some(Path::new("/etc/cachette/idp-ca.pem"))
    );

    // unknown keys inside an issuer block are rejected, not silently ignored
    assert!(
        toml::from_str::<OidcConfig>(
            "enabled = true\n[auth.oidc.\"https://idp.example.org\"]\nno_such_knob = true"
        )
        .is_err(),
        "unknown per-issuer keys must be denied"
    );
}

/// The v1.1 flat shape does not parse into the v1.2 surface silently: it is
/// kept only so the validation layer can name it.
#[test]
fn the_v11_flat_shape_is_rejected() {
    let flat = r#"
        enabled = true
        issuers = ["https://idp.example.org/realms/ci"]
        audiences = ["cachette"]
    "#;
    let parsed: OidcConfig = toml::from_str(flat).expect("the legacy keys still parse");
    assert!(
        parsed.legacy_issuers.is_some(),
        "the legacy issuer list must be visible to validation"
    );
}
