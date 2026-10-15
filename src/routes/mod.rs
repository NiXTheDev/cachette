//! HTTP route table (plan task 3 skeleton: `/health` + JSON 404 fallback).
//!
//! `/_internal/peers/*` (plan task 14) is the first pin-gated route group:
//! every request there must carry a peer certificate whose SPKI fingerprint is
//! pinned. Plan task 31 adds the relay endpoints to that group
//! (`reserve`/`upload`/`commit`, handled by [`peer_relay`]), which receive a v1
//! upload forwarded from the entry node. `/_internal/register` + `/_internal/revoke` (plan task 15) are the
//! admin token routes: `Authorization: Bearer <auth.secret>`, or loopback-only
//! when `[cluster] enabled` is false. The `/_apis/artifactcache/*` group is
//! auth-gated by a path-scoped layer (plan task 15) and served by the v1
//! handlers in [`v1`] (plan task 18). The Twirp v2 group (`/twirp/...`, plan
//! task 23) is served by [`twirp`], which enforces its own bearer/JWT policy.
//! Public routes and the 404/405 fallbacks never require a client cert.

mod health;
mod peer_relay;
mod twirp;
mod v1;
mod v2_download;
mod v2_upload;

use std::sync::Arc;

use axum::Json;
use axum::Router;
use axum::extract::{ConnectInfo, Query, Request, State};
use axum::http::{Uri, request::Parts};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, patch, post, put};

use crate::auth;
use crate::error::ApiError;
use crate::state::AppState;
use crate::tls::{PeerCert, PeerPins};

/// Build the application router: `GET /health`, the pin-gated peer group, the
/// admin token routes, the auth-gated v1 artifactcache routes, and JSON
/// 404/405 fallbacks.
pub fn router(state: AppState) -> Router {
    let peer_routes = Router::new()
        .route("/_internal/peers/hello", post(peer_hello))
        .route("/_internal/peers/heartbeat", post(peer_heartbeat))
        .route("/_internal/peers", get(peer_list))
        .route("/_internal/peers/reserve", post(peer_relay::reserve))
        .route("/_internal/peers/upload/{cacheId}", put(peer_relay::upload))
        .route(
            "/_internal/peers/commit/{cacheId}",
            post(peer_relay::commit),
        )
        .route("/_internal/peers/find", get(peer_relay::find))
        .route("/_internal/peers/v2/reserve", post(peer_relay::v2_reserve))
        .route(
            "/_internal/peers/v2/finalize",
            post(peer_relay::v2_finalize),
        )
        .route(
            "/_internal/peers/v2/supersede",
            post(peer_relay::v2_supersede),
        )
        .route_layer(middleware::from_fn_with_state(
            state.peers.clone(),
            require_pinned_peer,
        ));
    let admin_routes = Router::new()
        .route("/_internal/register", post(register_token))
        .route("/_internal/revoke", post(revoke_token));
    let v1_routes = Router::new()
        .route("/_apis/artifactcache/cache", get(v1::find))
        .route("/_apis/artifactcache/caches", post(v1::reserve))
        .route("/_apis/artifactcache/caches/clean", post(v1::clean))
        .route(
            "/_apis/artifactcache/caches/{cacheId}",
            patch(v1::patch_chunk).post(v1::commit),
        )
        .route(
            "/_apis/artifactcache/artifacts/{cacheId}",
            get(v1::download),
        );
    let twirp_routes = Router::new().route(
        "/twirp/github.actions.results.api.v1.CacheService/{method}",
        post(twirp::dispatch),
    );
    let v2_routes = Router::new()
        .route("/v2/upload/{entryId}", put(v2_upload::upload))
        .route("/v2/artifacts/{entryId}", get(v2_download::download));
    Router::new()
        .route("/health", get(health::health))
        .merge(peer_routes)
        .merge(admin_routes)
        .merge(v1_routes)
        .merge(twirp_routes)
        .merge(v2_routes)
        .with_state(state.clone())
        .fallback(fallback_404)
        .method_not_allowed_fallback(fallback_405)
        .layer(middleware::from_fn_with_state(state, auth::require_auth))
}

/// HMAC secret for v2 capability URLs (task 24 mints, tasks 25/26 validate).
/// Both sides MUST agree, so the fallback for a secretless boot lives here:
/// when `[auth] secret` is unset the fixed placeholder is used (tests /
/// `--print-config` boots); production always serves with a real secret.
pub(crate) const FALLBACK_SIGNING_SECRET: &str = "cachette-v2-route";

/// Resolve the signing secret for a v2 capability URL.
pub(crate) fn signing_secret(state: &AppState) -> &str {
    state
        .auth
        .secret
        .as_deref()
        .unwrap_or(FALLBACK_SIGNING_SECRET)
}

/// Runner-visible base URL of a remote owner B (plan task 32 / M12): B's
/// configured `[server] external_url` when it reported one, else its dial
/// address (`advertise_addr`) under the same `http://` scheme the config
/// resolver uses for `external_url`. Trailing slashes are trimmed so
/// `base + path` is exact. A's capability URLs must host B, never A — the
/// runner talks to the owner directly.
pub(crate) fn owner_base_url(external_url: Option<&str>, addr: &str) -> String {
    match external_url.map(str::trim).filter(|url| !url.is_empty()) {
        Some(url) => url.trim_end_matches('/').to_owned(),
        None => format!("http://{addr}"),
    }
}

fn client_fingerprint(parts: &Parts) -> Option<String> {
    parts
        .extensions
        .get::<ConnectInfo<PeerCert>>()
        .and_then(|info| info.0.fingerprint.clone())
}

/// `POST /_internal/peers/hello` — cluster hello (plan task 28 / M5).
///
/// The caller (a pinned peer) reports its identity; the responder refreshes
/// the peer's `last_hello`, folds the identity into any pre-existing seed or
/// mDNS record, and answers with its own `{node_id, fingerprint}` so the
/// caller can learn it in turn. The body is optional: a pinned peer that sends
/// no body still identifies itself through its client-certificate fingerprint.
async fn peer_hello(State(state): State<AppState>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let cert_fingerprint = client_fingerprint(&parts);
    let bytes = match axum::body::to_bytes(body, 4096).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return ApiError::BadRequest(String::from("hello body too large")).into_response();
        }
    };
    let hello: Option<HelloBody> = if bytes.is_empty() {
        None
    } else {
        match serde_json::from_slice(&bytes) {
            Ok(hello) => Some(hello),
            Err(_) => {
                return ApiError::BadRequest(String::from("invalid hello body")).into_response();
            }
        }
    };
    let fingerprint = hello
        .as_ref()
        .and_then(|hello| hello.fingerprint.clone())
        .or(cert_fingerprint);
    if let Some(fingerprint) = fingerprint {
        let node_id = hello
            .as_ref()
            .and_then(|hello| hello.node_id.clone())
            .unwrap_or_else(|| fingerprint.clone());
        let addr = hello
            .as_ref()
            .and_then(|hello| hello.addr.clone())
            .unwrap_or_default();
        state
            .peer_table
            .hello(&node_id, &fingerprint, &addr, auth::now_secs() as u64);
    }
    // The responder's own identity (M5/M13: hello returns {node_id,
    // fingerprint}); `state.node_id` is the Ed25519 fingerprint at serve time.
    Json(serde_json::json!({
        "accepted": true,
        "node_id": state.node_id,
        "fingerprint": state.node_id,
    }))
    .into_response()
}

/// Allowed clock skew for an inbound heartbeat timestamp (plan task 29: a
/// heartbeat outside ±10s must not count into freshness).
const HEARTBEAT_SKEW_SECS: u64 = 10;

/// `POST /_internal/peers/heartbeat` — freshness + capacity refresh (plan
/// task 29 / M15).
///
/// A pinned peer posts its live B3 stats every `heartbeat_interval_seconds`.
/// The body's `ts` must sit within ±[`HEARTBEAT_SKEW_SECS`] of this node's
/// clock: a stale (or future) timestamp is ignored — it must not refresh
/// `last_hello` — and the response reports `accepted: false`. The identity
/// falls back to the client-certificate fingerprint, exactly like hello.
async fn peer_heartbeat(State(state): State<AppState>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let fingerprint = client_fingerprint(&parts).unwrap_or_default();
    let bytes = match axum::body::to_bytes(body, 4096).await {
        Ok(bytes) => bytes,
        Err(_) => return ApiError::BadRequest(String::from("body too large")).into_response(),
    };
    let beat: HeartbeatBody = match serde_json::from_slice(&bytes) {
        Ok(beat) => beat,
        Err(_) => {
            return ApiError::BadRequest(String::from("invalid heartbeat body")).into_response();
        }
    };
    let now = auth::now_secs();
    let node_id = beat.node_id.unwrap_or_else(|| fingerprint.clone());
    // Wrapping arithmetic so a pathological `ts` (i64::MIN/MAX) cannot
    // overflow-panic the skew check; only the magnitude matters.
    if now.wrapping_sub(beat.ts).unsigned_abs() > HEARTBEAT_SKEW_SECS {
        tracing::debug!(node_id = %node_id, ts = beat.ts, now, "stale heartbeat ts ignored");
        return Json(serde_json::json!({ "accepted": false })).into_response();
    }
    let table = &state.peer_table;
    table.heartbeat(
        &node_id,
        &fingerprint,
        beat.used_bytes,
        beat.total_bytes,
        now as u64,
    );
    Json(serde_json::json!({ "accepted": true })).into_response()
}

/// `GET /_internal/peers` — debug peer list (plan task 28, criterion 7).
///
/// Every peer record with its identity, address, capacity stats, and health.
async fn peer_list(State(state): State<AppState>) -> Json<serde_json::Value> {
    let peers: Vec<serde_json::Value> = state
        .peer_table
        .snapshot()
        .iter()
        .map(|peer| {
            serde_json::json!({
                "node_id": peer.node_id,
                "fingerprint": peer.fingerprint,
                "addr": peer.addr,
                "used_bytes": peer.used_bytes,
                "total_bytes": peer.total_bytes,
                "healthy": peer.healthy,
                "last_hello": peer.last_hello,
            })
        })
        .collect();
    Json(serde_json::json!({ "peers": peers }))
}

/// Optional hello body: the caller's identity (and, when known, its dial
/// address). The certificate fingerprint is the fallback identity.
#[derive(serde::Deserialize)]
struct HelloBody {
    node_id: Option<String>,
    fingerprint: Option<String>,
    addr: Option<String>,
}

/// Heartbeat body: the sender's identity plus its live B3 stats and a Unix
/// seconds timestamp checked against this node's clock (±10s).
#[derive(serde::Deserialize)]
struct HeartbeatBody {
    node_id: Option<String>,
    used_bytes: u64,
    total_bytes: u64,
    ts: i64,
}

/// Query parameter for the admin token routes: `?token=<token>`.
#[derive(serde::Deserialize)]
struct TokenParams {
    token: Option<String>,
}

/// `POST /_internal/register?token=<token>` — mint a dynamic bearer token.
/// Idempotent: re-registering an existing token is a no-op.
async fn register_token(
    State(state): State<AppState>,
    Query(params): Query<TokenParams>,
    request: Request,
) -> Response {
    if !admin_authorized(&state, &request) {
        return ApiError::Unauthorized(String::from("authentication required")).into_response();
    }
    let Some(token) = params.token.filter(|token| !token.is_empty()) else {
        return ApiError::BadRequest(String::from("token query parameter is required"))
            .into_response();
    };
    match state.tokens.register(&token).await {
        Ok(()) => Json(serde_json::json!({"ok": true})).into_response(),
        Err(err) => {
            tracing::error!(error = %err, "token register failed");
            ApiError::Internal.into_response()
        }
    }
}

/// `POST /_internal/revoke?token=<token>` — revoke a dynamic bearer token.
/// Revoking an unknown token is a no-op.
async fn revoke_token(
    State(state): State<AppState>,
    Query(params): Query<TokenParams>,
    request: Request,
) -> Response {
    if !admin_authorized(&state, &request) {
        return ApiError::Unauthorized(String::from("authentication required")).into_response();
    }
    let Some(token) = params.token.filter(|token| !token.is_empty()) else {
        return ApiError::BadRequest(String::from("token query parameter is required"))
            .into_response();
    };
    match state.tokens.revoke(&token).await {
        Ok(()) => Json(serde_json::json!({"ok": true})).into_response(),
        Err(err) => {
            tracing::error!(error = %err, "token revoke failed");
            ApiError::Internal.into_response()
        }
    }
}

/// Admin gate for the token routes: `Authorization: Bearer <auth.secret>`, or
/// loopback-only when `[cluster] enabled` is false (standalone node).
fn admin_authorized(state: &AppState, request: &Request) -> bool {
    let secret_ok = match (
        state.auth.secret.as_deref(),
        auth::bearer_token(request.headers()),
    ) {
        (Some(secret), Some(token)) => auth::constant_time_eq(token.as_bytes(), secret.as_bytes()),
        _ => false,
    };
    if secret_ok {
        return true;
    }
    match request.extensions().get::<ConnectInfo<PeerCert>>() {
        Some(ConnectInfo(peer)) => !state.auth.cluster_enabled && peer.remote.ip().is_loopback(),
        None => false,
    }
}

/// Pin gate for `/_internal/peers/*`.
///
/// Accepts only when the connection presented a client certificate whose SPKI
/// fingerprint is pinned (`[cluster] seed_fingerprints`) or TOFU-learned while
/// `[cluster] enabled`. A missing certificate — or an unpinned one — is
/// rejected with `403 {"error":"peer auth required"}`.
async fn require_pinned_peer(
    State(pins): State<Arc<PeerPins>>,
    request: Request,
    next: Next,
) -> Response {
    let fingerprint = request
        .extensions()
        .get::<ConnectInfo<PeerCert>>()
        .and_then(|info| info.0.fingerprint.clone());
    match fingerprint {
        Some(fingerprint) if pins.authorize(&fingerprint) => next.run(request).await,
        _ => ApiError::Forbidden(String::from("peer auth required")).into_response(),
    }
}

/// 404 fallback: `{"error":"not found"}` on plain/v1 paths, Twirp envelope
/// `{"code":"not_found","msg":"not found"}` on `/twirp/*` paths.
async fn fallback_404(uri: Uri) -> Response {
    let err = ApiError::not_found();
    if uri.path().starts_with("/twirp/") {
        err.into_twirp_response()
    } else {
        err.into_response()
    }
}

/// 405 fallback: `{"error":"method not allowed"}` when a registered path is
/// hit with an unsupported method (axum's default 405 has an empty body).
async fn fallback_405() -> Response {
    ApiError::MethodNotAllowed.into_response()
}
