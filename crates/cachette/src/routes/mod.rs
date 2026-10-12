//! HTTP route table (plan task 3 skeleton: `/health` + JSON 404 fallback).
//!
//! `/_internal/peers/*` (plan task 14) is the first pin-gated route group:
//! every request there must carry a peer certificate whose SPKI fingerprint is
//! pinned. `/_internal/register` + `/_internal/revoke` (plan task 15) are the
//! admin token routes: `Authorization: Bearer <auth.secret>`, or loopback-only
//! when `[cluster] enabled` is false. The `/_apis/artifactcache/*` group is
//! auth-gated by a path-scoped layer (plan task 15) and served by the v1
//! handlers in [`v1`] (plan task 18). The Twirp v2 group (`/twirp/...`, plan
//! task 23) is served by [`twirp`], which enforces its own bearer/JWT policy.
//! Public routes and the 404/405 fallbacks never require a client cert.

mod health;
mod twirp;
mod v1;

use std::sync::Arc;

use axum::Json;
use axum::Router;
use axum::extract::{ConnectInfo, Query, Request, State};
use axum::http::Uri;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, patch, post};

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
    Router::new()
        .route("/health", get(health::health))
        .merge(peer_routes)
        .merge(admin_routes)
        .merge(v1_routes)
        .merge(twirp_routes)
        .with_state(state.clone())
        .fallback(fallback_404)
        .method_not_allowed_fallback(fallback_405)
        .layer(middleware::from_fn_with_state(state, auth::require_auth))
}

/// Minimal cluster hello (plan task 28 expands it): reports the responding node.
async fn peer_hello(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({"node_id": state.node_id, "accepted": true}))
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
