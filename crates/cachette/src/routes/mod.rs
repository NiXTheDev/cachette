//! HTTP route table (plan task 3 skeleton: `/health` + JSON 404 fallback).
//!
//! `/_internal/peers/*` (plan task 14) is the first pin-gated route group:
//! every request there must carry a peer certificate whose SPKI fingerprint is
//! pinned. Public routes and the 404 fallback never require a client cert.
//! Storage/auth/v1/v2 routes are added by later plan tasks.

mod health;

use std::sync::Arc;

use axum::Json;
use axum::Router;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::Uri;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};

use crate::error::ApiError;
use crate::state::AppState;
use crate::tls::{PeerCert, PeerPins};

/// Build the application router: `GET /health`, the pin-gated peer group, and
/// a JSON 404 fallback.
pub fn router(state: AppState) -> Router {
    let peer_routes = Router::new()
        .route("/_internal/peers/hello", post(peer_hello))
        .route_layer(middleware::from_fn_with_state(
            state.peers.clone(),
            require_pinned_peer,
        ));
    Router::new()
        .route("/health", get(health::health))
        .merge(peer_routes)
        .with_state(state)
        .fallback(fallback_404)
}

/// Minimal cluster hello (plan task 28 expands it): reports the responding node.
async fn peer_hello(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({"node_id": state.node_id, "accepted": true}))
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
