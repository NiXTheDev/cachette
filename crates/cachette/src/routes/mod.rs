//! HTTP route table (plan task 3 skeleton: `/health` + JSON 404 fallback).
//!
//! Storage/auth/v1/v2 routes are added by later plan tasks.

mod health;

use axum::Router;
use axum::http::Uri;
use axum::response::{IntoResponse, Response};
use axum::routing::get;

use crate::error::ApiError;
use crate::state::AppState;

/// Build the application router: `GET /health` plus a JSON 404 fallback.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health::health))
        .with_state(state)
        .fallback(fallback_404)
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
