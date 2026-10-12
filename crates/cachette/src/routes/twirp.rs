//! Twirp v2 `CacheService` plumbing: JSON dispatch + auth (plan task 23).
//!
//! GitHub's cache-results API is a Twirp service at
//! `POST /twirp/github.actions.results.api.v1.CacheService/{Method}` speaking
//! JSON (`application/json`; `text/json` is accepted too). This module routes
//! the five methods, enforces the same bearer/JWT policy the v1 routes use, and
//! answers with Twirp-shaped error envelopes. Real cache behaviour is deferred:
//! tasks 24-26 replace the skeleton bodies.
//!
//! Method → (request fields, skeleton response body): the JSON names match the
//! go-actions-cache `CacheService` contract (the vendored `.proto` is owned by
//! task 22 and may not exist yet, so the field names live here as the record):
//!
//! | method | request | response |
//! |---|---|---|
//! | `CreateCacheEntry` | `metadata`, `key`, `version` | `{"ok":false}` |
//! | `FinalizeCacheEntryUpload` | `metadata`, `key`, `sizeBytes`, `version` | `{"ok":false}` |
//! | `SupersedeCacheEntry` | `metadata`, `key`, `version` | `{"ok":false}` |
//! | `GetCacheEntryDownloadURL` | `metadata`, `key`, `restoreKeys`, `version` | `{"signedDownloadUrl":""}` |
//! | `FindMissingOrStaleCacheEntries` | `keyVersions` | `{"cacheEntries":[]}` |
//!
//! Auth policy on `/twirp/*` (mirrors the v1 handler matrix):
//! * static tokens (`[auth] tokens` + the dynamic `TokenStore`) are accepted in
//!   **every** mode;
//! * a self-minted JWT is accepted only in `bearer`/`merge` modes;
//! * in `hmac` mode a JWT is **never** accepted (Forgejo HMAC headers do not
//!   authenticate v2 either);
//! * missing/invalid credentials → `401 {"code":"unauthenticated",...}`.

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::json;

use crate::auth::{self, jwt};
use crate::config::AuthMode;
use crate::error::ApiError;
use crate::state::AppState;

/// The five `CacheService` methods this node answers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Method {
    CreateCacheEntry,
    FinalizeCacheEntryUpload,
    SupersedeCacheEntry,
    GetCacheEntryDownloadURL,
    FindMissingOrStaleCacheEntries,
}

impl Method {
    /// Resolve a Twirp method name (`{method}` path segment) to a handler.
    fn from_path(name: &str) -> Option<Self> {
        match name {
            "CreateCacheEntry" => Some(Self::CreateCacheEntry),
            "FinalizeCacheEntryUpload" => Some(Self::FinalizeCacheEntryUpload),
            "SupersedeCacheEntry" => Some(Self::SupersedeCacheEntry),
            "GetCacheEntryDownloadURL" => Some(Self::GetCacheEntryDownloadURL),
            "FindMissingOrStaleCacheEntries" => Some(Self::FindMissingOrStaleCacheEntries),
            _ => None,
        }
    }
}

/// `POST {SERVICE_PREFIX}/{method}` — Twirp JSON dispatch.
///
/// Order of checks: method routing (unknown → `404 bad_route`), authentication
/// (`401 unauthenticated`), content type (`400 invalid_argument`), then body
/// parse (`400 invalid_argument`). Bodies are validated as JSON but the fields
/// are not yet consumed — unknown fields are accepted and ignored.
pub async fn dispatch(
    State(state): State<AppState>,
    Path(method): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(known) = Method::from_path(&method) else {
        return bad_route(&method);
    };
    if !authorized(&state, &headers).await {
        return ApiError::Unauthorized(String::from("authentication required"))
            .into_twirp_response();
    }
    if !accepts_json(&headers) {
        return ApiError::BadRequest(String::from(
            "unsupported content type; use application/json",
        ))
        .into_twirp_response();
    }
    if let Err(err) = serde_json::from_slice::<serde_json::Value>(&body) {
        return ApiError::BadRequest(format!("malformed JSON request: {err}"))
            .into_twirp_response();
    }
    match known {
        Method::CreateCacheEntry => Json(json!({"ok": false})).into_response(),
        Method::FinalizeCacheEntryUpload => Json(json!({"ok": false})).into_response(),
        Method::SupersedeCacheEntry => Json(json!({"ok": false})).into_response(),
        Method::GetCacheEntryDownloadURL => Json(json!({"signedDownloadUrl": ""})).into_response(),
        Method::FindMissingOrStaleCacheEntries => Json(json!({"cacheEntries": []})).into_response(),
    }
}

/// Bearer/JWT gate: static tokens first (all modes), then dynamic tokens
/// (all modes), then a self-minted JWT in `bearer`/`merge` modes only.
async fn authorized(state: &AppState, headers: &HeaderMap) -> bool {
    let Some(token) = auth::bearer_token(headers) else {
        return false;
    };
    let is_static = state
        .auth
        .static_tokens
        .iter()
        .any(|candidate| auth::constant_time_eq(candidate.as_bytes(), token.as_bytes()));
    if is_static || state.tokens.is_valid(token).await.unwrap_or(false) {
        return true;
    }
    match state.auth.mode {
        AuthMode::Hmac => false,
        AuthMode::Bearer | AuthMode::Merge => jwt_is_valid(state, token),
    }
}

/// Validate a self-minted JWT against the configured signing secret.
fn jwt_is_valid(state: &AppState, token: &str) -> bool {
    match state.auth.secret.as_deref() {
        Some(secret) => jwt::validate(token, secret, auth::now_secs()).is_ok(),
        None => false,
    }
}

/// `true` when the request declares a JSON content type (or none at all, which
/// Twirp clients omit). `text/json` is accepted alongside `application/json`.
fn accepts_json(headers: &HeaderMap) -> bool {
    let Some(raw) = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
    else {
        return true;
    };
    let mime = raw.split(';').next().unwrap_or_default().trim();
    mime.eq_ignore_ascii_case("application/json") || mime.eq_ignore_ascii_case("text/json")
}

/// Twirp `bad_route` envelope for an unknown method name (`404`).
fn bad_route(method: &str) -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(json!({
            "code": "bad_route",
            "msg": format!("no handler for method \"{method}\""),
        })),
    )
        .into_response()
}
