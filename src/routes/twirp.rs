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
//! | `CreateCacheEntry` | `metadata`, `key`, `version`, `scope` | `{"ok","signedUploadUrl","signedDownloadUrl","cacheId"}` (task 24) |
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

use std::sync::atomic::{AtomicU64, Ordering};

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::json;

use crate::auth::{self, jwt, urls};
use crate::config::AuthMode;
use crate::error::ApiError;
use crate::state::AppState;
use crate::storage::eviction::Capacity;
use crate::storage::normalize_key;

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
        Method::CreateCacheEntry => create_cache_entry(&state, &body).await,
        Method::FinalizeCacheEntryUpload => Json(json!({"ok": false})).into_response(),
        Method::SupersedeCacheEntry => Json(json!({"ok": false})).into_response(),
        Method::GetCacheEntryDownloadURL => Json(json!({"signedDownloadUrl": ""})).into_response(),
        Method::FindMissingOrStaleCacheEntries => Json(json!({"cacheEntries": []})).into_response(),
    }
}

/// Capability-URL path prefixes for the v2 entry (plan tasks 24/25/26). The
/// signed MAC binds the exact path, so these MUST match the handlers that
/// eventually serve them (`/v2/upload/{id}` upload, `/v2/artifacts/{id}`
/// download); both routes land in tasks 25/26.
const UPLOAD_PATH_PREFIX: &str = "/v2/upload/";
const ARTIFACT_PATH_PREFIX: &str = "/v2/artifacts/";

// HMAC secret fallback when `auth.secret` is unset is shared with the upload
// route ([`super::signing_secret`] / [`super::FALLBACK_SIGNING_SECRET`]) so
// minting and validation always agree.

/// `CreateCacheEntry` request. `key`/`version` are the reservation identity;
/// `scope` (`refs/heads/main`-style or a sha) is stored verbatim and never
/// parsed further. Both a top-level `scope` and the proto's
/// `metadata.scope` are accepted; unknown fields are ignored.
#[derive(serde::Deserialize)]
struct CreateCacheEntryRequest {
    #[serde(default)]
    key: String,
    #[serde(default)]
    version: String,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    metadata: Option<CacheMetadata>,
}

/// Nested `metadata` message (go-actions-cache `CacheMetadata`): only `scope`
/// is consumed here.
#[derive(serde::Deserialize)]
struct CacheMetadata {
    #[serde(default)]
    scope: Option<String>,
}

/// `CreateCacheEntry` (plan task 24): reserve a v2 entry and mint the signed
/// upload/download capability URLs.
///
/// A COMPLETE entry for the normalized key is a duplicate → HTTP 200
/// `{"ok":false,"otherFields":{"duplicateKey":true},...}` (never 400); an
/// incomplete reservation is not a duplicate, so a repeat create mints a fresh
/// id. The size is absent on this path, so B3 admission uses the `min_free`
/// floor (logged, not rejected — the eviction service is off the request
/// path). Single-node: the owner is this node, so the URLs point at our own
/// external host (`server.external_url`).
async fn create_cache_entry(state: &AppState, body: &[u8]) -> Response {
    let request: CreateCacheEntryRequest = match serde_json::from_slice(body) {
        Ok(request) => request,
        Err(err) => {
            return ApiError::BadRequest(format!("malformed CreateCacheEntry request: {err}"))
                .into_twirp_response();
        }
    };
    let Some(storage) = state.storage.as_deref() else {
        return ApiError::Unavailable(String::from("storage backend not configured"))
            .into_twirp_response();
    };
    let key = normalize_key(&request.key, state.cache.key_case);
    // v2 duplicate rule (plan task 24 / handoff): a COMPLETE entry OR a
    // still-open reservation for the key is a duplicate — a concurrent
    // same-key reserve must be rejected. `stat` sees only finalized entries,
    // so both checks are needed.
    match storage.stat(&key).await {
        Ok(Some(_)) => return duplicate_entry_response(),
        Ok(None) => {}
        Err(err) => {
            tracing::error!(error = %err, "v2 create: duplicate check failed");
            return ApiError::Internal.into_twirp_response();
        }
    }
    let now_unix = u64::try_from(auth::now_secs()).unwrap_or(0);
    match storage.reservation_exists(&key, now_unix).await {
        Ok(true) => return duplicate_entry_response(),
        Ok(false) => {}
        Err(err) => {
            tracing::error!(error = %err, "v2 create: reservation check failed");
            return ApiError::Internal.into_twirp_response();
        }
    }
    let used = match storage.used_bytes().await {
        Ok(used) => used,
        Err(err) => {
            tracing::error!(error = %err, "v2 create: usage accounting failed");
            return ApiError::Internal.into_twirp_response();
        }
    };
    if state.cache.max_size > 0 {
        let capacity = Capacity::resolve(state.cache.min_free, state.cache.max_size, 0, used);
        if !capacity.admits(None) {
            tracing::debug!(
                free = capacity.free(),
                min_free = capacity.min_free,
                "v2 create: below free-space floor (admission estimate)"
            );
        }
    }
    let cache_id = generate_cache_id(&key, &request.version);
    let expires_at = now_unix.saturating_add(state.cache.reservation_ttl_seconds);
    if let Err(err) = storage
        .reserve(&cache_id, &key, &request.version, expires_at)
        .await
    {
        tracing::error!(error = %err, "v2 create: staging reservation failed");
        return ApiError::Internal.into_twirp_response();
    }
    let scope = request
        .scope
        .or_else(|| request.metadata.and_then(|metadata| metadata.scope));
    if let Some(scope) = scope {
        tracing::debug!(cache_id = %cache_id, scope = %scope, "v2 create: scope observed");
    }
    if state.auth.cluster_enabled {
        tracing::debug!(cache_id = %cache_id, "v2 create: cluster mode (owner placement wired in task 30/31)");
    }
    let secret = super::signing_secret(state);
    let now = auth::now_secs();
    let ttl = state.cache.signed_url_ttl_seconds;
    let base = state.external_url.as_deref().unwrap_or_default();
    let upload_path = format!("{UPLOAD_PATH_PREFIX}{cache_id}");
    let download_path = format!("{ARTIFACT_PATH_PREFIX}{cache_id}");
    let signed_upload = format!(
        "{base}{upload_path}{}",
        urls::mint(&upload_path, &cache_id, secret, ttl, now).query()
    );
    let signed_download = format!(
        "{base}{download_path}{}",
        urls::mint(&download_path, &cache_id, secret, ttl, now).query()
    );
    Json(json!({
        "ok": true,
        "signedUploadUrl": signed_upload,
        "signedDownloadUrl": signed_download,
        "cacheId": cache_id,
    }))
    .into_response()
}

/// Duplicate-entry body (plan task 24): HTTP 200 `{"ok":false,...}` with the
/// `otherFields.duplicateKey` flag and a human reason — deliberately NOT 400.
fn duplicate_entry_response() -> Response {
    Json(json!({
        "ok": false,
        "reason": "a cache entry already exists for this key and version",
        "otherFields": { "duplicateKey": true },
    }))
    .into_response()
}

/// Generate a fresh 32-hex `cacheId` (no `uuid`/`rand` dependency is
/// available). FNV-1a over `key|version|now|sequence` with a splitmix64
/// avalanche; the process-global sequence keeps ids distinct for identical
/// key/version reservations within the same second, matching `v1.rs`.
fn generate_cache_id(key: &str, version: &str) -> String {
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let mut input = Vec::with_capacity(key.len() + version.len() + 17);
    input.extend_from_slice(key.as_bytes());
    input.push(b'|');
    input.extend_from_slice(version.as_bytes());
    input.extend_from_slice(&auth::now_secs().to_le_bytes());
    input.extend_from_slice(&sequence.to_le_bytes());
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in input {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash ^= hash >> 30;
    hash = hash.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    hash ^= hash >> 27;
    hash = hash.wrapping_mul(0x94d0_49bb_1331_11eb);
    hash ^= hash >> 31;
    format!("{hash:016x}{sequence:016x}")
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
