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
//! | `FinalizeCacheEntryUpload` | `metadata`, `key`, `sizeBytes`, `version`, `cacheId` | `{"ok":true}` or `{"ok":false,"message":"..."}` |
//! | `SupersedeCacheEntry` | `metadata`, `key`, `version` | `{"ok":true}` |
//! | `GetCacheEntryDownloadURL` | `metadata`, `key`, `restoreKeys`, `version` | `{"ok":true,"signedDownloadUrl":"...","matchedKey":"..."}` or `{"ok":false,"signedDownloadUrl":""}` |
//! | `FindMissingOrStaleCacheEntries` | `keyVersions` | `{"cacheEntries":[{"key","version","size","creationTime"}]}` |
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
use crate::storage::{Entry, Version, lookup, normalize_key};

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
        Method::FinalizeCacheEntryUpload => finalize_cache_entry(&state, &body).await,
        Method::SupersedeCacheEntry => supersede_cache_entry(&state, &body).await,
        Method::GetCacheEntryDownloadURL => get_cache_entry_download_url(&state, &body).await,
        Method::FindMissingOrStaleCacheEntries => {
            find_missing_or_stale_cache_entries(&state, &body).await
        }
    }
}

/// Capability-URL path prefixes for the v2 entry (plan tasks 24/25/26). The
/// signed MAC binds the exact path, so these MUST match the handlers that
/// eventually serve them (`/v2/upload/{id}` upload, `/v2/artifacts/{id}`
/// download); both routes land in tasks 25/26.
const UPLOAD_PATH_PREFIX: &str = "/v2/upload/";
const ARTIFACT_PATH_PREFIX: &str = "/v2/artifacts/";

// HMAC secret fallback when `auth.secret` is unset is shared with the upload
// and download routes ([`super::signing_secret`] /
// [`super::FALLBACK_SIGNING_SECRET`]) so minting and validation always agree.

/// `FinalizeCacheEntryUpload` request (go-actions-cache proto fields `key`,
/// `version`, `sizeBytes`, `cacheId`). Only `key`, `sizeBytes`, and `cacheId`
/// are consumed: the published entry is addressed by its artifact key, and the
/// proto's `metadata`/`version` are ignored (serde drops unknown fields).
#[derive(serde::Deserialize)]
struct FinalizeCacheEntryUploadRequest {
    #[serde(default)]
    key: String,
    #[serde(default, alias = "sizeBytes")]
    size_bytes: Option<u64>,
    #[serde(default, alias = "cacheId")]
    cache_id: Option<String>,
}

/// `SupersedeCacheEntry` request (go-actions-cache proto fields `metadata`,
/// `key`, `version`). The entry is deleted by its normalized key.
#[derive(serde::Deserialize)]
struct SupersedeCacheEntryRequest {
    #[serde(default)]
    key: String,
}

/// `GetCacheEntryDownloadURL` request (go-actions-cache proto fields `metadata`,
/// `key`, `restoreKeys`, `version`).
#[derive(serde::Deserialize)]
struct GetCacheEntryDownloadURLRequest {
    #[serde(default)]
    key: String,
    #[serde(default)]
    version: String,
    #[serde(default, alias = "restoreKeys")]
    restore_keys: Option<Vec<String>>,
}

/// A single key-version pair for FindMissing.
#[derive(serde::Deserialize, Clone)]
struct KeyVersion {
    #[serde(default)]
    key: String,
    #[serde(default)]
    version: String,
}

/// `FindMissingOrStaleCacheEntries` request.
#[derive(serde::Deserialize)]
struct FindMissingOrStaleCacheEntriesRequest {
    #[serde(default, alias = "keyVersions")]
    key_versions: Vec<KeyVersion>,
}

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

/// `FinalizeCacheEntryUpload` (plan task 26): the runner reports the uploaded
/// size for a reservation it just assembled. The B5 commit (tasks 21/25) has
/// already published the entry under its artifact key, so this only verifies
/// the blob is present (and, when given, that `sizeBytes` matches).
///
/// * blob present, size matches (or omitted) → 200 `{"ok":true}`;
/// * blob present, size mismatched → 200 `{"ok":false,"message":"size mismatch"}`
///   (a client error, deliberately NOT 500);
/// * blob absent → HTTP 500 with `{"ok":false,...}` — never `ok:true`.
///
/// Single-node: the blob is local. In cluster mode the owning node may be a
/// peer; task 32 forwards this call to `POST B/_internal/peers/v2/finalize`.
async fn finalize_cache_entry(state: &AppState, body: &[u8]) -> Response {
    let request: FinalizeCacheEntryUploadRequest = match serde_json::from_slice(body) {
        Ok(request) => request,
        Err(err) => {
            return ApiError::BadRequest(format!(
                "malformed FinalizeCacheEntryUpload request: {err}"
            ))
            .into_twirp_response();
        }
    };
    let Some(storage) = state.storage.as_deref() else {
        return ApiError::Unavailable(String::from("storage backend not configured"))
            .into_twirp_response();
    };
    let key = normalize_key(&request.key, state.cache.key_case);
    // Cluster seam (plan tasks 31/32): on entry node A a finalize for a blob
    // owned by B is forwarded to B's peer route; single-node serving is complete.
    if state.auth.cluster_enabled {
        tracing::debug!(
            key = %key,
            cache_id = ?request.cache_id,
            "v2 finalize: cluster mode (peer forwarding wired in task 32)"
        );
    }
    // The published entry is addressed by its artifact key (B5 commit). Fall
    // back to the reservation `cacheId` for a backend that publishes under the
    // reservation id instead.
    let stat = match storage.stat(&key).await {
        Ok(Some(stat)) => Some(stat),
        Ok(None) => match request.cache_id.as_deref().filter(|id| !id.is_empty()) {
            Some(cache_id) => match storage.stat(cache_id).await {
                Ok(found) => found,
                Err(err) => {
                    tracing::error!(error = %err, "v2 finalize: stat failed");
                    return ApiError::Internal.into_twirp_response();
                }
            },
            None => None,
        },
        Err(err) => {
            tracing::error!(error = %err, "v2 finalize: stat failed");
            return ApiError::Internal.into_twirp_response();
        }
    };
    let Some(stat) = stat else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"ok": false, "message": "cache entry blob not found"})),
        )
            .into_response();
    };
    if let Some(size) = request.size_bytes
        && size != stat.size
    {
        return Json(json!({"ok": false, "message": "size mismatch"})).into_response();
    }
    Json(json!({"ok": true})).into_response()
}

/// `SupersedeCacheEntry` (plan task 26): delete the entry for the normalized
/// key so a follow-up `CreateCacheEntry` is no longer a duplicate. Idempotent —
/// superseding a missing key is still `{"ok":true}`.
///
/// Single-node: deletes locally. In cluster mode task 32 forwards this to the
/// owner (`POST B/_internal/peers/v2/supersede`).
async fn supersede_cache_entry(state: &AppState, body: &[u8]) -> Response {
    let request: SupersedeCacheEntryRequest = match serde_json::from_slice(body) {
        Ok(request) => request,
        Err(err) => {
            return ApiError::BadRequest(format!("malformed SupersedeCacheEntry request: {err}"))
                .into_twirp_response();
        }
    };
    let Some(storage) = state.storage.as_deref() else {
        return ApiError::Unavailable(String::from("storage backend not configured"))
            .into_twirp_response();
    };
    let key = normalize_key(&request.key, state.cache.key_case);
    if state.auth.cluster_enabled {
        tracing::debug!(key = %key, "v2 supersede: cluster mode (peer forwarding wired in task 32)");
    }
    if let Err(err) = storage.delete(&key).await {
        tracing::error!(error = %err, "v2 supersede: delete failed");
        return ApiError::Internal.into_twirp_response();
    }
    Json(json!({"ok": true})).into_response()
}

/// `GetCacheEntryDownloadURL` (plan task 26): find a complete entry for `key`
/// (falling back through `restoreKeys` in order, exactly like
/// [`v1::find`](super::v1)) and mint a signed download URL bound to
/// `/v2/artifacts/{matchedKey}` on `server.external_url`.
///
/// Hit → 200 `{"ok":true,"signedDownloadUrl":"...","matchedKey":"..."}`;
/// miss → 200 `{"ok":false,"signedDownloadUrl":""}`. The proto field is
/// `signedDownloadUrl`.
///
/// Single-node: mints locally. In cluster mode task 32 forwards this to the
/// owner (`POST B/_internal/peers/v2/getdownloadurl`).
async fn get_cache_entry_download_url(state: &AppState, body: &[u8]) -> Response {
    let request: GetCacheEntryDownloadURLRequest = match serde_json::from_slice(body) {
        Ok(request) => request,
        Err(err) => {
            return ApiError::BadRequest(format!(
                "malformed GetCacheEntryDownloadURL request: {err}"
            ))
            .into_twirp_response();
        }
    };
    let Some(storage) = state.storage.as_deref() else {
        return ApiError::Unavailable(String::from("storage backend not configured"))
            .into_twirp_response();
    };
    let key = normalize_key(&request.key, state.cache.key_case);
    if state.auth.cluster_enabled {
        tracing::debug!(key = %key, "v2 getdownloadurl: cluster mode (peer forwarding wired in task 32)");
    }
    let mut lookup_keys = vec![key];
    if let Some(restore_keys) = &request.restore_keys {
        lookup_keys.extend(
            restore_keys
                .iter()
                .map(|restore| normalize_key(restore, state.cache.key_case)),
        );
    }
    let finalized = match storage.list().await {
        Ok(entries) => entries,
        Err(err) => {
            tracing::error!(error = %err, "v2 getdownloadurl: listing entries failed");
            return ApiError::Internal.into_twirp_response();
        }
    };
    // `list` yields `EntryStat` (no protocol version); stamp the requested
    // version so `lookup`'s version-filtered exact-then-prefix pass runs (the
    // same skeleton-only stand-in `v1::find` documents).
    let candidates: Vec<Entry> = finalized
        .into_iter()
        .map(|stat| Entry {
            key: stat.key,
            version: request.version.clone(),
            size: stat.size,
            created_at: stat.created_at,
            accessed_at: stat.accessed_at,
            complete: true,
        })
        .collect();
    match lookup(
        &candidates,
        &lookup_keys,
        &Version::from(request.version.as_str()),
        state.cache.key_case,
    ) {
        Some(entry) => {
            let matched_key = entry.key.clone();
            let artifact_path = format!("{ARTIFACT_PATH_PREFIX}{matched_key}");
            let signed = format!(
                "{}{artifact_path}{}",
                state.external_url.as_deref().unwrap_or_default(),
                urls::mint(
                    &artifact_path,
                    &matched_key,
                    super::signing_secret(state),
                    state.cache.signed_url_ttl_seconds,
                    auth::now_secs(),
                )
                .query()
            );
            Json(json!({
                "ok": true,
                "signedDownloadUrl": signed,
                "matchedKey": matched_key,
            }))
            .into_response()
        }
        None => Json(json!({"ok": false, "signedDownloadUrl": ""})).into_response(),
    }
}

/// `FindMissingOrStaleCacheEntries` (plan task 26): report the requested
/// key-version pairs that are PRESENT as complete entries. Missing pairs are
/// implicitly absent from `cacheEntries`.
///
/// Single-node: reports this node's entries. In cluster mode task 32 fans the
/// query out across healthy peers and unions the responses
/// (`POST B/_internal/peers/v2/findmissing`).
async fn find_missing_or_stale_cache_entries(state: &AppState, body: &[u8]) -> Response {
    let request: FindMissingOrStaleCacheEntriesRequest = match serde_json::from_slice(body) {
        Ok(request) => request,
        Err(err) => {
            return ApiError::BadRequest(format!(
                "malformed FindMissingOrStaleCacheEntries request: {err}"
            ))
            .into_twirp_response();
        }
    };
    if state.auth.cluster_enabled {
        tracing::debug!("v2 findmissing: cluster mode (peer fan-out wired in task 32)");
    }
    let Some(storage) = state.storage.as_deref() else {
        return Json(json!({"cacheEntries": []})).into_response();
    };
    let finalized = match storage.list().await {
        Ok(entries) => entries,
        Err(err) => {
            tracing::error!(error = %err, "v2 findmissing: listing entries failed");
            return ApiError::Internal.into_twirp_response();
        }
    };
    let mut cache_entries: Vec<serde_json::Value> = Vec::new();
    for key_version in &request.key_versions {
        let key = normalize_key(&key_version.key, state.cache.key_case);
        let version = key_version.version.clone();
        let candidates: Vec<Entry> = finalized
            .iter()
            .filter(|stat| stat.key == key)
            .map(|stat| Entry {
                key: stat.key.clone(),
                version: version.clone(),
                size: stat.size,
                created_at: stat.created_at,
                accessed_at: stat.accessed_at,
                complete: true,
            })
            .collect();
        if let Some(hit) = lookup(
            &candidates,
            &[key],
            &Version::from(version.as_str()),
            state.cache.key_case,
        ) {
            cache_entries.push(json!({
                "key": hit.key.clone(),
                "version": version,
                "size": hit.size,
                "creationTime": hit.created_at,
            }));
        }
    }
    Json(json!({"cacheEntries": cache_entries})).into_response()
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
