//! Twirp v2 `CacheService` plumbing: JSON dispatch + auth (plan task 23).
//!
//! GitHub's cache-results API is a Twirp service at
//! `POST /twirp/github.actions.results.api.v1.CacheService/{Method}` speaking
//! JSON (`application/json`; `text/json` is accepted too). This module routes
//! the five methods, enforces the same bearer/JWT policy the v1 routes use, and
//! answers with Twirp-shaped error envelopes. Real cache behaviour is deferred:
//! tasks 24-26 replace the skeleton bodies.
//!
//! Method → (request fields, response body): the JSON names match the
//! go-actions-cache `CacheService` contract (the vendored `.proto` is owned by
//! task 22 and may not exist yet, so the field names live here as the record).
//!
//! **JSON casing**: Twirp marshals with the proto field names, which are
//! `snake_case`; the vendored go-actions-cache client (`cache_v2.go`) reads
//! `encoding/json` struct tags like `signed_upload_url`, `signed_download_url`,
//! `matched_key`, `size_bytes`, `restore_keys`, `entry_id`. Responses therefore
//! use `snake_case`. Requests accept BOTH spellings (`serde` `alias`) so a
//! camelCase caller still parses.
//!
//! | method | request | response |
//! |---|---|---|
//! | `CreateCacheEntry` | `metadata`, `key`, `version`, `scope` | `{"ok","signed_upload_url","signed_download_url","cache_id"}` (task 24) |
//! | `FinalizeCacheEntryUpload` | `metadata`, `key`, `size_bytes`, `version`, `cache_id` | `{"ok":true}` or `{"ok":false,"message":"..."}` |
//! | `SupersedeCacheEntry` | `metadata`, `key`, `version` | `{"ok":true}` |
//! | `GetCacheEntryDownloadURL` | `metadata`, `key`, `restore_keys`, `version` | `{"ok":true,"signed_download_url":"...","matched_key":"..."}` or `{"ok":false,"signed_download_url":""}` |
//! | `FindMissingOrStaleCacheEntries` | `key_versions` | `{"cache_entries":[{"key","version","size","creation_time"}]}` |
//!
//! Auth policy on `/twirp/*` (mirrors the v1 handler matrix):
//! * static tokens (`[auth] tokens` + the dynamic `TokenStore`) are accepted in
//!   **every** mode;
//! * a self-minted JWT is accepted only in `bearer`/`merge` modes;
//! * in `hmac` mode a JWT is **never** accepted (Forgejo HMAC headers do not
//!   authenticate v2 either);
//! * missing/invalid credentials → `401 {"code":"unauthenticated",...}`.

use std::io;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::json;

use crate::auth::{self, jwt, urls};
use crate::cluster::relay::{self, V2Finalize, V2Reserve};
use crate::config::AuthMode;
use crate::error::ApiError;
use crate::state::AppState;
use crate::storage::eviction::Capacity;
use crate::storage::{Entry, EntryStat, StorageBackend, Version, lookup, normalize_key};

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
/// `version`, `size_bytes`, `cache_id`). Only `key`, `size_bytes`, and
/// `cache_id` are consumed: the published entry is addressed by its artifact
/// key, and the proto's `metadata`/`version` are ignored (serde drops unknown
/// fields). Both `sizeBytes`/`cacheId` aliases are accepted for tolerance.
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
    // Cluster placement (plan task 32): when a relay is configured the owner is
    // chosen by placement over the healthy peers. A self-owner falls through to
    // the local path below; a remote owner B gets a v2 reservation forwarded to
    // it (so the runner's direct upload to B succeeds) and A mints capability
    // URLs against B's host. No healthy owner at all → `ok:false`.
    if let Some(relay) = state.relay.as_deref() {
        match relay.owner_candidate() {
            None => {
                tracing::warn!(key = %key, "v2 create: no healthy owner");
                return Json(json!({
                    "ok": false,
                    "message": "no healthy storage owner is available",
                }))
                .into_response();
            }
            Some(owner) if !relay.is_self_node(&owner) => {
                let cache_id = generate_cache_id(&key, &request.version);
                return match relay
                    .v2_reserve(&owner, &cache_id, &key, &request.version)
                    .await
                {
                    V2Reserve::Accepted { external_url } => {
                        let base = super::owner_base_url(external_url.as_deref(), &owner.addr);
                        tracing::debug!(
                            owner = %owner.node_id, addr = %owner.addr, cache_id = %cache_id,
                            "v2 create: reserved on remote owner"
                        );
                        mint_create_response(state, &base, &cache_id)
                    }
                    V2Reserve::Duplicate => duplicate_entry_response(),
                    V2Reserve::NoCapacity => Json(json!({
                        "ok": false,
                        "message": "the storage owner is below its free-space floor",
                    }))
                    .into_response(),
                    V2Reserve::Unreachable => Json(json!({
                        "ok": false,
                        "message": "the storage owner is unreachable",
                    }))
                    .into_response(),
                };
            }
            Some(_) => {}
        }
    }
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
        tracing::debug!(cache_id = %cache_id, "v2 create: cluster mode (self-owned entry)");
    }
    let base = state.external_url.as_deref().unwrap_or_default();
    mint_create_response(state, base, &cache_id)
}

/// Mint the `CreateCacheEntry` capability URLs against `base` (the host that
/// owns the entry: self on the single-node/self-owner path, a remote owner B on
/// the cluster path). The MAC key is the shared secret (M12), so B validates
/// URLs A minted, and the paths match the `/v2/upload` + `/v2/artifacts`
/// handlers.
fn mint_create_response(state: &AppState, base: &str, cache_id: &str) -> Response {
    let secret = super::signing_secret(state);
    let now = auth::now_secs();
    let ttl = state.cache.signed_url_ttl_seconds;
    let upload_path = format!("{UPLOAD_PATH_PREFIX}{cache_id}");
    let download_path = format!("{ARTIFACT_PATH_PREFIX}{cache_id}");
    let signed_upload = format!(
        "{base}{upload_path}{}",
        urls::mint(&upload_path, cache_id, secret, ttl, now).query()
    );
    let signed_download = format!(
        "{base}{download_path}{}",
        urls::mint(&download_path, cache_id, secret, ttl, now).query()
    );
    // `snake_case` proto/Twirp JSON names (see the module docs): the vendored
    // go-actions-cache `cache_v2.go` reads `signed_upload_url` from this
    // response, so camelCase would silently break its `Save`.
    Json(json!({
        "ok": true,
        "signed_upload_url": signed_upload,
        "signed_download_url": signed_download,
        "cache_id": cache_id,
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
    let stat = match stat_key_or_id(storage, &key, request.cache_id.as_deref()).await {
        Ok(stat) => stat,
        Err(err) => {
            tracing::error!(error = %err, "v2 finalize: stat failed");
            return ApiError::Internal.into_twirp_response();
        }
    };
    if let Some(stat) = stat {
        if let Some(size) = request.size_bytes
            && size != stat.size
        {
            return Json(json!({"ok": false, "message": "size mismatch"})).into_response();
        }
        return Json(json!({"ok": true})).into_response();
    }
    // Not held locally: in cluster mode the owning node may be a peer, so fan
    // the finalize out to the healthy owner(s) (plan task 32).
    if let Some(relay) = state.relay.as_deref() {
        match relay
            .v2_finalize(&key, request.size_bytes, request.cache_id.as_deref())
            .await
        {
            V2Finalize::Ok => return Json(json!({"ok": true})).into_response(),
            V2Finalize::SizeMismatch => {
                return Json(json!({"ok": false, "message": "size mismatch"})).into_response();
            }
            V2Finalize::Missing => {}
        }
    }
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"ok": false, "message": "cache entry blob not found"})),
    )
        .into_response()
}

/// Stat by artifact key, falling back to the reservation `cache_id` (the two
/// places a backend may publish an entry under). Shared by the local finalize
/// and the pin-gated peer finalize endpoint.
pub(crate) async fn stat_key_or_id(
    storage: &dyn StorageBackend,
    key: &str,
    cache_id: Option<&str>,
) -> io::Result<Option<EntryStat>> {
    if let Some(stat) = storage.stat(key).await? {
        return Ok(Some(stat));
    }
    match cache_id.filter(|id| !id.is_empty()) {
        Some(cache_id) => storage.stat(cache_id).await,
        None => Ok(None),
    }
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
    if let Some(relay) = state.relay.as_deref() {
        relay.v2_supersede(&key).await;
        return Json(json!({"ok": true})).into_response();
    }
    if let Err(err) = storage.delete(&key).await {
        tracing::error!(error = %err, "v2 supersede: delete failed");
        return ApiError::Internal.into_twirp_response();
    }
    Json(json!({"ok": true})).into_response()
}

/// `GetCacheEntryDownloadURL` (plan task 26): find a complete entry for `key`
/// (falling back through `restore_keys` in order, exactly like
/// [`v1::find`](super::v1)) and mint a signed download URL bound to
/// `/v2/artifacts/{matched_key}` on `server.external_url`.
///
/// Hit → 200 `{"ok":true,"signed_download_url":"...","matched_key":"..."}`;
/// miss → 200 `{"ok":false,"signed_download_url":""}`. The proto field is
/// `signed_download_url` (snake_case: the vendored client reads that exact
/// key).
///
/// Single-node: mints locally. In cluster mode the entry node first checks
/// locally (self-owned) and, on miss, fans out to the owner (task 32) — it
/// never proxies the download body.
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
    if let Some(entry) = lookup(
        &candidates,
        &lookup_keys,
        &Version::from(request.version.as_str()),
        state.cache.key_case,
    ) {
        {
            let matched_key = entry.key.clone();
            let artifact_path = format!("{ARTIFACT_PATH_PREFIX}{matched_key}");
            let base = state.external_url.as_deref().unwrap_or_default();
            let signed = format!(
                "{}{artifact_path}{}",
                base,
                urls::mint(
                    &artifact_path,
                    &matched_key,
                    super::signing_secret(state),
                    state.cache.signed_url_ttl_seconds,
                    auth::now_secs(),
                )
                .query()
            );
            return Json(json!({
                "ok": true,
                "signed_download_url": signed,
                "matched_key": matched_key,
            }))
            .into_response();
        }
    }
    // Local miss: fan out to owners (plan task 32). Only queries peers, never
    // proxies the download body.
    if let Some(relay) = state.relay.as_deref() {
        let hits = relay.find(&lookup_keys, &request.version).await;
        if let Some(hit) = relay::best_hit(&hits, &lookup_keys, state.cache.key_case) {
            let matched_key = hit.key.clone();
            let artifact_path = format!("{ARTIFACT_PATH_PREFIX}{matched_key}");
            let base = super::owner_base_url(hit.external_url.as_deref(), &hit.addr);
            let signed = format!(
                "{}{artifact_path}{}",
                base,
                urls::mint(
                    &artifact_path,
                    &matched_key,
                    super::signing_secret(state),
                    state.cache.signed_url_ttl_seconds,
                    auth::now_secs(),
                )
                .query()
            );
            tracing::debug!(owner = %hit.node_id, matched_key = %matched_key, "v2 getdownloadurl: owner hit");
            return Json(json!({
                "ok": true,
                "signed_download_url": signed,
                "matched_key": matched_key,
            }))
            .into_response();
        }
    }
    Json(json!({"ok": false, "signed_download_url": ""})).into_response()
}

/// `FindMissingOrStaleCacheEntries` (plan task 26): report the requested
/// key-version pairs that are PRESENT as complete entries. Missing pairs are
/// implicitly absent from `cache_entries`.
///
/// Single-node: reports this node's entries. In cluster mode task 32 fans the
/// query out across healthy peers and unions the responses.
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
    let Some(storage) = state.storage.as_deref() else {
        return Json(json!({"cache_entries": []})).into_response();
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
            std::slice::from_ref(&key),
            &Version::from(version.as_str()),
            state.cache.key_case,
        ) {
            cache_entries.push(json!({
                "key": hit.key.clone(),
                "version": version,
                "size": hit.size,
                "creation_time": hit.created_at,
            }));
            continue;
        }
        if let Some(relay) = state.relay.as_deref() {
            let hits = relay.find(std::slice::from_ref(&key), &version).await;
            if let Some(hit) =
                relay::best_hit(&hits, std::slice::from_ref(&key), state.cache.key_case)
            {
                cache_entries.push(json!({
                    "key": hit.key.clone(),
                    "version": version,
                    "size": hit.size,
                    "creation_time": hit.created_at,
                }));
            }
        }
    }
    Json(json!({"cache_entries": cache_entries})).into_response()
}
/// Duplicate-entry body (plan task 24): HTTP 200 `{"ok":false,...}` with a human
/// `message` (the field the go-actions-cache `cache_v2.go` reads), the
/// `reason`/`otherFields.duplicateKey` flag the plan records — deliberately NOT
/// 400.
fn duplicate_entry_response() -> Response {
    Json(json!({
        "ok": false,
        "message": "a cache entry already exists for this key and version",
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
