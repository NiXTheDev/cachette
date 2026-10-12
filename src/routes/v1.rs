//! v1 artifactcache route skeleton (plan task 18).
//!
//! The GitHub Actions cache v1 HTTP contract, minus the storage machinery that
//! later tasks own. This module fixes the **status-code contract** (criterion
//! 1) so the real logic can be dropped in behind it:
//!
//! - `GET  /_apis/artifactcache/cache?keys=&version=` — fully wired: exact-then
//!   prefix lookup ([`crate::storage::lookup`]) over finalized entries, with a
//!   signed `archiveLocation` on a hit ([`crate::auth::urls::mint`], task 16)
//!   and an **empty** 204 on a miss.
//! - `POST /_apis/artifactcache/caches` — reserve: rejects a duplicate finalized
//!   `(key, version)` with 409, stages an expiry-stamped reservation under a
//!   fresh 32-hex `cacheId`, and reports `cacheSize = max(0, max_size -
//!   used_bytes)`. Version siblings live behind the artifact-key primary index
//!   (tasks 30/31).
//! - `PATCH /_apis/artifactcache/caches/{cacheId}` — accepts a chunk and
//!   returns 204. The parts/resume machinery lands in task 20.
//! - `POST /_apis/artifactcache/caches/{cacheId}` `{size}` — accepts the commit
//!   and returns 204. Size verification + assembly land in task 21.
//! - `GET  /_apis/artifactcache/artifacts/{cacheId}` — fully wired: full 200 or
//!   a 206 slice with `Content-Range`, via [`crate::storage::StorageBackend`].
//! - `POST /_apis/artifactcache/caches/clean` — 200 no-op.
//!
//! Deliberate skeleton limits (documented so tasks 19-21 can lift them):
//! - The reservation keyed by `cacheId` stays staged (invisible) — there is no
//!   HTTP path to a *visible* entry until task 21 finalizes a commit, so the
//!   find/download fixtures in the tests are seeded directly into storage.
//! - [`crate::storage::StorageBackend::list`] yields `EntryStat`, which carries
//!   no protocol `version`; the requested version is stamped onto the candidate
//!   entries so `lookup`'s exact-then-prefix ordering is exercised end-to-end
//!   until task 19/21 add the versioned reservation index.
//! - `archiveLocation` is a **relative** path. `AppState` does not carry
//!   `server.external_url` (main.rs is task-34-owned), so a later task must
//!   prefix the absolute host when the value becomes available.

use std::ops::Range;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::json;
use tokio::io::AsyncReadExt;

use crate::auth::{self, urls};
use crate::error::ApiError;
use crate::state::AppState;
use crate::storage::eviction::Capacity;
use crate::storage::{Entry, StorageBackend, Version, lookup, normalize_key};

/// Signed-URL TTL for `archiveLocation` (seconds). Mirrors
/// `config.v1.signed_url_ttl_seconds` (`V1Config::default()`); wiring the live
/// config into `AppState` is a later task (main.rs is task-34-owned).
const SIGNED_URL_TTL_SECONDS: u64 = 900;

/// HMAC secret fallback when `auth.secret` is unset (tests / `--print-config`
/// boots without a secret). Production always serves with a real secret.
const FALLBACK_SECRET: &str = "cachette-v1-route-skeleton";

/// Artifact URL prefix the signed `archiveLocation` points at.
const ARTIFACT_PATH_PREFIX: &str = "/_apis/artifactcache/artifacts/";

/// Error name carried in the duplicate-reserve body (GitHub v1 spec).
const DUPLICATE_ERROR: &str = "ArtifactCacheItemAlreadyExistsException";

/// `GET /_apis/artifactcache/cache` query parameters.
#[derive(serde::Deserialize)]
pub struct FindQuery {
    /// Comma-separated restore keys, most specific first.
    pub keys: Option<String>,
    /// Protocol version marker (exact match, never case-folded).
    pub version: Option<String>,
}

/// `POST /_apis/artifactcache/caches` request body.
#[derive(serde::Deserialize)]
pub struct ReserveRequest {
    /// Cache key to reserve.
    pub key: String,
    /// Protocol version marker.
    pub version: String,
}

/// `POST /_apis/artifactcache/caches/{cacheId}` request body.
#[derive(serde::Deserialize)]
pub struct CommitRequest {
    /// Declared total size (used by task 21's verification).
    pub size: u64,
}

/// `GET /_apis/artifactcache/cache` — lookup a cache entry.
///
/// Hit: 200 `{"result":"hit","cacheKey":"<key>","archiveLocation":"<signed>"}`.
/// Miss (or empty `keys`): 204 with an **empty** body.
pub async fn find(State(state): State<AppState>, Query(query): Query<FindQuery>) -> Response {
    let Some(storage) = state.storage.as_deref() else {
        return ApiError::Unavailable(String::from("storage backend not configured"))
            .into_response();
    };
    let keys: Vec<String> = query
        .keys
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|key| !key.is_empty())
        .map(str::to_owned)
        .collect();
    if keys.is_empty() {
        return StatusCode::NO_CONTENT.into_response();
    }
    let version = query.version.unwrap_or_default();
    let finalized = match storage.list().await {
        Ok(entries) => entries,
        Err(err) => {
            tracing::error!(error = %err, "v1 find: listing entries failed");
            return ApiError::Internal.into_response();
        }
    };
    // `list` yields `EntryStat` (no version); stamp the requested version so
    // `lookup` can run its version-filtered exact-then-prefix pass (see module
    // docs for why this is a skeleton-only stand-in).
    let candidates: Vec<Entry> = finalized
        .into_iter()
        .map(|stat| Entry {
            key: stat.key,
            version: version.clone(),
            size: stat.size,
            created_at: stat.created_at,
            accessed_at: stat.accessed_at,
            complete: true,
        })
        .collect();
    let marker = Version::from(version);
    match lookup(&candidates, &keys, &marker, state.cache.key_case) {
        Some(entry) => {
            let cache_key = entry.key.clone();
            let secret = state.auth.secret.as_deref().unwrap_or(FALLBACK_SECRET);
            let path = format!("{ARTIFACT_PATH_PREFIX}{cache_key}");
            let signed = urls::mint(
                &path,
                &cache_key,
                secret,
                SIGNED_URL_TTL_SECONDS,
                auth::now_secs(),
            );
            let archive_location = format!("{path}{}", signed.query());
            Json(json!({
                "result": "hit",
                "cacheKey": cache_key,
                "archiveLocation": archive_location,
            }))
            .into_response()
        }
        None => StatusCode::NO_CONTENT.into_response(),
    }
}

/// `POST /_apis/artifactcache/caches` — reserve a new entry.
///
/// 200 `{"cacheId":"<32-hex>","cacheSize":<n>}` where
/// `cacheSize = max(0, cache.max_size - used_bytes)`; 409 with the GitHub
/// duplicate body when a finalized entry already holds `(key, version)`.
pub async fn reserve(
    State(state): State<AppState>,
    Json(request): Json<ReserveRequest>,
) -> Response {
    let Some(storage) = state.storage.as_deref() else {
        return ApiError::Unavailable(String::from("storage backend not configured"))
            .into_response();
    };
    let key = normalize_key(&request.key, state.cache.key_case);
    // A complete entry holding the exact key is a duplicate (409); an
    // incomplete reservation (or nothing) falls through to a fresh 200.
    match storage.stat(&key).await {
        Ok(Some(_)) => return duplicate_response(&request.key),
        Ok(None) => {}
        Err(err) => {
            tracing::error!(error = %err, "v1 reserve: duplicate check failed");
            return ApiError::Internal.into_response();
        }
    }
    let used = match storage.used_bytes().await {
        Ok(used) => used,
        Err(err) => {
            tracing::error!(error = %err, "v1 reserve: usage accounting failed");
            return ApiError::Internal.into_response();
        }
    };
    // B3 admission estimate: at reserve time the artifact size is unknown
    // (`PATCH` carries no `Content-Length` contract), so admission is judged
    // against the `min_free` floor; the eviction service is not on the request
    // path, so a below-floor reserve is logged, not rejected, and `cacheSize`
    // simply clamps to 0 (criterion 1 QA).
    if state.cache.max_size > 0 {
        let capacity = Capacity::resolve(state.cache.min_free, state.cache.max_size, 0, used);
        if !capacity.admits(None) {
            tracing::debug!(
                free = capacity.free(),
                min_free = capacity.min_free,
                "v1 reserve: below free-space floor (admission estimate)"
            );
        }
    }
    let cache_size = state.cache.max_size.saturating_sub(used);
    let cache_id = generate_cache_id(&key, &request.version);
    let expires_at = u64::try_from(auth::now_secs())
        .unwrap_or(0)
        .saturating_add(state.cache.reservation_ttl_seconds);
    if let Err(err) = storage.reserve(&cache_id, expires_at).await {
        tracing::error!(error = %err, "v1 reserve: staging reservation failed");
        return ApiError::Internal.into_response();
    }
    // Cluster seam (plan tasks 30/31): cluster mode advertises the chosen
    // owner's `cacheId` for relay; single-node serving is complete without it.
    if state.auth.cluster_enabled {
        tracing::debug!(cache_id = %cache_id, "v1 reserve: cluster mode (placement/relay wired in task 30/31)");
    }
    Json(json!({"cacheId": cache_id, "cacheSize": cache_size})).into_response()
}

/// `PATCH /_apis/artifactcache/caches/{cacheId}` — accept an upload chunk.
///
/// Skeleton: acknowledge with an empty 204. Chunk staging, resume and overlap
/// detection are task 20.
pub async fn patch_chunk(Path(_cache_id): Path<String>) -> Response {
    StatusCode::NO_CONTENT.into_response()
}

/// `POST /_apis/artifactcache/caches/{cacheId}` — commit an upload.
///
/// Skeleton: accept `{size}` and reply with an empty 204. Size verification,
/// part assembly and supersede are task 21.
pub async fn commit(Path(_cache_id): Path<String>, Json(request): Json<CommitRequest>) -> Response {
    tracing::debug!(size = request.size, "v1 commit skeleton: accepted");
    StatusCode::NO_CONTENT.into_response()
}

/// `GET /_apis/artifactcache/artifacts/{cacheId}` — download an entry.
///
/// No `Range`: 200 with the full body. With `Range: bytes=a-b`: 206 with the
/// slice and `Content-Range: bytes a-b/<size>`. Unknown id: 404 JSON.
pub async fn download(
    State(state): State<AppState>,
    Path(cache_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let Some(storage) = state.storage.as_deref() else {
        return ApiError::Unavailable(String::from("storage backend not configured"))
            .into_response();
    };
    let size = match storage.stat(&cache_id).await {
        Ok(Some(stat)) => stat.size,
        Ok(None) => return ApiError::not_found().into_response(),
        Err(err) => {
            tracing::error!(error = %err, "v1 download: stat failed");
            return ApiError::Internal.into_response();
        }
    };
    let range = headers
        .get(header::RANGE)
        .and_then(|value| value.to_str().ok());
    match range {
        None => match read_range(storage, &cache_id, 0..size).await {
            Some(bytes) => (
                StatusCode::OK,
                [(header::ACCEPT_RANGES, String::from("bytes"))],
                bytes,
            )
                .into_response(),
            None => ApiError::not_found().into_response(),
        },
        Some(raw) => {
            let Some((start, end)) = parse_range(raw, size) else {
                return range_not_satisfiable(size);
            };
            let Some(bytes) = read_range(storage, &cache_id, start..end + 1).await else {
                return range_not_satisfiable(size);
            };
            (
                StatusCode::PARTIAL_CONTENT,
                [
                    (header::CONTENT_RANGE, format!("bytes {start}-{end}/{size}")),
                    (header::ACCEPT_RANGES, String::from("bytes")),
                ],
                bytes,
            )
                .into_response()
        }
    }
}

/// `POST /_apis/artifactcache/caches/clean` — 200 no-op.
pub async fn clean() -> Response {
    StatusCode::OK.into_response()
}

/// GitHub v1 duplicate-reserve body:
/// `{"error":"ArtifactCacheItemAlreadyExistsException","type":"key","key":"<k>"}`.
fn duplicate_response(key: &str) -> Response {
    (
        StatusCode::CONFLICT,
        Json(json!({
            "error": DUPLICATE_ERROR,
            "type": "key",
            "key": key,
        })),
    )
        .into_response()
}

/// Read a finalized entry's `range` into memory (test/skeleton-scale payloads).
async fn read_range(storage: &dyn StorageBackend, key: &str, range: Range<u64>) -> Option<Vec<u8>> {
    let mut stream = storage.get_range(key, range).await.ok()?;
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).await.ok()?;
    Some(bytes)
}

/// Parse a single `Range: bytes=a-b` request against `size` into an inclusive
/// `(start, end)`. Supports open ends (`bytes=a-`) and suffixes (`bytes=-n`);
/// multi-range and out-of-bounds requests return `None` (→ 416).
fn parse_range(raw: &str, size: u64) -> Option<(u64, u64)> {
    if size == 0 {
        return None;
    }
    let spec = raw.trim().strip_prefix("bytes=")?;
    let (start_raw, end_raw) = spec.split_once('-')?;
    let last = size - 1;
    let start_raw = start_raw.trim();
    let end_raw = end_raw.trim();
    if start_raw.is_empty() {
        let suffix: u64 = end_raw.parse().ok()?;
        if suffix == 0 {
            return None;
        }
        return Some((size.saturating_sub(suffix), last));
    }
    let start: u64 = start_raw.parse().ok()?;
    if start > last {
        return None;
    }
    let end = if end_raw.is_empty() {
        last
    } else {
        end_raw.parse::<u64>().ok()?.min(last)
    };
    (end >= start).then_some((start, end))
}

/// 416 response with `Content-Range: bytes */<size>` (RFC 9110).
fn range_not_satisfiable(size: u64) -> Response {
    (
        StatusCode::RANGE_NOT_SATISFIABLE,
        [
            (header::CONTENT_RANGE, format!("bytes */{size}")),
            (header::ACCEPT_RANGES, String::from("bytes")),
        ],
    )
        .into_response()
}

/// Generate a fresh 32-hex-char `cacheId`.
///
/// No `uuid`/`rand` dependency is available (and none may be added for this
/// task), so this is a FNV-1a hash of `key|version|now|sequence` with a
/// splitmix64 avalanche. The process-wide atomic sequence makes ids unique
/// even for identical key/version reservations within the same second; lower
/// 64 bits expose the sequence for easy debugging. Task 19 may swap in a UUID.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_range_handles_bounded_open_and_suffix_forms() {
        assert_eq!(parse_range("bytes=0-99", 1000), Some((0, 99)));
        assert_eq!(parse_range("bytes=0-", 1000), Some((0, 999)));
        assert_eq!(parse_range("bytes=990-2000", 1000), Some((990, 999)));
        assert_eq!(parse_range("bytes=-100", 1000), Some((900, 999)));
        assert_eq!(parse_range("bytes=5-5", 1000), Some((5, 5)));
    }

    #[test]
    fn parse_range_rejects_multi_unsatisfiable_and_malformed_forms() {
        assert_eq!(parse_range("bytes=0-1,3-4", 1000), None);
        assert_eq!(parse_range("bytes=1000-1001", 1000), None);
        assert_eq!(parse_range("items=0-1", 1000), None);
        assert_eq!(parse_range("bytes=0-1", 0), None);
        assert_eq!(parse_range("bytes=-0", 1000), None);
    }

    #[test]
    fn cache_id_is_32_lowercase_hex_and_unique_per_call() {
        let first = generate_cache_id("k", "2");
        let second = generate_cache_id("k", "2");
        assert_eq!(first.len(), 32);
        assert!(first.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(first, second, "sequence must keep ids unique");
    }
}
