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
//! - `POST /_apis/artifactcache/caches/{cacheId}` `{size}` — commit: assemble
//!   the staged chunks, verify their total equals `{size}`, publish the entry
//!   under its artifact key (superseding a same-key sibling), and return 204
//!   (task 21). A size mismatch is 400 and marks the reservation for reaping.
//! - `GET  /_apis/artifactcache/artifacts/{cacheId}` — download: full 200 or a
//!   206 slice with `Content-Range`, gated by a signed URL in bearer/merge or
//!   clustered deployments, via [`crate::storage::StorageBackend`].
//! - `POST /_apis/artifactcache/caches/clean` — 200 no-op.
//!
//! Deliberate skeleton limits (documented so later tasks can lift them):
//! - Supersede keeps one visible entry per artifact key (last-writer-wins);
//!   same-key versions are replaced, not stored side-by-side.
//! - [`crate::storage::StorageBackend::list`] yields `EntryStat`, which carries
//!   no protocol `version`; the requested version is stamped onto the candidate
//!   entries so `lookup`'s exact-then-prefix ordering is exercised end-to-end
//!   until task 19/21 add the versioned reservation index.
//! - `archiveLocation` is a **relative** path. `AppState` does not carry
//!   `server.external_url` (main.rs is task-34-owned), so a later task must
//!   prefix the absolute host when the value becomes available.

use std::collections::HashMap;
use std::io;
use std::ops::Range;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::Json;
use axum::body::{Body, to_bytes};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use serde_json::json;
use tokio::io::AsyncReadExt;

use crate::auth::{self, urls};
use crate::config::AuthMode;
use crate::error::ApiError;
use crate::state::AppState;
use crate::storage::eviction::Capacity;
use crate::storage::{
    ByteStream, Chunk, ChunkRange, Entry, LocalRelay, RelayTransport, StorageBackend, Version,
    lookup, normalize_key,
};

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

/// Largest single PATCH chunk accepted (guards the in-memory read; the
/// go-actions-cache fixture uses 32 MiB chunks, the toolkit 4 MiB).
const MAX_CHUNK_BYTES: u64 = 256 * 1024 * 1024;

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
    if let Err(err) = storage
        .reserve(&cache_id, &key, &request.version, expires_at)
        .await
    {
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
/// `Content-Range: bytes start-end/*` (end inclusive) addresses the chunk;
/// the bytes are streamed to `parts/{cacheId}/{start}.part` without assembling
/// the blob (task 21 owns commit/assembly). 204 on success (including an
/// idempotent re-PATCH of an already-received range); 400 for a malformed
/// header, an overlapping range, a length mismatch, or `cacheId=0`; 404 for an
/// unknown/expired reservation; 409 when the entry is already complete.
pub async fn patch_chunk(
    State(state): State<AppState>,
    Path(cache_id): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let Some(storage) = state.storage.as_deref() else {
        return ApiError::Unavailable(String::from("storage backend not configured"))
            .into_response();
    };
    if cache_id == "0" {
        return ApiError::BadRequest(String::from("cacheId 0 is not a valid reservation"))
            .into_response();
    }
    let Some(range) = parse_content_range(headers.get(header::CONTENT_RANGE)) else {
        return ApiError::BadRequest(String::from("invalid or missing Content-Range"))
            .into_response();
    };
    let expected = range.len();
    if expected > MAX_CHUNK_BYTES {
        return ApiError::BadRequest(String::from("chunk exceeds the maximum size"))
            .into_response();
    }
    let limit = usize::try_from(expected).unwrap_or(usize::MAX);
    let bytes = match to_bytes(body, limit).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return ApiError::BadRequest(String::from("chunk body could not be read"))
                .into_response();
        }
    };
    if bytes.len() as u64 != expected {
        return ApiError::BadRequest(String::from("chunk length does not match Content-Range"))
            .into_response();
    }
    let stream: ByteStream<'_> = Box::pin(std::io::Cursor::new(bytes));
    let chunk = Chunk {
        range,
        body: stream,
    };
    // Relay seam (plan tasks 20/31): single-node serving writes locally; task
    // 31 swaps in a cluster transport that forwards to the placement owner.
    if state.auth.cluster_enabled {
        tracing::debug!(cache_id = %cache_id, "v1 patch: cluster mode (relay wired in task 31)");
    }
    let relay = LocalRelay;
    match relay.stream_to_owner(storage, &cache_id, chunk).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => chunk_error(err),
    }
}

/// `POST /_apis/artifactcache/caches/{cacheId}` — commit an upload.
///
/// Assembles the reservation's staged chunks into the final blob, verifies
/// their total equals `{size}` and publishes the entry (superseding a same-key
/// sibling). 204 on success; 400 when the chunks do not match `{size}` (the
/// reservation is marked failed for the reaper); 404 for an unknown/expired
/// reservation; 400 for `cacheId=0`.
pub async fn commit(
    State(state): State<AppState>,
    Path(cache_id): Path<String>,
    Json(request): Json<CommitRequest>,
) -> Response {
    let Some(storage) = state.storage.as_deref() else {
        return ApiError::Unavailable(String::from("storage backend not configured"))
            .into_response();
    };
    if cache_id == "0" {
        return ApiError::BadRequest(String::from("cacheId 0 is not a valid reservation"))
            .into_response();
    }
    match storage.commit_chunks(&cache_id, request.size).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => commit_error(err),
    }
}

/// `GET /_apis/artifactcache/artifacts/{cacheId}` — download an entry.
///
/// No `Range`: 200 with the full body. With `Range: bytes=a-b`: 206 with the
/// slice and `Content-Range: bytes a-b/<size>`. Unknown id: 404 JSON.
///
/// Authorization (M2/M3): when signed URLs are enforced (bearer/merge modes, or
/// any cluster), the request must carry a valid `?id&exp&mac` minted by find →
/// 403 otherwise. In pure HMAC single-node mode the global HMAC gate already
/// authorizes the request, so a bare signed-URL-less GET is allowed.
pub async fn download(
    State(state): State<AppState>,
    Path(cache_id): Path<String>,
    uri: Uri,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let Some(storage) = state.storage.as_deref() else {
        return ApiError::Unavailable(String::from("storage backend not configured"))
            .into_response();
    };
    if requires_signed_url(&state) {
        let secret = state.auth.secret.as_deref().unwrap_or(FALLBACK_SECRET);
        if let Err(err) = urls::validate(&query, uri.path(), secret, auth::now_secs()) {
            return ApiError::from(err).into_response();
        }
    }
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
/// Shared with the v2 artifact download (plan task 26) so both protocols slice
/// bytes identically.
pub(crate) async fn read_range(
    storage: &dyn StorageBackend,
    key: &str,
    range: Range<u64>,
) -> Option<Vec<u8>> {
    let mut stream = storage.get_range(key, range).await.ok()?;
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).await.ok()?;
    Some(bytes)
}

/// Parse a single `Range: bytes=a-b` request against `size` into an inclusive
/// `(start, end)`. Supports open ends (`bytes=a-`) and suffixes (`bytes=-n`);
/// multi-range and out-of-bounds requests return `None` (→ 416).
pub(crate) fn parse_range(raw: &str, size: u64) -> Option<(u64, u64)> {
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
pub(crate) fn range_not_satisfiable(size: u64) -> Response {
    (
        StatusCode::RANGE_NOT_SATISFIABLE,
        [
            (header::CONTENT_RANGE, format!("bytes */{size}")),
            (header::ACCEPT_RANGES, String::from("bytes")),
        ],
    )
        .into_response()
}

/// Parse a PATCH `Content-Range: bytes start-end/*` header into an inclusive
/// [`ChunkRange`]. The total is `*` on the upload path (the size is only known
/// at commit); a numeric total is tolerated and ignored. Malformed input —
/// wrong unit, missing `-`/`/`, non-numeric bounds, or `end < start` — yields
/// `None` (→ 400).
fn parse_content_range(value: Option<&HeaderValue>) -> Option<ChunkRange> {
    let raw = value?.to_str().ok()?.trim();
    let spec = raw
        .strip_prefix("bytes ")
        .or_else(|| raw.strip_prefix("bytes="))?;
    let (range_part, total_part) = spec.split_once('/')?;
    let total = total_part.trim();
    if total != "*" && (total.is_empty() || !total.bytes().all(|b| b.is_ascii_digit())) {
        return None;
    }
    let (start_raw, end_raw) = range_part.split_once('-')?;
    let start = start_raw.trim().parse::<u64>().ok()?;
    let end = end_raw.trim().parse::<u64>().ok()?;
    (end >= start).then_some(ChunkRange { start, end })
}

/// Map a chunk-staging `io::Error` to its HTTP contract: 404 unknown/expired
/// reservation, 409 already-complete entry, 400 overlap/length, 500 otherwise.
fn chunk_error(err: io::Error) -> Response {
    match err.kind() {
        io::ErrorKind::NotFound => ApiError::not_found().into_response(),
        io::ErrorKind::AlreadyExists => ApiError::Conflict(err.to_string()).into_response(),
        io::ErrorKind::InvalidInput => ApiError::BadRequest(err.to_string()).into_response(),
        _ => {
            tracing::error!(error = %err, "v1 patch: chunk staging failed");
            ApiError::Internal.into_response()
        }
    }
}

/// Map a commit `io::Error` to its HTTP contract: 404 unknown/expired
/// reservation, 409 already-complete entry, 400 size mismatch, 500 otherwise.
fn commit_error(err: io::Error) -> Response {
    match err.kind() {
        io::ErrorKind::NotFound => ApiError::not_found().into_response(),
        io::ErrorKind::AlreadyExists => ApiError::Conflict(err.to_string()).into_response(),
        io::ErrorKind::InvalidInput => ApiError::BadRequest(err.to_string()).into_response(),
        _ => {
            tracing::error!(error = %err, "v1 commit: assembly failed");
            ApiError::Internal.into_response()
        }
    }
}

/// Whether a download must present a signed URL: bearer/merge auth or any
/// cluster deployment. Pure HMAC single-node serving relies on the HMAC gate.
fn requires_signed_url(state: &AppState) -> bool {
    state.auth.cluster_enabled || matches!(state.auth.mode, AuthMode::Bearer | AuthMode::Merge)
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

    #[test]
    fn content_range_accepts_star_total_and_inclusive_bounds() {
        let h = |s: &str| HeaderValue::from_str(s).expect("header value");
        assert_eq!(
            parse_content_range(Some(&h("bytes 0-4194303/*"))),
            Some(ChunkRange {
                start: 0,
                end: 4194303
            })
        );
        assert_eq!(
            parse_content_range(Some(&h("bytes=4194304-8388607/*"))),
            Some(ChunkRange {
                start: 4194304,
                end: 8388607
            })
        );
        assert_eq!(
            parse_content_range(Some(&h("bytes 5-5/*"))),
            Some(ChunkRange { start: 5, end: 5 })
        );
        // A numeric total is tolerated (the upload path only knows it at commit).
        assert_eq!(
            parse_content_range(Some(&h("bytes 0-99/100"))),
            Some(ChunkRange { start: 0, end: 99 })
        );
    }

    #[test]
    fn content_range_rejects_malformed_forms() {
        let h = |s: &str| HeaderValue::from_str(s).expect("header value");
        assert_eq!(parse_content_range(None), None);
        assert_eq!(parse_content_range(Some(&h("items 0-1/*"))), None);
        assert_eq!(parse_content_range(Some(&h("bytes 0-1"))), None);
        assert_eq!(parse_content_range(Some(&h("bytes 0/*"))), None);
        assert_eq!(parse_content_range(Some(&h("bytes a-b/*"))), None);
        assert_eq!(parse_content_range(Some(&h("bytes 5-4/*"))), None);
        assert_eq!(parse_content_range(Some(&h("bytes 0-1/abc"))), None);
    }
}
