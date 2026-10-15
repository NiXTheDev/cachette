//! Pin-gated peer endpoints that receive a forwarded v1 upload (plan task 31).
//!
//! The entry node A ([`crate::cluster::relay`]) forwards a cluster-mode
//! artifactcache reservation, its PATCH chunks, and its commit to the owner B
//! over mTLS. These handlers run on B, behind the `require_pinned_peer` layer
//! (only a certificate whose SPKI fingerprint is pinned may call them), and
//! drive B's local [`StorageBackend`](crate::storage::StorageBackend):
//!
//! * `POST /_internal/peers/reserve` — M10 duplicate check, then a fresh
//!   **live** B3 admission re-check (M15): below the free-space floor the
//!   owner refuses with `503 {"error":"insufficient capacity"}` (never 429 —
//!   M1) so A can retry the next healthy peer. On accept B issues its own
//!   numeric `cacheId`.
//! * `PUT /_internal/peers/upload/{cacheId}?offset=<start>` — one chunk body,
//!   written to B's local parts directory. B reconstructs the inclusive range
//!   from `offset` + the body length.
//! * `POST /_internal/peers/commit/{cacheId}` `{size, key?}` — verify + publish
//!   the entry. Idempotent: a repeat whose reservation B already published (the
//!   finalize deleted the reservation) succeeds when a size-matched finalized
//!   entry for `key` exists.

use std::io::Cursor;

use axum::Json;
use axum::body::{Body, to_bytes};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

use crate::error::ApiError;
use crate::state::AppState;
use crate::storage::eviction::Capacity;
use crate::storage::{Chunk, ChunkRange, normalize_key};

/// `POST /_internal/peers/reserve` request body.
#[derive(serde::Deserialize)]
pub(crate) struct ReserveBody {
    key: String,
    version: String,
    /// Declared size when known; v1 reserve omits it, so admission falls back
    /// to the `min_free` floor.
    #[serde(default)]
    size: Option<u64>,
}

/// `POST /_internal/peers/reserve` — accept a forwarded reservation.
///
/// 200 `{"cacheId":<n>,"cacheSize":<n>}` on accept; 409 with the GitHub
/// duplicate body when B already holds `(key, version)`; 503
/// `{"error":"insufficient capacity"}` when B is below its free-space floor.
pub(crate) async fn reserve(
    State(state): State<AppState>,
    Json(body): Json<ReserveBody>,
) -> Response {
    let Some(storage) = state.storage.as_deref() else {
        return ApiError::Unavailable(String::from("storage backend not configured"))
            .into_response();
    };
    let key = normalize_key(&body.key, state.cache.key_case);
    match storage.stat(&key).await {
        Ok(Some(_)) => return super::v1::duplicate_response(&body.key),
        Ok(None) => {}
        Err(err) => {
            tracing::error!(error = %err, "peer reserve: duplicate check failed");
            return ApiError::Internal.into_response();
        }
    }
    let used = match storage.used_bytes().await {
        Ok(used) => used,
        Err(err) => {
            tracing::error!(error = %err, "peer reserve: usage accounting failed");
            return ApiError::Internal.into_response();
        }
    };
    // M15: the owner re-checks its OWN live admission at accept time — a stale
    // placement estimate must never let an over-floor reservation through.
    let capacity = Capacity::resolve(
        state.cache.min_free,
        state.cache.max_size,
        state.capacity_total,
        used,
    );
    if !capacity.admits(body.size) {
        tracing::debug!(
            free = capacity.free(),
            min_free = capacity.min_free,
            "peer reserve: refusing (below free-space floor)"
        );
        return ApiError::Unavailable(String::from("insufficient capacity")).into_response();
    }
    let cache_id = super::v1::generate_cache_id(&key, &body.version);
    let cache_id_key = cache_id.to_string();
    let expires_at = u64::try_from(crate::auth::now_secs())
        .unwrap_or(0)
        .saturating_add(state.cache.reservation_ttl_seconds);
    if let Err(err) = storage
        .reserve(&cache_id_key, &key, &body.version, expires_at)
        .await
    {
        tracing::error!(error = %err, "peer reserve: staging reservation failed");
        return ApiError::Internal.into_response();
    }
    let cache_size = state.cache.max_size.saturating_sub(used);
    Json(json!({"cacheId": cache_id, "cacheSize": cache_size})).into_response()
}

/// `PUT /_internal/peers/upload/{cacheId}?offset=<start>` query parameters.
#[derive(serde::Deserialize)]
pub(crate) struct UploadParams {
    offset: u64,
}

/// `PUT /_internal/peers/upload/{cacheId}?offset=<start>` — stage one forwarded
/// chunk. 204 on success; the same status contract as the v1 PATCH path
/// (404/409/400/500) for the owner-local reservation state.
pub(crate) async fn upload(
    State(state): State<AppState>,
    Path(cache_id): Path<String>,
    Query(params): Query<UploadParams>,
    body: Body,
) -> Response {
    let Some(storage) = state.storage.as_deref() else {
        return ApiError::Unavailable(String::from("storage backend not configured"))
            .into_response();
    };
    let limit = usize::try_from(super::v1::MAX_CHUNK_BYTES).unwrap_or(usize::MAX);
    let bytes = match to_bytes(body, limit).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return ApiError::BadRequest(String::from("chunk body could not be read"))
                .into_response();
        }
    };
    if bytes.is_empty() {
        return ApiError::BadRequest(String::from("chunk body was empty")).into_response();
    }
    // Reconstruct the inclusive range from the byte offset + body length: the
    // v1 PATCH contract always sends contiguous bytes for one range.
    let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    let range = ChunkRange {
        start: params.offset,
        end: params.offset.saturating_add(len).saturating_sub(1),
    };
    let chunk = Chunk {
        range,
        body: Box::pin(Cursor::new(bytes)),
    };
    match storage.write_chunk(&cache_id, chunk).await {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => super::v1::chunk_error(err),
    }
}

/// `POST /_internal/peers/commit/{cacheId}` request body.
#[derive(serde::Deserialize)]
pub(crate) struct CommitBody {
    size: u64,
    /// Artifact key, so a repeat commit can recognise the already-published
    /// entry after the reservation row was removed by the first commit.
    #[serde(default)]
    key: Option<String>,
}

/// `POST /_internal/peers/commit/{cacheId}` — verify + publish a forwarded
/// upload. 204 when B publishes (or already published) the entry; 404/400/409
/// mirror the v1 commit contract.
pub(crate) async fn commit(
    State(state): State<AppState>,
    Path(cache_id): Path<String>,
    Json(body): Json<CommitBody>,
) -> Response {
    let Some(storage) = state.storage.as_deref() else {
        return ApiError::Unavailable(String::from("storage backend not configured"))
            .into_response();
    };
    match storage.commit_chunks(&cache_id, body.size).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            // Idempotency: a repeat forward after B already published the entry
            // finds no reservation but a size-matched finalized entry under the
            // artifact key — treat it as success (commit is idempotent by
            // cacheId).
            if let Some(raw_key) = body.key.as_deref() {
                let key = normalize_key(raw_key, state.cache.key_case);
                if let Ok(Some(stat)) = storage.stat(&key).await
                    && stat.size == body.size
                {
                    return StatusCode::NO_CONTENT.into_response();
                }
            }
            ApiError::not_found().into_response()
        }
        Err(err) => super::v1::commit_error(err),
    }
}
