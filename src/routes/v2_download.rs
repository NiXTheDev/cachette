//! v2 artifact download (`GET /v2/artifacts/{entryId}`) (plan task 26).
//!
//! `GetCacheEntryDownloadURL` mints a signed capability URL at exactly
//! `/v2/artifacts/{entryId}?id=<id>&exp=<unix>&mac=<hex>`, where `entryId` is
//! the matched entry's ARTIFACT KEY (the B5 commit publishes each entry under
//! that key). This handler mirrors the v1 download
//! ([`crate::routes::v1::download`]):
//!
//! - the request is authorized by the signed URL ALONE (the path
//!   `/v2/artifacts/{entryId}` is bound into the MAC); a missing, tampered, or
//!   expired URL maps to 403 `{"error":"invalid or expired url"}`;
//! - a missing (or not-yet-complete) entry maps to 404;
//! - no range → 200 with the full body; a byte range → 206 with the exact
//!   slice and `Content-Range: bytes a-b/<size>`; an unsatisfiable range
//!   → 416 with `Content-Range: bytes */<size>`. Both the standard `Range`
//!   header and Azure's `x-ms-range` are honoured (`x-ms-range` wins when both
//!   are present, matching the Azure Blob service): the Azure SDK /
//!   go-actions-cache v2 client sets `x-ms-range`, NOT `Range`, on every
//!   ranged `DownloadStream`.
//!
//! Cluster seam (plan tasks 31/32): single-node serving reads local storage; in
//! cluster mode the owning node may be a peer and task 32 forwards/replicates
//! the read (the URL already points at `server.external_url`).

use std::collections::HashMap;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};

use crate::auth::{self, urls};
use crate::error::ApiError;
use crate::state::AppState;

use super::v1::{parse_range, range_not_satisfiable, read_range};

/// `GET /v2/artifacts/{entryId}?id&exp&mac` — signed, ranged artifact download.
pub async fn download(
    State(state): State<AppState>,
    Path(entry_id): Path<String>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let Some(storage) = state.storage.as_deref() else {
        return ApiError::Unavailable(String::from("storage backend not configured"))
            .into_response();
    };
    // The MAC binds the exact resource path, reconstructed from the route param
    // (so a traversal-style path can never spoof it).
    let path = format!("/v2/artifacts/{entry_id}");
    let policy = state.auth();
    if let Err(err) = urls::validate(
        &query,
        &path,
        super::signing_secret(&policy),
        auth::now_secs(),
    ) {
        return ApiError::from(err).into_response();
    }
    if policy.cluster_enabled {
        tracing::debug!(
            entry_id = %entry_id,
            "v2 download: cluster mode (peer forwarding wired in task 32)"
        );
    }
    let size = match storage.stat(&entry_id).await {
        Ok(Some(stat)) => stat.size,
        Ok(None) => return ApiError::not_found().into_response(),
        Err(err) => {
            tracing::error!(error = %err, "v2 download: stat failed");
            return ApiError::Internal.into_response();
        }
    };
    // Prefer Azure's `x-ms-range` (what the SDK sends) and fall back to the
    // standard `Range`. Azure uses `x-ms-range` when both are present.
    let range = headers
        .get("x-ms-range")
        .or_else(|| headers.get(header::RANGE))
        .and_then(|value| value.to_str().ok());
    match range {
        None => match read_range(storage, &entry_id, 0..size).await {
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
            let Some(bytes) = read_range(storage, &entry_id, start..end + 1).await else {
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
