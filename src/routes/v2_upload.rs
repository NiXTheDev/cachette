//! Azure Blob "Put Block" / "Put Block List" emulation (plan task 25).
//!
//! The v2 `CreateCacheEntry` response (task 24) mints a `signedUploadUrl` at
//! exactly `/v2/upload/{entryId}?id=<id>&exp=<unix>&mac=<hex>`. The runner's
//! block-blob client then drives the Azure upload protocol against that URL:
//!
//! - `PUT /v2/upload/{entryId}?comp=block&blockid=<base64>` — stage one named
//!   block. `blockid` base64-decodes to exactly 48 or 64 bytes; anything else
//!   is a 400. 201 with an empty body.
//! - `PUT /v2/upload/{entryId}?comp=blocklist` — assemble the listed blocks in
//!   document order into the final blob and publish it (B5 ordering: blob
//!   file, then the index row). 201 with an empty body and a non-empty
//!   `x-ms-request-id`. The `<BlockList>` XML is accepted from EITHER the
//!   `blocklist=<urlencoded XML>` query parameter (the cachette-native form
//!   task 25 minted) OR the request BODY: the real Azure SDK /
//!   go-actions-cache client sends `comp=blocklist` with the XML in the body
//!   (and no `blocklist` query parameter — see `azblob`
//!   `commitBlockListCreateRequest`). Body form takes effect only when the
//!   query parameter is absent, so the existing contract is unchanged.
//! - `PUT /v2/upload/{entryId}` with no `comp` (Azure "Put Blob") — the whole
//!   blob in one request. This is what the real client uses for payloads
//!   smaller than one 1 MiB block. The body is staged as a single synthetic
//!   block and immediately assembled, so the entry publishes under the
//!   artifact key just like the block-list path. A bodiless no-comp PUT stays
//!   the historical 201 no-op.
//! - Any OTHER `comp` with a request body — 400 (a body on an unsupported
//!   `comp` is a protocol error). A bodyless no-op is accepted as 201.
//!
//! Every request is authorized by the signed capability URL alone (the path
//! `/v2/upload/{entryId}` is bound into the MAC): a missing, tampered, or
//! expired URL maps to 403 `{"error":"invalid or expired url"}`. An unknown
//! `entryId` (no open reservation) maps to 404.
//!
//! Routing: the route is registered at exactly `/v2/upload/{entryId}` — the
//! path task 24 mints and binds into the MAC. Optional Azure account/container
//! path segments (`/devstoreaccount1/<container>/v2/upload/...`) are NOT
//! required by the runner and are therefore not accepted (they would not match
//! the route and would fall through to the JSON 404). The minted URL is used
//! verbatim by the client.

use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::body::{Body, Bytes, to_bytes};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};

use crate::auth::{self, urls};
use crate::error::ApiError;
use crate::state::AppState;
use crate::storage::{ByteStream, StorageBackend};

/// Azure response header echoing a per-request id.
const REQUEST_ID_HEADER: &str = "x-ms-request-id";

/// A block id must base64-decode to exactly this many bytes (Azure spec).
const BLOCK_ID_LENGTHS: [usize; 2] = [48, 64];

/// Synthetic block token under which a bare Azure "Put Blob" body (no `comp`)
/// is staged before being assembled in one shot.
const PUT_BLOB_BLOCK_ID: &str = "putblob";

/// `PUT /v2/upload/{entryId}` — Azure block-blob upload emulation.
pub async fn upload(
    State(state): State<AppState>,
    Path(entry_id): Path<String>,
    Query(query): Query<HashMap<String, String>>,
    body: Body,
) -> Response {
    let Some(storage) = state.storage.as_deref() else {
        return ApiError::Unavailable(String::from("storage backend not configured"))
            .into_response();
    };
    // The MAC binds the exact resource path task 24 minted, reconstructed from
    // the route param (so it can never be spoofed by a traversal-style path).
    let path = format!("/v2/upload/{entry_id}");
    let policy = state.auth();
    let secret = super::signing_secret(&policy);
    if let Err(err) = urls::validate(&query, &path, secret, auth::now_secs()) {
        return ApiError::from(err).into_response();
    }
    let max_bytes = usize::try_from(state.cache_limits().max_chunk_bytes).unwrap_or(usize::MAX);
    match query.get("comp").map(String::as_str) {
        Some("block") => stage_block(storage, &entry_id, &query, body, max_bytes).await,
        Some("blocklist") => commit_block_list(&state, &entry_id, &query, body, max_bytes).await,
        None => put_blob(&state, &entry_id, body, max_bytes).await,
        Some(_) => unsupported_comp(body, max_bytes).await,
    }
}

/// `comp=block`: validate and stage one named block.
async fn stage_block(
    storage: &dyn StorageBackend,
    entry_id: &str,
    query: &HashMap<String, String>,
    body: Body,
    max_bytes: usize,
) -> Response {
    let Some(raw) = query.get("blockid").filter(|value| !value.is_empty()) else {
        return ApiError::BadRequest(String::from("blockid query parameter is required"))
            .into_response();
    };
    let Some(decoded) = decode_block_id(raw) else {
        return ApiError::BadRequest(String::from("blockid is not valid base64")).into_response();
    };
    if !BLOCK_ID_LENGTHS.contains(&decoded.len()) {
        return ApiError::BadRequest(String::from(
            "blockid must base64-decode to exactly 48 or 64 bytes",
        ))
        .into_response();
    }
    let block_id = to_hex(&decoded);
    let bytes = match read_body(body, max_bytes).await {
        Ok(bytes) => bytes,
        Err(err) => return err.into_response(),
    };
    let stream: ByteStream<'_> = Box::pin(std::io::Cursor::new(bytes));
    match storage.put_block(entry_id, &block_id, stream).await {
        Ok(()) => created(),
        Err(err) => storage_error(err),
    }
}

/// `comp=blocklist`: assemble the listed blocks (in order) and publish.
///
/// The `<BlockList>` XML comes from the `blocklist` query parameter when
/// present (cachette-native form) and otherwise from the request BODY — the
/// shape the real Azure SDK / go-actions-cache v2 client sends.
async fn commit_block_list(
    state: &AppState,
    entry_id: &str,
    query: &HashMap<String, String>,
    body: Body,
    max_bytes: usize,
) -> Response {
    let Some(storage) = state.storage.as_deref() else {
        return ApiError::Unavailable(String::from("storage backend not configured"))
            .into_response();
    };
    let xml = match query.get("blocklist").filter(|value| !value.is_empty()) {
        Some(xml) => xml.clone(),
        None => match read_body(body, max_bytes).await {
            Ok(bytes) if bytes.is_empty() => {
                return ApiError::BadRequest(String::from("blocklist query parameter is required"))
                    .into_response();
            }
            Ok(bytes) => match String::from_utf8(bytes.to_vec()) {
                Ok(xml) => xml,
                Err(_) => {
                    return ApiError::BadRequest(String::from("blocklist XML is not valid UTF-8"))
                        .into_response();
                }
            },
            Err(err) => return err.into_response(),
        },
    };
    let block_ids = match parse_block_list(&xml) {
        Ok(ids) if !ids.is_empty() => ids,
        Ok(_) => {
            return ApiError::BadRequest(String::from("blocklist lists no blocks")).into_response();
        }
        Err(()) => {
            return ApiError::BadRequest(String::from("malformed blocklist XML")).into_response();
        }
    };
    match storage.assemble_blocks(entry_id, &block_ids).await {
        Ok(_size) => {
            state.metrics.add_reservations(-1);
            if let Ok(used) = storage.used_bytes().await {
                state.metrics.set_storage_used(used);
            }
            created()
        }
        Err(err) => storage_error(err),
    }
}

/// Bare `PUT /v2/upload/{entryId}` (Azure "Put Blob"): the whole blob in one
/// request, which the real client uses for payloads under one 1 MiB block.
/// The body is staged under a synthetic block token and immediately assembled,
/// so it publishes under the artifact key exactly like the block-list path.
/// A bodiless request stays the historical 201 no-op.
async fn put_blob(state: &AppState, entry_id: &str, body: Body, max_bytes: usize) -> Response {
    let Some(storage) = state.storage.as_deref() else {
        return ApiError::Unavailable(String::from("storage backend not configured"))
            .into_response();
    };
    let bytes = match read_body(body, max_bytes).await {
        Ok(bytes) => bytes,
        Err(err) => return err.into_response(),
    };
    if bytes.is_empty() {
        return created();
    }
    let block_id = PUT_BLOB_BLOCK_ID.to_owned();
    let stream: ByteStream<'_> = Box::pin(std::io::Cursor::new(bytes));
    if let Err(err) = storage.put_block(entry_id, &block_id, stream).await {
        return storage_error(err);
    }
    match storage
        .assemble_blocks(entry_id, std::slice::from_ref(&block_id))
        .await
    {
        Ok(_size) => {
            state.metrics.add_reservations(-1);
            if let Ok(used) = storage.used_bytes().await {
                state.metrics.set_storage_used(used);
            }
            created()
        }
        Err(err) => storage_error(err),
    }
}

/// Any `comp` other than `block`/`blocklist`: a request body makes it a
/// protocol error (400); a bodyless no-op is accepted as 201.
async fn unsupported_comp(body: Body, max_bytes: usize) -> Response {
    match read_body(body, max_bytes).await {
        Ok(bytes) if bytes.is_empty() => created(),
        Ok(_) => ApiError::BadRequest(String::from("unsupported comp carries a request body"))
            .into_response(),
        Err(err) => err.into_response(),
    }
}

/// Buffer the request body, bounded by `limit` — the configured
/// `[server] max_chunk_bytes` (plan task 45). The `blocklist` XML and
/// `put_blob` bodies are inherently whole-document reads; `put_block` stages
/// whatever buffer it is handed without a second copy.
async fn read_body(body: Body, limit: usize) -> Result<Bytes, ApiError> {
    to_bytes(body, limit)
        .await
        .map_err(|_| ApiError::BadRequest(String::from("request body could not be read")))
}

/// 201 with an empty body and a fresh `x-ms-request-id`.
fn created() -> Response {
    let mut response = StatusCode::CREATED.into_response();
    response.headers_mut().insert(
        HeaderName::from_static(REQUEST_ID_HEADER),
        HeaderValue::from_str(&generate_request_id())
            .expect("hex request id is always a valid header value"),
    );
    response
}

/// Map a storage `io::Error` to its HTTP contract: 404 unknown/expired
/// reservation, 409 already-complete entry, 400 unknown block, 500 otherwise.
fn storage_error(err: io::Error) -> Response {
    match err.kind() {
        io::ErrorKind::NotFound => ApiError::not_found().into_response(),
        io::ErrorKind::AlreadyExists => ApiError::Conflict(err.to_string()).into_response(),
        io::ErrorKind::InvalidInput => ApiError::BadRequest(err.to_string()).into_response(),
        _ => {
            tracing::error!(error = %err, "v2 upload: storage failure");
            ApiError::Internal.into_response()
        }
    }
}

/// Parse a `<BlockList>` document, returning each listed block id (lowercase
/// hex) in DOCUMENT ORDER. Both `<Latest>` and `<Committed>` entries are
/// accepted; the id inside each element is base64 in either alphabet.
fn parse_block_list(xml: &str) -> Result<Vec<String>, ()> {
    let mut block_ids = Vec::new();
    let mut rest = xml;
    loop {
        let next = match (rest.find("<Latest>"), rest.find("<Committed>")) {
            (Some(latest), Some(committed)) if latest <= committed => Some(("Latest", 8, latest)),
            (Some(latest), None) => Some(("Latest", 8, latest)),
            (Some(_), Some(committed)) => Some(("Committed", 11, committed)),
            (None, Some(committed)) => Some(("Committed", 11, committed)),
            (None, None) => None,
        };
        let Some((tag, open_len, start)) = next else {
            break;
        };
        let after_open = &rest[start + open_len..];
        let close = format!("</{tag}>");
        let end = after_open.find(&close).ok_or(())?;
        let decoded = decode_block_id(&after_open[..end]).ok_or(())?;
        if !BLOCK_ID_LENGTHS.contains(&decoded.len()) {
            return Err(());
        }
        block_ids.push(to_hex(&decoded));
        rest = &after_open[end + close.len()..];
    }
    Ok(block_ids)
}

/// Decode an Azure `blockid` value: accepts the standard AND URL-safe base64
/// alphabets, with or without padding. The value may still carry percent
/// escapes (the query parser decodes `form-urlencoded`, but a client can
/// double-encode), and a literal `+` in a query value arrives as a space.
fn decode_block_id(raw: &str) -> Option<Vec<u8>> {
    let normalized = normalize_b64_value(raw)?;
    let trimmed = normalized.trim_end_matches('=');
    let url_safe = normalized.contains('-') || normalized.contains('_');
    let standard = normalized.contains('+') || normalized.contains('/');
    if url_safe && standard {
        // Mixed alphabets are not a valid base64 string.
        return None;
    }
    let engine = if url_safe {
        &URL_SAFE_NO_PAD
    } else {
        &STANDARD_NO_PAD
    };
    engine.decode(trimmed).ok()
}

/// Undo `form-urlencoded` `+`→space and any `%XX` escapes in a base64 value.
fn normalize_b64_value(raw: &str) -> Option<String> {
    let plus_fixed: String = raw
        .chars()
        .map(|ch| if ch == ' ' { '+' } else { ch })
        .collect();
    let src = plus_fixed.as_bytes();
    let mut bytes = Vec::with_capacity(src.len());
    let mut index = 0;
    while index < src.len() {
        if src[index] == b'%'
            && index + 2 < src.len()
            && let (Some(hi), Some(lo)) = (hex_value(src[index + 1]), hex_value(src[index + 2]))
        {
            bytes.push((hi << 4) | lo);
            index += 3;
            continue;
        }
        bytes.push(src[index]);
        index += 1;
    }
    String::from_utf8(bytes).ok()
}

/// Numeric value of one ASCII hex digit.
fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Lowercase-hex a byte slice (the filesystem-safe block token).
fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Generate a non-empty, practically unique `x-ms-request-id`. No `uuid`/`rand`
/// dependency is available, so this reuses the FNV-1a + splitmix64 scheme
/// `twirp.rs`/`v1.rs` use, over `now|sequence`.
fn generate_request_id() -> String {
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let mut input = Vec::with_capacity(16);
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
