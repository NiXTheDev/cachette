//! Storage abstraction (plan task 8).
//!
//! [`StorageBackend`] is the object-safe seam between the HTTP layers and
//! whatever holds the bytes: the node-local FS backend ([`fs::FsStorage`],
//! plan task 9) or the in-memory double ([`MemoryStorage`]) used by unit and
//! handler tests.
//!
//! Semantics (plan m4 + B5):
//! - `put_stream` stages bytes under an opaque key; nothing is visible to
//!   `get_range`/`stat`/`list` until `finalize` flips the entry visible —
//!   the atomic-commit seam. B5 commit ordering itself lives in the FS
//!   backend (parts → blob rename → index commit).
//! - Dropping the future returned by `put_stream` cancels the put with no
//!   partial visibility (cancel-safe).
//! - Keys are opaque strings — no POSIX coupling. Callers apply
//!   [`normalize_key`] with the configured [`KeyCase`] before reserving;
//!   storage itself is case-agnostic. Restore-time selection (plan task 10)
//!   lives in [`lookup`], which folds the request keys itself and enforces
//!   exact-then-ordered-prefix semantics.
//! - Multipart/ETag helpers are intentionally omitted (plan m4); they can
//!   be layered on later without changing this trait.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::ops::Range;
use std::pin::Pin;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::sync::RwLock;

use crate::config::KeyCase;

pub mod eviction;
pub mod fs;

/// Boxed future used by [`StorageBackend`] so the trait stays
/// dyn-compatible (`Arc<dyn StorageBackend>`) without an `async-trait`
/// dependency — native async fns in traits are not object-safe.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Streaming byte source for [`StorageBackend`] put/get handles.
pub type ByteStream<'a> = Pin<Box<dyn AsyncRead + Send + 'a>>;

/// Metadata for one visible entry (plan m4 `EntryStat`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EntryStat {
    /// Opaque storage key.
    pub key: String,
    /// Total size in bytes.
    pub size: u64,
    /// Unix seconds the entry became visible (finalize time).
    pub created_at: u64,
    /// Unix seconds of the last ranged read (LRU input, plan task 11).
    pub accessed_at: u64,
}

/// Entry row shared by the FS backend and its metadata index (plan task 9
/// schema, minus the cluster/lease columns added by later tasks).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Entry {
    /// Opaque storage key.
    pub key: String,
    /// Protocol version marker (exact-match filter; never normalized).
    pub version: String,
    /// Total size in bytes.
    pub size: u64,
    /// Unix seconds.
    pub created_at: u64,
    /// Unix seconds.
    pub accessed_at: u64,
    /// `false` while staged, `true` once finalized/visible.
    pub complete: bool,
}

/// Protocol version marker stored with an entry. Exact-match only — never
/// key-normalized (plan task 10 lookup semantics).
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Hash)]
pub struct Version(pub String);

impl Version {
    /// Borrow the raw version string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<String> for Version {
    fn from(raw: String) -> Self {
        Self(raw)
    }
}

impl From<&str> for Version {
    fn from(raw: &str) -> Self {
        Self(raw.to_owned())
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Normalize a cache key per `[cache] key_case` (plan tasks 8/10): `Lower`
/// lowercases ASCII only, `Preserve` returns the key unchanged.
#[must_use]
pub fn normalize_key(key: &str, case: KeyCase) -> String {
    match case {
        KeyCase::Lower => key.to_ascii_lowercase(),
        KeyCase::Preserve => key.to_owned(),
    }
}

/// Ordered exact-then-prefix lookup over candidate entries (plan task 10).
///
/// Semantics (GitHub `restore-keys` ordering, Metis criterion 3):
/// 1. Normalize every requested key with `case` via [`normalize_key`] — the
///    same fold the reserve path applies to stored keys (M11).
/// 2. Exact phase: the newest entry whose key equals the FIRST requested key
///    and whose `version` equals `version` wins outright (exact beats prefix).
/// 3. Prefix phase (only after an exact miss): walk the requested keys in
///    sent order; the FIRST key with any prefix match wins — ordered
///    first-hit, not longest-prefix-maximal and not a union across keys.
///    Within that key's matched set the newest entry wins (`created_at`
///    DESC, `key` DESC as the deterministic stand-in for the plan's
///    `id DESC` tie-break: rows are unique per key).
/// 4. Nothing matched — or `keys` was empty — is a miss (`None`; the route
///    layer maps that to 204).
///
/// Matching is plain [`str::starts_with`] equality: no fuzzy or regex
/// patterns, and in [`KeyCase::Preserve`] a differently-cased query misses
/// on purpose. `version` filters both phases byte-exactly and is never
/// normalized regardless of `case`. Callers pass finalized entries; staged
/// rows are excluded by the backend queries feeding this function.
#[must_use]
pub fn lookup<'a, K: AsRef<str>>(
    entries: &'a [Entry],
    keys: &[K],
    version: &Version,
    case: KeyCase,
) -> Option<&'a Entry> {
    let normalized: Vec<String> = keys
        .iter()
        .map(|key| normalize_key(key.as_ref(), case))
        .collect();
    let first = normalized.first()?;

    if let Some(hit) = newest(
        entries
            .iter()
            .filter(|e| e.key == first.as_str() && e.version == version.as_str()),
    ) {
        return Some(hit);
    }

    for key in &normalized {
        if let Some(hit) = newest(
            entries
                .iter()
                .filter(|e| e.key.starts_with(key.as_str()) && e.version == version.as_str()),
        ) {
            return Some(hit);
        }
    }

    None
}

/// Newest entry in `candidates`: `created_at` DESC, then `key` DESC as a
/// deterministic tie-break for equal timestamps (see [`lookup`]).
fn newest<'a>(candidates: impl Iterator<Item = &'a Entry>) -> Option<&'a Entry> {
    candidates.max_by(|a, b| {
        a.created_at
            .cmp(&b.created_at)
            .then_with(|| a.key.cmp(&b.key))
    })
}

/// Inclusive byte range covered by one uploaded PATCH chunk (plan task 20).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChunkRange {
    /// First byte offset of the chunk (inclusive).
    pub start: u64,
    /// Last byte offset of the chunk (inclusive).
    pub end: u64,
}

impl ChunkRange {
    /// Number of bytes the range covers.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.end.saturating_sub(self.start).saturating_add(1)
    }

    /// Whether the range covers no bytes (`end < start`). The Content-Range
    /// parser never produces this, but callers get an honest predicate.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.end < self.start
    }

    /// Whether two inclusive ranges share at least one byte.
    #[must_use]
    pub fn overlaps(&self, other: &Self) -> bool {
        self.start <= other.end && other.start <= self.end
    }
}

/// Result of staging one PATCH chunk into a reservation (plan task 20).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChunkOutcome {
    /// The chunk was newly written.
    Written,
    /// The exact range was already present; nothing was written (resume).
    AlreadyPresent,
}

/// One inbound PATCH chunk: its inclusive byte range plus the body stream.
pub struct Chunk<'a> {
    /// Byte range this chunk covers.
    pub range: ChunkRange,
    /// Chunk body, streamed to disk by the storage backend.
    pub body: ByteStream<'a>,
}

/// Cluster relay seam for chunked PATCH (plan tasks 20/31).
///
/// The PATCH path never writes a chunk to disk directly; it hands the chunk to
/// a [`RelayTransport`]. The default implementation ([`LocalRelay`]) streams it
/// into the reservation owner's local parts directory. Plan task 31 supplies a
/// cluster implementation that forwards the chunk to the placement owner's
/// peer endpoint instead.
pub trait RelayTransport: Send + Sync {
    /// Relay `chunk` for reservation `cache_id` to whichever node owns it. The
    /// default single-node body writes it locally via
    /// [`StorageBackend::write_chunk`].
    fn stream_to_owner<'a>(
        &'a self,
        storage: &'a dyn StorageBackend,
        cache_id: &'a str,
        chunk: Chunk<'a>,
    ) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async move { storage.write_chunk(cache_id, chunk).await.map(|_| ()) })
    }
}

/// Single-node relay: writes each chunk into local storage. Cluster mode (plan
/// task 31) replaces this with a peer-forwarding implementation.
#[derive(Clone, Copy, Debug, Default)]
pub struct LocalRelay;

impl RelayTransport for LocalRelay {}

/// Node-local cache storage (plan task 8 / m4).
///
/// Keys are opaque strings; every method is async and object-safe so
/// `AppState` can hold `Arc<dyn StorageBackend>`.
// TODO(plan m4): multipart/ETag convenience methods intentionally omitted.
pub trait StorageBackend: Send + Sync {
    /// Stage `source`'s bytes under `key`. Cancel-safe: dropping the future
    /// leaves no staged or visible data for this put. Staged data replaces
    /// any previous staged data for `key` but stays invisible until
    /// [`Self::finalize`].
    fn put_stream<'a>(
        &'a self,
        key: &'a str,
        source: ByteStream<'a>,
    ) -> BoxFuture<'a, io::Result<()>>;

    /// Read `range` (start inclusive, end exclusive) of the finalized entry
    /// for `key` and bump its `accessed_at`. `Err(InvalidInput)` if
    /// `range.start > range.end` or past the end of the entry; `end` is
    /// clamped to the entry size. `Err(NotFound)` if the key is missing or
    /// staged-but-not-finalized.
    fn get_range<'a>(
        &'a self,
        key: &'a str,
        range: Range<u64>,
    ) -> BoxFuture<'a, io::Result<ByteStream<'a>>>;

    /// Remove both staged and visible data for `key`. Idempotent.
    fn delete<'a>(&'a self, key: &'a str) -> BoxFuture<'a, io::Result<()>>;

    /// Metadata for the finalized entry `key`, or `Ok(None)` if the key is
    /// missing or staged-but-not-finalized.
    fn stat<'a>(&'a self, key: &'a str) -> BoxFuture<'a, io::Result<Option<EntryStat>>>;

    /// Metadata for every finalized entry, sorted by key.
    fn list<'a>(&'a self) -> BoxFuture<'a, io::Result<Vec<EntryStat>>>;

    /// Make staged data for `key` visible (atomic-commit seam). Idempotent
    /// when the key is already visible and nothing new is staged;
    /// `Err(NotFound)` when there is neither staged nor visible data.
    fn finalize<'a>(&'a self, key: &'a str) -> BoxFuture<'a, io::Result<()>>;

    /// Accounted bytes of finalized entries only (plan B3 capacity input:
    /// `[cache] max_size - used_bytes`; reservations and staged data never
    /// count).
    fn used_bytes<'a>(&'a self) -> BoxFuture<'a, io::Result<u64>>;

    /// Stage an EMPTY reservation for `key` that stays invisible to
    /// [`Self::stat`]/[`Self::list`]/[`Self::get_range`] until
    /// [`Self::finalize`], stamped with `expires_at` (Unix seconds) so the
    /// reaper reclaims an abandoned reservation (plan task 19 / M4).
    /// Supersedes any staged data for `key`.
    fn reserve<'a>(&'a self, key: &'a str, expires_at: u64) -> BoxFuture<'a, io::Result<()>>;

    /// Stage one chunk of a chunked upload under the reservation `key`
    /// (plan task 20), addressing part files as `parts/{key}/{start}.part`.
    ///
    /// Error kinds the route layer maps to HTTP: `NotFound` when `key` is not
    /// an open reservation (unknown or expired) → 404; `AlreadyExists` when a
    /// finalized entry already holds `key` → 409; `InvalidInput` when `range`
    /// overlaps an already-staged chunk, or the body length disagrees with the
    /// range → 400. An exact re-PATCH is accepted without a write
    /// ([`ChunkOutcome::AlreadyPresent`]) so a resumed upload idempotently
    /// replays ranges.
    fn write_chunk<'a>(
        &'a self,
        key: &'a str,
        chunk: Chunk<'a>,
    ) -> BoxFuture<'a, io::Result<ChunkOutcome>>;
}

/// In-memory [`StorageBackend`] double for unit and handler tests:
/// concurrent-safe (`tokio::sync::RwLock`), no filesystem involvement.
#[derive(Debug, Default)]
pub struct MemoryStorage {
    inner: RwLock<MemoryState>,
}

#[derive(Debug, Default)]
struct MemoryState {
    /// Staged (put, not yet finalized) blobs.
    staged: HashMap<String, Staged>,
    /// Visible (finalized) blobs.
    visible: HashMap<String, Visible>,
    /// Open reservations: `key` → expiry (Unix seconds).
    reservations: HashMap<String, u64>,
    /// Chunk ranges already staged per reservation `key`.
    chunks: HashMap<String, Vec<ChunkRange>>,
}

#[derive(Debug)]
struct Staged {
    data: Vec<u8>,
    created_at: u64,
}

#[derive(Debug)]
struct Visible {
    data: Vec<u8>,
    created_at: u64,
    accessed_at: u64,
}

impl MemoryStorage {
    /// Fresh, empty storage.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl StorageBackend for MemoryStorage {
    fn put_stream<'a>(
        &'a self,
        key: &'a str,
        mut source: ByteStream<'a>,
    ) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async move {
            let mut data = Vec::new();
            source.read_to_end(&mut data).await?;
            let mut state = self.inner.write().await;
            state.staged.insert(
                key.to_owned(),
                Staged {
                    data,
                    created_at: unix_now(),
                },
            );
            Ok(())
        })
    }

    fn get_range<'a>(
        &'a self,
        key: &'a str,
        range: Range<u64>,
    ) -> BoxFuture<'a, io::Result<ByteStream<'a>>> {
        Box::pin(async move {
            if range.start > range.end {
                return Err(invalid_range("range start after end"));
            }
            let mut state = self.inner.write().await;
            let entry = state.visible.get_mut(key).ok_or_else(|| not_found(key))?;
            let size = entry.data.len() as u64;
            if range.start > size {
                return Err(invalid_range("range start past end of entry"));
            }
            let end = range.end.min(size);
            let bytes = entry.data[range.start as usize..end as usize].to_vec();
            entry.accessed_at = unix_now();
            let stream: ByteStream<'a> = Box::pin(std::io::Cursor::new(bytes));
            Ok(stream)
        })
    }

    fn delete<'a>(&'a self, key: &'a str) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async move {
            let mut state = self.inner.write().await;
            state.staged.remove(key);
            state.visible.remove(key);
            state.reservations.remove(key);
            state.chunks.remove(key);
            Ok(())
        })
    }

    fn stat<'a>(&'a self, key: &'a str) -> BoxFuture<'a, io::Result<Option<EntryStat>>> {
        Box::pin(async move {
            let state = self.inner.read().await;
            Ok(state.visible.get(key).map(|entry| EntryStat {
                key: key.to_owned(),
                size: entry.data.len() as u64,
                created_at: entry.created_at,
                accessed_at: entry.accessed_at,
            }))
        })
    }

    fn list<'a>(&'a self) -> BoxFuture<'a, io::Result<Vec<EntryStat>>> {
        Box::pin(async move {
            let state = self.inner.read().await;
            let mut entries: Vec<EntryStat> = state
                .visible
                .iter()
                .map(|(key, entry)| EntryStat {
                    key: key.clone(),
                    size: entry.data.len() as u64,
                    created_at: entry.created_at,
                    accessed_at: entry.accessed_at,
                })
                .collect();
            entries.sort_by(|a, b| a.key.cmp(&b.key));
            Ok(entries)
        })
    }

    fn finalize<'a>(&'a self, key: &'a str) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async move {
            let mut state = self.inner.write().await;
            match state.staged.remove(key) {
                Some(staged) => {
                    state.reservations.remove(key);
                    state.chunks.remove(key);
                    state.visible.insert(
                        key.to_owned(),
                        Visible {
                            data: staged.data,
                            created_at: staged.created_at,
                            accessed_at: staged.created_at,
                        },
                    );
                    Ok(())
                }
                // Idempotent commit of an already-visible key.
                None if state.visible.contains_key(key) => Ok(()),
                None => Err(not_found(key)),
            }
        })
    }

    fn used_bytes<'a>(&'a self) -> BoxFuture<'a, io::Result<u64>> {
        Box::pin(async move {
            let state = self.inner.read().await;
            let total = state
                .visible
                .values()
                .map(|entry| entry.data.len() as u64)
                .sum();
            Ok(total)
        })
    }

    fn reserve<'a>(&'a self, key: &'a str, expires_at: u64) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async move {
            let mut state = self.inner.write().await;
            state.reservations.insert(key.to_owned(), expires_at);
            state.chunks.remove(key);
            state.staged.insert(
                key.to_owned(),
                Staged {
                    data: Vec::new(),
                    created_at: unix_now(),
                },
            );
            Ok(())
        })
    }

    fn write_chunk<'a>(
        &'a self,
        key: &'a str,
        chunk: Chunk<'a>,
    ) -> BoxFuture<'a, io::Result<ChunkOutcome>> {
        Box::pin(async move {
            let mut state = self.inner.write().await;
            if state.visible.contains_key(key) {
                return Err(complete(key));
            }
            match state.reservations.get(key).copied() {
                None => return Err(not_found(key)),
                Some(expires_at) if expires_at <= unix_now() => {
                    state.reservations.remove(key);
                    return Err(not_found(key));
                }
                Some(_) => {}
            }
            let ranges = state.chunks.entry(key.to_owned()).or_default();
            for existing in ranges.iter() {
                if *existing == chunk.range {
                    return Ok(ChunkOutcome::AlreadyPresent);
                }
                if existing.overlaps(&chunk.range) {
                    return Err(invalid_range("chunk overlaps an already-received range"));
                }
            }
            ranges.push(chunk.range);
            Ok(ChunkOutcome::Written)
        })
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

pub(crate) fn not_found(key: &str) -> io::Error {
    io::Error::new(io::ErrorKind::NotFound, format!("no such key: {key}"))
}

pub(crate) fn invalid_range(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg.to_owned())
}

pub(crate) fn complete(key: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::AlreadyExists,
        format!("cache entry already complete: {key}"),
    )
}

#[cfg(test)]
mod trait_contract {
    use std::io::Cursor;
    use std::sync::Arc;

    use tokio::io::AsyncReadExt;

    use super::*;

    fn bytes(data: &[u8]) -> ByteStream<'static> {
        Box::pin(Cursor::new(data.to_vec()))
    }

    async fn read_all(mut stream: ByteStream<'_>) -> Vec<u8> {
        let mut out = Vec::new();
        stream.read_to_end(&mut out).await.expect("read stream");
        out
    }

    #[tokio::test]
    async fn put_is_invisible_until_finalize_then_round_trips() {
        let storage = MemoryStorage::new();
        storage
            .put_stream("nginx-src-1.30.5", bytes(b"hello world"))
            .await
            .expect("put");

        assert_eq!(
            storage.stat("nginx-src-1.30.5").await.expect("stat"),
            None,
            "staged key must be invisible"
        );
        let err = storage
            .get_range("nginx-src-1.30.5", 0..11)
            .await
            .err()
            .expect("staged key unreadable");
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        assert!(storage.list().await.expect("list").is_empty());

        storage
            .finalize("nginx-src-1.30.5")
            .await
            .expect("finalize");

        let stat = storage
            .stat("nginx-src-1.30.5")
            .await
            .expect("stat")
            .expect("visible after finalize");
        assert_eq!(stat.key, "nginx-src-1.30.5");
        assert_eq!(stat.size, 11);

        let full = read_all(
            storage
                .get_range("nginx-src-1.30.5", 0..11)
                .await
                .expect("get full"),
        )
        .await;
        assert_eq!(full, b"hello world");

        let partial = read_all(
            storage
                .get_range("nginx-src-1.30.5", 0..5)
                .await
                .expect("get partial"),
        )
        .await;
        assert_eq!(partial, b"hello");

        let listed = storage.list().await.expect("list");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].key, stat.key);
        assert_eq!(listed[0].size, stat.size);
        assert!(listed[0].accessed_at >= stat.accessed_at);
    }

    #[tokio::test]
    async fn delete_removes_visible_and_staged_entries_and_is_idempotent() {
        let storage = MemoryStorage::new();
        storage.put_stream("gone", bytes(b"g")).await.expect("put");
        storage.finalize("gone").await.expect("finalize");
        storage
            .put_stream("staged", bytes(b"s"))
            .await
            .expect("put staged");

        storage.delete("gone").await.expect("delete visible");
        storage.delete("staged").await.expect("delete staged");
        storage.delete("missing").await.expect("idempotent delete");

        assert_eq!(storage.stat("gone").await.expect("stat"), None);
        assert!(storage.list().await.expect("list").is_empty());
        let err = storage
            .finalize("staged")
            .await
            .expect_err("staged deleted");
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[tokio::test]
    async fn finalize_is_idempotent_and_new_put_supersedes_after_refinalize() {
        let storage = MemoryStorage::new();
        storage.put_stream("k", bytes(b"v1")).await.expect("put");
        storage.finalize("k").await.expect("finalize");
        storage.finalize("k").await.expect("idempotent finalize");
        let v1 = read_all(storage.get_range("k", 0..2).await.expect("get")).await;
        assert_eq!(v1, b"v1");

        storage
            .put_stream("k", bytes(b"v2-longer"))
            .await
            .expect("reput");
        let still_v1 = read_all(storage.get_range("k", 0..2).await.expect("get")).await;
        assert_eq!(still_v1, b"v1", "staged replacement stays invisible");

        storage.finalize("k").await.expect("refinalize");
        let v2 = read_all(storage.get_range("k", 0..9).await.expect("get")).await;
        assert_eq!(v2, b"v2-longer");
        let stat = storage
            .stat("k")
            .await
            .expect("stat")
            .expect("entry after refinalize");
        assert_eq!(stat.size, 9);
    }

    #[tokio::test]
    async fn get_range_rejects_inverted_and_out_of_bounds_ranges() {
        let storage = MemoryStorage::new();
        storage
            .put_stream("k", bytes(b"0123456789"))
            .await
            .expect("put");
        storage.finalize("k").await.expect("finalize");

        // Struct spelling bypasses clippy::reversed_empty_ranges (which only
        // flags the `a..b` literal form) while still testing inverted input.
        let inverted = Range { start: 4, end: 2 };
        let err = storage
            .get_range("k", inverted)
            .await
            .err()
            .expect("inverted");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        let err = storage
            .get_range("k", 11..12)
            .await
            .err()
            .expect("past end");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);

        let clamped = read_all(storage.get_range("k", 8..99).await.expect("clamp")).await;
        assert_eq!(clamped, b"89");
        let empty = read_all(storage.get_range("k", 3..3).await.expect("empty")).await;
        assert!(empty.is_empty());
    }

    #[tokio::test]
    async fn finalize_unknown_key_reports_not_found() {
        let storage = MemoryStorage::new();
        let err = storage.finalize("nope").await.expect_err("missing");
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[tokio::test]
    async fn concurrent_puts_all_become_visible() {
        let storage = Arc::new(MemoryStorage::new());
        let mut handles = Vec::new();
        for i in 0..8 {
            let storage = Arc::clone(&storage);
            handles.push(tokio::spawn(async move {
                let key = format!("key-{i}");
                storage.put_stream(&key, bytes(b"x")).await.expect("put");
                storage.finalize(&key).await.expect("finalize");
            }));
        }
        for handle in handles {
            handle.await.expect("join");
        }
        assert_eq!(storage.list().await.expect("list").len(), 8);
    }

    #[test]
    fn normalize_key_lowercases_ascii_only_and_preserve_is_identity() {
        assert_eq!(normalize_key("MiXeD-Key", KeyCase::Lower), "mixed-key");
        assert_eq!(normalize_key("MiXeD-Key", KeyCase::Preserve), "MiXeD-Key");
        // Non-ASCII bytes are untouched by the Lower rule (ASCII-only).
        assert_eq!(normalize_key("ÄBC", KeyCase::Lower), "Äbc");
    }
}

#[cfg(test)]
mod lookup {
    use super::*;

    fn entry(key: &str, version: &str, created_at: u64) -> Entry {
        Entry {
            key: key.to_owned(),
            version: version.to_owned(),
            size: 1,
            created_at,
            accessed_at: created_at,
            complete: true,
        }
    }

    fn fixture() -> Vec<Entry> {
        vec![
            entry("nginx-src-1.30.5-extra", "2", 100),
            entry("nginx-src-1.30", "2", 200),
            entry("nginx-src-1.30.5", "2", 300),
        ]
    }

    #[test]
    fn criterion_a_exact_first_key_beats_prefix() {
        let entries = fixture();
        let keys = ["nginx-src-1.30.5", "nginx-src-1.30"];
        let hit = lookup(&entries, &keys, &Version::from("2"), KeyCase::Lower)
            .expect("exact hit on the first key");
        assert_eq!(hit.key, "nginx-src-1.30.5");
        assert_eq!(hit.created_at, 300);
    }

    #[test]
    fn exact_first_key_wins_over_newer_prefix_sibling() {
        let entries = vec![
            entry("nginx-src-1.30", "2", 100),
            entry("nginx-src-1.30.5", "2", 200),
        ];
        let keys = ["nginx-src-1.30"];
        let hit = lookup(&entries, &keys, &Version::from("2"), KeyCase::Lower)
            .expect("exact hit on the first key");
        assert_eq!(hit.key, "nginx-src-1.30");
        assert_eq!(hit.created_at, 100);
    }

    #[test]
    fn criterion_b_no_exact_first_restore_key_prefix_wins_newest() {
        let entries = fixture();
        let keys = ["nginx-src-1.30.4", "nginx-src-1.30"];
        let hit = lookup(&entries, &keys, &Version::from("2"), KeyCase::Lower)
            .expect("first restore key prefix hit");
        assert_eq!(hit.key, "nginx-src-1.30.5");
        assert_eq!(hit.created_at, 300);
    }

    #[test]
    fn criterion_c_ordered_first_hit_beats_longer_second_key() {
        let entries = fixture();
        let keys = ["nginx-src", "nginx-src-1.30.5-extra"];
        let hit = lookup(&entries, &keys, &Version::from("2"), KeyCase::Lower)
            .expect("prefix hit on the first key");
        assert_eq!(hit.key, "nginx-src-1.30.5");
        assert_eq!(hit.created_at, 300);
    }

    #[test]
    fn criterion_d_version_mismatch_misses_every_key_list() {
        let entries = fixture();
        let lists: [&[&str]; 3] = [
            &["nginx-src-1.30.5", "nginx-src-1.30"],
            &["nginx-src-1.30.4", "nginx-src-1.30"],
            &["nginx-src", "nginx-src-1.30.5-extra"],
        ];
        for keys in lists {
            assert!(
                lookup(&entries, keys, &Version::from("9"), KeyCase::Lower).is_none(),
                "version 9 must miss for {keys:?}"
            );
        }
    }

    #[test]
    fn lower_folds_query_but_preserve_misses_on_case_mismatch() {
        let entries = fixture();
        let folded = lookup(
            &entries,
            &["NGINX-SRC-1.30.5"],
            &Version::from("2"),
            KeyCase::Lower,
        )
        .expect("Lower folds the query key");
        assert_eq!(folded.key, "nginx-src-1.30.5");
        assert!(
            lookup(
                &entries,
                &["NGINX-SRC-1.30.5"],
                &Version::from("2"),
                KeyCase::Preserve,
            )
            .is_none(),
            "same key different case must miss in Preserve mode"
        );
        let folded_restore = lookup(
            &entries,
            &["NGINX-SRC"],
            &Version::from("2"),
            KeyCase::Lower,
        )
        .expect("Lower folds restore keys too");
        assert_eq!(folded_restore.key, "nginx-src-1.30.5");
    }

    #[test]
    fn non_ascii_case_uses_ascii_only_lowercasing() {
        let entries = vec![entry("Äbc", "2", 100)];
        let hit = lookup(&entries, &["ÄBC"], &Version::from("2"), KeyCase::Lower)
            .expect("Lower folds only the ASCII letters of the query");
        assert_eq!(hit.key, "Äbc");
        assert!(
            lookup(&entries, &["ÄBC"], &Version::from("2"), KeyCase::Preserve).is_none(),
            "Preserve compares bytes; ÄBC must not match Äbc"
        );
    }

    #[test]
    fn empty_key_list_is_a_miss() {
        let entries = fixture();
        let keys: [&str; 0] = [];
        assert!(
            lookup(&entries, &keys, &Version::from("2"), KeyCase::Lower).is_none(),
            "empty keys must miss"
        );
    }

    #[test]
    fn version_is_never_case_folded_by_key_case() {
        let entries = vec![entry("k", "V2", 100)];
        assert!(
            lookup(&entries, &["k"], &Version::from("v2"), KeyCase::Lower).is_none(),
            "version compares byte-exactly even under Lower"
        );
        assert!(
            lookup(&entries, &["k"], &Version::from("V2"), KeyCase::Lower).is_some(),
            "byte-exact version match"
        );
    }
}
