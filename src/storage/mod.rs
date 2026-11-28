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
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::sync::RwLock;

use crate::config::KeyCase;

pub mod azure;
pub mod blob;
pub mod cdc;
pub mod copyparty;
pub mod digest;
pub mod eviction;
pub mod fs;
pub mod ftp;
pub mod http;
pub mod s3;
pub mod sftp;
pub mod webdav;

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
    /// What this backend can do with payloads. Validation and the route layer
    /// ask this instead of switching on a config `type`.
    fn capabilities(&self) -> blob::Capabilities;

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

    /// Accounted bytes per namespace, sorted by namespace name (v1.2
    /// workstream F, `docs/shared-cache.md` §5): the admin-wide view quota
    /// eviction sweeps. Independent of the view this is called on.
    fn usage_by_namespace(&self) -> BoxFuture<'_, io::Result<Vec<(String, u64)>>>;

    /// Instance-local usage for eviction. Defaults to the global view for
    /// backends that do not share an index across instances.
    fn instance_usage_by_namespace(&self) -> BoxFuture<'_, io::Result<Vec<(String, u64)>>> {
        self.usage_by_namespace()
    }

    /// Accounted bytes of THIS view's namespace only (quota math and the v1
    /// `cacheSize` remaining-budget report).
    fn namespace_bytes(&self) -> BoxFuture<'_, io::Result<u64>>;

    /// Stage an EMPTY reservation named `cache_id` that stays invisible to
    /// [`Self::stat`]/[`Self::list`]/[`Self::get_range`] until it is published
    /// by [`Self::commit_chunks`] (plan task 21), stamped with `expires_at`
    /// (Unix seconds) so the reaper reclaims an abandoned reservation (plan
    /// task 19 / M4). `key` is the artifact key the reservation will publish
    /// under and `version` the protocol version marker stored with it; both are
    /// carried to commit so it can address the entry and supersede a same-key
    /// sibling. Supersedes any staged data for `cache_id`.
    fn reserve<'a>(
        &'a self,
        cache_id: &'a str,
        key: &'a str,
        version: &'a str,
        expires_at: u64,
    ) -> BoxFuture<'a, io::Result<()>>;

    /// Whether an OPEN (unfinalized) reservation for artifact `key` exists and
    /// has not expired at `now_unix` (v2 `CreateCacheEntry` duplicate rule,
    /// plan task 24: a concurrent same-key reserve must be rejected). Finalized
    /// entries are reported by [`Self::stat`], not here.
    fn reservation_exists<'a>(
        &'a self,
        key: &'a str,
        now_unix: u64,
    ) -> BoxFuture<'a, io::Result<bool>>;

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

    /// Assemble every chunk staged under reservation `cache_id` into the final
    /// blob and publish it under the reservation's artifact key (plan task 21).
    ///
    /// Verifies the staged chunks tile `[0, declared_size)` exactly — starting
    /// at 0, contiguous, total == `declared_size` — before writing any blob.
    /// Error kinds the route layer maps to HTTP: `NotFound` when `cache_id` is
    /// not an open reservation (unknown, committed, or expired) → 404;
    /// `InvalidInput` when the chunks do not match `declared_size` → 400, with
    /// the reservation marked for reaping. Publishing supersedes any existing
    /// visible entry sharing the artifact key (last-writer-wins; the
    /// [`StorageBackend`] contract keeps at most one visible entry per key).
    fn commit_chunks<'a>(
        &'a self,
        cache_id: &'a str,
        declared_size: u64,
    ) -> BoxFuture<'a, io::Result<()>>;

    /// Stage one named Azure "Put Block" block for reservation `cache_id`
    /// (plan task 25). `block_id` is a filesystem-safe caller-supplied token
    /// (the route layer lowercase-hex-encodes the decoded Azure `blockid`,
    /// which is exactly 48 or 64 bytes). Error kinds the route layer maps to
    /// HTTP: `NotFound` when `cache_id` is not an open reservation (unknown or
    /// expired) → 404; `AlreadyExists` when a finalized entry already holds
    /// `cache_id` → 409.
    fn put_block<'a>(
        &'a self,
        cache_id: &'a str,
        block_id: &'a str,
        source: ByteStream<'a>,
    ) -> BoxFuture<'a, io::Result<()>>;

    /// Assemble the blocks staged by [`Self::put_block`] for reservation
    /// `cache_id` in `ordered_block_ids` order and publish the result as a
    /// COMPLETE entry (plan task 25). Returns the assembled size.
    ///
    /// Error kinds the route layer maps to HTTP: `NotFound` when `cache_id` is
    /// not an open reservation (unknown or expired) → 404; `InvalidInput` when
    /// any listed block is not staged → 400. Publishing is B5-ordered (blob
    /// file first, then the index row) and supersedes any existing visible
    /// entry sharing the artifact key (one visible entry per key).
    fn assemble_blocks<'a>(
        &'a self,
        cache_id: &'a str,
        ordered_block_ids: &'a [String],
    ) -> BoxFuture<'a, io::Result<u64>>;

    /// Synchronous accounted bytes, for admin/status snapshots.
    fn used_bytes_sync(&self) -> u64 {
        0
    }

    /// `(logical chunk bytes, unique bytes, saved bytes)` for CDC payloads.
    fn dedup_stats(&self) -> (u64, u64, u64) {
        (0, 0, 0)
    }

    /// A view of this backend restricted to one namespace (v1.2 workstream F,
    /// `docs/shared-cache.md` §1/§4).
    ///
    /// The namespace is part of a row's identity: a view only ever observes
    /// and mutates rows in its own namespace, so two namespaces never see
    /// each other's rows even with identical keys and versions (the design's
    /// isolation guarantee), while views of the same namespace deliberately
    /// share rows on purpose. The view shares the backend's underlying state
    /// (connection, write gate, chunk locks) with `self`; creating one is
    /// cheap enough for the per-request namespace resolution the route layer
    /// performs. The legacy single-tenant rows live in the `""` namespace
    /// (schema v3 backfill) and are what an unscoped backend operates on.
    fn scoped(&self, namespace: &str) -> Arc<dyn StorageBackend>;
}

/// In-memory [`StorageBackend`] double for unit and handler tests:
/// concurrent-safe (`tokio::sync::RwLock`), no filesystem involvement.
/// Namespace-aware (v1.2 workstream F): each view shares one inner state and
/// reads/writes exactly its own namespace's rows, mirroring the FS backend's
/// namespaced index views.
#[derive(Debug, Default)]
pub struct MemoryStorage {
    inner: Arc<RwLock<MemoryState>>,
    /// The namespace this view reads and writes; `""` is the legacy
    /// single-tenant row set (`MemoryStorage::new()`'s namespace), reachable
    /// exactly as before namespaces existed.
    namespace: String,
}

#[derive(Debug, Default)]
struct MemoryState {
    /// Rows per namespace: the namespace is part of a row's identity
    /// (`docs/shared-cache.md` §4), so two namespaces holding the same key
    /// and version are two distinct rows by construction.
    namespaces: HashMap<String, NsState>,
}

/// One namespace's rows inside [`MemoryState`].
#[derive(Debug, Default)]
struct NsState {
    /// Staged (put, not yet finalized) blobs.
    staged: HashMap<String, Staged>,
    /// Visible (finalized) blobs.
    visible: HashMap<String, Visible>,
    /// Open reservations: `cache_id` → reservation metadata.
    reservations: HashMap<String, Reservation>,
    /// Chunks already staged per reservation `cache_id`.
    chunks: HashMap<String, Vec<StagedChunk>>,
    /// Azure "Put Block" blocks staged per reservation `cache_id`:
    /// `block_id` (hex token) → bytes (plan task 25).
    blocks: HashMap<String, HashMap<String, Vec<u8>>>,
}

/// A lazily-created empty [`NsState`] so read paths on a namespace that has
/// never been written behave like "no rows" without inserting a row set.
static EMPTY_NS: std::sync::LazyLock<NsState> = std::sync::LazyLock::new(NsState::default);

impl MemoryState {
    /// The rows of `namespace` (an empty set when it holds none yet).
    fn ns(&self, namespace: &str) -> &NsState {
        self.namespaces.get(namespace).unwrap_or(&EMPTY_NS)
    }

    /// The rows of `namespace`, created when absent (write paths).
    fn ns_mut(&mut self, namespace: &str) -> &mut NsState {
        self.namespaces.entry(namespace.to_owned()).or_default()
    }
}

#[derive(Debug)]
struct Reservation {
    key: String,
    expires_at: u64,
}

/// One staged PATCH chunk: its inclusive byte range plus the bytes.
#[derive(Debug)]
struct StagedChunk {
    range: ChunkRange,
    data: Vec<u8>,
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
    /// Fresh, empty storage in the legacy (`""`) namespace.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A view of this state restricted to one namespace (v1.2 workstream F,
    /// the in-memory twin of [`FsStorage::scoped`]): the view shares the
    /// inner state with `self` and only ever touches its own namespace's
    /// rows, so two views of different namespaces never share a row.
    #[must_use]
    pub fn scoped(&self, namespace: &str) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            namespace: namespace.to_owned(),
        }
    }
}

impl StorageBackend for MemoryStorage {
    fn capabilities(&self) -> blob::Capabilities {
        // The in-memory double models the local backend's feature set.
        blob::Capabilities::FS
    }

    fn scoped(&self, namespace: &str) -> Arc<dyn StorageBackend> {
        Arc::new(MemoryStorage::scoped(self, namespace))
    }

    fn put_stream<'a>(
        &'a self,
        key: &'a str,
        mut source: ByteStream<'a>,
    ) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async move {
            let mut data = Vec::new();
            source.read_to_end(&mut data).await?;
            let mut state = self.inner.write().await;
            state.ns_mut(&self.namespace).staged.insert(
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
            let ns = state.ns_mut(&self.namespace);
            let entry = ns.visible.get_mut(key).ok_or_else(|| not_found(key))?;
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
            let ns = state.ns_mut(&self.namespace);
            ns.staged.remove(key);
            ns.visible.remove(key);
            ns.reservations.remove(key);
            ns.chunks.remove(key);
            ns.blocks.remove(key);
            Ok(())
        })
    }

    fn stat<'a>(&'a self, key: &'a str) -> BoxFuture<'a, io::Result<Option<EntryStat>>> {
        Box::pin(async move {
            let state = self.inner.read().await;
            Ok(state
                .ns(&self.namespace)
                .visible
                .get(key)
                .map(|entry| EntryStat {
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
                .ns(&self.namespace)
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
            let ns = state.ns_mut(&self.namespace);
            match ns.staged.remove(key) {
                Some(staged) => {
                    ns.reservations.remove(key);
                    ns.chunks.remove(key);
                    ns.visible.insert(
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
                None if ns.visible.contains_key(key) => Ok(()),
                None => Err(not_found(key)),
            }
        })
    }

    fn used_bytes<'a>(&'a self) -> BoxFuture<'a, io::Result<u64>> {
        Box::pin(async move {
            let state = self.inner.read().await;
            // The TOTAL across namespaces, matching the FS backend: this is
            // the whole-index budget the eviction floor and the storage gauge
            // read, not one tenant's share.
            let total = state
                .namespaces
                .values()
                .flat_map(|ns| ns.visible.values())
                .map(|entry| entry.data.len() as u64)
                .sum();
            Ok(total)
        })
    }

    fn usage_by_namespace(&self) -> BoxFuture<'_, io::Result<Vec<(String, u64)>>> {
        Box::pin(async move {
            let state = self.inner.read().await;
            let mut usage: Vec<(String, u64)> = state
                .namespaces
                .iter()
                .map(|(namespace, ns)| {
                    let bytes = ns
                        .visible
                        .values()
                        .map(|entry| entry.data.len() as u64)
                        .sum();
                    (namespace.clone(), bytes)
                })
                .collect();
            usage.sort_by(|(a, _), (b, _)| a.cmp(b));
            Ok(usage)
        })
    }

    fn namespace_bytes(&self) -> BoxFuture<'_, io::Result<u64>> {
        Box::pin(async move {
            let state = self.inner.read().await;
            let bytes = state
                .ns(&self.namespace)
                .visible
                .values()
                .map(|entry| entry.data.len() as u64)
                .sum();
            Ok(bytes)
        })
    }

    fn reserve<'a>(
        &'a self,
        cache_id: &'a str,
        key: &'a str,
        _version: &'a str,
        expires_at: u64,
    ) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async move {
            let mut state = self.inner.write().await;
            let ns = state.ns_mut(&self.namespace);
            ns.reservations.insert(
                cache_id.to_owned(),
                Reservation {
                    key: key.to_owned(),
                    expires_at,
                },
            );
            // A fresh reserve supersedes any blocks staged for this cache_id.
            ns.blocks.remove(cache_id);
            Ok(())
        })
    }

    fn reservation_exists<'a>(
        &'a self,
        key: &'a str,
        now_unix: u64,
    ) -> BoxFuture<'a, io::Result<bool>> {
        Box::pin(async move {
            let state = self.inner.read().await;
            Ok(state
                .ns(&self.namespace)
                .reservations
                .values()
                .any(|reservation| reservation.key == key && reservation.expires_at > now_unix))
        })
    }

    fn write_chunk<'a>(
        &'a self,
        cache_id: &'a str,
        mut chunk: Chunk<'a>,
    ) -> BoxFuture<'a, io::Result<ChunkOutcome>> {
        Box::pin(async move {
            let mut data = Vec::new();
            chunk.body.read_to_end(&mut data).await?;
            let mut state = self.inner.write().await;
            let ns = state.ns_mut(&self.namespace);
            match ns.reservations.get(cache_id) {
                None => return Err(not_found(cache_id)),
                Some(reservation) if reservation.expires_at <= unix_now() => {
                    ns.reservations.remove(cache_id);
                    ns.chunks.remove(cache_id);
                    return Err(not_found(cache_id));
                }
                Some(_) => {}
            }
            let staged = ns.chunks.entry(cache_id.to_owned()).or_default();
            for existing in staged.iter() {
                if existing.range == chunk.range {
                    return Ok(ChunkOutcome::AlreadyPresent);
                }
                if existing.range.overlaps(&chunk.range) {
                    return Err(invalid_range("chunk overlaps an already-received range"));
                }
            }
            staged.push(StagedChunk {
                range: chunk.range,
                data,
            });
            Ok(ChunkOutcome::Written)
        })
    }

    fn commit_chunks<'a>(
        &'a self,
        cache_id: &'a str,
        declared_size: u64,
    ) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async move {
            let mut state = self.inner.write().await;
            let ns = state.ns_mut(&self.namespace);
            let Some(reservation) = ns.reservations.get(cache_id) else {
                return Err(not_found(cache_id));
            };
            if reservation.expires_at <= unix_now() {
                ns.reservations.remove(cache_id);
                ns.chunks.remove(cache_id);
                ns.blocks.remove(cache_id);
                return Err(not_found(cache_id));
            }
            let key = reservation.key.clone();
            let mut staged = ns.chunks.remove(cache_id).unwrap_or_default();
            staged.sort_by_key(|chunk| chunk.range.start);
            let mut expected = 0_u64;
            let mut contiguous = true;
            for chunk in &staged {
                if chunk.range.start != expected {
                    contiguous = false;
                    break;
                }
                expected = expected.saturating_add(chunk.range.len());
            }
            if !contiguous || expected != declared_size {
                ns.reservations.remove(cache_id);
                return Err(invalid_range(
                    "committed size does not match the uploaded chunks",
                ));
            }
            let mut data = Vec::with_capacity(usize::try_from(declared_size).unwrap_or(0));
            for chunk in &staged {
                data.extend_from_slice(&chunk.data);
            }
            let created_at = unix_now();
            ns.visible.insert(
                key,
                Visible {
                    data,
                    created_at,
                    accessed_at: created_at,
                },
            );
            ns.reservations.remove(cache_id);
            ns.blocks.remove(cache_id);
            Ok(())
        })
    }

    fn put_block<'a>(
        &'a self,
        cache_id: &'a str,
        block_id: &'a str,
        mut source: ByteStream<'a>,
    ) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async move {
            let mut data = Vec::new();
            source.read_to_end(&mut data).await?;
            let mut state = self.inner.write().await;
            let ns = state.ns_mut(&self.namespace);
            match ns.reservations.get(cache_id) {
                None => return Err(not_found(cache_id)),
                Some(reservation) if reservation.expires_at <= unix_now() => {
                    ns.reservations.remove(cache_id);
                    ns.blocks.remove(cache_id);
                    return Err(not_found(cache_id));
                }
                Some(_) => {}
            }
            ns.blocks
                .entry(cache_id.to_owned())
                .or_default()
                .insert(block_id.to_owned(), data);
            Ok(())
        })
    }

    fn assemble_blocks<'a>(
        &'a self,
        cache_id: &'a str,
        ordered_block_ids: &'a [String],
    ) -> BoxFuture<'a, io::Result<u64>> {
        Box::pin(async move {
            let mut state = self.inner.write().await;
            let ns = state.ns_mut(&self.namespace);
            let Some(reservation) = ns.reservations.get(cache_id) else {
                return Err(not_found(cache_id));
            };
            if reservation.expires_at <= unix_now() {
                ns.reservations.remove(cache_id);
                ns.blocks.remove(cache_id);
                return Err(not_found(cache_id));
            }
            let key = reservation.key.clone();
            let staged = ns.blocks.get(cache_id);
            let mut data = Vec::new();
            for block_id in ordered_block_ids {
                let Some(bytes) = staged.and_then(|blocks| blocks.get(block_id)) else {
                    return Err(invalid_range("blocklist references an unknown block"));
                };
                data.extend_from_slice(bytes);
            }
            let size = data.len() as u64;
            let created_at = unix_now();
            ns.visible.insert(
                key,
                Visible {
                    data,
                    created_at,
                    accessed_at: created_at,
                },
            );
            ns.reservations.remove(cache_id);
            ns.blocks.remove(cache_id);
            Ok(size)
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
mod namespace_scoping {
    //! The design's isolation guarantees (docs/shared-cache.md §Test plan),
    //! exercised through the trait so both backends must honor them.

    use std::io::Cursor;

    use super::*;

    async fn put_visible(storage: &dyn StorageBackend, key: &str, data: &[u8]) {
        storage
            .put_stream(key, Box::pin(Cursor::new(data.to_vec())))
            .await
            .expect("put");
        storage.finalize(key).await.expect("finalize");
    }

    /// Two namespaces, same key: two distinct rows — a write in one namespace
    /// is invisible to a view of the other, and each view's `stat`/`list`
    /// only sees its own row set.
    #[tokio::test]
    async fn two_namespaces_same_key_are_distinct_rows() {
        let root = MemoryStorage::new();
        let a = root.scoped("forge-a");
        let b = root.scoped("forge-b");

        put_visible(&a, "shared-key", b"a-data").await;

        assert!(b.stat("shared-key").await.expect("stat").is_none());
        assert!(b.list().await.expect("list").is_empty());

        put_visible(&b, "shared-key", b"b-data").await;

        // Both rows coexist under one key; neither view sees the other's.
        let stat_a = a.stat("shared-key").await.expect("stat").expect("a row");
        let stat_b = b.stat("shared-key").await.expect("stat").expect("b row");
        assert_eq!(stat_a.size, 6);
        assert_eq!(stat_b.size, 6);
        assert_eq!(
            a.list().await.expect("list").len(),
            1,
            "a view lists only its own namespace's rows"
        );
    }

    /// A cross-namespace read is a miss (the route layer maps that to 204).
    #[tokio::test]
    async fn cross_namespace_read_is_a_miss() {
        let root = MemoryStorage::new();
        let a = root.scoped("forge-a");
        put_visible(&a, "k", b"data").await;

        let err = root
            .get_range("k", 0..4)
            .await
            .err()
            .expect("the legacy view must not see a namespaced row");
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    /// A cross-namespace delete is a no-op against the other namespace's row.
    #[tokio::test]
    async fn cross_namespace_delete_is_a_no_op() {
        let root = MemoryStorage::new();
        let a = root.scoped("forge-a");
        let b = root.scoped("forge-b");
        put_visible(&a, "k", b"data").await;

        b.delete("k").await.expect("delete");

        assert!(
            a.stat("k").await.expect("stat").is_some(),
            "deleting in namespace b must not touch namespace a's row"
        );
    }

    /// A cross-namespace finalize cannot publish: staging in namespace a and
    /// committing in namespace b leaves a's data staged (invisible) and b
    /// without a row.
    #[tokio::test]
    async fn cross_namespace_finalize_cannot_publish() {
        let root = MemoryStorage::new();
        let a = root.scoped("forge-a");
        let b = root.scoped("forge-b");
        a.put_stream("k", Box::pin(Cursor::new(b"staged".to_vec())))
            .await
            .expect("stage in a");

        let err = b
            .finalize("k")
            .await
            .expect_err("finalize in b must not see a's staged data");
        assert_eq!(err.kind(), io::ErrorKind::NotFound);

        assert!(
            a.stat("k").await.expect("stat").is_none(),
            "a's staged data stays invisible"
        );
        assert!(b.stat("k").await.expect("stat").is_none());
    }

    /// Views of the SAME namespace deliberately share rows (the
    /// shared-namespace case; the admin decided, the client cannot opt out).
    #[tokio::test]
    async fn same_namespace_views_share_rows() {
        let root = MemoryStorage::new();
        let a1 = root.scoped("shared");
        let a2 = root.scoped("shared");
        put_visible(&a1, "k", b"data").await;

        let stat = a2.stat("k").await.expect("stat").expect("shared row");
        assert_eq!(stat.size, 4);
        assert_eq!(a2.used_bytes().await.expect("used"), 4);
    }

    /// Duplicate-reservation detection (`reservation_exists`, the v2
    /// CreateCacheEntry rule) is namespace-scoped: a concurrent same-key
    /// reserve in another namespace is allowed, in the same one rejected.
    #[tokio::test]
    async fn reservation_exists_is_namespace_scoped() {
        let root = MemoryStorage::new();
        let a = root.scoped("forge-a");
        let b = root.scoped("forge-b");
        a.reserve("cid", "k", "2", u64::MAX).await.expect("reserve");

        assert!(
            a.reservation_exists("k", 0).await.expect("exists"),
            "same namespace sees the open reservation"
        );
        assert!(
            !b.reservation_exists("k", 0).await.expect("exists"),
            "another namespace must not see it"
        );
    }

    /// The trait-level `scoped` works through `dyn StorageBackend` — the
    /// shape the route layer will consume when it resolves a request's
    /// namespace from its credential.
    #[tokio::test]
    async fn trait_scoped_returns_an_isolated_dyn_view() {
        let backend: Arc<dyn StorageBackend> = Arc::new(MemoryStorage::new());
        let a = backend.scoped("forge-a");
        let b = backend.scoped("forge-b");
        put_visible(&*a, "k", b"data").await;

        assert!(b.stat("k").await.expect("stat").is_none());
        assert!(a.stat("k").await.expect("stat").is_some());
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
