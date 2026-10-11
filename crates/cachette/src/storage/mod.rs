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
//!   [`normalize_key`] with the configured [`KeyCase`] before reserving or
//!   looking up; storage itself is case-agnostic.
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
