//! Filesystem-backed storage with a SQLite metadata index (plan task 9 / B5).
//!
//! Layout under the configured data root (`[storage.fs] path`):
//!
//! ```text
//! <root>/cachette.sqlite3   metadata + accounting index (rusqlite, WAL)
//! <root>/blobs/{id}.blob    finalized (visible) blob payloads
//! <root>/parts/{id}.part    staged payload awaiting finalize
//! <root>/tmp/               scratch for atomic temp-file + rename writes
//! ```
//!
//! `id` is the lowercase hex SHA-256 of the opaque key: keys never become
//! path segments (no POSIX coupling) and the [`StorageBackend`] contract
//! allows at most one visible entry per key, so the key alone is a complete
//! address. Protocol `version` stays `''` until plan task 10 wires the
//! versioned lookup model; the column exists per the B5 schema. The
//! reservation multipart layout (`parts/{reservationId}/{n}.part`) arrives
//! with plan task 18; trait-level `put_stream` stages a single part file.
//!
//! B5 commit ordering lives in [`StorageBackend::finalize`]: the staged
//! part is renamed into `blobs/` first, then the index row is upserted
//! `complete=1` and the transaction committed — a crash in between leaves an
//! orphan blob for the task-11 reaper, never a half-visible entry.
//!
//! Boot reconciliation ([`FsStorage::open`]): index rows whose blob file is
//! missing are deleted and `accounting.used_bytes` is recomputed from the
//! surviving complete rows; blob files without a row are left untouched
//! (plan rule: never delete a blob that has a complete row — orphans belong
//! to the reaper).

use std::collections::HashMap;
use std::fmt::Write as _;
use std::fs::File;
use std::io;
use std::io::{Seek, SeekFrom, Write};
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::RwLock;

use super::{
    BoxFuture, ByteStream, Chunk, ChunkOutcome, ChunkRange, EntryStat, StorageBackend, complete,
    digest::{self, DigestWriter},
    invalid_range, not_found,
};

/// Metadata + accounting schema (B5). The cluster/reservation columns stay
/// empty until the tasks that populate them (11/18); `complete` doubles as
/// the reservation marker there, while this task only writes `complete=1`.
const SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS entries (
        id                      TEXT PRIMARY KEY,
        key                     TEXT NOT NULL,
        version                 TEXT NOT NULL DEFAULT '',
        size                    INTEGER NOT NULL,
        created_at              INTEGER NOT NULL,
        accessed_at             INTEGER NOT NULL,
        complete                INTEGER NOT NULL DEFAULT 0,
        owner_node              TEXT NOT NULL DEFAULT '',
        reservation_expires_at  INTEGER,
        artifact_key            TEXT NOT NULL DEFAULT '',
        digest                  TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX IF NOT EXISTS entries_key_idx ON entries(key);
    CREATE TABLE IF NOT EXISTS accounting (used_bytes INTEGER NOT NULL);
    INSERT INTO accounting (used_bytes)
        SELECT 0 WHERE NOT EXISTS (SELECT 1 FROM accounting);
";

/// Per-reservation serialization for chunk staging (plan task 20): one async
/// mutex per reservation key so sequential chunks from one client never race,
/// while different reservations write concurrently.
type ChunkLocks = Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>;

/// Health of one published blob, as reported by [`FsStorage::verify_all`]
/// (plan task 50).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EntryHealth {
    /// The on-disk bytes hash to the digest recorded at publish time.
    Ok,
    /// The index has a complete row but `blobs/{id}.blob` is gone.
    MissingBlob,
    /// The row predates task 50 and carries no digest to check against.
    MissingDigest,
    /// Size on disk disagrees with the size committed in the index.
    SizeMismatch {
        /// Size recorded when the entry was published.
        expected: u64,
        /// Size of the blob file now.
        actual: u64,
    },
    /// Byte count matches but the content no longer hashes to the digest.
    DigestMismatch {
        /// Digest recorded when the entry was published.
        expected: String,
        /// Digest of the blob file now.
        actual: String,
    },
}

/// One entry's integrity verdict from [`FsStorage::verify_all`] (plan task 50).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifyReport {
    /// Artifact key the entry is published under.
    pub key: String,
    /// Size committed in the index.
    pub size: u64,
    /// What the on-disk blob looks like now.
    pub health: EntryHealth,
}

impl VerifyReport {
    /// Whether the entry needs no attention.
    #[must_use]
    pub fn is_ok(&self) -> bool {
        self.health == EntryHealth::Ok
    }
}

/// Node-local blob store: raw files for payloads plus one SQLite file for
/// the metadata index. Share behind `Arc`: SQLite access is funnelled
/// through a mutex inside tokio's blocking pool, and mutating operations
/// additionally take the single-writer gate so B5's rename-then-commit
/// ordering is never interleaved.
pub struct FsStorage {
    root: PathBuf,
    conn: Arc<Mutex<Connection>>,
    /// Single-writer gate for put/finalize/delete; readers take it shared so
    /// metadata is never observed describing a blob mid-swap.
    gate: RwLock<()>,
    /// Per-reservation chunk locks (see [`ChunkLocks`]).
    chunk_locks: ChunkLocks,
}

impl std::fmt::Debug for FsStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FsStorage")
            .field("root", &self.root)
            .finish_non_exhaustive()
    }
}

impl FsStorage {
    /// Open (creating when missing) the storage at `root`, initialise the
    /// schema, and run boot reconciliation. Blocking (rusqlite + mkdirs):
    /// call during startup or tests, never on the request path.
    pub fn open(root: impl AsRef<Path>) -> io::Result<Self> {
        let root = root.as_ref().to_path_buf();
        for dir in ["blobs", "parts", "tmp"] {
            std::fs::create_dir_all(root.join(dir))?;
        }
        let conn = Connection::open(root.join("cachette.sqlite3")).map_err(sql)?;
        conn.busy_timeout(Duration::from_secs(5)).map_err(sql)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")
            .map_err(sql)?;
        conn.execute_batch(SCHEMA).map_err(sql)?;
        migrate(&conn)?;
        let storage = Self {
            root,
            conn: Arc::new(Mutex::new(conn)),
            gate: RwLock::new(()),
            chunk_locks: Mutex::new(HashMap::new()),
        };
        storage.reconcile()?;
        Ok(storage)
    }

    /// Re-hash every published blob and compare it with the digest recorded
    /// when the entry was committed (plan task 50). Blocking: it reads each
    /// blob in bounded chunks, so call it from an ops command (`cachette
    /// verify`, task 46) or the periodic scrub, never the request path.
    ///
    /// `Err` is reserved for real I/O failures (for example an unreadable
    /// blob); a blob that has gone missing or was modified comes back as an
    /// [`EntryHealth`] that is not [`EntryHealth::Ok`].
    pub fn verify_all(&self) -> io::Result<Vec<VerifyReport>> {
        let rows: Vec<(String, String, i64, String)> = {
            let conn = lock(&self.conn)?;
            let mut stmt = conn
                .prepare(
                    "SELECT id, key, size, digest FROM entries \
                     WHERE complete = 1 ORDER BY key",
                )
                .map_err(sql)?;
            let rows = stmt
                .query_map([], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
                })
                .map_err(sql)?;
            rows.collect::<Result<Vec<_>, _>>().map_err(sql)?
        };
        let mut reports = Vec::with_capacity(rows.len());
        for (id, key, size, stored) in rows {
            let recorded = u64::try_from(size).unwrap_or(0);
            let blob = self.blob_path(&id);
            let health = match std::fs::metadata(&blob) {
                Err(err) if err.kind() == io::ErrorKind::NotFound => EntryHealth::MissingBlob,
                Err(err) => return Err(err),
                Ok(meta) => {
                    let on_disk = meta.len();
                    if on_disk != recorded {
                        EntryHealth::SizeMismatch {
                            expected: recorded,
                            actual: on_disk,
                        }
                    } else if stored.is_empty() {
                        EntryHealth::MissingDigest
                    } else {
                        let actual = digest::hash_file(&blob)?;
                        if actual == stored {
                            EntryHealth::Ok
                        } else {
                            EntryHealth::DigestMismatch {
                                expected: stored,
                                actual,
                            }
                        }
                    }
                }
            };
            reports.push(VerifyReport {
                key,
                size: recorded,
                health,
            });
        }
        Ok(reports)
    }

    /// Reservation TTL reaper (plan task 11 / M4): delete staged
    /// reservation rows whose `reservation_expires_at` has passed and the
    /// staged parts backing them. Rows without an expiry are left alone.
    /// Returns the number of reservations reaped.
    pub async fn reap_expired_reservations(&self, now_unix: u64) -> io::Result<u64> {
        let _gate = self.gate.write().await;
        let conn = Arc::clone(&self.conn);
        let parts = self.root.join("parts");
        blocking(move || {
            let mut conn = lock(&conn)?;
            let tx = conn.transaction().map_err(sql)?;
            let expired: Vec<(String, String)> = {
                let mut stmt = tx
                    .prepare(
                        "SELECT id, key FROM entries WHERE complete = 0 \
                         AND reservation_expires_at IS NOT NULL \
                         AND reservation_expires_at <= ?1",
                    )
                    .map_err(sql)?;
                let rows = stmt
                    .query_map(params![now_unix], |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                    })
                    .map_err(sql)?;
                rows.collect::<Result<Vec<_>, _>>().map_err(sql)?
            };
            for (id, _key) in &expired {
                tx.execute("DELETE FROM entries WHERE id = ?1", [id])
                    .map_err(sql)?;
            }
            tx.commit().map_err(sql)?;
            // Files last (B5 convention): a crash in between leaves rowless
            // parts for the boot sweep, never a dangling row.
            for (id, key) in &expired {
                let _ = std::fs::remove_file(parts.join(format!("{id}.part")));
                let _ = std::fs::remove_dir_all(parts.join(id));
                let _ = std::fs::remove_dir_all(parts.join(key));
            }
            tracing::debug!(reaped = expired.len(), "expired reservations reaped");
            Ok(expired.len() as u64)
        })
        .await
    }

    /// Reservation TTL reaper (plan task 11): delete blob files with no
    /// index row that are older than `older_than_unix` — rowless leftovers
    /// of a crash between the B5 blob rename and the index commit. Recent
    /// orphans are kept: they may belong to a finalize still in flight.
    /// Returns the number of blobs swept.
    pub async fn sweep_orphan_blobs(&self, older_than_unix: u64) -> io::Result<u64> {
        let _gate = self.gate.write().await;
        let conn = Arc::clone(&self.conn);
        let blobs = self.root.join("blobs");
        blocking(move || {
            let known: std::collections::HashSet<String> = {
                let conn = lock(&conn)?;
                let mut stmt = conn.prepare("SELECT id FROM entries").map_err(sql)?;
                let rows = stmt
                    .query_map([], |row| row.get::<_, String>(0))
                    .map_err(sql)?;
                rows.collect::<Result<_, _>>().map_err(sql)?
            };
            let cutoff = i64::try_from(older_than_unix).unwrap_or(i64::MAX);
            let mut swept = 0_u64;
            let read = match std::fs::read_dir(&blobs) {
                Ok(read) => read,
                Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(0),
                Err(err) => return Err(err),
            };
            for dirent in read.flatten() {
                let Some(name) = dirent.file_name().to_str().map(str::to_owned) else {
                    continue;
                };
                let Some(id) = name.strip_suffix(".blob") else {
                    continue;
                };
                if known.contains(id) {
                    continue;
                }
                match modified_unix(&dirent.path()) {
                    Ok(mtime) if mtime <= cutoff => {}
                    _ => continue,
                }
                if std::fs::remove_file(dirent.path()).is_ok() {
                    swept += 1;
                }
            }
            tracing::debug!(swept, "rowless blobs swept");
            Ok(swept)
        })
        .await
    }

    /// Task-11 test seam: plant a staged reservation row plus its part
    /// file — the state an abandoned reserve-then-PATCH upload leaves
    /// behind. Never counts toward `accounting` (only complete rows do).
    #[cfg(test)]
    pub(crate) async fn seed_reservation(
        &self,
        key: &str,
        bytes: &[u8],
        expires_at: u64,
    ) -> io::Result<()> {
        let id = entry_id(key);
        let tmp = self.tmp_path(&id);
        let part = self.part_path(&id);
        let conn = Arc::clone(&self.conn);
        let key = key.to_owned();
        let bytes = bytes.to_vec();
        let _gate = self.gate.write().await;
        blocking(move || {
            write_atomic(&tmp, &part, &bytes)?;
            let created_at = unix_now();
            let size = i64::try_from(bytes.len())
                .map_err(|_| io::Error::other("reservation exceeds SQLite integer range"))?;
            let expires_at = i64::try_from(expires_at)
                .map_err(|_| io::Error::other("expiry exceeds SQLite integer range"))?;
            let conn = lock(&conn)?;
            conn.execute(
                "INSERT INTO entries \
                     (id, key, version, size, created_at, accessed_at, complete, \
                      reservation_expires_at) \
                 VALUES (?1, ?2, '', ?3, ?4, ?4, 0, ?5) \
                 ON CONFLICT(id) DO UPDATE SET \
                     complete = 0, reservation_expires_at = excluded.reservation_expires_at",
                params![id, key, size, created_at, expires_at],
            )
            .map_err(sql)?;
            Ok(())
        })
        .await
    }

    fn blob_path(&self, id: &str) -> PathBuf {
        self.root.join("blobs").join(format!("{id}.blob"))
    }
    fn part_path(&self, id: &str) -> PathBuf {
        self.root.join("parts").join(format!("{id}.part"))
    }

    fn tmp_path(&self, id: &str) -> PathBuf {
        self.root.join("tmp").join(format!("{id}.tmp"))
    }

    /// Per-reservation async mutex serializing chunk staging for `key`.
    fn chunk_lock(&self, key: &str) -> Arc<tokio::sync::Mutex<()>> {
        let mut locks = self.chunk_locks.lock().expect("chunk lock map poisoned");
        Arc::clone(
            locks
                .entry(key.to_owned())
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(()))),
        )
    }

    /// Drop per-key chunk locks nobody holds any more (plan T52: bound idle
    /// RSS). Without this the map grows one entry per cache key ever staged
    /// and never shrinks. Race-free: a lock is only removable while its `Arc`
    /// has no other clones, and this check, like [`Self::chunk_lock`]'s clone,
    /// happens under the map mutex, so a sweep can never remove a lock that a
    /// task is holding or waiting on.
    pub fn sweep_chunk_locks(&self) -> u64 {
        let mut locks = self.chunk_locks.lock().expect("chunk lock map poisoned");
        let before = locks.len();
        locks.retain(|_, lock| Arc::strong_count(lock) > 1);
        (before - locks.len()) as u64
    }

    /// Plan B5 boot reconciliation: drop index rows whose blob file is
    /// gone, recompute accounting from the survivors, discard leftover
    /// scratch. Rowless blob files stay put for the task-11 reaper.
    fn reconcile(&self) -> io::Result<()> {
        let conn = lock(&self.conn)?;
        let ids: Vec<String> = {
            let mut stmt = conn.prepare("SELECT id FROM entries").map_err(sql)?;
            let rows = stmt
                .query_map([], |row| row.get::<_, String>(0))
                .map_err(sql)?;
            rows.collect::<Result<Vec<_>, _>>().map_err(sql)?
        };
        let mut dropped = 0_u64;
        for id in ids {
            if !self.blob_path(&id).exists() {
                conn.execute("DELETE FROM entries WHERE id = ?1", [&id])
                    .map_err(sql)?;
                dropped += 1;
            }
        }
        conn.execute(
            "UPDATE accounting SET used_bytes = \
             COALESCE((SELECT SUM(size) FROM entries WHERE complete = 1), 0)",
            [],
        )
        .map_err(sql)?;
        drop(conn);
        // Scratch only ever holds in-progress writes; a fresh boot means the
        // write they belonged to is dead.
        let _ = std::fs::remove_dir_all(self.root.join("tmp"));
        let _ = std::fs::create_dir(self.root.join("tmp"));
        tracing::debug!(dropped_rows = dropped, "storage reconciliation done");
        Ok(())
    }
}

impl StorageBackend for FsStorage {
    fn put_stream<'a>(
        &'a self,
        key: &'a str,
        mut source: ByteStream<'a>,
    ) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async move {
            // Stream straight to the scratch file instead of buffering the
            // whole body (plan task 45: this path used to be a latent
            // whole-blob RAM bomb). The per-key lock keeps two concurrent puts
            // of the same key off one scratch file; the guard drops a partial
            // scratch file if the future is cancelled mid-copy.
            let chunk_lock = self.chunk_lock(key);
            let _chunk_guard = chunk_lock.lock().await;
            let id = entry_id(key);
            let tmp = self.tmp_path(&id);
            let part = self.part_path(&id);
            let guard = TmpGuard::new(tmp.clone());
            stream_chunk_to_file(&tmp, &mut source).await?;
            // The one un-cancellable window is the atomic rename under the
            // write gate, which stages complete bytes — never partial, never
            // visible without a later finalize.
            let _gate = self.gate.write().await;
            tokio::fs::rename(&tmp, &part).await?;
            guard.disarm();
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
            let _gate = self.gate.read().await;
            let id = entry_id(key);
            let key = key.to_owned();
            let blob = self.blob_path(&id);
            let conn = Arc::clone(&self.conn);
            let file = blocking(move || {
                let conn = lock(&conn)?;
                let size: Option<u64> = conn
                    .query_row(
                        "SELECT size FROM entries WHERE id = ?1 AND complete = 1",
                        [&id],
                        |row| row.get(0),
                    )
                    .optional()
                    .map_err(sql)?;
                let Some(size) = size else {
                    return Err(not_found(&key));
                };
                if range.start > size {
                    return Err(invalid_range("range start past end of entry"));
                }
                conn.execute(
                    "UPDATE entries SET accessed_at = ?1 WHERE id = ?2",
                    params![unix_now(), id],
                )
                .map_err(sql)?;
                let mut file = File::open(&blob).map_err(|err| {
                    if err.kind() == io::ErrorKind::NotFound {
                        not_found(&key)
                    } else {
                        err
                    }
                })?;
                if range.start > 0 {
                    file.seek(SeekFrom::Start(range.start))?;
                }
                Ok(file)
            })
            .await?;
            // `take` clamps at EOF, matching the trait's end-clamping rule.
            let len = range.end.saturating_sub(range.start);
            let stream: ByteStream<'a> = Box::pin(tokio::fs::File::from_std(file).take(len));
            Ok(stream)
        })
    }

    fn delete<'a>(&'a self, key: &'a str) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async move {
            let _gate = self.gate.write().await;
            let id = entry_id(key);
            let blob = self.blob_path(&id);
            let part = self.part_path(&id);
            let conn = Arc::clone(&self.conn);
            blocking(move || {
                let mut conn = lock(&conn)?;
                let tx = conn.transaction().map_err(sql)?;
                let size: Option<u64> = tx
                    .query_row(
                        "SELECT size FROM entries WHERE id = ?1 AND complete = 1",
                        [&id],
                        |row| row.get(0),
                    )
                    .optional()
                    .map_err(sql)?;
                if let Some(size) = size {
                    let used: i64 = tx
                        .query_row("SELECT used_bytes FROM accounting", [], |row| row.get(0))
                        .optional()
                        .map_err(sql)?
                        .unwrap_or(0);
                    let used = used.saturating_sub(i64::try_from(size).unwrap_or(i64::MAX));
                    tx.execute("UPDATE accounting SET used_bytes = ?1", [used])
                        .map_err(sql)?;
                }
                tx.execute("DELETE FROM entries WHERE id = ?1", [&id])
                    .map_err(sql)?;
                tx.commit().map_err(sql)?;
                // Files last: a crash in between leaves rowless blobs/parts
                // for reconciliation/reaper, never a dangling row.
                let _ = std::fs::remove_file(&blob);
                let _ = std::fs::remove_file(&part);
                Ok(())
            })
            .await
        })
    }

    fn stat<'a>(&'a self, key: &'a str) -> BoxFuture<'a, io::Result<Option<EntryStat>>> {
        Box::pin(async move {
            let _gate = self.gate.read().await;
            let id = entry_id(key);
            let conn = Arc::clone(&self.conn);
            blocking(move || {
                let conn = lock(&conn)?;
                let stat = conn
                    .query_row(
                        "SELECT key, size, created_at, accessed_at \
                         FROM entries WHERE id = ?1 AND complete = 1",
                        [&id],
                        |row| {
                            Ok(EntryStat {
                                key: row.get(0)?,
                                size: row.get(1)?,
                                created_at: row.get(2)?,
                                accessed_at: row.get(3)?,
                            })
                        },
                    )
                    .optional()
                    .map_err(sql)?;
                Ok(stat)
            })
            .await
        })
    }

    fn list<'a>(&'a self) -> BoxFuture<'a, io::Result<Vec<EntryStat>>> {
        Box::pin(async move {
            let _gate = self.gate.read().await;
            let conn = Arc::clone(&self.conn);
            blocking(move || {
                let conn = lock(&conn)?;
                let mut stmt = conn
                    .prepare(
                        "SELECT key, size, created_at, accessed_at FROM entries \
                         WHERE complete = 1 ORDER BY key",
                    )
                    .map_err(sql)?;
                let rows = stmt
                    .query_map([], |row| {
                        Ok(EntryStat {
                            key: row.get(0)?,
                            size: row.get(1)?,
                            created_at: row.get(2)?,
                            accessed_at: row.get(3)?,
                        })
                    })
                    .map_err(sql)?;
                rows.collect::<Result<Vec<_>, _>>().map_err(sql)
            })
            .await
        })
    }

    fn finalize<'a>(&'a self, key: &'a str) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async move {
            let _gate = self.gate.write().await;
            let id = entry_id(key);
            let key = key.to_owned();
            let part = self.part_path(&id);
            let blob = self.blob_path(&id);
            let conn = Arc::clone(&self.conn);
            blocking(move || {
                if !part.exists() {
                    // Nothing staged: idempotent only when already visible.
                    let conn = lock(&conn)?;
                    let visible = conn
                        .query_row(
                            "SELECT 1 FROM entries WHERE id = ?1 AND complete = 1",
                            [&id],
                            |_| Ok(()),
                        )
                        .optional()
                        .map_err(sql)?
                        .is_some();
                    return if visible {
                        Ok(())
                    } else {
                        Err(not_found(&key))
                    };
                }
                let created_at = modified_unix(&part)?;
                // Task 50: `finalize` has no streaming write to fold the hash
                // into (the part is already on disk), so read it back in
                // bounded chunks. The chunk and block publish paths hash while
                // they copy instead.
                let digest = digest::hash_file(&part)?;
                // B5 ordering: blob file first, index commit second.
                std::fs::rename(&part, &blob)?;
                let size = std::fs::metadata(&blob)?.len();
                let size = i64::try_from(size)
                    .map_err(|_| io::Error::other("blob exceeds SQLite integer range"))?;
                let mut conn = lock(&conn)?;
                let tx = conn.transaction().map_err(sql)?;
                let previous: Option<i64> = tx
                    .query_row(
                        "SELECT size FROM entries WHERE id = ?1 AND complete = 1",
                        [&id],
                        |row| row.get(0),
                    )
                    .optional()
                    .map_err(sql)?;
                let version: String = tx
                    .query_row("SELECT version FROM entries WHERE id = ?1", [&id], |row| {
                        row.get(0)
                    })
                    .optional()
                    .map_err(sql)?
                    .unwrap_or_default();
                tx.execute(
                    "INSERT INTO entries \
                         (id, key, version, size, created_at, accessed_at, complete, \
                          owner_node, artifact_key, digest) \
                         VALUES (?1, ?2, ?3, ?4, ?5, ?5, 1, '', '', ?6) \
                         ON CONFLICT(id) DO UPDATE SET \
                             key = excluded.key, version = excluded.version, \
                             size = excluded.size, \
                             created_at = excluded.created_at, \
                             accessed_at = excluded.accessed_at, complete = 1, \
                             artifact_key = '', digest = excluded.digest",
                    params![id, key, version, size, created_at, digest],
                )
                .map_err(sql)?;
                let used: i64 = tx
                    .query_row("SELECT used_bytes FROM accounting", [], |row| row.get(0))
                    .optional()
                    .map_err(sql)?
                    .unwrap_or(0);
                let used = used
                    .saturating_sub(previous.unwrap_or(0))
                    .saturating_add(size);
                tx.execute("UPDATE accounting SET used_bytes = ?1", [used])
                    .map_err(sql)?;
                tx.commit().map_err(sql)?;
                Ok(())
            })
            .await
        })
    }

    fn used_bytes<'a>(&'a self) -> BoxFuture<'a, io::Result<u64>> {
        Box::pin(async move {
            let conn = Arc::clone(&self.conn);
            blocking(move || {
                let conn = lock(&conn)?;
                let used: i64 = conn
                    .query_row("SELECT used_bytes FROM accounting", [], |row| row.get(0))
                    .optional()
                    .map_err(sql)?
                    .unwrap_or(0);
                Ok(used.max(0) as u64)
            })
            .await
        })
    }

    fn reserve<'a>(
        &'a self,
        cache_id: &'a str,
        key: &'a str,
        version: &'a str,
        expires_at: u64,
    ) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async move {
            let id = entry_id(cache_id);
            let tmp = self.tmp_path(&id);
            let part = self.part_path(&id);
            let conn = Arc::clone(&self.conn);
            let cache_id = cache_id.to_owned();
            let key = key.to_owned();
            let version = version.to_owned();
            let _gate = self.gate.write().await;
            blocking(move || {
                write_atomic(&tmp, &part, &[])?;
                let created_at = unix_now();
                let expires_at = i64::try_from(expires_at)
                    .map_err(|_| io::Error::other("expiry exceeds SQLite integer range"))?;
                let conn = lock(&conn)?;
                conn.execute(
                    "INSERT INTO entries \
                         (id, key, version, size, created_at, accessed_at, complete, \
                          reservation_expires_at, artifact_key) \
                     VALUES (?1, ?2, ?3, 0, ?4, ?4, 0, ?5, ?6) \
                     ON CONFLICT(id) DO UPDATE SET \
                         key = excluded.key, version = excluded.version, size = 0, \
                         created_at = excluded.created_at, \
                         accessed_at = excluded.accessed_at, complete = 0, \
                         reservation_expires_at = excluded.reservation_expires_at, \
                         artifact_key = excluded.artifact_key",
                    params![id, cache_id, version, created_at, expires_at, key],
                )
                .map_err(sql)?;
                Ok(())
            })
            .await
        })
    }

    fn reservation_exists<'a>(
        &'a self,
        key: &'a str,
        now_unix: u64,
    ) -> BoxFuture<'a, io::Result<bool>> {
        Box::pin(async move {
            let _gate = self.gate.read().await;
            let conn = Arc::clone(&self.conn);
            let key = key.to_owned();
            let now = i64::try_from(now_unix).unwrap_or(i64::MAX);
            blocking(move || {
                let conn = lock(&conn)?;
                let found: i64 = conn
                    .query_row(
                        "SELECT COUNT(*) FROM entries \
                         WHERE artifact_key = ?1 AND complete = 0 \
                         AND (reservation_expires_at IS NULL OR reservation_expires_at > ?2)",
                        params![key, now],
                        |row| row.get(0),
                    )
                    .map_err(sql)?;
                Ok(found > 0)
            })
            .await
        })
    }

    fn write_chunk<'a>(
        &'a self,
        key: &'a str,
        mut chunk: Chunk<'a>,
    ) -> BoxFuture<'a, io::Result<ChunkOutcome>> {
        Box::pin(async move {
            let chunk_lock = self.chunk_lock(key);
            let _chunk_guard = chunk_lock.lock().await;
            let _gate = self.gate.read().await;
            let id = entry_id(key);
            let now = unix_now();
            let conn = Arc::clone(&self.conn);
            let id_for_query = id.clone();
            let status = blocking(move || {
                let conn = lock(&conn)?;
                let row: Option<(i64, Option<i64>)> = conn
                    .query_row(
                        "SELECT complete, reservation_expires_at FROM entries WHERE id = ?1",
                        [&id_for_query],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .optional()
                    .map_err(sql)?;
                Ok(match row {
                    None => ReservationState::Missing,
                    Some((1, _)) => ReservationState::Complete,
                    Some((0, Some(expires_at))) if expires_at <= now => ReservationState::Missing,
                    Some(_) => ReservationState::Open,
                })
            })
            .await?;
            match status {
                ReservationState::Complete => return Err(complete(key)),
                ReservationState::Missing => return Err(not_found(key)),
                ReservationState::Open => {}
            }
            let dir = self.root.join("parts").join(key);
            let dir_for_list = dir.clone();
            let existing = blocking(move || list_chunk_ranges(&dir_for_list)).await?;
            for range in &existing {
                if *range == chunk.range {
                    return Ok(ChunkOutcome::AlreadyPresent);
                }
                if range.overlaps(&chunk.range) {
                    return Err(invalid_range("chunk overlaps an already-received range"));
                }
            }
            let tmp = self
                .root
                .join("tmp")
                .join(format!("{id}-{}.chunk.tmp", chunk.range.start));
            // The guard drops the partial temp file if the copy errors or the
            // request is cancelled mid-body (plan task 45).
            let guard = TmpGuard::new(tmp.clone());
            let written = stream_chunk_to_file(&tmp, &mut chunk.body).await?;
            if written != chunk.range.len() {
                return Err(invalid_range(
                    "chunk body length does not match Content-Range",
                ));
            }
            let dest = dir.join(format!("{}.part", chunk.range.start));
            tokio::fs::create_dir_all(&dir).await?;
            tokio::fs::rename(&tmp, &dest).await?;
            guard.disarm();
            Ok(ChunkOutcome::Written)
        })
    }

    fn commit_chunks<'a>(
        &'a self,
        cache_id: &'a str,
        declared_size: u64,
    ) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async move {
            let chunk_lock = self.chunk_lock(cache_id);
            let _chunk_guard = chunk_lock.lock().await;
            let _gate = self.gate.write().await;
            let root = self.root.clone();
            let conn = Arc::clone(&self.conn);
            let res_id = entry_id(cache_id);
            let cache_id = cache_id.to_owned();
            blocking(move || {
                let now = unix_now();
                let reservation: Option<(String, String, Option<i64>)> = {
                    let conn = lock(&conn)?;
                    conn.query_row(
                        "SELECT artifact_key, version, reservation_expires_at \
                         FROM entries WHERE id = ?1 AND complete = 0",
                        [&res_id],
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                    )
                    .optional()
                    .map_err(sql)?
                };
                let Some((artifact_key, version, expires_at)) = reservation else {
                    return Err(not_found(&cache_id));
                };
                if expires_at.is_some_and(|expiry| expiry <= now) {
                    return Err(not_found(&cache_id));
                }
                let dir = root.join("parts").join(&cache_id);
                let parts = list_part_files(&dir)?;
                let mut expected = 0_u64;
                let mut contiguous = true;
                for (start, len, _path) in &parts {
                    if *start != expected {
                        contiguous = false;
                        break;
                    }
                    expected = expected.saturating_add(*len);
                }
                if !contiguous || expected != declared_size {
                    mark_reservation_failed(&conn, &res_id)?;
                    return Err(invalid_range(
                        "committed size does not match the uploaded chunks",
                    ));
                }
                let blob_id = entry_id(&artifact_key);
                let tmp = root.join("tmp").join(format!("{blob_id}.assemble"));
                let blob = root.join("blobs").join(format!("{blob_id}.blob"));
                let digest = {
                    let mut out = DigestWriter::new(File::create(&tmp)?);
                    for (_start, _len, path) in &parts {
                        let mut input = File::open(path)?;
                        std::io::copy(&mut input, &mut out)?;
                    }
                    let (file, digest) = out.finish()?;
                    file.sync_all()?;
                    digest
                };
                // B5 ordering: blob file first, index commit second, so a crash
                // in between leaves a rowless blob for the reaper.
                std::fs::rename(&tmp, &blob)?;
                let size = i64::try_from(declared_size)
                    .map_err(|_| io::Error::other("blob exceeds SQLite integer range"))?;
                let mut conn = lock(&conn)?;
                let tx = conn.transaction().map_err(sql)?;
                let previous: Option<i64> = tx
                    .query_row(
                        "SELECT size FROM entries WHERE id = ?1 AND complete = 1",
                        [&blob_id],
                        |row| row.get(0),
                    )
                    .optional()
                    .map_err(sql)?;
                tx.execute(
                    "INSERT INTO entries \
                         (id, key, version, size, created_at, accessed_at, complete, \
                          owner_node, artifact_key, reservation_expires_at, digest) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?5, 1, '', '', NULL, ?6) \
                     ON CONFLICT(id) DO UPDATE SET \
                         key = excluded.key, version = excluded.version, \
                         size = excluded.size, created_at = excluded.created_at, \
                         accessed_at = excluded.accessed_at, complete = 1, \
                         artifact_key = '', reservation_expires_at = NULL, \
                         digest = excluded.digest",
                    params![blob_id, artifact_key, version, size, now, digest],
                )
                .map_err(sql)?;
                tx.execute("DELETE FROM entries WHERE id = ?1", [&res_id])
                    .map_err(sql)?;
                let used: i64 = tx
                    .query_row("SELECT used_bytes FROM accounting", [], |row| row.get(0))
                    .optional()
                    .map_err(sql)?
                    .unwrap_or(0);
                let used = used
                    .saturating_sub(previous.unwrap_or(0))
                    .saturating_add(size);
                tx.execute("UPDATE accounting SET used_bytes = ?1", [used])
                    .map_err(sql)?;
                tx.commit().map_err(sql)?;
                drop(conn);
                let _ = std::fs::remove_dir_all(&dir);
                let _ = std::fs::remove_file(root.join("parts").join(format!("{res_id}.part")));
                Ok(())
            })
            .await
        })
    }

    fn put_block<'a>(
        &'a self,
        cache_id: &'a str,
        block_id: &'a str,
        mut source: ByteStream<'a>,
    ) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async move {
            // Stream into the scratch file first: the block body is never held
            // whole in memory (plan task 45). The guard drops the partial
            // scratch file if the future is cancelled mid-copy.
            let res_id = entry_id(cache_id);
            let now = unix_now();
            let cache_id = cache_id.to_owned();
            let block_id = block_id.to_owned();
            let dir = self.root.join("parts").join(&cache_id).join("blocks");
            let tmp = self
                .root
                .join("tmp")
                .join(format!("{res_id}-{block_id}.block.tmp"));
            let dest = dir.join(format!("{block_id}.block"));
            let guard = TmpGuard::new(tmp.clone());
            stream_chunk_to_file(&tmp, &mut source).await?;
            // Validate the reservation under the write gate, then publish with
            // one atomic rename.
            let _gate = self.gate.write().await;
            let conn = Arc::clone(&self.conn);
            {
                let res_id = res_id.clone();
                let cache_id = cache_id.clone();
                blocking(move || {
                    let status = {
                        let conn = lock(&conn)?;
                        let row: Option<(i64, Option<i64>)> = conn
                            .query_row(
                                "SELECT complete, reservation_expires_at FROM entries WHERE id = ?1",
                                [&res_id],
                                |row| Ok((row.get(0)?, row.get(1)?)),
                            )
                            .optional()
                            .map_err(sql)?;
                        match row {
                            None => ReservationState::Missing,
                            Some((1, _)) => ReservationState::Complete,
                            Some((0, Some(expires_at))) if expires_at <= now => {
                                ReservationState::Missing
                            }
                            Some(_) => ReservationState::Open,
                        }
                    };
                    match status {
                        ReservationState::Complete => Err(complete(&cache_id)),
                        ReservationState::Missing => Err(not_found(&cache_id)),
                        ReservationState::Open => Ok(()),
                    }
                })
                .await?;
            }
            tokio::fs::create_dir_all(&dir).await?;
            tokio::fs::rename(&tmp, &dest).await?;
            guard.disarm();
            Ok(())
        })
    }

    fn assemble_blocks<'a>(
        &'a self,
        cache_id: &'a str,
        ordered_block_ids: &'a [String],
    ) -> BoxFuture<'a, io::Result<u64>> {
        Box::pin(async move {
            let chunk_lock = self.chunk_lock(cache_id);
            let _chunk_guard = chunk_lock.lock().await;
            let _gate = self.gate.write().await;
            let root = self.root.clone();
            let conn = Arc::clone(&self.conn);
            let res_id = entry_id(cache_id);
            let cache_id = cache_id.to_owned();
            let ordered = ordered_block_ids.to_vec();
            blocking(move || {
                let now = unix_now();
                let reservation: Option<(String, String, Option<i64>)> = {
                    let conn = lock(&conn)?;
                    conn.query_row(
                        "SELECT artifact_key, version, reservation_expires_at \
                         FROM entries WHERE id = ?1 AND complete = 0",
                        [&res_id],
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                    )
                    .optional()
                    .map_err(sql)?
                };
                let Some((artifact_key, version, expires_at)) = reservation else {
                    return Err(not_found(&cache_id));
                };
                if expires_at.is_some_and(|expiry| expiry <= now) {
                    return Err(not_found(&cache_id));
                }
                let blocks = root.join("parts").join(&cache_id).join("blocks");
                let blob_id = entry_id(&artifact_key);
                let tmp = root.join("tmp").join(format!("{blob_id}.assemble"));
                let blob = root.join("blobs").join(format!("{blob_id}.blob"));
                let mut total = 0_u64;
                let digest = {
                    let mut out = DigestWriter::new(File::create(&tmp)?);
                    for block_id in &ordered {
                        let path = blocks.join(format!("{block_id}.block"));
                        let mut input = File::open(&path).map_err(|err| {
                            if err.kind() == io::ErrorKind::NotFound {
                                invalid_range("blocklist references an unknown block")
                            } else {
                                err
                            }
                        })?;
                        total = total.saturating_add(std::io::copy(&mut input, &mut out)?);
                    }
                    let (file, digest) = out.finish()?;
                    file.sync_all()?;
                    digest
                };
                // B5 ordering: blob file first, index commit second, so a crash
                // in between leaves a rowless blob for the reaper.
                std::fs::rename(&tmp, &blob)?;
                let size = i64::try_from(total)
                    .map_err(|_| io::Error::other("blob exceeds SQLite integer range"))?;
                let mut conn = lock(&conn)?;
                let tx = conn.transaction().map_err(sql)?;
                let previous: Option<i64> = tx
                    .query_row(
                        "SELECT size FROM entries WHERE id = ?1 AND complete = 1",
                        [&blob_id],
                        |row| row.get(0),
                    )
                    .optional()
                    .map_err(sql)?;
                tx.execute(
                    "INSERT INTO entries \
                         (id, key, version, size, created_at, accessed_at, complete, \
                          owner_node, artifact_key, reservation_expires_at, digest) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?5, 1, '', '', NULL, ?6) \
                     ON CONFLICT(id) DO UPDATE SET \
                         key = excluded.key, version = excluded.version, \
                         size = excluded.size, created_at = excluded.created_at, \
                         accessed_at = excluded.accessed_at, complete = 1, \
                         artifact_key = '', reservation_expires_at = NULL, \
                         digest = excluded.digest",
                    params![blob_id, artifact_key, version, size, now, digest],
                )
                .map_err(sql)?;
                tx.execute("DELETE FROM entries WHERE id = ?1", [&res_id])
                    .map_err(sql)?;
                let used: i64 = tx
                    .query_row("SELECT used_bytes FROM accounting", [], |row| row.get(0))
                    .optional()
                    .map_err(sql)?
                    .unwrap_or(0);
                let used = used
                    .saturating_sub(previous.unwrap_or(0))
                    .saturating_add(size);
                tx.execute("UPDATE accounting SET used_bytes = ?1", [used])
                    .map_err(sql)?;
                tx.commit().map_err(sql)?;
                drop(conn);
                let _ = std::fs::remove_dir_all(&blocks);
                let _ = std::fs::remove_file(root.join("parts").join(format!("{res_id}.part")));
                Ok(total)
            })
            .await
        })
    }
}

/// Address for a key: hex(SHA-256(key)). Keys stay opaque (never path
/// segments) and the one-visible-entry-per-key contract maps onto the PK.
fn entry_id(key: &str) -> String {
    let digest = Sha256::digest(key.as_bytes());
    let mut id = String::with_capacity(digest.len() * 2);
    for &byte in digest.as_slice() {
        let _ = write!(id, "{byte:02x}");
    }
    id
}

/// Bring a pre-task-21 index up to the current schema: `artifact_key` lets a
/// reservation carry the artifact key it will publish under while `key` stays
/// the reservation's own `cacheId` (so the reaper's `parts/{key}/` cleanup
/// still applies), and `digest` (task 50) carries the entry's content hash so
/// `cachette verify` can detect a later mutation of the blob.
fn migrate(conn: &Connection) -> io::Result<()> {
    let present: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM pragma_table_info('entries') WHERE name = 'artifact_key'",
            [],
            |row| row.get(0),
        )
        .map_err(sql)?;
    if present == 0 {
        conn.execute(
            "ALTER TABLE entries ADD COLUMN artifact_key TEXT NOT NULL DEFAULT ''",
            [],
        )
        .map_err(sql)?;
    }
    // Task 50: content digest for `cachette verify`. Rows written before the
    // column existed keep the '' default and are reported as
    // `EntryHealth::MissingDigest` until they are rewritten.
    let has_digest: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM pragma_table_info('entries') WHERE name = 'digest'",
            [],
            |row| row.get(0),
        )
        .map_err(sql)?;
    if has_digest == 0 {
        conn.execute(
            "ALTER TABLE entries ADD COLUMN digest TEXT NOT NULL DEFAULT ''",
            [],
        )
        .map_err(sql)?;
    }
    Ok(())
}

/// Atomic write: scratch file, fsync, rename into place. Readers never see
/// partial bytes at `dest`.
fn write_atomic(tmp: &Path, dest: &Path, data: &[u8]) -> io::Result<()> {
    let mut file = File::create(tmp)?;
    file.write_all(data)?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(tmp, dest)?;
    Ok(())
}

/// Removes a scratch file when dropped, unless [`disarm`](Self::disarm)ed.
///
/// The streaming write paths (plan task 45) create the temp file before the
/// bytes arrive, so a request dropped mid-copy would otherwise leave a partial
/// scratch file behind. The guard makes that cleanup unconditional; the caller
/// disarms it only once the temp file has been renamed into place.
struct TmpGuard {
    path: PathBuf,
    armed: bool,
}

impl TmpGuard {
    fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }

    fn disarm(mut self) {
        self.armed = false;
    }
}

impl Drop for TmpGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// Reservation gate result for [`FsStorage::write_chunk`].
enum ReservationState {
    Missing,
    Complete,
    Open,
}

/// List the inclusive byte ranges already staged for a reservation by reading
/// the `{start}.part` file names and sizes in `parts/{key}/`. An absent
/// directory means no chunks yet.
fn list_chunk_ranges(dir: &Path) -> io::Result<Vec<ChunkRange>> {
    let read = match std::fs::read_dir(dir) {
        Ok(read) => read,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err),
    };
    let mut ranges = Vec::new();
    for dirent in read.flatten() {
        let Some(name) = dirent.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Some(stem) = name.strip_suffix(".part") else {
            continue;
        };
        let Ok(start) = stem.parse::<u64>() else {
            continue;
        };
        let len = dirent.metadata()?.len();
        if len == 0 {
            continue;
        }
        ranges.push(ChunkRange {
            start,
            end: start.saturating_add(len - 1),
        });
    }
    Ok(ranges)
}

/// List a reservation's staged chunk parts as `(start, len, path)` sorted by
/// start offset. An absent directory means the reservation staged no chunks.
fn list_part_files(dir: &Path) -> io::Result<Vec<(u64, u64, PathBuf)>> {
    let read = match std::fs::read_dir(dir) {
        Ok(read) => read,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err),
    };
    let mut parts = Vec::new();
    for dirent in read.flatten() {
        let Some(name) = dirent.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Some(stem) = name.strip_suffix(".part") else {
            continue;
        };
        let Ok(start) = stem.parse::<u64>() else {
            continue;
        };
        let len = dirent.metadata()?.len();
        parts.push((start, len, dirent.path()));
    }
    parts.sort_by_key(|(start, _, _)| *start);
    Ok(parts)
}

/// Expire a reservation immediately so the reaper reclaims its staged bytes
/// (used when a commit's declared size disagrees with the uploaded chunks).
fn mark_reservation_failed(conn: &Arc<Mutex<Connection>>, id: &str) -> io::Result<()> {
    let conn = lock(conn)?;
    conn.execute(
        "UPDATE entries SET reservation_expires_at = 0 WHERE id = ?1",
        [id],
    )
    .map_err(sql)?;
    Ok(())
}

/// Stream a chunk body to `tmp` and fsync it, returning the byte count. The
/// caller renames `tmp` into place only after validating the length.
async fn stream_chunk_to_file(tmp: &Path, source: &mut ByteStream<'_>) -> io::Result<u64> {
    let mut file = tokio::fs::File::create(tmp).await?;
    let written = tokio::io::copy(source, &mut file).await?;
    file.flush().await?;
    file.sync_all().await?;
    Ok(written)
}

fn modified_unix(path: &Path) -> io::Result<i64> {
    let modified = std::fs::metadata(path)?.modified()?;
    let secs = modified
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0);
    i64::try_from(secs).map_err(|_| io::Error::other("mtime exceeds SQLite range"))
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| i64::try_from(elapsed.as_secs()).unwrap_or(0))
}

fn lock(conn: &Mutex<Connection>) -> io::Result<MutexGuard<'_, Connection>> {
    conn.lock()
        .map_err(|_| io::Error::other("sqlite connection mutex poisoned"))
}

async fn blocking<T, F>(work: F) -> io::Result<T>
where
    F: FnOnce() -> io::Result<T> + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(work)
        .await
        .map_err(io::Error::other)?
}

fn sql(err: rusqlite::Error) -> io::Error {
    io::Error::other(err)
}

/// Test suite for the FS backend. The module name keeps the plan's
/// acceptance filter `cargo test storage_fs` matching these tests.
#[cfg(test)]
mod storage_fs {
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static DIR_SEQ: AtomicU64 = AtomicU64::new(0);

    /// Unique temp directory per test, removed on drop (no tempfile dep).
    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Self {
            let seq = DIR_SEQ.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("cachette-storage-fs-{}-{seq}", std::process::id()));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).expect("create test dir");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn bytes(data: &[u8]) -> ByteStream<'static> {
        Box::pin(std::io::Cursor::new(data.to_vec()))
    }

    async fn read_all(mut stream: ByteStream<'_>) -> Vec<u8> {
        let mut out = Vec::new();
        stream.read_to_end(&mut out).await.expect("read stream");
        out
    }

    /// T52: the per-key chunk-lock map must not grow without bound. Idle locks
    /// (no live clone) are swept; a lock a task still holds survives.
    #[test]
    fn chunk_lock_sweep_prunes_idle_entries_and_keeps_held_ones() {
        let dir = TestDir::new();
        let storage = FsStorage::open(dir.path()).expect("open");
        let len = |storage: &FsStorage| {
            storage
                .chunk_locks
                .lock()
                .expect("chunk lock map poisoned")
                .len()
        };

        // Idle locks accumulate one per key ...
        for i in 0..64 {
            drop(storage.chunk_lock(&format!("staged-{i}")));
        }
        assert_eq!(len(&storage), 64);
        // ... and one sweep drops every one of them.
        assert_eq!(storage.sweep_chunk_locks(), 64);
        assert_eq!(len(&storage), 0);

        // A lock a task is still holding (or waiting on) survives the sweep.
        let held = storage.chunk_lock("in-flight");
        assert_eq!(storage.sweep_chunk_locks(), 0);
        assert_eq!(len(&storage), 1);
        drop(held);
        assert_eq!(storage.sweep_chunk_locks(), 1);
        assert_eq!(len(&storage), 0);
    }

    #[tokio::test]
    async fn put_is_invisible_until_finalize_then_round_trips() {
        let dir = TestDir::new();
        let storage = FsStorage::open(dir.path()).expect("open");
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
        assert_eq!(storage.used_bytes().await.expect("used"), 0);

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
        assert_eq!(storage.used_bytes().await.expect("used"), 11);

        let full = read_all(
            storage
                .get_range("nginx-src-1.30.5", 0..11)
                .await
                .expect("get full"),
        )
        .await;
        assert_eq!(full, b"hello world");

        let mid = read_all(
            storage
                .get_range("nginx-src-1.30.5", 6..11)
                .await
                .expect("get mid"),
        )
        .await;
        assert_eq!(mid, b"world");

        let clamped = read_all(
            storage
                .get_range("nginx-src-1.30.5", 8..99)
                .await
                .expect("clamp"),
        )
        .await;
        assert_eq!(clamped, b"rld");

        let reread = storage
            .stat("nginx-src-1.30.5")
            .await
            .expect("stat")
            .expect("stat again");
        assert!(
            reread.accessed_at >= stat.accessed_at,
            "range read bumps accessed_at"
        );

        let listed = storage.list().await.expect("list");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].key, stat.key);
        assert_eq!(listed[0].size, stat.size);
    }

    #[tokio::test]
    async fn delete_removes_visible_and_staged_and_is_idempotent() {
        let dir = TestDir::new();
        let storage = FsStorage::open(dir.path()).expect("open");
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
        assert_eq!(storage.used_bytes().await.expect("used"), 0);
        let err = storage
            .finalize("staged")
            .await
            .expect_err("staged deleted");
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[tokio::test]
    async fn finalize_is_idempotent_and_reput_supersedes_after_refinalize() {
        let dir = TestDir::new();
        let storage = FsStorage::open(dir.path()).expect("open");
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
        assert_eq!(storage.used_bytes().await.expect("used"), 9);
    }

    #[tokio::test]
    async fn get_range_rejects_inverted_and_out_of_bounds_ranges() {
        let dir = TestDir::new();
        let storage = FsStorage::open(dir.path()).expect("open");
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
        let dir = TestDir::new();
        let storage = FsStorage::open(dir.path()).expect("open");
        let err = storage.finalize("nope").await.expect_err("missing");
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[tokio::test]
    async fn empty_blob_round_trips() {
        let dir = TestDir::new();
        let storage = FsStorage::open(dir.path()).expect("open");
        storage.put_stream("e", bytes(b"")).await.expect("put");
        storage.finalize("e").await.expect("finalize");
        let stat = storage.stat("e").await.expect("stat").expect("visible");
        assert_eq!(stat.size, 0);
        let body = read_all(storage.get_range("e", 0..0).await.expect("get")).await;
        assert!(body.is_empty());
        let err = storage.get_range("e", 1..2).await.err().expect("past end");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn accounting_tracks_complete_entries_with_zero_drift_across_cycles() {
        let dir = TestDir::new();
        let storage = FsStorage::open(dir.path()).expect("open");
        let (a, b, c) = (vec![0x11; 1024], vec![0x22; 2048], vec![0x33; 3072]);
        let mut running = 0_u64;
        for (key, blob, gained) in [("a", &a, 1024), ("b", &b, 2048), ("c", &c, 3072)] {
            storage.put_stream(key, bytes(blob)).await.expect("put");
            assert_eq!(storage.used_bytes().await.expect("used"), running);
            storage.finalize(key).await.expect("finalize");
            running += gained;
            assert_eq!(storage.used_bytes().await.expect("used"), running);
        }

        storage.delete("b").await.expect("delete b");
        running -= 2048;
        assert_eq!(storage.used_bytes().await.expect("used"), running);

        // Replacing a with a different size moves accounting by the delta.
        let a2 = vec![0x44; 4096];
        storage.put_stream("a", bytes(&a2)).await.expect("reput a");
        storage.finalize("a").await.expect("refinalize a");
        running = running - 1024 + 4096;
        assert_eq!(storage.used_bytes().await.expect("used"), running);

        storage.delete("a").await.expect("delete a");
        storage.delete("c").await.expect("delete c");
        storage.delete("c").await.expect("idempotent delete");
        assert_eq!(storage.used_bytes().await.expect("used"), 0);
    }

    #[tokio::test]
    async fn crash_before_finalize_leaves_part_and_no_visible_entry_after_reboot() {
        let dir = TestDir::new();
        {
            let storage = FsStorage::open(dir.path()).expect("open");
            // Simulate "parts written, process killed before commit".
            storage
                .put_stream("k", bytes(b"staged bytes"))
                .await
                .expect("put");
        }
        let part = dir
            .path()
            .join("parts")
            .join(format!("{}.part", entry_id("k")));
        assert!(part.exists(), "staged part retained across crash");

        let storage = FsStorage::open(dir.path()).expect("reopen");
        assert_eq!(
            storage.stat("k").await.expect("stat"),
            None,
            "entry not visible after crash-before-commit"
        );
        assert!(storage.list().await.expect("list").is_empty());
        assert_eq!(storage.used_bytes().await.expect("used"), 0);
        assert!(part.exists(), "reconciliation keeps parts");

        // Surviving parts still carry a complete payload: a retried finalize
        // commits them (upload recovery path).
        storage.finalize("k").await.expect("finalize after reboot");
        let body = read_all(storage.get_range("k", 0..12).await.expect("get")).await;
        assert_eq!(body, b"staged bytes");
    }

    #[tokio::test]
    async fn crash_after_commit_is_visible_after_reboot() {
        let dir = TestDir::new();
        {
            let storage = FsStorage::open(dir.path()).expect("open");
            storage
                .put_stream("k", bytes(b"committed"))
                .await
                .expect("put");
            storage.finalize("k").await.expect("finalize");
        }
        let storage = FsStorage::open(dir.path()).expect("reopen");
        let stat = storage.stat("k").await.expect("stat").expect("visible");
        assert_eq!(stat.size, 9);
        let body = read_all(storage.get_range("k", 0..9).await.expect("get")).await;
        assert_eq!(body, b"committed");
        assert_eq!(storage.used_bytes().await.expect("used"), 9);
    }

    #[tokio::test]
    async fn crash_during_assembly_is_invisible_and_scratch_is_cleared() {
        let dir = TestDir::new();
        {
            let _storage = FsStorage::open(dir.path()).expect("open");
        }
        // Simulate a crash mid-write: scratch left, no part, no row.
        let scratch = dir.path().join("tmp").join("half-written.tmp");
        std::fs::write(&scratch, b"partial").expect("write scratch");

        let storage = FsStorage::open(dir.path()).expect("reopen");
        assert!(storage.list().await.expect("list").is_empty());
        assert!(!scratch.exists(), "stale scratch cleared at boot");
        let err = storage.get_range("k", 0..1).await.err().expect("miss");
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[tokio::test]
    async fn reboot_reconciliation_drops_rowless_rows_and_keeps_orphan_blobs() {
        let dir = TestDir::new();
        {
            let storage = FsStorage::open(dir.path()).expect("open");
            storage
                .put_stream("k", bytes(b"payload"))
                .await
                .expect("put");
            storage.finalize("k").await.expect("finalize");
        }
        // Crash simulation: the blob vanished (external wipe) — its row must
        // go and accounting must be corrected at boot.
        std::fs::remove_file(
            dir.path()
                .join("blobs")
                .join(format!("{}.blob", entry_id("k"))),
        )
        .expect("remove blob");
        // Rowless blob: must survive for the task-11 reaper (B5 rule).
        let orphan = dir.path().join("blobs").join("0000deadbeef.blob");
        std::fs::write(&orphan, b"orphan").expect("write orphan");

        let storage = FsStorage::open(dir.path()).expect("reopen");
        assert_eq!(storage.stat("k").await.expect("stat"), None);
        assert!(storage.list().await.expect("list").is_empty());
        assert_eq!(
            storage.used_bytes().await.expect("used"),
            0,
            "accounting recomputed from surviving rows"
        );
        assert!(orphan.exists(), "rowless blob left for the reaper");
    }

    #[tokio::test]
    async fn concurrent_puts_all_become_visible() {
        let dir = TestDir::new();
        let storage = Arc::new(FsStorage::open(dir.path()).expect("open"));
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
        assert_eq!(storage.used_bytes().await.expect("used"), 8);
    }

    #[tokio::test]
    async fn list_sorts_by_key_and_stat_matches_accounting_for_many_entries() {
        let dir = TestDir::new();
        let storage = FsStorage::open(dir.path()).expect("open");
        // Insert out of list order: `list` must return key-sorted metadata.
        for (key, payload) in [("c-key", "ccc"), ("a-key", "a"), ("b-key", "bb")] {
            storage
                .put_stream(key, bytes(payload.as_bytes()))
                .await
                .expect("put");
            storage.finalize(key).await.expect("finalize");
        }

        let listed = storage.list().await.expect("list");
        let keys: Vec<&str> = listed.iter().map(|entry| entry.key.as_str()).collect();
        assert_eq!(keys, ["a-key", "b-key", "c-key"], "list is key-sorted");

        let mut sum = 0_u64;
        for entry in &listed {
            sum += entry.size;
            let found = storage
                .stat(&entry.key)
                .await
                .expect("stat")
                .expect("listed entry stat-able");
            assert_eq!(&found, entry, "stat agrees with list");
            let body = read_all(
                storage
                    .get_range(&entry.key, 0..entry.size)
                    .await
                    .expect("get"),
            )
            .await;
            assert_eq!(body.len() as u64, entry.size, "full read matches size");
        }
        assert_eq!(sum, 6);
        assert_eq!(
            storage.used_bytes().await.expect("used"),
            sum,
            "accounting equals the sum of listed sizes"
        );
    }

    #[tokio::test]
    async fn get_range_boundaries_clamp_end_and_reject_start_past_size() {
        let dir = TestDir::new();
        let storage = FsStorage::open(dir.path()).expect("open");
        storage
            .put_stream("k", bytes(b"0123456789"))
            .await
            .expect("put");
        storage.finalize("k").await.expect("finalize");

        // start == size is an empty read at EOF, not an error.
        let at_eof = read_all(storage.get_range("k", 10..10).await.expect("at eof")).await;
        assert!(at_eof.is_empty());
        let clamped = read_all(storage.get_range("k", 10..99).await.expect("clamp")).await;
        assert!(clamped.is_empty(), "end clamps to size, leaving nothing");
        let tail = read_all(storage.get_range("k", 5..u64::MAX).await.expect("huge end")).await;
        assert_eq!(tail, b"56789");

        // start strictly past size errors even when the range is empty.
        let err = storage
            .get_range("k", 11..11)
            .await
            .err()
            .expect("empty range past end");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn boot_reconciliation_corrects_accounting_drift() {
        let dir = TestDir::new();
        {
            let storage = FsStorage::open(dir.path()).expect("open");
            for (key, payload) in [("a", "aaaaa"), ("b", "bbbbbb")] {
                storage
                    .put_stream(key, bytes(payload.as_bytes()))
                    .await
                    .expect("put");
                storage.finalize(key).await.expect("finalize");
            }
            assert_eq!(storage.used_bytes().await.expect("used"), 11);
        }
        // Corrupt the index directly: the stale total an unclean shutdown
        // could leave behind.
        {
            let conn = Connection::open(dir.path().join("cachette.sqlite3")).expect("open db");
            conn.execute("UPDATE accounting SET used_bytes = 99999", [])
                .expect("plant drift");
        }

        let storage = FsStorage::open(dir.path()).expect("reopen");
        assert_eq!(
            storage.used_bytes().await.expect("used"),
            11,
            "accounting recomputed from surviving rows at boot"
        );
        assert_eq!(
            storage.list().await.expect("list").len(),
            2,
            "entries untouched"
        );
    }

    #[tokio::test]
    async fn crash_between_blob_rename_and_index_commit_is_invisible_and_sweepable() {
        let dir = TestDir::new();
        let storage = FsStorage::open(dir.path()).expect("open");
        storage
            .put_stream("keep", bytes(b"keep"))
            .await
            .expect("put");
        storage.finalize("keep").await.expect("finalize");

        // Simulate the crash window after the B5 blob rename but before the
        // index commit: blob file present, no row, no part.
        let orphan = dir
            .path()
            .join("blobs")
            .join(format!("{}.blob", entry_id("ghost")));
        std::fs::write(&orphan, b"half committed").expect("plant orphan");
        drop(storage);

        let storage = FsStorage::open(dir.path()).expect("reopen");
        assert_eq!(
            storage.stat("ghost").await.expect("stat"),
            None,
            "rowless blob is never visible"
        );
        let err = storage
            .get_range("ghost", 0..1)
            .await
            .err()
            .expect("unreadable");
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        assert!(
            orphan.exists(),
            "boot reconciliation leaves orphans for the reaper"
        );
        assert_eq!(storage.used_bytes().await.expect("used"), 4);

        // The orphan sweeper clears it; indexed blobs are never touched.
        let swept = storage.sweep_orphan_blobs(u64::MAX).await.expect("sweep");
        assert_eq!(swept, 1);
        assert!(!orphan.exists(), "rowless blob swept");
        assert_eq!(storage.used_bytes().await.expect("used"), 4);
        let stat = storage
            .stat("keep")
            .await
            .expect("stat")
            .expect("indexed entry kept");
        assert_eq!(stat.size, 4);
        // Idempotent: nothing left to sweep.
        let again = storage.sweep_orphan_blobs(u64::MAX).await.expect("resweep");
        assert_eq!(again, 0);
    }

    #[tokio::test]
    async fn concurrent_put_and_finalize_on_one_key_settle_on_one_visible_version() {
        let dir = TestDir::new();
        let storage = Arc::new(FsStorage::open(dir.path()).expect("open"));
        let mut handles = Vec::new();
        for i in 0..6_usize {
            let storage = Arc::clone(&storage);
            handles.push(tokio::spawn(async move {
                let payload = vec![b'x'; i + 1];
                storage
                    .put_stream("hot-key", bytes(&payload))
                    .await
                    .expect("put");
                storage.finalize("hot-key").await.expect("finalize");
            }));
        }
        for handle in handles {
            handle.await.expect("join");
        }

        // Whichever contender landed last commits as one atomic version:
        // a whole payload of one size, never an interleaved mix.
        let stat = storage
            .stat("hot-key")
            .await
            .expect("stat")
            .expect("one contender's version is visible");
        assert!(
            (1..=6).contains(&stat.size),
            "size is one contender's payload: {}",
            stat.size
        );
        assert_eq!(
            storage.used_bytes().await.expect("used"),
            stat.size,
            "accounting matches the surviving version"
        );
        let body = read_all(
            storage
                .get_range("hot-key", 0..stat.size)
                .await
                .expect("get"),
        )
        .await;
        assert_eq!(
            body,
            vec![b'x'; stat.size as usize],
            "whole payload readable"
        );
    }

    #[tokio::test]
    async fn put_stages_a_part_and_finalize_renames_it_to_a_hashed_blob() {
        let dir = TestDir::new();
        let storage = FsStorage::open(dir.path()).expect("open");
        let id = entry_id("k");
        let part = dir.path().join("parts").join(format!("{id}.part"));
        let blob = dir.path().join("blobs").join(format!("{id}.blob"));

        storage
            .put_stream("k", bytes(b"staged"))
            .await
            .expect("put");
        assert!(part.exists(), "put stages parts/{id}.part");
        assert!(!blob.exists(), "no blob before finalize");
        assert_eq!(std::fs::read(&part).expect("read part"), b"staged");
        assert_eq!(id.len(), 64, "entry id is hex SHA-256");
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(
            std::fs::read_dir(dir.path().join("tmp"))
                .expect("read tmp")
                .next()
                .is_none(),
            "scratch is empty once the atomic write completes"
        );

        storage.finalize("k").await.expect("finalize");
        assert!(!part.exists(), "part renamed away by finalize");
        assert_eq!(std::fs::read(&blob).expect("read blob"), b"staged");
        assert_eq!(storage.used_bytes().await.expect("used"), 6);
    }

    #[tokio::test]
    async fn keys_with_path_metacharacters_stay_inside_the_data_root() {
        let dir = TestDir::new();
        let storage = FsStorage::open(dir.path()).expect("open");
        let keys = ["../evil", "nested/dir/key", "ünïcödé-☃", "..", "a\\b"];
        for key in keys {
            storage
                .put_stream(key, bytes(key.as_bytes()))
                .await
                .expect("put");
            storage.finalize(key).await.expect("finalize");
        }
        for key in keys {
            let stat = storage.stat(key).await.expect("stat").expect("key visible");
            assert_eq!(stat.size, key.len() as u64);
            let body = read_all(storage.get_range(key, 0..stat.size).await.expect("get")).await;
            assert_eq!(body, key.as_bytes(), "round-trip for {key:?}");
        }
        // Every blob file is a bare 64-hex name: keys never became path
        // segments, so no metacharacter could escape the data root.
        let mut names: Vec<String> = std::fs::read_dir(dir.path().join("blobs"))
            .expect("read blobs")
            .map(|entry| {
                entry
                    .expect("dirent")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        names.sort();
        assert_eq!(names.len(), keys.len());
        for name in names {
            let stem = name.strip_suffix(".blob").expect("blob suffix");
            assert_eq!(stem.len(), 64);
            assert!(stem.chars().all(|c| c.is_ascii_hexdigit()), "{name}");
        }
    }

    #[tokio::test]
    async fn aborting_a_put_stream_future_leaves_no_staged_or_visible_state() {
        use std::pin::Pin;
        use std::task::{Context, Poll};
        use tokio::io::{AsyncRead, ReadBuf};

        /// Stream that never yields bytes: aborting the put must cancel it
        /// before anything reaches the filesystem (trait cancel-safety).
        struct PendingStream;

        impl AsyncRead for PendingStream {
            fn poll_read(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                _buf: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                Poll::Pending
            }
        }

        let dir = TestDir::new();
        let storage = Arc::new(FsStorage::open(dir.path()).expect("open"));
        let put = tokio::spawn({
            let storage = Arc::clone(&storage);
            async move {
                let stream: ByteStream<'static> = Box::pin(PendingStream);
                storage.put_stream("k", stream).await
            }
        });
        put.abort();
        let join = put.await.expect_err("aborted before completion");
        assert!(join.is_cancelled());

        assert_eq!(storage.stat("k").await.expect("stat"), None);
        assert!(storage.list().await.expect("list").is_empty());
        assert_eq!(storage.used_bytes().await.expect("used"), 0);
        assert!(
            std::fs::read_dir(dir.path().join("parts"))
                .expect("read parts")
                .next()
                .is_none(),
            "cancelled put stages no part file"
        );
        assert!(
            std::fs::read_dir(dir.path().join("blobs"))
                .expect("read blobs")
                .next()
                .is_none(),
            "cancelled put writes no blob"
        );
    }

    /// Plan task 45: a `PATCH` whose body copy is cancelled mid-flight leaves
    /// no scratch file behind — the `TmpGuard` reaps the partial temp file, so
    /// a dropped connection cannot leak `tmp/` entries.
    #[tokio::test]
    async fn aborting_a_write_chunk_mid_copy_leaves_no_scratch_file() {
        use std::pin::Pin;
        use std::task::{Context, Poll};
        use std::time::Duration;
        use tokio::io::{AsyncRead, ReadBuf};

        /// Emits 64 KiB and then parks forever, so the future is guaranteed to
        /// be cancelled while the scratch file is open on disk.
        struct StallingStream {
            emitted: usize,
        }

        impl AsyncRead for StallingStream {
            fn poll_read(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                buf: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                let this = self.get_mut();
                if this.emitted >= 64 * 1024 {
                    return Poll::Pending;
                }
                let n = buf.remaining().min(4096);
                buf.put_slice(&vec![0_u8; n]);
                this.emitted += n;
                Poll::Ready(Ok(()))
            }
        }

        let dir = TestDir::new();
        let storage = Arc::new(FsStorage::open(dir.path()).expect("open"));
        let expires_at = u64::try_from(unix_now()).expect("unix now") + 3600;
        storage
            .reserve("cache", "artifact-key", "v1", expires_at)
            .await
            .expect("reserve");

        let scratch = dir
            .path()
            .join("tmp")
            .join(format!("{}-0.chunk.tmp", entry_id("cache")));
        let put = tokio::spawn({
            let storage = Arc::clone(&storage);
            async move {
                let chunk = Chunk {
                    range: ChunkRange {
                        start: 0,
                        end: 128 * 1024 - 1,
                    },
                    body: Box::pin(StallingStream { emitted: 0 }),
                };
                storage.write_chunk("cache", chunk).await
            }
        });

        for _ in 0..1_000 {
            if scratch.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        assert!(scratch.exists(), "write_chunk opened its scratch file");

        put.abort();
        let join = put.await.expect_err("aborted mid-copy");
        assert!(join.is_cancelled());

        assert!(!scratch.exists(), "cancelled copy removes its scratch file");
        assert!(
            std::fs::read_dir(dir.path().join("tmp"))
                .expect("tmp dir")
                .next()
                .is_none(),
            "cancelled copy leaves the tmp dir empty"
        );
        assert!(
            std::fs::read_dir(dir.path().join("parts").join("cache")).is_err(),
            "cancelled copy stages no part file"
        );
        assert_eq!(storage.used_bytes().await.expect("used"), 0);
        assert_eq!(storage.stat("artifact-key").await.expect("stat"), None);
    }

    #[tokio::test]
    async fn delete_removes_both_blob_and_part_when_a_reput_is_staged() {
        let dir = TestDir::new();
        let storage = FsStorage::open(dir.path()).expect("open");
        let id = entry_id("k");
        storage.put_stream("k", bytes(b"v1")).await.expect("put v1");
        storage.finalize("k").await.expect("finalize v1");
        storage
            .put_stream("k", bytes(b"v2"))
            .await
            .expect("stage v2");

        let part = dir.path().join("parts").join(format!("{id}.part"));
        let blob = dir.path().join("blobs").join(format!("{id}.blob"));
        assert!(part.exists() && blob.exists(), "reput leaves both files");

        storage.delete("k").await.expect("delete");
        assert!(!part.exists(), "staged part removed");
        assert!(!blob.exists(), "visible blob removed");
        assert_eq!(storage.used_bytes().await.expect("used"), 0);
        assert_eq!(storage.stat("k").await.expect("stat"), None);
    }

    #[tokio::test]
    async fn rebooted_part_is_replaced_by_a_new_put_before_finalize() {
        let dir = TestDir::new();
        {
            let storage = FsStorage::open(dir.path()).expect("open");
            storage
                .put_stream("k", bytes(b"abandoned"))
                .await
                .expect("put");
        }
        // Crash-before-commit left the old part; a retried upload replaces
        // it wholesale so finalize commits only the new bytes.
        let storage = FsStorage::open(dir.path()).expect("reopen");
        storage
            .put_stream("k", bytes(b"fresh"))
            .await
            .expect("replace part");
        let part = dir
            .path()
            .join("parts")
            .join(format!("{}.part", entry_id("k")));
        assert_eq!(std::fs::read(&part).expect("read part"), b"fresh");

        storage.finalize("k").await.expect("finalize");
        let body = read_all(storage.get_range("k", 0..5).await.expect("get")).await;
        assert_eq!(body, b"fresh");
        assert_eq!(
            storage
                .stat("k")
                .await
                .expect("stat")
                .expect("visible")
                .size,
            5
        );
        assert_eq!(storage.used_bytes().await.expect("used"), 5);
    }

    #[tokio::test]
    async fn reservation_row_dies_at_boot_but_its_part_still_finalizes() {
        let dir = TestDir::new();
        {
            let storage = FsStorage::open(dir.path()).expect("open");
            storage
                .seed_reservation("res", b"reserved", i64::MAX as u64)
                .await
                .expect("seed");
        }
        let part = dir
            .path()
            .join("parts")
            .join(format!("{}.part", entry_id("res")));
        assert!(part.exists(), "seeded part on disk");

        // Boot reconciliation drops the row (no blob backing it) but keeps
        // the part, which still carries a complete payload.
        let storage = FsStorage::open(dir.path()).expect("reopen");
        assert_eq!(storage.stat("res").await.expect("stat"), None);
        assert!(storage.list().await.expect("list").is_empty());
        assert_eq!(storage.used_bytes().await.expect("used"), 0);
        assert!(part.exists(), "part retained across reboot");

        storage
            .finalize("res")
            .await
            .expect("finalize after reboot");
        let body = read_all(storage.get_range("res", 0..8).await.expect("get")).await;
        assert_eq!(body, b"reserved");
        assert_eq!(storage.used_bytes().await.expect("used"), 8);
    }

    #[tokio::test]
    async fn reserve_stages_a_reaper_visible_row_that_finalize_can_publish() {
        let dir = TestDir::new();
        let storage = FsStorage::open(dir.path()).expect("open");
        let now = u64::try_from(unix_now()).expect("positive clock");
        storage
            .reserve("live", "live", "", now + 3600)
            .await
            .expect("reserve");
        storage
            .reserve("expired", "expired", "", now.saturating_sub(1))
            .await
            .expect("reserve");

        assert_eq!(storage.stat("live").await.expect("stat"), None);
        assert!(storage.list().await.expect("list").is_empty());
        assert_eq!(
            storage.used_bytes().await.expect("used"),
            0,
            "reservations never count toward accounting"
        );

        let reaped = storage.reap_expired_reservations(now).await.expect("reap");
        assert_eq!(reaped, 1, "only the past-expiry reservation is reclaimed");

        storage
            .finalize("live")
            .await
            .expect("finalize live reservation");
        assert!(storage.stat("live").await.expect("stat").is_some());
    }

    #[tokio::test]
    async fn reservation_exists_reports_open_but_not_expired_reservations() {
        let dir = TestDir::new();
        let storage = FsStorage::open(dir.path()).expect("open");
        let now = u64::try_from(unix_now()).expect("positive clock");
        storage
            .reserve("open-id", "open-key", "v1", now + 3600)
            .await
            .expect("reserve open");
        storage
            .reserve("expired-id", "expired-key", "v1", now.saturating_sub(1))
            .await
            .expect("reserve expired");

        assert!(
            storage
                .reservation_exists("open-key", now)
                .await
                .expect("open")
        );
        assert!(
            !storage
                .reservation_exists("expired-key", now)
                .await
                .expect("expired")
        );
        assert!(
            !storage
                .reservation_exists("absent-key", now)
                .await
                .expect("absent")
        );
    }

    #[tokio::test]
    async fn reboots_preserve_mixed_staged_and_visible_state_with_accounting() {
        let dir = TestDir::new();
        {
            let storage = FsStorage::open(dir.path()).expect("open");
            storage
                .put_stream("keep", bytes(b"kept"))
                .await
                .expect("put");
            storage.finalize("keep").await.expect("finalize");
            storage
                .put_stream("later", bytes(b"pending"))
                .await
                .expect("stage later");
        }

        let storage = FsStorage::open(dir.path()).expect("reopen");
        let body = read_all(storage.get_range("keep", 0..4).await.expect("get")).await;
        assert_eq!(body, b"kept");
        assert_eq!(storage.used_bytes().await.expect("used"), 4);
        assert_eq!(storage.stat("later").await.expect("stat"), None);

        storage.finalize("later").await.expect("finalize later");
        let listed = storage.list().await.expect("list");
        let keys: Vec<&str> = listed.iter().map(|entry| entry.key.as_str()).collect();
        assert_eq!(keys, ["keep", "later"]);
        assert_eq!(storage.used_bytes().await.expect("used"), 11);
        drop(storage);

        let storage = FsStorage::open(dir.path()).expect("second reopen");
        assert_eq!(storage.list().await.expect("list").len(), 2);
        assert_eq!(storage.used_bytes().await.expect("used"), 11);
    }

    #[tokio::test]
    async fn binary_payload_windows_round_trip_byte_exact() {
        let dir = TestDir::new();
        let storage = FsStorage::open(dir.path()).expect("open");
        let data: Vec<u8> = (0_u8..=255).collect();
        storage.put_stream("bin", bytes(&data)).await.expect("put");
        storage.finalize("bin").await.expect("finalize");

        for (start, end) in [(0, 256), (0, 1), (128, 129), (128, 256), (255, 256)] {
            let window = read_all(storage.get_range("bin", start..end).await.expect("range")).await;
            assert_eq!(window, data[start as usize..end as usize], "{start}..{end}");
        }
        assert_eq!(
            storage
                .stat("bin")
                .await
                .expect("stat")
                .expect("visible")
                .size,
            256
        );
        assert_eq!(storage.used_bytes().await.expect("used"), 256);
    }

    /// Plan task 9 QA scenario: a 64 MiB save produces exactly one blob file
    /// of exact size and accounting survives reboot.
    #[tokio::test]
    #[ignore = "slow 64 MiB QA scenario; run with --ignored"]
    async fn large_blob_round_trip_64mib() {
        let dir = TestDir::new();
        let storage = FsStorage::open(dir.path()).expect("open");
        let size = 64 * 1024 * 1024;
        let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        storage.put_stream("big", bytes(&data)).await.expect("put");
        storage.finalize("big").await.expect("finalize");

        let stat = storage.stat("big").await.expect("stat").expect("visible");
        assert_eq!(stat.size, size);
        let blob = dir
            .path()
            .join("blobs")
            .join(format!("{}.blob", entry_id("big")));
        assert_eq!(
            std::fs::metadata(&blob).expect("blob metadata").len(),
            size,
            "exactly one blob file of exact size"
        );
        assert_eq!(
            std::fs::read_dir(dir.path().join("blobs"))
                .expect("read blobs dir")
                .count(),
            1
        );

        let window = read_all(
            storage
                .get_range("big", 1_000_000..1_000_100)
                .await
                .expect("range"),
        )
        .await;
        assert_eq!(window.as_slice(), &data[1_000_000..1_000_100]);
        drop(storage);

        let reopened = FsStorage::open(dir.path()).expect("reopen");
        assert_eq!(reopened.used_bytes().await.expect("used"), size);
    }

    #[tokio::test]
    async fn put_block_then_assemble_publishes_visible_entry_in_listed_order() {
        let dir = TestDir::new();
        let storage = FsStorage::open(dir.path()).expect("open");
        let now = u64::try_from(unix_now()).expect("positive clock");
        storage
            .reserve("cache-id", "artifact-key", "v1", now + 3600)
            .await
            .expect("reserve");

        // Stage three named blocks, then list them out of upload order.
        for (id, data) in [
            ("aa", &b"first"[..]),
            ("bb", &b"second"[..]),
            ("cc", &b"third"[..]),
        ] {
            storage
                .put_block("cache-id", id, bytes(data))
                .await
                .expect("put block");
        }
        assert_eq!(
            storage.stat("artifact-key").await.expect("stat"),
            None,
            "staged blocks stay invisible"
        );
        assert_eq!(storage.used_bytes().await.expect("used"), 0);

        let ordered = vec!["cc".to_owned(), "aa".to_owned(), "bb".to_owned()];
        let size = storage
            .assemble_blocks("cache-id", &ordered)
            .await
            .expect("assemble");
        assert_eq!(size, (5 + 5 + 6) as u64);

        let body = read_all(
            storage
                .get_range("artifact-key", 0..size)
                .await
                .expect("get"),
        )
        .await;
        assert_eq!(body, b"thirdfirstsecond");
        assert_eq!(storage.used_bytes().await.expect("used"), size);
        // The reservation is consumed: a second assemble is not found.
        let err = storage
            .assemble_blocks("cache-id", &ordered)
            .await
            .expect_err("reservation consumed");
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[tokio::test]
    async fn assemble_blocks_rejects_a_block_that_was_never_staged() {
        let dir = TestDir::new();
        let storage = FsStorage::open(dir.path()).expect("open");
        let now = u64::try_from(unix_now()).expect("positive clock");
        storage
            .reserve("cache-id", "artifact-key", "v1", now + 3600)
            .await
            .expect("reserve");
        storage
            .put_block("cache-id", "aa", bytes(b"present"))
            .await
            .expect("put block");

        let ordered = vec!["aa".to_owned(), "missing".to_owned()];
        let err = storage
            .assemble_blocks("cache-id", &ordered)
            .await
            .expect_err("unknown block");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(
            storage.stat("artifact-key").await.expect("stat"),
            None,
            "a failed assemble publishes nothing"
        );
    }

    #[tokio::test]
    async fn commit_chunks_records_a_digest_and_verify_flags_changed_bytes() {
        let dir = TestDir::new();
        let storage = FsStorage::open(dir.path()).expect("open");
        let now = u64::try_from(unix_now()).expect("positive clock");
        storage
            .reserve("cache-id", "artifact-key", "v1", now + 3600)
            .await
            .expect("reserve");

        let body = b"bitrot me";
        storage
            .write_chunk(
                "cache-id",
                Chunk {
                    range: ChunkRange {
                        start: 0,
                        end: (body.len() - 1) as u64,
                    },
                    body: bytes(body),
                },
            )
            .await
            .expect("write chunk");
        storage
            .commit_chunks("cache-id", body.len() as u64)
            .await
            .expect("commit");

        let report = storage.verify_all().expect("verify");
        assert_eq!(report.len(), 1);
        assert_eq!(report[0].key, "artifact-key");
        assert_eq!(report[0].size, body.len() as u64);
        assert_eq!(report[0].health, EntryHealth::Ok);
        assert!(report[0].is_ok());

        // Flip one byte in the published blob: verify must flag the entry, and
        // the recorded digest is still the digest of the untampered body.
        let blob = dir
            .path()
            .join("blobs")
            .join(format!("{}.blob", entry_id("artifact-key")));
        let mut on_disk = std::fs::read(&blob).expect("read blob");
        on_disk[0] ^= 0x01;
        std::fs::write(&blob, &on_disk).expect("rewrite blob");

        let report = storage.verify_all().expect("verify again");
        assert_eq!(report.len(), 1);
        match &report[0].health {
            EntryHealth::DigestMismatch { expected, actual } => {
                assert_eq!(expected, &digest::hash_bytes(body));
                assert_ne!(actual, expected);
            }
            other => panic!("expected a digest mismatch, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn assemble_blocks_records_a_digest_and_verify_flags_a_truncated_blob() {
        let dir = TestDir::new();
        let storage = FsStorage::open(dir.path()).expect("open");
        let now = u64::try_from(unix_now()).expect("positive clock");
        storage
            .reserve("cache-id", "artifact-key", "v1", now + 3600)
            .await
            .expect("reserve");
        storage
            .put_block("cache-id", "aa", bytes(b"first"))
            .await
            .expect("put block aa");
        storage
            .put_block("cache-id", "bb", bytes(b"second"))
            .await
            .expect("put block bb");
        let ordered = vec!["aa".to_owned(), "bb".to_owned()];
        storage
            .assemble_blocks("cache-id", &ordered)
            .await
            .expect("assemble");

        let report = storage.verify_all().expect("verify");
        assert_eq!(report.len(), 1);
        assert_eq!(report[0].size, 11);
        assert_eq!(report[0].health, EntryHealth::Ok);

        // Truncate the blob: the size check fires before any hashing.
        let blob = dir
            .path()
            .join("blobs")
            .join(format!("{}.blob", entry_id("artifact-key")));
        std::fs::write(&blob, b"firs").expect("truncate blob");

        let report = storage.verify_all().expect("verify again");
        assert_eq!(
            report[0].health,
            EntryHealth::SizeMismatch {
                expected: 11,
                actual: 4
            }
        );
    }

    #[test]
    fn migration_adds_the_digest_column_to_a_pre_t50_database() {
        let dir = TestDir::new();
        // Build a legacy index by hand: the entries table as it looked before
        // task 50, with no digest column.
        {
            let conn =
                Connection::open(dir.path().join("cachette.sqlite3")).expect("open legacy index");
            conn.execute_batch(
                "CREATE TABLE entries (\
                     id TEXT PRIMARY KEY, \
                     key TEXT NOT NULL, \
                     version TEXT NOT NULL DEFAULT '', \
                     size INTEGER NOT NULL, \
                     created_at INTEGER NOT NULL, \
                     accessed_at INTEGER NOT NULL, \
                     complete INTEGER NOT NULL DEFAULT 0, \
                     owner_node TEXT NOT NULL DEFAULT '', \
                     reservation_expires_at INTEGER, \
                     artifact_key TEXT NOT NULL DEFAULT '');\
                 CREATE TABLE accounting (used_bytes INTEGER NOT NULL);\
                 INSERT INTO accounting (used_bytes) VALUES (0);",
            )
            .expect("legacy schema");
        }

        let storage = FsStorage::open(dir.path()).expect("open migrates the legacy index");
        let conn = lock(&storage.conn).expect("lock");
        let mut stmt = conn
            .prepare("SELECT name FROM pragma_table_info('entries')")
            .expect("prepare");
        let columns: Vec<String> = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .expect("query")
            .collect::<Result<Vec<_>, _>>()
            .expect("collect columns");
        assert!(
            columns.iter().any(|name| name == "digest"),
            "digest column missing after migration: {columns:?}"
        );
    }

    #[tokio::test]
    async fn put_and_assemble_block_require_an_open_reservation() {
        let dir = TestDir::new();
        let storage = FsStorage::open(dir.path()).expect("open");

        let err = storage
            .put_block("unknown-cache", "aa", bytes(b"x"))
            .await
            .expect_err("put block without reservation");
        assert_eq!(err.kind(), io::ErrorKind::NotFound);

        let err = storage
            .assemble_blocks("unknown-cache", &["aa".to_owned()])
            .await
            .expect_err("assemble without reservation");
        assert_eq!(err.kind(), io::ErrorKind::NotFound);

        let now = u64::try_from(unix_now()).expect("positive clock");
        storage
            .reserve("expired-cache", "expired-key", "v1", now.saturating_sub(1))
            .await
            .expect("reserve expired");
        let err = storage
            .put_block("expired-cache", "aa", bytes(b"x"))
            .await
            .expect_err("put block on expired reservation");
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }
}
