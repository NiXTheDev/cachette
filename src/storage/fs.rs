//! Filesystem-backed storage with a SQLite metadata index (plan task 9 / B5).
//!
//! Layout under the configured data root (`[storage.fs] path`):
//!
//! ```text
//! <root>/cachette.sqlite3   metadata + accounting index (rusqlite, WAL)
//! <root>/blobs/{id}.blob    finalized whole-blob payloads
//! <root>/chunks/{id}.chunk  finalized content-defined chunk payloads (CDC)
//! <root>/parts/{id}.part    staged payload awaiting finalize
//! <root>/tmp/               scratch for atomic temp-file + rename writes
//! ```
//!
//! Entries carry a `layout` column (`whole` | `chunked`, docs/cdc.md): CDC-off
//! finalizations publish whole blobs exactly as v1.0; CDC-on finalizations cut
//! the staged payload into deduplicated content chunks ([`cdc::CdcSplitter`])
//! referenced from a per-entry manifest. The read path branches on `layout`,
//! so chunked at-rest data stays readable whatever the current flag says.
//! Accounting counts unique bytes at rest: whole blob sizes plus chunk sizes
//! with `refs > 0`.
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

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::fmt::Write as _;
use std::fs::File;
use std::io;
use std::io::{Read, Seek, SeekFrom, Write};
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use blake3::Hasher;
use rusqlite::{Connection, OptionalExtension, params, params_from_iter};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadBuf};
use tokio::sync::RwLock;

use super::{
    BoxFuture, ByteStream, Chunk, ChunkOutcome, ChunkRange, EntryStat, StorageBackend,
    cdc::{self, CdcParams},
    complete,
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
        digest                  TEXT NOT NULL DEFAULT '',
        layout                  TEXT NOT NULL DEFAULT 'whole',
        namespace               TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX IF NOT EXISTS entries_key_idx ON entries(key);
    CREATE TABLE IF NOT EXISTS accounting (
        namespace  TEXT NOT NULL DEFAULT '',
        used_bytes INTEGER NOT NULL
    );
    INSERT INTO accounting (used_bytes)
        SELECT 0 WHERE NOT EXISTS (SELECT 1 FROM accounting);
    CREATE TABLE IF NOT EXISTS chunks (
        id          TEXT PRIMARY KEY,
        size        INTEGER NOT NULL,
        refs        INTEGER NOT NULL DEFAULT 0,
        created_at  INTEGER NOT NULL,
        namespace   TEXT NOT NULL DEFAULT ''
    );
    CREATE TABLE IF NOT EXISTS entry_chunks (
        entry_id  TEXT NOT NULL,
        seq       INTEGER NOT NULL,
        chunk_id  TEXT NOT NULL,
        namespace TEXT NOT NULL DEFAULT '',
        PRIMARY KEY (entry_id, seq)
    );
    CREATE INDEX IF NOT EXISTS entry_chunks_chunk_idx ON entry_chunks(chunk_id);
    CREATE TABLE IF NOT EXISTS meta (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
    );
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
    /// A `chunked` entry's manifest names a `chunks/{id}.chunk` file that is
    /// gone (docs/cdc.md failure model). Reported as "missing M of N chunks".
    MissingChunk {
        /// Number of manifest chunks whose file is missing.
        missing: u64,
        /// Total chunks in the entry's manifest.
        total: u64,
    },
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
    /// metadata is never observed describing a blob mid-swap. Shared with the
    /// namespace views: one gate for the whole index.
    gate: Arc<RwLock<()>>,
    /// Per-reservation chunk locks (see [`ChunkLocks`]). Shared with the
    /// namespace views.
    chunk_locks: Arc<ChunkLocks>,
    /// CDC cutting params (v1.1 workstream B): `None` publishes whole blobs
    /// like v1.0. Only shapes new finalizations; reads are layout-aware
    /// regardless (docs/cdc.md).
    cdc: Option<CdcParams>,
    /// The namespace this view reads and writes (v1.2 workstream F,
    /// docs/shared-cache.md). The default namespace ("") keeps the v1.1 id
    /// derivation, so rows written before namespaces existed stay reachable;
    /// other namespaces get their own ids and their own accounting.
    namespace: String,
}

/// What one orphan-chunk sweep pass reclaimed (docs/cdc.md §GC).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChunkSweep {
    /// Rowless `chunks/{id}.chunk` files deleted.
    pub files: u64,
    /// Aged `chunks/{id}.chunk.tmp` finalize-scratch files deleted.
    pub temps: u64,
    /// Belt-and-braces `chunks` rows with `refs = 0` purged (the normal
    /// release paths delete those in-tx, so these should never exist).
    pub rows: u64,
}

/// One completed whole->chunked conversion (docs/cdc.md, Migration): the
/// entry flipped layout in a verified transaction and its blob file was
/// unlinked post-commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WholeConversion {
    /// The converted entry's id.
    pub id: String,
    /// Bytes the whole blob occupied (the entry's payload size).
    pub blob_bytes: u64,
    /// Bytes the entry's chunk manifest sums to (== `blob_bytes` when the
    /// chunks were all fresh; less when dedup hit shared content).
    pub chunk_bytes: u64,
}

/// What one backfill step decided (docs/cdc.md, Migration).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BackfillStep {
    /// An entry converted; its blob was unlinked after the commit.
    Converted(WholeConversion),
    /// The picked row changed under us (deleted, re-put with different
    /// content, or flipped by another writer) between the pick and the
    /// commit - the guarded `UPDATE` matched no row. Nothing was committed;
    /// any chunk files written for the abandoned pass are rowless and the
    /// sweeper converges on them. The next step re-picks.
    Raced,
    /// No convertible entry remains (every `whole` row either carries a
    /// legacy empty digest or sits in the caller's skip set).
    Exhausted,
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
    /// call during startup or tests, never on the request path. Finalizes
    /// publish whole blobs (CDC off).
    pub fn open(root: impl AsRef<Path>) -> io::Result<Self> {
        Self::open_cdc(root, None)
    }

    /// [`FsStorage::open`] with `[storage.cdc]` applied: passing
    /// [`Some`](Option)`(params)` makes every new finalization cut its payload
    /// into deduplicated content chunks; `None` behaves like `open`. Reads and
    /// deletes are layout-aware either way (docs/cdc.md).
    pub fn open_cdc(root: impl AsRef<Path>, cdc: Option<CdcParams>) -> io::Result<Self> {
        let root = root.as_ref().to_path_buf();
        for dir in ["blobs", "chunks", "parts", "tmp"] {
            std::fs::create_dir_all(root.join(dir))?;
        }
        let mut conn = Connection::open(root.join("cachette.sqlite3")).map_err(sql)?;
        conn.busy_timeout(Duration::from_secs(5)).map_err(sql)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")
            .map_err(sql)?;
        conn.execute_batch(SCHEMA).map_err(sql)?;
        let version = schema_version(&conn)?;
        if version > SCHEMA_VERSION {
            return Err(io::Error::other(format!(
                "storage index schema is at version {version}, newer than this \
                 binary's schema version {SCHEMA_VERSION}; downgrade refused and \
                 the index is left untouched"
            )));
        }
        if version < SCHEMA_VERSION {
            run_migrations(&mut conn, version)?;
            tracing::info!(
                from = version,
                to = SCHEMA_VERSION,
                "storage index schema migrated"
            );
        }
        // The version row can lie (a hand-mangled index, a partial restore
        // from backup): verification is unconditional on every boot, and a
        // gap refuses to open rather than serving from a lying schema.
        verify_schema(&conn)?;
        let storage = Self {
            root,
            conn: Arc::new(Mutex::new(conn)),
            gate: Arc::new(RwLock::new(())),
            chunk_locks: Arc::new(Mutex::new(HashMap::new())),
            cdc,
            namespace: String::new(),
        };
        storage.reconcile()?;
        Ok(storage)
    }

    /// A view of this index restricted to one namespace (v1.2 workstream F).
    ///
    /// The namespace is part of a row's identity: the ids differ, the
    /// accounting is per namespace, and the view shares the connection, the
    /// write gate and the chunk locks with the index it came from - two
    /// namespaces never share a lock, and neither shares a row.
    pub fn scoped(&self, namespace: &str) -> Self {
        Self {
            root: self.root.clone(),
            conn: Arc::clone(&self.conn),
            gate: Arc::clone(&self.gate),
            chunk_locks: Arc::clone(&self.chunk_locks),
            cdc: self.cdc,
            namespace: namespace.to_owned(),
        }
    }

    /// The id of the entry `key` resolves to in this view's namespace.
    fn entry_id_for(&self, key: &str) -> String {
        entry_id_in(&self.namespace, key)
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
        let rows: Vec<(String, String, i64, String, String)> = {
            let conn = lock(&self.conn)?;
            let mut stmt = conn
                .prepare(
                    "SELECT id, key, size, digest, layout FROM entries \
                     WHERE complete = 1 ORDER BY key",
                )
                .map_err(sql)?;
            let rows = stmt
                .query_map([], |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                })
                .map_err(sql)?;
            rows.collect::<Result<Vec<_>, _>>().map_err(sql)?
        };
        let mut reports = Vec::with_capacity(rows.len());
        for (id, key, size, stored, layout) in rows {
            let recorded = u64::try_from(size).unwrap_or(0);
            let health = if layout == "chunked" {
                self.verify_chunked(&id, recorded, &stored)?
            } else {
                let blob = self.blob_path(&id);
                match std::fs::metadata(&blob) {
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

    /// Integrity of one `chunked` entry (docs/cdc.md §verify semantics):
    /// every manifest chunk file must exist, the summed on-disk sizes must
    /// equal the recorded entry size, and the chunk bytes folded in sequence
    /// order must recompute the recorded whole-payload digest.
    fn verify_chunked(&self, id: &str, recorded: u64, stored: &str) -> io::Result<EntryHealth> {
        let manifest: Vec<(String, i64)> = {
            let conn = lock(&self.conn)?;
            let mut stmt = conn
                .prepare(
                    "SELECT c.id, c.size FROM entry_chunks ec \
                     JOIN chunks c ON c.id = ec.chunk_id \
                     WHERE ec.entry_id = ?1 ORDER BY ec.seq",
                )
                .map_err(sql)?;
            let rows = stmt
                .query_map([id], |row| Ok((row.get(0)?, row.get(1)?)))
                .map_err(sql)?;
            rows.collect::<Result<Vec<_>, _>>().map_err(sql)?
        };
        let mut on_disk = 0_u64;
        let mut missing = 0_u64;
        let mut files = Vec::with_capacity(manifest.len());
        for (chunk_id, _size) in &manifest {
            let path = self.chunk_path(chunk_id);
            match std::fs::metadata(&path) {
                Err(err) if err.kind() == io::ErrorKind::NotFound => missing += 1,
                Err(err) => return Err(err),
                Ok(meta) => {
                    on_disk += meta.len();
                    files.push(path);
                }
            }
        }
        if missing > 0 {
            return Ok(EntryHealth::MissingChunk {
                missing,
                total: u64::try_from(manifest.len()).unwrap_or(u64::MAX),
            });
        }
        if on_disk != recorded {
            return Ok(EntryHealth::SizeMismatch {
                expected: recorded,
                actual: on_disk,
            });
        }
        if stored.is_empty() {
            return Ok(EntryHealth::MissingDigest);
        }
        let actual = digest::hash_files(&files)?;
        Ok(if actual == stored {
            EntryHealth::Ok
        } else {
            EntryHealth::DigestMismatch {
                expected: stored.to_owned(),
                actual,
            }
        })
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
                    .query_map(
                        [i64::try_from(now_unix).expect("unix stamp fits i64")],
                        |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                    )
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
    /// owning row that are older than `older_than_unix` — rowless leftovers
    /// of a crash between the B5 blob rename and the index commit, plus a
    /// `chunked` row's blob file (the crash window between a whole->chunked
    /// conversion's commit and its blob unlink: only `whole` rows own a
    /// blob, docs/cdc.md §GC). Recent orphans are kept: they may belong to
    /// a finalize still in flight. Returns the number of blobs swept.
    pub async fn sweep_orphan_blobs(&self, older_than_unix: u64) -> io::Result<u64> {
        let _gate = self.gate.write().await;
        let conn = Arc::clone(&self.conn);
        let blobs = self.root.join("blobs");
        blocking(move || {
            let known: std::collections::HashSet<String> = {
                let conn = lock(&conn)?;
                let mut stmt = conn
                    .prepare("SELECT id FROM entries WHERE layout = 'whole'")
                    .map_err(sql)?;
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

    /// docs/cdc.md §GC backstop: age out the chunk-side leftovers the
    /// best-effort post-commit unlinks can leave behind, all under the same
    /// grace (a fresh leftover may belong to a pass still in flight):
    /// rowless `chunks/{id}.chunk` files, aged `chunks/{id}.chunk.tmp`
    /// finalize scratch, and belt-and-braces `chunks` rows with `refs = 0`
    /// (the release paths delete those in-tx, so they should not exist).
    /// Rows with `refs > 0` are never touched, and a zero-ref purge moves
    /// no accounting (only `refs > 0` bytes are counted). `tmp/` scratch is
    /// not this sweep's business: boot reconciliation wipes it wholesale.
    /// Returns the per-kind counts.
    pub async fn sweep_orphan_chunks(&self, older_than_unix: u64) -> io::Result<ChunkSweep> {
        let _gate = self.gate.write().await;
        let conn = Arc::clone(&self.conn);
        let chunks_dir = self.root.join("chunks");
        blocking(move || {
            let mut swept = ChunkSweep {
                files: 0,
                temps: 0,
                rows: 0,
            };
            let cutoff = i64::try_from(older_than_unix).unwrap_or(i64::MAX);
            let known: std::collections::HashSet<String> = {
                let conn = lock(&conn)?;
                // Zero-ref rows first: purging them makes their files
                // sweepable in this same pass (one-pass convergence).
                let stale: Vec<String> = {
                    let mut stmt = conn
                        .prepare("SELECT id FROM chunks WHERE refs <= 0 AND created_at <= ?1")
                        .map_err(sql)?;
                    let rows = stmt
                        .query_map([cutoff], |row| row.get::<_, String>(0))
                        .map_err(sql)?;
                    rows.collect::<Result<Vec<_>, _>>().map_err(sql)?
                };
                for id in &stale {
                    conn.execute("DELETE FROM chunks WHERE id = ?1", [id])
                        .map_err(sql)?;
                }
                swept.rows = u64::try_from(stale.len()).unwrap_or(u64::MAX);
                let mut stmt = conn.prepare("SELECT id FROM chunks").map_err(sql)?;
                let rows = stmt
                    .query_map([], |row| row.get::<_, String>(0))
                    .map_err(sql)?;
                rows.collect::<Result<_, _>>().map_err(sql)?
            };
            let read = match std::fs::read_dir(&chunks_dir) {
                Ok(read) => read,
                Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(swept),
                Err(err) => return Err(err),
            };
            for dirent in read.flatten() {
                let Some(name) = dirent.file_name().to_str().map(str::to_owned) else {
                    continue;
                };
                let temp = name.ends_with(".chunk.tmp");
                let Some(chunk_id) = name.strip_suffix(if temp { ".chunk.tmp" } else { ".chunk" })
                else {
                    continue;
                };
                if !temp && known.contains(chunk_id) {
                    continue;
                }
                match modified_unix(&dirent.path()) {
                    Ok(mtime) if mtime <= cutoff => {}
                    _ => continue,
                }
                if std::fs::remove_file(dirent.path()).is_ok() {
                    if temp {
                        swept.temps += 1;
                    } else {
                        swept.files += 1;
                    }
                }
            }
            tracing::debug!(
                files = swept.files,
                temps = swept.temps,
                zero_ref_rows = swept.rows,
                "rowless chunks swept"
            );
            Ok(swept)
        })
        .await
    }

    /// docs/cdc.md, Migration: convert ONE complete `whole` entry to the
    /// `chunked` layout, smallest first, skipping ids in `skip` (the
    /// caller-owned corruption park). Steps:
    ///
    /// 1. pick under the conn mutex only - the chunking pass below runs
    ///    lock-free, so live traffic interleaves with a conversion;
    /// 2. stream the blob through the chunker (bounded memory, same code
    ///    path as finalize). A blob that is gone, or whose content digests
    ///    differently than its row claims, is corruption rather than a
    ///    conversion failure: warn, park the id in `skip`, try the
    ///    next-smallest. A digest mismatch is only detected after the chunk
    ///    files are written; they stay rowless and the sweeper converges on
    ///    them, exactly like a finalize crash mid-pass;
    /// 3. commit under the single-writer gate (like finalize): one
    ///    transaction whose guarded UPDATE re-checks the picked row's
    ///    layout/completeness/size/digest, so a delete or a re-put with
    ///    different content in between matches no row and the pass is
    ///    discarded ([`BackfillStep::Raced`]); then register the manifest
    ///    (`acquire_chunk_manifest`), move accounting
    ///    (`used -= blob; used += added`, size-neutral without dedup), and
    ///    unlink the blob post-commit (best-effort: a missed unlink is the
    ///    sweeper's crash window, docs/cdc.md GC).
    ///
    /// Legacy rows with an empty digest are never picked (their integrity
    /// cannot be checked; they stay whole). Returns what happened; the next
    /// call re-picks, so a walker converges by looping until
    /// [`BackfillStep::Exhausted`].
    pub async fn backfill_step(
        &self,
        params: CdcParams,
        skip: &mut HashSet<String>,
    ) -> io::Result<BackfillStep> {
        loop {
            let picked = {
                let conn = lock(&self.conn)?;
                pick_whole_entry(&conn, skip)?
            };
            let Some((id, blob_bytes, digest, namespace)) = picked else {
                return Ok(BackfillStep::Exhausted);
            };
            let blob_path = self.root.join("blobs").join(format!("{id}.blob"));
            let mut blob = match File::open(&blob_path) {
                Ok(file) => file,
                Err(err) if err.kind() == io::ErrorKind::NotFound => {
                    tracing::warn!(entry = %id, "backfill: whole entry has no blob; skipping");
                    skip.insert(id);
                    continue;
                }
                Err(err) => return Err(err),
            };
            let chunks_dir = self.root.join("chunks");
            let payload = chunk_payload(&chunks_dir, params, &mut blob)?;
            if payload.digest != digest {
                tracing::warn!(
                    entry = %id,
                    "backfill: blob digest does not match its row; skipping"
                );
                skip.insert(id);
                continue;
            }
            let blob_size = i64::try_from(blob_bytes).unwrap_or(i64::MAX);
            let _gate = self.gate.write().await;
            let conn = Arc::clone(&self.conn);
            let row_id = id.clone();
            let committed = blocking(move || {
                let mut conn = lock(&conn)?;
                let tx = conn.transaction().map_err(sql)?;
                let changed = tx
                    .execute(
                        "UPDATE entries SET layout = 'chunked' \
                         WHERE id = ?1 AND layout = 'whole' AND complete = 1 \
                           AND size = ?2 AND digest = ?3",
                        params![row_id, blob_size, digest],
                    )
                    .map_err(sql)?;
                if changed == 0 {
                    tx.rollback().map_err(sql)?;
                    return Ok(None);
                }
                let mut unlink = Vec::new();
                let added =
                    acquire_chunk_manifest(&tx, &namespace, &row_id, &payload, &mut unlink)?;
                let used = namespace_used_bytes(&tx, &namespace)?;
                let used = used.saturating_sub(blob_size).saturating_add(added);
                set_namespace_used_bytes(&tx, &namespace, used)?;
                tx.commit().map_err(sql)?;
                Ok(Some(added))
            })
            .await?;
            let Some(added) = committed else {
                return Ok(BackfillStep::Raced);
            };
            if let Err(err) = std::fs::remove_file(&blob_path)
                && err.kind() != io::ErrorKind::NotFound
            {
                tracing::warn!(
                    entry = %id,
                    error = %err,
                    "backfill: blob unlink failed; the sweeper will reclaim it"
                );
            }
            return Ok(BackfillStep::Converted(WholeConversion {
                id,
                blob_bytes,
                chunk_bytes: u64::try_from(added).unwrap_or(0),
            }));
        }
    }

    /// How many entries still await backfill conversion: complete `whole`
    /// rows carrying a content digest (docs/cdc.md, Migration).
    pub async fn pending_whole_entries(&self) -> io::Result<u64> {
        let conn = Arc::clone(&self.conn);
        blocking(move || {
            let conn = lock(&conn)?;
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM entries \
                     WHERE complete = 1 AND layout = 'whole' AND digest != ''",
                    [],
                    |row| row.get(0),
                )
                .map_err(sql)?;
            Ok(u64::try_from(count.max(0)).unwrap_or(0))
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
        let id = self.entry_id_for(key);
        let tmp = self.tmp_path(&id);
        let part = self.part_path(&id);
        let conn = Arc::clone(&self.conn);
        let namespace = self.namespace.clone();
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
                      reservation_expires_at, namespace) \
                 VALUES (?1, ?2, '', ?3, ?4, ?4, 0, ?5, ?6) \
                 ON CONFLICT(id) DO UPDATE SET \
                     complete = 0, reservation_expires_at = excluded.reservation_expires_at",
                params![id, key, size, created_at, expires_at, namespace],
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

    /// Path of one at-rest CDC chunk payload (docs/cdc.md storage layout).
    fn chunk_path(&self, id: &str) -> PathBuf {
        self.root.join("chunks").join(format!("{id}.chunk"))
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
        let ids: Vec<(String, String)> = {
            let mut stmt = conn
                .prepare("SELECT id, layout FROM entries")
                .map_err(sql)?;
            let rows = stmt
                .query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })
                .map_err(sql)?;
            rows.collect::<Result<Vec<_>, _>>().map_err(sql)?
        };
        let mut dropped = 0_u64;
        for (id, layout) in ids {
            // `whole` entries die at boot when their blob file is gone
            // (unchanged v1.0 rule); `chunked` entries when any manifest
            // chunk file is missing, since the row can no longer serve its
            // contract. Broken entries release their chunk references so
            // the files' refcounts and accounting stay truthful.
            let intact = if layout == "chunked" {
                self.chunked_entry_intact(&conn, &id)?
            } else {
                self.blob_path(&id).exists()
            };
            if !intact {
                release_entry_manifest(&conn, &id)?;
                conn.execute("DELETE FROM entries WHERE id = ?1", [&id])
                    .map_err(sql)?;
                dropped += 1;
            }
        }
        // Unique bytes at rest (docs/cdc.md accounting invariant): whole
        // blob sizes plus chunk sizes with live references. The chunk half
        // is exact even under dedup; blob-less chunked entries never
        // double-count.
        //
        // Per namespace (v1.2 workstream F): the namespace is the unit the
        // accounting and the quotas count in, so each namespace's row is
        // recomputed on its own and the total is the sum of them.
        let mut per_namespace: BTreeMap<String, i64> = BTreeMap::new();
        {
            let mut stmt = conn
                .prepare(
                    "SELECT namespace, SUM(size) FROM entries \
                     WHERE complete = 1 AND layout = 'whole' GROUP BY namespace",
                )
                .map_err(sql)?;
            let rows = stmt
                .query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
                })
                .map_err(sql)?;
            for row in rows {
                let (namespace, size) = row.map_err(sql)?;
                per_namespace.entry(namespace.clone()).or_insert(0);
                if let Some(total) = per_namespace.get_mut(&namespace) {
                    *total += size;
                }
            }
        }
        {
            let mut stmt = conn
                .prepare(
                    "SELECT namespace, SUM(size) FROM chunks WHERE refs > 0 GROUP BY namespace",
                )
                .map_err(sql)?;
            let rows = stmt
                .query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
                })
                .map_err(sql)?;
            for row in rows {
                let (namespace, size) = row.map_err(sql)?;
                per_namespace.entry(namespace.clone()).or_insert(0);
                if let Some(total) = per_namespace.get_mut(&namespace) {
                    *total += size;
                }
            }
        }
        for (namespace, used) in &per_namespace {
            set_namespace_used_bytes(&conn, namespace, *used)?;
        }
        // Namespaces with nothing left must not keep a stale total: the
        // accounting is recomputed from the surviving rows. The DEFAULT
        // namespace's row is structural - delta writers upsert against it -
        // so it is zeroed rather than deleted; its row is recreated on the
        // next write either way.
        if !per_namespace.contains_key("") {
            set_namespace_used_bytes(&conn, "", 0)?;
        }
        conn.execute(
            "DELETE FROM accounting WHERE namespace != '' \
             AND namespace NOT IN (SELECT namespace FROM entries WHERE complete = 1)",
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

    /// Whether a `chunked` entry's manifest still backs its row: every
    /// manifest chunk file exists, and the manifest's summed sizes match the
    /// recorded whole-payload size. Checked at boot (reconcile) only.
    fn chunked_entry_intact(&self, conn: &Connection, id: &str) -> io::Result<bool> {
        let size: i64 = conn
            .query_row(
                "SELECT COALESCE((SELECT SUM(c.size) FROM entry_chunks ec \
                 JOIN chunks c ON c.id = ec.chunk_id WHERE ec.entry_id = ?1), 0)",
                [id],
                |row| row.get(0),
            )
            .map_err(sql)?;
        let recorded: i64 = conn
            .query_row("SELECT size FROM entries WHERE id = ?1", [id], |row| {
                row.get(0)
            })
            .map_err(sql)?;
        if size != recorded {
            return Ok(false);
        }
        let chunk_ids: Vec<String> = {
            let mut stmt = conn
                .prepare("SELECT DISTINCT chunk_id FROM entry_chunks WHERE entry_id = ?1")
                .map_err(sql)?;
            let rows = stmt
                .query_map([id], |row| row.get::<_, String>(0))
                .map_err(sql)?;
            rows.collect::<Result<_, _>>().map_err(sql)?
        };
        Ok(chunk_ids
            .iter()
            .all(|chunk_id| self.chunk_path(chunk_id).exists()))
    }
}

impl StorageBackend for FsStorage {
    fn scoped(&self, namespace: &str) -> Arc<dyn StorageBackend> {
        // The inherent `FsStorage::scoped` builds a cheap namespaced view
        // (shared connection/gate/locks); boxing it satisfies the trait's
        // dyn view without re-opening the index.
        Arc::new(FsStorage::scoped(self, namespace))
    }

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
            let id = self.entry_id_for(key);
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
            let id = self.entry_id_for(key);
            let key = key.to_owned();
            let key_hint = key.clone();
            let blob = self.blob_path(&id);
            let conn = Arc::clone(&self.conn);
            let chunks_dir = self.root.join("chunks");
            let resolved = blocking(move || {
                let conn = lock(&conn)?;
                let row: Option<(u64, String)> = conn
                    .query_row(
                        "SELECT size, layout FROM entries WHERE id = ?1 AND complete = 1",
                        [&id],
                        |row| Ok((sql_u64(row.get(0)?), row.get::<_, String>(1)?)),
                    )
                    .optional()
                    .map_err(sql)?;
                let Some((size, layout)) = row else {
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
                if layout == "chunked" {
                    let manifest: Vec<(String, u64)> = {
                        let mut stmt = conn
                            .prepare(
                                "SELECT c.id, c.size FROM entry_chunks ec \
                                 JOIN chunks c ON c.id = ec.chunk_id \
                                 WHERE ec.entry_id = ?1 ORDER BY ec.seq",
                            )
                            .map_err(sql)?;
                        let rows = stmt
                            .query_map([id], |row| {
                                Ok((row.get::<_, String>(0)?, sql_u64(row.get(1)?)))
                            })
                            .map_err(sql)?;
                        rows.collect::<Result<Vec<_>, _>>().map_err(sql)?
                    };
                    // Intersect each chunk's span with the clamped range:
                    // the emitted slices `skip` into the first chunk and cut
                    // off wherever `range.end` (or the entry size) lands.
                    let end = range.end.min(size);
                    let mut pos = 0_u64;
                    let mut parts = Vec::new();
                    let mut planned = 0_u64;
                    for (chunk_id, chunk_size) in manifest {
                        let stop = pos.saturating_add(chunk_size);
                        if stop > range.start && pos < end {
                            let skip = range.start.saturating_sub(pos);
                            let take = stop.min(end) - range.start.max(pos);
                            if take > 0 {
                                planned = planned.saturating_add(take);
                                parts.push((
                                    chunks_dir.join(format!("{chunk_id}.chunk")),
                                    skip,
                                    take,
                                ));
                            }
                        }
                        pos = stop;
                    }
                    if planned != end - range.start {
                        return Err(io::Error::other(
                            "chunked entry's manifest does not tile its recorded size",
                        ));
                    }
                    // Covering chunk files are called out at range time, the
                    // same way the plain layout's eager blob open is: a
                    // vanished chunk file fails here with the key named
                    // (reads must not discover breakage at first poll_read).
                    for (path, ..) in &parts {
                        if std::fs::metadata(path).is_err() {
                            return Err(not_found(&key));
                        }
                    }
                    Ok(ResolvedReader::Chunked {
                        parts,
                        remaining: end - range.start,
                    })
                } else {
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
                    Ok(ResolvedReader::Whole {
                        file,
                        len: range.end.saturating_sub(range.start),
                    })
                }
            })
            .await?;
            let stream: ByteStream<'a> = match resolved {
                ResolvedReader::Whole { file, len } => {
                    // `take` clamps at EOF, matching the trait's end-clamping rule.
                    Box::pin(tokio::fs::File::from_std(file).take(len))
                }
                ResolvedReader::Chunked { parts, remaining } => {
                    Box::pin(ChunkedReader::new(parts, remaining, key_hint))
                }
            };
            Ok(stream)
        })
    }

    fn delete<'a>(&'a self, key: &'a str) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async move {
            let namespace = self.namespace.clone();
            let _gate = self.gate.write().await;
            let id = self.entry_id_for(key);
            let blob = self.blob_path(&id);
            let part = self.part_path(&id);
            let chunks_dir = self.root.join("chunks");
            let conn = Arc::clone(&self.conn);
            blocking(move || {
                let mut conn = lock(&conn)?;
                let tx = conn.transaction().map_err(sql)?;
                // Layout-aware release (docs/cdc.md accounting): a `chunked`
                // entry frees only its EXCLUSIVE chunk bytes — chunks shared
                // with a sibling stay at rest for it; a `whole` entry frees
                // its blob size, the exact legacy math for v1.0 rows.
                let (removed, _superseded_blob, chunk_unlinks) = release_previous(&tx, &id)?;
                let used = namespace_used_bytes(&tx, &namespace)?;
                let used = used.saturating_sub(removed);
                set_namespace_used_bytes(&tx, &namespace, used)?;
                tx.execute("DELETE FROM entries WHERE id = ?1", [&id])
                    .map_err(sql)?;
                tx.commit().map_err(sql)?;
                // Files last: a crash in between leaves rowless blobs/parts
                // for reconciliation/reaper, never a dangling row. Chunk
                // files whose refs hit 0 go best-effort in the same window —
                // the chunk sweeper is the convergence backstop.
                let _ = std::fs::remove_file(&blob);
                let _ = std::fs::remove_file(&part);
                for chunk_id in &chunk_unlinks {
                    let _ = std::fs::remove_file(chunks_dir.join(format!("{chunk_id}.chunk")));
                }
                Ok(())
            })
            .await
        })
    }

    fn stat<'a>(&'a self, key: &'a str) -> BoxFuture<'a, io::Result<Option<EntryStat>>> {
        Box::pin(async move {
            let _gate = self.gate.read().await;
            let id = self.entry_id_for(key);
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
                                size: sql_u64(row.get(1)?),
                                created_at: sql_u64(row.get(2)?),
                                accessed_at: sql_u64(row.get(3)?),
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
                            size: sql_u64(row.get(1)?),
                            created_at: sql_u64(row.get(2)?),
                            accessed_at: sql_u64(row.get(3)?),
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
            let namespace = self.namespace.clone();
            let _gate = self.gate.write().await;
            let id = self.entry_id_for(key);
            let key = key.to_owned();
            let part = self.part_path(&id);
            let blob = self.blob_path(&id);
            let chunks_dir = self.root.join("chunks");
            let cdc: Option<CdcParams> = self.cdc;
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
                if let Some(params) = cdc {
                    // CDC: chunking is a finalize-time pass (docs/cdc.md §Write
                    // path). The task-50 digest still means "whole payload" and
                    // falls out of the same single read pass over the part.
                    // The staged part survives until the index commit, then is
                    // deleted — a crash before the commit leaves it for the
                    // parts sweeper, exactly like the whole path's staging.
                    let mut input = File::open(&part)?;
                    let payload = chunk_payload(&chunks_dir, params, &mut input)?;
                    let size = i64::try_from(payload.size)
                        .map_err(|_| io::Error::other("payload exceeds SQLite integer range"))?;
                    let mut conn = lock(&conn)?;
                    let tx = conn.transaction().map_err(sql)?;
                    let version: String = tx
                        .query_row("SELECT version FROM entries WHERE id = ?1", [&id], |row| {
                            row.get(0)
                        })
                        .optional()
                        .map_err(sql)?
                        .unwrap_or_default();
                    // One tx: release any superseded manifest + refs, stamp
                    // the chunked entry row, register chunks + refs.
                    let (removed, supersedes_blob, mut chunk_unlinks) = release_previous(&tx, &id)?;
                    tx.execute(
                        "INSERT INTO entries \
                             (id, key, version, size, created_at, accessed_at, complete, \
                              owner_node, artifact_key, digest, layout, namespace) \
                             VALUES (?1, ?2, ?3, ?4, ?5, ?5, 1, '', '', ?6, 'chunked', ?7) \
                             ON CONFLICT(id) DO UPDATE SET \
                                 key = excluded.key, version = excluded.version, \
                                 size = excluded.size, \
                                 created_at = excluded.created_at, \
                                 accessed_at = excluded.accessed_at, complete = 1, \
                                 artifact_key = '', digest = excluded.digest, \
                                 layout = 'chunked'",
                        params![
                            id,
                            key,
                            version,
                            size,
                            created_at,
                            payload.digest,
                            namespace
                        ],
                    )
                    .map_err(sql)?;
                    let added =
                        acquire_chunk_manifest(&tx, &namespace, &id, &payload, &mut chunk_unlinks)?;
                    let used = namespace_used_bytes(&tx, &namespace)?;
                    let used = used.saturating_sub(removed).saturating_add(added);
                    set_namespace_used_bytes(&tx, &namespace, used)?;
                    tx.commit().map_err(sql)?;
                    drop(conn);
                    // Files last (B5 convention): zero-ref chunk files and a
                    // superseded whole blob go best-effort after the commit;
                    // the staged part's deletion is likewise best-effort (the
                    // parts sweeper covers a lost delete).
                    if supersedes_blob {
                        let _ = std::fs::remove_file(&blob);
                    }
                    for chunk_id in &chunk_unlinks {
                        let _ = std::fs::remove_file(chunks_dir.join(format!("{chunk_id}.chunk")));
                    }
                    let _ = std::fs::remove_file(&part);
                    return Ok(());
                }
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
                let version: String = tx
                    .query_row("SELECT version FROM entries WHERE id = ?1", [&id], |row| {
                        row.get(0)
                    })
                    .optional()
                    .map_err(sql)?
                    .unwrap_or_default();
                // Release anything the CDC era left behind: when this finalize
                // supersedes an already-chunked entry (a `[storage.cdc]`
                // flip-off), its manifest and refs go with the row here. A
                // `whole` previous row releases nothing — the rename below
                // replaces its blob outright.
                let (removed, _supersedes_blob, chunk_unlinks) = release_previous(&tx, &id)?;
                tx.execute(
                    "INSERT INTO entries \
                         (id, key, version, size, created_at, accessed_at, complete, \
                          owner_node, artifact_key, digest, layout, namespace) \
                         VALUES (?1, ?2, ?3, ?4, ?5, ?5, 1, '', '', ?6, 'whole', ?7) \
                         ON CONFLICT(id) DO UPDATE SET \
                             key = excluded.key, version = excluded.version, \
                             size = excluded.size, \
                             created_at = excluded.created_at, \
                             accessed_at = excluded.accessed_at, complete = 1, \
                             artifact_key = '', digest = excluded.digest, \
                             layout = 'whole'",
                    params![id, key, version, size, created_at, digest, namespace],
                )
                .map_err(sql)?;
                let used = namespace_used_bytes(&tx, &namespace)?;
                let used = used.saturating_sub(removed).saturating_add(size);
                set_namespace_used_bytes(&tx, &namespace, used)?;
                tx.commit().map_err(sql)?;
                drop(conn);
                for chunk_id in &chunk_unlinks {
                    let _ = std::fs::remove_file(chunks_dir.join(format!("{chunk_id}.chunk")));
                }
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
                // The TOTAL across namespaces: the eviction floor is the
                // admin's disk budget, which is absolute for the whole index.
                let used = total_used_bytes(&conn)?;
                Ok(used.max(0) as u64)
            })
            .await
        })
    }

    fn usage_by_namespace(&self) -> BoxFuture<'_, io::Result<Vec<(String, u64)>>> {
        Box::pin(async move {
            let conn = Arc::clone(&self.conn);
            blocking(move || {
                let conn = lock(&conn)?;
                all_namespace_used_bytes(&conn)
            })
            .await
        })
    }

    fn namespace_bytes(&self) -> BoxFuture<'_, io::Result<u64>> {
        Box::pin(async move {
            let conn = Arc::clone(&self.conn);
            let namespace = self.namespace.clone();
            blocking(move || {
                let conn = lock(&conn)?;
                let used = namespace_used_bytes(&conn, &namespace)?;
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
            let namespace = self.namespace.clone();
            let id = self.entry_id_for(cache_id);
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
                          reservation_expires_at, artifact_key, namespace) \
                     VALUES (?1, ?2, ?3, 0, ?4, ?4, 0, ?5, ?6, ?7) \
                     ON CONFLICT(id) DO UPDATE SET \
                         key = excluded.key, version = excluded.version, size = 0, \
                         created_at = excluded.created_at, \
                         accessed_at = excluded.accessed_at, complete = 0, \
                         reservation_expires_at = excluded.reservation_expires_at, \
                         artifact_key = excluded.artifact_key",
                    params![
                        id, cache_id, version, created_at, expires_at, key, namespace
                    ],
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
            let id = self.entry_id_for(key);
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
            let namespace = self.namespace.clone();
            let res_id = entry_id_in(&namespace, cache_id);
            let cache_id = cache_id.to_owned();
            let cdc: Option<CdcParams> = self.cdc;
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
                let blob_id = entry_id_in(&namespace, &artifact_key);
                let blob = root.join("blobs").join(format!("{blob_id}.blob"));
                let chunks_dir = root.join("chunks");
                if let Some(params) = cdc {
                    // CDC: the staged parts are read back concatenated and cut
                    // into content chunks (docs/cdc.md §Write path); the
                    // published entry holds no blob file at all. The digest
                    // keeps its whole-payload meaning and comes from the same
                    // single pass.
                    let payload = chunk_payload(
                        &chunks_dir,
                        params,
                        MultiReader::new(
                            parts
                                .iter()
                                .map(|(_start, _len, path)| path.clone())
                                .collect(),
                        ),
                    )?;
                    let size = i64::try_from(payload.size)
                        .map_err(|_| io::Error::other("payload exceeds SQLite integer range"))?;
                    let mut conn = lock(&conn)?;
                    let tx = conn.transaction().map_err(sql)?;
                    let (removed, supersedes_blob, mut chunk_unlinks) =
                        release_previous(&tx, &blob_id)?;
                    tx.execute(
                        "INSERT INTO entries \
                             (id, key, version, size, created_at, accessed_at, complete, \
                              owner_node, artifact_key, reservation_expires_at, digest, layout, namespace) \
                          VALUES (?1, ?2, ?3, ?4, ?5, ?5, 1, '', '', NULL, ?6, 'chunked', ?7) \
                          ON CONFLICT(id) DO UPDATE SET \
                              key = excluded.key, version = excluded.version, \
                              size = excluded.size, created_at = excluded.created_at, \
                              accessed_at = excluded.accessed_at, complete = 1, \
                              artifact_key = '', reservation_expires_at = NULL, \
                              digest = excluded.digest, layout = 'chunked'",
                        params![blob_id, artifact_key, version, size, now, payload.digest, namespace],
                    )
                    .map_err(sql)?;
                    tx.execute("DELETE FROM entries WHERE id = ?1", [&res_id])
                        .map_err(sql)?;
                    let added =
                        acquire_chunk_manifest(&tx, &namespace, &blob_id, &payload, &mut chunk_unlinks)?;
                    let used = namespace_used_bytes(&tx, &namespace)?;                    let used = used.saturating_sub(removed).saturating_add(added);                    set_namespace_used_bytes(&tx, &namespace, used)?;
                    tx.commit().map_err(sql)?;
                    drop(conn);
                    // Files last: superseded blob + zero-ref chunks + the
                    // staging area, best-effort after the commit (crashes
                    // converge through the boot/parts/chunk sweeps).
                    if supersedes_blob {
                        let _ = std::fs::remove_file(&blob);
                    }
                    for chunk_id in &chunk_unlinks {
                        let _ = std::fs::remove_file(chunks_dir.join(format!("{chunk_id}.chunk")));
                    }
                    let _ = std::fs::remove_dir_all(&dir);
                    let _ = std::fs::remove_file(root.join("parts").join(format!("{res_id}.part")));
                    return Ok(());
                }
                let tmp = root.join("tmp").join(format!("{blob_id}.assemble"));
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
                // Release anything the CDC era left behind (a chunked previous
                // row under a flipped-off flag); a `whole` previous row
                // releases nothing — the rename above replaced its blob.
                let (removed, _supersedes_blob, chunk_unlinks) = release_previous(&tx, &blob_id)?;
                tx.execute(
                    "INSERT INTO entries \
                         (id, key, version, size, created_at, accessed_at, complete, \
                          owner_node, artifact_key, reservation_expires_at, digest, layout, namespace) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?5, 1, '', '', NULL, ?6, 'whole', ?7) \
                     ON CONFLICT(id) DO UPDATE SET \
                         key = excluded.key, version = excluded.version, \
                         size = excluded.size, created_at = excluded.created_at, \
                         accessed_at = excluded.accessed_at, complete = 1, \
                         artifact_key = '', reservation_expires_at = NULL, \
                         digest = excluded.digest, layout = 'whole'",
                    params![blob_id, artifact_key, version, size, now, digest, namespace],
                )
                .map_err(sql)?;
                tx.execute("DELETE FROM entries WHERE id = ?1", [&res_id])
                    .map_err(sql)?;
                let used = namespace_used_bytes(&tx, &namespace)?;                let used = used.saturating_sub(removed).saturating_add(size);                set_namespace_used_bytes(&tx, &namespace, used)?;
                tx.commit().map_err(sql)?;
                drop(conn);
                for chunk_id in &chunk_unlinks {
                    let _ = std::fs::remove_file(chunks_dir.join(format!("{chunk_id}.chunk")));
                }
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
            let res_id = self.entry_id_for(cache_id);
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
            let namespace = self.namespace.clone();
            let res_id = entry_id_in(&namespace, cache_id);
            let cache_id = cache_id.to_owned();
            let ordered = ordered_block_ids.to_vec();
            let cdc: Option<CdcParams> = self.cdc;
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
                let blob_id = entry_id_in(&namespace, &artifact_key);
                let blob = root.join("blobs").join(format!("{blob_id}.blob"));
                let chunks_dir = root.join("chunks");
                if let Some(params) = cdc {
                    // Same unknown-block verdict as the whole path — before any
                    // chunk bytes are written.
                    for block_id in &ordered {
                        let path = blocks.join(format!("{block_id}.block"));
                        if !path.exists() {
                            return Err(invalid_range("blocklist references an unknown block"));
                        }
                    }
                    // CDC: the listed blocks are read in order and cut into
                    // content chunks (docs/cdc.md §Write path); the published
                    // entry holds no blob file. The digest keeps its
                    // whole-payload meaning and comes from the same pass.
                    let payload = chunk_payload(
                        &chunks_dir,
                        params,
                        MultiReader::new(
                            ordered
                                .iter()
                                .map(|block_id| blocks.join(format!("{block_id}.block")))
                                .collect(),
                        ),
                    )?;
                    let size = i64::try_from(payload.size)
                        .map_err(|_| io::Error::other("payload exceeds SQLite integer range"))?;
                    let mut conn = lock(&conn)?;
                    let tx = conn.transaction().map_err(sql)?;
                    let (removed, supersedes_blob, mut chunk_unlinks) =
                        release_previous(&tx, &blob_id)?;
                    tx.execute(
                        "INSERT INTO entries \
                             (id, key, version, size, created_at, accessed_at, complete, \
                              owner_node, artifact_key, reservation_expires_at, digest, layout, namespace) \
                          VALUES (?1, ?2, ?3, ?4, ?5, ?5, 1, '', '', NULL, ?6, 'chunked', ?7) \
                          ON CONFLICT(id) DO UPDATE SET \
                              key = excluded.key, version = excluded.version, \
                              size = excluded.size, created_at = excluded.created_at, \
                              accessed_at = excluded.accessed_at, complete = 1, \
                              artifact_key = '', reservation_expires_at = NULL, \
                              digest = excluded.digest, layout = 'chunked'",
                        params![blob_id, artifact_key, version, size, now, payload.digest, namespace],
                    )
                    .map_err(sql)?;
                    tx.execute("DELETE FROM entries WHERE id = ?1", [&res_id])
                        .map_err(sql)?;
                    let added =
                        acquire_chunk_manifest(&tx, &namespace, &blob_id, &payload, &mut chunk_unlinks)?;
                    let used = namespace_used_bytes(&tx, &namespace)?;                    let used = used.saturating_sub(removed).saturating_add(added);                    set_namespace_used_bytes(&tx, &namespace, used)?;
                    tx.commit().map_err(sql)?;
                    drop(conn);
                    // Files last: superseded blob + zero-ref chunks + the
                    // staging area, best-effort after the commit.
                    if supersedes_blob {
                        let _ = std::fs::remove_file(&blob);
                    }
                    for chunk_id in &chunk_unlinks {
                        let _ = std::fs::remove_file(chunks_dir.join(format!("{chunk_id}.chunk")));
                    }
                    let _ = std::fs::remove_dir_all(&blocks);
                    let _ = std::fs::remove_file(root.join("parts").join(format!("{res_id}.part")));
                    return Ok(u64::try_from(size).unwrap_or(u64::MAX));
                }
                let tmp = root.join("tmp").join(format!("{blob_id}.assemble"));
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
                // Release anything the CDC era left behind (a chunked previous
                // row under a flipped-off flag); a `whole` previous row
                // releases nothing — the rename above replaced its blob.
                let (removed, _supersedes_blob, chunk_unlinks) = release_previous(&tx, &blob_id)?;
                tx.execute(
                    "INSERT INTO entries \
                         (id, key, version, size, created_at, accessed_at, complete, \
                          owner_node, artifact_key, reservation_expires_at, digest, layout, namespace) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?5, 1, '', '', NULL, ?6, 'whole', ?7) \
                     ON CONFLICT(id) DO UPDATE SET \
                         key = excluded.key, version = excluded.version, \
                         size = excluded.size, created_at = excluded.created_at, \
                         accessed_at = excluded.accessed_at, complete = 1, \
                         artifact_key = '', reservation_expires_at = NULL, \
                         digest = excluded.digest, layout = 'whole'",
                    params![blob_id, artifact_key, version, size, now, digest, namespace],
                )
                .map_err(sql)?;
                tx.execute("DELETE FROM entries WHERE id = ?1", [&res_id])
                    .map_err(sql)?;
                let used = namespace_used_bytes(&tx, &namespace)?;                let used = used.saturating_sub(removed).saturating_add(size);                set_namespace_used_bytes(&tx, &namespace, used)?;
                tx.commit().map_err(sql)?;
                drop(conn);
                for chunk_id in &chunk_unlinks {
                    let _ = std::fs::remove_file(chunks_dir.join(format!("{chunk_id}.chunk")));
                }
                let _ = std::fs::remove_dir_all(&blocks);
                let _ = std::fs::remove_file(root.join("parts").join(format!("{res_id}.part")));
                Ok(total)
            })
            .await
        })
    }
}

/// What a resolved [`get_range`](StorageBackend::get_range) hands out: a
/// positioned whole-blob file, or a manifest-driven slice plan for the
/// chunked layout.
enum ResolvedReader {
    Whole {
        file: File,
        len: u64,
    },
    Chunked {
        /// `(path, skip-inside-chunk, take)` per manifest chunk intersected
        /// with the clamped range, in stream order.
        parts: Vec<(PathBuf, u64, u64)>,
        remaining: u64,
    },
}

/// Stitches manifest-ordered chunk files into one byte stream, honoring a
/// range's skip/take, keeping ONE file open at a time. The blocking
/// [`File::read`] inside `poll_read` is the accepted pattern here
/// (tokio-util chunk streams are out of scope by design): at-rest chunks
/// live on the node's own disk and every poll reads at most one bounded
/// slice, so per-request buffering stays at one chunk window max.
struct ChunkedReader {
    parts: VecDeque<(PathBuf, u64, u64)>,
    remaining: u64,
    open: Option<File>,
    /// Included in read-time errors so a vanished chunk file names both the
    /// cache key and the missing content id.
    key_hint: String,
}

impl ChunkedReader {
    fn new(parts: Vec<(PathBuf, u64, u64)>, remaining: u64, key_hint: String) -> Self {
        Self {
            parts: parts.into(),
            remaining,
            open: None,
            key_hint,
        }
    }
}

impl AsyncRead for ChunkedReader {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // One bounded read per poll; the reader's own state machine (front
        // part's skip/take budget, one open file at a time) carries on across
        // polls, so cancellation and stream resumption never lose position.
        let this = self.get_mut();
        if this.remaining == 0 {
            // Take-clamped EOF: end-clamping is the trait's contract.
            return Poll::Ready(Ok(()));
        }
        let Some((path, skip, take)) = this.parts.front().cloned() else {
            return Poll::Ready(Err(io::Error::other(
                "chunk manifest shorter than the entry's recorded size",
            )));
        };
        if this.open.is_none() {
            let mut file = File::open(&path).map_err(|err| {
                if err.kind() == io::ErrorKind::NotFound {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("chunk file missing for {}: {path:?}", this.key_hint),
                    )
                } else {
                    err
                }
            })?;
            if skip > 0 {
                file.seek(SeekFrom::Start(skip))?;
            }
            this.open = Some(file);
        }
        let file = this.open.as_mut().expect("file just opened");
        let want = take
            .min(this.remaining)
            .min(u64::try_from(buf.remaining()).unwrap_or(u64::MAX)) as usize;
        if want == 0 {
            // Buffer full: resume on the next poll mid-chunk.
            return Poll::Ready(Ok(()));
        }
        let spare = buf.initialize_unfilled_to(want);
        let read = file.read(spare)?;
        if read == 0 {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("chunk file shorter than its recorded size: {path:?}"),
            )));
        }
        buf.advance(read);
        this.remaining -= read as u64;
        let (_, _, take_left) = this.parts.front_mut().expect("checked above");
        *take_left -= read as u64;
        if *take_left == 0 {
            this.parts.pop_front();
            this.open = None;
        }
        Poll::Ready(Ok(()))
    }
}

/// Concatenates a fixed, ordered list of files into one [`Read`] stream —
/// the reader-side input for assembled payload publishes (commit chunks in
/// offset order, listed blocks in list order).
struct MultiReader {
    paths: std::vec::IntoIter<PathBuf>,
    open: Option<File>,
}

impl MultiReader {
    fn new(paths: Vec<PathBuf>) -> Self {
        Self {
            paths: paths.into_iter(),
            open: None,
        }
    }
}

impl Read for MultiReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if buf.is_empty() {
                return Ok(0);
            }
            if self.open.is_none() {
                let Some(path) = self.paths.next() else {
                    return Ok(0);
                };
                self.open = Some(File::open(&path)?);
            }
            let read = self.open.as_mut().expect("just opened").read(buf)?;
            if read == 0 {
                self.open = None; // advance to the next file
                continue;
            }
            return Ok(read);
        }
    }
}

/// A finalize-time chunking pass output (docs/cdc.md §Write path): the
/// per-seq manifest (content id, chunk size), the whole-payload digest, and
/// the total payload size the manifest covers.
struct CdcPayload {
    chunks: Vec<(String, u64)>,
    digest: String,
    size: u64,
}

/// Stream `input` once: fold the whole-payload blake3, cut content-defined
/// chunks ([`cdc::CdcSplitter`]) and write each chunk payload to
/// `chunks/{id}.chunk` — dedup is the raw existence check, same bytes same
/// id. Memory stays bounded: batches are fixed-size and per-chunk buffering
/// never exceeds the `[min, max]` window (4 MiB at the default average).
/// A crash mid-pass leaves at most rowless chunk files, which the sweeps
/// converge on (docs/cdc.md §failure model).
fn chunk_payload(
    chunks_dir: &Path,
    params: CdcParams,
    mut input: impl Read,
) -> io::Result<CdcPayload> {
    const READ_BATCH: usize = 256 * 1024;
    let mut splitter = cdc::CdcSplitter::new(params);
    let mut whole = Hasher::new();
    let mut chunks: Vec<(String, u64)> = Vec::new();
    // In-progress chunk bytes; a cut can never lag past `max_chunk_bytes`.
    let mut pend: Vec<u8> = Vec::new();
    let mut batch = vec![0_u8; READ_BATCH];
    loop {
        let read = input.read(&mut batch)?;
        if read == 0 {
            break;
        }
        let batch = &batch[..read];
        whole.update(batch);
        // The splitter's state advances over the raw stream bytes; returned
        // lengths carve the fed prefix, and the first length may complete a
        // chunk whose head bytes sit in `pend` from an earlier batch.
        let mut consumed = 0;
        for len in splitter.feed(batch) {
            if pend.is_empty() {
                chunks.push(publish_chunk_file(
                    chunks_dir,
                    &batch[consumed..consumed + len],
                )?);
                consumed += len;
            } else {
                let head = pend.len();
                pend.extend_from_slice(&batch[consumed..consumed + len - head]);
                chunks.push(publish_chunk_file(chunks_dir, &pend)?);
                consumed += len - head;
                pend.clear();
            }
        }
        pend.extend_from_slice(&batch[consumed..]);
    }
    if !pend.is_empty() {
        // Stream end flushes the trailing chunk: shorter than `min` is
        // allowed only here, never longer than `max` (docs/cdc.md bounds).
        chunks.push(publish_chunk_file(chunks_dir, &pend)?);
    }
    let size = chunks.iter().map(|(_, len)| len).sum();
    Ok(CdcPayload {
        digest: digest::hex16(whole.finalize().as_bytes()),
        chunks,
        size,
    })
}

/// Write one chunk payload under its content id; returns `(id, len)`. The
/// blake3-16 hex id IS the file name, so the existence check is the dedup
/// test; the write itself is atomic (scratch + fsync + rename).
fn publish_chunk_file(chunks_dir: &Path, chunk: &[u8]) -> io::Result<(String, u64)> {
    let id = digest::hash_bytes(chunk);
    let dest = chunks_dir.join(format!("{id}.chunk"));
    if !dest.exists() {
        let tmp = chunks_dir.join(format!("{id}.chunk.tmp"));
        write_atomic(&tmp, &dest, chunk)?;
    }
    Ok((id, chunk.len() as u64))
}

/// Inside the caller's transaction: release the complete row `id`'s at-rest
/// state ahead of a supersede/delete. A `chunked` row drops its manifest and
/// decrements its chunks' refs, freeing — accounting-wise — only the chunk
/// bytes exclusive to it (`refs == 1` pre-decrement, the docs/cdc.md bound);
/// a `whole` row frees its blob size, the v1.0 math byte-for-byte, with the
/// blob file left for the caller's post-commit unlink. Nothing to release
/// (staged/reservation rows carry no rest state) is `(0, false, [])`.
fn release_previous(conn: &Connection, id: &str) -> io::Result<(i64, bool, Vec<String>)> {
    let previous: Option<(i64, String)> = conn
        .query_row(
            "SELECT size, layout FROM entries WHERE id = ?1 AND complete = 1",
            [id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(sql)?;
    let Some((size, layout)) = previous else {
        return Ok((0, false, Vec::new()));
    };
    if layout == "chunked" {
        let removed: i64 = conn
            .query_row(
                "SELECT COALESCE((SELECT SUM(size) FROM chunks \
                 WHERE refs = 1 AND id IN \
                 (SELECT DISTINCT chunk_id FROM entry_chunks WHERE entry_id = ?1)), 0)",
                [id],
                |row| row.get(0),
            )
            .map_err(sql)?;
        let unlinked = release_entry_manifest(conn, id)?;
        Ok((removed, false, unlinked))
    } else {
        Ok((size, true, Vec::new()))
    }
}

/// Drop `id`'s manifest rows and decrement its chunks' refs, once per
/// DISTINCT chunk id — `refs` counts referencing ENTRIES, not manifest
/// occurrences. Chunks that hit `refs == 0` leave the `chunks` table; their
/// ids are returned for the caller's post-commit (best-effort) unlink.
fn release_entry_manifest(conn: &Connection, id: &str) -> io::Result<Vec<String>> {
    let chunk_ids: Vec<String> = {
        let mut stmt = conn
            .prepare("SELECT DISTINCT chunk_id FROM entry_chunks WHERE entry_id = ?1")
            .map_err(sql)?;
        let rows = stmt
            .query_map([id], |row| row.get::<_, String>(0))
            .map_err(sql)?;
        rows.collect::<Result<_, _>>().map_err(sql)?
    };
    conn.execute("DELETE FROM entry_chunks WHERE entry_id = ?1", [id])
        .map_err(sql)?;
    let mut unlinked = Vec::with_capacity(chunk_ids.len());
    for chunk_id in chunk_ids {
        conn.execute(
            "UPDATE chunks SET refs = refs - 1 WHERE id = ?1 AND refs > 0",
            [&chunk_id],
        )
        .map_err(sql)?;
        let refs: i64 = conn
            .query_row(
                "SELECT refs FROM chunks WHERE id = ?1",
                [&chunk_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(sql)?
            .unwrap_or(0);
        if refs <= 0 {
            conn.execute("DELETE FROM chunks WHERE id = ?1", [&chunk_id])
                .map_err(sql)?;
            unlinked.push(chunk_id);
        }
    }
    Ok(unlinked)
}

/// Inside the caller's transaction: register a fresh manifest's chunks. Each
/// DISTINCT id gains one ref (this entry adds one ref, no matter how often
/// it reoccurs across seqs); chunks going `0 -> 1` add their size to the
/// returned delta — the unique bytes newly at rest. Manifest rows land
/// keyed `(entry_id, seq)`. Ids a same-transaction release queued for
/// unlinking are pruned from `unlink` when this entry still holds them.
fn acquire_chunk_manifest(
    conn: &Connection,
    namespace: &str,
    id: &str,
    payload: &CdcPayload,
    unlink: &mut Vec<String>,
) -> io::Result<i64> {
    let created_at = unix_now();
    let mut added = 0_i64;
    let mut seen: HashSet<&str> = HashSet::with_capacity(payload.chunks.len());
    for (seq, (chunk_id, chunk_size)) in payload.chunks.iter().enumerate() {
        let seq = i64::try_from(seq).map_err(|_| io::Error::other("manifest exceeds i64 seqs"))?;
        if seen.insert(chunk_id.as_str()) {
            let existing: Option<i64> = conn
                .query_row("SELECT refs FROM chunks WHERE id = ?1", [chunk_id], |row| {
                    row.get(0)
                })
                .optional()
                .map_err(sql)?;
            let requeued = |unlink: &mut Vec<String>| {
                if let Some(pos) = unlink.iter().position(|queued| queued == chunk_id) {
                    unlink.swap_remove(pos);
                }
            };
            match existing {
                None => {
                    // Fresh at-rest content (or a same-tx release that hit
                    // 0 and dropped its row): registered at one ref.
                    let size = i64::try_from(*chunk_size).unwrap_or(i64::MAX);
                    conn.execute(
                        "INSERT INTO chunks (id, size, refs, created_at, namespace) \
                         VALUES (?1, ?2, 1, ?3, ?4)",
                        params![chunk_id, size, created_at, namespace],
                    )
                    .map_err(sql)?;
                    added = added.saturating_add(size);
                    requeued(unlink);
                }
                Some(refs) => {
                    conn.execute(
                        "UPDATE chunks SET refs = ?1 WHERE id = ?2",
                        params![refs + 1, chunk_id],
                    )
                    .map_err(sql)?;
                    if refs == 0 {
                        added =
                            added.saturating_add(i64::try_from(*chunk_size).unwrap_or(i64::MAX));
                        requeued(unlink);
                    }
                }
            }
        }
        conn.execute(
            "INSERT INTO entry_chunks (entry_id, seq, chunk_id, namespace) \
             VALUES (?1, ?2, ?3, ?4) \
             ON CONFLICT(entry_id, seq) DO UPDATE SET chunk_id = excluded.chunk_id",
            params![id, seq, chunk_id, namespace],
        )
        .map_err(sql)?;
    }
    Ok(added)
}

/// The next backfill candidate (docs/cdc.md, Migration): the smallest
/// complete `whole` entry that carries a content digest and sits outside
/// the caller's skip set. Legacy rows with `digest = ''` are never picked
/// (their integrity cannot be checked, so they stay whole); the skip set is
/// a caller-owned corruption park passed in as a dynamic `NOT IN`.
fn pick_whole_entry(
    conn: &Connection,
    skip: &HashSet<String>,
) -> io::Result<Option<(String, u64, String, String)>> {
    let mut query = String::from(
        "SELECT id, size, digest, namespace FROM entries \
         WHERE complete = 1 AND layout = 'whole' AND digest != ''",
    );
    let mut values: Vec<String> = Vec::new();
    if !skip.is_empty() {
        let placeholders = skip.iter().map(|_| "?").collect::<Vec<_>>().join(", ");
        values.extend(skip.iter().cloned());
        let _ = write!(query, " AND id NOT IN ({placeholders})");
    }
    let _ = write!(query, " ORDER BY size ASC, id ASC LIMIT 1");
    let row = conn
        .query_row(&query, params_from_iter(values), |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .optional()
        .map_err(sql)?;
    Ok(row.map(|(id, size, digest, namespace)| {
        (
            id,
            u64::try_from(size.max(0)).unwrap_or(0),
            digest,
            namespace,
        )
    }))
}

/// The accounted bytes of one namespace (0 when it has no row yet).
///
/// The accounting table holds one row per namespace (v1.2 workstream F):
/// the namespace is the unit the quotas and the eviction count in, so a
/// namespace's usage is readable without summing anybody else's.
fn namespace_used_bytes(conn: &Connection, namespace: &str) -> io::Result<i64> {
    conn.query_row(
        "SELECT used_bytes FROM accounting WHERE namespace = ?1",
        [namespace],
        |row| row.get(0),
    )
    .optional()
    .map_err(sql)
    .map(|used| used.unwrap_or(0))
}

/// The accounted bytes of every namespace, sorted by name (v1.2 workstream
/// F, `docs/shared-cache.md` §5): the admin-wide usage view quotas and
/// eviction read.
fn all_namespace_used_bytes(conn: &Connection) -> io::Result<Vec<(String, u64)>> {
    let mut stmt = conn
        .prepare("SELECT namespace, used_bytes FROM accounting ORDER BY namespace")
        .map_err(sql)?;
    let rows = stmt
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })
        .map_err(sql)?;
    let mut usage = Vec::new();
    for row in rows {
        let (namespace, used) = row.map_err(sql)?;
        usage.push((namespace, used.max(0) as u64));
    }
    Ok(usage)
}

/// Set one namespace's accounted bytes, creating its row on demand.
fn set_namespace_used_bytes(conn: &Connection, namespace: &str, used: i64) -> io::Result<()> {
    conn.execute(
        "INSERT INTO accounting (namespace, used_bytes) VALUES (?1, ?2) \
         ON CONFLICT(namespace) DO UPDATE SET used_bytes = ?2",
        params![namespace, used],
    )
    .map_err(sql)?;
    Ok(())
}

/// The accounted bytes across every namespace: the eviction floor's input
/// (the admin's `min_free` is absolute across the whole index).
fn total_used_bytes(conn: &Connection) -> io::Result<i64> {
    conn.query_row(
        "SELECT COALESCE(SUM(used_bytes), 0) FROM accounting",
        [],
        |row| row.get(0),
    )
    .map_err(sql)
}

/// Address for a key: hex(SHA-256(key)). Keys stay opaque (never path
/// segments) and the one-visible-entry-per-key contract maps onto the PK.
///
/// In a namespace (v1.2 workstream F) the namespace is part of the
/// address: hex(SHA-256(namespace || 0x00 || key)). The default namespace
/// ("") keeps the v1.1 derivation verbatim, so rows written before
/// namespaces existed stay reachable - a migration that rewrote every id
/// would have orphaned every blob file.
#[cfg(test)]
fn entry_id(key: &str) -> String {
    entry_id_in("", key)
}

/// The namespaced form of [`entry_id`].
fn entry_id_in(namespace: &str, key: &str) -> String {
    let mut hasher = Sha256::new();
    if !namespace.is_empty() {
        hasher.update(namespace.as_bytes());
        hasher.update([0u8]);
    }
    hasher.update(key.as_bytes());
    let digest = hasher.finalize();
    let mut id = String::with_capacity(digest.len() * 2);
    for &byte in digest.as_slice() {
        let _ = write!(id, "{byte:02x}");
    }
    id
}

/// The index's schema version, stamped in the `meta` table once every
/// migration step has been applied AND verified - never the crate semver
/// (a patch release must never look like a schema event). Ledger:
///   1: v1.0-era index - `artifact_key` (task 21) and `digest` (task 50);
///   2: v1.1 CDC - the `layout` column (the `chunks` / `entry_chunks`
///      tables come from SCHEMA itself, so this step is the column alone);
///   3: v1.2 multi-tenant - the `namespace` column (workstream F: the
///      namespace is part of a row's identity and the unit the accounting
///      and the quotas count in).
const SCHEMA_VERSION: u64 = 3;

/// One schema migration step: brings an index at the listed version's
/// predecessor up to that version. Bodies stay introspection-guarded so a
/// re-run is always a no-op on an already-current schema.
type Migration = fn(&Connection) -> io::Result<()>;

/// The migration ledger, in version order. A new schema change appends an
/// entry and bumps [`SCHEMA_VERSION`] - nothing else.
const MIGRATIONS: &[(u64, &str, Migration)] = &[
    (
        1,
        "v1.0-era columns (artifact_key, digest)",
        migrate_v1_columns,
    ),
    (2, "v1.1 CDC layout column", migrate_v2_layout),
    (3, "v1.2 namespace column", migrate_v3_namespace),
];

/// Task 21 + task 50: `artifact_key` lets a reservation carry the artifact
/// key it will publish under while `key` stays the reservation's own
/// `cacheId` (so the reaper's `parts/{key}/` cleanup still applies), and
/// `digest` carries the entry's content hash so `cachette verify` can
/// detect a later mutation of the blob.
fn migrate_v1_columns(conn: &Connection) -> io::Result<()> {
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

/// v1.1 (workstream B): the at-rest layout of the row (`whole` | `chunked`,
/// docs/cdc.md). Pre-v1.1 rows are whole by definition; the default back-
/// fills them, and the chunked manifest lives in `chunks` / `entry_chunks`.
fn migrate_v2_layout(conn: &Connection) -> io::Result<()> {
    let has_layout: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM pragma_table_info('entries') WHERE name = 'layout'",
            [],
            |row| row.get(0),
        )
        .map_err(sql)?;
    if has_layout == 0 {
        conn.execute(
            "ALTER TABLE entries ADD COLUMN layout TEXT NOT NULL DEFAULT 'whole'",
            [],
        )
        .map_err(sql)?;
    }
    Ok(())
}

/// v1.2 (workstream F): the namespace column. A row's namespace is part
/// of its identity - the namespace is the unit the accounting, the quotas
/// and the eviction count in (docs/shared-cache.md). Pre-v1.2 rows belong
/// to the default namespace, so the backfill is ''.
fn migrate_v3_namespace(conn: &Connection) -> io::Result<()> {
    for (table, column) in [
        ("entries", "namespace"),
        ("chunks", "namespace"),
        ("entry_chunks", "namespace"),
        ("accounting", "namespace"),
    ] {
        let present: i64 = conn
            .query_row(
                &format!(
                    "SELECT COUNT(*) FROM pragma_table_info('{table}') WHERE name = '{column}'"
                ),
                [],
                |row| row.get(0),
            )
            .map_err(sql)?;
        if present == 0 {
            conn.execute(
                &format!("ALTER TABLE {table} ADD COLUMN {column} TEXT NOT NULL DEFAULT ''"),
                [],
            )
            .map_err(sql)?;
        }
    }
    // The namespace-scoped lookups ride their own index; the plain key
    // index stays for the single-namespace paths.
    conn.execute(
        "CREATE INDEX IF NOT EXISTS entries_namespace_key_idx ON entries(namespace, key)",
        [],
    )
    .map_err(sql)?;
    conn.execute(
        "CREATE INDEX IF NOT EXISTS entry_chunks_namespace_idx ON entry_chunks(namespace, chunk_id)",
        [],
    )
    .map_err(sql)?;
    // One accounting row per namespace: the quota work upserts into it.
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS accounting_namespace_idx ON accounting(namespace)",
        [],
    )
    .map_err(sql)?;
    Ok(())
}

/// The stored schema version; an index that predates the meta table (or has
/// no stamp yet) reads as version 0. A corrupt value refuses rather than
/// guessing.
fn schema_version(conn: &Connection) -> io::Result<u64> {
    let row: Option<String> = conn
        .query_row(
            "SELECT value FROM meta WHERE key = 'schema_version'",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(sql)?;
    let Some(text) = row else {
        return Ok(0);
    };
    text.parse::<u64>().map_err(|_| {
        io::Error::other(format!(
            "storage index has a corrupt schema_version ({text:?}); refusing to open"
        ))
    })
}

/// Boot-time schema verification: the required tables exist and every
/// required column is present by name (declared types are not policed -
/// hand surgery on the index is not a supported path, and the version
/// machinery exists precisely so reality and the stamp cannot drift
/// silently). Runs on every open; a gap refuses to open and names it.
fn verify_schema(conn: &Connection) -> io::Result<()> {
    const REQUIRED_TABLES: &[&str] = &["entries", "accounting", "chunks", "entry_chunks", "meta"];
    const REQUIRED_COLUMNS: &[(&str, &[&str])] = &[
        (
            "entries",
            &[
                "id",
                "key",
                "version",
                "size",
                "created_at",
                "accessed_at",
                "complete",
                "owner_node",
                "reservation_expires_at",
                "artifact_key",
                "digest",
                "layout",
                "namespace",
            ],
        ),
        ("accounting", &["used_bytes", "namespace"]),
        ("chunks", &["id", "size", "refs", "created_at", "namespace"]),
        (
            "entry_chunks",
            &["entry_id", "seq", "chunk_id", "namespace"],
        ),
        ("meta", &["key", "value"]),
    ];
    for &table in REQUIRED_TABLES {
        let present: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
                [table],
                |row| row.get(0),
            )
            .map_err(sql)?;
        if present == 0 {
            return Err(io::Error::other(format!(
                "schema verify: table `{table}` is missing"
            )));
        }
    }
    for (table, columns) in REQUIRED_COLUMNS {
        for &column in *columns {
            let present: i64 = conn
                .query_row(
                    &format!("SELECT COUNT(*) FROM pragma_table_info('{table}') WHERE name = ?1"),
                    [column],
                    |row| row.get(0),
                )
                .map_err(sql)?;
            if present == 0 {
                return Err(io::Error::other(format!(
                    "schema verify: column `{column}` is missing from `{table}`"
                )));
            }
        }
    }
    Ok(())
}

/// Bring an index at `from` up to [`SCHEMA_VERSION`]: apply every pending
/// step, verify the result, and stamp the version - all in one transaction,
/// so the stamp lands only on an applied-and-verified schema and the index
/// either jumps wholesale or stays exactly as it was. SQLite DDL is
/// transactional and the steps are constant-default ALTERs (O(1) metadata
/// work regardless of index size), so one transaction is cheap.
fn run_migrations(conn: &mut Connection, from: u64) -> io::Result<()> {
    let tx = conn.transaction().map_err(sql)?;
    for &(version, what, step) in MIGRATIONS {
        if version > from {
            step(&tx).map_err(|err| {
                io::Error::other(format!(
                    "schema migration to version {version} ({what}) failed: {err}"
                ))
            })?;
        }
    }
    verify_schema(&tx)?;
    tx.execute(
        "INSERT INTO meta (key, value) VALUES ('schema_version', ?1) \
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        [SCHEMA_VERSION.to_string()],
    )
    .map_err(sql)?;
    tx.commit().map_err(sql)?;
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

/// SQLite INTEGER column → `u64`: sizes and unix stamps are written as
/// non-negative integers, so a negative read means a corrupt database and
/// collapses to 0 here rather than panicking a worker thread. (rusqlite
/// 0.41 dropped the lossy `u64: FromSql` impl; INTEGER is a signed i64.)
fn sql_u64(int: i64) -> u64 {
    u64::try_from(int).unwrap_or(0)
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

    /// Two namespaces never see each other's rows (v1.2 workstream F): the
    /// namespace is part of the row identity, so the same key in two
    /// namespaces is two entries with two payloads - and the default
    /// namespace keeps the v1.1 id derivation, so a row written before
    /// namespaces existed stays reachable.
    #[tokio::test]
    async fn namespaces_are_isolated() {
        let dir = TestDir::new();
        let storage = FsStorage::open(dir.path()).expect("open");
        let a = storage.scoped("forge-a");
        let b = storage.scoped("forge-b");

        a.put_stream("k", bytes(b"alpha")).await.expect("put a");
        a.finalize("k").await.expect("finalize a");
        b.put_stream("k", bytes(b"beta")).await.expect("put b");
        b.finalize("k").await.expect("finalize b");

        // Each namespace reads its own bytes.
        assert_eq!(
            read_all(a.get_range("k", 0..5).await.expect("read a")).await,
            b"alpha"
        );
        assert_eq!(
            read_all(b.get_range("k", 0..4).await.expect("read b")).await,
            b"beta"
        );

        // The default namespace sees neither of them.
        assert!(storage.stat("k").await.expect("stat default").is_none());

        // A row in the default namespace stays where it always was.
        storage
            .put_stream("legacy", bytes(b"old"))
            .await
            .expect("put legacy");
        storage.finalize("legacy").await.expect("finalize legacy");
        assert!(storage.stat("legacy").await.expect("stat legacy").is_some());
        assert_eq!(
            read_all(
                storage
                    .get_range("legacy", 0..3)
                    .await
                    .expect("read legacy")
            )
            .await,
            b"old"
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

        // The scratch file appears only after the spawned task clears the
        // chunk lock, the gate read, and two blocking-pool round trips
        // (reservation query + parts listing) before it even opens the
        // file. The old 1 s window (1000 x 1 ms) was tuned for an idle
        // workstation and starved on loaded CI: release run 91 fired this
        // assert while the whole lib suite ran ~36x slower than locally.
        // 30 s stays bounded but leaves real headroom. The wait is
        // load-bearing: the abort below must land mid-copy, not pre-open,
        // or the cleanup assertions would pass vacuously.
        for _ in 0..30_000 {
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

    // ---- v1.1 workstream B: CDC at-rest layout (docs/cdc.md §Test plan) ----

    /// One xorshift step; nonzero seeds never collapse to the zero state.
    fn xorshift(state: u64) -> u64 {
        let mut next = state;
        next ^= next << 13;
        next ^= next >> 7;
        next ^= next << 17;
        next
    }

    /// Deterministic pseudo-random bytes: differing content makes the
    /// content-defined cuts land variedly, while an identical seed reproduces
    /// an identical stream (dedup tests rely on that).
    fn pattern(len: usize, seed: u64) -> Vec<u8> {
        let mut out = Vec::with_capacity(len + 8);
        let mut state = seed;
        while out.len() < len {
            state = xorshift(state);
            out.extend_from_slice(&state.to_le_bytes());
        }
        out.truncate(len);
        out
    }

    /// `prefix` followed by 8 KiB of seeded pseudo-random tail bytes.
    fn extended(prefix: &[u8], seed: u64) -> Vec<u8> {
        let mut payload = prefix.to_vec();
        payload.extend(pattern(8 * 1024, seed));
        payload
    }

    /// Open the storage with CDC on at avg 4096 (min 1024 / max 16384, per the
    /// docs/cdc.md bounds min = avg/4, max = avg*4).
    fn open_cdc(dir: &TestDir) -> FsStorage {
        FsStorage::open_cdc(dir.path(), Some(CdcParams::new(4096))).expect("open cdc storage")
    }

    /// Open the storage CDC-off: publishes are v1.0 whole blobs, reads keep
    /// branching on the row's layout.
    fn open_plain(dir: &TestDir) -> FsStorage {
        FsStorage::open(dir.path()).expect("open whole-only storage")
    }

    /// `(id, size, refs)` of every registered chunk.
    fn chunk_rows(storage: &FsStorage) -> Vec<(String, u64, u64)> {
        let conn = lock(&storage.conn).expect("lock");
        let mut stmt = conn
            .prepare("SELECT id, size, refs FROM chunks")
            .expect("prepare");
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    sql_u64(row.get(1)?),
                    sql_u64(row.get(2)?),
                ))
            })
            .expect("query");
        rows.collect::<Result<Vec<_>, _>>().expect("rows")
    }

    /// DISTINCT chunk ids backing one entry, in first-occurrence order.
    fn manifest_ids(storage: &FsStorage, id: &str) -> Vec<String> {
        let conn = lock(&storage.conn).expect("lock");
        let mut stmt = conn
            .prepare(
                "SELECT chunk_id FROM entry_chunks WHERE entry_id = ?1 \
                 GROUP BY chunk_id ORDER BY MIN(seq)",
            )
            .expect("prepare");
        let rows = stmt
            .query_map([id], |row| row.get::<_, String>(0))
            .expect("query");
        rows.collect::<Result<Vec<_>, _>>().expect("rows")
    }

    /// Manifest ROW count for one entry (occurrences, dedup included).
    fn manifest_len(storage: &FsStorage, id: &str) -> usize {
        let conn = lock(&storage.conn).expect("lock");
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM entry_chunks WHERE entry_id = ?1",
                [id],
                |row| row.get(0),
            )
            .expect("count");
        usize::try_from(count).expect("small count")
    }

    /// At-rest layout of the finalized entry `key`.
    fn layout_of(storage: &FsStorage, key: &str) -> Option<String> {
        let conn = lock(&storage.conn).expect("lock");
        conn.query_row(
            "SELECT layout FROM entries WHERE id = ?1 AND complete = 1",
            [entry_id(key)],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .expect("query")
    }

    /// docs/cdc.md accounting invariant, straight from the index: whole-entry
    /// bytes plus chunk bytes with live references.
    fn at_rest_invariant(storage: &FsStorage) -> u64 {
        let conn = lock(&storage.conn).expect("lock");
        let sum: i64 = conn
            .query_row(
                "SELECT COALESCE((SELECT SUM(size) FROM entries \
                     WHERE complete = 1 AND layout = 'whole'), 0) \
                 + COALESCE((SELECT SUM(size) FROM chunks WHERE refs > 0), 0)",
                [],
                |row| row.get(0),
            )
            .expect("invariant query");
        u64::try_from(sum).expect("non-negative sum")
    }

    async fn used_of(storage: &FsStorage) -> u64 {
        storage.used_bytes().await.expect("used bytes")
    }

    /// Sorted `chunks/{id}.chunk` file names on disk.
    fn chunk_files(dir: &TestDir) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir.path().join("chunks"))
            .expect("list chunks directory")
            .map(|entry| {
                entry
                    .expect("chunk entry")
                    .file_name()
                    .into_string()
                    .expect("utf8")
            })
            .collect();
        names.sort();
        names
    }

    /// Test plan #2: CDC rows are `chunked` (no whole blob), identical
    /// prefixes cut identically for sibling entries, refs count the two
    /// sharing entries, and the accounting rests the shared bytes once.
    #[tokio::test]
    async fn cdc_publishes_chunked_rows_and_dedups_the_shared_prefix() {
        let dir = TestDir::new();
        let storage = open_cdc(&dir);

        let prefix = pattern(64 * 1024, 1);
        let mut a = prefix.clone();
        a.extend(pattern(24 * 1024, 2));
        let mut b = prefix;
        b.extend(pattern(24 * 1024, 3));

        storage.put_stream("a", bytes(&a)).await.expect("put a");
        storage.finalize("a").await.expect("finalize a");
        storage.put_stream("b", bytes(&b)).await.expect("put b");
        storage.finalize("b").await.expect("finalize b");

        for key in ["a", "b"] {
            assert_eq!(
                layout_of(&storage, key),
                Some("chunked".to_owned()),
                "{key}"
            );
            let blob = dir
                .path()
                .join("blobs")
                .join(format!("{}.blob", entry_id(key)));
            assert!(!blob.exists(), "chunked {key} must not rest a whole blob");
        }

        let ids_a = manifest_ids(&storage, &entry_id("a"));
        let ids_b = manifest_ids(&storage, &entry_id("b"));
        assert!(
            ids_a.iter().any(|id| ids_b.contains(id)),
            "the shared prefix must dedup into shared chunks"
        );
        let rows = chunk_rows(&storage);
        assert!(
            rows.iter().any(|(_, _, refs)| *refs == 2),
            "refs = 2 for shared"
        );
        assert!(
            rows.iter().any(|(_, _, refs)| *refs == 1),
            "tails rest exclusively"
        );
        assert!(
            rows.iter().all(|(_, _, refs)| *refs == 1 || *refs == 2),
            "refs snapshot is exactly shared-or-exclusive"
        );

        let used = used_of(&storage).await;
        assert_eq!(used, at_rest_invariant(&storage), "accounting invariant");
        // Identical prefixes cut identically, so at least 64 KiB minus one
        // max-bound seam chunk of shared bytes rests exactly once.
        assert!(
            used < (a.len() + b.len()) as u64,
            "dedup must not rest the shared prefix twice (used={used})"
        );
        assert!(
            used <= (a.len() + b.len()) as u64 - 48 * 1024,
            "at least 48 KiB of the 64 KiB prefix deduped (used={used})"
        );

        // Byte-exactness while we are here: both keys read back whole.
        for (key, payload) in [("a", a.as_slice()), ("b", b.as_slice())] {
            let read = read_all(
                storage
                    .get_range(key, 0..payload.len() as u64)
                    .await
                    .expect("read full"),
            )
            .await;
            assert_eq!(read, payload, "{key} round trip");
        }
    }

    /// Test plan #2 (refs semantics): manifest rows count chunk OCCURRENCES,
    /// but `chunks.refs` counts referencing ENTRIES - a payload containing the
    /// same material twice dedups within itself to one ref.
    #[tokio::test]
    async fn cdc_refs_count_entries_not_manifest_occurrences() {
        let dir = TestDir::new();
        let storage = open_cdc(&dir);

        // The seam chunk (its content spans the copy's split point) differs;
        // every chunk that ends inside the repeated material reappears.
        let mut payload = pattern(48 * 1024, 4);
        payload.extend(pattern(48 * 1024, 4));
        storage
            .put_stream("dup", bytes(&payload))
            .await
            .expect("put");
        storage.finalize("dup").await.expect("finalize");

        let id = entry_id("dup");
        let rows = manifest_len(&storage, &id);
        let distinct = manifest_ids(&storage, &id).len();
        assert!(
            distinct < rows,
            "repeated material must dedup within one entry \
             (manifest {rows} rows, {distinct} distinct chunks)"
        );

        let wrong_refs: Vec<String> = chunk_rows(&storage)
            .into_iter()
            .filter(|(_, _, refs)| *refs != 1)
            .map(|(chunk_id, _, _)| chunk_id)
            .collect();
        assert!(
            wrong_refs.is_empty(),
            "refs count entries, not occurrences: {wrong_refs:?}"
        );

        let used = used_of(&storage).await;
        assert_eq!(used, at_rest_invariant(&storage), "accounting invariant");
        // Distinct content rests once: 48 KiB of material plus at most one
        // max-bound seam chunk of extra content.
        assert!(
            used < payload.len() as u64,
            "repeated ids must rest once each (used={used})"
        );
    }

    /// Test plan #3: chunked reads are byte-exact everywhere, including tiny
    /// edge windows and a dense grid that crosses the real (content-determined)
    /// chunk boundaries.
    #[tokio::test]
    async fn cdc_get_range_is_byte_exact_across_chunk_boundaries() {
        let dir = TestDir::new();
        let storage = open_cdc(&dir);
        let payload = pattern(96 * 1024, 5);
        storage.put_stream("r", bytes(&payload)).await.expect("put");
        storage.finalize("r").await.expect("finalize");
        let len = payload.len() as u64;

        let whole = read_all(storage.get_range("r", 0..len).await.expect("read whole")).await;
        assert_eq!(whole, payload);

        // Edge windows: first/last bytes, a two-byte slip, and the empty range.
        for (start, end) in [(0_u64, 1_u64), (1, 3), (len - 3, len), (0, 0)] {
            let slice = &payload[start as usize..end.min(len) as usize];
            let got = read_all(storage.get_range("r", start..end).await.expect("edge read")).await;
            assert_eq!(got, slice, "edge range {start}..{end}");
        }
        // A coarse grid steps over every chunk boundary somewhere.
        for start in (1024..len - 512).step_by(1021) {
            let end = start + 512;
            let got = read_all(storage.get_range("r", start..end).await.expect("grid read")).await;
            assert_eq!(
                got,
                &payload[start as usize..end as usize],
                "grid range {start}..{end}"
            );
        }
        // A fine grid over the first 16 KiB probes single-window offsets.
        for start in (0..16 * 1024).step_by(517) {
            let end = start + 64;
            let got = read_all(storage.get_range("r", start..end).await.expect("fine read")).await;
            assert_eq!(
                got,
                &payload[start as usize..end as usize],
                "fine range {start}..{end}"
            );
        }

        // End clamping at the entry size (trait contract) still applies.
        let tail = read_all(
            storage
                .get_range("r", len - 7..len + 9_999)
                .await
                .expect("clamped"),
        )
        .await;
        assert_eq!(tail, &payload[(len - 7) as usize..], "clamped tail");

        let err = match storage.get_range("r", len + 1..len + 2).await {
            Ok(_) => panic!("start past the end of a chunked entry"),
            Err(e) => e,
        };
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    /// Test plan #4: delete and supersede relieve exactly the entry's EXCLUSIVE
    /// bytes; shared chunks drop references instead of disappearing, and their
    /// files survive the sibling's removal (files unlinked once refs hit 0).
    #[tokio::test]
    async fn cdc_delete_relieves_exclusive_bytes_and_supersede_restores_sharing() {
        let dir = TestDir::new();
        let storage = open_cdc(&dir);

        let prefix = pattern(32 * 1024, 6);
        // Distinct tail seeds: identical seeds on these same-length keys
        // would yield identical tails and break the exclusive-bytes math.
        for (i, key) in ["a", "b", "s"].into_iter().enumerate() {
            storage
                .put_stream(key, bytes(&extended(&prefix, 61 + i as u64)))
                .await
                .expect("put a/b/s");
            storage.finalize(key).await.expect("finalize a/b/s");
        }

        let rows = chunk_rows(&storage);
        assert!(
            rows.iter().any(|(_, _, refs)| *refs == 3),
            "prefix shared by three"
        );
        assert!(
            rows.iter().any(|(_, _, refs)| *refs == 1),
            "tails exclusive"
        );
        assert!(
            rows.iter().all(|(_, _, refs)| *refs == 1 || *refs == 3),
            "refs snapshot is shared-or-exclusive"
        );
        let used_before = used_of(&storage).await;
        assert_eq!(used_before, at_rest_invariant(&storage));

        // Delete sibling b: only ITS exclusive bytes leave; shared prefix
        // chunks drop to refs=2 and keep their files.
        let b_ids: HashSet<String> = manifest_ids(&storage, &entry_id("b")).into_iter().collect();
        let exclusive_b: u64 = rows
            .iter()
            .filter(|(id, _, refs)| *refs == 1 && b_ids.contains(id))
            .map(|(_, size, _)| *size)
            .sum();
        assert!(exclusive_b > 0, "b's tail bytes are exclusive to b");

        storage.delete("b").await.expect("delete b");
        let rows_after = chunk_rows(&storage);
        assert!(
            !rows_after.iter().any(|(_, _, refs)| *refs < 1),
            "no zero-ref rows"
        );
        for id in rows_after.iter().map(|(id, _, _)| id) {
            assert!(
                dir.path()
                    .join("chunks")
                    .join(format!("{id}.chunk"))
                    .exists(),
                "referenced chunk {id} must keep its file"
            );
        }
        assert!(
            rows_after.iter().any(|(id, _, refs)| *refs == 2
                && dir
                    .path()
                    .join("chunks")
                    .join(format!("{id}.chunk"))
                    .exists()),
            "prefix chunks survive the sibling's delete with refs=2"
        );
        assert_eq!(
            rows_after.len(),
            chunk_files(&dir).len(),
            "index rows and rest files agree"
        );

        let used_after = used_of(&storage).await;
        assert_eq!(used_after, at_rest_invariant(&storage));
        assert_eq!(
            used_before - used_after,
            exclusive_b,
            "delete relieves exactly the exclusive bytes"
        );

        // Supersede s (re-put same key): the old exclusive tail frees, the
        // shared prefix re-dedups against sibling a.
        storage
            .put_stream("s", bytes(&extended(&prefix, 64)))
            .await
            .expect("re-put s");
        storage.finalize("s").await.expect("re-finalize s");
        let rows_superseded = chunk_rows(&storage);
        assert!(
            rows_superseded.iter().any(|(_, _, refs)| *refs == 2),
            "prefix chunks re-shared by a and the new s"
        );
        for id in rows_superseded.iter().map(|(id, _, _)| id) {
            assert!(
                dir.path()
                    .join("chunks")
                    .join(format!("{id}.chunk"))
                    .exists(),
                "referenced chunk {id} must keep its file"
            );
        }
        assert_eq!(
            rows_superseded.len(),
            chunk_files(&dir).len(),
            "index rows and rest files agree after supersede"
        );
        assert_eq!(
            used_of(&storage).await,
            at_rest_invariant(&storage),
            "accounting invariant after supersede"
        );

        // Wipe the rest: rows and files converge to zero (files-last unlink
        // covers full zero-ref convergence in series).
        storage.delete("a").await.expect("delete a");
        storage.delete("s").await.expect("delete s");
        assert_eq!(used_of(&storage).await, 0);
        assert!(chunk_rows(&storage).is_empty(), "chunk table emptied");
        assert!(chunk_files(&dir).is_empty(), "chunk files unlinked");
    }

    /// Test plan #7: with `[storage.cdc]` off, publishes are whole blobs again,
    /// chunked HISTORY stays readable, and flipping off mid-life supersedes the
    /// chunked row through the same release path (refs + exclusive files freed).
    #[tokio::test]
    async fn cdc_flip_off_supersedes_chunked_entries_and_reads_stay_layout_aware() {
        let dir = TestDir::new();
        let storage = open_cdc(&dir);
        let prefix = pattern(48 * 1024, 8);
        let g_payload = extended(&prefix, 82);
        storage
            .put_stream("f", bytes(&extended(&prefix, 81)))
            .await
            .expect("put f");
        storage.finalize("f").await.expect("finalize f");
        storage
            .put_stream("g", bytes(&g_payload))
            .await
            .expect("put g");
        storage.finalize("g").await.expect("finalize g");
        assert_eq!(layout_of(&storage, "g"), Some("chunked".to_owned()));
        drop(storage);

        let storage = open_plain(&dir);
        storage
            .put_stream("n", bytes(b"plain v1.0 payload"))
            .await
            .expect("put n");
        storage.finalize("n").await.expect("finalize n");
        assert_eq!(layout_of(&storage, "n"), Some("whole".to_owned()));

        // Supersede the chunked f with a whole finalize: the manifest and refs
        // go, exclusive chunk files unlink, g's share re-counts.
        storage
            .put_stream("f", bytes(b"whole now"))
            .await
            .expect("re-put f");
        storage.finalize("f").await.expect("re-finalize f");
        assert_eq!(layout_of(&storage, "f"), Some("whole".to_owned()));
        assert!(
            dir.path()
                .join("blobs")
                .join(format!("{}.blob", entry_id("f")))
                .exists(),
            "f now rests a whole blob"
        );
        for id in manifest_ids(&storage, &entry_id("g")) {
            assert!(
                dir.path()
                    .join("chunks")
                    .join(format!("{id}.chunk"))
                    .exists(),
                "g's chunks survive their sibling's supersede"
            );
        }
        // And g needs no flag: the read path branches on the ROW's layout.
        let read = read_all(
            storage
                .get_range("g", 0..g_payload.len() as u64)
                .await
                .expect("chunked history read"),
        )
        .await;
        assert_eq!(read, g_payload);

        assert_eq!(used_of(&storage).await, at_rest_invariant(&storage));

        // Deleting a chunked row under the flag OFF is layout-aware too.
        storage.delete("g").await.expect("delete g");
        assert_eq!(layout_of(&storage, "g"), None, "chunked g deleted");
        assert_eq!(used_of(&storage).await, at_rest_invariant(&storage));
        assert!(
            chunk_rows(&storage).is_empty(),
            "g was the last chunked row"
        );
        assert!(chunk_files(&dir).is_empty(), "g's files unlinked at refs 0");
    }

    /// Test plan #6: verify sees both layouts; a missing chunk file and a
    /// missing blob each flag distinctly; reads of the broken rows fail
    /// NotFound with the key; reopening reconciles the rows away and recomputes
    /// the unique-bytes accounting (orphaned chunk FILES are commit-3 sweep
    /// work, out of scope here).
    #[tokio::test]
    async fn cdc_verify_mixed_layouts_flags_missing_chunk_and_reopen_reconciles() {
        let dir = TestDir::new();
        let y_payload = pattern(64 * 1024, 9);
        {
            let storage = open_cdc(&dir);
            storage
                .put_stream("y", bytes(&y_payload))
                .await
                .expect("put y");
            storage.finalize("y").await.expect("finalize y");
        }
        // Flip off for a mixed-layout index: two whole rows join one chunked.
        let storage = open_plain(&dir);
        let x_payload = pattern(16 * 1024, 91);
        storage
            .put_stream("x", bytes(&x_payload))
            .await
            .expect("put x");
        storage.finalize("x").await.expect("finalize x");
        storage
            .put_stream("z", bytes(b"small whole row"))
            .await
            .expect("put z");
        storage.finalize("z").await.expect("finalize z");

        let reports = storage.verify_all().expect("verify all");
        let bad: Vec<&VerifyReport> = reports.iter().filter(|r| !r.is_ok()).collect();
        assert!(bad.is_empty(), "fresh storage must verify clean: {bad:?}");

        // Corrupt the at-rest data both ways: a chunk file gone on the chunked
        // row, a blob gone on a whole row.
        let victim = manifest_ids(&storage, &entry_id("y"))[0].clone();
        std::fs::remove_file(dir.path().join("chunks").join(format!("{victim}.chunk")))
            .expect("delete a chunk file");
        std::fs::remove_file(
            dir.path()
                .join("blobs")
                .join(format!("{}.blob", entry_id("x"))),
        )
        .expect("delete a blob file");

        let reports = storage.verify_all().expect("verify broken");
        let y_report = reports.iter().find(|r| r.key == "y").expect("y reported");
        match &y_report.health {
            EntryHealth::MissingChunk { missing, total } => {
                assert_eq!(*missing, 1);
                assert!(
                    *total > 1,
                    "a 64 KiB payload yields many chunks (got {total})"
                );
            }
            other => panic!("expected a missing chunk, got {other:?}"),
        }
        let x_report = reports.iter().find(|r| r.key == "x").expect("x reported");
        assert_eq!(x_report.health, EntryHealth::MissingBlob);
        let z_report = reports.iter().find(|r| r.key == "z").expect("z reported");
        assert_eq!(z_report.health, EntryHealth::Ok);

        // The broken chunked row fails at read time with the key in the error.
        let err = match storage.get_range("y", 0..y_payload.len() as u64).await {
            Ok(_) => panic!("read of a missing-chunk entry must fail"),
            Err(e) => e,
        };
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        assert!(err.to_string().contains("y"), "must name the key: {err}");
        let err = match storage.get_range("x", 0..x_payload.len() as u64).await {
            Ok(_) => panic!("read of a missing-blob entry must fail"),
            Err(e) => e,
        };
        assert_eq!(err.kind(), io::ErrorKind::NotFound);

        // Reboot: reconcile drops broken rows (their contracts are dead) and
        // recomputes the unique-bytes accounting.
        drop(storage);
        let storage = open_plain(&dir);
        let survivors: Vec<String> = storage
            .list()
            .await
            .expect("list")
            .into_iter()
            .map(|stat| stat.key)
            .collect();
        assert_eq!(
            survivors,
            vec!["z"],
            "broken y and x die, intact z survives"
        );
        let z_size = storage
            .stat("z")
            .await
            .expect("stat")
            .expect("z visible")
            .size;
        assert_eq!(used_of(&storage).await, z_size, "accounting = the survivor");
        assert!(
            chunk_rows(&storage).is_empty(),
            "released chunk rows purged"
        );
    }

    /// An empty payload publishes a `chunked` row with an empty manifest;
    /// empty and clamped reads stay empty and the digest folds to itself.
    #[tokio::test]
    async fn cdc_empty_payload_publishes_a_zero_chunk_entry() {
        let dir = TestDir::new();
        let storage = open_cdc(&dir);

        storage
            .put_stream("e", bytes(b""))
            .await
            .expect("put empty");
        storage.finalize("e").await.expect("finalize empty");

        assert_eq!(layout_of(&storage, "e"), Some("chunked".to_owned()));
        assert_eq!(
            storage
                .stat("e")
                .await
                .expect("stat")
                .expect("visible")
                .size,
            0,
            "no bytes, no chunks"
        );
        assert_eq!(
            manifest_len(&storage, &entry_id("e")),
            0,
            "no manifest rows"
        );
        assert!(chunk_rows(&storage).is_empty());
        assert_eq!(used_of(&storage).await, 0);

        let empty = read_all(storage.get_range("e", 0..0).await.expect("empty read")).await;
        assert!(empty.is_empty(), "empty range read");
        let clamped = read_all(storage.get_range("e", 0..4096).await.expect("clamped read")).await;
        assert!(clamped.is_empty(), "end clamp at a zero-size entry");

        let reports = storage.verify_all().expect("verify");
        assert_eq!(reports.len(), 1);
        assert_eq!(
            reports[0].health,
            EntryHealth::Ok,
            "empty digest folds to itself"
        );

        storage.delete("e").await.expect("delete");
        assert_eq!(used_of(&storage).await, 0);
    }

    /// v1.1 migration: a pre-v1.1 index (post task-50, so it HAS the digest
    /// column) gains the `layout` column and its rows read as `whole`.
    #[tokio::test]
    async fn migration_adds_the_layout_column_to_a_pre_v11_database() {
        let dir = TestDir::new();
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
                     artifact_key TEXT NOT NULL DEFAULT '', \
                     digest TEXT NOT NULL DEFAULT '');\
                 CREATE TABLE accounting (used_bytes INTEGER NOT NULL);\
                 INSERT INTO accounting (used_bytes) VALUES (0);",
            )
            .expect("legacy (post-task-50) schema");
            let old_id = entry_id("old");
            conn.execute(
                "INSERT INTO entries (id, key, version, size, created_at, accessed_at, \
                     complete, artifact_key, digest) \
                     VALUES (?1, 'old', '', 11, 0, 0, 1, '', '')",
                [&old_id],
            )
            .expect("seed a legacy published row");
        }
        // The v1.0 blob exists, so reconcile keeps the row alive (a plain boot
        // only creates blobs/ on the first entry, so the seed makes it first).
        std::fs::create_dir_all(dir.path().join("blobs")).expect("seed the blobs dir");
        std::fs::write(
            dir.path()
                .join("blobs")
                .join(format!("{}.blob", entry_id("old"))),
            b"hello world",
        )
        .expect("seed the legacy blob");

        let storage = open_plain(&dir);
        {
            // A schema probe needs the raw connection: scope it so the
            // Statement borrows the guard instead of a moved-out copy.
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
                columns.iter().any(|name| name == "layout"),
                "layout column missing after migration: {columns:?}"
            );
        }

        assert_eq!(
            layout_of(&storage, "old"),
            Some("whole".to_owned()),
            "legacy rows are whole by definition"
        );
        let read = read_all(storage.get_range("old", 0..11).await.expect("read legacy")).await;
        assert_eq!(read, b"hello world");
        assert_eq!(
            used_of(&storage).await,
            11,
            "reconcile re-counts the legacy row"
        );

        // Post-task-50 digests were optional: an empty one flags, not crashes.
        let reports = storage.verify_all().expect("verify");
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].health, EntryHealth::MissingDigest);
    }

    /// v1.2 migration: a pre-v1.2 index (post v1.1, so it HAS the layout
    /// column) gains the `namespace` column on every row table, and its
    /// rows land in the default namespace - the namespace is part of a
    /// row's identity (docs/shared-cache.md).
    #[tokio::test]
    async fn migration_adds_the_namespace_column_to_a_pre_v12_database() {
        let dir = TestDir::new();
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
                     artifact_key TEXT NOT NULL DEFAULT '', \
                     digest TEXT NOT NULL DEFAULT '', \
                     layout TEXT NOT NULL DEFAULT 'whole');\
                 CREATE TABLE accounting (used_bytes INTEGER NOT NULL);\
                 INSERT INTO accounting (used_bytes) VALUES (0);",
            )
            .expect("legacy (post-v1.1) schema");
            let old_id = entry_id("old");
            conn.execute(
                "INSERT INTO entries (id, key, version, size, created_at, accessed_at, \
                     complete, artifact_key, digest, layout) \
                     VALUES (?1, 'old', '', 11, 0, 0, 1, '', '', 'whole')",
                [&old_id],
            )
            .expect("seed a legacy published row");
        }
        std::fs::create_dir_all(dir.path().join("blobs")).expect("seed the blobs dir");
        std::fs::write(
            dir.path()
                .join("blobs")
                .join(format!("{}.blob", entry_id("old"))),
            b"hello world",
        )
        .expect("seed the legacy blob");

        let storage = open_plain(&dir);
        {
            let conn = lock(&storage.conn).expect("lock");
            for table in ["entries", "chunks", "entry_chunks", "accounting"] {
                let present: i64 = conn
                    .query_row(
                        &format!(
                            "SELECT COUNT(*) FROM pragma_table_info('{table}') WHERE name = 'namespace'"
                        ),
                        [],
                        |row| row.get(0),
                    )
                    .expect("probe");
                assert_eq!(present, 1, "{table} must carry the namespace column");
            }
            let namespace: String = conn
                .query_row(
                    "SELECT namespace FROM entries WHERE id = ?1",
                    [&entry_id("old")],
                    |row| row.get(0),
                )
                .expect("legacy row");
            assert_eq!(namespace, "", "pre-v1.2 rows land in the default namespace");
        }

        // The row still reads back: the migration moves no data.
        let read = read_all(storage.get_range("old", 0..11).await.expect("read legacy")).await;
        assert_eq!(read, b"hello world");
    }

    // ==== docs/cdc.md §GC: the chunk-side sweeper (B commit 3) ====

    /// Backdate `path`'s mtime — the sweeps' grace input (same pattern as
    /// the eviction tests: open-for-write + `File::set_times`).
    fn backdate(path: &Path, age: u64) {
        let mtime = std::time::SystemTime::now() - std::time::Duration::from_secs(age);
        let file = std::fs::File::options()
            .write(true)
            .open(path)
            .expect("open for times");
        file.set_times(std::fs::FileTimes::new().set_modified(mtime))
            .expect("backdate mtime");
    }

    /// A rowless `chunks/{id}.chunk` older than the grace is swept (the
    /// crash between finalize's chunk writes and its commit), a fresh one
    /// is kept (it may belong to a pass still in flight), and a file whose
    /// row exists is never touched.
    #[tokio::test]
    async fn sweep_ages_out_rowless_chunk_files_only() {
        let dir = TestDir::new();
        let storage = open_cdc(&dir);
        let payload = pattern(48 * 1024, 7);
        storage
            .put_stream("live", bytes(&payload))
            .await
            .expect("put");
        storage.finalize("live").await.expect("finalize");
        let (rowed_id, _, refs) = chunk_rows(&storage)[0].clone();
        assert!(refs >= 1, "published chunks are referenced");
        let live_rows = chunk_rows(&storage).len();

        let chunks = dir.path().join("chunks");
        let aged = chunks.join("deadbeefdeadbeef.chunk");
        let fresh = chunks.join("cafebabecafebabe.chunk");
        std::fs::write(&aged, b"stale").expect("plant aged orphan");
        std::fs::write(&fresh, b"fresh").expect("plant fresh orphan");
        backdate(&aged, 2 * 3600);

        let now = super::super::unix_now();
        let report = storage
            .sweep_orphan_chunks(now - 3600)
            .await
            .expect("sweep");
        assert_eq!(report.files, 1, "only the aged rowless file");
        assert_eq!(report.temps, 0, "no scratch planted");
        assert_eq!(report.rows, 0, "no zero-ref rows planted");
        assert!(!aged.exists(), "aged rowless chunk swept");
        assert!(fresh.exists(), "fresh rowless chunk kept");
        assert!(
            chunks.join(format!("{rowed_id}.chunk")).exists(),
            "referenced chunk file never swept"
        );
        assert_eq!(chunk_rows(&storage).len(), live_rows, "no row touched");
        assert_eq!(
            used_of(&storage).await,
            at_rest_invariant(&storage),
            "accounting rests on the invariant"
        );
    }

    /// Aged finalize scratch (`chunks/{id}.chunk.tmp`) is swept — including
    /// scratch whose stem matches a live chunk id (a rename that never
    /// happened); fresh scratch is kept, real chunk files are untouched,
    /// and temps are never counted as chunk files.
    #[tokio::test]
    async fn sweep_ages_out_chunk_temp_scratch_only_when_old() {
        let dir = TestDir::new();
        let storage = open_cdc(&dir);
        let payload = pattern(48 * 1024, 7);
        storage
            .put_stream("live", bytes(&payload))
            .await
            .expect("put");
        storage.finalize("live").await.expect("finalize");
        let (rowed_id, _, _) = chunk_rows(&storage)[0].clone();

        let chunks = dir.path().join("chunks");
        let aged_tmp = chunks.join(format!("{rowed_id}.chunk.tmp"));
        let fresh_tmp = chunks.join("cafebabe.chunk.tmp");
        std::fs::write(&aged_tmp, b"partial").expect("plant aged scratch");
        std::fs::write(&fresh_tmp, b"partial").expect("plant fresh scratch");
        backdate(&aged_tmp, 2 * 3600);

        let now = super::super::unix_now();
        let report = storage
            .sweep_orphan_chunks(now - 3600)
            .await
            .expect("sweep");
        assert_eq!(report.temps, 1, "only the aged scratch");
        assert_eq!(report.files, 0, "temps are not chunk files");
        assert!(!aged_tmp.exists(), "aged scratch swept");
        assert!(fresh_tmp.exists(), "fresh scratch kept");
        assert!(
            chunks.join(format!("{rowed_id}.chunk")).exists(),
            "the real file stays"
        );
    }

    /// Belt-and-braces: a `chunks` row with `refs = 0` (impossible via the
    /// normal paths - the release deletes it in-tx) is purged together with
    /// its file; referenced rows are untouched and accounting never moves.
    #[tokio::test]
    async fn sweep_purges_zero_ref_chunk_rows_but_never_referenced_ones() {
        let dir = TestDir::new();
        let storage = open_cdc(&dir);
        let payload = pattern(48 * 1024, 7);
        storage
            .put_stream("live", bytes(&payload))
            .await
            .expect("put");
        storage.finalize("live").await.expect("finalize");
        let live_rows = chunk_rows(&storage);
        assert!(live_rows.iter().all(|(_, _, refs)| *refs >= 1));

        // Plant the impossible: a zero-ref row aged past the grace, with
        // its (aged) file — the belt-and-braces sweep target.
        let chunks = dir.path().join("chunks");
        let ghost_path = chunks.join("deadbeefdeadbeef.chunk");
        std::fs::write(&ghost_path, b"ghost").expect("plant ghost file");
        backdate(&ghost_path, 2 * 3600);
        {
            let conn = lock(&storage.conn).expect("lock");
            conn.execute(
                "INSERT INTO chunks (id, size, refs, created_at) \
                 VALUES ('deadbeefdeadbeef', 5, 0, ?1)",
                [super::super::unix_now() as i64 - 7200],
            )
            .expect("plant ghost row");
        }

        let now = super::super::unix_now();
        let report = storage
            .sweep_orphan_chunks(now - 3600)
            .await
            .expect("sweep");
        assert_eq!(report.rows, 1, "the zero-ref row purged");
        assert_eq!(report.files, 1, "its file went with it");
        let rows = chunk_rows(&storage);
        assert_eq!(rows.len(), live_rows.len(), "only the ghost row went");
        assert!(
            rows.iter()
                .all(|(id, _, refs)| *refs >= 1 && id.as_str() != "deadbeefdeadbeef"),
            "referenced rows untouched"
        );
        assert_eq!(
            used_of(&storage).await,
            at_rest_invariant(&storage),
            "a zero-ref purge moves no accounting"
        );
    }

    /// The conversion crash window (docs/cdc.md §GC): a blob file whose row
    /// is `chunked` counts as rowless after the grace; a `whole` row's blob
    /// never does; a fresh chunked-row blob is kept (it may belong to a
    /// conversion still in flight).
    #[tokio::test]
    async fn sweep_treats_a_chunked_rows_blob_as_rowless_after_the_grace() {
        let dir = TestDir::new();
        let storage = open_cdc(&dir);
        let payload = pattern(48 * 1024, 7);
        storage
            .put_stream("cdc", bytes(&payload))
            .await
            .expect("put");
        storage.finalize("cdc").await.expect("finalize");
        storage
            .put_stream("cdc2", bytes(&payload))
            .await
            .expect("put");
        storage.finalize("cdc2").await.expect("finalize");

        // A `whole` row with its blob (the v1.0 shape).
        let whole_id = entry_id("legacy");
        {
            let conn = lock(&storage.conn).expect("lock");
            conn.execute(
                "INSERT INTO entries (id, key, version, size, created_at, accessed_at, \
                     complete, owner_node, artifact_key, reservation_expires_at, \
                     digest, layout) \
                     VALUES (?1, 'legacy', '', 5, 0, 0, 1, '', '', NULL, '', 'whole')",
                [&whole_id],
            )
            .expect("seed whole row");
        }
        let blobs = dir.path().join("blobs");
        let whole_blob = blobs.join(format!("{whole_id}.blob"));
        std::fs::write(&whole_blob, b"whole").expect("seed whole blob");

        // The crash state: blob files under chunked rows — one aged, one
        // fresh (the second entry's conversion "did not unlink yet").
        let aged_orphan = blobs.join(format!("{}.blob", entry_id("cdc")));
        std::fs::write(&aged_orphan, b"converted").expect("plant aged converted blob");
        backdate(&aged_orphan, 2 * 3600);
        let fresh_orphan = blobs.join(format!("{}.blob", entry_id("cdc2")));
        std::fs::write(&fresh_orphan, b"converted").expect("plant fresh converted blob");

        let now = super::super::unix_now();
        let swept = storage.sweep_orphan_blobs(now - 3600).await.expect("sweep");
        assert_eq!(swept, 1, "only the aged chunked-row blob");
        assert!(!aged_orphan.exists(), "chunked-row blob swept after grace");
        assert!(whole_blob.exists(), "a whole row owns its blob");
        assert!(
            fresh_orphan.exists(),
            "fresh converted blob kept under grace"
        );
    }

    /// The full §GC pass through `Reaper::sweep_once`: referenced chunk
    /// files are never swept even when aged past the grace; planted
    /// leftovers (rowless chunk, finalize scratch, rowless blob) are all
    /// reclaimed with their counters; a second pass is a no-op; accounting
    /// rests on the invariant throughout.
    #[tokio::test]
    async fn reaper_sweep_once_reclaims_chunk_garbage_and_is_idempotent() {
        use crate::storage::eviction::Reaper;

        let dir = TestDir::new();
        let storage = open_cdc(&dir);
        let payload = pattern(48 * 1024, 7);
        storage
            .put_stream("live", bytes(&payload))
            .await
            .expect("put");
        storage.finalize("live").await.expect("finalize");
        let live_rows = chunk_rows(&storage).len();

        // Referenced files age past the grace: their rows protect them.
        let chunks = dir.path().join("chunks");
        for name in chunk_files(&dir) {
            backdate(&chunks.join(&name), 2 * 3600);
        }

        // Plant every leftover shape, all aged past the grace.
        let ghost = chunks.join("deadbeefdeadbeef.chunk");
        let scratch = chunks.join("cafebabe.chunk.tmp");
        let orphan_blob = dir.path().join("blobs").join("beefdead.blob");
        std::fs::write(&ghost, b"ghost").expect("plant ghost chunk");
        std::fs::write(&scratch, b"partial").expect("plant scratch");
        std::fs::write(&orphan_blob, b"orphan").expect("plant orphan blob");
        for path in [&ghost, &scratch, &orphan_blob] {
            backdate(path, 2 * 3600);
        }
        let before = used_of(&storage).await;

        let report = Reaper::new(std::time::Duration::from_secs(3600))
            .sweep_once(&storage)
            .await
            .expect("sweep");
        assert_eq!(report.orphan_chunks_swept, 1, "the ghost chunk swept");
        assert_eq!(report.chunk_temps_swept, 1, "the scratch swept");
        assert_eq!(report.zero_ref_chunk_rows_purged, 0, "no zero-ref rows");
        assert_eq!(report.orphan_blobs_swept, 1, "the orphan blob swept");
        assert!(
            !ghost.exists() && !scratch.exists() && !orphan_blob.exists(),
            "all planted leftovers gone"
        );
        assert_eq!(chunk_rows(&storage).len(), live_rows, "no row touched");
        for name in chunk_files(&dir) {
            assert!(
                name.ends_with(".chunk") && !name.ends_with(".chunk.tmp"),
                "only real chunk files remain, got {name}"
            );
        }
        assert_eq!(used_of(&storage).await, before, "sweeps move no accounting");
        assert_eq!(
            used_of(&storage).await,
            at_rest_invariant(&storage),
            "accounting rests on the invariant"
        );

        // Idempotence: the second pass finds nothing.
        let again = Reaper::new(std::time::Duration::from_secs(3600))
            .sweep_once(&storage)
            .await
            .expect("second sweep");
        assert_eq!(
            (
                again.orphan_chunks_swept,
                again.chunk_temps_swept,
                again.zero_ref_chunk_rows_purged,
                again.orphan_blobs_swept
            ),
            (0, 0, 0, 0),
            "second pass is a no-op"
        );
    }

    // ==== schema versioning (the meta table + verified migrations) ====

    /// The stored schema_version stamp (works on both the storage's own
    /// connection and a raw one).
    fn stored_version(conn: &Connection) -> String {
        conn.query_row(
            "SELECT value FROM meta WHERE key = 'schema_version'",
            [],
            |row| row.get::<_, String>(0),
        )
        .expect("schema_version row")
    }

    /// A fresh boot stamps the verified schema version; a reboot is a no-op
    /// on it (the stamp and the schema agree, so nothing re-runs) and the
    /// stored data reads back byte-exact.
    #[tokio::test]
    async fn boot_stamps_the_schema_version_and_a_reboot_is_a_noop() {
        let dir = TestDir::new();
        let storage = open_plain(&dir);
        {
            let conn = lock(&storage.conn).expect("lock");
            assert_eq!(
                stored_version(&conn),
                SCHEMA_VERSION.to_string(),
                "fresh boot stamps SCHEMA_VERSION"
            );
        }
        storage
            .put_stream("entry", bytes(b"payload"))
            .await
            .expect("put");
        storage.finalize("entry").await.expect("finalize");
        drop(storage);

        let storage = open_plain(&dir);
        {
            let conn = lock(&storage.conn).expect("lock");
            assert_eq!(
                stored_version(&conn),
                SCHEMA_VERSION.to_string(),
                "reopen keeps the stamp"
            );
        }
        let read = read_all(storage.get_range("entry", 0..7).await.expect("read")).await;
        assert_eq!(read, b"payload");
    }

    /// A newer index refuses to open (an older binary must never touch a
    /// newer schema) and the refusal leaves the index untouched: the forged
    /// stamp and the stored entry both survive it.
    #[tokio::test]
    async fn a_newer_index_refuses_to_boot_and_stays_untouched() {
        let dir = TestDir::new();
        let storage = open_plain(&dir);
        storage
            .put_stream("keep", bytes(b"keep"))
            .await
            .expect("put");
        storage.finalize("keep").await.expect("finalize");
        drop(storage);

        {
            let conn = Connection::open(dir.path().join("cachette.sqlite3")).expect("raw open");
            conn.execute(
                "UPDATE meta SET value = '99' WHERE key = 'schema_version'",
                [],
            )
            .expect("forge a newer version stamp");
        }

        let err = FsStorage::open(dir.path()).expect_err("newer index must refuse");
        assert!(
            err.to_string().contains("downgrade refused"),
            "refusal names the downgrade: {err}"
        );

        let conn = Connection::open(dir.path().join("cachette.sqlite3")).expect("raw open");
        assert_eq!(
            stored_version(&conn),
            "99",
            "stamp untouched by the refusal"
        );
        let keep_id = entry_id("keep");
        let rows: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM entries WHERE id = ?1 AND complete = 1",
                [&keep_id],
                |row| row.get(0),
            )
            .expect("entry survives");
        assert_eq!(rows, 1, "the index is left untouched");
    }

    /// A lying stamp is caught on every boot: the schema claims the current
    /// version but the `namespace` column was hand-removed - the
    /// unconditional verify refuses to open and names the gap.
    #[tokio::test]
    async fn a_version_row_that_lies_refuses_to_boot() {
        let dir = TestDir::new();
        {
            // The current schema minus `namespace`, stamped as current: the
            // lie the version machinery exists to catch.
            let conn = Connection::open(dir.path().join("cachette.sqlite3")).expect("raw open");
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
                     artifact_key TEXT NOT NULL DEFAULT '', \
                     digest TEXT NOT NULL DEFAULT '', \
                     layout TEXT NOT NULL DEFAULT 'whole');\
                 CREATE TABLE accounting (used_bytes INTEGER NOT NULL);\
                 INSERT INTO accounting (used_bytes) VALUES (0);\
                 CREATE TABLE chunks (\
                     id TEXT PRIMARY KEY, \
                     size INTEGER NOT NULL, \
                     refs INTEGER NOT NULL DEFAULT 0, \
                     created_at INTEGER NOT NULL);\
                 CREATE TABLE entry_chunks (\
                     entry_id TEXT NOT NULL, \
                     seq INTEGER NOT NULL, \
                     chunk_id TEXT NOT NULL, \
                     PRIMARY KEY (entry_id, seq));\
                 CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);\
                 INSERT INTO meta (key, value) VALUES ('schema_version', '3');",
            )
            .expect("tampered (namespace-less) schema stamped current");
        }

        let err = FsStorage::open(dir.path()).expect_err("a lying stamp must refuse");
        assert!(
            err.to_string()
                .contains("column `namespace` is missing from `entries`"),
            "verify names the gap: {err}"
        );
    }

    /// A corrupt schema_version value refuses to boot instead of guessing.
    #[tokio::test]
    async fn a_corrupt_schema_version_value_refuses_to_boot() {
        let dir = TestDir::new();
        let storage = open_plain(&dir);
        drop(storage);
        {
            let conn = Connection::open(dir.path().join("cachette.sqlite3")).expect("raw open");
            conn.execute(
                "UPDATE meta SET value = 'not-a-version' WHERE key = 'schema_version'",
                [],
            )
            .expect("corrupt the stamp");
        }
        let err = FsStorage::open(dir.path()).expect_err("corrupt stamp must refuse");
        assert!(
            err.to_string().contains("corrupt schema_version"),
            "refusal names the corruption: {err}"
        );
    }

    // ==== whole->chunked backfill (docs/cdc.md, Migration) ====

    /// Seed a published `whole` entry the v1.0 way: one complete row with a
    /// real content digest and its blob file on disk. `digest::hash_bytes`
    /// is the same hex16(blake3) the finalize path stamps, so honest data
    /// passes the walker's digest check.
    fn seed_whole_entry(dir: &TestDir, storage: &FsStorage, key: &str, payload: &[u8]) -> String {
        let id = entry_id(key);
        let digest = digest::hash_bytes(payload);
        {
            let conn = lock(&storage.conn).expect("lock");
            conn.execute(
                "INSERT INTO entries (id, key, version, size, created_at, accessed_at, \
                     complete, owner_node, artifact_key, reservation_expires_at, \
                     digest, layout) \
                     VALUES (?1, ?2, '', ?3, 0, 0, 1, '', '', NULL, ?4, 'whole')",
                params![id, key, payload.len() as i64, digest],
            )
            .expect("seed whole row");
            // A real whole entry at rest contributes its size to the
            // accounting row - the seeded state must satisfy the invariant.
            conn.execute(
                "UPDATE accounting SET used_bytes = used_bytes + ?1",
                [payload.len() as i64],
            )
            .expect("seed accounting");
        }
        std::fs::write(dir.path().join("blobs").join(format!("{id}.blob")), payload)
            .expect("seed whole blob");
        id
    }

    /// One step converts the smallest seeded whole entry: layout flips,
    /// size and digest survive unchanged, the blob is unlinked post-commit,
    /// accounting is size-neutral (fresh chunks, no dedup), and the entry
    /// reads back byte-exact through the chunked path. A follow-up step is
    /// `Exhausted`.
    #[tokio::test]
    async fn backfill_converts_one_whole_entry_and_reads_back() {
        let dir = TestDir::new();
        let storage = open_cdc(&dir);
        let payload = pattern(48 * 1024, 11);
        let id = seed_whole_entry(&dir, &storage, "legacy", &payload);
        let before = used_of(&storage).await;

        let step = storage
            .backfill_step(CdcParams::new(4096), &mut HashSet::new())
            .await
            .expect("backfill step");
        let BackfillStep::Converted(conversion) = &step else {
            panic!("expected a conversion, got {step:?}");
        };
        assert_eq!(conversion.id, id);
        assert_eq!(conversion.blob_bytes, 48 * 1024);
        assert_eq!(
            conversion.chunk_bytes,
            48 * 1024,
            "fresh chunks: the manifest sums to the payload"
        );
        assert_eq!(layout_of(&storage, "legacy").as_deref(), Some("chunked"));
        assert!(
            !dir.path().join("blobs").join(format!("{id}.blob")).exists(),
            "blob unlinked post-commit"
        );
        assert_eq!(
            used_of(&storage).await,
            before,
            "size-neutral without dedup"
        );
        assert_eq!(
            used_of(&storage).await,
            at_rest_invariant(&storage),
            "accounting rests on the invariant"
        );
        let read = read_all(
            storage
                .get_range("legacy", 0..(48 * 1024))
                .await
                .expect("read"),
        )
        .await;
        assert_eq!(read, payload, "round trip through the chunked layout");
        assert_eq!(
            storage
                .backfill_step(CdcParams::new(4096), &mut HashSet::new())
                .await
                .expect("drained step"),
            BackfillStep::Exhausted
        );
    }

    /// A drain converts every convertible entry smallest-first
    /// (`pending_whole_entries` counts down to 0) and ends `Exhausted`
    /// idempotently; a legacy row with the empty digest is never counted
    /// nor converted.
    #[tokio::test]
    async fn backfill_drains_smallest_first_and_exhausts_idempotently() {
        let dir = TestDir::new();
        let storage = open_cdc(&dir);
        let small = pattern(4 * 1024, 1);
        let large = pattern(64 * 1024, 2);
        let small_id = seed_whole_entry(&dir, &storage, "small", &small);
        let large_id = seed_whole_entry(&dir, &storage, "large", &large);
        // A legacy row with the empty digest: integrity unverifiable, so
        // never convertible.
        let legacy_id = entry_id("legacy-empty-digest");
        {
            let conn = lock(&storage.conn).expect("lock");
            conn.execute(
                "INSERT INTO entries (id, key, version, size, created_at, accessed_at, \
                     complete, owner_node, artifact_key, reservation_expires_at, \
                     digest, layout) \
                     VALUES (?1, 'legacy-empty-digest', '', 11, 0, 0, 1, '', '', NULL, '', 'whole')",
                [&legacy_id],
            )
            .expect("seed legacy row");
        }
        std::fs::write(
            dir.path().join("blobs").join(format!("{legacy_id}.blob")),
            b"empty-digest",
        )
        .expect("seed legacy blob");

        assert_eq!(
            storage.pending_whole_entries().await.expect("pending"),
            2,
            "the empty-digest row is not pending"
        );

        let first = storage
            .backfill_step(CdcParams::new(4096), &mut HashSet::new())
            .await
            .expect("step 1");
        assert_eq!(
            first,
            BackfillStep::Converted(WholeConversion {
                id: small_id,
                blob_bytes: 4 * 1024,
                chunk_bytes: 4 * 1024,
            }),
            "smallest first"
        );
        assert_eq!(storage.pending_whole_entries().await.expect("pending"), 1);

        let second = storage
            .backfill_step(CdcParams::new(4096), &mut HashSet::new())
            .await
            .expect("step 2");
        assert_eq!(
            second,
            BackfillStep::Converted(WholeConversion {
                id: large_id,
                blob_bytes: 64 * 1024,
                chunk_bytes: 64 * 1024,
            })
        );
        assert_eq!(storage.pending_whole_entries().await.expect("pending"), 0);

        for _ in 0..2 {
            assert_eq!(
                storage
                    .backfill_step(CdcParams::new(4096), &mut HashSet::new())
                    .await
                    .expect("drained"),
                BackfillStep::Exhausted,
                "exhaustion is idempotent"
            );
        }
        assert_eq!(
            layout_of(&storage, "legacy-empty-digest").as_deref(),
            Some("whole"),
            "empty-digest rows are never converted"
        );
        assert!(
            dir.path()
                .join("blobs")
                .join(format!("{legacy_id}.blob"))
                .exists(),
            "the legacy blob stays"
        );
        let read = read_all(
            storage
                .get_range("large", 0..(64 * 1024))
                .await
                .expect("read"),
        )
        .await;
        assert_eq!(read, large, "the converted entry reads back byte-exact");
    }

    /// Corruption is parked, not fatal and never destructive: a whole entry
    /// whose blob is missing, and one whose blob digests differently than
    /// its row claims, are both skipped (row and blob untouched, ids in the
    /// caller's skip set) while the healthy sibling converts; the parked
    /// pass's rowless chunk files are sweeper fodder like any crash left.
    #[tokio::test]
    async fn backfill_parks_corrupt_entries_and_converts_the_rest() {
        let dir = TestDir::new();
        let storage = open_cdc(&dir);
        let healthy = pattern(16 * 1024, 3);
        let healthy_id = seed_whole_entry(&dir, &storage, "healthy", &healthy);
        // No blob at all.
        let missing_id = entry_id("missing-blob");
        {
            let conn = lock(&storage.conn).expect("lock");
            conn.execute(
                "INSERT INTO entries (id, key, version, size, created_at, accessed_at, \
                     complete, owner_node, artifact_key, reservation_expires_at, \
                     digest, layout) \
                     VALUES (?1, 'missing-blob', '', 5, 0, 0, 1, '', '', NULL, ?2, 'whole')",
                params![missing_id, digest::hash_bytes(b"gone")],
            )
            .expect("seed a row without its blob");
            conn.execute("UPDATE accounting SET used_bytes = used_bytes + 5", [])
                .expect("seed accounting for the blob-less row");
        }
        // A blob whose bytes do not match the row's digest.
        let mutated = pattern(16 * 1024, 4);
        let mutated_id = seed_whole_entry(&dir, &storage, "mutated", &mutated);
        std::fs::write(
            dir.path().join("blobs").join(format!("{mutated_id}.blob")),
            pattern(16 * 1024, 5),
        )
        .expect("swap the blob for other bytes");

        let mut skip: HashSet<String> = HashSet::new();
        let mut converted: Vec<String> = Vec::new();
        for _ in 0..5 {
            match storage
                .backfill_step(CdcParams::new(4096), &mut skip)
                .await
                .expect("step")
            {
                BackfillStep::Converted(conversion) => converted.push(conversion.id),
                BackfillStep::Exhausted => break,
                BackfillStep::Raced => panic!("no concurrent writers in this test"),
            }
        }
        assert_eq!(
            converted.as_slice(),
            std::slice::from_ref(&healthy_id),
            "only the healthy entry converts"
        );
        assert_eq!(skip.len(), 2, "both corrupt ids parked");
        assert!(skip.contains(&missing_id) && skip.contains(&mutated_id));
        assert_eq!(layout_of(&storage, "healthy").as_deref(), Some("chunked"));
        assert_eq!(
            layout_of(&storage, "missing-blob").as_deref(),
            Some("whole")
        );
        assert_eq!(layout_of(&storage, "mutated").as_deref(), Some("whole"));
        assert!(
            dir.path()
                .join("blobs")
                .join(format!("{mutated_id}.blob"))
                .exists(),
            "a corrupt blob is never deleted"
        );
        assert_eq!(used_of(&storage).await, at_rest_invariant(&storage));

        // The parked (mutated) pass left rowless chunk files; age them and
        // watch the sweeper converge, while the converted manifest's files
        // are protected by their rows.
        let rowed: HashSet<String> = chunk_rows(&storage)
            .into_iter()
            .map(|(id, _, _)| id)
            .collect();
        let chunks = dir.path().join("chunks");
        for name in chunk_files(&dir) {
            if let Some(stem) = name.strip_suffix(".chunk")
                && !rowed.contains(stem)
            {
                backdate(&chunks.join(&name), 2 * 3600);
            }
        }
        let now = super::super::unix_now();
        let swept = storage
            .sweep_orphan_chunks(now - 3600)
            .await
            .expect("sweep");
        assert!(swept.files >= 1, "the abandoned pass's leftovers swept");
        assert_eq!(chunk_rows(&storage).len(), rowed.len(), "no row touched");
    }

    /// The guarded commit: a row that changes between the pick and the
    /// commit - here a simulated concurrent re-put landing while the step
    /// is parked at the writer gate (the pick and the chunking run
    /// lock-free, the commit cannot) - makes the guarded UPDATE match no
    /// row: the pass is discarded (`Raced`), no manifest is committed, no
    /// accounting moves, the row and its blob stay, and the abandoned pass's
    /// chunk files are rowless for the sweeper.
    #[tokio::test]
    async fn backfill_discards_a_pass_whose_row_changed_under_it() {
        let dir = TestDir::new();
        let storage = Arc::new(open_cdc(&dir));
        let payload = pattern(48 * 1024, 6);
        let id = seed_whole_entry(&dir, storage.as_ref(), "racy", &payload);
        let before = used_of(&storage).await;

        // Hold the writer gate so the step parks between its chunking pass
        // and its commit; the parked step is observable via the chunk files
        // its pass writes (it cannot complete: the gate is held).
        let _gate = storage.gate.write().await;
        let task = {
            let storage = Arc::clone(&storage);
            tokio::spawn(async move {
                storage
                    .backfill_step(CdcParams::new(4096), &mut HashSet::new())
                    .await
                    .expect("step")
            })
        };
        let chunks = dir.path().join("chunks");
        let mut parked = false;
        for _ in 0..200 {
            if !chunk_files(&dir).is_empty() {
                parked = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(parked, "the pass reached its commit gate");

        // The re-put lands while the step waits: the row id is key-derived
        // (a delete + re-put of the same key reuses it), with different
        // size and digest.
        {
            let conn = lock(&storage.conn).expect("lock");
            conn.execute(
                "UPDATE entries SET size = size + 1, digest = ?2 WHERE id = ?1",
                params![id, digest::hash_bytes(b"different")],
            )
            .expect("re-put the row with different content");
        }
        drop(_gate);

        let step = task.await.expect("join");
        assert_eq!(step, BackfillStep::Raced);
        assert_eq!(layout_of(&storage, "racy").as_deref(), Some("whole"));
        assert!(
            dir.path().join("blobs").join(format!("{id}.blob")).exists(),
            "the blob stays (a re-put's blob must survive a raced pass)"
        );
        assert_eq!(chunk_rows(&storage), Vec::new(), "no manifest committed");
        assert_eq!(
            used_of(&storage).await,
            before,
            "a raced pass moves no accounting"
        );

        // The abandoned pass's chunk files are rowless; the sweeper takes
        // them once aged.
        for name in chunk_files(&dir) {
            backdate(&chunks.join(&name), 2 * 3600);
        }
        let now = super::super::unix_now();
        let swept = storage
            .sweep_orphan_chunks(now - 3600)
            .await
            .expect("sweep");
        assert!(swept.files >= 1, "abandoned chunk files swept");
        assert!(
            chunk_files(&dir).is_empty(),
            "the chunks dir converges to empty"
        );
    }

    /// The chunking pass holds no connection mutex: a concurrent
    /// put/finalize on another key completes while a conversion is in
    /// flight, and both entries read back byte-exact with accounting
    /// resting on the invariant.
    #[tokio::test]
    async fn backfill_interleaves_with_live_traffic() {
        let dir = TestDir::new();
        let storage = Arc::new(open_cdc(&dir));
        let payload = pattern(256 * 1024, 8);
        seed_whole_entry(&dir, &storage, "bulk", &payload);
        let live = pattern(8 * 1024, 9);

        let writer = {
            let storage = Arc::clone(&storage);
            let live = live.clone();
            tokio::spawn(async move {
                storage.put_stream("live", bytes(&live)).await.expect("put");
                storage.finalize("live").await.expect("finalize");
            })
        };
        let step = storage
            .backfill_step(CdcParams::new(4096), &mut HashSet::new())
            .await
            .expect("step");
        writer.await.expect("writer joins");
        assert!(
            matches!(step, BackfillStep::Converted(_)),
            "the conversion commits despite the interleaved write"
        );
        let read_bulk = read_all(
            storage
                .get_range("bulk", 0..(256 * 1024))
                .await
                .expect("read"),
        )
        .await;
        assert_eq!(read_bulk, payload);
        let read_live = read_all(
            storage
                .get_range("live", 0..(8 * 1024))
                .await
                .expect("read"),
        )
        .await;
        assert_eq!(read_live, live);
        assert_eq!(layout_of(&storage, "bulk").as_deref(), Some("chunked"));
        assert_eq!(layout_of(&storage, "live").as_deref(), Some("chunked"));
        assert_eq!(
            used_of(&storage).await,
            at_rest_invariant(&storage),
            "accounting rests on the invariant after both writes"
        );
    }
}
