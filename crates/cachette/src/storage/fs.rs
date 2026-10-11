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
use tokio::io::AsyncReadExt;
use tokio::sync::RwLock;

use super::{BoxFuture, ByteStream, EntryStat, StorageBackend, invalid_range, not_found};

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
        reservation_expires_at  INTEGER
    );
    CREATE INDEX IF NOT EXISTS entries_key_idx ON entries(key);
    CREATE TABLE IF NOT EXISTS accounting (used_bytes INTEGER NOT NULL);
    INSERT INTO accounting (used_bytes)
        SELECT 0 WHERE NOT EXISTS (SELECT 1 FROM accounting);
";

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
        let storage = Self {
            root,
            conn: Arc::new(Mutex::new(conn)),
            gate: RwLock::new(()),
        };
        storage.reconcile()?;
        Ok(storage)
    }

    /// Accounting total: sum of complete-entry sizes (plan B3 capacity
    /// input, also used by index self-verification in tests).
    pub async fn used_bytes(&self) -> io::Result<u64> {
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
            let expired: Vec<String> = {
                let mut stmt = tx
                    .prepare(
                        "SELECT id FROM entries WHERE complete = 0 \
                         AND reservation_expires_at IS NOT NULL \
                         AND reservation_expires_at <= ?1",
                    )
                    .map_err(sql)?;
                let rows = stmt
                    .query_map(params![now_unix], |row| row.get::<_, String>(0))
                    .map_err(sql)?;
                rows.collect::<Result<Vec<_>, _>>().map_err(sql)?
            };
            for id in &expired {
                tx.execute("DELETE FROM entries WHERE id = ?1", [&id])
                    .map_err(sql)?;
            }
            tx.commit().map_err(sql)?;
            // Files last (B5 convention): a crash in between leaves rowless
            // parts for the boot sweep, never a dangling row.
            for id in &expired {
                let _ = std::fs::remove_file(parts.join(format!("{id}.part")));
                let _ = std::fs::remove_dir_all(parts.join(id));
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
            // Buffer first so a cancelled future never reaches the
            // filesystem; the only un-cancellable window is the final atomic
            // rename, which stages complete bytes — never partial, never
            // visible without a later finalize.
            let mut data = Vec::new();
            source.read_to_end(&mut data).await?;
            let _gate = self.gate.write().await;
            let id = entry_id(key);
            let tmp = self.tmp_path(&id);
            let part = self.part_path(&id);
            blocking(move || write_atomic(&tmp, &part, &data)).await
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
                tx.execute(
                    "INSERT INTO entries \
                         (id, key, version, size, created_at, accessed_at, complete, \
                          owner_node) \
                         VALUES (?1, ?2, '', ?3, ?4, ?4, 1, '') \
                         ON CONFLICT(id) DO UPDATE SET \
                             key = excluded.key, size = excluded.size, \
                             created_at = excluded.created_at, \
                             accessed_at = excluded.accessed_at, complete = 1",
                    params![id, key, size, created_at],
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
}
