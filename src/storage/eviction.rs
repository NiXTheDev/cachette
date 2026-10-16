//! Eviction service + reservation TTL reaper (plan task 11; B3 capacity
//! model, M4 reservation cleanup).
//!
//! Three cooperating pieces:
//!
//! - [`Capacity`]: the single B3 capacity model. `total = cache.max_size`
//!   when set, else the disk total of the storage path; `used` comes from
//!   backend accounting; `free = total - used`. Admission passes when
//!   `free >= blob_size` (size known) else `free >= min_free`, where the
//!   configured [`MinFree`] fraction/percent/bytesize is resolved against
//!   `total` into a byte floor. `fill_percent` (`used/total`) is the
//!   placement input for the cluster tasks.
//! - [`EvictionService`]: evict-to-floor sweeps over any
//!   [`StorageBackend`]. Candidates are finalized entries only (staged,
//!   reserved-but-uncommitted data is never listed by the backend) and
//!   entries holding an active [`LeaseSet`] borrow (in-flight downloads)
//!   are skipped. `[cache] eviction` selects the order: `lru` =
//!   `accessed_at` asc, `oldest` = `created_at` asc, `none` = never evict
//!   (reserve-time admission simply refuses below the floor). Sweeps are
//!   budgeted ([`DEFAULT_SWEEP_BUDGET`], 50ms) so they never block a
//!   request path for long, and a sweep that cannot make progress
//!   (everything leased) warns and returns instead of deadlocking.
//! - [`Reaper`]: periodic reservation TTL cleanup for the FS backend (plan
//!   M4): rows with `reservation_expires_at < now` lose their parts and
//!   row, and rowless blob files older than [`ORPHAN_BLOB_GRACE`] (1h)
//!   are swept. The periodic interval is `reservation_ttl / 4`.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use crate::config::{Eviction, MinFree};

use super::EntryStat;
use super::StorageBackend;
use super::fs::FsStorage;

/// Free-space sweep budget: a single sweep chunk stops deleting once this
/// much wall time has passed (plan task 11: never block the request path
/// longer than 50ms per sweep chunk).
pub const DEFAULT_SWEEP_BUDGET: Duration = Duration::from_millis(50);

/// Default lease borrow time for an in-flight download: long enough for a
/// slow transfer, short enough that a crashed borrower cannot pin an entry
/// forever.
pub const DEFAULT_BORROW_TTL: Duration = Duration::from_secs(3600);

/// Rowless blob files younger than this are left alone by the reaper — a
/// recent orphan may belong to a finalize that is still in flight.
pub const ORPHAN_BLOB_GRACE: Duration = Duration::from_secs(3600);

/// B3 capacity model: one set of numbers drives reserve-time admission,
/// the eviction floor, and (later) cluster placement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Capacity {
    /// Volume size: `cache.max_size` when set, else the storage path's
    /// disk total.
    pub total: u64,
    /// Accounted bytes of finalized entries.
    pub used: u64,
    /// Free-space floor in bytes (`storage.fs.min_free` resolved against
    /// `total`).
    pub min_free: u64,
    /// `cache.max_size`; 0 = unlimited (the disk total still caps
    /// `total`).
    pub max_size: u64,
}

impl Capacity {
    /// Resolve the model from already-known inputs. `disk_total` is only
    /// consulted when `max_size` is 0 (see [`Self::from_disk`]).
    #[must_use]
    pub fn resolve(min_free: MinFree, max_size: u64, disk_total: u64, used: u64) -> Self {
        let total = if max_size > 0 { max_size } else { disk_total };
        Self {
            total,
            used,
            min_free: min_free.resolve(total),
            max_size,
        }
    }

    /// Resolve against a live storage path: queries the path's disk total
    /// only when `max_size` does not already pin `total`.
    pub fn from_disk(
        min_free: MinFree,
        max_size: u64,
        storage_path: &Path,
        used: u64,
    ) -> std::io::Result<Self> {
        let disk_total = if max_size > 0 {
            0
        } else {
            disk_total_bytes(storage_path)?
        };
        Ok(Self::resolve(min_free, max_size, disk_total, used))
    }

    /// `free = total - used` (saturating: over-quota caches read as 0).
    #[must_use]
    pub fn free(&self) -> u64 {
        self.total.saturating_sub(self.used)
    }

    /// `fill% = used/total` (cluster placement input); 0.0 when `total`
    /// is 0 (unknown volume).
    #[must_use]
    pub fn fill_percent(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            self.used as f64 / self.total as f64
        }
    }

    /// B3 admission: a known-size blob needs `free >= blob_size`; an
    /// unknown-size reservation only needs the `min_free` floor.
    #[must_use]
    pub fn admits(&self, blob_size: Option<u64>) -> bool {
        match blob_size {
            Some(size) => self.free() >= size,
            None => self.free() >= self.min_free,
        }
    }

    /// `free < min_free`: the free-space floor that eviction targets.
    #[must_use]
    pub fn below_floor(&self) -> bool {
        self.free() < self.min_free
    }

    /// `used > max_size` (only when a max is configured).
    #[must_use]
    pub fn over_max(&self) -> bool {
        self.max_size > 0 && self.used > self.max_size
    }

    /// Whether the evict-to-floor loop has work to do.
    #[must_use]
    pub fn needs_eviction(&self) -> bool {
        self.below_floor() || self.over_max()
    }

    /// Account `bytes` reclaimed by an eviction.
    pub fn note_evicted(&mut self, bytes: u64) {
        self.used = self.used.saturating_sub(bytes);
    }
}

/// Total size of the volume holding `path` (B3 fallback when
/// `cache.max_size` is 0).
pub fn disk_total_bytes(path: &Path) -> std::io::Result<u64> {
    fs2::total_space(path).map_err(|err| std::io::Error::other(err.to_string()))
}

/// In-memory lease set guarding entries from eviction while they are
/// being downloaded (and, later, reserved). A borrow older than the lease
/// TTL is treated as released so a crashed borrower cannot pin entries
/// forever.
#[derive(Debug)]
pub struct LeaseSet {
    leases: Mutex<HashMap<String, Instant>>,
    borrow_ttl: Duration,
}

impl LeaseSet {
    /// Lease set whose borrows expire after `borrow_ttl`.
    #[must_use]
    pub fn new(borrow_ttl: Duration) -> Self {
        Self {
            leases: Mutex::new(HashMap::new()),
            borrow_ttl,
        }
    }

    /// Mark `key` borrowed (download in flight). Re-borrowing an already
    /// leased key refreshes the borrow time.
    pub fn acquire(&self, key: impl Into<String>) {
        let mut leases = lock(&self.leases);
        leases.insert(key.into(), Instant::now());
    }

    /// Drop the borrow on `key` (idempotent).
    pub fn release(&self, key: &str) {
        lock(&self.leases).remove(key);
    }

    /// Whether `key` currently holds an unexpired borrow. Expired borrows
    /// are pruned as they are observed.
    #[must_use]
    pub fn is_leased(&self, key: &str) -> bool {
        let mut leases = lock(&self.leases);
        match leases.get(key) {
            Some(&borrowed) if borrowed.elapsed() < self.borrow_ttl => true,
            Some(_) => {
                leases.remove(key);
                false
            }
            None => false,
        }
    }

    /// Number of live (unexpired) borrows.
    #[must_use]
    pub fn len(&self) -> usize {
        let mut leases = lock(&self.leases);
        leases.retain(|_, &mut borrowed| borrowed.elapsed() < self.borrow_ttl);
        leases.len()
    }

    /// `true` when [`Self::len`] is zero.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Eviction candidate order for `policy`: `lru` by `accessed_at` asc,
/// `oldest` by `created_at` asc, `none` yields no candidates. Equal
/// timestamps tie-break by key ascending so the order is deterministic.
#[must_use]
pub fn eviction_order(policy: Eviction, entries: &[EntryStat]) -> Vec<&EntryStat> {
    let mut candidates: Vec<&EntryStat> = entries.iter().collect();
    match policy {
        Eviction::None => Vec::new(),
        Eviction::Lru => {
            candidates.sort_by(|a, b| {
                a.accessed_at
                    .cmp(&b.accessed_at)
                    .then_with(|| a.key.cmp(&b.key))
            });
            candidates
        }
        Eviction::Oldest => {
            candidates.sort_by(|a, b| {
                a.created_at
                    .cmp(&b.created_at)
                    .then_with(|| a.key.cmp(&b.key))
            });
            candidates
        }
    }
}

/// Why a sweep stopped.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SweepOutcome {
    /// The floor (and max size) is satisfied — or was before the sweep
    /// started.
    FloorReached,
    /// `[cache] eviction = "none"`: never evict.
    Disabled,
    /// Work remained but every remaining candidate is leased or missing —
    /// the deadlock guard: the sweep warns and returns instead of
    /// spinning.
    NoEligibleCandidates,
    /// The sweep budget elapsed; the next periodic sweep continues.
    BudgetExhausted,
}

/// Result of one evict-to-floor sweep.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SweepReport {
    /// Keys evicted, in eviction order.
    pub evicted: Vec<String>,
    /// Sum of evicted entry sizes.
    pub bytes_freed: u64,
    /// Why the sweep stopped.
    pub outcome: SweepOutcome,
}

/// Evict-to-floor service over any [`StorageBackend`]. Share the
/// [`LeaseSet`] with download handlers so in-flight transfers survive
/// sweeps.
pub struct EvictionService {
    policy: Eviction,
    leases: Arc<LeaseSet>,
    budget: Duration,
}

impl EvictionService {
    /// Service for `policy` sharing `leases`, with the default 50ms sweep
    /// budget.
    #[must_use]
    pub fn new(policy: Eviction, leases: Arc<LeaseSet>) -> Self {
        Self {
            policy,
            leases,
            budget: DEFAULT_SWEEP_BUDGET,
        }
    }

    /// Override the per-sweep time budget (tests use a large budget for
    /// determinism; `Duration::ZERO` stops before the first delete).
    #[must_use]
    pub fn with_budget(mut self, budget: Duration) -> Self {
        self.budget = budget;
        self
    }

    /// The shared lease set (download handlers borrow through this).
    #[must_use]
    pub fn leases(&self) -> &LeaseSet {
        &self.leases
    }

    /// Evict finalized, unleased entries in policy order until `capacity`
    /// no longer needs eviction (B3: `free >= min_free` and
    /// `used <= max_size`), the budget runs out, or no candidates remain.
    /// Never evicts staged or reserved-but-uncommitted rows (backends
    /// only list finalized entries) nor leased ones.
    pub async fn sweep<S: StorageBackend + ?Sized>(
        &self,
        storage: &S,
        capacity: &mut Capacity,
    ) -> std::io::Result<SweepReport> {
        let mut report = SweepReport {
            evicted: Vec::new(),
            bytes_freed: 0,
            outcome: SweepOutcome::FloorReached,
        };
        if !capacity.needs_eviction() {
            return Ok(report);
        }
        if self.policy == Eviction::None {
            tracing::debug!("eviction policy is none; sweep disabled");
            report.outcome = SweepOutcome::Disabled;
            return Ok(report);
        }
        let entries = storage.list().await?;
        let candidates: Vec<&EntryStat> = eviction_order(self.policy, &entries)
            .into_iter()
            .filter(|entry| !self.leases.is_leased(&entry.key))
            .collect();
        let started = Instant::now();
        for entry in candidates {
            if !capacity.needs_eviction() {
                break;
            }
            if started.elapsed() >= self.budget {
                report.outcome = SweepOutcome::BudgetExhausted;
                return Ok(report);
            }
            storage.delete(&entry.key).await?;
            capacity.note_evicted(entry.size);
            report.bytes_freed += entry.size;
            report.evicted.push(entry.key.clone());
        }
        if capacity.needs_eviction() {
            // Either no candidates qualified (all leased) or the eligible
            // ones ran out mid-sweep; either way the floor is unmet, so the
            // deadlock guard warns and returns instead of spinning.
            report.outcome = SweepOutcome::NoEligibleCandidates;
            tracing::warn!(
                policy = ?self.policy,
                free = capacity.free(),
                min_free = capacity.min_free,
                evicted = report.evicted.len(),
                "eviction sweep made no progress toward the free-space floor"
            );
        }
        Ok(report)
    }

    /// Reserve-time admission (B3): when the request would sit below the
    /// floor, sweep first, then decide. `eviction = "none"` therefore
    /// refuses reservations below the floor instead of evicting.
    pub async fn admit<S: StorageBackend + ?Sized>(
        &self,
        storage: &S,
        capacity: &mut Capacity,
        blob_size: Option<u64>,
    ) -> std::io::Result<bool> {
        if !capacity.admits(blob_size) {
            let report = self.sweep(storage, capacity).await?;
            tracing::debug!(
                outcome = ?report.outcome,
                evicted = report.evicted.len(),
                "reserve-time eviction sweep"
            );
        }
        Ok(capacity.admits(blob_size))
    }
}

/// Reservation TTL reaper (plan M4) for the FS backend: periodic
/// `sweep_once` runs reclaim expired reservations and old rowless blobs.
/// Build it with `[cache] reservation_ttl_seconds`; the loop interval is
/// a quarter of that TTL.
#[derive(Clone, Copy, Debug)]
pub struct Reaper {
    reservation_ttl: Duration,
}

/// What one reaper pass reclaimed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReapReport {
    /// Expired reservation rows (plus their parts) deleted.
    pub reservations_reaped: u64,
    /// Rowless blob files older than [`ORPHAN_BLOB_GRACE`] deleted.
    pub orphan_blobs_swept: u64,
    /// Idle per-key chunk locks dropped (T52): unbounded otherwise.
    pub chunk_locks_swept: u64,
}

impl Reaper {
    /// Reaper for reservations with `reservation_ttl` lifetimes.
    #[must_use]
    pub fn new(reservation_ttl: Duration) -> Self {
        Self { reservation_ttl }
    }

    /// Periodic tick interval: `reservation_ttl / 4`, clamped to a 1s
    /// floor so even a pathological TTL cannot hot-spin the loop.
    #[must_use]
    pub fn interval(&self) -> Duration {
        (self.reservation_ttl / 4).max(Duration::from_secs(1))
    }

    /// One pass: reap reservations whose `reservation_expires_at` has
    /// passed, sweep rowless blobs older than [`ORPHAN_BLOB_GRACE`], and drop
    /// idle chunk locks so that map cannot grow without bound.
    pub async fn sweep_once(&self, storage: &FsStorage) -> std::io::Result<ReapReport> {
        let now = super::unix_now();
        let reservations_reaped = storage.reap_expired_reservations(now).await?;
        let cutoff = now.saturating_sub(ORPHAN_BLOB_GRACE.as_secs());
        let orphan_blobs_swept = storage.sweep_orphan_blobs(cutoff).await?;
        let chunk_locks_swept = storage.sweep_chunk_locks();
        Ok(ReapReport {
            reservations_reaped,
            orphan_blobs_swept,
            chunk_locks_swept,
        })
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::SystemTime;

    use super::*;
    use crate::storage::ByteStream;
    use crate::storage::MemoryStorage;

    static DIR_SEQ: AtomicU64 = AtomicU64::new(0);

    /// Unique temp directory per test, removed on drop (no tempfile dep).
    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Self {
            let seq = DIR_SEQ.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "cachette-storage-eviction-{}-{seq}",
                std::process::id()
            ));
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
        Box::pin(Cursor::new(data.to_vec()))
    }

    async fn seed(storage: &MemoryStorage, key: &str, payload: &[u8]) {
        storage.put_stream(key, bytes(payload)).await.expect("put");
        storage.finalize(key).await.expect("finalize");
    }

    fn stat(key: &str, size: u64, created_at: u64, accessed_at: u64) -> EntryStat {
        EntryStat {
            key: key.to_owned(),
            size,
            created_at,
            accessed_at,
        }
    }

    fn leases() -> Arc<LeaseSet> {
        Arc::new(LeaseSet::new(DEFAULT_BORROW_TTL))
    }

    fn service(policy: Eviction) -> EvictionService {
        EvictionService::new(policy, leases()).with_budget(Duration::from_secs(30))
    }

    #[test]
    fn capacity_resolves_max_size_or_disk_total_and_min_free_floor() {
        // max_size pins total; disk total never consulted.
        let capped = Capacity::resolve(MinFree::Fraction(0.2), 1_000_000, 99, 100_000);
        assert_eq!(capped.total, 1_000_000);
        assert_eq!(capped.min_free, 200_000);
        // max_size 0 falls back to the disk total.
        let on_disk = Capacity::resolve(MinFree::Percent(25.0), 0, 1_000_000, 100_000);
        assert_eq!(on_disk.total, 1_000_000);
        assert_eq!(on_disk.min_free, 250_000);
        // Byte-form min_free is absolute regardless of total.
        let absolute = Capacity::resolve(MinFree::Bytes(4_096), 1_000_000, 0, 0);
        assert_eq!(absolute.min_free, 4_096);
    }

    #[test]
    fn capacity_from_disk_skips_the_disk_query_when_max_size_pins_total() {
        // A nonexistent path proves no syscall happened.
        let capacity = Capacity::from_disk(
            MinFree::Fraction(0.2),
            1_000,
            Path::new("/definitely/not/a/real/cachette/path"),
            100,
        )
        .expect("no disk query when max_size is set");
        assert_eq!(capacity.total, 1_000);
        assert_eq!(capacity.min_free, 200);
    }

    #[test]
    fn disk_total_bytes_reports_a_positive_total_for_a_real_path() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"));
        let total = disk_total_bytes(path).expect("disk total");
        assert!(total > 0, "disk total of the crate dir should be positive");
    }

    #[test]
    fn capacity_free_fill_and_admission_follow_b3() {
        let capacity = Capacity {
            total: 100,
            used: 60,
            min_free: 50,
            max_size: 100,
        };
        assert_eq!(capacity.free(), 40);
        assert!((capacity.fill_percent() - 0.6).abs() < f64::EPSILON);
        // Known size: only free >= blob_size matters.
        assert!(capacity.admits(Some(40)));
        assert!(!capacity.admits(Some(41)));
        // Unknown size: the min_free floor decides.
        assert!(!capacity.admits(None));
        assert!(capacity.below_floor());
        assert!(!capacity.over_max());
        assert!(capacity.needs_eviction());
        // Evicting 20 bytes lifts the cache above the floor.
        let mut freed = capacity;
        freed.note_evicted(20);
        assert_eq!(freed.used, 40);
        assert!(freed.admits(None));
        assert!(!freed.needs_eviction());
        // note_evicted never underflows.
        let mut drained = capacity;
        drained.note_evicted(u64::MAX);
        assert_eq!(drained.used, 0);
    }

    #[test]
    fn capacity_over_max_size_needs_eviction_even_above_the_floor() {
        let capacity = Capacity {
            total: 100,
            used: 90,
            min_free: 0,
            max_size: 30,
        };
        assert!(!capacity.below_floor());
        assert!(capacity.over_max());
        assert!(capacity.needs_eviction());
        // Unlimited caches (max_size 0) never trip the over-max branch.
        let unlimited = Capacity {
            total: 100,
            used: 100,
            min_free: 0,
            max_size: 0,
        };
        assert!(!unlimited.over_max());
        assert!(!unlimited.needs_eviction());
    }

    #[test]
    fn capacity_with_zero_total_reports_zero_fill() {
        let capacity = Capacity {
            total: 0,
            used: 0,
            min_free: 0,
            max_size: 0,
        };
        assert_eq!(capacity.fill_percent(), 0.0);
    }

    #[test]
    fn lru_orders_by_accessed_then_key_and_oldest_by_created_then_key() {
        let entries = vec![
            stat("b", 1, 5, 9),
            stat("c", 1, 1, 3),
            stat("a", 1, 5, 9),
            stat("d", 1, 2, 9),
        ];
        let lru: Vec<&str> = eviction_order(Eviction::Lru, &entries)
            .into_iter()
            .map(|entry| entry.key.as_str())
            .collect();
        assert_eq!(lru, vec!["c", "a", "b", "d"]);
        let oldest: Vec<&str> = eviction_order(Eviction::Oldest, &entries)
            .into_iter()
            .map(|entry| entry.key.as_str())
            .collect();
        assert_eq!(oldest, vec!["c", "d", "a", "b"]);
    }

    #[test]
    fn none_policy_yields_no_eviction_candidates() {
        let entries = vec![stat("a", 1, 1, 1)];
        assert!(eviction_order(Eviction::None, &entries).is_empty());
    }

    #[test]
    fn lease_set_tracks_borrows_and_expires_stale_ones() {
        let active = LeaseSet::new(DEFAULT_BORROW_TTL);
        assert!(!active.is_leased("k"));
        assert!(active.is_empty());
        active.acquire("k");
        assert!(active.is_leased("k"));
        assert_eq!(active.len(), 1);
        active.release("k");
        assert!(!active.is_leased("k"));
        // Idempotent release.
        active.release("k");
        // A zero TTL makes every borrow instantly stale.
        let ephemeral = LeaseSet::new(Duration::ZERO);
        ephemeral.acquire("k2");
        assert!(!ephemeral.is_leased("k2"), "expired borrow is not leased");
        assert!(ephemeral.is_empty());
    }

    #[tokio::test]
    async fn sweep_lru_evicts_until_the_free_floor_is_restored() {
        let storage = MemoryStorage::new();
        for key in ["a", "b", "c", "d", "e"] {
            seed(&storage, key, &[0_u8; 10]).await;
        }
        // All entries share timestamps (same second) so the key tie-break
        // fixes the eviction order: a, b, c, d.
        let mut capacity = Capacity {
            total: 100,
            used: 90,
            min_free: 50,
            max_size: 0,
        };
        let report = service(Eviction::Lru)
            .sweep(&storage, &mut capacity)
            .await
            .expect("sweep");
        assert_eq!(report.evicted, vec!["a", "b", "c", "d"]);
        assert_eq!(report.bytes_freed, 40);
        assert_eq!(report.outcome, SweepOutcome::FloorReached);
        assert_eq!(capacity.used, 50);
        assert!(!capacity.needs_eviction());
        let survivors = storage.list().await.expect("list");
        assert_eq!(survivors.len(), 1);
        assert_eq!(survivors[0].key, "e");
    }

    #[tokio::test]
    async fn sweep_skips_leased_entries_and_warns_when_stuck() {
        let storage = MemoryStorage::new();
        for key in ["a", "b", "c", "d", "e"] {
            seed(&storage, key, &[0_u8; 10]).await;
        }
        let shared = leases();
        shared.acquire("a");
        shared.acquire("b");
        let service =
            EvictionService::new(Eviction::Lru, shared).with_budget(Duration::from_secs(30));
        let mut capacity = Capacity {
            total: 100,
            used: 90,
            min_free: 50,
            max_size: 0,
        };
        let report = service.sweep(&storage, &mut capacity).await.expect("sweep");
        // Leased a and b survive; the floor is still not met, so the sweep
        // returns without progress instead of deadlocking.
        assert_eq!(report.evicted, vec!["c", "d", "e"]);
        assert_eq!(report.outcome, SweepOutcome::NoEligibleCandidates);
        assert_eq!(capacity.used, 60);
        let mut survivors: Vec<String> = storage
            .list()
            .await
            .expect("list")
            .into_iter()
            .map(|entry| entry.key)
            .collect();
        survivors.sort();
        assert_eq!(survivors, vec!["a", "b"]);
    }

    #[tokio::test]
    async fn sweep_with_all_entries_leased_is_a_no_op_deadlock_guard() {
        let storage = MemoryStorage::new();
        for key in ["a", "b"] {
            seed(&storage, key, &[0_u8; 10]).await;
        }
        let shared = leases();
        shared.acquire("a");
        shared.acquire("b");
        let service = EvictionService::new(Eviction::Lru, shared);
        let mut capacity = Capacity {
            total: 100,
            used: 90,
            min_free: 50,
            max_size: 0,
        };
        let report = service.sweep(&storage, &mut capacity).await.expect("sweep");
        assert!(report.evicted.is_empty());
        assert_eq!(report.bytes_freed, 0);
        assert_eq!(report.outcome, SweepOutcome::NoEligibleCandidates);
        assert_eq!(storage.list().await.expect("list").len(), 2);
    }

    #[tokio::test]
    async fn sweep_none_policy_never_evicts() {
        let storage = MemoryStorage::new();
        for key in ["a", "b"] {
            seed(&storage, key, &[0_u8; 10]).await;
        }
        let mut capacity = Capacity {
            total: 100,
            used: 90,
            min_free: 50,
            max_size: 0,
        };
        let report = service(Eviction::None)
            .sweep(&storage, &mut capacity)
            .await
            .expect("sweep");
        assert!(report.evicted.is_empty());
        assert_eq!(report.outcome, SweepOutcome::Disabled);
        assert_eq!(capacity.used, 90, "disabled eviction must not change used");
        assert_eq!(storage.list().await.expect("list").len(), 2);
    }

    #[tokio::test]
    async fn sweep_stops_before_deleting_once_the_budget_is_spent() {
        let storage = MemoryStorage::new();
        seed(&storage, "a", &[0_u8; 10]).await;
        let mut capacity = Capacity {
            total: 100,
            used: 90,
            min_free: 50,
            max_size: 0,
        };
        let report = EvictionService::new(Eviction::Lru, leases())
            .with_budget(Duration::ZERO)
            .sweep(&storage, &mut capacity)
            .await
            .expect("sweep");
        assert!(report.evicted.is_empty());
        assert_eq!(report.outcome, SweepOutcome::BudgetExhausted);
        assert_eq!(storage.list().await.expect("list").len(), 1);
    }

    #[tokio::test]
    async fn sweep_is_a_noop_when_the_capacity_already_sits_above_the_floor() {
        let storage = MemoryStorage::new();
        seed(&storage, "a", &[0_u8; 10]).await;
        let mut capacity = Capacity {
            total: 100,
            used: 10,
            min_free: 0,
            max_size: 0,
        };
        let report = service(Eviction::Lru)
            .sweep(&storage, &mut capacity)
            .await
            .expect("sweep");
        assert!(report.evicted.is_empty());
        assert_eq!(report.outcome, SweepOutcome::FloorReached);
    }

    #[tokio::test]
    async fn sweep_evicts_down_to_max_size_when_over_quota() {
        let storage = MemoryStorage::new();
        for key in ["a", "b", "c"] {
            seed(&storage, key, &[0_u8; 10]).await;
        }
        let mut capacity = Capacity {
            total: 100,
            used: 50,
            min_free: 0,
            max_size: 30,
        };
        let report = service(Eviction::Oldest)
            .sweep(&storage, &mut capacity)
            .await
            .expect("sweep");
        assert_eq!(report.evicted, vec!["a", "b"]);
        assert_eq!(capacity.used, 30);
        assert_eq!(report.outcome, SweepOutcome::FloorReached);
    }

    #[tokio::test]
    async fn admit_sweeps_then_accepts_and_none_refuses_below_the_floor() {
        let storage = MemoryStorage::new();
        for key in ["a", "b", "c", "d", "e"] {
            seed(&storage, key, &[0_u8; 10]).await;
        }

        // lru: the sweep frees enough room for the unknown-size request.
        let mut capacity = Capacity {
            total: 100,
            used: 90,
            min_free: 50,
            max_size: 0,
        };
        let admitted = service(Eviction::Lru)
            .admit(&storage, &mut capacity, None)
            .await
            .expect("admit");
        assert!(admitted, "sweeping must lift the cache above the floor");
        assert!(!capacity.needs_eviction());

        // none: no eviction happens, so the request stays refused.
        let mut refused = Capacity {
            total: 100,
            used: 90,
            min_free: 50,
            max_size: 0,
        };
        let admitted = service(Eviction::None)
            .admit(&storage, &mut refused, None)
            .await
            .expect("admit");
        assert!(!admitted, "eviction=none must refuse below the floor");

        // Known-size admission ignores the floor: 11 bytes are free.
        let mut known = Capacity {
            total: 100,
            used: 89,
            min_free: 50,
            max_size: 0,
        };
        let admitted = service(Eviction::None)
            .admit(&storage, &mut known, Some(11))
            .await
            .expect("admit");
        assert!(admitted, "known size only needs free >= blob_size");
    }

    #[test]
    fn reaper_interval_is_a_quarter_of_the_ttl_clamped_to_one_second() {
        assert_eq!(
            Reaper::new(Duration::from_secs(3600)).interval(),
            Duration::from_secs(900)
        );
        assert_eq!(
            Reaper::new(Duration::from_secs(2)).interval(),
            Duration::from_secs(1)
        );
        assert_eq!(
            Reaper::new(Duration::from_secs(1)).interval(),
            Duration::from_secs(1)
        );
    }

    #[tokio::test]
    async fn reaper_removes_expired_reservations_and_their_parts_only() {
        let dir = TestDir::new();
        let storage = FsStorage::open(dir.path()).expect("open");
        let now = super::super::unix_now();
        storage
            .seed_reservation("expired-key", b"partial-bytes", now - 1)
            .await
            .expect("seed expired");
        storage
            .seed_reservation("live-key", b"in-flight", now + 3600)
            .await
            .expect("seed live");

        let parts = dir.path().join("parts");
        let part_files = |n: usize| {
            std::fs::read_dir(&parts)
                .expect("read parts dir")
                .flatten()
                .filter(|entry| entry.path().is_file())
                .count()
                == n
        };
        assert!(part_files(2), "both reservations stage a part file");

        let report = Reaper::new(Duration::from_secs(3600))
            .sweep_once(&storage)
            .await
            .expect("sweep");
        assert_eq!(report.reservations_reaped, 1);
        assert!(part_files(1), "only the expired reservation's part is gone");

        // Idempotent: a second pass reaps nothing.
        let again = Reaper::new(Duration::from_secs(3600))
            .sweep_once(&storage)
            .await
            .expect("second sweep");
        assert_eq!(again.reservations_reaped, 0);
        assert!(part_files(1));
    }

    #[tokio::test]
    async fn reaper_sweeps_old_rowless_blobs_but_keeps_recent_and_rowed_ones() {
        let dir = TestDir::new();
        let storage = FsStorage::open(dir.path()).expect("open");
        // A real, indexed entry must never be swept.
        storage
            .put_stream("keep-me", bytes(b"keep"))
            .await
            .expect("put");
        storage.finalize("keep-me").await.expect("finalize");

        let blobs = dir.path().join("blobs");
        let old_orphan = blobs.join("deadbeef.blob");
        std::fs::write(&old_orphan, b"orphan").expect("plant old orphan");
        let two_hours_ago = SystemTime::now() - Duration::from_secs(7200);
        let file = std::fs::File::options()
            .write(true)
            .open(&old_orphan)
            .expect("open orphan");
        file.set_times(std::fs::FileTimes::new().set_modified(two_hours_ago))
            .expect("backdate orphan mtime");

        // A recent orphan may belong to an in-flight finalize — kept.
        let recent_orphan = blobs.join("cafebabe.blob");
        std::fs::write(&recent_orphan, b"recent").expect("plant recent orphan");

        let report = Reaper::new(Duration::from_secs(3600))
            .sweep_once(&storage)
            .await
            .expect("sweep");
        assert_eq!(report.orphan_blobs_swept, 1);
        assert!(!old_orphan.exists(), "old rowless blob swept");
        assert!(recent_orphan.exists(), "recent orphan kept");
        let stat = storage
            .stat("keep-me")
            .await
            .expect("stat")
            .expect("indexed entry survives");
        assert_eq!(stat.size, 4);
    }
}
