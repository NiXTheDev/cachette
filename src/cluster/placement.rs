//! Least-loaded cluster placement (plan task 30; B3 capacity model +
//! criterion 6).
//!
//! Placement answers "which healthy peer should own this reservation?" and is
//! the shared decision that the v1 relay (task 31) and the v2 owner route
//! (task 32) call. It is deliberately connect-free: the caller hands it the
//! [`PeerRecord`]s to consider (typically
//! [`PeerTable::healthy_sorted`](super::PeerTable::healthy_sorted)) and gets
//! back the chosen record.
//!
//! The algorithm is exactly the plan's three steps, ranking ONLY healthy
//! peers:
//!
//! 1. **Capacity filter (B3)** — every peer's capacity is modelled with the
//!    same [`Capacity`] / [`MinFree`] types as [`crate::storage::eviction`].
//!    A KNOWN reservation size keeps peers with `free >= size`; an UNKNOWN
//!    size keeps peers with `free >= min_free` (the floor resolved against the
//!    peer's total).
//! 2. **Minimum fill%** — order ascending by `used / total`
//!    ([`Capacity::fill_percent`]).
//! 3. **Tiebreak** among equally least-loaded peers (`[cluster] tiebreak`):
//!    - [`Tiebreak::Random`] — uniform pick among the tied set.
//!    - [`Tiebreak::RoundRobin`] — a per-tied-set cursor advancing to the next
//!      node on every call (`B, C, B, C, …`).
//!    - [`Tiebreak::Progressive`] — compare fill% at increasing DECIMAL
//!      precision until exactly one node remains; a set that is still exactly
//!      tied at full precision falls back to a random pick (never least-
//!      recently-chosen). The comparison is exact integer long division, not
//!      floating point, so `6000/10000 = 0.6000` beats
//!      `6001/10000 = 0.6001` at the 4th decimal on every run.
//!
//! Self is a candidate like any peer: the caller includes the own-node record
//! in the slice, so a single-node cluster resolves to self. Unhealthy and
//! over-capacity peers are never chosen, and there are no wall-clock jitter
//! hacks — the only randomness is the injected [`SeededRng`].
//!
//! ## State
//!
//! [`Tiebreak::RoundRobin`] needs a cursor that survives across calls, and
//! randomness needs a PRNG stream. Both live in [`Placement`], a cheaply
//! constructible handle that belongs in cluster state (see
//! [`ClusterRuntime::placement`](super::ClusterRuntime::placement)) — never a
//! global static. Tasks 31/32 should hold one `Arc<Placement>` for the process
//! and call [`Placement::place`]. For advanced callers, the free [`place`]
//! function takes the PRNG and cursor map explicitly.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::{MinFree, Tiebreak};
use crate::storage::eviction::Capacity;

use super::PeerRecord;

/// How many fractional decimal digits [`Tiebreak::Progressive`] compares
/// before declaring an exact tie (and falling back to random). 18 covers the
/// full precision of an `f64` fill ratio while keeping the integer long
/// division far below `u128::MAX`.
pub const MAX_PROGRESSIVE_PRECISION: u32 = 18;

/// A small deterministic PRNG (SplitMix64): placement needs randomness but the
/// crate ships no `rand` dependency. [`SeededRng::from_entropy`] seeds from
/// the clock + process id for real deployments; [`SeededRng::from_seed`] gives
/// tests a reproducible stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SeededRng {
    state: u64,
}

impl SeededRng {
    /// Deterministic stream from an explicit seed (tests).
    #[must_use]
    pub fn from_seed(seed: u64) -> Self {
        Self { state: seed }
    }

    /// Best-effort entropy seed: wall clock nanoseconds mixed with the process
    /// id (SplitMix64 then avalanches the first output, so adjacent times do
    /// not yield adjacent streams).
    #[must_use]
    pub fn from_entropy() -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos() as u64)
            .unwrap_or(0);
        let seed = nanos ^ (u64::from(std::process::id()).wrapping_mul(0x9E37_79B9_7F4A_7C15));
        Self::from_seed(seed)
    }

    /// Next raw 64-bit output.
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform index in `0..bound` (biased by at most one part in 2^64 — the
    /// modulo bias is negligible here). `bound` must be non-zero.
    fn below(&mut self, bound: usize) -> usize {
        debug_assert!(bound > 0, "below() requires a non-empty range");
        (self.next_u64() % bound as u64) as usize
    }
}

/// The process-lifetime placement handle: the configured `tiebreak` plus the
/// mutable state it needs (the PRNG stream and the round-robin cursors).
///
/// Hold one of these in cluster state; do NOT construct a fresh one per
/// request or the round-robin cursor resets. It is `Sync`, so a single
/// `Arc<Placement>` serves every handler.
#[derive(Debug)]
pub struct Placement {
    tiebreak: Tiebreak,
    rng: Mutex<SeededRng>,
    cursors: Mutex<HashMap<String, usize>>,
}

impl Placement {
    /// Placement for `tiebreak`, seeded from process entropy.
    #[must_use]
    pub fn new(tiebreak: Tiebreak) -> Self {
        Self::with_rng(tiebreak, SeededRng::from_entropy())
    }

    /// Placement for `tiebreak` with a reproducible random stream (tests).
    #[must_use]
    pub fn with_seed(tiebreak: Tiebreak, seed: u64) -> Self {
        Self::with_rng(tiebreak, SeededRng::from_seed(seed))
    }

    fn with_rng(tiebreak: Tiebreak, rng: SeededRng) -> Self {
        Self {
            tiebreak,
            rng: Mutex::new(rng),
            cursors: Mutex::new(HashMap::new()),
        }
    }

    /// The configured tiebreak method.
    #[must_use]
    pub fn tiebreak(&self) -> Tiebreak {
        self.tiebreak
    }

    /// Choose the least-loaded healthy peer that admits `size`.
    ///
    /// `min_free` / `max_size` are this node's `[storage.fs] min_free` and
    /// `[cache] max_size` (the B3 knobs); v1 assumes a homogeneous cluster, so
    /// each peer's capacity is resolved the same way the local one is. Returns
    /// the winning [`PeerRecord`], or `None` when no peer admits the request.
    #[must_use]
    pub fn place(
        &self,
        peers: &[PeerRecord],
        size: Option<u64>,
        min_free: MinFree,
        max_size: u64,
    ) -> Option<PeerRecord> {
        let mut rng = lock(&self.rng);
        let mut cursors = lock(&self.cursors);
        place(
            peers,
            size,
            min_free,
            max_size,
            self.tiebreak,
            &mut rng,
            &mut cursors,
        )
    }
}

/// Stateless core of [`Placement::place`]: inject the RNG stream and the
/// round-robin cursor map explicitly. Prefer [`Placement::place`] in
/// production; this form keeps the algorithm unit-testable without shared
/// state.
///
/// `cursors` is keyed by the tied set's node signature, so independent tie
/// groups advance independently. Peers are ranked by `node_id` (then `addr`)
/// before any tiebreak, so the round-robin order is deterministic regardless
/// of the input order.
#[must_use]
pub fn place(
    peers: &[PeerRecord],
    size: Option<u64>,
    min_free: MinFree,
    max_size: u64,
    tiebreak: Tiebreak,
    rng: &mut SeededRng,
    cursors: &mut HashMap<String, usize>,
) -> Option<PeerRecord> {
    // Step 1 — capacity filter over healthy peers only. `Capacity::resolve`
    // pins `total` to `max_size` when set (homogeneous v1 cluster), else to the
    // peer's heartbeat `total_bytes`, and resolves the `min_free` floor.
    let mut admitted: Vec<(&PeerRecord, Capacity)> = peers
        .iter()
        .filter(|peer| peer.healthy)
        .filter_map(|peer| {
            let capacity = Capacity::resolve(min_free, max_size, peer.total_bytes, peer.used_bytes);
            capacity.admits(size).then_some((peer, capacity))
        })
        .collect();
    if admitted.is_empty() {
        return None;
    }
    // Deterministic order: the tiebreak's node list must not depend on the
    // caller's slice order.
    admitted.sort_by(|(a, _), (b, _)| a.node_id.cmp(&b.node_id).then_with(|| a.addr.cmp(&b.addr)));

    let chosen = match tiebreak {
        // Step 2 + progressive step 3 are one comparison: the decimal-precision
        // walk runs over every admitted peer, not just an exact float tie.
        Tiebreak::Progressive => progressive_pick(&admitted, rng),
        Tiebreak::Random | Tiebreak::RoundRobin => {
            let tied = tied_by_min_fill(&admitted);
            match tiebreak {
                Tiebreak::Random => tied[rng.below(tied.len())],
                Tiebreak::RoundRobin => {
                    let key = tied_signature(&admitted, &tied);
                    let cursor = cursors.entry(key).or_insert(0);
                    let chosen = tied[*cursor % tied.len()];
                    *cursor = cursor.wrapping_add(1);
                    chosen
                }
                Tiebreak::Progressive => unreachable!("handled above"),
            }
        }
    };
    Some(admitted[chosen].0.clone())
}

/// Step 2 for the equality-based tiebreaks: the indices (into `admitted`) whose
/// `fill_percent` equals the minimum. `admitted` is non-empty, so the result is
/// non-empty.
fn tied_by_min_fill(admitted: &[(&PeerRecord, Capacity)]) -> Vec<usize> {
    let min_fill = admitted
        .iter()
        .map(|(_, capacity)| capacity.fill_percent())
        .fold(f64::INFINITY, f64::min);
    admitted
        .iter()
        .enumerate()
        .filter(|(_, (_, capacity))| capacity.fill_percent() == min_fill)
        .map(|(index, _)| index)
        .collect()
}

/// Stable key for one tied set: the sorted identity of its members. Round-robin
/// cursors are stored per key, so a tie set that changes membership starts a
/// fresh rotation instead of resuming a stale cursor position.
fn tied_signature(admitted: &[(&PeerRecord, Capacity)], tied: &[usize]) -> String {
    let mut parts: Vec<String> = tied
        .iter()
        .map(|&index| {
            let (peer, _) = admitted[index];
            format!("{}@{}", peer.node_id, peer.addr)
        })
        .collect();
    parts.sort();
    parts.join(",")
}

/// Progressive tiebreak: truncate every candidate's fill% to 1, 2, … decimal
/// digits and keep the strict minimum each round; stop as soon as exactly one
/// candidate remains. An exact tie at [`MAX_PROGRESSIVE_PRECISION`] falls back
/// to a uniform random pick.
fn progressive_pick(admitted: &[(&PeerRecord, Capacity)], rng: &mut SeededRng) -> usize {
    let mut tied: Vec<usize> = (0..admitted.len()).collect();
    for decimals in 1..=MAX_PROGRESSIVE_PRECISION {
        let mut best: Option<(u128, u128)> = None;
        for &index in &tied {
            let value = truncated_fill(&admitted[index].1, decimals);
            if best.is_none_or(|current| value < current) {
                best = Some(value);
            }
        }
        let Some(best) = best else {
            break;
        };
        let survivors: Vec<usize> = tied
            .iter()
            .copied()
            .filter(|&index| truncated_fill(&admitted[index].1, decimals) == best)
            .collect();
        if survivors.len() == 1 {
            return survivors[0];
        }
        tied = survivors;
    }
    // Exactly tied at full precision: random fallback (never alternation).
    tied[rng.below(tied.len())]
}

/// `fill% = used / total` truncated to `decimals` fractional digits, as an
/// exact `(integer part, fractional digits)` pair. Computed by integer long
/// division so no floating-point rounding can blur a near-tie. A zero total
/// reads as `(0, 0)`.
fn truncated_fill(capacity: &Capacity, decimals: u32) -> (u128, u128) {
    let total = u128::from(capacity.total);
    if total == 0 {
        return (0, 0);
    }
    let used = u128::from(capacity.used);
    let integer = used / total;
    let mut remainder = used % total;
    let mut fraction = 0_u128;
    for _ in 0..decimals {
        remainder *= 10;
        let digit = remainder / total;
        remainder %= total;
        fraction = fraction * 10 + digit;
    }
    (integer, fraction)
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(node_id: &str, used: u64, total: u64) -> PeerRecord {
        PeerRecord {
            node_id: node_id.to_owned(),
            fingerprint: format!("FP-{node_id}"),
            addr: format!("10.0.0.{}:9000", node_id.as_bytes()[0]),
            used_bytes: used,
            total_bytes: total,
            healthy: true,
            last_hello: 1,
        }
    }

    fn fixture() -> Vec<PeerRecord> {
        vec![peer("A", 90, 100), peer("B", 60, 100), peer("C", 60, 100)]
    }

    #[test]
    fn capacity_filter_drops_the_under_floored_peer() {
        // A free = 10 < min_free = 20 -> filtered; B/C survive.
        let picked = place(
            &fixture(),
            None,
            MinFree::Fraction(0.2),
            0,
            Tiebreak::Random,
            &mut SeededRng::from_seed(1),
            &mut HashMap::new(),
        )
        .expect("B or C admits");
        assert!(picked.node_id == "B" || picked.node_id == "C", "{picked:?}");
    }

    #[test]
    fn known_size_requires_free_at_least_size() {
        // free is 40 on B/C; a 41-byte reservation fits nowhere.
        let none = place(
            &fixture(),
            Some(41),
            MinFree::Fraction(0.2),
            0,
            Tiebreak::Random,
            &mut SeededRng::from_seed(1),
            &mut HashMap::new(),
        );
        assert!(none.is_none(), "over-capacity request must not place");
        let picked = place(
            &fixture(),
            Some(40),
            MinFree::Fraction(0.2),
            0,
            Tiebreak::Random,
            &mut SeededRng::from_seed(1),
            &mut HashMap::new(),
        )
        .expect("exactly 40 free admits");
        assert!(picked.node_id == "B" || picked.node_id == "C");
    }

    #[test]
    fn roundrobin_advances_across_successive_calls() {
        let placement = Placement::with_seed(Tiebreak::RoundRobin, 7);
        let peers = fixture();
        let sequence: Vec<String> = (0..4)
            .map(|_| {
                placement
                    .place(&peers, None, MinFree::Fraction(0.2), 0)
                    .expect("place")
                    .node_id
            })
            .collect();
        assert_eq!(sequence, vec!["B", "C", "B", "C"]);
    }

    #[test]
    fn progressive_breaks_a_near_tie_at_the_fourth_decimal() {
        let peers = vec![peer("B", 6000, 10_000), peer("C", 6001, 10_000)];
        let placement = Placement::with_seed(Tiebreak::Progressive, 99);
        for _ in 0..20 {
            let picked = placement
                .place(&peers, None, MinFree::Fraction(0.2), 0)
                .expect("place");
            assert_eq!(picked.node_id, "B");
        }
    }

    #[test]
    fn progressive_falls_back_to_random_on_an_exact_tie() {
        let peers = vec![peer("B", 6000, 10_000), peer("C", 6000, 10_000)];
        let placement = Placement::with_seed(Tiebreak::Progressive, 3);
        let picks: Vec<String> = (0..20)
            .map(|_| {
                placement
                    .place(&peers, None, MinFree::Fraction(0.2), 0)
                    .expect("place")
                    .node_id
            })
            .collect();
        assert!(picks.iter().all(|id| id == "B" || id == "C"), "{picks:?}");
        let alternating: Vec<String> = (0..20)
            .map(|index| if index % 2 == 0 { "B" } else { "C" }.to_owned())
            .collect();
        assert_ne!(picks, alternating, "exact ties must not alternate");
    }

    #[test]
    fn unhealthy_and_over_capacity_peers_are_never_chosen() {
        let mut peers = vec![peer("A", 90, 100), peer("B", 60, 100), peer("C", 60, 100)];
        let mut dead = peer("D", 0, 100);
        dead.healthy = false;
        peers.push(dead);
        let placement = Placement::with_seed(Tiebreak::Random, 11);
        for _ in 0..50 {
            let picked = placement
                .place(&peers, None, MinFree::Fraction(0.2), 0)
                .expect("place");
            assert!(picked.node_id == "B" || picked.node_id == "C", "{picked:?}");
        }
    }

    #[test]
    fn single_node_resolves_to_self() {
        let peers = vec![peer("SELF", 10, 100)];
        let picked = place(
            &peers,
            None,
            MinFree::Fraction(0.2),
            0,
            Tiebreak::Random,
            &mut SeededRng::from_seed(5),
            &mut HashMap::new(),
        )
        .expect("self is a candidate");
        assert_eq!(picked.node_id, "SELF");
    }

    #[test]
    fn no_healthy_peer_yields_none() {
        let mut peers = vec![peer("A", 0, 100)];
        peers[0].healthy = false;
        assert!(
            place(
                &peers,
                None,
                MinFree::Fraction(0.2),
                0,
                Tiebreak::Random,
                &mut SeededRng::from_seed(5),
                &mut HashMap::new(),
            )
            .is_none()
        );
    }

    #[test]
    fn zero_total_peer_admits_unknown_size_at_a_zero_floor() {
        // min_free 0 resolves to 0 on an unknown (total 0) volume, so the
        // B3 unknown-size rule admits it.
        let peers = vec![peer("UNKNOWN", 0, 0)];
        let picked = place(
            &peers,
            None,
            MinFree::Bytes(0),
            0,
            Tiebreak::Random,
            &mut SeededRng::from_seed(5),
            &mut HashMap::new(),
        )
        .expect("admits at a zero floor");
        assert_eq!(picked.node_id, "UNKNOWN");
    }

    #[test]
    fn truncated_fill_is_exact_integer_long_division() {
        let half = Capacity {
            total: 10_000,
            used: 6_000,
            min_free: 0,
            max_size: 0,
        };
        let other = Capacity {
            total: 10_000,
            used: 6_001,
            min_free: 0,
            max_size: 0,
        };
        assert_eq!(truncated_fill(&half, 4), (0, 6_000));
        assert_eq!(truncated_fill(&other, 4), (0, 6_001));
        // 1/3 = 0.333... truncates, never rounds up.
        let third = Capacity {
            total: 3,
            used: 1,
            min_free: 0,
            max_size: 0,
        };
        assert_eq!(truncated_fill(&third, 3), (0, 333));
    }
}
