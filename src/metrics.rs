//! Metrics counters (plan task 35) — hand-counted, no metrics dependency.
//!
//! Six counters are exposed as `GET /metrics` in the Prometheus text
//! exposition format: `requests_total{route,code}`, `bytes_in`, `bytes_out`,
//! `evictions_total`, `reservations_active`, `storage_used_bytes`.
//!
//! Everything is a `std::sync::atomic::AtomicU64` — there is no external
//! metrics crate, no scraping thread, and no per-request heap allocation on
//! the request path. `requests_total` is a fixed `[routes][codes]` matrix of
//! atomics indexed by [`Metrics::record_request`], which keeps the label set
//! bounded (memory-light requirement) while still reporting `route` + `code`.

use std::sync::atomic::{AtomicU64, Ordering};

/// Route label cardinality for `requests_total`. Kept small so the counter
/// matrix stays cheap (routes are bucketed by API group, not full path).
const ROUTES: &[&str] = &[
    "health", "metrics", "peers", "admin", "v1", "twirp", "v2", "other",
];

/// Status-code buckets for `requests_total`. A response code not listed here
/// is counted in the trailing `"other"` bucket so nothing is dropped.
const CODES: &[u16] = &[
    200, 201, 204, 301, 302, 400, 401, 403, 404, 405, 409, 410, 413, 415, 422, 429, 500, 502, 503,
    504,
];

/// `+1` for the `"other"` code bucket appended to [`CODES`].
const CODE_BUCKETS: usize = CODES.len() + 1;
const ROUTE_COUNT: usize = ROUTES.len();

/// Relay failure causes for `cachette_relay_failures_total{reason}` (plan task
/// 49): a peer relay that could not be reached (surfaced as `502`) and an owner
/// that refused on capacity (surfaced as `503`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelayFailure {
    /// Owner unreachable / errored (HTTP `502`).
    Unreachable,
    /// Owner below its free-space floor (HTTP `503`).
    Capacity,
}

impl RelayFailure {
    /// Every reason, in render order.
    const ALL: [RelayFailure; 2] = [RelayFailure::Unreachable, RelayFailure::Capacity];

    const fn index(self) -> usize {
        match self {
            RelayFailure::Unreachable => 0,
            RelayFailure::Capacity => 1,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            RelayFailure::Unreachable => "unreachable",
            RelayFailure::Capacity => "capacity",
        }
    }
}

/// Upper bounds (seconds) of the `cachette_peer_latency_seconds` histogram
/// (plan task 49) — aggregate over peer exchanges. Labels are fixed strings so
/// rendering never float-formats.
const PEER_LATENCY_BOUNDS: &[f64] = &[
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];
const PEER_LATENCY_LABELS: &[&str] = &[
    "0.005", "0.01", "0.025", "0.05", "0.1", "0.25", "0.5", "1", "2.5", "5", "10",
];

/// Upper bounds (hops) of the `cachette_relay_hops` histogram (plan task 49).
const RELAY_HOP_LABELS: &[&str] = &["0", "1", "2", "3", "4"];

/// The hand-counted counters. Cheap: the request matrix is a fixed array of
/// atomics, the histograms are fixed arrays of atomics, and the scalars are
/// plain atomics. Zero background work, no per-request heap allocation.
#[derive(Debug)]
pub struct Metrics {
    /// `requests_total{route,code}` — `[route_index][code_index]`.
    requests: [[AtomicU64; CODE_BUCKETS]; ROUTE_COUNT],
    /// Total request-body bytes observed (`Content-Length` or exact body size).
    bytes_in: AtomicU64,
    /// Total response-body bytes observed (`Content-Length` or exact body size).
    bytes_out: AtomicU64,
    /// Cache evictions performed by the reaper.
    evictions_total: AtomicU64,
    /// Currently active reservations.
    reservations_active: AtomicU64,
    /// Bytes currently occupied in storage.
    storage_used_bytes: AtomicU64,
    /// `1` while the node is draining, else `0` (plan task 49).
    draining: AtomicU64,
    /// Healthy peers in the cluster table (plan task 49).
    peers_healthy: AtomicU64,
    /// Known peers (healthy or not) in the cluster table.
    peers_known: AtomicU64,
    /// Peers discovered directly (identity known: mDNS/hello), not bare seeds.
    peers_direct: AtomicU64,
    /// `relay_failures_total{reason}` — indexed by [`RelayFailure::index`].
    relay_failures: [AtomicU64; 2],
    /// `peer_latency_seconds` histogram buckets + over+inf slot.
    peer_latency_buckets: [AtomicU64; PEER_LATENCY_BOUNDS.len() + 1],
    /// Sum of observed peer latencies, in microseconds (integer accumulation).
    peer_latency_micros: AtomicU64,
    /// Number of observed peer exchanges.
    peer_latency_count: AtomicU64,
    /// `relay_hops` histogram buckets + over+inf slot.
    relay_hop_buckets: [AtomicU64; RELAY_HOP_LABELS.len() + 1],
    /// Sum of observed hop counts.
    relay_hops_sum: AtomicU64,
    /// Number of observed relay placements.
    relay_hops_count: AtomicU64,
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Metrics {
    #[must_use]
    pub fn new() -> Self {
        // Zero-init the atomic matrices without heap allocation at boot.
        let requests = std::array::from_fn(|_| std::array::from_fn(|_| AtomicU64::new(0)));
        let zero = |_| AtomicU64::new(0);
        Self {
            requests,
            bytes_in: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
            evictions_total: AtomicU64::new(0),
            reservations_active: AtomicU64::new(0),
            storage_used_bytes: AtomicU64::new(0),
            draining: AtomicU64::new(0),
            peers_healthy: AtomicU64::new(0),
            peers_known: AtomicU64::new(0),
            peers_direct: AtomicU64::new(0),
            relay_failures: std::array::from_fn(zero),
            peer_latency_buckets: std::array::from_fn(zero),
            peer_latency_micros: AtomicU64::new(0),
            peer_latency_count: AtomicU64::new(0),
            relay_hop_buckets: std::array::from_fn(zero),
            relay_hops_sum: AtomicU64::new(0),
            relay_hops_count: AtomicU64::new(0),
        }
    }

    /// Classify a request path into a [`ROUTES`] label index.
    pub(crate) fn route_index(path: &str) -> usize {
        if path == "/health" {
            return 0;
        }
        if path == "/metrics" {
            return 1;
        }
        if path.starts_with("/_internal/peers") {
            return 2;
        }
        if path.starts_with("/_internal/") {
            return 3;
        }
        if path.starts_with("/_apis/artifactcache") {
            return 4;
        }
        if path.starts_with("/twirp/") {
            return 5;
        }
        if path.starts_with("/v2/") {
            return 6;
        }
        7
    }

    /// Bucket a status code into [`CODES`], falling back to `"other"`.
    const fn code_bucket(code: u16) -> usize {
        let mut i = 0;
        while i < CODES.len() {
            if CODES[i] == code {
                return i;
            }
            i += 1;
        }
        CODES.len()
    }

    /// Count one request: increment `requests_total{route,code}`.
    pub fn record_request(&self, path: &str, code: u16) {
        let r = Self::route_index(path);
        let c = Self::code_bucket(code);
        self.requests[r][c].fetch_add(1, Ordering::Relaxed);
    }

    /// Add `n` bytes to `bytes_in` (request bodies, sizes only).
    pub fn add_bytes_in(&self, n: u64) {
        self.bytes_in.fetch_add(n, Ordering::Relaxed);
    }

    /// Add `n` bytes to `bytes_out` (response bodies, sizes only).
    pub fn add_bytes_out(&self, n: u64) {
        self.bytes_out.fetch_add(n, Ordering::Relaxed);
    }

    /// Increment `evictions_total` (called by the reaper).
    pub fn inc_evictions(&self) {
        self.evictions_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Adjust `reservations_active` by `delta` (`+1` reserve, `-1` release).
    pub fn add_reservations(&self, delta: i64) {
        // i64 delta folded onto a u64 gauge via wrapping add: reservations are
        // balanced, so the running total never goes negative in practice.
        let magnitude = delta.unsigned_abs();
        if delta.is_negative() {
            self.reservations_active
                .fetch_sub(magnitude, Ordering::Relaxed);
        } else {
            self.reservations_active
                .fetch_add(magnitude, Ordering::Relaxed);
        }
    }

    /// Set `storage_used_bytes` to `bytes` (the reaper/heartbeat refreshes it).
    pub fn set_storage_used(&self, bytes: u64) {
        self.storage_used_bytes.store(bytes, Ordering::Relaxed);
    }

    /// Set the drain-state gauge (plan task 49): `1` while draining, else `0`.
    pub fn set_draining(&self, draining: bool) {
        self.draining.store(u64::from(draining), Ordering::Relaxed);
    }

    /// Set the cluster peer gauges (plan task 49): healthy, known (total), and
    /// directly-discovered (identity known) peer counts.
    pub fn set_peers(&self, healthy: u64, known: u64, direct: u64) {
        self.peers_healthy.store(healthy, Ordering::Relaxed);
        self.peers_known.store(known, Ordering::Relaxed);
        self.peers_direct.store(direct, Ordering::Relaxed);
    }

    /// Count one relay failure by cause (`502` unreachable / `503` capacity).
    pub fn inc_relay_failure(&self, reason: RelayFailure) {
        self.relay_failures[reason.index()].fetch_add(1, Ordering::Relaxed);
    }

    /// Observe one peer exchange's round-trip time (seconds) into
    /// `peer_latency_seconds`.
    pub fn observe_peer_latency(&self, seconds: f64) {
        let micros = (seconds.max(0.0) * 1_000_000.0) as u64;
        self.peer_latency_micros
            .fetch_add(micros, Ordering::Relaxed);
        self.peer_latency_count.fetch_add(1, Ordering::Relaxed);
        let slot = PEER_LATENCY_BOUNDS
            .iter()
            .position(|bound| seconds <= *bound)
            .unwrap_or(PEER_LATENCY_BOUNDS.len());
        self.peer_latency_buckets[slot].fetch_add(1, Ordering::Relaxed);
    }

    /// Observe the number of relay hops a placement took: `0` = served
    /// locally, `1` = forwarded to one owner.
    pub fn observe_relay_hops(&self, hops: u64) {
        self.relay_hops_sum.fetch_add(hops, Ordering::Relaxed);
        self.relay_hops_count.fetch_add(1, Ordering::Relaxed);
        let slot = RELAY_HOP_LABELS
            .iter()
            .position(|bound| hops <= bound.parse::<u64>().expect("numeric hop bound"))
            .unwrap_or(RELAY_HOP_LABELS.len());
        self.relay_hop_buckets[slot].fetch_add(1, Ordering::Relaxed);
    }

    /// Render the Prometheus text exposition format for `GET /metrics`.
    #[must_use]
    pub fn render_prometheus(&self) -> String {
        let mut out = String::with_capacity(2048);

        out.push_str(
            "# HELP cachette_requests_total Total HTTP requests by route and status code.\n",
        );
        out.push_str("# TYPE cachette_requests_total counter\n");
        for (r, route) in ROUTES.iter().enumerate() {
            for (c, code) in CODES.iter().enumerate() {
                let v = self.requests[r][c].load(Ordering::Relaxed);
                if v > 0 {
                    out.push_str(&format!(
                        "cachette_requests_total{{route=\"{route}\",code=\"{code}\"}} {v}\n"
                    ));
                }
            }
            let other = self.requests[r][CODES.len()].load(Ordering::Relaxed);
            if other > 0 {
                out.push_str(&format!(
                    "cachette_requests_total{{route=\"{route}\",code=\"other\"}} {other}\n"
                ));
            }
        }

        let bytes_in = self.bytes_in.load(Ordering::Relaxed);
        let bytes_out = self.bytes_out.load(Ordering::Relaxed);
        let evictions = self.evictions_total.load(Ordering::Relaxed);
        let reservations = self.reservations_active.load(Ordering::Relaxed);
        let storage = self.storage_used_bytes.load(Ordering::Relaxed);

        out.push_str("# HELP cachette_bytes_in Total request-body bytes received.\n");
        out.push_str("# TYPE cachette_bytes_in counter\n");
        out.push_str(&format!("cachette_bytes_in {bytes_in}\n"));

        out.push_str("# HELP cachette_bytes_out Total response-body bytes sent.\n");
        out.push_str("# TYPE cachette_bytes_out counter\n");
        out.push_str(&format!("cachette_bytes_out {bytes_out}\n"));

        out.push_str("# HELP cachette_evictions_total Total cache evictions.\n");
        out.push_str("# TYPE cachette_evictions_total counter\n");
        out.push_str(&format!("cachette_evictions_total {evictions}\n"));

        out.push_str("# HELP cachette_reservations_active Currently active reservations.\n");
        out.push_str("# TYPE cachette_reservations_active gauge\n");
        out.push_str(&format!("cachette_reservations_active {reservations}\n"));

        out.push_str("# HELP cachette_storage_used_bytes Bytes currently used in storage.\n");
        out.push_str("# TYPE cachette_storage_used_bytes gauge\n");
        out.push_str(&format!("cachette_storage_used_bytes {storage}\n"));

        // Drain state (plan task 49).
        let draining = self.draining.load(Ordering::Relaxed);
        out.push_str("# HELP cachette_draining 1 while the node is draining, else 0.\n");
        out.push_str("# TYPE cachette_draining gauge\n");
        out.push_str(&format!("cachette_draining {draining}\n"));

        // Cluster peer gauges (plan task 49).
        out.push_str("# HELP cachette_peers_healthy Healthy peers in the cluster table.\n");
        out.push_str("# TYPE cachette_peers_healthy gauge\n");
        out.push_str(&format!(
            "cachette_peers_healthy {}\n",
            self.peers_healthy.load(Ordering::Relaxed)
        ));
        out.push_str("# HELP cachette_peers_known Known peers (healthy or not).\n");
        out.push_str("# TYPE cachette_peers_known gauge\n");
        out.push_str(&format!(
            "cachette_peers_known {}\n",
            self.peers_known.load(Ordering::Relaxed)
        ));
        out.push_str("# HELP cachette_peers_direct Peers discovered directly (identity known).\n");
        out.push_str("# TYPE cachette_peers_direct gauge\n");
        out.push_str(&format!(
            "cachette_peers_direct {}\n",
            self.peers_direct.load(Ordering::Relaxed)
        ));

        // Relay failures by cause (plan task 49).
        out.push_str("# HELP cachette_relay_failures_total Peer relay failures by cause.\n");
        out.push_str("# TYPE cachette_relay_failures_total counter\n");
        for reason in RelayFailure::ALL {
            let v = self.relay_failures[reason.index()].load(Ordering::Relaxed);
            if v > 0 {
                out.push_str(&format!(
                    "cachette_relay_failures_total{{reason=\"{}\"}} {v}\n",
                    reason.as_str()
                ));
            }
        }

        // Peer-latency histogram (plan task 49); only emitted once observed.
        let count = self.peer_latency_count.load(Ordering::Relaxed);
        if count > 0 {
            out.push_str(
                "# HELP cachette_peer_latency_seconds Round-trip time of peer exchanges.\n",
            );
            out.push_str("# TYPE cachette_peer_latency_seconds histogram\n");
            let mut cumulative = 0u64;
            for (index, label) in PEER_LATENCY_LABELS.iter().enumerate() {
                cumulative += self.peer_latency_buckets[index].load(Ordering::Relaxed);
                out.push_str(&format!(
                    "cachette_peer_latency_seconds_bucket{{le=\"{label}\"}} {cumulative}\n"
                ));
            }
            out.push_str(&format!(
                "cachette_peer_latency_seconds_bucket{{le=\"+Inf\"}} {count}\n"
            ));
            let micros = self.peer_latency_micros.load(Ordering::Relaxed);
            out.push_str(&format!(
                "cachette_peer_latency_seconds_sum {}.{:06}\n",
                micros / 1_000_000,
                micros % 1_000_000
            ));
            out.push_str(&format!("cachette_peer_latency_seconds_count {count}\n"));
        }

        // Relay-hops histogram (plan task 49); only emitted once observed.
        let hop_count = self.relay_hops_count.load(Ordering::Relaxed);
        if hop_count > 0 {
            out.push_str("# HELP cachette_relay_hops Peer hops taken to place a relayed upload.\n");
            out.push_str("# TYPE cachette_relay_hops histogram\n");
            let mut cumulative = 0u64;
            for (index, label) in RELAY_HOP_LABELS.iter().enumerate() {
                cumulative += self.relay_hop_buckets[index].load(Ordering::Relaxed);
                out.push_str(&format!(
                    "cachette_relay_hops_bucket{{le=\"{label}\"}} {cumulative}\n"
                ));
            }
            out.push_str(&format!(
                "cachette_relay_hops_bucket{{le=\"+Inf\"}} {hop_count}\n"
            ));
            out.push_str(&format!(
                "cachette_relay_hops_sum {}\n",
                self.relay_hops_sum.load(Ordering::Relaxed)
            ));
            out.push_str(&format!("cachette_relay_hops_count {hop_count}\n"));
        }

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_requests_by_route_and_code() {
        let m = Metrics::new();
        m.record_request("/health", 200);
        m.record_request("/health", 200);
        m.record_request("/v2/upload/x", 500);
        let text = m.render_prometheus();
        assert!(text.contains(r#"cachette_requests_total{route="health",code="200"} 2"#));
        assert!(text.contains(r#"cachette_requests_total{route="v2",code="500"} 1"#));
    }

    #[test]
    fn unknown_code_falls_into_other_bucket() {
        let m = Metrics::new();
        m.record_request("/weird", 418); // teapot not in CODES
        let text = m.render_prometheus();
        assert!(text.contains(r#"cachette_requests_total{route="other",code="other"} 1"#));
    }

    #[test]
    fn scalar_counters_present_and_move() {
        let m = Metrics::new();
        m.add_bytes_in(1024);
        m.add_bytes_out(512);
        m.inc_evictions();
        m.add_reservations(1);
        m.set_storage_used(4096);
        let text = m.render_prometheus();
        assert!(text.contains("cachette_bytes_in 1024"));
        assert!(text.contains("cachette_bytes_out 512"));
        assert!(text.contains("cachette_evictions_total 1"));
        assert!(text.contains("cachette_reservations_active 1"));
        assert!(text.contains("cachette_storage_used_bytes 4096"));
    }

    #[test]
    fn route_classification_covers_groups() {
        assert_eq!(Metrics::route_index("/health"), 0);
        assert_eq!(Metrics::route_index("/metrics"), 1);
        assert_eq!(Metrics::route_index("/_internal/peers"), 2);
        assert_eq!(Metrics::route_index("/_internal/register"), 3);
        assert_eq!(Metrics::route_index("/_apis/artifactcache/cache"), 4);
        assert_eq!(Metrics::route_index("/twirp/x/y"), 5);
        assert_eq!(Metrics::route_index("/v2/upload/1"), 6);
        assert_eq!(Metrics::route_index("/nope"), 7);
    }

    #[test]
    fn reservations_gauge_decrements() {
        let m = Metrics::new();
        m.add_reservations(1);
        m.add_reservations(1);
        m.add_reservations(-1);
        let text = m.render_prometheus();
        assert!(text.contains("cachette_reservations_active 1"));
    }

    #[test]
    fn draining_gauge_reflects_state() {
        let m = Metrics::new();
        assert!(m.render_prometheus().contains("cachette_draining 0"));
        m.set_draining(true);
        assert!(m.render_prometheus().contains("cachette_draining 1"));
        m.set_draining(false);
        assert!(m.render_prometheus().contains("cachette_draining 0"));
    }

    #[test]
    fn peer_gauges_reflect_counts() {
        let m = Metrics::new();
        m.set_peers(2, 5, 3);
        let text = m.render_prometheus();
        assert!(text.contains("cachette_peers_healthy 2"));
        assert!(text.contains("cachette_peers_known 5"));
        assert!(text.contains("cachette_peers_direct 3"));
    }

    #[test]
    fn relay_failures_counted_by_reason() {
        let m = Metrics::new();
        // Reasons never observed are omitted (bounded cardinality).
        assert!(
            !m.render_prometheus()
                .contains("cachette_relay_failures_total{")
        );
        m.inc_relay_failure(RelayFailure::Unreachable);
        m.inc_relay_failure(RelayFailure::Unreachable);
        m.inc_relay_failure(RelayFailure::Capacity);
        let text = m.render_prometheus();
        assert!(text.contains(r#"cachette_relay_failures_total{reason="unreachable"} 2"#));
        assert!(text.contains(r#"cachette_relay_failures_total{reason="capacity"} 1"#));
    }

    #[test]
    fn peer_latency_histogram_buckets_and_sum() {
        let m = Metrics::new();
        // Not emitted until a sample lands.
        assert!(
            !m.render_prometheus()
                .contains("cachette_peer_latency_seconds")
        );
        m.observe_peer_latency(0.003); // <= 0.005
        m.observe_peer_latency(0.4); // <= 0.5
        m.observe_peer_latency(30.0); // +Inf only
        let text = m.render_prometheus();
        assert!(text.contains(r#"cachette_peer_latency_seconds_bucket{le="0.005"} 1"#));
        assert!(text.contains(r#"cachette_peer_latency_seconds_bucket{le="0.5"} 2"#));
        assert!(text.contains(r#"cachette_peer_latency_seconds_bucket{le="+Inf"} 3"#));
        assert!(text.contains("cachette_peer_latency_seconds_count 3"));
        // 0.003 + 0.4 + 30.0 = 30.403 exactly.
        assert!(text.contains("cachette_peer_latency_seconds_sum 30.403000"));
    }

    #[test]
    fn relay_hops_histogram_buckets_and_sum() {
        let m = Metrics::new();
        assert!(!m.render_prometheus().contains("cachette_relay_hops"));
        m.observe_relay_hops(0);
        m.observe_relay_hops(1);
        m.observe_relay_hops(9); // +Inf only
        let text = m.render_prometheus();
        assert!(text.contains(r#"cachette_relay_hops_bucket{le="0"} 1"#));
        assert!(text.contains(r#"cachette_relay_hops_bucket{le="1"} 2"#));
        assert!(text.contains(r#"cachette_relay_hops_bucket{le="4"} 2"#));
        assert!(text.contains(r#"cachette_relay_hops_bucket{le="+Inf"} 3"#));
        assert!(text.contains("cachette_relay_hops_sum 10"));
        assert!(text.contains("cachette_relay_hops_count 3"));
    }
}
