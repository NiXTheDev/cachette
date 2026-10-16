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

/// The six hand-counted counters. Cheap: the request matrix is a fixed array
/// of atomics; the scalar counters are plain atomics. Zero background work.
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
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Metrics {
    #[must_use]
    pub fn new() -> Self {
        // Zero-init the atomic matrix without heap allocation at boot.
        let requests = std::array::from_fn(|_| std::array::from_fn(|_| AtomicU64::new(0)));
        Self {
            requests,
            bytes_in: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
            evictions_total: AtomicU64::new(0),
            reservations_active: AtomicU64::new(0),
            storage_used_bytes: AtomicU64::new(0),
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
}
