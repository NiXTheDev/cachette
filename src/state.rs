//! Shared application state (plan task 3).

use std::path::PathBuf;
use std::sync::Arc;

use crate::auth::{AuthPolicy, TokenStore};
use crate::cluster::PeerTable;
use crate::config::{KeyCase, MinFree};
use crate::storage::StorageBackend;
use crate::tls::PeerPins;

/// Cache capacity + reservation knobs threaded onto the request path (plan
/// task 19). `AppState` carries no full [`crate::config::Config`] (the v1
/// module keeps its own constants for the write-once knobs), but the reserve
/// handler needs the live `[cache]` / `[storage.fs]` numbers to report
/// `cacheSize`, stamp `reservation_expires_at`, and fold keys.
#[derive(Clone, Copy, Debug)]
pub struct CacheLimits {
    /// `[cache] max_size` in bytes; 0 = unlimited.
    pub max_size: u64,
    /// `[storage.fs] min_free` floor (B3 reserve-time admission estimate).
    pub min_free: MinFree,
    /// `[cache] reservation_ttl_seconds`: reservation expiry = now + this.
    pub reservation_ttl_seconds: u64,
    /// `[cache] key_case`: fold applied before reserve/find matching (M11).
    pub key_case: KeyCase,
}

impl Default for CacheLimits {
    fn default() -> Self {
        Self {
            max_size: 0,
            min_free: MinFree::Fraction(0.2),
            reservation_ttl_seconds: 3600,
            key_case: KeyCase::Lower,
        }
    }
}

/// State threaded through every route handler.
#[derive(Clone)]
pub struct AppState {
    /// Crate version (`CARGO_PKG_VERSION`), surfaced by `/health`.
    pub version: &'static str,
    /// Node identity — replaced with the Ed25519 fingerprint during startup
    /// (plan task 13); the hostname placeholder applies only before then.
    pub node_id: String,
    /// `--config <path>` placeholder; config loading lands in plan task 5.
    pub config_path: Option<PathBuf>,
    /// Storage handle; `None` until a backend is constructed (plan tasks 8-9).
    pub storage: Option<Arc<dyn StorageBackend>>,
    /// Cluster peer-certificate pins (plan task 14 / B2). Seeded from
    /// `[cluster] seed_fingerprints`; gates `/_internal/peers/*`.
    pub peers: Arc<PeerPins>,
    /// Cluster peer table (plan task 28): the deduplicated set of discovered
    /// peers (seeds + mDNS + hello). `serve()` seeds it when `[cluster]
    /// enabled`; the default is an empty table so single-node tests keep
    /// working.
    pub peer_table: Arc<PeerTable>,
    /// Dynamic bearer-token store (plan task 15): sqlite-backed register/
    /// revoke, shared with the storage backend's database file.
    pub tokens: Arc<TokenStore>,
    /// Auth policy snapshot (plan task 15): per-request mode resolution for
    /// the v1 artifactcache routes plus the admin register/revoke gate.
    pub auth: Arc<AuthPolicy>,
    /// Cache capacity + reservation knobs (plan task 19). Defaults mirror
    /// `CacheConfig` / `FsConfig`; `serve()` overwrites them from the loaded
    /// config.
    pub cache: CacheLimits,
}

impl AppState {
    /// Fresh state: no config path, no storage backend, hostname node id, and
    /// an empty pin store (no seeded peers, TOFU off).
    pub fn new() -> Self {
        Self {
            version: env!("CARGO_PKG_VERSION"),
            node_id: default_node_id(),
            config_path: None,
            storage: None,
            peers: Arc::new(PeerPins::default()),
            peer_table: Arc::new(PeerTable::new()),
            tokens: Arc::new(TokenStore::open_memory().expect("in-memory token store")),
            auth: Arc::new(AuthPolicy::default()),
            cache: CacheLimits::default(),
        }
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

/// Placeholder node id: the host name — `COMPUTERNAME` on Windows, `HOSTNAME`
/// on Unix-likes — falling back to `"local"`. `serve()` overwrites it with the
/// certificate fingerprint (plan task 13).
fn default_node_id() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| String::from("local"))
}

#[cfg(test)]
mod tests {
    /// Plan task 3 acceptance: unit-test the version parse.
    #[test]
    fn version_parses_as_semver_matching_the_package() {
        let raw = env!("CARGO_PKG_VERSION");
        let components: Vec<u64> = raw
            .split('.')
            .map(|part| part.parse::<u64>().expect("version component is numeric"))
            .collect();
        assert_eq!(components, vec![0, 1, 0], "unexpected version: {raw}");
    }
}
