//! Shared application state (plan task 3).

use std::path::PathBuf;
use std::sync::Arc;

use crate::storage::StorageBackend;
use crate::tls::PeerPins;

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
