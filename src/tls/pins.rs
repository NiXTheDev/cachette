//! Peer certificate pin store for `/_internal/peers/*` (plan task 14 / B2).
//!
//! Cachette peers authenticate with self-signed certificates; trust is
//! expressed as raw SPKI-SHA256 fingerprints, never as a CA chain. Two ways a
//! fingerprint enters the store:
//!
//! * **Seeded** — `[cluster] seed_fingerprints = { name = "AA11…" }` in config.
//!   These are trusted at boot and are the intended production path.
//! * **Learned (TOFU)** — when `[cluster] enabled = true`, the first
//!   certificate seen from an unseeded peer is admitted and remembered, with a
//!   single one-time warning. This lets a fresh cluster bootstrap itself.
//!
//! When `[cluster] enabled = false` (single-node, the acceptance-test default)
//! TOFU is disabled, so only seeded fingerprints are accepted.

use std::collections::BTreeMap;
use std::sync::RwLock;
use std::sync::atomic::{AtomicBool, Ordering};

/// In-memory `name -> SPKI-SHA256 fingerprint` map of trusted cluster peers.
///
/// Lookups only ever compare fingerprint *values*: the map key is a
/// human-readable label used for diagnostics and config round-tripping.
#[derive(Debug)]
pub struct PeerPins {
    pins: RwLock<BTreeMap<String, String>>,
    /// Trust-on-first-use: admit unseeded fingerprints (`[cluster] enabled`).
    learn: bool,
    /// Emit the TOFU warning at most once per process.
    warned: AtomicBool,
}

impl PeerPins {
    /// Build a store seeded from `seed`; `learn` enables TOFU admission.
    #[must_use]
    pub fn new(seed: &BTreeMap<String, String>, learn: bool) -> Self {
        Self {
            pins: RwLock::new(seed.clone()),
            learn,
            warned: AtomicBool::new(false),
        }
    }

    /// Whether `fingerprint` is already pinned (seeded or previously learned).
    ///
    /// Never panics: a lock poisoned by a panicking writer is recovered via
    /// `into_inner`, because the map's contents are still consistent.
    #[must_use]
    pub fn is_pinned(&self, fingerprint: &str) -> bool {
        let pins = self
            .pins
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        pins.values().any(|pinned| pinned == fingerprint)
    }

    /// TOFU admission: learn `fingerprint` when TOFU is enabled; idempotent.
    ///
    /// Returns `true` when the peer is pinned after the call (either it was
    /// already pinned by a concurrent writer, or it was just learned). Returns
    /// `false` when TOFU is disabled and the fingerprint was not already
    /// present — the caller must treat that as unauthenticated.
    pub fn admit(&self, fingerprint: &str) -> bool {
        if !self.learn {
            return false;
        }
        let mut pins = self
            .pins
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if pins.values().any(|pinned| pinned == fingerprint) {
            return true;
        }
        pins.insert(format!("tofu:{fingerprint}"), fingerprint.to_owned());
        if !self.warned.swap(true, Ordering::Relaxed) {
            tracing::warn!(
                fingerprint,
                "TOFU: admitting unseeded peer fingerprint (cluster.enabled)"
            );
        }
        true
    }

    /// Pin gate: accept a verified peer certificate whose fingerprint is pinned,
    /// or learn it by TOFU when enabled.
    #[must_use]
    pub fn authorize(&self, fingerprint: &str) -> bool {
        self.is_pinned(fingerprint) || self.admit(fingerprint)
    }
}

impl Default for PeerPins {
    fn default() -> Self {
        Self::new(&BTreeMap::new(), false)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::PeerPins;

    fn seeded() -> BTreeMap<String, String> {
        BTreeMap::from([(String::from("node-a"), String::from("AAAA"))])
    }

    #[test]
    fn seeded_fingerprint_is_pinned_and_authorized() {
        let pins = PeerPins::new(&seeded(), false);
        assert!(pins.is_pinned("AAAA"));
        assert!(pins.authorize("AAAA"));
    }

    #[test]
    fn unknown_fingerprint_is_rejected_without_tofu() {
        let pins = PeerPins::new(&seeded(), false);
        assert!(!pins.authorize("BBBB"));
        assert!(
            !pins.is_pinned("BBBB"),
            "rejected cert must not be remembered"
        );
    }

    #[test]
    fn tofu_admits_unknown_fingerprint_once_enabled() {
        let pins = PeerPins::new(&BTreeMap::new(), true);
        assert!(pins.admit("CCCC"));
        assert!(pins.is_pinned("CCCC"));
        assert!(pins.authorize("CCCC"), "already-learned peer stays pinned");
    }
}
