//! Cluster peer table + discovery (plan task 28 / M5 / M13).
//!
//! The peer table is the single source of truth for "who is in the cluster".
//! Peers arrive from three places and are merged into one deduplicated set:
//!
//! * **Static seeds** — `[cluster] seeds`, identity unknown, deduped pre-hello
//!   by `addr:port`.
//! * **mDNS** — `_cachette._tcp.local.` services whose TXT records carry
//!   `node_id`, `fingerprint`, and `port`; identity is known on discovery.
//! * **Hello** — `POST /_internal/peers/hello`, mTLS-pinned; identity known.
//!
//! Post-hello, peers dedup by identity: `node_id` when set, else `fingerprint`
//! (M5/M13). A seed-discovered node and its mDNS record are ONE peer because
//! they share `addr:port` (criterion 7). The table is deliberately
//! connect-free: nothing here dials out at startup — transport is tasks 29-31.

mod mdns;
mod seeds;

use std::collections::HashMap;
use std::sync::RwLock;

use crate::config::ClusterConfig;
use crate::identity::Identity;

pub use seeds::{Seed, parse_seeds};

/// One cluster peer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerRecord {
    /// Human label; empty until the peer identifies itself.
    pub node_id: String,
    /// SPKI-SHA256 fingerprint (the peer's stable identity); empty pre-hello.
    pub fingerprint: String,
    /// `ip:port` (or `host:port`) dial target.
    pub addr: String,
    /// Bytes used on the peer (heartbeat, task 29).
    pub used_bytes: u64,
    /// Total capacity in bytes on the peer (heartbeat, task 29).
    pub total_bytes: u64,
    /// Alive and eligible for placement; false after a peer timeout.
    pub healthy: bool,
    /// Unix seconds of the last hello/heartbeat; 0 = never identified.
    pub last_hello: u64,
}

impl PeerRecord {
    fn blank(addr: &str) -> Self {
        Self {
            node_id: String::new(),
            fingerprint: String::new(),
            addr: addr.to_owned(),
            used_bytes: 0,
            total_bytes: 0,
            healthy: true,
            last_hello: 0,
        }
    }
}

/// Thread-safe, deduplicated peer set.
///
/// Records are keyed by identity (`id:<node_id>` / `fp:<fingerprint>`) once
/// known, and by `addr:<addr:port>` before that. Every insert reconciles along
/// both axes, so a seed record and an mDNS record for the same node collapse
/// into one entry.
#[derive(Debug, Default)]
pub struct PeerTable {
    inner: RwLock<HashMap<String, PeerRecord>>,
}

impl PeerTable {
    /// Empty table (single-node default).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Seed discovery: an address with no identity yet (pre-hello dedup key).
    pub fn observe_addr(&self, addr: &str) {
        self.merge(PeerRecord::blank(addr));
    }

    /// mDNS discovery: identity + address known at once.
    pub fn observe_discovered(&self, node_id: &str, fingerprint: &str, addr: &str, now: u64) {
        let mut record = PeerRecord::blank(addr);
        record.node_id = node_id.to_owned();
        record.fingerprint = fingerprint.to_owned();
        record.last_hello = now;
        self.merge(record);
    }

    /// `POST /_internal/peers/hello`: refresh freshness and fold the identity
    /// into any pre-existing seed/mDNS record. Returns the merged record.
    pub fn hello(&self, node_id: &str, fingerprint: &str, addr: &str, now: u64) -> PeerRecord {
        let mut record = PeerRecord::blank(addr);
        record.node_id = node_id.to_owned();
        record.fingerprint = fingerprint.to_owned();
        record.last_hello = now;
        self.merge(record)
    }

    /// Heartbeat (task 29): update capacity stats and freshness by identity.
    pub fn heartbeat(
        &self,
        node_id: &str,
        fingerprint: &str,
        used_bytes: u64,
        total_bytes: u64,
        now: u64,
    ) -> bool {
        let mut peers = self
            .inner
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some((_, record)) = peers
            .iter_mut()
            .find(|(_, record)| same_identity(record, node_id, fingerprint))
        else {
            return false;
        };
        record.used_bytes = used_bytes;
        record.total_bytes = total_bytes;
        record.healthy = true;
        record.last_hello = now;
        true
    }

    /// Mark a peer unhealthy after `peer_timeout_seconds` (task 29).
    pub fn mark_unhealthy(&self, node_id: &str, fingerprint: &str) -> bool {
        let mut peers = self
            .inner
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some((_, record)) = peers
            .iter_mut()
            .find(|(_, record)| same_identity(record, node_id, fingerprint))
        else {
            return false;
        };
        record.healthy = false;
        true
    }

    /// Snapshot of every peer, sorted by `node_id` then `addr`.
    #[must_use]
    pub fn snapshot(&self) -> Vec<PeerRecord> {
        let mut records: Vec<PeerRecord> = self
            .inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .cloned()
            .collect();
        records.sort_by(|a, b| (&a.node_id, &a.addr).cmp(&(&b.node_id, &b.addr)));
        records
    }

    /// Healthy peers only, sorted — the placement input (task 30).
    #[must_use]
    pub fn healthy_sorted(&self) -> Vec<PeerRecord> {
        let mut records = self.snapshot();
        records.retain(|record| record.healthy);
        records
    }

    /// Number of distinct peers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.snapshot().len()
    }

    /// Whether the table holds no peers.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Look up one record by its canonical key.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<PeerRecord> {
        self.inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(key)
            .cloned()
    }

    /// Insert `incoming`, merging it into the first record that shares its
    /// identity or its address. Returns the merged entry.
    fn merge(&self, incoming: PeerRecord) -> PeerRecord {
        let mut peers = self
            .inner
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let target = peers
            .iter()
            .find(|(_, existing)| {
                same_identity(existing, &incoming.node_id, &incoming.fingerprint)
                    || (!incoming.addr.is_empty() && existing.addr == incoming.addr)
            })
            .map(|(key, _)| key.clone());
        let key = target.unwrap_or_else(|| identity_key(&incoming));
        let entry = peers.entry(key).or_insert_with(|| PeerRecord::blank(""));
        merge_into(entry, incoming);
        entry.clone()
    }
}

/// Canonical table key: identity when known, else the pre-hello address.
fn identity_key(record: &PeerRecord) -> String {
    if !record.node_id.is_empty() {
        format!("id:{}", record.node_id)
    } else if !record.fingerprint.is_empty() {
        format!("fp:{}", record.fingerprint)
    } else {
        format!("addr:{}", record.addr)
    }
}

/// Identity match: shared non-empty `node_id` or shared non-empty `fingerprint`.
fn same_identity(record: &PeerRecord, node_id: &str, fingerprint: &str) -> bool {
    (!record.node_id.is_empty() && record.node_id == node_id)
        || (!record.fingerprint.is_empty() && record.fingerprint == fingerprint)
}

/// Fold `incoming` into `existing`: non-empty fields win, stats adopt when the
/// incoming record carries data, freshness only moves forward.
fn merge_into(existing: &mut PeerRecord, incoming: PeerRecord) {
    if !incoming.node_id.is_empty() {
        existing.node_id = incoming.node_id;
    }
    if !incoming.fingerprint.is_empty() {
        existing.fingerprint = incoming.fingerprint;
    }
    if !incoming.addr.is_empty() {
        existing.addr = incoming.addr;
    }
    if incoming.used_bytes > 0 || incoming.total_bytes > 0 {
        existing.used_bytes = incoming.used_bytes;
        existing.total_bytes = incoming.total_bytes;
    }
    existing.healthy |= incoming.healthy;
    if incoming.last_hello > existing.last_hello {
        existing.last_hello = incoming.last_hello;
    }
}

/// Handle keeping the mDNS daemon + browser alive for the process lifetime.
pub struct ClusterRuntime {
    peer_table: std::sync::Arc<PeerTable>,
    _mdns: Option<mdns::MdnsHandle>,
}

impl ClusterRuntime {
    /// The shared peer table (also reachable via `AppState::peer_table`).
    #[must_use]
    pub fn peer_table(&self) -> &std::sync::Arc<PeerTable> {
        &self.peer_table
    }
}

/// Start cluster discovery: parse seeds into the table, then (when
/// `cluster.mdns`) advertise this node and browse for peers. mDNS failure is
/// never fatal — a VPS has no link-local peers, so the node boots with the
/// seed set alone (m10).
#[must_use]
pub fn start(cluster: &ClusterConfig, identity: &Identity, listen: &str) -> ClusterRuntime {
    let peer_table = std::sync::Arc::new(PeerTable::new());
    let default_port = crate::config::split_host_port(listen)
        .map(|(_, port)| port)
        .unwrap_or(0);
    for seed in parse_seeds(&cluster.seeds, default_port) {
        peer_table.observe_addr(&seed.addr());
        tracing::debug!(addr = %seed.addr(), "seed peer registered");
    }
    let mdns = if cluster.mdns {
        let advertise = cluster.advertise_addr.as_deref().unwrap_or(listen);
        let node_id = cluster
            .node_id
            .as_deref()
            .filter(|value| !value.is_empty())
            .unwrap_or(identity.fingerprint());
        match mdns::start(advertise, node_id, identity.fingerprint(), &peer_table) {
            Ok(handle) => {
                tracing::info!(
                    service = handle.fullname(),
                    "mDNS responder + browser started"
                );
                Some(handle)
            }
            Err(err) => {
                tracing::warn!(error = %err, "mDNS unavailable; continuing with seeds only");
                None
            }
        }
    } else {
        None
    };
    ClusterRuntime {
        peer_table,
        _mdns: mdns,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_and_mdns_for_the_same_node_collapse_to_one_peer() {
        let table = PeerTable::new();
        table.observe_addr("127.0.0.1:9001");
        table.observe_discovered("node-b", "FBBB", "127.0.0.1:9001", 100);
        let peers = table.snapshot();
        assert_eq!(peers.len(), 1, "{peers:?}");
        assert_eq!(peers[0].node_id, "node-b");
        assert_eq!(peers[0].fingerprint, "FBBB");
        assert_eq!(peers[0].addr, "127.0.0.1:9001");
    }

    #[test]
    fn mdns_then_seed_order_also_collapses() {
        let table = PeerTable::new();
        table.observe_discovered("node-b", "FBBB", "127.0.0.1:9001", 100);
        table.observe_addr("127.0.0.1:9001");
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn hello_folds_identity_into_a_seed_record() {
        let table = PeerTable::new();
        table.observe_addr("127.0.0.1:9001");
        let merged = table.hello("node-b", "FBBB", "127.0.0.1:9001", 200);
        assert_eq!(table.len(), 1, "{:?}", table.snapshot());
        assert_eq!(merged.node_id, "node-b");
        assert_eq!(merged.fingerprint, "FBBB");
        assert_eq!(merged.addr, "127.0.0.1:9001");
        assert_eq!(merged.last_hello, 200);
    }

    #[test]
    fn hello_without_an_addr_does_not_guess_a_seed_match() {
        let table = PeerTable::new();
        table.observe_addr("127.0.0.1:9001");
        // An addr-less hello has no key in common with a bare seed record, so
        // it must not silently claim the seed's address.
        table.hello("node-b", "FBBB", "", 200);
        assert_eq!(table.len(), 2, "{:?}", table.snapshot());
    }

    #[test]
    fn hello_refreshes_last_hello_and_keeps_one_record() {
        let table = PeerTable::new();
        table.observe_discovered("node-b", "FBBB", "127.0.0.1:9001", 100);
        let refreshed = table.hello("node-b", "FBBB", "", 300);
        assert_eq!(table.len(), 1);
        assert_eq!(refreshed.last_hello, 300);
        assert!(refreshed.healthy);
    }

    #[test]
    fn distinct_peers_stay_distinct() {
        let table = PeerTable::new();
        table.observe_addr("127.0.0.1:9001");
        table.observe_addr("127.0.0.1:9002");
        table.observe_discovered("node-c", "FCCC", "127.0.0.1:9003", 1);
        assert_eq!(table.len(), 3);
    }

    #[test]
    fn heartbeat_updates_stats_and_mark_unhealthy_flips_health() {
        let table = PeerTable::new();
        table.observe_discovered("node-b", "FBBB", "127.0.0.1:9001", 100);
        assert!(table.heartbeat("node-b", "FBBB", 40, 100, 200));
        let peers = table.snapshot();
        assert_eq!(peers[0].used_bytes, 40);
        assert_eq!(peers[0].total_bytes, 100);
        assert!(table.mark_unhealthy("node-b", "FBBB"));
        assert!(table.healthy_sorted().is_empty());
        assert!(!table.heartbeat("ghost", "NOPE", 0, 0, 0));
    }

    #[test]
    fn snapshot_is_sorted_by_node_id() {
        let table = PeerTable::new();
        table.observe_discovered("node-c", "FCCC", "127.0.0.1:9003", 1);
        table.observe_discovered("node-a", "FAAA", "127.0.0.1:9001", 1);
        table.observe_discovered("node-b", "FBBB", "127.0.0.1:9002", 1);
        let peers = table.snapshot();
        let ids: Vec<&str> = peers.iter().map(|p| p.node_id.as_str()).collect();
        assert_eq!(ids, vec!["node-a", "node-b", "node-c"]);
    }

    #[test]
    fn start_with_mdns_off_registers_only_seeds() {
        let cluster = ClusterConfig {
            enabled: true,
            mdns: false,
            seeds: vec![String::from("cache-a"), String::from("cache-b:9002")],
            ..ClusterConfig::default()
        };
        let identity = Identity::load_or_generate(
            &std::env::temp_dir().join(format!("cachette-cluster-{}", std::process::id())),
            None,
            None,
        )
        .expect("identity");
        let runtime = start(&cluster, &identity, "0.0.0.0:8080");
        let peers = runtime.peer_table().snapshot();
        assert_eq!(peers.len(), 2, "{peers:?}");
        assert_eq!(peers[0].addr, "cache-a:8080");
        assert_eq!(peers[1].addr, "cache-b:9002");
        assert!(peers.iter().all(|p| p.fingerprint.is_empty()));
    }

    #[test]
    fn start_with_mdns_on_never_crashes() {
        let cluster = ClusterConfig {
            enabled: true,
            mdns: true,
            seeds: vec![String::from("cache-a:9001")],
            ..ClusterConfig::default()
        };
        let identity = Identity::load_or_generate(
            &std::env::temp_dir().join(format!("cachette-cluster-mdns-{}", std::process::id())),
            None,
            None,
        )
        .expect("identity");
        let runtime = start(&cluster, &identity, "127.0.0.1:8080");
        // Seeds are present regardless of whether mDNS found anything.
        assert_eq!(runtime.peer_table().len(), 1);
    }
}
