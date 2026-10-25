//! Outbound heartbeat sender + peer health maintenance (plan task 29 / M15).
//!
//! Every `heartbeat_interval_seconds` this node POSTs
//! `/_internal/peers/heartbeat {node_id, used_bytes, total_bytes, draining, ts}`
//! to each
//! discovered peer's `addr` over mTLS: the client presents this node's
//! identity certificate, and the server certificate is accepted only when its
//! SPKI fingerprint passes [`PeerPins`] (seeded or TOFU) — the mirror image of
//! the inbound pin gate in [`crate::routes`]. The same tick keeps the node's
//! own peer-table record alive with live B3 capacity values (the own node is
//! always included in placement) and sweeps peers that stop heartbeating
//! after `[cluster] peer_timeout_seconds`.
//!
//! The HTTP exchange is a hand-rolled HTTP/1.1 POST over the TLS stream: no
//! HTTP-client dependency is allowed, and the payload is one small JSON body.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use rustls::ClientConfig as RustlsClientConfig;
use rustls::Error as RustlsError;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::MissedTickBehavior;
use tokio_rustls::TlsConnector;

use crate::auth;
use crate::cluster::PeerTable;
use crate::config::{MinFree, split_host_port};
use crate::storage::StorageBackend;
use crate::storage::eviction::Capacity;
use crate::tls::PeerPins;

/// Path of the heartbeat route on the receiving peer.
const HEARTBEAT_PATH: &str = "/_internal/peers/heartbeat";

/// Per-dial budget: one unreachable peer must never stall the tick (and with
/// it the timeout sweep) longer than this, well under the sample defaults of
/// a 5s interval and a 15s peer timeout.
const DIAL_BUDGET: Duration = Duration::from_secs(2);

/// Everything the periodic heartbeat task needs (plan task 29 wiring from
/// `main.rs::serve`). Grouped into one struct because the task spans the peer
/// table, the pin store, the node identity, live storage, and `[cluster]`
/// timing.
pub struct HeartbeatConfig {
    /// This node's identity (`state.node_id`): the Ed25519 fingerprint at
    /// serve time; doubles as the self record's `node_id`/`fingerprint` and
    /// as the `node_id` sent in outbound heartbeat bodies.
    pub node_id: String,
    /// This node's identity certificate PEM (mTLS client credential).
    pub cert_pem: String,
    /// This node's identity private-key PEM (mTLS client credential).
    pub key_pem: String,
    /// Dial target advertised for this node (`cluster.advertise_addr`, else
    /// the listen address) — the self record's `addr`.
    pub advertise_addr: String,
    /// Shared peer table: self record, sweep, and send targets.
    pub peer_table: Arc<PeerTable>,
    /// Pin store: outbound server-certificate trust (seeded + TOFU).
    pub pins: Arc<PeerPins>,
    /// Storage accounting for the self record's live `used_bytes`.
    pub storage: Arc<dyn StorageBackend>,
    /// Storage root: the B3 disk-total fallback when `max_size` is unset.
    pub storage_path: PathBuf,
    /// `[storage.fs] min_free` — part of the B3 capacity model.
    pub min_free: MinFree,
    /// `[cache] max_size`; 0 = unlimited (the disk total caps `total`).
    pub max_size: u64,
    /// `[cluster] heartbeat_interval_seconds` (clamped to >= 1s).
    pub interval: Duration,
    /// `[cluster] peer_timeout_seconds`.
    pub timeout: Duration,
    /// Graceful-drain flag (plan task 47): when true the outbound heartbeat
    /// advertises `draining` so peers stop selecting this node for NEW
    /// placements; the self record carries it too.
    pub draining: Arc<AtomicBool>,
}

/// Handle to the spawned heartbeat task (plan task 47). Wraps the task's
/// [`JoinHandle`](tokio::task::JoinHandle) plus the [`Notify`](tokio::sync::Notify)
/// used to request an immediate send — `announce()` lets shutdown push a
/// draining heartbeat to peers without waiting a full interval.
pub struct HeartbeatHandle {
    task: tokio::task::JoinHandle<()>,
    notify: Arc<tokio::sync::Notify>,
}

impl HeartbeatHandle {
    /// Ask the task to send one heartbeat immediately (called when draining
    /// starts so peers learn within one round trip rather than one interval).
    pub fn announce(&self) {
        self.notify.notify_one();
    }

    /// Stop the heartbeat task.
    pub fn abort(&self) {
        self.task.abort();
    }
}

/// Spawn the periodic heartbeat + health-sweep task (mirrors the task-34
/// sweep task: `tokio::spawn` + `interval`; the first tick runs immediately,
/// and self is registered synchronously before the task is even queued so the
/// table always contains a healthy own node). Returns a [`HeartbeatHandle`] so
/// `serve()` can announce the drain and abort it during shutdown.
pub fn spawn(config: HeartbeatConfig) -> HeartbeatHandle {
    let id = config.node_id.as_str();
    config
        .peer_table
        .hello(id, id, &config.advertise_addr, auth::now_secs() as u64);
    let notify = Arc::new(tokio::sync::Notify::new());
    let task = tokio::spawn(run(config, notify.clone()));
    HeartbeatHandle { task, notify }
}

/// The tick loop: refresh self with live B3 values, sweep peer timeouts, then
/// send a heartbeat to every other peer. A [`Notify`](tokio::sync::Notify)
/// announced via [`HeartbeatHandle::announce`] short-circuits the interval so a
/// draining node reaches peers immediately (plan task 47).
async fn run(config: HeartbeatConfig, notify: Arc<tokio::sync::Notify>) {
    let client = match client_config(&config) {
        Ok(client) => Some(client),
        Err(err) => {
            // Practically unreachable: `serve()` already built the server
            // TLS config from the same PEMs. Keep sweeping/self-refreshing.
            tracing::warn!(error = %err, "heartbeat: outbound sender disabled (identity unusable)");
            None
        }
    };
    let mut ticker = tokio::time::interval(config.interval.max(Duration::from_secs(1)));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let id = config.node_id.as_str();
    loop {
        // First iteration fires immediately via the interval's first tick; a
        // drain `announce()` wakes the loop ahead of the next tick.
        tokio::select! {
            _ = ticker.tick() => {}
            () = notify.notified() => {}
        }
        let now = auth::now_secs();
        let stats = live_capacity(&config).await;
        if let Some((used, total)) = stats {
            config.peer_table.heartbeat(
                id,
                id,
                used,
                total,
                now as u64,
                config.draining.load(Ordering::Relaxed),
            );
        }
        let marked = config
            .peer_table
            .sweep_timeouts(now as u64, config.timeout.as_secs());
        if marked > 0 {
            tracing::info!(
                marked,
                timeout_s = config.timeout.as_secs(),
                "peer heartbeat timed out; marked unhealthy"
            );
        }
        if let (Some(client), Some((used, total))) = (&client, stats) {
            send_all(client, &config, now, used, total).await;
        }
    }
}

/// This node's live B3 numbers: `used` from storage accounting, `total` from
/// the B3 model (`[cache] max_size`, else the storage disk total). `None`
/// (with a warning) when either query fails — the tick then skips the self
/// refresh and the send rather than publishing zeros.
async fn live_capacity(config: &HeartbeatConfig) -> Option<(u64, u64)> {
    let used = match config.storage.used_bytes().await {
        Ok(used) => used,
        Err(err) => {
            tracing::warn!(error = %err, "heartbeat: used_bytes unavailable");
            return None;
        }
    };
    match Capacity::from_disk(config.min_free, config.max_size, &config.storage_path, used) {
        Ok(capacity) => Some((used, capacity.total)),
        Err(err) => {
            tracing::warn!(error = %err, "heartbeat: storage capacity unavailable");
            None
        }
    }
}

/// POST one heartbeat to every peer with a dial address, skipping this node's
/// own record.
async fn send_all(
    client: &Arc<RustlsClientConfig>,
    config: &HeartbeatConfig,
    now: i64,
    used: u64,
    total: u64,
) {
    let payload = serde_json::json!({
        "node_id": config.node_id,
        "used_bytes": used,
        "total_bytes": total,
        "draining": config.draining.load(Ordering::Relaxed),
        "ts": now,
    });
    let body = serde_json::to_string(&payload).expect("heartbeat JSON is a fixed shape");
    for peer in config.peer_table.snapshot() {
        if peer.addr.is_empty()
            || peer.fingerprint == config.node_id
            || peer.node_id == config.node_id
        {
            continue;
        }
        let attempt = tokio::time::timeout(DIAL_BUDGET, exchange(client, &peer.addr, &body)).await;
        match attempt {
            Ok(Ok(200)) => {
                tracing::debug!(node = %peer.node_id, addr = %peer.addr, "heartbeat sent");
            }
            Ok(Ok(status)) => {
                tracing::debug!(node = %peer.node_id, addr = %peer.addr, status, "heartbeat refused");
            }
            Ok(Err(err)) => {
                tracing::debug!(node = %peer.node_id, addr = %peer.addr, %err, "heartbeat failed");
            }
            Err(_) => {
                tracing::debug!(node = %peer.node_id, addr = %peer.addr, "heartbeat dial timed out");
            }
        }
    }
}

/// Hand-rolled HTTP/1.1 POST over a fresh TLS connection (`Connection: close`
/// + read-to-end, like the TLS integration tests); returns the status code.
async fn exchange(
    client: &Arc<RustlsClientConfig>,
    addr: &str,
    body: &str,
) -> std::io::Result<u16> {
    let (host, port) = split_host_port(addr).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("bad peer addr: {addr}"),
        )
    })?;
    let host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    let server_name = ServerName::try_from(host.to_owned()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("bad peer host: {host}"),
        )
    })?;
    let tcp = TcpStream::connect((host, port)).await?;
    let mut stream = TlsConnector::from(client.clone())
        .connect(server_name, tcp)
        .await
        .map_err(|err| {
            std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                format!("TLS handshake failed: {err}"),
            )
        })?;
    let request = format!(
        "POST {HEARTBEAT_PATH} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).await?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await?;
    let text = String::from_utf8_lossy(&raw);
    text.split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "no HTTP status in heartbeat response",
            )
        })
}

/// Assemble the outbound mTLS client: this node's identity certificate as the
/// client credential, [`PinnedServerCert`](crate::cluster::tls_client) as the
/// trust decision. Delegates to the shared peer-client builder (task 31 reuses
/// the exact same config for the relay's outbound calls).
fn client_config(config: &HeartbeatConfig) -> Result<Arc<RustlsClientConfig>, RustlsError> {
    crate::cluster::tls_client::client_config(
        &config.cert_pem,
        &config.key_pem,
        config.pins.clone(),
    )
}
