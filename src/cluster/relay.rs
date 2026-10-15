//! v1 relay transport: stream a v1 artifactcache upload to the placement owner
//! (plan task 31 / M7/M8/M10).
//!
//! With `[cluster] enabled`, the entry node A no longer stores the blob
//! locally. On reserve it runs [`Placement`] over its healthy peers (self
//! included) and forwards the reservation, every PATCH chunk, and the commit
//! to the winning owner B over mTLS (`POST /_internal/peers/reserve`,
//! `PUT /_internal/peers/upload/{cacheId}?offset=`,
//! `POST /_internal/peers/commit/{cacheId}` — see
//! [`crate::routes::peer_relay`]). A keeps only an in-memory relay session: the
//! blob bytes never touch A.
//!
//! Backpressure + fallback contract (the plan's M15 throttle):
//!
//! * The owner B re-checks its OWN live admission at accept time and answers
//!   **503 `{"error":"insufficient capacity"}`** (never 429 — M1) when it is
//!   below its free-space floor. A then tries the NEXT healthy peer from its
//!   placement order in the SAME request; only when every candidate rejects
//!   does A surface 503 to the client.
//! * A transport failure (unreachable owner, TLS error, timeout, 5xx) fails
//!   the relay with **502** (`ApiError::BadGateway`) and marks the session
//!   failed; B's abandoned reservation is reclaimed by its TTL reaper (M4).
//! * `commit` is idempotent: a re-forward of an already-committed session
//!   short-circuits, and B tolerates a repeat of a commit whose reservation it
//!   already published (size-matched finalized entry).
//!
//! The HTTP exchange is a hand-rolled HTTP/1.1 request over a fresh TLS
//! connection — no HTTP-client dependency is allowed. It reuses the shared
//! pinned mTLS client ([`crate::cluster::tls_client`]) the heartbeat already
//! uses, so peer trust is decided identically on both paths.

use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustls::ClientConfig as RustlsClientConfig;
use rustls::Error as RustlsError;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::cluster::PeerRecord;
use crate::cluster::PeerTable;
use crate::cluster::placement::Placement;
use crate::cluster::tls_client;
use crate::config::{MinFree, split_host_port};
use crate::tls::PeerPins;

/// Peer endpoint that accepts a forwarded reservation.
const RESERVE_PATH: &str = "/_internal/peers/reserve";
/// Peer endpoint prefix that accepts one forwarded PATCH chunk.
const UPLOAD_PATH_PREFIX: &str = "/_internal/peers/upload/";
/// Peer endpoint prefix that accepts a forwarded commit.
const COMMIT_PATH_PREFIX: &str = "/_internal/peers/commit/";

/// Budget for a control exchange (reserve/commit): a small JSON round trip.
const CONTROL_TIMEOUT: Duration = Duration::from_secs(15);
/// Budget for one forwarded chunk. Chunks are bounded by the PATCH route's
/// `MAX_CHUNK_BYTES`, so this is generous even on a slow link.
const UPLOAD_TIMEOUT: Duration = Duration::from_secs(300);

/// Everything [`ClusterRelay::new`] needs, grouped the way [`crate::cluster::
/// heartbeat::HeartbeatConfig`] groups the heartbeat task's inputs.
pub struct RelayConfig {
    /// This node's identity fingerprint (`state.node_id`); used to recognise
    /// the "owner is self" placement outcome.
    pub node_id: String,
    /// This node's identity certificate PEM (mTLS client credential).
    pub cert_pem: String,
    /// This node's identity private-key PEM (mTLS client credential).
    pub key_pem: String,
    /// Pin store: outbound server-certificate trust (seeded + TOFU).
    pub pins: Arc<PeerPins>,
    /// Shared placement handle (tiebreak state survives across requests).
    pub placement: Arc<Placement>,
    /// Shared peer table: the candidate owner set.
    pub peer_table: Arc<PeerTable>,
    /// `[storage.fs] min_free` — part of A's placement capacity model.
    pub min_free: MinFree,
    /// `[cache] max_size`; 0 = unlimited.
    pub max_size: u64,
}

/// Lifecycle of one relayed reservation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RelayState {
    /// Forwarded to the owner; chunks may still be streamed.
    Reserved,
    /// Owner confirmed the commit; further commits are idempotent 204s.
    Committed,
    /// A transport/owner failure poisoned the relay; later requests are 502.
    Failed,
}

/// One in-memory A-side relay session: the client-facing `cacheId` maps to the
/// owner's endpoint and cacheId. No blob bytes are held here.
#[derive(Clone, Debug)]
struct RelaySession {
    owner_node_id: String,
    owner_addr: String,
    owner_cache_id: String,
    key: String,
    version: String,
    state: RelayState,
}

/// A committed owner location, recorded for the task-32 find fan-out.
#[derive(Clone, Debug)]
pub struct OwnerRecord {
    /// Owner node identity (`node_id` at commit time).
    pub node_id: String,
    /// Owner dial address (`ip:port`).
    pub addr: String,
    /// Owner-side cacheId.
    pub cache_id: String,
    /// Normalized artifact key the blob is published under on the owner.
    pub key: String,
    /// Protocol version marker.
    pub version: String,
    /// Verified blob size.
    pub size: u64,
}

/// A-side outcome of a relaying reserve.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelayReserve {
    /// The placement winner is this node: the caller runs the local reserve
    /// path (self-owned entry), exactly as single-node mode does.
    Local,
    /// A remote owner accepted; the client keeps the `cacheId` it was issued
    /// and later PATCH/commit calls are forwarded to the owner.
    Relayed,
    /// The owner already holds `(key, version)`: surface the GitHub 409 body.
    Duplicate,
    /// Every candidate rejected on capacity: surface 503.
    NoCapacity,
    /// Every candidate errored or was unreachable: surface 502.
    Unreachable,
}

/// A-side outcome of forwarding one PATCH chunk.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RelayUpload {
    /// No relay session for this `cacheId`: the caller uses the local path.
    NoSession,
    /// Owner accepted the chunk.
    Written,
    /// Owner no longer knows the reservation (unknown/expired).
    NotFound,
    /// Owner reports the entry is already complete / overlapping range.
    Conflict(String),
    /// Owner rejected the chunk body (bad range/length).
    BadRequest(String),
    /// Owner unreachable or errored; the session is now failed.
    Unreachable,
}

/// A-side outcome of forwarding a commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RelayCommit {
    /// No relay session for this `cacheId`: the caller uses the local path.
    NoSession,
    /// Owner verified + published the entry (already committed counts).
    Committed,
    /// Owner no longer knows the reservation.
    NotFound,
    /// Owner rejected the declared size.
    BadRequest(String),
    /// Owner reports an already-complete entry conflict.
    Conflict(String),
    /// Owner unreachable or errored; the session is now failed.
    Unreachable,
}

/// Process-lifetime v1 relay transport (plan task 31). Shared via
/// `AppState::relay`; built only when `[cluster] enabled`.
pub struct ClusterRelay {
    node_id: String,
    client: Arc<RustlsClientConfig>,
    placement: Arc<Placement>,
    peer_table: Arc<PeerTable>,
    min_free: MinFree,
    max_size: u64,
    sessions: Mutex<HashMap<String, RelaySession>>,
    owners: Mutex<HashMap<String, OwnerRecord>>,
}

impl ClusterRelay {
    /// Build the relay, assembling the outbound mTLS client from this node's
    /// identity + pin store. Fails only when the identity PEMs are unusable
    /// (the same condition that would disable the heartbeat sender).
    pub fn new(config: RelayConfig) -> Result<Self, RustlsError> {
        let client = tls_client::client_config(&config.cert_pem, &config.key_pem, config.pins)?;
        Ok(Self {
            node_id: config.node_id,
            client,
            placement: config.placement,
            peer_table: config.peer_table,
            min_free: config.min_free,
            max_size: config.max_size,
            sessions: Mutex::new(HashMap::new()),
            owners: Mutex::new(HashMap::new()),
        })
    }

    /// The recorded owner for an artifact key once a relayed commit completed
    /// (consumed by the task-32 find fan-out).
    #[must_use]
    pub fn owner_for(&self, key: &str) -> Option<OwnerRecord> {
        lock(&self.owners).get(key).cloned()
    }

    /// Reserve `(key, version)` on the least-loaded healthy owner.
    ///
    /// `client_cache_id` is the numeric id already issued to the client; on a
    /// remote accept it becomes the session key. See [`RelayReserve`] for the
    /// caller's contract.
    pub async fn reserve(&self, client_cache_id: u64, key: &str, version: &str) -> RelayReserve {
        let candidates = self.rank_candidates();
        if candidates.is_empty() {
            // No peers at all (a lone cluster-enabled node with no heartbeat
            // yet): behave like single-node and serve locally.
            return RelayReserve::Local;
        }
        let mut saw_reject = false;
        let mut saw_unreachable = false;
        for peer in candidates {
            if self.is_self(&peer) {
                return RelayReserve::Local;
            }
            if peer.addr.is_empty() {
                saw_unreachable = true;
                continue;
            }
            match self.remote_reserve(&peer, key, version).await {
                Ok(RemoteReserve::Accepted { cache_id }) => {
                    let session = RelaySession {
                        owner_node_id: peer.node_id.clone(),
                        owner_addr: peer.addr.clone(),
                        owner_cache_id: cache_id,
                        key: key.to_owned(),
                        version: version.to_owned(),
                        state: RelayState::Reserved,
                    };
                    lock(&self.sessions).insert(client_cache_id.to_string(), session);
                    tracing::debug!(
                        owner = %peer.node_id,
                        addr = %peer.addr,
                        client_cache_id,
                        "v1 relay: reserved on owner"
                    );
                    return RelayReserve::Relayed;
                }
                Ok(RemoteReserve::Duplicate) => return RelayReserve::Duplicate,
                Ok(RemoteReserve::NoCapacity) => {
                    saw_reject = true;
                    tracing::debug!(owner = %peer.node_id, "v1 relay: owner refused (capacity)");
                }
                Err(err) => {
                    saw_unreachable = true;
                    tracing::warn!(owner = %peer.node_id, addr = %peer.addr, %err,
                        "v1 relay: owner reserve failed");
                }
            }
        }
        if saw_unreachable {
            RelayReserve::Unreachable
        } else if saw_reject {
            RelayReserve::NoCapacity
        } else {
            // Defensive: only possible if a candidate vanished mid-iteration.
            RelayReserve::Unreachable
        }
    }

    /// Forward one chunk of `client_cache_id` to its owner.
    pub async fn upload(&self, client_cache_id: &str, offset: u64, bytes: &[u8]) -> RelayUpload {
        let Some((addr, owner_cache_id, state)) = self.session_target(client_cache_id) else {
            return RelayUpload::NoSession;
        };
        match state {
            RelayState::Committed => {
                return RelayUpload::Conflict(String::from("entry is already complete"));
            }
            RelayState::Failed => return RelayUpload::Unreachable,
            RelayState::Reserved => {}
        }
        let path = format!("{UPLOAD_PATH_PREFIX}{owner_cache_id}?offset={offset}");
        match self
            .exchange(
                &addr,
                "PUT",
                &path,
                "application/octet-stream",
                bytes,
                UPLOAD_TIMEOUT,
            )
            .await
        {
            Ok(response) => match response.status {
                204 => RelayUpload::Written,
                404 => RelayUpload::NotFound,
                409 => RelayUpload::Conflict(String::from("entry is already complete")),
                400 => RelayUpload::BadRequest(String::from("owner rejected the chunk")),
                status => {
                    tracing::warn!(status, owner = %addr, "v1 relay: owner upload error");
                    self.mark_failed(client_cache_id);
                    RelayUpload::Unreachable
                }
            },
            Err(err) => {
                tracing::warn!(owner = %addr, %err, "v1 relay: owner unreachable during chunk");
                self.mark_failed(client_cache_id);
                RelayUpload::Unreachable
            }
        }
    }

    /// Forward the commit of `client_cache_id` to its owner (idempotent).
    pub async fn commit(&self, client_cache_id: &str, size: u64) -> RelayCommit {
        let Some(session) = self.session(client_cache_id) else {
            return RelayCommit::NoSession;
        };
        match session.state {
            RelayState::Committed => return RelayCommit::Committed,
            RelayState::Failed => return RelayCommit::Unreachable,
            RelayState::Reserved => {}
        }
        let path = format!("{COMMIT_PATH_PREFIX}{}", session.owner_cache_id);
        let body = serde_json::json!({ "size": size, "key": session.key });
        let body = serde_json::to_vec(&body).expect("commit JSON is a fixed shape");
        match self
            .exchange(
                &session.owner_addr,
                "POST",
                &path,
                "application/json",
                &body,
                CONTROL_TIMEOUT,
            )
            .await
        {
            Ok(response) => match response.status {
                204 => {
                    self.mark_committed(client_cache_id, size);
                    RelayCommit::Committed
                }
                404 => RelayCommit::NotFound,
                400 => RelayCommit::BadRequest(String::from("declared size rejected by owner")),
                409 => RelayCommit::Conflict(String::from("entry is already complete")),
                status => {
                    tracing::warn!(status, owner = %session.owner_addr,
                        "v1 relay: owner commit error");
                    self.mark_failed(client_cache_id);
                    RelayCommit::Unreachable
                }
            },
            Err(err) => {
                tracing::warn!(owner = %session.owner_addr, %err,
                    "v1 relay: owner unreachable during commit");
                self.mark_failed(client_cache_id);
                RelayCommit::Unreachable
            }
        }
    }

    /// Placement preference order over the healthy peers: repeatedly take the
    /// least-loaded admitted peer and remove it, so a capacity refusal can be
    /// retried against the next-best owner without re-running placement.
    fn rank_candidates(&self) -> Vec<PeerRecord> {
        let mut remaining = self.peer_table.healthy_sorted();
        let mut ranked = Vec::new();
        while let Some(chosen) =
            self.placement
                .place(&remaining, None, self.min_free, self.max_size)
        {
            remaining.retain(|peer| !same_peer(peer, &chosen));
            ranked.push(chosen);
        }
        ranked
    }

    fn is_self(&self, peer: &PeerRecord) -> bool {
        peer.node_id == self.node_id
            || (!peer.fingerprint.is_empty() && peer.fingerprint == self.node_id)
    }

    fn session(&self, client_cache_id: &str) -> Option<RelaySession> {
        lock(&self.sessions).get(client_cache_id).cloned()
    }

    fn session_target(&self, client_cache_id: &str) -> Option<(String, String, RelayState)> {
        let session = self.session(client_cache_id)?;
        Some((session.owner_addr, session.owner_cache_id, session.state))
    }

    fn mark_failed(&self, client_cache_id: &str) {
        if let Some(session) = lock(&self.sessions).get_mut(client_cache_id) {
            session.state = RelayState::Failed;
        }
    }

    fn mark_committed(&self, client_cache_id: &str, size: u64) {
        let mut sessions = lock(&self.sessions);
        if let Some(session) = sessions.get_mut(client_cache_id) {
            session.state = RelayState::Committed;
            let record = OwnerRecord {
                node_id: session.owner_node_id.clone(),
                addr: session.owner_addr.clone(),
                cache_id: session.owner_cache_id.clone(),
                key: session.key.clone(),
                version: session.version.clone(),
                size,
            };
            lock(&self.owners).insert(record.key.clone(), record);
        }
    }

    /// `POST /_internal/peers/reserve` on `peer` and map the wire response.
    async fn remote_reserve(
        &self,
        peer: &PeerRecord,
        key: &str,
        version: &str,
    ) -> io::Result<RemoteReserve> {
        let body = serde_json::json!({ "key": key, "version": version });
        let body = serde_json::to_vec(&body).expect("reserve JSON is a fixed shape");
        let response = self
            .exchange(
                &peer.addr,
                "POST",
                RESERVE_PATH,
                "application/json",
                &body,
                CONTROL_TIMEOUT,
            )
            .await?;
        match response.status {
            200 => {
                let cache_id = serde_json::from_slice::<serde_json::Value>(&response.body)
                    .ok()
                    .and_then(|value| value.get("cacheId").and_then(serde_json::Value::as_u64))
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "owner reserve response missing cacheId",
                        )
                    })?;
                Ok(RemoteReserve::Accepted {
                    cache_id: cache_id.to_string(),
                })
            }
            409 => Ok(RemoteReserve::Duplicate),
            503 => Ok(RemoteReserve::NoCapacity),
            status => Err(io::Error::other(format!(
                "owner reserve returned status {status}"
            ))),
        }
    }

    /// Hand-rolled HTTP/1.1 request over a fresh TLS connection
    /// (`Connection: close` + read-to-end, like the heartbeat sender).
    async fn exchange(
        &self,
        addr: &str,
        method: &str,
        path: &str,
        content_type: &str,
        body: &[u8],
        timeout: Duration,
    ) -> io::Result<PeerResponse> {
        let client = self.client.clone();
        let request = async move {
            let (host, port) = split_host_port(addr).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("bad peer addr: {addr}"),
                )
            })?;
            let host = host
                .strip_prefix('[')
                .and_then(|host| host.strip_suffix(']'))
                .unwrap_or(host);
            let server_name =
                rustls::pki_types::ServerName::try_from(host.to_owned()).map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("bad peer host: {host}"),
                    )
                })?;
            let tcp = TcpStream::connect((host, port)).await?;
            let mut stream = TlsConnector::from(client)
                .connect(server_name, tcp)
                .await
                .map_err(|err| {
                    io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        format!("TLS handshake failed: {err}"),
                    )
                })?;
            let head = format!(
                "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\
                 Content-Type: {content_type}\r\nContent-Length: {}\r\n\r\n",
                body.len()
            );
            stream.write_all(head.as_bytes()).await?;
            stream.write_all(body).await?;
            let mut raw = Vec::new();
            stream.read_to_end(&mut raw).await?;
            parse_response(&raw)
        };
        match tokio::time::timeout(timeout, request).await {
            Ok(result) => result,
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "peer exchange timed out",
            )),
        }
    }
}

/// Owner reply to a forwarded reserve.
enum RemoteReserve {
    Accepted { cache_id: String },
    Duplicate,
    NoCapacity,
}

/// Parsed peer HTTP response (status line + body bytes).
struct PeerResponse {
    status: u16,
    body: Vec<u8>,
}

/// Parse a raw HTTP/1.1 response into its status code and body. The peer sets
/// `Content-Length` (JSON) or sends an empty body, so a plain head/body split
/// is sufficient.
fn parse_response(raw: &[u8]) -> io::Result<PeerResponse> {
    let (head, body) = split_head_body(raw);
    let head = String::from_utf8_lossy(head);
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no HTTP status in response"))?;
    Ok(PeerResponse {
        status,
        body: body.to_vec(),
    })
}

/// Split a raw response at the header/body separator (`\r\n\r\n`).
fn split_head_body(raw: &[u8]) -> (&[u8], &[u8]) {
    let mut index = 0;
    while index + 4 <= raw.len() {
        if &raw[index..index + 4] == b"\r\n\r\n" {
            return (&raw[..index], &raw[index + 4..]);
        }
        index += 1;
    }
    (raw, &[])
}

/// Whether two peer records denote the same node (identity + dial address).
fn same_peer(a: &PeerRecord, b: &PeerRecord) -> bool {
    a.node_id == b.node_id && a.addr == b.addr
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_response_reads_status_and_body() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 12\r\n\r\n{\"a\":\"b\"}xx";
        let parsed = parse_response(raw).expect("parses");
        assert_eq!(parsed.status, 200);
        assert_eq!(parsed.body, b"{\"a\":\"b\"}xx");
    }

    #[test]
    fn parse_response_handles_a_bodyless_status() {
        let raw = b"HTTP/1.1 204 No Content\r\n\r\n";
        let parsed = parse_response(raw).expect("parses");
        assert_eq!(parsed.status, 204);
        assert!(parsed.body.is_empty());
    }

    #[test]
    fn split_head_body_without_separator_returns_no_body() {
        let raw = b"HTTP/1.1 200 OK";
        let (head, body) = split_head_body(raw);
        assert_eq!(head, raw);
        assert!(body.is_empty());
    }

    #[test]
    fn same_peer_compares_identity_and_addr() {
        let a = peer("node-b", "127.0.0.1:9001");
        let b = peer("node-b", "127.0.0.1:9002");
        assert!(same_peer(&a, &a.clone()));
        assert!(!same_peer(&a, &b));
    }

    fn peer(node_id: &str, addr: &str) -> PeerRecord {
        PeerRecord {
            node_id: node_id.to_owned(),
            fingerprint: format!("FP-{node_id}"),
            addr: addr.to_owned(),
            used_bytes: 0,
            total_bytes: 0,
            healthy: true,
            last_hello: 1,
        }
    }
}
