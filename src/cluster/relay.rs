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
//! Plan task 32 adds the **find fan-out** and the **v2 owner routing** on top
//! of the same transport:
//!
//! * [`ClusterRelay::find`] queries every healthy peer's
//!   `GET /_internal/peers/find?key=&version=` concurrently, under a hard
//!   [`FANOUT_TIMEOUT`] budget, and returns the owners that hold a match. A
//!   peer that is dead (unreachable, TLS error, timeout) simply contributes no
//!   hit — the caller treats it as a plain miss (never a hang).
//! * [`ClusterRelay::v2_reserve`] stages a v2 reservation on the chosen owner B
//!   so the runner's direct upload to B succeeds; the A-minted capability URLs
//!   then point at B's runner-visible base (its configured `external_url`, else
//!   its `advertise_addr`). A never proxies the transfer.
//! * [`ClusterRelay::v2_finalize`] / [`ClusterRelay::v2_supersede`] broadcast
//!   the corresponding v2 call to the healthy owners.
//!
//! **RAM-light (hard requirement):** the relay keeps no authoritative
//! per-artifact state. Owner resolution is the durable peer fan-out above; the
//! process-local [`ClusterRelay::owners`] / [`ClusterRelay::sessions`] maps are
//! only routing hints and are held in fixed-capacity
//! [`BoundedMap`]s (O(1) amortised insertion-order eviction) so they can never
//! grow without bound. A relayed session is also dropped once it is older than
//! the reservation TTL (the owner's reaper has reclaimed it by then).
//!
//! The HTTP exchange is a hand-rolled HTTP/1.1 request over a fresh TLS
//! connection — no HTTP-client dependency is allowed. It reuses the shared
//! pinned mTLS client ([`crate::cluster::tls_client`]) the heartbeat already
//! uses, so peer trust is decided identically on both paths.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rustls::ClientConfig as RustlsClientConfig;
use rustls::Error as RustlsError;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::JoinSet;
use tokio_rustls::TlsConnector;

use crate::cluster::PeerRecord;
use crate::cluster::PeerTable;
use crate::cluster::placement::Placement;
use crate::cluster::tls_client;
use crate::config::{KeyCase, MinFree, split_host_port};
use crate::storage::normalize_key;
use crate::tls::PeerPins;

/// Peer endpoint that accepts a forwarded reservation.
const RESERVE_PATH: &str = "/_internal/peers/reserve";
/// Peer endpoint prefix that accepts one forwarded PATCH chunk.
const UPLOAD_PATH_PREFIX: &str = "/_internal/peers/upload/";
/// Peer endpoint prefix that accepts a forwarded commit.
const COMMIT_PATH_PREFIX: &str = "/_internal/peers/commit/";
/// Peer endpoint that answers an owner lookup for `(key, version)`.
const FIND_PATH: &str = "/_internal/peers/find";
/// Peer endpoint that stages a v2 reservation under the entry `cache_id` A
/// minted (so the runner's direct upload to the owner succeeds).
const V2_RESERVE_PATH: &str = "/_internal/peers/v2/reserve";
/// Peer endpoint that verifies + publishes a v2 entry the runner uploaded.
const V2_FINALIZE_PATH: &str = "/_internal/peers/v2/finalize";
/// Peer endpoint that discards a v2 entry.
const V2_SUPERSEDE_PATH: &str = "/_internal/peers/v2/supersede";

/// Budget for a control exchange (reserve/commit): a small JSON round trip.
const CONTROL_TIMEOUT: Duration = Duration::from_secs(15);
/// Budget for one forwarded chunk. Chunks are bounded by the PATCH route's
/// `MAX_CHUNK_BYTES`, so this is generous even on a slow link.
const UPLOAD_TIMEOUT: Duration = Duration::from_secs(300);
/// Hard ceiling on a **fan-out**: the whole find/finalize broadcast must return
/// inside this window, so a dead owner degrades to a miss instead of hanging the
/// runner request. Deliberately much smaller than [`CONTROL_TIMEOUT`].
const FANOUT_TIMEOUT: Duration = Duration::from_secs(1);

/// RAM-light bound on the process-local relay session map. It is only a routing
/// hint (the durable record is the owner B, which the find fan-out reaches), so
/// past this many concurrent relays the oldest is dropped — a client whose
/// session was evicted simply falls back to the owner's own reservation state.
const SESSION_CACHE_CAPACITY: usize = 4096;
/// RAM-light bound on the process-local owner-hint map (see [`BoundedMap`]).
const OWNER_CACHE_CAPACITY: usize = 4096;

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
    /// `[cache] reservation_ttl_seconds`: how long a relayed session is
    /// considered live before it is lazily evicted (the owner's reaper has
    /// reclaimed the reservation by then).
    pub reservation_ttl_seconds: u64,
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
    /// When the session was recorded; bounds its lifetime against
    /// `[cache] reservation_ttl_seconds` (RAM-light).
    created_at: Instant,
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

/// One peer's answer to a find fan-out (plan task 32): the owner that holds a
/// matching finalised entry, plus the runner-visible base A needs to mint its
/// capability URL.
#[derive(Clone, Debug)]
pub struct FindHit {
    /// Owner node identity.
    pub node_id: String,
    /// Owner dial address (`ip:port`).
    pub addr: String,
    /// Owner's configured `[server] external_url` (runner-reachable base), when
    /// the owner reported one.
    pub external_url: Option<String>,
    /// The artifact key the entry is published under on the owner — the id A
    /// puts in the download path.
    pub key: String,
    /// Verified blob size.
    pub size: u64,
    /// Unix seconds the entry became visible.
    pub created_at: u64,
}

/// A-side outcome of staging a v2 reservation on the owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum V2Reserve {
    /// The owner staged the reservation; carries the owner's runner-visible
    /// base URL (its `external_url`) when it reported one.
    Accepted {
        /// Owner's `[server] external_url`, when set.
        external_url: Option<String>,
    },
    /// The owner already holds the `(key, version)` entry.
    Duplicate,
    /// The owner rejected on a live capacity re-check.
    NoCapacity,
    /// The owner was unreachable or errored.
    Unreachable,
}

/// A-side outcome of a v2 finalize fan-out.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum V2Finalize {
    /// Some owner verified + published the entry.
    Ok,
    /// Some owner holds the entry but with a different declared size.
    SizeMismatch,
    /// No owner holds the entry.
    Missing,
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
    reservation_ttl_seconds: u64,
    sessions: Mutex<BoundedMap<RelaySession>>,
    owners: Mutex<BoundedMap<OwnerRecord>>,
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
            reservation_ttl_seconds: config.reservation_ttl_seconds,
            sessions: Mutex::new(BoundedMap::new(SESSION_CACHE_CAPACITY)),
            owners: Mutex::new(BoundedMap::new(OWNER_CACHE_CAPACITY)),
        })
    }

    /// The recorded owner for an artifact key once a relayed commit completed.
    ///
    /// **Not load-bearing:** this is a bounded, process-local hint. Owner
    /// resolution on the request path is the durable [`Self::find`] fan-out, so
    /// this map being empty (fresh process) or evicted never hides an entry.
    #[must_use]
    pub fn owner_for(&self, key: &str) -> Option<OwnerRecord> {
        lock(&self.owners).get(key).cloned()
    }

    /// Whether `peer` is this node (a [`Self::owner_candidate`] outcome).
    #[must_use]
    pub fn is_self_node(&self, peer: &PeerRecord) -> bool {
        self.is_self(peer)
    }

    /// The least-loaded healthy owner from the placement order (self included),
    /// or `None` when NO peer is healthy — the v2-create "no healthy owner"
    /// condition.
    #[must_use]
    pub fn owner_candidate(&self) -> Option<PeerRecord> {
        self.rank_candidates().into_iter().next()
    }

    /// Fan out a `(keys, version)` lookup to every healthy peer (excluding
    /// self), concurrently, under one [`FANOUT_TIMEOUT`] budget.
    ///
    /// Each peer answers with at most its single best match (it runs the same
    /// exact-then-prefix [`crate::storage::lookup`] A would); a dead peer
    /// contributes nothing. Callers pick the winner with [`best_hit`]. This is
    /// the durable owner-resolution path — it needs no process-local state.
    pub async fn find(&self, keys: &[String], version: &str) -> Vec<FindHit> {
        if keys.is_empty() {
            return Vec::new();
        }
        let query = find_query(keys, version);
        let responses = self.fanout("GET", &query, "", &[]).await;
        let mut hits = Vec::new();
        for (peer, outcome) in responses {
            match outcome {
                Ok(response) if response.status == 200 => {
                    match serde_json::from_slice::<FindBody>(&response.body) {
                        Ok(body) => hits.push(body.into_hit(&peer)),
                        Err(err) => tracing::warn!(
                            owner = %peer.node_id, %err,
                            "cluster find fan-out: malformed owner response"
                        ),
                    }
                }
                Ok(response) if response.status == 204 => {}
                Ok(response) => tracing::warn!(
                    owner = %peer.node_id, status = response.status,
                    "cluster find fan-out: unexpected owner status"
                ),
                Err(err) => tracing::warn!(
                    owner = %peer.node_id, addr = %peer.addr, %err,
                    "cluster find fan-out: owner query failed (treated as a miss)"
                ),
            }
        }
        hits
    }

    /// Stage a v2 reservation for `(key, version)` on `owner`, under the entry
    /// `cache_id` A already minted. The owner's reply carries the base URL A
    /// mints the capability URLs against.
    pub async fn v2_reserve(
        &self,
        owner: &PeerRecord,
        cache_id: &str,
        key: &str,
        version: &str,
    ) -> V2Reserve {
        let body = serde_json::json!({
            "cache_id": cache_id,
            "key": key,
            "version": version,
        });
        let body = serde_json::to_vec(&body).expect("v2 reserve JSON is a fixed shape");
        match self
            .exchange(
                &owner.addr,
                "POST",
                V2_RESERVE_PATH,
                "application/json",
                &body,
                CONTROL_TIMEOUT,
            )
            .await
        {
            Ok(response) => match response.status {
                200 => {
                    let external_url = serde_json::from_slice::<serde_json::Value>(&response.body)
                        .ok()
                        .and_then(|value| {
                            value
                                .get("externalUrl")
                                .and_then(serde_json::Value::as_str)
                                .filter(|url| !url.is_empty())
                                .map(str::to_owned)
                        });
                    V2Reserve::Accepted { external_url }
                }
                409 => V2Reserve::Duplicate,
                503 => V2Reserve::NoCapacity,
                status => {
                    tracing::warn!(
                        owner = %owner.node_id, addr = %owner.addr, status,
                        "v2 relay: owner reserve error"
                    );
                    V2Reserve::Unreachable
                }
            },
            Err(err) => {
                tracing::warn!(
                    owner = %owner.node_id, addr = %owner.addr, %err,
                    "v2 relay: owner unreachable during reserve"
                );
                V2Reserve::Unreachable
            }
        }
    }

    /// Broadcast a v2 finalize to the healthy peers and collapse the answers:
    /// any owner that published the entry wins (a dead owner cannot veto a live
    /// one). A single mismatched size is reported only when nothing published.
    pub async fn v2_finalize(
        &self,
        key: &str,
        size: Option<u64>,
        cache_id: Option<&str>,
    ) -> V2Finalize {
        let body = serde_json::json!({
            "key": key,
            "size_bytes": size,
            "cache_id": cache_id,
        });
        let body = serde_json::to_vec(&body).expect("v2 finalize JSON is a fixed shape");
        let responses = self
            .fanout("POST", V2_FINALIZE_PATH, "application/json", &body)
            .await;
        let mut saw_mismatch = false;
        for (peer, outcome) in responses {
            match outcome {
                Ok(response) if response.status == 200 => return V2Finalize::Ok,
                Ok(response) if response.status == 409 => saw_mismatch = true,
                Ok(response) if response.status == 404 => {}
                Ok(response) => tracing::warn!(
                    owner = %peer.node_id, status = response.status,
                    "v2 finalize fan-out: unexpected owner status"
                ),
                Err(err) => tracing::warn!(
                    owner = %peer.node_id, addr = %peer.addr, %err,
                    "v2 finalize fan-out: owner query failed"
                ),
            }
        }
        if saw_mismatch {
            V2Finalize::SizeMismatch
        } else {
            V2Finalize::Missing
        }
    }

    /// Broadcast a v2 supersede (delete) to the healthy peers. Best effort:
    /// deletion is idempotent, so a dead owner is only a warning.
    pub async fn v2_supersede(&self, key: &str) {
        let body = serde_json::json!({ "key": key });
        let body = serde_json::to_vec(&body).expect("v2 supersede JSON is a fixed shape");
        for (peer, outcome) in self
            .fanout("POST", V2_SUPERSEDE_PATH, "application/json", &body)
            .await
        {
            match outcome {
                Ok(response) if response.status == 200 => {}
                Ok(response) => tracing::warn!(
                    owner = %peer.node_id, status = response.status,
                    "v2 supersede fan-out: unexpected owner status"
                ),
                Err(err) => tracing::warn!(
                    owner = %peer.node_id, addr = %peer.addr, %err,
                    "v2 supersede fan-out: owner query failed"
                ),
            }
        }
    }

    /// Send one identical request to every healthy peer (excluding self)
    /// concurrently, returning the per-peer outcome within a single
    /// [`FANOUT_TIMEOUT`] window. Stragglers are aborted, so the caller can
    /// never block past the budget.
    async fn fanout(
        &self,
        method: &str,
        path: &str,
        content_type: &str,
        body: &[u8],
    ) -> Vec<(PeerRecord, io::Result<PeerResponse>)> {
        let peers = self.fanout_peers();
        if peers.is_empty() {
            return Vec::new();
        }
        let mut set = JoinSet::new();
        for peer in peers {
            let client = self.client.clone();
            let method = method.to_owned();
            let path = path.to_owned();
            let content_type = content_type.to_owned();
            let body = body.to_vec();
            set.spawn(async move {
                let addr = peer.addr.clone();
                let outcome = exchange_with(
                    client,
                    &addr,
                    &method,
                    &path,
                    &content_type,
                    &body,
                    FANOUT_TIMEOUT,
                )
                .await;
                (peer, outcome)
            });
        }
        let deadline = tokio::time::Instant::now() + FANOUT_TIMEOUT;
        let mut responses = Vec::new();
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                tracing::warn!("cluster fan-out: overall deadline exceeded");
                break;
            }
            match tokio::time::timeout(remaining, set.join_next()).await {
                Ok(Some(Ok(response))) => responses.push(response),
                Ok(Some(Err(join_err))) => {
                    tracing::warn!(error = %join_err, "cluster fan-out: peer task panicked");
                }
                Ok(None) => break,
                Err(_) => {
                    tracing::warn!("cluster fan-out: overall deadline exceeded");
                    break;
                }
            }
        }
        set.abort_all();
        responses
    }

    /// Healthy peers that can take a fan-out query (self and addr-less entries
    /// excluded).
    fn fanout_peers(&self) -> Vec<PeerRecord> {
        self.peer_table
            .healthy_sorted()
            .into_iter()
            .filter(|peer| !self.is_self(peer) && !peer.addr.is_empty())
            .collect()
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
                        created_at: Instant::now(),
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
        let session = lock(&self.sessions).get(client_cache_id).cloned()?;
        // RAM-light: a relayed session older than the reservation TTL is dead
        // (the owner's reaper has reclaimed its reservation), so drop it lazily
        // on access rather than scanning the whole map.
        let ttl = Duration::from_secs(self.reservation_ttl_seconds.max(1));
        if session.created_at.elapsed() >= ttl {
            lock(&self.sessions).remove(client_cache_id);
            return None;
        }
        Some(session)
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
        exchange_with(
            self.client.clone(),
            addr,
            method,
            path,
            content_type,
            body,
            timeout,
        )
        .await
    }
}

/// Hand-rolled HTTP/1.1 request over a fresh TLS connection
/// (`Connection: close` + read-to-end, like the heartbeat sender). Free
/// function form so fan-out tasks can own the client + request.
async fn exchange_with(
    client: Arc<RustlsClientConfig>,
    addr: &str,
    method: &str,
    path: &str,
    content_type: &str,
    body: &[u8],
    timeout: Duration,
) -> io::Result<PeerResponse> {
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
        // `Content-Type` is omitted when the caller passes an empty one (the
        // GET find fan-out sends no body), so no empty header value is emitted.
        let mut head = format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n");
        if !content_type.is_empty() {
            head.push_str(&format!("Content-Type: {content_type}\r\n"));
        }
        head.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
        stream.write_all(head.as_bytes()).await?;
        stream.write_all(body).await?;
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).await?;
        parse_response(raw)
    };
    match tokio::time::timeout(timeout, request).await {
        Ok(result) => result,
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "peer exchange timed out",
        )),
    }
}

/// Owner reply to a forwarded reserve.
enum RemoteReserve {
    Accepted { cache_id: String },
    Duplicate,
    NoCapacity,
}

/// Owner reply to a find fan-out query, as received on the wire (camelCase, to
/// match the sibling peer endpoints' `cacheId`).
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct FindBody {
    /// Artifact key the entry is published under (the download path id).
    key: String,
    /// Verified blob size.
    size: u64,
    /// Unix seconds the entry became visible.
    #[serde(default)]
    created_at: u64,
    /// Owner's runner-visible base URL, when configured.
    #[serde(default)]
    external_url: Option<String>,
}

impl FindBody {
    fn into_hit(self, peer: &PeerRecord) -> FindHit {
        FindHit {
            node_id: peer.node_id.clone(),
            addr: peer.addr.clone(),
            external_url: self.external_url,
            key: self.key,
            size: self.size,
            created_at: self.created_at,
        }
    }
}

/// Build the `key=<csv>&version=<v>` query for a find fan-out (percent-encoded,
/// so keys with reserved characters survive the round trip).
fn find_query(keys: &[String], version: &str) -> String {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    serializer.append_pair("key", &keys.join(","));
    serializer.append_pair("version", version);
    format!("{FIND_PATH}?{}", serializer.finish())
}

/// Pick the best peer hit for a `(keys, version)` query, matching the
/// exact-then-prefix preference of [`crate::storage::lookup`]: an exact match on
/// the first requested key wins, else the earliest requested key that is a
/// prefix; ties break on the newest `created_at`.
#[must_use]
pub fn best_hit<'a>(
    hits: &'a [FindHit],
    keys: &[String],
    key_case: KeyCase,
) -> Option<&'a FindHit> {
    let normalized: Vec<String> = keys
        .iter()
        .map(|key| normalize_key(key, key_case))
        .collect();
    let first = normalized.first()?;
    hits.iter()
        .filter(|hit| hit.key == *first)
        .max_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.key.cmp(&b.key))
        })
        .or_else(|| {
            normalized.iter().find_map(|key| {
                let mut candidates: Vec<&FindHit> = hits
                    .iter()
                    .filter(|hit| hit.key.starts_with(key.as_str()))
                    .collect();
                candidates.sort_by(|a, b| {
                    b.created_at
                        .cmp(&a.created_at)
                        .then_with(|| a.key.cmp(&b.key))
                });
                candidates.first().copied()
            })
        })
}

/// Fixed-capacity map with O(1) amortised insertion-order (FIFO) eviction.
///
/// RAM-light requirement: the relay's process-local session/owner maps must be
/// bounded, so they can never grow with the cluster's lifetime request volume.
/// A strict LRU is unnecessary — these are routing hints, not the source of
/// truth — so plain FIFO keeps the hot path to a single hash lookup with no
/// per-request scan.
struct BoundedMap<V> {
    capacity: usize,
    inner: HashMap<String, V>,
    order: VecDeque<String>,
}

impl<V> BoundedMap<V> {
    fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            inner: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    fn get(&self, key: &str) -> Option<&V> {
        self.inner.get(key)
    }

    fn get_mut(&mut self, key: &str) -> Option<&mut V> {
        self.inner.get_mut(key)
    }

    fn insert(&mut self, key: String, value: V) {
        if self.inner.insert(key.clone(), value).is_none() {
            self.order.push_back(key);
            // Evict oldest keys until back within capacity. Popped keys are
            // either live (removed here) or stale (already gone), so this is
            // O(1) amortised — no full-map scan.
            while self.inner.len() > self.capacity {
                match self.order.pop_front() {
                    Some(oldest) => {
                        self.inner.remove(&oldest);
                    }
                    None => break,
                }
            }
        }
    }

    fn remove(&mut self, key: &str) -> Option<V> {
        self.inner.remove(key)
    }
}

/// Parsed peer HTTP response (status line + body bytes).
struct PeerResponse {
    status: u16,
    body: Vec<u8>,
}

/// Parse a raw HTTP/1.1 response into its status code and body. The peer sets
/// `Content-Length` (JSON) or sends an empty body, so a plain head/body split
/// is sufficient. Takes ownership of `raw` and shifts the body down in place,
/// so the received buffer is reused instead of copied (plan task 45).
fn parse_response(mut raw: Vec<u8>) -> io::Result<PeerResponse> {
    let body_start = head_body_split(&raw);
    let status = String::from_utf8_lossy(&raw[..body_start])
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no HTTP status in response"))?;
    raw.drain(..body_start);
    Ok(PeerResponse { status, body: raw })
}

/// Index just past the header/body separator (`\r\n\r\n`), or `raw.len()` when
/// the response carries no separator.
fn head_body_split(raw: &[u8]) -> usize {
    let mut index = 0;
    while index + 4 <= raw.len() {
        if &raw[index..index + 4] == b"\r\n\r\n" {
            return index + 4;
        }
        index += 1;
    }
    raw.len()
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
        let parsed = parse_response(raw.to_vec()).expect("parses");
        assert_eq!(parsed.status, 200);
        assert_eq!(parsed.body, b"{\"a\":\"b\"}xx");
    }

    #[test]
    fn parse_response_handles_a_bodyless_status() {
        let raw = b"HTTP/1.1 204 No Content\r\n\r\n";
        let parsed = parse_response(raw.to_vec()).expect("parses");
        assert_eq!(parsed.status, 204);
        assert!(parsed.body.is_empty());
    }

    #[test]
    fn head_body_split_without_separator_returns_the_whole_buffer() {
        let raw = b"HTTP/1.1 200 OK";
        assert_eq!(head_body_split(raw), raw.len());
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
            draining: false,
            last_hello: 1,
        }
    }

    fn hit(key: &str, created_at: u64) -> FindHit {
        FindHit {
            node_id: format!("node-{key}"),
            addr: String::from("127.0.0.1:9001"),
            external_url: None,
            key: key.to_owned(),
            size: 42,
            created_at,
        }
    }

    // RAM-light requirement (plan task 32 addendum): the process-local owner /
    // session maps are bounded hints, not the source of truth. These tests lock
    // in the fixed-capacity FIFO bound so a regression to an insert-only map
    // fails loudly.
    #[test]
    fn bounded_map_never_exceeds_its_capacity() {
        let mut map: BoundedMap<u64> = BoundedMap::new(3);
        for index in 0..100_u64 {
            map.insert(format!("key-{index}"), index);
        }
        assert_eq!(map.inner.len(), 3, "capacity bound holds under churn");
        // The most recent inserts survive; the oldest were evicted.
        assert!(map.get("key-99").is_some());
        assert!(map.get("key-97").is_some());
        assert!(map.get("key-0").is_none());
    }

    #[test]
    fn bounded_map_evicts_in_insertion_order() {
        let mut map: BoundedMap<u64> = BoundedMap::new(2);
        map.insert(String::from("a"), 1);
        map.insert(String::from("b"), 2);
        map.insert(String::from("c"), 3);
        assert_eq!(map.inner.len(), 2);
        assert!(map.get("a").is_none(), "oldest key is evicted first");
        assert_eq!(map.get("b"), Some(&2));
        assert_eq!(map.get("c"), Some(&3));
    }

    #[test]
    fn bounded_map_reinsert_of_a_live_key_does_not_grow_order() {
        let mut map: BoundedMap<u64> = BoundedMap::new(2);
        map.insert(String::from("a"), 1);
        map.insert(String::from("a"), 2);
        map.insert(String::from("b"), 3);
        // Re-inserting "a" must not have queued a second order entry, so "b"
        // does not evict the still-live "a".
        assert_eq!(map.inner.len(), 2);
        assert_eq!(map.get("a"), Some(&2), "value is overwritten in place");
        assert_eq!(map.get("b"), Some(&3));
    }

    #[test]
    fn find_query_percent_encodes_keys_and_version() {
        let keys = vec![String::from("linux node"), String::from("a/b")];
        let query = find_query(&keys, "v1");
        assert!(query.starts_with(FIND_PATH), "route path: {query}");
        assert!(
            query.contains("key=linux+node%2Ca%2Fb") || query.contains("key=linux%20node%2Ca%2Fb"),
            "reserved characters survive the round trip: {query}"
        );
        assert!(
            query.ends_with("&version=v1"),
            "version is carried: {query}"
        );
    }

    #[test]
    fn best_hit_prefers_an_exact_first_key_match() {
        let keys = vec![String::from("exact"), String::from("fallback")];
        let hits = vec![hit("fallback-1", 100), hit("exact", 5)];
        let best = best_hit(&hits, &keys, KeyCase::Lower).expect("a hit");
        assert_eq!(best.key, "exact", "exact match beats a prefix fallback");
    }

    #[test]
    fn best_hit_falls_back_to_a_prefix_match() {
        let keys = vec![String::from("base"), String::from("other")];
        let hits = vec![hit("base-suffix", 7)];
        let best = best_hit(&hits, &keys, KeyCase::Lower).expect("a prefix hit");
        assert_eq!(best.key, "base-suffix");
    }

    #[test]
    fn best_hit_returns_none_for_an_empty_query_or_no_match() {
        let keys = vec![String::from("missing")];
        assert!(best_hit(&[], &keys, KeyCase::Lower).is_none());
        assert!(best_hit(&[hit("unrelated", 1)], &keys, KeyCase::Lower).is_none());
        assert!(best_hit(&[hit("anything", 1)], &[], KeyCase::Lower).is_none());
    }
}
