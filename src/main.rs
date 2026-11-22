use std::collections::HashSet;
use std::error::Error;
use std::sync::Arc;
use std::time::Duration;

use cachette::auth;
use cachette::auth::{AuthPolicy, TokenStore};
use cachette::cli::Cli;
use cachette::cluster::heartbeat;
use cachette::cluster::relay::{ClusterRelay, RelayConfig};
use cachette::config::{self, Config};
use cachette::identity::Identity;
use cachette::logging::{self};
use cachette::routes;
use cachette::state::{AppState, CacheLimits};
use cachette::storage::StorageBackend;
use cachette::storage::eviction::{
    Capacity, DEFAULT_BORROW_TTL, EvictionService, LeaseSet, Reaper,
};
use cachette::storage::fs::{BackfillStep, FsStorage};
use cachette::tls::{self, PeerPins};
use clap::Parser;
use tower_http::trace::TraceLayer;

/// Backfill idle poll (docs/cdc.md, Migration): once the walker's step
/// reports `Exhausted` it re-checks for newly-`whole` entries this often
/// instead of pacing at `backfill_delay_ms` (one cheap `COUNT` per idle
/// poll, not per conversion).
const BACKFILL_IDLE: Duration = Duration::from_secs(30);

/// Quota/floor eviction cadence (v1.2 workstream F, `docs/shared-cache.md`
/// §5). Eviction never runs on the request path (B3); this is how often the
/// background loop enforces the per-namespace limits and the global floor.
const EVICTION_INTERVAL: Duration = Duration::from_secs(60);

fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();
    let config = match config::load(cli.config.clone()) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("cachette: {err}");
            std::process::exit(2);
        }
    };
    if cli.print_config {
        match config::render_masked(&config) {
            Ok(rendered) => {
                println!("{rendered}");
                std::process::exit(0);
            }
            Err(err) => {
                eprintln!("cachette: {err}");
                std::process::exit(2);
            }
        }
    }
    if let Some(command) = cli.command.as_ref() {
        match cachette::ops::run(command, &config) {
            Ok(code) => std::process::exit(code),
            Err(err) => {
                eprintln!("cachette: {err}");
                std::process::exit(2);
            }
        }
    }
    if let Err(err) = config.require_auth_secret() {
        eprintln!("cachette: {err}");
        std::process::exit(2);
    }
    // `[log] level` becomes the default tracing directive; an explicitly set
    // RUST_LOG still wins (logging::init parses it with from_env_lossy). The
    // level is passed directly (plan task 49) so a SIGHUP reload can swap it
    // through the installed reload handle without touching the environment.
    logging::init(
        config.log.format.into(),
        config.log.file.clone(),
        config.log.level,
    );
    tracing::debug!(config_path = ?cli.config, "command line parsed");
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(serve(config, cli))?;
    Ok(())
}

async fn serve(config: Config, cli: Cli) -> Result<(), Box<dyn Error>> {
    let mut state = AppState::new();
    state.config_path = cli.config;
    // One process owns the data directory (plan task 46): the server holds an
    // exclusive lock for its whole lifetime so offline ops commands (`verify`,
    // `cache`, `gc`) can detect a live server and refuse instead of racing it.
    // A second server on the same directory is likewise rejected here.
    // v1.3: control-plane state lives under server.data_path, not the payload
    // root. Legacy configs resolve data_path to the old root, so this is a
    // no-op for them.
    let state_dir = config.state_dir();
    let _data_lock = cachette::ops::DataDirLock::acquire(&state_dir)?;
    // First boot mints the Ed25519 identity at `cluster.cert_path`; later
    // boots reuse it, so the fingerprint survives restarts and storage wipes
    // (plan task 13). It also becomes the `/health` node_id.
    let identity = Identity::load_or_generate(
        &config.cert_path(),
        config.cluster.node_id.as_deref(),
        config.cluster.advertise_addr.as_deref(),
    )?;
    tracing::info!(
        fingerprint = identity.fingerprint(),
        cert_path = %identity.cert_path().display(),
        "node identity ready"
    );
    state.node_id = identity.fingerprint().to_owned();
    // Peer pin store (plan task 14 / B2): seeded fingerprints are always
    // trusted; TOFU admission follows `[cluster] enabled`.
    state.peers = Arc::new(PeerPins::new(
        &config.cluster.seed_fingerprints,
        config.cluster.enabled,
    ));
    // Cluster discovery (plan task 28): seeds + mDNS populate the peer table
    // when `[cluster] enabled`. The runtime handle is kept alive for the
    // process lifetime so the mDNS daemon keeps responding and browsing.
    let cluster_runtime = if config.cluster.enabled {
        let runtime = cachette::cluster::start(&config.cluster, &identity, &config.cluster.listen);
        state.peer_table = runtime.peer_table().clone();
        Some(runtime)
    } else {
        None
    };
    // v1 relay (plan task 31): with cluster mode on, the entry node forwards a
    // reservation/chunks/commit to the placement owner over mTLS. It reuses the
    // same pinned client config as the heartbeat sender and falls back to the
    // unchanged single-node path when disabled or when the client cannot be
    // built.
    if let Some(runtime) = cluster_runtime.as_ref() {
        let relay_config = RelayConfig {
            node_id: state.node_id.clone(),
            cert_pem: identity.cert_pem().to_owned(),
            key_pem: identity.key_pem().to_owned(),
            pins: state.peers.clone(),
            placement: runtime.placement().clone(),
            peer_table: state.peer_table.clone(),
            metrics: state.metrics.clone(),
            min_free: config.storage.fs.min_free,
            max_size: config.cache.max_size,
            reservation_ttl_seconds: config.cache.reservation_ttl_seconds,
        };
        match ClusterRelay::new(relay_config) {
            Ok(relay) => {
                state.relay = Some(Arc::new(relay));
                tracing::info!("v1 relay enabled (cluster mode)");
            }
            Err(err) => {
                tracing::warn!(error = %err, "v1 relay disabled: outbound mTLS client failed");
            }
        }
    }
    // Auth (plan task 15): sqlite-backed dynamic token store sharing the
    // storage database file, plus the per-request auth policy snapshot.
    state.tokens = Arc::new(TokenStore::open(&config.data_path)?);
    state.set_auth(AuthPolicy::from_config(&config));
    // Admin namespace mappings (v1.2 workstream F): a tenant the admin mapped
    // into a shared namespace resolves there; every other credential keeps
    // its derived namespace. Boot-time wiring, like the credential planes.
    state.namespaces = Arc::new(config.storage.namespaces.clone());
    // Per-namespace byte limits (v1.2 workstream F, `docs/shared-cache.md`
    // §5): parsed once at boot, like the namespace mapping; validation has
    // already proven the table parses, so this cannot fail late.
    state.quotas = Arc::new(config.storage.quotas.parse()?);
    // OIDC bearer verification (v1.1 workstream A): when `[auth.oidc]`
    // enabled, build the JWKS cache + verifier and hang them on the state.
    // A failure is boot-fatal; a disabled/absent table is a silent no-op, so
    // v1.0 behavior stays byte-identical. Reloads never swap the verifier.
    auth::oidc::install(&state, &config)?;
    // Forge runtime-token verification (v1.2 Plane B,
    // `docs/shared-cache.md` §3): each enabled `[auth.runtime."<forge>"]`
    // block reads its signing-secret file at boot. An unreadable or empty
    // secret is boot-fatal; no enabled block is a silent no-op.
    auth::runtime::install(&state, &config)?;
    // Runner-visible base URL for capability URLs (`/v2/*`); the config
    // resolver always derives it from `listen` when `external_url` is unset.
    state.external_url = config.server.external_url.clone();
    // Cache limits (plan task 19): the reserve handler reports capacity and
    // stamps reservation expiry from these numbers, so thread `[cache]` /
    // `[storage.fs]` onto the request path. `from_config` builds the same
    // snapshot the SIGHUP reload path (plan task 49) uses.
    state.set_cache_limits(CacheLimits::from_config(&config));
    // Resolve the B3 `total` once at boot (plan task 31): the peer reserve
    // admission path must not do a blocking disk query per request.
    state.capacity_total = Capacity::from_disk(
        config.storage.fs.min_free,
        config.cache.max_size,
        &config.storage.fs.path,
        0,
    )
    .map(|capacity| capacity.total)
    .unwrap_or(config.cache.max_size);

    // Storage + reaper (plan task 34). One `FsStorage` is constructed here and
    // shared by the routes, the periodic sweep, and the shutdown flush. Its
    // single-writer `gate` (an `RwLock`) serialises sweeps against writes:
    // `sweep_orphan_blobs`/`reap_expired_reservations` take `gate.write()`,
    // exactly like `put_stream`/`finalize`/`delete`. That is what guarantees a
    // sweep never deletes a blob a download is reading and shutdown never
    // interrupts a parts-write mid-rename — both wait for the same lock.
    // CDC `[storage.cdc]` (v1.1 workstream B): the flag only shapes new
    // finalizations; reads stay layout-aware regardless of it, so flipping it
    // off never orphans already-chunked at-rest data (docs/cdc.md).
    let cdc = config
        .storage
        .cdc
        .enabled
        .then(|| cachette::storage::cdc::CdcParams::new(config.storage.cdc.avg_chunk_bytes));
    let storage = Arc::new(FsStorage::open_cdc_with_db(
        &config.storage.fs.path,
        &config.data_path,
        cdc,
    )?);
    let backend: Arc<dyn StorageBackend> = storage.clone();
    state.storage = Some(backend.clone());
    let reaper = Reaper::new(Duration::from_secs(config.cache.reservation_ttl_seconds));
    // Startup sweep, before the listener binds: rowless blobs older than the
    // 1h grace and reservations whose TTL has passed (plan task 34).
    match reaper.sweep_once(&storage).await {
        Ok(report) => {
            state.set_storage_ok(true);
            tracing::info!(
                reservations = report.reservations_reaped,
                orphans = report.orphan_blobs_swept,
                orphan_chunks = report.orphan_chunks_swept,
                chunk_temps = report.chunk_temps_swept,
                zero_ref_chunk_rows = report.zero_ref_chunk_rows_purged,
                "startup sweep complete"
            );
        }
        Err(err) => {
            state.set_storage_ok(false);
            tracing::warn!(error = %err, "startup sweep failed");
        }
    }

    // Heartbeat + health (plan task 29 / M15): self-record with live B3
    // values, peer timeout sweep, and mTLS heartbeat sends to every peer. The
    // draining flag (task 47) is shared with the shutdown path so this node
    // (and an on-demand announce) advertises the drain to peers.
    let draining = state.draining.clone();
    let heartbeat_task = config.cluster.enabled.then(|| {
        heartbeat::spawn(heartbeat::HeartbeatConfig {
            node_id: state.node_id.clone(),
            cert_pem: identity.cert_pem().to_owned(),
            key_pem: identity.key_pem().to_owned(),
            advertise_addr: config
                .cluster
                .advertise_addr
                .as_deref()
                .unwrap_or(&config.cluster.listen)
                .to_owned(),
            peer_table: state.peer_table.clone(),
            pins: state.peers.clone(),
            storage: backend.clone(),
            storage_path: config.storage.fs.path.clone(),
            min_free: config.storage.fs.min_free,
            max_size: config.cache.max_size,
            interval: Duration::from_secs(config.cluster.heartbeat_interval_seconds),
            timeout: Duration::from_secs(config.cluster.peer_timeout_seconds),
            draining: draining.clone(),
        })
    });

    // TraceLayer logs each request/response at DEBUG — visible under
    // `RUST_LOG=debug`, silent under the default `info` and under `warn`.
    let app = routes::router(state.clone()).layer(TraceLayer::new_for_http());
    // Main listener: plaintext HTTP by default; TLS is opt-in through the
    // `[server] tls_cert`/`tls_key` pair (validated together-or-neither). The
    // listener is wrapped so both variants hand axum a `PeerCert` — a client
    // fingerprint exists only on TLS accepts, so pin-gated routes fail closed
    // on plaintext connections.
    let server_tls_cfg = if config.server.tls_cert.is_some() {
        Some(tls::server_config(&config.server, &identity)?)
    } else {
        None
    };
    let scheme = if server_tls_cfg.is_some() {
        "https"
    } else {
        "http"
    };
    let listener: tls::ServerListener = match server_tls_cfg {
        Some(tls_config) => {
            tls::ServerListener::Tls(tls::bind(&config.server.listen, tls_config).await?)
        }
        None => {
            tls::ServerListener::Plain(tokio::net::TcpListener::bind(&config.server.listen).await?)
        }
    };
    // Unconditional stdout line: the readiness gate for scripts (it must
    // appear even when `RUST_LOG` silences the tracing subscriber).
    let listen = &config.server.listen;
    println!("cachette listening on {scheme}://{listen}");
    tracing::info!(%listen, scheme, "listener ready");

    // Periodic sweep (plan task 34): `reservation_ttl / 4` (>= 1s), the cadence
    // the reaper documents. The first tick is immediate and skipped — the
    // startup sweep already ran.
    let sweep_storage = storage.clone();
    let sweep_metrics = state.metrics.clone();
    let sweep_storage_ok = state.storage_ok.clone();
    let sweep_interval = reaper.interval();
    let sweep_task = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(sweep_interval);
        ticker.tick().await;
        loop {
            ticker.tick().await;
            match reaper.sweep_once(&sweep_storage).await {
                Ok(report) => {
                    sweep_storage_ok.store(true, std::sync::atomic::Ordering::Relaxed);
                    if report.reservations_reaped > 0 {
                        sweep_metrics.add_reservations(-(report.reservations_reaped as i64));
                    }
                    if let Ok(used) = sweep_storage.used_bytes().await {
                        sweep_metrics.set_storage_used(used);
                    }
                    if report.reservations_reaped > 0
                        || report.orphan_blobs_swept > 0
                        || report.orphan_chunks_swept > 0
                        || report.chunk_temps_swept > 0
                        || report.zero_ref_chunk_rows_purged > 0
                        || report.chunk_locks_swept > 0
                    {
                        tracing::info!(
                            reservations = report.reservations_reaped,
                            orphans = report.orphan_blobs_swept,
                            orphan_chunks = report.orphan_chunks_swept,
                            chunk_temps = report.chunk_temps_swept,
                            zero_ref_chunk_rows = report.zero_ref_chunk_rows_purged,
                            chunk_locks = report.chunk_locks_swept,
                            "periodic sweep reclaimed storage"
                        );
                    }
                }
                Err(err) => {
                    sweep_storage_ok.store(false, std::sync::atomic::Ordering::Relaxed);
                    tracing::warn!(error = %err, "periodic sweep failed");
                }
            }
        }
    });

    // Quota-aware eviction (v1.2 workstream F, `docs/shared-cache.md` §5):
    // the reaper above reclaims abandoned uploads; this loop is what
    // actually enforces the per-namespace limits and the global
    // `min_free`/`max_size` floor - eviction stays off the request path
    // (B3), where a below-floor reserve is only logged.
    let eviction = EvictionService::new(
        config.cache.eviction,
        Arc::new(LeaseSet::new(DEFAULT_BORROW_TTL)),
    )
    .with_metrics(state.metrics.clone())
    .with_quotas(state.quotas.clone());
    let eviction_storage = storage.clone();
    let eviction_metrics = state.metrics.clone();
    let eviction_storage_ok = state.storage_ok.clone();
    let eviction_min_free = config.storage.fs.min_free;
    let eviction_max_size = config.cache.max_size;
    let eviction_total = state.capacity_total;
    let eviction_task = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(EVICTION_INTERVAL);
        // The first tick is immediate; nothing has accrued between the
        // startup reap and now, so skip it like the reaper loop does.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            let used = match eviction_storage.used_bytes().await {
                Ok(used) => used,
                Err(err) => {
                    eviction_storage_ok.store(false, std::sync::atomic::Ordering::Relaxed);
                    tracing::warn!(error = %err, "periodic eviction: usage accounting failed");
                    continue;
                }
            };
            let mut capacity =
                Capacity::resolve(eviction_min_free, eviction_max_size, eviction_total, used);
            match eviction.sweep(&*eviction_storage, &mut capacity).await {
                Ok(report) => {
                    eviction_storage_ok.store(true, std::sync::atomic::Ordering::Relaxed);
                    eviction_metrics.set_storage_used(capacity.used);
                    if !report.evicted.is_empty() {
                        tracing::info!(
                            evicted = report.evicted.len(),
                            bytes_freed = report.bytes_freed,
                            quota_namespaces = report.quota_freed.len(),
                            outcome = ?report.outcome,
                            "periodic eviction reclaimed storage"
                        );
                    }
                }
                Err(err) => {
                    eviction_storage_ok.store(false, std::sync::atomic::Ordering::Relaxed);
                    tracing::warn!(error = %err, "periodic eviction failed");
                }
            }
        }
    });

    // Whole->chunked backfill (v1.1 workstream B, docs/cdc.md Migration):
    // with `[storage.cdc] enabled = true` and `backfill` on (the default),
    // converge pre-CDC `whole` entries onto the chunked layout in the
    // background - one entry per step, smallest first, paced by
    // `backfill_delay_ms`. A step's chunking pass holds no locks, so live
    // traffic interleaves; a corrupt entry is parked in the local skip set
    // for this process lifetime. No task when CDC is off: nothing converges
    // and new writes stay whole anyway.
    let backfill_task = if config.storage.cdc.enabled && config.storage.cdc.backfill {
        let backfill_storage = storage.clone();
        let backfill_params =
            cachette::storage::cdc::CdcParams::new(config.storage.cdc.avg_chunk_bytes);
        let backfill_delay = Duration::from_millis(config.storage.cdc.backfill_delay_ms);
        Some(tokio::spawn(async move {
            let mut skip: HashSet<String> = HashSet::new();
            loop {
                match backfill_storage
                    .backfill_step(backfill_params, &mut skip)
                    .await
                {
                    Ok(BackfillStep::Converted(conversion)) => {
                        let pending = backfill_storage.pending_whole_entries().await.unwrap_or(0);
                        tracing::info!(
                            entry = %conversion.id,
                            blob_bytes = conversion.blob_bytes,
                            chunk_bytes = conversion.chunk_bytes,
                            pending,
                            "backfill converted a whole entry to chunks"
                        );
                    }
                    Ok(BackfillStep::Raced) => {
                        tracing::debug!("backfill step raced a writer; re-picking");
                    }
                    Ok(BackfillStep::Exhausted) => {
                        // Converged (for now): idle at a slow poll instead
                        // of the conversion pace.
                        tokio::time::sleep(BACKFILL_IDLE).await;
                        continue;
                    }
                    Err(err) => {
                        tracing::warn!(error = %err, "backfill step failed");
                    }
                }
                tokio::time::sleep(backfill_delay).await;
            }
        }))
    } else {
        None
    };

    // Live config reload (plan task 49): SIGHUP on POSIX (plus the documented
    // test-only trigger) re-reads the config file and applies the reloadable
    // subset — the auth policy, the cache limits, and the log level — in place.
    // Connections are never dropped and boot-only knobs (listen addresses, the
    // data directory, the storage backend, cluster wiring) are untouched. A
    // parse error is logged and the previous config is kept.
    let mut reload_signals = reload::listen();
    let reload_state = state.clone();
    let reload_task = tokio::spawn(async move {
        while reload_signals.recv().await.is_some() {
            match config::load(reload_state.config_path.clone()) {
                Ok(new_config) => {
                    reload_state.apply_reload(&new_config);
                    logging::reload_level(new_config.log.level);
                    tracing::info!("config reloaded (reloadable subset applied)");
                }
                Err(err) => {
                    tracing::error!(error = %err, "config reload failed; keeping previous config");
                }
            }
        }
    });

    // Shutdown (plan task 34): SIGINT (Ctrl+C on Windows and POSIX), SIGTERM
    // (POSIX), or the documented test-only trigger. The first signal starts a
    // graceful drain; a second aborts with exit 1.
    let (shutdown_notify, mut signals) = shutdown::listen();
    let drain_grace = Duration::from_secs(config.server.drain_grace_seconds);
    let serve_draining = draining.clone();
    // Cluster listener (`[cluster] enabled`): a dedicated port for peer
    // traffic that ALWAYS terminates TLS with the self-signed node identity
    // certificate — peers authenticate by SPKI fingerprint pin, not a CA
    // chain. The shim clears `tls_cert`/`tls_key` so the cluster port presents
    // the identity cert even when the main listener serves a configured PEM
    // pair (peer pins match the identity fingerprint, not the CA cert's).
    let mut cluster_handle = None;
    if config.cluster.enabled {
        let cluster_server = cachette::config::ServerConfig {
            tls_cert: None,
            tls_key: None,
            ..config.server.clone()
        };
        let cluster_tls = tls::server_config(&cluster_server, &identity)?;
        let cluster_listener = tls::bind(&config.cluster.listen, cluster_tls).await?;
        println!(
            "cachette cluster listening on https://{}",
            config.cluster.listen
        );
        tracing::info!(listen = %config.cluster.listen, "cluster listener ready");
        let cluster_app = app.clone();
        let cluster_notify = shutdown_notify.clone();
        // Aborted at shutdown flush (after the main serve drains): a peer
        // connection severed here only loses that one in-flight transfer;
        // the peer retries on its next heartbeat and orphan parts are swept.
        cluster_handle = Some(tokio::spawn(async move {
            axum::serve(
                cluster_listener,
                cluster_app.into_make_service_with_connect_info::<tls::PeerCert>(),
            )
            .with_graceful_shutdown(async move { cluster_notify.notified().await })
            .await
        }));
    }
    let serve = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<tls::PeerCert>(),
    )
    .with_graceful_shutdown(async move {
        shutdown_notify.notified().await;
        // Advertise the drain (plan task 47): peers stop selecting this node
        // for NEW placements and `/readyz` reports not-ready while in-flight
        // transfers finish.
        serve_draining.store(true, std::sync::atomic::Ordering::SeqCst);
        tracing::info!(
            grace_s = drain_grace.as_secs(),
            "shutdown: draining in-flight transfers"
        );
    });
    let mut serve = Box::pin(serve.into_future());

    // `biased` + serve-first: if the server has already finished draining when
    // a signal lands, the serve branch wins and the future is never polled
    // again (re-polling a completed future would panic).
    tokio::select! {
        biased;
        result = &mut serve => {
            result?;
        }
        _ = signals.recv() => {
            // Drain: `with_graceful_shutdown` has stopped accepting new
            // connections; wait for in-flight transfers, bounded by the grace
            // window, racing a second signal.
            //
            // Set the flag and announce here too (before the serve future is
            // polled) so the draining heartbeat is authoritative and reaches
            // peers immediately rather than after a full interval.
            draining.store(true, std::sync::atomic::Ordering::SeqCst);
            if let Some(handle) = heartbeat_task.as_ref() {
                handle.announce();
            }
            tokio::select! {
                biased;
                result = &mut serve => {
                    result?;
                }
                () = tokio::time::sleep(drain_grace) => {
                    tracing::warn!("shutdown: grace window elapsed; exiting with transfers in flight");
                }
                Some(()) = signals.recv() => {
                    tracing::error!("shutdown: second signal received; exiting immediately");
                    std::process::exit(1);
                }
            }
        }
    }

    // Flush: stop the periodic sweep, run one final reap (commits the WAL),
    // then drop the storage handle. SQLite runs in WAL mode with
    // `synchronous=NORMAL`, so the committed final sweep is durable.
    sweep_task.abort();
    eviction_task.abort();
    if let Some(handle) = backfill_task {
        handle.abort();
    }
    reload_task.abort();
    if let Some(handle) = heartbeat_task {
        handle.abort();
    }
    if let Some(handle) = cluster_handle {
        handle.abort();
    }
    match reaper.sweep_once(&storage).await {
        Ok(report) => tracing::info!(
            reservations = report.reservations_reaped,
            orphans = report.orphan_blobs_swept,
            "shutdown: final sweep complete"
        ),
        Err(err) => tracing::warn!(error = %err, "shutdown: final sweep failed"),
    }
    drop(serve);
    drop(storage);
    drop(cluster_runtime);
    tracing::info!("shutdown: complete");
    Ok(())
}

/// Graceful-shutdown plumbing (plan task 34).
///
/// Production path: the first SIGINT (Ctrl+C on Windows and POSIX) or SIGTERM
/// (POSIX only) starts a drain — the listener stops accepting new connections,
/// in-flight transfers get `[server] drain_grace_seconds` to finish, SQLite is
/// flushed, and the process exits 0. A second signal during the drain exits 1
/// immediately.
///
/// Test-only trigger: when `CACHETTE_TEST_SHUTDOWN_AFTER_MS` is set to a
/// millisecond count, the same drain path fires once after that delay. It
/// exists because delivering a Windows console Ctrl+C to a child process needs
/// `GenerateConsoleCtrlEvent` against a shared console process group, which is
/// impractical in CI; the variable is read only here, is never part of the
/// default config, and is never set by the server itself. The real signal
/// handlers below stay wired in production.
mod shutdown {
    use std::sync::Arc;
    use std::time::Duration;

    use tokio::sync::{Notify, mpsc};

    /// Test-only trigger (see module docs): milliseconds after startup.
    const TEST_TRIGGER_ENV: &str = "CACHETTE_TEST_SHUTDOWN_AFTER_MS";

    /// Start listening for shutdown signals. Returns the [`Notify`] the
    /// graceful-shutdown future awaits and a channel that yields one token per
    /// delivered signal (first token = begin drain, second = abort).
    pub fn listen() -> (Arc<Notify>, mpsc::Receiver<()>) {
        let notify = Arc::new(Notify::new());
        let (tx, rx) = mpsc::channel(4);
        let task_notify = notify.clone();
        tokio::spawn(async move {
            let mut term = make_term();
            let mut test_pending = test_trigger_delay();
            loop {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = terminate(&mut term) => {}
                    _ = test_trigger(&mut test_pending) => {}
                }
                task_notify.notify_one();
                if tx.send(()).await.is_err() {
                    break;
                }
            }
        });
        (notify, rx)
    }

    /// SIGTERM stream on POSIX; a never-resolving placeholder elsewhere.
    #[cfg(unix)]
    type TermStream = Option<tokio::signal::unix::Signal>;
    #[cfg(not(unix))]
    struct TermStream;

    #[cfg(unix)]
    fn make_term() -> TermStream {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok()
    }

    #[cfg(not(unix))]
    fn make_term() -> TermStream {
        TermStream
    }

    #[cfg(unix)]
    async fn terminate(term: &mut TermStream) {
        match term {
            Some(stream) => {
                stream.recv().await;
            }
            None => std::future::pending::<()>().await,
        }
    }

    #[cfg(not(unix))]
    async fn terminate(_term: &mut TermStream) {
        std::future::pending::<()>().await
    }

    fn test_trigger_delay() -> Option<Duration> {
        std::env::var(TEST_TRIGGER_ENV)
            .ok()
            .and_then(|raw| raw.parse::<u64>().ok())
            .map(Duration::from_millis)
    }

    /// One-shot test trigger: sleeps `delay` once, then never resolves again.
    async fn test_trigger(pending: &mut Option<Duration>) {
        match pending.take() {
            Some(delay) => tokio::time::sleep(delay).await,
            None => std::future::pending::<()>().await,
        }
    }
}

/// Live config reload plumbing (plan task 49).
///
/// Production path: `SIGHUP` (POSIX only) signals the server to re-read its
/// config file and apply the reloadable subset in place. The server never drops
/// a connection and never restarts the listener.
///
/// Test-only trigger: when `CACHETTE_TEST_RELOAD_AFTER_MS` is set to a
/// millisecond count, one reload fires after that delay — mirroring
/// [`shutdown`]'s `CACHETTE_TEST_SHUTDOWN_AFTER_MS` for the same reason
/// (delivering a real SIGHUP is impractical on Windows CI). The variable is
/// read only here, is never part of the default config, and is never set by the
/// server itself. The real signal handler stays wired in production.
mod reload {
    use std::time::Duration;

    use tokio::sync::mpsc;

    /// Test-only trigger (see module docs): milliseconds after startup.
    const TEST_TRIGGER_ENV: &str = "CACHETTE_TEST_RELOAD_AFTER_MS";

    /// Start listening for reload signals. Returns a channel that yields one
    /// token per delivered signal (SIGHUP, or the one-shot test trigger).
    pub fn listen() -> mpsc::Receiver<()> {
        let (tx, rx) = mpsc::channel(4);
        tokio::spawn(async move {
            let mut hup = make_hup();
            let mut test_pending = test_trigger_delay();
            loop {
                tokio::select! {
                    _ = hangup(&mut hup) => {}
                    _ = test_trigger(&mut test_pending) => {}
                }
                if tx.send(()).await.is_err() {
                    break;
                }
            }
        });
        rx
    }

    /// SIGHUP stream on POSIX; a never-resolving placeholder elsewhere.
    #[cfg(unix)]
    type HupStream = Option<tokio::signal::unix::Signal>;
    #[cfg(not(unix))]
    struct HupStream;

    #[cfg(unix)]
    fn make_hup() -> HupStream {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()).ok()
    }

    #[cfg(not(unix))]
    fn make_hup() -> HupStream {
        HupStream
    }

    #[cfg(unix)]
    async fn hangup(hup: &mut HupStream) {
        match hup {
            Some(stream) => {
                stream.recv().await;
            }
            None => std::future::pending::<()>().await,
        }
    }

    #[cfg(not(unix))]
    async fn hangup(_hup: &mut HupStream) {
        std::future::pending::<()>().await
    }

    fn test_trigger_delay() -> Option<Duration> {
        std::env::var(TEST_TRIGGER_ENV)
            .ok()
            .and_then(|raw| raw.parse::<u64>().ok())
            .map(Duration::from_millis)
    }

    /// One-shot test trigger: sleeps `delay` once, then never resolves again.
    async fn test_trigger(pending: &mut Option<Duration>) {
        match pending.take() {
            Some(delay) => tokio::time::sleep(delay).await,
            None => std::future::pending::<()>().await,
        }
    }
}
