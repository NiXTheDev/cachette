//! Offline ops + CLI surface (plan task 46).
//!
//! The server and its operator commands ship in one binary. Every subcommand
//! here except [`Command::Cluster`] runs **without** a live server; the ones
//! that touch the data directory (`verify`, `cache`, `gc`) take an exclusive
//! [`DataDirLock`] and refuse with a clear message when a running server holds
//! it. `doctor` is read-only and `token` never touches the data dir, so neither
//! locks.
//!
//! The lock is a byte-range advisory lock (`fs2`) on `<data_dir>/.cachette.lock`
//! that `serve()` also holds for the process lifetime. It is deliberately not
//! the SQLite file: SQLite already serialises its own writers across processes,
//! but it cannot tell an operator "a server is running here"; the lock file can.

use std::collections::BTreeMap;
use std::error::Error;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use fs2::FileExt;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::cli::{CacheCommand, ClusterCommand, Command, IdentityCommand, Scope, TokenCommand};
use crate::config::{Config, split_host_port};
use crate::identity::Identity;
use crate::storage::StorageBackend;
use crate::storage::eviction::{Capacity, Reaper};
use crate::storage::fs::{EntryHealth, FsStorage};

/// Lock file name inside the data directory.
const LOCK_FILE: &str = ".cachette.lock";

/// Exit code for a command that ran but found a problem (as opposed to `2`,
/// which `main` uses for a config/usage failure).
const FAILED: i32 = 1;

/// Failure acquiring or reading the data directory.
#[derive(Debug, Error)]
pub enum OpsError {
    /// The data directory is held by another cachette process (the server, or
    /// another ops command). `source` is the underlying lock error.
    #[error(
        "data directory {path} is in use by another cachette process \
         (stop the server or the other ops command first): {source}"
    )]
    Locked {
        /// The lock file path.
        path: PathBuf,
        /// The underlying OS lock error.
        source: io::Error,
    },

    /// Filesystem trouble creating or opening the lock file.
    #[error("i/o error at {path}: {source}")]
    Io {
        /// Path that failed.
        path: PathBuf,
        /// Underlying error.
        source: io::Error,
    },
}

/// Exclusive, process-lifetime lock over a cachette data directory.
///
/// Held by `serve()` while the server runs, and by the offline ops commands
/// (`verify`/`cache`/`gc`) for the duration of their run. Dropping the guard
/// closes the file and releases the lock.
#[derive(Debug)]
pub struct DataDirLock {
    file: std::fs::File,
}

impl DataDirLock {
    /// Acquire the lock under `dir`, creating the directory if needed.
    ///
    /// Returns [`OpsError::Locked`] when another process already holds it.
    pub fn acquire(dir: &Path) -> Result<Self, OpsError> {
        std::fs::create_dir_all(dir).map_err(|source| OpsError::Io {
            path: dir.to_path_buf(),
            source,
        })?;
        let path = dir.join(LOCK_FILE);
        let file = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&path)
            .map_err(|source| OpsError::Io {
                path: path.clone(),
                source,
            })?;
        file.try_lock_exclusive()
            .map_err(|source| OpsError::Locked {
                path: path.clone(),
                source,
            })?;
        Ok(Self { file })
    }
}

impl Drop for DataDirLock {
    fn drop(&mut self) {
        // Closing the file releases the advisory lock on every supported
        // platform; the explicit unlock just makes the intent clear.
        let _ = self.file.unlock();
    }
}

/// Dispatch one ops subcommand. Returns the process exit code.
///
/// # Errors
/// A hard failure that `main` maps to exit code 2 (bad config for the
/// command); a command that ran but found problems returns `Ok(1)` instead.
pub fn run(command: &Command, config: &Config) -> Result<i32, Box<dyn Error>> {
    match command {
        Command::Identity { action } => identity(action.as_ref(), config),
        Command::Verify => block_on(verify(config)),
        Command::Cache { action } => block_on(cache(action, config)),
        Command::Gc => block_on(gc(config)),
        Command::Doctor => block_on(doctor(config)),
        Command::Token { action } => token(action, config),
        Command::Cluster { action } => block_on(cluster_status(action, config)),
    }
}

/// Build a small current-thread runtime for the async ops bodies (the server's
/// multi-thread runtime is created only on the serve path).
fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build current-thread runtime")
        .block_on(future)
}

/// `cachette identity [rotate]` — print the fingerprint and cert path (plan
/// task 13); with `rotate`, first re-issue the certificate for the same key
/// (plan task 48). A missing/invalid identity is a hard error (exit code 2):
/// `rotate` never mints a new key, because a new key would change the pinned
/// fingerprint and partition the cluster.
fn identity(action: Option<&IdentityCommand>, config: &Config) -> Result<i32, Box<dyn Error>> {
    let dir = config.cert_path();
    let node_id = config.cluster.node_id.as_deref();
    let advertise_addr = config.cluster.advertise_addr.as_deref();
    let identity = match action {
        Some(IdentityCommand::Rotate) => Identity::renew(&dir, node_id, advertise_addr)?,
        // Bare `cachette identity` mints on first run, exactly as before.
        None => Identity::load_or_generate(&dir, node_id, advertise_addr)?,
    };
    println!("fingerprint: {}", identity.fingerprint());
    println!("cert_path: {}", identity.cert_path().display());
    if action.is_some() {
        println!("certificate renewed (same key; fingerprint unchanged)");
    }
    Ok(0)
}

/// Acquire the data-dir lock or return the exit code to use. The error is
/// printed here so every caller gets the same clear message.
fn acquire(dir: &Path) -> Result<DataDirLock, i32> {
    DataDirLock::acquire(dir).map_err(|err| {
        eprintln!("cachette: {err}");
        FAILED
    })
}

/// `cachette verify` — recompute every published entry's digest (plan task 50)
/// and report the ones that no longer match. Non-zero exit on any finding.
async fn verify(config: &Config) -> Result<i32, Box<dyn Error>> {
    let _lock = match acquire(&config.storage.fs.path) {
        Ok(lock) => lock,
        Err(code) => return Ok(code),
    };
    let storage = FsStorage::open(&config.storage.fs.path)?;
    let reports = storage.verify_all()?;
    let mut bad = 0usize;
    for report in &reports {
        if report.is_ok() {
            continue;
        }
        bad += 1;
        println!(
            "{}: {} (size={})",
            report.key,
            health_label(&report.health),
            report.size
        );
    }
    println!(
        "verified {} entr{}; {} need attention",
        reports.len(),
        if reports.len() == 1 { "y" } else { "ies" },
        bad
    );
    Ok(if bad == 0 { 0 } else { FAILED })
}

/// Human label for an [`EntryHealth`] verdict.
fn health_label(health: &EntryHealth) -> String {
    match health {
        EntryHealth::Ok => String::from("ok"),
        EntryHealth::MissingBlob => String::from("missing-blob"),
        EntryHealth::MissingDigest => String::from("missing-digest (pre-task-50 row)"),
        EntryHealth::SizeMismatch { expected, actual } => {
            format!("size-mismatch (expected {expected}, actual {actual})")
        }
        EntryHealth::DigestMismatch { expected, actual } => {
            format!("digest-mismatch (expected {expected}, actual {actual})")
        }
    }
}

/// `cachette cache list|prune` — inspect or selectively evict entries through
/// the same storage path the server uses (plan task 46).
async fn cache(action: &CacheCommand, config: &Config) -> Result<i32, Box<dyn Error>> {
    let _lock = match acquire(&config.storage.fs.path) {
        Ok(lock) => lock,
        Err(code) => return Ok(code),
    };
    let storage = FsStorage::open(&config.storage.fs.path)?;
    match action {
        CacheCommand::List { json } => {
            let entries = storage.list().await?;
            if *json {
                let rows: Vec<EntryJson<'_>> = entries
                    .iter()
                    .map(|entry| EntryJson {
                        key: entry.key.as_str(),
                        size: entry.size,
                        created_at: entry.created_at,
                        accessed_at: entry.accessed_at,
                    })
                    .collect();
                println!("{}", serde_json::to_string_pretty(&rows)?);
            } else {
                println!(
                    "{:<48} {:>12} {:>12} {:>12}",
                    "key", "size", "created", "accessed"
                );
                for entry in &entries {
                    println!(
                        "{:<48} {:>12} {:>12} {:>12}",
                        entry.key, entry.size, entry.created_at, entry.accessed_at
                    );
                }
                println!("{} entr{}", entries.len(), plural(entries.len()));
            }
            Ok(0)
        }
        CacheCommand::Prune {
            older_than,
            dry_run,
        } => {
            let window = parse_duration(older_than).map_err(invalid_input)?;
            let now = u64::try_from(crate::auth::now_secs()).unwrap_or(0);
            let cutoff = now.saturating_sub(window);
            let entries = storage.list().await?;
            let mut count = 0usize;
            let mut freed = 0u64;
            for entry in entries {
                // LRU window: an entry is pruneable when it has not been read
                // within `older_than` (accessed_at is the LRU input).
                if entry.accessed_at >= cutoff {
                    continue;
                }
                if *dry_run {
                    println!(
                        "would delete {} ({} bytes, last read {})",
                        entry.key, entry.size, entry.accessed_at
                    );
                } else {
                    storage.delete(&entry.key).await?;
                    println!("deleted {} ({} bytes)", entry.key, entry.size);
                }
                count += 1;
                freed += entry.size;
            }
            println!(
                "{} {} entr{}, {} bytes",
                if *dry_run { "would prune" } else { "pruned" },
                count,
                plural(count),
                freed
            );
            Ok(0)
        }
    }
}

/// Serializable entry row for `cache --json`.
#[derive(serde::Serialize)]
struct EntryJson<'a> {
    key: &'a str,
    size: u64,
    created_at: u64,
    accessed_at: u64,
}

/// `cachette gc` — one reservation-reaper + orphan-sweep pass (plan task 34's
/// [`Reaper`]) then exit.
async fn gc(config: &Config) -> Result<i32, Box<dyn Error>> {
    let _lock = match acquire(&config.storage.fs.path) {
        Ok(lock) => lock,
        Err(code) => return Ok(code),
    };
    let storage = FsStorage::open(&config.storage.fs.path)?;
    let reaper = Reaper::new(Duration::from_secs(config.cache.reservation_ttl_seconds));
    let report = reaper.sweep_once(&storage).await?;
    println!("reservations_reaped: {}", report.reservations_reaped);
    println!("orphan_blobs_swept: {}", report.orphan_blobs_swept);
    println!("chunk_locks_swept: {}", report.chunk_locks_swept);
    Ok(0)
}

/// `cachette doctor` — read-only health check of config, storage, SQLite,
/// identity, seeds, and disk headroom (plan task 46). Non-zero exit if any
/// check fails; the config itself was already parsed + validated by
/// [`crate::config::load`] before this runs.
async fn doctor(config: &Config) -> Result<i32, Box<dyn Error>> {
    let mut failures = 0usize;
    let path = &config.storage.fs.path;
    println!("config: ok");

    // Data directory writable.
    match probe_writable(path) {
        Ok(()) => println!("data dir: writable ({})", path.display()),
        Err(err) => {
            failures += 1;
            println!("data dir: NOT writable ({}): {err}", path.display());
        }
    }

    // SQLite: `PRAGMA integrity_check` + accounted bytes (read-only queries).
    let db = path.join("cachette.sqlite3");
    match sqlite_report(&db) {
        Ok((true, used, true)) => println!("sqlite: ok ({} bytes accounted)", used),
        Ok((_, _, false)) => println!("sqlite: not initialized (created on first boot)"),
        Ok((false, _, true)) => {
            failures += 1;
            println!("sqlite: integrity_check FAILED");
        }
        Err(err) => {
            failures += 1;
            println!("sqlite: unreadable: {err}");
        }
    }

    // Identity: present (generated on first boot) + fingerprint.
    match Identity::load_or_generate(
        &config.cert_path(),
        config.cluster.node_id.as_deref(),
        config.cluster.advertise_addr.as_deref(),
    ) {
        Ok(identity) => println!(
            "identity: ok (fingerprint {}, {})",
            identity.fingerprint(),
            identity.cert_path().display()
        ),
        Err(err) => {
            failures += 1;
            println!("identity: FAILED: {err}");
        }
    }

    // Seed reachability (only meaningful in cluster mode).
    if config.cluster.enabled {
        if config.cluster.seeds.is_empty() {
            println!("seeds: none configured");
        }
        for seed in &config.cluster.seeds {
            if !seed_reachable(seed).await {
                failures += 1;
                println!("seed {seed}: unreachable");
            } else {
                println!("seed {seed}: reachable");
            }
        }
    } else {
        println!("seeds: skipped (cluster disabled)");
    }

    // Disk free vs the configured floor. Sitting below `min_free` is a normal
    // operating condition (it is exactly what triggers eviction), so it is only
    // reported; doctor fails when the volume is so full that writes will fail.
    const CRITICAL_FREE: u64 = 64 * 1024 * 1024;
    let used = sqlite_report(&db).map(|(_, used, _)| used).unwrap_or(0);
    match Capacity::from_disk(
        config.storage.fs.min_free,
        config.cache.max_size,
        path,
        used,
    ) {
        Ok(capacity) => {
            let avail = fs2::available_space(path).unwrap_or(0);
            if avail < CRITICAL_FREE {
                failures += 1;
                println!(
                    "disk: CRITICALLY LOW ({avail} free, floor {}, < 64MiB headroom)",
                    capacity.min_free
                );
            } else if avail < capacity.min_free {
                println!(
                    "disk: below eviction floor ({avail} free, floor {}) - eviction will run",
                    capacity.min_free
                );
            } else {
                println!(
                    "disk: ok ({avail} free, floor {}, quota {})",
                    capacity.min_free,
                    if config.cache.max_size == 0 {
                        String::from("unlimited")
                    } else {
                        config.cache.max_size.to_string()
                    }
                );
            }
        }
        Err(err) => {
            failures += 1;
            println!("disk: cannot stat {}: {err}", path.display());
        }
    }

    Ok(if failures == 0 { 0 } else { FAILED })
}

/// Write and remove a probe file to prove `dir` is writable.
fn probe_writable(dir: &Path) -> io::Result<()> {
    std::fs::create_dir_all(dir)?;
    let probe = dir.join(format!(".cachette-doctor-{}", std::process::id()));
    std::fs::write(&probe, b"cachette-doctor")?;
    std::fs::remove_file(&probe)
}

/// `(integrity_ok, accounted_bytes, db_exists)` for the SQLite index at `db`.
fn sqlite_report(db: &Path) -> io::Result<(bool, u64, bool)> {
    if !db.is_file() {
        return Ok((true, 0, false));
    }
    let conn = rusqlite::Connection::open(db)
        .map_err(|err| io::Error::other(format!("open {}: {err}", db.display())))?;
    let integrity: String = conn
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .map_err(|err| io::Error::other(format!("integrity_check: {err}")))?;
    let used: i64 = conn
        .query_row(
            "SELECT COALESCE(SUM(size), 0) FROM entries WHERE complete = 1",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0);
    Ok((integrity == "ok", u64::try_from(used).unwrap_or(0), true))
}

/// TCP-connect a seed within a short timeout (reachability only).
async fn seed_reachable(seed: &str) -> bool {
    let Some((host, port)) = split_host_port(seed) else {
        return false;
    };
    let host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host)
        .to_owned();
    tokio::time::timeout(
        Duration::from_secs(2),
        TcpStream::connect((host.as_str(), port)),
    )
    .await
    .is_ok_and(|connected| connected.is_ok())
}

/// `cachette token mint` — print a Forgejo artifactcache HMAC token for the
/// configured secret (plan task 46).
fn token(action: &TokenCommand, config: &Config) -> Result<i32, Box<dyn Error>> {
    match action {
        TokenCommand::Mint { scope, repo, run } => {
            let secret = config
                .auth
                .secret
                .as_deref()
                .ok_or("auth.secret is not set; nothing to mint with")?;
            let timestamp = crate::auth::now_secs();
            // The artifactcache HMAC carries no server-side scope; the only
            // scope-like field is the verbatim write-isolation key. `write`
            // mints a non-empty key, `read` leaves it empty.
            let isolation = match scope {
                Scope::Read => "",
                Scope::Write => repo.as_str(),
            };
            let mac = crate::auth::hmac::mint(secret, repo, *run, timestamp, isolation);
            println!("{}: {repo}", crate::auth::hmac::HEADER_REPO);
            println!("{}: {run}", crate::auth::hmac::HEADER_RUN);
            println!("{}: {timestamp}", crate::auth::hmac::HEADER_TS);
            if !isolation.is_empty() {
                println!("{}: {isolation}", crate::auth::hmac::HEADER_WRITE_ISOLATION);
            }
            println!("{}: {mac}", crate::auth::hmac::HEADER_MAC);
            Ok(0)
        }
    }
}

/// `cachette cluster status [--watch]` — fetch the live member table from the
/// running server's loopback admin endpoint (plan task 46). This is the one
/// subcommand that requires a live server.
async fn cluster_status(action: &ClusterCommand, config: &Config) -> Result<i32, Box<dyn Error>> {
    let ClusterCommand::Status { watch } = action;
    loop {
        match fetch_cluster(config).await {
            Ok(body) => print_member_table(&body),
            Err(err) => {
                eprintln!("cachette: {err}");
                return Ok(FAILED);
            }
        }
        if !*watch {
            return Ok(0);
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

/// Dial the local server over mTLS (pinning the node's own SPKI fingerprint)
/// and `GET /_internal/cluster`, returning the JSON body.
async fn fetch_cluster(config: &Config) -> Result<String, Box<dyn Error>> {
    let secret = config
        .auth
        .secret
        .as_deref()
        .ok_or("auth.secret is not set; cannot authenticate to the admin endpoint")?;
    let identity = Identity::load_or_generate(
        &config.cert_path(),
        config.cluster.node_id.as_deref(),
        config.cluster.advertise_addr.as_deref(),
    )?;
    // Trust decision: the server presents its own identity certificate; we pin
    // exactly that SPKI fingerprint (the same model peers use), never a CA.
    let mut seed = BTreeMap::new();
    seed.insert(String::from("self"), identity.fingerprint().to_owned());
    let pins = Arc::new(crate::tls::PeerPins::new(&seed, false));
    let client =
        crate::cluster::tls_client::client_config(identity.cert_pem(), identity.key_pem(), pins)
            .map_err(|err| io::Error::other(format!("build TLS client: {err}")))?;

    let addr = connect_addr(config);
    let (host, port) = split_host_port(&addr).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, format!("bad address: {addr}"))
    })?;
    let host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host)
        .to_owned();
    let server_name = rustls::pki_types::ServerName::try_from(host.clone())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, format!("bad host: {host}")))?;

    let tcp = TcpStream::connect((host.as_str(), port))
        .await
        .map_err(|err| io::Error::other(format!("connect {addr}: {err}")))?;
    let mut stream = TlsConnector::from(client)
        .connect(server_name, tcp)
        .await
        .map_err(|err| io::Error::other(format!("TLS handshake failed: {err}")))?;
    let request = format!(
        "GET /_internal/cluster HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer {secret}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await?;
    parse_http(&raw)
}

/// The address to dial the local server: the advertise address (which defaults
/// to `[cluster] listen`), with wildcard hosts folded to loopback.
fn connect_addr(config: &Config) -> String {
    let raw = config
        .cluster
        .advertise_addr
        .clone()
        .unwrap_or_else(|| config.cluster.listen.clone());
    match split_host_port(&raw) {
        Some((host, port)) => {
            let host = match host {
                "0.0.0.0" => "127.0.0.1",
                "::" | "[::]" => "::1",
                other => other,
            };
            format!("{host}:{port}")
        }
        None => raw,
    }
}

/// Minimal HTTP/1.1 response parser for the `Connection: close` GET above:
/// split head/body, require a 2xx status, return the body.
fn parse_http(raw: &[u8]) -> Result<String, Box<dyn Error>> {
    let split = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or("malformed HTTP response (no header terminator)")?;
    let head = String::from_utf8_lossy(&raw[..split]);
    let body = String::from_utf8_lossy(&raw[split + 4..]).into_owned();
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or("malformed HTTP status line")?;
    if !(200..300).contains(&status) {
        return Err(format!("admin endpoint returned HTTP {status}: {body}").into());
    }
    Ok(body)
}

/// Render the member table from the JSON body.
fn print_member_table(body: &str) {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(body) else {
        println!("{body}");
        return;
    };
    let node_id = value.get("node_id").and_then(|v| v.as_str()).unwrap_or("");
    println!("node: {node_id}");
    let peers = value
        .get("peers")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    println!(
        "{:<24} {:<28} {:>8} {:>10} {:>10}",
        "node_id", "addr", "health", "age(s)", "used"
    );
    let now = u64::try_from(crate::auth::now_secs()).unwrap_or(0);
    for peer in &peers {
        let id = peer.get("node_id").and_then(|v| v.as_str()).unwrap_or("");
        let addr = peer.get("addr").and_then(|v| v.as_str()).unwrap_or("");
        let healthy = peer
            .get("healthy")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let last_hello = peer
            .get("last_hello")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        let used = peer
            .get("used_bytes")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        let age = if last_hello == 0 {
            String::from("-")
        } else {
            now.saturating_sub(last_hello).to_string()
        };
        println!(
            "{id:<24} {addr:<28} {:>8} {age:>10} {used:>10}",
            if healthy { "ok" } else { "unhealthy" }
        );
    }
    println!(
        "{} peer{}",
        peers.len(),
        if peers.len() == 1 { "" } else { "s" }
    );
}

/// Parse a `--older-than` window like `7d`, `12h`, `90s` into seconds. A bare
/// integer is rejected so the unit is never ambiguous.
fn parse_duration(raw: &str) -> Result<u64, String> {
    let raw = raw.trim();
    let (digits, unit) = raw.split_at(raw.len().checked_sub(1).ok_or("empty duration")?);
    let multiplier: u64 = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 60 * 60,
        "d" => 24 * 60 * 60,
        "w" => 7 * 24 * 60 * 60,
        _ => return Err(format!("unknown unit in {raw:?} (use s/m/h/d/w)")),
    };
    let value: u64 = digits
        .trim()
        .parse()
        .map_err(|_| format!("invalid duration {raw:?}"))?;
    value
        .checked_mul(multiplier)
        .ok_or_else(|| format!("duration {raw:?} overflows"))
}

/// Pluralization helper for the `entry`/`entries` summary lines.
fn plural(count: usize) -> &'static str {
    if count == 1 { "y" } else { "ies" }
}

/// Wrap a message as an [`io::Error`] for the `?`-friendly ops signatures.
fn invalid_input(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_duration_accepts_units_and_rejects_junk() {
        assert_eq!(parse_duration("90s"), Ok(90));
        assert_eq!(parse_duration("12h"), Ok(43_200));
        assert_eq!(parse_duration("7d"), Ok(604_800));
        assert_eq!(parse_duration("1w"), Ok(604_800));
        assert!(parse_duration("7").is_err());
        assert!(parse_duration("d").is_err());
        assert!(parse_duration("").is_err());
        assert!(parse_duration("7y").is_err());
    }

    #[test]
    fn data_dir_lock_is_exclusive_within_a_process() {
        let dir = std::env::temp_dir().join(format!("cachette-lock-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let first = DataDirLock::acquire(&dir).expect("first lock");
        // A second handle in the SAME process still conflicts: fs2 takes an
        // exclusive OS lock, not a per-handle one.
        let second = DataDirLock::acquire(&dir);
        assert!(matches!(second, Err(OpsError::Locked { .. })), "{second:?}");
        drop(first);
        DataDirLock::acquire(&dir).expect("lock released on drop");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn connect_addr_folds_wildcards_to_loopback() {
        let mut config = Config::default();
        config.cluster.listen = String::from("0.0.0.0:8081");
        config.cluster.advertise_addr = None;
        // No advertise override: the cluster listener address folds to loopback.
        assert_eq!(connect_addr(&config), "127.0.0.1:8081");

        config.cluster.advertise_addr = Some(String::from("cache-a:9000"));
        assert_eq!(connect_addr(&config), "cache-a:9000");
    }
}
