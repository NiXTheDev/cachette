//! Plan task 46 acceptance: the offline ops surface + `cluster status`.
//!
//! Every subcommand is driven as a real process (`cachette <subcommand>`) over
//! a fixture data directory, so the tests cover argument parsing, the
//! data-dir lock, output, and exit codes end to end:
//!
//! * `verify` exits non-zero and names a corrupted entry.
//! * `cache list --json` / `cache prune [--dry-run]` inspect and evict.
//! * `gc` runs one reaper pass and sweeps an old orphan blob.
//! * `doctor` exits 0 on a good fixture and non-zero on a bad config.
//! * `token mint` prints the `Forgejo-Cache-*` header values.
//! * `cluster status` reads the live member table from a running server.
//! * the offline commands refuse while a live server holds the data-dir lock.

use std::io::Cursor;
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime};

use cachette::storage::ByteStream;
use cachette::storage::StorageBackend;
use cachette::storage::fs::FsStorage;

const BIN: &str = env!("CARGO_BIN_EXE_cachette");
const SECRET: &str = "test-secret-0123456789abcdef";

/// Self-cleaning unique temp directory.
struct TestDir(PathBuf);

impl TestDir {
    fn new(tag: &str) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "cachette-ops-{tag}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("temp dir");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Build a small current-thread runtime for fixture seeding (the ops commands
/// themselves build their own; nothing here runs inside another runtime).
fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(future)
}

/// Write a serve/ops config into `dir` and return its path.
fn write_config(dir: &Path, listen: &str, cluster: bool) -> PathBuf {
    write_config_body(dir, &base_config(dir, listen, cluster))
}

/// Write an arbitrary config body into `dir/cachette.toml`.
fn write_config_body(dir: &Path, body: &str) -> PathBuf {
    let path = dir.join("cachette.toml");
    std::fs::write(&path, body).expect("write config");
    path
}

/// A minimal config with `storage.fs.path = <dir>/data`.
fn base_config(dir: &Path, listen: &str, cluster: bool) -> String {
    let data = dir.join("data");
    let cluster = if cluster {
        "\n[cluster]\nenabled = true\nmdns = false\n"
    } else {
        ""
    };
    format!(
        "[server]\nlisten = \"{listen}\"\n\n[storage.fs]\npath = '{data}'\nmin_free = \"1MiB\"\n\n[auth]\nsecret = \"{SECRET}\"\n{cluster}",
        data = data.display()
    )
}

fn data_dir(dir: &Path) -> PathBuf {
    dir.join("data")
}

/// Seed one finalized entry with `bytes` directly through the FS backend.
fn seed_entry(data: &Path, key: &str, bytes: &[u8]) {
    block_on(async {
        let storage = FsStorage::open(data).expect("open storage");
        let stream: ByteStream<'static> = Box::pin(Cursor::new(bytes.to_vec()));
        storage.put_stream(key, stream).await.expect("put");
        storage.finalize(key).await.expect("finalize");
    });
}

/// Run `cachette <args> --config <cfg>` and return (exit code, stdout+stderr).
fn run_cli(config: &Path, args: &[&str]) -> (i32, String) {
    let output = Command::new(BIN)
        .args(args)
        .arg("--config")
        .arg(config)
        .env("RUST_LOG", "warn")
        .output()
        .expect("spawn cachette");
    let mut combined = String::from_utf8_lossy(&output.stdout).into_owned();
    combined.push_str(&String::from_utf8_lossy(&output.stderr));
    (output.status.code().unwrap_or(-1), combined)
}

/// A free loopback port (bind, read, drop — a tiny race that CI tolerates).
fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    listener.local_addr().expect("local addr").port()
}

/// A running server child process, killed on drop.
struct Server {
    child: Child,
}

impl Server {
    /// Spawn the real binary against `config` and wait for its listener.
    fn start(config: &Path, port: u16) -> Self {
        let mut child = Command::new(BIN)
            .arg("--config")
            .arg(config)
            .env("RUST_LOG", "warn")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn server");
        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline {
            if TcpStream::connect(("127.0.0.1", port)).is_ok() {
                return Self { child };
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        // Reap the process before failing so no zombie is left behind.
        let _ = child.kill();
        let _ = child.wait();
        panic!("server did not start listening on {port}");
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The single blob file under `<data>/blobs`.
fn sole_blob(data: &Path) -> PathBuf {
    let dir = data.join("blobs");
    let mut blobs: Vec<PathBuf> = std::fs::read_dir(&dir)
        .expect("read blobs")
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "blob"))
        .collect();
    assert_eq!(blobs.len(), 1, "expected one blob, got {blobs:?}");
    blobs.pop().expect("one blob")
}

#[test]
fn verify_exits_zero_then_names_a_corrupted_entry() {
    let dir = TestDir::new("verify");
    let data = data_dir(dir.path());
    seed_entry(&data, "artifact-key", b"the original bytes");
    let config = write_config(dir.path(), "127.0.0.1:0", false);

    let (code, out) = run_cli(&config, &["verify"]);
    assert_eq!(code, 0, "intact entry verifies: {out}");
    assert!(out.contains("0 need attention"), "{out}");

    // Flip one byte in the only blob: same size, different content.
    let blob = sole_blob(&data);
    let mut bytes = std::fs::read(&blob).expect("read blob");
    bytes[0] ^= 0xff;
    std::fs::write(&blob, &bytes).expect("corrupt blob");

    let (code, out) = run_cli(&config, &["verify"]);
    assert_eq!(code, 1, "corrupt entry fails verify: {out}");
    assert!(out.contains("artifact-key"), "names the entry: {out}");
    assert!(out.contains("digest-mismatch"), "{out}");
}

#[test]
fn cache_list_json_then_prune_dry_run_and_delete() {
    let dir = TestDir::new("cache");
    let data = data_dir(dir.path());
    seed_entry(&data, "keep-me", b"fresh");
    seed_entry(&data, "prune-me", b"stale");
    // Age only `prune-me` (entry_id order is key-hashed, so age by key).
    let conn = rusqlite::Connection::open(data.join("cachette.sqlite3")).expect("open db");
    conn.execute(
        "UPDATE entries SET accessed_at = 1 WHERE key = 'prune-me'",
        [],
    )
    .expect("age one");

    let config = write_config(dir.path(), "127.0.0.1:0", false);

    let (code, out) = run_cli(&config, &["cache", "list", "--json"]);
    assert_eq!(code, 0, "{out}");
    let rows: serde_json::Value = serde_json::from_str(&out).expect("json list");
    let keys: Vec<String> = rows
        .as_array()
        .expect("array")
        .iter()
        .map(|row| row["key"].as_str().unwrap_or_default().to_owned())
        .collect();
    assert!(keys.contains(&String::from("keep-me")), "{out}");
    assert!(keys.contains(&String::from("prune-me")), "{out}");

    // Dry run reports without deleting.
    let (code, out) = run_cli(
        &config,
        &["cache", "prune", "--older-than", "1h", "--dry-run"],
    );
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("would prune 1 entry"), "{out}");
    assert!(out.contains("prune-me"), "{out}");

    // Real prune deletes the stale entry and keeps the fresh one.
    let (code, out) = run_cli(&config, &["cache", "prune", "--older-than", "1h"]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("pruned 1 entry"), "{out}");

    let (_, out) = run_cli(&config, &["cache", "list", "--json"]);
    let rows: serde_json::Value = serde_json::from_str(&out).expect("json list");
    let keys: Vec<String> = rows
        .as_array()
        .expect("array")
        .iter()
        .map(|row| row["key"].as_str().unwrap_or_default().to_owned())
        .collect();
    assert_eq!(keys, vec![String::from("keep-me")], "{out}");
}

#[test]
fn gc_sweeps_an_old_orphan_blob() {
    let dir = TestDir::new("gc");
    let data = data_dir(dir.path());
    // An empty data dir initializes storage, then we plant a rowless blob.
    block_on(async {
        let _ = FsStorage::open(&data).expect("open storage");
    });
    let blobs = data.join("blobs");
    let orphan = blobs.join(format!("{}.blob", "a".repeat(64)));
    std::fs::write(&orphan, b"orphan").expect("plant orphan");
    let old = SystemTime::now() - Duration::from_secs(7200);
    std::fs::OpenOptions::new()
        .write(true)
        .open(&orphan)
        .expect("open orphan")
        .set_modified(old)
        .expect("age orphan");

    let config = write_config(dir.path(), "127.0.0.1:0", false);
    let (code, out) = run_cli(&config, &["gc"]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("orphan_blobs_swept: 1"), "{out}");
    assert!(!orphan.exists(), "orphan swept");
}

#[test]
fn doctor_ok_on_fixture_and_nonzero_on_bad_config() {
    let dir = TestDir::new("doctor");
    let data = data_dir(dir.path());
    seed_entry(&data, "k", b"v");
    let config = write_config(dir.path(), "127.0.0.1:0", false);
    let (code, out) = run_cli(&config, &["doctor"]);
    assert_eq!(code, 0, "doctor ok: {out}");
    assert!(out.contains("config: ok"), "{out}");
    assert!(out.contains("data dir: writable"), "{out}");
    assert!(out.contains("sqlite: ok"), "{out}");
    assert!(out.contains("identity: ok"), "{out}");

    // A bad config never reaches the doctor body: `config::load` fails first.
    let bad = TestDir::new("doctor-bad");
    let bad_config = write_config_body(bad.path(), "[server]\nlisten = \"nonsense\"\n");
    let (code, out) = run_cli(&bad_config, &["doctor"]);
    assert_ne!(code, 0, "bad config exits non-zero: {out}");
}

#[test]
fn identity_rotate_keeps_the_fingerprint_and_rewrites_only_the_certificate() {
    let dir = TestDir::new("rotate");
    let config = write_config(dir.path(), "127.0.0.1:0", false);

    // Bare `identity` mints the pair and prints fingerprint + cert path.
    let (code, out) = run_cli(&config, &["identity"]);
    assert_eq!(code, 0, "{out}");
    let fingerprint = header_value(&out, "fingerprint").expect("fingerprint line");
    let cert_path = PathBuf::from(header_value(&out, "cert_path").expect("cert_path line"));
    let key_path = cert_path.join("key.pem");
    let cert_before = std::fs::read(cert_path.join("cert.pem")).expect("cert bytes");
    let key_before = std::fs::read(&key_path).expect("key bytes");

    let (code, out) = run_cli(&config, &["identity", "rotate"]);
    assert_eq!(code, 0, "rotate ok: {out}");
    assert!(
        out.contains(&format!("fingerprint: {fingerprint}")),
        "fingerprint unchanged: {out}"
    );
    assert!(out.contains("certificate renewed"), "{out}");
    assert_eq!(
        std::fs::read(&key_path).expect("key bytes"),
        key_before,
        "key file untouched"
    );
    assert_ne!(
        std::fs::read(cert_path.join("cert.pem")).expect("cert bytes"),
        cert_before,
        "certificate rewritten"
    );

    // A missing identity is a hard error (exit 2) and is NOT minted: a fresh
    // key would change the pinned fingerprint.
    let fresh = TestDir::new("rotate-missing");
    let fresh_config = write_config(fresh.path(), "127.0.0.1:0", false);
    let (code, out) = run_cli(&fresh_config, &["identity", "rotate"]);
    assert_eq!(code, 2, "missing identity exits 2: {out}");
    assert!(out.contains("is missing"), "{out}");
    assert!(
        !fresh.path().join("data").join("identity").exists(),
        "no identity minted: {out}"
    );
}

#[test]
fn token_mint_prints_headers() {
    let dir = TestDir::new("token");
    let config = write_config(dir.path(), "127.0.0.1:0", false);

    let (code, out) = run_cli(
        &config,
        &["token", "mint", "--scope", "read", "--repo", "o/r"],
    );
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("forgejo-cache-repo: o/r"), "{out}");
    assert!(out.contains("forgejo-cache-runnumber: 0"), "{out}");
    assert!(out.contains("forgejo-cache-timestamp: "), "{out}");
    assert!(
        !out.contains("forgejo-cache-writeisolationkey"),
        "read scope: {out}"
    );
    let mac = header_value(&out, "forgejo-cache-mac").expect("mac present");
    assert_eq!(mac.len(), 64, "hex sha256 mac: {mac}");
    assert!(mac.chars().all(|c| c.is_ascii_hexdigit()), "{mac}");

    // `write` scope adds a non-empty write-isolation key.
    let (code, out) = run_cli(
        &config,
        &["token", "mint", "--scope", "write", "--repo", "o/r"],
    );
    assert_eq!(code, 0, "{out}");
    assert!(
        out.contains("forgejo-cache-writeisolationkey: o/r"),
        "write scope: {out}"
    );
}

fn header_value(output: &str, name: &str) -> Option<String> {
    output
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{name}: ")))
        .map(str::to_owned)
}

#[test]
fn cluster_status_reads_the_running_server() {
    let dir = TestDir::new("cluster");
    let data = data_dir(dir.path());
    // Pre-create the identity so we can assert on its fingerprint.
    block_on(async {
        let _ = FsStorage::open(&data).expect("open storage");
    });
    let port = free_port();
    let config = write_config(dir.path(), &format!("127.0.0.1:{port}"), true);
    let server = Server::start(&config, port);

    let (code, out) = run_cli(&config, &["cluster", "status"]);
    assert_eq!(code, 0, "cluster status ok: {out}");
    assert!(out.contains("node: "), "{out}");
    // The table always renders a summary; the exact membership is cluster state,
    // not this subcommand's contract.
    assert!(out.contains("peer"), "{out}");
    drop(server);
}

#[test]
fn offline_commands_refuse_while_the_server_holds_the_lock() {
    let dir = TestDir::new("locked");
    let data = data_dir(dir.path());
    seed_entry(&data, "k", b"v");
    let port = free_port();
    let config = write_config(dir.path(), &format!("127.0.0.1:{port}"), false);
    let server = Server::start(&config, port);

    let (code, out) = run_cli(&config, &["verify"]);
    assert_eq!(code, 1, "verify refused: {out}");
    assert!(
        out.contains("in use by another cachette process"),
        "clear refusal message: {out}"
    );
    drop(server);
}
