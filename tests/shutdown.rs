//! Plan task 34 acceptance: orphan sweep + graceful shutdown.
//!
//! (a) `orphan_blob_is_swept_by_reaper_tick`: a rowless blob older than the
//!     1h grace is removed by one reaper pass.
//! (b) `graceful_shutdown_exits_zero_with_drain_line`: the real binary, driven
//!     by the documented test-only trigger (`CACHETTE_TEST_SHUTDOWN_AFTER_MS`),
//!     drains and exits 0 within the 10s grace, logging the drain line.
//! (c) `startup_sweep_removes_rowless_blob_before_serving`: a rowless blob
//!     planted before boot is gone once the readiness line appears.
//! (d) `restart_after_shutdown_leaves_no_half_row`: after a graceful shutdown
//!     the storage reopens cleanly with no visible entries and no scratch.
//!
//! The test-only trigger is used because Windows console Ctrl+C delivery to a
//! child needs `GenerateConsoleCtrlEvent` against a shared console process
//! group (impractical in CI); the real SIGINT/SIGTERM handlers stay wired in
//! `main.rs`. On POSIX the `sigterm_triggers_graceful_shutdown` test exercises
//! the real `kill -TERM` path.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use cachette::storage::StorageBackend;
use cachette::storage::eviction::Reaper;
use cachette::storage::fs::FsStorage;

const SECRET: &str = "test-secret-0123456789abcdef";
const DRAIN_LINE: &str = "shutdown: draining in-flight transfers";

/// Self-cleaning unique temp directory (mirrors `tests/auth.rs`).
struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let unique = format!(
            "cachette-shutdown-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let path = std::env::temp_dir().join(unique);
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

/// Write a minimal serve config pointing storage at `<dir>/data`.
fn write_config(dir: &TestDir) -> PathBuf {
    let data = dir.path().join("data");
    std::fs::create_dir_all(&data).expect("data dir");
    let config = format!(
        "[server]\nlisten = \"127.0.0.1:0\"\n\n[storage.fs]\npath = '{data}'\n\n[auth]\nsecret = \"{SECRET}\"\n",
        data = data.display()
    );
    let path = dir.path().join("cachette.toml");
    std::fs::write(&path, config).expect("write config");
    path
}

/// Plant a rowless blob with an mtime `age_secs` in the past.
fn plant_rowless_blob(data_dir: &Path, id: &str, age_secs: u64) {
    let blobs = data_dir.join("blobs");
    std::fs::create_dir_all(&blobs).expect("blobs dir");
    let path = blobs.join(format!("{id}.blob"));
    std::fs::write(&path, b"orphan").expect("write blob");
    let mtime = SystemTime::now() - Duration::from_secs(age_secs);
    std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .expect("open blob")
        .set_modified(mtime)
        .expect("set mtime");
}

/// Spawn the real binary against `config_path` and wait for it to exit,
/// bounded by the 10s grace window. `test_trigger_ms` arms the documented
/// test-only shutdown trigger.
async fn run_binary(config_path: &Path, test_trigger_ms: Option<u64>) -> std::process::Output {
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_cachette"));
    command
        .arg("--config")
        .arg(config_path)
        .env("CACHETTE__AUTH__SECRET", SECRET)
        .env("RUST_LOG", "info")
        .kill_on_drop(true)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(ms) = test_trigger_ms {
        command.env("CACHETTE_TEST_SHUTDOWN_AFTER_MS", ms.to_string());
    }
    let child = command.spawn().expect("spawn cachette");
    tokio::time::timeout(Duration::from_secs(10), child.wait_with_output())
        .await
        .expect("process exits within 10s")
        .expect("wait succeeds")
}

fn combined_output(output: &std::process::Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[tokio::test]
async fn orphan_blob_is_swept_by_reaper_tick() {
    let dir = TestDir::new();
    let data = dir.path().join("data");
    std::fs::create_dir_all(&data).expect("data dir");
    let storage = FsStorage::open(&data).expect("storage opens");
    let id = "a".repeat(64);
    plant_rowless_blob(&data, &id, 7200);
    let blob = data.join("blobs").join(format!("{id}.blob"));
    assert!(blob.exists(), "blob planted");

    let reaper = Reaper::new(Duration::from_secs(3600));
    let report = reaper.sweep_once(&storage).await.expect("sweep runs");
    assert_eq!(report.orphan_blobs_swept, 1, "one orphan swept");
    assert!(!blob.exists(), "rowless blob removed");
}

#[tokio::test]
async fn graceful_shutdown_exits_zero_with_drain_line() {
    let dir = TestDir::new();
    let config_path = write_config(&dir);
    let output = run_binary(&config_path, Some(600)).await;
    assert_eq!(output.status.code(), Some(0), "graceful shutdown exits 0");
    let combined = combined_output(&output);
    assert!(
        combined.contains(DRAIN_LINE),
        "drain line present: {combined}"
    );
}

#[tokio::test]
async fn startup_sweep_removes_rowless_blob_before_serving() {
    let dir = TestDir::new();
    let config_path = write_config(&dir);
    let data = dir.path().join("data");
    let id = "b".repeat(64);
    plant_rowless_blob(&data, &id, 7200);
    let blob = data.join("blobs").join(format!("{id}.blob"));
    assert!(blob.exists(), "blob planted");

    let output = run_binary(&config_path, Some(600)).await;
    assert_eq!(output.status.code(), Some(0), "clean exit");
    assert!(
        !blob.exists(),
        "startup sweep removed the rowless blob before serving"
    );
}

#[tokio::test]
async fn restart_after_shutdown_leaves_no_half_row() {
    let dir = TestDir::new();
    let config_path = write_config(&dir);
    let output = run_binary(&config_path, Some(600)).await;
    assert_eq!(output.status.code(), Some(0), "clean exit");

    let data = dir.path().join("data");
    let storage = FsStorage::open(&data).expect("storage reopens");
    let entries = storage.list().await.expect("list");
    assert!(
        entries.is_empty(),
        "no half-rows after restart: {entries:?}"
    );
    let scratch: Vec<_> = std::fs::read_dir(data.join("tmp"))
        .map(|read| read.flatten().collect())
        .unwrap_or_default();
    assert!(scratch.is_empty(), "no scratch files: {scratch:?}");
}

#[cfg(unix)]
#[tokio::test]
async fn sigterm_triggers_graceful_shutdown() {
    use tokio::io::AsyncBufReadExt;
    use tokio::io::AsyncReadExt;

    let dir = TestDir::new();
    let config_path = write_config(&dir);
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_cachette"))
        .arg("--config")
        .arg(&config_path)
        .env("CACHETTE__AUTH__SECRET", SECRET)
        .env("RUST_LOG", "info")
        .kill_on_drop(true)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn cachette");

    let stdout = child.stdout.take().expect("stdout piped");
    let mut reader = tokio::io::BufReader::new(stdout);
    // Startup INFO logs share stdout with the readiness gate (`logging::init`
    // writes to stdout), so with `RUST_LOG=info` the identity log can precede
    // the marker: scan lines instead of assuming the first one is readiness.
    // Keep the lines we consumed so the drain-line assertion below still sees
    // them.
    let mut transcript = String::new();
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut line = String::new();
        loop {
            line.clear();
            let read = reader.read_line(&mut line).await.expect("read line");
            assert!(read != 0, "stdout closed before the readiness line");
            transcript.push_str(&line);
            if line.contains("cachette listening on") {
                return;
            }
        }
    })
    .await
    .expect("readiness within 10s");

    let pid = child.id().expect("child pid");
    let killed = std::process::Command::new("kill")
        .arg("-TERM")
        .arg(pid.to_string())
        .status()
        .expect("kill runs");
    assert!(killed.success(), "kill -TERM delivered");

    // `child.stdout` was `take()`n above, so `wait_with_output()` would hand
    // back EMPTY pipes and could never observe the drain line. Drain the
    // remainder of the same reader, then reap the child and assert the exit.
    let drain = async {
        let mut rest = String::new();
        reader
            .read_to_string(&mut rest)
            .await
            .expect("read remaining stdout");
        (reader, rest)
    };
    let (reader, rest) = tokio::time::timeout(Duration::from_secs(10), drain)
        .await
        .expect("drain line within 10s");
    transcript.push_str(&rest);
    let _ = reader;

    let status = tokio::time::timeout(Duration::from_secs(10), child.wait())
        .await
        .expect("exits within 10s")
        .expect("wait");
    assert_eq!(status.code(), Some(0), "SIGTERM drains and exits 0");
    assert!(
        transcript.contains(DRAIN_LINE),
        "drain line present: {transcript}"
    );
}
