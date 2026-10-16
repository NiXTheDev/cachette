//! Plan task 52 acceptance (v1.1): the idle-footprint budget.
//!
//! Starts the real binary with a default config (cluster disabled) on an
//! ephemeral loopback port, waits for the readiness line, then samples the
//! child's CPU time and RSS across an idle window and asserts the budget:
//! ~0% CPU (no busy-poll, zero-delay timer, unbounded background task, or
//! per-request task outliving its request) and bounded RSS (the storage stays
//! SQLite-backed; no whole index is held in memory).
//!
//! Sampling is per-OS and dependency-free:
//!   * Windows: `GetProcessTimes` + `GetProcessMemoryInfo` (kernel32/psapi).
//!   * Linux:   `/proc/<pid>/stat` (utime+stime) + `/proc/<pid>/status` (VmRSS).
//!
//! The window defaults to 10s so the pre-commit gate stays quick; set
//! `CACHETTE_IDLE_WINDOW_SECS=60` to reproduce the plan's full 60s window (CI /
//! T53 should). The measured numbers are printed (`-- --nocapture` shows them
//! for a passing run; libtest always shows them on failure).

#![cfg(any(windows, target_os = "linux"))]

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const SECRET: &str = "test-secret-0123456789abcdef";
/// The unconditional readiness line `main.rs` prints once the listener binds.
const READY: &str = "cachette listening on";

/// Plan T52 RSS budget: idle RSS must stay under 256 MiB. Deliberately loose
/// (the observed figure is single-digit MiB) so a shared CI runner cannot make
/// it flap, while still catching an index held in memory or a leaked map.
const RSS_BUDGET_BYTES: u64 = 256 * 1024 * 1024;
/// Sanity floor: a live server cannot idle at ~0 RSS. Catches a broken sampler
/// rather than a real regression.
const RSS_FLOOR_BYTES: u64 = 1024 * 1024;
/// Idle CPU allowance over the window as a fraction of one core. A busy-poll or
/// zero-delay timer burns ~1.0 (100%); the real idle figure measures 0.0.
const CPU_BUDGET_FRACTION: f64 = 0.01;
/// Let the runtime reach steady state after readiness before sampling.
const SETTLE: Duration = Duration::from_secs(2);
const DEFAULT_WINDOW_SECS: u64 = 10;

/// Self-cleaning unique temp directory (mirrors `tests/shutdown.rs`).
struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let unique = format!(
            "cachette-idle-{}-{}",
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

/// Write a minimal serve config: every knob at its default except the two that
/// have no default (storage path, auth secret) and an ephemeral port.
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

/// Kills the server when the test ends, however it ends.
struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Drains a child pipe into a shared buffer on a background thread. Draining
/// (rather than reading only the readiness line) matters: a full pipe buffer
/// would block the server on its next log write and fake a 0% CPU reading.
fn drain<R: Read + Send + 'static>(pipe: R, sink: Arc<Mutex<String>>) {
    std::thread::spawn(move || {
        let mut reader = pipe;
        let mut buf = [0u8; 4096];
        loop {
            match reader.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if let Ok(mut text) = sink.lock() {
                        text.push_str(&String::from_utf8_lossy(&buf[..n]));
                    }
                }
            }
        }
    });
}

/// Spawn the binary and block until it prints the readiness line (bounded).
fn start(config: &Path) -> Server {
    let mut child = Command::new(env!("CARGO_BIN_EXE_cachette"))
        .arg("--config")
        .arg(config)
        .env("RUST_LOG", "info")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn cachette");

    let stdout = child.stdout.take().expect("stdout piped");
    let stderr = child.stderr.take().expect("stderr piped");
    let log = Arc::new(Mutex::new(String::new()));
    drain(stdout, Arc::clone(&log));
    drain(stderr, Arc::clone(&log));

    let mut server = Server(child);
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        {
            let text = log.lock().expect("log lock");
            if text.contains(READY) {
                return server;
            }
        }
        if let Ok(Some(status)) = server.0.try_wait() {
            panic!(
                "server exited before readiness ({status}):\n{}",
                log.lock().expect("log lock")
            );
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!(
        "readiness line '{READY}' not seen within 15s:\n{}",
        log.lock().expect("log lock")
    );
}

/// A CPU-time and resident-set reading of the child process.
#[derive(Clone, Copy, Debug)]
struct Footprint {
    cpu: Duration,
    rss: u64,
}

#[cfg(windows)]
mod probe {
    use super::Footprint;
    use std::ffi::c_void;
    use std::os::windows::io::AsRawHandle;
    use std::process::Child;
    use std::time::Duration;

    #[repr(C)]
    struct FileTime {
        low: u32,
        high: u32,
    }

    impl FileTime {
        fn ticks(&self) -> u64 {
            (u64::from(self.high) << 32) | u64::from(self.low)
        }
    }

    #[repr(C)]
    struct MemoryCounters {
        cb: u32,
        page_fault_count: u32,
        peak_working_set_size: usize,
        working_set_size: usize,
        quota_peak_paged_pool_usage: usize,
        quota_paged_pool_usage: usize,
        quota_peak_non_paged_pool_usage: usize,
        quota_non_paged_pool_usage: usize,
        pagefile_usage: usize,
        peak_pagefile_usage: usize,
    }

    // `K32GetProcessMemoryInfo` is the kernel32 forwarder for
    // `GetProcessMemoryInfo`, so no extra import library is needed.
    unsafe extern "system" {
        fn GetProcessTimes(
            process: *mut c_void,
            creation: *mut FileTime,
            exit: *mut FileTime,
            kernel: *mut FileTime,
            user: *mut FileTime,
        ) -> i32;
        fn K32GetProcessMemoryInfo(
            process: *mut c_void,
            counters: *mut MemoryCounters,
            cb: u32,
        ) -> i32;
    }

    pub struct Probe {
        handle: *mut c_void,
    }

    impl Probe {
        pub fn new(child: &Child) -> Self {
            Self {
                handle: child.as_raw_handle(),
            }
        }

        pub fn sample(&self) -> Option<Footprint> {
            let mut creation = FileTime { low: 0, high: 0 };
            let mut exit = FileTime { low: 0, high: 0 };
            let mut kernel = FileTime { low: 0, high: 0 };
            let mut user = FileTime { low: 0, high: 0 };
            // SAFETY: `handle` is the live child handle (valid until reaped);
            // every out-param is an owned local of the correct layout.
            let times = unsafe {
                GetProcessTimes(
                    self.handle,
                    &mut creation,
                    &mut exit,
                    &mut kernel,
                    &mut user,
                )
            };
            if times == 0 {
                return None;
            }
            let mut counters = MemoryCounters {
                cb: std::mem::size_of::<MemoryCounters>() as u32,
                page_fault_count: 0,
                peak_working_set_size: 0,
                working_set_size: 0,
                quota_peak_paged_pool_usage: 0,
                quota_paged_pool_usage: 0,
                quota_peak_non_paged_pool_usage: 0,
                quota_non_paged_pool_usage: 0,
                pagefile_usage: 0,
                peak_pagefile_usage: 0,
            };
            // SAFETY: same live handle; `cb` is the size of the struct we pass.
            let ok = unsafe {
                K32GetProcessMemoryInfo(
                    self.handle,
                    &mut counters,
                    std::mem::size_of::<MemoryCounters>() as u32,
                )
            };
            if ok == 0 {
                return None;
            }
            Some(Footprint {
                // FILETIME is 100 ns units; kernel + user = total CPU time.
                cpu: Duration::from_nanos((kernel.ticks() + user.ticks()) * 100),
                rss: counters.working_set_size as u64,
            })
        }
    }
}

#[cfg(target_os = "linux")]
mod probe {
    use super::Footprint;
    use std::process::Child;
    use std::time::Duration;

    pub struct Probe {
        pid: u32,
    }

    impl Probe {
        pub fn new(child: &Child) -> Self {
            Self { pid: child.id() }
        }

        pub fn sample(&self) -> Option<Footprint> {
            let stat = std::fs::read_to_string(format!("/proc/{}/stat", self.pid)).ok()?;
            // `comm` (field 2) can contain spaces and parens, so split after the
            // final ')'. The tail then starts at field 3 (state).
            let tail = stat.rsplit_once(')')?.1;
            let fields: Vec<&str> = tail.split_whitespace().collect();
            // utime = field 14, stime = field 15 -> indices 11 and 12 here.
            let utime: u64 = fields.get(11)?.parse().ok()?;
            let stime: u64 = fields.get(12)?.parse().ok()?;
            let status = std::fs::read_to_string(format!("/proc/{}/status", self.pid)).ok()?;
            let rss_kb: u64 = status
                .lines()
                .find_map(|line| line.strip_prefix("VmRSS:"))?
                .split_whitespace()
                .next()?
                .parse()
                .ok()?;
            Some(Footprint {
                // USER_HZ is 100 on every mainstream Linux; the exact rate only
                // scales an idle baseline of zero, and a busy-poll blows past
                // the budget under any plausible rate.
                cpu: Duration::from_millis((utime + stime) * 10),
                rss: rss_kb * 1024,
            })
        }
    }
}

/// Idle window in seconds (`CACHETTE_IDLE_WINDOW_SECS`, default 10).
fn window() -> Duration {
    let secs = std::env::var("CACHETTE_IDLE_WINDOW_SECS")
        .ok()
        .and_then(|raw| raw.parse::<u64>().ok())
        .filter(|secs| *secs > 0)
        .unwrap_or(DEFAULT_WINDOW_SECS);
    Duration::from_secs(secs)
}

/// T52: with zero traffic the server must consume ~no CPU and hold bounded RSS
/// for the whole window.
#[test]
fn idle_footprint_stays_within_budget() {
    let dir = TestDir::new();
    let config = write_config(&dir);
    let server = start(&config);
    let probe = probe::Probe::new(&server.0);

    std::thread::sleep(SETTLE);
    let before = probe
        .sample()
        .expect("sample the server before the idle window");

    let window = window();
    let started = Instant::now();
    std::thread::sleep(window);
    let elapsed = started.elapsed();
    let after = probe
        .sample()
        .expect("sample the server after the idle window");

    let cpu = after.cpu.saturating_sub(before.cpu);
    let cpu_fraction = cpu.as_secs_f64() / elapsed.as_secs_f64();
    let mib = |bytes: u64| bytes as f64 / (1024.0 * 1024.0);
    println!(
        "idle window {:.1}s: cpu {} ms ({:.3}% of one core), rss {:.1} MiB (start {:.1} MiB)",
        elapsed.as_secs_f64(),
        cpu.as_millis(),
        cpu_fraction * 100.0,
        mib(after.rss),
        mib(before.rss),
    );

    assert!(
        after.rss >= RSS_FLOOR_BYTES,
        "sampler looks broken: idle rss {} B is below the {} B sanity floor",
        after.rss,
        RSS_FLOOR_BYTES
    );
    assert!(
        after.rss <= RSS_BUDGET_BYTES,
        "idle rss {} B ({:.1} MiB) exceeds the {} MiB budget (whole index held in memory?)",
        after.rss,
        mib(after.rss),
        RSS_BUDGET_BYTES / (1024 * 1024)
    );
    assert!(
        cpu_fraction < CPU_BUDGET_FRACTION,
        "idle cpu {:.3}% of one core over {:.1}s exceeds the {:.0}% budget \
         (busy-poll, zero-delay timer, or runaway background task?)",
        cpu_fraction * 100.0,
        elapsed.as_secs_f64(),
        CPU_BUDGET_FRACTION * 100.0
    );
}
