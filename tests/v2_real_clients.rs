//! Plan task 27 — prove the v2 Twirp + Azure block-blob protocol against the
//! *real* client that GitHub's own `actions/cache` and `docker buildx
//! --cache-to type=gha` use: the vendored `github.com/tonistiigi/go-actions-cache`
//! `CacheService` client (the `gac` fixture), driven in v2 mode.
//!
//! The fixture is built from the pinned vendored reference under
//! `tests/fixtures/gac-reference/` (the same source task 22 exercised for v1)
//! and constructed with the upstream env-aware `actionscache.TryEnv`, so this
//! test exercises the real client's real v2 code path — not a re-implementation:
//!
//! * `CreateCacheEntry`      → `reserveV2` (mints the Azure `signed_upload_url`)
//! * Azure block-blob upload → `uploadV2` (`blockblob.UploadStream`)
//! * `FinalizeCacheEntryUpload` → `commitV2`
//! * `GetCacheEntryDownloadURL`  → `loadV2`
//! * Azure ranged download    → `downloadV2` (`blockblob.DownloadStream`)
//!
//! Two payload sizes are round-tripped so BOTH of the Azure SDK's upload paths
//! are exercised:
//!
//! * [`LARGE_PAYLOAD_BYTES`] (5 MiB, > one 1 MiB block) → `comp=block` staging
//!   plus `comp=blocklist` commit (the XML is sent in the request BODY), and
//! * [`SMALL_PAYLOAD_BYTES`] (64 KiB, < one block) → the SDK's one-shot
//!   "Put Blob" path (a bare `PUT`, no `comp`).
//!
//! Both must restore byte-identically (sha256). A never-saved key must be a
//! clean v2 miss (exit 0, `result=miss`, no panic). Finally a raw
//! `x-ms-range` GET proves the Azure range contract the SDK relies on:
//! `bytes=1000-1099` → 206 with the exact slice and `Content-Range`.
//!
//! The test starts ONE in-process cachette router (the same
//! `cachette::routes::router` the binary serves) in `auth.mode = "merge"` with
//! the fixture token `tok-a` plus a self-minted JWT. The JWT is required
//! because the Go client calls `jwt.ParseUnverified` in `New` and rejects any
//! token without `ac`/`exp`/`nbf` claims; it is registered as a static token so
//! the server accepts it too. Payloads are generated at run time and never
//! committed. Missing prerequisites (`go`) fail the test; it never skips.

use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cachette::auth::{AuthPolicy, jwt, urls};
use cachette::config::AuthMode;
use cachette::routes;
use cachette::state::AppState;
use cachette::storage::fs::FsStorage;
use serde_json::Value;
use sha2::{Digest, Sha256};

/// The plan's fixture bearer token (also the toolkit's `ACTIONS_RUNTIME_TOKEN`).
const FIXTURE_TOKEN: &str = "tok-a";
/// HMAC secret for the fixture; also the v2 signed-URL secret.
const FIXTURE_SECRET: &str = "task-27-fixture-secret-0123456789abcdef";
/// 5 MiB: larger than the Azure SDK's 1 MiB block, so `UploadStream` stages
/// blocks and commits a block list.
const LARGE_PAYLOAD_BYTES: usize = 5 * 1024 * 1024;
/// 64 KiB: smaller than one block, so the SDK takes its one-shot Put Blob path.
const SMALL_PAYLOAD_BYTES: usize = 64 * 1024;
/// Offset/length for the raw `x-ms-range` conformance probe (non-zero offset is
/// the case that silently corrupts if the server ignores `x-ms-range`).
const RANGE_OFFSET: usize = 1000;
const RANGE_LEN: usize = 100;

const LARGE_KEY: &str = "cachette-task27-large";
const SMALL_KEY: &str = "cachette-task27-small";
const MISS_KEY: &str = "cachette-task27-never-saved";

/// A scratch directory removed on drop.
struct Scratch {
    root: PathBuf,
}

impl Scratch {
    fn new(tag: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let mut root = std::env::temp_dir();
        root.push(format!("cachette-t27-{tag}-{}-{nanos}", std::process::id()));
        fs::create_dir_all(&root).expect("create scratch dir");
        Self { root }
    }

    fn path(&self) -> &Path {
        &self.root
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// One captured client invocation.
struct Observed {
    code: i32,
    stdout: String,
    stderr: String,
}

impl Observed {
    /// The last `__CACHETTE_JSON__{...}` marker the fixture printed.
    fn marker(&self) -> Option<Value> {
        self.stdout.lines().rev().find_map(|line| {
            line.trim()
                .strip_prefix("__CACHETTE_JSON__")
                .and_then(|json| serde_json::from_str::<Value>(json).ok())
        })
    }

    fn field(&self, key: &str) -> Option<String> {
        self.marker()
            .and_then(|value| value.get(key).and_then(|v| v.as_str()).map(str::to_owned))
    }

    fn result(&self) -> Option<String> {
        self.field("result")
    }

    fn transcript(&self) -> String {
        format!(
            "exit code: {}\n--- stdout ---\n{}--- stderr ---\n{}",
            self.code, self.stdout, self.stderr
        )
    }
}

/// A raw HTTP/1.1 response captured by [`raw_get`].
struct Probe {
    status: u16,
    content_range: Option<String>,
    body: Vec<u8>,
}

impl Probe {
    fn transcript(&self) -> String {
        format!(
            "HTTP status: {}\nContent-Range: {}\nbody bytes: {}",
            self.status,
            self.content_range.as_deref().unwrap_or("<none>"),
            self.body.len()
        )
    }
}

/// Everything the scenario run observed.
struct Outcome {
    endpoint: String,
    large_input_sha: String,
    small_input_sha: String,
    large_miss: Observed,
    large_save: Observed,
    large_restore: Observed,
    small_save: Observed,
    small_restore: Observed,
    ranged_probe: Probe,
    expected_range_slice: Vec<u8>,
}

impl Outcome {
    fn steps(&self) -> [(&'static str, &Observed); 5] {
        [
            ("v2 miss (never-saved key)", &self.large_miss),
            ("v2 save (5 MiB: block + blocklist)", &self.large_save),
            ("v2 restore (5 MiB)", &self.large_restore),
            ("v2 save (64 KiB: Put Blob)", &self.small_save),
            ("v2 restore (64 KiB)", &self.small_restore),
        ]
    }

    fn report(&self) {
        eprintln!("\n============ task 27 · v2 real-client transcripts ============");
        eprintln!("server endpoint: {}", self.endpoint);
        eprintln!(
            "client: vendored go-actions-cache CacheService v2 \
             (ACTIONS_CACHE_SERVICE_V2=true)"
        );
        for (label, observed) in self.steps() {
            eprintln!("\n### {label}\n{}", observed.transcript());
        }
        eprintln!(
            "\n### raw x-ms-range GET (bytes={RANGE_OFFSET}-{})",
            RANGE_OFFSET + RANGE_LEN - 1
        );
        eprintln!("{}", self.ranged_probe.transcript());
        eprintln!("\n--- sha256 ---");
        eprintln!("large input    : {}", self.large_input_sha);
        eprintln!(
            "large restored : {}",
            self.large_restore.field("sha256").unwrap_or_default()
        );
        eprintln!("small input    : {}", self.small_input_sha);
        eprintln!(
            "small restored : {}",
            self.small_restore.field("sha256").unwrap_or_default()
        );
        eprintln!("==============================================================\n");
    }

    /// Strict acceptance: both payloads round-trip byte-identically through the
    /// real v2 client, the miss is clean, and the Azure range contract holds.
    fn assert_byte_identical(&self) {
        assert_eq!(
            self.large_miss.code,
            0,
            "v2 miss must exit cleanly\n{}",
            self.large_miss.transcript()
        );
        assert_eq!(
            self.large_miss.result().as_deref(),
            Some("miss"),
            "v2 miss on an unsaved key\n{}",
            self.large_miss.transcript()
        );

        for (label, saved, restored) in [
            (
                "large (block + blocklist)",
                &self.large_save,
                &self.large_restore,
            ),
            ("small (Put Blob)", &self.small_save, &self.small_restore),
        ] {
            assert_eq!(
                saved.result().as_deref(),
                Some("saved"),
                "v2 {label} save\n{}",
                saved.transcript()
            );
            assert_eq!(
                restored.result().as_deref(),
                Some("restored"),
                "v2 {label} restore\n{}",
                restored.transcript()
            );
        }

        assert_eq!(
            self.large_restore.field("sha256").as_deref(),
            Some(self.large_input_sha.as_str()),
            "v2 large restore must be byte-identical\n{}",
            self.large_restore.transcript()
        );
        assert_eq!(
            self.small_restore.field("sha256").as_deref(),
            Some(self.small_input_sha.as_str()),
            "v2 small restore must be byte-identical\n{}",
            self.small_restore.transcript()
        );

        assert_eq!(
            self.ranged_probe.status,
            206,
            "x-ms-range GET must be a partial response\n{}",
            self.ranged_probe.transcript()
        );
        assert_eq!(
            self.ranged_probe.body,
            self.expected_range_slice,
            "x-ms-range slice must match the source bytes\n{}",
            self.ranged_probe.transcript()
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v2_real_clients_byte_identical_round_trip() {
    // Never skip silently: this test's whole purpose is to prove the v2
    // contract against the real client, so a missing `go` is a hard failure.
    let outcome = run_scenarios()
        .await
        .expect("v2 real-client prerequisites (go) must be available");
    outcome.report();
    outcome.assert_byte_identical();
}

async fn run_scenarios() -> Result<Outcome, String> {
    let go = which("go").ok_or_else(|| String::from("`go` not found on PATH"))?;

    let fixtures = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures");

    let scratch = Scratch::new("clients");
    let storage_dir = scratch.path().join("storage");
    let work = scratch.path().join("work");
    fs::create_dir_all(&storage_dir).map_err(|e| format!("create storage dir: {e}"))?;
    fs::create_dir_all(&work).map_err(|e| format!("create work dir: {e}"))?;

    let gac_bin = scratch.path().join("gac.exe");
    build_go_fixture(&go, &fixtures.join("gac"), &gac_bin)?;

    let jwt = jwt::mint(FIXTURE_SECRET, "[]", 3600, now_secs());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| format!("bind loopback listener: {e}"))?;
    let addr = listener
        .local_addr()
        .map_err(|e| format!("read listener address: {e}"))?;
    let base = format!("http://{addr}/");

    let state = fixture_state(&storage_dir, &jwt, &base);
    let app = routes::router(state);
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let large_payload = work.join("large-payload.bin");
    make_payload(&large_payload, LARGE_PAYLOAD_BYTES);
    let large_input_sha = sha256_file(&large_payload);
    let large_bytes = fs::read(&large_payload).map_err(|e| format!("read large payload: {e}"))?;
    let expected_range_slice = large_bytes[RANGE_OFFSET..RANGE_OFFSET + RANGE_LEN].to_vec();

    let small_payload = work.join("small-payload.bin");
    make_payload(&small_payload, SMALL_PAYLOAD_BYTES);
    let small_input_sha = sha256_file(&small_payload);

    let large_restored = work.join("large-restored.bin");
    let small_restored = work.join("small-restored.bin");
    let large_payload_arg = large_payload.to_string_lossy().into_owned();
    let small_payload_arg = small_payload.to_string_lossy().into_owned();
    let large_restored_arg = large_restored.to_string_lossy().into_owned();
    let small_restored_arg = small_restored.to_string_lossy().into_owned();

    let large_miss = run(&mut go_v2_command(
        &gac_bin,
        &["miss", MISS_KEY],
        &work,
        &base,
        &jwt,
    ));
    let large_save = run(&mut go_v2_command(
        &gac_bin,
        &["save", LARGE_KEY, &large_payload_arg],
        &work,
        &base,
        &jwt,
    ));
    let large_restore = run(&mut go_v2_command(
        &gac_bin,
        &["restore", LARGE_KEY, &large_restored_arg],
        &work,
        &base,
        &jwt,
    ));
    let small_save = run(&mut go_v2_command(
        &gac_bin,
        &["save", SMALL_KEY, &small_payload_arg],
        &work,
        &base,
        &jwt,
    ));
    let small_restore = run(&mut go_v2_command(
        &gac_bin,
        &["restore", SMALL_KEY, &small_restored_arg],
        &work,
        &base,
        &jwt,
    ));

    // Probe the Azure range contract directly: a correctly-signed artifact URL
    // with `x-ms-range: bytes=1000-1099` (what `blockblob.DownloadStream` sends
    // for a non-zero offset) must return 206 + the exact slice.
    let artifact_path = format!("/v2/artifacts/{LARGE_KEY}");
    let signed = urls::mint(&artifact_path, LARGE_KEY, FIXTURE_SECRET, 600, now_secs());
    let ranged_probe = raw_get(
        addr,
        &format!("{artifact_path}{}", signed.query()),
        &[(
            "x-ms-range",
            &format!("bytes={RANGE_OFFSET}-{}", RANGE_OFFSET + RANGE_LEN - 1),
        )],
    );

    server.abort();
    let _ = server.await;

    Ok(Outcome {
        endpoint: base,
        large_input_sha,
        small_input_sha,
        large_miss,
        large_save,
        large_restore,
        small_save,
        small_restore,
        ranged_probe,
        expected_range_slice,
    })
}

/// Build the fixture `AppState`: real `FsStorage`, `merge` auth, `tok-a` + the
/// minted JWT as static tokens, and the absolute external host the v2 signed
/// upload/download URLs are prefixed with.
fn fixture_state(storage_dir: &Path, jwt: &str, base: &str) -> AppState {
    let storage = FsStorage::open(storage_dir).expect("open fs storage");
    let mut state = AppState::new();
    state.storage = Some(Arc::new(storage));
    state.external_url = Some(base.trim_end_matches('/').to_owned());
    state.set_auth(AuthPolicy {
        mode: AuthMode::Merge,
        secret: Some(FIXTURE_SECRET.to_owned()),
        hmac_max_age_seconds: 600,
        static_tokens: vec![FIXTURE_TOKEN.to_owned(), jwt.to_owned()],
        cluster_enabled: false,
    });
    state
}

/// The v2 real-client command: the same fixture as task 22's v1 run, but with
/// the environment selecting the `CacheService` (v2) protocol.
fn go_v2_command(binary: &Path, args: &[&str], cwd: &Path, base: &str, token: &str) -> Command {
    let mut cmd = Command::new(binary);
    cmd.args(args);
    cmd.current_dir(cwd);
    cmd.env("ACTIONS_CACHE_SERVICE_V2", "true");
    cmd.env("ACTIONS_RESULTS_URL", base);
    // Harmless under v2 (the client reads ACTIONS_RESULTS_URL); set so a stray
    // ACTIONS_CACHE_API_FORCE_VERSION in the ambient env cannot flip the mode.
    cmd.env("ACTIONS_CACHE_URL", base);
    cmd.env_remove("ACTIONS_CACHE_API_FORCE_VERSION");
    cmd.env("ACTIONS_RUNTIME_TOKEN", token);
    cmd
}

fn run(cmd: &mut Command) -> Observed {
    let output = cmd.output().expect("spawn fixture process");
    Observed {
        code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

/// Issue a bare HTTP/1.1 `GET` with extra headers and capture status,
/// `Content-Range`, and raw body bytes. The v2 artifact GET carries no bearer
/// token, so this mirrors exactly what the Azure SDK's download path sends.
fn raw_get(addr: SocketAddr, target_with_query: &str, extra: &[(&str, &str)]) -> Probe {
    let mut stream = TcpStream::connect(addr).expect("connect to fixture server");
    stream.set_read_timeout(Some(Duration::from_secs(30))).ok();
    let mut request = format!(
        "GET {target_with_query} HTTP/1.1\r\nHost: {addr}\r\nAccept: */*\r\nConnection: close\r\n"
    );
    for (name, value) in extra {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("\r\n");
    stream
        .write_all(request.as_bytes())
        .expect("write raw request");
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).expect("read raw response");
    let split = bytes.windows(4).position(|window| window == b"\r\n\r\n");
    let (head, body) = match split {
        Some(idx) => (&bytes[..idx], bytes[idx + 4..].to_vec()),
        None => (&bytes[..], Vec::new()),
    };
    let head = String::from_utf8_lossy(head).into_owned();
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    let content_range = head.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("content-range")
            .then(|| value.trim().to_owned())
    });
    Probe {
        status,
        content_range,
        body,
    }
}

/// Compile the Go fixture against the vendored reference into `out`.
fn build_go_fixture(go: &Path, gac_dir: &Path, out: &Path) -> Result<(), String> {
    let output = Command::new(go)
        .arg("build")
        .arg("-o")
        .arg(out)
        .arg(".")
        .current_dir(gac_dir)
        .output()
        .map_err(|e| format!("spawn `go build`: {e}"))?;
    if output.status.success() {
        return Ok(());
    }
    Err(format!(
        "`go build` failed in {}:\n{}\n{}",
        gac_dir.display(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    ))
}

/// Current Unix time in seconds (the test crate cannot reach `auth::now_secs`).
fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs() as i64
}

/// Generate a deterministic-but-non-repeating payload of `size` bytes.
fn make_payload(path: &Path, size: usize) {
    let mut file = fs::File::create(path).expect("create payload");
    let mut buf = vec![0u8; 1 << 20];
    let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut left = size;
    while left > 0 {
        let take = left.min(buf.len());
        for byte in &mut buf[..take] {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *byte = (state >> 24) as u8;
        }
        file.write_all(&buf[..take]).expect("write payload");
        left -= take;
    }
    file.flush().expect("flush payload");
}

fn sha256_file(path: &Path) -> String {
    let mut file = fs::File::open(path).expect("open payload");
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buf).expect("read payload");
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
    }
    hex(&hasher.finalize())
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

/// Locate an executable on PATH (honouring `PATHEXT` on Windows).
fn which(program: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    let extensions: Vec<String> = if cfg!(windows) {
        std::env::var("PATHEXT")
            .unwrap_or_else(|_| String::from(".COM;.EXE;.BAT;.CMD"))
            .split(';')
            .filter(|ext| !ext.is_empty())
            .map(str::to_ascii_lowercase)
            .collect()
    } else {
        vec![String::new()]
    };
    for dir in std::env::split_paths(&path) {
        let direct = dir.join(program);
        if direct.is_file() {
            return Some(direct);
        }
        for ext in &extensions {
            if ext.is_empty() {
                continue;
            }
            let candidate = dir.join(format!("{program}{ext}"));
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}
