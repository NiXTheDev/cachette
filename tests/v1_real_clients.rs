//! Plan task 22 â€” prove the v1 artifactcache protocol against the *real*
//! clients that GitHub Actions runners use in production:
//!
//! * the GitHub Actions toolkit â€” `@actions/cache` v3 (the `toolkit.js`
//!   fixture drives its public `saveCache` / `restoreCache` API), and
//! * the vendored `github.com/tonistiigi/go-actions-cache` client (the `gac`
//!   fixture, the library `docker buildx --cache-to type=gha` uses).
//!
//! The test starts ONE in-process cachette router (the same
//! `cachette::routes::router` the binary serves) in `auth.mode = "merge"` with
//! the plan's fixture token `tok-a` plus a self-minted JWT. The JWT is needed
//! because the Go client calls `jwt.ParseUnverified` in `New` and rejects any
//! token that does not carry `ac`/`exp`/`nbf` claims (`tok-a` is not
//! JWT-shaped); the token is registered as a static token so the server accepts
//! it too. The scenarios are:
//!
//! * toolkit: `miss â†’ save â†’ lookup(hit) â†’ restore`
//! * go-actions-cache: `miss â†’ cross-client find â†’ cross-client restore â†’ save
//!   â†’ restore`
//! * a bare, correctly-signed `GET` of the artifact URL with no bearer token,
//!   exactly what both clients' download path issues.
//!
//! All payloads are generated at run time and never committed. Missing
//! prerequisites (`node`, `npm`, `go`) fail the test; it never silently skips.
//!
//! # The two tests
//!
//! * [`v1_real_clients_characterize_contract`] runs by default. It asserts
//!   everything the server does correctly and tolerates the known server gaps
//!   (below) so a failure is always accompanied by the full client transcripts.
//! * [`v1_real_clients_byte_identical_round_trip`] is the strict acceptance
//!   test from the plan: both clients must round-trip byte-identically and the
//!   signed `archiveLocation` alone must authorize the download.
//!
//! # v1 server compliance fixed for these real clients
//!
//! The real clients surfaced three v1 server defects, all now fixed:
//!
//! 1. `find` returns an **absolute** `archiveLocation`: it prefixes
//!    `AppState::external_url`, which production resolves from `listen`. The
//!    toolkit runs `new URL(archiveLocation)` and the Go client issues the GET
//!    verbatim, so a bare relative path breaks both.
//! 2. `reserve` returns a **numeric** `cacheId` (GitHub's v1 contract). The Go
//!    client unmarshals it into `ReserveCacheResp.CacheID int` (and rejects 0),
//!    and the JS toolkit round-trips it through a `number`, so the id is kept
//!    within `Number.MAX_SAFE_INTEGER`.
//! 3. `auth::require_auth` exempts the `/_apis/artifactcache/artifacts/`
//!    download path: both clients follow `archiveLocation` with **no**
//!    `Authorization` header, so the signed URL alone authorizes the download
//!    (`v1::download` still enforces the signature).

use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use cachette::auth::{AuthPolicy, jwt, urls};
use cachette::config::AuthMode;
use cachette::routes;
use cachette::state::AppState;
use cachette::storage::fs::FsStorage;
use serde_json::Value;
use sha2::{Digest, Sha256};

/// The plan's fixture bearer token (the toolkit's `ACTIONS_RUNTIME_TOKEN`).
const FIXTURE_TOKEN: &str = "tok-a";
/// HMAC secret for the fixture; also the v1 signed-URL secret.
const FIXTURE_SECRET: &str = "task-22-fixture-secret-0123456789abcdef";
/// Toolkit payload: 8 MiB, i.e. 2 x the toolkit's 4 MiB upload chunk.
const TOOLKIT_PAYLOAD_BYTES: usize = 8 * 1024 * 1024;
/// Go payload: 64 MiB, matching the plan's 32 MiB x 4 chunk scenario.
const GO_PAYLOAD_BYTES: usize = 64 * 1024 * 1024;

const TOOLKIT_KEY: &str = "cachette-task22-toolkit";
const GO_KEY: &str = "cachette-task22-go";
const MISS_KEY: &str = "cachette-task22-never-saved";

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
        root.push(format!("cachette-t22-{tag}-{}-{nanos}", std::process::id()));
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

/// A raw HTTP/1.1 response captured by [`raw_get`].
struct Probe {
    status: u16,
    body: String,
}

impl Probe {
    fn transcript(&self) -> String {
        format!("HTTP status: {}\nbody: {}", self.status, self.body)
    }

    fn is_unauthorized(&self) -> bool {
        self.status == 401
    }

    fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
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

    fn warnings(&self) -> Vec<String> {
        self.marker()
            .and_then(|value| value.get("warnings").and_then(|w| w.as_array()).cloned())
            .map(|items| {
                items
                    .iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn transcript(&self) -> String {
        format!(
            "exit code: {}\n--- stdout ---\n{}--- stderr ---\n{}",
            self.code, self.stdout, self.stderr
        )
    }
}

/// Everything the scenario run observed.
struct Outcome {
    endpoint: String,
    toolkit_input_sha: String,
    go_input_sha: String,
    toolkit_miss: Observed,
    toolkit_save: Observed,
    toolkit_lookup: Observed,
    toolkit_restore: Observed,
    go_miss: Observed,
    go_cross_client_load: Observed,
    go_cross_client_restore: Observed,
    go_save: Observed,
    go_restore: Observed,
    unauth_artifact_probe: Probe,
}

impl Outcome {
    fn steps(&self) -> [(&'static str, &Observed); 9] {
        [
            ("toolkit miss (never-saved key)", &self.toolkit_miss),
            ("toolkit save (8 MiB archive)", &self.toolkit_save),
            (
                "toolkit lookup (find only, no download)",
                &self.toolkit_lookup,
            ),
            (
                "toolkit restore (download + extract)",
                &self.toolkit_restore,
            ),
            ("go-actions-cache miss (never-saved key)", &self.go_miss),
            (
                "go-actions-cache load of the toolkit key (cross-client find)",
                &self.go_cross_client_load,
            ),
            (
                "go-actions-cache restore of the toolkit key (cross-client download)",
                &self.go_cross_client_restore,
            ),
            ("go-actions-cache save (64 MiB)", &self.go_save),
            ("go-actions-cache restore", &self.go_restore),
        ]
    }

    /// The v1 server gaps this run reproduced (empty when the server is correct).
    fn gaps(&self) -> Vec<&'static str> {
        let mut gaps = Vec::new();
        if self.toolkit_restore.result().as_deref() != Some("restored") {
            gaps.push("GAP 1a: `find` served a *relative* archiveLocation; the toolkit runs `new URL(...)` and aborts with `Invalid URL` before downloading.");
        }
        if self.go_cross_client_restore.result().as_deref() != Some("restored")
            && self.go_cross_client_restore.result().as_deref() != Some("miss")
        {
            gaps.push("GAP 1b: `find` served a *relative* archiveLocation; go-actions-cache GETs `ce.URL` verbatim and aborts with `unsupported protocol scheme \"\"`.");
        }
        if self.go_save.result().as_deref() != Some("saved") {
            gaps.push("GAP 2: `POST /caches` returned a 32-hex *string* cacheId; go-actions-cache unmarshals it into `ReserveCacheResp.CacheID int` and aborts.");
        }
        if self.go_restore.result().as_deref() == Some("error") {
            gaps.push("GAP 1c: go-actions-cache could not download the served archiveLocation.");
        }
        if self.unauth_artifact_probe.is_unauthorized() {
            gaps.push("GAP 3: the artifact download is gated by `require_auth`, so a bare GET (what both real clients issue) is rejected with 401 even when the archiveLocation is *correctly signed*.");
        }
        gaps
    }

    fn report(&self) {
        eprintln!("\n================= task 22 Â· v1 real-client transcripts =================");
        eprintln!("server endpoint: {}", self.endpoint);
        for (label, observed) in self.steps() {
            eprintln!("\n### {label}\n{}", observed.transcript());
        }
        eprintln!("\n### unauthenticated GET of a correctly-signed artifact URL");
        eprintln!("{}", self.unauth_artifact_probe.transcript());
        eprintln!("\n--- sha256 ---");
        eprintln!("toolkit input    : {}", self.toolkit_input_sha);
        eprintln!(
            "toolkit restored : {}",
            self.toolkit_restore.field("sha256").unwrap_or_default()
        );
        eprintln!("go input         : {}", self.go_input_sha);
        eprintln!(
            "go restored      : {}",
            self.go_restore.field("sha256").unwrap_or_default()
        );
        let gaps = self.gaps();
        if gaps.is_empty() {
            eprintln!("\nRESULT: both real clients completed a byte-identical v1 round trip.");
        } else {
            eprintln!(
                "\nRESULT: {} v1 server gap(s) reproduced with the real clients:",
                gaps.len()
            );
            for gap in gaps {
                eprintln!("  - {gap}");
            }
            eprintln!(
                "These are server defects (src/** is out of scope for task 22) and are REPORTED, not fixed."
            );
        }
        eprintln!("=======================================================================\n");
    }

    /// Tolerant contract check: assert everything the server does correctly and
    /// either a byte-identical round trip or the precise known gap.
    fn assert_contract(&self) {
        // 1. A miss on a never-saved key is clean: exit 0, no warning, no panic.
        assert_eq!(
            self.toolkit_miss.code,
            0,
            "toolkit miss must exit cleanly\n{}",
            self.toolkit_miss.transcript()
        );
        assert_eq!(
            self.toolkit_miss.result().as_deref(),
            Some("miss"),
            "toolkit miss on an unsaved key\n{}",
            self.toolkit_miss.transcript()
        );
        assert!(
            self.toolkit_miss.warnings().is_empty(),
            "a clean v1 miss must not warn\n{}",
            self.toolkit_miss.transcript()
        );

        // 2. The server accepts the toolkit's save.
        assert_eq!(
            self.toolkit_save.result().as_deref(),
            Some("saved"),
            "toolkit save must be accepted\n{}",
            self.toolkit_save.transcript()
        );

        // 3. find returns the saved entry (lookupOnly: no download involved).
        assert_eq!(
            self.toolkit_lookup.result().as_deref(),
            Some("hit"),
            "find must return the saved entry\n{}",
            self.toolkit_lookup.transcript()
        );

        // 4. The Go client sees a clean miss and, cross-client, the toolkit entry.
        assert_eq!(
            self.go_miss.code,
            0,
            "go miss must exit cleanly\n{}",
            self.go_miss.transcript()
        );
        assert_eq!(
            self.go_miss.result().as_deref(),
            Some("miss"),
            "go miss on an unsaved key\n{}",
            self.go_miss.transcript()
        );
        assert_eq!(
            self.go_cross_client_load.result().as_deref(),
            Some("hit"),
            "go-actions-cache must find the entry the toolkit saved\n{}",
            self.go_cross_client_load.transcript()
        );

        // 4b. Cross-client download: the Go client must be able to download the
        // entry the toolkit created, or reproduce the relative-URL gap. The two
        // clients use different archive formats (the toolkit stores tar.gz, the
        // Go client a raw blob), so only download *success* is asserted here â€”
        // never payload-byte equality.
        match self.go_cross_client_restore.result().as_deref() {
            Some("restored") => {}
            Some("error") => {
                let text = self
                    .go_cross_client_restore
                    .field("error")
                    .unwrap_or_default();
                assert!(
                    mentions_download_gap(&text),
                    "unexpected cross-client go restore failure:\n{text}\n{}",
                    self.go_cross_client_restore.transcript()
                );
            }
            other => panic!(
                "unexpected cross-client go restore result {other:?}\n{}",
                self.go_cross_client_restore.transcript()
            ),
        }

        // 5. Toolkit round trip: byte-identical, or the known download gap.
        if self.toolkit_restore.result().as_deref() == Some("restored") {
            assert_eq!(
                self.toolkit_restore.field("sha256").as_deref(),
                Some(self.toolkit_input_sha.as_str()),
                "toolkit restore must be byte-identical\n{}",
                self.toolkit_restore.transcript()
            );
        } else {
            assert_eq!(
                self.toolkit_restore.result().as_deref(),
                Some("miss"),
                "a hit whose download failed surfaces as a miss\n{}",
                self.toolkit_restore.transcript()
            );
            let warnings = self.toolkit_restore.warnings();
            assert!(
                !warnings.is_empty(),
                "a failed download must surface a core.warning\n{}",
                self.toolkit_restore.transcript()
            );
            let text = warnings.join("\n");
            assert!(
                mentions_download_gap(&text),
                "unexpected toolkit restore failure:\n{text}\n{}",
                self.toolkit_restore.transcript()
            );
        }

        // 6. Go round trip: byte-identical, or the known cacheId / download gap.
        if self.go_save.result().as_deref() == Some("saved") {
            match self.go_restore.result().as_deref() {
                Some("restored") => assert_eq!(
                    self.go_restore.field("sha256").as_deref(),
                    Some(self.go_input_sha.as_str()),
                    "go restore must be byte-identical\n{}",
                    self.go_restore.transcript()
                ),
                Some("error") => {
                    let text = self.go_restore.field("error").unwrap_or_default();
                    assert!(
                        mentions_download_gap(&text),
                        "unexpected go restore failure:\n{text}\n{}",
                        self.go_restore.transcript()
                    );
                }
                other => panic!(
                    "unexpected go restore result {other:?}\n{}",
                    self.go_restore.transcript()
                ),
            }
        } else {
            assert_eq!(
                self.go_save.result().as_deref(),
                Some("error"),
                "go save must either succeed or report an error\n{}",
                self.go_save.transcript()
            );
            let text = self.go_save.field("error").unwrap_or_default();
            assert!(
                text.contains("unmarshal") || text.contains("cacheID") || text.contains("int"),
                "unexpected go save failure:\n{text}\n{}",
                self.go_save.transcript()
            );
            // With save blocked there is no entry, so the restore is a clean miss.
            assert_eq!(
                self.go_restore.result().as_deref(),
                Some("miss"),
                "with save blocked the go restore must be a clean miss\n{}",
                self.go_restore.transcript()
            );
        }

        // 7. The artifact download must be authorized by the signed URL alone:
        // both real clients issue a bare GET carrying no bearer token. Accept
        // the current 401 gap or a successful download once `require_auth` stops
        // gating the artifact route.
        assert!(
            self.unauth_artifact_probe.is_unauthorized() || self.unauth_artifact_probe.is_success(),
            "unexpected unauthenticated artifact download response\n{}",
            self.unauth_artifact_probe.transcript()
        );
    }

    /// Strict plan-task-22 acceptance: both clients must round-trip byte-identically.
    fn assert_byte_identical(&self) {
        assert_eq!(
            self.toolkit_save.result().as_deref(),
            Some("saved"),
            "toolkit save\n{}",
            self.toolkit_save.transcript()
        );
        assert_eq!(
            self.toolkit_restore.result().as_deref(),
            Some("restored"),
            "toolkit restore must download\n{}",
            self.toolkit_restore.transcript()
        );
        assert_eq!(
            self.toolkit_restore.field("sha256").as_deref(),
            Some(self.toolkit_input_sha.as_str()),
            "toolkit restore must be byte-identical\n{}",
            self.toolkit_restore.transcript()
        );
        assert_eq!(
            self.go_save.result().as_deref(),
            Some("saved"),
            "go save\n{}",
            self.go_save.transcript()
        );
        assert_eq!(
            self.go_restore.result().as_deref(),
            Some("restored"),
            "go restore must download\n{}",
            self.go_restore.transcript()
        );
        assert_eq!(
            self.go_restore.field("sha256").as_deref(),
            Some(self.go_input_sha.as_str()),
            "go restore must be byte-identical\n{}",
            self.go_restore.transcript()
        );
        assert_eq!(
            self.go_cross_client_restore.result().as_deref(),
            Some("restored"),
            "go cross-client restore must download\n{}",
            self.go_cross_client_restore.transcript()
        );
        assert!(
            self.unauth_artifact_probe.is_success(),
            "the signed archiveLocation alone must authorize the download\n{}",
            self.unauth_artifact_probe.transcript()
        );
    }
}

/// Whether a failure text matches one of the known download gaps (relative URL
/// or the unauthenticated artifact download).
fn mentions_download_gap(text: &str) -> bool {
    const NEEDLES: &[&str] = &[
        "Invalid URL",
        "invalid URL",
        "unsupported protocol scheme",
        "Cache service responded with 401",
        "Unexpected HTTP response: 401",
        "Failed to restore",
        "invalid status response",
    ];
    NEEDLES.iter().any(|needle| text.contains(needle))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v1_real_clients_characterize_contract() {
    // Never skip silently: this test's whole purpose is to prove the contract
    // against the real clients, so missing prerequisites are a hard failure.
    let outcome = run_scenarios()
        .await
        .expect("v1 real-client prerequisites (node, npm and go) must be available");
    outcome.report();
    outcome.assert_contract();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v1_real_clients_byte_identical_round_trip() {
    let outcome = run_scenarios()
        .await
        .expect("v1 real-client prerequisites (node, npm and go) must be available");
    outcome.report();
    outcome.assert_byte_identical();
}

async fn run_scenarios() -> Result<Outcome, String> {
    let node = which("node").ok_or_else(|| String::from("`node` not found on PATH"))?;
    let go = which("go").ok_or_else(|| String::from("`go` not found on PATH"))?;

    let fixtures = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures");
    ensure_node_deps(&fixtures)?;

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

    let toolkit_payload = work.join("payload.bin");
    make_payload(&toolkit_payload, TOOLKIT_PAYLOAD_BYTES);
    let toolkit_input_sha = sha256_file(&toolkit_payload);

    let go_payload = work.join("go-payload.bin");
    make_payload(&go_payload, GO_PAYLOAD_BYTES);
    let go_input_sha = sha256_file(&go_payload);
    let go_restored = work.join("go-restored.bin");
    let go_restored_arg = go_restored.to_string_lossy().into_owned();
    let go_payload_arg = go_payload.to_string_lossy().into_owned();
    let go_cross_restored = work.join("go-cross-restored.bin");
    let go_cross_restored_arg = go_cross_restored.to_string_lossy().into_owned();

    let toolkit_js = fixtures.join("toolkit.js");

    let toolkit_miss = run(&mut node_command(
        &node,
        &toolkit_js,
        &["miss", MISS_KEY],
        &work,
        &base,
    ));
    let toolkit_save = run(&mut node_command(
        &node,
        &toolkit_js,
        &["save", TOOLKIT_KEY, "payload.bin"],
        &work,
        &base,
    ));
    let toolkit_lookup = run(&mut node_command(
        &node,
        &toolkit_js,
        &["lookup", TOOLKIT_KEY, "payload.bin"],
        &work,
        &base,
    ));

    let go_miss = run(&mut go_command(
        &gac_bin,
        &["miss", MISS_KEY],
        &work,
        &base,
        &jwt,
    ));
    let go_cross_client_load = run(&mut go_command(
        &gac_bin,
        &["miss", TOOLKIT_KEY],
        &work,
        &base,
        &jwt,
    ));
    let go_cross_client_restore = run(&mut go_command(
        &gac_bin,
        &["restore", TOOLKIT_KEY, &go_cross_restored_arg],
        &work,
        &base,
        &jwt,
    ));
    let go_save = run(&mut go_command(
        &gac_bin,
        &["save", GO_KEY, &go_payload_arg],
        &work,
        &base,
        &jwt,
    ));
    let go_restore = run(&mut go_command(
        &gac_bin,
        &["restore", GO_KEY, &go_restored_arg],
        &work,
        &base,
        &jwt,
    ));

    // Last: the toolkit restore deletes and must recreate `payload.bin`.
    let toolkit_restore = run(&mut node_command(
        &node,
        &toolkit_js,
        &["restore", TOOLKIT_KEY, "payload.bin"],
        &work,
        &base,
    ));

    // Probe the artifact route with a *correctly signed* URL but no bearer
    // token â€” exactly what both real clients' download path issues. If the
    // server answers 200 the signed URL alone authorizes the download; a 401
    // proves the global `require_auth` layer wrongly gates it.
    let artifact_path = format!("/_apis/artifactcache/artifacts/{TOOLKIT_KEY}");
    let signed = urls::mint(&artifact_path, TOOLKIT_KEY, FIXTURE_SECRET, 600, now_secs());
    let unauth_artifact_probe = raw_get(addr, &format!("{artifact_path}{}", signed.query()));

    server.abort();
    let _ = server.await;

    Ok(Outcome {
        endpoint: base,
        toolkit_input_sha,
        go_input_sha,
        toolkit_miss,
        toolkit_save,
        toolkit_lookup,
        toolkit_restore,
        go_miss,
        go_cross_client_load,
        go_cross_client_restore,
        go_save,
        go_restore,
        unauth_artifact_probe,
    })
}

/// Build the fixture `AppState`: real `FsStorage`, `merge` auth, `tok-a` + the
/// minted JWT as static tokens, and the (ignored by v1 `find`) absolute host.
fn fixture_state(storage_dir: &Path, jwt: &str, base: &str) -> AppState {
    let storage = FsStorage::open(storage_dir).expect("open fs storage");
    let mut state = AppState::new();
    state.storage = Some(Arc::new(storage));
    state.external_url = Some(base.trim_end_matches('/').to_owned());
    state.auth = Arc::new(AuthPolicy {
        mode: AuthMode::Merge,
        secret: Some(FIXTURE_SECRET.to_owned()),
        hmac_max_age_seconds: 600,
        static_tokens: vec![FIXTURE_TOKEN.to_owned(), jwt.to_owned()],
        cluster_enabled: false,
    });
    state
}

fn node_command(node: &Path, script: &Path, args: &[&str], cwd: &Path, base: &str) -> Command {
    let mut cmd = Command::new(node);
    cmd.arg(script);
    cmd.args(args);
    cmd.current_dir(cwd);
    cmd.env("ACTIONS_CACHE_URL", base);
    cmd.env("ACTIONS_RUNTIME_TOKEN", FIXTURE_TOKEN);
    cmd.env("ACTIONS_STEP_DEBUG", "false");
    // Git's GNU tar drives the toolkit archive and shells out to `gzip`; prepend
    // Git's usr/bin so both are found regardless of the ambient PATH.
    cmd.env("PATH", augmented_path());
    cmd.env_remove("GITHUB_WORKSPACE");
    cmd
}

fn go_command(binary: &Path, args: &[&str], cwd: &Path, base: &str, token: &str) -> Command {
    let mut cmd = Command::new(binary);
    cmd.args(args);
    cmd.current_dir(cwd);
    cmd.env("ACTIONS_CACHE_URL", base);
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

/// Issue a bare HTTP/1.1 `GET` with no `Authorization` header and capture the
/// status line + body. This mirrors what the real clients' artifact download
/// does (the toolkit's `HttpClient('actions/cache')` and go-actions-cache's
/// `Entry.Download` both send no bearer); it isolates the server's own auth
/// layer and is never a substitute for the real clients, which run above.
fn raw_get(addr: SocketAddr, target_with_query: &str) -> Probe {
    let mut stream = TcpStream::connect(addr).expect("connect to fixture server");
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(30)))
        .ok();
    let request = format!(
        "GET {target_with_query} HTTP/1.1\r\nHost: {addr}\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .expect("write raw request");
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).expect("read raw response");
    let split = bytes.windows(4).position(|window| window == b"\r\n\r\n");
    let (head, body) = match split {
        Some(idx) => (&bytes[..idx], &bytes[idx + 4..]),
        None => (&bytes[..], &[][..]),
    };
    let status = String::from_utf8_lossy(head)
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    let body = String::from_utf8_lossy(&body[..body.len().min(400)]).into_owned();
    Probe { status, body }
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

/// Ensure `@actions/cache` is installed under `tests/fixtures` (never committed).
fn ensure_node_deps(fixtures: &Path) -> Result<(), String> {
    let marker = fixtures
        .join("node_modules")
        .join("@actions")
        .join("cache")
        .join("package.json");
    if marker.is_file() {
        return Ok(());
    }
    let Some(npm) = which("npm") else {
        return Err(String::from(
            "`npm` not found and tests/fixtures/node_modules is absent; run `npm ci` in tests/fixtures",
        ));
    };
    let output = Command::new(&npm)
        .args(["ci", "--no-audit", "--no-fund"])
        .current_dir(fixtures)
        .output()
        .map_err(|e| format!("spawn `npm ci`: {e}"))?;
    if output.status.success() && marker.is_file() {
        return Ok(());
    }
    Err(format!(
        "`npm ci` failed in {}:\n{}\n{}",
        fixtures.display(),
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

/// PATH with Git's `usr/bin` (tar/gzip) prepended when present.
fn augmented_path() -> std::ffi::OsString {
    let mut parts: Vec<PathBuf> = Vec::new();
    if let Some(dir) = git_usr_bin() {
        parts.push(dir);
    }
    if let Some(existing) = std::env::var_os("PATH") {
        parts.extend(std::env::split_paths(&existing));
    }
    std::env::join_paths(parts).unwrap_or_default()
}

fn git_usr_bin() -> Option<PathBuf> {
    [
        PathBuf::from(r"C:\Program Files\Git\usr\bin"),
        PathBuf::from(r"C:\Program Files (x86)\Git\usr\bin"),
    ]
    .into_iter()
    .find(|dir| dir.join("gzip.exe").is_file())
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
