//! Plan task 35 acceptance: metrics counters + structured logging.
//!
//! (a) `metrics_endpoint_exposes_six_counters_after_one_save`: drive a full v1
//!     save (reserve → PATCH → commit) through the real router, then `GET
//!     /metrics` and assert the six counters are present with sane (non-zero
//!     where a save implies it) values, and that they move between two curls.
//! (b) `json_log_format_writes_parseable_lines`: boot the real binary with
//!     `[log] format="json"` and `[log] file=<path>`, then parse every line of
//!     the written log file as JSON.
//! (c) `log_file_is_created_with_parent_dirs`: covered by the logging unit
//!     test; here we assert the binary honors `[log] file` end-to-end.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use cachette::auth::AuthPolicy;
use cachette::config::AuthMode;
use cachette::routes;
use cachette::state::AppState;
use cachette::storage::MemoryStorage;
use tower::ServiceExt;

const SECRET: &str = "test-secret-0123456789abcdef";
const TOKEN: &str = "v1-metrics-token";

/// Self-cleaning unique temp directory (mirrors `tests/shutdown.rs`).
struct TestDir(PathBuf);

impl TestDir {
    fn new(tag: &str) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let unique = format!(
            "cachette-{tag}-{}-{}",
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

fn metrics_state() -> AppState {
    let storage = Arc::new(MemoryStorage::new());
    let mut state = AppState::new();
    state.storage = Some(storage);
    state.set_auth(AuthPolicy {
        mode: AuthMode::Bearer,
        secret: Some(SECRET.to_owned()),
        hmac_max_age_seconds: 600,
        static_tokens: vec![TOKEN.to_owned()],
        cluster_enabled: false,
    });
    state
}

async fn call(app: &Router, request: Request<Body>) -> (StatusCode, Vec<u8>) {
    let response = app.clone().oneshot(request).await.expect("router responds");
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("response body")
        .to_vec();
    (status, body)
}

fn request(method: &str, path: &str, body: impl AsRef<[u8]>) -> Request<Body> {
    let bytes = body.as_ref().to_vec();
    let len = bytes.len();
    Request::builder()
        .method(method)
        .uri(path)
        .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CONTENT_LENGTH, len)
        .body(Body::from(bytes))
        .expect("request builds")
}

/// Drive one full v1 save; returns nothing but leaves counters moved.
async fn one_save(app: &Router) {
    let (status, body) = call(
        app,
        request(
            "POST",
            "/_apis/artifactcache/caches",
            r#"{"key":"metrics-key","version":"v1"}"#,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "reserve ok: {}", body_str(&body));
    let reserve: serde_json::Value = serde_json::from_slice(&body).expect("reserve json");
    let cache_id = reserve["cacheId"].as_u64().expect("cacheId");
    let payload = b"metrics payload body";

    let end = payload.len() - 1;
    let (status, _) = call(
        app,
        Request::builder()
            .method("PATCH")
            .uri(format!("/_apis/artifactcache/caches/{cache_id}"))
            .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
            .header(header::CONTENT_RANGE, format!("bytes 0-{end}/*"))
            .header(header::CONTENT_LENGTH, payload.len())
            .body(Body::from(payload.to_vec()))
            .expect("patch builds"),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "patch stores chunk");

    let (status, _) = call(
        app,
        request(
            "POST",
            &format!("/_apis/artifactcache/caches/{cache_id}"),
            format!(r#"{{"size":{}}}"#, payload.len()),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "commit publishes entry");
}

fn body_str(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[tokio::test]
async fn metrics_endpoint_exposes_six_counters_after_one_save() {
    let state = metrics_state();
    let metrics = state.metrics.clone();
    let app = routes::router(state);

    one_save(&app).await;

    let (status, body) = call(
        &app,
        Request::builder()
            .method("GET")
            .uri("/metrics")
            .body(Body::empty())
            .expect("metrics builds"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "/metrics is 200");
    let text = body_str(&body);

    // All six counters present.
    for name in [
        "cachette_requests_total",
        "cachette_bytes_in",
        "cachette_bytes_out",
        "cachette_evictions_total",
        "cachette_reservations_active",
        "cachette_storage_used_bytes",
    ] {
        assert!(text.contains(name), "/metrics mentions {name}:\n{text}");
    }

    // The save path moved the request + byte counters, and the storage gauge
    // reflects the committed entry.
    assert!(
        text.contains("cachette_requests_total{route=\"v1\",code=\"200\"}"),
        "v1 200 counted:\n{text}"
    );
    assert!(
        text.contains("cachette_requests_total{route=\"v1\",code=\"204\"}"),
        "v1 204 counted:\n{text}"
    );
    assert!(
        !text.contains("cachette_bytes_in 0"),
        "bytes_in moved:\n{text}"
    );
    assert!(
        !text.contains("cachette_bytes_out 0"),
        "bytes_out moved:\n{text}"
    );
    assert!(
        !text.contains("cachette_storage_used_bytes 0"),
        "storage_used moved:\n{text}"
    );
    // Reservations balanced back to 0 after commit.
    assert!(
        text.contains("cachette_reservations_active 0"),
        "reservations balanced:\n{text}"
    );

    // Happy-path QA: counters move between two curls.
    let before = metrics.render_prometheus();
    let (_, _) = call(
        &app,
        Request::builder()
            .method("GET")
            .uri("/health")
            .body(Body::empty())
            .expect("health builds"),
    )
    .await;
    let after = metrics.render_prometheus();
    assert_ne!(before, after, "a second request moves the counters");
}

#[tokio::test]
async fn json_log_format_writes_parseable_lines() {
    let dir = TestDir::new("metrics-jsonlog");
    let data = dir.path().join("data");
    std::fs::create_dir_all(&data).expect("data dir");
    let log_path = dir.path().join("logs").join("cachette.log");
    let config = format!(
        "[server]\nlisten = \"127.0.0.1:0\"\n\n[storage.fs]\npath = '{data}'\n\n[auth]\nsecret = \"{SECRET}\"\n\n[log]\nformat = \"json\"\nfile = '{log}'\n",
        data = data.display(),
        log = log_path.display()
    );
    let config_path = dir.path().join("cachette.toml");
    std::fs::write(&config_path, config).expect("write config");

    let output = tokio::process::Command::new(env!("CARGO_BIN_EXE_cachette"))
        .arg("--config")
        .arg(&config_path)
        .env("CACHETTE__AUTH__SECRET", SECRET)
        .env("CACHETTE_TEST_SHUTDOWN_AFTER_MS", "300")
        .env("RUST_LOG", "info")
        .kill_on_drop(true)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .expect("run cachette");
    assert_eq!(output.status.code(), Some(0), "clean exit");

    let body = std::fs::read_to_string(&log_path).expect("log file written");
    assert!(!body.trim().is_empty(), "log file has content");
    for line in body.lines().filter(|line| !line.trim().is_empty()) {
        let parsed: serde_json::Value =
            serde_json::from_str(line).unwrap_or_else(|err| panic!("line is JSON ({err}): {line}"));
        assert!(parsed.is_object(), "each line is a JSON object: {line}");
    }
    assert!(
        body.contains("listener ready"),
        "startup log line present in the file:\n{body}"
    );
}
