//! Plan task 45 acceptance: the v1 `PATCH` path streams request bodies
//! straight into storage instead of buffering each body in memory.
//!
//! Eight parallel 4 MiB `PATCH`es of one 32 MiB entry are driven in-process
//! through the real router, and this process's RSS is sampled while they are
//! in flight. Growth past one chunk means the request path is holding a
//! per-request copy again (the pre-task-45 shape was one 4 MiB buffer per
//! concurrent request).

#![cfg(any(windows, target_os = "linux"))]

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use axum::Router;
use axum::body::{Body, Bytes};
use axum::http::{Request, StatusCode};
use cachette::auth::AuthPolicy;
use cachette::config::AuthMode;
use cachette::routes;
use cachette::state::AppState;
use cachette::storage::StorageBackend;
use cachette::storage::fs::FsStorage;
use tower::ServiceExt;

const SECRET: &str = "test-secret-0123456789abcdef";
const TOKEN: &str = "v1-memory-token";
const KEY: &str = "memory-key";
/// One upload chunk (the toolkit's chunk size).
const CHUNK: usize = 4 * 1024 * 1024;
/// Chunks uploaded concurrently against one reservation.
const PARALLEL: usize = 8;

static DIR_SEQ: AtomicU64 = AtomicU64::new(0);

/// Unique temp directory per test, removed on drop (no tempfile dep).
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let seq = DIR_SEQ.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "cachette-request-memory-{}-{seq}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("create test dir");
        Self(path)
    }

    fn path(&self) -> &PathBuf {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Resident set size of the CURRENT process.
fn rss_bytes() -> Option<u64> {
    #[cfg(windows)]
    {
        use std::ffi::c_void;

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
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn GetCurrentProcess() -> *mut c_void;
            fn K32GetProcessMemoryInfo(
                process: *mut c_void,
                counters: *mut MemoryCounters,
                cb: u32,
            ) -> i32;
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
        // SAFETY: the pseudo-handle is always valid; `cb` matches the struct.
        let ok = unsafe {
            K32GetProcessMemoryInfo(
                GetCurrentProcess(),
                &mut counters,
                std::mem::size_of::<MemoryCounters>() as u32,
            )
        };
        (ok != 0).then_some(counters.working_set_size as u64)
    }
    #[cfg(target_os = "linux")]
    {
        let status = std::fs::read_to_string("/proc/self/status").ok()?;
        let rss_kb: u64 = status
            .lines()
            .find_map(|line| line.strip_prefix("VmRSS:"))?
            .split_whitespace()
            .next()?
            .parse()
            .ok()?;
        Some(rss_kb * 1024)
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        None
    }
}

fn app_state(storage: Arc<FsStorage>) -> AppState {
    let mut state = AppState::new();
    state.storage = Some(storage);
    state.auth = Arc::new(AuthPolicy {
        mode: AuthMode::Bearer,
        secret: Some(SECRET.to_owned()),
        hmac_max_age_seconds: 600,
        static_tokens: vec![TOKEN.to_owned()],
        cluster_enabled: false,
    });
    state
}

/// Reserve a fresh reservation and return its numeric `cacheId`.
async fn reserve(app: &axum::Router, key: &str) -> String {
    let response = app
        .clone()
        .oneshot(
            Request::post("/_apis/artifactcache/caches")
                .header("authorization", format!("Bearer {TOKEN}"))
                .header("content-type", "application/json")
                .body(Body::from(format!(r#"{{"key":"{key}","version":"1"}}"#)))
                .expect("reserve request builds"),
        )
        .await
        .expect("router responds");
    assert_eq!(response.status(), StatusCode::OK, "reserve {key}");
    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .expect("reserve body reads");
    serde_json::from_slice::<serde_json::Value>(&body).expect("reserve body is JSON")["cacheId"]
        .as_u64()
        .expect("cacheId number")
        .to_string()
}

/// PATCH `PARALLEL` consecutive 4 MiB chunks concurrently and return statuses.
async fn patch_parallel(app: &Router, cache_id: &str, payload: Bytes) -> Vec<StatusCode> {
    let mut tasks = Vec::with_capacity(PARALLEL);
    for i in 0..PARALLEL {
        let app = app.clone();
        let payload = payload.clone();
        let cache_id = cache_id.to_owned();
        tasks.push(tokio::spawn(async move {
            let start = i as u64 * CHUNK as u64;
            let end = start + CHUNK as u64 - 1;
            let response = app
                .oneshot(
                    Request::patch(format!("/_apis/artifactcache/caches/{cache_id}"))
                        .header("authorization", format!("Bearer {TOKEN}"))
                        .header("content-range", format!("bytes {start}-{end}/*"))
                        .body(Body::from(payload))
                        .expect("patch request builds"),
                )
                .await
                .expect("router responds");
            response.status()
        }));
    }
    let mut statuses = Vec::with_capacity(PARALLEL);
    for task in tasks {
        statuses.push(task.await.expect("patch task joins"));
    }
    statuses
}

/// Commit `PARALLEL` chunks of `CHUNK` bytes and return the reply status.
async fn commit(app: &Router, cache_id: &str) -> StatusCode {
    let size = PARALLEL as u64 * CHUNK as u64;
    let response = app
        .clone()
        .oneshot(
            Request::post(format!("/_apis/artifactcache/caches/{cache_id}"))
                .header("authorization", format!("Bearer {TOKEN}"))
                .header("content-type", "application/json")
                .body(Body::from(format!(r#"{{"size":{size}}}"#)))
                .expect("commit request builds"),
        )
        .await
        .expect("router responds");
    response.status()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn parallel_chunk_uploads_stream_without_chunk_sized_buffers() {
    let dir = TempDir::new();
    let storage = Arc::new(FsStorage::open(dir.path()).expect("fs storage opens"));
    let app = routes::router(app_state(Arc::clone(&storage)));
    let payload: Bytes = Bytes::from(vec![0x5a_u8; CHUNK]);

    // Warm-up round: allocator/runtime growth is excluded from the baseline.
    let warm_id = reserve(&app, "warmup-key").await;
    for status in patch_parallel(&app, &warm_id, payload.clone()).await {
        assert_eq!(status, StatusCode::NO_CONTENT, "warm-up chunk");
    }
    assert_eq!(commit(&app, &warm_id).await, StatusCode::NO_CONTENT);

    let cache_id = reserve(&app, KEY).await;
    let baseline = rss_bytes();
    let uploads = {
        let app = app.clone();
        let payload = payload.clone();
        let cache_id = cache_id.clone();
        tokio::spawn(async move { patch_parallel(&app, &cache_id, payload).await })
    };

    // Sample RSS while the uploads are in flight.
    let mut peak = baseline;
    while !uploads.is_finished() {
        tokio::time::sleep(Duration::from_millis(1)).await;
        if let Some(rss) = rss_bytes() {
            peak = Some(peak.unwrap_or(0).max(rss));
        }
    }
    let statuses = uploads.await.expect("upload task joins");
    assert_eq!(statuses.len(), PARALLEL);
    for status in statuses {
        assert_eq!(status, StatusCode::NO_CONTENT, "parallel chunk");
    }

    // Streaming delivered every byte: the entry commits at the full size.
    assert_eq!(commit(&app, &cache_id).await, StatusCode::NO_CONTENT);
    let stat = storage.stat(KEY).await.expect("stat").expect("visible");
    assert_eq!(stat.size, PARALLEL as u64 * CHUNK as u64);

    let (Some(baseline), Some(rss)) = (baseline, rss_bytes()) else {
        return;
    };
    let growth = rss.max(peak.unwrap_or(0)).saturating_sub(baseline);
    println!("T45 rss growth: {growth} bytes (baseline {baseline}, peak {peak:?})");
    assert!(
        growth < CHUNK as u64,
        "8 concurrent {CHUNK}-byte PATCHes grew RSS by {growth} bytes \
         (baseline {baseline}, peak {peak:?}); the request path must not keep \
         one chunk-sized buffer per concurrent request"
    );
}
