//! B4 probe logging proxy (plan task 27).
//!
//! A byte-preserving HTTP pass-through that records every request (method,
//! path, query, headers, body) and the upstream response status *before*
//! forwarding it to the cachette server. It exists to answer Metis B4: which
//! protocol does the real client actually speak to our server?
//!
//! The real client under test is `docker buildx --cache-to type=gha`, which
//! links `github.com/tonistiigi/go-actions-cache` — the same client a Forgejo
//! `act_runner` uses when `cache.external_server` is configured. Pointing
//! buildx's cache URL at this proxy makes buildkit's traffic observable.
//!
//! Usage (see `probe/run.ps1` for the full, reproducible driver):
//!
//! ```text
//! LOGPROXY_LISTEN=127.0.0.1:18080 \
//! UPSTREAM=https://127.0.0.1:18443 \
//! B4_LOG=<scratch>\logproxy.jsonl \
//! logproxy
//! ```
//!
//! `UPSTREAM` is required and must include the scheme. TLS verification of the
//! upstream is deliberately disabled: cachette mints a self-signed Ed25519
//! identity at first boot, so a fixture server needs no trust-store wiring.
//! This is a probe fixture, never a production component.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{HeaderMap, Method, Uri};
use axum::response::Response;
use serde_json::{Value, json};
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

/// Preview cap for request/response bodies recorded in the log.
const BODY_PREVIEW: usize = 4096;

/// Hop-by-hop headers are neither forwarded nor recorded as forwarded
/// (RFC 9110 §7.6.1); `content-length` is recomputed by the client.
fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name,
        "connection"
            | "keep-alive"
            | "proxy-connection"
            | "transfer-encoding"
            | "te"
            | "trailer"
            | "upgrade"
            | "host"
            | "content-length"
    )
}

struct Cfg {
    upstream: String,
    client: reqwest::Client,
    log: Mutex<Option<tokio::fs::File>>,
    seq: AtomicU64,
}

/// Append one JSON record to the log file (the authoritative artifact) and
/// echo it to stdout so the driving script shows live progress.
async fn emit(cfg: &Cfg, value: Value) {
    let line = format!("{value}\n");
    {
        let mut guard = cfg.log.lock().await;
        if let Some(file) = guard.as_mut() {
            let _ = file.write_all(line.as_bytes()).await;
            let _ = file.flush().await;
        }
    }
    print!("{line}");
}

/// Record a body inline when it is small text; otherwise only the length.
/// This makes reserve/finalize payloads visible without bloating the log with
/// binary cache chunks.
fn body_preview(bytes: &Bytes) -> Value {
    if bytes.is_empty() {
        return Value::Null;
    }
    if bytes.len() > BODY_PREVIEW {
        return Value::String(format!("<{} bytes, not shown>", bytes.len()));
    }
    match std::str::from_utf8(bytes) {
        Ok(text) => Value::String(text.to_owned()),
        Err(_) => Value::String(format!("<{} binary bytes>", bytes.len())),
    }
}

fn header_pairs(headers: &HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_owned(),
                String::from_utf8_lossy(value.as_bytes()).into_owned(),
            )
        })
        .collect()
}

/// Full error chain: `reqwest::Error`'s `Display` alone hides the TLS/IO
/// cause, which is the detail that matters when a probe run fails.
fn error_chain(err: &(dyn std::error::Error + 'static)) -> Vec<String> {
    let mut chain = vec![err.to_string()];
    let mut source = err.source();
    while let Some(cause) = source {
        chain.push(cause.to_string());
        source = cause.source();
    }
    chain
}

async fn handle(
    State(cfg): State<Arc<Cfg>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let path_and_query = uri
        .path_and_query()
        .map(|p| p.as_str().to_owned())
        .unwrap_or_else(|| uri.path().to_owned());
    let url = format!(
        "{}{}",
        cfg.upstream.trim_end_matches('/'),
        if path_and_query.starts_with('/') {
            path_and_query
        } else {
            format!("/{path_and_query}")
        }
    );
    let seq = cfg.seq.fetch_add(1, Ordering::SeqCst) + 1;
    let request_headers = header_pairs(&headers);

    let upstream_method =
        reqwest::Method::from_bytes(method.as_str().as_bytes()).unwrap_or(reqwest::Method::GET);
    let mut builder = cfg.client.request(upstream_method, &url);
    for (name, value) in headers.iter() {
        if is_hop_by_hop(name.as_str()) {
            continue;
        }
        builder = builder.header(name.as_str(), value.as_bytes());
    }

    let started = Instant::now();
    match builder.body(body.to_vec()).send().await {
        Ok(response) => {
            let status = response.status().as_u16();
            let forwarded_headers = response.headers().clone();
            let response_headers = header_pairs(&forwarded_headers);
            let response_body = response.bytes().await.unwrap_or_default();

            emit(
                &cfg,
                json!({
                    "event": "proxied",
                    "seq": seq,
                    "method": method.as_str(),
                    "path": uri.path(),
                    "query": uri.query().unwrap_or(""),
                    "upstream_url": url,
                    "request_headers": request_headers,
                    "request_body_len": body.len(),
                    "request_body": body_preview(&body),
                    "upstream_status": status,
                    "response_headers": response_headers,
                    "response_body_len": response_body.len(),
                    "response_body": body_preview(&response_body),
                    "elapsed_ms": started.elapsed().as_millis() as u64,
                }),
            )
            .await;

            let mut out = Response::builder().status(status);
            for (name, value) in forwarded_headers.iter() {
                if is_hop_by_hop(name.as_str()) {
                    continue;
                }
                out = out.header(name.as_str(), value.as_bytes());
            }
            out.body(Body::from(response_body))
                .unwrap_or_else(|_| Response::new(Body::empty()))
        }
        Err(err) => {
            emit(
                &cfg,
                json!({
                    "event": "upstream_error",
                    "seq": seq,
                    "method": method.as_str(),
                    "path": uri.path(),
                    "query": uri.query().unwrap_or(""),
                    "upstream_url": url,
                    "request_headers": request_headers,
                    "request_body_len": body.len(),
                    "elapsed_ms": started.elapsed().as_millis() as u64,
                    "error": err.to_string(),
                    "error_chain": error_chain(&err),
                }),
            )
            .await;
            Response::builder()
                .status(502)
                .body(Body::from(format!("logproxy: upstream error: {err}")))
                .unwrap_or_else(|_| Response::new(Body::empty()))
        }
    }
}

#[tokio::main]
async fn main() {
    let listen =
        std::env::var("LOGPROXY_LISTEN").unwrap_or_else(|_| "127.0.0.1:18080".to_owned());
    let upstream = std::env::var("UPSTREAM")
        .expect("UPSTREAM (e.g. https://127.0.0.1:18443) is required");
    let log_path = std::env::var("B4_LOG").ok();

    let file = match &log_path {
        Some(path) => Some(
            tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .await
                .unwrap_or_else(|err| panic!("cannot open B4_LOG {path}: {err}")),
        ),
        None => None,
    };

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::none())
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .build()
        .expect("reqwest client");

    let cfg = Arc::new(Cfg {
        upstream: upstream.clone(),
        client,
        log: Mutex::new(file),
        seq: AtomicU64::new(0),
    });

    let listener = tokio::net::TcpListener::bind(&listen)
        .await
        .unwrap_or_else(|err| panic!("cannot bind {listen}: {err}"));
    let addr = listener.local_addr().expect("local_addr");

    emit(
        &cfg,
        json!({
            "event": "startup",
            "listen": format!("http://{addr}"),
            "upstream": upstream,
            "log_path": log_path,
            "note": "pass-through logger; every request is forwarded to UPSTREAM with TLS verification disabled",
        }),
    )
    .await;
    println!("logproxy listening on http://{addr} -> {upstream}");

    let app = Router::new().fallback(handle).with_state(cfg);
    axum::serve(listener, app).await.expect("serve");
}
