//! The plaintext main listener (no `[server] tls_cert`/`tls_key` configured).
//!
//! The default listener is plain HTTP: `/health` answers over a raw socket
//! connection, and the pin-gated peer routes fail closed — a plaintext
//! connection can never present a client certificate, so
//! `/_internal/peers/*` rejects with `403 peer auth required` (the same gate
//! a TLS connection without a client certificate gets). This is the negative
//! half of the two-listener contract: self-signed TLS belongs to the cluster
//! port, and the main port only becomes TLS when an explicit PEM pair is
//! configured.

use std::net::SocketAddr;

use cachette::state::AppState;
use cachette::tls::{PeerCert, ServerListener};

/// Bind a plaintext `ServerListener` on an ephemeral port and serve the real
/// router on a task — exactly the shape `main.rs::serve` uses when no TLS
/// pair is configured.
async fn serve_plaintext() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("binds ephemeral port");
    let addr = listener.local_addr().expect("bound addr");
    let state = AppState::new();
    let app = cachette::routes::router(state);
    let server = ServerListener::Plain(listener);
    tokio::spawn(async move {
        axum::serve(
            server,
            app.into_make_service_with_connect_info::<PeerCert>(),
        )
        .await
        .expect("serve");
    });
    addr
}

/// Hand-rolled HTTP/1.1 GET over a raw TCP socket (no HTTP client
/// dependency, mirroring the in-tree client helpers).
async fn raw_get(addr: SocketAddr, path: &str) -> String {
    let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let request = format!("GET {path} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n");
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write request");
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.expect("read response");
    String::from_utf8_lossy(&raw).into_owned()
}

#[tokio::test]
async fn plaintext_health_serves_200() {
    let addr = serve_plaintext().await;
    let response = raw_get(addr, "/health").await;
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "expected 200 over plaintext, got: {response}"
    );
    assert!(
        response.contains("\"version\"") && response.contains("\"node_id\""),
        "expected the health JSON, got: {response}"
    );
}

#[tokio::test]
async fn pin_gated_peer_routes_fail_closed_on_plaintext() {
    let addr = serve_plaintext().await;
    let response = raw_get(addr, "/_internal/peers").await;
    assert!(
        response.starts_with("HTTP/1.1 403"),
        "expected 403 without TLS, got: {response}"
    );
    assert!(
        response.contains("peer auth required"),
        "expected the pin-gate error body, got: {response}"
    );
}
