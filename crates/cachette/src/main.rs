use std::net::SocketAddr;

use cachette::cli::Cli;
use cachette::logging::{self, LogFormat};
use cachette::routes;
use cachette::state::AppState;
use clap::Parser;
use tower_http::trace::TraceLayer;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    // Text now; `LogFormat::Json` becomes reachable once config `[log] format`
    // is wired up in plan task 5.
    logging::init(LogFormat::Text);
    tracing::debug!(config = ?cli.config, "command line parsed");

    // Hardcoded default until config loading lands in plan task 5.
    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));
    let mut state = AppState::new();
    state.config_path = cli.config;
    // TraceLayer logs each request/response at DEBUG — visible under
    // `RUST_LOG=debug`, silent under the default `info` and under `warn`.
    let app = routes::router(state).layer(TraceLayer::new_for_http());
    let listener = tokio::net::TcpListener::bind(addr).await?;
    // Unconditional stdout line: the readiness gate for scripts (it must
    // appear even when `RUST_LOG` silences the tracing subscriber).
    println!("cachette listening on http://{addr}");
    tracing::info!(%addr, "listener ready");
    axum::serve(listener, app).await?;
    Ok(())
}
