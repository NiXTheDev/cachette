use std::error::Error;

use cachette::cli::Cli;
use cachette::config::{self, Config};
use cachette::logging::{self};
use cachette::routes;
use cachette::state::AppState;
use clap::Parser;
use tower_http::trace::TraceLayer;

fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();
    let config = match config::load(cli.config.clone()) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("cachette: {err}");
            std::process::exit(2);
        }
    };
    if cli.print_config {
        match config::render_masked(&config) {
            Ok(rendered) => {
                println!("{rendered}");
                std::process::exit(0);
            }
            Err(err) => {
                eprintln!("cachette: {err}");
                std::process::exit(2);
            }
        }
    }
    if let Err(err) = config.require_auth_secret() {
        eprintln!("cachette: {err}");
        std::process::exit(2);
    }
    // `[log] level` becomes the default tracing directive; an explicitly set
    // RUST_LOG still wins (logging::init parses it with from_env_lossy).
    if std::env::var_os("RUST_LOG").is_none()
        && config.log.level != cachette::config::LogLevel::Info
    {
        // SAFETY: runs on the main thread before the tokio runtime (the
        // process's first thread pool) is created, so nothing can observe the
        // environment concurrently.
        unsafe { std::env::set_var("RUST_LOG", config.log.level.as_str()) };
    }
    logging::init(config.log.format.into());
    tracing::debug!(config_path = ?cli.config, "command line parsed");
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(serve(config, cli))?;
    Ok(())
}

async fn serve(config: Config, cli: Cli) -> Result<(), Box<dyn Error>> {
    let mut state = AppState::new();
    state.config_path = cli.config;
    // TraceLayer logs each request/response at DEBUG — visible under
    // `RUST_LOG=debug`, silent under the default `info` and under `warn`.
    let app = routes::router(state).layer(TraceLayer::new_for_http());
    let listener = tokio::net::TcpListener::bind(config.server.listen.as_str()).await?;
    // Unconditional stdout line: the readiness gate for scripts (it must
    // appear even when `RUST_LOG` silences the tracing subscriber).
    let listen = &config.server.listen;
    println!("cachette listening on http://{listen}");
    tracing::info!(%listen, "listener ready");
    axum::serve(listener, app).await?;
    Ok(())
}
