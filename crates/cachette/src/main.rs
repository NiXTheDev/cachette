use std::error::Error;
use std::sync::Arc;

use cachette::cli::{Cli, Command};
use cachette::config::{self, Config};
use cachette::identity::Identity;
use cachette::logging::{self};
use cachette::routes;
use cachette::state::AppState;
use cachette::tls::{self, PeerPins};
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
    if matches!(cli.command, Some(Command::Identity)) {
        let result = Identity::load_or_generate(
            &config.cert_path(),
            config.cluster.node_id.as_deref(),
            config.cluster.advertise_addr.as_deref(),
        );
        match result {
            Ok(identity) => {
                println!("fingerprint: {}", identity.fingerprint());
                println!("cert_path: {}", identity.cert_path().display());
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
    // First boot mints the Ed25519 identity at `cluster.cert_path`; later
    // boots reuse it, so the fingerprint survives restarts and storage wipes
    // (plan task 13). It also becomes the `/health` node_id.
    let identity = Identity::load_or_generate(
        &config.cert_path(),
        config.cluster.node_id.as_deref(),
        config.cluster.advertise_addr.as_deref(),
    )?;
    tracing::info!(
        fingerprint = identity.fingerprint(),
        cert_path = %identity.cert_path().display(),
        "node identity ready"
    );
    state.node_id = identity.fingerprint().to_owned();
    // Peer pin store (plan task 14 / B2): seeded fingerprints are always
    // trusted; TOFU admission follows `[cluster] enabled`.
    state.peers = Arc::new(PeerPins::new(
        &config.cluster.seed_fingerprints,
        config.cluster.enabled,
    ));
    // TraceLayer logs each request/response at DEBUG — visible under
    // `RUST_LOG=debug`, silent under the default `info` and under `warn`.
    let app = routes::router(state).layer(TraceLayer::new_for_http());
    // Single TLS listener (plan task 14 / B1): every route is served over
    // HTTPS; client certs are optional at the TLS layer and gated per-route.
    let tls_config = tls::server_config(&config.server, &identity)?;
    let listener = tls::bind(config.server.listen.as_str(), tls_config).await?;
    // Unconditional stdout line: the readiness gate for scripts (it must
    // appear even when `RUST_LOG` silences the tracing subscriber).
    let listen = &config.server.listen;
    println!("cachette listening on https://{listen}");
    tracing::info!(%listen, "listener ready");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<tls::PeerCert>(),
    )
    .await?;
    Ok(())
}
