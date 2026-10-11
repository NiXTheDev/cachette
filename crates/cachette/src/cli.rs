//! Command-line interface (plan task 4).

use std::path::PathBuf;

use clap::Parser;

/// Cachette - GitHub Actions cache server (v1 artifactcache + Twirp v2).
#[derive(Debug, Parser)]
#[command(version)]
pub struct Cli {
    /// Path to a TOML config file (default: cachette.toml if present).
    #[arg(long, value_name = "path")]
    pub config: Option<PathBuf>,
    /// Print the resolved configuration (secrets masked) and exit.
    #[arg(long)]
    pub print_config: bool,
}
