//! Command-line interface (plan task 4).

use std::path::PathBuf;

use clap::Parser;
use clap::Subcommand;

/// Cachette - GitHub Actions cache server (v1 artifactcache + Twirp v2).
#[derive(Debug, Parser)]
#[command(version)]
pub struct Cli {
    /// Path to a TOML config file. When omitted, the platform default is used
    /// if present: /etc/cachette/cachette.toml (*nix),
    /// %APPDATA%\cachette\cachette.toml (Windows), /config/cachette.toml
    /// (Docker image). An explicit path always overrides the default.
    #[arg(long, value_name = "path")]
    pub config: Option<PathBuf>,
    /// Print the resolved configuration (secrets masked) and exit.
    #[arg(long)]
    pub print_config: bool,
    /// Actions that print and exit without starting the server.
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Subcommand)]
pub enum Command {
    /// Print the node fingerprint and identity certificate path (plan task 13).
    Identity,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_subcommand_parses_alongside_print_config() {
        let cli = Cli::try_parse_from(["cachette", "identity"]).expect("subcommand parses");
        assert_eq!(cli.command, Some(Command::Identity));
        assert!(!cli.print_config);

        let cli = Cli::try_parse_from(["cachette", "--print-config"]).expect("flag parses");
        assert_eq!(cli.command, None);
        assert!(cli.print_config);

        let cli = Cli::try_parse_from(["cachette", "--config", "x.toml", "identity"])
            .expect("flag + subcommand combine");
        assert_eq!(cli.config, Some(PathBuf::from("x.toml")));
        assert_eq!(cli.command, Some(Command::Identity));
    }
}
