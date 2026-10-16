//! Command-line interface (plan task 4; ops subcommands plan task 46).

use std::path::PathBuf;

use clap::Parser;
use clap::Subcommand;
use clap::ValueEnum;

/// Cachette - GitHub Actions cache server (v1 artifactcache + Twirp v2).
#[derive(Debug, Parser)]
#[command(version)]
pub struct Cli {
    /// Path to a TOML config file. When omitted, the platform default is used
    /// if present: /etc/cachette/cachette.toml (*nix),
    /// %APPDATA%\cachette\cachette.toml (Windows), /config/cachette.toml
    /// (Docker image). An explicit path always overrides the default.
    #[arg(long, value_name = "path", global = true)]
    pub config: Option<PathBuf>,
    /// Print the resolved configuration (secrets masked) and exit.
    #[arg(long)]
    pub print_config: bool,
    /// Actions that print and exit without starting the server.
    #[command(subcommand)]
    pub command: Option<Command>,
}

/// Offline/ops subcommands (plan task 46). Every variant except
/// [`Command::Cluster`] runs without a live server; the ones that touch the
/// data directory take its exclusive lock and refuse if a server holds it.
#[derive(Clone, Debug, Eq, PartialEq, Subcommand)]
pub enum Command {
    /// Print the node fingerprint and identity certificate path (plan task 13).
    Identity,
    /// Recompute every published entry's stored digest and report mismatches.
    Verify,
    /// Inspect or prune cached entries (offline; takes the data-dir lock).
    Cache {
        /// `list` or `prune`.
        #[command(subcommand)]
        action: CacheCommand,
    },
    /// Run the reservation reaper and orphan-blob sweep once, then exit.
    Gc,
    /// Check config, data dir, SQLite, identity, seeds, and disk headroom.
    Doctor,
    /// Print a Forgejo artifactcache HMAC token for the configured secret.
    Token {
        /// `mint`.
        #[command(subcommand)]
        action: TokenCommand,
    },
    /// Print the live cluster member table from a running server.
    Cluster {
        /// `status`.
        #[command(subcommand)]
        action: ClusterCommand,
    },
}

/// `cachette cache <action>`.
#[derive(Clone, Debug, Eq, PartialEq, Subcommand)]
pub enum CacheCommand {
    /// List finalized cache entries.
    List {
        /// Emit a JSON array instead of one line per entry.
        #[arg(long)]
        json: bool,
    },
    /// Delete entries not accessed within `--older-than` (e.g. 7d, 12h, 30m).
    Prune {
        /// Age window: integer plus a s/m/h/d/w suffix (e.g. 90s, 12h, 7d).
        #[arg(long, value_name = "dur")]
        older_than: String,
        /// Print what would be deleted without deleting anything.
        #[arg(long)]
        dry_run: bool,
    },
}

/// `cachette token <action>`.
#[derive(Clone, Debug, Eq, PartialEq, Subcommand)]
pub enum TokenCommand {
    /// Mint an HMAC token; prints the `Forgejo-Cache-*` header values.
    Mint {
        /// `write` sets a non-empty write-isolation key, `read` leaves it empty.
        #[arg(long, value_enum, default_value = "write")]
        scope: Scope,
        /// Repository the token is for (`owner/repo`).
        #[arg(long, default_value = "cachette/ops")]
        repo: String,
        /// Workflow run number the token is for.
        #[arg(long, default_value = "0")]
        run: u64,
    },
}

/// `cachette cluster <action>`.
#[derive(Clone, Debug, Eq, PartialEq, Subcommand)]
pub enum ClusterCommand {
    /// Print the member table once, or follow it with `--watch`.
    Status {
        /// Refresh every few seconds until interrupted.
        #[arg(long)]
        watch: bool,
    },
}

/// HMAC token scope. The artifactcache HMAC scheme carries no server-side
/// scope; `write` sets a non-empty write-isolation key, `read` leaves it empty.
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum Scope {
    /// Read scope: empty write-isolation key.
    Read,
    /// Write scope: non-empty write-isolation key.
    Write,
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

    #[test]
    fn ops_subcommands_parse() {
        assert_eq!(
            Cli::try_parse_from(["cachette", "verify"]).unwrap().command,
            Some(Command::Verify)
        );
        assert_eq!(
            Cli::try_parse_from(["cachette", "gc"]).unwrap().command,
            Some(Command::Gc)
        );
        assert_eq!(
            Cli::try_parse_from(["cachette", "doctor"]).unwrap().command,
            Some(Command::Doctor)
        );
        assert_eq!(
            Cli::try_parse_from(["cachette", "cache", "list", "--json"])
                .unwrap()
                .command,
            Some(Command::Cache {
                action: CacheCommand::List { json: true }
            })
        );
        assert_eq!(
            Cli::try_parse_from(["cachette", "cache", "prune", "--older-than", "7d"])
                .unwrap()
                .command,
            Some(Command::Cache {
                action: CacheCommand::Prune {
                    older_than: String::from("7d"),
                    dry_run: false,
                }
            })
        );
        assert_eq!(
            Cli::try_parse_from(["cachette", "cluster", "status", "--watch"])
                .unwrap()
                .command,
            Some(Command::Cluster {
                action: ClusterCommand::Status { watch: true }
            })
        );
    }

    #[test]
    fn token_mint_defaults_and_scope_choice() {
        assert_eq!(
            Cli::try_parse_from(["cachette", "token", "mint"])
                .unwrap()
                .command,
            Some(Command::Token {
                action: TokenCommand::Mint {
                    scope: Scope::Write,
                    repo: String::from("cachette/ops"),
                    run: 0,
                }
            })
        );
        assert_eq!(
            Cli::try_parse_from([
                "cachette", "token", "mint", "--scope", "read", "--repo", "o/r", "--run", "7",
            ])
            .unwrap()
            .command,
            Some(Command::Token {
                action: TokenCommand::Mint {
                    scope: Scope::Read,
                    repo: String::from("o/r"),
                    run: 7,
                }
            })
        );
    }
}
