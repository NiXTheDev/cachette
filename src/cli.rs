//! Command-line interface (plan task 4; ops subcommands plan task 46).

use std::path::PathBuf;

use clap::Parser;
use clap::Subcommand;
use clap::ValueEnum;

/// Sort keys accepted by `cluster status --sort`, across both tables.
const SORT_KEYS: &[&str] = &[
    "node", "id", "type", "size", "used", "avail", "use%", "instance", "logical", "unique",
    "saved", "dedup%",
];

/// Validate the comma-separated `--sort` spec so a typo is a usage error
/// instead of silently unsorted output. A key absent from one table is still
/// ignored there, since the two tables expose different columns.
fn parse_sort_keys(raw: &str) -> Result<String, String> {
    for part in raw.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let key = part.strip_prefix('-').unwrap_or(part).to_ascii_lowercase();
        if !SORT_KEYS.contains(&key.as_str()) {
            return Err(format!(
                "unknown sort key `{key}` (valid: {})",
                SORT_KEYS.join(", ")
            ));
        }
    }
    Ok(raw.to_owned())
}

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
    /// With `rotate`, re-issue the certificate for the same key.
    Identity {
        /// `rotate` renews the certificate; omitted, only prints.
        #[command(subcommand)]
        action: Option<IdentityCommand>,
    },
    /// Recompute every published entry's stored digest and report mismatches.
    Verify {
        /// Storage instance to operate on (default: `default`).
        #[arg(long, value_name = "name")]
        storage: Option<String>,
    },
    /// Inspect or prune cached entries (offline; takes the data-dir lock).
    Cache {
        /// Storage instance to operate on (default: `default`).
        #[arg(long, value_name = "name")]
        storage: Option<String>,
        /// `list` or `prune`.
        #[command(subcommand)]
        action: CacheCommand,
    },
    /// Run the reservation reaper and orphan-blob sweep once, then exit.
    Gc {
        /// Storage instance to operate on (default: `default`).
        #[arg(long, value_name = "name")]
        storage: Option<String>,
    },
    /// Check config, data dir, SQLite, identity, seeds, and disk headroom, or
    /// migrate a v1.2 config/data layout to v1.3.
    Doctor {
        #[command(subcommand)]
        action: Option<DoctorCommand>,
    },
    /// Offline control-plane state migration and restore.
    State {
        #[command(subcommand)]
        action: StateCommand,
    },
    /// Mint tokens for the configured secret: Forgejo HMAC headers (the
    /// default) or a buildx `type=gha` bearer JWT (`buildx-jwt`).
    Token {
        /// `mint`.
        #[command(subcommand)]
        action: TokenCommand,
    },
    /// Configuration utilities.
    Config {
        #[command(subcommand)]
        action: ConfigCommand,
    },
    /// Print the live cluster member table from a running server.
    Cluster {
        /// `status`.
        #[command(subcommand)]
        action: ClusterCommand,
    },
}

/// `cachette config <action>`.
#[derive(Clone, Debug, Eq, PartialEq, Subcommand)]
pub enum ConfigCommand {
    /// Print the complete generated example config.
    Example,
}

/// `cachette doctor <action>`.
#[derive(Clone, Debug, Eq, PartialEq, Subcommand)]
pub enum DoctorCommand {
    /// Full migration: back up, write the new config, move state and data.
    Migrate {
        /// Config file to migrate in place.
        file: PathBuf,
        /// Pause after the config write so it can be edited before file moves.
        #[arg(long)]
        let_me_edit: bool,
        /// Accept CAUTION-level changes.
        #[arg(long)]
        ack_caution: bool,
        /// Typed confirmation for a DANGER step (`migrate-state`, ...).
        #[arg(long = "confirm", value_name = "action")]
        confirm: Vec<String>,
    },
    /// Config-only migration; no data is moved.
    MigrateConfig {
        file: PathBuf,
        /// Replace the original (old config is copied to `<file>.bak`).
        #[arg(long)]
        write: bool,
        #[arg(long)]
        ack_caution: bool,
    },
}

/// `cachette state <action>`.
#[derive(Clone, Debug, Eq, PartialEq, Subcommand)]
pub enum StateCommand {
    /// Copy the control plane to a new directory.
    Migrate {
        #[arg(long)]
        from: PathBuf,
        #[arg(long)]
        to: PathBuf,
        #[arg(long = "confirm", value_name = "action")]
        confirm: Option<String>,
    },
    /// Restore a verified snapshot archive.
    Restore {
        archive: PathBuf,
        #[arg(long)]
        to: PathBuf,
        #[arg(long)]
        force: bool,
    },
    /// Convert the legacy hashed payload layout to the v1.3 hierarchy.
    Layout {
        #[arg(long = "confirm", value_name = "action")]
        confirm: Option<String>,
    },
    /// Re-tag legacy `""` rows into their real namespaces.
    Retag {
        /// Repeatable `old=new` pairs.
        #[arg(long = "retag", value_name = "old=new")]
        retag: Vec<String>,
        /// Optional TOML mapping file for bulk rewrites.
        #[arg(long)]
        file: Option<PathBuf>,
        #[arg(long = "confirm", value_name = "action")]
        confirm: Option<String>,
    },
    /// Delete a migrated source after verification.
    DeleteSource {
        backup: PathBuf,
        #[arg(long = "confirm", value_name = "action")]
        confirm: Option<String>,
    },
}

/// `cachette identity <action>`.
#[derive(Clone, Debug, Eq, PartialEq, Subcommand)]
pub enum IdentityCommand {
    /// Re-issue the certificate for the SAME key: the fingerprint — and so
    /// every peer pin — is unchanged (plan task 48).
    Rotate,
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
        /// Age window: bare seconds or a s/m/h/d/w/y suffix (e.g. 3600, 90s, 12h, 7d).
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
    /// Mint a token. Bare `mint` means `hmac` (the `Forgejo-Cache-*` header
    /// mint); `buildx-jwt` prints an HS256 bearer JWT for the buildx
    /// `type=gha` exporter / the @actions/cache toolkit.
    Mint {
        /// hmac defaults, used when no variant is named: `write` sets a
        /// non-empty write-isolation key, `read` leaves it empty.
        #[arg(long, value_enum, default_value = "write")]
        scope: Scope,
        /// hmac default repo (used when no variant is named).
        #[arg(long, default_value = "cachette/ops")]
        repo: String,
        /// hmac default run number (used when no variant is named).
        #[arg(long, default_value = "0")]
        run: u64,
        /// `hmac` or `buildx-jwt`; omitted means `hmac` with the flags above.
        #[command(subcommand)]
        kind: Option<MintKind>,
    },
}

/// Which token kind `token mint` produces.
#[derive(Clone, Debug, Eq, PartialEq, Subcommand)]
pub enum MintKind {
    /// Forgejo artifactcache HMAC; prints the `Forgejo-Cache-*` header values.
    Hmac {
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
    /// HS256 bearer JWT for buildx `type=gha` and the @actions/cache toolkit
    /// (`ac`/`exp`/`nbf`, three dot-separated segments). List the printed
    /// string verbatim in the forge secret `CACHETTE_BUILDX_JWT` and in
    /// cachette's `[auth] tokens`; see docs/clients.md.
    BuildxJwt {
        /// Lifetime of the `exp` claim, counted from now: a bare integer
        /// counts as seconds (`3600` = 1h), or use `s`/`m`/`h`/`d`/`w`/`y`
        /// suffixes (`90s`, `12h`, `7d`, `10y`).
        #[arg(long, value_name = "dur", default_value = "10y")]
        exp: String,
    },
}

/// `cachette cluster <action>`.
#[derive(Clone, Debug, Eq, PartialEq, Subcommand)]
pub enum ClusterCommand {
    /// Rich cluster overview: peers, storage, and dedup savings.
    Status {
        /// Comma-separated sort keys (optional leading `-` for descending),
        /// e.g. `used,-node`. Applied to both tables.
        #[arg(long, value_name = "KEYS", value_parser = parse_sort_keys)]
        sort: Option<String>,
        /// Table colours: auto, none, dark, light, or ansi.
        #[arg(
            long,
            value_name = "THEME",
            value_parser = ["auto", "none", "dark", "light", "ansi"],
            default_value = "auto"
        )]
        theme: String,
    },
    /// Inspect or edit the live peer table.
    Peer {
        #[command(subcommand)]
        action: PeerCommand,
    },
}

/// `cachette cluster peer <action>`.
#[derive(Clone, Debug, Eq, PartialEq, Subcommand)]
pub enum PeerCommand {
    /// Print the peer table once, or follow it with `--watch[=INTERVAL]`.
    List {
        #[arg(long, num_args = 0..=1, default_missing_value = "2s", value_name = "INTERVAL")]
        watch: Option<String>,
    },
    /// Add a peer address (identity optional; use `--node-id` and
    /// `--fingerprint` to seed it already identified).
    Add {
        addr: String,
        #[arg(long)]
        node_id: Option<String>,
        #[arg(long)]
        fingerprint: Option<String>,
    },
    /// Remove a peer by node id, fingerprint, or address.
    Remove { peer: String },
    /// Edit a peer's address or identity in place.
    Edit {
        peer: String,
        #[arg(long)]
        addr: Option<String>,
        #[arg(long)]
        node_id: Option<String>,
        #[arg(long)]
        fingerprint: Option<String>,
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
        assert_eq!(cli.command, Some(Command::Identity { action: None }));
        assert!(!cli.print_config);

        let cli = Cli::try_parse_from(["cachette", "--print-config"]).expect("flag parses");
        assert_eq!(cli.command, None);
        assert!(cli.print_config);

        let cli = Cli::try_parse_from(["cachette", "--config", "x.toml", "identity"])
            .expect("flag + subcommand combine");
        assert_eq!(cli.config, Some(PathBuf::from("x.toml")));
        assert_eq!(cli.command, Some(Command::Identity { action: None }));
    }

    #[test]
    fn identity_rotate_parses_and_takes_the_global_config() {
        assert_eq!(
            Cli::try_parse_from(["cachette", "identity", "rotate"])
                .unwrap()
                .command,
            Some(Command::Identity {
                action: Some(IdentityCommand::Rotate)
            })
        );
        // `--config` is global, so it is accepted after the nested subcommand.
        let cli = Cli::try_parse_from(["cachette", "identity", "rotate", "--config", "x.toml"])
            .expect("global flag after nested subcommand");
        assert_eq!(cli.config, Some(PathBuf::from("x.toml")));
        assert_eq!(
            cli.command,
            Some(Command::Identity {
                action: Some(IdentityCommand::Rotate)
            })
        );
    }

    #[test]
    fn ops_subcommands_parse() {
        assert_eq!(
            Cli::try_parse_from(["cachette", "verify"]).unwrap().command,
            Some(Command::Verify { storage: None })
        );
        assert_eq!(
            Cli::try_parse_from(["cachette", "gc"]).unwrap().command,
            Some(Command::Gc { storage: None })
        );
        assert_eq!(
            Cli::try_parse_from(["cachette", "doctor"]).unwrap().command,
            Some(Command::Doctor { action: None })
        );
        assert_eq!(
            Cli::try_parse_from(["cachette", "cache", "list", "--json"])
                .unwrap()
                .command,
            Some(Command::Cache {
                storage: None,
                action: CacheCommand::List { json: true }
            })
        );
        assert_eq!(
            Cli::try_parse_from(["cachette", "cache", "prune", "--older-than", "7d"])
                .unwrap()
                .command,
            Some(Command::Cache {
                storage: None,
                action: CacheCommand::Prune {
                    older_than: String::from("7d"),
                    dry_run: false,
                }
            })
        );
        assert_eq!(
            Cli::try_parse_from(["cachette", "cluster", "status"])
                .unwrap()
                .command,
            Some(Command::Cluster {
                action: ClusterCommand::Status {
                    sort: None,
                    theme: String::from("auto"),
                }
            })
        );
        assert_eq!(
            Cli::try_parse_from([
                "cachette",
                "cluster",
                "status",
                "--sort",
                "used,-node",
                "--theme",
                "light"
            ])
            .unwrap()
            .command,
            Some(Command::Cluster {
                action: ClusterCommand::Status {
                    sort: Some(String::from("used,-node")),
                    theme: String::from("light"),
                }
            })
        );
        assert!(
            Cli::try_parse_from(["cachette", "cluster", "status", "--sort", "use"])
                .is_err_and(|err| err.to_string().contains("unknown sort key `use`"))
        );
        assert_eq!(
            Cli::try_parse_from(["cachette", "cluster", "peer", "list", "--watch", "2m"])
                .unwrap()
                .command,
            Some(Command::Cluster {
                action: ClusterCommand::Peer {
                    action: PeerCommand::List {
                        watch: Some(String::from("2m")),
                    }
                }
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
                    kind: None,
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
                    kind: None,
                }
            })
        );
    }

    #[test]
    fn token_mint_kind_variants_parse() {
        // Bare mint is hmac with the parent defaults (parent flags are parsed
        // but unused when a variant is named).
        let cli = Cli::try_parse_from(["cachette", "token", "mint"]).unwrap();
        if let Some(Command::Token {
            action: TokenCommand::Mint { kind, .. },
        }) = cli.command
        {
            assert_eq!(kind, None);
        } else {
            panic!("bare mint does not parse: {cli:?}");
        }
        // The explicit hmac variant carries its own flags.
        let cli = Cli::try_parse_from([
            "cachette", "token", "mint", "hmac", "--scope", "read", "--run", "7",
        ])
        .unwrap();
        assert_eq!(
            cli.command,
            Some(Command::Token {
                action: TokenCommand::Mint {
                    scope: Scope::Write,
                    repo: String::from("cachette/ops"),
                    run: 0,
                    kind: Some(MintKind::Hmac {
                        scope: Scope::Read,
                        repo: String::from("cachette/ops"),
                        run: 7,
                    }),
                }
            })
        );
        // buildx-jwt: the default lifetime and a custom one.
        let cli = Cli::try_parse_from(["cachette", "token", "mint", "buildx-jwt"]).unwrap();
        assert_eq!(
            cli.command,
            Some(Command::Token {
                action: TokenCommand::Mint {
                    scope: Scope::Write,
                    repo: String::from("cachette/ops"),
                    run: 0,
                    kind: Some(MintKind::BuildxJwt {
                        exp: String::from("10y"),
                    }),
                }
            })
        );
        let cli = Cli::try_parse_from(["cachette", "token", "mint", "buildx-jwt", "--exp", "90s"])
            .unwrap();
        assert_eq!(
            cli.command,
            Some(Command::Token {
                action: TokenCommand::Mint {
                    scope: Scope::Write,
                    repo: String::from("cachette/ops"),
                    run: 0,
                    kind: Some(MintKind::BuildxJwt {
                        exp: String::from("90s"),
                    }),
                }
            })
        );
    }
}
