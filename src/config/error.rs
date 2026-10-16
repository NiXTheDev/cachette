//! Config loading/validation errors (plan task 5).
//!
//! Every variant names the offending key or environment variable so an
//! operator can fix the input without guessing.

/// A configuration problem, mapped by `main.rs` to exit code 2.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// `--config <path>` (or the default `cachette.toml`) could not be read.
    #[error("cannot read config file {path}: {msg}")]
    ReadFile { path: String, msg: String },

    /// The config file is not valid TOML. The wrapped message carries the
    /// line/column snippet produced by the `toml` crate.
    #[error("invalid TOML in config file: {0}")]
    Toml(String),

    /// A TOML section (or the value inside it) failed to deserialize. The
    /// serde message names the unknown/invalid field.
    #[error("invalid config in [{section}]: {msg}")]
    InSection { section: String, msg: String },

    /// A top-level key that is not a known section.
    #[error("unknown configuration key: {0}")]
    UnknownKey(String),

    /// A `CACHETTE__*` variable that maps to no known config key.
    #[error("unknown environment variable: {0}")]
    UnknownEnvVar(String),

    /// A `CACHETTE__*` variable whose value failed to parse. Always names
    /// the variable (Metis M16).
    #[error("invalid value for environment variable {var}: {msg}")]
    InvalidEnvValue { var: String, msg: String },

    /// A `min_free` value that is none of fraction / percent / bytesize.
    #[error("invalid storage.fs.min_free value {value:?}: {msg}")]
    MinFree { value: String, msg: String },

    /// `server.listen` is not `host:port`.
    #[error("invalid server.listen value {value:?}: {msg}")]
    Listen { value: String, msg: String },

    /// Only one of `server.tls_cert` / `server.tls_key` was set.
    #[error("{set_key} is set but {missing_key} is not; they must be configured together")]
    TlsPair {
        set_key: &'static str,
        missing_key: &'static str,
    },

    /// `[storage.fs] path` is empty.
    #[error("storage.fs.path must not be empty")]
    EmptyStoragePath,

    /// `[cache] reservation_ttl_seconds` is zero.
    #[error("cache.reservation_ttl_seconds must be greater than 0")]
    ZeroReservationTtl,

    /// `[server] max_chunk_bytes` is zero.
    #[error("server.max_chunk_bytes must be greater than 0")]
    ZeroMaxChunkBytes,

    /// `[cluster] cert_path` collides with the storage root.
    #[error("cluster.cert_path must differ from storage.fs.path")]
    CertPathCollides,

    /// `[auth] secret` missing at serve time (not checked by `--print-config`).
    #[error(
        "auth.secret is required to serve: set [auth] secret in the config file or the \
         CACHETTE__AUTH__SECRET environment variable (minimum 16 characters)"
    )]
    MissingSecret,

    /// `[auth] secret` shorter than 16 characters at serve time.
    #[error("auth.secret must be at least 16 characters (got {len})")]
    ShortSecret { len: usize },

    /// A `serde_json` failure while rendering `--print-config` output.
    /// Effectively unreachable; kept so rendering never panics.
    #[error("internal config serialization error: {0}")]
    Internal(String),
}
