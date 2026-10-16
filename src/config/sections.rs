//! Config file sections (plan task 5): one struct per TOML section, mirroring
//! the draft config spec exactly. Every struct denies unknown keys and every
//! field has a spec-defined default (via the section's `Default` impl).

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::Deserialize;
use serde::Serialize;

use crate::config::min_free::MinFree;

/// `[server]` - the one listener both runners and peers enter through.
#[derive(Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServerConfig {
    pub listen: String,
    pub external_url: Option<String>,
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
    /// Largest single uploaded chunk/block accepted (bytes). Bounds how much
    /// one request may occupy on the request path (plan task 45); the default
    /// is 2x the largest chunk any real client (go-actions-cache) sends.
    pub max_chunk_bytes: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: String::from("0.0.0.0:8080"),
            external_url: None,
            tls_cert: None,
            tls_key: None,
            max_chunk_bytes: 64 * 1024 * 1024,
        }
    }
}

/// `[storage]` - backend selection plus the `fs` sub-table.
#[derive(Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct StorageConfig {
    pub backend: Backend,
    pub fs: FsConfig,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            backend: Backend::Fs,
            fs: FsConfig::default(),
        }
    }
}

/// `[storage.fs]` - blob root + free-space floor.
#[derive(Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct FsConfig {
    pub path: PathBuf,
    pub min_free: MinFree,
}

impl Default for FsConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::from("/var/lib/cachette"),
            min_free: MinFree::Fraction(0.2),
        }
    }
}

/// Storage backend id. Only `"fs"` ships in v1; others are future
/// `StorageBackend` implementations and are rejected clearly today.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Backend {
    Fs,
}

/// `[cache]` - local size accounting + eviction knobs.
#[derive(Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct CacheConfig {
    /// 0 = unlimited.
    pub max_size: u64,
    pub eviction: Eviction,
    pub key_case: KeyCase,
    pub reservation_ttl_seconds: u64,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_size: 0,
            eviction: Eviction::Lru,
            key_case: KeyCase::Preserve,
            reservation_ttl_seconds: 3600,
        }
    }
}

/// Eviction policy: least-recently-used, oldest-first, or never (`none`
/// refuses new reservations below the free-space floor instead).
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Eviction {
    Lru,
    Oldest,
    None,
}

/// Key normalization before exact/prefix matching (M11). GitHub cache keys are
/// case-sensitive, so `preserve` is the default (GitHub parity); `lower` is the
/// Forgejo-style fold and is opt-in.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyCase {
    /// Fold keys to lowercase before matching (Forgejo-style).
    Lower,
    /// Match keys byte-exactly, as GitHub does (default).
    Preserve,
}

/// `[auth]` - request authentication.
#[derive(Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuthConfig {
    pub mode: AuthMode,
    /// Required to serve (min 16 chars); unset is tolerated by
    /// `--print-config` only.
    pub secret: Option<String>,
    pub tokens: Vec<String>,
    /// 0 = disabled (GitHub parity, M14).
    pub hmac_max_age_seconds: u64,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            mode: AuthMode::Merge,
            secret: None,
            tokens: Vec::new(),
            hmac_max_age_seconds: 600,
        }
    }
}

/// Base auth mode: Forgejo HMAC, static bearer tokens, or both.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthMode {
    Hmac,
    Bearer,
    Merge,
}

/// `[v1]` - artifactcache protocol knobs.
#[derive(Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct V1Config {
    pub signed_url_ttl_seconds: u64,
}

impl Default for V1Config {
    fn default() -> Self {
        Self {
            signed_url_ttl_seconds: 900,
        }
    }
}

/// `[v2]` - Twirp protocol knobs.
#[derive(Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct V2Config {
    /// Falls back to `[auth] secret` when unset.
    pub jwt_secret: Option<String>,
    pub jwt_ttl_seconds: u64,
}

impl Default for V2Config {
    fn default() -> Self {
        Self {
            jwt_secret: None,
            jwt_ttl_seconds: 300,
        }
    }
}

/// `[cluster]` - peer discovery + heartbeat. Off = standalone node.
#[derive(Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ClusterConfig {
    pub enabled: bool,
    pub node_id: Option<String>,
    /// Defaults to `server.listen` (m5).
    pub advertise_addr: Option<String>,
    pub mdns: bool,
    pub seeds: Vec<String>,
    pub seed_fingerprints: BTreeMap<String, String>,
    pub tiebreak: Tiebreak,
    /// Defaults to `<storage.fs.path>/identity` (M6).
    pub cert_path: Option<PathBuf>,
    pub heartbeat_interval_seconds: u64,
    pub peer_timeout_seconds: u64,
}

impl Default for ClusterConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            node_id: None,
            advertise_addr: None,
            mdns: true,
            seeds: Vec::new(),
            seed_fingerprints: BTreeMap::new(),
            tiebreak: Tiebreak::Random,
            cert_path: None,
            heartbeat_interval_seconds: 5,
            peer_timeout_seconds: 15,
        }
    }
}

/// Tie-breaking when several nodes are equally least-loaded.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Tiebreak {
    Random,
    RoundRobin,
    Progressive,
}

/// `[log]` - tracing subscriber configuration.
#[derive(Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct LogConfig {
    pub level: LogLevel,
    pub format: LogFormat,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: LogLevel::Info,
            format: LogFormat::Text,
        }
    }
}

/// Tracing filter level; `as_str` feeds the default `RUST_LOG` directive.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl LogLevel {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Trace => "trace",
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
        }
    }
}

/// Tracing output format (selects `logging::LogFormat` at startup).
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    Text,
    Json,
}

impl From<LogFormat> for crate::logging::LogFormat {
    fn from(value: LogFormat) -> Self {
        match value {
            LogFormat::Text => Self::Text,
            LogFormat::Json => Self::Json,
        }
    }
}
