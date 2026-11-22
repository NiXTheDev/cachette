//! Config file sections (plan task 5): one struct per TOML section, mirroring
//! the draft config spec exactly. Every struct denies unknown keys and every
//! field has a spec-defined default (via the section's `Default` impl).

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::Deserialize;
use serde::Serialize;

use crate::config::min_free::MinFree;
use crate::config::quotas::QuotasConfig;
use crate::config::v13::{ForgeAuthConfig, StorageInstanceConfig};

/// `[server]` - the main listener runners and clients enter through. It is
/// plaintext HTTP unless `tls_cert`/`tls_key` are both set; peers have their
/// own dedicated `[cluster] listen` port.
#[derive(Debug, Clone, Deserialize, Serialize)]
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
    /// Graceful-shutdown drain window (plan task 47): on SIGTERM/SIGINT the
    /// node advertises `draining`, refuses new uploads with `503`, and keeps
    /// serving in-flight requests for up to this many seconds before exiting.
    pub drain_grace_seconds: u64,
    /// v1.3 control-plane state directory (or a `.db` file path). Populated by
    /// legacy normalization for v1.2 configs; later slices resolve the
    /// config-dir default and move DB/identity/lock here.
    pub data_path: Option<PathBuf>,
    /// v1.3: old `[cache]` keys, copied here at load time.
    pub max_size: Option<u64>,
    pub eviction: Option<String>,
    pub key_case: Option<String>,
    pub reservation_ttl_seconds: Option<u64>,
    /// v1.3: old `[log]` keys, copied here at load time.
    pub level: Option<String>,
    pub format: Option<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: String::from("0.0.0.0:8080"),
            external_url: None,
            tls_cert: None,
            tls_key: None,
            max_chunk_bytes: 64 * 1024 * 1024,
            drain_grace_seconds: 30,
            data_path: None,
            max_size: None,
            eviction: None,
            key_case: None,
            reservation_ttl_seconds: None,
            level: None,
            format: None,
        }
    }
}

/// `[storage]` - backend selection plus the `fs` sub-table.
#[derive(Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct StorageConfig {
    pub backend: Backend,
    pub fs: FsConfig,
    /// Finalize-time content-defined chunking (v1.1); `[storage.cdc]` may
    /// be absent entirely - everything defaults off.
    pub cdc: CdcConfig,
    /// Admin namespace mappings (v1.2 workstream F,
    /// `docs/shared-cache.md` §7): `"<forge>|<tenant>"` -> namespace name.
    /// A tenant not listed keeps its default `"<forge>|<tenant>"` namespace.
    pub namespaces: BTreeMap<String, String>,
    /// Per-namespace byte limits (v1.2 workstream F, `docs/shared-cache.md`
    /// §5): a `default` plus exact and wildcard overrides. Absent or empty
    /// means every namespace is unlimited.
    pub quotas: QuotasConfig,
    /// v1.3 repeatable `[[storage]]` instances. A legacy `[storage.fs]` config
    /// gets a synthesized `default` instance at load time.
    pub instances: Vec<StorageInstanceConfig>,
    /// v1.3: resolved namespace -> instance name, with `"*"` catch-all.
    pub routes: BTreeMap<String, String>,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            backend: Backend::Fs,
            fs: FsConfig::default(),
            cdc: CdcConfig::default(),
            namespaces: BTreeMap::new(),
            quotas: QuotasConfig::default(),
            instances: Vec::new(),
            routes: BTreeMap::new(),
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

/// `[storage.cdc]` - finalize-time content-defined chunking (v1.1; the
/// contract lives in `docs/cdc.md`). Off by default: entries are stored
/// whole exactly as in v1.0, and the read path stays chunk-aware regardless
/// of the flag, so flipping it off never orphans already-chunked data.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct CdcConfig {
    /// Cut finalized payloads into deduplicated content chunks at rest.
    pub enabled: bool,
    /// Target mean chunk size in bytes; validation keeps it within
    /// [`MIN_AVG_CHUNK_BYTES`](crate::storage::cdc::MIN_AVG_CHUNK_BYTES)
    /// ..[`MAX_AVG_CHUNK_BYTES`](crate::storage::cdc::MAX_AVG_CHUNK_BYTES).
    pub avg_chunk_bytes: u64,
    /// Converge pre-CDC `whole` entries onto the chunked layout in the
    /// background when `enabled` is on (docs/cdc.md, Migration). Default on:
    /// turning `[storage.cdc] enabled` on means "converge", not just "new
    /// writes chunk".
    pub backfill: bool,
    /// Pause between single-entry backfill conversions; bounds the walker's
    /// interference with live traffic. Validated `>= 1` regardless of
    /// `enabled` (a zero delay would hot-spin once enabled flips on).
    pub backfill_delay_ms: u64,
}

impl Default for CdcConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            avg_chunk_bytes: crate::storage::cdc::DEFAULT_AVG_CHUNK_BYTES,
            backfill: true,
            backfill_delay_ms: 100,
        }
    }
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
    /// OIDC RS256 bearer acceptance (v1.1); `None` = table absent = disabled.
    pub oidc: Option<OidcConfig>,
    /// Forge runtime-token acceptance (v1.2 Plane B,
    /// `docs/shared-cache.md` §3): one block per forge, keyed by the forge
    /// id. Empty = Plane B off.
    pub runtime: BTreeMap<String, RuntimeForgeConfig>,
    /// v1.3: every credential plane for one forge in a single block.
    pub forge: BTreeMap<String, ForgeAuthConfig>,
    /// v1.3: old `[v1]`/`[v2]` keys and `[auth.oidc]` globals, copied here at
    /// load time. Runtime still reads the legacy locations for now.
    pub signed_url_ttl_seconds: Option<u64>,
    pub jwt_secret: Option<String>,
    pub jwt_ttl_seconds: Option<u64>,
    pub oidc_jwks_refresh_seconds: Option<u64>,
    pub oidc_jwks_max_keys: Option<u64>,
    pub oidc_jwks_ca_pem: Option<PathBuf>,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            mode: AuthMode::Merge,
            secret: None,
            tokens: Vec::new(),
            hmac_max_age_seconds: 600,
            oidc: None,
            runtime: BTreeMap::new(),
            forge: BTreeMap::new(),
            signed_url_ttl_seconds: None,
            jwt_secret: None,
            jwt_ttl_seconds: None,
            oidc_jwks_refresh_seconds: None,
            oidc_jwks_max_keys: None,
            oidc_jwks_ca_pem: None,
        }
    }
}

/// `[auth.runtime."<forge>"]` - the forge whose runtime tokens cachette
/// verifies (v1.2 Plane B, `docs/shared-cache.md` §3). The forge id is the
/// block key and becomes the forge half of `"<forge>|<tenant>"`.
///
/// ```toml
/// [auth.runtime."https://hangar.nixthedev.ru"]
/// enabled = true
/// secret = "/etc/cachette/forgejo-token-secret"
/// tenant_claim = "oidc_extra.repository"
/// scopes = ["repo:NiXTheDev/*"]
/// require = { "event_name" = "push" }
/// leeway_seconds = 30
/// ```
///
/// The secret is a FILE PATH: holding that key puts this deployment inside
/// the forge's trust boundary, so it is provisioned like a key, not pasted
/// into a shareable config.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct RuntimeForgeConfig {
    /// Master switch for this forge; a disabled block is inert.
    pub enabled: bool,
    /// Path to the forge's general token signing secret (trimmed; must be
    /// non-empty).
    pub secret: PathBuf,
    /// Claim path whose VALUE is the tenant. Default
    /// `oidc_extra.repository`, falling back to
    /// `oidc_extra.repository_owner` when that is absent.
    pub tenant_claim: String,
    /// Optional `scp` allow-list: the token must carry at least one scope
    /// entry matching one pattern (`*` matches any run of characters).
    pub scopes: Vec<String>,
    /// Optional claim pins, same semantics as the OIDC gate's `require`
    /// (exact string or array membership). A bare key first matches a
    /// top-level claim, then falls back into `oidc_extra`.
    pub require: BTreeMap<String, String>,
    /// Clock-skew leeway for `exp`/`nbf`.
    pub leeway_seconds: u64,
}

impl Default for RuntimeForgeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            secret: PathBuf::new(),
            tenant_claim: String::from("oidc_extra.repository"),
            scopes: Vec::new(),
            require: BTreeMap::new(),
            leeway_seconds: 30,
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

/// `[auth.oidc]` - OIDC RS256 bearer acceptance (v1.1 workstream A;
/// docs/oidc.md is the contract). Entirely default-off: omitting the table
/// (or leaving `enabled = false`) leaves v1.0 behavior byte-identical.
///
/// v1.2 shape: the parent table carries the global knobs, and each
/// **issuer** is its own block:
///
/// ```toml
/// [auth.oidc]
/// enabled = true
/// jwks_refresh_seconds = 1800
/// jwks_max_keys = 32
/// jwks_ca_pem = "/etc/ssl/certs/ca-certificates.crt"
///
/// [auth.oidc."https://idp.example.org/realms/ci"]
/// audiences = ["cachette"]
/// jwks_url = "https://idp.example.org/realms/ci/protocol/openid-connect/certs"
/// tenant_claim = "repository"
/// require = { "groups" = "ci" }
/// leeway_seconds = 30
/// ca_pem = "/etc/ssl/certs/private-root.pem"
/// ```
///
/// The v1.1 flat shape (`issuers` / `audiences` / `jwks_urls` / `require`
/// on the parent) is gone: audiences and claim pins are per-issuer, because
/// one deployment routinely trusts several IdPs whose audiences and pins
/// have nothing to do with each other.
///
/// `#[serde(flatten)]` cannot be combined with `deny_unknown_fields`
/// (serde rejects the combination), so the parent drops that attribute -
/// but a mistyped *global* key still fails loudly: it lands in the issuer
/// map and cannot deserialize as an issuer block. The per-issuer struct
/// keeps `deny_unknown_fields`, so an unknown key *inside* a block is
/// rejected too.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct OidcConfig {
    /// Master switch; the whole table is inert when false.
    pub enabled: bool,
    /// Periodic JWKS re-fetch interval (lazy unknown-kid refresh happens
    /// regardless); 0 is rejected by `config::validate`.
    pub jwks_refresh_seconds: u64,
    /// Hard cap on cached keys server-wide (rotation-flooding guard).
    pub jwks_max_keys: usize,
    /// Default trust roots for the JWKS fetch (a per-issuer `ca_pem`
    /// overrides this for a private-CA issuer).
    pub jwks_ca_pem: Option<PathBuf>,
    /// Per-issuer blocks, keyed by the issuer string (the exact `iss`
    /// claim the tokens carry). Last field on purpose: with `flatten` the
    /// map's tables must be emitted after the parent's own values (TOML
    /// requires values before tables).
    #[serde(flatten)]
    pub issuers: BTreeMap<String, OidcIssuerConfig>,

    // ---- the v1.1 flat shape, accepted ONLY to fail precisely ----
    //
    // v1.2 moved `issuers` / `audiences` / `jwks_urls` / `require` /
    // `leeway_seconds` into per-issuer blocks. Without these fields a
    // v1.1 config would fail with a serde type error ("invalid type:
    // sequence, expected struct OidcIssuerConfig") that says nothing about
    // the new form; with them the validation layer can name it. They are
    // never read for anything else and never serialized back.
    #[serde(rename = "issuers", default, skip_serializing)]
    pub legacy_issuers: Option<Vec<String>>,
    #[serde(rename = "audiences", default, skip_serializing)]
    pub legacy_audiences: Option<Vec<String>>,
    #[serde(rename = "jwks_urls", default, skip_serializing)]
    pub legacy_jwks_urls: Option<BTreeMap<String, String>>,
    #[serde(rename = "require", default, skip_serializing)]
    pub legacy_require: Option<BTreeMap<String, String>>,
    #[serde(rename = "leeway_seconds", default, skip_serializing)]
    pub legacy_leeway_seconds: Option<u64>,
}

/// One configured OIDC issuer (v1.2 shape: `[auth.oidc."<issuer>"]`).
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct OidcIssuerConfig {
    /// `aud` values a token may state (any of); required.
    pub audiences: Vec<String>,
    /// Explicit JWKS URL; the default endpoint is derived as
    /// `{issuer}/.well-known/jwks.json` (docs/oidc.md §JWKS handling).
    pub jwks_url: Option<String>,
    /// Claim whose VALUE is the tenant of this issuer's tokens
    /// (`docs/shared-cache.md` §7): the namespace becomes
    /// `"<issuer>|<tenant>"` unless an admin mapping overrides it. Defaults
    /// to `repository`; a token without this claim is rejected in
    /// multi-tenant use, never defaulted.
    #[serde(default = "default_tenant_claim")]
    pub tenant_claim: String,
    /// Optional claim -> exact-value pin (`repository = "owner/repo"`).
    /// Array-valued claims authorize when they contain the value.
    pub require: BTreeMap<String, String>,
    /// Clock skew tolerated on `exp`/`nbf` (seconds) for this issuer.
    pub leeway_seconds: u64,
    /// Trust roots for this issuer's JWKS fetch; overrides
    /// `[auth.oidc] jwks_ca_pem`.
    pub ca_pem: Option<PathBuf>,
}

fn default_tenant_claim() -> String {
    String::from("repository")
}

impl Default for OidcIssuerConfig {
    fn default() -> Self {
        Self {
            audiences: Vec::new(),
            jwks_url: None,
            tenant_claim: default_tenant_claim(),
            require: BTreeMap::new(),
            leeway_seconds: 30,
            ca_pem: None,
        }
    }
}

impl Default for OidcConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            jwks_refresh_seconds: 1800,
            jwks_max_keys: 32,
            jwks_ca_pem: None,
            issuers: BTreeMap::new(),
            legacy_issuers: None,
            legacy_audiences: None,
            legacy_jwks_urls: None,
            legacy_require: None,
            legacy_leeway_seconds: None,
        }
    }
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
    /// Dedicated mTLS listener for peer traffic (always on when `enabled`).
    /// Serves the self-signed node identity certificate; peer trust is by
    /// SPKI fingerprint pin, not a CA chain.
    pub listen: String,
    /// Defaults to `cluster.listen` (m5).
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
            listen: String::from("0.0.0.0:8081"),
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
    pub file: Option<PathBuf>,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: LogLevel::Info,
            format: LogFormat::Text,
            file: None,
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
