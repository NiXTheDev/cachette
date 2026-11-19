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

    /// `[storage.cdc] avg_chunk_bytes` outside the chunker's useful window;
    /// validated regardless of `enabled` so a bad value cannot hide until
    /// the flag flips on.
    #[error("storage.cdc.avg_chunk_bytes must be within 32768..=1048576 (got {value})")]
    CdcAvgRange { value: u64 },

    /// `[storage.cdc] backfill_delay_ms` is zero - the backfill walker would
    /// hot-spin between conversions; validated regardless of `enabled` so a
    /// bad value cannot hide until the flag flips on (same policy as
    /// `avg_chunk_bytes`).
    #[error("storage.cdc.backfill_delay_ms must be at least 1 (got 0)")]
    ZeroCdcBackfillDelay,

    /// `[auth] secret` missing at serve time (not checked by `--print-config`).
    #[error(
        "auth.secret is required to serve: set [auth] secret in the config file or the \
         CACHETTE__AUTH__SECRET environment variable (minimum 16 characters)"
    )]
    MissingSecret,

    /// `[auth] secret` shorter than 16 characters at serve time.
    #[error("auth.secret must be at least 16 characters (got {len})")]
    ShortSecret { len: usize },

    /// `[auth.oidc] enabled without a required list, pin or CA bundle.
    #[error(
        "storage.namespaces key {key:?} must have the form \"<forge>|<tenant>\" with both halves non-empty"
    )]
    NamespaceMappingKey { key: String },
    #[error("auth.oidc is enabled but {field} must be configured")]
    OidcMissingRequired { field: &'static str },

    /// A per-issuer OIDC block is missing something it needs.
    #[error("auth.oidc block for issuer {issuer:?} is missing {field}")]
    OidcIssuerMissing { issuer: String, field: &'static str },

    /// The v1.1 flat `[auth.oidc]` shape, which v1.2 replaced with
    /// per-issuer blocks.
    #[error(
        "auth.oidc.{key} is the v1.1 flat shape; v1.2 configures one block per issuer: \
         [auth.oidc.\"<issuer>\"] with audiences = [...] (and require / jwks_url / ca_pem / \
         leeway_seconds inside that block)"
    )]
    OidcLegacyShape { key: &'static str },

    /// `[auth.oidc] jwks_refresh_seconds` is zero.
    #[error("auth.oidc.jwks_refresh_seconds must be greater than 0")]
    OidcZeroRefresh,

    /// `[auth.oidc] jwks_max_keys` is zero.
    #[error("auth.oidc.jwks_max_keys must be greater than 0")]
    OidcZeroMaxKeys,

    /// A `jwks_urls` endpoint (or a default derivation target) is not HTTPS.
    #[error("auth.oidc JWKS endpoint for {issuer:?} must be https (got {url})")]
    OidcJwksPlaintext { issuer: String, url: String },

    /// An issuer URL is not HTTPS: the default JWKS endpoint would be
    /// derived as `{issuer}/.well-known/jwks.json`, so a plaintext issuer
    /// would mean a plaintext fetch. Only explicit overrides may deviate,
    /// and those are already pinned to `https` themselves.
    #[error(
        "auth.oidc issuer {issuer:?} must be an https URL (default JWKS endpoints derive from it)"
    )]
    OidcIssuerPlaintext { issuer: String },

    /// An `[auth.runtime]` forge id is empty or contains the namespace
    /// separator (`"<forge>|<tenant>"` would be ambiguous).
    #[error(
        "auth.runtime forge key {forge:?} must be non-empty and must not contain '|' (it is the \
         forge half of the namespace)"
    )]
    RuntimeForgeKey { forge: String },

    /// An enabled runtime block names no secret file.
    #[error("auth.runtime forge {forge:?} is enabled but secret is not configured")]
    RuntimeSecretMissing { forge: String },

    /// An enabled runtime block has an empty tenant claim path.
    #[error("auth.runtime forge {forge:?} has an empty tenant_claim")]
    RuntimeTenantClaimMissing { forge: String },

    /// A tenant-yielding credential plane is enabled (`[auth.oidc]
    /// enabled = true`) together with the HMAC plane. Plane C's repo/run
    /// fields are client-asserted and cannot express a tenant, so an
    /// `hmac`/`merge` mode would funnel every HMAC request into one shared
    /// namespace (`docs/shared-cache.md` §2/§9).
    #[error(
        "auth.mode = \"{mode}\" with a tenant-yielding credential plane ([auth.oidc] enabled) \
         is a multi-tenant deployment, but HMAC cannot express a tenant - set \
         auth.mode = \"bearer\""
    )]
    HmacInMultiTenant { mode: &'static str },

    /// A tenant-yielding credential plane is enabled with `cluster.enabled`.
    /// The peer wire does not carry namespaces yet (§8), so a peer would
    /// relay and store namespaced rows as legacy ones.
    #[error(
        "cluster.enabled with a tenant-yielding credential plane ([auth.oidc] enabled) is not \
         supported yet: the peer wire does not carry namespaces (docs/shared-cache.md §8)"
    )]
    ClusterInMultiTenant,

    /// A `serde_json` failure while rendering `--print-config` output.
    /// Effectively unreachable; kept so rendering never panics.
    #[error("internal config serialization error: {0}")]
    Internal(String),
}
