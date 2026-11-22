//! Shared application state (plan task 3).

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};

use crate::auth::oidc::OidcVerifier;
use crate::auth::runtime::{RuntimeVerifier, SharedRuntimeVerifier};
use crate::auth::{AuthPolicy, Namespace, TokenStore};
use crate::cluster::PeerTable;
use crate::cluster::quota::ClusterQuota;
use crate::cluster::relay::ClusterRelay;
use crate::config::{Config, KeyCase, MinFree, OidcConfig, Quotas, glob_matches};
use crate::metrics::Metrics;
use crate::storage::StorageBackend;
use crate::tls::PeerPins;

/// Cache capacity + reservation knobs threaded onto the request path (plan
/// task 19). `AppState` carries no full [`crate::config::Config`] (the v1
/// module keeps its own constants for the write-once knobs), but the reserve
/// handler needs the live `[cache]` / `[storage.fs]` numbers to report
/// `cacheSize`, stamp `reservation_expires_at`, and fold keys.
#[derive(Clone, Copy, Debug)]
pub struct CacheLimits {
    /// `[cache] max_size` in bytes; 0 = unlimited.
    pub max_size: u64,
    /// `[storage.fs] min_free` floor (B3 reserve-time admission estimate).
    pub min_free: MinFree,
    /// `[cache] reservation_ttl_seconds`: reservation expiry = now + this.
    pub reservation_ttl_seconds: u64,
    /// `[cache] key_case`: fold applied before reserve/find matching (M11).
    pub key_case: KeyCase,
    /// `[v1] signed_url_ttl_seconds` for capability/signed URLs.
    pub signed_url_ttl_seconds: u64,
    /// `[server] max_chunk_bytes` (plan task 45): the largest single PATCH
    /// chunk / Azure block the request path accepts. One request can hold at
    /// most this many bytes, so it bounds per-request memory.
    pub max_chunk_bytes: u64,
}

impl CacheLimits {
    /// Snapshot the reloadable `[cache]` / `[storage.fs]` / protocol knobs from
    /// a resolved config. Used at boot and by the SIGHUP reload path (plan task
    /// 49) so both construct limits identically.
    #[must_use]
    pub fn from_config(config: &Config) -> Self {
        Self {
            max_size: config.cache.max_size,
            min_free: config.storage.fs.min_free,
            reservation_ttl_seconds: config.cache.reservation_ttl_seconds,
            key_case: config.cache.key_case,
            signed_url_ttl_seconds: config.v1.signed_url_ttl_seconds,
            max_chunk_bytes: config.server.max_chunk_bytes,
        }
    }
}

impl Default for CacheLimits {
    fn default() -> Self {
        Self {
            max_size: 0,
            min_free: MinFree::Fraction(0.2),
            reservation_ttl_seconds: 3600,
            key_case: KeyCase::Preserve,
            signed_url_ttl_seconds: crate::config::V1Config::default().signed_url_ttl_seconds,
            max_chunk_bytes: crate::config::ServerConfig::default().max_chunk_bytes,
        }
    }
}

/// OIDC runtime state (v1.1 workstream A): the verifier `auth::oidc::install`
/// hung on the state at BOOT plus the boot config's `[auth.oidc]` signature.
/// A SIGHUP reload never swaps the verifier (docs/oidc.md rollout: toggling
/// `enabled` requires only a restart); `apply_reload` warns when the
/// reloaded table differs from the boot signature.
#[derive(Debug, Default)]
pub struct OidcRuntime {
    /// The boot-installed verifier; `None` when `[auth.oidc]` was absent or
    /// disabled at boot.
    pub verifier: Option<Arc<OidcVerifier>>,
    /// JSON signature of the `[auth.oidc]` section the boot install used,
    /// for the reload warn-on-change; `None` = installed with OIDC off (or
    /// never installed).
    pub boot_signature: Option<String>,
}

/// Named storage backends and the namespace -> instance routing table.
/// Backends and the default instance are fixed at boot; routes are swapped
/// atomically by a SIGHUP reload.
#[derive(Default)]
pub struct InstanceRegistry {
    backends: BTreeMap<String, Arc<dyn StorageBackend>>,
    routes: Vec<(String, String)>,
    default_name: String,
}

impl InstanceRegistry {
    pub fn new(
        backends: BTreeMap<String, Arc<dyn StorageBackend>>,
        routes: Vec<(String, String)>,
        default_name: String,
    ) -> Self {
        Self {
            backends,
            routes,
            default_name,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.backends.is_empty()
    }

    pub fn set_routes(&mut self, routes: Vec<(String, String)>) {
        self.routes = routes;
    }

    pub fn names(&self) -> Vec<String> {
        self.backends.keys().cloned().collect()
    }

    /// Exact namespace match, then the longest matching glob, then `"*"`,
    /// then the default instance.
    pub fn resolve(&self, namespace: &str) -> &str {
        let mut best: Option<(&str, &str)> = None; // (pattern, instance)
        for (pattern, instance) in &self.routes {
            let matches =
                pattern == namespace || (pattern.contains('*') && glob_matches(pattern, namespace));
            if !matches {
                continue;
            }
            let is_star = pattern == "*";
            let better = match best {
                None => true,
                Some((current, _)) => !is_star && (current == "*" || pattern.len() > current.len()),
            };
            if better {
                best = Some((pattern, instance));
            }
        }
        best.map(|(_, instance)| instance)
            .filter(|name| self.backends.contains_key(*name))
            .unwrap_or(self.default_name.as_str())
    }

    pub fn get(&self, name: &str) -> Option<Arc<dyn StorageBackend>> {
        self.backends.get(name).cloned()
    }
}

/// State threaded through every route handler.
#[derive(Clone)]
pub struct AppState {
    /// Crate version (`CARGO_PKG_VERSION`), surfaced by `/health`.
    pub version: &'static str,
    /// Node identity — replaced with the Ed25519 fingerprint during startup
    /// (plan task 13); the hostname placeholder applies only before then.
    pub node_id: String,
    /// `--config <path>` placeholder; config loading lands in plan task 5.
    pub config_path: Option<PathBuf>,
    /// Storage handle; `None` until a backend is constructed (plan tasks 8-9).
    /// v1.3: the `default` instance is also held here so capacity/reaper code
    /// keeps its existing call shape.
    pub storage: Option<Arc<dyn StorageBackend>>,
    /// v1.3 named storage instances and namespace routes. Empty for legacy
    /// single-backend deployments and tests, which keep using `storage`.
    pub instances: Arc<RwLock<InstanceRegistry>>,
    /// Cluster peer-certificate pins (plan task 14 / B2). Seeded from
    /// `[cluster] seed_fingerprints`; gates `/_internal/peers/*`.
    pub peers: Arc<PeerPins>,
    /// Cluster peer table (plan task 28): the deduplicated set of discovered
    /// peers (seeds + mDNS + hello). `serve()` seeds it when `[cluster]
    /// enabled`; the default is an empty table so single-node tests keep
    /// working.
    pub peer_table: Arc<PeerTable>,
    /// Dynamic bearer-token store (plan task 15): sqlite-backed register/
    /// revoke, shared with the storage backend's database file.
    pub tokens: Arc<TokenStore>,
    /// Auth policy snapshot (plan task 15): per-request mode resolution for
    /// the v1 artifactcache routes plus the admin register/revoke gate.
    ///
    /// The inner `Arc<AuthPolicy>` is swapped wholesale by a SIGHUP config
    /// reload (plan task 49) — readers clone the `Arc` (an atomic refcount
    /// bump, no heap allocation) so an in-flight request keeps the policy it
    /// started with and never holds the lock across an `.await`.
    pub auth: Arc<RwLock<Arc<AuthPolicy>>>,
    /// OIDC bearer verification (v1.1 workstream A): the boot-installed
    /// verifier behind [`OidcRuntime`]. Reload keeps whatever was installed
    /// and only warns on a changed config (restart required).
    pub oidc: Arc<RwLock<OidcRuntime>>,
    /// Forge runtime-token verification (v1.2 Plane B,
    /// `docs/shared-cache.md` §3): the boot-installed verifier, if any.
    /// Boot-time only, like the OIDC verifier - a SIGHUP reload never swaps
    /// it. `None` keeps Plane B off.
    pub runtime: Arc<RwLock<Option<SharedRuntimeVerifier>>>,
    /// Cache capacity + reservation knobs (plan task 19), shared so a SIGHUP
    /// reload (plan task 49) can refresh them live. Readers take a `Copy`
    /// snapshot through [`AppState::cache_limits`].
    pub cache: Arc<RwLock<CacheLimits>>,
    /// Admin namespace mappings (v1.2 workstream F, `docs/shared-cache.md`
    /// §7): `"<forge>|<tenant>"` -> namespace name. Boot-time wiring (the
    /// Rollout contract: changing tenancy needs a restart); the default is
    /// empty, so every credential keeps its derived namespace.
    pub namespaces: Arc<std::collections::BTreeMap<String, String>>,
    /// Per-namespace byte limits (v1.2 workstream F, `docs/shared-cache.md`
    /// §5). Swapped wholesale by a SIGHUP reload; the default has no quotas,
    /// so every namespace is unlimited.
    pub quotas: Arc<RwLock<Arc<Quotas>>>,
    /// Cluster gossip: peer quota votes and per-(instance, namespace) usage.
    pub cluster_quota: Arc<RwLock<ClusterQuota>>,
    /// Runner-visible base URL (`[server] external_url`, resolved from `listen`
    /// when unset) prefixed onto capability URLs minted for `/v2/*` (task 24).
    /// `None` yields host-relative URLs (tests without a configured host).
    pub external_url: Option<String>,
    /// v1 relay transport (plan task 31): forwards a cluster-mode upload to the
    /// placement owner. `Some` only when `[cluster] enabled`; `None` keeps the
    /// single-node local path byte-for-byte unchanged.
    pub relay: Option<Arc<ClusterRelay>>,
    /// Resolved B3 `total` bytes (`[cache] max_size` when set, else the storage
    /// path's disk total), cached at boot (plan task 31): the owner reservation
    /// path re-checks live admission without a blocking disk query on the
    /// request path.
    pub capacity_total: u64,
    /// Hand-counted request-path counters exposed by `GET /metrics` (task 35).
    pub metrics: Arc<Metrics>,
    /// Graceful-drain flag (plan task 47): set on SIGTERM/SIGINT. While true the
    /// node advertises `draining` via heartbeat, reports not-ready on `/readyz`,
    /// and refuses NEW uploads with `503` while still serving in-flight
    /// requests (PATCH chunks, finalize, downloads).
    pub draining: Arc<AtomicBool>,
    /// Storage-backend health (plan task 49): readiness reports not-ready while
    /// false. Defaults `true`; the periodic sweep (and shutdown) flips it on a
    /// storage error and back on the next success. Tests flip it directly to
    /// exercise the `/readyz` storage-fault branch.
    pub storage_ok: Arc<AtomicBool>,
}

impl AppState {
    /// Fresh state: no config path, no storage backend, hostname node id, and
    /// an empty pin store (no seeded peers, TOFU off).
    pub fn new() -> Self {
        Self {
            version: env!("CARGO_PKG_VERSION"),
            node_id: default_node_id(),
            config_path: None,
            storage: None,
            instances: Arc::new(RwLock::new(InstanceRegistry::default())),
            peers: Arc::new(PeerPins::default()),
            peer_table: Arc::new(PeerTable::new()),
            tokens: Arc::new(TokenStore::open_memory().expect("in-memory token store")),
            auth: Arc::new(RwLock::new(Arc::new(AuthPolicy::default()))),
            oidc: Arc::new(RwLock::new(OidcRuntime::default())),
            runtime: Arc::new(RwLock::new(None)),
            cache: Arc::new(RwLock::new(CacheLimits::default())),
            namespaces: Arc::new(std::collections::BTreeMap::new()),
            quotas: Arc::new(RwLock::new(Arc::new(Quotas::default()))),
            cluster_quota: Arc::new(RwLock::new(ClusterQuota::default())),
            external_url: None,
            relay: None,
            capacity_total: 0,
            metrics: Arc::new(Metrics::default()),
            draining: Arc::new(AtomicBool::new(false)),
            storage_ok: Arc::new(AtomicBool::new(true)),
        }
    }

    /// The live auth policy (plan task 49). Clones the inner `Arc` — no heap
    /// allocation, and the returned handle is `Send`, so callers may hold it
    /// across an `.await` (the lock itself is released immediately).
    #[must_use]
    pub fn auth(&self) -> Arc<AuthPolicy> {
        self.auth
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Replace the live auth policy (boot + SIGHUP reload).
    pub fn set_auth(&self, policy: AuthPolicy) {
        *self
            .auth
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(policy);
    }

    /// Install the boot-built OIDC verifier (v1.1 workstream A): the verifier
    /// itself plus a JSON signature of the `[auth.oidc]` section that built
    /// it. Called once at boot by [`crate::auth::oidc::install`]; a SIGHUP
    /// reload never re-installs (docs/oidc.md rollout: toggling `enabled`
    /// requires only a restart).
    pub fn install_oidc(&self, verifier: OidcVerifier, oidc: &OidcConfig) {
        *self
            .oidc
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = OidcRuntime {
            verifier: Some(Arc::new(verifier)),
            boot_signature: Some(oidc_signature(oidc)),
        };
    }

    /// The boot-installed OIDC verifier, if any. `None` when `[auth.oidc]`
    /// was absent or disabled at boot — rejection behavior is then exactly
    /// v1.0's. Clones the `Arc` (atomic refcount bump, no lock held after).
    #[must_use]
    pub fn oidc(&self) -> Option<Arc<OidcVerifier>> {
        self.oidc
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .verifier
            .clone()
    }

    /// Install the boot-built forge runtime-token verifier (v1.2 Plane B,
    /// `docs/shared-cache.md` §3). Called once at boot by
    /// [`crate::auth::runtime::install`]; a SIGHUP reload never re-installs.
    pub fn install_runtime(&self, verifier: RuntimeVerifier) {
        *self
            .runtime
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Arc::new(verifier));
    }

    /// The boot-installed runtime-token verifier, if any. `None` when no
    /// `[auth.runtime]` block was enabled at boot - Plane B is then off.
    /// Clones the `Arc` (atomic refcount bump, no lock held after).
    #[must_use]
    pub fn runtime(&self) -> Option<SharedRuntimeVerifier> {
        self.runtime
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// A `Copy` snapshot of the live cache limits (no lock held afterwards).
    #[must_use]
    pub fn cache_limits(&self) -> CacheLimits {
        *self
            .cache
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// A view of the storage backend restricted to `namespace` (v1.2
    /// workstream F, `docs/shared-cache.md` §1/§4).
    ///
    /// The namespace is part of a row's identity: the view only ever observes
    /// and mutates rows of its own namespace, so two tenants never share a
    /// row even with identical keys and versions. The legacy `""` namespace
    /// is the single-tenant row set — what the unscoped backend operates on —
    /// so single-tenant deployments are unchanged. Creating a view is cheap
    /// (shared connection/gate/locks, no re-open), which is what makes
    /// per-request namespace resolution viable.
    #[must_use]
    pub fn storage_scoped(&self, namespace: &str) -> Option<Arc<dyn StorageBackend>> {
        let registry = self
            .instances
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if registry.is_empty() {
            return self
                .storage
                .as_ref()
                .map(|backend| backend.scoped(namespace));
        }
        let name = registry.resolve(namespace);
        registry.get(name).map(|backend| backend.scoped(namespace))
    }

    /// Install the boot-time instance set and routing table.
    pub fn set_instances(
        &self,
        backends: BTreeMap<String, Arc<dyn StorageBackend>>,
        routes: Vec<(String, String)>,
        default_name: String,
    ) {
        let mut registry = self
            .instances
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *registry = InstanceRegistry::new(backends, routes, default_name);
    }

    /// Replace the live routing table on a SIGHUP reload. In-flight requests
    /// that already cloned a scoped backend keep using it for that call.
    pub fn set_routes(&self, routes: Vec<(String, String)>) {
        self.instances
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .set_routes(routes);
    }

    /// Instance name a namespace resolves to, for logs and the cluster wire.
    #[must_use]
    pub fn resolve_storage(&self, namespace: &str) -> String {
        let registry = self
            .instances
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if registry.is_empty() {
            String::from("default")
        } else {
            registry.resolve(namespace).to_owned()
        }
    }

    /// Apply the admin namespace mapping (v1.2 workstream F,
    /// `docs/shared-cache.md` §7): an exact `"<forge>|<tenant>"` match
    /// replaces the derived namespace; every other identity keeps it. The
    /// mapping is boot-time wiring - tenancy changes need a restart.
    #[must_use]
    pub fn resolve_namespace(&self, namespace: Namespace) -> Namespace {
        self.namespaces
            .get(&namespace.0)
            .map(|mapped| Namespace(mapped.clone()))
            .unwrap_or(namespace)
    }

    /// The byte limit of a RESOLVED namespace (v1.2 workstream F,
    /// `docs/shared-cache.md` §5), or `None` when quotas are off.
    #[must_use]
    pub fn quota_for(&self, namespace: &str) -> Option<u64> {
        let local = self
            .quotas
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .limit_for(namespace);
        if local.is_some() {
            return local;
        }
        // Semi-binding fallback: the cluster's plurality vote for this exact
        // target, then its `*` catch-all. Abstentions are ignored by `consensus`.
        let gossip = self
            .cluster_quota
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        gossip
            .consensus("namespace", namespace)
            .or_else(|| gossip.consensus("namespace", "*"))
    }

    /// Replace one peer's quota votes and usage reports from its heartbeat.
    pub fn observe_quota(
        &self,
        node: &str,
        votes: Vec<crate::cluster::quota::RuleVote>,
        usage: Vec<crate::cluster::quota::UsageReport>,
    ) {
        self.cluster_quota
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .observe(node, votes, usage);
    }

    /// Snapshot for the eviction reaper (boot and reload).
    #[must_use]
    pub fn quotas_snapshot(&self) -> Arc<Quotas> {
        self.quotas
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Replace the live quota rules (boot + SIGHUP reload).
    pub fn set_quotas(&self, quotas: Quotas) {
        *self
            .quotas
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(quotas);
    }

    /// Replace the live cache limits (boot + SIGHUP reload).
    pub fn set_cache_limits(&self, limits: CacheLimits) {
        *self
            .cache
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = limits;
    }

    /// Mutate the live cache limits in place (test helper).
    pub fn with_cache_limits(&self, f: impl FnOnce(&mut CacheLimits)) {
        let mut guard = self
            .cache
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        f(&mut guard);
    }

    /// Whether the storage backend is currently considered healthy (plan task
    /// 49 readiness signal).
    #[must_use]
    pub fn storage_ok(&self) -> bool {
        self.storage_ok.load(Ordering::Relaxed)
    }

    /// Record the storage backend's health (readiness signal).
    pub fn set_storage_ok(&self, ok: bool) {
        self.storage_ok.store(ok, Ordering::Relaxed);
    }

    /// Apply one reloaded config's reloadable subset in place (plan task 49):
    /// the auth policy and the cache limits. Boot-only knobs (listen addresses,
    /// the data directory, the storage backend, cluster wiring) are not touched.
    ///
    /// v1.1: the OIDC verifier installed at boot is deliberately NOT swapped
    /// (docs/oidc.md rollout — toggling/retuning OIDC requires a restart, so
    /// an in-flight verifier keeps a consistent JWKS/trust state). A reloaded
    /// `[auth.oidc]` section that differs from the boot signature is warned
    /// about on every such reload — persistent by design, a standing reminder
    /// that the running verifier is not the configured one.
    pub fn apply_reload(&self, config: &Config) {
        self.set_auth(AuthPolicy::from_config(config));
        self.set_cache_limits(CacheLimits::from_config(config));
        self.set_routes(config.storage.routes.clone().into_iter().collect());
        // Validation at load time guarantees the rules parse.
        if let Ok(quotas) = config.storage.quotas.parse() {
            self.set_quotas(quotas);
        }
        let reloaded_signature = config
            .auth
            .oidc
            .as_ref()
            .filter(|oidc| oidc.enabled)
            .map(oidc_signature);
        let runtime = self
            .oidc
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if runtime.boot_signature != reloaded_signature && reloaded_signature.is_some() {
            tracing::warn!(
                "reloaded [auth.oidc] differs from the section the boot verifier was built \
                 with; the boot verifier stays active until a restart"
            );
        }
    }
}

/// JSON signature of an `[auth.oidc]` section for boot-vs-reload comparison.
/// Complexity is fine here: called once per install and once per reload.
fn oidc_signature(oidc: &OidcConfig) -> String {
    serde_json::to_string(oidc).unwrap_or_else(|_| String::from("<unrepresentable>"))
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

/// Placeholder node id: the host name — `COMPUTERNAME` on Windows, `HOSTNAME`
/// on Unix-likes — falling back to `"local"`. `serve()` overwrites it with the
/// certificate fingerprint (plan task 13).
fn default_node_id() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| String::from("local"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Plan task 3 acceptance: unit-test the version parse - the crate's
    /// own version is semver: exactly three numeric components. (The
    /// literal [1, 0, 0] this once pinned died with the 1.1.0 cut: a
    /// version snapshot is not the contract, the parse is.)
    #[test]
    fn version_parses_as_semver_matching_the_package() {
        let raw = env!("CARGO_PKG_VERSION");
        let components: Vec<u64> = raw
            .split('.')
            .map(|part| part.parse::<u64>().expect("version component is numeric"))
            .collect();
        assert_eq!(components.len(), 3, "unexpected version: {raw}");
    }

    /// `docs/shared-cache.md` §7: an exact `"<forge>|<tenant>"` mapping
    /// replaces the derived namespace; every other identity keeps it.
    #[test]
    fn resolve_namespace_applies_the_admin_mapping() {
        let mut state = AppState::new();
        state.namespaces = Arc::new(std::collections::BTreeMap::from([(
            String::from("https://forge.example.org|octo-org/api"),
            String::from("acme-shared"),
        )]));
        assert_eq!(
            state.resolve_namespace(Namespace(String::from(
                "https://forge.example.org|octo-org/api"
            ))),
            Namespace(String::from("acme-shared"))
        );
        assert_eq!(
            state.resolve_namespace(Namespace(String::from(
                "https://forge.example.org|octo-org/other"
            ))),
            Namespace(String::from("https://forge.example.org|octo-org/other"))
        );
        assert_eq!(
            state.resolve_namespace(Namespace::legacy()),
            Namespace::legacy()
        );
    }

    #[test]
    fn registry_resolves_exact_then_longest_glob_then_star_then_default() {
        let dir = std::env::temp_dir().join(format!("cachette-registry-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let fs: Arc<dyn StorageBackend> =
            Arc::new(crate::storage::fs::FsStorage::open(&dir).expect("fs"));
        let mut backends = BTreeMap::new();
        for name in ["default", "east", "scratch"] {
            backends.insert(String::from(name), fs.clone());
        }
        let routes = vec![
            (String::from("acme|*"), String::from("east")),
            (String::from("acme|team/*"), String::from("scratch")),
            (String::from("acme|team/exact"), String::from("default")),
            (String::from("*"), String::from("default")),
        ];
        let registry = InstanceRegistry::new(backends, routes, String::from("default"));
        assert_eq!(registry.resolve("acme|team/exact"), "default");
        assert_eq!(registry.resolve("acme|team/other"), "scratch");
        assert_eq!(registry.resolve("acme|ops"), "east");
        assert_eq!(registry.resolve("other|ns"), "default");
        std::fs::remove_dir_all(&dir).ok();
    }
}
