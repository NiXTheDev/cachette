//! Live JWKS fetching for OIDC bearer verification (v1.1 workstream A;
//! docs/oidc.md §JWKS handling / §Fetching is the contract).
//!
//! [`JwksCache`] is the production [`RsaKeySource`]: it keeps an
//! `(issuer, kid) -> JwksKey` map for the *configured* issuers and refreshes
//! it on TWO triggers — a periodic pass every `jwks_refresh_seconds`, and a
//! lazy singleflight kicked by a token whose `kid` is not cached yet (one
//! fetch in flight per spacing window; other misses fail with the current
//! knowledge cached). Signature verification itself lives in
//! [`crate::auth::oidc`]; this module only ever supplies key material.
//!
//! Fetching follows the hand-rolled HTTP/1.1 + `Connection: close` pattern
//! already proven in [`crate::cluster::heartbeat`] (no HTTP client crate is
//! added): a fresh TLS connection per fetch, rustls verifying the IdP's
//! chain against the configured `jwks_ca_pem` bundle (self-hosted IdPs carry
//! their own CA; no web-roots crate). Failures — DNS, TLS, non-2xx, a body
//! over the size cap, junk JSON — log one line and leave the cache
//! untouched, so previously-cached keys keep verifying while tokens needing
//! a NEW key fail closed.
//!
//! Locking: `key()` is a synchronous trait method called from async
//! executors, so the key map and the throttle stamps use std locks held
//! briefly enough to never await (a tokio `RwLock` would panic under
//! `blocking_read` semantics here). Background tasks hold only a `Weak`
//! between ticks: dropping the cache (a process exit or an eventual
//! verifier replacement) silently ends both loops.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::{Duration, Instant};

use rustls::pki_types::ServerName;
use rustls::{ClientConfig as RustlsClientConfig, RootCertStore};
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::runtime::Handle;
use tokio::time::MissedTickBehavior;
use tokio_rustls::TlsConnector;

use crate::auth::jwks::{JwksKey, RsaKeySource};
use crate::config::OidcConfig;

/// Whole-fetch budget: TCP + TLS + the full response. A stalled IdP legs a
/// lazy refresh at most this long (the miss fails closed meanwhile).
const FETCH_BUDGET: Duration = Duration::from_secs(5);

/// Response cap: a JWKS bundle for sane IdPs is a few KiB; anything over
/// this is refused wholesale rather than buffered (rotation-flooding guard).
const MAX_BODY_BYTES: usize = 1024 * 1024;

/// Lazy-refresh spacing window: the FIRST miss stamps the issuer and spawns
/// one fetch; further misses inside the window do not re-fetch (the
/// singleflight, docs/oidc.md). Windowed rather than "await the in-flight
/// fetch" because `key()` is synchronous by contract.
const MIN_REFRESH_SPACING: Duration = Duration::from_secs(5);

/// Why a JWKS cache could not even be built (boot-fatal; `config::validate`
/// already guarantees the config surface, so these guard file-level reality).
#[derive(Debug, thiserror::Error)]
pub enum JwksCacheError {
    /// `[auth.oidc] enabled` without `jwks_ca_pem` (validate's belt; never
    /// reached through [`crate::auth::oidc::install`], kept for direct use).
    #[error("auth.oidc is enabled but jwks_ca_pem must be configured")]
    MissingCaPem,
    /// The CA bundle path is unreadable or unparseable.
    #[error("jwks_ca_pem {path}: {source}")]
    CaUnreadable {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// The bundle parsed but contains no usable certificate: an empty
    /// trust store would silently trust nothing, so it refuses to boot.
    #[error("jwks_ca_pem {0} contains no usable certificate")]
    CaEmpty(PathBuf),
    /// The rustls client could not be assembled.
    #[error("jwks fetch TLS client: {0}")]
    Tls(String),
}

/// The insertion-ordered key set. A successful refresh REPLACES the whole
/// issuer set (docs/oidc.md rotation semantics); the global `jwks_max_keys`
/// cap evicts in insertion order across all issuers.
#[derive(Debug, Default)]
struct KeyMap {
    map: BTreeMap<(String, String), JwksKey>,
    /// Insertion order over live `map` entries, for the cap's eviction.
    order: VecDeque<(String, String)>,
}

impl KeyMap {
    fn get(&self, issuer: &str, kid: &str) -> Option<JwksKey> {
        self.map.get(&(issuer.to_owned(), kid.to_owned())).cloned()
    }

    /// Drop everything captured under the old issuer set and insert the new
    /// one, then enforce the global cap by evicting oldest-first.
    fn replace_issuer(&mut self, issuer: &str, keys: Vec<(String, JwksKey)>, max_keys: usize) {
        self.map.retain(|(cached, _), _| cached != issuer);
        self.order.retain(|(cached, _)| cached != issuer);
        for (kid, key) in keys {
            let index = (issuer.to_owned(), kid);
            self.map.insert(index.clone(), key);
            self.order.push_back(index);
        }
        while self.map.len() > max_keys {
            let Some(oldest) = self.order.pop_front() else {
                break;
            };
            self.map.remove(&oldest);
        }
    }
}

/// Poison-tolerant std lock (matches the `state.rs` idiom).
fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// `(issuer, kid) -> key` cache over the configured IdPs. Built at boot by
/// [`crate::auth::oidc::install`]; never replaced at runtime (a reload warns
/// and requires a restart to apply config changes).
#[derive(Debug)]
pub struct JwksCache {
    /// Weak self-reference for the two background tasks (they upgrade per
    /// iteration, so dropping the cache ends both loops without leaks).
    self_ref: Weak<Self>,
    /// CA-pinned rustls client: every fetch presents the IdP chain to the
    /// configured bundle and standard webpki verification (the aws-lc-rs
    /// provider rustls already resolves in this tree).
    client: Arc<RustlsClientConfig>,
    /// Configured issuers — the ONLY issuers ever fetched. A token carrying
    /// any other issuer misses and fails closed with no outbound request.
    issuers: BTreeSet<String>,
    /// Explicit JWKS URL per issuer (`jwks_urls`); defaults derive from the
    /// issuer itself.
    urls: BTreeMap<String, String>,
    /// Global key cap (`jwks_max_keys`).
    max_keys: usize,
    /// Periodic refresh cadence (`jwks_refresh_seconds`, clamped >= 1s).
    refresh_interval: Duration,
    /// Runtime handle the background tasks are spawned on.
    handle: Handle,
    /// The key set; std lock, brief critical sections only.
    keys: Mutex<KeyMap>,
    /// Per-issuer throttle stamps backing the lazy singleflight.
    stamps: Mutex<HashMap<String, Instant>>,
}

impl JwksCache {
    /// Build the cache from an enabled `[auth.oidc]` table: parse the CA
    /// bundle, assemble the rustls client, and start the periodic refresh
    /// task (whose first tick fires immediately and warms the cache).
    ///
    /// # Errors
    /// [`JwksCacheError`] when the CA bundle cannot back a client.
    ///
    /// # Panics
    /// Without a running tokio runtime (`Handle::current()`); construction
    /// happens inside `serve()` / async tests only.
    pub fn try_new(oidc: &OidcConfig) -> Result<Arc<Self>, JwksCacheError> {
        let client = match oidc.jwks_ca_pem.as_deref() {
            Some(path) => client_config(path)?,
            None => return Err(JwksCacheError::MissingCaPem),
        };
        let this = Arc::new_cyclic(|weak| Self {
            self_ref: weak.clone(),
            client,
            issuers: oidc.issuers.iter().cloned().collect(),
            urls: oidc.jwks_urls.clone(),
            max_keys: oidc.jwks_max_keys.max(1),
            refresh_interval: Duration::from_secs(oidc.jwks_refresh_seconds.max(1)),
            handle: Handle::current(),
            keys: Mutex::new(KeyMap::default()),
            stamps: Mutex::new(HashMap::new()),
        });
        this.spawn_periodic();
        Ok(this)
    }

    /// Periodic refresh: first tick immediate (boot prefetch), then one full
    /// pass per cadence. Held only as a `Weak` between ticks.
    fn spawn_periodic(&self) {
        let weak = self.self_ref.clone();
        let interval = self.refresh_interval;
        self.handle.spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                let Some(this) = weak.upgrade() else {
                    return;
                };
                this.refresh_all().await;
            }
        });
    }

    /// The JWKS URL for an issuer: the explicit override when present, else
    /// `{issuer}/.well-known/jwks.json` (trailing slashes on the issuer
    /// dropped so the derived path stays canonical).
    fn jwks_url(&self, issuer: &str) -> String {
        if let Some(url) = self.urls.get(issuer) {
            return url.clone();
        }
        format!("{}/.well-known/jwks.json", issuer.trim_end_matches('/'))
    }

    /// Refresh every configured issuer; one failing IdP never blocks the
    /// others' pass.
    async fn refresh_all(&self) {
        for issuer in self.issuers.clone() {
            self.refresh_one(&issuer).await;
        }
    }

    /// Fetch one issuer's JWKS and REPLACE its cached set on success. Any
    /// failure (budget timeout, TLS, non-2xx, oversize, parse) or an empty
    /// RSA set leaves the cache untouched and logs one line: previously
    /// cached keys keep verifying, tokens needing a new key fail closed.
    async fn refresh_one(&self, issuer: &str) {
        let url = self.jwks_url(issuer);
        let fetch = tokio::time::timeout(FETCH_BUDGET, fetch_jwks(&self.client, &url));
        let keys = match fetch.await {
            Ok(Ok(keys)) => keys,
            Ok(Err(reason)) => {
                tracing::warn!(issuer, %reason, "jwks refresh failed; cache kept");
                return;
            }
            Err(_) => {
                tracing::warn!(
                    issuer,
                    budget_secs = FETCH_BUDGET.as_secs(),
                    "jwks refresh timed out; cache kept"
                );
                return;
            }
        };
        // An empty successful reply would otherwise wipe the issuer's keys
        // wholesale on an IdP incident: treated as a failure, cache kept
        // until the endpoint serves key material again.
        if keys.is_empty() {
            tracing::warn!(issuer, "jwks endpoint returned no RSA keys; cache kept");
            return;
        }
        let count = keys.len();
        locked(&self.keys).replace_issuer(issuer, keys, self.max_keys);
        tracing::debug!(issuer, keys = count, "jwks refreshed");
    }

    /// Lazy singleflight for an unknown kid: the first miss inside the
    /// spacing window stamps the issuer and spawns one refresh; misses
    /// within the window return immediately (the caller fails this token
    /// closed, documented as "other requests await or fail with the current
    /// knowledge cached"). Only CONFIGURED issuers are ever fetched.
    fn request_refresh(&self, issuer: &str) {
        if !self.issuers.contains(issuer) {
            tracing::debug!(issuer, "token issuer not configured; no jwks fetch");
            return;
        }
        let now = Instant::now();
        {
            let mut stamps = locked(&self.stamps);
            if stamps
                .get(issuer)
                .is_some_and(|stamp| now.duration_since(*stamp) < MIN_REFRESH_SPACING)
            {
                return;
            }
            // Stamped BEFORE the spawn: the stamp is the singleflight, so a
            // burst of misses produces exactly one fetch.
            stamps.insert(issuer.to_owned(), now);
        }
        let Some(this) = self.self_ref.upgrade() else {
            return;
        };
        let weak = Arc::downgrade(&this);
        let issuer = issuer.to_owned();
        this.handle.spawn(async move {
            if let Some(this) = weak.upgrade() {
                this.refresh_one(&issuer).await;
            }
        });
    }
}

impl RsaKeySource for JwksCache {
    /// Look up the key for the token's untrusted `(issuer, kid)` indices.
    /// The singleflight hook fires on a miss for a configured issuer; the
    /// caller still fails THIS token closed (the refresh is asynchronous).
    fn key(&self, issuer: &str, kid: &str) -> Option<JwksKey> {
        let cached = locked(&self.keys).get(issuer, kid);
        if cached.is_some() {
            return cached;
        }
        self.request_refresh(issuer);
        None
    }
}

/// Test-only: clear the lazy singleflight stamps so a test can re-trigger a
/// refresh immediately (production cadence is unaffected).
#[cfg(test)]
impl JwksCache {
    fn reset_throttle_for_tests(&self) {
        locked(&self.stamps).clear();
    }
}

/// CA bundle -> rustls client config with standard webpki server
/// verification (both the chain and the host name are checked), mirroring
/// the `tests/auth_tls.rs` trust-store assembly.
fn client_config(ca_pem_path: &Path) -> Result<Arc<RustlsClientConfig>, JwksCacheError> {
    let path = ca_pem_path.to_path_buf();
    let pem =
        std::fs::read_to_string(ca_pem_path).map_err(|source| JwksCacheError::CaUnreadable {
            path: path.clone(),
            source,
        })?;
    let mut reader = BufReader::new(pem.as_bytes());
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| JwksCacheError::CaUnreadable {
            path: path.clone(),
            source,
        })?;
    let mut roots = RootCertStore::empty();
    for cert in &certs {
        // Lenient bundle parse: odd/duplicate records are skipped, an
        // entirely unusable bundle falls through to the CaEmpty error.
        let _ = roots.add(cert.clone());
    }
    if roots.is_empty() {
        return Err(JwksCacheError::CaEmpty(path));
    }
    let tls = RustlsClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(tls))
}

/// Wire shape of a JWKS document. Unknown fields are ignored; every record
/// missing `kty == "RSA"`, a non-empty `kid`, or a decodable `n`/`e` pair is
/// skipped (ES/EC and symmetric keys are never admitted, docs/oidc.md).
#[derive(Deserialize)]
struct JwksDoc {
    #[serde(default)]
    keys: Vec<JwkEntry>,
}

#[derive(Deserialize)]
struct JwkEntry {
    kty: Option<String>,
    kid: Option<String>,
    n: Option<String>,
    e: Option<String>,
}

/// One JWKS response: bundle-level cap from the caller; here only the parse.
fn parse_jwks(body: &[u8]) -> Result<Vec<(String, JwksKey)>, String> {
    let doc: JwksDoc = serde_json::from_slice(body).map_err(|err| format!("jwks json: {err}"))?;
    let mut keys = Vec::new();
    for entry in doc.keys {
        if entry.kty.as_deref() != Some("RSA") {
            continue;
        }
        let Some(kid) = entry.kid.filter(|kid| !kid.is_empty()) else {
            continue;
        };
        let (Some(n), Some(e)) = (entry.n, entry.e) else {
            continue;
        };
        if let Some(key) = JwksKey::from_b64url(&n, &e) {
            keys.push((kid, key));
        }
    }
    Ok(keys)
}

/// HTTPS GET one JWKS URL with the `Connection: close` heartbeat pattern:
/// fresh TLS connection, hand-rolled request line, read to EOF under the
/// bundle cap, then head/body split (minimal chunked de-chunking when the
/// endpoint speaks it) and a strict 2xx gate. Never inspects token material,
/// only config-derived data.
async fn fetch_jwks(
    client: &Arc<RustlsClientConfig>,
    url_text: &str,
) -> Result<Vec<(String, JwksKey)>, String> {
    let url = url::Url::parse(url_text).map_err(|err| format!("jwks url {url_text}: {err}"))?;
    // Depth defense: config::validate already rejects plaintext issuers and
    // overrides; keep the fetch itself https-only so a hand-edited config
    // can never downgrade this transport.
    if url.scheme() != "https" {
        return Err(format!("jwks url {url_text} is not https"));
    }
    let host = url
        .host_str()
        .ok_or_else(|| format!("jwks url {url_text} has no host"))?
        .to_owned();
    let port = url
        .port_or_known_default()
        .ok_or_else(|| format!("jwks url {url_text} has no port"))?;
    let sni = host
        .strip_prefix('[')
        .and_then(|sni| sni.strip_suffix(']'))
        .unwrap_or(&host)
        .to_owned();
    let server_name = ServerName::try_from(sni.clone())
        .map_err(|_| format!("jwks host {host} is not a valid DNS/IP name"))?;

    let tcp = TcpStream::connect((sni.as_str(), port))
        .await
        .map_err(|err| format!("jwks connect {host}:{port}: {err}"))?;
    let mut stream = TlsConnector::from(client.clone())
        .connect(server_name, tcp)
        .await
        .map_err(|err| format!("jwks TLS handshake to {host}:{port}: {err}"))?;

    let path = match url.query() {
        Some(query) if !query.is_empty() => format!("{}?{query}", url.path()),
        _ => url.path().to_owned(),
    };
    let host_header = match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.clone(),
    };
    // `Accept-Encoding: identity` because decoding foreign transfer styles
    // is out of scope; the body cap and Connection: close bound the read.
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host_header}\r\nConnection: close\r\n\
         User-Agent: cachette/{version} (jwks)\r\nAccept: application/json\r\n\
         Accept-Encoding: identity\r\n\r\n",
        version = env!("CARGO_PKG_VERSION"),
    );
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|err| format!("jwks request write to {host}:{port}: {err}"))?;

    let mut raw = Vec::new();
    // Tolerant read: rustls fails the stream when the peer closes the TCP
    // connection without a TLS close_notify (nginx-style IdP pools do), but
    // the plaintext delivered up to the FIN is already complete here. Treat
    // an unexpected EOF as end-of-response and let the downstream gates
    // (separator split, status, cap, JSON parse) judge the bytes; anything
    // genuinely truncated fails there. Other errors are hard failures.
    match stream
        .take((MAX_BODY_BYTES + 1) as u64)
        .read_to_end(&mut raw)
        .await
    {
        Ok(_) => {}
        Err(source) if source.kind() == std::io::ErrorKind::UnexpectedEof => {
            tracing::debug!(
                host,
                port,
                "jwks response ended without close_notify; using the received bytes"
            );
        }
        Err(source) => {
            return Err(format!("jwks response read from {host}:{port}: {source}"));
        }
    }
    if raw.is_empty() {
        return Err(format!("jwks response from {host}:{port} carried no bytes"));
    }
    if raw.len() > MAX_BODY_BYTES {
        return Err(format!(
            "jwks response from {host}:{port} exceeds the {} KiB cap",
            MAX_BODY_BYTES / 1024
        ));
    }

    let (status, body) = parse_response(&raw)?;
    if !(200..300).contains(&status) {
        return Err(format!(
            "jwks endpoint {host}:{port} answered HTTP {status}"
        ));
    }
    parse_jwks(&body)
}

/// Split a raw HTTP/1.1 response into (status, body); `Transfer-Encoding:
/// chunked` bodies are de-chunked (minimal: collected bytes, no streaming).
fn parse_response(raw: &[u8]) -> Result<(u16, Vec<u8>), String> {
    let split = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| String::from("no header/body separator"))?;
    let head =
        std::str::from_utf8(&raw[..split]).map_err(|_| String::from("non-utf8 response head"))?;
    let mut body = raw[split + 4..].to_vec();

    let status_line = head.split("\r\n").next().unwrap_or_default();
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| format!("malformed status line: {status_line:?}"))?;
    if head_chunked(head) {
        body = dechunk(&body)?;
    }
    Ok((status, body))
}

/// `Transfer-Encoding: chunked` in the head (case-insensitive header name
/// and value scan over whole lines).
fn head_chunked(head: &str) -> bool {
    head.split("\r\n").skip(1).any(|line| {
        let mut parts = line.splitn(2, ':');
        let name = parts.next().unwrap_or_default().trim();
        let value = parts.next().unwrap_or_default();
        name.eq_ignore_ascii_case("transfer-encoding")
            && value
                .split(',')
                .any(|value| value.trim().eq_ignore_ascii_case("chunked"))
    })
}

/// De-chunk a collected body: hex sizes (+ optional extensions), chunk
/// bytes, CRLF; the terminating zero chunk (and any trailers) ends the
/// scan. Truncation or any malformed framing is a fetch failure.
fn dechunk(raw: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut cursor = 0usize;
    loop {
        let separator = raw[cursor.min(raw.len())..]
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or_else(|| String::from("truncated chunk header"))?;
        let size_text = &raw[cursor..cursor + separator];
        let size_token = size_text
            .split(|byte| *byte == b';')
            .next()
            .unwrap_or_default();
        let size_token = std::str::from_utf8(size_token)
            .map_err(|_| String::from("non-utf8 chunk size"))?
            .trim();
        let size = usize::from_str_radix(size_token, 16)
            .map_err(|_| format!("malformed chunk size {size_token:?}"))?;
        if size == 0 {
            break;
        }
        let start = cursor + separator + 2;
        if start.checked_add(size).is_none() || start + size > raw.len() {
            return Err(String::from("truncated chunk data"));
        }
        out.extend_from_slice(&raw[start..start + size]);
        cursor = start + size;
        if raw.get(cursor..cursor + 2) != Some(b"\r\n") {
            return Err(String::from("chunk data not CRLF terminated"));
        }
        cursor += 2;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex as StdMutex;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    use serde::Deserialize;
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;
    use tokio_rustls::server::TlsStream;

    use super::*;

    /// The throwaway RSA fixture (see the file's note field): tokens are
    /// signed with its private half; the JWKS JSON values below serve its
    /// public half. Keys handed to `key()` here are compared against the
    /// fixture's public half directly.
    const FIXTURE_JSON: &str = include_str!("../../tests/fixtures/oidc-rsa.json");

    const ISSUER: &str = "https://idp.example.org/realms/ci";
    const JWKS_PATH: &str = "/_jwks";

    #[derive(Deserialize)]
    struct RsaFixture {
        #[allow(dead_code)]
        pkcs8: String,
        jwks_n: String,
        jwks_e: String,
        kid: String,
        #[allow(dead_code)]
        issuer: String,
    }

    fn rsa() -> RsaFixture {
        serde_json::from_str(FIXTURE_JSON).expect("fixture parses")
    }

    fn fixture_key() -> JwksKey {
        let fx = rsa();
        JwksKey::from_b64url(&fx.jwks_n, &fx.jwks_e).expect("fixture JWKS decodes")
    }

    /// A JWKS doc serving the fixture key under each of `kids`.
    fn jwks_doc(kids: &[&str]) -> String {
        let fx = rsa();
        let keys: Vec<_> = kids
            .iter()
            .map(|kid| serde_json::json!({ "kty": "RSA", "kid": kid, "n": fx.jwks_n, "e": fx.jwks_e }))
            .collect();
        serde_json::json!({ "keys": keys }).to_string()
    }

    /// A JWKS doc with the fixture RSA entry plus noise an IdP may serve:
    /// EC and symmetric records, a kid-less RSA, and an RSA with an
    /// undecodable modulus. Only the well-formed RSA-with-kid is admitted.
    fn mixed_doc() -> String {
        let fx = rsa();
        serde_json::json!({
            "keys": [
                { "kty": "EC", "kid": "ec-key", "crv": "P-256", "x": "a", "y": "b" },
                { "kty": "oct", "kid": "oct-key", "k": "c" },
                { "kty": "RSA", "n": fx.jwks_n, "e": fx.jwks_e },
                { "kty": "RSA", "kid": "broken", "n": "%%%not-b64url%%%", "e": fx.jwks_e },
                { "kty": "RSA", "kid": "test-key-1", "n": fx.jwks_n, "e": fx.jwks_e },
            ],
        })
        .to_string()
    }

    /// A live TLS JWKS endpoint on a loopback ephemeral port, leaf ==
    /// self-signed CA (SAN `127.0.0.1`), accepting swaps of the document it
    /// serves and counting requests by path. Marker documents drive
    /// deliberately malformed responses.
    struct JwksServer {
        port: u16,
        doc: Arc<StdMutex<String>>,
        hits: Arc<AtomicUsize>,
        paths: Arc<StdMutex<Vec<String>>>,
        accept_task: tokio::task::JoinHandle<()>,
        ca_pem_path: PathBuf,
    }

    impl JwksServer {
        fn url(&self) -> String {
            format!("https://127.0.0.1:{}{JWKS_PATH}", self.port)
        }

        fn hits(&self) -> usize {
            self.hits.load(Ordering::SeqCst)
        }

        fn recorded_paths(&self) -> Vec<String> {
            locked(&self.paths).clone()
        }

        /// Swap the document the endpoint serves (the next connection sees
        /// it).
        fn set_doc(&self, doc: &str) {
            *locked(&self.doc) = doc.to_owned();
        }

        /// Kill the endpoint: further dials are refused (sync — tokio's
        /// `JoinHandle::abort` takes `&self`).
        fn abort(&self) {
            self.accept_task.abort();
        }

        /// The cache config aimed at this endpoint; `jwks_refresh_seconds`
        /// stays large so only the boot prefetch and lazy refreshes hit the
        /// wire within a test's lifetime.
        fn config(&self, fields: impl FnOnce(&mut OidcConfig)) -> OidcConfig {
            let mut oidc = OidcConfig {
                enabled: true,
                issuers: vec![ISSUER.to_owned()],
                audiences: vec![String::from("cachette")],
                jwks_ca_pem: Some(self.ca_pem_path.clone()),
                ..OidcConfig::default()
            };
            oidc.jwks_urls.insert(ISSUER.to_owned(), self.url());
            fields(&mut oidc);
            oidc
        }

        /// Remove the per-test temp dir holding the CA bundle.
        fn cleanup(self) {
            if let Some(dir) = self.ca_pem_path.parent() {
                let _ = std::fs::remove_dir_all(dir);
            }
        }
    }

    async fn spawn_jwks_server(initial_doc: &str) -> JwksServer {
        // Self-signed leaf-as-CA with an IP SAN: webpki trusts it from the
        // bundle, matching the deployment shape with an IdP's own CA.
        let cert = rcgen::generate_simple_self_signed(vec![String::from("127.0.0.1")])
            .expect("test leaf cert");
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();

        // The CA bundle passes through a real FILE on disk, so `try_new`'s
        // read path is exercised too.
        let dir = std::env::temp_dir().join(test_dir_name());
        std::fs::create_dir_all(&dir).expect("test dir");
        let ca_pem_path = dir.join("ca.pem");
        std::fs::write(&ca_pem_path, &cert_pem).expect("ca pem written");

        let mut reader = BufReader::new(key_pem.as_bytes());
        let key = rustls_pemfile::private_key(&mut reader)
            .expect("key parses")
            .expect("key present");
        let mut reader = BufReader::new(cert_pem.as_bytes());
        let certs = rustls_pemfile::certs(&mut reader)
            .collect::<Result<Vec<_>, _>>()
            .expect("certs parse");
        let tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .expect("server config");
        let acceptor = TlsAcceptor::from(Arc::new(tls));

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let port = listener.local_addr().expect("addr").port();

        let doc = Arc::new(StdMutex::new(initial_doc.to_owned()));
        let hits = Arc::new(AtomicUsize::new(0));
        let paths = Arc::new(StdMutex::new(Vec::new()));
        let accept_task = tokio::spawn(accept_loop(
            listener,
            acceptor,
            ServerState {
                doc: doc.clone(),
                hits: hits.clone(),
                paths: paths.clone(),
            },
        ));
        JwksServer {
            port,
            doc,
            hits,
            paths,
            accept_task,
            ca_pem_path,
        }
    }

    /// Shared server state (one Arc per field; the accept loop clones the
    /// bundle per connection).
    #[derive(Clone)]
    struct ServerState {
        doc: Arc<StdMutex<String>>,
        hits: Arc<AtomicUsize>,
        paths: Arc<StdMutex<Vec<String>>>,
    }

    /// Accept forever: each connection reads the request head
    /// (head-terminated — the client never half-closes), records the path,
    /// and answers the marker/normal variants with `Connection: close`.
    async fn accept_loop(listener: TcpListener, acceptor: TlsAcceptor, state: ServerState) {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let state = state.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(stream).await else {
                    return;
                };
                let Some(head) = read_head(&mut tls).await else {
                    return;
                };
                let path = head
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or_default()
                    .split('?')
                    .next()
                    .unwrap_or_default()
                    .to_owned();
                state.hits.fetch_add(1, Ordering::SeqCst);
                locked(&state.paths).push(path);
                let body = locked(&state.doc).clone();
                let response = render_response(&body);
                let _ = tls.write_all(response.as_bytes()).await;
                // Close cleanly (close_notify) — the client's read treats a
                // missing close_notify as end-of-response, but a harness that
                // behaves like a real IdP exercises the clean path too.
                let _ = tls.shutdown().await;
                drop(tls);
            });
        }
    }

    /// Head-terminated server read: the client sends the GET then waits for
    /// the response, so EOF never arrives — the empty line is the end.
    async fn read_head(tls: &mut TlsStream<TcpStream>) -> Option<String> {
        let mut buf = Vec::new();
        let mut scratch = [0u8; 2048];
        loop {
            let read = tls.read(&mut scratch).await.ok()?;
            if read == 0 {
                return None;
            }
            buf.extend_from_slice(&scratch[..read]);
            if buf.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
            if buf.len() > 16 * 1024 {
                return None;
            }
        }
        Some(String::from_utf8_lossy(&buf).into_owned())
    }

    /// Marker protocol for deliberate failures; `#CHUNKED#`-prefixed docs
    /// are served with a hand-computed chunked transfer encoding.
    fn render_response(body: &str) -> String {
        if body == "__500__" {
            return String::from(
                "HTTP/1.1 500 nope\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            );
        }
        if body == "__oversize__" {
            let junk = "x".repeat(MAX_BODY_BYTES + 16);
            return format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{junk}",
                junk.len()
            );
        }
        if let Some(real) = body.strip_prefix("#CHUNKED#") {
            let (a, b) = real.split_at(real.len() / 2);
            return format!(
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n{a}\r\n{:x}\r\n{b}\r\n0\r\n\r\n",
                a.len(),
                b.len()
            );
        }
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    }

    /// Poll `pred` with sleeps until the deadline; the last check decides.
    async fn wait_until(timeout: Duration, mut pred: impl FnMut() -> bool) -> bool {
        let start = std::time::Instant::now();
        while std::time::Instant::now() < start + timeout {
            if pred() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        pred()
    }

    /// Unique temp-dir name for a test's CA bundle.
    fn test_dir_name() -> String {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        format!(
            "cachette-jwks-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        )
    }

    async fn warm_boot(server: &JwksServer, kid: &str) -> Arc<JwksCache> {
        let cache = JwksCache::try_new(&server.config(|_| {})).expect("cache builds");
        assert!(
            wait_until(Duration::from_secs(3), || cache.key(ISSUER, kid).is_some()).await,
            "boot prefetch should cache the initial kid"
        );
        cache
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn lazy_refresh_resolves_a_rotated_kid() {
        let kid_a = rsa().kid;
        let kid_b = "rotated-kid-b";
        let server = spawn_jwks_server(&jwks_doc(&[kid_a.as_str()])).await;
        let cache = warm_boot(&server, &kid_a).await;

        // Rotation: the endpoint now serves only kid_b (same public key,
        // fresh kid label — the fixture keypair is the signer either way).
        server.set_doc(&jwks_doc(&[kid_b]));
        assert_eq!(cache.key(ISSUER, kid_b), None, "unknown kid before refresh");
        assert!(
            wait_until(Duration::from_secs(5), || cache
                .key(ISSUER, kid_b)
                .is_some())
            .await,
            "lazy refresh should fetch the rotated kid"
        );
        assert_eq!(cache.key(ISSUER, kid_b).unwrap(), fixture_key());
        // Replacement semantics: the rotated-away kid is gone.
        assert_eq!(cache.key(ISSUER, kid_a.as_str()), None);

        drop(cache);
        server.cleanup();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn singleflight_concurrent_misses_trigger_one_fetch() {
        let kid_a = rsa().kid;
        let server = spawn_jwks_server(&jwks_doc(&[kid_a.as_str()])).await;
        let cache = warm_boot(&server, &kid_a).await;
        // warm_boot polls may already have stamped (and fetched for) this
        // issuer; clear the stamps so the burst below starts from a clean
        // singleflight window and the count is deterministic.
        cache.reset_throttle_for_tests();
        let hits_before_burst = server.hits();

        // 24 concurrent misses on one unknown kid must produce exactly one
        // lazy fetch: the first miss stamps the issuer, the other 23 fall
        // inside the spacing window and stay silent.
        for _ in 0..24 {
            let source = Arc::clone(&cache);
            tokio::spawn(async move {
                let _ = source.key(ISSUER, "unknown-kid-1");
            });
        }
        // Let the burst start and the spawned fetch complete.
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert_eq!(
            server.hits(),
            hits_before_burst + 1,
            "the burst of misses must produce exactly one lazy fetch"
        );
        // ... and nothing else inside the spacing window.
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(server.hits(), hits_before_burst + 1);

        server.cleanup();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn endpoint_down_keeps_cached_keys_fails_new_ones() {
        let kid_a = rsa().kid;
        let server = spawn_jwks_server(&jwks_doc(&[kid_a.as_str()])).await;
        let cache = warm_boot(&server, &kid_a).await;
        server.abort();

        // Cached keys verify without any endpoint.
        assert_eq!(cache.key(ISSUER, kid_a.as_str()).unwrap(), fixture_key());
        // New kids fail closed; the doomed refresh must not panic or corrupt.
        assert_eq!(cache.key(ISSUER, "kid-after-outage"), None);
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(cache.key(ISSUER, "kid-after-outage"), None);
        assert_eq!(cache.key(ISSUER, kid_a.as_str()).unwrap(), fixture_key());

        server.cleanup();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn failed_refresh_leaves_cache_untouched() {
        let kid = rsa().kid;
        let server = spawn_jwks_server("__500__").await;
        let cache = JwksCache::try_new(&server.config(|_| {})).expect("cache builds");
        // The endpoint rejects everything: boot prefetch and the first miss
        // both fail; the map stays empty, nothing panics.
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(cache.key(ISSUER, kid.as_str()), None);

        // Recovery: once the endpoint serves again, the next lazy fetch
        // populates the cache (the throttle is cleared so the test need not
        // wait out the spacing window).
        server.set_doc(&jwks_doc(&[kid.as_str()]));
        cache.reset_throttle_for_tests();
        assert!(
            wait_until(Duration::from_secs(5), || cache.key(ISSUER, &kid).is_some()).await,
            "recovered endpoint should resolve the kid"
        );
        server.cleanup();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cap_evicts_in_insertion_order() {
        let kid = rsa().kid;
        let server = spawn_jwks_server(&jwks_doc(&["cap-a", "cap-b", kid.as_str()])).await;
        let config = server.config(|oidc| {
            oidc.jwks_max_keys = 2;
        });
        let cache = JwksCache::try_new(&config).expect("cache builds");
        assert!(
            wait_until(Duration::from_secs(3), || cache
                .key(ISSUER, "cap-b")
                .is_some())
            .await,
            "boot prefetch done"
        );
        // Insertion order cap-a, cap-b, fixture-kid -> the first is evicted;
        // later refreshes re-insert all three and evict the same one.
        assert_eq!(cache.key(ISSUER, "cap-a"), None);
        assert!(cache.key(ISSUER, "cap-b").is_some());
        assert!(cache.key(ISSUER, &kid).is_some());
        server.cleanup();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unconfigured_issuer_misses_without_fetching() {
        let kid = rsa().kid;
        let server = spawn_jwks_server(&jwks_doc(&[kid.as_str()])).await;
        let cache = warm_boot(&server, &kid).await;
        let hits_after_prefetch = server.hits();

        // An issuer the node never configured must not trigger any fetch.
        assert_eq!(
            cache.key("https://evil.example.org/realms/rogue", &kid),
            None
        );
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(
            server.hits(),
            hits_after_prefetch,
            "no fetch for a rogue issuer"
        );

        server.cleanup();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fetched_key_matches_the_wire_and_the_recorded_path() {
        let kid = rsa().kid;
        let server = spawn_jwks_server(&jwks_doc(&[kid.as_str()])).await;
        let cache = warm_boot(&server, &kid).await;

        // warm_boot's polls may themselves trigger lazy refreshes (the boot
        // prefetch racing the first poll), so the exact request count is
        // racy by design — what must hold: at least one fetch happened and
        // EVERY request targeted the configured URL path, and the payload
        // came from the real wire.
        let paths = server.recorded_paths();
        assert!(!paths.is_empty(), "the endpoint should have been fetched");
        assert!(
            paths.iter().all(|path| path == JWKS_PATH),
            "every request must target the configured URL; recorded: {paths:?}"
        );
        assert_eq!(cache.key(ISSUER, &kid).unwrap(), fixture_key());
        server.cleanup();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn chunked_transfer_decodes_and_oversize_fails_closed() {
        let kid = rsa().kid;

        // 1) a chunked response decodes to the same keys on the wire.
        let server = spawn_jwks_server(&format!("#CHUNKED#{}", jwks_doc(&[kid.as_str()]))).await;
        let cache = JwksCache::try_new(&server.config(|_| {})).expect("cache builds");
        assert!(
            wait_until(Duration::from_secs(3), || cache.key(ISSUER, &kid).is_some()).await,
            "chunked fetch resolves"
        );
        assert_eq!(cache.key(ISSUER, &kid).unwrap(), fixture_key());
        server.cleanup();

        // 2) an over-cap body is refused wholesale and the cache stays.
        let server = spawn_jwks_server("__oversize__").await;
        let cache = JwksCache::try_new(&server.config(|_| {})).expect("cache builds");
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(cache.key(ISSUER, "oversize-kid"), None);
        // ... but the endpoint WAS contacted (the fetch was attempted).
        assert!(server.hits() >= 1);
        server.cleanup();
    }

    #[test]
    fn missing_or_empty_ca_bundle_fails_boot() {
        let dir = std::env::temp_dir().join(test_dir_name());
        std::fs::create_dir_all(&dir).expect("dir");
        let cleanup = |dirs: Vec<PathBuf>| {
            for dir in dirs {
                let _ = std::fs::remove_dir_all(dir);
            }
        };

        let empty = dir.join("empty.pem");
        std::fs::write(&empty, "").expect("empty bundle");
        let boot_config = |ca_pem: Option<PathBuf>| OidcConfig {
            enabled: true,
            jwks_ca_pem: ca_pem,
            ..OidcConfig::default()
        };
        assert!(matches!(
            JwksCache::try_new(&boot_config(Some(empty.clone()))),
            Err(JwksCacheError::CaEmpty(_))
        ));

        assert!(matches!(
            JwksCache::try_new(&boot_config(Some(dir.join("does-not-exist.pem")))),
            Err(JwksCacheError::CaUnreadable { .. })
        ));

        assert!(matches!(
            JwksCache::try_new(&boot_config(None)),
            Err(JwksCacheError::MissingCaPem)
        ));

        cleanup(vec![dir]);
    }

    #[test]
    fn jwks_parse_filters_to_rsa_keys_with_kids() {
        let keys = parse_jwks(mixed_doc().as_bytes()).expect("mixed doc parses");
        assert_eq!(keys.len(), 1, "only the well-formed RSA record survives");
        assert_eq!(keys[0].0, "test-key-1");
        assert_eq!(keys[0].1, fixture_key());
        // Junk JSON is an explicit failure, not an empty success.
        assert!(parse_jwks(b"not json").is_err());
    }

    #[test]
    fn response_parse_reads_status_and_dechunks() {
        let plain =
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\nbody-here";
        assert_eq!(parse_response(plain), Ok((200, b"body-here".to_vec())));

        let chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n\
            4\r\nWiki\r\n6\r\npedia.\r\n0\r\n\r\n";
        assert_eq!(parse_response(chunked), Ok((200, b"Wikipedia.".to_vec())));

        let chunked_mixed_case = b"HTTP/1.1 201 Created\r\nTRANSFER-ENCODING: Chunked\r\n\r\n\
            3\r\nabc\r\n0\r\n\r\n";
        assert_eq!(
            parse_response(chunked_mixed_case),
            Ok((201, b"abc".to_vec()))
        );

        assert!(
            parse_response(b"HTTP/1.1 200 OK\r\n half").is_err(),
            "no header/body separator"
        );
        assert!(dechunk(b"zz\r\n").is_err(), "malformed chunk size");
        assert!(dechunk(b"2\r\na\r\na\r\n").is_err(), "truncated chunk");
    }
}
