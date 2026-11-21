//! Plane B: forge runtime tokens (v1.2 workstream F,
//! `docs/shared-cache.md` §3).
//!
//! Forgejo hands every job an `ACTIONS_RUNTIME_TOKEN` - an HS256 JWT signed
//! with the instance's general token signing secret
//! (`services/actions/auth.go::CreateAuthorizationToken`). The claims carry
//! the job identity inside `oidc_extra` (`repository`,
//! `repository_owner`, `event_name`, ...), alongside `exp`, `nbf`, `scp`
//! and `ac`. Cachette cannot verify Plane A's tokens for every forge, but a
//! deployment that holds the forge's signing secret can verify these - at
//! the price of sitting inside that forge's trust boundary, which
//! `docs/shared-cache.md` states plainly.
//!
//! The verifier is configured per forge (`[auth.runtime."<forge>"]`): each
//! block names its secret file, the claim path holding the tenant (default
//! `oidc_extra.repository`, falling back to
//! `oidc_extra.repository_owner`), an optional `scp` allow-list and
//! optional claim pins. A verified token yields the configured forge id and
//! that tenant, so the namespace is `"<forge>|<tenant>"` like Plane A's.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, KeyInit, Mac};
use serde::Deserialize;
use serde_json::{Map, Value};
use sha2::Sha256;

use crate::config::{Config, RuntimeForgeConfig};
use crate::state::AppState;

/// Default tenant claim path (`docs/shared-cache.md` §3).
const DEFAULT_TENANT_CLAIM: &str = "oidc_extra.repository";
/// Used when the default path is absent: a token scoped to an owner still
/// names a tenant.
const OWNER_TENANT_CLAIM: &str = "oidc_extra.repository_owner";

/// Why a bearer token was not accepted as a forge runtime token.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RuntimeError {
    #[error("malformed token")]
    Malformed,
    #[error("unsupported algorithm")]
    Alg,
    #[error("bad signature")]
    Signature,
    #[error("token expired")]
    Expired,
    #[error("token not yet valid")]
    NotYetValid,
    #[error("scope not allowed")]
    Scope,
    #[error("required claim mismatch")]
    Require,
    #[error("tenant claim missing")]
    Tenant,
}

/// The identity a verified runtime token yields to the shared cache: the
/// configured forge id is the **forge** and the tenant claim's value is the
/// **tenant** (`docs/shared-cache.md` §7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeTenant {
    /// The `[auth.runtime."<forge>"]` key whose secret verified the token.
    pub forge: String,
    /// The value resolved at that block's `tenant_claim`.
    pub tenant: String,
}

impl RuntimeTenant {
    /// The default namespace for this identity: `"<forge>|<tenant>"`.
    #[must_use]
    pub fn namespace(&self) -> String {
        format!("{}|{}", self.forge, self.tenant)
    }
}

/// Boot-fatal runtime-plane wiring error.
#[derive(Debug, thiserror::Error)]
pub enum RuntimeInstallError {
    /// The configured secret file could not be read.
    #[error("auth.runtime forge {forge:?}: cannot read secret file {path}: {msg}")]
    Secret {
        forge: String,
        path: PathBuf,
        msg: String,
    },
    /// The secret file exists but holds no secret.
    #[error("auth.runtime forge {forge:?}: secret file {path} is empty")]
    EmptySecret { forge: String, path: PathBuf },
}

/// One enabled forge block, with its secret material read at boot.
struct ForgeVerifier {
    id: String,
    secret: Vec<u8>,
    tenant_claim: String,
    scopes: Vec<String>,
    require: BTreeMap<String, String>,
    leeway_seconds: i64,
}

/// Stateless verifier for HS256 runtime tokens across the configured
/// forges. Per-request verification is pure computation - no I/O, no locks.
pub struct RuntimeVerifier {
    forges: Vec<ForgeVerifier>,
}

impl RuntimeVerifier {
    /// Build the verifier from the enabled `[auth.runtime]` blocks, reading
    /// each secret file. `None` when no block is enabled (Plane B off).
    ///
    /// # Errors
    /// [`RuntimeInstallError`] when an enabled block's secret is unreadable
    /// or empty - a misconfigured trust root must fail the boot.
    pub fn from_config(
        runtime: &BTreeMap<String, RuntimeForgeConfig>,
    ) -> Result<Option<Self>, RuntimeInstallError> {
        let mut forges = Vec::new();
        for (forge, block) in runtime.iter().filter(|(_, block)| block.enabled) {
            let secret = std::fs::read_to_string(&block.secret).map_err(|err| {
                RuntimeInstallError::Secret {
                    forge: forge.clone(),
                    path: block.secret.clone(),
                    msg: err.to_string(),
                }
            })?;
            let secret = secret.trim();
            if secret.is_empty() {
                return Err(RuntimeInstallError::EmptySecret {
                    forge: forge.clone(),
                    path: block.secret.clone(),
                });
            }
            forges.push(ForgeVerifier {
                id: forge.clone(),
                secret: secret.as_bytes().to_vec(),
                tenant_claim: block.tenant_claim.clone(),
                scopes: block.scopes.clone(),
                require: block.require.clone(),
                leeway_seconds: i64::try_from(block.leeway_seconds).unwrap_or(i64::MAX),
            });
        }
        if forges.is_empty() {
            return Ok(None);
        }
        Ok(Some(Self { forges }))
    }

    /// Verify an HS256 runtime token and resolve its tenant.
    ///
    /// The token is matched against every enabled forge's secret; the first
    /// signature hit selects the forge, and that block's tenant path,
    /// scopes and pins then judge the claims.
    pub fn verify(&self, token: &str, now_unix: i64) -> Result<RuntimeTenant, RuntimeError> {
        let (header_seg, payload_seg, signature_seg) = split(token)?;
        let header: Header = decode_json(header_seg).map_err(|_| RuntimeError::Malformed)?;
        if header.alg != "HS256" {
            return Err(RuntimeError::Alg);
        }
        let signature = URL_SAFE_NO_PAD
            .decode(signature_seg)
            .map_err(|_| RuntimeError::Malformed)?;
        let signing_input = format!("{header_seg}.{payload_seg}");
        let forged = self
            .forges
            .iter()
            .find(|forge| mac_matches(&forge.secret, &signing_input, &signature))
            .ok_or(RuntimeError::Signature)?;

        let payload: Value = decode_json(payload_seg).map_err(|_| RuntimeError::Malformed)?;
        let Value::Object(claims) = &payload else {
            return Err(RuntimeError::Malformed);
        };
        check_time(claims, now_unix, forged.leeway_seconds)?;
        check_scopes(claims, &forged.scopes)?;
        for (key, expected) in &forged.require {
            check_require(&payload, key, expected)?;
        }
        let tenant = tenant_claim(&payload, &forged.tenant_claim)?;
        Ok(RuntimeTenant {
            forge: forged.id.clone(),
            tenant,
        })
    }
}

/// Boot wiring: when at least one `[auth.runtime]` block is enabled, build
/// the verifier and hang it on the state. A failure is boot-fatal; no
/// enabled block is a silent no-op, leaving Plane B off.
///
/// # Errors
/// [`RuntimeInstallError`] when an enabled block's secret cannot be read.
pub fn install(state: &AppState, config: &Config) -> Result<(), RuntimeInstallError> {
    let Some(verifier) = RuntimeVerifier::from_config(&config.auth.runtime)? else {
        return Ok(());
    };
    tracing::info!(
        forges = ?config
            .auth
            .runtime
            .iter()
            .filter(|(_, block)| block.enabled)
            .map(|(forge, _)| forge)
            .collect::<Vec<_>>(),
        "runtime-token bearer verification installed"
    );
    state.install_runtime(verifier);
    Ok(())
}

#[derive(Deserialize)]
struct Header {
    alg: String,
}

/// Split a compact JWS into its three segments; anything else is malformed.
fn split(token: &str) -> Result<(&str, &str, &str), RuntimeError> {
    let mut parts = token.split('.');
    let header = parts.next().ok_or(RuntimeError::Malformed)?;
    let payload = parts.next().ok_or(RuntimeError::Malformed)?;
    let signature = parts.next().ok_or(RuntimeError::Malformed)?;
    if parts.next().is_some() {
        return Err(RuntimeError::Malformed);
    }
    Ok((header, payload, signature))
}

/// Decode a base64url (no padding) segment and parse it as JSON.
fn decode_json<T: serde::de::DeserializeOwned>(segment: &str) -> Result<T, RuntimeError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|_| RuntimeError::Malformed)?;
    serde_json::from_slice(&bytes).map_err(|_| RuntimeError::Malformed)
}

/// Constant-time HS256 check (`Mac::verify_slice` is constant-time).
fn mac_matches(secret: &[u8], signing_input: &str, signature: &[u8]) -> bool {
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(secret) else {
        return false;
    };
    mac.update(signing_input.as_bytes());
    mac.verify_slice(signature).is_ok()
}

/// `exp` is required; `nbf` is optional (RFC 7519, same rule as the OIDC
/// gate). Leeway credits its seconds: expired at `now >= exp + leeway`, not
/// yet valid at `now + leeway < nbf`.
fn check_time(
    claims: &Map<String, Value>,
    now_unix: i64,
    leeway_seconds: i64,
) -> Result<(), RuntimeError> {
    let exp = claims
        .get("exp")
        .and_then(Value::as_i64)
        .ok_or(RuntimeError::Malformed)?;
    if now_unix >= exp.saturating_add(leeway_seconds) {
        return Err(RuntimeError::Expired);
    }
    if let Some(nbf) = claims.get("nbf") {
        let nbf = nbf.as_i64().ok_or(RuntimeError::Malformed)?;
        if now_unix.saturating_add(leeway_seconds) < nbf {
            return Err(RuntimeError::NotYetValid);
        }
    }
    Ok(())
}

/// `scp` is a space-separated list (`repo:owner/name write:actions`). With
/// an allow-list configured, the token must carry at least one matching
/// entry; `*` matches any run of characters.
fn check_scopes(claims: &Map<String, Value>, allowed: &[String]) -> Result<(), RuntimeError> {
    if allowed.is_empty() {
        return Ok(());
    }
    let Some(scopes) = claims.get("scp").and_then(Value::as_str) else {
        return Err(RuntimeError::Scope);
    };
    if scopes
        .split_whitespace()
        .any(|scope| allowed.iter().any(|pattern| wildcard_match(pattern, scope)))
    {
        Ok(())
    } else {
        Err(RuntimeError::Scope)
    }
}

/// A `require` pin matches like the OIDC gate's: exact string equality, or
/// array membership. Bare keys fall back into `oidc_extra` (the claim block
/// where the job identity lives), so `event_name = "push"` works without
/// spelling the prefix.
fn check_require(payload: &Value, key: &str, expected: &str) -> Result<(), RuntimeError> {
    let value = claim_at(payload, key).or_else(|| {
        if key.contains('.') {
            None
        } else {
            claim_at(payload, &format!("oidc_extra.{key}"))
        }
    });
    let Some(value) = value else {
        return Err(RuntimeError::Require);
    };
    match value {
        Value::String(got) if got == expected => Ok(()),
        Value::Array(items)
            if items
                .iter()
                .any(|item| matches!(item, Value::String(got) if got == expected)) =>
        {
            Ok(())
        }
        _ => Err(RuntimeError::Require),
    }
}

/// Resolve the tenant claim. The default path falls back to the owner when
/// the repository is absent; an admin-chosen path has no fallback.
fn tenant_claim(payload: &Value, path: &str) -> Result<String, RuntimeError> {
    let mut value = claim_at(payload, path)
        .and_then(Value::as_str)
        .filter(|tenant| !tenant.is_empty());
    if value.is_none() && path == DEFAULT_TENANT_CLAIM {
        value = claim_at(payload, OWNER_TENANT_CLAIM)
            .and_then(Value::as_str)
            .filter(|tenant| !tenant.is_empty());
    }
    value.map(str::to_owned).ok_or(RuntimeError::Tenant)
}

/// Walk a dotted path through nested JSON objects.
fn claim_at<'a>(payload: &'a Value, path: &str) -> Option<&'a Value> {
    let mut node = payload;
    for segment in path.split('.') {
        node = node.get(segment)?;
    }
    Some(node)
}

/// Glob match where `*` matches any run of characters (the wildcard the
/// quota rules use, `docs/shared-cache.md` §5).
fn wildcard_match(pattern: &str, value: &str) -> bool {
    let pattern = pattern.as_bytes();
    let value = value.as_bytes();
    let (mut p, mut v) = (0usize, 0usize);
    let mut star = None;
    let mut resume = 0usize;
    while v < value.len() {
        if p < pattern.len() && pattern[p] == value[v] {
            p += 1;
            v += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            star = Some(p);
            p += 1;
            resume = v;
        } else if let Some(star_at) = star {
            p = star_at + 1;
            resume += 1;
            v = resume;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }
    p == pattern.len()
}

/// Shared handle type used by [`AppState`].
pub type SharedRuntimeVerifier = Arc<RuntimeVerifier>;

#[cfg(test)]
mod tests {
    use super::*;

    const FORGE: &str = "https://forge.example.org";
    const SECRET: &str = "runtime-secret";

    fn sign(secret: &str, payload: &str) -> String {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(payload.as_bytes());
        let signing_input = format!("{header}.{payload}");
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("hmac key");
        mac.update(signing_input.as_bytes());
        format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
        )
    }

    fn verifier(require: BTreeMap<String, String>, scopes: Vec<String>) -> RuntimeVerifier {
        RuntimeVerifier {
            forges: vec![ForgeVerifier {
                id: FORGE.to_owned(),
                secret: SECRET.as_bytes().to_vec(),
                tenant_claim: DEFAULT_TENANT_CLAIM.to_owned(),
                scopes,
                require,
                leeway_seconds: 30,
            }],
        }
    }

    fn claims(extra: &str) -> String {
        format!(
            r#"{{"exp":2000,"nbf":900,"scp":"repo:octo-org/api write:actions","oidc_extra":{{"repository":"octo-org/api","repository_owner":"octo-org"{extra}}}}}"#
        )
    }
    #[test]
    fn a_verified_token_yields_forge_and_tenant() {
        let v = verifier(BTreeMap::new(), Vec::new());
        let token = sign(SECRET, &claims(""));
        assert_eq!(
            v.verify(&token, 1000),
            Ok(RuntimeTenant {
                forge: FORGE.to_owned(),
                tenant: String::from("octo-org/api"),
            })
        );
        assert_eq!(
            v.verify(&token, 1000).expect("accepted").namespace(),
            format!("{FORGE}|octo-org/api")
        );
    }

    #[test]
    fn a_foreign_signature_is_rejected() {
        let v = verifier(BTreeMap::new(), Vec::new());
        let token = sign("some-other-secret", &claims(""));
        assert_eq!(v.verify(&token, 1000), Err(RuntimeError::Signature));
    }

    #[test]
    fn algorithm_is_pinned_to_hs256() {
        let v = verifier(BTreeMap::new(), Vec::new());
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(claims("").as_bytes());
        let token = format!("{header}.{payload}.c2ln");
        assert_eq!(v.verify(&token, 1000), Err(RuntimeError::Alg));
    }

    #[test]
    fn expiry_and_nbf_honour_leeway() {
        let v = verifier(BTreeMap::new(), Vec::new());
        // exp=1000, leeway 30: expiry begins at now >= 1030.
        let expired = sign(SECRET, r#"{"exp":1000,"oidc_extra":{"repository":"r"}}"#);
        assert_eq!(
            v.verify(&expired, 1029),
            Ok(RuntimeTenant {
                forge: FORGE.to_owned(),
                tenant: String::from("r"),
            })
        );
        assert_eq!(v.verify(&expired, 1030), Err(RuntimeError::Expired));

        // nbf=1100, leeway 30: valid once now + 30 >= 1100.
        let future = sign(
            SECRET,
            r#"{"exp":2000,"nbf":1100,"oidc_extra":{"repository":"r"}}"#,
        );
        assert_eq!(v.verify(&future, 1069), Err(RuntimeError::NotYetValid));
        assert_eq!(
            v.verify(&future, 1070),
            Ok(RuntimeTenant {
                forge: FORGE.to_owned(),
                tenant: String::from("r"),
            })
        );
    }

    #[test]
    fn the_tenant_falls_back_to_the_owner_only_for_the_default_path() {
        let v = verifier(BTreeMap::new(), Vec::new());
        let owner_only = sign(
            SECRET,
            r#"{"exp":2000,"oidc_extra":{"repository_owner":"octo-org"}}"#,
        );
        assert_eq!(
            v.verify(&owner_only, 1000),
            Ok(RuntimeTenant {
                forge: FORGE.to_owned(),
                tenant: String::from("octo-org"),
            })
        );

        let empty = sign(
            SECRET,
            r#"{"exp":2000,"oidc_extra":{"repository":"","repository_owner":"octo-org"}}"#,
        );
        assert_eq!(
            v.verify(&empty, 1000),
            Ok(RuntimeTenant {
                forge: FORGE.to_owned(),
                tenant: String::from("octo-org"),
            })
        );
    }

    #[test]
    fn a_token_without_any_tenant_claim_is_rejected() {
        let v = verifier(BTreeMap::new(), Vec::new());
        let token = sign(SECRET, r#"{"exp":2000,"oidc_extra":{}}"#);
        assert_eq!(v.verify(&token, 1000), Err(RuntimeError::Tenant));
    }

    #[test]
    fn scopes_are_an_allow_list_with_wildcards() {
        let v = verifier(BTreeMap::new(), vec![String::from("repo:octo-org/*")]);
        let token = sign(SECRET, &claims(""));
        assert!(v.verify(&token, 1000).is_ok());

        let outside = sign(
            SECRET,
            r#"{"exp":2000,"scp":"repo:other/api","oidc_extra":{"repository":"r"}}"#,
        );
        assert_eq!(v.verify(&outside, 1000), Err(RuntimeError::Scope));

        let missing = sign(SECRET, r#"{"exp":2000,"oidc_extra":{"repository":"r"}}"#);
        assert_eq!(v.verify(&missing, 1000), Err(RuntimeError::Scope));
    }

    #[test]
    fn require_pins_match_top_level_and_oidc_extra_claims() {
        let v = verifier(
            BTreeMap::from([
                (String::from("event_name"), String::from("push")),
                (String::from("ac"), String::from("cache")),
            ]),
            Vec::new(),
        );
        let token = sign(
            SECRET,
            r#"{"exp":2000,"ac":"cache","oidc_extra":{"repository":"r","event_name":"push"}}"#,
        );
        assert!(v.verify(&token, 1000).is_ok());

        let wrong = sign(
            SECRET,
            r#"{"exp":2000,"ac":"cache","oidc_extra":{"repository":"r","event_name":"pull_request"}}"#,
        );
        assert_eq!(v.verify(&wrong, 1000), Err(RuntimeError::Require));
    }

    #[test]
    fn structural_garbage_is_malformed() {
        let v = verifier(BTreeMap::new(), Vec::new());
        for token in ["", "only.two", "a.b.c.d", "!.b.c", "e30.e30.@@"] {
            assert_eq!(v.verify(token, 1000), Err(RuntimeError::Malformed));
        }
    }

    #[test]
    fn wildcard_match_covers_prefix_suffix_and_middle() {
        assert!(wildcard_match("repo:octo-org/*", "repo:octo-org/api"));
        assert!(wildcard_match("*:api", "repo:api"));
        assert!(
            wildcard_match("repo:*", "repo:"),
            "the empty middle matches"
        );
        assert!(!wildcard_match("repo:octo-org/*", "repo:other/api"));
        assert!(wildcard_match("*", "anything"));
        assert!(!wildcard_match("a*b", "abx"));
    }
}
