//! OIDC RS256 bearer tokens (v1.1 workstream A; docs/oidc.md is the
//! contract).
//!
//! An *additional* acceptance path behind the same `Authorization: Bearer`
//! header: a token that fails the static/TokenStore checks is attempted as a
//! JOSE JWT issued by a configured OIDC IdP. The chain is deliberately
//! ordered so untrusted token content never reaches a security decision:
//!
//! 1. structural parse (three unpadded base64url segments);
//! 2. algorithm pin - `alg` must be exactly `RS256`, rejected **before any
//!    key material is consulted** (the algorithm-confusion family);
//! 3. key resolution by `(issuer, kid)` - both are untrusted strings used
//!    only as cache indices; a miss fails closed;
//! 4. RS256 signature over the two segments - the first check that trusts
//!    *anything* from the token;
//! 5. claims-side gates, strictly post-signature, in this order: `iss` in
//!    the configured issuers, `aud` in the configured audiences, `exp`/
//!    `nbf` with the configured leeway, the optional `require` pins (exact
//!    string equality; array claims must contain the value), then the
//!    issuer's `tenant_claim` - whose value becomes the tenant half of the
//!    namespace (docs/shared-cache.md §7). A missing or non-string tenant
//!    claim is a structural rejection, never a default tenant.
//!
//! Error variants are plain tags by design: nothing from the token (claims,
//! segment bytes, kid text) is ever echoed to logs or responses.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use serde_json::Value;

use crate::auth::jwks::RsaKeySource;
use crate::auth::jwks_cache::{JwksCache, JwksCacheError};
use crate::config::{Config, OidcConfig, OidcIssuerConfig};
use crate::state::AppState;

const ALGORITHM: &str = "RS256";

/// JOSE header of an OIDC token: the `alg` pin input and the optional `kid`.
/// Other fields (`typ`, any extras) are ignored - the pin is on `alg` only.
#[derive(Deserialize)]
struct Header {
    alg: String,
    kid: Option<String>,
}

/// Why a bearer token was not accepted as an OIDC JWT.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum OidcError {
    #[error("malformed token")]
    Malformed,
    #[error("unsupported algorithm")]
    Alg,
    #[error("unknown signing key")]
    UnknownKid,
    #[error("bad signature")]
    Signature,
    #[error("issuer not trusted")]
    Issuer,
    #[error("audience not granted")]
    Audience,
    #[error("token expired")]
    Expired,
    #[error("token not yet valid")]
    NotYetValid,
    #[error("required claim mismatch")]
    Require,
    #[error("tenant claim missing")]
    Tenant,
}

/// The identity a verified OIDC token yields to the shared cache
/// (`docs/shared-cache.md` §7): the issuer is the **forge**, the configured
/// tenant claim's value is the **tenant**, and the default namespace is
/// `"<issuer>|<tenant>"`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OidcTenant {
    /// The token's `iss` (an exact configured issuer string).
    pub issuer: String,
    /// The value of that issuer block's `tenant_claim`.
    pub tenant: String,
}

impl OidcTenant {
    /// The default namespace for this identity: `"<issuer>|<tenant>"`.
    #[must_use]
    pub fn namespace(&self) -> String {
        format!("{}|{}", self.issuer, self.tenant)
    }
}

/// Stateless verifier for RS256 OIDC bearer tokens. Holds the configured
/// trust set **per issuer** (v1.2 shape: each `[auth.oidc."<issuer>"]`
/// block carries its own audiences, `require` pins and clock skew) and the
/// `(issuer, kid)` key source; per-request verification is pure computation
/// over those.
pub struct OidcVerifier {
    /// Per-issuer trust sets, keyed by the issuer string (the exact `iss`
    /// claim the token carries).
    issuers: BTreeMap<String, IssuerTrust>,
    keys: Arc<dyn RsaKeySource>,
}

/// One issuer's trust set: what its tokens may claim, and how much clock
/// skew the gate tolerates.
#[derive(Clone, Debug)]
pub struct IssuerTrust {
    /// `aud` values a token may state (any of).
    pub audiences: Vec<String>,
    /// Claim whose value is the tenant (docs/shared-cache.md §7).
    pub tenant_claim: String,
    /// Optional claim -> exact-value pin (`repository = "owner/repo"`).
    pub require: BTreeMap<String, String>,
    /// Clock skew tolerated on `exp`/`nbf` (seconds).
    pub leeway_seconds: u64,
}

impl Default for IssuerTrust {
    fn default() -> Self {
        Self {
            audiences: Vec::new(),
            tenant_claim: String::from("repository"),
            require: BTreeMap::new(),
            leeway_seconds: 0,
        }
    }
}

impl fmt::Debug for OidcVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The key source is opaque (the live cache holds IdP state); an
        // operator snapshot needs the config half only.
        f.debug_struct("OidcVerifier")
            .field("issuers", &self.issuers)
            .finish_non_exhaustive()
    }
}

impl OidcVerifier {
    /// Assemble a verifier from the resolved `[auth.oidc]` config and a key
    /// source. Built by the auth-policy loader; `config::validate`
    /// guarantees the required surface before one is constructed.
    pub fn new(issuers: BTreeMap<String, IssuerTrust>, keys: Arc<dyn RsaKeySource>) -> Self {
        Self { issuers, keys }
    }

    /// Verify `token` at unix time `now_unix` (docs/oidc.md chain) and return
    /// the identity it yields: the issuer (forge) and the configured tenant
    /// claim's value (`docs/shared-cache.md` §7).
    ///
    /// # Errors
    /// The stage the token failed; the caller logs the stage and 401s.
    pub fn verify(&self, token: &str, now_unix: i64) -> Result<OidcTenant, OidcError> {
        let mut parts = token.split('.');
        let header_seg = parts.next().ok_or(OidcError::Malformed)?;
        let payload_seg = parts.next().ok_or(OidcError::Malformed)?;
        let signature_seg = parts.next().ok_or(OidcError::Malformed)?;
        if parts.next().is_some() {
            return Err(OidcError::Malformed);
        }

        // Step 2: the alg pin gates everything. Key material is consulted
        // only after a token declared RS256, closing the alg-confusion
        // family (a `none`/symmetric variant fed the RSA material).
        let header: Header = decode_json(header_seg)?;
        if header.alg != ALGORITHM {
            return Err(OidcError::Alg);
        }
        let Some(kid) = header.kid.filter(|kid| !kid.is_empty()) else {
            return Err(OidcError::Malformed);
        };

        // Claims are a generic JSON object: the `require` pins may address
        // any claim name, so a fixed claims struct would reject otherwise
        // valid tokens.
        let claims: Value = decode_json(payload_seg)?;
        let Some(claims) = claims.as_object() else {
            return Err(OidcError::Malformed);
        };
        let Some(issuer) = claims.get("iss").and_then(Value::as_str) else {
            return Err(OidcError::Malformed);
        };

        // Steps 3+4: resolve, then bind. The issuer string and `kid` are
        // pure indices here; trusting either happens only after the
        // signature bound them (the live cache only ever holds keys for
        // *configured* issuers, so an arbitrary issuer misses and fails
        // closed even before the pin below).
        let Some(key) = self.keys.key(issuer, &kid) else {
            return Err(OidcError::UnknownKid);
        };
        let signing_input = format!("{header_seg}.{payload_seg}");
        let signature = decode(signature_seg).ok_or(OidcError::Malformed)?;
        key.verify(signing_input.as_bytes(), &signature)
            .map_err(|_| OidcError::Signature)?;

        // Step 5: claims-side gates, strictly after the signature bound
        // them. Order: iss, aud, exp, nbf, require (docs/oidc.md step 3).
        // The issuer selects the trust set: audiences, claim pins and clock
        // skew are per issuer (v1.2 shape), so a token is judged by the
        // rules of the IdP that issued it.
        let Some(trust) = self.issuers.get(issuer) else {
            return Err(OidcError::Issuer);
        };
        if !trust.audience_granted(claims.get("aud")) {
            return Err(OidcError::Audience);
        }
        let leeway = trust.leeway_seconds as i64;
        // `exp` gains the leeway as credit (a clock-skew tolerance);
        // `leeway = 0` degenerates to the strict `exp > now` rule. `nbf`
        // is symmetric on the other side.
        let exp = claim_secs(claims.get("exp"))?;
        if now_unix >= exp.saturating_add(leeway) {
            return Err(OidcError::Expired);
        }
        // `nbf` is OPTIONAL (RFC 7519 section 4.1.5): an absent claim means
        // no lower bound, while a PRESENT but non-numeric one is a
        // structurally broken token. (v1.1 mapped a missing claim to
        // `Malformed`, which rejected every token from an issuer that
        // omits it - Forgejo's OAuth2-app id_token among them.)
        let nbf = match claims.get("nbf") {
            Some(value) => claim_secs(Some(value))?,
            None => 0,
        };
        if now_unix.saturating_add(leeway) < nbf {
            return Err(OidcError::NotYetValid);
        }
        for (claim, expected) in &trust.require {
            let granted = match claims.get(claim) {
                Some(Value::String(actual)) => actual == expected,
                // Array-valued claims authorize when they *contain* the
                // pinned value (docs/oidc.md: exact strings or contains).
                Some(Value::Array(actual)) => actual
                    .iter()
                    .any(|item| item.as_str() == Some(expected.as_str())),
                _ => false,
            };
            if !granted {
                return Err(OidcError::Require);
            }
        }
        // Tenant extraction is the LAST gate: the signature and every pin
        // have already bound the claims. The tenant must be a single
        // non-empty string - an array or a missing claim is structural, not
        // a default, because defaulting would silently merge tenants.
        let Some(tenant) = claims.get(&trust.tenant_claim).and_then(Value::as_str) else {
            return Err(OidcError::Tenant);
        };
        if tenant.is_empty() {
            return Err(OidcError::Tenant);
        }
        Ok(OidcTenant {
            issuer: issuer.to_owned(),
            tenant: tenant.to_owned(),
        })
    }
}

impl IssuerTrust {
    /// `aud` gate: the claim may be one string or an array of strings; any
    /// overlap with this issuer's audiences authorizes.
    fn audience_granted(&self, aud: Option<&Value>) -> bool {
        let Some(aud) = aud else { return false };
        match aud {
            Value::String(aud) => self.audiences.contains(aud),
            Value::Array(auds) => auds.iter().any(|item| {
                let Value::String(aud) = item else {
                    return false;
                };
                self.audiences.contains(aud)
            }),
            _ => false,
        }
    }
}

/// Boot wiring (v1.1): when `[auth.oidc] enabled`, build the [`JwksCache`]
/// from the configured CA bundle and hang a verifier on `state`. A failure
/// is boot-fatal — a broken IdP trust configuration must never serve. A
/// disabled or absent table is a silent no-op, leaving v1.0 behavior
/// byte-identical. SIGHUP reloads never install or remove the verifier
/// (docs/oidc.md rollout: toggling `enabled` requires only a restart);
/// `apply_reload` only warns on a detected config change.
///
/// # Errors
/// [`JwksCacheError`] when the CA bundle cannot back a fetch client.
pub fn install(state: &AppState, config: &Config) -> Result<(), JwksCacheError> {
    // v1.3: per-forge blocks feed the same verifier as the legacy per-issuer
    // tables. An explicitly configured issuer of the same URL wins.
    let mut combined = config.auth.oidc.clone().unwrap_or_default();
    if let Some(value) = config.auth.oidc_jwks_refresh_seconds {
        combined.jwks_refresh_seconds = value;
    }
    if let Some(value) = config.auth.oidc_jwks_max_keys {
        combined.jwks_max_keys = usize::try_from(value).unwrap_or(usize::MAX);
    }
    if let Some(value) = &config.auth.oidc_jwks_ca_pem {
        combined.jwks_ca_pem = Some(value.clone());
    }
    for block in config.auth.forge.values() {
        let Some(issuer) = &block.oidc_issuer else {
            continue;
        };
        let mut issuer_block = OidcIssuerConfig::default();
        if let Some(audiences) = &block.oidc_audiences {
            issuer_block.audiences = audiences.clone();
        }
        issuer_block.jwks_url = block.oidc_jwks_url.clone();
        if let Some(claim) = &block.oidc_tenant_claim {
            issuer_block.tenant_claim = claim.clone();
        }
        if let Some(require) = &block.oidc_require {
            issuer_block.require = require.clone();
        }
        if let Some(leeway) = block.oidc_leeway_seconds {
            issuer_block.leeway_seconds = leeway;
        }
        combined
            .issuers
            .entry(issuer.clone())
            .or_insert(issuer_block);
        combined.enabled = true;
    }
    if !combined.enabled {
        return Ok(());
    }
    let oidc: &OidcConfig = &combined;
    let keys = JwksCache::try_new(oidc)?;
    let trust: BTreeMap<String, IssuerTrust> = oidc
        .issuers
        .iter()
        .map(|(issuer, block)| {
            (
                issuer.clone(),
                IssuerTrust {
                    audiences: block.audiences.clone(),
                    tenant_claim: block.tenant_claim.clone(),
                    require: block.require.clone(),
                    leeway_seconds: block.leeway_seconds,
                },
            )
        })
        .collect();
    state.install_oidc(OidcVerifier::new(trust, keys), oidc);
    tracing::info!(
        issuers = ?oidc.issuers.keys().collect::<Vec<_>>(),
        "oidc bearer verification installed"
    );
    Ok(())
}

/// Integer-valued claim; anything non-numeric is structurally broken.
fn claim_secs(value: Option<&Value>) -> Result<i64, OidcError> {
    value.and_then(Value::as_i64).ok_or(OidcError::Malformed)
}

fn decode(segment: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(segment).ok()
}

fn decode_json<T: serde::de::DeserializeOwned>(segment: &str) -> Result<T, OidcError> {
    let bytes = decode(segment).ok_or(OidcError::Malformed)?;
    serde_json::from_slice(&bytes).map_err(|_| OidcError::Malformed)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{RSA_PKCS1_SHA256, RsaKeyPair};
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    use serde::Deserialize;

    use super::*;
    use crate::auth::jwks::JwksKey;

    /// The throwaway RSA fixture (see the file's note field). Tokens are
    /// minted in tests with its private half; verification uses the JWKS
    /// halves - exactly the deployment shape.
    const FIXTURE_JSON: &str = include_str!("../../tests/fixtures/oidc-rsa.json");

    #[derive(Deserialize)]
    struct RsaFixture {
        pkcs8: String,
        jwks_n: String,
        jwks_e: String,
        kid: String,
        issuer: String,
    }

    const NOW: i64 = 1_700_000_000;

    fn rsa() -> RsaFixture {
        serde_json::from_str(FIXTURE_JSON).expect("fixture parses")
    }

    fn seg(json: &str) -> String {
        URL_SAFE_NO_PAD.encode(json.as_bytes())
    }

    /// Mint a token: RS256-PKCS1-SHA256 over `header_seg.payload_seg`.
    fn sign(fx: &RsaFixture, header_seg: &str, payload_seg: &str) -> String {
        let der = STANDARD
            .decode(fx.pkcs8.as_bytes())
            .expect("fixture pkcs8 decodes");
        let key_pair = RsaKeyPair::from_pkcs8(&der).expect("pkcs8 loads");
        let mut signature = vec![0; key_pair.public_modulus_len()];
        let signing_input = format!("{header_seg}.{payload_seg}");
        key_pair
            .sign(
                &RSA_PKCS1_SHA256,
                &SystemRandom::new(),
                signing_input.as_bytes(),
                &mut signature,
            )
            .expect("signs");
        format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(&signature))
    }

    struct TestKeySource {
        keys: BTreeMap<(String, String), JwksKey>,
    }

    impl RsaKeySource for TestKeySource {
        fn key(&self, issuer: &str, kid: &str) -> Option<JwksKey> {
            self.keys.get(&(issuer.to_owned(), kid.to_owned())).cloned()
        }
    }

    fn key_source() -> (RsaFixture, TestKeySource) {
        let fx = rsa();
        let key = JwksKey::from_b64url(&fx.jwks_n, &fx.jwks_e).expect("fixture jwks");
        let mut keys = BTreeMap::new();
        keys.insert((fx.issuer.clone(), fx.kid.clone()), key);
        (fx, TestKeySource { keys })
    }

    /// A source that panics if consulted: it *proves* the verifier never
    /// touches key material before the RS256 pin passes.
    struct NoConsultKeySource;

    impl RsaKeySource for NoConsultKeySource {
        fn key(&self, _issuer: &str, _kid: &str) -> Option<JwksKey> {
            panic!("key material consulted before the RS256 pin passed");
        }
    }

    /// Build a verifier with one trust set per issuer (v1.2 shape). Every
    /// issuer gets the `cachette` audience plus the caller's pins and
    /// leeway; the per-issuer test below overrides them.
    fn verifier(
        issuers: Vec<String>,
        require: BTreeMap<String, String>,
        leeway_seconds: u64,
        keys: Arc<dyn RsaKeySource>,
    ) -> OidcVerifier {
        let trust = issuers
            .into_iter()
            .map(|issuer| {
                (
                    issuer,
                    IssuerTrust {
                        audiences: vec![String::from("cachette")],
                        tenant_claim: String::from("repository"),
                        require: require.clone(),
                        leeway_seconds,
                    },
                )
            })
            .collect();
        OidcVerifier::new(trust, keys)
    }

    fn std_setup() -> (RsaFixture, OidcVerifier) {
        let (fx, source) = key_source();
        let v = verifier(
            vec![fx.issuer.clone()],
            BTreeMap::new(),
            30,
            Arc::new(source),
        );
        (fx, v)
    }

    const HEADER: &str = r#"{"alg":"RS256","typ":"JWT","kid":"test-key-1"}"#;

    const REPOSITORY: &str = "NiXTheDev/cachette";

    fn claims(iss: &str) -> String {
        format!(
            r#"{{"iss":"{iss}","aud":"cachette","sub":"ci-1","repository":"{REPOSITORY}","exp":{},"nbf":{}}}"#,
            NOW + 300,
            NOW - 5
        )
    }

    fn signed_token(fx: &RsaFixture, header_json: &str, payload_json: &str) -> String {
        sign(fx, &seg(header_json), &seg(payload_json))
    }

    #[test]
    fn valid_token_is_accepted() {
        let (fx, v) = std_setup();
        let token = signed_token(&fx, HEADER, &claims(&fx.issuer));
        assert!(v.verify(&token, NOW).is_ok());
    }

    /// The verified identity is the namespace input: the issuer (forge) plus
    /// the value of the issuer block's tenant claim (`docs/shared-cache.md`
    /// §7), and the default namespace is their `|`-joined pair.
    #[test]
    fn verified_token_yields_issuer_and_tenant() {
        let (fx, v) = std_setup();
        let token = signed_token(&fx, HEADER, &claims(&fx.issuer));
        assert_eq!(
            v.verify(&token, NOW),
            Ok(OidcTenant {
                issuer: fx.issuer.clone(),
                tenant: String::from(REPOSITORY),
            })
        );
        assert_eq!(
            v.verify(&token, NOW).expect("verified").namespace(),
            format!("{}|{REPOSITORY}", fx.issuer)
        );
    }

    /// No tenant claim means no tenant: a structural rejection, never a
    /// silent default namespace.
    #[test]
    fn a_token_without_the_tenant_claim_is_rejected() {
        let (fx, v) = std_setup();
        let payload = format!(
            r#"{{"iss":"{}","aud":"cachette","exp":{},"nbf":{}}}"#,
            fx.issuer,
            NOW + 300,
            NOW - 5
        );
        let token = signed_token(&fx, HEADER, &payload);
        assert_eq!(v.verify(&token, NOW), Err(OidcError::Tenant));
    }

    /// The tenant claim is a per-issuer knob: any claim that carries a
    /// single non-empty string can name the tenant.
    #[test]
    fn a_custom_tenant_claim_is_honoured() {
        let (fx, source) = key_source();
        let trust = BTreeMap::from([(
            fx.issuer.clone(),
            IssuerTrust {
                audiences: vec![String::from("cachette")],
                tenant_claim: String::from("sub"),
                require: BTreeMap::new(),
                leeway_seconds: 30,
            },
        )]);
        let v = OidcVerifier::new(trust, Arc::new(source));
        let token = signed_token(&fx, HEADER, &claims(&fx.issuer));
        let identity = v.verify(&token, NOW).expect("verified");
        assert_eq!(identity.tenant, "ci-1");
    }

    /// RFC 7519 section 4.1.5: `nbf` is OPTIONAL. An absent claim means no
    /// lower bound (v1.1 mapped it to `Malformed`, which rejected every
    /// token from an issuer that omits it - Forgejo's OAuth2-app id_token
    /// among them); a present but non-numeric one is structurally broken.
    #[test]
    fn absent_nbf_is_accepted_and_a_broken_one_is_malformed() {
        let (fx, v) = std_setup();
        let payload = format!(
            r#"{{"iss":"{}","aud":"cachette","sub":"ci-1","repository":"{REPOSITORY}","exp":{}}}"#,
            fx.issuer,
            NOW + 300
        );
        let token = signed_token(&fx, HEADER, &payload);
        assert!(v.verify(&token, NOW).is_ok());

        let payload = format!(
            r#"{{"iss":"{}","aud":"cachette","exp":{},"nbf":"soon"}}"#,
            fx.issuer,
            NOW + 300
        );
        let token = signed_token(&fx, HEADER, &payload);
        assert_eq!(v.verify(&token, NOW), Err(OidcError::Malformed));
    }

    /// Each issuer is judged by its OWN audiences and claim pins (v1.2
    /// shape): one deployment can trust several IdPs whose audiences and
    /// pins have nothing to do with each other.
    #[test]
    fn each_issuer_is_judged_by_its_own_audiences_and_pins() {
        let (fx, mut source) = key_source();
        let other = String::from("https://other.example.org/realms/ci");
        let key = source
            .keys
            .get(&(fx.issuer.clone(), fx.kid.clone()))
            .cloned()
            .expect("fixture key");
        source.keys.insert((other.clone(), fx.kid.clone()), key);
        let trust = BTreeMap::from([
            (
                fx.issuer.clone(),
                IssuerTrust {
                    audiences: vec![String::from("cachette")],
                    tenant_claim: String::from("repository"),
                    require: BTreeMap::new(),
                    leeway_seconds: 30,
                },
            ),
            (
                other.clone(),
                IssuerTrust {
                    audiences: vec![String::from("other-svc")],
                    tenant_claim: String::from("repository"),
                    require: BTreeMap::from([(String::from("sub"), String::from("ci-2"))]),
                    leeway_seconds: 30,
                },
            ),
        ]);
        let v = OidcVerifier::new(trust, Arc::new(source));

        // The first issuer's token carrying the SECOND issuer's audience is
        // rejected: audiences are per issuer, not global.
        let payload = format!(
            r#"{{"iss":"{}","aud":"other-svc","sub":"ci-1","exp":{},"nbf":{}}}"#,
            fx.issuer,
            NOW + 300,
            NOW - 5
        );
        let token = signed_token(&fx, HEADER, &payload);
        assert_eq!(v.verify(&token, NOW), Err(OidcError::Audience));

        // The second issuer's own token passes its audience and its pin.
        let payload = format!(
            r#"{{"iss":"{}","aud":"other-svc","sub":"ci-2","repository":"{REPOSITORY}","exp":{},"nbf":{}}}"#,
            other,
            NOW + 300,
            NOW - 5
        );
        let token = signed_token(&fx, HEADER, &payload);
        assert!(v.verify(&token, NOW).is_ok());

        // ... and the same token with another subject fails that pin.
        let payload = format!(
            r#"{{"iss":"{}","aud":"other-svc","sub":"ci-1","exp":{},"nbf":{}}}"#,
            other,
            NOW + 300,
            NOW - 5
        );
        let token = signed_token(&fx, HEADER, &payload);
        assert_eq!(v.verify(&token, NOW), Err(OidcError::Require));
    }

    #[test]
    fn array_audience_claim_is_accepted_on_any_overlap() {
        let (fx, v) = std_setup();
        let payload = format!(
            r#"{{"iss":"{}","aud":["other-svc","cachette"],"repository":"{REPOSITORY}","exp":{},"nbf":{}}}"#,
            fx.issuer,
            NOW + 300,
            NOW - 5
        );
        let token = signed_token(&fx, HEADER, &payload);
        assert!(v.verify(&token, NOW).is_ok());
    }

    #[test]
    fn algorithm_pin_rejects_before_any_key_is_consulted() {
        for alg in ["none", "HS256", "HS384", "PS256", "RS384"] {
            let header = format!(r#"{{"alg":"{alg}","typ":"JWT","kid":"test-key-1"}}"#);
            let token = format!(
                "{}.{}.sig",
                seg(&header),
                seg(&claims("https://idp.example.org/realms/ci")),
            );
            let v = verifier(
                Vec::new(),
                BTreeMap::new(),
                30,
                Arc::new(NoConsultKeySource),
            );
            assert_eq!(v.verify(&token, NOW), Err(OidcError::Alg), "alg {alg}");
        }
    }

    #[test]
    fn unknown_kid_fails_closed() {
        let (fx, v) = std_setup();
        let header = r#"{"alg":"RS256","typ":"JWT","kid":"rotated-away"}"#;
        let token = signed_token(&fx, header, &claims(&fx.issuer));
        assert_eq!(v.verify(&token, NOW), Err(OidcError::UnknownKid));
    }

    #[test]
    fn unknown_issuer_fails_only_after_signature() {
        // The rogue issuer is registered in the source (a real cache would
        // never hold its key): this pins the *verifier* half of the
        // contract - issuer trust is decided strictly after the signature.
        let (fx, mut source) = key_source();
        let rogue = String::from("https://evil.example.org/realms/rogue");
        let key = source
            .keys
            .get(&(fx.issuer.clone(), fx.kid.clone()))
            .cloned()
            .expect("fixture key present");
        source.keys.insert((rogue.clone(), fx.kid.clone()), key);
        let v = verifier(
            vec![fx.issuer.clone()],
            BTreeMap::new(),
            30,
            Arc::new(source),
        );
        let token = signed_token(&fx, HEADER, &claims(&rogue));
        assert_eq!(v.verify(&token, NOW), Err(OidcError::Issuer));
    }

    #[test]
    fn tampered_payload_breaks_the_signature() {
        let (fx, v) = std_setup();
        let honest_signed = signed_token(&fx, HEADER, &claims(&fx.issuer));
        let signature = honest_signed.rsplit_once('.').expect("three segments").1;
        // Present a different (decode-clean, valid-JSON) payload under the
        // original signature.
        let forged = claims(&fx.issuer).replace("ci-1", "ci-9");
        let header_seg = seg(HEADER);
        let forged_seg = seg(&forged);
        let token = format!("{header_seg}.{forged_seg}.{signature}");
        assert_eq!(v.verify(&token, NOW), Err(OidcError::Signature));
    }

    #[test]
    fn expired_is_rejected_and_leeway_credits_its_seconds() {
        let (fx, v) = std_setup();
        // exp = NOW - 30 sits exactly at the boundary (now >= exp + leeway).
        let at_boundary = format!(
            r#"{{"iss":"{}","aud":"cachette","exp":{},"nbf":{}}}"#,
            fx.issuer,
            NOW - 30,
            NOW - 40
        );
        let token = signed_token(&fx, HEADER, &at_boundary);
        assert_eq!(v.verify(&token, NOW), Err(OidcError::Expired));

        // exp = NOW - 29 is one leeway-second short of expiring: accepted.
        let within_leeway = format!(
            r#"{{"iss":"{}","aud":"cachette","repository":"{REPOSITORY}","exp":{},"nbf":{}}}"#,
            fx.issuer,
            NOW - 29,
            NOW - 40
        );
        let token = signed_token(&fx, HEADER, &within_leeway);
        assert!(v.verify(&token, NOW).is_ok());
    }

    #[test]
    fn zero_leeway_returns_to_strict_exp_and_nbf_rules() {
        let (fx, source) = key_source();
        let v = verifier(
            vec![fx.issuer.clone()],
            BTreeMap::new(),
            0,
            Arc::new(source),
        );
        let payload = format!(
            r#"{{"iss":"{}","aud":"cachette","exp":{},"nbf":{}}}"#,
            fx.issuer,
            NOW - 1,
            NOW - 2
        );
        let token = signed_token(&fx, HEADER, &payload);
        assert_eq!(v.verify(&token, NOW), Err(OidcError::Expired));
    }

    #[test]
    fn future_nbf_is_rejected_and_leeway_credits_its_seconds() {
        let (fx, v) = std_setup();
        let beyond_leeway = format!(
            r#"{{"iss":"{}","aud":"cachette","exp":{},"nbf":{}}}"#,
            fx.issuer,
            NOW + 300,
            NOW + 31
        );
        let token = signed_token(&fx, HEADER, &beyond_leeway);
        assert_eq!(v.verify(&token, NOW), Err(OidcError::NotYetValid));

        let within_leeway = format!(
            r#"{{"iss":"{}","aud":"cachette","repository":"{REPOSITORY}","exp":{},"nbf":{}}}"#,
            fx.issuer,
            NOW + 300,
            NOW + 30
        );
        let token = signed_token(&fx, HEADER, &within_leeway);
        assert!(v.verify(&token, NOW).is_ok());
    }

    #[test]
    fn require_pins_match_exact_strings_and_array_members() {
        let (fx, source) = key_source();
        let mut require = BTreeMap::new();
        require.insert(String::from("sub"), String::from("ci-1"));
        require.insert(String::from("groups"), String::from("ci"));
        let v = verifier(vec![fx.issuer.clone()], require, 30, Arc::new(source));
        let payload = format!(
            r#"{{"iss":"{}","aud":"cachette","sub":"ci-1","groups":["devs","ci"],"repository":"{REPOSITORY}","exp":{},"nbf":{}}}"#,
            fx.issuer,
            NOW + 300,
            NOW - 5
        );
        let token = signed_token(&fx, HEADER, &payload);
        assert!(v.verify(&token, NOW).is_ok());

        // Wrong exact string value.
        let wrong_sub = format!(
            r#"{{"iss":"{}","aud":"cachette","sub":"ci-9","groups":["devs","ci"],"exp":{},"nbf":{}}}"#,
            fx.issuer,
            NOW + 300,
            NOW - 5
        );
        let token = signed_token(&fx, HEADER, &wrong_sub);
        assert_eq!(v.verify(&token, NOW), Err(OidcError::Require));

        // Array claim without the pinned member.
        let subset_groups = format!(
            r#"{{"iss":"{}","aud":"cachette","sub":"ci-1","groups":["devs"],"exp":{},"nbf":{}}}"#,
            fx.issuer,
            NOW + 300,
            NOW - 5
        );
        let token = signed_token(&fx, HEADER, &subset_groups);
        assert_eq!(v.verify(&token, NOW), Err(OidcError::Require));

        // An absent pinned claim never grants.
        let absent = format!(
            r#"{{"iss":"{}","aud":"cachette","sub":"ci-1","exp":{},"nbf":{}}}"#,
            fx.issuer,
            NOW + 300,
            NOW - 5
        );
        let token = signed_token(&fx, HEADER, &absent);
        assert_eq!(v.verify(&token, NOW), Err(OidcError::Require));
    }

    #[test]
    fn missing_required_claims_are_structural_failures() {
        let (fx, v) = std_setup();
        // No `aud` claim: signed fine, rejected at the aud gate.
        let no_aud = format!(
            r#"{{"iss":"{}","exp":{},"nbf":{}}}"#,
            fx.issuer,
            NOW + 300,
            NOW - 5
        );
        let token = signed_token(&fx, HEADER, &no_aud);
        assert_eq!(v.verify(&token, NOW), Err(OidcError::Audience));

        // No `exp`/`nbf` claims: signed fine, structurally broken.
        let no_ttl = format!(r#"{{"iss":"{}","aud":"cachette"}}"#, fx.issuer);
        let token = signed_token(&fx, HEADER, &no_ttl);
        assert_eq!(v.verify(&token, NOW), Err(OidcError::Malformed));

        // No `iss`: the key index cannot even be formed.
        let no_iss = format!(
            r#"{{"aud":"cachette","exp":{},"nbf":{}}}"#,
            NOW + 300,
            NOW - 5
        );
        let token = signed_token(&fx, HEADER, &no_iss);
        assert_eq!(v.verify(&token, NOW), Err(OidcError::Malformed));
    }

    #[test]
    fn header_without_kid_is_rejected_before_lookup() {
        let (fx, v) = std_setup();
        let header = r#"{"alg":"RS256","typ":"JWT"}"#;
        let token = signed_token(&fx, header, &claims(&fx.issuer));
        assert_eq!(v.verify(&token, NOW), Err(OidcError::Malformed));
    }

    #[test]
    fn malformed_tokens_are_rejected() {
        let (fx, v) = std_setup();
        assert_eq!(v.verify("garbage", NOW), Err(OidcError::Malformed));
        assert_eq!(v.verify("a.b", NOW), Err(OidcError::Malformed));
        assert_eq!(v.verify("a.b.c.d", NOW), Err(OidcError::Malformed));
        // Payload that decodes but is not a JSON object.
        let token = signed_token(&fx, HEADER, "[]");
        assert_eq!(v.verify(&token, NOW), Err(OidcError::Malformed));
    }
}
