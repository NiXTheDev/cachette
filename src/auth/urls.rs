//! Signed download/upload URLs (plan task 16, M2/M3).
//!
//! A signed URL carries `?id=<entryId>&exp=<unix>&mac=<hex>` — plus, since the
//! multi-tenant cache (v1.2 workstream F, `docs/shared-cache.md` §4), an
//! optional `&ns=<namespace>`: `mac = hex(HMAC-SHA256(secret, payload))` over
//! `"{path}|{id}|{exp}"` when no namespace is bound, and
//! `"{path}|{id}|{exp}|{ns}"` when one is. The same primitive backs v1 artifact
//! downloads and v2 capability URLs, so one TTL knob
//! (`v1.signed_url_ttl_seconds`) governs both (M2/M3).
//!
//! `path` is the exact resource path the URL was minted for; it is bound into
//! the MAC, so the `id` in the query is cross-checked against the path and any
//! substitution of either is caught as a MAC mismatch. The namespace rides the
//! same way: it is mint-side data the client only echoes, so a URL minted for
//! one tenant cannot be replayed into another's namespace — stripping the `ns`
//! parameter is a MAC mismatch, exactly like tampering with `id`.
//!
//! A URL without `ns` validates to the legacy (default) namespace — the shape
//! every pre-namespaces mint produced, so a rolling upgrade keeps serving
//! URLs minted before the restart.
//!
//! Expiry is checked at request start only: a transfer already in progress runs
//! to completion (m7). Validation is fail-closed and opaque — every rejection
//! maps to HTTP 403 `{"error":"invalid or expired url"}` through
//! [`From<UrlError> for ApiError`].

use std::collections::HashMap;

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use super::Namespace;
use crate::auth::constant_time_eq;
use crate::error::ApiError;

/// A minted signed-URL token: the query components only, ready to append to a
/// resource path (see [`SignedUrl::query`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedUrl {
    /// Entry id the token is bound to.
    pub id: String,
    /// Absolute Unix expiry (seconds).
    pub exp: i64,
    /// The namespace the URL resolves to; empty = the legacy namespace, and
    /// the parameter is then OMITTED from the query (the pre-namespaces wire
    /// shape, byte for byte).
    pub ns: String,
    /// Lowercase-hex HMAC-SHA256 over the payload (`"{path}|{id}|{exp}"`,
    /// with `|{ns}` appended when a namespace is bound).
    pub mac: String,
}

impl SignedUrl {
    /// Render the query suffix, e.g. `?id=42&exp=1700000900&mac=<hex>`.
    ///
    /// The namespace is percent-encoded (its default form contains `|` and a
    /// URL issuer); the MAC covers the RAW namespace, and the server's query
    /// parser decodes the wire form back before validation compares MACs.
    #[must_use]
    pub fn query(&self) -> String {
        let mut query = format!("?id={}&exp={}", self.id, self.exp);
        if !self.ns.is_empty() {
            query.push_str("&ns=");
            query.push_str(&percent_encode(&self.ns));
        }
        query.push_str("&mac=");
        query.push_str(&self.mac);
        query
    }
}

/// Percent-encode a query component: everything outside the RFC 3986
/// unreserved set becomes `%XX` (uppercase hex). Hand-rolled because the
/// namespace is the only encoded field and `form_urlencoded` would also
/// encode/normalize shapes this URL grammar must not touch.
fn percent_encode(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(*byte as char);
            }
            other => {
                encoded.push('%');
                encoded.push_str(&format!("{other:02X}"));
            }
        }
    }
    encoded
}

/// Why a signed URL failed validation. Every variant collapses to the same
/// opaque 403 at the HTTP boundary; the distinction is for internal tests and
/// diagnostics only.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum UrlError {
    #[error("missing id")]
    MissingId,
    #[error("missing exp")]
    MissingExp,
    #[error("missing mac")]
    MissingMac,
    #[error("invalid exp")]
    InvalidExp,
    #[error("mac mismatch")]
    MacMismatch,
    #[error("expired")]
    Expired,
}

impl From<UrlError> for ApiError {
    fn from(_: UrlError) -> Self {
        // Deliberately opaque: never reveal which check failed (M2/M3).
        Self::Forbidden(String::from("invalid or expired url"))
    }
}

/// Mint a signed-URL token for `path`/`id` with the given TTL, evaluated at
/// `now_unix` (injected so callers and tests are deterministic), bound to
/// `namespace`. An empty namespace mints the legacy wire shape (no `ns`
/// parameter) — byte-identical to every pre-namespaces mint.
#[must_use]
pub fn mint(
    path: &str,
    id: &str,
    secret: &str,
    ttl_seconds: u64,
    now_unix: i64,
    namespace: &str,
) -> SignedUrl {
    let exp = now_unix + ttl_seconds as i64;
    let mac = sign(path, id, exp, namespace, secret);
    SignedUrl {
        id: id.to_owned(),
        exp,
        ns: namespace.to_owned(),
        mac,
    }
}

/// Validate query parameters against the resource `path` and `secret`.
///
/// Rejects (all mapped to one 403 by the caller): missing `id`/`exp`/`mac`,
/// an unparseable `exp`, a MAC mismatch (covers any tampering with `path`,
/// `id`, `exp`, or the bound namespace — including stripping a minted `ns`
/// parameter), and expiry (`exp <= now_unix`). On success returns the bound
/// namespace: the `ns` query value when the URL carries one, the legacy
/// namespace otherwise.
pub fn validate(
    query: &HashMap<String, String>,
    path: &str,
    secret: &str,
    now_unix: i64,
) -> Result<Namespace, UrlError> {
    let id = query.get("id").ok_or(UrlError::MissingId)?;
    let exp_raw = query.get("exp").ok_or(UrlError::MissingExp)?;
    let mac = query.get("mac").ok_or(UrlError::MissingMac)?;
    let exp: i64 = exp_raw.parse().map_err(|_| UrlError::InvalidExp)?;
    let ns = query.get("ns").map(String::as_str).unwrap_or_default();

    let expected = sign(path, id, exp, ns, secret);
    if !constant_time_eq(expected.as_bytes(), mac.as_bytes()) {
        return Err(UrlError::MacMismatch);
    }
    if exp <= now_unix {
        return Err(UrlError::Expired);
    }
    Ok(Namespace(ns.to_owned()))
}

/// Lowercase-hex HMAC-SHA256 over the canonical payload: `"{path}|{id}|{exp}"`
/// when `namespace` is empty (the legacy shape), with `|{namespace}` appended
/// otherwise — so a minted namespace cannot be stripped or swapped without a
/// MAC mismatch.
fn sign(path: &str, id: &str, exp: i64, namespace: &str, secret: &str) -> String {
    let mut payload = format!("{path}|{id}|{exp}");
    if !namespace.is_empty() {
        payload.push('|');
        payload.push_str(namespace);
    }
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts keys of any length");
    mac.update(payload.as_bytes());
    mac.finalize()
        .into_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use axum::http::StatusCode;

    use super::*;

    const SECRET: &str = "test-secret-0123456789abcdef";
    const PATH: &str = "/_apis/artifactcache/artifacts/42";
    const ID: &str = "42";
    const NOW: i64 = 1_700_000_000;

    fn params(signed: &SignedUrl) -> HashMap<String, String> {
        let mut query = HashMap::from([
            (String::from("id"), signed.id.clone()),
            (String::from("exp"), signed.exp.to_string()),
        ]);
        if !signed.ns.is_empty() {
            query.insert(String::from("ns"), signed.ns.clone());
        }
        query.insert(String::from("mac"), signed.mac.clone());
        query
    }

    fn mutate_mac_byte(mac: &str, index: usize) -> String {
        let mut bytes = mac.as_bytes().to_vec();
        bytes[index] = if bytes[index] == b'0' { b'1' } else { b'0' };
        String::from_utf8(bytes).expect("hex is utf-8")
    }

    #[test]
    fn mint_then_validate_roundtrips() {
        let signed = mint(PATH, ID, SECRET, 900, NOW, "");
        assert_eq!(signed.exp, NOW + 900);
        assert_eq!(signed.ns, "");
        // The legacy shape: no ns parameter on the wire at all.
        assert_eq!(
            signed.query(),
            format!("?id=42&exp={}&mac={}", NOW + 900, signed.mac)
        );
        let ns = validate(&params(&signed), PATH, SECRET, NOW).expect("fresh url validates");
        assert_eq!(ns, Namespace::legacy());
    }

    #[test]
    fn minted_namespace_roundtrips_through_the_query() {
        let ns = "https://forge.example|owner/repo";
        let signed = mint(PATH, ID, SECRET, 900, NOW, ns);
        assert_eq!(signed.ns, ns);
        // The namespace is percent-encoded on the wire (`|` is not query-safe)
        // but the MAC covers the raw form.
        assert!(
            signed
                .query()
                .contains("&ns=https%3A%2F%2Fforge.example%7Cowner%2Frepo&")
        );
        let resolved = validate(&params(&signed), PATH, SECRET, NOW).expect("namespaced url");
        assert_eq!(resolved, Namespace(ns.to_owned()));
    }

    #[test]
    fn stripping_a_minted_namespace_is_a_mac_mismatch() {
        let signed = mint(
            PATH,
            ID,
            SECRET,
            900,
            NOW,
            "https://forge.example|owner/repo",
        );
        let mut query = params(&signed);
        query.remove("ns");
        assert_eq!(
            validate(&query, PATH, SECRET, NOW),
            Err(UrlError::MacMismatch)
        );
    }

    #[test]
    fn a_minted_namespace_cannot_be_swapped_for_another() {
        let signed = mint(PATH, ID, SECRET, 900, NOW, "forge-a|tenant-a");
        let mut query = params(&signed);
        query.insert(String::from("ns"), String::from("forge-a|tenant-b"));
        assert_eq!(
            validate(&query, PATH, SECRET, NOW),
            Err(UrlError::MacMismatch)
        );
    }

    #[test]
    fn an_empty_ns_parameter_is_the_legacy_namespace() {
        let signed = mint(PATH, ID, SECRET, 900, NOW, "");
        let mut query = params(&signed);
        query.insert(String::from("ns"), String::new());
        let resolved = validate(&query, PATH, SECRET, NOW).expect("legacy with explicit ns");
        assert_eq!(resolved, Namespace::legacy());
    }

    #[test]
    fn tampered_mac_is_rejected() {
        let signed = mint(PATH, ID, SECRET, 900, NOW, "");
        let mut query = params(&signed);
        query.insert(String::from("mac"), mutate_mac_byte(&signed.mac, 0));
        assert_eq!(
            validate(&query, PATH, SECRET, NOW),
            Err(UrlError::MacMismatch)
        );
    }

    #[test]
    fn id_mismatch_is_rejected() {
        let signed = mint(PATH, ID, SECRET, 900, NOW, "");
        let mut query = params(&signed);
        query.insert(String::from("id"), String::from("43"));
        assert_eq!(
            validate(&query, PATH, SECRET, NOW),
            Err(UrlError::MacMismatch)
        );
    }

    #[test]
    fn different_path_is_rejected() {
        let signed = mint(PATH, ID, SECRET, 900, NOW, "");
        assert_eq!(
            validate(
                &params(&signed),
                "/_apis/artifactcache/artifacts/43",
                SECRET,
                NOW
            ),
            Err(UrlError::MacMismatch)
        );
    }

    #[test]
    fn exp_in_the_past_is_rejected() {
        // A genuinely minted URL whose exp is `now - 1` (ttl elapsed one second ago).
        let signed = mint(PATH, ID, SECRET, 0, NOW - 1, "");
        assert_eq!(signed.exp, NOW - 1);
        assert_eq!(
            validate(&params(&signed), PATH, SECRET, NOW),
            Err(UrlError::Expired)
        );
    }

    #[test]
    fn expiry_boundary_is_exp_le_now() {
        let signed = mint(PATH, ID, SECRET, 900, NOW, "");
        let query = params(&signed);
        validate(&query, PATH, SECRET, NOW + 899).expect("valid just before exp");
        assert_eq!(
            validate(&query, PATH, SECRET, NOW + 900),
            Err(UrlError::Expired)
        );
    }

    #[test]
    fn ttl_900_stays_valid_at_600_and_expires_by_901() {
        let signed = mint(PATH, ID, SECRET, 900, NOW, "");
        let query = params(&signed);
        validate(&query, PATH, SECRET, NOW + 600).expect("valid at t+600");
        assert_eq!(
            validate(&query, PATH, SECRET, NOW + 901),
            Err(UrlError::Expired)
        );
    }

    #[test]
    fn missing_id_exp_mac_are_rejected() {
        let signed = mint(PATH, ID, SECRET, 900, NOW, "");
        let mut no_id = params(&signed);
        no_id.remove("id");
        let mut no_exp = params(&signed);
        no_exp.remove("exp");
        let mut no_mac = params(&signed);
        no_mac.remove("mac");
        assert_eq!(
            validate(&no_id, PATH, SECRET, NOW),
            Err(UrlError::MissingId)
        );
        assert_eq!(
            validate(&no_exp, PATH, SECRET, NOW),
            Err(UrlError::MissingExp)
        );
        assert_eq!(
            validate(&no_mac, PATH, SECRET, NOW),
            Err(UrlError::MissingMac)
        );
    }

    #[test]
    fn malformed_exp_is_rejected() {
        let signed = mint(PATH, ID, SECRET, 900, NOW, "");
        let mut query = params(&signed);
        query.insert(String::from("exp"), String::from("not-a-number"));
        assert_eq!(
            validate(&query, PATH, SECRET, NOW),
            Err(UrlError::InvalidExp)
        );
    }

    #[test]
    fn url_errors_map_to_403_invalid_or_expired_url() {
        let errors = [
            UrlError::MissingId,
            UrlError::MissingExp,
            UrlError::MissingMac,
            UrlError::InvalidExp,
            UrlError::MacMismatch,
            UrlError::Expired,
        ];
        for err in errors {
            let api = ApiError::from(err);
            assert_eq!(api.status(), StatusCode::FORBIDDEN, "err: {err:?}");
            assert_eq!(api.to_string(), "invalid or expired url", "err: {err:?}");
        }
    }
}
