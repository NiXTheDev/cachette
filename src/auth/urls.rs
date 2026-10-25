//! Signed download/upload URLs (plan task 16, M2/M3).
//!
//! A signed URL carries `?id=<entryId>&exp=<unix>&mac=<hex>`, where
//! `mac = hex(HMAC-SHA256(secret, "{path}|{id}|{exp}"))`. The same primitive
//! backs v1 artifact downloads and v2 capability URLs, so one TTL knob
//! (`v1.signed_url_ttl_seconds`) governs both (M2/M3).
//!
//! `path` is the exact resource path the URL was minted for; it is bound into
//! the MAC, so the `id` in the query is cross-checked against the path and any
//! substitution of either is caught as a MAC mismatch.
//!
//! Expiry is checked at request start only: a transfer already in progress runs
//! to completion (m7). Validation is fail-closed and opaque — every rejection
//! maps to HTTP 403 `{"error":"invalid or expired url"}` through
//! [`From<UrlError> for ApiError`].

use std::collections::HashMap;

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

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
    /// Lowercase-hex HMAC-SHA256 over `"{path}|{id}|{exp}"`.
    pub mac: String,
}

impl SignedUrl {
    /// Render the query suffix, e.g. `?id=42&exp=1700000900&mac=<hex>`.
    #[must_use]
    pub fn query(&self) -> String {
        format!("?id={}&exp={}&mac={}", self.id, self.exp, self.mac)
    }
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
/// `now_unix` (injected so callers and tests are deterministic).
#[must_use]
pub fn mint(path: &str, id: &str, secret: &str, ttl_seconds: u64, now_unix: i64) -> SignedUrl {
    let exp = now_unix + ttl_seconds as i64;
    let mac = sign(path, id, exp, secret);
    SignedUrl {
        id: id.to_owned(),
        exp,
        mac,
    }
}

/// Validate query parameters against the resource `path` and `secret`.
///
/// Rejects (all mapped to one 403 by the caller): missing `id`/`exp`/`mac`,
/// an unparseable `exp`, a MAC mismatch (covers any tampering with `path`,
/// `id`, or `exp`), and expiry (`exp <= now_unix`).
pub fn validate(
    query: &HashMap<String, String>,
    path: &str,
    secret: &str,
    now_unix: i64,
) -> Result<(), UrlError> {
    let id = query.get("id").ok_or(UrlError::MissingId)?;
    let exp_raw = query.get("exp").ok_or(UrlError::MissingExp)?;
    let mac = query.get("mac").ok_or(UrlError::MissingMac)?;
    let exp: i64 = exp_raw.parse().map_err(|_| UrlError::InvalidExp)?;

    let expected = sign(path, id, exp, secret);
    if !constant_time_eq(expected.as_bytes(), mac.as_bytes()) {
        return Err(UrlError::MacMismatch);
    }
    if exp <= now_unix {
        return Err(UrlError::Expired);
    }
    Ok(())
}

/// Lowercase-hex HMAC-SHA256 over the canonical `"{path}|{id}|{exp}"` payload.
fn sign(path: &str, id: &str, exp: i64, secret: &str) -> String {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts keys of any length");
    mac.update(format!("{path}|{id}|{exp}").as_bytes());
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
        HashMap::from([
            (String::from("id"), signed.id.clone()),
            (String::from("exp"), signed.exp.to_string()),
            (String::from("mac"), signed.mac.clone()),
        ])
    }

    fn mutate_mac_byte(mac: &str, index: usize) -> String {
        let mut bytes = mac.as_bytes().to_vec();
        bytes[index] = if bytes[index] == b'0' { b'1' } else { b'0' };
        String::from_utf8(bytes).expect("hex is utf-8")
    }

    #[test]
    fn mint_then_validate_roundtrips() {
        let signed = mint(PATH, ID, SECRET, 900, NOW);
        assert_eq!(signed.exp, NOW + 900);
        assert_eq!(
            signed.query(),
            format!("?id=42&exp={}&mac={}", NOW + 900, signed.mac)
        );
        validate(&params(&signed), PATH, SECRET, NOW).expect("fresh url validates");
    }

    #[test]
    fn tampered_mac_is_rejected() {
        let signed = mint(PATH, ID, SECRET, 900, NOW);
        let mut query = params(&signed);
        query.insert(String::from("mac"), mutate_mac_byte(&signed.mac, 0));
        assert_eq!(
            validate(&query, PATH, SECRET, NOW),
            Err(UrlError::MacMismatch)
        );
    }

    #[test]
    fn id_mismatch_is_rejected() {
        let signed = mint(PATH, ID, SECRET, 900, NOW);
        let mut query = params(&signed);
        query.insert(String::from("id"), String::from("43"));
        assert_eq!(
            validate(&query, PATH, SECRET, NOW),
            Err(UrlError::MacMismatch)
        );
    }

    #[test]
    fn different_path_is_rejected() {
        let signed = mint(PATH, ID, SECRET, 900, NOW);
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
        let signed = mint(PATH, ID, SECRET, 0, NOW - 1);
        assert_eq!(signed.exp, NOW - 1);
        assert_eq!(
            validate(&params(&signed), PATH, SECRET, NOW),
            Err(UrlError::Expired)
        );
    }

    #[test]
    fn expiry_boundary_is_exp_le_now() {
        let signed = mint(PATH, ID, SECRET, 900, NOW);
        let query = params(&signed);
        validate(&query, PATH, SECRET, NOW + 899).expect("valid just before exp");
        assert_eq!(
            validate(&query, PATH, SECRET, NOW + 900),
            Err(UrlError::Expired)
        );
    }

    #[test]
    fn ttl_900_stays_valid_at_600_and_expires_by_901() {
        let signed = mint(PATH, ID, SECRET, 900, NOW);
        let query = params(&signed);
        validate(&query, PATH, SECRET, NOW + 600).expect("valid at t+600");
        assert_eq!(
            validate(&query, PATH, SECRET, NOW + 901),
            Err(UrlError::Expired)
        );
    }

    #[test]
    fn missing_id_exp_mac_are_rejected() {
        let signed = mint(PATH, ID, SECRET, 900, NOW);
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
        let signed = mint(PATH, ID, SECRET, 900, NOW);
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
