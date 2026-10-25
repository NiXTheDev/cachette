//! v2 HS256 JWTs (plan task 16, M2/M3).
//!
//! The Twirp API self-mints a short-lived JWT at request time from
//! `v2.jwt_secret` (falling back to `auth.secret`) and validates it on the
//! next call. Claims are `{ac, exp: now + jwt_ttl_seconds, nbf: now - 5}`;
//! the header is `{"alg":"HS256","typ":"JWT"}` and every segment is
//! base64url without padding.
//!
//! The JWT is accepted only by the Twirp API auth gate (tasks 23/27): it is
//! never carried on capability URLs and never authenticates v1 routes. This
//! module supplies only the mint/validate primitive.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

const ALGORITHM: &str = "HS256";
const TYPE: &str = "JWT";
/// `nbf` is set this many seconds in the past to tolerate clock skew.
const NOT_BEFORE_SKEW_SECONDS: i64 = 5;

/// Fixed JOSE header. Field order is declaration order, so the encoded header
/// is the canonical `{"alg":"HS256","typ":"JWT"}`.
#[derive(Deserialize, Serialize)]
struct Header {
    alg: String,
    typ: String,
}

/// Verified JWT claims. Deserialization requires every field, so a token
/// missing `ac`/`exp`/`nbf` is rejected as malformed.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct JwtClaims {
    /// Application-defined claim minted with the token (plan `ac`).
    pub ac: String,
    /// Absolute Unix expiry (seconds).
    pub exp: i64,
    /// Absolute Unix "not before" (seconds).
    pub nbf: i64,
}

/// Why a JWT failed validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum JwtError {
    #[error("malformed token")]
    Malformed,
    #[error("unsupported algorithm")]
    UnsupportedAlg,
    #[error("bad signature")]
    BadSignature,
    #[error("token expired")]
    Expired,
    #[error("token not yet valid")]
    NotYetValid,
}

/// Mint an HS256 JWT for `ac` with the given TTL, evaluated at `now_unix`.
#[must_use]
pub fn mint(secret: &str, ac: &str, ttl_seconds: u64, now_unix: i64) -> String {
    let header = Header {
        alg: String::from(ALGORITHM),
        typ: String::from(TYPE),
    };
    let claims = JwtClaims {
        ac: ac.to_owned(),
        exp: now_unix + ttl_seconds as i64,
        nbf: now_unix - NOT_BEFORE_SKEW_SECONDS,
    };
    // Serializing a fixed struct of strings/i64 cannot fail.
    let header_seg = encode(serde_json::to_vec(&header).expect("header serializes"));
    let payload_seg = encode(serde_json::to_vec(&claims).expect("claims serialize"));
    let signing_input = format!("{header_seg}.{payload_seg}");
    let signature = {
        let mut mac = key(secret);
        mac.update(signing_input.as_bytes());
        encode(mac.finalize().into_bytes())
    };
    format!("{signing_input}.{signature}")
}

/// Validate an HS256 JWT: structure, header algorithm, signature
/// (constant-time), then `nbf`/`exp` against `now_unix`.
pub fn validate(token: &str, secret: &str, now_unix: i64) -> Result<JwtClaims, JwtError> {
    let mut parts = token.split('.');
    let header_seg = parts.next().ok_or(JwtError::Malformed)?;
    let payload_seg = parts.next().ok_or(JwtError::Malformed)?;
    let signature_seg = parts.next().ok_or(JwtError::Malformed)?;
    if parts.next().is_some() {
        return Err(JwtError::Malformed);
    }

    let header: Header = decode_json(header_seg)?;
    if header.alg != ALGORITHM {
        return Err(JwtError::UnsupportedAlg);
    }

    let signature = decode(signature_seg).ok_or(JwtError::Malformed)?;
    let signing_input = format!("{header_seg}.{payload_seg}");
    let mut mac = key(secret);
    mac.update(signing_input.as_bytes());
    mac.verify_slice(&signature)
        .map_err(|_| JwtError::BadSignature)?;

    let claims: JwtClaims = decode_json(payload_seg)?;
    if now_unix < claims.nbf {
        return Err(JwtError::NotYetValid);
    }
    if now_unix >= claims.exp {
        return Err(JwtError::Expired);
    }
    Ok(claims)
}

/// HMAC-SHA256 (HS256) over `data`.
///
/// HMAC accepts keys of any length, so `new_from_slice` cannot fail here.
fn key(secret: &str) -> Hmac<Sha256> {
    Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts keys of any length")
}

fn encode(bytes: impl AsRef<[u8]>) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn decode(segment: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(segment).ok()
}

fn decode_json<T: serde::de::DeserializeOwned>(segment: &str) -> Result<T, JwtError> {
    let bytes = decode(segment).ok_or(JwtError::Malformed)?;
    serde_json::from_slice(&bytes).map_err(|_| JwtError::Malformed)
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;

    const SECRET: &str = "test-secret-0123456789abcdef";
    const AC: &str = "write";
    const NOW: i64 = 1_700_000_000;

    fn segment(json: &str) -> String {
        URL_SAFE_NO_PAD.encode(json.as_bytes())
    }

    fn sign_raw(secret: &str, signing_input: &str) -> String {
        let mut mac = key(secret);
        mac.update(signing_input.as_bytes());
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    }

    #[test]
    fn mint_then_validate_roundtrips_claims() {
        let token = mint(SECRET, AC, 300, NOW);
        assert_eq!(token.split('.').count(), 3);
        let claims = validate(&token, SECRET, NOW).expect("fresh token validates");
        assert_eq!(claims.ac, AC);
        assert_eq!(claims.exp, NOW + 300);
        assert_eq!(claims.nbf, NOW - 5);

        let payload = URL_SAFE_NO_PAD
            .decode(token.split('.').nth(1).expect("payload segment"))
            .expect("payload is base64url");
        let value: Value = serde_json::from_slice(&payload).expect("payload is json");
        assert_eq!(value["ac"], AC);
        assert_eq!(value["exp"], NOW + 300);
        assert_eq!(value["nbf"], NOW - 5);
    }

    #[test]
    fn header_is_hs256_jwt_and_segments_are_unpadded() {
        let token = mint(SECRET, AC, 300, NOW);
        assert!(!token.contains('='), "segments must be unpadded: {token}");
        let header = URL_SAFE_NO_PAD
            .decode(token.split('.').next().expect("header segment"))
            .expect("header is base64url");
        let value: Value = serde_json::from_slice(&header).expect("header is json");
        assert_eq!(value["alg"], "HS256");
        assert_eq!(value["typ"], "JWT");
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let token = mint(SECRET, AC, 300, NOW);
        let (body, signature) = token.rsplit_once('.').expect("three segments");
        let mut bytes = signature.as_bytes().to_vec();
        bytes[0] = if bytes[0] == b'A' { b'B' } else { b'A' };
        let tampered = format!("{body}.{}", String::from_utf8(bytes).expect("utf-8"));
        assert_eq!(
            validate(&tampered, SECRET, NOW),
            Err(JwtError::BadSignature)
        );
    }

    #[test]
    fn wrong_secret_is_rejected() {
        let token = mint(SECRET, AC, 300, NOW);
        assert_eq!(
            validate(&token, "other-secret-0123456789", NOW),
            Err(JwtError::BadSignature)
        );
    }

    #[test]
    fn expired_token_is_rejected() {
        let token = mint(SECRET, AC, 300, NOW - 400); // exp = NOW - 100
        assert_eq!(validate(&token, SECRET, NOW), Err(JwtError::Expired));
    }

    #[test]
    fn not_yet_valid_token_is_rejected() {
        let token = mint(SECRET, AC, 300, NOW); // nbf = NOW - 5
        assert_eq!(
            validate(&token, SECRET, NOW - 10),
            Err(JwtError::NotYetValid)
        );
    }

    #[test]
    fn malformed_tokens_are_rejected() {
        assert_eq!(validate("garbage", SECRET, NOW), Err(JwtError::Malformed));
        assert_eq!(validate("a.b", SECRET, NOW), Err(JwtError::Malformed));
        assert_eq!(validate("a.b.c.d", SECRET, NOW), Err(JwtError::Malformed));
        assert_eq!(validate("not.a.jwt", SECRET, NOW), Err(JwtError::Malformed));
    }

    #[test]
    fn unsupported_algorithm_is_rejected() {
        let header = segment(r#"{"alg":"none","typ":"JWT"}"#);
        let payload = segment(r#"{"ac":"write","exp":1700000300,"nbf":1699999995}"#);
        let token = format!("{header}.{payload}.sig");
        assert_eq!(validate(&token, SECRET, NOW), Err(JwtError::UnsupportedAlg));
    }

    #[test]
    fn missing_claim_is_rejected_even_with_valid_signature() {
        let header = segment(r#"{"alg":"HS256","typ":"JWT"}"#);
        let payload = segment(r#"{"exp":1700000300,"nbf":1699999995}"#); // no `ac`
        let signing_input = format!("{header}.{payload}");
        let signature = sign_raw(SECRET, &signing_input);
        let token = format!("{signing_input}.{signature}");
        assert_eq!(validate(&token, SECRET, NOW), Err(JwtError::Malformed));
    }
}
