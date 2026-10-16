//! Forgejo artifactcache HMAC authentication (plan task 15).
//!
//! Mirrors the Forgejo runner (`act/artifactcache/mac.go`): the MAC is
//! `hex(HMAC-SHA256(secret, "<repo>><run>><timestamp>><writeIsolationKey>"))`
//! carried in the `Forgejo-Cache-*` headers. The timestamp is Unix seconds;
//! Forgejo rejects timestamps in the future, and cachette additionally
//! rejects stale timestamps older than `[auth] hmac_max_age_seconds`
//! (0 = disabled, GitHub parity).

use axum::http::HeaderMap;

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use crate::auth::AuthPolicy;
use crate::auth::now_secs;

/// `Forgejo-Cache-Repo` — repository path, e.g. `owner/repo`.
pub const HEADER_REPO: &str = "forgejo-cache-repo";
/// `Forgejo-Cache-RunNumber` — workflow run number.
pub const HEADER_RUN: &str = "forgejo-cache-runnumber";
/// `Forgejo-Cache-Timestamp` — Unix seconds when the MAC was minted.
pub const HEADER_TS: &str = "forgejo-cache-timestamp";
/// `Forgejo-Cache-MAC` — hex HMAC-SHA256 over the joined fields.
pub const HEADER_MAC: &str = "forgejo-cache-mac";
/// `Forgejo-Cache-WriteIsolationKey` — optional; empty when absent.
pub const HEADER_WRITE_ISOLATION: &str = "forgejo-cache-writeisolationkey";

/// Clock-skew tolerance for future timestamps (seconds).
const MAX_FUTURE_SKEW_SECONDS: i64 = 5;

/// Verify the Forgejo HMAC headers against `policy.secret`.
///
/// Fails closed: any missing header, unparseable timestamp, bad hex, or MAC
/// mismatch rejects the request. A missing `auth.secret` rejects everything.
pub fn verify(policy: &AuthPolicy, headers: &HeaderMap) -> bool {
    let Some(secret) = policy.secret.as_deref() else {
        return false;
    };
    let Some(repo) = header(headers, HEADER_REPO) else {
        return false;
    };
    let Some(run) = header(headers, HEADER_RUN) else {
        return false;
    };
    let Some(ts) = header(headers, HEADER_TS) else {
        return false;
    };
    let Some(provided) = header(headers, HEADER_MAC) else {
        return false;
    };
    let Ok(ts) = ts.parse::<i64>() else {
        return false;
    };
    let now = now_secs();
    if ts > now + MAX_FUTURE_SKEW_SECONDS {
        return false;
    }
    if policy.hmac_max_age_seconds > 0 && now - ts > policy.hmac_max_age_seconds as i64 {
        return false;
    }
    let isolation = header(headers, HEADER_WRITE_ISOLATION).unwrap_or("");
    let payload = format!("{repo}>{run}>{ts}>{isolation}");
    let Some(provided) = hex_decode(provided) else {
        return false;
    };
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(secret.as_bytes()) else {
        return false;
    };
    mac.update(payload.as_bytes());
    mac.verify_slice(&provided).is_ok()
}

/// Mint the hex `Forgejo-Cache-MAC` over `repo`, `run`, `timestamp`, and
/// `isolation` for `secret` — the exact inverse of [`verify`]'s payload
/// assembly, so `cachette token mint` (plan task 46) never hand-rolls the
/// signature. A timestamp in the future (beyond the 5s skew) or older than
/// `[auth] hmac_max_age_seconds` is rejected by the server, exactly as for a
/// runner-minted token.
#[must_use]
pub fn mint(secret: &str, repo: &str, run: u64, timestamp: i64, isolation: &str) -> String {
    let payload = format!("{repo}>{run}>{timestamp}>{isolation}");
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(payload.as_bytes());
    hex_encode(&mac.finalize().into_bytes())
}

/// Lowercase hex of `bytes` (the wire form of the MAC header).
fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

fn hex_decode(hex: &str) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    for pair in hex.as_bytes().chunks(2) {
        let hi = hex_val(pair[0])?;
        let lo = hex_val(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

fn hex_val(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderMap;
    use axum::http::HeaderValue;

    use super::*;

    /// A minted MAC round-trips through [`verify`] and rejects when any signed
    /// field changes (plan task 46: `token mint` shares verify's payload).
    #[test]
    fn mint_round_trips_through_verify() {
        let policy = AuthPolicy {
            secret: Some(String::from("super-secret-key-16")),
            ..AuthPolicy::default()
        };
        let ts = now_secs();
        let mac = mint("super-secret-key-16", "owner/repo", 42, ts, "owner/repo");

        let mut headers = HeaderMap::new();
        headers.insert(HEADER_REPO, HeaderValue::from_static("owner/repo"));
        headers.insert(HEADER_RUN, HeaderValue::from_static("42"));
        headers.insert(HEADER_TS, HeaderValue::from_str(&ts.to_string()).unwrap());
        headers.insert(
            HEADER_WRITE_ISOLATION,
            HeaderValue::from_static("owner/repo"),
        );
        headers.insert(HEADER_MAC, HeaderValue::from_str(&mac).unwrap());
        assert!(verify(&policy, &headers), "freshly minted MAC verifies");

        // A read-scope token (no isolation header) also verifies.
        let read_mac = mint("super-secret-key-16", "owner/repo", 42, ts, "");
        let mut read_headers = HeaderMap::new();
        read_headers.insert(HEADER_REPO, HeaderValue::from_static("owner/repo"));
        read_headers.insert(HEADER_RUN, HeaderValue::from_static("42"));
        read_headers.insert(HEADER_TS, HeaderValue::from_str(&ts.to_string()).unwrap());
        read_headers.insert(HEADER_MAC, HeaderValue::from_str(&read_mac).unwrap());
        assert!(verify(&policy, &read_headers), "read-scope MAC verifies");

        // Tampering with the run invalidates it.
        headers.insert(HEADER_RUN, HeaderValue::from_static("43"));
        assert!(!verify(&policy, &headers), "changed run rejects");
    }

    #[test]
    fn mint_matches_a_hand_computed_mac() {
        // Independent computation (not via `verify`) for a known vector.
        let mut mac = Hmac::<Sha256>::new_from_slice(b"secret").unwrap();
        mac.update(b"o/r>7>1700000000>iso");
        let expected: String =
            mac.finalize()
                .into_bytes()
                .iter()
                .fold(String::new(), |mut acc, byte| {
                    use std::fmt::Write as _;
                    let _ = write!(acc, "{byte:02x}");
                    acc
                });
        assert_eq!(mint("secret", "o/r", 7, 1_700_000_000, "iso"), expected);
    }
}
