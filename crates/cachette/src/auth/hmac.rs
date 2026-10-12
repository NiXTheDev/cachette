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
