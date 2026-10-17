//! Per-request authentication (plan task 15): Forgejo HMAC, bearer tokens, or
//! both (`merge`), plus the sqlite-backed dynamic token store behind the
//! admin register/revoke routes.
//!
//! Mode resolution happens per request in [`require_auth`]:
//! - `hmac`    — `Forgejo-Cache-*` headers only; missing/invalid → 401.
//! - `bearer`  — `Authorization: Bearer <token>` only; missing/invalid → 401.
//! - `merge`   — either; missing/invalid → 401.
//!
//! Authentication never falls through to anonymous.

pub mod bearer;
pub mod hmac;
pub mod jwt;
pub mod tokens;
pub mod urls;

use axum::extract::{Request, State};
use axum::http::HeaderMap;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::config::{AuthMode, Config};
use crate::error::ApiError;
use crate::state::AppState;

pub use jwt::{JwtClaims, JwtError};
pub use tokens::TokenStore;
pub use urls::{SignedUrl, UrlError};

/// Path prefix guarded by [`require_auth`]; plan task 18 owns the handlers.
pub const ARTIFACTCACHE_PREFIX: &str = "/_apis/artifactcache";

/// Artifact **downloads** are authorized by their signed URL alone: the GitHub
/// contract calls `archiveLocation` "already authenticated", and both real
/// clients (`@actions/cache`, `go-actions-cache`) follow it with **no**
/// `Authorization` header. They are therefore exempt from the HMAC/bearer gate
/// here; `routes::v1::download` still enforces `?id&exp&mac` whenever signed
/// URLs are required (bearer/merge modes, or any cluster) and permits a bare
/// GET only in pure single-node HMAC (the Forgejo proxy pattern, task 21
/// M2/M3). See plan task 22.
pub const ARTIFACT_DOWNLOAD_PREFIX: &str = "/_apis/artifactcache/artifacts/";

/// Auth policy snapshot: mode, admin secret, HMAC staleness window, static
/// bearer tokens, and whether cluster mode is on (loopback admin bypass).
#[derive(Clone, Debug)]
pub struct AuthPolicy {
    pub mode: AuthMode,
    pub secret: Option<String>,
    pub hmac_max_age_seconds: u64,
    pub static_tokens: Vec<String>,
    pub cluster_enabled: bool,
}

impl AuthPolicy {
    /// Snapshot the resolved `[auth]` + `[cluster]` settings.
    pub fn from_config(config: &Config) -> Self {
        Self {
            mode: config.auth.mode,
            secret: config.auth.secret.clone(),
            hmac_max_age_seconds: config.auth.hmac_max_age_seconds,
            static_tokens: config.auth.tokens.clone(),
            cluster_enabled: config.cluster.enabled,
        }
    }
}

impl Default for AuthPolicy {
    fn default() -> Self {
        Self {
            mode: AuthMode::Merge,
            secret: None,
            hmac_max_age_seconds: 600,
            static_tokens: Vec::new(),
            cluster_enabled: false,
        }
    }
}

/// Authentication gate for the v1 artifactcache routes.
///
/// The `/_apis/artifactcache/*` group has no handlers until plan task 18, and
/// axum's `route_layer` panics on an empty router, so the gate is applied as
/// a path-scoped layer instead: requests outside the prefix pass through
/// untouched, everything under it must authenticate.
pub async fn require_auth(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let path = request.uri().path();
    if !path.starts_with(ARTIFACTCACHE_PREFIX) || path.starts_with(ARTIFACT_DOWNLOAD_PREFIX) {
        return next.run(request).await;
    }
    let policy = state.auth();
    let authorized = match policy.mode {
        AuthMode::Hmac => hmac::verify(&policy, request.headers()),
        AuthMode::Bearer => bearer::verify(&policy, &state.tokens, request.headers()).await,
        AuthMode::Merge => {
            hmac::verify(&policy, request.headers())
                || bearer::verify(&policy, &state.tokens, request.headers()).await
        }
    };
    if authorized {
        next.run(request).await
    } else {
        ApiError::Unauthorized(String::from("authentication required")).into_response()
    }
}

/// Extract the token from an `Authorization: Bearer <token>` header.
/// The scheme is case-insensitive; empty tokens are rejected.
pub(crate) fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    let (scheme, token) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = token.trim();
    if token.is_empty() { None } else { Some(token) }
}

/// Constant-time byte comparison (no early exit on the first mismatch).
pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Current Unix time in seconds.
pub(crate) fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_secs() as i64
}

/// The auth module is exercised end-to-end by `tests/auth.rs`; keep the
/// policy snapshot honest here with a tiny unit check.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_eq_matches_and_mismatches() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
    }

    #[test]
    fn bearer_token_parses_case_insensitively() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            "Bearer abc-123".parse().unwrap(),
        );
        assert_eq!(bearer_token(&headers), Some("abc-123"));
        headers.insert(
            axum::http::header::AUTHORIZATION,
            "bearer abc-123".parse().unwrap(),
        );
        assert_eq!(bearer_token(&headers), Some("abc-123"));
        headers.insert(
            axum::http::header::AUTHORIZATION,
            "Bearer   ".parse().unwrap(),
        );
        assert_eq!(bearer_token(&headers), None);
        headers.insert(
            axum::http::header::AUTHORIZATION,
            "Basic abc".parse().unwrap(),
        );
        assert_eq!(bearer_token(&headers), None);
    }
}
