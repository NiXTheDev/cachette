//! Bearer-token authentication (plan task 15).
//!
//! Accepts `Authorization: Bearer <token>` when the token is in the static
//! `[auth] tokens` list, currently registered in the dynamic `TokenStore`,
//! or — v1.1, when an OIDC verifier was installed at boot — a conformant
//! RS256 JWT from a configured IdP. Acceptance order: static, TokenStore,
//! OIDC; the first hit authorizes. Comparison is constant-time; a database
//! failure fails closed.

use std::sync::Arc;

use axum::http::HeaderMap;

use crate::auth::oidc::{OidcError, OidcVerifier};
use crate::auth::{AuthPolicy, TokenStore, constant_time_eq, now_secs};

/// Verify the request's bearer token against static tokens, the dynamic
/// store, and (when installed) the OIDC verifier.
///
/// `oidc` is the boot-installed verifier (docs/oidc.md); `None` keeps v1.0
/// behavior byte-identical — a JWT-looking token is then just an unknown
/// bearer and fails silently.
pub async fn verify(
    policy: &AuthPolicy,
    tokens: &TokenStore,
    oidc: Option<&Arc<OidcVerifier>>,
    headers: &HeaderMap,
) -> bool {
    let Some(token) = crate::auth::bearer_token(headers) else {
        return false;
    };
    if policy
        .static_tokens
        .iter()
        .any(|candidate| constant_time_eq(candidate.as_bytes(), token.as_bytes()))
    {
        return true;
    }
    if tokens.is_valid(token).await.unwrap_or(false) {
        return true;
    }
    // OIDC acceptance path (v1.1): a token matched by neither the static
    // list nor the store is attempted as an RS256 JWT. The verifier never
    // echoes token material; each rejection is one line naming the stage.
    let Some(oidc) = oidc else {
        return false;
    };
    match oidc.verify(token, now_secs()) {
        Ok(()) => true,
        // Structural garbage (not a JWT at all) is everyday scanner noise:
        // a debug line. Anything well-formed but untrustable — a bad
        // signature, an unconfigured issuer/audience — is worth a warn:
        // both are single lines and neither carries token material.
        Err(OidcError::Malformed) => {
            tracing::debug!("bearer token rejected by the oidc verifier: malformed token");
            false
        }
        Err(stage) => {
            tracing::warn!(stage = %stage, "bearer token rejected by the oidc verifier");
            false
        }
    }
}
