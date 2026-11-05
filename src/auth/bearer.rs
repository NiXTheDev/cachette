//! Bearer-token authentication (plan task 15).
//!
//! Accepts `Authorization: Bearer <token>` when the token is in the static
//! `[auth] tokens` list, currently registered in the dynamic `TokenStore`,
//! a self-minted HS256 JWT whose signature verifies against `[auth].secret`
//! (the `cachette token mint buildx-jwt` shape — the server holds the key it
//! was signed with, so no registration is needed), or — v1.1, when an OIDC
//! verifier was installed at boot — a conformant RS256 JWT from a configured
//! IdP. Acceptance order: static, TokenStore, self-minted JWT, OIDC; the
//! first hit authorizes. Comparison is constant-time; a database failure
//! fails closed.

use std::sync::Arc;

use axum::http::HeaderMap;

use crate::auth::jwt::{JwtError, validate};
use crate::auth::oidc::{OidcError, OidcVerifier};
use crate::auth::{AuthPolicy, TokenStore, constant_time_eq, now_secs};

/// Verify the request's bearer token against static tokens, the dynamic
/// store, the self-minted JWT key, and (when installed) the OIDC verifier.
///
/// `oidc` is the boot-installed verifier (docs/oidc.md); `None` keeps the
/// v1.0 acceptance paths minus the JWT step — a JWT-looking token is then
/// just an unknown bearer and fails silently.
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
    // Self-minted JWT (v1.0 shape, now verified in the bearer gate): the
    // mint CLI signs with `[auth].secret`, the server holds that key, so
    // the signature alone authorizes — no listing in `[auth] tokens`. Kept
    // ahead of the OIDC step so our own tokens never reach its errors (an
    // HS256 token is always rejected there, `alg` pin). A failure here only
    // falls through; it can never reject a token that the OIDC verifier
    // would accept (`UnsupportedAlg` is RS256 territory).
    if let Some(secret) = policy.secret.as_deref() {
        match validate(token, secret, now_secs()) {
            Ok(_) => return true,
            // Well-formed but signed by an unknown key: one warn line, same
            // reasoning as the OIDC gate's bad signature. `header.alg` said
            // HS256, so the OIDC verifier (RS256 pin) would reject it too —
            // this line names the live failure, no token material echoed.
            Err(JwtError::BadSignature) => {
                tracing::warn!("bearer token rejected: jwt signed with a foreign key");
            }
            // Structural garbage is everyday scanner noise; expiry drift is
            // a client clock. Both are debug lines.
            Err(err) => {
                tracing::debug!(stage = %err, "bearer token not accepted as a jwt");
            }
        }
    }
    // OIDC acceptance path (v1.1): a token matched by neither the static
    // list, the store, nor the signing key is attempted as an RS256 JWT.
    // The verifier never echoes token material; each rejection is one line
    // naming the stage.
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
