//! Bearer-token authentication (plan task 15).
//!
//! Accepts `Authorization: Bearer <token>` when the token is in the static
//! `[auth] tokens` list or currently registered in the dynamic `TokenStore`.
//! Comparison is constant-time; a database failure fails closed.

use axum::http::HeaderMap;

use crate::auth::AuthPolicy;
use crate::auth::TokenStore;
use crate::auth::constant_time_eq;

/// Verify the request's bearer token against static and dynamic tokens.
pub async fn verify(policy: &AuthPolicy, tokens: &TokenStore, headers: &HeaderMap) -> bool {
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
    tokens.is_valid(token).await.unwrap_or(false)
}
