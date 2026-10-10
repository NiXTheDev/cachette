//! The single error type for every HTTP handler (plan task 3).
//!
//! Two wire shapes:
//! - v1 / plain routes: `{"error":"<msg>"}`
//! - `/twirp/*` paths:  `{"code":"<code>","msg":"<msg>"}` (Twirp JSON envelope)

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

/// API error mapped to an HTTP status and a protocol-appropriate JSON body.
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("not found")]
    NotFound,
    #[error("method not allowed")]
    MethodNotAllowed,
    #[error("{0}")]
    BadRequest(String),
    #[error("{0}")]
    Unauthorized(String),
    #[error("{0}")]
    Forbidden(String),
    #[error("{0}")]
    Conflict(String),
    #[error("{0}")]
    Unavailable(String),
    #[error("internal error")]
    Internal,
}

impl ApiError {
    /// Canonical constructor for the 404 JSON fallback and missing routes.
    pub fn not_found() -> Self {
        Self::NotFound
    }

    /// HTTP status for this error.
    #[must_use]
    pub fn status(&self) -> StatusCode {
        match self {
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::MethodNotAllowed => StatusCode::METHOD_NOT_ALLOWED,
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            Self::Forbidden(_) => StatusCode::FORBIDDEN,
            Self::Conflict(_) => StatusCode::CONFLICT,
            Self::Unavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            Self::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Twirp status code (used in the `/twirp/*` error envelope).
    fn twirp_code(&self) -> &'static str {
        match self {
            Self::NotFound => "not_found",
            Self::MethodNotAllowed => "bad_route",
            Self::BadRequest(_) => "invalid_argument",
            Self::Unauthorized(_) => "unauthenticated",
            Self::Forbidden(_) => "permission_denied",
            Self::Conflict(_) => "already_exists",
            Self::Unavailable(_) => "unavailable",
            Self::Internal => "internal",
        }
    }

    /// Twirp JSON error envelope: `{"code":"<code>","msg":"<msg>"}`.
    pub fn into_twirp_response(self) -> Response {
        let status = self.status();
        let body = json!({"code": self.twirp_code(), "msg": self.to_string()});
        (status, Json(body)).into_response()
    }
}

/// Plain/v1 JSON error body: `{"error":"<msg>"}`.
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status();
        let body = json!({"error": self.to_string()});
        (status, Json(body)).into_response()
    }
}
