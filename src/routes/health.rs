//! `GET /health` — liveness + node identity probe (plan task 3).
//!
//! `GET /healthz` is the same liveness probe under the conventional name, and
//! `GET /readyz` is the readiness probe (plan task 47): it reports
//! `503 draining` while the node is shutting down and `503 starting` before
//! storage is attached, so a load balancer / peer stops routing NEW work here.

use std::sync::atomic::Ordering;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};

use crate::state::AppState;

/// Health body: `{"version":"<semver>","node_id":"<id>"}`.
///
/// `Serialize` is implemented by hand (serde's `derive` feature is not part
/// of this crate's pinned dep set) so the field order — `version` then
/// `node_id` — is guaranteed; `serde_json::json!` would sort keys instead.
pub struct HealthBody {
    version: &'static str,
    node_id: String,
}

impl Serialize for HealthBody {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("HealthBody", 2)?;
        state.serialize_field("version", self.version)?;
        state.serialize_field("node_id", &self.node_id)?;
        state.end()
    }
}

/// `GET /health` → 200 with the crate version and the placeholder node id.
pub async fn health(State(state): State<AppState>) -> Json<HealthBody> {
    Json(HealthBody {
        version: state.version,
        node_id: state.node_id,
    })
}

/// Readiness body: `{"status":"ready" | "draining" | "starting"}`.
///
/// Hand-serialized, like [`HealthBody`], so the field order is guaranteed.
pub struct ReadyBody {
    status: &'static str,
}

impl Serialize for ReadyBody {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("ReadyBody", 1)?;
        state.serialize_field("status", self.status)?;
        state.end()
    }
}

/// `GET /readyz` → 200 `ready` when serving, else 503.
///
/// Draining (plan task 47) reports `draining`; a node without storage yet
/// reports `starting`. The readiness flag is advertised to peers via heartbeat
/// and read here, so a load balancer and the cluster agree on eligibility.
pub async fn readyz(State(state): State<AppState>) -> Response {
    let (code, status) = if state.draining.load(Ordering::Relaxed) {
        (StatusCode::SERVICE_UNAVAILABLE, "draining")
    } else if state.storage.is_none() {
        (StatusCode::SERVICE_UNAVAILABLE, "starting")
    } else {
        (StatusCode::OK, "ready")
    };
    (code, Json(ReadyBody { status })).into_response()
}

#[cfg(test)]
mod tests {
    use super::HealthBody;

    #[test]
    fn health_body_serializes_version_first_then_node_id() {
        let body = HealthBody {
            version: "0.1.0",
            node_id: "test-host".to_owned(),
        };
        let json = serde_json::to_string(&body).expect("HealthBody serializes");
        assert_eq!(json, r#"{"version":"0.1.0","node_id":"test-host"}"#);
    }
}
