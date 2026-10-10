//! `GET /health` — liveness + node identity probe (plan task 3).

use axum::Json;
use axum::extract::State;
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
