//! v1.3 config shape and load-time normalization of legacy v1.2 documents.
//! The new sections drive runtime behavior; legacy tables stay accepted and
//! authoritative only where a v1.3 block was not supplied.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::config::min_free::MinFree;

/// Storage instance kind. Unknown values are rejected at parse time so a typo
/// cannot silently fall back to a local root; see `capabilities_for` for what
/// each implemented kind supports.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum StorageKind {
    #[default]
    Fs,
    S3,
    WebDav,
    CopyParty,
    Azure,
    Ftp,
    Sftp,
}

/// One `[[storage]]` instance.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct StorageInstanceConfig {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: StorageKind,
    pub path: PathBuf,
    /// Overrides the server-level `min_free` when set.
    pub min_free: Option<MinFree>,
    /// S3 bucket/region/endpoint. Ignored for `fs`.
    pub bucket: Option<String>,
    pub region: Option<String>,
    pub endpoint: Option<String>,
    /// Remote mount URL for `fs` instances backed by SMB/NFS/WebDAV.
    /// The OS mounts it; cachette sees a local filesystem path.
    pub mount_url: Option<String>,
    /// Direct WebDAV endpoint URL for `type = "webdav"` instances.
    pub url: Option<String>,
    /// WebDAV / copyparty credentials (optional; public endpoints need none).
    pub username: Option<String>,
    pub password_file: Option<PathBuf>,
    /// Key prefix in an S3 bucket, or path prefix for other remote stores.
    pub prefix: Option<String>,
    /// TLS trust bundle for https remote endpoints. Required for https.
    pub ca_pem: Option<PathBuf>,
    /// S3 credentials (env wins). Azure account key fallback.
    pub access_key: Option<String>,
    pub secret_key: Option<String>,
    /// Copyparty file-ID salt (server `--wsalt`).
    pub wsalt: Option<String>,
    /// Azure storage account and container.
    pub account: Option<String>,
    pub container: Option<String>,
    /// SSH private key for `type = "sftp"` (agent/key auth; no password auth).
    pub private_key_file: Option<PathBuf>,
    /// OpenSSH known_hosts file pinning the SFTP server host key. Without it
    /// the native client trusts any host key (TOFU); the system `sftp`
    /// fallback always uses its own known_hosts.
    pub known_hosts_file: Option<PathBuf>,
    /// Per-instance CDC override. `true`/`false` overrides the global
    /// `[storage.cdc] enabled`; `avg_chunk_bytes` overrides the global target.
    pub cdc: Option<bool>,
    pub avg_chunk_bytes: Option<u64>,
}

impl Default for StorageInstanceConfig {
    fn default() -> Self {
        Self {
            name: String::from("default"),
            kind: StorageKind::Fs,
            path: PathBuf::from("/var/lib/cachette"),
            min_free: None,
            bucket: None,
            region: None,
            endpoint: None,
            mount_url: None,
            url: None,
            username: None,
            password_file: None,
            prefix: None,
            ca_pem: None,
            access_key: None,
            secret_key: None,
            wsalt: None,
            account: None,
            container: None,
            private_key_file: None,
            known_hosts_file: None,
            cdc: None,
            avg_chunk_bytes: None,
        }
    }
}

/// Which resource a `[[quota]]` rule caps.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum QuotaScope {
    Instance,
    #[default]
    Namespace,
}

/// One `[[quota]]` rule.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct QuotaRuleConfig {
    pub scope: QuotaScope,
    pub target: String,
    /// Byte-size string (1024-based denominations), parsed by later slices.
    pub limit: String,
}

impl Default for QuotaRuleConfig {
    fn default() -> Self {
        Self {
            scope: QuotaScope::Namespace,
            target: String::from("*"),
            limit: String::new(),
        }
    }
}

/// One `[auth.<forge>]` block: every credential plane for that forge.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ForgeAuthConfig {
    pub hmac_secret: Option<String>,
    pub runtime_secret: Option<PathBuf>,
    pub runtime_tenant_claim: Option<String>,
    pub oidc_issuer: Option<String>,
    pub oidc_audiences: Option<Vec<String>>,
    pub oidc_jwks_url: Option<String>,
    pub oidc_tenant_claim: Option<String>,
    pub oidc_require: Option<BTreeMap<String, String>>,
    pub oidc_leeway_seconds: Option<u64>,
}

fn table_mut<'a>(map: &'a mut Map<String, Value>, key: &str) -> &'a mut Map<String, Value> {
    let entry = map
        .entry(key.to_owned())
        .or_insert_with(|| Value::Object(Map::new()));
    if !entry.is_object() {
        *entry = Value::Object(Map::new());
    }
    entry.as_object_mut().expect("just made an object")
}

fn copy_keys(from: &Map<String, Value>, to: &mut Map<String, Value>) {
    for (key, value) in from {
        to.entry(key.clone()).or_insert_with(|| value.clone());
    }
}

/// Suggest a label for an OIDC issuer: its URL host, or the whole issuer if
/// there is no host. The admin can always rename the block in the config file.
fn issuer_label(issuer: &str) -> String {
    issuer
        .split_once("://")
        .and_then(|(_, rest)| rest.split('/').next())
        .filter(|host| !host.is_empty())
        .unwrap_or(issuer)
        .to_owned()
}

/// Normalize a legacy v1.2 document into the v1.3 shape **without removing
/// anything**. The old fields keep driving runtime behavior; the new fields
/// are populated so later slices can switch over without another migration.
pub(crate) fn normalize(doc: &mut Map<String, Value>) {
    // Copy, never remove: the legacy sections still drive runtime behavior.
    if let Some(cache) = doc.get("cache").and_then(Value::as_object).cloned() {
        copy_keys(&cache, table_mut(doc, "server"));
    }
    if let Some(log) = doc.get("log").and_then(Value::as_object).cloned() {
        let server = table_mut(doc, "server");
        for key in ["level", "format"] {
            if let Some(value) = log.get(key) {
                server
                    .entry(key.to_owned())
                    .or_insert_with(|| value.clone());
            }
        }
    }
    if let Some(v1) = doc.get("v1").and_then(Value::as_object).cloned() {
        copy_keys(&v1, table_mut(doc, "auth"));
    }
    if let Some(v2) = doc.get("v2").and_then(Value::as_object).cloned() {
        copy_keys(&v2, table_mut(doc, "auth"));
    }

    // [storage.quotas] -> [[quota]] (default becomes the "*" catch-all).
    // Copy: the legacy quota table still drives eviction for now.
    let legacy_quotas = doc
        .get("storage")
        .and_then(Value::as_object)
        .and_then(|s| s.get("quotas"))
        .and_then(Value::as_object)
        .cloned();
    if let Some(quotas) = legacy_quotas {
        let rules: Vec<Value> = quotas
            .into_iter()
            .map(|(key, limit)| {
                let target = if key == "default" { "*" } else { &key };
                serde_json::json!({
                    "scope": "namespace",
                    "target": target,
                    "limit": limit,
                })
            })
            .collect();
        doc.entry("quota".to_owned())
            .or_insert_with(|| Value::Array(rules));
    }

    // OIDC issuers and runtime forges -> [auth.forge.<label>]. Copies only:
    // the legacy planes stay installed so behavior is unchanged.
    if let Some(auth) = doc.get_mut("auth").and_then(Value::as_object_mut) {
        let oidc = auth.get("oidc").and_then(Value::as_object).cloned();
        let runtime = auth.get("runtime").and_then(Value::as_object).cloned();

        // Global knobs -> oidc_* on [auth] (copy, legacy table stays).
        if let Some(oidc) = &oidc {
            for key in ["jwks_refresh_seconds", "jwks_max_keys", "jwks_ca_pem"] {
                if let Some(value) = oidc.get(key) {
                    auth.entry(format!("oidc_{key}"))
                        .or_insert_with(|| value.clone());
                }
            }
        }

        if let Some(oidc) = oidc {
            let forges = table_mut(auth, "forge");
            for issuer in oidc.values().filter_map(Value::as_object) {
                let Some(issuer_url) = issuer.get("issuer").and_then(Value::as_str) else {
                    continue;
                };
                let label = issuer_label(issuer_url);
                let block = table_mut(forges, &label);
                block.insert(
                    "oidc_issuer".to_owned(),
                    Value::String(issuer_url.to_owned()),
                );
                for (from, to) in [
                    ("audiences", "oidc_audiences"),
                    ("jwks_url", "oidc_jwks_url"),
                    ("tenant_claim", "oidc_tenant_claim"),
                    ("require", "oidc_require"),
                    ("leeway_seconds", "oidc_leeway_seconds"),
                ] {
                    if let Some(value) = issuer.get(from) {
                        block.entry(to.to_owned()).or_insert_with(|| value.clone());
                    }
                }
            }
        }
        if let Some(runtime) = runtime {
            let forges = table_mut(auth, "forge");
            for (label, value) in runtime {
                let Some(block) = value.as_object() else {
                    continue;
                };
                let target = table_mut(forges, &label);
                for (from, to) in [
                    ("secret", "runtime_secret"),
                    ("tenant_claim", "runtime_tenant_claim"),
                ] {
                    if let Some(value) = block.get(from) {
                        target.entry(to.to_owned()).or_insert_with(|| value.clone());
                    }
                }
            }
        }
    }

    // Legacy [storage.fs] -> a `default` instance, and state path derivation.
    if let Some(storage) = doc.get("storage").and_then(Value::as_object) {
        let has_instances = storage
            .get("instances")
            .and_then(Value::as_array)
            .is_some_and(|a| !a.is_empty());
        if !has_instances {
            let fs = storage.get("fs").and_then(Value::as_object);
            let path = fs
                .and_then(|f| f.get("path"))
                .cloned()
                .unwrap_or_else(|| Value::String(String::from("/var/lib/cachette")));
            let mut instance = serde_json::json!({
                "name": "default",
                "type": "fs",
                "path": path,
            });
            if let Some(min_free) = fs.and_then(|f| f.get("min_free")) {
                instance
                    .as_object_mut()
                    .expect("object")
                    .insert("min_free".to_owned(), min_free.clone());
            }
            let instances = doc
                .get_mut("storage")
                .and_then(Value::as_object_mut)
                .map(|s| {
                    s.entry("instances".to_owned())
                        .or_insert_with(|| Value::Array(Vec::new()))
                })
                .and_then(Value::as_array_mut);
            if let Some(instances) = instances
                && instances.is_empty()
            {
                instances.push(instance);
            }
            if let Some(server) = doc.get_mut("server").and_then(Value::as_object_mut) {
                server.entry("data_path".to_owned()).or_insert(path);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn normalize_text(text: &str) -> Map<String, Value> {
        let table: toml::Table = toml::from_str(text).expect("valid toml");
        let mut doc = serde_json::to_value(table)
            .expect("json")
            .as_object()
            .unwrap()
            .clone();
        normalize(&mut doc);
        doc
    }

    #[test]
    fn legacy_config_gets_new_fields_without_losing_old_ones() {
        let doc = normalize_text(
            r#"
            [server]
            listen = "127.0.0.1:9999"
            [cache]
            max_size = 1234
            [log]
            level = "debug"
            [v1]
            signed_url_ttl_seconds = 42
            [v2]
            jwt_ttl_seconds = 99
            [storage.fs]
            path = "/tmp/cachette-legacy"
            [storage.quotas]
            default = "1GiB"
            "#,
        );
        let server = doc["server"].as_object().unwrap();
        assert_eq!(server["max_size"], 1234);
        assert_eq!(server["level"], "debug");
        assert_eq!(server["data_path"], "/tmp/cachette-legacy");
        assert_eq!(doc["auth"]["signed_url_ttl_seconds"], 42);
        assert_eq!(doc["auth"]["jwt_ttl_seconds"], 99);
        assert!(doc["cache"].as_object().unwrap()["max_size"] == 1234);
        assert_eq!(doc["quota"][0]["target"], "*");
        assert_eq!(doc["quota"][0]["limit"], "1GiB");
        let instances = doc["storage"]["instances"].as_array().unwrap();
        assert_eq!(instances.len(), 1);
        assert_eq!(instances[0]["name"], "default");
        assert_eq!(instances[0]["path"], "/tmp/cachette-legacy");
    }

    #[test]
    fn explicit_instances_are_preserved() {
        let doc = normalize_text(
            r#"
            [[storage.instances]]
            name = "scratch"
            type = "fs"
            path = "/cache"
            "#,
        );
        let instances = doc["storage"]["instances"].as_array().unwrap();
        assert_eq!(instances.len(), 1);
        assert_eq!(instances[0]["name"], "scratch");
    }

    #[test]
    fn issuer_label_uses_host() {
        assert_eq!(
            issuer_label("https://idp.example.org/realms/ci"),
            "idp.example.org"
        );
        assert_eq!(issuer_label("not a url"), "not a url");
    }
}
