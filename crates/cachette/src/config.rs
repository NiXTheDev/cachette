//! Configuration: TOML file + `CACHETTE__*` env overrides + validation
//! (plan task 5).
//!
//! Load order: `--config <path>` (default `cachette.toml` if present), then
//! environment variables (env wins). Unknown TOML keys and unknown
//! `CACHETTE__*` variables are hard errors. `auth.secret` is only required
//! to serve: `--print-config` succeeds without it (secrets render as `***`).

use std::path::PathBuf;

use serde::Serialize;
use serde_json::Value;

use crate::config::env::apply as apply_env;
use crate::config::validate::split_host_port;

mod env;
mod error;
mod min_free;
mod sections;
mod validate;

pub use error::ConfigError;
pub use min_free::MinFree;
pub use sections::*;

pub const DEFAULT_CONFIG_FILE: &str = "cachette.toml";

/// Fully resolved configuration: file, env, and derived defaults applied.
#[derive(Debug, Default, Serialize)]
pub struct Config {
    pub server: ServerConfig,
    pub storage: StorageConfig,
    pub cache: CacheConfig,
    pub auth: AuthConfig,
    pub v1: V1Config,
    pub v2: V2Config,
    pub cluster: ClusterConfig,
    pub log: LogConfig,
}

impl Config {
    /// Serve-time gate: `auth.secret` must be set and at least 16 chars.
    /// `--print-config` deliberately skips this check.
    pub fn require_auth_secret(&self) -> Result<(), ConfigError> {
        match self.auth.secret.as_deref() {
            None => Err(ConfigError::MissingSecret),
            Some(secret) if secret.len() < 16 => {
                Err(ConfigError::ShortSecret { len: secret.len() })
            }
            Some(_) => Ok(()),
        }
    }
}

/// Load the config file (`--config <path>`, else `cachette.toml` if present)
/// and overlay `CACHETTE__*` environment variables.
pub fn load(cli_config: Option<PathBuf>) -> Result<Config, ConfigError> {
    let explicit = cli_config.is_some();
    let path = cli_config.unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_FILE));
    let raw = if explicit || path.exists() {
        Some(
            std::fs::read_to_string(&path).map_err(|err| ConfigError::ReadFile {
                path: path.display().to_string(),
                msg: err.to_string(),
            })?,
        )
    } else {
        None
    };
    let vars: Vec<(String, String)> = std::env::vars().collect();
    let env: Vec<(&str, &str)> = vars
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();
    from_sources(raw.as_deref(), &env)
}

/// Pure loader core: TOML text + env pairs in, resolved `Config` out.
/// Injecting env pairs (instead of reading the process environment) keeps
/// the unit tests race-free.
pub(crate) fn from_sources(
    file: Option<&str>,
    env: &[(&str, &str)],
) -> Result<Config, ConfigError> {
    let mut doc = match file {
        None => Value::Object(serde_json::Map::new()),
        Some(text) => {
            let table: toml::Table =
                toml::from_str(text).map_err(|err| ConfigError::Toml(err.to_string()))?;
            serde_json::to_value(&table).map_err(|err| ConfigError::Toml(err.to_string()))?
        }
    };
    apply_env(&mut doc, env)?;
    let object = doc
        .as_object_mut()
        .ok_or_else(|| ConfigError::Toml(String::from("top level must be a table")))?;
    let config = Config {
        server: take(object, "server")?,
        storage: take(object, "storage")?,
        cache: take(object, "cache")?,
        auth: take(object, "auth")?,
        v1: take(object, "v1")?,
        v2: take(object, "v2")?,
        cluster: take(object, "cluster")?,
        log: take(object, "log")?,
    };
    if let Some(key) = object.keys().next() {
        return Err(ConfigError::UnknownKey(key.clone()));
    }
    validate::validate(&config)?;
    Ok(resolve(config))
}

/// Deserialize one section out of the merged document; a missing section is
/// `T::default()`, and serde errors are prefixed with the section name.
fn take<T>(
    doc: &mut serde_json::Map<String, Value>,
    section: &'static str,
) -> Result<T, ConfigError>
where
    T: Default + serde::de::DeserializeOwned,
{
    match doc.remove(section) {
        Some(value) => serde_json::from_value::<T>(value).map_err(|err| ConfigError::InSection {
            section: section.to_owned(),
            msg: err.to_string(),
        }),
        None => Ok(T::default()),
    }
}

/// Derive spec defaults that depend on other fields (m5/M6 + v2 fallback).
fn resolve(mut config: Config) -> Config {
    if config.server.external_url.is_none() {
        config.server.external_url = default_external_url(&config.server.listen);
    }
    if config.cluster.advertise_addr.is_none() {
        config.cluster.advertise_addr = Some(config.server.listen.clone());
    }
    if config.cluster.cert_path.is_none() {
        config.cluster.cert_path = Some(config.storage.fs.path.join("identity"));
    }
    if config.v2.jwt_secret.is_none() {
        config.v2.jwt_secret = config.auth.secret.clone();
    }
    config
}

/// `listen` -> runner-visible URL: wildcard hosts become loopback.
fn default_external_url(listen: &str) -> Option<String> {
    let (host, port) = split_host_port(listen)?;
    let host = match host {
        "0.0.0.0" => "127.0.0.1",
        "::" => "[::1]",
        other => other,
    };
    Some(format!("http://{host}:{port}"))
}

/// Render the resolved config as pretty JSON with secrets masked (`***`),
/// in deterministic key order (`serde_json` maps are `BTreeMap`s).
pub fn render_masked(config: &Config) -> Result<String, ConfigError> {
    let mut value =
        serde_json::to_value(config).map_err(|err| ConfigError::Internal(err.to_string()))?;
    if let Some(object) = value.as_object_mut() {
        if let Some(auth) = object.get_mut("auth").and_then(Value::as_object_mut) {
            if let Some(secret) = auth.get_mut("secret") {
                mask_string(secret);
            }
            if let Some(tokens) = auth.get_mut("tokens").and_then(Value::as_array_mut) {
                for token in tokens {
                    mask_string(token);
                }
            }
        }
        if let Some(v2) = object.get_mut("v2").and_then(Value::as_object_mut)
            && let Some(jwt_secret) = v2.get_mut("jwt_secret")
        {
            mask_string(jwt_secret);
        }
    }
    serde_json::to_string_pretty(&value).map_err(|err| ConfigError::Internal(err.to_string()))
}

fn mask_string(value: &mut Value) {
    if let Value::String(text) = value
        && !text.is_empty()
    {
        text.clear();
        text.push_str("***");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "0123456789abcdef";

    #[test]
    fn smoke_env_overrides_defaults_and_secrets_are_masked() {
        let file = format!("[auth]\nsecret = \"{SECRET}\"\n[cache]\nmax_size = 100\n");
        let env = [
            ("CACHETTE__SERVER__LISTEN", "127.0.0.1:9999"),
            ("CACHETTE__AUTH__TOKENS", "a, b"),
            ("CACHETTE__CLUSTER__SEED_FINGERPRINTS", "{\"p1\":\"aa\"}"),
        ];
        let config = from_sources(Some(&file), &env).expect("config resolves");
        assert_eq!(config.server.listen, "127.0.0.1:9999");
        assert_eq!(
            config.server.external_url.as_deref(),
            Some("http://127.0.0.1:9999")
        );
        assert_eq!(config.cache.max_size, 100);
        assert_eq!(config.cache.eviction, Eviction::Lru);
        assert_eq!(config.storage.fs.min_free, MinFree::Fraction(0.2));
        assert_eq!(config.storage.fs.path, PathBuf::from("/var/lib/cachette"));
        assert_eq!(
            config.cluster.advertise_addr.as_deref(),
            Some("127.0.0.1:9999")
        );
        assert_eq!(
            config.cluster.cert_path.as_deref(),
            Some(std::path::Path::new("/var/lib/cachette/identity"))
        );
        assert_eq!(config.auth.tokens, vec!["a".to_owned(), "b".to_owned()]);
        assert_eq!(
            config
                .cluster
                .seed_fingerprints
                .get("p1")
                .map(String::as_str),
            Some("aa")
        );
        assert_eq!(config.v2.jwt_secret.as_deref(), Some(SECRET));
        config.require_auth_secret().expect("secret serves");
        let rendered = render_masked(&config).expect("renders");
        assert!(!rendered.contains(SECRET));
        assert!(rendered.contains("\"secret\": \"***\""));
        assert!(rendered.contains("\"jwt_secret\": \"***\""));
        assert!(rendered.contains("\"***\""));
    }

    #[test]
    fn smoke_rejects_unknown_key_names_it_and_short_secret_fails_serving() {
        let unknown =
            from_sources(Some("[server]\nlisten2 = \"x:1\"\n"), &[]).expect_err("unknown key");
        assert!(unknown.to_string().contains("listen2"));
        let unknown_env =
            from_sources(None, &[("CACHETTE__NOPE__X", "1")]).expect_err("unknown env");
        assert!(unknown_env.to_string().contains("CACHETTE__NOPE__X"));
        let short = from_sources(Some("[auth]\nsecret = \"short\"\n"), &[]).expect("parses");
        assert!(short.require_auth_secret().is_err());
    }

    #[test]
    fn smoke_min_free_forms_are_1024_based_and_resolved() {
        assert_eq!(
            MinFree::parse_str("2GiB").ok(),
            Some(MinFree::Bytes(2 * 1024 * 1024 * 1024))
        );
        assert_eq!(
            MinFree::parse_str("2GB").ok(),
            Some(MinFree::Bytes(2 * 1024 * 1024 * 1024))
        );
        assert_eq!(
            MinFree::parse_str("20%").unwrap().resolve(1_000_000),
            200_000
        );
        let bare = MinFree::parse_str("abc")
            .expect_err("rejects bare word")
            .to_string();
        assert!(bare.contains("min_free"));
        assert!(bare.contains("abc"));
    }
}
