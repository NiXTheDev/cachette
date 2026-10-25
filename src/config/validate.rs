//! Post-parse validation (plan task 5): structural checks that serde types
//! cannot express. Closed sets (eviction, key_case, tiebreak, mode, backend,
//! log level/format) are enforced by their serde enums at parse time.

use crate::config::Config;
use crate::config::error::ConfigError;

/// Split `host:port` (IPv6 literals bracketed: `[::1]:8080`).
pub(crate) fn split_host_port(raw: &str) -> Option<(&str, u16)> {
    let (host, port) = raw.rsplit_once(':')?;
    if host.is_empty() || host.contains(char::is_whitespace) {
        return None;
    }
    if host.contains(':') && !(host.starts_with('[') && host.ends_with(']')) {
        return None;
    }
    port.parse::<u16>().ok().map(|number| (host, number))
}

pub(crate) fn validate(config: &Config) -> Result<(), ConfigError> {
    validate_listen(&config.server.listen)?;
    validate_listen(&config.cluster.listen)?;
    validate_tls_pair(config)?;
    if config.storage.fs.path.as_os_str().is_empty() {
        return Err(ConfigError::EmptyStoragePath);
    }
    if config.cache.reservation_ttl_seconds == 0 {
        return Err(ConfigError::ZeroReservationTtl);
    }
    if config.server.max_chunk_bytes == 0 {
        return Err(ConfigError::ZeroMaxChunkBytes);
    }
    if let Some(cert_path) = config.cluster.cert_path.as_ref()
        && *cert_path == config.storage.fs.path
    {
        return Err(ConfigError::CertPathCollides);
    }
    validate_oidc(config)?;
    Ok(())
}

/// `[auth.oidc]` wiring rules (v1.1; docs/oidc.md §Config surface):
/// `enabled` implies the issuer/audience lists, the CA bundle, a positive
/// refresh interval and key cap; `jwks_urls` may only name configured
/// issuers with `https` endpoints. A disabled/absent table is always fine.
fn validate_oidc(config: &Config) -> Result<(), ConfigError> {
    let Some(oidc) = config.auth.oidc.as_ref() else {
        return Ok(());
    };
    if !oidc.enabled {
        return Ok(());
    }
    if oidc.issuers.is_empty() {
        return Err(ConfigError::OidcMissingRequired {
            field: "auth.oidc.issuers",
        });
    }
    if oidc.audiences.is_empty() {
        return Err(ConfigError::OidcMissingRequired {
            field: "auth.oidc.audiences",
        });
    }
    if oidc.jwks_ca_pem.is_none() {
        return Err(ConfigError::OidcMissingRequired {
            field: "auth.oidc.jwks_ca_pem",
        });
    }
    if oidc.jwks_refresh_seconds == 0 {
        return Err(ConfigError::OidcZeroRefresh);
    }
    if oidc.jwks_max_keys == 0 {
        return Err(ConfigError::OidcZeroMaxKeys);
    }
    for (issuer, url) in &oidc.jwks_urls {
        if !oidc.issuers.contains(issuer) {
            return Err(ConfigError::OidcJwksIssuerUnknown {
                issuer: issuer.clone(),
            });
        }
        let scheme = url::Url::parse(url).is_ok_and(|u| u.scheme() == "https");
        if !scheme {
            return Err(ConfigError::OidcJwksPlaintext {
                issuer: issuer.clone(),
                url: url.clone(),
            });
        }
    }
    Ok(())
}

fn validate_listen(listen: &str) -> Result<(), ConfigError> {
    if split_host_port(listen).is_some() {
        return Ok(());
    }
    Err(ConfigError::Listen {
        value: listen.to_owned(),
        msg: String::from("expected host:port, e.g. 0.0.0.0:8080 or cache-a:8080"),
    })
}

fn validate_tls_pair(config: &Config) -> Result<(), ConfigError> {
    match (
        config.server.tls_cert.as_ref(),
        config.server.tls_key.as_ref(),
    ) {
        (Some(_), None) => Err(ConfigError::TlsPair {
            set_key: "server.tls_cert",
            missing_key: "server.tls_key",
        }),
        (None, Some(_)) => Err(ConfigError::TlsPair {
            set_key: "server.tls_key",
            missing_key: "server.tls_cert",
        }),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::config::OidcConfig;

    /// A `Config` with `[auth.oidc]` built from the default surface.
    fn oidc_config(fields: impl FnOnce(&mut OidcConfig)) -> Config {
        let mut config = Config::default();
        let mut oidc = OidcConfig::default();
        fields(&mut oidc);
        config.auth.oidc = Some(oidc);
        config
    }

    /// Realistic enabled surface (overridable per test).
    fn enabled_oidc() -> Config {
        oidc_config(|oidc| {
            oidc.enabled = true;
            oidc.issuers = vec![String::from("https://idp.example.org/realms/ci")];
            oidc.audiences = vec![String::from("cachette")];
            oidc.jwks_ca_pem = Some(PathBuf::from("/etc/cachette/idp-ca.pem"));
        })
    }

    #[test]
    fn split_host_port_accepts_valid_addresses() {
        assert_eq!(split_host_port("127.0.0.1:8080"), Some(("127.0.0.1", 8080)));
        assert_eq!(split_host_port("0.0.0.0:8080"), Some(("0.0.0.0", 8080)));
        assert_eq!(split_host_port("cache-a:8080"), Some(("cache-a", 8080)));
        assert_eq!(split_host_port("[::1]:8080"), Some(("[::1]", 8080)));
        assert_eq!(split_host_port("[::]:8080"), Some(("[::]", 8080)));
    }

    #[test]
    fn split_host_port_rejects_malformed_addresses() {
        let malformed = [
            "127.0.0.1",
            "127.0.0.1:",
            ":8080",
            "host:99999",
            "host:abc",
            "host:",
            "::1:8080",
            "fe80::1",
            "[::1]",
            "[::1]8080",
            "127.0.0.1 :8080",
            "host :8080",
        ];
        for raw in malformed {
            assert_eq!(split_host_port(raw), None, "{raw:?} should be rejected");
        }
    }

    #[test]
    fn validate_listen_accepts_host_port_and_names_bad_values() {
        assert!(validate_listen("127.0.0.1:8080").is_ok());
        assert!(validate_listen("0.0.0.0:8080").is_ok());
        assert!(validate_listen("[::1]:8080").is_ok());

        let err = validate_listen("nope").expect_err("rejects");
        match &err {
            ConfigError::Listen { value, msg } => {
                assert_eq!(value, "nope");
                assert!(msg.contains("host:port"), "{msg}");
            }
            other => panic!("expected Listen error, got {other:?}"),
        }
    }

    #[test]
    fn validate_accepts_default_config() {
        assert!(validate(&Config::default()).is_ok());
    }

    #[test]
    fn tls_pair_requires_both_cert_and_key() {
        let mut config = Config::default();
        config.server.tls_cert = Some(PathBuf::from("/etc/cachette/tls.crt"));
        let cert_only = validate(&config).expect_err("cert without key");
        assert!(
            matches!(
                cert_only,
                ConfigError::TlsPair {
                    set_key: "server.tls_cert",
                    missing_key: "server.tls_key",
                }
            ),
            "unexpected error: {cert_only:?}"
        );

        let mut config = Config::default();
        config.server.tls_key = Some(PathBuf::from("/etc/cachette/tls.key"));
        let key_only = validate(&config).expect_err("key without cert");
        assert!(
            matches!(
                key_only,
                ConfigError::TlsPair {
                    set_key: "server.tls_key",
                    missing_key: "server.tls_cert",
                }
            ),
            "unexpected error: {key_only:?}"
        );

        let mut config = Config::default();
        config.server.tls_cert = Some(PathBuf::from("/etc/cachette/tls.crt"));
        config.server.tls_key = Some(PathBuf::from("/etc/cachette/tls.key"));
        assert!(validate(&config).is_ok());
    }

    #[test]
    fn empty_storage_path_is_rejected() {
        let mut config = Config::default();
        config.storage.fs.path = PathBuf::new();
        let err = validate(&config).expect_err("empty path");
        assert!(
            matches!(err, ConfigError::EmptyStoragePath),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn zero_reservation_ttl_is_rejected() {
        let mut config = Config::default();
        config.cache.reservation_ttl_seconds = 0;
        let err = validate(&config).expect_err("zero ttl");
        assert!(
            matches!(err, ConfigError::ZeroReservationTtl),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn zero_max_chunk_bytes_is_rejected() {
        let mut config = Config::default();
        config.server.max_chunk_bytes = 0;
        let err = validate(&config).expect_err("zero chunk cap");
        assert!(
            matches!(err, ConfigError::ZeroMaxChunkBytes),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn cert_path_colliding_with_storage_root_is_rejected() {
        let mut config = Config::default();
        let storage_root = PathBuf::from("/var/lib/cachette");
        config.storage.fs.path = storage_root.clone();
        config.cluster.cert_path = Some(storage_root);
        let err = validate(&config).expect_err("collision");
        assert!(
            matches!(err, ConfigError::CertPathCollides),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn disabled_or_absent_oidc_needs_nothing() {
        assert!(validate(&Config::default()).is_ok());
        assert!(
            validate(&oidc_config(|oidc| {
                oidc.enabled = false;
                oidc.issuers = vec![String::from("https://idp.example.org/realms/ci")];
            }))
            .is_ok()
        );
    }

    #[test]
    fn enabled_oidc_requires_issuers_audiences_and_ca_pem() {
        let err = validate(&oidc_config(|oidc| oidc.enabled = true)).expect_err("no lists, no pem");
        assert!(
            matches!(
                err,
                ConfigError::OidcMissingRequired {
                    field: "auth.oidc.issuers"
                }
            ),
            "unexpected error: {err:?}"
        );

        let err = validate(&oidc_config(|oidc| {
            oidc.enabled = true;
            oidc.issuers = vec![String::from("https://idp.example.org/realms/ci")];
        }))
        .expect_err("no audiences");
        assert!(
            matches!(
                err,
                ConfigError::OidcMissingRequired {
                    field: "auth.oidc.audiences"
                }
            ),
            "unexpected error: {err:?}"
        );

        let err = validate(&oidc_config(|oidc| {
            oidc.enabled = true;
            oidc.issuers = vec![String::from("https://idp.example.org/realms/ci")];
            oidc.audiences = vec![String::from("cachette")];
        }))
        .expect_err("no CA bundle");
        assert!(
            matches!(
                err,
                ConfigError::OidcMissingRequired {
                    field: "auth.oidc.jwks_ca_pem"
                }
            ),
            "unexpected error: {err:?}"
        );

        assert!(validate(&enabled_oidc()).is_ok());
    }

    #[test]
    fn zero_oidc_refresh_and_key_cap_are_rejected() {
        let surface = crate::config::OidcConfig {
            enabled: true,
            issuers: vec![String::from("https://idp.example.org/realms/ci")],
            audiences: vec![String::from("cachette")],
            jwks_ca_pem: Some(PathBuf::from("/etc/cachette/idp-ca.pem")),
            ..crate::config::OidcConfig::default()
        };
        let mut config = Config::default();

        config.auth.oidc = Some(crate::config::OidcConfig {
            jwks_refresh_seconds: 0,
            ..surface.clone()
        });
        let err = validate(&config).expect_err("zero refresh");
        assert!(
            matches!(err, ConfigError::OidcZeroRefresh),
            "unexpected error: {err:?}"
        );

        config.auth.oidc = Some(crate::config::OidcConfig {
            jwks_max_keys: 0,
            ..surface
        });
        let err = validate(&config).expect_err("zero key cap");
        assert!(
            matches!(err, ConfigError::OidcZeroMaxKeys),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn jwks_urls_must_target_configured_https_issuers() {
        fn enabled(base: impl FnOnce(&mut OidcConfig)) -> Config {
            oidc_config(|oidc| {
                oidc.enabled = true;
                oidc.issuers = vec![String::from("https://idp.example.org/realms/ci")];
                oidc.audiences = vec![String::from("cachette")];
                oidc.jwks_ca_pem = Some(PathBuf::from("/etc/cachette/idp-ca.pem"));
                base(oidc);
            })
        }

        let mut config = enabled(|oidc| {
            oidc.jwks_urls.insert(
                String::from("https://other.example.org"),
                String::from("https://other.example.org/jwks.json"),
            );
        });
        let err = validate(&config).expect_err("url for an unlisted issuer");
        match &err {
            ConfigError::OidcJwksIssuerUnknown { issuer } => {
                assert_eq!(issuer, "https://other.example.org");
            }
            other => panic!("expected OidcJwksIssuerUnknown, got {other:?}"),
        }

        config = enabled(|oidc| {
            oidc.jwks_urls.insert(
                String::from("https://idp.example.org/realms/ci"),
                String::from("http://idp.example.org/jwks.json"),
            );
        });
        let err = validate(&config).expect_err("plaintext url");
        assert!(
            matches!(err, ConfigError::OidcJwksPlaintext { .. }),
            "unexpected error: {err:?}"
        );

        config = enabled(|oidc| {
            oidc.jwks_urls.insert(
                String::from("https://idp.example.org/realms/ci"),
                String::from("https://idp.example.org/jwks.json"),
            );
        });
        assert!(validate(&config).is_ok());
    }
}
