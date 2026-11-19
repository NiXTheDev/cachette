//! Post-parse validation (plan task 5): structural checks that serde types
//! cannot express. Closed sets (eviction, key_case, tiebreak, mode, backend,
//! log level/format) are enforced by their serde enums at parse time.

use std::collections::BTreeMap;

use crate::config::error::ConfigError;
use crate::config::{AuthMode, Config};

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
    // `[storage.cdc] avg_chunk_bytes` outside the chunker window — checked
    // regardless of `enabled` (docs/cdc.md §Config surface): a bad value
    // must not hide until the flag one day flips on.
    let cdc = config.storage.cdc;
    if cdc.avg_chunk_bytes < crate::storage::cdc::MIN_AVG_CHUNK_BYTES
        || cdc.avg_chunk_bytes > crate::storage::cdc::MAX_AVG_CHUNK_BYTES
    {
        return Err(ConfigError::CdcAvgRange {
            value: cdc.avg_chunk_bytes,
        });
    }
    // `[storage.cdc] backfill_delay_ms` of zero would hot-spin the walker -
    // checked regardless of `enabled` and `backfill`, same hide-nothing
    // policy as the avg window above.
    if cdc.backfill_delay_ms == 0 {
        return Err(ConfigError::ZeroCdcBackfillDelay);
    }
    if let Some(cert_path) = config.cluster.cert_path.as_ref()
        && *cert_path == config.storage.fs.path
    {
        return Err(ConfigError::CertPathCollides);
    }
    validate_namespaces(&config.storage.namespaces)?;
    validate_oidc(config)?;
    validate_tenancy(config)?;
    Ok(())
}

/// `[storage.namespaces]` mapping keys are credential identities
/// (`docs/shared-cache.md` §7): `"<forge>|<tenant>"`, both halves present.
/// The tenant half is dynamic (only the admin knows which repos exist), so
/// this is a shape check - a mistyped tenant simply keeps its own default
/// namespace rather than joining the intended shared one.
fn validate_namespaces(namespaces: &BTreeMap<String, String>) -> Result<(), ConfigError> {
    for key in namespaces.keys() {
        let well_formed = key
            .split_once('|')
            .is_some_and(|(forge, tenant)| !forge.trim().is_empty() && !tenant.trim().is_empty());
        if !well_formed {
            return Err(ConfigError::NamespaceMappingKey { key: key.clone() });
        }
    }
    Ok(())
}

/// `[auth.oidc]` wiring rules (v1.2 shape; docs/oidc.md §Config surface):
/// the parent table carries the global knobs, every issuer is its own block
/// (`[auth.oidc."<issuer>"]`) with its own audiences, pins, roots and clock
/// skew. `enabled` implies at least one issuer block, a positive refresh
/// interval and key cap, and usable trust roots for every issuer. The v1.1
/// flat shape is rejected with a precise error. A disabled/absent table is
/// always fine.
fn validate_oidc(config: &Config) -> Result<(), ConfigError> {
    let Some(oidc) = config.auth.oidc.as_ref() else {
        return Ok(());
    };
    if !oidc.enabled {
        return Ok(());
    }
    // The v1.1 flat shape is a configuration error, not a silent fallback:
    // name the key that carries it and the shape that replaced it.
    for (key, present) in [
        ("issuers", oidc.legacy_issuers.is_some()),
        ("audiences", oidc.legacy_audiences.is_some()),
        ("jwks_urls", oidc.legacy_jwks_urls.is_some()),
        ("require", oidc.legacy_require.is_some()),
        ("leeway_seconds", oidc.legacy_leeway_seconds.is_some()),
    ] {
        if present {
            return Err(ConfigError::OidcLegacyShape { key });
        }
    }
    if oidc.issuers.is_empty() {
        return Err(ConfigError::OidcMissingRequired {
            field: "at least one [auth.oidc.\"<issuer>\"] block",
        });
    }
    if oidc.jwks_refresh_seconds == 0 {
        return Err(ConfigError::OidcZeroRefresh);
    }
    if oidc.jwks_max_keys == 0 {
        return Err(ConfigError::OidcZeroMaxKeys);
    }
    for (issuer, block) in &oidc.issuers {
        // Every issuer must itself be an https URL: the default JWKS endpoint
        // is derived as `{issuer}/.well-known/jwks.json`, so a plaintext
        // issuer would mean a plaintext fetch. An explicit override cannot
        // rescue it - verification binds tokens to the issuer string whatever
        // URL serves keys, and the fetch layer is https-only as depth
        // defense.
        if !url::Url::parse(issuer).is_ok_and(|url| url.scheme() == "https") {
            return Err(ConfigError::OidcIssuerPlaintext {
                issuer: issuer.clone(),
            });
        }
        if block.audiences.is_empty() {
            return Err(ConfigError::OidcIssuerMissing {
                issuer: issuer.clone(),
                field: "audiences",
            });
        }
        // The tenant namespace's second half comes from this claim's value;
        // an empty name would silently address a claim no token carries.
        if block.tenant_claim.trim().is_empty() {
            return Err(ConfigError::OidcIssuerMissing {
                issuer: issuer.clone(),
                field: "tenant_claim",
            });
        }
        if let Some(url) = &block.jwks_url
            && !url::Url::parse(url).is_ok_and(|u| u.scheme() == "https")
        {
            return Err(ConfigError::OidcJwksPlaintext {
                issuer: issuer.clone(),
                url: url.clone(),
            });
        }
        // Trust roots: the issuer's own bundle, or the global default.
        if block.ca_pem.is_none() && oidc.jwks_ca_pem.is_none() {
            return Err(ConfigError::OidcIssuerMissing {
                issuer: issuer.clone(),
                field: "ca_pem (or the global auth.oidc.jwks_ca_pem)",
            });
        }
    }
    Ok(())
}

/// Multi-tenant boot guard (`docs/shared-cache.md` §2/§9 and §8). A
/// credential plane that yields a tenant makes the deployment
/// multi-tenant; Plane A (`[auth.oidc] enabled`) is such a plane, Plane B
/// joins when it lands. Then:
/// - the HMAC plane must be off: its repo/run fields are client-asserted
///   and cannot express a tenant, so `hmac`/`merge` would silently funnel
///   every HMAC request into one shared namespace;
/// - cluster mode must be off until the peer wire carries namespaces (§8):
///   peers would relay and store namespaced rows as legacy ones.
///
/// No tenant-yielding plane means v1.1 behavior, which validates unchanged.
/// Runs after [`validate_oidc`] so a structural OIDC error takes precedence.
fn validate_tenancy(config: &Config) -> Result<(), ConfigError> {
    let oidc_enabled = config.auth.oidc.as_ref().is_some_and(|oidc| oidc.enabled);
    if !oidc_enabled {
        return Ok(());
    }
    match config.auth.mode {
        AuthMode::Bearer => {}
        AuthMode::Hmac => return Err(ConfigError::HmacInMultiTenant { mode: "hmac" }),
        AuthMode::Merge => return Err(ConfigError::HmacInMultiTenant { mode: "merge" }),
    }
    if config.cluster.enabled {
        return Err(ConfigError::ClusterInMultiTenant);
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
    use std::collections::BTreeMap;

    use crate::config::{AuthMode, OidcConfig, OidcIssuerConfig};

    /// A `Config` with `[auth.oidc]` built from the default surface. An
    /// enabled OIDC table is tenant-yielding, so the HMAC plane must be off
    /// (`validate_tenancy`); every OIDC fixture therefore serves bearer-only.
    fn oidc_config(fields: impl FnOnce(&mut OidcConfig)) -> Config {
        let mut config = Config::default();
        config.auth.mode = AuthMode::Bearer;
        let mut oidc = OidcConfig::default();
        fields(&mut oidc);
        config.auth.oidc = Some(oidc);
        config
    }

    /// Realistic enabled surface (overridable per test).
    fn enabled_oidc() -> Config {
        oidc_config(|oidc| {
            oidc.enabled = true;
            oidc.jwks_ca_pem = Some(PathBuf::from("/etc/cachette/idp-ca.pem"));
            oidc.issuers.insert(
                String::from("https://idp.example.org/realms/ci"),
                OidcIssuerConfig {
                    audiences: vec![String::from("cachette")],
                    ..OidcIssuerConfig::default()
                },
            );
        })
    }

    /// Enabled surface with a specific issuer list (issuer-scheme tests).
    fn enabled_oidc_with_issuers(issuers: Vec<String>) -> Config {
        oidc_config(|oidc| {
            oidc.enabled = true;
            oidc.jwks_ca_pem = Some(PathBuf::from("/etc/cachette/idp-ca.pem"));
            for issuer in issuers {
                oidc.issuers.insert(
                    issuer,
                    OidcIssuerConfig {
                        audiences: vec![String::from("cachette")],
                        ..OidcIssuerConfig::default()
                    },
                );
            }
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

    /// The avg window is validated regardless of `enabled` (docs/cdc.md):
    /// a value outside `[32KiB, 1MiB]` must be named wherever it is edited.
    #[test]
    fn cdc_avg_chunk_bytes_is_capped_either_side() {
        for value in [32 * 1024 - 1, 1024 * 1024 + 1, 0, 1024 * 1024 * 1024] {
            let mut config = Config::default();
            config.storage.cdc.avg_chunk_bytes = value;
            let err = validate(&config).expect_err("outside the chunker window");
            match &err {
                ConfigError::CdcAvgRange { value: got } if *got == value => {}
                other => panic!("for {value}: expected CdcAvgRange, got {other:?}"),
            }
            // ...and the same bad value is rejected disabled or not.
            config.storage.cdc.enabled = true;
            assert!(
                matches!(validate(&config), Err(ConfigError::CdcAvgRange { .. })),
                "the enabled flag must not dodge the cap check"
            );
        }

        let mut config = Config::default();
        config.storage.cdc.avg_chunk_bytes = 32 * 1024;
        assert!(validate(&config).is_ok());
        config.storage.cdc.avg_chunk_bytes = 1024 * 1024;
        assert!(validate(&config).is_ok());
        config.storage.cdc.enabled = true;
        assert!(validate(&config).is_ok());
    }

    /// `backfill_delay_ms = 0` is rejected regardless of `enabled` and
    /// `backfill` (docs/cdc.md Config surface): the walker must never be
    /// configurable into a hot spin.
    #[test]
    fn cdc_backfill_delay_must_not_be_zero() {
        let mut config = Config::default();
        config.storage.cdc.backfill_delay_ms = 0;
        assert!(
            matches!(validate(&config), Err(ConfigError::ZeroCdcBackfillDelay)),
            "zero delay is rejected while disabled"
        );
        config.storage.cdc.enabled = true;
        assert!(
            matches!(validate(&config), Err(ConfigError::ZeroCdcBackfillDelay)),
            "the enabled flag must not dodge the zero check"
        );
        config.storage.cdc.backfill = false;
        assert!(
            matches!(validate(&config), Err(ConfigError::ZeroCdcBackfillDelay)),
            "the backfill flag must not dodge the zero check"
        );

        config.storage.cdc.backfill_delay_ms = 1;
        assert!(validate(&config).is_ok());
        config.storage.cdc.enabled = false;
        config.storage.cdc.backfill = true;
        assert!(validate(&config).is_ok());
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
                oidc.issuers.insert(
                    String::from("https://idp.example.org/realms/ci"),
                    OidcIssuerConfig::default(),
                );
            }))
            .is_ok()
        );
    }

    #[test]
    fn enabled_oidc_requires_an_issuer_block_audiences_and_roots() {
        let err = validate(&oidc_config(|oidc| oidc.enabled = true)).expect_err("no issuer block");
        assert!(
            matches!(
                err,
                ConfigError::OidcMissingRequired {
                    field: "at least one [auth.oidc.\"<issuer>\"] block"
                }
            ),
            "unexpected error: {err:?}"
        );

        let issuer = String::from("https://idp.example.org/realms/ci");
        let err = validate(&oidc_config(|oidc| {
            oidc.enabled = true;
            oidc.issuers
                .insert(issuer.clone(), OidcIssuerConfig::default());
        }))
        .expect_err("no audiences");
        assert!(
            matches!(
                &err,
                ConfigError::OidcIssuerMissing { issuer: got, field: "audiences" } if got == &issuer
            ),
            "unexpected error: {err:?}"
        );

        let err = validate(&oidc_config(|oidc| {
            oidc.enabled = true;
            oidc.issuers.insert(
                issuer.clone(),
                OidcIssuerConfig {
                    audiences: vec![String::from("cachette")],
                    ..OidcIssuerConfig::default()
                },
            );
        }))
        .expect_err("no CA bundle");
        assert!(
            matches!(
                &err,
                ConfigError::OidcIssuerMissing { issuer: got, .. } if got == &issuer
            ),
            "unexpected error: {err:?}"
        );

        assert!(validate(&enabled_oidc()).is_ok());
    }

    /// `docs/shared-cache.md` §2/§9: the HMAC plane cannot express a
    /// tenant, so a tenant-yielding plane (enabled OIDC) refuses `hmac` and
    /// `merge` with a precise error naming the mode.
    #[test]
    fn tenant_yielding_plane_refuses_the_hmac_plane() {
        let mut config = enabled_oidc();
        assert!(
            validate(&config).is_ok(),
            "bearer + OIDC is the supported shape"
        );

        config.auth.mode = AuthMode::Hmac;
        let err = validate(&config).expect_err("hmac with OIDC");
        assert!(
            matches!(&err, ConfigError::HmacInMultiTenant { mode } if *mode == "hmac"),
            "unexpected error: {err:?}"
        );

        config.auth.mode = AuthMode::Merge;
        let err = validate(&config).expect_err("merge with OIDC");
        assert!(
            matches!(&err, ConfigError::HmacInMultiTenant { mode } if *mode == "merge"),
            "unexpected error: {err:?}"
        );

        // No tenant-yielding plane: HMAC keeps its v1.1 behavior.
        let mut config = Config::default();
        config.auth.mode = AuthMode::Hmac;
        assert!(validate(&config).is_ok());
    }

    /// `docs/shared-cache.md` §8: the peer wire does not carry namespaces
    /// yet, so a tenant-yielding plane with cluster mode would relay and
    /// store tenant rows as legacy ones.
    #[test]
    fn tenant_yielding_plane_refuses_cluster_mode() {
        let mut config = enabled_oidc();
        config.cluster.enabled = true;
        let err = validate(&config).expect_err("cluster with OIDC");
        assert!(
            matches!(err, ConfigError::ClusterInMultiTenant),
            "unexpected error: {err:?}"
        );

        // Cluster mode alone (no tenant-yielding plane) is unchanged.
        let mut config = Config::default();
        config.cluster.enabled = true;
        config.auth.mode = AuthMode::Hmac;
        assert!(validate(&config).is_ok());
    }

    /// A per-issuer `ca_pem` covers that issuer on its own; the global
    /// `jwks_ca_pem` is the fallback for issuers that name none.
    #[test]
    fn per_issuer_ca_pem_covers_its_issuer() {
        let issuer = String::from("https://idp.example.org/realms/ci");
        let config = oidc_config(|oidc| {
            oidc.enabled = true;
            oidc.issuers.insert(
                issuer.clone(),
                OidcIssuerConfig {
                    audiences: vec![String::from("cachette")],
                    ca_pem: Some(PathBuf::from("/etc/cachette/other-ca.pem")),
                    ..OidcIssuerConfig::default()
                },
            );
        });
        assert!(validate(&config).is_ok());
    }

    /// The v1.1 flat shape is a configuration error, not a silent fallback:
    /// the error names the key and the shape that replaced it.
    #[test]
    fn the_v11_flat_shape_is_rejected_with_a_precise_error() {
        for (key, set) in [
            ("issuers", 0),
            ("audiences", 1),
            ("jwks_urls", 2),
            ("require", 3),
            ("leeway_seconds", 4),
        ] {
            let err = validate(&oidc_config(|oidc| {
                oidc.enabled = true;
                match set {
                    0 => oidc.legacy_issuers = Some(vec![String::from("https://idp.example.org")]),
                    1 => oidc.legacy_audiences = Some(vec![String::from("cachette")]),
                    2 => oidc.legacy_jwks_urls = Some(BTreeMap::new()),
                    3 => oidc.legacy_require = Some(BTreeMap::new()),
                    _ => oidc.legacy_leeway_seconds = Some(30),
                }
            }))
            .expect_err("v1.1 flat shape");
            assert!(
                matches!(&err, ConfigError::OidcLegacyShape { key: got } if *got == key),
                "unexpected error for {key}: {err:?}"
            );
        }
    }

    #[test]
    fn zero_oidc_refresh_and_key_cap_are_rejected() {
        let surface = crate::config::OidcConfig {
            enabled: true,
            jwks_ca_pem: Some(PathBuf::from("/etc/cachette/idp-ca.pem")),
            issuers: BTreeMap::from([(
                String::from("https://idp.example.org/realms/ci"),
                OidcIssuerConfig {
                    audiences: vec![String::from("cachette")],
                    ..OidcIssuerConfig::default()
                },
            )]),
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

    /// A per-issuer `jwks_url` is an outbound fetch target: https only.
    #[test]
    fn jwks_url_must_be_https() {
        let issuer = String::from("https://idp.example.org/realms/ci");
        let config = oidc_config(|oidc| {
            oidc.enabled = true;
            oidc.jwks_ca_pem = Some(PathBuf::from("/etc/cachette/idp-ca.pem"));
            oidc.issuers.insert(
                issuer.clone(),
                OidcIssuerConfig {
                    audiences: vec![String::from("cachette")],
                    jwks_url: Some(String::from("http://idp.example.org/jwks.json")),
                    ..OidcIssuerConfig::default()
                },
            );
        });
        let err = validate(&config).expect_err("plaintext url");
        assert!(
            matches!(err, ConfigError::OidcJwksPlaintext { .. }),
            "unexpected error: {err:?}"
        );

        let config = oidc_config(|oidc| {
            oidc.enabled = true;
            oidc.jwks_ca_pem = Some(PathBuf::from("/etc/cachette/idp-ca.pem"));
            oidc.issuers.insert(
                issuer.clone(),
                OidcIssuerConfig {
                    audiences: vec![String::from("cachette")],
                    jwks_url: Some(String::from("https://idp.example.org/jwks.json")),
                    ..OidcIssuerConfig::default()
                },
            );
        });
        assert!(validate(&config).is_ok());
    }

    /// A plaintext issuer means a plaintext *derived* JWKS endpoint
    /// (`{issuer}/.well-known/jwks.json`), so only https issuer URLs are
    /// ever valid.
    #[test]
    fn plaintext_issuers_are_rejected() {
        let err = validate(&enabled_oidc_with_issuers(vec![String::from(
            "http://idp.example.org/realms/ci",
        )]))
        .expect_err("plaintext issuer");
        match &err {
            ConfigError::OidcIssuerPlaintext { issuer } => {
                assert_eq!(issuer, "http://idp.example.org/realms/ci");
            }
            other => panic!("expected OidcIssuerPlaintext, got {other:?}"),
        }

        // A relative string is not a URL at all — also rejected (it cannot
        // back a derivation, and tokens carry it as an untrusted index).
        let err = validate(&enabled_oidc_with_issuers(vec![String::from(
            "idp.example.org/realms/ci",
        )]))
        .expect_err("non-URL issuer");
        assert!(
            matches!(err, ConfigError::OidcIssuerPlaintext { .. }),
            "unexpected error: {err:?}"
        );

        // Trailing-slash https issuers remain fine (the fetch layer trims).
        assert!(
            validate(&enabled_oidc_with_issuers(vec![String::from(
                "https://idp.example.org/realms/ci/"
            )]))
            .is_ok()
        );
    }

    /// Multiple issuers, one bad: the loop names the offending one.
    #[test]
    fn one_bad_issuer_names_it() {
        let err = validate(&enabled_oidc_with_issuers(vec![
            String::from("https://good.example.org/realms/ci"),
            String::from("http://bad.example.org/realms/ci"),
        ]))
        .expect_err("mixed scheme issuer set");
        match &err {
            ConfigError::OidcIssuerPlaintext { issuer } => {
                assert_eq!(issuer, "http://bad.example.org/realms/ci");
            }
            other => panic!("expected OidcIssuerPlaintext, got {other:?}"),
        }
    }

    /// `[storage.namespaces]` keys are credential identities
    /// (`docs/shared-cache.md` §7): both halves must be present. A target
    /// may be any name (including `""`, the legacy opt-in).
    #[test]
    fn namespace_mappings_require_forge_and_tenant_halves() {
        let mut config = Config::default();
        config.storage.namespaces.insert(
            String::from("https://hangar.nixthedev.ru|NiXTheDev/cachette"),
            String::from("nixthedev"),
        );
        config.storage.namespaces.insert(
            String::from("https://github.com|octo-org/api"),
            String::new(),
        );
        assert!(validate(&config).is_ok());

        for key in [
            "NiXTheDev/cachette",
            "|NiXTheDev/cachette",
            "https://forge|",
        ] {
            let mut config = Config::default();
            config
                .storage
                .namespaces
                .insert(String::from(key), String::from("shared"));
            let err = validate(&config).expect_err("malformed mapping key");
            assert!(
                matches!(&err, ConfigError::NamespaceMappingKey { key: got } if got == key),
                "unexpected error: {err:?}"
            );
        }
    }
}
