//! Declarative config schema and one renderer for `cachette config example`
//! and `doctor --migrate`. Every knob appears with its default; optional
//! keys are commented out so the emitted file boots as-is.

/// How a field is rendered.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Form {
    /// Present with its default value.
    Required,
    /// Commented out with the default spelled in the comment.
    Optional,
}

/// One config knob.
#[derive(Clone, Copy, Debug)]
pub struct Field {
    pub key: &'static str,
    pub default: &'static str,
    pub form: Form,
    pub comment: &'static str,
}

/// One TOML section (a literal header; empty means root-level).
#[derive(Clone, Copy, Debug)]
pub struct Section {
    pub header: &'static str,
    pub fields: &'static [Field],
}

/// The canonical spec. Ordering here is the order in the generated file and
/// in migration output.
pub static SECTIONS: &[Section] = &[
    Section {
        header: "server",
        fields: &[
            Field {
                key: "data_path",
                default: "\"/etc/cachette\"",
                form: Form::Optional,
                comment: "directory -> <dir>/cachette.db, or a .db file path",
            },
            Field {
                key: "listen",
                default: "\"0.0.0.0:8080\"",
                form: Form::Required,
                comment: "runner-facing listener (host:port)",
            },
            Field {
                key: "external_url",
                default: "\"http://127.0.0.1:8080\"",
                form: Form::Optional,
                comment: "runner-visible base URL",
            },
            Field {
                key: "max_size",
                default: "0",
                form: Form::Required,
                comment: "0 = use disk total; accepts bytesizes like \"32GiB\"",
            },
            Field {
                key: "eviction",
                default: "\"lru\"",
                form: Form::Required,
                comment: "lru | oldest | none",
            },
            Field {
                key: "key_case",
                default: "\"preserve\"",
                form: Form::Required,
                comment: "preserve | lower",
            },
            Field {
                key: "reservation_ttl_seconds",
                default: "3600",
                form: Form::Required,
                comment: "reservation lifetime",
            },
            Field {
                key: "max_chunk_bytes",
                default: "67108864",
                form: Form::Required,
                comment: "largest single upload chunk",
            },
            Field {
                key: "drain_grace_seconds",
                default: "30",
                form: Form::Required,
                comment: "graceful-shutdown window",
            },
            Field {
                key: "tls_cert",
                default: "\"/etc/cachette/tls.crt\"",
                form: Form::Optional,
                comment: "TLS cert (must be set with tls_key)",
            },
            Field {
                key: "tls_key",
                default: "\"/etc/cachette/tls.key\"",
                form: Form::Optional,
                comment: "TLS key",
            },
            Field {
                key: "level",
                default: "\"info\"",
                form: Form::Required,
                comment: "log level",
            },
            Field {
                key: "format",
                default: "\"text\"",
                form: Form::Required,
                comment: "text | json",
            },
        ],
    },
    Section {
        header: "auth",
        fields: &[
            Field {
                key: "mode",
                default: "\"merge\"",
                form: Form::Required,
                comment: "hmac | bearer | merge",
            },
            Field {
                key: "secret",
                default: "\"CHANGE_ME_MIN_16_CHARS\"",
                form: Form::Required,
                comment: "HMAC key (minimum 16 characters)",
            },
            Field {
                key: "tokens",
                default: "[]",
                form: Form::Optional,
                comment: "static bearer tokens",
            },
            Field {
                key: "hmac_max_age_seconds",
                default: "600",
                form: Form::Required,
                comment: "0 disables the staleness check",
            },
            Field {
                key: "signed_url_ttl_seconds",
                default: "900",
                form: Form::Required,
                comment: "v1/v2 capability URL lifetime",
            },
            Field {
                key: "jwt_secret",
                default: "\"CHANGE_ME_MIN_16_CHARS\"",
                form: Form::Optional,
                comment: "falls back to [auth] secret",
            },
            Field {
                key: "jwt_ttl_seconds",
                default: "300",
                form: Form::Required,
                comment: "Twirp v2 JWT lifetime",
            },
            Field {
                key: "oidc_jwks_refresh_seconds",
                default: "1800",
                form: Form::Optional,
                comment: "JWKS prefetch interval",
            },
            Field {
                key: "oidc_jwks_max_keys",
                default: "32",
                form: Form::Optional,
                comment: "cached-key cap",
            },
            Field {
                key: "oidc_jwks_ca_pem",
                default: "\"/etc/ssl/certs/ca-certificates.crt\"",
                form: Form::Optional,
                comment: "default JWKS trust roots",
            },
        ],
    },
    Section {
        header: "auth.forge.\"<forge>\"",
        fields: &[
            Field {
                key: "hmac_secret",
                default: "\"CHANGE_ME_MIN_16_CHARS\"",
                form: Form::Required,
                comment: "runner cache.secret; yields forge + signed repo tenant",
            },
            Field {
                key: "runtime_secret",
                default: "\"/etc/cachette/forge-token.secret\"",
                form: Form::Optional,
                comment: "file holding the forge's token signing secret",
            },
            Field {
                key: "runtime_tenant_claim",
                default: "\"oidc_extra.repository\"",
                form: Form::Optional,
                comment: "where the runtime token carries the tenant",
            },
            Field {
                key: "oidc_issuer",
                default: "\"https://idp.example.org/realms/ci\"",
                form: Form::Optional,
                comment: "exact iss claim for this forge",
            },
            Field {
                key: "oidc_audiences",
                default: "[\"cachette\"]",
                form: Form::Optional,
                comment: "accepted aud values",
            },
            Field {
                key: "oidc_jwks_url",
                default: "\"https://idp.example.org/realms/ci/protocol/openid-connect/certs\"",
                form: Form::Optional,
                comment: "explicit JWKS endpoint",
            },
            Field {
                key: "oidc_tenant_claim",
                default: "\"repository\"",
                form: Form::Optional,
                comment: "claim whose value becomes the tenant",
            },
            Field {
                key: "oidc_require",
                default: "{ \"groups\" = \"ci\" }",
                form: Form::Optional,
                comment: "claim pins",
            },
            Field {
                key: "oidc_leeway_seconds",
                default: "30",
                form: Form::Optional,
                comment: "clock skew",
            },
        ],
    },
    Section {
        header: "storage.fs",
        fields: &[
            Field {
                key: "path",
                default: "\"/var/lib/cachette\"",
                form: Form::Required,
                comment: "legacy local root; also the default control-DB directory",
            },
            Field {
                key: "min_free",
                default: "0.2",
                form: Form::Required,
                comment: "default free-space floor for all instances",
            },
        ],
    },
    Section {
        header: "storage",
        fields: &[Field {
            key: "routes",
            default: "{}",
            form: Form::Optional,
            comment: "resolved namespace -> instance; see [storage.routes]",
        }],
    },
    Section {
        header: "storage.cdc",
        fields: &[
            Field {
                key: "enabled",
                default: "false",
                form: Form::Required,
                comment: "content-defined chunking",
            },
            Field {
                key: "avg_chunk_bytes",
                default: "131072",
                form: Form::Optional,
                comment: "target mean chunk size",
            },
            Field {
                key: "backfill",
                default: "true",
                form: Form::Optional,
                comment: "convert existing whole entries",
            },
            Field {
                key: "backfill_delay_ms",
                default: "100",
                form: Form::Optional,
                comment: "pace between conversions",
            },
        ],
    },
    Section {
        header: "[[storage.instances]]",
        fields: &[
            Field {
                key: "name",
                default: "\"default\"",
                form: Form::Required,
                comment: "routing target; repeat this block for more instances",
            },
            Field {
                key: "type",
                default: "\"fs\"",
                form: Form::Required,
                comment: "fs | s3 | webdav | copyparty | azure | ftp | sftp",
            },
            Field {
                key: "path",
                default: "\"/var/lib/cachette\"",
                form: Form::Required,
                comment: "local root (also the mount point for mounted SMB/NFS/WebDAV)",
            },
            Field {
                key: "mount_url",
                default: "\"//nas.example.org/cache\"",
                form: Form::Optional,
                comment: "documentation only: what is mounted at path",
            },
            Field {
                key: "bucket",
                default: "\"cachette\"",
                form: Form::Optional,
                comment: "required for type = \"s3\"",
            },
            Field {
                key: "region",
                default: "\"us-east-1\"",
                form: Form::Optional,
                comment: "S3 region",
            },
            Field {
                key: "endpoint",
                default: "\"https://minio.example.org:9000\"",
                form: Form::Optional,
                comment: "custom S3 endpoint (path-style addressing)",
            },
            Field {
                key: "url",
                default: "\"https://copyparty.example.org/cachette/\"",
                form: Form::Optional,
                comment: "endpoint for webdav/copyparty/ftp/sftp instances",
            },
            Field {
                key: "prefix",
                default: "\"blobs\"",
                form: Form::Optional,
                comment: "key prefix inside the remote store",
            },
            Field {
                key: "username",
                default: "\"cachette\"",
                form: Form::Optional,
                comment: "remote username / basic auth",
            },
            Field {
                key: "password_file",
                default: "\"/etc/cachette/remote.password\"",
                form: Form::Optional,
                comment: "file holding the remote password or copyparty PW header",
            },
            Field {
                key: "ca_pem",
                default: "\"/etc/ssl/certs/ca-certificates.crt\"",
                form: Form::Optional,
                comment: "trust roots; required whenever the endpoint is https",
            },
            Field {
                key: "access_key",
                default: "\"CHANGE_ME\"",
                form: Form::Optional,
                comment: "S3 access key fallback (AWS_ACCESS_KEY_ID wins)",
            },
            Field {
                key: "secret_key",
                default: "\"CHANGE_ME\"",
                form: Form::Optional,
                comment: "S3 secret key fallback (AWS_SECRET_ACCESS_KEY wins)",
            },
            Field {
                key: "wsalt",
                default: "\"hunter2\"",
                form: Form::Optional,
                comment: "copyparty file-ID salt (must match server --wsalt)",
            },
            Field {
                key: "account",
                default: "\"cachetteaccount\"",
                form: Form::Optional,
                comment: "Azure storage account (env AZURE_STORAGE_ACCOUNT wins)",
            },
            Field {
                key: "container",
                default: "\"cachette\"",
                form: Form::Optional,
                comment: "Azure blob container",
            },
            Field {
                key: "private_key_file",
                default: "\"/etc/cachette/id_sftp\"",
                form: Form::Optional,
                comment: "SSH key for type = \"sftp\" (agent/key auth only)",
            },
            Field {
                key: "known_hosts_file",
                default: "\"/etc/cachette/sftp_known_hosts\"",
                form: Form::Optional,
                comment: "pin the SFTP host key; native client trusts any key without it",
            },
            Field {
                key: "cdc",
                default: "true",
                form: Form::Optional,
                comment: "override the global [storage.cdc] enabled for this instance",
            },
            Field {
                key: "avg_chunk_bytes",
                default: "131072",
                form: Form::Optional,
                comment: "per-instance CDC target chunk size",
            },
        ],
    },
    Section {
        header: "[[quota]]",
        fields: &[
            Field {
                key: "scope",
                default: "\"namespace\"",
                form: Form::Required,
                comment: "namespace | instance",
            },
            Field {
                key: "target",
                default: "\"*\"",
                form: Form::Required,
                comment: "exact name or glob",
            },
            Field {
                key: "limit",
                default: "\"20GiB\"",
                form: Form::Required,
                comment: "positive bytesize",
            },
        ],
    },
    Section {
        header: "cluster",
        fields: &[
            Field {
                key: "enabled",
                default: "false",
                form: Form::Required,
                comment: "peer-to-peer clustering",
            },
            Field {
                key: "listen",
                default: "\"0.0.0.0:8081\"",
                form: Form::Required,
                comment: "always-mTLS peer listener",
            },
            Field {
                key: "advertise_addr",
                default: "\"0.0.0.0:8081\"",
                form: Form::Optional,
                comment: "peer-facing address",
            },
            Field {
                key: "node_id",
                default: "\"node-a\"",
                form: Form::Optional,
                comment: "override the fingerprint node id",
            },
            Field {
                key: "mdns",
                default: "true",
                form: Form::Optional,
                comment: "mDNS discovery",
            },
            Field {
                key: "seeds",
                default: "[]",
                form: Form::Optional,
                comment: "static peer addresses",
            },
            Field {
                key: "seed_fingerprints",
                default: "{}",
                form: Form::Optional,
                comment: "static peer pin map",
            },
            Field {
                key: "tiebreak",
                default: "\"random\"",
                form: Form::Optional,
                comment: "placement tie-break",
            },
            Field {
                key: "heartbeat_interval_seconds",
                default: "5",
                form: Form::Optional,
                comment: "heartbeat cadence",
            },
            Field {
                key: "peer_timeout_seconds",
                default: "15",
                form: Form::Optional,
                comment: "peer staleness window",
            },
            Field {
                key: "cert_path",
                default: "\"/etc/cachette/identity\"",
                form: Form::Optional,
                comment: "identity key/cert directory",
            },
        ],
    },
    Section {
        header: "log",
        fields: &[Field {
            key: "file",
            default: "\"/var/log/cachette.log\"",
            form: Form::Optional,
            comment: "log file (stdout when unset)",
        }],
    },
];

/// Render the complete commented example config.
#[must_use]
pub fn render_example() -> String {
    let mut out = String::from(
        "# cachette configuration - generated from the config schema.\n# Every knob is present; optional keys are commented out with their defaults.\n\n",
    );
    for section in SECTIONS {
        if section.header.starts_with("[[") {
            out.push_str(&format!("{}\n", section.header));
        } else {
            out.push_str(&format!("[{}]\n", section.header));
        }
        for field in section.fields {
            match field.form {
                Form::Required => {
                    out.push_str(&format!(
                        "{} = {} # {}\n",
                        field.key, field.default, field.comment
                    ));
                }
                Form::Optional => {
                    out.push_str(&format!(
                        "# {} = {} # {}\n",
                        field.key, field.default, field.comment
                    ));
                }
            }
        }
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example_covers_every_section_and_parses() {
        let rendered = render_example();
        for section in SECTIONS {
            let expected = if section.header.starts_with("[[") {
                section.header.to_owned()
            } else {
                format!("[{}]", section.header)
            };
            assert!(rendered.contains(&expected), "missing header {expected}");
            for field in section.fields {
                assert!(rendered.contains(field.key), "missing {}", field.key);
            }
        }
        let table: toml::Table =
            toml::from_str(&rendered).expect("generated example is valid TOML");
        assert!(table.contains_key("server"));
        assert!(table.contains_key("auth"));
        // "Boots as-is" is part of the contract: run the generated text
        // through the real loader (normalization, env merge, validation).
        super::super::from_sources(Some(&rendered), &[])
            .expect("generated example loads and validates");
    }
}
