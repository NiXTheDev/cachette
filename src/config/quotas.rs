//! `[storage.quotas]`: per-namespace byte limits (v1.2 workstream F,
//! `docs/shared-cache.md` §5).
//!
//! The table carries one **required** `default` limit and any number of
//! override rules. A rule key is either a full namespace
//! (`"<forge>|<tenant>"`), a forge-scoped pattern
//! (`"<forge>|<tenant-pattern>"`), or a tenant-only pattern
//! (`"<tenant-pattern>"`, matched against every forge). Rules are
//! overrides: the default governs every namespace no rule matches.
//!
//! Lookup order, most specific first:
//!
//! 1. the exact namespace string;
//! 2. the longest matching pattern (`*` matches any run of characters,
//!    anchored at both ends; equal-length ties fall back to the
//!    lexicographically smaller key so the choice is deterministic);
//! 3. `default`.
//!
//! A pattern is a shorthand for "the same limit for each matched
//! namespace", never a shared pool: only namespaces the admin deliberately
//! maps into one namespace share a budget.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde::Serialize;

use crate::config::error::ConfigError;
use crate::config::min_free::parse_byte_size;

/// Key of the table's default limit (not a namespace or pattern).
const DEFAULT_KEY: &str = "default";

/// Raw `[storage.quotas]` table, as authored: rule key -> bytesize string.
/// An absent (or empty) table means quotas are off.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(transparent)]
pub struct QuotasConfig(pub BTreeMap<String, String>);

impl QuotasConfig {
    /// Whether the table carries any rule at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Parse into the runtime rule set. Validation calls this too, so a
    /// config that passes validation always parses here.
    pub fn parse(&self) -> Result<Quotas, ConfigError> {
        Quotas::from_config(self)
    }
}

/// Parsed quota rules. `Default` is "no quotas configured" - every
/// namespace is unlimited.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Quotas {
    /// Limit for every namespace no rule matches. `Some` exactly when the
    /// config table is present.
    default: Option<u64>,
    /// Override rules, ordered by key (the source `BTreeMap` order).
    rules: Vec<Rule>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Rule {
    /// The authored rule key (also the pattern text for wildcards).
    key: String,
    limit: u64,
    pattern: Pattern,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Pattern {
    /// No `*`: matches the namespace string byte-exactly.
    Exact,
    /// `<forge>|<tenant-glob>`: the forge half matched exactly.
    Forge { forge: String, tenant: String },
    /// `<tenant-glob>`: matched against the tenant half of any forge's
    /// namespace (or the whole name when it carries no forge half).
    Tenant(String),
}

impl Quotas {
    /// Build the rule set from the raw table.
    ///
    /// An empty table is "quotas off". A present table must name a positive
    /// `default`; every rule key must be shaped like a namespace (or
    /// tenant-side pattern) and every value must be a positive bytesize.
    pub fn from_config(config: &QuotasConfig) -> Result<Self, ConfigError> {
        if config.0.is_empty() {
            return Ok(Self::default());
        }
        let default_raw = config
            .0
            .get(DEFAULT_KEY)
            .ok_or(ConfigError::QuotaDefaultMissing)?;
        let default = parse_limit(DEFAULT_KEY, default_raw)?;
        let mut rules = Vec::with_capacity(config.0.len().saturating_sub(1));
        for (key, value) in &config.0 {
            if key == DEFAULT_KEY {
                continue;
            }
            let limit = parse_limit(key, value)?;
            rules.push(Rule {
                key: key.clone(),
                limit,
                pattern: parse_pattern(key)?,
            });
        }
        Ok(Self {
            default: Some(default),
            rules,
        })
    }

    /// Apply v1.3 `[[quota]]` namespace rules on top of the legacy table.
    /// Instance-scoped rules are parsed and validated but still need a
    /// per-instance eviction pass; they are deliberately ignored here rather
    /// than misapplied to a namespace of the same name.
    pub fn apply_v13(
        &mut self,
        rules: &[crate::config::QuotaRuleConfig],
    ) -> Result<(), ConfigError> {
        for rule in rules {
            if rule.scope != crate::config::QuotaScope::Namespace {
                continue;
            }
            let limit = parse_limit(&rule.target, &rule.limit)?;
            if rule.target == "*" || rule.target == "default" {
                self.default = Some(limit);
            } else if let Some(existing) = self
                .rules
                .iter_mut()
                .find(|existing| existing.key == rule.target)
            {
                existing.limit = limit;
                existing.pattern = parse_pattern(&rule.target)?;
            } else {
                self.rules.push(Rule {
                    key: rule.target.clone(),
                    limit,
                    pattern: parse_pattern(&rule.target)?,
                });
            }
        }
        self.rules.sort_by(|a, b| a.key.cmp(&b.key));
        Ok(())
    }

    /// Whether any quota is configured (a present table always has a
    /// `default`).
    #[must_use]
    pub fn is_configured(&self) -> bool {
        self.default.is_some()
    }

    /// One `(target, limit)` vote per configured rule, with `*` carrying the
    /// default. Used by the cluster's quota consensus gossip.
    #[must_use]
    pub fn votes(&self) -> Vec<(String, u64)> {
        let mut votes = Vec::new();
        if let Some(default) = self.default {
            votes.push((String::from("*"), default));
        }
        votes.extend(self.rules.iter().map(|rule| (rule.key.clone(), rule.limit)));
        votes
    }

    /// The configured total (bytes) of `namespace`, or `None` when quotas
    /// are off. The namespace is the RESOLVED one (after
    /// `[storage.namespaces]` mapping).
    #[must_use]
    pub fn limit_for(&self, namespace: &str) -> Option<u64> {
        let default = self.default?;
        let tenant = namespace
            .split_once('|')
            .map_or(namespace, |(_forge, tenant)| tenant);
        if let Some(rule) = self
            .rules
            .iter()
            .find(|rule| rule.pattern == Pattern::Exact && rule.key == namespace)
        {
            return Some(rule.limit);
        }
        let mut best: Option<&Rule> = None;
        for rule in &self.rules {
            let matched = match &rule.pattern {
                Pattern::Exact => false,
                Pattern::Forge { forge, tenant: pat } => namespace
                    .split_once('|')
                    .is_some_and(|(actual, tenant)| actual == forge && glob_matches(pat, tenant)),
                Pattern::Tenant(pat) => glob_matches(pat, tenant),
            };
            if matched && best.is_none_or(|current| rule.key.len() > current.key.len()) {
                best = Some(rule);
            }
        }
        Some(best.map_or(default, |rule| rule.limit))
    }
}

/// Parse one limit: a positive bytesize (`"20GiB"`, `"512MiB"`).
fn parse_limit(key: &str, raw: &str) -> Result<u64, ConfigError> {
    match parse_byte_size(raw.trim()) {
        Some(bytes) if bytes > 0 => Ok(bytes),
        _ => Err(ConfigError::QuotaValue {
            key: key.to_owned(),
            value: raw.to_owned(),
        }),
    }
}

/// Validate and classify a rule key.
fn parse_pattern(key: &str) -> Result<Pattern, ConfigError> {
    if key.trim().is_empty() || key.trim() != key {
        return Err(ConfigError::QuotaRuleKey {
            key: key.to_owned(),
        });
    }
    if let Some((forge, tenant)) = key.split_once('|') {
        if forge.trim().is_empty()
            || forge.contains('*')
            || forge.trim() != forge
            || tenant.trim().is_empty()
            || tenant.trim() != tenant
        {
            return Err(ConfigError::QuotaRuleKey {
                key: key.to_owned(),
            });
        }
        if tenant.contains('*') {
            return Ok(Pattern::Forge {
                forge: forge.to_owned(),
                tenant: tenant.to_owned(),
            });
        }
        return Ok(Pattern::Exact);
    }
    if key.contains('*') {
        Ok(Pattern::Tenant(key.to_owned()))
    } else {
        Ok(Pattern::Exact)
    }
}

/// Anchored glob: `*` matches any run of characters, including an empty
/// one. Byte-wise, so UTF-8 names match exactly and only on whole bytes.
pub(crate) fn glob_matches(pattern: &str, value: &str) -> bool {
    let pattern = pattern.as_bytes();
    let value = value.as_bytes();
    let (mut pi, mut vi) = (0usize, 0usize);
    let mut star: Option<usize> = None;
    let mut star_vi = 0usize;
    while vi < value.len() {
        if pi < pattern.len() && pattern[pi] == b'*' {
            star = Some(pi);
            star_vi = vi;
            pi += 1;
        } else if pi < pattern.len() && pattern[pi] == value[vi] {
            pi += 1;
            vi += 1;
        } else if let Some(star_pi) = star {
            star_vi += 1;
            vi = star_vi;
            pi = star_pi + 1;
        } else {
            return false;
        }
    }
    while pi < pattern.len() && pattern[pi] == b'*' {
        pi += 1;
    }
    pi == pattern.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    const GIB: u64 = 1024 * 1024 * 1024;

    fn quotas(pairs: &[(&str, &str)]) -> Quotas {
        let config = QuotasConfig(
            pairs
                .iter()
                .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
                .collect(),
        );
        config.parse().expect("valid quotas")
    }

    #[test]
    fn empty_table_means_no_quotas() {
        let quotas = Quotas::default();
        assert!(!quotas.is_configured());
        assert_eq!(quotas.limit_for("forge|owner/repo"), None);
    }

    #[test]
    fn exact_beats_wildcard_beats_default() {
        let quotas = quotas(&[
            ("default", "20GiB"),
            ("owner/*", "5GiB"),
            ("https://forge.example|owner/repo", "50GiB"),
        ]);
        assert_eq!(
            quotas.limit_for("https://forge.example|owner/repo"),
            Some(50 * GIB)
        );
        assert_eq!(
            quotas.limit_for("https://forge.example|owner/other"),
            Some(5 * GIB)
        );
        assert_eq!(
            quotas.limit_for("https://other.example|someone/else"),
            Some(20 * GIB)
        );
    }

    #[test]
    fn tenant_only_pattern_covers_every_forge() {
        let quotas = quotas(&[("default", "1GiB"), ("owner/*", "7GiB")]);
        for namespace in [
            "https://forge.example|owner/repo",
            "https://github.com|owner/repo",
            "owner/repo",
        ] {
            assert_eq!(quotas.limit_for(namespace), Some(7 * GIB), "{namespace}");
        }
        assert_eq!(
            quotas.limit_for("https://github.com|someone/repo"),
            Some(GIB)
        );
    }

    #[test]
    fn forge_pattern_does_not_cross_forges() {
        let quotas = quotas(&[
            ("default", "1GiB"),
            ("https://github.com|octo-org/*", "5GiB"),
        ]);
        assert_eq!(
            quotas.limit_for("https://github.com|octo-org/api"),
            Some(5 * GIB)
        );
        assert_eq!(
            quotas.limit_for("https://forge.example|octo-org/api"),
            Some(GIB)
        );
    }

    #[test]
    fn longest_matching_pattern_wins() {
        let quotas = quotas(&[
            ("default", "1GiB"),
            ("owner/*", "5GiB"),
            ("owner/app-*", "9GiB"),
        ]);
        assert_eq!(
            quotas.limit_for("https://forge.example|owner/app-web"),
            Some(9 * GIB)
        );
        assert_eq!(
            quotas.limit_for("https://forge.example|owner/other"),
            Some(5 * GIB)
        );
    }

    #[test]
    fn glob_is_anchored_and_crosses_separators() {
        assert!(glob_matches("owner/*", "owner/a/b"));
        assert!(glob_matches("*", ""));
        assert!(glob_matches("a*b", "ab"));
        assert!(glob_matches("a*b", "axxb"));
        assert!(!glob_matches("a*b", "abx"));
        assert!(!glob_matches("owner/*", "other/owner/x"));
        assert!(!glob_matches("a*c", "ab"));
    }

    #[test]
    fn validation_rejects_missing_default_or_bad_limits() {
        let missing = QuotasConfig(
            [("owner/*".to_owned(), "5GiB".to_owned())]
                .into_iter()
                .collect(),
        );
        assert!(matches!(
            missing.parse(),
            Err(ConfigError::QuotaDefaultMissing)
        ));

        for bad in ["5", "0GiB", "", "5XB", "-1GiB"] {
            let config = QuotasConfig(
                [
                    ("default".to_owned(), "1GiB".to_owned()),
                    ("owner/*".to_owned(), bad.to_owned()),
                ]
                .into_iter()
                .collect(),
            );
            assert!(
                matches!(config.parse(), Err(ConfigError::QuotaValue { .. })),
                "accepted {bad:?}"
            );
        }

        let zero_default = QuotasConfig(
            [("default".to_owned(), "0GiB".to_owned())]
                .into_iter()
                .collect(),
        );
        assert!(matches!(
            zero_default.parse(),
            Err(ConfigError::QuotaValue { .. })
        ));
    }

    #[test]
    fn validation_rejects_malformed_rule_keys() {
        for key in ["", "   ", "|tenant", "forge|", "*|tenant", " forge |tenant"] {
            let config = QuotasConfig(
                [
                    ("default".to_owned(), "1GiB".to_owned()),
                    (key.to_owned(), "5GiB".to_owned()),
                ]
                .into_iter()
                .collect(),
            );
            assert!(
                matches!(config.parse(), Err(ConfigError::QuotaRuleKey { .. })),
                "accepted {key:?}"
            );
        }
    }
}
