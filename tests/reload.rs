//! Plan task 49 acceptance: a SIGHUP (or test-triggered) config reload swaps
//! the live `[auth]` and `[cache]` policy in place, so an HMAC token minted
//! against the pre-reload secret is rejected afterwards while a token minted
//! against the new secret is accepted — and nothing else (boot-only knobs) is
//! disturbed.
//!
//! v1.1 workstream A addendum: a reload NEVER swaps (or uninstalls) the
//! boot-installed OIDC verifier — the section's signature change warns in
//! production and the restart applies it (docs/oidc.md rollout).
//!
//! The signal itself is `cfg(unix)` and cannot be delivered to a child on
//! Windows CI, so the reload is applied through the same entry point the
//! signal handler uses (`AppState::apply_reload`, fed by `config::load`), and
//! the request path is then driven with real HMAC headers.

use axum::http::{HeaderMap, HeaderName, HeaderValue};
use std::collections::BTreeMap;
use std::sync::Arc;

use cachette::auth::hmac;
use cachette::config::{Config, OidcConfig};
use cachette::state::AppState;

/// Build a resolved [`Config`] with the given HMAC secret and cache size.
fn config(secret: &str, max_size: u64) -> Config {
    let mut config = Config::default();
    config.auth.secret = Some(secret.to_owned());
    config.cache.max_size = max_size;
    config
}

/// A Forgejo HMAC [`HeaderMap`] signed with `secret` for `repo`/`run`.
fn hmac_headers(secret: &str, repo: &str, run: u64, timestamp: i64) -> HeaderMap {
    let mac = hmac::mint(secret, repo, run, timestamp, "");
    let mut headers = HeaderMap::new();
    headers.insert(
        HeaderName::from_static(hmac::HEADER_REPO),
        HeaderValue::from_str(repo).expect("repo header"),
    );
    headers.insert(
        HeaderName::from_static(hmac::HEADER_RUN),
        HeaderValue::from_str(&run.to_string()).expect("run header"),
    );
    headers.insert(
        HeaderName::from_static(hmac::HEADER_TS),
        HeaderValue::from_str(&timestamp.to_string()).expect("ts header"),
    );
    headers.insert(
        HeaderName::from_static(hmac::HEADER_MAC),
        HeaderValue::from_str(&mac).expect("mac header"),
    );
    headers
}

#[test]
fn hmac_token_is_rejected_after_secret_reload() {
    let state = AppState::new();
    state.apply_reload(&config("old-secret-at-least-16", 0));

    // A token minted against the pre-reload secret verifies.
    let before = hmac_headers("old-secret-at-least-16", "owner/repo", 42, now());
    assert!(
        hmac::verify(&state.auth(), &before),
        "token minted before the reload must verify"
    );

    // Reload with a new secret.
    state.apply_reload(&config("new-secret-at-least-16", 0));
    assert_eq!(
        state.auth().secret.as_deref(),
        Some("new-secret-at-least-16"),
        "apply_reload swaps the live secret"
    );

    // The pre-reload token is now rejected; a freshly minted one is accepted.
    assert!(
        !hmac::verify(&state.auth(), &before),
        "token minted before the reload must be rejected afterwards"
    );
    let after = hmac_headers("new-secret-at-least-16", "owner/repo", 42, now());
    assert!(
        hmac::verify(&state.auth(), &after),
        "token minted against the new secret must verify"
    );
}

#[test]
fn apply_reload_updates_cache_limits() {
    let state = AppState::new();
    state.apply_reload(&config("reload-secret-16chars", 1024));
    assert_eq!(state.cache_limits().max_size, 1024);

    state.apply_reload(&config("reload-secret-16chars", 65536));
    assert_eq!(
        state.cache_limits().max_size,
        65536,
        "apply_reload swaps the live cache limits"
    );
}

#[test]
fn apply_reload_replaces_static_tokens() {
    // A static bearer token present before the reload disappears afterwards:
    // the reload replaces the whole policy rather than merging into it.
    let mut first = config("reload-secret-16chars", 0);
    first.auth.tokens = vec!["old-token".to_owned()];
    let state = AppState::new();
    state.apply_reload(&first);
    assert_eq!(state.auth().static_tokens, vec!["old-token".to_owned()]);

    let mut second = config("reload-secret-16chars", 0);
    second.auth.tokens = vec!["new-token".to_owned()];
    state.apply_reload(&second);
    assert_eq!(state.auth().static_tokens, vec!["new-token".to_owned()]);
}

/// Current Unix seconds (the HMAC staleness window is measured against it).
fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after the epoch")
        .as_secs() as i64
}

// -- v1.1 workstream A: reloads never swap (or uninstall) the OIDC verifier —

/// A key source that is never consulted: the reload tests assert verifier
/// identity, not token answers.
struct ReloadKeys;

impl cachette::auth::jwks::RsaKeySource for ReloadKeys {
    fn key(&self, _issuer: &str, _kid: &str) -> Option<cachette::auth::jwks::JwksKey> {
        None
    }
}

/// Enabled `[auth.oidc]` surface with a distinct issuer string.
fn oidc_config() -> Config {
    let mut config = Config::default();
    config.auth.oidc = Some(OidcConfig {
        enabled: true,
        jwks_ca_pem: Some(std::path::PathBuf::from("/etc/cachette/idp-ca.pem")),
        ..OidcConfig::default()
    });
    config
        .auth
        .oidc
        .as_mut()
        .expect("oidc table")
        .issuers
        .insert(
            String::from("https://idp.example.org/realms/ci"),
            cachette::config::OidcIssuerConfig {
                audiences: vec![String::from("cachette")],
                ..cachette::config::OidcIssuerConfig::default()
            },
        );
    config
}

fn fixture_verifier(issuers: Vec<String>) -> cachette::auth::oidc::OidcVerifier {
    let trust = issuers
        .into_iter()
        .map(|issuer| {
            (
                issuer,
                cachette::auth::oidc::IssuerTrust {
                    audiences: vec![String::from("cachette")],
                    require: BTreeMap::new(),
                    leeway_seconds: 30,
                },
            )
        })
        .collect();
    cachette::auth::oidc::OidcVerifier::new(trust, Arc::new(ReloadKeys))
}

/// A SIGHUP reload keeps the boot-installed OIDC verifier — with the same
/// section (warn-free), with a retuned section (warns in production), and
/// even with `enabled = false`: toggling/uninstalling requires a restart.
#[test]
fn reload_keeps_the_boot_oidc_verifier_installed() {
    let config = oidc_config();
    let oidc_cfg = config.auth.oidc.clone().expect("table present");
    let state = AppState::new();
    state.install_oidc(
        fixture_verifier(oidc_cfg.issuers.keys().cloned().collect()),
        &oidc_cfg,
    );

    let boot = state.oidc().expect("boot install");
    assert!(
        Arc::ptr_eq(&boot, state.oidc().as_ref().expect("kept")),
        "the handle must stay stable between reads"
    );

    // Same-section reload: nothing changes.
    state.apply_reload(&config);
    assert!(
        Arc::ptr_eq(&boot, state.oidc().as_ref().expect("kept")),
        "a same-section reload must not swap the verifier"
    );

    // Retuned-but-enabled reload: the verifier is still the boot one (the
    // production log warns about the signature change; the restart applies).
    let mut retuned = oidc_config();
    retuned
        .auth
        .oidc
        .as_mut()
        .expect("present")
        .issuers
        .get_mut("https://idp.example.org/realms/ci")
        .expect("issuer block")
        .leeway_seconds = 90;
    state.apply_reload(&retuned);
    assert!(
        Arc::ptr_eq(&boot, state.oidc().as_ref().expect("kept")),
        "a changed-section reload must not swap the verifier"
    );

    // Disabling in a reload keeps the verifier running, too.
    let mut off = oidc_config();
    off.auth.oidc.as_mut().expect("present").enabled = false;
    state.apply_reload(&off);
    assert!(
        state.oidc().is_some(),
        "a reload must never uninstall OIDC mid-flight"
    );
}
