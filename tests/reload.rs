//! Plan task 49 acceptance: a SIGHUP (or test-triggered) config reload swaps
//! the live `[auth]` and `[cache]` policy in place, so an HMAC token minted
//! against the pre-reload secret is rejected afterwards while a token minted
//! against the new secret is accepted — and nothing else (boot-only knobs) is
//! disturbed.
//!
//! The signal itself is `cfg(unix)` and cannot be delivered to a child on
//! Windows CI, so the reload is applied through the same entry point the
//! signal handler uses (`AppState::apply_reload`, fed by `config::load`), and
//! the request path is then driven with real HMAC headers.

use axum::http::{HeaderMap, HeaderName, HeaderValue};

use cachette::auth::hmac;
use cachette::config::Config;
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
