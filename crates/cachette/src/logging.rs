//! Tracing subscriber installation (plan task 4).
//!
//! One `fmt` subscriber, filtered by `RUST_LOG` (default `info`), installed
//! exactly once for the whole process. `RUST_LOG` parsing is lossy: an unset
//! or malformed variable falls back to `info` instead of aborting startup.

use std::sync::Once;

use tracing_subscriber::EnvFilter;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::fmt;

/// Log output format.
///
/// `Text` is the pretty dev default; `Json` is wired to config
/// `[log] format` in plan task 5 and is selectable today via this enum.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum LogFormat {
    /// Human-readable text lines (default).
    #[default]
    Text,
    /// One JSON object per line.
    Json,
}

/// Guards the one-time subscriber installation; later calls are no-ops.
static INIT: Once = Once::new();

/// Install the `fmt` subscriber filtered by `RUST_LOG` (default `info`).
///
/// Idempotent: only the first call installs a subscriber — subsequent calls
/// (tests, re-entry) are silent no-ops and never panic, and a failure to
/// install (e.g. a subscriber already set by a test harness) is reported on
/// stderr rather than aborting the process.
pub fn init(format: LogFormat) {
    INIT.call_once(|| {
        let filter = EnvFilter::builder()
            .with_default_directive(LevelFilter::INFO.into())
            .from_env_lossy();
        let installed = match format {
            LogFormat::Text => fmt().with_env_filter(filter).try_init(),
            LogFormat::Json => fmt().json().with_env_filter(filter).try_init(),
        };
        if let Err(err) = installed {
            eprintln!("cachette: tracing subscriber not installed: {err}");
        }
    });
}

#[cfg(test)]
mod tests {
    use super::{LogFormat, init};

    /// Plan task 4 test guard: a second (and third) `init` call must be a
    /// silent no-op — no double-install panic, no process abort.
    #[test]
    fn init_is_idempotent_across_repeated_calls() {
        init(LogFormat::Text);
        init(LogFormat::Text);
        init(LogFormat::Json);
    }
}
