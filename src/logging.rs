//! Tracing subscriber installation (plan task 4/35) and live level reload
//! (plan task 49).
//!
//! One `fmt` subscriber, filtered by `RUST_LOG` (default: `[log] level`),
//! installed exactly once for the whole process. `RUST_LOG` parsing is lossy:
//! an unset or malformed variable falls back to the configured level instead of
//! aborting startup.
//!
//! The filter sits behind a [`tracing_subscriber::reload`] layer, so a SIGHUP
//! config reload ([`reload_level`]) can swap the level in place without
//! reinstalling the subscriber or dropping any connections.

use std::path::PathBuf;
use std::sync::{Once, OnceLock};

use tracing_subscriber::EnvFilter;
use tracing_subscriber::Registry;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::fmt;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::reload;
use tracing_subscriber::util::SubscriberInitExt;

use crate::config::LogLevel;

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

/// The reload handle for the installed `EnvFilter` (plan task 49). Set once by
/// [`init`]; [`reload_level`] swaps the filter through it.
static FILTER: OnceLock<reload::Handle<EnvFilter, Registry>> = OnceLock::new();

/// Build the `EnvFilter`: `[log] level` as the default directive, with an
/// explicitly set `RUST_LOG` winning (lossy parse — malformed values fall back).
fn build_filter(level: LogLevel) -> EnvFilter {
    EnvFilter::builder()
        .with_default_directive(level_filter(level).into())
        .from_env_lossy()
}

/// Map a config [`LogLevel`] to a tracing [`LevelFilter`].
const fn level_filter(level: LogLevel) -> LevelFilter {
    match level {
        LogLevel::Trace => LevelFilter::TRACE,
        LogLevel::Debug => LevelFilter::DEBUG,
        LogLevel::Info => LevelFilter::INFO,
        LogLevel::Warn => LevelFilter::WARN,
        LogLevel::Error => LevelFilter::ERROR,
    }
}

/// Install the `fmt` subscriber filtered by `RUST_LOG` (default `level`).
///
/// Idempotent: only the first call installs a subscriber — subsequent calls
/// (tests, re-entry) are silent no-ops and never panic, and a failure to
/// install (e.g. a subscriber already set by a test harness) is reported on
/// stderr rather than aborting the process.
pub fn init(format: LogFormat, file: Option<PathBuf>, level: LogLevel) {
    INIT.call_once(|| {
        // Resolve the writer first so the reload handle is set exactly once.
        let file_writer = file.and_then(|path| match open_log_file(&path) {
            Ok(f) => Some(f),
            Err(err) => {
                eprintln!(
                    "cachette: failed to open log file {}: {err}",
                    path.display()
                );
                None
            }
        });
        let (filter_layer, handle) = reload::Layer::new(build_filter(level));
        let _ = FILTER.set(handle);
        match file_writer {
            Some(f) => install(filter_layer, format, f),
            None => install(filter_layer, format, std::io::stdout),
        }
    });
}

/// Layer the reloadable filter and the `fmt` writer together and install.
fn install<W>(filter_layer: reload::Layer<EnvFilter, Registry>, format: LogFormat, writer: W)
where
    W: for<'writer> fmt::MakeWriter<'writer> + Send + Sync + 'static,
{
    let base = tracing_subscriber::registry().with(filter_layer);
    let installed = match format {
        LogFormat::Text => base.with(fmt::layer().with_writer(writer)).try_init(),
        LogFormat::Json => base
            .with(fmt::layer().with_writer(writer).json())
            .try_init(),
    };
    if let Err(err) = installed {
        eprintln!("cachette: tracing subscriber not installed: {err}");
    }
}

/// Swap the live log level after a config reload (plan task 49). A no-op when
/// [`init`] has not installed a subscriber (tests) or when a `RUST_LOG` value
/// was set explicitly at boot — the rebuilt filter still honours `RUST_LOG`
/// first, so an operator override is preserved.
pub fn reload_level(level: LogLevel) {
    let Some(handle) = FILTER.get() else {
        return;
    };
    if let Err(err) = handle.reload(build_filter(level)) {
        eprintln!("cachette: log level reload failed: {err}");
    }
}

/// Open (creating parent directories and appending) the user-configured
/// `[log] file`. `append` mode is deliberate so a restart never truncates the
/// operator's log. Shared by [`init`] and its test.
pub(crate) fn open_log_file(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
}

#[cfg(test)]
mod tests {
    use super::{LogFormat, init, reload_level};
    use crate::config::LogLevel;

    /// Plan task 4 test guard: a second (and third) `init` call must be a
    /// silent no-op — no double-install panic, no process abort.
    #[test]
    fn init_is_idempotent_across_repeated_calls() {
        init(LogFormat::Text, None, LogLevel::Info);
        init(LogFormat::Text, None, LogLevel::Info);
        init(LogFormat::Json, None, LogLevel::Debug);
    }

    /// Plan task 49: a level reload through the installed handle must not panic
    /// (the filter behind the `reload` layer is swapped in place).
    #[test]
    fn reload_level_swaps_the_live_filter() {
        init(LogFormat::Text, None, LogLevel::Info);
        reload_level(LogLevel::Debug);
        reload_level(LogLevel::Warn);
    }

    /// Plan task 35: `log.file` creates missing parent directories and appends
    /// (never truncates) across opens.
    #[test]
    fn open_log_file_creates_parents_and_appends() {
        let dir = std::env::temp_dir().join(format!(
            "cachette-logfile-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let nested = dir.join("a").join("b").join("cachette.log");
        {
            use std::io::Write as _;
            let mut f = super::open_log_file(&nested).expect("open creates parents");
            writeln!(f, "first").expect("write");
        }
        {
            use std::io::Write as _;
            let mut f = super::open_log_file(&nested).expect("reopen appends");
            writeln!(f, "second").expect("write");
        }
        let body = std::fs::read_to_string(&nested).expect("read back");
        assert_eq!(body, "first\nsecond\n", "append, not truncate");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
