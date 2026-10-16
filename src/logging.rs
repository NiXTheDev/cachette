//! Tracing subscriber installation (plan task 4/35).
//!
//! One `fmt` subscriber, filtered by `RUST_LOG` (default `info`), installed
//! exactly once for the whole process. `RUST_LOG` parsing is lossy: an unset
//! or malformed variable falls back to `info` instead of aborting startup.

use std::path::PathBuf;
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
pub fn init(format: LogFormat, file: Option<PathBuf>) {
    INIT.call_once(|| {
        let filter = EnvFilter::builder()
            .with_default_directive(LevelFilter::INFO.into())
            .from_env_lossy();
        if let Some(path) = file {
            match open_log_file(&path) {
                Ok(f) => {
                    let installed = match format {
                        LogFormat::Text => fmt().with_writer(f).with_env_filter(filter).try_init(),
                        LogFormat::Json => fmt()
                            .with_writer(f)
                            .json()
                            .with_env_filter(filter)
                            .try_init(),
                    };
                    if let Err(err) = installed {
                        eprintln!("cachette: tracing subscriber not installed: {err}");
                    }
                    return;
                }
                Err(err) => {
                    eprintln!(
                        "cachette: failed to open log file {}: {err}",
                        path.display()
                    );
                }
            }
        }
        let installed = match format {
            LogFormat::Text => fmt().with_env_filter(filter).try_init(),
            LogFormat::Json => fmt().json().with_env_filter(filter).try_init(),
        };
        if let Err(err) = installed {
            eprintln!("cachette: tracing subscriber not installed: {err}");
        }
    });
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
    use super::{LogFormat, init};

    /// Plan task 4 test guard: a second (and third) `init` call must be a
    /// silent no-op — no double-install panic, no process abort.
    #[test]
    fn init_is_idempotent_across_repeated_calls() {
        init(LogFormat::Text, None);
        init(LogFormat::Text, None);
        init(LogFormat::Json, None);
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
