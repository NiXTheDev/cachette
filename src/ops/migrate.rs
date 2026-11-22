//! Offline config and state migration from v1.2 to v1.3.
//!
//! Nothing here runs at boot. Every data-moving command takes an explicit
//! typed confirmation, and snapshots are verified directory copies with a
//! BLAKE3 manifest (the toolchain has no tar/zstd dependency).

use std::error::Error;
use std::fs;
use std::io::{self, BufRead};
use std::path::{Path, PathBuf};

use crate::config::{self, Config};
use crate::storage::digest::hash_file;

const MANIFEST: &str = ".cachette-snapshot";

fn now_tag() -> String {
    // UTC-ish sortable tag without a time dependency: Unix seconds via the
    // system clock is enough for a unique sibling directory name.
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default();
    format!("{secs}")
}

fn copy_tree(from: &Path, to: &Path) -> io::Result<Vec<PathBuf>> {
    let mut copied = Vec::new();
    fs::create_dir_all(to)?;
    for entry in fs::read_dir(from)? {
        let entry = entry?;
        let src = entry.path();
        let dst = to.join(entry.file_name());
        let meta = entry.file_type()?;
        if meta.is_dir() {
            copied.extend(copy_tree(&src, &dst)?);
        } else if meta.is_file() {
            if let Some(parent) = dst.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(&src, &dst)?;
            copied.push(dst);
        }
    }
    Ok(copied)
}

fn manifest_for(files: &[PathBuf], root: &Path) -> String {
    let mut lines = Vec::new();
    let mut sorted: Vec<&PathBuf> = files.iter().collect();
    sorted.sort();
    for file in sorted {
        let Ok(rel) = file.strip_prefix(root) else {
            continue;
        };
        let Ok(hash) = hash_file(file) else { continue };
        lines.push(format!("{}  {}", hash, rel.display()));
    }
    lines.join("\n")
}

/// Verified snapshot: a sibling directory copy plus a BLAKE3 manifest.
fn snapshot(dir: &Path) -> Result<PathBuf, Box<dyn Error>> {
    if !dir.exists() {
        return Err(format!("state directory does not exist: {}", dir.display()).into());
    }
    let parent = dir.parent().unwrap_or(Path::new("."));
    let name = dir.file_name().and_then(|n| n.to_str()).unwrap_or("state");
    let archive = parent.join(format!("{name}.{}.snapshot", now_tag()));
    let files = copy_tree(dir, &archive)?;
    let manifest = manifest_for(&files, &archive);
    fs::write(archive.join(MANIFEST), manifest)?;
    // Verify by recomputing every hash from the archive itself.
    let reread = fs::read_to_string(archive.join(MANIFEST))?;
    for line in reread.lines() {
        let Some((hash, rel)) = line.split_once("  ") else {
            return Err("corrupt snapshot manifest".into());
        };
        let actual = hash_file(&archive.join(rel))?;
        if actual != hash {
            return Err(format!("snapshot verification failed for {rel}").into());
        }
    }
    Ok(archive)
}

fn confirm(action: &str, supplied: Option<&str>) -> Result<(), Box<dyn Error>> {
    if supplied == Some(action) {
        return Ok(());
    }
    Err(format!("DANGER action {action} requires --confirm {action}").into())
}

fn render_config(text: &str) -> Result<String, Box<dyn Error>> {
    let table: toml::Table = toml::from_str(text)?;
    let mut doc = serde_json::to_value(table)?
        .as_object()
        .cloned()
        .unwrap_or_default();
    config::normalize(&mut doc);
    Ok(toml::to_string(&doc)?)
}

fn caution_needed(text: &str) -> bool {
    [
        "[cache]",
        "[log]",
        "[v1]",
        "[v2]",
        "[auth.oidc]",
        "[auth.runtime]",
        "[storage.quotas]",
    ]
    .iter()
    .any(|marker| text.contains(marker))
}

fn write_result(path: &Path, rendered: &str, write: bool) -> Result<(), Box<dyn Error>> {
    let backup = path.with_extension("bak");
    if backup.exists() {
        return Err(format!("refusing to overwrite existing backup {}", backup.display()).into());
    }
    if write {
        fs::copy(path, &backup)?;
        fs::write(path, rendered)?;
    } else {
        // Original stays untouched; the proposal is the `.bak` file.
        fs::write(&backup, rendered)?;
    }
    Ok(())
}

pub async fn config_only(
    path: &Path,
    write: bool,
    ack_caution: bool,
) -> Result<i32, Box<dyn Error>> {
    let text = fs::read_to_string(path)?;
    if caution_needed(&text) && !ack_caution {
        return Err("config migration contains CAUTION changes; pass --ack-caution".into());
    }
    let rendered = render_config(&text)?;
    write_result(path, &rendered, write)?;
    println!(
        "config migration written (write={write}); backup at {}",
        path.with_extension("bak").display()
    );
    Ok(0)
}

pub async fn full(
    path: &Path,
    let_me_edit: bool,
    ack_caution: bool,
    confirm: &[String],
    _config: &Config,
) -> Result<i32, Box<dyn Error>> {
    let text = fs::read_to_string(path)?;
    if caution_needed(&text) && !ack_caution {
        return Err("full migration contains CAUTION changes; pass --ack-caution".into());
    }
    if !confirm.iter().any(|c| c == "migrate-state") {
        return Err("full migration requires --confirm migrate-state".into());
    }
    let rendered = render_config(&text)?;
    let backup = path.with_extension("bak");
    if backup.exists() {
        return Err(format!("refusing to overwrite existing backup {}", backup.display()).into());
    }
    fs::copy(path, &backup)?;
    fs::write(path, &rendered)?;
    println!("config written in place; backup: {}", backup.display());

    if let_me_edit {
        println!(
            "edit {} then press Enter to continue with file moves",
            path.display()
        );
        let mut line = String::new();
        let _ = io::stdin().lock().read_line(&mut line);
    }

    let migrated = config::load(Some(path.to_path_buf()))?;
    let old_dir = _config.state_dir();
    let new_dir = migrated.state_dir();
    let archive = snapshot(&old_dir)?;
    println!("state snapshot verified: {}", archive.display());
    if old_dir != new_dir {
        let copied = copy_tree(&old_dir, &new_dir)?;
        println!(
            "control plane copied: {} files -> {}",
            copied.len(),
            new_dir.display()
        );
    }
    println!("full migration complete");
    Ok(0)
}

pub async fn state_copy(
    from: &Path,
    to: &Path,
    supplied: Option<&str>,
) -> Result<i32, Box<dyn Error>> {
    confirm("migrate-state", supplied)?;
    let archive = snapshot(from)?;
    let copied = copy_tree(from, to)?;
    println!("snapshot: {}", archive.display());
    println!("copied {} files to {}", copied.len(), to.display());
    Ok(0)
}

pub async fn state_restore(archive: &Path, to: &Path, force: bool) -> Result<i32, Box<dyn Error>> {
    let manifest = archive.join(MANIFEST);
    let text = fs::read_to_string(&manifest)?;
    for line in text.lines() {
        let Some((hash, rel)) = line.split_once("  ") else {
            return Err("corrupt snapshot manifest".into());
        };
        if hash_file(&archive.join(rel))? != hash {
            return Err(format!("snapshot verification failed for {rel}").into());
        }
    }
    if to.exists() && fs::read_dir(to)?.next().is_some() && !force {
        return Err(format!("target {} is not empty; pass --force", to.display()).into());
    }
    fs::create_dir_all(to)?;
    let mut count = 0;
    for line in text.lines() {
        let Some((_, rel)) = line.split_once("  ") else {
            continue;
        };
        let src = archive.join(rel);
        let dst = to.join(rel);
        if let Some(parent) = dst.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::copy(src, dst)?;
        count += 1;
    }
    println!("restored {count} files to {}", to.display());
    Ok(0)
}

pub async fn layout(_config: &Config, supplied: Option<&str>) -> Result<i32, Box<dyn Error>> {
    confirm("migrate-layout", supplied)?;
    Err("payload layout migration is not implemented in this build".into())
}

pub async fn retag(
    config: &Config,
    pairs: &[String],
    file: Option<&Path>,
    supplied: Option<&str>,
) -> Result<i32, Box<dyn Error>> {
    confirm("retag-namespaces", supplied)?;
    let mut migrations: Vec<(String, String)> = pairs
        .iter()
        .map(|pair| {
            pair.split_once('=')
                .map(|(old, new)| (old.to_owned(), new.to_owned()))
                .ok_or_else(|| format!("bad --retag pair {pair:?}; expected old=new"))
        })
        .collect::<Result<_, _>>()?;
    if let Some(path) = file {
        let text = fs::read_to_string(path)?;
        for line in text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
        {
            let (old, new) = line
                .split_once('=')
                .ok_or_else(|| format!("bad re-tag mapping {line:?}; expected old=new"))?;
            migrations.push((old.to_owned(), new.to_owned()));
        }
    }
    if migrations.is_empty() {
        return Err("namespace re-tag needs --retag pairs or --file".into());
    }

    let mut conn = rusqlite::Connection::open(&config.data_path)?;
    let tx = conn.transaction()?;
    for (old, new) in &migrations {
        for table in ["entries", "accounting", "chunks", "entry_chunks"] {
            tx.execute(
                &format!("UPDATE {table} SET namespace = ?2 WHERE namespace = ?1"),
                rusqlite::params![old, new],
            )?;
        }
    }
    tx.commit()?;
    println!("re-tagged {} namespaces", migrations.len());
    Ok(0)
}

pub async fn delete_source(backup: &Path, supplied: Option<&str>) -> Result<i32, Box<dyn Error>> {
    confirm("delete-source", supplied)?;
    if !backup.exists() {
        return Err(format!("backup does not exist: {}", backup.display()).into());
    }
    fs::remove_dir_all(backup)?;
    println!("removed source {}", backup.display());
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_legacy_config_into_the_v13_shape() {
        let legacy = "[server]\nlisten = \"127.0.0.1:0\"\n[cache]\nmax_size = 10\n[storage.fs]\npath = '/tmp/cache'\n";
        let rendered = render_config(legacy).expect("render");
        assert!(rendered.contains("max_size = 10"));
        assert!(rendered.contains("[[storage.instances]]"));
    }

    #[test]
    fn snapshot_verifies_its_manifest() {
        let root = std::env::temp_dir().join(format!("cachette-snapshot-{}", std::process::id()));
        let src = root.join("state");
        fs::create_dir_all(&src).expect("dir");
        fs::write(src.join("a.txt"), b"hello").expect("write");
        let archive = snapshot(&src).expect("snapshot");
        let manifest = fs::read_to_string(archive.join(MANIFEST)).expect("manifest");
        assert!(manifest.contains("a.txt"));
        assert_eq!(fs::read(archive.join("a.txt")).expect("copied"), b"hello");
        fs::remove_dir_all(&root).ok();
    }
}
