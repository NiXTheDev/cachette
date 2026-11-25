//! Storage capabilities and the blob-store seam (v1.3).
//!
//! [`StorageBackend`](super::StorageBackend) owns the index, reservations,
//! parts and CDC chunks. The payload bytes of `whole` entries go through a
//! [`BlobStore`] instead: a local directory for `type = "fs"`, or a remote
//! object store behind a small read-through cache for the whole-blob backends.
//!
//! A backend advertises what it can actually do through [`Capabilities`].
//! Validation asks those capabilities rather than switching on the config
//! `type`, so a new backend cannot silently promise CDC it does not implement.

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::sync::Mutex;

use crate::config::{StorageInstanceConfig, StorageKind};

pub use super::BoxFuture;

/// What a storage backend can do with payloads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Capabilities {
    /// Content-defined chunking: the index may store a chunk manifest instead
    /// of a single whole blob. Remote whole-blob stores leave this off.
    pub chunked: bool,
    /// Byte-range reads are supported by the remote store. A false value is
    /// still readable (the cache fetches the whole object), just wasteful.
    pub ranged: bool,
    /// Publishing is atomic at the store itself. Remote stores stage locally
    /// and commit the index row only after the upload succeeds instead.
    pub atomic_commit: bool,
}

impl Capabilities {
    /// Local filesystem: chunk manifests, native range reads, atomic rename.
    pub const FS: Self = Self {
        chunked: true,
        ranged: true,
        atomic_commit: true,
    };

    /// Remote whole-blob stores: no CDC, HTTP range reads, emulated commit.
    pub const REMOTE: Self = Self {
        chunked: false,
        ranged: true,
        atomic_commit: false,
    };
}

/// Capabilities implied by a config `type`. Kept here so validation and the
/// backend constructor agree on one table.
#[must_use]
pub const fn capabilities_for(kind: StorageKind) -> Capabilities {
    match kind {
        StorageKind::Fs => Capabilities::FS,
        StorageKind::S3
        | StorageKind::WebDav
        | StorageKind::CopyParty
        | StorageKind::Azure
        | StorageKind::Ftp
        | StorageKind::Sftp => Capabilities::REMOTE,
    }
}

/// Where the bytes of a `whole` entry actually live.
pub trait BlobStore: Send + Sync {
    /// What this store can do.
    fn capabilities(&self) -> Capabilities;

    /// Whether a missing local blob file means a missing entry. Local stores
    /// say yes; remote stores keep a read-through cache and say no, because
    /// the authoritative copy lives elsewhere.
    fn local_authoritative(&self) -> bool {
        true
    }

    /// Human-readable store name for logs and errors.
    fn name(&self) -> &'static str;

    /// Push the blob at `path` to its authoritative home. Called after the
    /// index commit; on failure the caller compensates by dropping the row.
    fn publish<'a>(&'a self, id: &'a str, path: &'a Path) -> BoxFuture<'a, io::Result<()>>;

    /// Make `len` bytes starting at `offset` available in the local cache file.
    /// Local stores only have to check it exists.
    fn fetch_range<'a>(
        &'a self,
        id: &'a str,
        path: &'a Path,
        offset: u64,
        len: u64,
    ) -> BoxFuture<'a, io::Result<()>>;

    /// Drop idle per-object hint state. Remote stores use this to keep their
    /// lock map from growing with every object ever fetched.
    fn sweep_locks(&self) -> u64 {
        0
    }

    /// Remove the authoritative copy (the local cache file is removed by the
    /// caller). No-op for local stores.
    fn remove<'a>(&'a self, id: &'a str) -> BoxFuture<'a, io::Result<()>> {
        let _ = id;
        Box::pin(async { Ok(()) })
    }
}

/// The plain local `blobs/{id}.blob` store.
#[derive(Clone, Copy, Debug, Default)]
pub struct FsBlobStore;

impl BlobStore for FsBlobStore {
    fn capabilities(&self) -> Capabilities {
        Capabilities::FS
    }

    fn name(&self) -> &'static str {
        "fs"
    }

    fn publish<'a>(&'a self, id: &'a str, path: &'a Path) -> BoxFuture<'a, io::Result<()>> {
        let _ = id;
        let exists = path.exists();
        Box::pin(async move {
            if exists {
                Ok(())
            } else {
                Err(super::not_found("<blob>"))
            }
        })
    }

    fn fetch_range<'a>(
        &'a self,
        id: &'a str,
        path: &'a Path,
        offset: u64,
        len: u64,
    ) -> BoxFuture<'a, io::Result<()>> {
        let _ = (offset, len);
        let exists = path.is_file();
        let id = id.to_owned();
        Box::pin(async move {
            if exists {
                Ok(())
            } else {
                Err(super::not_found(&id))
            }
        })
    }
}

/// The operations a remote store must provide. Split out from [`BlobStore`]
/// so the cache/locking behaviour is written once for every backend.
pub trait RemoteOps: Send + Sync {
    /// Backend name for logs.
    fn name(&self) -> &'static str;

    /// Upload the local file to the authoritative object.
    fn put<'a>(&'a self, id: &'a str, path: &'a Path) -> BoxFuture<'a, io::Result<()>>;

    /// Download exactly `[offset, offset + len)` into `path`. The file is
    /// created or extended to cover the range; already-cached bytes must be
    /// left untouched.
    fn get_range<'a>(
        &'a self,
        id: &'a str,
        path: &'a Path,
        offset: u64,
        len: u64,
    ) -> BoxFuture<'a, io::Result<()>>;

    /// Delete the authoritative object.
    fn delete<'a>(&'a self, id: &'a str) -> BoxFuture<'a, io::Result<()>>;
}

/// Remote blob store with a local read-through cache under `blobs/`.
///
/// Writes stage and publish locally first (the index's B5 ordering), then the
/// upload runs; the cache file is dropped once the upload succeeds. Reads
/// fetch only the requested byte range into the sparse cache file, so a ranged
/// request never downloads a whole artifact.
pub struct CachedRemoteStore {
    ops: Arc<dyn RemoteOps>,
    /// Per-id lock so two concurrent range reads cannot write one cache file.
    locks: std::sync::RwLock<HashMap<String, Arc<Mutex<()>>>>,
    /// Byte ranges known to be present in each cache file. Length alone is
    /// not enough: a mid-file write leaves sparse zeros before its offset.
    coverage: std::sync::Mutex<HashMap<String, Vec<(u64, u64)>>>,
}

impl CachedRemoteStore {
    #[must_use]
    pub fn new(ops: Arc<dyn RemoteOps>) -> Self {
        Self {
            ops,
            locks: std::sync::RwLock::new(HashMap::new()),
            coverage: std::sync::Mutex::new(HashMap::new()),
        }
    }

    fn lock_for(&self, id: &str) -> Arc<Mutex<()>> {
        {
            let locks = self.locks.read().expect("lock map poisoned");
            if let Some(lock) = locks.get(id) {
                return Arc::clone(lock);
            }
        }
        let mut locks = self.locks.write().expect("lock map poisoned");
        Arc::clone(locks.entry(id.to_owned()).or_default())
    }

    fn covers(ranges: &[(u64, u64)], offset: u64, end: u64) -> bool {
        ranges
            .iter()
            .any(|&(start, stop)| start <= offset && end <= stop)
    }

    fn record_covered(&self, id: &str, start: u64, end: u64) {
        let mut all = self.coverage.lock().expect("coverage poisoned");
        let ranges = all.entry(id.to_owned()).or_default();
        ranges.retain(|&(from, to)| to < start || from > end);
        ranges.push((start, end));
        ranges.sort_unstable();
    }

    async fn forget(&self, id: &str) {
        self.coverage.lock().expect("coverage poisoned").remove(id);
        // Drop the per-id lock once no one holds or waits on it, so the hint
        // map cannot grow with the number of objects ever fetched.
        let removable = {
            let locks = self.locks.read().expect("lock map poisoned");
            locks
                .get(id)
                .is_some_and(|lock| Arc::strong_count(lock) == 1)
        };
        if removable {
            let mut locks = self.locks.write().expect("lock map poisoned");
            if locks
                .get(id)
                .is_some_and(|lock| Arc::strong_count(lock) == 1)
            {
                locks.remove(id);
            }
        }
    }
}

impl std::fmt::Debug for CachedRemoteStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedRemoteStore")
            .field("backend", &self.ops.name())
            .finish_non_exhaustive()
    }
}

impl BlobStore for CachedRemoteStore {
    fn capabilities(&self) -> Capabilities {
        Capabilities::REMOTE
    }

    fn local_authoritative(&self) -> bool {
        false
    }

    fn name(&self) -> &'static str {
        self.ops.name()
    }

    fn publish<'a>(&'a self, id: &'a str, path: &'a Path) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async move {
            {
                let lock = self.lock_for(id);
                let _guard = lock.lock().await;
                self.ops.put(id, path).await?;
                // The remote object is authoritative now; keeping the local
                // copy would double the footprint and make `du` misleading.
                let _ = tokio::fs::remove_file(path).await;
            }
            self.forget(id).await;
            Ok(())
        })
    }

    fn fetch_range<'a>(
        &'a self,
        id: &'a str,
        path: &'a Path,
        offset: u64,
        len: u64,
    ) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async move {
            let end = offset.saturating_add(len);
            let covered = {
                let all = self.coverage.lock().expect("coverage poisoned");
                all.get(id)
                    .is_some_and(|ranges| Self::covers(ranges, offset, end))
            };
            if covered {
                return Ok(());
            }
            let lock = self.lock_for(id);
            let _guard = lock.lock().await;
            // Re-check under the lock: another waiter may have filled it.
            let covered = {
                let all = self.coverage.lock().expect("coverage poisoned");
                all.get(id)
                    .is_some_and(|ranges| Self::covers(ranges, offset, end))
            };
            if covered {
                return Ok(());
            }
            if let Some(parent) = path.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
            // Always fill from byte 0 through `end`. A mid-file fetch would
            // otherwise leave a sparse hole before `offset`, and a later
            // earlier-range read would serve those zeros as real bytes.
            // Coverage is in-memory only, so after a restart the prefix is
            // downloaded again rather than trusting a stale cache file.
            self.ops.get_range(id, path, 0, end).await?;
            self.record_covered(id, 0, end);
            Ok(())
        })
    }

    fn sweep_locks(&self) -> u64 {
        let mut locks = self.locks.write().expect("lock map poisoned");
        let before = locks.len();
        locks.retain(|_, lock| Arc::strong_count(lock) > 1);
        (before - locks.len()) as u64
    }

    fn remove<'a>(&'a self, id: &'a str) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async move {
            self.ops.delete(id).await?;
            self.forget(id).await;
            Ok(())
        })
    }
}

/// Local cache path for one remote object (kept distinct from a native blob
/// so a backend switch cannot mistake one for the other).
#[must_use]
pub fn cache_path(root: &Path, id: &str) -> PathBuf {
    root.join("blobs").join(format!("{id}.blob"))
}

/// Build the payload store for one `[[storage.instances]]` entry.
pub fn from_config(instance: &StorageInstanceConfig) -> io::Result<Arc<dyn BlobStore>> {
    let password = instance
        .password_file
        .as_ref()
        .map(|path| {
            std::fs::read_to_string(path).map(|text| text.trim_end_matches(['\r', '\n']).to_owned())
        })
        .transpose()?;
    let ca_pem = instance.ca_pem.as_deref();
    let remote_url = |url: &str| -> String {
        match instance.prefix.as_deref() {
            Some(prefix) if !prefix.is_empty() => {
                format!("{}/{}", url.trim_end_matches('/'), prefix.trim_matches('/'))
            }
            _ => url.to_owned(),
        }
    };
    let remote: Arc<dyn RemoteOps> = match instance.kind {
        StorageKind::Fs => return Ok(Arc::new(FsBlobStore)),
        StorageKind::S3 => Arc::new(super::s3::S3Ops::new(
            super::s3::S3Config {
                bucket: instance.bucket.clone().unwrap_or_default(),
                region: instance
                    .region
                    .clone()
                    .unwrap_or_else(|| String::from("us-east-1")),
                endpoint: instance.endpoint.clone(),
                prefix: instance.prefix.clone(),
                access_key: instance.access_key.clone(),
                secret_key: instance.secret_key.clone(),
            },
            ca_pem,
        )?),
        StorageKind::WebDav => Arc::new(super::webdav::WebDavOps::new(
            super::webdav::WebDavConfig {
                url: remote_url(instance.url.as_deref().unwrap_or_default()),
                username: instance.username.clone(),
                password: password.clone(),
            },
            ca_pem,
        )?),
        StorageKind::CopyParty => Arc::new(super::copyparty::CopyPartyOps::new(
            super::copyparty::CopyPartyConfig {
                url: remote_url(instance.url.as_deref().unwrap_or_default()),
                password: password.clone(),
                username: instance.username.clone(),
                wsalt: instance
                    .wsalt
                    .clone()
                    .unwrap_or_else(|| String::from("hunter2")),
            },
            ca_pem,
        )?),
        StorageKind::Azure => Arc::new(super::azure::AzureOps::new(
            super::azure::AzureConfig {
                account: instance.account.clone().unwrap_or_default(),
                container: instance.container.clone().unwrap_or_default(),
                endpoint: instance.endpoint.clone(),
                prefix: instance.prefix.clone(),
                key: instance.access_key.clone().unwrap_or_default(),
            },
            ca_pem,
        )?),
        StorageKind::Ftp => Arc::new(super::ftp::FtpOps::new(super::ftp::FtpConfig {
            url: remote_url(instance.url.as_deref().unwrap_or_default()),
            username: instance.username.clone(),
            password: password.clone(),
        })),
        StorageKind::Sftp => Arc::new(super::sftp::SftpOps::new(super::sftp::SftpConfig {
            url: remote_url(instance.url.as_deref().unwrap_or_default()),
            username: instance.username.clone(),
            private_key_file: instance.private_key_file.clone(),
        })),
    };
    Ok(Arc::new(CachedRemoteStore::new(remote)))
}

#[cfg(test)]
mod cache_coverage {
    use super::*;
    use crate::storage::http::{BodyWriter, FileWriter};

    #[derive(Default)]
    struct RecordingOps {
        calls: std::sync::Mutex<Vec<(u64, u64)>>,
    }

    impl RemoteOps for RecordingOps {
        fn name(&self) -> &'static str {
            "recording-coverage"
        }

        fn put<'a>(&'a self, id: &'a str, path: &'a Path) -> BoxFuture<'a, io::Result<()>> {
            let _ = (id, path);
            Box::pin(async { Ok(()) })
        }

        fn get_range<'a>(
            &'a self,
            id: &'a str,
            path: &'a Path,
            offset: u64,
            len: u64,
        ) -> BoxFuture<'a, io::Result<()>> {
            let _ = id;
            self.calls.lock().expect("poisoned").push((offset, len));
            let path = path.to_owned();
            Box::pin(async move {
                let mut writer = FileWriter::new(&path, offset, 0, Some(len))?;
                let bytes = vec![b'x'; len as usize];
                writer.write(&bytes)?;
                let file = tokio::fs::OpenOptions::new()
                    .create(true)
                    .truncate(false)
                    .write(true)
                    .open(&path)
                    .await?;
                if file.metadata().await?.len() < offset + len {
                    file.set_len(offset + len).await?;
                }
                Ok(())
            })
        }

        fn delete<'a>(&'a self, id: &'a str) -> BoxFuture<'a, io::Result<()>> {
            let _ = id;
            Box::pin(async { Ok(()) })
        }
    }

    #[tokio::test]
    async fn mid_file_fetch_fills_from_zero_and_tracks_coverage() {
        let ops = Arc::new(RecordingOps::default());
        let store = CachedRemoteStore::new(ops.clone());
        let dir = std::env::temp_dir().join(format!("cachette-coverage-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("blob");
        let _ = std::fs::remove_file(&path);

        store
            .fetch_range("id", &path, 10, 5)
            .await
            .expect("first fetch");
        assert_eq!(*ops.calls.lock().expect("poisoned"), vec![(0, 15)]);

        // An earlier range is covered by the prefix fetched above: no holes.
        store
            .fetch_range("id", &path, 0, 5)
            .await
            .expect("covered fetch");
        assert_eq!(*ops.calls.lock().expect("poisoned"), vec![(0, 15)]);

        // A later range extends the prefix rather than leaving a hole.
        store
            .fetch_range("id", &path, 20, 5)
            .await
            .expect("extended fetch");
        assert_eq!(*ops.calls.lock().expect("poisoned"), vec![(0, 15), (0, 25)]);

        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
pub mod test_support {
    //! A recording remote store so the index-level tests can prove the
    //! publish/fetch/remove hooks fire without a network server.

    use tokio::io::{AsyncSeekExt, AsyncWriteExt};

    use super::*;

    #[derive(Default)]
    pub struct RecordingBlobStore {
        pub published: std::sync::Mutex<Vec<String>>,
        pub fetched: std::sync::Mutex<Vec<(String, u64, u64)>>,
        pub removed: std::sync::Mutex<Vec<String>>,
        pub bytes: std::sync::Mutex<Vec<u8>>,
    }

    impl BlobStore for RecordingBlobStore {
        fn capabilities(&self) -> Capabilities {
            Capabilities::REMOTE
        }

        fn local_authoritative(&self) -> bool {
            false
        }

        fn name(&self) -> &'static str {
            "recording"
        }

        fn publish<'a>(&'a self, id: &'a str, path: &'a Path) -> BoxFuture<'a, io::Result<()>> {
            self.published.lock().expect("poisoned").push(id.to_owned());
            let path = path.to_owned();
            Box::pin(async move {
                let _ = tokio::fs::remove_file(&path).await;
                Ok(())
            })
        }

        fn fetch_range<'a>(
            &'a self,
            id: &'a str,
            path: &'a Path,
            offset: u64,
            len: u64,
        ) -> BoxFuture<'a, io::Result<()>> {
            self.fetched
                .lock()
                .expect("poisoned")
                .push((id.to_owned(), offset, len));
            let bytes = self.bytes.lock().expect("poisoned").clone();
            let path = path.to_owned();
            Box::pin(async move {
                let mut file = tokio::fs::OpenOptions::new()
                    .create(true)
                    .truncate(false)
                    .write(true)
                    .open(&path)
                    .await?;
                file.seek(std::io::SeekFrom::Start(offset)).await?;
                let end = (offset + len).min(bytes.len() as u64) as usize;
                file.write_all(&bytes[offset as usize..end]).await?;
                file.set_len(offset + len).await?;
                Ok(())
            })
        }

        fn remove<'a>(&'a self, id: &'a str) -> BoxFuture<'a, io::Result<()>> {
            self.removed.lock().expect("poisoned").push(id.to_owned());
            Box::pin(async { Ok(()) })
        }
    }
}
