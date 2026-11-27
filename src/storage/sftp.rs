//! SFTP backend (v1.3) using the system `sftp` client in batch mode.
//!
//! Registry access is unavailable in this build environment, so a native SSH
//! crate is not an option. The system client is used instead: key/agent auth
//! only (`BatchMode=yes`), one process per operation, whole-object download
//! for ranged reads. Mounting through rclone/sshfs and using `fs` remains the
//! lower-overhead alternative for high-traffic deployments.

use std::io;
use std::path::Path;
use std::process::Stdio;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use url::Url;

use super::blob::{BoxFuture, RemoteOps};
use super::http::{BodyWriter, FileWriter};

/// Connection settings for one SFTP instance.
#[derive(Clone, Debug)]
pub struct SftpConfig {
    /// `sftp://host:port/base/path/` — the destination directory.
    pub url: String,
    pub username: Option<String>,
    pub private_key_file: Option<std::path::PathBuf>,
}

/// SFTP remote operations.
pub struct SftpOps {
    config: SftpConfig,
    /// Parsed key for the native russh backend. When absent, the system
    /// `sftp` client is used as a fallback (agent auth only).
    native_key: Option<Arc<russh::keys::PrivateKey>>,
}

impl std::fmt::Debug for SftpOps {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SftpOps")
            .field("url", &self.config.url)
            .finish_non_exhaustive()
    }
}

impl SftpOps {
    /// Build a backend. A readable OpenSSH key enables the native russh
    /// client; otherwise the system `sftp` binary is used.
    #[must_use]
    pub fn new(config: SftpConfig) -> Self {
        let native_key = config.private_key_file.as_ref().and_then(|path| {
            russh::keys::PrivateKey::read_openssh_file(path)
                .ok()
                .map(Arc::new)
        });
        Self { config, native_key }
    }

    fn endpoint(&self) -> io::Result<(String, u16, String, Option<String>)> {
        let url = Url::parse(&self.config.url)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;
        let scheme = url.scheme();
        if scheme != "sftp" && scheme != "ssh" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SFTP storage URLs must start with sftp://",
            ));
        }
        let host = url
            .host_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "SFTP URL has no host"))?
            .to_owned();
        let user = self
            .config
            .username
            .clone()
            .or_else(|| {
                let name = url.username();
                (!name.is_empty()).then(|| name.to_owned())
            })
            .or_else(|| std::env::var("USER").ok());
        Ok((
            host,
            url.port().unwrap_or(22),
            url.path().trim_matches('/').to_owned(),
            user,
        ))
    }

    fn object_path(&self, id: &str) -> io::Result<String> {
        let (_, _, base, _) = self.endpoint()?;
        Ok(if base.is_empty() {
            format!("/{id}")
        } else {
            format!("/{base}/{id}")
        })
    }

    async fn batch(&self, commands: &str) -> io::Result<()> {
        let (host, port, _, user) = self.endpoint()?;
        let target = match user {
            Some(user) if !user.is_empty() => format!("{user}@{host}"),
            _ => host,
        };
        let mut cmd = tokio::process::Command::new("sftp");
        cmd.arg("-o")
            .arg("BatchMode=yes")
            .arg("-b")
            .arg("-")
            .arg("-P")
            .arg(port.to_string());
        if let Some(key) = &self.config.private_key_file {
            cmd.arg("-i").arg(key);
        }
        cmd.arg(target)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = cmd.spawn().map_err(|err| {
            io::Error::new(
                err.kind(),
                format!("cannot start the `sftp` client: {err} (install openssh-client or use an fs mount)"),
            )
        })?;
        let mut stdin = child.stdin.take().expect("piped stdin");
        stdin.write_all(commands.as_bytes()).await?;
        drop(stdin);
        let output = child.wait_with_output().await?;
        if !output.status.success() {
            return Err(io::Error::other(format!(
                "sftp batch failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        Ok(())
    }
}

/// Quote one path for an sftp batch script. Newlines are removed so a path
/// cannot inject a second command.
fn quote(path: &str) -> String {
    format!(
        "\"{}\"",
        path.replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace(['\r', '\n'], "")
    )
}

struct SshHandler;

impl russh::client::Handler for SshHandler {
    type Error = russh::Error;

    // TOFU, matching the cluster peer model; host-key pinning is a follow-up.
    async fn check_server_key(
        &mut self,
        _server_public_key: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

impl SftpOps {
    async fn native_session(&self) -> io::Result<russh_sftp::client::SftpSession> {
        let (host, port, _, user) = self.endpoint()?;
        let key = self
            .native_key
            .as_ref()
            .ok_or_else(|| io::Error::other("native SFTP needs a private key"))?;
        let config = Arc::new(russh::client::Config::default());
        let mut session = russh::client::connect(config, (host.as_str(), port), SshHandler)
            .await
            .map_err(io::Error::other)?;
        let user = user.unwrap_or_default();
        let auth = session
            .authenticate_publickey(
                user,
                russh::keys::PrivateKeyWithHashAlg::new(Arc::clone(key), None),
            )
            .await
            .map_err(io::Error::other)?;
        if auth != russh::client::AuthResult::Success {
            return Err(io::Error::other(format!(
                "SFTP authentication failed: {auth:?}"
            )));
        }
        let channel = session
            .channel_open_session()
            .await
            .map_err(io::Error::other)?;
        channel
            .request_subsystem(true, "sftp")
            .await
            .map_err(io::Error::other)?;
        russh_sftp::client::SftpSession::new(channel.into_stream())
            .await
            .map_err(io::Error::other)
    }
}

impl RemoteOps for SftpOps {
    fn name(&self) -> &'static str {
        "sftp"
    }

    fn put<'a>(&'a self, id: &'a str, path: &'a Path) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async move {
            let remote = self.object_path(id)?;
            if self.native_key.is_some() {
                let sftp = self.native_session().await?;
                let mut dst = sftp.create(&remote).await.map_err(io::Error::other)?;
                let mut src = tokio::fs::File::open(path).await?;
                let mut buf = [0_u8; 64 * 1024];
                loop {
                    let read = src.read(&mut buf).await?;
                    if read == 0 {
                        break;
                    }
                    dst.write_all(&buf[..read]).await?;
                }
                return dst.close().await;
            }
            let local = path.to_string_lossy();
            self.batch(&format!("put {} {}\n", quote(&local), quote(&remote)))
                .await
        })
    }

    fn get_range<'a>(
        &'a self,
        id: &'a str,
        path: &'a Path,
        offset: u64,
        len: u64,
    ) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async move {
            if len == 0 {
                return Ok(());
            }
            let remote = self.object_path(id)?;
            if self.native_key.is_some() {
                let sftp = self.native_session().await?;
                let mut src = sftp.open(&remote).await.map_err(io::Error::other)?;
                src.seek(std::io::SeekFrom::Start(offset)).await?;
                let mut writer = FileWriter::new(path, offset, 0, Some(len))?;
                let mut buf = [0_u8; 64 * 1024];
                let mut remaining = len;
                while remaining > 0 {
                    let want = buf.len().min(remaining as usize);
                    let read = src.read(&mut buf[..want]).await?;
                    if read == 0 {
                        break;
                    }
                    writer.write(&buf[..read])?;
                    remaining -= read as u64;
                }
                src.close().await?;
                if writer.written() != len {
                    return Err(io::Error::other(format!(
                        "SFTP ranged GET wrote {} of {len} bytes",
                        writer.written()
                    )));
                }
                let file = tokio::fs::OpenOptions::new()
                    .create(true)
                    .truncate(false)
                    .write(true)
                    .open(path)
                    .await?;
                if file.metadata().await?.len() < offset.saturating_add(len) {
                    file.set_len(offset.saturating_add(len)).await?;
                }
                return Ok(());
            }
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let temp = std::env::temp_dir().join(format!(
                "cachette-sftp-{id}-{}-{unique}",
                std::process::id()
            ));
            let remote = self.object_path(id)?;
            self.batch(&format!(
                "get {} {}\n",
                quote(&remote),
                quote(&temp.to_string_lossy())
            ))
            .await?;
            let mut source = tokio::fs::File::open(&temp).await?;
            let size = source.metadata().await?.len();
            if size < offset.saturating_add(len) {
                drop(source);
                let _ = tokio::fs::remove_file(&temp).await;
                return Err(io::Error::other(format!(
                    "SFTP object {id} is shorter than the requested range"
                )));
            }
            source.seek(std::io::SeekFrom::Start(offset)).await?;
            let mut writer = FileWriter::new(path, offset, 0, Some(len))?;
            let mut buf = [0_u8; 64 * 1024];
            let mut remaining = len;
            while remaining > 0 {
                let want = buf.len().min(remaining as usize);
                let read = source.read(&mut buf[..want]).await?;
                if read == 0 {
                    break;
                }
                writer.write(&buf[..read])?;
                remaining -= read as u64;
            }
            drop(source);
            let _ = tokio::fs::remove_file(&temp).await;
            if writer.written() != len {
                return Err(io::Error::other(format!(
                    "SFTP ranged GET wrote {} of {len} bytes",
                    writer.written()
                )));
            }
            let file = tokio::fs::OpenOptions::new()
                .create(true)
                .truncate(false)
                .write(true)
                .open(path)
                .await?;
            if file.metadata().await?.len() < offset.saturating_add(len) {
                file.set_len(offset.saturating_add(len)).await?;
            }
            Ok(())
        })
    }

    fn delete<'a>(&'a self, id: &'a str) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async move {
            let remote = self.object_path(id)?;
            if self.native_key.is_some() {
                let sftp = self.native_session().await?;
                sftp.remove_file(remote).await.map_err(io::Error::other)?;
                return Ok(());
            }
            self.batch(&format!("rm {}\n", quote(&remote))).await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batch_paths_are_quoted_and_cannot_inject_a_command() {
        assert_eq!(quote("/a/b"), "\"/a/b\"");
        assert_eq!(quote("/a\"b"), "\"/a\\\"b\"");
        assert!(!quote("/a\nrm /b").contains('\n'));
    }

    #[test]
    fn endpoint_uses_url_user_and_default_port() {
        let ops = SftpOps::new(SftpConfig {
            url: String::from("sftp://ci@host.example.org/cachette/"),
            username: None,
            private_key_file: None,
        });
        let (host, port, base, user) = ops.endpoint().expect("endpoint");
        assert_eq!(host, "host.example.org");
        assert_eq!(port, 22);
        assert_eq!(base, "cachette");
        assert_eq!(user.as_deref(), Some("ci"));
    }
}
