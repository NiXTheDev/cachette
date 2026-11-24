//! Plain FTP backend (v1.3), passive mode, dependency-free.
//!
//! Ranged reads use `REST <offset>` + `RETR`, which most FTP servers support.
//! FTPS is not implemented here; mount an FTPS endpoint through rclone and use
//! an `fs` instance if TLS is required.

use std::io;
use std::path::Path;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use url::Url;

use super::blob::{BoxFuture, RemoteOps};
use super::http::{BodyWriter, FileWriter};

/// Connection settings for one FTP instance.
#[derive(Clone, Debug)]
pub struct FtpConfig {
    /// `ftp://host:port/base/path/` — the destination directory.
    pub url: String,
    pub username: Option<String>,
    pub password: Option<String>,
}

/// FTP remote operations. Each operation opens a fresh control connection;
/// there is no session state to keep between calls.
pub struct FtpOps {
    config: FtpConfig,
}

impl std::fmt::Debug for FtpOps {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FtpOps")
            .field("url", &self.config.url)
            .finish_non_exhaustive()
    }
}

impl FtpOps {
    #[must_use]
    pub fn new(config: FtpConfig) -> Self {
        Self { config }
    }

    fn endpoint(&self) -> io::Result<(String, u16, String)> {
        let url = Url::parse(&self.config.url)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;
        if url.scheme() != "ftp" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "FTP storage URLs must start with ftp://",
            ));
        }
        let host = url
            .host_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "FTP URL has no host"))?
            .to_owned();
        let port = url.port().unwrap_or(21);
        let base = url.path().trim_matches('/').to_owned();
        Ok((host, port, base))
    }

    fn object_path(&self, id: &str) -> io::Result<String> {
        let (_, _, base) = self.endpoint()?;
        Ok(if base.is_empty() {
            format!("/{id}")
        } else {
            format!("/{base}/{id}")
        })
    }
}

struct Control {
    reader: BufReader<TcpStream>,
}

impl Control {
    async fn connect(host: &str, port: u16) -> io::Result<Self> {
        let stream = TcpStream::connect((host, port)).await?;
        let mut control = Self {
            reader: BufReader::new(stream),
        };
        control.expect(220, "greeting").await?;
        Ok(control)
    }

    async fn command(&mut self, line: &str) -> io::Result<(u16, String)> {
        self.reader
            .get_mut()
            .write_all(format!("{line}\r\n").as_bytes())
            .await?;
        self.read_reply().await
    }

    async fn read_reply(&mut self) -> io::Result<(u16, String)> {
        loop {
            let mut line = String::new();
            if self.reader.read_line(&mut line).await? == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "FTP control connection closed",
                ));
            }
            let bytes = line.as_bytes();
            if bytes.len() < 4 || !bytes[..3].iter().all(u8::is_ascii_digit) {
                return Err(io::Error::other(format!("bad FTP reply: {line}")));
            }
            let code = line[..3].parse::<u16>().map_err(io::Error::other)?;
            if bytes[3] == b' ' {
                return Ok((code, line.trim_end().to_owned()));
            }
        }
    }

    async fn expect(&mut self, code: u16, what: &str) -> io::Result<String> {
        let (got, text) = self.read_reply().await?;
        if got != code {
            return Err(io::Error::other(format!(
                "FTP {what}: expected {code}, got {got}: {text}"
            )));
        }
        Ok(text)
    }

    async fn expect_command(&mut self, command: &str, code: u16) -> io::Result<String> {
        let (got, text) = self.command(command).await?;
        if got != code {
            return Err(io::Error::other(format!(
                "FTP {command:?}: expected {code}, got {got}: {text}"
            )));
        }
        Ok(text)
    }

    /// Enter passive mode and return the data port. EPSV is tried first;
    /// servers without it fall back to PASV. The control peer's address is
    /// always used, never the address in the PASV reply.
    async fn passive_port(&mut self) -> io::Result<u16> {
        let (epsv_code, epsv_text) = self.command("EPSV").await?;
        if epsv_code == 229 {
            let port = epsv_text
                .split(|c: char| !c.is_ascii_digit())
                .filter(|part| !part.is_empty())
                .filter_map(|part| part.parse::<u16>().ok())
                .next_back();
            if let Some(port) = port {
                return Ok(port);
            }
        }
        let text = self.expect_command("PASV", 227).await?;
        let parts: Vec<u16> = text
            .split(|c: char| !c.is_ascii_digit())
            .filter(|part| !part.is_empty())
            .filter_map(|part| part.parse::<u16>().ok())
            .collect();
        if parts.len() < 6 {
            return Err(io::Error::other(format!("bad FTP PASV reply: {text}")));
        }
        Ok(parts[4] * 256 + parts[5])
    }
}

impl FtpOps {
    async fn login(&self) -> io::Result<(Control, String, u16)> {
        let (host, port, _) = self.endpoint()?;
        let mut control = Control::connect(&host, port).await?;
        let user = self.config.username.as_deref().unwrap_or("anonymous");
        let (code, _) = control.command(&format!("USER {user}")).await?;
        if code == 331 {
            let password = self.config.password.as_deref().unwrap_or("anonymous@");
            control
                .expect_command(&format!("PASS {password}"), 230)
                .await?;
        } else if code != 230 {
            return Err(io::Error::other(format!("FTP USER reply: {code}")));
        }
        control.expect_command("TYPE I", 200).await?;
        Ok((control, host, port))
    }
}

impl RemoteOps for FtpOps {
    fn name(&self) -> &'static str {
        "ftp"
    }

    fn put<'a>(&'a self, id: &'a str, path: &'a Path) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async move {
            let (mut control, host, _) = self.login().await?;
            let port = control.passive_port().await?;
            let mut data = TcpStream::connect((host.as_str(), port)).await?;
            control
                .expect_command(&format!("STOR {}", self.object_path(id)?), 150)
                .await?;
            let mut file = tokio::fs::File::open(path).await?;
            tokio::io::copy(&mut file, &mut data).await?;
            data.shutdown().await?;
            drop(data);
            control.expect(226, "transfer complete").await?;
            Ok(())
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
            let (mut control, host, _) = self.login().await?;
            if control.command(&format!("REST {offset}")).await?.0 != 350 {
                return Err(io::Error::other(
                    "FTP server does not support REST; ranged reads unavailable",
                ));
            }
            let port = control.passive_port().await?;
            let mut data = TcpStream::connect((host.as_str(), port)).await?;
            control
                .expect_command(&format!("RETR {}", self.object_path(id)?), 150)
                .await?;
            let mut writer = FileWriter::new(path, offset, 0, Some(len))?;
            // Stream in bounded chunks; never allocate the requested range.
            let mut buf = [0_u8; 64 * 1024];
            let mut remaining = len;
            while remaining > 0 {
                let want = buf.len().min(remaining as usize);
                let read = data.read(&mut buf[..want]).await?;
                if read == 0 {
                    break;
                }
                writer.write(&buf[..read])?;
                remaining -= read as u64;
            }
            data.shutdown().await?;
            drop(data);
            control.expect(226, "transfer complete").await?;
            if writer.written() != len {
                return Err(io::Error::other(format!(
                    "FTP ranged GET wrote {} of {len} bytes",
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
            let (mut control, _, _) = self.login().await?;
            let path = self.object_path(id)?;
            let (code, text) = control.command(&format!("DELE {path}")).await?;
            if code == 550 && text.to_ascii_lowercase().contains("not found") {
                return Ok(()); // already gone; storage deletes are idempotent
            }
            if code != 250 {
                return Err(io::Error::other(format!(
                    "FTP DELE failed ({code}): {text}"
                )));
            }
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_parses_host_port_and_base_path() {
        let ops = FtpOps::new(FtpConfig {
            url: String::from("ftp://ftp.example.org/cachette/"),
            username: None,
            password: None,
        });
        let (host, port, base) = ops.endpoint().expect("endpoint");
        assert_eq!(host, "ftp.example.org");
        assert_eq!(port, 21);
        assert_eq!(base, "cachette");
        assert_eq!(
            ops.object_path("deadbeef").expect("path"),
            "/cachette/deadbeef"
        );
    }
}
