//! Native copyparty backend using its up2k protocol (v1.3).
//!
//! up2k is chunked on the wire but stores whole files on the server, so it
//! complements cachette's local CDC: the index and chunk manifests stay on
//! the node, while whole `whole`-layout blobs are uploaded by content hash.
//! A handshake tells us which chunks copyparty is missing; only those are
//! sent, and a second handshake detects files it already had (including its
//! server-side hardlink dedup).

use std::io;
use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use sha2::{Digest, Sha512};
use tokio::io::AsyncReadExt;
use url::Url;

use super::blob::{BoxFuture, RemoteOps};
use super::http::{Body, FileWriter, HttpClient};

/// Connection settings for one copyparty instance.
#[derive(Clone, Debug)]
pub struct CopyPartyConfig {
    /// Destination folder URL, e.g. `https://copyparty.example.org/cachette/`.
    pub url: String,
    /// copyparty `PW` header (password, or `user:password`).
    pub password: Option<String>,
    /// Optional HTTP basic-auth credentials.
    pub username: Option<String>,
    /// File-ID salt; must match the server's `--wsalt` for stable warks.
    pub wsalt: String,
}

/// One up2k chunk: base64url(SHA-512[:33]) plus its place in the file.
#[derive(Clone, Debug)]
struct ChunkId {
    hash: String,
    offset: u64,
    size: u64,
}

/// up2k's chunk-size ladder (from `u2c.py::up2k_chunksize`).
fn up2k_chunksize(filesize: u64) -> u64 {
    let mut chunksize = 1024 * 1024_u64;
    let mut stepsize = 512 * 1024_u64;
    loop {
        for mul in [1_u64, 2] {
            let nchunks = filesize.div_ceil(chunksize).max(1);
            if nchunks <= 256 || (chunksize >= 32 * 1024 * 1024 && nchunks <= 4096) {
                return chunksize;
            }
            chunksize += stepsize;
            stepsize *= mul;
        }
    }
}

/// Hash one chunk the way up2k does: SHA-512, first 33 bytes, base64url no pad.
fn up2k_hash(bytes: &[u8]) -> String {
    let digest = Sha512::digest(bytes);
    URL_SAFE_NO_PAD.encode(&digest[..33])
}

async fn hashlist(path: &Path, size: u64) -> io::Result<Vec<ChunkId>> {
    let chunk_size = up2k_chunksize(size);
    let mut file = tokio::fs::File::open(path).await?;
    let mut chunks = Vec::with_capacity(size.div_ceil(chunk_size) as usize);
    let mut offset = 0_u64;
    while offset < size {
        let len = chunk_size.min(size - offset);
        let mut buf = vec![0_u8; len as usize];
        file.read_exact(&mut buf).await?;
        chunks.push(ChunkId {
            hash: up2k_hash(&buf),
            offset,
            size: len,
        });
        offset += len;
    }
    Ok(chunks)
}

#[derive(Debug, Deserialize)]
struct Handshake {
    /// Chunk hashes the server still needs. Empty means already complete.
    #[serde(default)]
    hash: Vec<String>,
    /// Path the chunk POSTs go to.
    #[serde(default)]
    purl: String,
    /// File identifier returned by the server.
    #[serde(default)]
    wark: String,
}

/// Native copyparty remote operations.
pub struct CopyPartyOps {
    client: HttpClient,
    config: CopyPartyConfig,
}

impl std::fmt::Debug for CopyPartyOps {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CopyPartyOps")
            .field("url", &self.config.url)
            .finish_non_exhaustive()
    }
}

impl CopyPartyOps {
    /// Connect with the CA bundle configured on the instance (https only).
    pub fn new(config: CopyPartyConfig, ca_pem: Option<&Path>) -> io::Result<Self> {
        Ok(Self {
            client: HttpClient::new(ca_pem)?,
            config,
        })
    }

    fn auth_headers(&self) -> Vec<(&'static str, String)> {
        let mut headers = Vec::new();
        if let Some(password) = &self.config.password {
            headers.push(("PW", password.clone()));
        }
        if let Some(username) = &self.config.username {
            let password = self.config.password.as_deref().unwrap_or_default();
            // Basic auth uses standard base64, not the URL-safe alphabet.
            let token =
                base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"));
            headers.push(("Authorization", format!("Basic {token}")));
        }
        headers
    }

    /// URL of the stored object. The configured URL is a destination folder;
    /// cachette stores each blob under its hex entry id inside it.
    fn object_url(&self, id: &str) -> io::Result<String> {
        let mut url = Url::parse(&self.config.url)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;
        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|_| io::Error::other("copyparty URL cannot be a base"))?;
            segments.pop_if_empty().push(id);
        }
        Ok(url.to_string())
    }

    /// Relative path used by copyparty's `?delete` endpoint.
    fn object_relpath(&self, id: &str) -> io::Result<String> {
        let url = Url::parse(&self.config.url)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;
        let prefix = url.path().trim_matches('/');
        Ok(if prefix.is_empty() {
            id.to_owned()
        } else {
            format!("{prefix}/{id}")
        })
    }
}

impl RemoteOps for CopyPartyOps {
    fn name(&self) -> &'static str {
        "copyparty"
    }

    fn put<'a>(&'a self, id: &'a str, path: &'a Path) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async move {
            let size = tokio::fs::metadata(path).await?.len();
            let chunks = hashlist(path, size).await?;
            let mut headers = self.auth_headers();
            headers.push(("Content-Type", String::from("application/json")));
            let request = serde_json::json!({
                "hash": chunks.iter().map(|c| c.hash.as_str()).collect::<Vec<_>>(),
                "name": id,
                "lmod": 0,
                "size": size,
                "replace": true,
            })
            .to_string();
            let response = self
                .client
                .send(
                    "POST",
                    &self.config.url,
                    headers.clone(),
                    Body::Bytes(request.as_bytes()),
                )
                .await?;
            if !response.is_ok() {
                return Err(io::Error::other(format!(
                    "copyparty handshake failed ({}): {}",
                    response.status,
                    response.text()
                )));
            }
            let handshake: Handshake = serde_json::from_slice(&response.body)
                .map_err(|err| io::Error::other(format!("bad copyparty handshake reply: {err}")))?;
            if handshake.hash.is_empty() {
                return Ok(()); // already stored (often via hardlink dedup)
            }
            let base = Url::parse(&self.config.url)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;
            let target = if handshake.purl.is_empty() {
                self.object_url(id)?
            } else {
                base.join(&handshake.purl)
                    .map(|url| url.to_string())
                    .unwrap_or_else(|_| self.object_url(id).unwrap_or_default())
            };
            let by_hash: std::collections::HashMap<&str, &ChunkId> = chunks
                .iter()
                .map(|chunk| (chunk.hash.as_str(), chunk))
                .collect();
            for missing in &handshake.hash {
                let Some(chunk) = by_hash.get(missing.as_str()) else {
                    return Err(io::Error::other(format!(
                        "copyparty requested unknown chunk {missing}"
                    )));
                };
                let mut upload_headers = self.auth_headers();
                upload_headers.push(("Content-Type", String::from("application/octet-stream")));
                upload_headers.push(("X-Up2k-Hash", missing.clone()));
                upload_headers.push(("X-Up2k-Wark", handshake.wark.clone()));
                let reply = self
                    .client
                    .send(
                        "POST",
                        &target,
                        upload_headers,
                        Body::FileRange {
                            path,
                            offset: chunk.offset,
                            len: chunk.size,
                        },
                    )
                    .await?;
                if !reply.is_ok() {
                    return Err(io::Error::other(format!(
                        "copyparty chunk upload failed ({}): {}",
                        reply.status,
                        reply.text()
                    )));
                }
            }
            // u2c.py re-handshakes after the chunk POSTs so the server
            // finalizes the file. An empty missing set confirms it is stored;
            // 409 is the server's "already exists" success case.
            let finalize = self
                .client
                .send(
                    "POST",
                    &self.config.url,
                    headers,
                    Body::Bytes(request.as_bytes()),
                )
                .await?;
            if finalize.status == 409 {
                return Ok(());
            }
            if !finalize.is_ok() {
                return Err(io::Error::other(format!(
                    "copyparty finalize handshake failed ({}): {}",
                    finalize.status,
                    finalize.text()
                )));
            }
            if let Ok(reply) = serde_json::from_slice::<Handshake>(&finalize.body)
                && !reply.hash.is_empty()
            {
                return Err(io::Error::other(
                    "copyparty did not finalize the uploaded file",
                ));
            }
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
            let url = self.object_url(id)?;
            let mut headers = self.auth_headers();
            let end = offset.saturating_add(len).saturating_sub(1);
            headers.push(("Range", format!("bytes={offset}-{end}")));
            let mut writer = FileWriter::new(path, offset, 0, Some(len))?;
            let response = self
                .client
                .send_to("GET", &url, headers, Body::Empty, &mut writer)
                .await?;
            if response.status == 404 {
                return Err(super::not_found(id));
            }
            if !response.is_ok() {
                return Err(io::Error::other(format!(
                    "copyparty read failed ({}): {}",
                    response.status,
                    response.text()
                )));
            }
            if writer.written() != len {
                return Err(io::Error::other(format!(
                    "copyparty ranged GET wrote {} of {len} bytes (status {}, content-range {:?})",
                    writer.written(),
                    response.status,
                    response.header("content-range")
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
            let mut url = Url::parse(&self.config.url)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;
            // u2c.py posts to `/?delete`: an empty path with `delete` as the
            // query key, not a path segment containing a literal '?'.
            url.set_path("/");
            url.set_query(Some("delete"));
            let mut headers = self.auth_headers();
            headers.push(("Content-Type", String::from("application/json")));
            let body = serde_json::json!([self.object_relpath(id)?]).to_string();
            let response = self
                .client
                .send("POST", url.as_str(), headers, Body::Bytes(body.as_bytes()))
                .await?;
            if response.status == 404 {
                return Ok(()); // already gone; storage deletes are idempotent
            }
            if !response.is_ok() {
                return Err(io::Error::other(format!(
                    "copyparty delete failed ({}): {}",
                    response.status,
                    response.text()
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
    fn chunk_size_matches_up2k_ladder() {
        assert_eq!(up2k_chunksize(1024), 1024 * 1024);
        assert_eq!(up2k_chunksize(256 * 1024 * 1024), 1024 * 1024);
        // Just past the 256-chunk threshold, the ladder steps up.
        assert_eq!(up2k_chunksize(257 * 1024 * 1024), 1536 * 1024);
    }

    #[test]
    fn chunk_hashes_are_33_byte_base64url() {
        let hash = up2k_hash(b"hello world");
        assert_eq!(hash.len(), 44, "{hash}");
        assert!(!hash.contains('+') && !hash.contains('/') && !hash.contains('='));
        assert_eq!(URL_SAFE_NO_PAD.decode(&hash).expect("decode").len(), 33);
    }

    /// Minimal single-connection HTTP peer that records requests and answers
    /// with fixed replies, so the up2k handshake is exercised without a real
    /// copyparty server.
    async fn mock_peer(
        replies: Vec<(u16, String)>,
    ) -> (String, tokio::task::JoinHandle<Vec<String>>) {
        use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let url = format!("http://{}/cachette/", listener.local_addr().expect("addr"));
        let handle = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("accept");
            let mut stream = BufReader::new(socket);
            let mut seen = Vec::new();
            for (status, body) in replies {
                let mut head = String::new();
                loop {
                    let mut line = String::new();
                    let read = stream.read_line(&mut line).await.expect("head line");
                    if read == 0 {
                        break;
                    }
                    head.push_str(&line);
                    if line == "\r\n" {
                        break;
                    }
                }
                let len = head
                    .lines()
                    .find_map(|line| {
                        let (key, value) = line.split_once(':')?;
                        key.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())
                            .flatten()
                    })
                    .unwrap_or(0);
                let mut payload = vec![0_u8; len];
                stream.read_exact(&mut payload).await.expect("body");
                seen.push(format!("{head}{}", String::from_utf8_lossy(&payload)));
                let response = format!(
                    "HTTP/1.1 {status} OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream
                    .get_mut()
                    .write_all(response.as_bytes())
                    .await
                    .expect("reply");
            }
            seen
        });
        (url, handle)
    }

    #[tokio::test]
    async fn handshake_skips_upload_when_copyparty_already_has_the_blob() {
        let payload = b"hello remote";
        let chunk = up2k_hash(payload);
        let reply = serde_json::json!({
            "hash": [],
            "purl": "/cachette/object",
            "name": "object",
            "wark": "wark",
        })
        .to_string();
        let (url, server) = mock_peer(vec![(200, reply)]).await;
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("cachette-up2c-{}-{seq}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("blob");
        std::fs::write(&path, payload).expect("write");
        let ops = CopyPartyOps::new(
            CopyPartyConfig {
                url,
                password: Some(String::from("s3cret")),
                username: None,
                wsalt: String::from("hunter2"),
            },
            None,
        )
        .expect("client");
        ops.put("deadbeef", &path).await.expect("put");
        let requests = server.await.expect("join");
        assert_eq!(requests.len(), 1);
        assert!(requests[0].contains("PW: s3cret"), "{}", requests[0]);
        assert!(
            requests[0].contains(&chunk),
            "handshake must carry the up2k hash list: {}",
            requests[0]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
