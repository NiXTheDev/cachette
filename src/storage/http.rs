//! Small HTTP/1.1 client shared by the remote blob backends.
//!
//! The project already pulls in `hyper` through axum, but a direct dependency
//! would need a registry fetch, so this is a deliberately narrow client over
//! `tokio::net` + `tokio-rustls`: one request, one response, no pooling. Blob
//! operations are a handful of large requests per artifact; that trade is
//! worth avoiding a new crate.

use std::io::{self, Seek, Write};
use std::path::Path;
use std::sync::Arc;

use tokio::io::{
    AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWrite, AsyncWriteExt, BufReader,
};
use tokio::net::TcpStream;
use url::Url;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig as RustlsClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

/// Request body. `FileRange` streams from disk without buffering the payload.
pub enum Body<'a> {
    Empty,
    Bytes(&'a [u8]),
    FileRange {
        path: &'a Path,
        offset: u64,
        len: u64,
    },
}

/// Request headers as `(name, value)` pairs.
pub type Headers<'a> = Vec<(&'a str, String)>;

/// Whole-request budget (connect + TLS + headers + body). Large blob uploads
/// are streamed, so five minutes is generous without being unbounded.
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// Parsed response head. `body` is a short prefix kept for error messages and
/// JSON replies; large bodies go straight to a [`BodyWriter`].
#[derive(Debug)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    /// Case-insensitive header lookup.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// Response body as UTF-8, replacing invalid sequences.
    #[must_use]
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    /// Whether the response succeeded.
    #[must_use]
    pub fn is_ok(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

/// Destination for a response body.
pub trait BodyWriter {
    /// Called once with the response head, before any body bytes arrive.
    fn set_head(&mut self, status: u16, headers: &[(String, String)]) -> io::Result<()> {
        let _ = (status, headers);
        Ok(())
    }

    /// Consume one decoded chunk of the body.
    fn write(&mut self, bytes: &[u8]) -> io::Result<()>;
}

impl BodyWriter for Vec<u8> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.extend_from_slice(bytes);
        Ok(())
    }
}

/// Writes the body into a sparse local file at `offset`, skipping `skip`
/// leading bytes (a server that ignores `Range` returns the whole object).
pub struct FileWriter {
    file: std::fs::File,
    offset: u64,
    skip: u64,
    remaining: Option<u64>,
    written: u64,
}

impl FileWriter {
    /// Open (creating if needed) `path` for a body landing at `offset`.
    pub fn new(path: &Path, offset: u64, skip: u64, take: Option<u64>) -> io::Result<Self> {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(path)?;
        file.seek(io::SeekFrom::Start(offset))?;
        Ok(Self {
            file,
            offset,
            skip,
            remaining: take,
            written: 0,
        })
    }

    /// Bytes actually written into the cache file. A server that returns a
    /// short body must be reported, not silently padded with sparse zeros.
    #[must_use]
    pub const fn written(&self) -> u64 {
        self.written
    }
}

impl BodyWriter for FileWriter {
    fn set_head(&mut self, status: u16, headers: &[(String, String)]) -> io::Result<()> {
        // A server that ignores `Range` answers 200 with the whole object;
        // skip the bytes before our window. A proper 206 is already sliced.
        if status == 200
            && !headers
                .iter()
                .any(|(key, _)| key.eq_ignore_ascii_case("content-range"))
        {
            self.skip = self.offset;
        }
        Ok(())
    }

    fn write(&mut self, bytes: &[u8]) -> io::Result<()> {
        let mut bytes = bytes;
        if self.skip > 0 {
            let skipped = self.skip.min(bytes.len() as u64) as usize;
            self.skip -= skipped as u64;
            bytes = &bytes[skipped..];
        }
        if let Some(remaining) = &mut self.remaining {
            let limited = (*remaining).min(bytes.len() as u64) as usize;
            bytes = &bytes[..limited];
            *remaining -= limited as u64;
        }
        self.file.write_all(bytes)?;
        self.written += bytes.len() as u64;
        Ok(())
    }
}

/// TLS configuration for https endpoints. A CA bundle is required: the same
/// posture as OIDC's `jwks_ca_pem`, so an untuned install never trusts the
/// ambient system store by accident.
#[derive(Clone)]
pub struct HttpClient {
    tls: Option<Arc<RustlsClientConfig>>,
}

impl std::fmt::Debug for HttpClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpClient")
            .field("tls", &self.tls.is_some())
            .finish_non_exhaustive()
    }
}

impl HttpClient {
    /// Build a client from an optional PEM CA bundle. Plain http endpoints
    /// work without it; https endpoints require one.
    pub fn new(ca_pem: Option<&Path>) -> io::Result<Self> {
        let Some(path) = ca_pem else {
            return Ok(Self { tls: None });
        };
        let pem = std::fs::read_to_string(path)?;
        let certs = rustls_pemfile::certs(&mut std::io::BufReader::new(pem.as_bytes()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(io::Error::other)?;
        let mut roots = RootCertStore::empty();
        for cert in certs {
            let _ = roots.add(cert);
        }
        if roots.is_empty() {
            return Err(io::Error::other(format!(
                "CA bundle {} has no certificates",
                path.display()
            )));
        }
        let config = RustlsClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(Self {
            tls: Some(Arc::new(config)),
        })
    }

    /// Send one request, collecting a bounded response body. For large
    /// downloads use [`Self::send_to`].
    pub async fn send(
        &self,
        method: &'static str,
        url: &str,
        headers: Headers<'_>,
        body: Body<'_>,
    ) -> io::Result<Response> {
        let mut out = Vec::new();
        self.send_to(method, url, headers, body, &mut out).await
    }

    /// Send one request, streaming the response into `writer`. Every phase —
    /// connect, TLS handshake, headers and body — shares one wall-clock
    /// budget, so a dead storage server cannot wedge a request handler.
    pub async fn send_to(
        &self,
        method: &'static str,
        url: &str,
        headers: Headers<'_>,
        body: Body<'_>,
        writer: &mut (dyn BodyWriter + Send),
    ) -> io::Result<Response> {
        tokio::time::timeout(
            REQUEST_TIMEOUT,
            self.send_inner(method, url, headers, body, writer),
        )
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                format!("storage HTTP request timed out after {:?}", REQUEST_TIMEOUT),
            )
        })?
    }

    async fn send_inner(
        &self,
        method: &'static str,
        url: &str,
        headers: Headers<'_>,
        body: Body<'_>,
        writer: &mut (dyn BodyWriter + Send),
    ) -> io::Result<Response> {
        let url = Url::parse(url)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;
        let scheme = url.scheme();
        if scheme != "http" && scheme != "https" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsupported URL scheme {scheme:?}; expected http or https"),
            ));
        }
        let host = url
            .host_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "URL has no host"))?;
        let port = url
            .port_or_known_default()
            .unwrap_or(if scheme == "https" { 443 } else { 80 });
        let tls = if scheme == "https" {
            Some(self.tls.clone().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "https storage endpoints require ca_pem",
                )
            })?)
        } else {
            None
        };
        let tcp = TcpStream::connect((host, port)).await?;
        tcp.set_nodelay(true)?;
        let (reader, writer_half): (
            Box<dyn AsyncRead + Send + Unpin>,
            Box<dyn AsyncWrite + Send + Unpin>,
        ) = if scheme == "https" {
            let tls = tls.expect("checked above");
            let name = ServerName::try_from(host.to_owned()).map_err(|err| {
                io::Error::new(io::ErrorKind::InvalidInput, format!("bad TLS host: {err}"))
            })?;
            let tls = TlsConnector::from(tls).connect(name, tcp).await?;
            let (read, write) = tokio::io::split(tls);
            (Box::new(read), Box::new(write))
        } else {
            let (read, write) = tokio::io::split(tcp);
            (Box::new(read), Box::new(write))
        };
        let mut reader = BufReader::new(reader);
        let mut writer_half = writer_half;

        let mut target = url.path().to_owned();
        if let Some(query) = url.query() {
            target.push('?');
            target.push_str(query);
        }
        let mut head = format!(
            "{method} {target} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n",
            url.authority()
        );
        for (key, value) in &headers {
            validate_header(key, value)?;
            head.push_str(key);
            head.push_str(": ");
            head.push_str(value);
            head.push_str("\r\n");
        }
        let content_length = match &body {
            Body::Empty => None,
            Body::Bytes(bytes) => Some(bytes.len() as u64),
            Body::FileRange { len, .. } => Some(*len),
        };
        if let Some(len) = content_length {
            head.push_str(&format!("Content-Length: {len}\r\n"));
        }
        head.push_str("\r\n");
        writer_half.write_all(head.as_bytes()).await?;
        match &body {
            Body::Empty => {}
            Body::Bytes(bytes) => writer_half.write_all(bytes).await?,
            Body::FileRange { path, offset, len } => {
                let mut file = tokio::fs::File::open(path).await?;
                file.seek(std::io::SeekFrom::Start(*offset)).await?;
                let copied = tokio::io::copy(&mut file.take(*len), &mut writer_half).await?;
                if copied != *len {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        format!("short body read from {}", path.display()),
                    ));
                }
            }
        }
        writer_half.flush().await?;
        drop(writer_half);

        let (status, response_headers) = read_head(&mut reader).await?;
        writer.set_head(status, &response_headers)?;
        let mut short = Vec::new();
        read_body(&mut reader, &response_headers, writer, &mut short).await?;
        Ok(Response {
            status,
            headers: response_headers,
            body: short,
        })
    }
}

fn validate_header(key: &str, value: &str) -> io::Result<()> {
    let clean = |bytes: &[u8]| bytes.iter().all(|byte| *byte >= 0x20 && *byte != 0x7f);
    if key.is_empty() || !clean(key.as_bytes()) || !clean(value.as_bytes()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "header contains a control character",
        ));
    }
    Ok(())
}

async fn read_head<R: tokio::io::AsyncBufRead + Unpin>(
    reader: &mut R,
) -> io::Result<(u16, Vec<(String, String)>)> {
    // Read line by line on the BufReader: a bulk `read` could swallow body
    // bytes along with the head and they would be lost when the head is
    // parsed.
    let mut lines = Vec::new();
    loop {
        let mut line = Vec::new();
        let read = reader.read_until(b'\n', &mut line).await?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "server closed before response headers",
            ));
        }
        lines.push(line);
        if lines.iter().map(Vec::len).sum::<usize>() > 64 * 1024 {
            return Err(io::Error::other("response headers too large"));
        }
        if lines.last().is_some_and(|line| line.as_slice() == b"\r\n") {
            break;
        }
    }
    let mut parsed = lines.iter();
    let status_line = String::from_utf8_lossy(parsed.next().map(Vec::as_slice).unwrap_or_default());
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| io::Error::other("malformed HTTP status line"))?;
    let mut headers = Vec::new();
    for line in parsed {
        let line = String::from_utf8_lossy(line).trim().to_owned();
        if let Some((key, value)) = line.split_once(':') {
            headers.push((key.trim().to_owned(), value.trim().to_owned()));
        }
    }
    Ok((status, headers))
}

async fn read_body<R: tokio::io::AsyncBufRead + Unpin>(
    reader: &mut R,
    headers: &[(String, String)],
    writer: &mut (dyn BodyWriter + Send),
    short: &mut Vec<u8>,
) -> io::Result<()> {
    let chunked = headers.iter().any(|(key, value)| {
        key.eq_ignore_ascii_case("transfer-encoding")
            && value.to_ascii_lowercase().contains("chunked")
    });
    let mut push = |bytes: &[u8]| -> io::Result<()> {
        if short.len() < 8192 {
            let take = (8192 - short.len()).min(bytes.len());
            short.extend_from_slice(&bytes[..take]);
        }
        writer.write(bytes)
    };
    if chunked {
        loop {
            let mut size_line = Vec::new();
            reader.read_until(b'\n', &mut size_line).await?;
            let line = String::from_utf8_lossy(&size_line);
            let hex = line.trim().split(';').next().unwrap_or_default().trim();
            let size = usize::from_str_radix(hex, 16)
                .map_err(|_| io::Error::other("malformed HTTP chunk size"))?;
            if size == 0 {
                let mut trailer = Vec::new();
                let _ = reader.read_until(b'\n', &mut trailer).await?;
                break;
            }
            let mut chunk = vec![0_u8; size];
            reader.read_exact(&mut chunk).await?;
            let mut crlf = [0_u8; 2];
            reader.read_exact(&mut crlf).await?;
            push(&chunk)?;
        }
        return Ok(());
    }
    if let Some(len) = headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.parse::<u64>().ok())
    {
        let mut remaining = len;
        let mut buf = [0_u8; 64 * 1024];
        while remaining > 0 {
            let want = buf.len().min(remaining as usize);
            let read = reader.read(&mut buf[..want]).await?;
            if read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "short HTTP response body",
                ));
            }
            push(&buf[..read])?;
            remaining -= read as u64;
        }
        return Ok(());
    }
    let mut limited = reader.take(64 * 1024 * 1024 + 1);
    let mut buf = Vec::new();
    limited.read_to_end(&mut buf).await?;
    if buf.len() > 64 * 1024 * 1024 {
        return Err(io::Error::other("HTTP response body too large"));
    }
    push(&buf)
}
