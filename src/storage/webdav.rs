//! Direct WebDAV backend (v1.3). Mounted WebDAV needs no code — it is an
//! `fs` instance with a `mount_url` for documentation; this is the HTTP mode
//! (PROPFIND-free PUT/GET/DELETE against object paths).

use std::io;
use std::path::Path;

use url::Url;

use super::blob::{BoxFuture, RemoteOps};
use super::http::{Body, FileWriter, HttpClient};

/// Connection settings for a direct WebDAV instance.
#[derive(Clone, Debug)]
pub struct WebDavConfig {
    /// Base collection URL, e.g. `https://dav.example.org/cachette/`.
    pub url: String,
    pub username: Option<String>,
    pub password: Option<String>,
}

/// WebDAV remote operations.
pub struct WebDavOps {
    client: HttpClient,
    config: WebDavConfig,
    basic: Option<String>,
}

impl std::fmt::Debug for WebDavOps {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebDavOps")
            .field("url", &self.config.url)
            .finish_non_exhaustive()
    }
}

impl WebDavOps {
    /// Connect with the CA bundle configured on the instance (https only).
    pub fn new(config: WebDavConfig, ca_pem: Option<&Path>) -> io::Result<Self> {
        let basic = config.username.as_ref().map(|user| {
            use base64::Engine as _;
            let password = config.password.as_deref().unwrap_or_default();
            let token =
                base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"));
            format!("Basic {token}")
        });
        Ok(Self {
            client: HttpClient::new(ca_pem)?,
            config,
            basic,
        })
    }

    fn headers(&self) -> Vec<(&'static str, String)> {
        self.basic
            .as_ref()
            .map(|value| vec![("Authorization", value.clone())])
            .unwrap_or_default()
    }

    fn object_url(&self, id: &str) -> io::Result<String> {
        let mut url = Url::parse(&self.config.url)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;
        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|_| io::Error::other("WebDAV URL cannot be a base"))?;
            segments.pop_if_empty().push(id);
        }
        Ok(url.to_string())
    }
}

impl RemoteOps for WebDavOps {
    fn name(&self) -> &'static str {
        "webdav"
    }

    fn put<'a>(&'a self, id: &'a str, path: &'a Path) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async move {
            let mut headers = self.headers();
            headers.push(("Content-Type", String::from("application/octet-stream")));
            let response = self
                .client
                .send(
                    "PUT",
                    &self.object_url(id)?,
                    headers,
                    Body::FileRange {
                        path,
                        offset: 0,
                        len: tokio::fs::metadata(path).await?.len(),
                    },
                )
                .await?;
            if !response.is_ok() {
                return Err(io::Error::other(format!(
                    "WebDAV PUT failed ({}): {}",
                    response.status,
                    response.text()
                )));
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
            let mut headers = self.headers();
            let end = offset.saturating_add(len).saturating_sub(1);
            headers.push(("Range", format!("bytes={offset}-{end}")));
            let mut writer = FileWriter::new(path, offset, 0, Some(len))?;
            let response = self
                .client
                .send_to(
                    "GET",
                    &self.object_url(id)?,
                    headers,
                    Body::Empty,
                    &mut writer,
                )
                .await?;
            if response.status == 404 {
                return Err(super::not_found(id));
            }
            if !response.is_ok() {
                return Err(io::Error::other(format!(
                    "WebDAV GET failed ({}): {}",
                    response.status,
                    response.text()
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
            let response = self
                .client
                .send("DELETE", &self.object_url(id)?, self.headers(), Body::Empty)
                .await?;
            if !response.is_ok() {
                return Err(io::Error::other(format!(
                    "WebDAV DELETE failed ({}): {}",
                    response.status,
                    response.text()
                )));
            }
            Ok(())
        })
    }
}
