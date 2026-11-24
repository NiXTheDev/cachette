//! Azure Blob Storage backend (v1.3) with Shared Key signing.
//!
//! Same whole-blob shape as S3: one container, per-instance key prefixes,
//! local index and CDC chunks. Credentials come from the standard Azure env
//! vars with config fallback; no new crate is needed.

use std::io;
use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use hmac::{Hmac, KeyInit as _, Mac};
use sha2::Sha256;
use url::Url;

use super::blob::{BoxFuture, RemoteOps};
use super::http::{Body, FileWriter, HttpClient};

/// Connection settings for one Azure instance.
#[derive(Clone, Debug)]
pub struct AzureConfig {
    pub account: String,
    pub container: String,
    /// Custom endpoint (Azurite). Without it, the public Azure host is used.
    pub endpoint: Option<String>,
    pub prefix: Option<String>,
    /// Config fallback for AZURE_STORAGE_KEY.
    pub key: String,
}

/// Azure remote operations.
pub struct AzureOps {
    client: HttpClient,
    config: AzureConfig,
    key: Vec<u8>,
}

impl std::fmt::Debug for AzureOps {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AzureOps")
            .field("account", &self.config.account)
            .field("container", &self.config.container)
            .finish_non_exhaustive()
    }
}

impl AzureOps {
    /// Resolve credentials (env wins) and connect.
    pub fn new(config: AzureConfig, ca_pem: Option<&Path>) -> io::Result<Self> {
        let account = std::env::var("AZURE_STORAGE_ACCOUNT")
            .ok()
            .filter(|v| !v.is_empty())
            .unwrap_or(config.account.clone());
        let key_text = std::env::var("AZURE_STORAGE_KEY")
            .ok()
            .filter(|v| !v.is_empty())
            .unwrap_or(config.key.clone());
        if account.is_empty() || key_text.is_empty() {
            return Err(io::Error::other(
                "Azure needs AZURE_STORAGE_ACCOUNT/KEY or account/access_key config",
            ));
        }
        let key = STANDARD.decode(key_text.trim()).map_err(|err| {
            io::Error::new(io::ErrorKind::InvalidInput, format!("bad Azure key: {err}"))
        })?;
        Ok(Self {
            client: HttpClient::new(ca_pem)?,
            config: AzureConfig { account, ..config },
            key,
        })
    }

    fn object_url(&self, id: &str) -> io::Result<String> {
        let blob = match self.config.prefix.as_deref() {
            Some(prefix) if !prefix.is_empty() => format!("{}/{}", prefix.trim_matches('/'), id),
            _ => id.to_owned(),
        };
        match &self.config.endpoint {
            Some(endpoint) => {
                let mut url = Url::parse(endpoint)
                    .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;
                {
                    let mut segments = url
                        .path_segments_mut()
                        .map_err(|_| io::Error::other("Azure endpoint cannot be a base"))?;
                    segments.pop_if_empty().push(&self.config.account);
                    segments.push(&self.config.container);
                    segments.push(&blob);
                }
                Ok(url.to_string())
            }
            None => Ok(format!(
                "https://{}.blob.core.windows.net/{}/{}",
                self.config.account, self.config.container, blob
            )),
        }
    }

    fn authorization(
        &self,
        url: &str,
        method: &'static str,
        content_length: Option<u64>,
        range: Option<&str>,
        blob_type: bool,
    ) -> io::Result<(String, String)> {
        let parsed = Url::parse(url)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;
        let date = http_date();
        let mut canonical = format!(
            "{method}\n\n\n{}\n\n\n\n\n\n{}\n",
            content_length.map_or_else(String::new, |n| n.to_string()),
            range.unwrap_or_default()
        );
        if blob_type {
            canonical.push_str("x-ms-blob-type:BlockBlob\n");
        }
        canonical.push_str(&format!("x-ms-date:{date}\nx-ms-version:2021-08-06\n\n"));
        // Virtual-host addressing omits the account from the URL path; the
        // canonical resource always carries it.
        let resource = if self.config.endpoint.is_some() {
            parsed.path().to_owned()
        } else {
            format!("/{}{}", self.config.account, parsed.path())
        };
        canonical.push_str(&resource);
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.key).expect("HMAC accepts any key");
        mac.update(canonical.as_bytes());
        let signature = STANDARD.encode(mac.finalize().into_bytes());
        Ok((
            format!("SharedKey {}:{signature}", self.config.account),
            date,
        ))
    }

    fn signed_headers(
        &self,
        url: &str,
        method: &'static str,
        content_length: Option<u64>,
        range: Option<&str>,
        blob_type: bool,
    ) -> io::Result<Vec<(&'static str, String)>> {
        let (authorization, date) =
            self.authorization(url, method, content_length, range, blob_type)?;
        let mut headers: Vec<(&'static str, String)> = vec![
            ("Authorization", authorization),
            ("x-ms-date", date),
            ("x-ms-version", String::from("2021-08-06")),
        ];
        if blob_type {
            headers.push(("x-ms-blob-type", String::from("BlockBlob")));
        }
        if let Some(range) = range {
            headers.push(("Range", range.to_owned()));
        }
        Ok(headers)
    }
}

impl RemoteOps for AzureOps {
    fn name(&self) -> &'static str {
        "azure"
    }

    fn put<'a>(&'a self, id: &'a str, path: &'a Path) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async move {
            let len = tokio::fs::metadata(path).await?.len();
            let url = self.object_url(id)?;
            let headers = self.signed_headers(&url, "PUT", Some(len), None, true)?;
            let response = self
                .client
                .send(
                    "PUT",
                    &url,
                    headers,
                    Body::FileRange {
                        path,
                        offset: 0,
                        len,
                    },
                )
                .await?;
            if !response.is_ok() {
                return Err(io::Error::other(format!(
                    "Azure PUT failed ({}): {}",
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
            let url = self.object_url(id)?;
            let end = offset.saturating_add(len).saturating_sub(1);
            let range = format!("bytes={offset}-{end}");
            let headers = self.signed_headers(&url, "GET", None, Some(&range), false)?;
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
                    "Azure GET failed ({}): {}",
                    response.status,
                    response.text()
                )));
            }
            if writer.written() != len {
                return Err(io::Error::other(format!(
                    "Azure ranged GET wrote {} of {len} bytes (status {})",
                    writer.written(),
                    response.status
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
            let url = self.object_url(id)?;
            let headers = self.signed_headers(&url, "DELETE", None, None, false)?;
            let response = self
                .client
                .send("DELETE", &url, headers, Body::Empty)
                .await?;
            if response.status == 404 {
                return Ok(());
            }
            if !response.is_ok() {
                return Err(io::Error::other(format!(
                    "Azure DELETE failed ({}): {}",
                    response.status,
                    response.text()
                )));
            }
            Ok(())
        })
    }
}

/// RFC 1123 date required by Azure's `x-ms-date`. No date crate in tree.
fn http_date() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let weekday =
        ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"][(days + 4).rem_euclid(7) as usize];
    let month = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ][(month - 1) as usize];
    format!(
        "{weekday}, {day:02} {month} {year:04} {:02}:{:02}:{:02} GMT",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_date_matches_a_known_epoch_day() {
        assert_eq!(http_date_from_days(0), "Thu, 01 Jan 1970 00:00:00 GMT");
    }

    fn http_date_from_days(days: i64) -> String {
        let (year, month, day) = civil_from_days(days);
        let weekday =
            ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"][(days + 4).rem_euclid(7) as usize];
        let month = [
            "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
        ][(month - 1) as usize];
        format!("{weekday}, {day:02} {month} {year:04} 00:00:00 GMT")
    }
}
