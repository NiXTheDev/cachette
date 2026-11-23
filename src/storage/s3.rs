//! Whole-blob S3 backend (v1.3) with hand-rolled SigV4.
//!
//! Objects live in one bucket under a key prefix (the cachette entry id).
//! S3 has no CDC, so validation rejects `cdc.enabled` for this backend via
//! its capability descriptor. Credentials come from the standard AWS env
//! variables, with optional config fallback; env always wins.

use std::collections::BTreeMap;
use std::io;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, KeyInit as _, Mac};
use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;
use url::Url;

use super::blob::{BoxFuture, RemoteOps};
use super::http::{Body, FileWriter, HttpClient};

/// Connection settings for one S3-compatible instance.
#[derive(Clone, Debug)]
pub struct S3Config {
    pub bucket: String,
    pub region: String,
    /// Custom endpoint (MinIO, Ceph, ...). When absent, AWS virtual-host
    /// addressing is used.
    pub endpoint: Option<String>,
    /// Optional key prefix inside the bucket.
    pub prefix: Option<String>,
    /// Config fallback credentials; environment variables take precedence.
    pub access_key: Option<String>,
    pub secret_key: Option<String>,
}

/// S3 remote operations.
pub struct S3Ops {
    client: HttpClient,
    config: S3Config,
    access_key: String,
    secret_key: String,
    session_token: Option<String>,
}

impl std::fmt::Debug for S3Ops {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3Ops")
            .field("bucket", &self.config.bucket)
            .field("region", &self.config.region)
            .finish_non_exhaustive()
    }
}

impl S3Ops {
    /// Resolve credentials (env wins) and connect.
    pub fn new(config: S3Config, ca_pem: Option<&Path>) -> io::Result<Self> {
        let access_key = std::env::var("AWS_ACCESS_KEY_ID")
            .ok()
            .filter(|value| !value.is_empty())
            .or_else(|| config.access_key.clone())
            .ok_or_else(|| io::Error::other("S3 needs AWS_ACCESS_KEY_ID or access_key"))?;
        let secret_key = std::env::var("AWS_SECRET_ACCESS_KEY")
            .ok()
            .filter(|value| !value.is_empty())
            .or_else(|| config.secret_key.clone())
            .ok_or_else(|| io::Error::other("S3 needs AWS_SECRET_ACCESS_KEY or secret_key"))?;
        let session_token = std::env::var("AWS_SESSION_TOKEN")
            .ok()
            .filter(|v| !v.is_empty());
        Ok(Self {
            client: HttpClient::new(ca_pem)?,
            config,
            access_key,
            secret_key,
            session_token,
        })
    }

    fn object_url(&self, id: &str) -> io::Result<String> {
        let key = match &self.config.prefix {
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
                        .map_err(|_| io::Error::other("S3 endpoint cannot be a base"))?;
                    segments.pop_if_empty().push(&self.config.bucket);
                    for segment in key.split('/') {
                        segments.push(segment);
                    }
                }
                Ok(url.to_string())
            }
            None => Ok(format!(
                "https://{}.s3.{}.amazonaws.com/{}",
                self.config.bucket, self.config.region, key
            )),
        }
    }

    fn authorization(
        &self,
        url: &str,
        method: &'static str,
        payload_hash: &str,
        extra_headers: &[(&str, String)],
    ) -> io::Result<(String, String, String)> {
        let parsed = Url::parse(url)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;
        let host = parsed
            .host_str()
            .ok_or_else(|| io::Error::other("S3 URL has no host"))?;
        let authority = match parsed.port() {
            Some(port)
                if !((parsed.scheme() == "https" && port == 443)
                    || (parsed.scheme() == "http" && port == 80)) =>
            {
                format!("{host}:{port}")
            }
            _ => host.to_owned(),
        };
        let (date, amz_date) = utc_now();
        let mut signed: BTreeMap<String, String> = BTreeMap::new();
        signed.insert("host".to_owned(), authority);
        signed.insert("x-amz-content-sha256".to_owned(), payload_hash.to_owned());
        signed.insert("x-amz-date".to_owned(), amz_date.clone());
        if let Some(token) = &self.session_token {
            signed.insert("x-amz-security-token".to_owned(), token.clone());
        }
        for (name, value) in extra_headers {
            signed.insert(name.to_ascii_lowercase(), value.clone());
        }
        let canonical_headers = signed
            .iter()
            .map(|(name, value)| format!("{name}:{}\n", value.trim()))
            .collect::<String>();
        let signed_headers = signed.keys().cloned().collect::<Vec<_>>().join(";");
        let canonical_request = format!(
            "{method}\n{}\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}",
            aws_encode_path(parsed.path())
        );
        let scope = format!("{}/{}/s3/aws4_request", date, self.config.region);
        let to_sign = format!(
            "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
            hex(&Sha256::digest(canonical_request.as_bytes()))
        );
        let key = hmac_sha256(
            format!("AWS4{}", self.secret_key).as_bytes(),
            date.as_bytes(),
        );
        let key = hmac_sha256(&key, self.config.region.as_bytes());
        let key = hmac_sha256(&key, b"s3");
        let key = hmac_sha256(&key, b"aws4_request");
        let signature = hex(&hmac_sha256(&key, to_sign.as_bytes()));
        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",
            self.access_key
        );
        Ok((authorization, amz_date, payload_hash.to_owned()))
    }

    fn signed_headers<'a>(
        &self,
        url: &str,
        method: &'static str,
        payload_hash: &str,
        extra: &[(&'a str, String)],
    ) -> io::Result<Vec<(&'a str, String)>> {
        let (authorization, amz_date, payload_hash) =
            self.authorization(url, method, payload_hash, extra)?;
        let mut headers: Vec<(&'a str, String)> = vec![
            ("Authorization", authorization),
            ("X-Amz-Date", amz_date),
            ("X-Amz-Content-Sha256", payload_hash),
        ];
        if let Some(token) = &self.session_token {
            headers.push(("X-Amz-Security-Token", token.clone()));
        }
        headers.extend_from_slice(extra);
        Ok(headers)
    }
}

impl RemoteOps for S3Ops {
    fn name(&self) -> &'static str {
        "s3"
    }

    fn put<'a>(&'a self, id: &'a str, path: &'a Path) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async move {
            let payload_hash = hex(&file_sha256(path).await?);
            let url = self.object_url(id)?;
            let headers = self.signed_headers(&url, "PUT", &payload_hash, &[])?;
            let response = self
                .client
                .send(
                    "PUT",
                    &url,
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
                    "S3 PUT failed ({}): {}",
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
            let extra = vec![("range", format!("bytes={offset}-{end}"))];
            let headers = self.signed_headers(&url, "GET", EMPTY_SHA256, &extra)?;
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
                    "S3 GET failed ({}): {}",
                    response.status,
                    response.text()
                )));
            }
            if writer.written() != len {
                return Err(io::Error::other(format!(
                    "S3 ranged GET wrote {} of {len} bytes (status {}, content-range {:?})",
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
            let url = self.object_url(id)?;
            let headers = self.signed_headers(&url, "DELETE", EMPTY_SHA256, &[])?;
            let response = self
                .client
                .send("DELETE", &url, headers, Body::Empty)
                .await?;
            if response.status == 404 {
                return Ok(()); // already gone; storage deletes are idempotent
            }
            if !response.is_ok() {
                return Err(io::Error::other(format!(
                    "S3 DELETE failed ({}): {}",
                    response.status,
                    response.text()
                )));
            }
            Ok(())
        })
    }
}

const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

async fn file_sha256(path: &Path) -> io::Result<Vec<u8>> {
    let mut file = tokio::fs::File::open(path).await?;
    let mut hash = Sha256::new();
    let mut buf = [0_u8; 256 * 1024];
    loop {
        let read = file.read(&mut buf).await?;
        if read == 0 {
            break;
        }
        hash.update(&buf[..read]);
    }
    Ok(hash.finalize().to_vec())
}

/// AWS percent-encoding for a URI path. Unreserved bytes pass through.
fn aws_encode_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for &byte in path.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~' | b'/') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// `(YYYYMMDD, YYYYMMDDTHHMMSSZ)` in UTC, without a date crate.
fn utc_now() -> (String, String) {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let hour = rem / 3600;
    let minute = (rem % 3600) / 60;
    let second = rem % 60;
    let (year, month, day) = civil_from_days(days);
    (
        format!("{year:04}{month:02}{day:02}"),
        format!("{year:04}{month:02}{day:02}T{hour:02}{minute:02}{second:02}Z"),
    )
}

/// Howard Hinnant's days-from-civil inverse (proleptic Gregorian).
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
    fn civil_dates_match_known_epoch_days() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(20_454), (2026, 1, 1));
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
    }

    #[test]
    fn sigv4_encode_keeps_unreserved_and_escapes_others() {
        assert_eq!(aws_encode_path("/a b/c~d"), "/a%20b/c~d");
    }
}
