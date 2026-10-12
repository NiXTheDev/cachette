//! Node identity (plan task 13 / Metis M6): first-boot Ed25519 keypair plus
//! self-signed certificate under `cluster.cert_path`, reused verbatim on every
//! later boot.
//!
//! Layout inside the identity directory (created on first boot):
//!
//! - `key.pem` — PKCS#8 Ed25519 private key (mode 0600 on Unix)
//! - `cert.pem` — self-signed X.509 certificate, CN = `[cluster] node_id`
//!   (empty subject when unset) and SANs for the `[cluster] advertise_addr`
//!   host/IP (Metis M13)
//!
//! **Fingerprint format**: uppercase hex SHA-256 over the DER-encoded
//! `SubjectPublicKeyInfo` of the key — 64 characters. It is the node's stable
//! identity: restarts and storage-dir wipes never change it, because the files
//! live at `cluster.cert_path`, outside the storage root.
//!
//! Loading is idempotent: an intact key/cert pair is read, never regenerated
//! (silent regeneration would silently change the node's identity). Only a
//! missing or partial pair triggers generation; a corrupt pair is reported as
//! [`IdentityError::Invalid`].

use std::fmt::Write as _;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_ED25519};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::config::split_host_port;

/// Private key file inside the identity directory.
const KEY_FILE: &str = "key.pem";
/// Self-signed certificate file inside the identity directory.
const CERT_FILE: &str = "cert.pem";

/// Identity failure, mapped to exit code 2 by `main.rs` (CLI) or to boot
/// failure by `serve()`.
#[derive(Debug, Error)]
pub enum IdentityError {
    /// Filesystem trouble reading or writing the identity directory.
    #[error("identity i/o error at {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },

    /// rcgen could not generate the key/certificate (or the SAN strings
    /// could not be encoded).
    #[error("identity generation failed: {0}")]
    Generate(#[from] rcgen::Error),

    /// Both files exist but do not form a usable identity: the key is not a
    /// parseable PEM, the certificate is not a PEM certificate, or the
    /// certificate does not carry this key's public key. Never "repaired" by
    /// regeneration — that would change the node's identity.
    #[error("identity at {dir} is invalid: {reason}")]
    Invalid { dir: PathBuf, reason: String },
}

/// The node's persisted Ed25519 identity (key + certificate + fingerprint).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Identity {
    dir: PathBuf,
    fingerprint: String,
    cert_pem: String,
    key_pem: String,
}

impl Identity {
    /// Load the identity at `dir`, generating it on first boot (i.e. when
    /// either file is missing — including completing an interrupted first
    /// boot). An intact pair is reused as-is.
    ///
    /// * `node_id` — becomes the certificate CN when set and non-empty.
    /// * `advertise_addr` — `host:port`, `[v6]:port` or bare host/IP whose
    ///   host part becomes the certificate SAN (Metis M13).
    pub fn load_or_generate(
        dir: &Path,
        node_id: Option<&str>,
        advertise_addr: Option<&str>,
    ) -> Result<Self, IdentityError> {
        let key_path = dir.join(KEY_FILE);
        let cert_path = dir.join(CERT_FILE);
        if key_path.is_file() && cert_path.is_file() {
            Self::load(dir, &key_path, &cert_path)
        } else {
            Self::generate(dir, node_id, advertise_addr)
        }
    }

    /// Read an existing pair; every inconsistency is [`IdentityError::Invalid`]
    /// rather than a regeneration.
    fn load(dir: &Path, key_path: &Path, cert_path: &Path) -> Result<Self, IdentityError> {
        let key_pem = fs::read_to_string(key_path).map_err(|source| io_error(key_path, source))?;
        let cert_pem =
            fs::read_to_string(cert_path).map_err(|source| io_error(cert_path, source))?;
        let key_pair = KeyPair::from_pem(&key_pem).map_err(|_| IdentityError::Invalid {
            dir: dir.to_path_buf(),
            reason: format!("{KEY_FILE} is not a parseable PEM private key"),
        })?;
        let spki = key_pair.public_key_der();
        let cert_der = first_cert_der(&cert_pem).ok_or_else(|| IdentityError::Invalid {
            dir: dir.to_path_buf(),
            reason: format!("{CERT_FILE} contains no valid PEM certificate"),
        })?;
        // The certificate embeds the SPKI verbatim; a mismatch means key and
        // cert disagree and the fingerprint would not match the served cert.
        if !cert_der
            .windows(spki.len())
            .any(|window| window == spki.as_slice())
        {
            return Err(IdentityError::Invalid {
                dir: dir.to_path_buf(),
                reason: format!("{CERT_FILE} does not carry the public key of {KEY_FILE}"),
            });
        }
        Ok(Self {
            dir: dir.to_path_buf(),
            fingerprint: fingerprint_spki(&spki),
            cert_pem,
            key_pem,
        })
    }

    /// First boot: create the directory, mint an Ed25519 key + self-signed
    /// certificate, and persist both atomically (scratch file + rename).
    fn generate(
        dir: &Path,
        node_id: Option<&str>,
        advertise_addr: Option<&str>,
    ) -> Result<Self, IdentityError> {
        fs::create_dir_all(dir).map_err(|source| io_error(dir, source))?;
        restrict_dir(dir)?;
        let key_pair = KeyPair::generate_for(&PKCS_ED25519)?;
        let mut params = CertificateParams::new(advertise_san(advertise_addr))?;
        // Replace rcgen's placeholder CN ("rcgen self signed cert"); an empty
        // subject is intentional when no node_id is configured.
        let mut subject = DistinguishedName::new();
        if let Some(node_id) = node_id.filter(|value| !value.is_empty()) {
            subject.push(DnType::CommonName, node_id);
        }
        params.distinguished_name = subject;
        let cert = params.self_signed(&key_pair)?;
        let key_pem = key_pair.serialize_pem();
        let cert_pem = cert.pem();
        let fingerprint = fingerprint_spki(&key_pair.public_key_der());
        write_private(dir, KEY_FILE, key_pem.as_bytes())?;
        write_private(dir, CERT_FILE, cert_pem.as_bytes())?;
        tracing::info!(dir = %dir.display(), "first-boot Ed25519 identity generated");
        Ok(Self {
            dir: dir.to_path_buf(),
            fingerprint,
            cert_pem,
            key_pem,
        })
    }

    /// Uppercase hex SHA-256 of the SPKI DER (64 chars) — the node's stable
    /// identity, as printed by `cachette identity`.
    #[must_use]
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// Self-signed certificate (PEM).
    #[must_use]
    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// PKCS#8 private key (PEM) matching [`Self::cert_pem`].
    #[must_use]
    pub fn key_pem(&self) -> &str {
        &self.key_pem
    }

    /// Identity directory (`cluster.cert_path`).
    #[must_use]
    pub fn cert_path(&self) -> &Path {
        &self.dir
    }
}

/// Fingerprint of a DER-encoded `SubjectPublicKeyInfo`: uppercase hex
/// SHA-256 (64 chars) — the format documented in the module docs and the
/// one `cachette identity` prints.
#[must_use]
pub fn fingerprint_spki(spki_der: &[u8]) -> String {
    let digest = Sha256::digest(spki_der);
    let mut fingerprint = String::with_capacity(digest.len() * 2);
    for &byte in digest.as_slice() {
        let _ = write!(fingerprint, "{byte:02X}");
    }
    fingerprint
}

/// Subject alternative names for the certificate: the `advertise_addr` host
/// as an IP or DNS-name SAN. An unparseable address contributes no SAN
/// instead of failing the boot (Metis M13).
fn advertise_san(advertise_addr: Option<&str>) -> Vec<String> {
    advertise_addr
        .and_then(advertise_host)
        .map_or_else(Vec::new, |host| vec![host.to_owned()])
}

/// Host part of an `advertise_addr` — `host:port`, `[v6]:port`, a bare IP or
/// a bare hostname. `None` for empty, whitespace-ridden or malformed values
/// (e.g. `host:port` with a non-numeric port, which must not become a SAN).
fn advertise_host(addr: &str) -> Option<&str> {
    let host = split_host_port(addr).map_or(addr, |(host, _)| host);
    let host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    if host.is_empty() || host.contains(char::is_whitespace) {
        return None;
    }
    // IP literals become IP SANs (rcgen parses them itself); anything else
    // must be a DNS name, so leftover colons mean the address is malformed.
    if host.parse::<IpAddr>().is_ok() || !host.contains(':') {
        Some(host)
    } else {
        None
    }
}

/// First X.509 certificate in a PEM document; `None` when the document has
/// no certificate or does not parse.
fn first_cert_der(pem: &str) -> Option<Vec<u8>> {
    let mut bytes = pem.as_bytes();
    let mut certs = rustls_pemfile::certs(&mut bytes);
    certs.next()?.ok().map(|cert| cert.as_ref().to_vec())
}

/// Write one identity file atomically (scratch file + rename) with
/// restrictive rights.
fn write_private(dir: &Path, name: &str, data: &[u8]) -> Result<(), IdentityError> {
    let tmp = dir.join(format!("{name}.tmp"));
    let dest = dir.join(name);
    write_scratch(&tmp, data)?;
    fs::rename(&tmp, &dest).map_err(|source| io_error(&dest, source))
}

/// Create/truncate `path` and write `data` with owner-only rights on Unix.
#[cfg(unix)]
fn write_scratch(path: &Path, data: &[u8]) -> Result<(), IdentityError> {
    use std::io::Write as _;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|source| io_error(path, source))?;
    file.write_all(data)
        .map_err(|source| io_error(path, source))?;
    file.sync_all().map_err(|source| io_error(path, source))?;
    drop(file);
    // `mode` applies at creation only; a scratch file left behind by a
    // crashed boot may still carry looser rights.
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|source| io_error(path, source))
}

/// Create/truncate `path` and write `data` (Windows has no Unix modes).
#[cfg(not(unix))]
fn write_scratch(path: &Path, data: &[u8]) -> Result<(), IdentityError> {
    fs::write(path, data).map_err(|source| io_error(path, source))
}

/// Identity directory is owner-only on Unix (applied at generation time).
#[cfg(unix)]
fn restrict_dir(dir: &Path) -> Result<(), IdentityError> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
        .map_err(|source| io_error(dir, source))
}

/// No permission bits to restrict on Windows.
#[cfg(not(unix))]
fn restrict_dir(_dir: &Path) -> Result<(), IdentityError> {
    Ok(())
}

/// Shared [`IdentityError::Io`] constructor.
fn io_error(path: &Path, source: std::io::Error) -> IdentityError {
    IdentityError::Io {
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static DIR_SEQ: AtomicU64 = AtomicU64::new(0);

    /// Unique temp directory per test, removed on drop (no tempfile dep).
    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Self {
            let seq = DIR_SEQ.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("cachette-identity-{}-{seq}", std::process::id()));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).expect("create test dir");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn first_boot_generates_key_and_cert_with_spec_fingerprint() {
        let root = TestDir::new();
        let dir = root.path().join("identity");
        let identity = Identity::load_or_generate(&dir, Some("node-a"), Some("127.0.0.1:8080"))
            .expect("first boot generates");

        assert_eq!(identity.cert_path(), dir.as_path());
        let key_pem = fs::read_to_string(dir.join(KEY_FILE)).expect("key exists");
        let cert_pem = fs::read_to_string(dir.join(CERT_FILE)).expect("cert exists");
        assert!(key_pem.contains("PRIVATE KEY"), "not a key PEM");
        assert!(cert_pem.contains("BEGIN CERTIFICATE"), "not a cert PEM");

        // Spec: uppercase hex SHA-256 over the DER-encoded SPKI, 64 chars.
        let fingerprint = identity.fingerprint();
        assert_eq!(fingerprint.len(), 64, "{fingerprint}");
        assert!(
            fingerprint
                .chars()
                .all(|c| c.is_ascii_digit() || ('A'..='F').contains(&c)),
            "not uppercase hex: {fingerprint}"
        );
        let key_pair = KeyPair::from_pem(&key_pem).expect("generated key parses");
        assert_eq!(fingerprint, fingerprint_spki(&key_pair.public_key_der()));
        assert_eq!(identity.key_pem(), key_pem);
        assert_eq!(identity.cert_pem(), cert_pem);
    }

    #[test]
    fn second_boot_reuses_the_pair_instead_of_regenerating() {
        let root = TestDir::new();
        let dir = root.path().join("identity");
        let first = Identity::load_or_generate(&dir, Some("node-a"), Some("cache-a:8080"))
            .expect("first boot");
        let key_before = fs::read(dir.join(KEY_FILE)).expect("key bytes");
        let cert_before = fs::read(dir.join(CERT_FILE)).expect("cert bytes");

        // Simulated restart: both files intact → load, never regenerate.
        let second = Identity::load_or_generate(&dir, Some("node-a"), Some("cache-a:8080"))
            .expect("second boot");
        assert_eq!(first, second);
        assert_eq!(fs::read(dir.join(KEY_FILE)).expect("key bytes"), key_before);
        assert_eq!(
            fs::read(dir.join(CERT_FILE)).expect("cert bytes"),
            cert_before
        );
    }

    #[test]
    fn storage_dir_wipe_never_changes_the_fingerprint() {
        let root = TestDir::new();
        let dir = root.path().join("identity");
        let storage = root.path().join("data");
        fs::create_dir_all(&storage).expect("storage dir");

        let before = Identity::load_or_generate(&dir, Some("node-a"), None).expect("first boot");
        fs::write(storage.join("blob"), b"cached").expect("blob");
        // Criterion 11: wipe blobs + sqlite (the whole storage dir here).
        fs::remove_dir_all(&storage).expect("wipe storage");

        let after =
            Identity::load_or_generate(&dir, Some("node-a"), None).expect("restart after wipe");
        assert_eq!(before.fingerprint(), after.fingerprint());
        assert_eq!(before.cert_pem(), after.cert_pem());
    }

    #[test]
    fn independent_first_boots_get_distinct_fingerprints() {
        let a_root = TestDir::new();
        let b_root = TestDir::new();
        let a = Identity::load_or_generate(&a_root.path().join("identity"), None, None)
            .expect("node a");
        let b = Identity::load_or_generate(&b_root.path().join("identity"), None, None)
            .expect("node b");
        assert_ne!(a.fingerprint(), b.fingerprint());
    }

    #[test]
    fn partial_pair_from_an_interrupted_boot_is_completed() {
        let root = TestDir::new();
        let dir = root.path().join("identity");
        fs::create_dir_all(&dir).expect("identity dir");
        // Crash after the key rename, before the cert rename: garbage-free
        // key only. The pair is unusable, so first boot re-runs.
        fs::write(dir.join(KEY_FILE), b"not a pem yet").expect("key file");

        let identity =
            Identity::load_or_generate(&dir, None, Some("host:bad")).expect("completes the pair");
        assert!(dir.join(CERT_FILE).is_file());
        assert_eq!(identity.fingerprint().len(), 64);
        let key_pem = fs::read_to_string(dir.join(KEY_FILE)).expect("key");
        assert!(key_pem.contains("PRIVATE KEY"));
    }

    #[test]
    fn corrupt_intact_pair_is_rejected_without_regeneration() {
        let root = TestDir::new();
        let dir = root.path().join("identity");
        fs::create_dir_all(&dir).expect("identity dir");
        fs::write(dir.join(KEY_FILE), b"garbage").expect("key file");
        fs::write(dir.join(CERT_FILE), b"garbage").expect("cert file");

        let err = Identity::load_or_generate(&dir, Some("node-a"), None)
            .expect_err("corrupt pair must not be replaced silently");
        assert!(matches!(err, IdentityError::Invalid { .. }), "{err:?}");
        // The files are untouched — regeneration would change identity.
        assert_eq!(fs::read(dir.join(KEY_FILE)).expect("key"), b"garbage");
        assert_eq!(fs::read(dir.join(CERT_FILE)).expect("cert"), b"garbage");
    }

    #[test]
    fn advertise_host_accepts_every_address_form_and_rejects_junk() {
        assert_eq!(advertise_host("cache-a:8080"), Some("cache-a"));
        assert_eq!(advertise_host("127.0.0.1:8080"), Some("127.0.0.1"));
        assert_eq!(advertise_host("[::1]:8080"), Some("::1"));
        assert_eq!(advertise_host("10.0.0.1"), Some("10.0.0.1"));
        assert_eq!(advertise_host("2001:db8::1"), Some("2001:db8::1"));
        assert_eq!(advertise_host("cache-a"), Some("cache-a"));
        assert_eq!(advertise_host("host:bad"), None);
        assert_eq!(advertise_host(""), None);
        assert_eq!(advertise_host("bad host:8080"), None);
    }

    #[cfg(unix)]
    #[test]
    fn key_and_identity_dir_carry_owner_only_rights() {
        use std::os::unix::fs::PermissionsExt;

        let root = TestDir::new();
        let dir = root.path().join("identity");
        Identity::load_or_generate(&dir, None, None).expect("first boot");

        let key_mode = fs::metadata(dir.join(KEY_FILE))
            .expect("key metadata")
            .permissions()
            .mode();
        assert_eq!(key_mode & 0o777, 0o600, "key.pem mode {key_mode:o}");
        let dir_mode = fs::metadata(&dir)
            .expect("dir metadata")
            .permissions()
            .mode();
        assert_eq!(dir_mode & 0o777, 0o700, "identity dir mode {dir_mode:o}");
    }
}
