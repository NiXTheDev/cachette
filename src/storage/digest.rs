//! Per-entry content digests (plan task 50).
//!
//! Every finalized entry records a `blake3-256` hash truncated to 16 bytes
//! (32 lowercase hex characters). The digest falls out of the same pass that
//! writes the blob — no second read of the payload and no whole-blob buffer —
//! and is re-checked offline by `cachette verify` (plan task 46) to catch
//! bitrot, a truncated write, or a blob swapped under a live index row.
//!
//! 16 bytes is the width the plan fixes for the task-41 chunk index; keeping
//! one width for both leaves a single routine (and a single hex length) in
//! play when dedup lands.

use std::fmt::Write as _;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;

/// Stored digest width in bytes.
pub const DIGEST_BYTES: usize = 16;

/// Stored digest width in lowercase hex characters.
pub const DIGEST_HEX_LEN: usize = DIGEST_BYTES * 2;

/// Read buffer for [`hash_file`]: the offline scrub stays at a few tens of
/// KiB per entry no matter how large the blob is.
const HASH_CHUNK: usize = 64 * 1024;

/// A `Write` adapter that folds every byte written through it into a `blake3`
/// hasher, so the copy-to-disk pass and the digest are one operation. Partial
/// writes are honoured: only the bytes the inner writer accepted are hashed.
#[derive(Debug)]
pub struct DigestWriter<W> {
    inner: W,
    hasher: blake3::Hasher,
}

impl<W: Write> DigestWriter<W> {
    /// Wrap `inner`; the digest starts empty.
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            hasher: blake3::Hasher::new(),
        }
    }

    /// Digest of every byte written so far, as [`DIGEST_HEX_LEN`] hex chars.
    #[must_use]
    pub fn digest(&self) -> String {
        hex16(self.hasher.finalize().as_bytes())
    }

    /// Flush the inner writer and hand it back together with the digest of
    /// everything written through it.
    pub fn finish(mut self) -> io::Result<(W, String)> {
        self.inner.flush()?;
        let digest = self.digest();
        Ok((self.inner, digest))
    }
}

impl<W: Write> Write for DigestWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let written = self.inner.write(buf)?;
        self.hasher.update(&buf[..written]);
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Digest of an in-memory buffer, as [`DIGEST_HEX_LEN`] hex chars.
#[must_use]
pub fn hash_bytes(data: &[u8]) -> String {
    hex16(blake3::hash(data).as_bytes())
}

/// Digest of a whole file, streamed through a fixed [`HASH_CHUNK`] buffer.
pub fn hash_file(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0_u8; HASH_CHUNK];
    loop {
        let read = file.read(&mut buf)?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
    }
    Ok(hex16(hasher.finalize().as_bytes()))
}

/// Lowercase hex of the first [`DIGEST_BYTES`] bytes of `digest`.
#[must_use]
pub fn hex16(digest: &[u8]) -> String {
    let mut out = String::with_capacity(DIGEST_HEX_LEN);
    for byte in digest.iter().take(DIGEST_BYTES) {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> std::path::PathBuf {
        let path =
            std::env::temp_dir().join(format!("cachette-digest-{}-{name}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        path
    }

    #[test]
    fn hex_is_lowercase_and_truncated_to_the_stored_width() {
        assert_eq!(hex16(&[0xab; 32]), "ab".repeat(DIGEST_BYTES));
        assert_eq!(hex16(&[0xab; 32]).len(), DIGEST_HEX_LEN);
        assert_eq!(hex16(&[0x0f, 0xf0]), "0ff0");
    }

    #[test]
    fn digest_writer_hashes_every_byte_across_separate_writes() {
        let mut writer = DigestWriter::new(Vec::new());
        writer.write_all(b"hello ").expect("write 1");
        writer.write_all(b"world").expect("write 2");
        let (bytes, digest) = writer.finish().expect("finish");
        assert_eq!(bytes, b"hello world");
        assert_eq!(digest, hash_bytes(b"hello world"));
    }

    #[test]
    fn hash_file_matches_the_in_memory_digest_and_tracks_a_flipped_byte() {
        let path = scratch("flip");
        std::fs::write(&path, b"payload").expect("write fixture");
        let original = hash_file(&path).expect("hash");
        assert_eq!(original, hash_bytes(b"payload"));

        std::fs::write(&path, b"payloae").expect("rewrite fixture");
        let flipped = hash_file(&path).expect("hash flipped");
        assert_ne!(flipped, original);
        assert_eq!(flipped, hash_bytes(b"payloae"));

        std::fs::remove_file(&path).ok();
    }
}
