//! Request-body adapters that keep the upload path bounded (plan task 45).
//!
//! Before task 45 every PATCH/block handler buffered its whole body with
//! `axum::body::to_bytes`, so one request could pin a chunk (up to the old
//! 256 MiB cap) in memory. These adapters let a handler hand the HTTP body
//! straight to storage as an `AsyncRead` instead:
//!
//! - [`BodyReader`] turns an [`axum::body::Body`]'s frame stream into an
//!   `AsyncRead`, so `write_chunk` streams the body to its temp file while the
//!   bytes are still arriving.
//! - [`LimitedReader`] enforces the byte cap *during* the copy. It reproduces
//!   `to_bytes(body, limit)`'s semantics — exactly `limit` bytes is fine, one
//!   byte more is an `InvalidInput` error (mapped to HTTP 400) — without ever
//!   holding the oversize body in memory or on disk.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use axum::body::HttpBody;
use tokio::io::{AsyncRead, ReadBuf};

/// Largest slice [`LimitedReader`] hands to the wrapped reader per poll, so the
/// bounding copy stays on the stack.
const SCRATCH_LEN: usize = 8 * 1024;

/// Adapts a request [`axum::body::Body`] to an [`AsyncRead`].
///
/// The reader yields the body's data frames in order and ignores trailers. A
/// frame-stream error surfaces as an `io::Error`, which the route maps to the
/// same 400 it returned when the body was buffered.
pub(crate) struct BodyReader {
    body: axum::body::Body,
    pending: Option<axum::body::Bytes>,
}

impl BodyReader {
    pub(crate) fn new(body: axum::body::Body) -> Self {
        Self {
            body,
            pending: None,
        }
    }
}

impl AsyncRead for BodyReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if let Some(chunk) = this.pending.take() {
                if chunk.is_empty() {
                    continue;
                }
                let n = buf.remaining().min(chunk.len());
                buf.put_slice(&chunk[..n]);
                if n < chunk.len() {
                    this.pending = Some(chunk.slice(n..));
                }
                return Poll::Ready(Ok(()));
            }
            match Pin::new(&mut this.body).poll_frame(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Ready(Some(Ok(frame))) => {
                    // Trailers carry no data; skip them and keep polling.
                    if let Ok(data) = frame.into_data() {
                        this.pending = Some(data);
                    }
                }
                Poll::Ready(Some(Err(err))) => {
                    return Poll::Ready(Err(io::Error::other(err)));
                }
            }
        }
    }
}

/// Wraps an `AsyncRead` and rejects a body longer than `limit` bytes.
///
/// Reads up to `limit` bytes normally; once the limit is reached it probes for
/// one more byte and fails with [`io::ErrorKind::InvalidInput`] if the source
/// is not at EOF. That keeps the "declared length is the whole body" guarantee
/// of the old `to_bytes` call while streaming.
pub(crate) struct LimitedReader<R> {
    inner: R,
    remaining: u64,
}

impl<R> LimitedReader<R> {
    pub(crate) fn new(inner: R, limit: u64) -> Self {
        Self {
            inner,
            remaining: limit,
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for LimitedReader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.remaining == 0 {
            let mut probe = [0u8; 1];
            let mut probe_buf = ReadBuf::new(&mut probe);
            match Pin::new(&mut this.inner).poll_read(cx, &mut probe_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Ready(Ok(())) => {
                    if probe_buf.filled().is_empty() {
                        return Poll::Ready(Ok(()));
                    }
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "request body exceeds the maximum chunk size",
                    )));
                }
            }
        }
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let allowed = usize::try_from(this.remaining.min(buf.remaining() as u64))
            .expect("remaining fits in usize when buf.remaining does");
        // Bound the inner read through a small stack buffer so it can never
        // over-read past the limit; the extra copy is a few KiB at most.
        let mut scratch = [0u8; SCRATCH_LEN];
        let cap = allowed.min(scratch.len());
        let mut sub = ReadBuf::new(&mut scratch[..cap]);
        match Pin::new(&mut this.inner).poll_read(cx, &mut sub) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Ready(Ok(())) => {
                let chunk = sub.filled();
                let n = chunk.len();
                this.remaining -= n as u64;
                buf.put_slice(chunk);
                Poll::Ready(Ok(()))
            }
        }
    }
}

#[cfg(test)]
mod body_io_tests {
    use super::{BodyReader, LimitedReader};
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn body_reader_yields_the_body_bytes() {
        let body = axum::body::Body::from(axum::body::Bytes::from_static(b"hello world"));
        let mut reader = BodyReader::new(body);
        let mut out = Vec::new();
        reader.read_to_end(&mut out).await.expect("read body");
        assert_eq!(out, b"hello world");
    }

    #[tokio::test]
    async fn limited_reader_accepts_exactly_the_limit() {
        let mut reader = LimitedReader::new(&b"abcd"[..], 4);
        let mut out = Vec::new();
        reader
            .read_to_end(&mut out)
            .await
            .expect("exact limit is ok");
        assert_eq!(out, b"abcd");
    }

    #[tokio::test]
    async fn limited_reader_rejects_one_byte_over() {
        let mut reader = LimitedReader::new(&b"abcde"[..], 4);
        let mut out = Vec::new();
        let err = reader.read_to_end(&mut out).await.expect_err("over limit");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }
}
