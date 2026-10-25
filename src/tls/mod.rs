//! Listener plumbing for the two ports (plan task 14 / B1 + B2, revised).
//!
//! Cachette serves TWO listeners. The MAIN listener (`[server] listen`) is
//! plaintext HTTP by default and terminates TLS only when the
//! `[server] tls_cert`/`tls_key` pair is configured. The CLUSTER listener
//! (`[cluster] listen`, only when `[cluster] enabled`) always terminates TLS
//! with the self-signed node identity certificate. On both, client
//! authentication is *optional* at the TLS layer: the handshake offers a
//! client certificate and accepts whatever is presented (or nothing). Which
//! peers are trusted is enforced per-route by [`PeerPins`], not by the TLS
//! handshake — see [`crate::routes`] and [`crate::routes::router`]. A
//! plaintext connection therefore carries no client fingerprint, and the pin
//! middleware rejects it — the peer routes fail closed without TLS.
//!
//! A connection's peer certificate is surfaced as [`PeerCert`], an axum
//! `Connected` value carrying the SPKI-SHA256 fingerprint. The pin middleware
//! reads it from the request extensions (installed by
//! `into_make_service_with_connect_info::<PeerCert>()`).
//!
//! Modules: [`verifier`] holds the accept-any client-cert verifier, [`pins`]
//! the SHA-256 pin store.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::extract::connect_info::Connected;
use axum::serve::{IncomingStream, Listener};
use rustls::ServerConfig as RustlsServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use thiserror::Error;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;

use crate::config::ServerConfig;
use crate::identity::{Identity, fingerprint_spki};

mod pins;
mod verifier;

pub use pins::PeerPins;
pub use verifier::OptionalClientCert;

/// Failures while building or binding the TLS listener.
#[derive(Debug, Error)]
pub enum TlsError {
    /// Reading or parsing an explicit PEM file (`[server] tls_cert`/`tls_key`).
    #[error("TLS material at {path}: {source}")]
    Material {
        /// File that failed to load.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// The certificate file contained no PEM certificate.
    #[error("no certificate found in {path}")]
    NoCertificate {
        /// Certificate file that was empty.
        path: PathBuf,
    },
    /// The private-key file contained no PEM private key.
    #[error("no private key found in {path}")]
    NoPrivateKey {
        /// Key file that was empty.
        path: PathBuf,
    },
    /// The in-memory identity PEM could not be parsed (task 13 guarantee broken).
    #[error("identity PEM is unusable: {reason}")]
    Identity {
        /// Why the identity PEM could not be used.
        reason: String,
    },
    /// rustls rejected the assembled configuration (typically cert/key mismatch).
    #[error("TLS configuration failed: {0}")]
    Rustls(#[from] rustls::Error),
    /// Binding the listen address failed.
    #[error("failed to bind TLS listener: {0}")]
    Bind(#[from] std::io::Error),
}

/// Peer certificate info attached to each accepted connection.
#[derive(Clone, Debug)]
pub struct PeerCert {
    /// Socket address of the peer (diagnostics only; never used for auth).
    pub remote: SocketAddr,
    /// SPKI-SHA256 fingerprint of the presented client certificate, if any.
    /// `None` means the peer sent no client certificate.
    pub fingerprint: Option<String>,
}

/// The single TLS listener: accepts TCP, completes the handshake, records the
/// peer fingerprint, and hands axum a [`TlsStream`].
pub struct TlsListener {
    listener: TcpListener,
    acceptor: TlsAcceptor,
}

impl TlsListener {
    /// The bound local address — meaningful after an ephemeral `:0` bind.
    ///
    /// # Errors
    /// Propagates the underlying `local_addr` I/O error.
    pub fn bind_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }
}

/// Bind `addr` and wrap it with `config`'s TLS acceptor.
///
/// # Errors
/// [`TlsError::Bind`] if the address cannot be bound.
pub async fn bind(addr: &str, config: RustlsServerConfig) -> Result<TlsListener, TlsError> {
    let listener = TcpListener::bind(addr).await?;
    Ok(TlsListener {
        listener,
        acceptor: TlsAcceptor::from(Arc::new(config)),
    })
}

/// An accepted connection: plain TCP, or a completed TLS handshake.
#[derive(Debug)]
pub enum AcceptedStream {
    /// Plaintext TCP stream (no TLS termination on this listener).
    Plain(TcpStream),
    /// TLS stream accepted by [`TlsListener`]. Boxed to keep the enum small
    /// (the TLS state machine is over 1 KB).
    Tls(Box<TlsStream<TcpStream>>),
}

impl tokio::io::AsyncRead for AcceptedStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Plain(stream) => std::pin::Pin::new(stream).poll_read(cx, buf),
            Self::Tls(stream) => std::pin::Pin::new(stream.as_mut()).poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for AcceptedStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match &mut *self {
            Self::Plain(stream) => std::pin::Pin::new(stream).poll_write(cx, buf),
            Self::Tls(stream) => std::pin::Pin::new(stream.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Plain(stream) => std::pin::Pin::new(stream).poll_flush(cx),
            Self::Tls(stream) => std::pin::Pin::new(stream.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Plain(stream) => std::pin::Pin::new(stream).poll_shutdown(cx),
            Self::Tls(stream) => std::pin::Pin::new(stream.as_mut()).poll_shutdown(cx),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            Self::Plain(stream) => stream.is_write_vectored(),
            Self::Tls(stream) => stream.is_write_vectored(),
        }
    }
}

/// The server's main listener: plaintext TCP by default, TLS when
/// `[server] tls_cert`/`tls_key` are configured. Either way, the connection
/// info handed to axum is a [`PeerCert`] — with a client-certificate
/// fingerprint only on the TLS variant, so pin-gated routes fail closed on
/// plaintext connections.
pub enum ServerListener {
    /// Plaintext TCP listener (the default; no TLS pair configured).
    Plain(TcpListener),
    /// TLS listener ([`TlsListener`] with the configured or identity cert).
    Tls(TlsListener),
}

impl Listener for ServerListener {
    type Io = AcceptedStream;
    type Addr = PeerCert;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self {
            Self::Plain(listener) => {
                // Axum's blanket `Listener` impl for tokio `TcpListener`
                // already retries failed accepts internally.
                let (tcp, remote) = listener.accept().await;
                (
                    Self::Io::Plain(tcp),
                    PeerCert {
                        remote,
                        fingerprint: None,
                    },
                )
            }
            // `TlsListener::accept` already retries failed handshakes internally.
            Self::Tls(listener) => {
                let (stream, addr) = listener.accept().await;
                (Self::Io::Tls(Box::new(stream)), addr)
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        Ok(match self {
            Self::Plain(listener) => PeerCert {
                remote: listener.local_addr()?,
                fingerprint: None,
            },
            Self::Tls(listener) => listener.local_addr()?,
        })
    }
}

impl<'a> Connected<IncomingStream<'a, ServerListener>> for PeerCert {
    fn connect_info(stream: IncomingStream<'a, ServerListener>) -> Self {
        stream.remote_addr().clone()
    }
}

impl Listener for TlsListener {
    type Io = TlsStream<TcpStream>;
    type Addr = PeerCert;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        // axum's `Listener::accept` cannot report errors, so a failed TCP
        // accept or TLS handshake must be retried here rather than surfaced.
        loop {
            match self.listener.accept().await {
                Ok((tcp, remote)) => match self.acceptor.accept(tcp).await {
                    Ok(stream) => {
                        let fingerprint = peer_fingerprint(stream.get_ref().1);
                        return (
                            stream,
                            PeerCert {
                                remote,
                                fingerprint,
                            },
                        );
                    }
                    Err(err) => {
                        tracing::debug!(%err, "TLS handshake failed; dropping connection");
                    }
                },
                Err(err) => {
                    tracing::warn!(%err, "TCP accept failed; retrying");
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        Ok(PeerCert {
            remote: self.listener.local_addr()?,
            fingerprint: None,
        })
    }
}

impl<'a> Connected<IncomingStream<'a, TlsListener>> for PeerCert {
    fn connect_info(stream: IncomingStream<'a, TlsListener>) -> Self {
        stream.remote_addr().clone()
    }
}

/// Assemble the server TLS configuration.
///
/// Uses `[server] tls_cert`/`tls_key` when both are set, otherwise the task-13
/// Ed25519 [`Identity`] minted at `cluster.cert_path`. The client-certificate
/// verifier is optional ([`OptionalClientCert`]); the crypto provider is the
/// rustls default (aws-lc-rs).
///
/// # Errors
/// [`TlsError`] if PEM material is missing/unparseable or rustls rejects the
/// cert/key pair.
pub fn server_config(
    server: &ServerConfig,
    identity: &Identity,
) -> Result<RustlsServerConfig, TlsError> {
    let (certs, key) = match (server.tls_cert.as_deref(), server.tls_key.as_deref()) {
        (Some(cert_path), Some(key_path)) => (load_certs(cert_path)?, load_key(key_path)?),
        _ => (
            certs_from_pem(identity.cert_pem(), "identity certificate")?,
            key_from_pem(identity.key_pem())?,
        ),
    };
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let signature_algorithms = provider.signature_verification_algorithms;
    Ok(RustlsServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_client_cert_verifier(Arc::new(OptionalClientCert::new(signature_algorithms)))
        .with_single_cert(certs, key)?)
}

/// SPKI-SHA256 fingerprint of the peer's leaf certificate.
fn peer_fingerprint(connection: &rustls::ServerConnection) -> Option<String> {
    let leaf = connection.peer_certificates()?.first()?;
    let parsed = rustls::server::ParsedCertificate::try_from(leaf).ok()?;
    Some(fingerprint_spki(parsed.subject_public_key_info().as_ref()))
}

/// Read every certificate from a PEM file.
fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let data = std::fs::read(path).map_err(|source| TlsError::Material {
        path: path.to_path_buf(),
        source,
    })?;
    let mut reader = std::io::BufReader::new(data.as_slice());
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| TlsError::Material {
            path: path.to_path_buf(),
            source,
        })?;
    if certs.is_empty() {
        return Err(TlsError::NoCertificate {
            path: path.to_path_buf(),
        });
    }
    Ok(certs)
}

/// Read one private key from a PEM file.
fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>, TlsError> {
    let data = std::fs::read(path).map_err(|source| TlsError::Material {
        path: path.to_path_buf(),
        source,
    })?;
    let mut reader = std::io::BufReader::new(data.as_slice());
    rustls_pemfile::private_key(&mut reader)
        .map_err(|source| TlsError::Material {
            path: path.to_path_buf(),
            source,
        })?
        .ok_or_else(|| TlsError::NoPrivateKey {
            path: path.to_path_buf(),
        })
}

/// Parse certificates out of an in-memory PEM string (task-13 identity).
fn certs_from_pem(pem: &str, what: &str) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let mut reader = std::io::BufReader::new(pem.as_bytes());
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| TlsError::Identity {
            reason: format!("{what}: {source}"),
        })?;
    if certs.is_empty() {
        return Err(TlsError::Identity {
            reason: format!("{what} PEM contained no certificate"),
        });
    }
    Ok(certs)
}

/// Parse one private key out of an in-memory PEM string (task-13 identity).
fn key_from_pem(pem: &str) -> Result<PrivateKeyDer<'static>, TlsError> {
    let mut reader = std::io::BufReader::new(pem.as_bytes());
    rustls_pemfile::private_key(&mut reader)
        .map_err(|source| TlsError::Identity {
            reason: format!("identity private key: {source}"),
        })?
        .ok_or_else(|| TlsError::Identity {
            reason: String::from("identity private-key PEM contained no key"),
        })
}
