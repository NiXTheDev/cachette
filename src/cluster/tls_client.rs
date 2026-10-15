//! Shared outbound mTLS client for peer-to-peer calls (plan tasks 29/31).
//!
//! Both the heartbeat sender (task 29) and the v1 relay (task 31) dial peers
//! over a fresh TLS connection that presents *this* node's identity certificate
//! as the client credential and accepts the peer's certificate only when its
//! SPKI-SHA256 fingerprint passes [`PeerPins`] (seeded or TOFU) — the mirror
//! image of the inbound pin gate in [`crate::routes`]. Factoring the client
//! config here keeps the two callers in agreement on that trust decision.
//!
//! This is deliberately *not* a web-PKI decision: peers are self-signed and
//! trusted by raw fingerprint pinning. Signature checks still run through the
//! crypto provider, so a peer cannot present a certificate whose private key it
//! does not hold.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig as RustlsClientConfig, DigitallySignedStruct, Error as RustlsError,
    SignatureScheme,
};

use crate::identity::fingerprint_spki;
use crate::tls::PeerPins;

/// Pin-based server-certificate verifier for outbound peer connections.
#[derive(Debug)]
pub(crate) struct PinnedServerCert {
    pins: Arc<PeerPins>,
    algs: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for PinnedServerCert {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        let parsed = rustls::server::ParsedCertificate::try_from(end_entity)
            .map_err(|err| RustlsError::General(format!("peer certificate unusable: {err}")))?;
        let fingerprint = fingerprint_spki(parsed.subject_public_key_info().as_ref());
        if self.pins.authorize(&fingerprint) {
            return Ok(ServerCertVerified::assertion());
        }
        Err(RustlsError::General(format!(
            "peer certificate not pinned: {fingerprint}"
        )))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls12_signature(message, cert, dss, &self.algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

/// Assemble the outbound mTLS client: `cert_pem`/`key_pem` (this node's
/// identity) as the client credential, [`PinnedServerCert`] as the trust
/// decision against `pins`.
pub(crate) fn client_config(
    cert_pem: &str,
    key_pem: &str,
    pins: Arc<PeerPins>,
) -> Result<Arc<RustlsClientConfig>, RustlsError> {
    let mut reader = std::io::BufReader::new(cert_pem.as_bytes());
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()
        .map_err(|err| RustlsError::General(format!("identity certificate: {err}")))?;
    if certs.is_empty() {
        return Err(RustlsError::General(String::from(
            "identity certificate PEM was empty",
        )));
    }
    let mut reader = std::io::BufReader::new(key_pem.as_bytes());
    let key = rustls_pemfile::private_key(&mut reader)
        .map_err(|err| RustlsError::General(format!("identity key: {err}")))?
        .ok_or_else(|| RustlsError::General(String::from("identity key PEM was empty")))?;
    let verifier = PinnedServerCert {
        pins,
        algs: rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms,
    };
    let tls = RustlsClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_client_auth_cert(certs, key)?;
    Ok(Arc::new(tls))
}
