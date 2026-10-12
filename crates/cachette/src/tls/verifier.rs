//! Client-certificate verifier for the single TLS listener (plan task 14 / B1).
//!
//! Cachette serves every route on one rustls listener, but only the internal
//! `/_internal/peers/*` routes require a peer certificate. The verifier here
//! therefore *offers* client authentication without requiring it: a connection
//! may present no certificate at all (public health/v1/v2 traffic), and any
//! certificate that is presented is accepted at the TLS layer and its SPKI
//! fingerprint is checked later by the pin middleware ([`crate::tls::PeerPins`]).
//!
//! This is deliberately *not* a web-PKI trust decision: cachette peers are
//! self-signed and trusted by raw SPKI-fingerprint pinning, not by a CA. The
//! verifier still delegates signature checks to the crypto provider so a peer
//! cannot present a certificate whose key it does not hold.

use rustls::client::danger::HandshakeSignatureValid;
use rustls::crypto::{WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DistinguishedName, Error, SignatureScheme};

/// A [`ClientCertVerifier`] that accepts any presented certificate.
///
/// * `offer_client_auth` is `true` so the server sends a CertificateRequest.
/// * `client_auth_mandatory` is `false` so certless clients still complete the
///   handshake (public routes never inspect a peer certificate).
/// * `verify_client_cert` accepts unconditionally; authorization is the pin
///   store's job, not the TLS layer's.
/// * The TLS 1.2/1.3 signature callbacks are delegated to the provider's
///   [`WebPkiSupportedAlgorithms`], so a peer must actually hold the private
///   key for the certificate it presents.
#[derive(Debug)]
pub struct OptionalClientCert {
    signature_algorithms: WebPkiSupportedAlgorithms,
}

impl OptionalClientCert {
    /// Wrap the provider's signature algorithm set (typically
    /// [`rustls::crypto::aws_lc_rs::default_provider`]'s
    /// `signature_verification_algorithms`).
    #[must_use]
    pub fn new(signature_algorithms: WebPkiSupportedAlgorithms) -> Self {
        Self {
            signature_algorithms,
        }
    }
}

impl ClientCertVerifier for OptionalClientCert {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        false
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        // Accept at the TLS layer; the pin middleware decides authorization.
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls12_signature(message, cert, dss, &self.signature_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(message, cert, dss, &self.signature_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.signature_algorithms.supported_schemes()
    }
}
