//! JWKS key material and the `(issuer, kid)` lookup contract (docs/oidc.md).
//!
//! `auth::oidc` verifies RS256 signatures against a [`JwksKey`] resolved by
//! `(issuer, kid)`. This file keeps the two halves of the mechanism apart:
//! the *key representation* + *lookup contract* live here, the deployment
//! plumbing (a periodic + lazy singleflight fetcher over the configured IdP
//! endpoints) follows as the live [`RsaKeySource`] implementation. Unit tests
//! inject an in-memory source instead.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// One RSA public key in JWKS shape: modulus `n` and exponent `e`, both
/// already base64url-decoded. Only `kty == "RSA"` records are admitted
/// upstream; ES/EC and symmetric keys never become a [`JwksKey`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JwksKey {
    /// RSA modulus (big-endian bytes).
    pub n: Vec<u8>,
    /// RSA public exponent (big-endian bytes; standard JWKS `AQAB` = 65537).
    pub e: Vec<u8>,
}

impl JwksKey {
    /// Build a key from a JWKS record's base64url-encoded `n`/`e` fields.
    /// Undecodable fields produce `None`; the record is ignored.
    pub fn from_b64url(n: &str, e: &str) -> Option<Self> {
        let n = URL_SAFE_NO_PAD.decode(n).ok()?;
        let e = URL_SAFE_NO_PAD.decode(e).ok()?;
        Some(Self { n, e })
    }

    /// Verify an RS256 (PKCS#1 SHA-256) signature over `message`.
    ///
    /// The parameters are fixed to RSA_PKCS1_2048_8192_SHA256 (2048..=8192
    /// bit keys); the verifier never negotiates a weaker parameter set.
    ///
    /// # Errors
    /// The wrapped error is the raw verification failure; `auth::oidc` maps
    /// it to its `Signature` gate without inspecting it.
    pub fn verify(
        &self,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), aws_lc_rs::error::Unspecified> {
        let components = aws_lc_rs::signature::RsaPublicKeyComponents {
            n: self.n.as_slice(),
            e: self.e.as_slice(),
        };
        components.verify(
            &aws_lc_rs::signature::RSA_PKCS1_2048_8192_SHA256,
            message,
            signature,
        )
    }
}

/// `(issuer, kid) -> RSA key` lookup for `auth::oidc`.
///
/// A `None` return is the "no key (yet)" signal: the verifier fails that one
/// token closed ([`crate::auth::oidc::OidcError::UnknownKid`]) without
/// distinguishing it from a signature failure - the 401 is identical.
///
/// The method is synchronous by contract: the live implementation performs
/// its lazy unknown-kid refresh synchronously under the fetcher's bounded
/// IO timeouts, so the verifier never bears an `async` plumbing surface.
pub trait RsaKeySource: Send + Sync {
    /// Look up the key minted by `issuer` under key id `kid`.
    fn key(&self, issuer: &str, kid: &str) -> Option<JwksKey>;
}
