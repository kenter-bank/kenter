use base64::prelude::*;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha512};
use stellar_strkey::ed25519::{
    PrivateKey as StellarSecret, PublicKey as StellarPublic,
};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{CryptoError, Result};

/// Unified keypair bridging Stellar, Ed25519, and X25519.
///
/// Wraps an Ed25519 signing key and provides conversions to all the
/// key formats needed by the Kenter system:
/// - Stellar addresses (G.../S... format)
/// - X25519 keys (for ECDH)
/// - Biscuit keypairs (for token signing)
pub struct StellarKeypair {
    signing: SigningKey,
}

impl StellarKeypair {
    /// Generate a random keypair.
    pub fn random() -> Self {
        let mut rng = rand::rngs::OsRng;
        let signing = SigningKey::generate(&mut rng);
        Self { signing }
    }

    /// Create from a Stellar secret key string (S...).
    pub fn from_stellar_secret(secret: &str) -> Result<Self> {
        let decoded = StellarSecret::from_string(secret)
            .map_err(|e| CryptoError::InvalidStellarSecret(e.to_string()))?;
        Ok(Self::from_raw_secret(&decoded.0))
    }

    /// Create a verify-only keypair from a Stellar address (G...).
    ///
    /// This constructs a keypair that can only verify signatures — signing
    /// will produce invalid results since we don't have the real secret.
    /// Used for sender authentication in decryption.
    pub fn from_stellar_address(address: &str) -> Result<VerifyOnlyKey> {
        let decoded = StellarPublic::from_string(address)
            .map_err(|e| CryptoError::InvalidStellarAddress(e.to_string()))?;
        let verifying_key = VerifyingKey::from_bytes(&decoded.0)
            .map_err(|e| CryptoError::InvalidStellarAddress(e.to_string()))?;
        Ok(VerifyOnlyKey { verifying_key })
    }

    /// Create from raw 32-byte Ed25519 seed.
    pub fn from_raw_secret(bytes: &[u8; 32]) -> Self {
        let signing = SigningKey::from_bytes(bytes);
        Self { signing }
    }

    // -- Identity --

    /// Stellar public address (G...).
    pub fn stellar_address(&self) -> String {
        let pub_bytes = self.signing.verifying_key().to_bytes();
        let heapless_str = StellarPublic(pub_bytes).to_string();
        String::from(heapless_str.as_str())
    }

    /// Stellar secret key (S...). Returns zeroizing wrapper.
    pub fn stellar_secret(&self) -> Zeroizing<String> {
        let secret_bytes = self.signing.to_bytes();
        let heapless_str = StellarSecret(secret_bytes).to_string();
        let s = String::from(heapless_str.as_str());
        let _ = Zeroizing::new(secret_bytes);
        Zeroizing::new(s)
    }

    /// Raw 32-byte Ed25519 secret seed.
    pub fn raw_secret(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.signing.to_bytes())
    }

    /// Raw 32-byte Ed25519 public key.
    pub fn raw_public(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    /// Ed25519 verifying (public) key.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }

    // -- Ed25519 signing --

    /// Sign a message with this keypair's Ed25519 key.
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing.sign(message)
    }

    /// Verify a signature against a public key.
    pub fn verify(
        public: &VerifyingKey,
        message: &[u8],
        sig: &Signature,
    ) -> Result<()> {
        public
            .verify(message, sig)
            .map_err(|_| CryptoError::SignatureVerificationFailed)
    }

    // -- X25519 conversion (for ECDH) --

    /// Convert Ed25519 secret to X25519 static secret.
    ///
    /// Uses the standard Ed25519→X25519 clamping conversion:
    /// SHA-512 the seed, take first 32 bytes, clamp.
    /// This matches libsodium's `crypto_sign_ed25519_sk_to_curve25519`.
    pub fn to_x25519_secret(&self) -> Zeroizing<StaticSecret> {
        let ed_secret = self.signing.to_bytes();
        let hash = Sha512::digest(ed_secret);
        let mut curve_secret = [0u8; 32];
        curve_secret.copy_from_slice(&hash[..32]);

        // Clamp (same as libsodium)
        curve_secret[0] &= 248;
        curve_secret[31] &= 127;
        curve_secret[31] |= 64;

        let static_secret = StaticSecret::from(curve_secret);
        curve_secret.zeroize();
        Zeroizing::new(static_secret)
    }

    /// Get X25519 public key derived from this keypair.
    pub fn to_x25519_public(&self) -> X25519Public {
        let secret = self.to_x25519_secret();
        X25519Public::from(&*secret)
    }

    /// Convert an Ed25519 verifying key to X25519 public key.
    ///
    /// Uses the birational map from the Ed25519 Edwards curve to the
    /// X25519 Montgomery curve. Matches libsodium's
    /// `crypto_sign_ed25519_pk_to_curve25519`.
    pub fn x25519_public_from_ed25519(ed_pub: &VerifyingKey) -> Result<X25519Public> {
        use curve25519_dalek::edwards::CompressedEdwardsY;

        let compressed = CompressedEdwardsY::from_slice(ed_pub.as_bytes())
            .map_err(|e| CryptoError::InvalidKeyLength {
                expected: 32,
                got: e.to_string().len(),
            })?;

        let point = compressed
            .decompress()
            .ok_or_else(|| CryptoError::EcdhFailed("invalid Ed25519 point".into()))?;

        let montgomery = point.to_montgomery();
        Ok(X25519Public::from(montgomery.to_bytes()))
    }

    /// X25519 public key as base64url (matches Python's `public_key()` method).
    ///
    /// The Python side does:
    ///   base64.urlsafe_b64encode(x25519_public_bytes)
    /// which includes `=` padding.
    pub fn x25519_public_b64url(&self) -> String {
        let x_pub = self.to_x25519_public();
        BASE64_URL_SAFE.encode(x_pub.as_bytes())
    }

}

/// A public-key-only handle for signature verification.
///
/// Created from a Stellar address when we need to verify a signature
/// but don't have (or need) the private key.
pub struct VerifyOnlyKey {
    verifying_key: VerifyingKey,
}

impl VerifyOnlyKey {
    /// Verify a signature against this public key.
    pub fn verify(&self, message: &[u8], sig: &Signature) -> Result<()> {
        self.verifying_key
            .verify(message, sig)
            .map_err(|_| CryptoError::SignatureVerificationFailed)
    }
}

impl Clone for StellarKeypair {
    fn clone(&self) -> Self {
        Self {
            signing: self.signing.clone(),
        }
    }
}

impl Drop for StellarKeypair {
    fn drop(&mut self) {
        // SigningKey from ed25519-dalek with zeroize feature handles this,
        // but we explicitly note the intent here.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip_stellar_secret() {
        let kp = StellarKeypair::random();
        let secret = kp.stellar_secret();
        let kp2 = StellarKeypair::from_stellar_secret(&secret).unwrap();
        assert_eq!(kp.stellar_address(), kp2.stellar_address());
    }

    #[test]
    fn test_sign_verify() {
        let kp = StellarKeypair::random();
        let msg = b"hello world";
        let sig = kp.sign(msg);
        StellarKeypair::verify(&kp.verifying_key(), msg, &sig).unwrap();
    }

    #[test]
    fn test_x25519_public_from_ed25519_roundtrip() {
        let kp = StellarKeypair::random();
        let x_pub_direct = kp.to_x25519_public();
        let x_pub_from_ed =
            StellarKeypair::x25519_public_from_ed25519(&kp.verifying_key()).unwrap();
        assert_eq!(x_pub_direct.as_bytes(), x_pub_from_ed.as_bytes());
    }
}
