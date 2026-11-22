use sha2::{Digest, Sha256};
use x25519_dalek::PublicKey as X25519Public;
use zeroize::Zeroizing;

use crate::domain::DomainSeparation;
use crate::error::{CryptoError, Result};
use crate::keypair::StellarKeypair;

/// ECDH shared secret derivation between two Stellar identities.
///
/// Mirrors the Python `StellarKeyBase` / `StellarSharedKey` behavior:
/// 1. Convert Ed25519 keys to X25519
/// 2. Perform NaCl Box key derivation (X25519 DH + HSalsa20)
/// 3. Optionally derive key with salt: SHA256(salt || shared_secret)
///
/// IMPORTANT: Python's `Box(PrivateKey, PublicKey).shared_key()` does NOT
/// return the raw X25519 DH output. It returns `HSalsa20(raw_dh)` — the
/// NaCl "beforenm" key. We must replicate that exact derivation.
pub struct SharedSecret {
    /// The NaCl Box shared key (HSalsa20 of raw X25519 DH output).
    /// This is what Python's `box.shared_key()` returns.
    raw: Zeroizing<[u8; 32]>,
}

impl SharedSecret {
    /// Perform NaCl-compatible ECDH: X25519 DH + HSalsa20.
    ///
    /// This matches Python's `Box(PrivateKey, PublicKey).shared_key()`.
    fn from_nacl_box(
        own_x25519_secret: &x25519_dalek::StaticSecret,
        peer_x25519_public: &X25519Public,
    ) -> Self {
        // crypto_box::SalsaBox computes the NaCl shared key internally.
        // We need to extract it. The NaCl shared key is:
        //   HSalsa20(X25519(sk, pk), zero_nonce)
        //
        // We can compute this using the crypto_box precomputation.
        use crypto_box::aead::OsRng;

        // Convert to crypto_box types
        let secret_key = crypto_box::SecretKey::from(own_x25519_secret.to_bytes());
        let public_key = crypto_box::PublicKey::from(*peer_x25519_public.as_bytes());

        // SalsaBox::new performs the HSalsa20 key derivation
        let salsa_box = crypto_box::SalsaBox::new(&public_key, &secret_key);

        // Extract the shared key bytes.
        // crypto_box doesn't expose the shared key directly, so we need
        // to use the low-level HSalsa20 function ourselves.
        let raw_dh = own_x25519_secret.diffie_hellman(peer_x25519_public);
        let shared_key = hsalsa20(raw_dh.as_bytes());

        drop(salsa_box);
        let _ = OsRng; // suppress unused import

        Self {
            raw: Zeroizing::new(shared_key),
        }
    }

    /// Perform NaCl-compatible ECDH from raw X25519 keys.
    ///
    /// Public entry point for use by the encrypt module.
    pub fn derive_from_x25519(
        own_secret: &x25519_dalek::StaticSecret,
        peer_public: &X25519Public,
    ) -> Self {
        Self::from_nacl_box(own_secret, peer_public)
    }

    /// Derive shared secret from two Stellar keypairs.
    ///
    /// Converts Ed25519 keys to X25519, then performs NaCl Box key derivation.
    /// Both parties get the same result regardless of who is "sender" vs "receiver".
    pub fn derive(
        own_keypair: &StellarKeypair,
        peer_keypair: &StellarKeypair,
    ) -> Self {
        let own_x25519 = own_keypair.to_x25519_secret();
        let peer_x25519 = peer_keypair.to_x25519_public();
        Self::from_nacl_box(&own_x25519, &peer_x25519)
    }

    /// Derive shared secret from own keypair and peer's base64url-encoded
    /// X25519 public key (the 32-byte Curve25519 form of the Stellar key).
    pub fn derive_from_b64url(
        own_keypair: &StellarKeypair,
        peer_x25519_pub_b64url: &str,
    ) -> Result<Self> {
        use base64::prelude::*;

        let peer_bytes = BASE64_URL_SAFE
            .decode(peer_x25519_pub_b64url)
            .map_err(|e| CryptoError::Base64Error(e.to_string()))?;

        if peer_bytes.len() != 32 {
            return Err(CryptoError::InvalidKeyLength {
                expected: 32,
                got: peer_bytes.len(),
            });
        }

        let mut arr = [0u8; 32];
        arr.copy_from_slice(&peer_bytes);
        let peer_x25519 = X25519Public::from(arr);

        let own_x25519 = own_keypair.to_x25519_secret();
        Ok(Self::from_nacl_box(&own_x25519, &peer_x25519))
    }

    /// Raw 32-byte shared secret (NaCl Box shared key).
    ///
    /// In Python: `box.shared_key()` or `shared_secret()` with no salt.
    pub fn raw_bytes(&self) -> &[u8; 32] {
        &self.raw
    }

    /// Derive a key using salt: SHA256(salt || shared_secret).
    ///
    /// Matches Python's `_derive_key(salt)`.
    pub fn derive_key(&self, salt: &[u8]) -> Zeroizing<[u8; 32]> {
        let mut hasher = Sha256::new();
        hasher.update(salt);
        hasher.update(self.raw.as_ref());
        let hash = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&hash);
        Zeroizing::new(key)
    }

    /// Derive a signing key with domain separation.
    ///
    /// Matches Python's `_derive_signing_key(shared_secret, domain)`:
    ///   SHA256(domain + shared_secret).hexdigest()
    ///
    /// Returns the hex-encoded 32-byte key (64 ASCII chars).
    pub fn derive_signing_key(&self, domain: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(domain);
        hasher.update(self.raw.as_ref());
        let hash = hasher.finalize();
        hex::encode(hash)
    }

    /// Derive signing key using default TOKEN_SIGNING domain.
    pub fn derive_token_signing_key(&self) -> String {
        self.derive_signing_key(DomainSeparation::TOKEN_SIGNING)
    }
}

/// HSalsa20 core function: derives a 32-byte key from a 32-byte input.
///
/// This is what NaCl uses to convert the raw X25519 DH output into the
/// crypto_box shared key. Uses a zero nonce.
///
/// Reference: https://cr.yp.to/highspeed/naclcrypto-20090310.pdf
fn hsalsa20(shared_point: &[u8; 32]) -> [u8; 32] {
    use salsa20::cipher::consts::U10;
    use salsa20::cipher::generic_array::GenericArray;
    use salsa20::hsalsa;

    let key = GenericArray::from_slice(shared_point);
    let zero_nonce: GenericArray<u8, _> = GenericArray::default(); // 16 zero bytes

    let result = hsalsa::<U10>(key, &zero_nonce);
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

impl Drop for SharedSecret {
    fn drop(&mut self) {
        // Zeroizing handles cleanup of raw bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ecdh_symmetry() {
        let kp1 = StellarKeypair::random();
        let kp2 = StellarKeypair::random();

        let shared_1_2 = SharedSecret::derive(&kp1, &kp2);
        let shared_2_1 = SharedSecret::derive(&kp2, &kp1);

        assert_eq!(shared_1_2.raw_bytes(), shared_2_1.raw_bytes());
    }

    #[test]
    fn test_derive_from_b64url() {
        let kp1 = StellarKeypair::random();
        let kp2 = StellarKeypair::random();

        let b64url = kp2.x25519_public_b64url();

        let shared_direct = SharedSecret::derive(&kp1, &kp2);
        let shared_b64 = SharedSecret::derive_from_b64url(&kp1, &b64url).unwrap();

        assert_eq!(shared_direct.raw_bytes(), shared_b64.raw_bytes());
    }
}
