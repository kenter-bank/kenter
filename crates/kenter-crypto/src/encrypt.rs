use base64::prelude::*;
use crypto_box::{
    aead::{Aead, AeadCore, KeyInit},
    SalsaBox,
};
use sha2::{Digest, Sha256};
use x25519_dalek::PublicKey as X25519Public;

use crate::ecdh::SharedSecret;
use crate::error::{CryptoError, Result};
use crate::keypair::StellarKeypair;

/// XSalsa20-Poly1305 nonce length. Named so the length check below is
/// obviously the same number the cipher expects.
const NONCE_LEN: usize = 24;

/// Compute the NaCl Box shared key from ephemeral key bytes.
///
/// This is needed because `crypto_box::SecretKey` reduces the scalar modulo
/// the group order, which gives incorrect results for arbitrary 32-byte inputs
/// (like SHA256-derived ephemeral keys in the hybrid scheme). For legitimate
/// X25519 public keys the reduction is transparent, but SHA256 outputs can
/// represent Montgomery points with non-trivial cofactor components.
///
/// Instead, we use `x25519_dalek::StaticSecret` (which does NOT reduce mod order)
/// for the DH, then apply HSalsa20 manually.
fn ephemeral_shared_key(private_bytes: &[u8; 32], public_bytes: &[u8; 32]) -> [u8; 32] {
    let static_secret = x25519_dalek::StaticSecret::from(*private_bytes);
    let public_key = x25519_dalek::PublicKey::from(*public_bytes);
    let raw_dh = static_secret.diffie_hellman(&public_key);

    // Apply HSalsa20 with zero nonce (matches NaCl's crypto_box_beforenm)
    use salsa20::cipher::consts::U10;
    use salsa20::cipher::generic_array::GenericArray;
    use salsa20::hsalsa;

    let key = GenericArray::from_slice(raw_dh.as_bytes());
    let zero_nonce: GenericArray<u8, _> = GenericArray::default();
    let result = hsalsa::<U10>(key, &zero_nonce);

    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Asymmetric encryption using NaCl Box (XSalsa20-Poly1305).
///
/// Matches Python's `StellarSharedKey.asymmetric_encrypt()`.
///
/// Wire format: `base64url(salt) | base64url(nonce) | hex(ciphertext)`
///
/// Note: salt is included for format compatibility but is NOT used in
/// key derivation for asymmetric mode — the raw NaCl Box key is used directly.
pub fn asymmetric_encrypt(
    sender: &StellarKeypair,
    receiver_x25519_pub: &X25519Public,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let sender_secret = sender.to_x25519_secret();

    let secret_key = crypto_box::SecretKey::from(sender_secret.to_bytes());
    let public_key = crypto_box::PublicKey::from(*receiver_x25519_pub.as_bytes());
    let salsa_box = SalsaBox::new(&public_key, &secret_key);

    // Generate random salt and nonce
    let salt: [u8; 32] = rand::random();
    let nonce = SalsaBox::generate_nonce(&mut rand::rngs::OsRng);

    // Encrypt
    let ciphertext = salsa_box
        .encrypt(&nonce, plaintext)
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

    // Format: salt_b64url | nonce_b64url | ciphertext_hex
    let mut output = Vec::new();
    output.extend_from_slice(BASE64_URL_SAFE.encode(salt).as_bytes());
    output.push(b'|');
    output.extend_from_slice(BASE64_URL_SAFE.encode(nonce.as_slice()).as_bytes());
    output.push(b'|');
    output.extend_from_slice(hex::encode(&ciphertext).as_bytes());

    Ok(output)
}

/// Asymmetric decryption using NaCl Box.
///
/// Matches Python's `StellarSharedDecryption.asymmetric_decrypt()`.
pub fn asymmetric_decrypt(
    receiver: &StellarKeypair,
    sender_x25519_pub: &X25519Public,
    encrypted_data: &[u8],
) -> Result<Vec<u8>> {
    let parts: Vec<&[u8]> = encrypted_data.splitn(3, |&b| b == b'|').collect();
    if parts.len() != 3 {
        return Err(CryptoError::InvalidTokenFormat(
            "expected salt|nonce|ciphertext".into(),
        ));
    }

    let _salt = BASE64_URL_SAFE
        .decode(parts[0])
        .map_err(|e| CryptoError::Base64Error(e.to_string()))?;

    let nonce_bytes = BASE64_URL_SAFE
        .decode(parts[1])
        .map_err(|e| CryptoError::Base64Error(e.to_string()))?;

    // Length-checked rather than passed straight to `from_slice`,
    // which panics on anything but 24 bytes. The input here is an
    // attacker-shaped string: this is reached from
    // `RedemptionSession::receive_shard`, so a node could abort the
    // wallet with a short nonce instead of merely failing to decrypt.
    if nonce_bytes.len() != NONCE_LEN {
        return Err(CryptoError::DecryptionFailed(format!(
            "nonce is {} bytes, expected {NONCE_LEN}",
            nonce_bytes.len()
        )));
    }
    let nonce = crypto_box::Nonce::from_slice(&nonce_bytes);

    let ciphertext = hex::decode(parts[2])
        .map_err(|e| CryptoError::DecryptionFailed(format!("hex decode: {e}")))?;

    let receiver_secret = receiver.to_x25519_secret();
    let secret_key = crypto_box::SecretKey::from(receiver_secret.to_bytes());
    let public_key = crypto_box::PublicKey::from(*sender_x25519_pub.as_bytes());
    let salsa_box = SalsaBox::new(&public_key, &secret_key);

    salsa_box
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))
}

/// Signature-based hybrid encryption.
///
/// Matches Python's `StellarSharedKey.encrypt()`.
///
/// Wire format: `base64url(salt) | base64url(nonce) | base64url(signature) | hex(ciphertext)`
///
/// Steps:
/// 1. Generate random salt (32 bytes) and nonce (24 bytes)
/// 2. Derive base key: SHA256(salt || NaCl_shared_key)
/// 3. Sign (salt || nonce) with sender's Ed25519 key → 64-byte signature
/// 4. Derive ephemeral Box keys from signature halves:
///    - private = SHA256(derived_key || sig[0..32])
///    - public  = SHA256(derived_key || sig[32..64])
/// 5. Encrypt with ephemeral NaCl Box
pub fn hybrid_encrypt(
    sender: &StellarKeypair,
    receiver_x25519_pub: &X25519Public,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    // Step 1: Generate fresh salt and nonce
    let salt: [u8; 32] = rand::random();
    let nonce_bytes: [u8; 24] = rand::random();

    // Step 2: Derive base key from NaCl shared key
    let shared = SharedSecret::derive_from_x25519(
        &sender.to_x25519_secret(),
        receiver_x25519_pub,
    );
    let derived_key = shared.derive_key(&salt);

    // Step 3: Sign salt+nonce with sender's Ed25519 key
    let mut message = Vec::with_capacity(56);
    message.extend_from_slice(&salt);
    message.extend_from_slice(&nonce_bytes);
    let signature = sender.sign(&message);
    let sig_bytes = signature.to_bytes();

    // Step 4: Derive ephemeral keys (SHA256 of derived_key + signature halves)
    let private_bytes: [u8; 32] = Sha256::digest([derived_key.as_ref(), &sig_bytes[..32]].concat()).into();
    let public_bytes: [u8; 32] = Sha256::digest([derived_key.as_ref(), &sig_bytes[32..]].concat()).into();

    // Step 5: Encrypt using XSalsa20Poly1305 with manually computed shared key.
    // We bypass SalsaBox::new because crypto_box::SecretKey reduces the scalar
    // mod the group order, which gives wrong results for arbitrary key bytes.
    let shared_key = ephemeral_shared_key(&private_bytes, &public_bytes);
    let cipher = crypto_secretbox::XSalsa20Poly1305::new(
        crypto_box::aead::generic_array::GenericArray::from_slice(&shared_key),
    );
    let nonce_ga = crypto_box::aead::generic_array::GenericArray::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce_ga, plaintext)
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

    // Format: salt_b64url | nonce_b64url | sig_b64url | ciphertext_hex
    let mut output = Vec::new();
    output.extend_from_slice(BASE64_URL_SAFE.encode(salt).as_bytes());
    output.push(b'|');
    output.extend_from_slice(BASE64_URL_SAFE.encode(nonce_bytes).as_bytes());
    output.push(b'|');
    output.extend_from_slice(BASE64_URL_SAFE.encode(sig_bytes).as_bytes());
    output.push(b'|');
    output.extend_from_slice(hex::encode(&ciphertext).as_bytes());

    Ok(output)
}

/// Signature-based hybrid decryption.
///
/// Matches Python's `StellarSharedDecryption.decrypt()`.
///
/// Verifies the sender's Ed25519 signature for authenticity before decrypting.
pub fn hybrid_decrypt(
    receiver: &StellarKeypair,
    sender_x25519_pub: &X25519Public,
    sender_ed25519_address: &str,
    encrypted_data: &[u8],
) -> Result<Vec<u8>> {
    let parts: Vec<&[u8]> = encrypted_data.splitn(4, |&b| b == b'|').collect();
    if parts.len() != 4 {
        return Err(CryptoError::InvalidTokenFormat(
            "expected salt|nonce|signature|ciphertext".into(),
        ));
    }

    // Decode components
    let salt = BASE64_URL_SAFE
        .decode(parts[0])
        .map_err(|e| CryptoError::Base64Error(e.to_string()))?;
    let nonce_bytes = BASE64_URL_SAFE
        .decode(parts[1])
        .map_err(|e| CryptoError::Base64Error(e.to_string()))?;
    let sig_bytes = BASE64_URL_SAFE
        .decode(parts[2])
        .map_err(|e| CryptoError::Base64Error(e.to_string()))?;
    let ciphertext = hex::decode(parts[3])
        .map_err(|e| CryptoError::DecryptionFailed(format!("hex decode: {e}")))?;

    // Verify sender's signature
    let sender_verify = StellarKeypair::from_stellar_address(sender_ed25519_address)?;
    let mut message = Vec::with_capacity(salt.len() + nonce_bytes.len());
    message.extend_from_slice(&salt);
    message.extend_from_slice(&nonce_bytes);

    let signature = ed25519_dalek::Signature::from_slice(&sig_bytes)
        .map_err(|_| CryptoError::SignatureVerificationFailed)?;
    sender_verify.verify(&message, &signature)?;

    // Derive base key
    let shared = SharedSecret::derive_from_x25519(
        &receiver.to_x25519_secret(),
        sender_x25519_pub,
    );
    let derived_key = shared.derive_key(&salt);

    // Derive ephemeral keys
    let private_bytes: [u8; 32] = Sha256::digest([derived_key.as_ref(), &sig_bytes[..32]].concat()).into();
    let public_bytes: [u8; 32] = Sha256::digest([derived_key.as_ref(), &sig_bytes[32..]].concat()).into();

    // Decrypt using XSalsa20Poly1305 with manually computed shared key.
    // We bypass SalsaBox::new because crypto_box::SecretKey reduces the scalar
    // mod the group order, which gives wrong results for arbitrary key bytes.
    let shared_key = ephemeral_shared_key(&private_bytes, &public_bytes);
    let cipher = crypto_secretbox::XSalsa20Poly1305::new(
        crypto_box::aead::generic_array::GenericArray::from_slice(&shared_key),
    );
    let nonce_ga = crypto_box::aead::generic_array::GenericArray::from_slice(&nonce_bytes);

    cipher
        .decrypt(nonce_ga, ciphertext.as_ref())
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))
}

/// Encrypt a Stellar keypair's raw secret for transmission.
///
/// The shared keypair secret (32 bytes) is hex-encoded then encrypted
/// using asymmetric encryption. This is the Rust replacement for the
/// Python macaroon-wrapped account token.
pub fn encrypt_keypair(
    sender: &StellarKeypair,
    receiver_x25519_pub: &X25519Public,
    shared_keypair: &StellarKeypair,
) -> Result<Vec<u8>> {
    let secret_hex = hex::encode(shared_keypair.raw_secret().as_ref());
    asymmetric_encrypt(sender, receiver_x25519_pub, secret_hex.as_bytes())
}

/// Decrypt a Stellar keypair from an encrypted transmission.
pub fn decrypt_keypair(
    receiver: &StellarKeypair,
    sender_x25519_pub: &X25519Public,
    encrypted_data: &[u8],
) -> Result<StellarKeypair> {
    let decrypted = asymmetric_decrypt(receiver, sender_x25519_pub, encrypted_data)?;
    let secret_hex = String::from_utf8(decrypted)
        .map_err(|e| CryptoError::DecryptionFailed(format!("invalid UTF-8: {e}")))?;
    let secret_bytes = hex::decode(&secret_hex)
        .map_err(|e| CryptoError::DecryptionFailed(format!("invalid hex: {e}")))?;
    if secret_bytes.len() != 32 {
        return Err(CryptoError::InvalidKeyLength {
            expected: 32,
            got: secret_bytes.len(),
        });
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&secret_bytes);
    Ok(StellarKeypair::from_raw_secret(&arr))
}

#[cfg(test)]
mod tests {
    /// **Crypto C5 regression.** A short nonce is an error, not a panic.
    ///
    /// This path is reached from `RedemptionSession::receive_shard`, so
    /// the string is whatever a node sent. `Nonce::from_slice` panics on
    /// anything but 24 bytes, which let a node abort the wallet rather
    /// than merely fail to decrypt.
    #[test]
    fn a_short_nonce_is_refused_without_panicking() {
        use super::*;
        let receiver = StellarKeypair::random();
        let sender = StellarKeypair::random();
        let sender_pub = sender.to_x25519_public();

        for nonce_len in [0usize, 3, 23, 25, 64] {
            let nonce = BASE64_URL_SAFE.encode(vec![0u8; nonce_len]);
            let payload = format!("{}|{nonce}|{}", BASE64_URL_SAFE.encode([0u8; 16]), "aabb");
            let r = asymmetric_decrypt(&receiver, &sender_pub, payload.as_bytes());
            assert!(r.is_err(), "nonce of {nonce_len} bytes must be refused");
        }
    }

    use super::*;

    #[test]
    fn test_asymmetric_roundtrip() {
        let sender = StellarKeypair::random();
        let receiver = StellarKeypair::random();
        let plaintext = b"hello from Kenter";

        let encrypted = asymmetric_encrypt(
            &sender,
            &receiver.to_x25519_public(),
            plaintext,
        )
        .unwrap();

        let decrypted = asymmetric_decrypt(
            &receiver,
            &sender.to_x25519_public(),
            &encrypted,
        )
        .unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_hybrid_roundtrip() {
        let sender = StellarKeypair::random();
        let receiver = StellarKeypair::random();
        let plaintext = b"hybrid encryption test data";

        let encrypted = hybrid_encrypt(
            &sender,
            &receiver.to_x25519_public(),
            plaintext,
        )
        .unwrap();

        let decrypted = hybrid_decrypt(
            &receiver,
            &sender.to_x25519_public(),
            &sender.stellar_address(),
            &encrypted,
        )
        .unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_keypair_encrypt_decrypt() {
        let sender = StellarKeypair::random();
        let receiver = StellarKeypair::random();
        let shared = StellarKeypair::random();

        let encrypted = encrypt_keypair(
            &sender,
            &receiver.to_x25519_public(),
            &shared,
        )
        .unwrap();

        let decrypted = decrypt_keypair(
            &receiver,
            &sender.to_x25519_public(),
            &encrypted,
        )
        .unwrap();

        assert_eq!(decrypted.stellar_address(), shared.stellar_address());
        assert_eq!(*decrypted.raw_secret(), *shared.raw_secret());
    }
}
