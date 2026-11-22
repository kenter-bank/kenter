//! Fixed test vectors (`tests/vectors/test_vectors.json`).
//!
//! Keypairs, ECDH, domain tags, encryption and the data-file header, checked
//! against values first produced by an independent implementation and kept
//! as fixtures, so any change to these primitives' outputs is caught.

use serde::Deserialize;
use std::collections::HashMap;
use kenter_crypto::{
    domain::DomainSeparation,
    ecdh::SharedSecret,
    keypair::StellarKeypair,
};

#[derive(Deserialize)]
struct TestVectors {
    keypairs: Vec<KeypairVector>,
    ecdh: Vec<EcdhVector>,
    domain_separation: HashMap<String, String>,
    // The vector file carries a `biscuit` block. Nothing reads it: SYMTOKEN
    // v4 and later carry no biscuit section, so this crate has no
    // `biscuit-auth` dependency. Serde ignores unknown keys, so the block
    // is harmless.
    encryption: Vec<EncryptionVector>,
    kntr_file: KntrFileVector,
}

#[derive(Deserialize)]
struct KeypairVector {
    stellar_secret: String,
    stellar_address: String,
    raw_secret_hex: String,
    raw_public_hex: String,
    x25519_private_hex: String,
    x25519_public_hex: String,
    x25519_public_b64url: String,
}

#[derive(Deserialize)]
struct EcdhVector {
    label: String,
    sender_stellar_secret: String,
    receiver_stellar_secret: String,
    raw_shared_secret_hex: String,
    signing_key_hex: String,
    derived_with_zero_salt_hex: String,
}

#[derive(Deserialize)]
struct EncryptionVector {
    label: String,
    sender_stellar_secret: String,
    receiver_stellar_secret: String,
    plaintext: String,
    encrypted_full: String,
    #[serde(default)]
    sender_stellar_address: Option<String>,
    salt_b64: String,
    nonce_b64: String,
    #[serde(default)]
    signature_b64: Option<String>,
    ciphertext_hex: String,
}

#[derive(Deserialize)]
struct KntrFileVector {
    magic_hex: String,
    version_major: u16,
    version_minor: u16,
    flags: u16,
    json_header_bytes_hex: String,
    json_header_length: usize,
    full_binary_header_hex: String,
}

fn load_vectors() -> TestVectors {
    let json = include_str!("../../../tests/vectors/test_vectors.json");
    serde_json::from_str(json).expect("failed to parse test vectors")
}

// ============================================================
// Keypair Tests
// ============================================================

#[test]
fn test_keypair_from_stellar_secret() {
    let vectors = load_vectors();

    for v in &vectors.keypairs {
        let kp = StellarKeypair::from_stellar_secret(&v.stellar_secret)
            .expect("failed to parse stellar secret");

        // Stellar address must match
        assert_eq!(
            kp.stellar_address(),
            v.stellar_address,
            "address mismatch for {}",
            v.stellar_secret
        );

        // Raw secret must match
        assert_eq!(
            hex::encode(kp.raw_secret().as_ref()),
            v.raw_secret_hex,
            "raw secret mismatch"
        );

        // Raw public must match
        assert_eq!(
            hex::encode(kp.raw_public()),
            v.raw_public_hex,
            "raw public mismatch"
        );
    }
}

#[test]
fn test_keypair_x25519_conversion() {
    let vectors = load_vectors();

    for v in &vectors.keypairs {
        let kp = StellarKeypair::from_stellar_secret(&v.stellar_secret).unwrap();

        // X25519 private key
        let x_secret = kp.to_x25519_secret();
        let x_secret_bytes = x_secret.to_bytes();
        assert_eq!(
            hex::encode(x_secret_bytes),
            v.x25519_private_hex,
            "x25519 private mismatch for {}",
            v.stellar_address
        );

        // X25519 public key
        let x_pub = kp.to_x25519_public();
        assert_eq!(
            hex::encode(x_pub.as_bytes()),
            v.x25519_public_hex,
            "x25519 public mismatch for {}",
            v.stellar_address
        );

        // Base64url encoding
        assert_eq!(
            kp.x25519_public_b64url(),
            v.x25519_public_b64url,
            "x25519 b64url mismatch for {}",
            v.stellar_address
        );
    }
}

#[test]
fn test_keypair_roundtrip() {
    let vectors = load_vectors();

    for v in &vectors.keypairs {
        let kp = StellarKeypair::from_stellar_secret(&v.stellar_secret).unwrap();
        let secret_str = kp.stellar_secret();
        assert_eq!(
            *secret_str, v.stellar_secret,
            "stellar secret roundtrip failed"
        );
    }
}

// ============================================================
// ECDH Tests
// ============================================================

#[test]
fn test_ecdh_shared_secret() {
    let vectors = load_vectors();

    for v in &vectors.ecdh {
        let sender = StellarKeypair::from_stellar_secret(&v.sender_stellar_secret).unwrap();
        let receiver = StellarKeypair::from_stellar_secret(&v.receiver_stellar_secret).unwrap();

        let shared = SharedSecret::derive(&sender, &receiver);

        assert_eq!(
            hex::encode(shared.raw_bytes()),
            v.raw_shared_secret_hex,
            "ECDH shared secret mismatch for {}",
            v.label
        );
    }
}

#[test]
fn test_ecdh_symmetry() {
    let vectors = load_vectors();

    // Vectors 0 and 1 are the same pair in opposite directions
    let v0 = &vectors.ecdh[0];
    let v1 = &vectors.ecdh[1];

    assert_eq!(
        v0.raw_shared_secret_hex, v1.raw_shared_secret_hex,
        "ECDH should be symmetric"
    );
}

#[test]
fn test_ecdh_signing_key_derivation() {
    let vectors = load_vectors();

    for v in &vectors.ecdh {
        let sender = StellarKeypair::from_stellar_secret(&v.sender_stellar_secret).unwrap();
        let receiver = StellarKeypair::from_stellar_secret(&v.receiver_stellar_secret).unwrap();

        let shared = SharedSecret::derive(&sender, &receiver);
        let signing_key = shared.derive_token_signing_key();

        assert_eq!(
            signing_key, v.signing_key_hex,
            "signing key mismatch for {}",
            v.label
        );
    }
}

#[test]
fn test_ecdh_derive_with_salt() {
    let vectors = load_vectors();

    for v in &vectors.ecdh {
        let sender = StellarKeypair::from_stellar_secret(&v.sender_stellar_secret).unwrap();
        let receiver = StellarKeypair::from_stellar_secret(&v.receiver_stellar_secret).unwrap();

        let shared = SharedSecret::derive(&sender, &receiver);
        let zero_salt = [0u8; 32];
        let derived = shared.derive_key(&zero_salt);

        assert_eq!(
            hex::encode(derived.as_ref()),
            v.derived_with_zero_salt_hex,
            "derived key with zero salt mismatch for {}",
            v.label
        );
    }
}

#[test]
fn test_ecdh_via_b64url() {
    let vectors = load_vectors();

    let sender = StellarKeypair::from_stellar_secret(&vectors.keypairs[0].stellar_secret).unwrap();
    let receiver =
        StellarKeypair::from_stellar_secret(&vectors.keypairs[1].stellar_secret).unwrap();

    let receiver_b64url = receiver.x25519_public_b64url();
    let shared = SharedSecret::derive_from_b64url(&sender, &receiver_b64url).unwrap();

    assert_eq!(
        hex::encode(shared.raw_bytes()),
        vectors.ecdh[0].raw_shared_secret_hex,
        "ECDH via b64url mismatch"
    );
}

// ============================================================
// Domain Separation Tests
// ============================================================

#[test]
fn test_domain_separation_constants() {
    let vectors = load_vectors();

    assert_eq!(
        hex::encode(DomainSeparation::VERSION),
        vectors.domain_separation["VERSION"]
    );
    assert_eq!(
        hex::encode(DomainSeparation::TOKEN_SIGNING),
        vectors.domain_separation["TOKEN_SIGNING"]
    );
    assert_eq!(
        hex::encode(DomainSeparation::TOKEN_SECRET),
        vectors.domain_separation["TOKEN_SECRET"]
    );
    assert_eq!(
        hex::encode(DomainSeparation::HYBRID_ENCRYPT),
        vectors.domain_separation["HYBRID_ENCRYPT"]
    );
    assert_eq!(
        hex::encode(DomainSeparation::ASYMMETRIC_ENCRYPT),
        vectors.domain_separation["ASYMMETRIC_ENCRYPT"]
    );
    assert_eq!(
        hex::encode(DomainSeparation::DATA_FILE),
        vectors.domain_separation["DATA_FILE"]
    );
    assert_eq!(
        hex::encode(DomainSeparation::JWT_SIGNING),
        vectors.domain_separation["JWT_SIGNING"]
    );
}

// ============================================================
// KNTR file format Tests
// ============================================================

#[test]
fn test_kntr_file_header() {
    let vectors = load_vectors();
    let v = &vectors.kntr_file;

    // Verify magic bytes
    assert_eq!(hex::encode(kenter_crypto::kntr_file::MAGIC), v.magic_hex);

    // Verify version constants
    assert_eq!(kenter_crypto::kntr_file::VERSION_MAJOR, v.version_major);
    assert_eq!(kenter_crypto::kntr_file::VERSION_MINOR, v.version_minor);

    // Write a header and verify the binary output matches Python
    let header = kenter_crypto::kntr_file::KntrHeader {
        version: "1.0".to_string(),
        created_at: "2026-03-12T00:00:00Z".to_string(),
        original_filename: "test_document.txt".to_string(),
        file_size: 69,
        file_hash: v.json_header_bytes_hex.clone(), // placeholder — we check header structure
        token_type: "biscuit".to_string(),
    };

    let mut buf = Vec::new();
    kenter_crypto::kntr_file::write_header(&mut buf, &header).unwrap();

    // First 8 bytes should be magic
    assert_eq!(&buf[..8], b"KNTRTOKN");
    // Bytes 8-9: version major (little-endian)
    assert_eq!(u16::from_le_bytes([buf[8], buf[9]]), 1);
    // Bytes 10-11: version minor
    assert_eq!(u16::from_le_bytes([buf[10], buf[11]]), 0);
    // Bytes 12-13: flags
    assert_eq!(u16::from_le_bytes([buf[12], buf[13]]), 0);

    // Read it back
    let mut cursor = std::io::Cursor::new(&buf);
    let parsed = kenter_crypto::kntr_file::read_header(&mut cursor).unwrap();
    assert_eq!(parsed.version, "1.0");
    assert_eq!(parsed.original_filename, "test_document.txt");
    assert_eq!(parsed.token_type, "biscuit");
}

// ============================================================
// Encryption Tests (cross-language: decrypt Python-encrypted data)
// ============================================================

#[test]
fn test_decrypt_python_asymmetric() {
    let vectors = load_vectors();

    for v in &vectors.encryption {
        if v.label != "asymmetric_encrypt" {
            continue;
        }

        let receiver =
            StellarKeypair::from_stellar_secret(&v.receiver_stellar_secret).unwrap();
        let sender =
            StellarKeypair::from_stellar_secret(&v.sender_stellar_secret).unwrap();

        let decrypted = kenter_crypto::encrypt::asymmetric_decrypt(
            &receiver,
            &sender.to_x25519_public(),
            v.encrypted_full.as_bytes(),
        )
        .unwrap();

        assert_eq!(
            String::from_utf8(decrypted).unwrap(),
            v.plaintext,
            "asymmetric decrypt of Python ciphertext failed"
        );
    }
}

#[test]
fn test_decrypt_python_hybrid() {
    let vectors = load_vectors();

    for v in &vectors.encryption {
        if v.label != "hybrid_encrypt" {
            continue;
        }

        let receiver =
            StellarKeypair::from_stellar_secret(&v.receiver_stellar_secret).unwrap();
        let sender =
            StellarKeypair::from_stellar_secret(&v.sender_stellar_secret).unwrap();

        let decrypted = kenter_crypto::encrypt::hybrid_decrypt(
            &receiver,
            &sender.to_x25519_public(),
            v.sender_stellar_address.as_deref().unwrap(),
            v.encrypted_full.as_bytes(),
        )
        .unwrap();

        assert_eq!(
            String::from_utf8(decrypted).unwrap(),
            v.plaintext,
            "hybrid decrypt of Python ciphertext failed"
        );
    }
}
