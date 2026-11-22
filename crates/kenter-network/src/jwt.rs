//! Stellar JWTs for relay authentication.
//!
//! JWT structure:
//!   Header:  {"alg":"EdDSA","typ":"JWT","kid":"G..."}
//!   Payload: {"iss":"kenter_tunnler","sub":"G...","aud":"G...",
//!             "iat":...,"services":[...],...custom_claims}
//!   Signature: Ed25519(base64url(header) + "." + base64url(payload))

use base64::prelude::*;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use kenter_crypto::keypair::StellarKeypair;

/// Create a Stellar JWT token for tunnel authentication.
///
/// Produces a JWT signed with the keypair's Ed25519 secret key,
/// in the form the relay (`kenter-tunnler`) verifies.
pub fn create_stellar_jwt(
    keypair: &StellarKeypair,
    audience: &str,
    services: &[String],
    expires_in_secs: Option<u64>,
    custom_claims: &HashMap<String, serde_json::Value>,
) -> String {
    let stellar_address = keypair.stellar_address();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_secs();

    create_stellar_jwt_at(
        keypair,
        &stellar_address,
        audience,
        services,
        now,
        expires_in_secs,
        custom_claims,
    )
}

/// Create a Stellar JWT with explicit timestamp (for testing).
pub fn create_stellar_jwt_at(
    keypair: &StellarKeypair,
    stellar_address: &str,
    audience: &str,
    services: &[String],
    issued_at: u64,
    expires_in_secs: Option<u64>,
    custom_claims: &HashMap<String, serde_json::Value>,
) -> String {
    // Header — compact JSON, alphabetical key order is fine since the
    // server verifies the signature over the raw base64 bytes, not
    // re-serialized JSON.
    let header = serde_json::json!({
        "alg": "EdDSA",
        "typ": "JWT",
        "kid": stellar_address,
    });

    // Payload
    let mut payload = serde_json::Map::new();
    payload.insert("iss".into(), serde_json::json!("kenter_tunnler"));
    payload.insert("sub".into(), serde_json::json!(stellar_address));
    payload.insert("aud".into(), serde_json::json!(audience));
    payload.insert("iat".into(), serde_json::json!(issued_at));
    payload.insert("services".into(), serde_json::json!(services));

    if let Some(exp_secs) = expires_in_secs {
        payload.insert("exp".into(), serde_json::json!(issued_at + exp_secs));
    }

    // Merge custom claims (overrides standard claims if collision)
    for (key, value) in custom_claims {
        payload.insert(key.clone(), value.clone());
    }

    let header_b64 = base64url_encode(
        &serde_json::to_vec(&header).expect("header serialization"),
    );
    let payload_b64 = base64url_encode(
        &serde_json::to_vec(&serde_json::Value::Object(payload))
            .expect("payload serialization"),
    );

    // Sign: Ed25519 over "header_b64.payload_b64" as UTF-8 bytes
    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature = keypair.sign(signing_input.as_bytes());
    let signature_b64 = base64url_encode(&signature.to_bytes());

    format!("{header_b64}.{payload_b64}.{signature_b64}")
}

/// Base64url encode without padding (RFC 4648 §5).
fn base64url_encode(data: &[u8]) -> String {
    BASE64_URL_SAFE_NO_PAD.encode(data)
}

/// Base64url decode with optional padding.
fn base64url_decode(data: &str) -> Result<Vec<u8>, base64::DecodeError> {
    // Restore padding if stripped
    let padded = match data.len() % 4 {
        2 => format!("{data}=="),
        3 => format!("{data}="),
        _ => data.to_string(),
    };
    BASE64_URL_SAFE.decode(padded.as_bytes())
}

/// Verify a Stellar JWT's Ed25519 signature.
///
/// Returns the parsed claims if the signature is valid.
pub fn verify_stellar_jwt(
    jwt: &str,
    signer_public: &[u8; 32],
) -> Result<serde_json::Value, String> {
    let parts: Vec<&str> = jwt.splitn(3, '.').collect();
    if parts.len() != 3 {
        return Err("invalid JWT format: expected 3 dot-separated parts".into());
    }

    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let signature_bytes = base64url_decode(parts[2])
        .map_err(|e| format!("invalid signature base64: {e}"))?;

    if signature_bytes.len() != 64 {
        return Err(format!(
            "invalid signature length: expected 64, got {}",
            signature_bytes.len()
        ));
    }

    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&signature_bytes);
    let signature = ed25519_dalek::Signature::from_bytes(&sig_arr);

    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(signer_public)
        .map_err(|e| format!("invalid public key: {e}"))?;

    use ed25519_dalek::Verifier;
    verifying_key
        .verify(signing_input.as_bytes(), &signature)
        .map_err(|_| "signature verification failed".to_string())?;

    // Parse payload
    let payload_bytes = base64url_decode(parts[1])
        .map_err(|e| format!("invalid payload base64: {e}"))?;
    let claims: serde_json::Value = serde_json::from_slice(&payload_bytes)
        .map_err(|e| format!("invalid payload JSON: {e}"))?;

    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwt_creation_and_verification() {
        let keypair = StellarKeypair::random();
        let audience = "GSERVER_ADDRESS_HERE_56_CHARS_PLACEHOLDER_FOR_TESTING_1234";

        let jwt = create_stellar_jwt(
            &keypair,
            audience,
            &["kenter".to_string()],
            Some(3600),
            &HashMap::new(),
        );

        // JWT should have 3 dot-separated parts
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT must have header.payload.signature");

        // Verify signature
        let claims = verify_stellar_jwt(&jwt, &keypair.raw_public()).unwrap();

        assert_eq!(claims["sub"].as_str().unwrap(), keypair.stellar_address());
        assert_eq!(claims["aud"].as_str().unwrap(), audience);
        assert_eq!(claims["iss"].as_str().unwrap(), "kenter_tunnler");
        assert!(claims["iat"].as_u64().is_some());
        assert!(claims["exp"].as_u64().is_some());
        assert_eq!(claims["services"][0].as_str().unwrap(), "kenter");
    }

    #[test]
    fn test_jwt_with_custom_claims() {
        let keypair = StellarKeypair::random();
        let mut claims = HashMap::new();
        claims.insert(
            "challenge".to_string(),
            serde_json::json!("random_challenge_value"),
        );

        let jwt = create_stellar_jwt(
            &keypair,
            "GSERVER",
            &["kenter".to_string()],
            Some(3600),
            &claims,
        );

        let parsed = verify_stellar_jwt(&jwt, &keypair.raw_public()).unwrap();
        assert_eq!(
            parsed["challenge"].as_str().unwrap(),
            "random_challenge_value"
        );
    }

    #[test]
    fn test_jwt_no_expiration() {
        let keypair = StellarKeypair::random();

        let jwt = create_stellar_jwt(
            &keypair,
            "GSERVER",
            &["kenter".to_string()],
            None,
            &HashMap::new(),
        );

        let parsed = verify_stellar_jwt(&jwt, &keypair.raw_public()).unwrap();
        assert!(parsed.get("exp").is_none());
    }

    #[test]
    fn test_jwt_wrong_key_fails() {
        let keypair = StellarKeypair::random();
        let wrong_key = StellarKeypair::random();

        let jwt = create_stellar_jwt(
            &keypair,
            "GSERVER",
            &["kenter".to_string()],
            Some(3600),
            &HashMap::new(),
        );

        assert!(verify_stellar_jwt(&jwt, &wrong_key.raw_public()).is_err());
    }

    #[test]
    fn test_jwt_tamper_detection() {
        let keypair = StellarKeypair::random();

        let jwt = create_stellar_jwt(
            &keypair,
            "GSERVER",
            &["kenter".to_string()],
            Some(3600),
            &HashMap::new(),
        );

        // Tamper with payload
        let parts: Vec<&str> = jwt.split('.').collect();
        let tampered = format!("{}.dGFtcGVyZWQ.{}", parts[0], parts[2]);
        assert!(verify_stellar_jwt(&tampered, &keypair.raw_public()).is_err());
    }

    #[test]
    fn test_jwt_header_structure() {
        let keypair = StellarKeypair::random();

        let jwt = create_stellar_jwt(
            &keypair,
            "GSERVER",
            &[],
            None,
            &HashMap::new(),
        );

        let header_b64 = jwt.split('.').next().unwrap();
        let header_bytes = base64url_decode(header_b64).unwrap();
        let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();

        assert_eq!(header["alg"].as_str().unwrap(), "EdDSA");
        assert_eq!(header["typ"].as_str().unwrap(), "JWT");
        assert_eq!(
            header["kid"].as_str().unwrap(),
            keypair.stellar_address()
        );
    }
}
