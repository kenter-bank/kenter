use std::time::{SystemTime, UNIX_EPOCH};

use stellar_strkey::ed25519::PublicKey as StellarPublic;
use kenter_network::jwt::verify_stellar_jwt;

/// Verify a client JWT and extract claims.
///
/// Checks:
/// 1. Ed25519 signature is valid (using `kid` header as public key)
/// 2. Audience matches the server's Stellar address
/// 3. Token is not expired (with clock skew tolerance)
/// 4. Challenge claim matches the expected challenge value
/// 5. `sub` matches the key that signed the JWT (`kid`)
pub fn verify_client_jwt(
    jwt: &str,
    server_address: &str,
    expected_challenge: &str,
    clock_skew_secs: u64,
) -> Result<JwtClaims, String> {
    // Parse header to get kid (signer's Stellar address)
    let parts: Vec<&str> = jwt.splitn(3, '.').collect();
    if parts.len() != 3 {
        return Err("invalid JWT format".into());
    }

    let header_bytes = base64url_decode(parts[0])
        .map_err(|e| format!("invalid header base64: {e}"))?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes)
        .map_err(|e| format!("invalid header JSON: {e}"))?;

    let kid = header["kid"]
        .as_str()
        .ok_or("missing kid in JWT header")?;

    // Convert kid (Stellar address G...) to raw public key bytes
    let stellar_pub = StellarPublic::from_string(kid)
        .map_err(|e| format!("invalid kid Stellar address: {e}"))?;

    // Verify Ed25519 signature and parse claims
    let claims = verify_stellar_jwt(jwt, &stellar_pub.0)?;

    // Verify sub matches kid (signer is who they claim to be)
    let sub = claims["sub"]
        .as_str()
        .ok_or("missing sub claim")?;
    if sub != kid {
        return Err("sub does not match kid".into());
    }

    // Verify audience
    let aud = claims["aud"]
        .as_str()
        .ok_or("missing aud claim")?;
    if aud != server_address {
        return Err(format!("audience mismatch: expected {server_address}, got {aud}"));
    }

    // Verify expiration (with clock skew)
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before epoch")
        .as_secs();

    if let Some(exp) = claims["exp"].as_u64() {
        if now > exp + clock_skew_secs {
            return Err("JWT expired".into());
        }
    }

    // Verify issued-at not in far future
    if let Some(iat) = claims["iat"].as_u64() {
        if iat > now + clock_skew_secs {
            return Err("JWT issued in the future".into());
        }
    }

    // Verify challenge
    let challenge = claims["challenge"]
        .as_str()
        .ok_or("missing challenge claim")?;
    if challenge != expected_challenge {
        return Err("challenge mismatch".into());
    }

    // Extract services
    let services: Vec<String> = claims["services"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_else(|| vec!["kenter".into()]);

    // Extract session timeout from exp
    let session_expires_at = claims["exp"].as_u64();

    Ok(JwtClaims {
        stellar_address: sub.to_string(),
        public_key: stellar_pub.0,
        services,
        session_expires_at,
    })
}

#[derive(Debug)]
pub struct JwtClaims {
    pub stellar_address: String,
    pub public_key: [u8; 32],
    pub services: Vec<String>,
    pub session_expires_at: Option<u64>,
}

fn base64url_decode(data: &str) -> std::result::Result<Vec<u8>, base64::DecodeError> {
    use base64::prelude::*;
    let padded = match data.len() % 4 {
        2 => format!("{data}=="),
        3 => format!("{data}="),
        _ => data.to_string(),
    };
    BASE64_URL_SAFE.decode(padded.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use kenter_crypto::keypair::StellarKeypair;
    use kenter_network::jwt::create_stellar_jwt;

    #[test]
    fn test_verify_client_jwt_success() {
        let client = StellarKeypair::random();
        let server = StellarKeypair::random();
        let challenge = "test_challenge_value";

        let mut custom = HashMap::new();
        custom.insert("challenge".into(), serde_json::json!(challenge));

        let jwt = create_stellar_jwt(
            &client,
            &server.stellar_address(),
            &["kenter".into()],
            Some(3600),
            &custom,
        );

        let claims = verify_client_jwt(
            &jwt,
            &server.stellar_address(),
            challenge,
            60,
        )
        .unwrap();

        assert_eq!(claims.stellar_address, client.stellar_address());
        assert_eq!(claims.services, vec!["kenter"]);
    }

    #[test]
    fn test_wrong_audience_rejected() {
        let client = StellarKeypair::random();
        let server = StellarKeypair::random();
        let wrong_server = StellarKeypair::random();

        let mut custom = HashMap::new();
        custom.insert("challenge".into(), serde_json::json!("challenge"));

        let jwt = create_stellar_jwt(
            &client,
            &server.stellar_address(),
            &["kenter".into()],
            Some(3600),
            &custom,
        );

        let result = verify_client_jwt(
            &jwt,
            &wrong_server.stellar_address(),
            "challenge",
            60,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("audience"));
    }

    #[test]
    fn test_wrong_challenge_rejected() {
        let client = StellarKeypair::random();
        let server = StellarKeypair::random();

        let mut custom = HashMap::new();
        custom.insert("challenge".into(), serde_json::json!("real_challenge"));

        let jwt = create_stellar_jwt(
            &client,
            &server.stellar_address(),
            &["kenter".into()],
            Some(3600),
            &custom,
        );

        let result = verify_client_jwt(
            &jwt,
            &server.stellar_address(),
            "wrong_challenge",
            60,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("challenge"));
    }
}
