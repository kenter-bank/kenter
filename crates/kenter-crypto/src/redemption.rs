//! Redemption flow: encrypted shard transport, composition, and transaction signing.
//!
//! At redemption time, one node per pair re-derives its shard via ECDH,
//! encrypts the scalar to the combiner node using NaCl Box, and sends it.
//! The combiner collects all shards, composes the full keypair, signs the
//! redemption transaction, and immediately wipes the secret.
//!
//! No single node ever holds all shards simultaneously except the combiner,
//! and only for the brief moment of signing.

use ed25519_dalek::Signature;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::compose::CompositionBuilder;
use crate::domain::DomainSeparation;
use crate::encrypt;
use crate::error::{CryptoError, Result};
use crate::keypair::StellarKeypair;
use crate::shard::{derive_shard, ChainLink, PairInfo};
use crate::token::BearerToken;

/// A signed request to redeem a bearer token.
#[derive(Debug, Clone)]
pub struct RedemptionRequest {
    /// The bearer token being redeemed.
    pub token: BearerToken,
    /// SHA-256 hash of the serialized token container.
    pub token_hash: [u8; 32],
    /// Stellar address of the holder requesting redemption.
    pub holder_address: String,
    /// Ed25519 signature by the holder over the signable payload.
    pub holder_signature: [u8; 64],
    /// Ed25519 public key of the designated combiner (bound to prevent MITM substitution).
    pub combiner_public_key: [u8; 32],
    /// Random nonce for replay protection.
    pub nonce: [u8; 32],
    /// Unix timestamp of the request.
    pub timestamp: i64,
}

impl RedemptionRequest {
    /// Create a signed redemption request.
    ///
    /// The `combiner_public_key` is the Ed25519 public key of the node that
    /// will collect and decrypt shards. Binding it into the signed payload
    /// prevents MITM attacks where an attacker substitutes their own combiner
    /// key to intercept encrypted shards.
    pub fn new(
        token: BearerToken,
        token_hash: [u8; 32],
        holder_keypair: &StellarKeypair,
        combiner_public_key: [u8; 32],
        timestamp: i64,
    ) -> Self {
        let nonce: [u8; 32] = rand::random();
        let holder_address = holder_keypair.stellar_address();

        let signable = Self::signable_bytes(
            &token_hash,
            &holder_address,
            &combiner_public_key,
            &nonce,
            timestamp,
        );
        let signature = holder_keypair.sign(&signable);

        Self {
            token,
            token_hash,
            holder_address,
            holder_signature: signature.to_bytes(),
            combiner_public_key,
            nonce,
            timestamp,
        }
    }

    /// Verify the holder's signature on the redemption request.
    pub fn verify_holder_signature(&self) -> Result<()> {
        verify_holder_signature(
            &self.token_hash,
            &self.holder_address,
            &self.combiner_public_key,
            &self.nonce,
            self.timestamp,
            &self.holder_signature,
        )
    }

    fn signable_bytes(
        token_hash: &[u8; 32],
        holder_address: &str,
        combiner_public_key: &[u8; 32],
        nonce: &[u8; 32],
        timestamp: i64,
    ) -> Vec<u8> {
        holder_signable_bytes(token_hash, holder_address, combiner_public_key, nonce, timestamp)
    }
}

/// The exact bytes a holder signs to authorize shard collection for a redemption.
///
/// Binding `combiner_public_key` into the signature is the anti-MITM property: a
/// relay cannot substitute its own combiner key to intercept the encrypted
/// shards, because the pair node re-derives these bytes and rejects a signature
/// that doesn't cover the combiner key it is about to encrypt to. `token_hash`
/// binds the authorization to one specific token; `nonce`/`timestamp` scope it.
pub fn holder_signable_bytes(
    token_hash: &[u8; 32],
    holder_address: &str,
    combiner_public_key: &[u8; 32],
    nonce: &[u8; 32],
    timestamp: i64,
) -> Vec<u8> {
    let tag = DomainSeparation::REDEMPTION_REQUEST;
    let mut buf = Vec::with_capacity(tag.len() + 32 + 56 + 32 + 32 + 8);
    buf.extend_from_slice(tag);
    buf.extend_from_slice(token_hash);
    buf.extend_from_slice(holder_address.as_bytes());
    buf.extend_from_slice(combiner_public_key);
    buf.extend_from_slice(nonce);
    buf.extend_from_slice(&timestamp.to_le_bytes());
    buf
}

/// Verify a holder's shard-collection authorization signature over the given
/// fields (see [`holder_signable_bytes`]). Used by pair nodes before serving a
/// shard, so they only ever encrypt to a combiner key the holder actually signed.
pub fn verify_holder_signature(
    token_hash: &[u8; 32],
    holder_address: &str,
    combiner_public_key: &[u8; 32],
    nonce: &[u8; 32],
    timestamp: i64,
    signature: &[u8; 64],
) -> Result<()> {
    let signable = holder_signable_bytes(token_hash, holder_address, combiner_public_key, nonce, timestamp);
    let holder_pub = StellarKeypair::from_stellar_address(holder_address)?;
    holder_pub.verify(&signable, &ed25519_dalek::Signature::from_bytes(signature))
}

/// An encrypted shard contribution from a pair node.
///
/// The shard scalar is encrypted to the combiner's X25519 public key
/// using NaCl Box (asymmetric encryption). The contributor also signs
/// the encrypted payload for non-repudiation.
#[derive(Debug, Clone)]
pub struct EncryptedShard {
    /// Index of the ChainLink this shard belongs to.
    pub link_index: u16,
    /// Stellar address of the contributing node.
    pub contributor_address: String,
    /// The shard scalar, encrypted to the combiner's X25519 key.
    pub encrypted_scalar: Vec<u8>,
    /// SHA-256 commitment of the shard scalar (for verification).
    pub commitment: [u8; 32],
    /// Ed25519 signature by the contributor over the transport payload.
    pub contributor_signature: [u8; 64],
}

impl EncryptedShard {
    fn signable_bytes(
        link_index: u16,
        contributor_address: &str,
        encrypted_scalar: &[u8],
        commitment: &[u8; 32],
    ) -> Vec<u8> {
        let tag = DomainSeparation::SHARD_TRANSPORT;
        let mut buf = Vec::with_capacity(tag.len() + 2 + 56 + encrypted_scalar.len() + 32);
        buf.extend_from_slice(tag);
        buf.extend_from_slice(&link_index.to_le_bytes());
        buf.extend_from_slice(contributor_address.as_bytes());
        buf.extend_from_slice(encrypted_scalar);
        buf.extend_from_slice(commitment);
        buf
    }
}

/// Maximum age of a shard request in seconds (5 minutes).
pub const SHARD_REQUEST_MAX_AGE_SECS: i64 = 300;

/// Maximum clock skew tolerance for future timestamps (60 seconds).
pub const SHARD_REQUEST_MAX_FUTURE_SECS: i64 = 60;

/// Re-derive a shard from ECDH and contribute it (encrypted) to the combiner.
///
/// The contributing node:
/// 1. Validates the request timestamp is within the acceptable window
/// 2. Re-derives the shard via ECDH with its partner (salted by event_id)
/// 3. Verifies the shard matches the ChainLink commitment
/// 4. Encrypts the shard scalar to the combiner's X25519 key
/// 5. Signs the encrypted payload for non-repudiation
///
/// `combiner_public` is the combiner's Ed25519 public key (32 bytes).
/// It is converted to X25519 for encryption — the pair node never needs
/// the combiner's secret key.
pub fn contribute_shard(
    own_keypair: &StellarKeypair,
    partner_public: &ed25519_dalek::VerifyingKey,
    chain_link: &ChainLink,
    combiner_public: &[u8; 32],
    event_id: &[u8; 32],
    request_timestamp: i64,
    current_time: i64,
) -> Result<EncryptedShard> {
    // Validate request freshness
    let age = current_time - request_timestamp;
    if !(-SHARD_REQUEST_MAX_FUTURE_SECS..=SHARD_REQUEST_MAX_AGE_SECS).contains(&age) {
        return Err(CryptoError::RedemptionFailed(format!(
            "shard request outside valid time window (age: {age}s, \
             allowed: -{SHARD_REQUEST_MAX_FUTURE_SECS}s to +{SHARD_REQUEST_MAX_AGE_SECS}s)"
        )));
    }

    // Re-derive the shard (salted with event_id for per-token uniqueness)
    let shard = derive_shard(own_keypair, partner_public, event_id)?;

    // Verify against the ChainLink commitment
    if shard.commitment() != &chain_link.shard_commitment {
        return Err(CryptoError::ShardCommitmentMismatch);
    }

    // Verify partial public key matches
    if shard.partial_public_bytes() != chain_link.partial_public_key {
        return Err(CryptoError::ChainVerificationFailed(
            "rederived shard partial public key does not match chain link".into(),
        ));
    }

    // Convert combiner's Ed25519 public key to X25519 for encryption
    let combiner_vk = ed25519_dalek::VerifyingKey::from_bytes(combiner_public)
        .map_err(|e| CryptoError::RedemptionFailed(format!("invalid combiner public key: {e}")))?;
    let combiner_x25519 = StellarKeypair::x25519_public_from_ed25519(&combiner_vk)?;

    // Encrypt the scalar to the combiner's X25519 key
    let scalar_bytes = shard.scalar().as_bytes();
    let encrypted_scalar = encrypt::asymmetric_encrypt(
        own_keypair,
        &combiner_x25519,
        scalar_bytes,
    )?;

    // Sign for non-repudiation
    let contributor_address = own_keypair.stellar_address();
    let signable = EncryptedShard::signable_bytes(
        chain_link.link_index,
        &contributor_address,
        &encrypted_scalar,
        shard.commitment(),
    );
    let signature = own_keypair.sign(&signable);

    Ok(EncryptedShard {
        link_index: chain_link.link_index,
        contributor_address,
        encrypted_scalar,
        commitment: *shard.commitment(),
        contributor_signature: signature.to_bytes(),
    })
}

/// Manages shard collection and composition for a single redemption.
///
/// The combiner node creates a session, receives encrypted shards from
/// each pair node, and when complete, composes the full keypair to sign
/// the redemption transaction. The secret is wiped immediately after signing.
pub struct RedemptionSession {
    /// The redemption request.
    request: RedemptionRequest,
    /// Combiner's keypair (for decrypting shards).
    combiner_keypair: StellarKeypair,
    /// Collected decrypted shards, indexed by link_index.
    shards: Vec<Option<ShardData>>,
    /// Total expected shards.
    total: usize,
    /// Number of shards received so far.
    received: usize,
}

/// Internal: decrypted shard data with metadata.
struct ShardData {
    scalar_bytes: Zeroizing<[u8; 32]>,
    pair_info: PairInfo,
}

impl RedemptionSession {
    /// Create a new redemption session.
    ///
    /// The combiner verifies the redemption request and prepares to
    /// receive encrypted shards from each pair in the chain.
    pub fn new(
        request: RedemptionRequest,
        combiner_keypair: StellarKeypair,
    ) -> Result<Self> {
        // Verify the token's chain integrity
        request.token.verify_chain_integrity()?;

        // Verify holder signature
        request.verify_holder_signature()?;

        let total = request.token.chain.links.len();

        Ok(Self {
            request,
            combiner_keypair,
            shards: (0..total).map(|_| None).collect(),
            total,
            received: 0,
        })
    }

    /// Receive an encrypted shard from a pair node.
    ///
    /// Decrypts the shard, verifies commitment and partial public key
    /// against the ChainLink, and stores it.
    pub fn receive_shard(
        &mut self,
        encrypted: &EncryptedShard,
        contributor_verifying_key: &ed25519_dalek::VerifyingKey,
    ) -> Result<()> {
        let idx = encrypted.link_index as usize;
        if idx >= self.total {
            return Err(CryptoError::InvalidToken(format!(
                "link index {idx} out of range (total: {})",
                self.total
            )));
        }

        if self.shards[idx].is_some() {
            return Err(CryptoError::DuplicateShard {
                index: encrypted.link_index,
            });
        }

        // Verify contributor signature
        let signable = EncryptedShard::signable_bytes(
            encrypted.link_index,
            &encrypted.contributor_address,
            &encrypted.encrypted_scalar,
            &encrypted.commitment,
        );
        let sig = ed25519_dalek::Signature::from_bytes(&encrypted.contributor_signature);
        StellarKeypair::verify(contributor_verifying_key, &signable, &sig)?;

        // Decrypt the shard scalar
        let contributor_x25519 =
            StellarKeypair::x25519_public_from_ed25519(contributor_verifying_key)?;
        let decrypted = encrypt::asymmetric_decrypt(
            &self.combiner_keypair,
            &contributor_x25519,
            &encrypted.encrypted_scalar,
        )?;

        if decrypted.len() != 32 {
            return Err(CryptoError::RedemptionFailed(
                "decrypted scalar is not 32 bytes".into(),
            ));
        }

        let mut scalar_bytes = Zeroizing::new([0u8; 32]);
        scalar_bytes.copy_from_slice(&decrypted);

        // Verify commitment: SHA-256(scalar_bytes) == chain_link.shard_commitment
        let chain_link = &self.request.token.chain.links[idx];
        let commitment: [u8; 32] = Sha256::digest(*scalar_bytes).into();
        if commitment != chain_link.shard_commitment {
            return Err(CryptoError::ShardCommitmentMismatch);
        }

        // Verify partial public key: scalar * G == chain_link.partial_public_key
        let scalar = curve25519_dalek::Scalar::from_canonical_bytes(*scalar_bytes)
            .into_option()
            .ok_or_else(|| {
                CryptoError::RedemptionFailed("invalid scalar bytes".into())
            })?;
        let point = &scalar * curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
        if point.compress().to_bytes() != chain_link.partial_public_key {
            return Err(CryptoError::ChainVerificationFailed(
                "scalar * G does not match partial public key".into(),
            ));
        }

        let pair_info: PairInfo = chain_link.into();

        self.shards[idx] = Some(ShardData {
            scalar_bytes,
            pair_info,
        });
        self.received += 1;

        Ok(())
    }

    /// Check if all shards have been received.
    pub fn is_complete(&self) -> bool {
        self.received == self.total
    }

    /// Number of shards received so far.
    pub fn received_count(&self) -> usize {
        self.received
    }

    /// Total expected shards.
    pub fn total_count(&self) -> usize {
        self.total
    }

    /// Compose all shards and sign a message (e.g., redemption transaction).
    ///
    /// This consumes the session. The composed secret is wiped immediately
    /// after signing — it exists only for the duration of this call.
    pub fn compose_and_sign(self, message: &[u8]) -> Result<(Signature, [u8; 32])> {
        if !self.is_complete() {
            return Err(CryptoError::RedemptionIncomplete {
                received: self.received,
                total: self.total,
            });
        }

        let mut builder = CompositionBuilder::new();

        for shard_data in self.shards.into_iter() {
            let data = shard_data.unwrap(); // safe: is_complete() verified

            // Reconstruct the shard from scalar bytes
            let scalar =
                curve25519_dalek::Scalar::from_canonical_bytes(*data.scalar_bytes)
                    .into_option()
                    .ok_or_else(|| {
                        CryptoError::RedemptionFailed("invalid scalar bytes".into())
                    })?;

            let partial_public =
                &scalar * curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;

            let shard = crate::shard::Shard::from_raw(scalar, partial_public);
            builder.add_shard(shard, data.pair_info);
        }

        let (composed, _pairs) = builder.build()?;
        let public_bytes = composed.public_bytes();

        // Verify the composed key matches the token's ephemeral key
        if public_bytes != self.request.token.ephemeral_public_key {
            return Err(CryptoError::RedemptionFailed(
                "composed key does not match ephemeral key".into(),
            ));
        }

        // Sign and immediately drop composed (which zeroizes the scalar)
        let signature = composed.sign(message);

        Ok((signature, public_bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_TIME: i64 = 1741800000;

    #[test]
    fn test_contribute_shard_and_verify() {
        let kp1 = StellarKeypair::random();
        let kp2 = StellarKeypair::random();
        let combiner = StellarKeypair::random();
        let event_id = [0xAA; 32];

        let shard = derive_shard(&kp1, &kp2.verifying_key(), &event_id).unwrap();
        let link = ChainLink::create(&kp1, &kp2, &shard, [0; 32], 0, &event_id);

        let encrypted = contribute_shard(
            &kp1, &kp2.verifying_key(), &link, &combiner.raw_public(), &event_id,
            TEST_TIME, TEST_TIME,
        ).unwrap();

        assert_eq!(encrypted.link_index, 0);
        assert_eq!(encrypted.commitment, *shard.commitment());
    }

    #[test]
    fn test_contribute_shard_wrong_commitment_fails() {
        let kp1 = StellarKeypair::random();
        let kp2 = StellarKeypair::random();
        let kp3 = StellarKeypair::random();
        let combiner = StellarKeypair::random();
        let event_id = [0xBB; 32];

        // Create a link with kp1+kp2's shard
        let shard = derive_shard(&kp1, &kp2.verifying_key(), &event_id).unwrap();
        let link = ChainLink::create(&kp1, &kp2, &shard, [0; 32], 0, &event_id);

        // Try to contribute with kp1+kp3 (different shard → different commitment)
        let result = contribute_shard(
            &kp1, &kp3.verifying_key(), &link, &combiner.raw_public(), &event_id,
            TEST_TIME, TEST_TIME,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_contribute_shard_stale_request_rejected() {
        let kp1 = StellarKeypair::random();
        let kp2 = StellarKeypair::random();
        let combiner = StellarKeypair::random();
        let event_id = [0xAA; 32];

        let shard = derive_shard(&kp1, &kp2.verifying_key(), &event_id).unwrap();
        let link = ChainLink::create(&kp1, &kp2, &shard, [0; 32], 0, &event_id);

        // Request from 10 minutes ago — should be rejected (max age 5 min)
        let result = contribute_shard(
            &kp1, &kp2.verifying_key(), &link, &combiner.raw_public(), &event_id,
            TEST_TIME - 600, TEST_TIME,
        );
        assert!(result.is_err());

        // Request from 2 minutes in the future — should be rejected (max future 60s)
        let result = contribute_shard(
            &kp1, &kp2.verifying_key(), &link, &combiner.raw_public(), &event_id,
            TEST_TIME + 120, TEST_TIME,
        );
        assert!(result.is_err());

        // Request from 30 seconds in the future — should be accepted (within skew)
        let encrypted = contribute_shard(
            &kp1, &kp2.verifying_key(), &link, &combiner.raw_public(), &event_id,
            TEST_TIME + 30, TEST_TIME,
        );
        assert!(encrypted.is_ok());
    }

    #[test]
    fn test_full_redemption_flow() {
        use crate::container::serialize_bearer_token;
        use crate::token::{assemble_bearer_token, PartialToken};

        let node_1 = StellarKeypair::random();
        let node_2 = StellarKeypair::random();
        let node_3 = StellarKeypair::random();
        let node_4 = StellarKeypair::random();
        let requestor = StellarKeypair::random();
        let node_5 = StellarKeypair::random();

        let event_id = [0xCC; 32];

        // Build a 3-pair bearer token
        let (mut partial, _) = PartialToken::initiate(
            event_id,
            1741737600,
            Some(10_000_000),
            3,
            &node_1,
            &node_2,
            vec![],
        )
        .unwrap();

        let _ = partial.extend(&node_3, &node_4).unwrap();

        let token = assemble_bearer_token(
            &partial,
            &requestor,
            &node_5,
            7,
            Some(1741824000),
        )
        .unwrap();

        // Hash the serialized container
        let container_bytes = serialize_bearer_token(&token, &requestor).unwrap();
        let token_hash: [u8; 32] = Sha256::digest(&container_bytes).into();

        // Extract chain links before moving token into request
        let chain_links_snapshot: Vec<ChainLink> = token.chain.links.clone();

        // Combiner keypair — save secret so we can reconstruct for session
        let combiner = StellarKeypair::random();
        let combiner_secret = combiner.raw_secret();
        let combiner_public = combiner.raw_public();

        // Create redemption request — combiner key is bound to the signed payload
        let request = RedemptionRequest::new(
            token, token_hash, &requestor, combiner_public, TEST_TIME,
        );
        request.verify_holder_signature().unwrap();

        // Contribute shards (need combiner for encryption, chain links for verification)
        let enc_0 = contribute_shard(
            &node_1,
            &node_2.verifying_key(),
            &chain_links_snapshot[0],
            &combiner.raw_public(),
            &event_id,
            TEST_TIME, TEST_TIME,
        )
        .unwrap();

        let enc_1 = contribute_shard(
            &node_3,
            &node_4.verifying_key(),
            &chain_links_snapshot[1],
            &combiner.raw_public(),
            &event_id,
            TEST_TIME, TEST_TIME,
        )
        .unwrap();

        let enc_2 = contribute_shard(
            &requestor,
            &node_5.verifying_key(),
            &chain_links_snapshot[2],
            &combiner.raw_public(),
            &event_id,
            TEST_TIME, TEST_TIME,
        )
        .unwrap();

        // Create session with a fresh combiner from the same secret
        let combiner_for_session = StellarKeypair::from_raw_secret(&combiner_secret);
        let mut session = RedemptionSession::new(request, combiner_for_session).unwrap();

        assert!(!session.is_complete());
        assert_eq!(session.received_count(), 0);
        assert_eq!(session.total_count(), 3);

        session
            .receive_shard(&enc_0, &node_1.verifying_key())
            .unwrap();

        session
            .receive_shard(&enc_1, &node_3.verifying_key())
            .unwrap();

        session
            .receive_shard(&enc_2, &requestor.verifying_key())
            .unwrap();

        assert!(session.is_complete());

        // Compose and sign a redemption transaction
        let tx_message = b"stellar:redeem:txhash:abc123";
        let ephemeral_key = session.request.token.ephemeral_public_key;
        let (signature, public_bytes) = session.compose_and_sign(tx_message).unwrap();

        // Verify the signature is valid standard Ed25519
        assert_eq!(public_bytes, ephemeral_key);
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&public_bytes).unwrap();
        vk.verify_strict(tx_message, &signature)
            .expect("redemption signature must be valid");
    }

    #[test]
    fn test_combiner_key_binding() {
        use crate::container::serialize_bearer_token;
        use crate::token::{assemble_bearer_token, PartialToken};

        let node_1 = StellarKeypair::random();
        let node_2 = StellarKeypair::random();
        let requestor = StellarKeypair::random();
        let node_3 = StellarKeypair::random();

        let (partial, _) = PartialToken::initiate(
            [0xFF; 32], 1741737600, Some(100), 2,
            &node_1, &node_2, vec![],
        ).unwrap();

        let token = assemble_bearer_token(&partial, &requestor, &node_3, 7, None).unwrap();
        let container_bytes = serialize_bearer_token(&token, &requestor).unwrap();
        let token_hash: [u8; 32] = Sha256::digest(&container_bytes).into();

        let combiner = StellarKeypair::random();
        let combiner_public = combiner.raw_public();

        // Create request with combiner key bound
        let request = RedemptionRequest::new(
            token, token_hash, &requestor, combiner_public, TEST_TIME,
        );
        request.verify_holder_signature().unwrap();

        // Tamper with the combiner key (simulates MITM substitution)
        let mut tampered = request.clone();
        let attacker = StellarKeypair::random();
        tampered.combiner_public_key = attacker.raw_public();

        // Signature verification must fail — combiner key is bound
        assert!(
            tampered.verify_holder_signature().is_err(),
            "MITM combiner key substitution must be detected"
        );
    }

    #[test]
    fn test_duplicate_shard_rejected() {
        use crate::container::serialize_bearer_token;
        use crate::token::{assemble_bearer_token, PartialToken};

        let node_1 = StellarKeypair::random();
        let node_2 = StellarKeypair::random();
        let requestor = StellarKeypair::random();
        let node_3 = StellarKeypair::random();

        let (partial, _) = PartialToken::initiate(
            [0xDD; 32],
            1741737600,
            Some(100),
            2,
            &node_1,
            &node_2,
            vec![],
        )
        .unwrap();

        let token = assemble_bearer_token(&partial, &requestor, &node_3, 7, None).unwrap();
        let container_bytes = serialize_bearer_token(&token, &requestor).unwrap();
        let token_hash: [u8; 32] = Sha256::digest(&container_bytes).into();

        let combiner = StellarKeypair::random();
        let combiner_secret = combiner.raw_secret();
        let combiner_public = combiner.raw_public();

        let event_id = [0xDD; 32];
        let chain_links: Vec<ChainLink> = token.chain.links.clone();
        let enc_0 = contribute_shard(
            &node_1,
            &node_2.verifying_key(),
            &chain_links[0],
            &combiner.raw_public(),
            &event_id,
            TEST_TIME, TEST_TIME,
        )
        .unwrap();

        // Move token into request after extracting chain_links
        let request = RedemptionRequest::new(
            token, token_hash, &requestor, combiner_public, TEST_TIME,
        );
        let combiner_for_session = StellarKeypair::from_raw_secret(&combiner_secret);
        let mut session = RedemptionSession::new(request, combiner_for_session).unwrap();

        session
            .receive_shard(&enc_0, &node_1.verifying_key())
            .unwrap();

        // Second submission of same shard should fail
        let result = session.receive_shard(&enc_0, &node_1.verifying_key());
        assert!(result.is_err());
    }

    #[test]
    fn test_incomplete_redemption_rejected() {
        use crate::container::serialize_bearer_token;
        use crate::token::{assemble_bearer_token, PartialToken};

        let node_1 = StellarKeypair::random();
        let node_2 = StellarKeypair::random();
        let requestor = StellarKeypair::random();
        let node_3 = StellarKeypair::random();

        let (partial, _) = PartialToken::initiate(
            [0xEE; 32],
            1741737600,
            None,
            2,
            &node_1,
            &node_2,
            vec![],
        )
        .unwrap();

        let token = assemble_bearer_token(&partial, &requestor, &node_3, 7, None).unwrap();
        let container_bytes = serialize_bearer_token(&token, &requestor).unwrap();
        let token_hash: [u8; 32] = Sha256::digest(&container_bytes).into();

        let combiner_public = StellarKeypair::random().raw_public();
        let request = RedemptionRequest::new(
            token, token_hash, &requestor, combiner_public, TEST_TIME,
        );
        let combiner_for_session = StellarKeypair::random();
        let session = RedemptionSession::new(request, combiner_for_session).unwrap();

        // Try to compose without all shards
        let result = session.compose_and_sign(b"test");
        assert!(result.is_err());
    }
}
