use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::Scalar;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use stellar_strkey::ed25519::PublicKey as StellarPublic;
use x25519_dalek::PublicKey as X25519Public;
use zeroize::Zeroizing;

use crate::domain::DomainSeparation;
use crate::error::{CryptoError, Result};
use crate::keypair::StellarKeypair;

/// An Ed25519 scalar derived from ECDH between two nodes in a pair.
///
/// Derivation: SHA-512(raw_X25519_DH(node_a, node_b)) → 64 bytes → reduce mod L
///
/// Both nodes in the pair independently derive the same shard (ECDH symmetry).
/// The scalar never leaves this struct except during composition.
pub struct Shard {
    /// Ed25519 scalar (mod L). Zeroized on drop.
    scalar: Zeroizing<Scalar>,
    /// Partial public key: scalar * G (EdwardsPoint).
    partial_public: EdwardsPoint,
    /// SHA-256(scalar_bytes) — commitment for verification.
    commitment: [u8; 32],
}

impl Shard {
    /// The Ed25519 scalar (for composition only).
    pub fn scalar(&self) -> &Scalar {
        &self.scalar
    }

    /// Partial public key P_i = shard_scalar * G.
    pub fn partial_public(&self) -> &EdwardsPoint {
        &self.partial_public
    }

    /// Compressed partial public key bytes (32 bytes).
    pub fn partial_public_bytes(&self) -> [u8; 32] {
        self.partial_public.compress().to_bytes()
    }

    /// SHA-256 commitment of the shard scalar bytes.
    pub fn commitment(&self) -> &[u8; 32] {
        &self.commitment
    }

    /// Verify that the commitment matches the scalar.
    pub fn verify_commitment(&self) -> bool {
        let computed = Sha256::digest(self.scalar.as_bytes());
        computed.as_slice() == self.commitment
    }

    /// Verify that the partial public key matches scalar * G.
    pub fn verify_partial_public(&self) -> bool {
        let expected = &*self.scalar * ED25519_BASEPOINT_TABLE;
        expected == self.partial_public
    }

    /// Reconstruct a Shard from raw scalar and point (used during redemption).
    pub fn from_raw(scalar: Scalar, partial_public: EdwardsPoint) -> Self {
        let commitment: [u8; 32] = Sha256::digest(scalar.as_bytes()).into();
        Self {
            scalar: Zeroizing::new(scalar),
            partial_public,
            commitment,
        }
    }
}

impl Drop for Shard {
    fn drop(&mut self) {
        // Zeroizing<Scalar> handles scalar cleanup
    }
}

/// Public information about a pair's contribution to the chain.
///
/// This is the data that gets serialized into the token — no secrets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairInfo {
    /// Stellar address (G...) of node A in the pair.
    pub node_a_address: String,
    /// Stellar address (G...) of node B in the pair.
    pub node_b_address: String,
    /// Partial public key P_i = shard_i * G (compressed Edwards Y, 32 bytes).
    pub partial_public_key: [u8; 32],
    /// SHA-256(shard_i scalar bytes) — commitment for later verification.
    pub shard_commitment: [u8; 32],
}

impl PairInfo {
    /// Create PairInfo from a shard and the two node addresses.
    pub fn from_shard(shard: &Shard, node_a_address: String, node_b_address: String) -> Self {
        Self {
            node_a_address,
            node_b_address,
            partial_public_key: shard.partial_public_bytes(),
            shard_commitment: *shard.commitment(),
        }
    }

    /// Decompress the partial public key to an EdwardsPoint.
    pub fn decompress_partial_public(&self) -> Result<EdwardsPoint> {
        let compressed = CompressedEdwardsY::from_slice(&self.partial_public_key)
            .map_err(|_| CryptoError::ChainVerificationFailed("invalid partial public key length".into()))?;
        compressed
            .decompress()
            .ok_or_else(|| CryptoError::ChainVerificationFailed("invalid Edwards point".into()))
    }
}

/// Serde helper for `[u8; 64]` arrays (Ed25519 signatures).
mod serde_sig_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let v: Vec<u8> = Deserialize::deserialize(d)?;
        v.try_into()
            .map_err(|_| serde::de::Error::custom("expected 64 bytes for signature"))
    }
}

/// An authenticated, hash-chained link in the bearer token's daisy chain.
///
/// Each ChainLink wraps the same cryptographic data as a PairInfo, but adds:
/// - **Hash chain**: `prev_link_hash` links to the previous link (SHA-256)
/// - **Dual authentication**: both nodes in the pair sign the link (Ed25519)
/// - **Domain separation**: `event_id` is included in signable bytes to prevent
///   cross-token splicing (the event_id is passed as a parameter, not stored)
///
/// This makes the chain tamper-evident: inserting, removing, or modifying
/// any link breaks the hash chain and invalidates signatures.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainLink {
    /// Raw Ed25519 public key of node A in the pair.
    pub node_a_public: [u8; 32],
    /// Raw Ed25519 public key of node B in the pair.
    pub node_b_public: [u8; 32],
    /// Partial public key P_i = shard_i * G (compressed Edwards Y, 32 bytes).
    pub partial_public_key: [u8; 32],
    /// SHA-256(shard_i scalar bytes) — commitment for later verification.
    pub shard_commitment: [u8; 32],
    /// SHA-256 of the previous link, or [0; 32] for the genesis link.
    pub prev_link_hash: [u8; 32],
    /// Zero-based index of this link in the chain.
    pub link_index: u16,
    /// Ed25519 signature by node A over signable_bytes.
    #[serde(with = "serde_sig_bytes")]
    pub signature_a: [u8; 64],
    /// Ed25519 signature by node B over signable_bytes.
    #[serde(with = "serde_sig_bytes")]
    pub signature_b: [u8; 64],
}

impl ChainLink {
    /// Create a new ChainLink, signed by both nodes.
    ///
    /// Both nodes must be present (hold their secret keys) at creation time.
    /// This is expected — both nodes in the pair must cooperate to produce
    /// the ECDH shard, so they're both available to sign.
    pub fn create(
        node_a: &StellarKeypair,
        node_b: &StellarKeypair,
        shard: &Shard,
        prev_link_hash: [u8; 32],
        link_index: u16,
        event_id: &[u8; 32],
    ) -> Self {
        let node_a_public = node_a.raw_public();
        let node_b_public = node_b.raw_public();
        let partial_public_key = shard.partial_public_bytes();
        let shard_commitment = *shard.commitment();

        let signable = Self::compute_signable_bytes(
            &node_a_public,
            &node_b_public,
            &partial_public_key,
            &shard_commitment,
            &prev_link_hash,
            link_index,
            event_id,
        );

        let signature_a = node_a.sign(&signable);
        let signature_b = node_b.sign(&signable);

        Self {
            node_a_public,
            node_b_public,
            partial_public_key,
            shard_commitment,
            prev_link_hash,
            link_index,
            signature_a: signature_a.to_bytes(),
            signature_b: signature_b.to_bytes(),
        }
    }

    /// The bytes that both nodes sign.
    ///
    /// Format: `domain_tag || node_a_pub(32) || node_b_pub(32) ||
    ///          partial_public_key(32) || shard_commitment(32) ||
    ///          prev_link_hash(32) || link_index(2 LE) || event_id(32)`
    pub fn signable_bytes(&self, event_id: &[u8; 32]) -> Vec<u8> {
        Self::compute_signable_bytes(
            &self.node_a_public,
            &self.node_b_public,
            &self.partial_public_key,
            &self.shard_commitment,
            &self.prev_link_hash,
            self.link_index,
            event_id,
        )
    }

    fn compute_signable_bytes(
        node_a_public: &[u8; 32],
        node_b_public: &[u8; 32],
        partial_public_key: &[u8; 32],
        shard_commitment: &[u8; 32],
        prev_link_hash: &[u8; 32],
        link_index: u16,
        event_id: &[u8; 32],
    ) -> Vec<u8> {
        let tag = DomainSeparation::CHAIN_LINK;
        let mut buf = Vec::with_capacity(tag.len() + 32 * 5 + 2 + 32);
        buf.extend_from_slice(tag);
        buf.extend_from_slice(node_a_public);
        buf.extend_from_slice(node_b_public);
        buf.extend_from_slice(partial_public_key);
        buf.extend_from_slice(shard_commitment);
        buf.extend_from_slice(prev_link_hash);
        buf.extend_from_slice(&link_index.to_le_bytes());
        buf.extend_from_slice(event_id);
        buf
    }

    /// SHA-256 hash of this link (used as `prev_link_hash` for the next link).
    ///
    /// Hash covers: `signable_bytes || signature_a || signature_b`
    pub fn link_hash(&self, event_id: &[u8; 32]) -> [u8; 32] {
        let signable = self.signable_bytes(event_id);
        let mut hasher = Sha256::new();
        hasher.update(&signable);
        hasher.update(self.signature_a);
        hasher.update(self.signature_b);
        hasher.finalize().into()
    }

    /// Verify both Ed25519 signatures on this link.
    pub fn verify_signatures(&self, event_id: &[u8; 32]) -> Result<()> {
        let signable = self.signable_bytes(event_id);

        let vk_a = VerifyingKey::from_bytes(&self.node_a_public)
            .map_err(|_| CryptoError::ChainLinkSignatureInvalid {
                index: self.link_index,
            })?;
        let sig_a = Signature::from_bytes(&self.signature_a);
        vk_a.verify_strict(&signable, &sig_a)
            .map_err(|_| CryptoError::ChainLinkSignatureInvalid {
                index: self.link_index,
            })?;

        let vk_b = VerifyingKey::from_bytes(&self.node_b_public)
            .map_err(|_| CryptoError::ChainLinkSignatureInvalid {
                index: self.link_index,
            })?;
        let sig_b = Signature::from_bytes(&self.signature_b);
        vk_b.verify_strict(&signable, &sig_b)
            .map_err(|_| CryptoError::ChainLinkSignatureInvalid {
                index: self.link_index,
            })?;

        Ok(())
    }

    /// Decompress the partial public key to an EdwardsPoint.
    pub fn decompress_partial_public(&self) -> Result<EdwardsPoint> {
        let compressed = CompressedEdwardsY::from_slice(&self.partial_public_key).map_err(
            |_| CryptoError::ChainVerificationFailed("invalid partial public key length".into()),
        )?;
        compressed
            .decompress()
            .ok_or_else(|| CryptoError::ChainVerificationFailed("invalid Edwards point".into()))
    }

    /// Stellar address (G...) of node A.
    pub fn node_a_address(&self) -> String {
        let s = StellarPublic(self.node_a_public).to_string();
        String::from(s.as_str())
    }

    /// Stellar address (G...) of node B.
    pub fn node_b_address(&self) -> String {
        let s = StellarPublic(self.node_b_public).to_string();
        String::from(s.as_str())
    }
}

impl From<&ChainLink> for PairInfo {
    fn from(link: &ChainLink) -> Self {
        Self {
            node_a_address: link.node_a_address(),
            node_b_address: link.node_b_address(),
            partial_public_key: link.partial_public_key,
            shard_commitment: link.shard_commitment,
        }
    }
}

/// Derive a shard from the ECDH between two Stellar keypairs.
///
/// The `event_id` acts as a per-token salt, ensuring that the same pair of
/// nodes produces a different shard for each token. Without this, shards
/// would be deterministic across tokens — compromising one token's shard
/// for pair (A, B) would reveal that shard for ALL tokens involving (A, B).
///
/// Steps:
/// 1. Convert Ed25519 keys to X25519
/// 2. Raw X25519 DH (NO HSalsa20 — this is distinct from NaCl Box shared key)
/// 3. SHA-512(SHARD_DERIVE || raw_dh || event_id) → 64 bytes
/// 4. Scalar::from_bytes_mod_order_wide → valid Ed25519 scalar mod L
/// 5. partial_public = scalar * G
/// 6. commitment = SHA-256(scalar_bytes)
pub fn derive_shard(
    own_keypair: &StellarKeypair,
    partner_verifying_key: &VerifyingKey,
    event_id: &[u8; 32],
) -> Result<Shard> {
    let own_x25519 = own_keypair.to_x25519_secret();
    let partner_x25519 = StellarKeypair::x25519_public_from_ed25519(partner_verifying_key)?;
    derive_shard_from_x25519(&own_x25519, &partner_x25519, event_id)
}

/// Derive a shard from raw X25519 keys with per-token salt.
pub fn derive_shard_from_x25519(
    own_secret: &x25519_dalek::StaticSecret,
    partner_public: &X25519Public,
    event_id: &[u8; 32],
) -> Result<Shard> {
    // Raw X25519 DH — no HSalsa20, no NaCl Box derivation
    let raw_dh = own_secret.diffie_hellman(partner_public);

    // SHA-512(domain_tag || raw_dh || event_id) → 64 bytes
    // Domain tag + event_id salt ensures per-token shard uniqueness
    let mut hasher = Sha512::new();
    hasher.update(DomainSeparation::SHARD_DERIVE);
    hasher.update(raw_dh.as_bytes());
    hasher.update(event_id);
    let hash: [u8; 64] = hasher.finalize().into();

    // Reduce mod L to get a valid Ed25519 scalar (unbiased)
    let scalar = Scalar::from_bytes_mod_order_wide(&hash);

    // Partial public key: scalar * G
    let partial_public = &scalar * ED25519_BASEPOINT_TABLE;

    // Commitment: SHA-256(scalar_bytes)
    let commitment: [u8; 32] = Sha256::digest(scalar.as_bytes()).into();

    Ok(Shard {
        scalar: Zeroizing::new(scalar),
        partial_public,
        commitment,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_EVENT_ID: [u8; 32] = [0xAB; 32];

    #[test]
    fn test_shard_derivation_deterministic() {
        let kp1 = StellarKeypair::random();
        let kp2 = StellarKeypair::random();

        let shard_a = derive_shard(&kp1, &kp2.verifying_key(), &TEST_EVENT_ID).unwrap();
        let shard_b = derive_shard(&kp1, &kp2.verifying_key(), &TEST_EVENT_ID).unwrap();

        assert_eq!(shard_a.scalar().as_bytes(), shard_b.scalar().as_bytes());
        assert_eq!(shard_a.partial_public_bytes(), shard_b.partial_public_bytes());
        assert_eq!(shard_a.commitment(), shard_b.commitment());
    }

    #[test]
    fn test_shard_symmetry() {
        // Both nodes in a pair derive the same shard (same event_id)
        let kp1 = StellarKeypair::random();
        let kp2 = StellarKeypair::random();

        let shard_1to2 = derive_shard(&kp1, &kp2.verifying_key(), &TEST_EVENT_ID).unwrap();
        let shard_2to1 = derive_shard(&kp2, &kp1.verifying_key(), &TEST_EVENT_ID).unwrap();

        assert_eq!(
            shard_1to2.scalar().as_bytes(),
            shard_2to1.scalar().as_bytes(),
            "ECDH shards must be symmetric"
        );
        assert_eq!(
            shard_1to2.partial_public_bytes(),
            shard_2to1.partial_public_bytes()
        );
        assert_eq!(shard_1to2.commitment(), shard_2to1.commitment());
    }

    #[test]
    fn test_shard_commitment_verification() {
        let kp1 = StellarKeypair::random();
        let kp2 = StellarKeypair::random();
        let shard = derive_shard(&kp1, &kp2.verifying_key(), &TEST_EVENT_ID).unwrap();

        assert!(shard.verify_commitment());
    }

    #[test]
    fn test_shard_partial_public_verification() {
        let kp1 = StellarKeypair::random();
        let kp2 = StellarKeypair::random();
        let shard = derive_shard(&kp1, &kp2.verifying_key(), &TEST_EVENT_ID).unwrap();

        assert!(shard.verify_partial_public());
    }

    #[test]
    fn test_shard_different_pairs_differ() {
        let kp1 = StellarKeypair::random();
        let kp2 = StellarKeypair::random();
        let kp3 = StellarKeypair::random();

        let shard_12 = derive_shard(&kp1, &kp2.verifying_key(), &TEST_EVENT_ID).unwrap();
        let shard_13 = derive_shard(&kp1, &kp3.verifying_key(), &TEST_EVENT_ID).unwrap();

        assert_ne!(
            shard_12.scalar().as_bytes(),
            shard_13.scalar().as_bytes(),
            "different pairs should produce different shards"
        );
    }

    #[test]
    fn test_shard_different_event_ids_differ() {
        // Same pair, different event_id → different shard (per-token uniqueness)
        let kp1 = StellarKeypair::random();
        let kp2 = StellarKeypair::random();

        let event_a = [0x01; 32];
        let event_b = [0x02; 32];

        let shard_a = derive_shard(&kp1, &kp2.verifying_key(), &event_a).unwrap();
        let shard_b = derive_shard(&kp1, &kp2.verifying_key(), &event_b).unwrap();

        assert_ne!(
            shard_a.scalar().as_bytes(),
            shard_b.scalar().as_bytes(),
            "same pair with different event_ids must produce different shards"
        );
        assert_ne!(shard_a.partial_public_bytes(), shard_b.partial_public_bytes());
        assert_ne!(shard_a.commitment(), shard_b.commitment());
    }

    #[test]
    fn test_pair_info_from_shard() {
        let kp1 = StellarKeypair::random();
        let kp2 = StellarKeypair::random();
        let shard = derive_shard(&kp1, &kp2.verifying_key(), &TEST_EVENT_ID).unwrap();

        let info = PairInfo::from_shard(
            &shard,
            kp1.stellar_address(),
            kp2.stellar_address(),
        );

        assert_eq!(info.partial_public_key, shard.partial_public_bytes());
        assert_eq!(info.shard_commitment, *shard.commitment());

        // Decompress should roundtrip
        let decompressed = info.decompress_partial_public().unwrap();
        assert_eq!(decompressed, *shard.partial_public());
    }

    // -- ChainLink tests --

    #[test]
    fn test_chain_link_create_and_verify() {
        let kp1 = StellarKeypair::random();
        let kp2 = StellarKeypair::random();
        let event_id = [0xAA; 32];
        let shard = derive_shard(&kp1, &kp2.verifying_key(), &event_id).unwrap();

        let link = ChainLink::create(&kp1, &kp2, &shard, [0; 32], 0, &event_id);

        assert_eq!(link.link_index, 0);
        assert_eq!(link.prev_link_hash, [0; 32]);
        assert_eq!(link.partial_public_key, shard.partial_public_bytes());
        assert_eq!(link.shard_commitment, *shard.commitment());
        link.verify_signatures(&event_id).unwrap();
    }

    #[test]
    fn test_chain_link_hash_chaining() {
        let kp1 = StellarKeypair::random();
        let kp2 = StellarKeypair::random();
        let kp3 = StellarKeypair::random();
        let kp4 = StellarKeypair::random();
        let event_id = [0xBB; 32];

        let shard_1 = derive_shard(&kp1, &kp2.verifying_key(), &event_id).unwrap();
        let link_0 = ChainLink::create(&kp1, &kp2, &shard_1, [0; 32], 0, &event_id);
        let hash_0 = link_0.link_hash(&event_id);

        let shard_2 = derive_shard(&kp3, &kp4.verifying_key(), &event_id).unwrap();
        let link_1 = ChainLink::create(&kp3, &kp4, &shard_2, hash_0, 1, &event_id);

        assert_eq!(link_1.prev_link_hash, hash_0);
        link_1.verify_signatures(&event_id).unwrap();

        // Hash is deterministic
        assert_eq!(link_0.link_hash(&event_id), hash_0);
    }

    #[test]
    fn test_chain_link_wrong_event_id_fails() {
        let kp1 = StellarKeypair::random();
        let kp2 = StellarKeypair::random();
        let event_id = [0xCC; 32];
        let wrong_event_id = [0xDD; 32];
        let shard = derive_shard(&kp1, &kp2.verifying_key(), &event_id).unwrap();

        let link = ChainLink::create(&kp1, &kp2, &shard, [0; 32], 0, &event_id);

        // Correct event_id succeeds
        link.verify_signatures(&event_id).unwrap();
        // Wrong event_id fails (prevents cross-token splicing)
        assert!(link.verify_signatures(&wrong_event_id).is_err());
    }

    #[test]
    fn test_chain_link_tamper_detection() {
        let kp1 = StellarKeypair::random();
        let kp2 = StellarKeypair::random();
        let event_id = [0xEE; 32];
        let shard = derive_shard(&kp1, &kp2.verifying_key(), &event_id).unwrap();

        let mut link = ChainLink::create(&kp1, &kp2, &shard, [0; 32], 0, &event_id);
        link.verify_signatures(&event_id).unwrap();

        // Tamper with partial_public_key
        link.partial_public_key[0] ^= 0xFF;
        assert!(link.verify_signatures(&event_id).is_err());
    }

    #[test]
    fn test_chain_link_to_pair_info() {
        let kp1 = StellarKeypair::random();
        let kp2 = StellarKeypair::random();
        let event_id = [0xFF; 32];
        let shard = derive_shard(&kp1, &kp2.verifying_key(), &event_id).unwrap();

        let link = ChainLink::create(&kp1, &kp2, &shard, [0; 32], 0, &event_id);
        let pair_info: PairInfo = (&link).into();

        assert_eq!(pair_info.node_a_address, kp1.stellar_address());
        assert_eq!(pair_info.node_b_address, kp2.stellar_address());
        assert_eq!(pair_info.partial_public_key, link.partial_public_key);
        assert_eq!(pair_info.shard_commitment, link.shard_commitment);
    }

    #[test]
    fn test_chain_link_addresses() {
        let kp1 = StellarKeypair::random();
        let kp2 = StellarKeypair::random();
        let event_id = [0x11; 32];
        let shard = derive_shard(&kp1, &kp2.verifying_key(), &event_id).unwrap();

        let link = ChainLink::create(&kp1, &kp2, &shard, [0; 32], 0, &event_id);

        assert_eq!(link.node_a_address(), kp1.stellar_address());
        assert_eq!(link.node_b_address(), kp2.stellar_address());
        assert!(link.node_a_address().starts_with('G'));
        assert_eq!(link.node_a_address().len(), 56);
    }
}
