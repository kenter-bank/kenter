use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::Scalar;
use ed25519_dalek::hazmat::{raw_sign, ExpandedSecretKey};
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha512};
use stellar_strkey::ed25519::PublicKey as StellarPublic;
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};
use crate::shard::{ChainLink, PairInfo, Shard};

/// Incremental builder for composing a keypair from multiple shards.
///
/// Each shard is added via `add_shard()`. When all shards have been added,
/// call `build()` to produce the final `ComposedKeypair`.
pub struct CompositionBuilder {
    /// Running sum of scalars (mod L).
    scalar_sum: Zeroizing<Scalar>,
    /// Running sum of Edwards points (partial public keys).
    point_sum: EdwardsPoint,
    /// Pair information collected during composition.
    pairs: Vec<PairInfo>,
    /// Number of shards added.
    count: usize,
}

impl CompositionBuilder {
    /// Create a new empty builder.
    pub fn new() -> Self {
        Self {
            scalar_sum: Zeroizing::new(Scalar::ZERO),
            point_sum: EdwardsPoint::default(), // identity point
            pairs: Vec::new(),
            count: 0,
        }
    }

    /// Add a shard and its pair info to the composition.
    pub fn add_shard(&mut self, shard: Shard, pair_info: PairInfo) -> &mut Self {
        *self.scalar_sum += shard.scalar();
        self.point_sum += shard.partial_public();
        self.pairs.push(pair_info);
        self.count += 1;
        self
    }

    /// Number of shards added so far.
    pub fn count(&self) -> usize {
        self.count
    }

    /// The running combined public point (sum of partial public keys).
    pub fn running_public_bytes(&self) -> [u8; 32] {
        self.point_sum.compress().to_bytes()
    }

    /// The collected pair information.
    pub fn pairs(&self) -> &[PairInfo] {
        &self.pairs
    }

    /// Verify consistency: each partial public key decompresses and sums
    /// to the running point_sum.
    pub fn verify_consistency(&self) -> Result<()> {
        let mut check_sum = EdwardsPoint::default();
        for pair in &self.pairs {
            let point = pair.decompress_partial_public()?;
            check_sum += point;
        }
        if check_sum.compress() != self.point_sum.compress() {
            return Err(CryptoError::ChainVerificationFailed(
                "partial public key sum does not match running total".into(),
            ));
        }
        Ok(())
    }

    /// Finalize the composition and produce a `ComposedKeypair`.
    ///
    /// Requires at least 1 shard. Verifies consistency before building.
    pub fn build(self) -> Result<(ComposedKeypair, Vec<PairInfo>)> {
        if self.count == 0 {
            return Err(CryptoError::CompositionFailed(
                "no shards added".into(),
            ));
        }

        self.verify_consistency()?;

        // Derive the nonce key (hash_prefix) deterministically from the scalar.
        // In standard Ed25519: hash_prefix = SHA-512(seed)[32..64]
        // For composed keys: hash_prefix = SHA-512(scalar_bytes)[32..64]
        let scalar_bytes = self.scalar_sum.as_bytes();
        let hash = Sha512::digest(scalar_bytes);
        let mut nonce_key = Zeroizing::new([0u8; 32]);
        nonce_key.copy_from_slice(&hash[32..64]);

        Ok((
            ComposedKeypair {
                scalar: self.scalar_sum,
                public_point: self.point_sum,
                nonce_key,
            },
            self.pairs,
        ))
    }
}

impl Default for CompositionBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// A keypair composed from multiple ECDH shards via additive composition.
///
/// The secret scalar is `s = shard_1 + shard_2 + ... + shard_n (mod L)`.
/// The public point is `P = P_1 + P_2 + ... + P_n`.
///
/// This keypair can produce standard Ed25519 signatures that verify against P.
/// From Stellar's perspective, this is a normal account with a normal Ed25519 key.
pub struct ComposedKeypair {
    /// Combined secret scalar. Zeroized on drop.
    scalar: Zeroizing<Scalar>,
    /// Combined public point.
    public_point: EdwardsPoint,
    /// Nonce key for Ed25519 signing (derived from scalar via SHA-512).
    nonce_key: Zeroizing<[u8; 32]>,
}

impl ComposedKeypair {
    /// Sign a message using the composed secret scalar.
    ///
    /// Uses `ed25519_dalek::hazmat::raw_sign` with an `ExpandedSecretKey`
    /// constructed from the composed scalar and derived nonce key.
    pub fn sign(&self, message: &[u8]) -> Signature {
        let expanded = ExpandedSecretKey {
            scalar: *self.scalar,
            hash_prefix: *self.nonce_key,
        };

        let verifying_key = self.verifying_key();
        raw_sign::<Sha512>(&expanded, message, &verifying_key)
    }

    /// The Ed25519 verifying key derived from the composed public point.
    pub fn verifying_key(&self) -> VerifyingKey {
        let compressed = self.public_point.compress();
        VerifyingKey::from_bytes(&compressed.to_bytes())
            .expect("composed public point should be a valid verifying key")
    }

    /// Compressed 32-byte public key.
    pub fn public_bytes(&self) -> [u8; 32] {
        self.public_point.compress().to_bytes()
    }

    /// Stellar address (G...) for the composed public key.
    pub fn stellar_address(&self) -> String {
        let pub_bytes = self.public_bytes();
        let heapless_str = StellarPublic(pub_bytes).to_string();
        String::from(heapless_str.as_str())
    }

    /// Verify a signature against a composed public key.
    pub fn verify_signature(
        public_bytes: &[u8; 32],
        message: &[u8],
        signature: &Signature,
    ) -> Result<()> {
        let verifying_key = VerifyingKey::from_bytes(public_bytes)
            .map_err(|e| CryptoError::ChainVerificationFailed(e.to_string()))?;
        verifying_key
            .verify_strict(message, signature)
            .map_err(|_| CryptoError::SignatureVerificationFailed)
    }
}

impl Drop for ComposedKeypair {
    fn drop(&mut self) {
        // Zeroizing<Scalar> and Zeroizing<[u8; 32]> handle cleanup
    }
}

/// Verify that a set of partial public keys sums to the expected combined key.
///
/// This is the chain consistency check performed during token verification.
pub fn verify_chain_public_key(
    pairs: &[PairInfo],
    expected_public_bytes: &[u8; 32],
) -> Result<()> {
    let mut sum = EdwardsPoint::default();
    for pair in pairs {
        let point = pair.decompress_partial_public()?;
        sum += point;
    }

    let expected = CompressedEdwardsY::from_slice(expected_public_bytes)
        .map_err(|_| CryptoError::ChainVerificationFailed("invalid ephemeral key length".into()))?;

    if sum.compress() != expected {
        return Err(CryptoError::ChainVerificationFailed(
            "partial public keys do not sum to ephemeral key".into(),
        ));
    }

    Ok(())
}

/// Compute the ephemeral public key from ChainLinks (public data only).
///
/// This sums all partial public keys from the chain links using Edwards
/// point addition. No secret scalars are needed.
pub fn compute_ephemeral_from_links(links: &[ChainLink]) -> Result<[u8; 32]> {
    if links.is_empty() {
        return Err(CryptoError::ChainVerificationFailed(
            "empty chain".into(),
        ));
    }
    let mut sum = EdwardsPoint::default();
    for link in links {
        let point = link.decompress_partial_public()?;
        sum += point;
    }
    Ok(sum.compress().to_bytes())
}

/// Verify that ChainLink partial public keys sum to the expected combined key.
pub fn verify_chain_public_key_from_links(
    links: &[ChainLink],
    expected_public_bytes: &[u8; 32],
) -> Result<()> {
    let computed = compute_ephemeral_from_links(links)?;
    if computed != *expected_public_bytes {
        return Err(CryptoError::ChainVerificationFailed(
            "partial public keys do not sum to ephemeral key".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keypair::StellarKeypair;
    use crate::shard::{derive_shard, PairInfo};
    use ed25519_dalek::Verifier;

    const TEST_EVENT_ID: [u8; 32] = [0xAB; 32];

    #[test]
    fn test_two_shard_composition() {
        let kp1 = StellarKeypair::random();
        let kp2 = StellarKeypair::random();
        let kp3 = StellarKeypair::random();

        let shard_12 = derive_shard(&kp1, &kp2.verifying_key(), &TEST_EVENT_ID).unwrap();
        let shard_23 = derive_shard(&kp2, &kp3.verifying_key(), &TEST_EVENT_ID).unwrap();

        let info_12 = PairInfo::from_shard(&shard_12, kp1.stellar_address(), kp2.stellar_address());
        let info_23 = PairInfo::from_shard(&shard_23, kp2.stellar_address(), kp3.stellar_address());

        let mut builder = CompositionBuilder::new();
        builder.add_shard(shard_12, info_12);
        builder.add_shard(shard_23, info_23);

        let (composed, pairs) = builder.build().unwrap();
        assert_eq!(pairs.len(), 2);

        // Verify the public key is the sum of partial keys
        verify_chain_public_key(&pairs, &composed.public_bytes()).unwrap();
    }

    #[test]
    fn test_three_shard_composition() {
        let kp1 = StellarKeypair::random();
        let kp2 = StellarKeypair::random();
        let kp3 = StellarKeypair::random();
        let kp4 = StellarKeypair::random();

        let shard_12 = derive_shard(&kp1, &kp2.verifying_key(), &TEST_EVENT_ID).unwrap();
        let shard_34 = derive_shard(&kp3, &kp4.verifying_key(), &TEST_EVENT_ID).unwrap();
        let shard_14 = derive_shard(&kp1, &kp4.verifying_key(), &TEST_EVENT_ID).unwrap();

        let info_12 = PairInfo::from_shard(&shard_12, kp1.stellar_address(), kp2.stellar_address());
        let info_34 = PairInfo::from_shard(&shard_34, kp3.stellar_address(), kp4.stellar_address());
        let info_14 = PairInfo::from_shard(&shard_14, kp1.stellar_address(), kp4.stellar_address());

        let mut builder = CompositionBuilder::new();
        builder.add_shard(shard_12, info_12);
        builder.add_shard(shard_34, info_34);
        builder.add_shard(shard_14, info_14);

        let (composed, pairs) = builder.build().unwrap();
        assert_eq!(pairs.len(), 3);
        verify_chain_public_key(&pairs, &composed.public_bytes()).unwrap();
    }

    #[test]
    fn test_composition_order_independent() {
        let kp1 = StellarKeypair::random();
        let kp2 = StellarKeypair::random();
        let kp3 = StellarKeypair::random();

        // Derive shards twice (same inputs + same event_id → same outputs)
        let shard_12a = derive_shard(&kp1, &kp2.verifying_key(), &TEST_EVENT_ID).unwrap();
        let shard_23a = derive_shard(&kp2, &kp3.verifying_key(), &TEST_EVENT_ID).unwrap();
        let shard_12b = derive_shard(&kp1, &kp2.verifying_key(), &TEST_EVENT_ID).unwrap();
        let shard_23b = derive_shard(&kp2, &kp3.verifying_key(), &TEST_EVENT_ID).unwrap();

        let info_12a = PairInfo::from_shard(&shard_12a, kp1.stellar_address(), kp2.stellar_address());
        let info_23a = PairInfo::from_shard(&shard_23a, kp2.stellar_address(), kp3.stellar_address());
        let info_12b = PairInfo::from_shard(&shard_12b, kp1.stellar_address(), kp2.stellar_address());
        let info_23b = PairInfo::from_shard(&shard_23b, kp2.stellar_address(), kp3.stellar_address());

        // Order A: 12 then 23
        let mut builder_a = CompositionBuilder::new();
        builder_a.add_shard(shard_12a, info_12a);
        builder_a.add_shard(shard_23a, info_23a);
        let (composed_a, _) = builder_a.build().unwrap();

        // Order B: 23 then 12
        let mut builder_b = CompositionBuilder::new();
        builder_b.add_shard(shard_23b, info_23b);
        builder_b.add_shard(shard_12b, info_12b);
        let (composed_b, _) = builder_b.build().unwrap();

        assert_eq!(
            composed_a.public_bytes(),
            composed_b.public_bytes(),
            "composition must be order-independent"
        );
    }

    #[test]
    fn test_composed_sign_verify() {
        let kp1 = StellarKeypair::random();
        let kp2 = StellarKeypair::random();
        let kp3 = StellarKeypair::random();

        let shard_12 = derive_shard(&kp1, &kp2.verifying_key(), &TEST_EVENT_ID).unwrap();
        let shard_23 = derive_shard(&kp2, &kp3.verifying_key(), &TEST_EVENT_ID).unwrap();

        let info_12 = PairInfo::from_shard(&shard_12, kp1.stellar_address(), kp2.stellar_address());
        let info_23 = PairInfo::from_shard(&shard_23, kp2.stellar_address(), kp3.stellar_address());

        let mut builder = CompositionBuilder::new();
        builder.add_shard(shard_12, info_12);
        builder.add_shard(shard_23, info_23);
        let (composed, _) = builder.build().unwrap();

        let message = b"Kenter bearer token test message";
        let signature = composed.sign(message);

        // Verify with our method
        ComposedKeypair::verify_signature(&composed.public_bytes(), message, &signature).unwrap();
    }

    #[test]
    fn test_composed_standard_ed25519_verify() {
        // Verify that a composed signature is a standard Ed25519 signature
        // verifiable by any Ed25519 implementation (not just ours)
        let kp1 = StellarKeypair::random();
        let kp2 = StellarKeypair::random();

        let shard = derive_shard(&kp1, &kp2.verifying_key(), &TEST_EVENT_ID).unwrap();
        let info = PairInfo::from_shard(&shard, kp1.stellar_address(), kp2.stellar_address());

        let mut builder = CompositionBuilder::new();
        builder.add_shard(shard, info);
        let (composed, _) = builder.build().unwrap();

        let message = b"standard Ed25519 verification";
        let signature = composed.sign(message);

        // Use ed25519_dalek's standard Verifier trait
        let vk = composed.verifying_key();
        vk.verify(message, &signature)
            .expect("composed signature must be standard Ed25519");
    }

    #[test]
    fn test_composed_stellar_address() {
        let kp1 = StellarKeypair::random();
        let kp2 = StellarKeypair::random();

        let shard = derive_shard(&kp1, &kp2.verifying_key(), &TEST_EVENT_ID).unwrap();
        let info = PairInfo::from_shard(&shard, kp1.stellar_address(), kp2.stellar_address());

        let mut builder = CompositionBuilder::new();
        builder.add_shard(shard, info);
        let (composed, _) = builder.build().unwrap();

        let addr = composed.stellar_address();
        assert!(addr.starts_with('G'), "Stellar address must start with G");
        assert_eq!(addr.len(), 56, "Stellar address must be 56 chars");
    }

    #[test]
    fn test_empty_builder_fails() {
        let builder = CompositionBuilder::new();
        assert!(builder.build().is_err());
    }

    #[test]
    fn test_verify_chain_public_key() {
        let kp1 = StellarKeypair::random();
        let kp2 = StellarKeypair::random();
        let kp3 = StellarKeypair::random();

        let shard_12 = derive_shard(&kp1, &kp2.verifying_key(), &TEST_EVENT_ID).unwrap();
        let shard_23 = derive_shard(&kp2, &kp3.verifying_key(), &TEST_EVENT_ID).unwrap();

        let info_12 = PairInfo::from_shard(&shard_12, kp1.stellar_address(), kp2.stellar_address());
        let info_23 = PairInfo::from_shard(&shard_23, kp2.stellar_address(), kp3.stellar_address());

        let mut builder = CompositionBuilder::new();
        builder.add_shard(shard_12, info_12.clone());
        builder.add_shard(shard_23, info_23.clone());
        let (composed, _) = builder.build().unwrap();

        // Should pass
        verify_chain_public_key(&[info_12.clone(), info_23.clone()], &composed.public_bytes()).unwrap();

        // Wrong key should fail
        let wrong_key = [0u8; 32];
        assert!(verify_chain_public_key(&[info_12, info_23], &wrong_key).is_err());
    }
}
