use serde::{Deserialize, Serialize};

use crate::compose::{compute_ephemeral_from_links, verify_chain_public_key_from_links};
use crate::error::{CryptoError, Result};
use crate::keypair::StellarKeypair;
use crate::shard::{derive_shard, ChainLink, Shard};

/// Token type discriminator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum TokenType {
    Bearer = 0x01,
    Data = 0x02,
    Partial = 0x03,
}

impl TokenType {
    pub fn from_u8(v: u8) -> Result<Self> {
        match v {
            0x01 => Ok(Self::Bearer),
            0x02 => Ok(Self::Data),
            0x03 => Ok(Self::Partial),
            _ => Err(CryptoError::InvalidToken(format!("unknown token type: {v:#x}"))),
        }
    }
}

/// Header common to all token types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenHeader {
    pub version: u16,
    pub token_type: TokenType,
    /// SHA-256 of the print request event.
    pub event_id: [u8; 32],
    /// Unix timestamp of printing.
    pub print_timestamp: i64,
    /// Optional denomination in stroops (1 XLM = 10^7 stroops).
    pub denomination: Option<u64>,
}

/// Chain section recording all pair contributions as authenticated ChainLinks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainSection {
    /// Authenticated, hash-chained links — one per pair.
    pub links: Vec<ChainLink>,
    pub total_pairs: u16,
    /// Required pairs for redemption (== total_pairs for n-of-n Phase 1).
    pub required_pairs: u16,
}

/// Initiation proof from the chain initiator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitiationProof {
    /// Ed25519 public key of the initiator (32 bytes).
    pub initiator_public_key: [u8; 32],
    /// VRF proof bytes (opaque for Phase 1).
    pub vrf_proof: Vec<u8>,
}

/// Caveats attached to a token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TokenCaveat {
    /// Expiration as Unix timestamp.
    Expiration(i64),
    /// Maximum redemptions (Phase 1: always 1).
    MaxRedemptions(u32),
    /// Custom key-value caveat.
    Custom(String, String),
}

impl TokenCaveat {
    /// Type discriminator byte for serialization.
    pub fn type_byte(&self) -> u8 {
        match self {
            Self::Expiration(_) => 0x01,
            Self::MaxRedemptions(_) => 0x02,
            Self::Custom(_, _) => 0x03,
        }
    }
}

/// Which deployment issued a note, and what it redeems in.
///
/// Without this a note cannot be accepted from a stranger once more
/// than one mint exists. `slot_id` is only unique *within* a mint --
/// slot 1 exists on every deployment -- so a holder who asks the wrong
/// contract gets a different live note's record back. The gates catch
/// it, because `describes()` compares the chain hash and it will not
/// match, but what the holder sees is their own good note reported as
/// DISPUTED. That is the direction that loses money: the next step is
/// `forget`, and the only copy is gone.
///
/// Carrying it here also means the payee learns what they are being
/// paid in *before* accepting, from the signed bytes, with no network
/// round trip and nothing to trust.
///
/// Both are raw 32-byte contract ids -- the payload of a `C…` strkey.
/// `kenter-crypto` stays free of strkey so it can build for wasm;
/// callers encode and decode at the edges.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MintBinding {
    /// The mint contract that holds this note's escrow.
    pub mint: [u8; 32],
    /// The asset that mint escrows, as its SAC contract id.
    ///
    /// Recorded separately rather than looked up, because it decides
    /// whether the note can be frozen: an issued asset's `auth_revocable`
    /// flag reaches contract balances, so the escrow behind a note can
    /// be frozen by the asset's issuer. Native XLM has no issuer and so
    /// cannot be. A payee is entitled to know which they are holding.
    pub pay_token: [u8; 32],
}

/// A complete bearer token.
#[derive(Debug, Clone)]
pub struct BearerToken {
    pub header: TokenHeader,
    /// Which mint issued this note, and in what asset.
    ///
    /// `None` for a note assembled without a mint -- the offline
    /// `print` path, which escrows nothing and has no slot. A note that
    /// came off a real print always carries it.
    pub mint_binding: Option<MintBinding>,
    /// Combined public key P = P_1 + P_2 + ... + P_n (compressed Edwards, 32 bytes).
    /// The print slot this note was registered under.
    ///
    /// The mint keys records by slot, so this is how a redemption finds
    /// one. Keying by `ephemeral_public_key` would not do: it is a public
    /// value anyone could name first.
    pub slot_id: u32,
    pub ephemeral_public_key: [u8; 32],
    /// Secret half of the note's **claim key**. The public half is
    /// committed on-chain at registration; this never leaves the
    /// container.
    ///
    /// Path B redemption presents a signature from this key rather than
    /// the chain preimage alone. The chain is published by any redemption
    /// attempt, and an attempt that fails on-chain publishes it while the
    /// note is still live -- so without this, reading a failed
    /// transaction off the ledger was enough to take the note.
    ///
    /// **Independent randomness.** It must not be derived from anything
    /// that gets published, and in particular not from the chain: that
    /// would hand the key to the very observer this exists to stop.
    ///
    /// **Not in `PartialToken`.** A partial token travels from node to
    /// node while printing; the finished note is assembled by the
    /// requestor, which is the only place this belongs.
    ///
    /// The note stays bearer: the key is in the file rather than bound to
    /// a person, so copying the file copies the right to redeem.
    pub claim_secret: [u8; 32],
    pub chain: ChainSection,
    pub initiation_proof: InitiationProof,
    pub caveats: Vec<TokenCaveat>,
    /// Ed25519 signature over all preceding fields (signed by requestor).
    pub signature: [u8; 64],
}

impl BearerToken {
    /// Stellar address derived from the ephemeral public key.
    pub fn ephemeral_address(&self) -> String {
        let heapless_str =
            stellar_strkey::ed25519::PublicKey(self.ephemeral_public_key).to_string();
        String::from(heapless_str.as_str())
    }

    /// Public half of the claim key, which the mint records at
    /// registration and checks at Path B redemption.
    pub fn claim_public_key(&self) -> [u8; 32] {
        ed25519_dalek::SigningKey::from_bytes(&self.claim_secret)
            .verifying_key()
            .to_bytes()
    }

    /// Sign a Path B redemption, binding it to `recipient`.
    ///
    /// `contract_xdr` and `recipient_xdr` are the XDR encodings the mint
    /// hashes, so the digest built here matches the one it verifies.
    pub fn sign_claim(&self, contract_xdr: &[u8], recipient_xdr: &[u8]) -> [u8; 64] {
        use ed25519_dalek::Signer;
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(crate::domain::DomainSeparation::REDEEM_CLAIM);
        h.update(contract_xdr);
        h.update(self.slot_id.to_be_bytes());
        h.update(self.ephemeral_public_key);
        h.update(recipient_xdr);
        let digest: [u8; 32] = h.finalize().into();
        ed25519_dalek::SigningKey::from_bytes(&self.claim_secret)
            .sign(&digest)
            .to_bytes()
    }

    /// Verify chain consistency: partial public keys must sum to ephemeral key.
    pub fn verify_chain(&self) -> Result<()> {
        verify_chain_public_key_from_links(&self.chain.links, &self.ephemeral_public_key)
    }

    /// Verify full chain integrity: signatures, hash chain, and key consistency.
    pub fn verify_chain_integrity(&self) -> Result<()> {
        verify_chain_integrity(&self.chain.links, &self.header.event_id)?;
        self.verify_chain()
    }
}

/// A partial (in-flight) token during chain construction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartialToken {
    pub header: TokenHeader,
    /// Running combined public key (sum of partial keys so far).
    pub running_public_key: [u8; 32],
    pub chain: ChainSection,
    pub initiation_proof: InitiationProof,
    /// How many more pairs are needed.
    pub remaining_pairs: u16,
}

impl PartialToken {
    /// Create the initial partial token (first pair in the chain).
    ///
    /// Both nodes must be present to derive the shard and sign the ChainLink.
    pub fn initiate(
        event_id: [u8; 32],
        print_timestamp: i64,
        denomination: Option<u64>,
        total_pairs: u16,
        initiator_keypair: &StellarKeypair,
        partner_keypair: &StellarKeypair,
        vrf_proof: Vec<u8>,
    ) -> Result<(Self, Shard)> {
        let shard = derive_shard(initiator_keypair, &partner_keypair.verifying_key(), &event_id)?;

        let link = ChainLink::create(
            initiator_keypair,
            partner_keypair,
            &shard,
            [0u8; 32], // genesis: no previous link
            0,          // first link
            &event_id,
        );

        let running_public_key = shard.partial_public_bytes();

        let token = PartialToken {
            header: TokenHeader {
                // The container's version, which is what this reads back
                // as off the wire. A literal 2 here made the struct and its
                // own bytes disagree; nothing signs or hashes the field.
                version: crate::container::SYMTOKEN_VERSION,
                token_type: TokenType::Partial,
                event_id,
                print_timestamp,
                denomination,
            },
            running_public_key,
            chain: ChainSection {
                links: vec![link],
                total_pairs,
                required_pairs: total_pairs,
            },
            initiation_proof: InitiationProof {
                initiator_public_key: initiator_keypair.raw_public(),
                vrf_proof,
            },
            remaining_pairs: total_pairs - 1,
        };

        Ok((token, shard))
    }

    /// Extend the chain with a new pair.
    ///
    /// Verifies existing chain integrity before extending. Both nodes in
    /// the new pair must be present to derive the shard and sign the link.
    pub fn extend(
        &mut self,
        new_node_keypair: &StellarKeypair,
        partner_keypair: &StellarKeypair,
    ) -> Result<Shard> {
        if self.remaining_pairs == 0 {
            return Err(CryptoError::InvalidToken(
                "no remaining pairs — use assemble() for the final link".into(),
            ));
        }

        // Verify existing chain integrity before extending
        self.verify_chain_integrity()?;

        let shard = derive_shard(new_node_keypair, &partner_keypair.verifying_key(), &self.header.event_id)?;

        // Chain the new link to the previous one
        let prev_hash = self.chain.links.last().unwrap().link_hash(&self.header.event_id);
        let link_index = self.chain.links.len() as u16;

        let link = ChainLink::create(
            new_node_keypair,
            partner_keypair,
            &shard,
            prev_hash,
            link_index,
            &self.header.event_id,
        );

        // Update running public key: add the new partial public key
        let current_point = decompress_point(&self.running_public_key)?;
        let new_point = current_point + shard.partial_public();
        self.running_public_key = new_point.compress().to_bytes();

        self.chain.links.push(link);
        self.remaining_pairs -= 1;

        Ok(shard)
    }

    /// Verify full chain integrity: dual signatures, hash chain, sequential indices.
    pub fn verify_chain_integrity(&self) -> Result<()> {
        verify_chain_integrity(&self.chain.links, &self.header.event_id)
    }
}

/// Assemble a complete bearer token from a partial token.
///
/// The requestor calls this as the final link in the chain. The requestor
/// derives the final shard with its partner, creates the final ChainLink,
/// and computes the ephemeral public key from **public data only** — no
/// prior shard scalars are needed.
///
/// The `ComposedKeypair` (full secret) is NOT produced here — that only
/// happens during redemption when all pair nodes contribute their shards.
///
/// The note's **claim key** is generated here, because here is the first
/// and only place the whole note exists: the requestor assembles it
/// locally, and no node ever sees it. The public half goes to
/// `register_token`; the secret half stays in the container.
pub fn assemble_bearer_token(
    partial: &PartialToken,
    requestor_keypair: &StellarKeypair,
    partner_keypair: &StellarKeypair,
    slot_id: u32,
    expiration: Option<i64>,
) -> Result<BearerToken> {
    // Verify chain integrity before assembly
    partial.verify_chain_integrity()?;

    if partial.remaining_pairs != 1 {
        return Err(CryptoError::InvalidToken(format!(
            "expected 1 remaining pair for assembly, got {}",
            partial.remaining_pairs
        )));
    }

    // Derive the requestor's (final) shard
    let final_shard = derive_shard(requestor_keypair, &partner_keypair.verifying_key(), &partial.header.event_id)?;

    // Create the final ChainLink, chained to the last existing link
    let prev_hash = partial
        .chain
        .links
        .last()
        .unwrap()
        .link_hash(&partial.header.event_id);
    let link_index = partial.chain.links.len() as u16;

    let final_link = ChainLink::create(
        requestor_keypair,
        partner_keypair,
        &final_shard,
        prev_hash,
        link_index,
        &partial.header.event_id,
    );

    // Build complete chain with all links
    let mut all_links = partial.chain.links.clone();
    all_links.push(final_link);

    // Compute ephemeral public key from PUBLIC data only (sum of partial public keys)
    let ephemeral_public_key = compute_ephemeral_from_links(&all_links)?;

    // Build caveats
    let mut caveats = Vec::new();
    if let Some(exp) = expiration {
        caveats.push(TokenCaveat::Expiration(exp));
    }
    caveats.push(TokenCaveat::MaxRedemptions(1));

    // Independent randomness, never derived from the chain: the chain is
    // published by any redemption attempt, so a key derived from it would
    // be handed to the same observer this is meant to stop.
    let claim_secret: [u8; 32] = rand::random();

    let token = BearerToken {
        slot_id,
        // Set by the caller that knows the deployment; assembly does
        // not, and must not guess.
        mint_binding: None,
        header: TokenHeader {
            version: crate::container::SYMTOKEN_VERSION,
            token_type: TokenType::Bearer,
            event_id: partial.header.event_id,
            print_timestamp: partial.header.print_timestamp,
            denomination: partial.header.denomination,
        },
        ephemeral_public_key,
        claim_secret,
        chain: ChainSection {
            links: all_links,
            total_pairs: partial.chain.total_pairs,
            required_pairs: partial.chain.required_pairs,
        },
        initiation_proof: partial.initiation_proof.clone(),
        caveats,
        signature: [0u8; 64], // placeholder — set by container serialization
    };

    Ok(token)
}

/// Verify chain integrity: dual signatures, hash chain, sequential indices.
fn verify_chain_integrity(links: &[ChainLink], event_id: &[u8; 32]) -> Result<()> {
    let mut expected_prev_hash = [0u8; 32]; // genesis

    for (i, link) in links.iter().enumerate() {
        // Verify sequential index
        if link.link_index != i as u16 {
            return Err(CryptoError::ChainLinkHashMismatch {
                index: i as u16,
            });
        }

        // Verify prev_link_hash chain
        if link.prev_link_hash != expected_prev_hash {
            return Err(CryptoError::ChainLinkHashMismatch {
                index: i as u16,
            });
        }

        // Verify dual signatures
        link.verify_signatures(event_id)?;

        // Advance the hash chain
        expected_prev_hash = link.link_hash(event_id);
    }

    Ok(())
}

fn decompress_point(bytes: &[u8; 32]) -> Result<curve25519_dalek::edwards::EdwardsPoint> {
    let compressed = curve25519_dalek::edwards::CompressedEdwardsY::from_slice(bytes)
        .map_err(|_| CryptoError::InvalidToken("invalid Edwards point length".into()))?;
    compressed
        .decompress()
        .ok_or_else(|| CryptoError::InvalidToken("invalid Edwards point".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_partial_token_initiation() {
        let initiator = StellarKeypair::random();
        let partner = StellarKeypair::random();
        let event_id = [0xABu8; 32];

        let (partial, shard) = PartialToken::initiate(
            event_id,
            1741737600,
            Some(10_000_000),
            3,
            &initiator,
            &partner,
            vec![0x01, 0x02, 0x03],
        )
        .unwrap();

        assert_eq!(partial.header.version, crate::container::SYMTOKEN_VERSION);
        assert_eq!(partial.header.token_type, TokenType::Partial);
        assert_eq!(partial.chain.links.len(), 1);
        assert_eq!(partial.remaining_pairs, 2);
        assert_eq!(partial.running_public_key, shard.partial_public_bytes());

        // Chain integrity should verify
        partial.verify_chain_integrity().unwrap();
    }

    #[test]
    fn test_partial_token_extension() {
        let kp1 = StellarKeypair::random();
        let kp2 = StellarKeypair::random();
        let kp3 = StellarKeypair::random();
        let kp4 = StellarKeypair::random();

        let (mut partial, _shard1) = PartialToken::initiate(
            [0xBB; 32],
            1741737600,
            None,
            3,
            &kp1,
            &kp2,
            vec![],
        )
        .unwrap();

        let _shard2 = partial.extend(&kp3, &kp4).unwrap();
        assert_eq!(partial.chain.links.len(), 2);
        assert_eq!(partial.remaining_pairs, 1);

        // Chain integrity should still verify
        partial.verify_chain_integrity().unwrap();

        // Hash chain should be correct
        let link_0_hash = partial.chain.links[0].link_hash(&partial.header.event_id);
        assert_eq!(partial.chain.links[1].prev_link_hash, link_0_hash);
    }

    #[test]
    fn test_bearer_token_assembly() {
        let kp1 = StellarKeypair::random();
        let kp2 = StellarKeypair::random();
        let requestor = StellarKeypair::random();
        let kp3 = StellarKeypair::random();

        // Initiate chain: pair (kp1, kp2)
        let (partial, _shard1) = PartialToken::initiate(
            [0xCC; 32],
            1741737600,
            Some(5_000_000),
            2,
            &kp1,
            &kp2,
            vec![0xFF],
        )
        .unwrap();

        // Requestor assembles: pair (requestor, kp3)
        let token = assemble_bearer_token(
            &partial,
            &requestor,
            &kp3,
            7,
            Some(1741824000),
        )
        .unwrap();

        assert_eq!(token.header.token_type, TokenType::Bearer);
        assert_eq!(token.chain.links.len(), 2);
        assert_eq!(token.chain.total_pairs, 2);

        // Chain verification (public key consistency)
        token.verify_chain().unwrap();

        // Full chain integrity (signatures + hash chain + key consistency)
        token.verify_chain_integrity().unwrap();

        // Stellar address should be valid
        let addr = token.ephemeral_address();
        assert!(addr.starts_with('G'));
    }

    #[test]
    fn test_bearer_token_chain_verification_detects_tampering() {
        let kp1 = StellarKeypair::random();
        let kp2 = StellarKeypair::random();
        let requestor = StellarKeypair::random();
        let kp3 = StellarKeypair::random();

        let (partial, _shard1) = PartialToken::initiate(
            [0xDD; 32],
            1741737600,
            None,
            2,
            &kp1,
            &kp2,
            vec![],
        )
        .unwrap();

        let mut token = assemble_bearer_token(
            &partial,
            &requestor,
            &kp3,
            7,
            None,
        )
        .unwrap();

        // Tamper with the ephemeral key
        token.ephemeral_public_key = [0u8; 32];
        assert!(token.verify_chain().is_err());
    }

    #[test]
    fn test_assembly_rejects_wrong_remaining_pairs() {
        let kp1 = StellarKeypair::random();
        let kp2 = StellarKeypair::random();
        let requestor = StellarKeypair::random();
        let kp3 = StellarKeypair::random();

        // 3-pair chain, only 1 pair collected → remaining_pairs = 2, not 1
        let (partial, _shard1) = PartialToken::initiate(
            [0xEE; 32],
            1741737600,
            None,
            3,
            &kp1,
            &kp2,
            vec![],
        )
        .unwrap();

        // Should reject: 2 remaining pairs, but assembly needs exactly 1
        let result = assemble_bearer_token(&partial, &requestor, &kp3, 7, None);
        assert!(result.is_err());
    }
}
