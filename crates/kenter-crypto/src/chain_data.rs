//! Canonical Path-B `chain_data` serialization and `chain_hash` commitment.
//!
//! This is the **single source of truth** for the byte layout that the
//! `kenter-mint` contract parses in `verify::verify_chain` and commits to via
//! the `chain_hash` stored at `register_token`. It MUST stay byte-for-byte in
//! lockstep with `contracts/kenter-mint/src/verify.rs` — the contract re-hashes
//! the submitted blob and rejects any mismatch (see
//! `docs/architecture/security-model.md`),
//! so a divergence here makes legitimate Path-B redemptions fail.
//!
//! ## Layout (total = 34 + n·290 bytes)
//!
//! ```text
//! event_id    : 32 bytes
//! link_count  :  2 bytes (u16 little-endian)
//! links       : link_count × 290 bytes
//! ```
//!
//! ### ChainLink (290 bytes), fields in order
//!
//! ```text
//! node_a_public      : 32
//! node_b_public      : 32
//! partial_public_key : 32
//! shard_commitment   : 32
//! prev_link_hash     : 32
//! link_index         :  2 (u16 little-endian)
//! signature_a        : 64
//! signature_b        : 64
//! ```
//!
//! The depositor computes `chain_hash = SHA-256(serialize_chain_data(..))` and
//! passes it to `register_token`. On redemption the contract recomputes the hash
//! over the submitted bytes and requires equality before paying out.

use sha2::{Digest, Sha256};

use crate::error::{CryptoError, Result};
use crate::shard::ChainLink;
use crate::token::BearerToken;

/// Size of one serialized `ChainLink` in `chain_data`, in bytes.
pub const CHAIN_LINK_SIZE: usize = 290;

/// Fixed header size: `event_id`(32) + `link_count`(2), in bytes.
pub const CHAIN_HEADER_SIZE: usize = 34;

/// Maximum number of links the on-chain `link_count` (a `u16`) can encode.
pub const MAX_CHAIN_LINKS: usize = u16::MAX as usize;

/// Total serialized size for a chain of `n` links.
#[inline]
pub fn chain_data_len(num_links: usize) -> usize {
    CHAIN_HEADER_SIZE + num_links * CHAIN_LINK_SIZE
}

/// Serialize a signature chain into the canonical Path-B `chain_data` blob.
///
/// The output is the exact byte string `kenter-mint::verify_chain` re-parses on
/// redemption, and the preimage of the `chain_hash` commitment. Field order and
/// endianness are frozen here (see module docs).
///
/// Errors if the chain is empty, exceeds [`MAX_CHAIN_LINKS`], or any link's
/// `link_index` is not its sequential position (the contract enforces
/// `link_index == i`, so a mismatch would make a legitimate redemption fail —
/// we reject it before it can reach the ledger).
pub fn serialize_chain_data(event_id: &[u8; 32], links: &[ChainLink]) -> Result<Vec<u8>> {
    if links.is_empty() {
        return Err(CryptoError::ChainVerificationFailed(
            "cannot serialize an empty chain".into(),
        ));
    }
    if links.len() > MAX_CHAIN_LINKS {
        return Err(CryptoError::ChainVerificationFailed(format!(
            "chain has {} links, exceeds u16 link_count max ({MAX_CHAIN_LINKS})",
            links.len(),
        )));
    }

    let link_count = links.len() as u16;
    let mut buf = Vec::with_capacity(chain_data_len(links.len()));

    buf.extend_from_slice(event_id);
    buf.extend_from_slice(&link_count.to_le_bytes());

    for (i, link) in links.iter().enumerate() {
        if link.link_index as usize != i {
            return Err(CryptoError::ChainVerificationFailed(format!(
                "link at position {i} has link_index {}; chain must be sequential",
                link.link_index,
            )));
        }
        buf.extend_from_slice(&link.node_a_public);
        buf.extend_from_slice(&link.node_b_public);
        buf.extend_from_slice(&link.partial_public_key);
        buf.extend_from_slice(&link.shard_commitment);
        buf.extend_from_slice(&link.prev_link_hash);
        buf.extend_from_slice(&link.link_index.to_le_bytes());
        buf.extend_from_slice(&link.signature_a);
        buf.extend_from_slice(&link.signature_b);
    }

    debug_assert_eq!(buf.len(), chain_data_len(links.len()));
    Ok(buf)
}

/// Compute the `chain_hash` commitment registered at `register_token`.
///
/// `chain_hash = SHA-256(serialize_chain_data(event_id, links))`.
pub fn chain_hash(event_id: &[u8; 32], links: &[ChainLink]) -> Result<[u8; 32]> {
    let bytes = serialize_chain_data(event_id, links)?;
    Ok(Sha256::digest(&bytes).into())
}

/// Serialize the canonical `chain_data` directly from a [`BearerToken`].
pub fn serialize_token_chain_data(token: &BearerToken) -> Result<Vec<u8>> {
    serialize_chain_data(&token.header.event_id, &token.chain.links)
}

/// Compute the `chain_hash` commitment directly from a [`BearerToken`].
///
/// This is the value to pass to `MintClient::register_token` for the token.
pub fn token_chain_hash(token: &BearerToken) -> Result<[u8; 32]> {
    chain_hash(&token.header.event_id, &token.chain.links)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keypair::StellarKeypair;
    use crate::shard::{derive_shard, ChainLink};

    /// Build a real, signed chain of `n` links over `event_id`.
    fn build_links(event_id: &[u8; 32], n: u16) -> Vec<ChainLink> {
        let mut links = Vec::new();
        let mut prev_hash = [0u8; 32];
        for i in 0..n {
            let a = StellarKeypair::random();
            let b = StellarKeypair::random();
            let shard = derive_shard(&a, &b.verifying_key(), event_id).unwrap();
            let link = ChainLink::create(&a, &b, &shard, prev_hash, i, event_id);
            prev_hash = link.link_hash(event_id);
            links.push(link);
        }
        links
    }

    #[test]
    fn serializes_to_expected_length() {
        let event_id = [0xAB; 32];
        for n in 1u16..=4 {
            let links = build_links(&event_id, n);
            let bytes = serialize_chain_data(&event_id, &links).unwrap();
            assert_eq!(bytes.len(), chain_data_len(n as usize));
            assert_eq!(bytes.len(), 34 + (n as usize) * 290);
        }
    }

    #[test]
    fn header_and_field_offsets_match_layout() {
        // Locks the byte layout that contracts/kenter-mint/src/verify.rs parses.
        let event_id = [0x11; 32];
        let links = build_links(&event_id, 2);
        let bytes = serialize_chain_data(&event_id, &links).unwrap();

        // Header: event_id(32) || link_count(2 LE)
        assert_eq!(&bytes[0..32], &event_id);
        assert_eq!(&bytes[32..34], &2u16.to_le_bytes());

        for (i, link) in links.iter().enumerate() {
            let base = 34 + i * CHAIN_LINK_SIZE;
            assert_eq!(&bytes[base..base + 32], &link.node_a_public);
            assert_eq!(&bytes[base + 32..base + 64], &link.node_b_public);
            assert_eq!(&bytes[base + 64..base + 96], &link.partial_public_key);
            assert_eq!(&bytes[base + 96..base + 128], &link.shard_commitment);
            assert_eq!(&bytes[base + 128..base + 160], &link.prev_link_hash);
            assert_eq!(&bytes[base + 160..base + 162], &(i as u16).to_le_bytes());
            assert_eq!(&bytes[base + 162..base + 226], &link.signature_a);
            assert_eq!(&bytes[base + 226..base + 290], &link.signature_b);
        }
    }

    #[test]
    fn chain_hash_is_sha256_of_serialization() {
        let event_id = [0x22; 32];
        let links = build_links(&event_id, 3);
        let bytes = serialize_chain_data(&event_id, &links).unwrap();
        let expected: [u8; 32] = Sha256::digest(&bytes).into();
        assert_eq!(chain_hash(&event_id, &links).unwrap(), expected);
    }

    #[test]
    fn empty_chain_is_rejected() {
        assert!(serialize_chain_data(&[0u8; 32], &[]).is_err());
    }

    #[test]
    fn non_sequential_link_index_is_rejected() {
        let event_id = [0x33; 32];
        let mut links = build_links(&event_id, 2);
        links[1].link_index = 5; // not its position
        assert!(serialize_chain_data(&event_id, &links).is_err());
    }
}
