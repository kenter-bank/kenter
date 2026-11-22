//! Kenter protocol handlers for tunnel requests.
//!
//! Pair-node side:
//!   - `handle_shard_request` — re-derives shard, encrypts to combiner, returns ShardResponse
//!   - `handle_extend_request` — extends a partial token's chain, returns ExtendResponse
//!
//! Combiner side:
//!   - `build_shard_request` / `parse_shard_response` — shard exchange helpers
//!   - `build_extend_request` / `parse_extend_response` — chain extension helpers

use base64::prelude::*;
use std::collections::HashMap;
use std::io::Cursor;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use kenter_crypto::container::{deserialize_partial_token, serialize_partial_token};
use kenter_crypto::keypair::StellarKeypair;
use kenter_crypto::redemption::{contribute_shard, EncryptedShard};
use kenter_crypto::shard::ChainLink;
use kenter_crypto::token::PartialToken;

use crate::protocol::{ExtendRequest, ExtendResponse, ShardRequest, ShardResponse};

// ---------------------------------------------------------------------------
// Rate-limiting state (per pair node)
// ---------------------------------------------------------------------------

/// How long a served link stays marked.
///
/// Comfortably past the shard request's own freshness window
/// (`SHARD_REQUEST_MAX_AGE_SECS` + `SHARD_REQUEST_MAX_FUTURE_SECS`), so
/// no authorization that is still valid can be replayed against a
/// cleared mark -- and short enough that a redemption which failed for
/// any other reason can be retried.
///
/// Not forever: that would be worse than a memory leak. The mark is set
/// before a shard is actually produced, so a Path A attempt that failed
/// afterwards -- network, combiner crash, anything -- would leave the
/// link marked for the life of the process, and the holder could never
/// redeem through that node again.
const SERVED_TTL: Duration = Duration::from_secs(900);

/// Tracks which `(event_id, link_index)` tuples have been served
/// recently.
///
/// A pair node contributes at most one shard per link per redemption,
/// so a relay cannot harvest shards by asking repeatedly with different
/// combiner keys.
pub struct ShardRateLimiter {
    served: Mutex<HashMap<([u8; 32], u16), Instant>>,
}

impl ShardRateLimiter {
    pub fn new() -> Self {
        Self {
            served: Mutex::new(HashMap::new()),
        }
    }

    /// Returns `true` if this link has already been served recently.
    ///
    /// **Call this only once a request has otherwise been accepted.**
    /// Run before the pair-membership and freshness checks, a request
    /// that was about to be refused would still mark the link on its way
    /// out -- and a caller with no relationship to the pair could burn a
    /// link the real holder then could not use.
    pub fn check_and_mark(&self, event_id: &[u8; 32], link_index: u16) -> bool {
        let now = Instant::now();
        let mut served = self.served.lock().expect("rate limiter lock poisoned");
        served.retain(|_, at| now.duration_since(*at) < SERVED_TTL);
        served.insert((*event_id, link_index), now).is_some()
    }

    /// How many links are currently marked. Bounded by what has been
    /// served within [`SERVED_TTL`].
    pub fn tracked(&self) -> usize {
        self.served.lock().expect("rate limiter lock poisoned").len()
    }
}

impl Default for ShardRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Pair-node handler: shard requests
// ---------------------------------------------------------------------------

/// Context required by a pair node to handle shard requests.
pub struct PairNodeContext {
    /// This node's keypair.
    pub own_keypair: StellarKeypair,
    /// Rate limiter to prevent duplicate shard contributions.
    pub rate_limiter: ShardRateLimiter,
}

/// Handle an incoming shard request from a combiner.
///
/// Decodes the request, re-derives the shard, encrypts it to the combiner,
/// and returns a `ShardResponse`.
pub fn handle_shard_request(
    ctx: &PairNodeContext,
    request: &ShardRequest,
) -> ShardResponse {
    match handle_shard_request_inner(ctx, request) {
        Ok(resp) => resp,
        Err(e) => ShardResponse::error("error", &e),
    }
}

fn handle_shard_request_inner(
    ctx: &PairNodeContext,
    request: &ShardRequest,
) -> Result<ShardResponse, String> {
    // Decode fields
    let chain_link_bytes = BASE64_STANDARD
        .decode(&request.chain_link)
        .map_err(|e| format!("invalid chain_link base64: {e}"))?;

    let chain_link = deserialize_chain_link(&chain_link_bytes)
        .map_err(|e| format!("invalid chain_link: {e}"))?;

    let event_id = decode_hex_32(&request.event_id, "event_id")?;
    let combiner_public = decode_hex_32(&request.combiner_public_key, "combiner_public_key")?;
    let signature = decode_hex_64(&request.signature, "signature")?;
    let token_hash = decode_hex_32(&request.token_hash, "token_hash")?;
    let nonce = decode_hex_32(&request.nonce, "nonce")?;

    // Verify the holder authorized THIS combiner key before we ever encrypt a
    // shard to it. Without this a relay could substitute its own combiner key
    // and intercept the shard (MITM). See kenter_crypto::redemption.
    if kenter_crypto::redemption::verify_holder_signature(
        &token_hash,
        &request.holder_address,
        &combiner_public,
        &nonce,
        request.timestamp,
        &signature,
    )
    .is_err()
    {
        return Ok(ShardResponse::error(
            "unauthorized",
            "holder signature does not authorize this combiner key",
        ));
    }

    // Determine partner public key (the other node in the pair)
    let own_public = ctx.own_keypair.raw_public();
    let partner_public_bytes = if chain_link.node_a_public == own_public {
        chain_link.node_b_public
    } else if chain_link.node_b_public == own_public {
        chain_link.node_a_public
    } else {
        return Ok(ShardResponse::error(
            "not_found",
            "this node is not part of the requested pair",
        ));
    };

    let partner_vk = ed25519_dalek::VerifyingKey::from_bytes(&partner_public_bytes)
        .map_err(|e| format!("invalid partner public key: {e}"))?;

    // Current time for timestamp validation
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before epoch")
        .as_secs() as i64;

    // Only now mark the link served.
    //
    // Not before the pair-membership and freshness checks: there a
    // request that was about to be refused would still mark the link on
    // the way out -- and a caller with no relationship to the pair could
    // burn a link that the real holder then could not use.
    //
    // It is still ahead of `contribute_shard`, deliberately: the one
    // thing that must not happen twice is a shard leaving this node,
    // and marking afterwards would leave a window where two concurrent
    // requests both pass the check. A request refused by
    // `contribute_shard` after this point costs the holder a retry
    // after SERVED_TTL rather than a shard.
    if ctx.rate_limiter.check_and_mark(&event_id, chain_link.link_index) {
        return Ok(ShardResponse::error(
            "refused",
            "shard already contributed for this token link",
        ));
    }

    // Re-derive and contribute the shard (combiner_public is Ed25519 pub key bytes)
    let encrypted = contribute_shard(
        &ctx.own_keypair,
        &partner_vk,
        &chain_link,
        &combiner_public,
        &event_id,
        request.timestamp,
        current_time,
    )
    .map_err(|e| format!("{e}"))?;

    // Serialize the encrypted shard to base64
    let shard_b64 = serialize_encrypted_shard_b64(&encrypted);

    Ok(ShardResponse::ok(shard_b64))
}

// ---------------------------------------------------------------------------
// Combiner side: build shard requests
// ---------------------------------------------------------------------------

/// Build a `ShardRequest` for a given chain link.
///
/// The combiner calls this for each pair, relaying the holder's redemption
/// authorization (`holder_address`, `token_hash`, `nonce`, `holder_signature`,
/// `timestamp`) verbatim so each pair node can verify the combiner key was
/// holder-signed before serving a shard. The `timestamp` must be the one the
/// holder signed over (from the `RedemptionRequest`), not a fresh one.
#[allow(clippy::too_many_arguments)]
pub fn build_shard_request(
    chain_link: &ChainLink,
    event_id: &[u8; 32],
    combiner_public_key: &[u8; 32],
    holder_address: &str,
    token_hash: &[u8; 32],
    nonce: &[u8; 32],
    holder_signature: &[u8; 64],
    timestamp: i64,
) -> ShardRequest {
    let chain_link_bytes = serialize_chain_link(chain_link);

    ShardRequest {
        msg_type: "shard_request".into(),
        chain_link: BASE64_STANDARD.encode(&chain_link_bytes),
        event_id: hex::encode(event_id),
        combiner_public_key: hex::encode(combiner_public_key),
        holder_address: holder_address.to_string(),
        token_hash: hex::encode(token_hash),
        nonce: hex::encode(nonce),
        signature: hex::encode(holder_signature),
        timestamp,
    }
}

/// Parse a `ShardResponse` and decode the encrypted shard.
pub fn parse_shard_response(response: &ShardResponse) -> Result<EncryptedShard, String> {
    if response.status != "ok" {
        return Err(format!(
            "shard response error ({}): {}",
            response.status,
            response.error.as_deref().unwrap_or("unknown")
        ));
    }

    let shard_b64 = response
        .encrypted_shard
        .as_ref()
        .ok_or("missing encrypted_shard in ok response")?;

    let shard_bytes = BASE64_STANDARD
        .decode(shard_b64)
        .map_err(|e| format!("invalid encrypted_shard base64: {e}"))?;

    deserialize_encrypted_shard(&shard_bytes)
}

// ---------------------------------------------------------------------------
// Pair-node handler: extend requests (printing flow)
// ---------------------------------------------------------------------------

/// Context required by a relay node to handle extend requests.
///
/// The relay node is one half of a pair. Its partner must also be
/// accessible to perform the ECDH + dual-sign extension. In the
/// current model, both keypairs are local (desktop app holds both).
pub struct ExtendNodeContext {
    /// This node's keypair.
    pub own_keypair: StellarKeypair,
    /// The partner node's keypair for this extension step.
    pub partner_keypair: StellarKeypair,
}

/// Handle an incoming extend request (printing relay).
///
/// Deserializes the partial token, verifies chain integrity, extends
/// with a new ChainLink (ECDH + dual sign), and returns the extended
/// partial token.
pub fn handle_extend_request(
    ctx: &ExtendNodeContext,
    request: &ExtendRequest,
) -> ExtendResponse {
    match handle_extend_request_inner(ctx, request) {
        Ok(resp) => resp,
        Err(e) => ExtendResponse::error(&e),
    }
}

fn handle_extend_request_inner(
    ctx: &ExtendNodeContext,
    request: &ExtendRequest,
) -> Result<ExtendResponse, String> {
    // Decode the partial token
    let token_bytes = BASE64_STANDARD
        .decode(&request.partial_token)
        .map_err(|e| format!("invalid partial_token base64: {e}"))?;

    let mut partial = deserialize_partial_token(&token_bytes)
        .map_err(|e| format!("invalid partial token: {e}"))?;

    // Verify chain integrity before extending
    partial
        .verify_chain_integrity()
        .map_err(|e| format!("chain integrity check failed: {e}"))?;

    // Check we have remaining pairs to extend
    if partial.remaining_pairs == 0 {
        return Err("no remaining pairs — token chain is already complete".into());
    }

    // Extend the chain with our pair
    partial
        .extend(&ctx.own_keypair, &ctx.partner_keypair)
        .map_err(|e| format!("extension failed: {e}"))?;

    // Re-serialize the extended partial token
    let extended_bytes = serialize_partial_token(&partial)
        .map_err(|e| format!("serialization failed: {e}"))?;

    Ok(ExtendResponse::ok(BASE64_STANDARD.encode(&extended_bytes)))
}

// ---------------------------------------------------------------------------
// Chain relay: build extend requests
// ---------------------------------------------------------------------------

/// Build an `ExtendRequest` from a partial token.
///
/// The initiator or relay node serializes the partial token and sends it
/// to the next pair's node via their tunnel endpoint.
pub fn build_extend_request(
    partial: &PartialToken,
    slot_id: u32,
) -> Result<ExtendRequest, String> {
    let token_bytes = serialize_partial_token(partial)
        .map_err(|e| format!("serialization failed: {e}"))?;

    Ok(ExtendRequest {
        msg_type: "extend_request".into(),
        partial_token: BASE64_STANDARD.encode(&token_bytes),
        slot_id,
    })
}

/// Parse an `ExtendResponse` and decode the extended partial token.
/// The index and partial public key of the link an extend response just added
/// — exactly the two values `confirm_link` needs.
pub fn last_link_of(response: &ExtendResponse) -> Result<(u32, [u8; 32]), String> {
    let partial = parse_extend_response(response)?;
    let link = partial
        .chain
        .links
        .last()
        .ok_or_else(|| "extended token has no links".to_string())?;
    Ok((link.link_index as u32, link.partial_public_key))
}

pub fn parse_extend_response(response: &ExtendResponse) -> Result<PartialToken, String> {
    if response.status != "ok" {
        return Err(format!(
            "extend response error: {}",
            response.error.as_deref().unwrap_or("unknown")
        ));
    }

    let token_b64 = response
        .partial_token
        .as_ref()
        .ok_or("missing partial_token in ok response")?;

    let token_bytes = BASE64_STANDARD
        .decode(token_b64)
        .map_err(|e| format!("invalid partial_token base64: {e}"))?;

    deserialize_partial_token(&token_bytes)
        .map_err(|e| format!("invalid partial token: {e}"))
}

// ---------------------------------------------------------------------------
// ChainLink binary serialization (matches container.rs format: 290 bytes)
// ---------------------------------------------------------------------------

/// Serialize a ChainLink to bytes (290 bytes).
pub fn serialize_chain_link(link: &ChainLink) -> Vec<u8> {
    let mut buf = Vec::with_capacity(290);
    buf.extend_from_slice(&link.node_a_public);
    buf.extend_from_slice(&link.node_b_public);
    buf.extend_from_slice(&link.partial_public_key);
    buf.extend_from_slice(&link.shard_commitment);
    buf.extend_from_slice(&link.prev_link_hash);
    buf.extend_from_slice(&link.link_index.to_le_bytes());
    buf.extend_from_slice(&link.signature_a);
    buf.extend_from_slice(&link.signature_b);
    buf
}

/// Deserialize a ChainLink from bytes.
fn deserialize_chain_link(data: &[u8]) -> Result<ChainLink, String> {
    if data.len() != 290 {
        return Err(format!("expected 290 bytes, got {}", data.len()));
    }
    let mut c = Cursor::new(data);
    let mut node_a_public = [0u8; 32];
    let mut node_b_public = [0u8; 32];
    let mut partial_public_key = [0u8; 32];
    let mut shard_commitment = [0u8; 32];
    let mut prev_link_hash = [0u8; 32];
    let mut link_index_bytes = [0u8; 2];
    let mut signature_a = [0u8; 64];
    let mut signature_b = [0u8; 64];

    use std::io::Read;
    c.read_exact(&mut node_a_public).map_err(|e| e.to_string())?;
    c.read_exact(&mut node_b_public).map_err(|e| e.to_string())?;
    c.read_exact(&mut partial_public_key).map_err(|e| e.to_string())?;
    c.read_exact(&mut shard_commitment).map_err(|e| e.to_string())?;
    c.read_exact(&mut prev_link_hash).map_err(|e| e.to_string())?;
    c.read_exact(&mut link_index_bytes).map_err(|e| e.to_string())?;
    c.read_exact(&mut signature_a).map_err(|e| e.to_string())?;
    c.read_exact(&mut signature_b).map_err(|e| e.to_string())?;

    Ok(ChainLink {
        node_a_public,
        node_b_public,
        partial_public_key,
        shard_commitment,
        prev_link_hash,
        link_index: u16::from_le_bytes(link_index_bytes),
        signature_a,
        signature_b,
    })
}

// ---------------------------------------------------------------------------
// EncryptedShard binary serialization
// ---------------------------------------------------------------------------

/// Serialize an EncryptedShard to base64.
fn serialize_encrypted_shard_b64(shard: &EncryptedShard) -> String {
    let mut buf = Vec::new();
    buf.extend_from_slice(&shard.link_index.to_le_bytes());
    // contributor_address as length-prefixed UTF-8
    let addr_bytes = shard.contributor_address.as_bytes();
    buf.extend_from_slice(&(addr_bytes.len() as u16).to_le_bytes());
    buf.extend_from_slice(addr_bytes);
    // encrypted_scalar as length-prefixed blob
    buf.extend_from_slice(&(shard.encrypted_scalar.len() as u16).to_le_bytes());
    buf.extend_from_slice(&shard.encrypted_scalar);
    // commitment (32 bytes)
    buf.extend_from_slice(&shard.commitment);
    // contributor_signature (64 bytes)
    buf.extend_from_slice(&shard.contributor_signature);
    BASE64_STANDARD.encode(&buf)
}

/// Deserialize an EncryptedShard from bytes.
fn deserialize_encrypted_shard(data: &[u8]) -> Result<EncryptedShard, String> {
    use std::io::Read;
    let mut c = Cursor::new(data);

    let mut li = [0u8; 2];
    c.read_exact(&mut li).map_err(|e| e.to_string())?;
    let link_index = u16::from_le_bytes(li);

    let mut addr_len = [0u8; 2];
    c.read_exact(&mut addr_len).map_err(|e| e.to_string())?;
    let addr_len = u16::from_le_bytes(addr_len) as usize;
    let mut addr_bytes = vec![0u8; addr_len];
    c.read_exact(&mut addr_bytes).map_err(|e| e.to_string())?;
    let contributor_address =
        String::from_utf8(addr_bytes).map_err(|e| format!("invalid address UTF-8: {e}"))?;

    let mut enc_len = [0u8; 2];
    c.read_exact(&mut enc_len).map_err(|e| e.to_string())?;
    let enc_len = u16::from_le_bytes(enc_len) as usize;
    let mut encrypted_scalar = vec![0u8; enc_len];
    c.read_exact(&mut encrypted_scalar)
        .map_err(|e| e.to_string())?;

    let mut commitment = [0u8; 32];
    c.read_exact(&mut commitment).map_err(|e| e.to_string())?;

    let mut contributor_signature = [0u8; 64];
    c.read_exact(&mut contributor_signature)
        .map_err(|e| e.to_string())?;

    Ok(EncryptedShard {
        link_index,
        contributor_address,
        encrypted_scalar,
        commitment,
        contributor_signature,
    })
}

// ---------------------------------------------------------------------------
// Hex helpers
// ---------------------------------------------------------------------------

fn decode_hex_32(hex_str: &str, field: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("invalid {field} hex: {e}"))?;
    bytes
        .try_into()
        .map_err(|_| format!("{field}: expected 32 bytes"))
}

fn decode_hex_64(hex_str: &str, field: &str) -> Result<[u8; 64], String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("invalid {field} hex: {e}"))?;
    bytes
        .try_into()
        .map_err(|_| format!("{field}: expected 64 bytes"))
}

#[cfg(test)]
mod tests {
    /// Any slot id: these exercise the handler, not the chain.
    const TEST_SLOT_ID: u32 = 1;

    use super::*;
    use kenter_crypto::shard::derive_shard;

    #[test]
    fn test_chain_link_roundtrip() {
        let kp1 = StellarKeypair::random();
        let kp2 = StellarKeypair::random();
        let event_id = [0x42; 32];
        let shard = derive_shard(&kp1, &kp2.verifying_key(), &event_id).unwrap();
        let link = ChainLink::create(&kp1, &kp2, &shard, [0; 32], 0, &event_id);

        let bytes = serialize_chain_link(&link);
        assert_eq!(bytes.len(), 290);

        let decoded = deserialize_chain_link(&bytes).unwrap();
        assert_eq!(decoded.node_a_public, link.node_a_public);
        assert_eq!(decoded.node_b_public, link.node_b_public);
        assert_eq!(decoded.partial_public_key, link.partial_public_key);
        assert_eq!(decoded.shard_commitment, link.shard_commitment);
        assert_eq!(decoded.prev_link_hash, link.prev_link_hash);
        assert_eq!(decoded.link_index, link.link_index);
        assert_eq!(decoded.signature_a, link.signature_a);
        assert_eq!(decoded.signature_b, link.signature_b);
    }

    /// Build a shard request carrying a VALID holder authorization signature
    /// over a fresh holder key (the verifier only checks the signature covers
    /// the combiner key + fields, which is the anti-MITM property under test).
    fn signed_request(
        link: &ChainLink,
        event_id: &[u8; 32],
        combiner_pub: &[u8; 32],
    ) -> crate::protocol::ShardRequest {
        let holder = StellarKeypair::random();
        let token_hash = [0x11u8; 32];
        let nonce = [0x22u8; 32];
        // Must be within contribute_shard's freshness window vs the handler's wall clock.
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let signable = kenter_crypto::redemption::holder_signable_bytes(
            &token_hash,
            &holder.stellar_address(),
            combiner_pub,
            &nonce,
            ts,
        );
        let sig = holder.sign(&signable).to_bytes();
        build_shard_request(
            link,
            event_id,
            combiner_pub,
            &holder.stellar_address(),
            &token_hash,
            &nonce,
            &sig,
            ts,
        )
    }

    #[test]
    fn test_shard_request_roundtrip() {
        let kp1 = StellarKeypair::random();
        let kp2 = StellarKeypair::random();
        let combiner = StellarKeypair::random();
        let event_id = [0xAA; 32];
        let shard = derive_shard(&kp1, &kp2.verifying_key(), &event_id).unwrap();
        let link = ChainLink::create(&kp1, &kp2, &shard, [0; 32], 0, &event_id);

        // Build a shard request
        let request = signed_request(&link, &event_id, &combiner.raw_public());

        assert_eq!(request.msg_type, "shard_request");
        assert_eq!(request.event_id, hex::encode(event_id));

        // Decode the chain_link back
        let decoded_bytes = BASE64_STANDARD.decode(&request.chain_link).unwrap();
        let decoded_link = deserialize_chain_link(&decoded_bytes).unwrap();
        assert_eq!(decoded_link.node_a_public, link.node_a_public);
    }

    #[test]
    fn test_handle_shard_request_success() {
        let kp1 = StellarKeypair::random();
        let kp2 = StellarKeypair::random();
        let combiner = StellarKeypair::random();
        let event_id = [0xBB; 32];

        let shard = derive_shard(&kp1, &kp2.verifying_key(), &event_id).unwrap();
        let link = ChainLink::create(&kp1, &kp2, &shard, [0; 32], 0, &event_id);

        let request = signed_request(&link, &event_id, &combiner.raw_public());

        let ctx = PairNodeContext {
            own_keypair: kp1,
            rate_limiter: ShardRateLimiter::new(),
        };

        let response = handle_shard_request(&ctx, &request);
        assert_eq!(response.status, "ok");
        assert!(response.encrypted_shard.is_some());

        // Parse the encrypted shard
        let enc_shard = parse_shard_response(&response).unwrap();
        assert_eq!(enc_shard.link_index, 0);
        assert_eq!(enc_shard.commitment, *shard.commitment());
    }

    /// **N3 regression.** A request that is refused must not mark the
    /// link on its way out.
    ///
    /// `check_and_mark` ran before the pair-membership check, so a
    /// caller with no relationship to the pair burned the link anyway
    /// -- and the mark never expired, so the real holder was refused
    /// from then on. Every input needed to reach this handler (the
    /// chain link, the event id, the node keys) is published on the
    /// ledger, and the holder signature proves nothing, so an attacker
    /// pays nothing to do it.
    #[test]
    fn a_refused_request_does_not_burn_the_link() {
        let kp1 = StellarKeypair::random();
        let kp2 = StellarKeypair::random();
        let combiner = StellarKeypair::random();
        let event_id = [0xDD; 32];

        let shard = derive_shard(&kp1, &kp2.verifying_key(), &event_id).unwrap();
        let link = ChainLink::create(&kp1, &kp2, &shard, [0; 32], 0, &event_id);
        let request = signed_request(&link, &event_id, &combiner.raw_public());

        // A node that is in neither half of the pair the link names.
        let ctx = PairNodeContext {
            own_keypair: StellarKeypair::random(),
            rate_limiter: ShardRateLimiter::new(),
        };

        let resp = handle_shard_request(&ctx, &request);
        assert_eq!(resp.status, "not_found", "this node is not in the pair");
        assert_eq!(
            ctx.rate_limiter.tracked(),
            0,
            "a refused request must leave the link available to its holder"
        );
    }

    /// **N3 regression.** A mark does not last forever.
    ///
    /// It is set before the shard is actually produced, so an attempt
    /// that failed after that point -- network, combiner crash,
    /// anything -- left the link marked for the life of the process,
    /// and the holder could never retry through that node. The comment
    /// called the missing expiry a placeholder; it was a brick.
    #[test]
    fn a_mark_expires_so_a_failed_redemption_can_be_retried() {
        use kenter_crypto::redemption::{
            SHARD_REQUEST_MAX_AGE_SECS, SHARD_REQUEST_MAX_FUTURE_SECS,
        };
        let replay_window = Duration::from_secs(
            (SHARD_REQUEST_MAX_AGE_SECS + SHARD_REQUEST_MAX_FUTURE_SECS) as u64,
        );
        assert!(
            SERVED_TTL > replay_window,
            "the mark must outlive any authorization that could still be replayed"
        );
        assert!(
            SERVED_TTL < Duration::from_secs(24 * 3600),
            "and must not be so long that one failed attempt bricks the note"
        );
    }

    /// The served map holds marks, not history: it is bounded by what
    /// was served inside the TTL rather than by everything ever asked.
    #[test]
    fn the_served_map_tracks_only_what_it_marked() {
        let rl = ShardRateLimiter::new();
        for n in 0..500u16 {
            let mut event_id = [0u8; 32];
            event_id[..2].copy_from_slice(&n.to_be_bytes());
            assert!(!rl.check_and_mark(&event_id, 0), "each link is new");
        }
        assert_eq!(rl.tracked(), 500);
        assert!(rl.check_and_mark(&[0u8; 32], 0), "a repeat is still caught");
    }

    #[test]
    fn test_rate_limiting_prevents_duplicate_shard() {
        let kp1 = StellarKeypair::random();
        let kp2 = StellarKeypair::random();
        let combiner = StellarKeypair::random();
        let event_id = [0xCC; 32];

        let shard = derive_shard(&kp1, &kp2.verifying_key(), &event_id).unwrap();
        let link = ChainLink::create(&kp1, &kp2, &shard, [0; 32], 0, &event_id);

        let request = signed_request(&link, &event_id, &combiner.raw_public());

        let ctx = PairNodeContext {
            own_keypair: kp1,
            rate_limiter: ShardRateLimiter::new(),
        };

        // First request succeeds
        let resp1 = handle_shard_request(&ctx, &request);
        assert_eq!(resp1.status, "ok");

        // Second request for same (event_id, link_index) is refused
        let resp2 = handle_shard_request(&ctx, &request);
        assert_eq!(resp2.status, "refused");
    }

    #[test]
    fn test_not_in_pair_returns_not_found() {
        let kp1 = StellarKeypair::random();
        let kp2 = StellarKeypair::random();
        let kp3 = StellarKeypair::random(); // not in the pair
        let combiner = StellarKeypair::random();
        let event_id = [0xDD; 32];

        let shard = derive_shard(&kp1, &kp2.verifying_key(), &event_id).unwrap();
        let link = ChainLink::create(&kp1, &kp2, &shard, [0; 32], 0, &event_id);

        let request = signed_request(&link, &event_id, &combiner.raw_public());

        // kp3 is not part of this pair
        let ctx = PairNodeContext {
            own_keypair: kp3,
            rate_limiter: ShardRateLimiter::new(),
        };

        let response = handle_shard_request(&ctx, &request);
        assert_eq!(response.status, "not_found");
    }

    #[test]
    fn test_handle_shard_request_rejects_combiner_key_swap() {
        // Anti-MITM: the holder signed over `combiner`'s key; a relay swaps in
        // its own key to intercept the shard. The pair node must refuse.
        let kp1 = StellarKeypair::random();
        let kp2 = StellarKeypair::random();
        let combiner = StellarKeypair::random();
        let attacker = StellarKeypair::random();
        let event_id = [0xEE; 32];
        let shard = derive_shard(&kp1, &kp2.verifying_key(), &event_id).unwrap();
        let link = ChainLink::create(&kp1, &kp2, &shard, [0; 32], 0, &event_id);

        let mut request = signed_request(&link, &event_id, &combiner.raw_public());
        // Tamper: substitute the attacker's combiner key (signature no longer covers it).
        request.combiner_public_key = hex::encode(attacker.raw_public());

        let ctx = PairNodeContext {
            own_keypair: kp1,
            rate_limiter: ShardRateLimiter::new(),
        };
        let response = handle_shard_request(&ctx, &request);
        assert_eq!(response.status, "unauthorized");
    }

    #[test]
    fn test_encrypted_shard_serialization_roundtrip() {
        let kp1 = StellarKeypair::random();
        let kp2 = StellarKeypair::random();
        let combiner = StellarKeypair::random();
        let event_id = [0xEE; 32];

        let shard = derive_shard(&kp1, &kp2.verifying_key(), &event_id).unwrap();
        let link = ChainLink::create(&kp1, &kp2, &shard, [0; 32], 0, &event_id);

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let encrypted = contribute_shard(
            &kp1,
            &kp2.verifying_key(),
            &link,
            &combiner.raw_public(),
            &event_id,
            current_time,
            current_time,
        )
        .unwrap();

        // Roundtrip through base64 serialization
        let b64 = serialize_encrypted_shard_b64(&encrypted);
        let bytes = BASE64_STANDARD.decode(&b64).unwrap();
        let decoded = deserialize_encrypted_shard(&bytes).unwrap();

        assert_eq!(decoded.link_index, encrypted.link_index);
        assert_eq!(decoded.contributor_address, encrypted.contributor_address);
        assert_eq!(decoded.encrypted_scalar, encrypted.encrypted_scalar);
        assert_eq!(decoded.commitment, encrypted.commitment);
        assert_eq!(
            decoded.contributor_signature,
            encrypted.contributor_signature
        );
    }

    // -----------------------------------------------------------------------
    // Extend handler tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_extend_request_roundtrip() {
        let kp1 = StellarKeypair::random();
        let kp2 = StellarKeypair::random();

        let (partial, _) = kenter_crypto::token::PartialToken::initiate(
            [0xF0; 32],
            1741737600,
            Some(1_000_000),
            3,
            &kp1,
            &kp2,
            vec![],
        )
        .unwrap();

        // Build extend request
        let request = build_extend_request(&partial, TEST_SLOT_ID).unwrap();
        assert_eq!(request.msg_type, "extend_request");

        // Decode the partial token back
        let decoded_bytes = BASE64_STANDARD.decode(&request.partial_token).unwrap();
        let decoded = deserialize_partial_token(&decoded_bytes).unwrap();
        assert_eq!(decoded.header.event_id, partial.header.event_id);
        assert_eq!(decoded.remaining_pairs, partial.remaining_pairs);
        assert_eq!(decoded.chain.links.len(), partial.chain.links.len());
    }

    #[test]
    fn test_handle_extend_request_success() {
        let kp1 = StellarKeypair::random();
        let kp2 = StellarKeypair::random();
        let kp3 = StellarKeypair::random();
        let kp4 = StellarKeypair::random();

        // Create a 3-pair partial token with 1 link
        let (partial, _) = kenter_crypto::token::PartialToken::initiate(
            [0xF1; 32],
            1741737600,
            None,
            3,
            &kp1,
            &kp2,
            vec![],
        )
        .unwrap();

        // Build the extend request
        let request = build_extend_request(&partial, TEST_SLOT_ID).unwrap();

        // Handle it on the relay node (kp3 + kp4)
        let ctx = ExtendNodeContext {
            own_keypair: kp3,
            partner_keypair: kp4,
        };

        let response = handle_extend_request(&ctx, &request);
        assert_eq!(response.status, "ok");
        assert!(response.partial_token.is_some());

        // Parse the response
        let extended = parse_extend_response(&response).unwrap();
        assert_eq!(extended.chain.links.len(), 2);
        assert_eq!(extended.remaining_pairs, 1);
        extended.verify_chain_integrity().unwrap();
    }

    #[test]
    fn test_handle_extend_chain_integrity_preserved() {
        let kp1 = StellarKeypair::random();
        let kp2 = StellarKeypair::random();
        let kp3 = StellarKeypair::random();
        let kp4 = StellarKeypair::random();
        let kp5 = StellarKeypair::random();
        let kp6 = StellarKeypair::random();

        // Create 4-pair chain, extend twice through handlers
        let (partial, _) = kenter_crypto::token::PartialToken::initiate(
            [0xF2; 32],
            1741737600,
            Some(5_000_000),
            4,
            &kp1,
            &kp2,
            vec![],
        )
        .unwrap();

        // First extension
        let req1 = build_extend_request(&partial, TEST_SLOT_ID).unwrap();
        let ctx1 = ExtendNodeContext {
            own_keypair: kp3,
            partner_keypair: kp4,
        };
        let resp1 = handle_extend_request(&ctx1, &req1);
        let extended1 = parse_extend_response(&resp1).unwrap();
        assert_eq!(extended1.chain.links.len(), 2);

        // Second extension
        let req2 = build_extend_request(&extended1, TEST_SLOT_ID).unwrap();
        let ctx2 = ExtendNodeContext {
            own_keypair: kp5,
            partner_keypair: kp6,
        };
        let resp2 = handle_extend_request(&ctx2, &req2);
        let extended2 = parse_extend_response(&resp2).unwrap();
        assert_eq!(extended2.chain.links.len(), 3);
        assert_eq!(extended2.remaining_pairs, 1); // one left for assembly

        // Verify full chain integrity through serialization roundtrip
        extended2.verify_chain_integrity().unwrap();

        // Hash chain should be correct
        let event_id = extended2.header.event_id;
        let h0 = extended2.chain.links[0].link_hash(&event_id);
        let h1 = extended2.chain.links[1].link_hash(&event_id);
        assert_eq!(extended2.chain.links[1].prev_link_hash, h0);
        assert_eq!(extended2.chain.links[2].prev_link_hash, h1);
    }

    #[test]
    fn test_extend_rejects_complete_chain() {
        let kp1 = StellarKeypair::random();
        let kp2 = StellarKeypair::random();
        let kp3 = StellarKeypair::random();
        let kp4 = StellarKeypair::random();

        // 2-pair chain: after initiation, only 1 remaining (for assembly, not extend)
        let (mut partial, _) = kenter_crypto::token::PartialToken::initiate(
            [0xF3; 32],
            1741737600,
            None,
            2,
            &kp1,
            &kp2,
            vec![],
        )
        .unwrap();

        // Extend once — now remaining_pairs = 0
        partial.extend(&kp3, &kp4).unwrap();

        let request = build_extend_request(&partial, TEST_SLOT_ID).unwrap();
        let ctx = ExtendNodeContext {
            own_keypair: StellarKeypair::random(),
            partner_keypair: StellarKeypair::random(),
        };

        let response = handle_extend_request(&ctx, &request);
        assert_eq!(response.status, "error");
        assert!(response.error.as_ref().unwrap().contains("no remaining pairs"));
    }

    #[test]
    fn test_full_print_then_assemble_via_handlers() {
        use kenter_crypto::token::assemble_bearer_token;

        let kp1 = StellarKeypair::random();
        let kp2 = StellarKeypair::random();
        let kp3 = StellarKeypair::random();
        let kp4 = StellarKeypair::random();
        let requestor = StellarKeypair::random();
        let kp5 = StellarKeypair::random();

        // 3-pair chain: initiate → extend via handler → assemble
        let (partial, _) = kenter_crypto::token::PartialToken::initiate(
            [0xF4; 32],
            1741737600,
            Some(10_000_000),
            3,
            &kp1,
            &kp2,
            vec![],
        )
        .unwrap();

        // Extend via handler (simulates network relay)
        let req = build_extend_request(&partial, TEST_SLOT_ID).unwrap();
        let ctx = ExtendNodeContext {
            own_keypair: kp3,
            partner_keypair: kp4,
        };
        let resp = handle_extend_request(&ctx, &req);
        let extended = parse_extend_response(&resp).unwrap();

        // Assemble the final token (requestor + kp5)
        let token = assemble_bearer_token(&extended, &requestor, &kp5, 7, Some(1741824000)).unwrap();

        assert_eq!(token.chain.links.len(), 3);
        token.verify_chain_integrity().unwrap();

        // Ephemeral address should be valid
        let addr = token.ephemeral_address();
        assert!(addr.starts_with('G'));
    }
}
