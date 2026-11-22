//! Kenter wire protocol message types.
//!
//! These travel as JSON bodies inside tunnel HTTP request/response wrappers.

use serde::{Deserialize, Serialize};

/// Shard request from combiner to pair node.
///
/// Carries the holder's redemption authorization so the pair node can verify the
/// `combiner_public_key` it is about to encrypt to was actually signed by the
/// holder (anti-MITM — see `kenter_crypto::redemption::verify_holder_signature`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardRequest {
    #[serde(rename = "type")]
    pub msg_type: String,
    /// Base64-encoded ChainLink (290 bytes).
    pub chain_link: String,
    /// Hex-encoded event_id (32 bytes).
    pub event_id: String,
    /// Hex-encoded combiner Ed25519 public key (32 bytes).
    pub combiner_public_key: String,
    /// Stellar address (G…) of the holder who signed the authorization.
    pub holder_address: String,
    /// Hex-encoded SHA-256 of the token container (32 bytes) — binds the auth to one token.
    pub token_hash: String,
    /// Hex-encoded replay nonce (32 bytes).
    pub nonce: String,
    /// Hex-encoded holder signature from RedemptionRequest (64 bytes).
    pub signature: String,
    /// Unix timestamp the holder signed over.
    pub timestamp: i64,
}

/// Shard response from pair node to combiner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardResponse {
    #[serde(rename = "type")]
    pub msg_type: String,
    /// "ok", "commitment_mismatch", "refused", "not_found", "stale_request"
    pub status: String,
    /// Base64-encoded EncryptedShard (present when status == "ok").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_shard: Option<String>,
    /// Error message (present when status != "ok").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Extend request: relay a partial token for chain extension.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtendRequest {
    #[serde(rename = "type")]
    pub msg_type: String,
    /// Base64-encoded serialized PartialToken.
    pub partial_token: String,
    /// The on-chain print slot this chain belongs to.
    ///
    /// Required because the mint lets only a member of the assigned pair call
    /// `confirm_link`, so a node must know *which* slot it is extending to
    /// record its link. Without it a node can extend a chain but never confirm
    /// it, and the depositor has to play every node role to complete a print.
    pub slot_id: u32,
}

/// Extend response: return the extended partial token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtendResponse {
    #[serde(rename = "type")]
    pub msg_type: String,
    /// "ok" or error status.
    pub status: String,
    /// Base64-encoded extended PartialToken (present when status == "ok").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partial_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Health check response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    /// This node's Stellar address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_address: Option<String>,
    /// Its pair partner's address.
    ///
    /// A depositor must name **both** members of every pair in `request_print`,
    /// but a node is only reachable by its own address — the partner is not
    /// discoverable anywhere else, so without this a print driver cannot build
    /// the pair list for nodes it did not create.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub partner_address: Option<String>,
}

impl ShardResponse {
    pub fn ok(encrypted_shard: String) -> Self {
        Self {
            msg_type: "shard_response".into(),
            status: "ok".into(),
            encrypted_shard: Some(encrypted_shard),
            error: None,
        }
    }

    pub fn error(status: &str, message: &str) -> Self {
        Self {
            msg_type: "shard_response".into(),
            status: status.into(),
            encrypted_shard: None,
            error: Some(message.into()),
        }
    }
}

impl ExtendResponse {
    pub fn ok(partial_token: String) -> Self {
        Self {
            msg_type: "extend_response".into(),
            status: "ok".into(),
            partial_token: Some(partial_token),
            error: None,
        }
    }

    pub fn error(message: &str) -> Self {
        Self {
            msg_type: "extend_response".into(),
            status: "error".into(),
            partial_token: None,
            error: Some(message.into()),
        }
    }
}
