/// Domain separation tags for cryptographic independence.
///
/// These constants prefix all key derivations, ensuring that keys derived
/// for different purposes are cryptographically independent. This prevents
/// cross-protocol attacks where a key valid in one context could be
/// misused in another.
///
/// Every tag is part of the protocol: changing one changes every signature,
/// commitment and key derived under it.
pub struct DomainSeparation;

impl DomainSeparation {
    pub const VERSION: &[u8] = b"kntr_v1";

    // Token domains
    pub const TOKEN_SIGNING: &[u8] = b"kntr_v1:token:sign";
    pub const TOKEN_SECRET: &[u8] = b"kntr_v1:token:secret";

    // Encryption domains
    pub const HYBRID_ENCRYPT: &[u8] = b"kntr_v1:hybrid:encrypt";
    pub const ASYMMETRIC_ENCRYPT: &[u8] = b"kntr_v1:asymmetric:encrypt";

    // Data token domains
    pub const DATA_FILE: &[u8] = b"kntr_v1:data:file";

    // JWT domains (not ported, included for completeness)
    pub const JWT_SIGNING: &[u8] = b"kntr_v1:jwt:sign";

    // Bearer token domains
    pub const BEARER_TOKEN: &[u8] = b"kntr_v1:bearer:token";
    pub const SHARD_DERIVE: &[u8] = b"kntr_v1:shard:derive";
    pub const TOKEN_COMPOSE: &[u8] = b"kntr_v1:token:compose";

    // Chain link domains
    pub const CHAIN_LINK: &[u8] = b"kntr_v1:chain:link";

    // Redemption domains
    pub const REDEMPTION_REQUEST: &[u8] = b"kntr_v1:redemption:request";

    /// Path B claim proof. MUST byte-match `CLAIM_TAG` in the mint
    /// contract, or signatures made here will not verify there.
    pub const REDEEM_CLAIM: &[u8] = b"kntr_v1:redeem:claim";
    pub const SHARD_TRANSPORT: &[u8] = b"kntr_v1:shard:transport";

    // Spend-mode (nullification) domains — see docs/architecture/spend-mode.md.
    /// Commits an owner's Ed25519 public key: commitment = SHA-256(tag || pubkey).
    pub const SPEND_OWNER_COMMIT: &[u8] = b"kntr_v1:spend:owner";
    /// The message a current owner signs to authorize a spend (transfer).
    pub const SPEND_AUTH: &[u8] = b"kntr_v1:spend:auth";
    /// The message a current owner signs to authorize redemption (spend-mode tokens).
    pub const SPEND_REDEEM: &[u8] = b"kntr_v1:spend:redeem";
}
