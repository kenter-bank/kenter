use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("invalid Stellar secret key: {0}")]
    InvalidStellarSecret(String),

    #[error("invalid Stellar address: {0}")]
    InvalidStellarAddress(String),

    #[error("invalid key length: expected {expected}, got {got}")]
    InvalidKeyLength { expected: usize, got: usize },

    #[error("ECDH key exchange failed: {0}")]
    EcdhFailed(String),

    #[error("encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("signature verification failed")]
    SignatureVerificationFailed,

    #[error("invalid token format: {0}")]
    InvalidTokenFormat(String),

    #[error("hash mismatch: data integrity compromised")]
    HashMismatch,

    #[error("caveat verification failed: {0}")]
    CaveatFailed(String),

    #[error("token expired")]
    TokenExpired,

    #[error("invalid KNTR file: {0}")]
    InvalidKntrFile(String),

    #[error("file too large: {size} bytes (max {max})")]
    FileTooLarge { size: u64, max: u64 },

    #[error("base64 decode error: {0}")]
    Base64Error(String),

    #[error("shard derivation failed: {0}")]
    ShardDerivationFailed(String),

    #[error("composition failed: {0}")]
    CompositionFailed(String),

    #[error("invalid token: {0}")]
    InvalidToken(String),

    #[error("chain verification failed: {0}")]
    ChainVerificationFailed(String),

    #[error("shard commitment mismatch")]
    ShardCommitmentMismatch,

    #[error("owner commitment does not open to the given key (spend mode)")]
    OwnerCommitmentMismatch,

    #[error("chain link signature invalid at index {index}")]
    ChainLinkSignatureInvalid { index: u16 },

    #[error("chain link hash mismatch at index {index}")]
    ChainLinkHashMismatch { index: u16 },

    #[error("redemption failed: {0}")]
    RedemptionFailed(String),

    #[error("redemption incomplete: received {received} of {total} shards")]
    RedemptionIncomplete { received: usize, total: usize },

    #[error("duplicate shard at index {index}")]
    DuplicateShard { index: u16 },

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, CryptoError>;
