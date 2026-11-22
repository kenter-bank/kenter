use std::time::Duration;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("RPC request failed: {0}")]
    RpcTransport(#[from] reqwest::Error),

    #[error("RPC error: {code} — {message}")]
    RpcError { code: i64, message: String },

    #[error("simulation failed: {0}")]
    SimulationFailed(String),

    #[error("transaction failed: {status} — {detail}")]
    TransactionFailed { status: String, detail: String },

    #[error("transaction timeout after {0:?}")]
    TransactionTimeout(Duration),

    #[error("XDR encode error: {0}")]
    XdrEncode(String),

    #[error("XDR decode error: {0}")]
    XdrDecode(String),

    #[error("contract error code {0}")]
    ContractError(u32),

    #[error("invalid address: {0}")]
    InvalidAddress(String),

    #[error("missing return value")]
    MissingReturnValue,

    /// The RPC answered with a ledger entry that is not the one we asked
    /// for.
    ///
    /// Every direct ledger read took `entries[0]` on faith, so an RPC could
    /// answer a question about one note with another note's record -- or
    /// another contract's. The payee gates are self-certifying only if the
    /// thing they certify is the thing that was asked about.
    #[error("the RPC returned the wrong ledger entry: {0}")]
    WrongLedgerEntry(String),

    /// A declared resource fee above what the caller is willing to sign.
    #[error("the RPC asked for a resource fee of {asked} stroops, above the {cap} limit")]
    FeeTooHigh { asked: u64, cap: u64 },

    /// A plaintext RPC endpoint that is not loopback.
    #[error("refusing to speak to {0} over plain HTTP; use https, or a loopback address for local development")]
    InsecureRpcUrl(String),

    #[error("{0}")]
    Other(String),
}
