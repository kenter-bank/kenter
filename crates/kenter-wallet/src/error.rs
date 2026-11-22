//! Wallet-core error type.

use std::fmt;

use thiserror::Error;

/// Which receive gate rejected a token (`docs/architecture/spend-mode.md`,
/// "The receive gates").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gate {
    /// G1 — offline structural verification of the container.
    Structure,
    /// G2 — the ledger's record: existence, state, amount.
    Ledger,
    /// G3 — the live owner commitment is ours.
    Ownership,
}

impl fmt::Display for Gate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Gate::Structure => "G1 (structure)",
            Gate::Ledger => "G2 (ledger)",
            Gate::Ownership => "G3 (ownership)",
        })
    }
}

/// Errors from the wallet core. Port implementations map their own failures
/// (I/O, network, RPC) into [`WalletError::Store`] / [`WalletError::Chain`].
#[derive(Debug, Error)]
pub enum WalletError {
    /// A token failed offline cryptographic verification on import.
    #[error("token failed verification: {0}")]
    InvalidToken(String),

    /// The token could not be (de)serialized via the container codec.
    #[error("token codec error: {0}")]
    Codec(String),

    /// A `Store` implementation failed.
    #[error("store error: {0}")]
    Store(String),

    /// A `ChainRead` implementation failed.
    #[error("chain error: {0}")]
    Chain(String),

    /// A token with this id already exists in the store.
    #[error("token already held: {0}")]
    Duplicate(String),

    /// No held token with this id.
    #[error("token not held: {0}")]
    NotHeld(String),

    /// A mandatory receive gate (G1–G4, see [`Gate`]) did not pass. The
    /// payee is **not** paid; nothing may be released.
    ///
    /// `retryable` says whether waiting could change the answer — the payer's
    /// spend may simply not have landed yet. A caller that polls must branch on
    /// this field and not on the message text: a reworded string would silently
    /// turn a permanent failure into an endless wait, or abandon a payment that
    /// was about to settle.
    #[error("receive gate {gate} failed: {detail}")]
    ReceiveGate {
        gate: Gate,
        detail: String,
        retryable: bool,
    },

    /// A custody backend failed (derive/sign).
    #[error("vault error: {0}")]
    Vault(String),

    /// The credential was wrong — a mistyped passphrase, a wrong PIN.
    ///
    /// Its own variant because this is the one vault failure where asking the
    /// holder again is the right move; every other is a condition a retry will
    /// not change. Telling them apart must not require matching on message
    /// text, which works until someone rewords it and then quietly turns a
    /// re-prompt into an error dialog.
    #[error("wrong passphrase or PIN")]
    BadCredential,

    /// Export or restore of a token backup failed.
    #[error("backup error: {0}")]
    Backup(String),

    /// The holder refused, or dismissed the prompt.
    ///
    /// A decision, not a fault: callers must stop cleanly and must not retry.
    /// Distinct from [`WalletError::PromptFailed`] so a shell can tell "they
    /// said no" from "we could not ask", which are opposite situations — the
    /// first needs no message at all, the second is a bug worth surfacing.
    #[error("authorization declined")]
    Declined,

    /// No authorization could be obtained: no prompt is wired up, the shell is
    /// shutting down, the card reader is gone.
    #[error("cannot authorize: {0}")]
    PromptFailed(String),
}

/// Convenience alias for wallet-core results.
pub type Result<T> = std::result::Result<T, WalletError>;
