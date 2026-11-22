//! `kenter_wallet::ChainRead` adapter over [`MintClient`] (feature `wallet`).
//!
//! Lives here (not in a shell) because orphan rules bar a shell from implementing
//! a foreign trait (`ChainRead`) for a foreign type (`MintClient`). Both desktop
//! shells (CLI + GUI) reuse this one adapter by enabling `kenter-client/wallet`.
//!
//! Backed by [`MintClient::token_or_marker`], a `&self` read, so no interior
//! mutability is needed. It reads the token record and the redemption marker
//! together, because redemption removes the record and leaving the marker
//! unread reports a note that was paid out as one that never existed.

use kenter_wallet::models::{OnChainToken, TokenStatus};
use kenter_wallet::ports::ChainRead;
use kenter_wallet::{Result as WalletResult, WalletError};

use crate::mint::{SlotRecord, TokenMode, TokenState};
use crate::MintClient;

/// Wraps a [`MintClient`] and exposes it as a [`ChainRead`] for the wallet core.
pub struct WalletChain {
    mint: MintClient,
}

impl WalletChain {
    pub fn new(mint: MintClient) -> Self {
        WalletChain { mint }
    }

    pub fn mint(&self) -> &MintClient {
        &self.mint
    }

    pub fn into_inner(self) -> MintClient {
        self.mint
    }
}

impl ChainRead for WalletChain {
    async fn token_status(&self, slot_id: u32) -> WalletResult<OnChainToken> {
        let record = self
            .mint
            .token_or_marker(slot_id)
            .await
            .map_err(|e| WalletError::Chain(e.to_string()))?;

        let info = match record {
            SlotRecord::Token(t) => Some(*t),
            // Redemption removes the record, so this is the only way the
            // wallet learns a note was paid out. Reading only `Token`
            // reports it as a slot that never existed, and a note that
            // never existed is `unverified`, which the headline balance
            // counts as still held -- so a redeemed note would stay in
            // the total.
            SlotRecord::Redeemed(_) => {
                return Ok(OnChainToken {
                    status: TokenStatus::Redeemed,
                    amount: None,
                    chain_hash: None,
                    owner_commitment: None,
                    spend_nonce: None,
                    claim_pubkey: None,
                    ephemeral_key: None,
                    event_id: None,
                    participants_len: None,
                })
            }
            // A record exists but is not in the live state. Not spendable
            // on what we can see, and emphatically not "never existed".
            SlotRecord::Archived => {
                return Ok(OnChainToken {
                    status: TokenStatus::Unknown,
                    amount: None,
                    chain_hash: None,
                    owner_commitment: None,
                    spend_nonce: None,
                    claim_pubkey: None,
                    ephemeral_key: None,
                    event_id: None,
                    participants_len: None,
                })
            }
            SlotRecord::NotFound => None,
        };

        Ok(match info {
            None => OnChainToken {
                status: TokenStatus::NotFound,
                amount: None,
                chain_hash: None,
                owner_commitment: None,
                spend_nonce: None,
                claim_pubkey: None,
                ephemeral_key: None,
                event_id: None,
                participants_len: None,
            },
            Some(t) => {
                let status = match t.state {
                    TokenState::Active => TokenStatus::Active,
                    TokenState::Redeemed => TokenStatus::Redeemed,
                    // Printing / Cancelled / Unknown → not spendable, not cleanly redeemed.
                    _ => TokenStatus::Unknown,
                };
                // Only meaningful in spend mode; pure-bearer records carry a
                // sentinel the wallet should not mistake for an owner.
                let owner_commitment = match t.mode {
                    TokenMode::Spend => Some(t.owner_commitment),
                    TokenMode::PureBearer => None,
                };
                OnChainToken {
                    status,
                    amount: Some(t.amount),
                    chain_hash: Some(t.chain_hash),
                    event_id: Some(t.event_id),
                    participants_len: Some(t.participants_len),
                    owner_commitment,
                    spend_nonce: Some(t.spend_nonce),
                    claim_pubkey: Some(t.claim_pubkey),
                    ephemeral_key: Some(t.ephemeral_key),
                }
            }
        })
    }

    fn ledger_source(&self) -> String {
        self.mint.tx().rpc().host_only()
    }

    fn mint_contract_xdr(&self) -> Vec<u8> {
        // `MintClient` only ever holds a contract id it parsed, so this
        // cannot fail in practice; an empty vec would still be caught by the
        // mint rejecting the signature rather than by silently signing the
        // wrong digest.
        crate::tx::address_xdr(self.mint.contract_id()).unwrap_or_default()
    }

    fn mint_id(&self) -> String {
        self.mint.contract_id().to_string()
    }
}
