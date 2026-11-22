//! Owner-key authorizations (`docs/architecture/spend-mode.md`, "What the
//! owner signs").
//!
//! These need a [`DerivingVault`] and nothing else — no chain, no store — so
//! they are free functions rather than methods. [`TokenWallet`] delegates to
//! them, and a caller holding only a vault (the CLI, signing a redemption) uses
//! them directly instead of standing up a wallet it does not need.
//!
//! Keeping one implementation matters more than where it lives: the digest rule
//! and the "does this index actually own the token" check are the difference
//! between a signature the mint accepts and an on-chain revert.
//!
//! [`TokenWallet`]: crate::TokenWallet

use kenter_crypto::spend::{
    owner_commitment, redeem_owner_digest, spend_auth_digest, RedeemOwnerProof,
    SpendAuthorization,
};
use kenter_vault::DerivingVault;

use crate::error::{Result, WalletError};

/// Map a vault failure, keeping "wrong passphrase or PIN" distinguishable.
///
/// It is the only vault error a caller should answer by asking the holder
/// again, so it must be a variant and not a string a shell has to recognise.
fn vault_err(e: kenter_vault::VaultError) -> WalletError {
    match e {
        kenter_vault::VaultError::BadCredential => WalletError::BadCredential,
        other => WalletError::Vault(other.to_string()),
    }
}

/// The owner commitment for a derivation index — what a payer spends to.
pub fn commitment_for<V: DerivingVault>(
    vault: &mut V,
    index: u32,
    credential: &[u8],
) -> Result<[u8; 32]> {
    let pubkey = vault
        .derive_public(index, credential)
        .map_err(vault_err)?;
    Ok(owner_commitment(&pubkey))
}

/// Derive the owner key at `index` and confirm it opens `live`, so a wrong index
/// fails here rather than as an on-chain revert.
fn owning_pubkey<V: DerivingVault>(
    vault: &mut V,
    index: u32,
    live: &[u8; 32],
    credential: &[u8],
) -> Result<[u8; 32]> {
    let pubkey = vault
        .derive_public(index, credential)
        .map_err(vault_err)?;
    if &owner_commitment(&pubkey) != live {
        return Err(WalletError::Vault(format!(
            "owner index {index} does not open the live commitment"
        )));
    }
    Ok(pubkey)
}

/// Owner proof for redeeming a spend-mode token.
///
/// Signs the 32-byte digest, never the raw message, so software- and
/// card-produced signatures are interchangeable.
///
/// `contract_xdr` and `spend_nonce` must describe the mint and the record the
/// proof will be presented to. They are parameters rather than something read
/// here because this function is deliberately chainless — [`TokenWallet`]
/// reads them fresh and passes them in.
///
/// [`TokenWallet`]: crate::TokenWallet
pub fn authorize_redeem<V: DerivingVault>(
    vault: &mut V,
    index: u32,
    contract_xdr: &[u8],
    slot_id: u32,
    ephemeral_key: &[u8; 32],
    live_owner_commitment: &[u8; 32],
    spend_nonce: u32,
    recipient_xdr: &[u8],
    credential: &[u8],
) -> Result<RedeemOwnerProof> {
    let owner_pubkey = owning_pubkey(vault, index, live_owner_commitment, credential)?;
    let digest = redeem_owner_digest(
        contract_xdr,
        slot_id,
        ephemeral_key,
        live_owner_commitment,
        spend_nonce,
        recipient_xdr,
    );
    let signature = vault
        .sign_derived(index, &digest, credential)
        .map_err(vault_err)?;
    Ok(RedeemOwnerProof { owner_pubkey, signature })
}

/// Authorization to transfer a spend-mode token to `new_owner_commitment`.
pub fn authorize_spend<V: DerivingVault>(
    vault: &mut V,
    index: u32,
    contract_xdr: &[u8],
    slot_id: u32,
    ephemeral_key: &[u8; 32],
    live_owner_commitment: &[u8; 32],
    new_owner_commitment: &[u8; 32],
    spend_nonce: u32,
    credential: &[u8],
) -> Result<SpendAuthorization> {
    let current_owner_pubkey =
        owning_pubkey(vault, index, live_owner_commitment, credential)?;
    let digest = spend_auth_digest(
        contract_xdr,
        slot_id,
        ephemeral_key,
        live_owner_commitment,
        new_owner_commitment,
        spend_nonce,
    );
    let signature = vault
        .sign_derived(index, &digest, credential)
        .map_err(vault_err)?;
    Ok(SpendAuthorization {
        current_owner_pubkey,
        new_owner_commitment: *new_owner_commitment,
        signature,
    })
}
