//! Redeeming a note.
//!
//! The holder presents the chain data from the
//! container they already hold, the contract checks it against the
//! `chain_hash` committed at registration, and pays
//! `amount − node_fee × 2 × pairs` from escrow. Node-free: no shard
//! secrets, no network of daemons.
//!
//! Not secret-free. Presenting the chain *publishes* it, and a transaction
//! that fails on-chain publishes it while leaving the note live -- so the
//! chain alone would be enough for whoever read that failure. Pure-bearer
//! redemption also signs the recipient with the
//! note's claim key, whose secret half stays in the container and never
//! reaches the ledger.
//!
//! Spend-mode notes need the owner's proof on top, which is why this takes a
//! credential: the owner key is derived, never stored.
//!
//! The escrow goes wherever the holder names — not necessarily to them
//! Paying someone who does not run a Kenter client is
//! one transaction rather than redeem-then-send, with no moment where the
//! note is destroyed and the payment has not landed.
//!
//! **Irreversible, with nothing to appeal to.** The note is destroyed against
//! an immutable adminless mint. There is no cancel and no clawback, which is
//! why the authorization prompt for it carries the amount, the token and the
//! destination account — the last because paying out to the wrong account of
//! your own is the mistake available here.

use kenter_client::MintClient;
use kenter_crypto::chain_data::serialize_token_chain_data;
use kenter_crypto::container::deserialize_bearer_token;
use kenter_wallet::{HeldToken, Store};

use crate::GuiWallet;

/// What redeeming a note will do, before it is done.
#[derive(Debug, Clone)]
pub struct Quote {
    pub id: String,
    pub short_id: String,
    pub face: u64,
    /// Face minus this note's own fees — what actually arrives.
    pub payout: u64,
    pub fee: u64,
    pub spend_mode: bool,
    /// Where the escrow will be paid.
    pub to_account: String,
    /// The holder's own account — what `to_account` started as.
    ///
    /// Kept so the screen can tell "paying myself" from "paying someone
    /// else" without asking the vault again, and so the holder can get back
    /// to the default after typing over it.
    pub own_account: String,
}

/// Work out what a note redeems for, from the note itself.
///
/// The pair count comes from the container rather than being assumed: the fee
/// is `node_fee × 2 × (pairs − 2)` (`deposit::fees_for`), so two notes of identical face are worth
/// different amounts if they were printed differently, and quoting the face
/// would be quoting a number nobody receives.
pub fn quote(held: &HeldToken, node_fee: u64, to_account: &str) -> Result<Quote, String> {
    let token = deserialize_bearer_token(&held.blob).map_err(|e| format!("container: {e}"))?;
    let fee = crate::deposit::fees_for(token.chain.total_pairs, node_fee);
    let payout = held
        .amount
        .checked_sub(fee)
        .ok_or_else(|| "this note's fees exceed its face value".to_string())?;
    Ok(Quote {
        short_id: crate::wallet::short(&held.id),
        id: held.id.clone(),
        face: held.amount,
        payout,
        fee,
        spend_mode: held.owner_index.is_some(),
        to_account: to_account.to_string(),
        own_account: to_account.to_string(),
    })
}

/// Burn the note and take the escrow.
///
/// Returns what the contract actually paid, which is the figure to show —
/// not the quote, which was this client's arithmetic.
pub async fn redeem(
    wallet: &mut GuiWallet,
    mint: &mut MintClient,
    held: &HeldToken,
    recipient: &str,
    credential: &[u8],
) -> Result<i128, String> {
    // The mint pays whoever is named here, which is why the owner's proof
    // below has to bind it: a signature that did not would authorise
    // "redeem this note" and let anyone holding it choose the destination.
    let recipient_xdr = kenter_client::tx::address_xdr(recipient)
        .map_err(|e| format!("recipient {recipient}: {e}"))?;
    let token = deserialize_bearer_token(&held.blob).map_err(|e| format!("container: {e}"))?;
    let chain_data = serialize_token_chain_data(&token).map_err(|e| format!("chain data: {e}"))?;
    let ek = held.ephemeral_public_key;

    let paid = match held.owner_index {
        None => {
            // Pure bearer: the chain alone is not the proof. Sign
            // the recipient with the note's claim key, so a transaction
            // carrying this chain -- including one that fails and leaves
            // the note live -- is useless to anyone who reads it.
            let claim_sig = token.sign_claim(
                &kenter_client::tx::address_xdr(mint.contract_id())
                    .map_err(|e| format!("contract: {e}"))?,
                &recipient_xdr,
            );
            mint.redeem_by_chain(recipient, held.slot_id, chain_data, claim_sig)
                .await
                .map_err(|e| format!("redeem: {e}"))?
        }
        Some(index) => {
            // Derived when it was not recorded — see the note in
            // `pay::repoint`. Without this a spend-mode note the holder
            // minted themselves could be neither paid nor redeemed: the
            // escrow would be real, held, and unreachable.
            let live = match held.owner_commitment {
                Some(c) => c,
                None => wallet
                    .owner_commitment_for(index, credential)
                    .map_err(|e| format!("deriving the owner commitment: {e}"))?,
            };
            let proof = wallet
                .authorize_redeem(index, held.slot_id, &ek, &live, &recipient_xdr, credential)
                .await
                .map_err(|e| e.to_string())?;
            mint.redeem_by_chain_owned(
                recipient,
                held.slot_id,
                chain_data,
                proof.owner_pubkey,
                proof.signature,
            )
            .await
            .map_err(|e| format!("redeem: {e}"))?
        }
    };

    // The ledger says redeemed now; recording it locally means the billfold
    // is right immediately rather than at the next sweep.
    let _ = wallet.mark_spent(&held.id, true).await;
    Ok(paid)
}

/// Notes that can still be redeemed.
pub async fn redeemable(wallet: &GuiWallet) -> Result<Vec<HeldToken>, String> {
    Ok(wallet
        .store()
        .all()
        .await
        .map_err(|e| e.to_string())?
        .into_iter()
        .filter(|t| !t.spent_away && !t.marked_spent)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two notes of equal face are worth different amounts if they were
    /// printed with different pair counts. Quoting face would quote a number
    /// nobody receives.
    #[test]
    fn the_quote_follows_the_pair_count() {
        // 3 pairs at 100 stroops a node: 600 in fees.
        let container = crate::deposit::tests_support::token_bytes(25_000_000, 3);
        let held = HeldToken {
                       slot_id: 1,
            id: "GTEST".into(),
            ephemeral_public_key: [1; 32],
            event_id: [0; 32],
            amount: 25_000_000,
            blob: container,
            imported_at: 0,
            mint: None,
            label: None,
            owner_index: None,
            owner_commitment: None,
            spent_away: false,
            exports: Default::default(),
            marked_spent: false,
        };
        let q = quote(&held, 100, "GDEST").unwrap();
        // One interior pair, two participants: the mint's own arithmetic.
        assert_eq!(q.fee, 200);
        assert_eq!(q.payout, 24_999_800);
        assert!(!q.spend_mode);
    }

    #[test]
    fn a_note_worth_less_than_its_fees_is_refused_rather_than_underflowing() {
        let container = crate::deposit::tests_support::token_bytes(100, 3);
        let held = HeldToken {
                       slot_id: 1,
            id: "GTEST".into(),
            ephemeral_public_key: [1; 32],
            event_id: [0; 32],
            amount: 100,
            blob: container,
            imported_at: 0,
            mint: None,
            label: None,
            owner_index: None,
            owner_commitment: None,
            spent_away: false,
            exports: Default::default(),
            marked_spent: false,
        };
        assert!(quote(&held, 100, "GDEST").is_err());
    }

    /// A fresh quote pays the holder, and says so in a way the screen can
    /// check. `own_account` is what lets the confirmation tell "paying
    /// myself" from "paying someone else" without asking the vault again --
    /// and getting that backwards would put the reassuring label on the
    /// payout that leaves the wallet.
    #[test]
    fn a_fresh_quote_pays_the_holder_and_records_that_it_does() {
        let container = crate::deposit::tests_support::token_bytes(25_000_000, 3);
        let held = HeldToken {
                       slot_id: 1,
            id: "GTEST".into(),
            ephemeral_public_key: [1; 32],
            event_id: [0; 32],
            amount: 25_000_000,
            blob: container,
            imported_at: 0,
            mint: None,
            label: None,
            owner_index: None,
            owner_commitment: None,
            spent_away: false,
            exports: Default::default(),
            marked_spent: false,
        };
        let q = quote(&held, 100, "GMINE").expect("quotable");
        assert_eq!(q.to_account, "GMINE");
        assert_eq!(
            q.own_account, "GMINE",
            "the default destination is the holder"
        );

        let mine = crate::RedeemQuote {
            id: q.id.clone(),
            short_id: q.short_id.clone(),
            face: String::new(),
            payout: String::new(),
            fee: String::new(),
            spend_mode: false,
            to_account: "GMINE".into(),
            own_account: "GMINE".into(),
        };
        assert!(!mine.elsewhere(), "paying yourself is not paying elsewhere");

        let theirs = crate::RedeemQuote {
            to_account: "GTHEM".into(),
            ..mine
        };
        assert!(
            theirs.elsewhere(),
            "a changed destination has to read as one"
        );
    }
}
