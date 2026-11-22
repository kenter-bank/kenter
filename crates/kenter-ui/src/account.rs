//! The Stellar account — the other kind of money this client holds.
//!
//! # Why this is a separate place
//!
//! Two kinds of value pass through this client, and until now only one of
//! them had a surface.
//!
//! **Notes** live in the billfold. Each is a distinct bearer instrument with
//! its own pair count, its own fee and its own redemption value. Their sum
//! is not a balance and must not be shown as one.
//!
//! **The account** is an ordinary Stellar account holding ordinary,
//! fungible, divisible balances: XLM for fees and the reserve, and whatever
//! the mint escrows — USDC — for depositing. Every crossing in the system
//! goes between the two. A deposit takes the asset out of the account and
//! gives back a note. A redemption destroys a note and pays the asset back in.
//!
//! Folding the second into the first would produce exactly the "sum you can
//! spend" that must never be shown. Leaving it out altogether would be
//! worse: a holder who funded nothing would be offered a deposit form that
//! quoted fees and totals as though it could be paid, and find out at
//! `request_print` that they held no USDC. The form would have every number
//! except the one that mattered.
//!
//! So: a separate place, named for what it is, showing the balances, the
//! address to send to, and what each one is *for*.
//!
//! # Not a payments screen
//!
//! There is deliberately no "send" here yet. The account exists to be
//! funded, to be deposited from, and to receive payouts; sending value out
//! of it without making a note is a different feature, and an
//! unlabelled send button next to a bearer-note wallet is the kind of thing
//! that moves someone's money to the wrong place.

use kenter_client::Holdings;

use crate::wallet::Network;

/// What the account screen shows.
#[derive(Debug, Clone, Default)]
pub struct Account {
    pub address: String,
    /// `None` when the account does not exist on the ledger yet.
    pub holdings: Option<Holdings>,
    /// Code of the asset this mint escrows, once known.
    pub asset_code: Option<String>,
    pub asset_issuer: Option<String>,
    pub error: Option<String>,
}

/// Enough XLM for the reserve, a trustline, and fees with room to spare.
///
/// A Stellar account's minimum balance is `(2 + subentries) × 0.5 XLM`, so
/// one trustline puts the hard floor at 1.5. Three is the number to ask a
/// person for: it clears the floor, leaves 1.5 for fees, and needs no
/// arithmetic to act on.
pub const MIN_XLM: i128 = 30_000_000;

impl Account {
    /// Does this account exist and hold enough XLM to do anything?
    ///
    /// Existing is not enough. An account holding exactly its reserve can
    /// pay for nothing, and reporting it as funded is how someone ends up at
    /// a failed transaction instead of a clear instruction.
    pub fn usable(&self) -> bool {
        self.holdings.as_ref().is_some_and(|h| h.native >= MIN_XLM)
    }

    /// Is there a trustline for the mint's asset?
    ///
    /// `None` while the asset is unknown — which is not the same as "no",
    /// and must not be rendered as one.
    pub fn has_trustline(&self) -> Option<bool> {
        let (code, issuer) = (self.asset_code.as_ref()?, self.asset_issuer.as_ref()?);
        let holdings = self.holdings.as_ref()?;
        Some(holdings.asset(code, issuer).is_some())
    }

    /// Spendable balance of the mint's asset, in stroops. Zero when there is
    /// no trustline or nothing has arrived.
    pub fn asset_balance(&self) -> i128 {
        let (Some(code), Some(issuer), Some(h)) =
            (&self.asset_code, &self.asset_issuer, &self.holdings)
        else {
            return 0;
        };
        h.asset(code, issuer).unwrap_or(0)
    }

    /// Everything that still stands between this account and a client that
    /// can deposit, in the order it has to be done.
    pub fn blocked_by(&self) -> Option<String> {
        if self.holdings.is_none() {
            return Some("this account does not exist yet — send it XLM".into());
        }
        if !self.usable() {
            return Some(format!(
                "needs at least {} XLM to cover the reserve and fees",
                MIN_XLM / 10_000_000
            ));
        }
        if self.has_trustline() == Some(false) {
            let code = self
                .asset_code
                .clone()
                .unwrap_or_else(|| "the asset".into());
            return Some(format!("needs a {code} trustline before it can be paid"));
        }
        None
    }
}

/// Read the account: holdings from Horizon, asset identity from the mint.
///
/// Horizon rather than the asset contract, because an account that does not
/// exist cannot be a simulation source — and "nothing has arrived yet" is
/// precisely the state this screen most needs to report.
pub async fn read(net: Network, address: &str) -> Account {
    let mut account = Account {
        address: address.to_string(),
        ..Default::default()
    };

    match net.rpc_client()
        .get_holdings(address)
        .await
    {
        Ok(h) => account.holdings = h,
        Err(e) => {
            account.error = Some(format!("could not reach Horizon: {e}"));
            return account;
        }
    }

    // What the mint escrows needs a funded source to read, so it is asked
    // only once there is one. Until then the screen is still useful: it can
    // say how to fund the account, which is the only thing to do anyway.
    if account.usable() {
        match crate::settings::escrow_asset(net).await {
            Ok(asset) => {
                account.asset_issuer = asset.issuer.clone();
                account.asset_code = Some(asset.code);
            }
            Err(e) => account.error = Some(format!("could not read the mint: {e}")),
        }
    }
    account
}

/// Escrow sitting in a print that never finished.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stalled {
    pub slot_id: u32,
    /// What the slot holds, in stroops — refunded in full on cancel.
    pub amount: i128,
    pub confirmed: u32,
    pub total: u32,
}

/// How far back to look for stalled prints.
///
/// There is no index from depositor to slot, so finding one's own means
/// reading slots and checking who owns them. Bounded because the cost is one
/// ledger read per slot: a client should not spend a thousand reads on
/// startup to find nothing. The bound is a real limit, not a formality — a
/// print stranded more than this many slots ago will not be found, and the
/// fix is an index the contract does not have.
const SCAN_DEPTH: u32 = 250;

/// Prints of this depositor's that took escrow and never finished.
///
/// `cancel_print` refunds these in full: depositor-only, state `Printing`,
/// no expiry condition. Until this existed there was no way to reach that
/// money from any surface — the contract would have given it back and
/// nothing asked.
pub async fn stalled_prints(net: Network, address: &str) -> Result<Vec<Stalled>, String> {
    use kenter_client::{MintClient, TxBuilder};

    let mint = MintClient::new(
        TxBuilder::read_only(net.rpc_client(), address),
        net.contract,
    );
    let next = mint
        .next_slot_id()
        .await
        .map_err(|e| format!("next_slot_id: {e}"))?;
    let from = next.saturating_sub(SCAN_DEPTH);

    let mut out = Vec::new();
    for id in from..next {
        let Some(slot) = mint
            .get_slot(id)
            .await
            .map_err(|e| format!("get_slot {id}: {e}"))?
        else {
            continue;
        };
        if slot.depositor == address && slot.state == kenter_client::TokenState::Printing {
            out.push(Stalled {
                slot_id: slot.slot_id,
                amount: slot.amount,
                confirmed: slot.completed_links,
                total: slot.total_pairs,
            });
        }
    }
    Ok(out)
}

/// Cancel a stalled print and take the escrow back.
///
/// Returns what the contract refunded, which is the figure to show — not
/// what the slot said it held, which is this client's reading of it.
pub async fn cancel(net: Network, credential: &[u8], slot_id: u32) -> Result<i128, String> {
    let vault_path =
        crate::receive::default_vault_path().ok_or_else(|| "set KENTER_VAULT".to_string())?;
    let vault = kenter_vault::SoftVault::open(&vault_path).map_err(|e| e.to_string())?;
    let slot = kenter_vault::KeyVault::list_keys(&vault)
        .map_err(|e| e.to_string())?
        .first()
        .map(|k| k.slot)
        .ok_or_else(|| "no account in the vault".to_string())?;
    // The contract accepts this only from the depositor, so it has to be
    // signed by the same key that opened the slot.
    let kp = vault.keypair(slot, credential).map_err(|e| e.to_string())?;
    let mut mint = kenter_client::MintClient::new(
        kenter_client::TxBuilder::new(
            net.rpc_client(),
            kp,
        ),
        net.contract,
    );
    mint.cancel_print(slot_id)
        .await
        .map_err(|e| format!("cancel_print {slot_id}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn holdings(native: i128, assets: Vec<(&str, &str, i128)>) -> Holdings {
        Holdings {
            native,
            subentries: assets.len() as u32,
            assets: assets
                .into_iter()
                .map(|(c, i, a)| (c.to_string(), i.to_string(), a))
                .collect(),
        }
    }

    fn with(h: Option<Holdings>) -> Account {
        Account {
            address: "GTEST".into(),
            holdings: h,
            asset_code: Some("USDC".into()),
            asset_issuer: Some("GISSUER".into()),
            error: None,
        }
    }

    /// Existing is not usable. An account holding its bare reserve can pay
    /// for nothing, and calling that "funded" sends someone to a failed
    /// transaction instead of to a faucet.
    #[test]
    fn existing_is_not_the_same_as_usable() {
        assert!(!with(None).usable());
        assert!(!with(Some(holdings(10_000_000, vec![]))).usable());
        assert!(with(Some(holdings(MIN_XLM, vec![]))).usable());
    }

    /// The three obstacles have to be reported in the order they can be
    /// fixed: a trustline is a transaction, so funding always comes first.
    #[test]
    fn obstacles_come_in_the_order_they_can_be_cleared() {
        assert!(with(None).blocked_by().unwrap().contains("does not exist"));
        assert!(with(Some(holdings(10_000_000, vec![])))
            .blocked_by()
            .unwrap()
            .contains("at least 3 XLM"));
        assert!(with(Some(holdings(MIN_XLM, vec![])))
            .blocked_by()
            .unwrap()
            .contains("trustline"));
        // Funded, with a trustline, holding nothing: nothing is blocked.
        // Having no USDC is not an obstacle to *using* the client, it is
        // just an empty account.
        let ready = with(Some(holdings(MIN_XLM, vec![("USDC", "GISSUER", 0)])));
        assert_eq!(ready.blocked_by(), None);
        assert_eq!(ready.asset_balance(), 0);
    }

    /// An unknown asset must not render as "no trustline" — that would send
    /// someone to add one they may already have.
    #[test]
    fn an_unknown_asset_is_not_a_missing_trustline() {
        let unknown = Account {
            address: "GTEST".into(),
            holdings: Some(holdings(MIN_XLM, vec![])),
            asset_code: None,
            asset_issuer: None,
            error: None,
        };
        assert_eq!(unknown.has_trustline(), None);
        assert_eq!(
            with(Some(holdings(MIN_XLM, vec![]))).has_trustline(),
            Some(false)
        );
        assert_eq!(
            with(Some(holdings(MIN_XLM, vec![("USDC", "GISSUER", 5)]))).has_trustline(),
            Some(true)
        );
    }

    #[test]
    fn the_asset_balance_is_the_one_a_deposit_can_spend() {
        let a = with(Some(holdings(
            MIN_XLM,
            vec![("USDC", "GISSUER", 191_500_000)],
        )));
        assert_eq!(a.asset_balance(), 191_500_000);
        // A different issuer is a different asset, however familiar the code.
        let b = with(Some(holdings(
            MIN_XLM,
            vec![("USDC", "GOTHER", 191_500_000)],
        )));
        assert_eq!(b.asset_balance(), 0);
    }
}
