//! Every on-chain thing a node does for itself: join, reactivate, record
//! its endpoint, heartbeat, claim, leave, withdraw, and the reads behind
//! `status`.
//!
//! Each call builds a fresh `TxBuilder`, so it reads the account sequence
//! from the ledger rather than trusting a cached one. That is what lets the
//! daemon's other submitters (the link confirmer above all) share an
//! account with these calls, given the daemon serialises them
//! (`daemon::OwnKeyLock`).

use kenter_client::{AssetClient, MintClient, NetworkConfig, NodeInfo, RosterClient, TxBuilder};
use kenter_crypto::keypair::StellarKeypair;

/// One XLM, in stroops.
pub const XLM: i128 = 10_000_000;

/// XLM a node keeps above its reserve for transaction fees, before it asks
/// for more. `confirm_link` costs about 0.0014 XLM (`docs/LEDGER_COSTS.md`),
/// so this is over a thousand prints; the margin is for `join`, which prepays
/// the new roster entry's rent.
pub const FEE_FLOAT: i128 = 5 * XLM;

/// Below this much spendable XLM the node warns (amber).
pub const LOW_BALANCE: i128 = 2 * XLM;

/// What one address needs before it can join: the stake, the account's own
/// reserve (two base reserves, plus one for the fee-token trustline a paid
/// node needs to be paid), and the fee float.
pub fn funding_target(min_stake: i128, volunteer: bool) -> i128 {
    let reserve = XLM + if volunteer { 0 } else { XLM / 2 };
    min_stake + reserve + FEE_FLOAT
}

/// What the operator sends to the node's own address for the whole pair.
/// The node then funds its partner from it, so there is one address and
/// one amount to deal with: both addresses' targets,
/// plus a little for the transaction that moves the partner's share.
pub fn pair_funding_target(min_stake: i128, volunteer: bool) -> i128 {
    2 * funding_target(min_stake, volunteer) + XLM / 10
}

/// XLM above the account's minimum balance. The stake is not in the
/// account once joined, so this is what pays fees.
pub fn spendable(native: i128, subentries: u32) -> i128 {
    native - (2 + subentries as i128) * (XLM / 2)
}

/// `12.5` for 125 000 000 stroops; trailing zeros dropped.
pub fn xlm(stroops: i128) -> String {
    let sign = if stroops < 0 { "-" } else { "" };
    let s = stroops.unsigned_abs();
    let whole = s / XLM as u128;
    let frac = s % XLM as u128;
    if frac == 0 {
        format!("{sign}{whole}")
    } else {
        let f = format!("{frac:07}");
        format!("{sign}{whole}.{}", f.trim_end_matches('0'))
    }
}

/// One address's state, as `status` shows it.
#[derive(Debug, Clone, Default)]
pub struct AccountView {
    pub address: String,
    /// `None`: the account does not exist yet (never funded).
    pub native: Option<i128>,
    pub subentries: u32,
    /// `None`: not on the roster (never joined, or withdrawn).
    pub node: Option<NodeInfo>,
    /// Fees credited and not yet claimed, in pay-token stroops.
    pub accrued: Option<i128>,
}

pub struct Chain {
    pub net: NetworkConfig,
}

impl Chain {
    pub fn new(net: NetworkConfig) -> Self {
        Self { net }
    }

    fn roster(&self, kp: &StellarKeypair) -> RosterClient {
        RosterClient::new(TxBuilder::new(self.net.rpc_client(), kp.clone()), &self.net.roster)
    }

    fn mint(&self, kp: &StellarKeypair) -> MintClient {
        MintClient::new(TxBuilder::new(self.net.rpc_client(), kp.clone()), &self.net.mint)
    }

    /// The roster's bond, read without a funded source account (a fresh
    /// install asks this before anything is funded).
    pub async fn min_stake(&self, any_address: &str) -> Result<i128, String> {
        let tx = TxBuilder::read_only(self.net.rpc_client(), any_address);
        let v = tx
            .simulate_invoke_ro(&self.net.roster, "min_stake", vec![])
            .await
            .map_err(|e| format!("reading min_stake: {e}"))?
            .ok_or("min_stake returned nothing")?;
        kenter_client::tx::scval_to_i128(&v).map_err(|e| format!("min_stake: {e}"))
    }

    pub async fn view(&self, kp: &StellarKeypair) -> Result<AccountView, String> {
        let address = kp.stellar_address();
        let holdings = self
            .net
            .rpc_client()
            .get_holdings(&address)
            .await
            .map_err(|e| format!("balance of {address}: {e}"))?;
        let Some(h) = holdings else {
            // An unfunded account cannot be a simulation source, and has
            // joined nothing.
            return Ok(AccountView { address, ..Default::default() });
        };
        let node = self
            .roster(kp)
            .get_node(&address)
            .await
            .map_err(|e| format!("roster record of {address}: {e}"))?;
        let accrued = self.mint(kp).accrued_fees(&address).await.ok();
        Ok(AccountView {
            address,
            native: Some(h.native),
            subentries: h.subentries,
            node,
            accrued,
        })
    }

    /// Join, or volunteer, with the pair's label. Nothing else: callers
    /// decide whether joining is what the record calls for.
    pub async fn join(&self, kp: &StellarKeypair, name: &str, volunteer: bool) -> Result<(), String> {
        let address = kp.stellar_address();
        let mut roster = self.roster(kp);
        let r = if volunteer {
            roster.volunteer(name, "").await
        } else {
            roster.join(name, "").await
        };
        r.map(|_| ()).map_err(|e| format!("joining the roster as {address}: {e}"))
    }

    /// Send XLM from `from` to `to`, creating `to` if it does not exist.
    pub async fn send_xlm(&self, from: &StellarKeypair, to: &str, stroops: i128, create: bool) -> Result<(), String> {
        let amount = i64::try_from(stroops).map_err(|_| "amount out of range".to_string())?;
        TxBuilder::new(self.net.rpc_client(), from.clone())
            .send_xlm(to, amount, create)
            .await
            .map(|_| ())
            .map_err(|e| format!("sending {} XLM to {to}: {e}", xlm(stroops)))
    }

    /// Move the partner's spendable XLM back to the node's own address, so
    /// a withdrawn stake comes back as one sum. Leaves a hair for the fee.
    /// Returns what was moved (0 if nothing worth moving).
    pub async fn sweep_partner(&self, own: &StellarKeypair, partner: &StellarKeypair) -> Result<i128, String> {
        let v = self.view(partner).await?;
        let Some(native) = v.native else { return Ok(0) };
        let amount = spendable(native, v.subentries) - XLM / 100;
        if amount <= 0 {
            return Ok(0);
        }
        self.send_xlm(partner, &own.stellar_address(), amount, false).await?;
        Ok(amount)
    }

    pub async fn set_active(&self, kp: &StellarKeypair, active: bool) -> Result<(), String> {
        self.roster(kp)
            .update_node(None, None, Some(active))
            .await
            .map(|_| ())
            .map_err(|e| format!("setting {} active={active}: {e}", kp.stellar_address()))
    }

    pub async fn set_endpoint(&self, kp: &StellarKeypair, endpoint: &str) -> Result<(), String> {
        self.roster(kp)
            .update_node(None, Some(endpoint), None)
            .await
            .map(|_| ())
            .map_err(|e| format!("recording endpoint for {}: {e}", kp.stellar_address()))
    }

    pub async fn heartbeat(&self, kp: &StellarKeypair) -> Result<u32, String> {
        self.roster(kp)
            .heartbeat()
            .await
            .map_err(|e| format!("heartbeat for {}: {e}", kp.stellar_address()))
    }

    pub async fn leave(&self, kp: &StellarKeypair) -> Result<u32, String> {
        self.roster(kp)
            .leave()
            .await
            .map_err(|e| format!("leaving as {}: {e}", kp.stellar_address()))
    }

    pub async fn withdraw(&self, kp: &StellarKeypair) -> Result<i128, String> {
        self.roster(kp)
            .withdraw_stake()
            .await
            .map_err(|e| format!("withdrawing the stake of {}: {e}", kp.stellar_address()))
    }

    /// Claim credited fees, opening the fee token's trustline first if the
    /// account has none (a payout cannot reach an account without one).
    /// Returns the amount and the fee token's code; 0 and an empty code,
    /// without a transaction, when nothing is owed.
    pub async fn claim(&self, kp: &StellarKeypair) -> Result<(i128, String), String> {
        let address = kp.stellar_address();
        let mut mint = self.mint(kp);
        let owed = mint
            .accrued_fees(&address)
            .await
            .map_err(|e| format!("fees owed to {address}: {e}"))?;
        if owed <= 0 {
            return Ok((0, String::new()));
        }
        let pay_token = mint.pay_token().await.map_err(|e| format!("mint pay token: {e}"))?;
        let asset = AssetClient::new(TxBuilder::new(self.net.rpc_client(), kp.clone()), &pay_token)
            .describe()
            .await
            .map_err(|e| format!("describing {pay_token}: {e}"))?;
        if asset.needs_trustline() {
            let issuer = asset.issuer.clone().unwrap_or_default();
            let mut tx = TxBuilder::new(self.net.rpc_client(), kp.clone());
            let trusted = tx
                .has_trustline(&asset.code, &issuer)
                .await
                .map_err(|e| format!("trustline check: {e}"))?;
            if !trusted {
                tx.change_trust(&asset.code, &issuer, i64::MAX)
                    .await
                    .map_err(|e| format!("opening a {} trustline: {e}", asset.code))?;
            }
        }
        let got = mint
            .claim_fees()
            .await
            .map_err(|e| format!("claiming fees for {address}: {e}"))?;
        Ok((got, asset.code))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xlm_formats_without_noise() {
        assert_eq!(xlm(150 * XLM), "150");
        assert_eq!(xlm(125_000_000), "12.5");
        assert_eq!(xlm(14_000), "0.0014");
        assert_eq!(xlm(-XLM / 2), "-0.5");
    }

    #[test]
    fn the_funding_target_covers_stake_reserve_and_fees() {
        let stake = 150 * XLM;
        assert_eq!(funding_target(stake, true), stake + XLM + FEE_FLOAT);
        assert_eq!(funding_target(stake, false), stake + XLM + XLM / 2 + FEE_FLOAT);
    }

    #[test]
    fn one_address_is_funded_for_the_pair() {
        let stake = 150 * XLM;
        assert_eq!(
            pair_funding_target(stake, true),
            2 * funding_target(stake, true) + XLM / 10
        );
    }

    #[test]
    fn spendable_is_above_the_minimum_balance() {
        assert_eq!(spendable(10 * XLM, 0), 9 * XLM);
        assert_eq!(spendable(10 * XLM, 1), 9 * XLM - XLM / 2);
    }
}
