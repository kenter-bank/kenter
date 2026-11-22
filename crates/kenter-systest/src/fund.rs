//! Funding a wallet the operator has just created in the GUI.
//!
//! The system test provisions its own accounts, so it never needed this. A
//! UI run is the other way round: the wallet is made in the window, from a
//! seed this harness has no business holding, and all we are given is the
//! `G…` it shows on the Activate screen.
//!
//! # The order is forced, and there is a human in the middle of it
//!
//! | | | signed by |
//! |---|---|---|
//! | 1 | XLM from friendbot | nobody — friendbot creates the account |
//! | 2 | a trustline for the mint's asset | **the wallet** |
//! | 3 | USDC from the funder | the funder |
//!
//! XLM first because until friendbot creates it the account does not exist
//! on the ledger at all: it has no sequence number, so it cannot sign, and
//! `ChangeTrust` raises the base reserve it has to cover.
//!
//! USDC last because a SAC `transfer` into an account with no trustline
//! fails. So step 2 gates step 3 — and step 2 is not ours to take, because
//! `ChangeTrust` is signed by the account it affects and only the wallet
//! holds that key. This errand therefore stops at the gate and says what to
//! press, rather than pretending it can close it from here.
//!
//! Every leg is idempotent, so running it again after the trustline lands
//! picks up where it stopped. That is the intended shape: run, click, run.

use crate::chain::{self, Account};
use kenter_client::{AssetClient, SorobanRpcClient, TxBuilder};

/// Fund `to` for a UI test run against `mint_id`.
///
/// Returns the number of legs still outstanding, which the caller turns
/// into an exit code: 0 means the wallet is ready to deposit.
pub async fn errand(
    funder: &Account,
    to: &str,
    amount: i128,
    mint_id: &str,
) -> Result<usize, String> {
    // Caught here rather than three RPC calls later, because the common
    // mistake is pasting a contract id or a secret, and both of those fail
    // much further in with a much worse message.
    if !to.starts_with('G') || to.len() != 56 {
        return Err(format!(
            "{to} is not a Stellar account address — the Activate screen shows a \
             G… of 56 characters"
        ));
    }
    if to == funder.address {
        return Err("that is the funder's own address".into());
    }

    println!("funding {to}");
    println!("  from  {}", funder.address);
    println!("  mint  {mint_id}");

    // ── 1 ── XLM ────────────────────────────────────────────────────────
    //
    // Asked only when the account is not there. Friendbot does not refuse an
    // account it has already created — it grants another 10 000 — so calling
    // it on the second half of a `run, click, run` silently doubles the
    // balance while the line on screen says the same word it said the first
    // time. The gate is what makes this leg genuinely a no-op rather than
    // merely harmless.
    if chain::exists(to).await {
        println!("\n1. XLM  already funded, friendbot not asked");
    } else {
        let xlm = chain::fund(to).await?;
        println!("\n1. XLM  {xlm}");
        // Friendbot answering 200 is not the same as the entry being
        // readable, and everything below assumes the account exists.
        if !chain::exists(to).await {
            return Err(format!(
                "friendbot reported {xlm} but {to} has no ledger entry — wait \
                 a few seconds and run this again"
            ));
        }
    }

    // ── 2 ── the trustline the wallet has to add for itself ─────────────
    //
    // Read what the mint escrows rather than assuming USDC: a mint is
    // constructor-pinned to its `pay_token`, and pointing a client at the
    // XLM mint while funding for the USDC one is a mistake that looks like
    // a working run right up until the deposit.
    let mut mint = chain::mint(funder, mint_id);
    let token = mint
        .pay_token()
        .await
        .map_err(|e| format!("reading pay_token from {mint_id}: {e}"))?;
    let mut asset_client = AssetClient::new(funder.tx(), &token);
    let asset = asset_client
        .describe()
        .await
        .map_err(|e| format!("describing {token}: {e}"))?;

    let Some(issuer) = asset.issuer.clone() else {
        println!(
            "\n2. this mint escrows native {}, which needs no trustline",
            asset.code
        );
        println!("\nthe wallet is ready — nothing further to send.");
        return Ok(0);
    };

    let reader = TxBuilder::read_only(SorobanRpcClient::new(chain::RPC, chain::PASSPHRASE), to);
    let has = reader
        .has_trustline(&asset.code, &issuer)
        .await
        .map_err(|e| format!("reading the {} trustline on {to}: {e}", asset.code))?;
    if !has {
        println!("\n2. {} trustline  MISSING — stopping here", asset.code);
        println!(
            "\n   Only the wallet can add it: ChangeTrust is signed by the account it\n   \
             affects, and this errand does not hold that key. In the window:\n\
             \n     first run   the Activate screen offers it once the XLM has landed\n     \
             later       Settings, the `trustline` row\n\
             \n   Then run this again. Step 1 is idempotent, so nothing is repeated."
        );
        return Ok(1);
    }
    println!("\n2. {} trustline  present", asset.code);

    // ── 3 ── the escrow asset ───────────────────────────────────────────
    let d = asset.decimals;
    let held = chain::balance(funder, &token, &funder.address).await?;
    if held < amount {
        return Err(format!(
            "the funder holds {} {} and this would send {} — see the footer below \
             for where to top it up\n  funder {}",
            units(held, d),
            asset.code,
            units(amount, d),
            funder.address
        ));
    }

    let before = chain::balance(funder, &token, to).await.unwrap_or(0);
    let hash = chain::pay(funder, &token, to, amount).await?;
    let after = chain::balance(funder, &token, to).await?;
    println!(
        "\n3. {} sent  {} → {}",
        asset.code,
        units(before, d),
        units(after, d)
    );
    println!("   tx {hash}");

    println!("\nthe wallet is ready to deposit.");
    println!(
        "\nfunder has {} {} left. More comes from Circle's faucet\n\
         (faucet.circle.com, interactive) or any account that will send to\n  {}",
        units(held - amount, d),
        asset.code,
        funder.address
    );
    Ok(0)
}

/// Stroops as whole units, for a line a human reads.
///
/// Balances move in stroops everywhere else in this harness, deliberately —
/// the assertions compare integers. This exists only so the operator is not
/// asked to count zeroes in a progress line.
fn units(stroops: i128, decimals: u32) -> String {
    let scale = 10i128.pow(decimals);
    let whole = stroops / scale;
    let frac = (stroops % scale).unsigned_abs();
    format!("{whole}.{frac:0width$}", width = decimals as usize)
}

#[cfg(test)]
mod tests {
    use super::units;

    #[test]
    fn stroops_render_as_units() {
        assert_eq!(units(10_000_000, 7), "1.0000000");
        assert_eq!(units(19_150_000, 7), "1.9150000");
        assert_eq!(units(0, 7), "0.0000000");
        assert_eq!(units(1, 7), "0.0000001");
    }

    /// A SAC can declare something other than seven, and the funder's
    /// balance line must not silently shift by three orders of magnitude.
    #[test]
    fn decimals_come_from_the_asset() {
        assert_eq!(units(1_500_000, 6), "1.500000");
        assert_eq!(units(1_500_000, 7), "0.1500000");
    }
}
