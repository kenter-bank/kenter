//! Deposit: value in, a note out.
//!
//! Printing a note is a deposit: value goes into escrow and an instrument
//! comes back, so that is what the client calls it. On-chain it is
//! `request_print` (escrow, a slot naming the depositor's own end pairs),
//! a seed from the drand beacon, claims by the nodes the draw favours,
//! each selected pair's `confirm_link`, and `register_token`. Only after
//! the last is there a redeemable instrument.
//!
//! ## The network chooses the nodes
//!
//! The holder chooses only how many pairs. Which nodes serve is decided by
//! the draw (`docs/architecture/node-selection.md`): nodes claim positions
//! after a public beacon round seeds the slot, and the lowest scores win. The wallet has
//! no node list and no relay setting. It reaches each selected node
//! through the relay its roster endpoint names. This is
//! `kenter_print::print_selected`, the same code the CLI's `print-net`
//! drives.
//!
//! ## One note at a time, for now
//!
//! A deposit could be a batch with per-note denominations and per-note
//! state. This builds the single-note case: it is the whole of the on-chain
//! sequence, and the batch is a loop plus the partial-failure display around
//! it. Named here so the gap is deliberate rather than an oversight.
//!
//! ## The depositor is still four of the participants
//!
//! `DepositorPairs::testbed` fills both depositor pairs with the one
//! account, so the two chain-closing pairs derive the same shard rather
//! than two independent ones. Harmless -- the depositor is the honest party
//! at both ends either way -- and the end pairs need no stake, since the
//! mint exempts them from the roster check.

use kenter_client::{Beacon, MintClient, RosterClient, TokenMode, TxBuilder};
use kenter_crypto::keypair::StellarKeypair;
use kenter_crypto::token::{assemble_bearer_token, BearerToken, PartialToken};

use crate::wallet::Network;

/// Node fee per participant, in stroops. The contract charges
/// `node_fee * 2 * (pairs - 2)` per note -- interior pairs only; the
/// depositor's two end pairs are neither charged nor credited -- taken out
/// of face value at redemption.
///
/// The form has to show the arithmetic before it has talked to anyone, so
/// this is the planned mainnet value. It must match what the deployed
/// contract charges, or the form quotes a fee the note will not pay (see
/// `docs/LEDGER_COSTS.md`).
pub const ASSUMED_NODE_FEE: u64 = 25_000;

/// What a note of this size and shape will actually redeem for.
pub fn redemption_value(amount: u64, pairs: u16, node_fee: u64) -> Option<u64> {
    amount.checked_sub(fees_for(pairs, node_fee))
}

/// Total fee a note of this shape carries: two participants for each
/// interior pair, as the mint charges. The single copy of the formula; the
/// redemption quote uses it too.
pub fn fees_for(pairs: u16, node_fee: u64) -> u64 {
    node_fee * 2 * pairs.saturating_sub(2) as u64
}

/// The smallest note that can be printed at this pair count.
///
/// `request_print` rejects `total_fees >= amount` outright, so this is a hard
/// floor and not a recommendation. It rises with the pair count, which is the
/// unintuitive part: asking for more privacy raises the minimum you can put
/// in a note.
pub fn floor(pairs: u16, node_fee: u64) -> u64 {
    fees_for(pairs, node_fee) + 1
}

/// Parse a decimal amount into stroops.
///
/// Rejects more than seven decimal places rather than rounding: a client that
/// silently alters the amount someone typed into a money field has made a
/// decision that was not its to make.
pub fn parse_amount(text: &str) -> Result<u64, String> {
    let t = text.trim();
    if t.is_empty() {
        return Err("enter an amount".into());
    }
    let (whole, frac) = match t.split_once('.') {
        Some((w, f)) => (w, f),
        None => (t, ""),
    };
    if frac.len() > 7 {
        return Err("at most 7 decimal places".into());
    }
    if whole.is_empty() && frac.is_empty() {
        return Err("enter an amount".into());
    }
    let parse = |s: &str, what: &str| -> Result<u64, String> {
        if s.is_empty() {
            return Ok(0);
        }
        s.parse::<u64>()
            .map_err(|_| format!("{what} is not a number"))
    };
    let whole = parse(whole, "the amount")?;
    let frac_padded = format!("{frac:0<7}");
    let frac = parse(&frac_padded, "the decimal part")?;
    whole
        .checked_mul(10_000_000)
        .and_then(|w| w.checked_add(frac))
        .ok_or_else(|| "that amount is too large".into())
}

/// Seconds since the epoch, for a token header.
fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Mint a token in process: the depositor plays every node.
///
/// Takes the slot rather than inventing one: the note carries the slot
/// it was registered under, because the mint keys records by slot.
/// That means the escrow has to exist before the
/// container can be assembled, so `request_print` runs first and
/// its id comes in here.
fn build(
    amount: u64,
    pairs: u16,
    event_id: [u8; 32],
    slot_id: u32,
) -> Result<(BearerToken, StellarKeypair), String> {
    if pairs < 2 {
        return Err("a note needs at least 2 pairs".into());
    }
    let timestamp = now();
    let requestor = StellarKeypair::random();

    let (n0a, n0b) = (StellarKeypair::random(), StellarKeypair::random());
    let (mut partial, _shard0) =
        PartialToken::initiate(event_id, timestamp, Some(amount), pairs, &n0a, &n0b, vec![])
            .map_err(|e| format!("initiate: {e}"))?;
    for _ in 0..(pairs - 2) {
        let (na, nb) = (StellarKeypair::random(), StellarKeypair::random());
        partial
            .extend(&na, &nb)
            .map_err(|e| format!("extend: {e}"))?;
    }
    let partner = StellarKeypair::random();
    let token = assemble_bearer_token(&partial, &requestor, &partner, slot_id, None)
        .map_err(|e| format!("assemble: {e}"))?;
    Ok((token, requestor))
}

/// What a deposit produced.
pub struct Deposited {
    /// Container bytes, ready to import.
    pub container: Vec<u8>,
    /// The token's ephemeral Stellar address.
    pub id: String,
    pub amount: u64,
}

/// Run the whole sequence. Reports each step so the screen can say where it is.
///
/// `pairs` is the holder's choice, at least 3: the two end pairs are the
/// depositor's and `pairs - 2` are chosen by the network. The depositor
/// never joins the roster: its end pairs are exempt from the roster check
/// by the mint, and joining would lock `min_stake` for nothing.
///
/// Not resumable yet: a failure between `request_print` and
/// `register_token` leaves escrow in a slot. `print_selected` cancels what
/// it can and says so; the slot id is in every error, so it is not lost.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    net: Network,
    submitter: StellarKeypair,
    amount: u64,
    pairs: u16,
    mode: TokenMode,
    owner_commitment: [u8; 32],
    step: impl Fn(String),
) -> Result<Deposited, String> {
    if pairs < 3 {
        return Err("a print needs at least 3 pairs: yours at both ends, and one chosen by the network".into());
    }
    let mut mint = MintClient::new(TxBuilder::new(net.rpc_client(), submitter.clone()), net.contract);
    let roster = RosterClient::new(
        TxBuilder::read_only(net.rpc_client(), &submitter.stellar_address()),
        net.roster,
    );
    // Only this build's relays: a relay list from anywhere else could
    // route a print through hosts this build never named.
    let mut reach = kenter_print::Reach::Roster {
        roster,
        relays: kenter_client::network::built().relays.iter().map(|r| r.to_string()).collect(),
    };
    let beacon = Beacon::quicknet().map_err(|e| format!("beacon: {e}"))?;
    let order = kenter_print::PrintOrder {
        total_pairs: pairs as u32,
        event_id: rand::random(),
        denomination: amount,
        timestamp: now(),
        mode,
        owner_commitment,
    };

    step(format!("printing {pairs} pairs: {} chosen by the network", pairs - 2));
    let (token, container) = kenter_print::print_selected(
        &mut mint,
        &mut reach,
        &beacon,
        &kenter_print::DepositorPairs::testbed(&submitter),
        &order,
        // The progress lines are written for a reader, so they pass
        // through rather than being replaced by a step counter that would
        // say less about where the chain has got to.
        &|line: &str| step(line.trim().to_string()),
    )
    .await?;

    Ok(Deposited {
        container,
        id: kenter_wallet::note_id(&token.ephemeral_address(), token.slot_id),
        amount,
    })
}

/// Building a real container, for tests in this crate that need one.
///
/// Not behind `#[cfg(test)]`: `redemption.rs` needs it too, and a second copy of
/// the minting dance would be a second thing to keep correct.
#[doc(hidden)]
pub mod tests_support {
    /// A serialized bearer token of this denomination and pair count.
    ///
    /// The slot is a stand-in: nothing here talks to a mint, so there
    /// is no issued slot to carry. A test that checks a slot-addressed
    /// call needs to agree with whatever it registered.
    pub fn token_bytes(amount: u64, pairs: u16) -> Vec<u8> {
        let (token, requestor) =
            super::build(amount, pairs, rand::random(), 0).expect("build");
        kenter_crypto::container::serialize_bearer_token(&token, &requestor).expect("serialize")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amounts_parse_the_way_people_type_them() {
        assert_eq!(parse_amount("1").unwrap(), 10_000_000);
        assert_eq!(parse_amount("2.5").unwrap(), 25_000_000);
        assert_eq!(parse_amount("0.0000001").unwrap(), 1);
        assert_eq!(parse_amount(" 0.3 ").unwrap(), 3_000_000);
        assert_eq!(parse_amount(".5").unwrap(), 5_000_000);
    }

    /// Rounding would change the number someone typed into a money field.
    #[test]
    fn too_many_decimals_is_refused_rather_than_rounded() {
        let err = parse_amount("1.00000001").unwrap_err();
        assert!(err.contains("7 decimal"), "{err}");
    }

    #[test]
    fn nonsense_is_refused() {
        for bad in ["", "   ", "abc", "1.2.3", "-1", "1e5"] {
            assert!(parse_amount(bad).is_err(), "{bad:?} should not parse");
        }
    }

    #[test]
    fn an_overflowing_amount_does_not_wrap() {
        assert!(parse_amount("99999999999999999999").is_err());
    }

    /// D3: the fee is flat per note, so granularity costs money and the floor
    /// rises with the pair count. Both are easy to get backwards.
    #[test]
    fn fees_are_per_note_and_the_floor_follows_the_pair_count() {
        // Interior pairs only: 3 pairs is one charged pair, 24 is 22.
        assert_eq!(fees_for(3, 100), 200);
        assert_eq!(fees_for(24, 100), 4_400);
        // The mainnet figure on an 8-pair note: 0.03 USDC.
        assert_eq!(fees_for(8, 25_000), 300_000);
        // Four notes of a quarter each cost four times one note's fee.
        assert_eq!(fees_for(3, 100) * 4, 800);
        assert_eq!(floor(3, 100), 201);
        assert!(floor(24, 100) > floor(3, 100));
    }

    #[test]
    fn redemption_value_is_face_less_this_notes_own_fees() {
        assert_eq!(redemption_value(3_000_000, 3, 100), Some(2_999_800));
        // Below the floor there is nothing to redeem, and the contract
        // would refuse to print it in the first place.
        assert_eq!(redemption_value(150, 3, 100), None);
    }

    #[test]
    fn a_note_needs_at_least_two_pairs() {
        assert!(build(10_000_000, 1, rand::random(), 0).is_err());
    }

    #[test]
    fn a_built_note_carries_the_amount_and_verifies_offline() {
        let (token, _requestor) = build(25_000_000, 3, rand::random(), 0).unwrap();
        token.verify_chain_integrity().unwrap();
        assert_eq!(token.chain.total_pairs, 3);
    }
}
