#![no_std]

mod types;
mod verify;

use soroban_sdk::{
    contract, contractimpl,
    crypto::bls12_381::{G1Affine, G2Affine},
    panic_with_error, symbol_short, vec, xdr::ToXdr, Address, Bytes, BytesN, Env, IntoVal,
    Symbol, Vec, token,
};

use types::*;

// ── State archival ──
//
// An entry nobody bumps drifts toward archival, and the cost of restoring
// it lands on whoever next touches it -- for a note, the holder redeeming
// it. Protocol 23 restores an archived persistent entry automatically when
// the transaction lists it, and fails the transaction outright when it
// does not, so archival is never a loss of funds nor a way to erase the
// redeemed-token nullifier. It is a bill handed to the wrong person, and
// an off-ledger `get_token` that can answer "not found" about a note that
// exists. Hence the bumps below.
//
// Reads do not bump. A query entry point that wrote would turn a payee's
// simulated gate check into a fee.

/// Ledgers in a day at Stellar's 5-second close target.
const DAY_LEDGERS: u32 = 17_280;

/// Bump an entry once it has less than 30 days left...
const TTL_THRESHOLD: u32 = 30 * DAY_LEDGERS;

/// ...and when bumping, aim 120 days out.
///
/// What the network actually allows is a protocol setting that has moved
/// before and is not the same on every network, so [`extend_to`] asks for
/// it rather than this file asserting a figure it cannot check.
const TTL_EXTEND: u32 = 120 * DAY_LEDGERS;

/// The extension to request: what we want, or the network's ceiling,
/// whichever is lower.
///
/// `extend_ttl` is defined against the live `max_entry_ttl`, so a constant
/// written above it is at best clamped and at worst a comment that lies
/// about how long an entry survives.
fn extend_to(e: &Env) -> u32 {
    let max = e.storage().max_ttl();
    if TTL_EXTEND < max {
        TTL_EXTEND
    } else {
        max
    }
}

/// The threshold to bump at, never above the extension we could reach.
fn threshold(e: &Env) -> u32 {
    let to = extend_to(e);
    if TTL_THRESHOLD < to {
        TTL_THRESHOLD
    } else {
        to
    }
}

/// The least life any record is left with by a call that touches it.
///
/// Not a top-up to [`TTL_EXTEND`]: a note's life is the holder's
/// choice ([`KenterMint::bump_token`]), and guessing it on their
/// behalf would make `register_token` ~90% prepaid rent for a note
/// that might be redeemed next week. This is only a floor, so a spend
/// cannot leave a record a day from archival, and a node's earnings
/// are not left to expire between prints.
///
/// Usually free. A newly written persistent entry already gets
/// `min_persistent_ttl` from the network -- 120,960 ledgers on
/// Stellar testnet and mainnet, well above this -- so the bump is a
/// no-op there and does something only where the network minimum is
/// smaller. A contract cannot read that setting, hence a floor rather
/// than an assumption.
const MIN_LIVE_LEDGERS: u32 = 7 * DAY_LEDGERS;

/// How long a print slot has to stay readable.
///
/// A slot lives from `request_print` until `register_token` deletes it
/// -- seconds, typically -- but it has to survive long enough for an
/// abandoned print to be cancelled or cleared, which is
/// `max_print_ledgers`. A day of margin covers the gap between a slot
/// expiring and someone noticing.
///
/// Not [`TTL_EXTEND`]: 120 days would make ~96% of `request_print`'s
/// cost rent on an entry with a median life under a minute, and rent is
/// not refunded on delete (`docs/LEDGER_COSTS.md`).
///
/// **A fixed end, not a window from now.** The
/// slot and its draw live until `created_at + max_print_ledgers + 1 day`,
/// and this is how many ledgers are left until then, clamped to the
/// network's `max_entry_ttl`. Extending to "a window from now" on every
/// write would make a write late in the window pay rent on the whole draw for
/// every ledger since the last write, not only on its own bytes. With a
/// fixed end, an extension after the first finds the entry already there
/// and does nothing; only a window longer than `max_entry_ttl` ever
/// extends again.
fn slot_ttl(e: &Env, created_at: u32, max_print_ledgers: u32) -> u32 {
    let end = created_at
        .saturating_add(max_print_ledgers)
        .saturating_add(DAY_LEDGERS);
    let left = end.saturating_sub(e.ledger().sequence());
    let max = e.storage().max_ttl();
    if left < max {
        left
    } else {
        max
    }
}

/// What a keeper's `bump` tops entries up to: anything not already at
/// the ceiling.
///
/// `extend_ttl` does nothing when an entry's remaining life is at or
/// above the threshold it is given. A threshold one ledger below the
/// ceiling therefore means a keeper pays for exactly the time that has
/// passed since it last called, and pays nothing at all if it calls
/// twice in the same ledger.
fn keeper_threshold(e: &Env) -> u32 {
    extend_to(e).saturating_sub(1)
}

const KENTMINT: Symbol = symbol_short!("KNTRMINT");
const DOMAIN_TAG: &[u8] = b"kntr_v1:redeem:key";

// Spend-mode domain tags — MUST byte-match `kenter_crypto::domain` so client
// signatures/commitments verify here. See `docs/architecture/spend-mode.md`.
const SPEND_OWNER_COMMIT: &[u8] = b"kntr_v1:spend:owner";
const SPEND_AUTH: &[u8] = b"kntr_v1:spend:auth";
const SPEND_REDEEM: &[u8] = b"kntr_v1:spend:redeem";

/// Domain tag for the Path B claim signature.
const CLAIM_TAG: &[u8] = b"kntr_v1:redeem:claim";

// ── Node selection (`docs/architecture/node-selection.md`) ──

/// Domain tag for a slot's selection seed.
const SELECT_TAG: &[u8] = b"kenter:select:v1";

/// Domain tag for a seed set by `seed_fallback`. Distinct from
/// `SELECT_TAG`, so a fallback seed can never equal a beacon seed.
const FALLBACK_TAG: &[u8] = b"kenter:select:fallback:v1";

/// The shortest `fallback_delay` a deployment may choose, in seconds.
///
/// The fallback seed is known from the moment a slot is requested, so if
/// it became usable as soon as round `R` is due, whoever preferred it
/// could post it in the same ledger as the round and win the race about
/// half the time: the draw would be steerable whenever the beacon is up.
/// Five minutes is about sixty ledgers in which the round, once out, can
/// be posted first; daemons post it within seconds.
const MIN_FALLBACK_DELAY: u64 = 300;

/// The beacon scheme's hash-to-curve tag: drand `bls-unchained-g1-rfc9380`
/// (quicknet), RFC 9380 on G1. Part of the scheme, not of the chain, so it
/// is fixed here rather than taken as a parameter.
const BEACON_DST: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";

/// The negated G2 generator, uncompressed. A constant of the curve; the
/// beacon check is `e(sig, -g2) * e(H(m), pk) == 1`. Checked against
/// arkworks' generator in `contracts/drand-spike`, which measured this
/// verification at 27.6M instructions on the real wasm and 28.2M
/// simulated on testnet.
const NEG_G2: [u8; 192] = [
    0x13, 0xe0, 0x2b, 0x60, 0x52, 0x71, 0x9f, 0x60, 0x7d, 0xac, 0xd3, 0xa0,
    0x88, 0x27, 0x4f, 0x65, 0x59, 0x6b, 0xd0, 0xd0, 0x99, 0x20, 0xb6, 0x1a,
    0xb5, 0xda, 0x61, 0xbb, 0xdc, 0x7f, 0x50, 0x49, 0x33, 0x4c, 0xf1, 0x12,
    0x13, 0x94, 0x5d, 0x57, 0xe5, 0xac, 0x7d, 0x05, 0x5d, 0x04, 0x2b, 0x7e,
    0x02, 0x4a, 0xa2, 0xb2, 0xf0, 0x8f, 0x0a, 0x91, 0x26, 0x08, 0x05, 0x27,
    0x2d, 0xc5, 0x10, 0x51, 0xc6, 0xe4, 0x7a, 0xd4, 0xfa, 0x40, 0x3b, 0x02,
    0xb4, 0x51, 0x0b, 0x64, 0x7a, 0xe3, 0xd1, 0x77, 0x0b, 0xac, 0x03, 0x26,
    0xa8, 0x05, 0xbb, 0xef, 0xd4, 0x80, 0x56, 0xc8, 0xc1, 0x21, 0xbd, 0xb8,
    0x13, 0xfa, 0x4d, 0x4a, 0x0a, 0xd8, 0xb1, 0xce, 0x18, 0x6e, 0xd5, 0x06,
    0x17, 0x89, 0x21, 0x3d, 0x99, 0x39, 0x23, 0x06, 0x6d, 0xdd, 0xaf, 0x10,
    0x40, 0xbc, 0x3f, 0xf5, 0x9f, 0x82, 0x5c, 0x78, 0xdf, 0x74, 0xf2, 0xd7,
    0x54, 0x67, 0xe2, 0x5e, 0x0f, 0x55, 0xf8, 0xa0, 0x0f, 0xa0, 0x30, 0xed,
    0x0d, 0x1b, 0x3c, 0xc2, 0xc7, 0x02, 0x78, 0x88, 0xbe, 0x51, 0xd9, 0xef,
    0x69, 0x1d, 0x77, 0xbc, 0xb6, 0x79, 0xaf, 0xda, 0x66, 0xc7, 0x3f, 0x17,
    0xf9, 0xee, 0x38, 0x37, 0xa5, 0x50, 0x24, 0xf7, 0x8c, 0x71, 0x36, 0x32,
    0x75, 0xa7, 0x5d, 0x75, 0xd8, 0x6b, 0xab, 0x79, 0xf7, 0x47, 0x82, 0xaa,
];

/// The smallest `min_pairs` a deployment may choose.
///
/// A print is the depositor's opening pair, at least one node pair, and
/// the depositor's closing pair. The end pairs are exempt from the
/// distinctness and roster checks, so the floor is what guarantees a
/// print always contains a pair that is neither.
const MIN_ALLOWED_PAIRS: u32 = 3;

/// The largest `max_pairs` a deployment may choose.
///
/// **Set by what a holder can carry and back up, not by the CPU
/// budget.** A note the holder cannot keep on a card or restore from
/// paper is a note this product cannot honour its promise about, and
/// that binds long before verification cost does. At 12 pairs
/// (`docs/architecture/custody.md`, `backup.rs`):
///
/// - a note's container is 4172 B, which is 17 of the card's 217
///   blocks, so a card holds about 12 such notes -- against 31 at the
///   three pairs a print actually uses;
/// - sealed for paper it is 4212 B, which is 5 QR symbols, and the
///   chunks of one note carry **no redundancy between them**, so all
///   five must read or the note is lost.
///
/// The CPU budget is nowhere near. Path B verification costs roughly
/// `1.6M + 3.81M · pairs` instructions on a network -- measured
/// against testnet, the dearer of the two cost tables, not derived --
/// so 12 pairs lands near 47M against a `tx_max_instructions` of
/// 400,000,000 on both testnet and mainnet as measured. That is 12%.
/// The budget would permit about 52.
///
/// Two tempting bounds do not apply. The SDK's test default of 100M
/// instructions is not any network's limit, so a ceiling derived from it
/// overstates the cost about fourfold. And the card has no per-note size
/// ceiling: its store is 217 shared blocks, so a larger note is accepted
/// and simply costs the holder notes (seven to a card at 24 pairs).
///
/// 12 is chosen as the largest count the custody and paper
/// paths serve without degrading, and it is a ceiling rather than a
/// target: mainnet ships `max_pairs = 8`. Extra pairs do not
/// strengthen a note against the node network, because the depositor
/// holds the first and last pair at any `n` and never serves those
/// shards, so no coalition of interior nodes can compose the secret.
/// They cost fees, latency, stall risk, ~290 bytes, one more QR every
/// three pairs, and ~3.81M instructions each.
///
/// A note above what a network can verify can only be redeemed
/// through Path A and the node network, which is precisely the
/// dependency Path B was chosen to avoid -- and the mint cannot be
/// changed to stop issuing them. That is why the ceiling is here and
/// not in a deploy script: the script checks the live cost table and
/// can refuse a configuration, but only this constant travels with
/// the wasm.
const MAX_REDEEMABLE_PAIRS: u32 = 12;

/// Where the fees a settlement took out of an escrow went.
///
/// `credited` landed in nodes' `Accrued` balances; `burned` was a
/// volunteer's and was destroyed. The
/// escrow is reduced by both.
#[derive(Default)]
struct FeeSplit {
    credited: i128,
    burned: i128,
}

impl FeeSplit {
    fn total(&self) -> i128 {
        self.credited + self.burned
    }
}

#[contract]
pub struct KenterMint;

#[contractimpl]
impl KenterMint {
    /// All monetary parameters are immutable after construction.
    /// No admin keys, no upgrade path, no fund withdrawal.
    pub fn __constructor(
        e: Env,
        node_fee: u32,
        min_pairs: u32,
        max_pairs: u32,
        pay_token: Address,
        roster: Address,
        max_print_ledgers: u32,
        selection: SelectionConfig,
    ) {
        // A mint has no admin, no upgrade path and no way to change these
        // afterwards, so a deployment that cannot mint stays that way. The
        // combinations below are not edge cases to be tolerated -- each one
        // makes `request_print` or `confirm_link` unreachable for every
        // caller forever, and the only cure is a new address.
        if min_pairs < MIN_ALLOWED_PAIRS || max_pairs < min_pairs {
            // A print is the depositor's opening pair, at least one node
            // pair, and the depositor's closing pair. Below three there
            // is no interior pair at all -- and since the two end pairs
            // are the depositor's own and exempt from the distinctness
            // and roster checks, a two-pair print would be exempt end to
            // end: a self-print with no node in it, which is the thing
            // those checks exist to prevent.
            //
            // It also excludes `min_pairs = 1`, where one node would hold
            // every shard of the chain and could compose the ephemeral
            // secret alone.
            //
            // An upper bound under the lower one admits no count at all.
            panic_with_error!(&e, Error::InvalidConfig);
        }
        if max_print_ledgers == 0 {
            // Every slot would be expired in the ledger that created it.
            panic_with_error!(&e, Error::InvalidConfig);
        }
        if max_pairs > MAX_REDEEMABLE_PAIRS {
            // A print above this mints a note Path B cannot verify
            // inside the instruction budget. Such a note is still
            // redeemable through Path A, which needs the node network
            // -- so the mint would be issuing notes that forfeit the
            // one property Path B exists to provide, with no way to
            // change its mind afterwards.
            panic_with_error!(&e, Error::InvalidConfig);
        }
        // Selection. Each of these, wrong, makes every
        // print unreachable: a zero period divides by zero in every
        // request, a zero lead lets the depositor know the draw, a zero
        // window or timeout closes before anyone can act, and a window at
        // or past the print deadline expires every slot before its claims.
        if selection.beacon_period == 0
            || selection.beacon_lead == 0
            || selection.claim_window == 0
            || selection.serve_timeout == 0
            || selection.claim_window >= max_print_ledgers
        {
            panic_with_error!(&e, Error::InvalidConfig);
        }
        // A short fallback delay makes every draw steerable, not only
        // those during an outage (`MIN_FALLBACK_DELAY`). A long one only
        // lets slots expire before the fallback opens, which is today's
        // behaviour without it, so the upper bound is the deploy
        // script's to check against the print window.
        if selection.fallback_delay < MIN_FALLBACK_DELAY {
            panic_with_error!(&e, Error::InvalidConfig);
        }
        // The identity is in the subgroup, and under it the identity
        // signature verifies for every round, so anyone could seed any slot
        // with a value of their choosing. Its
        // encoding is the infinity flag and nothing else.
        let mut identity = [0u8; 192];
        identity[0] = 0x40;
        if selection.beacon_pk.to_array() == identity {
            panic_with_error!(&e, Error::InvalidConfig);
        }
        // A key off the curve traps here; one off the subgroup is refused.
        // Either way no signature could ever verify against it.
        if !e
            .crypto()
            .bls12_381()
            .g2_is_in_subgroup(&G2Affine::from_bytes(selection.beacon_pk.clone()))
        {
            panic_with_error!(&e, Error::InvalidConfig);
        }

        let config = MintConfig {
            symbol: KENTMINT,
            node_fee,
            min_pairs,
            max_pairs,
            pay_token,
            roster,
            max_print_ledgers,
            start_ledger: e.ledger().sequence(),
            selection,
        };

        e.storage().persistent().set(&DataKey::Config, &config);
        e.storage().persistent().set(&DataKey::NextSlotId, &0_u32);
    }

    // ── Print Request ──

    /// Reserve a slot and escrow the deposit, naming only the depositor's
    /// own two end pairs. The interior is chosen by the draw:
    /// `seed_print`, then `claim_position`.
    pub fn request_print(
        e: Env,
        caller: Address,
        event_id: BytesN<32>,
        amount: i128,
        total_pairs: u32,
        first_pair: PairEntry,
        last_pair: PairEntry,
    ) -> Result<u32, Error> {
        caller.require_auth();

        let config = Self::get_config(&e);

        if total_pairs < config.min_pairs || total_pairs > config.max_pairs {
            return Err(Error::InvalidPairCount);
        }

        if amount <= 0 {
            return Err(Error::InvalidAmount);
        }

        // Verify total fees don't exceed deposit.
        //
        // Only the interior pairs are paid: the depositor's two end
        // pairs do no node work and are not credited, so charging for
        // them here would reserve money nobody ever receives.
        //
        // The same reserve covers abandoning the print after its draw.
        // Settlement then pays at most one fee per confirmed interior link
        // and forfeits two per unconfirmed position, so it never exceeds
        // `2 * node_fee * k`. Skips are
        // paid by the depositor when made, not from the escrow, so they
        // need no reserve of their own.
        let paid_pairs = (total_pairs as i128) - 2;
        let total_fees = (config.node_fee as i128) * 2 * paid_pairs;
        if total_fees >= amount {
            return Err(Error::InvalidAmount);
        }

        // An event_id is how every off-chain party names a print. Two
        // prints answering to one name is a reconciliation problem with no
        // fix after the fact.
        //
        // Squatting an id is possible and cheap -- a cancel before the
        // seed is a full refund, so burning someone's `event_id` costs a
        // transaction fee. It needs a same-ledger front-run: the id is
        // first revealed in the victim's own `request_print`, before any
        // network contact, and the victim loses nothing but a retry with
        // a fresh id. Left open deliberately; the alternative is a
        // commit-reveal on a value whose only job is to be unique.
        if e.storage()
            .persistent()
            .has(&DataKey::EventIdUsed(event_id.clone()))
        {
            return Err(Error::EventIdInUse);
        }

        // **The end pairs are the depositor's own, and exempt** from the
        // roster and distinctness checks every interior pair passes in
        // `claim_position`. The rule buys nothing there: the depositor
        // holds both end pairs by construction, so repeating one key
        // across them costs only the depositor, who is the honest party at
        // both ends. Applied to those four slots it would demand four
        // funded, roster-joined, separately bonded accounts before anyone
        // could print their own note.
        //
        // **The exemption is positional, not an identity check.** This
        // contract cannot tell that the end pairs belong to the caller; it
        // only declines to check them. That is safe because the depositor
        // names the end pairs and nothing else: interior positions are
        // filled only by the draw, so no caller can place anyone there,
        // and no claim can reach an end one.
        //
        // Every slot is still checked against this contract's own address.
        // An end pair draws no fee and an interior one must pass the
        // roster, but both of those are facts about other code, and the
        // contract is immutable -- so the invariant is stated here.
        for who in [
            &first_pair.node_a,
            &first_pair.node_b,
            &last_pair.node_a,
            &last_pair.node_b,
        ] {
            Self::reject_self(&e, who)?;
        }

        // Transfer deposit to escrow
        let client = token::Client::new(&e, &config.pay_token);
        client.transfer(&caller, &e.current_contract_address(), &amount);

        // Allocate slot
        // The constructor writes this, so it is never legitimately
        // absent -- and `unwrap_or(0)` would read a missing counter as
        // "start issuing ids from zero", which is the one
        // interpretation that silently reissues ids already spent.
        //
        // `Slot` and `Token` are both deleted once a note is settled, so
        // nothing would catch a reissued id, and duplicate ids across the
        // history are unfixable after the fact. Trap instead.
        let slot_id: u32 = e
            .storage()
            .persistent()
            .get(&DataKey::NextSlotId)
            .expect("NextSlotId is written by the constructor");
        e.storage()
            .persistent()
            // Traps at `u32::MAX` under `overflow-checks`, which is the
            // right failure: prints stop, and every note already printed
            // stays redeemable. Four billion prints is not a reachable
            // number, and silently wrapping to slot 0 -- whose record
            // still exists and is the nullifier -- would be far worse
            // than refusing.
            .set(&DataKey::NextSlotId, &(slot_id + 1));

        // The round that will seed this slot. It does not exist yet: the
        // lead puts it `beacon_lead` periods after this ledger's close
        // time, so nobody -- the depositor included -- can compute the
        // draw when the request is made.
        let sel = &config.selection;
        let beacon_round =
            Self::round_at(sel, e.ledger().timestamp()).saturating_add(sel.beacon_lead);

        let now = e.ledger().sequence();
        let slot = PrintSlot {
            slot_id,
            depositor: caller.clone(),
            event_id: event_id.clone(),
            amount,
            total_pairs,
            pairs: vec![&e, first_pair.clone(), last_pair.clone()],
            completed_links: 0,
            partial_keys: Vec::new(&e),
            confirmers: Vec::new(&e),
            volunteers: 0,
            state: TokenState::Printing,
            created_at: now,
            beacon_round,
            seed: None,
            claim_deadline: 0,
            claims: Vec::new(&e),
            closed: false,
            last_progress: now,
            filled: false,
            lapsed: false,
        };

        // The slot is two entries: the
        // escrow core, persistent and fixed in size from here on, and the
        // draw, temporary, which is all that grows. Both get the print
        // window, not 120 days; on mainnet the core gets 120 days anyway,
        // and pays it once, here.
        Self::save_slot(&e, &slot, &config);

        e.storage()
            .persistent()
            .set(&DataKey::EventIdUsed(event_id.clone()), &slot_id);

        Self::bump_key(&e, &DataKey::NextSlotId, threshold(&e));

        // `EventIdUsed` is not bumped at all. It has to answer forever,
        // which no bump achieves -- nothing re-extends it after this
        // call, so any finite TTL expires and leaves the same archived
        // entry. It is read only when someone reuses an event id, and
        // protocol 23 restores it automatically for that check, so
        // paying 0.0223 XLM here buys 120 days of marginally cheaper
        // refusal for a question almost nobody asks.

        e.events().publish(
            (symbol_short!("PRINT"), symbol_short!("request")),
            PrintRequestEvent {
                slot_id,
                event_id,
                amount,
                total_pairs,
                first_pair,
                last_pair,
                depositor: caller,
                beacon_round,
            },
        );

        Ok(slot_id)
    }

    // ── Selection ──

    /// Seed a slot with its beacon round's signature. Anyone may call it:
    /// a BLS signature is unique, so whoever posts it has nothing to
    /// choose, and withholding it only delays the print.
    ///
    /// `signature` is the round's G1 signature, uncompressed. A point off
    /// the curve or outside the subgroup traps in the host before any
    /// pairing; a valid point that is not this round's signature is
    /// `BadBeacon`.
    pub fn seed_print(e: Env, slot_id: u32, signature: BytesN<96>) -> Result<BytesN<32>, Error> {
        let mut slot = Self::live_slot(&e, slot_id)?;
        let config = Self::get_config(&e);
        if slot.seed.is_some() {
            return Err(Error::AlreadySeeded);
        }
        if !Self::beacon_verifies(&e, &config.selection, slot.beacon_round, &signature) {
            return Err(Error::BadBeacon);
        }

        // The mint and the slot are mixed in so two prints seeded by one
        // round do not share a draw.
        let mut m = Bytes::from_slice(&e, SELECT_TAG);
        m.append(&e.current_contract_address().to_xdr(&e));
        m.extend_from_array(&slot_id.to_be_bytes());
        m.extend_from_array(&e.crypto().sha256(&signature.into()).to_array());
        let seed = e.crypto().sha256(&m).to_bytes();

        Self::set_seed(&e, &mut slot, &config, seed.clone());
        Ok(seed)
    }

    /// Seed a slot the beacon never seeded, once its round has been due for
    /// `fallback_delay` seconds. Anyone may call it, and the seed is fixed
    /// by the slot, so the caller has nothing to choose.
    ///
    /// **This keeps issuance alive if drand stops**, for minutes or for
    /// good; without it every print would wait out its window and be
    /// refunded. The price is that the fallback seed is computable from
    /// the request onward: while the beacon is down, a depositor can pick
    /// the moment they request, and so their draw. That buys fee capture,
    /// the same as steering always did (`docs/architecture/
    /// node-selection.md`), never another holder's funds. While the beacon
    /// is up, round `R` is posted long before the fallback opens, so the
    /// fallback is never used.
    ///
    /// Everything after the seed is unchanged: claims, the window, and the
    /// forfeit, which treats a fallback-seeded slot as seeded.
    pub fn seed_fallback(e: Env, slot_id: u32) -> Result<BytesN<32>, Error> {
        let mut slot = Self::live_slot(&e, slot_id)?;
        let config = Self::get_config(&e);
        if slot.seed.is_some() {
            return Err(Error::AlreadySeeded);
        }
        let opens = Self::round_time(&config.selection, slot.beacon_round)
            .saturating_add(config.selection.fallback_delay);
        if e.ledger().timestamp() < opens {
            return Err(Error::FallbackNotReady);
        }

        let mut m = Bytes::from_slice(&e, FALLBACK_TAG);
        m.append(&e.current_contract_address().to_xdr(&e));
        m.extend_from_array(&slot_id.to_be_bytes());
        m.extend_from_array(&slot.beacon_round.to_be_bytes());
        let seed = e.crypto().sha256(&m).to_bytes();

        e.events().publish(
            (symbol_short!("PRINT"), symbol_short!("fallback")),
            PrintFallbackEvent {
                slot_id,
                beacon_round: slot.beacon_round,
            },
        );
        Self::set_seed(&e, &mut slot, &config, seed.clone());
        Ok(seed)
    }

    /// Claim an interior position for the pair `(node_a, node_b)`.
    ///
    /// Both members sign: otherwise anyone could enter an honest pair into
    /// a print it never agreed to serve. The score is
    /// computed here from the seed and the pair, so it cannot be chosen,
    /// and a later claim with a lower score displaces a higher one until
    /// selection closes -- being first earns nothing.
    ///
    /// Returns the claim's rank, 0 being the lowest score so far.
    pub fn claim_position(
        e: Env,
        slot_id: u32,
        node_a: Address,
        node_b: Address,
    ) -> Result<u32, Error> {
        // A pair of one address is refused before asking for the second
        // signature, which would be the same signature twice.
        node_a.require_auth();
        if node_a == node_b {
            return Err(Error::NodesNotDistinct);
        }
        node_b.require_auth();

        let mut slot = Self::live_slot(&e, slot_id)?;
        let config = Self::get_config(&e);
        let Some(seed) = slot.seed.clone() else {
            return Err(Error::NotSeeded);
        };
        let k = slot.total_pairs - 2;
        // After the window, claims are taken only to fill positions still
        // empty, so an overestimated roster costs time and not the print.
        // Once full, the set is fixed, and anyone can read
        // the positions off it before the first interior link.
        if slot.closed || (e.ledger().sequence() > slot.claim_deadline && slot.claims.len() >= k) {
            return Err(Error::ClaimsClosed);
        }

        Self::reject_self(&e, &node_a)?;
        Self::reject_self(&e, &node_b)?;

        // Every interior node on the roster, and no node twice anywhere in
        // the print.
        //
        // Distinctness is the property that makes a pair a pair. A shard
        // takes both halves of a link to produce, so a link whose two
        // nodes are one address is a shard one operator holds alone, and
        // a print whose every pair is that same operator is a chain with
        // a single point of trust wearing the shape of many. Nothing
        // downstream can tell the difference: the links are well-formed,
        // the signatures verify, the chain hashes. That is a claim about
        // how many independent parties a chain really has -- not a theft
        // vector, because no coalition of nodes can compose the ephemeral
        // secret without the depositor's two shards (see
        // `docs/architecture/security-model.md`).
        //
        // A claim must differ from the end pairs as well as from the other
        // claims. Otherwise the depositor's own keys could take an
        // interior position too, and the pair count would overstate the
        // independent parties.
        //
        // Every claim ever accepted stays in the list or was displaced by
        // a lower score, and a displaced pair cannot come back -- its
        // score is fixed and the list only gets more competitive -- so
        // checking the list as it stands is checking every pair that can
        // still be selected.
        if node_a == node_b {
            return Err(Error::NodesNotDistinct);
        }
        let taken = |x: &Address, p: &PairEntry| *x == p.node_a || *x == p.node_b;
        for p in slot.pairs.iter() {
            if taken(&node_a, &p) || taken(&node_b, &p) {
                return Err(Error::NodesNotDistinct);
            }
        }
        for c in slot.claims.iter() {
            if taken(&node_a, &c.pair) || taken(&node_b, &c.pair) {
                return Err(Error::NodesNotDistinct);
            }
        }

        // Membership and terms in one call per node.
        let volunteer_a = Self::roster_node_terms(&e, &config.roster, &node_a)
            .ok_or(Error::NodeNotOnRoster)?;
        let volunteer_b = Self::roster_node_terms(&e, &config.roster, &node_b)
            .ok_or(Error::NodeNotOnRoster)?;

        // A freshly bought fleet waits before it can be drawn.
        let min_age = config.selection.min_node_age;
        if min_age > 0 {
            let now = e.ledger().sequence();
            for n in [&node_a, &node_b] {
                let joined = Self::roster_joined_at(&e, &config.roster, n)
                    .ok_or(Error::NodeNotOnRoster)?;
                if now.saturating_sub(joined) < min_age {
                    return Err(Error::NodeTooNew);
                }
            }
        }

        // A registered pair, registered before this slot was requested.
        // The round is fixed at request, so a pair
        // registered earlier was fixed before anyone could know the seed:
        // an operator cannot try its addresses in every combination
        // against the draw and claim with the best. Re-pairing still works,
        // but only for prints requested after it.
        let registered = |me: &Address, partner: &Address| {
            e.storage()
                .persistent()
                .get::<DataKey, RegisteredPair>(&DataKey::PairOf(me.clone()))
                .is_some_and(|r| r.partner == *partner && r.registered_at < slot.created_at)
        };
        if !registered(&node_a, &node_b) || !registered(&node_b, &node_a) {
            return Err(Error::PairNotRegistered);
        }
        // An active pair keeps its registration alive; usually a no-op.
        Self::bump_key(&e, &DataKey::PairOf(node_a.clone()), threshold(&e));
        Self::bump_key(&e, &DataKey::PairOf(node_b.clone()), threshold(&e));

        let score = Self::score(&e, &seed, &node_a, &node_b);

        // Insert in score order, after any equal score: ties go to the
        // earlier claim, which is the only order left to break them by,
        // and a 256-bit tie is not a case anyone will meet.
        let cap = 2 * k;
        let mut rank = slot.claims.len();
        for (i, c) in slot.claims.iter().enumerate() {
            if score < c.score {
                rank = i as u32;
                break;
            }
        }
        if rank >= cap {
            return Err(Error::ClaimNotCompetitive);
        }
        let pair = PairEntry {
            node_a: node_a.clone(),
            node_b: node_b.clone(),
        };
        slot.claims.insert(
            rank,
            Claim {
                score: score.clone(),
                pair: pair.clone(),
                volunteer_a,
                volunteer_b,
            },
        );
        if slot.claims.len() > cap {
            slot.claims.pop_back();
        }
        // The list never drops below `k` once there, until it closes, so
        // this is set once and stays true. The forfeit reads it from the
        // core, which outlives the draw.
        if slot.claims.len() >= k {
            slot.filled = true;
        }
        // A claim that fills a short list after the deadline is what fixes
        // the positions, so position 1's serve clock starts here (see
        // `close_selection`).
        slot.last_progress = e.ledger().sequence();
        Self::save_slot(&e, &slot, &config);

        e.events().publish(
            (symbol_short!("PRINT"), symbol_short!("claim")),
            ClaimEvent {
                slot_id,
                pair,
                score,
                rank,
            },
        );
        Ok(rank)
    }

    /// Register `(node_a, node_b)` as a pair, so it may claim positions on
    /// prints requested from the next ledger on.
    ///
    /// Both sign; both must be selectable on the roster and old enough
    /// (`min_node_age`); and each address is in at most one registered
    /// pair, so a set of addresses cannot be re-combined per draw. Returns
    /// the registration ledger.
    pub fn register_pair(e: Env, node_a: Address, node_b: Address) -> Result<u32, Error> {
        node_a.require_auth();
        if node_a == node_b {
            return Err(Error::NodesNotDistinct);
        }
        node_b.require_auth();
        Self::reject_self(&e, &node_a)?;
        Self::reject_self(&e, &node_b)?;
        let config = Self::get_config(&e);
        for n in [&node_a, &node_b] {
            Self::roster_node_terms(&e, &config.roster, n).ok_or(Error::NodeNotOnRoster)?;
        }
        let now = e.ledger().sequence();
        let min_age = config.selection.min_node_age;
        if min_age > 0 {
            for n in [&node_a, &node_b] {
                let joined = Self::roster_joined_at(&e, &config.roster, n)
                    .ok_or(Error::NodeNotOnRoster)?;
                if now.saturating_sub(joined) < min_age {
                    return Err(Error::NodeTooNew);
                }
            }
        }
        for n in [&node_a, &node_b] {
            if e.storage().persistent().has(&DataKey::PairOf(n.clone())) {
                return Err(Error::AlreadyPaired);
            }
        }
        for (me, partner) in [(&node_a, &node_b), (&node_b, &node_a)] {
            let key = DataKey::PairOf(me.clone());
            e.storage().persistent().set(
                &key,
                &RegisteredPair {
                    partner: partner.clone(),
                    registered_at: now,
                },
            );
            Self::bump_key(&e, &key, threshold(&e));
        }
        Self::bump_instance(&e, threshold(&e));
        e.events().publish(
            (symbol_short!("PAIR"), symbol_short!("register")),
            PairEvent {
                node_a,
                node_b,
                registered: true,
            },
        );
        Ok(now)
    }

    /// Dissolve the caller's registered pair. Either member may; the
    /// partner's record goes too. Returns the former partner.
    pub fn unpair(e: Env, caller: Address) -> Result<Address, Error> {
        caller.require_auth();
        let rec: RegisteredPair = e
            .storage()
            .persistent()
            .get(&DataKey::PairOf(caller.clone()))
            .ok_or(Error::NotPaired)?;
        e.storage().persistent().remove(&DataKey::PairOf(caller.clone()));
        e.storage()
            .persistent()
            .remove(&DataKey::PairOf(rec.partner.clone()));
        e.events().publish(
            (symbol_short!("PAIR"), symbol_short!("unpair")),
            PairEvent {
                node_a: caller,
                node_b: rec.partner.clone(),
                registered: false,
            },
        );
        Ok(rec.partner)
    }

    /// The pair `node` is registered in, if any.
    pub fn pair_of(e: Env, node: Address) -> Option<RegisteredPair> {
        e.storage().persistent().get(&DataKey::PairOf(node))
    }

    /// Replace the selected pair at the next position with the best
    /// runner-up, because it did not confirm within `serve_timeout`.
    ///
    /// **The depositor pays one pair's fee, `2 * node_fee`, burned.** The
    /// contract cannot tell a dead node from a depositor who never sent the
    /// extend request, so skipping has to cost something, or it would be a
    /// free way to steer positions toward one's own runners-up. It is
    /// charged from the depositor rather than the escrow, so the escrow
    /// stays equal to the note's face.
    ///
    /// Returns the position skipped.
    pub fn skip_position(e: Env, caller: Address, slot_id: u32) -> Result<u32, Error> {
        caller.require_auth();

        let mut slot = Self::live_slot(&e, slot_id)?;
        if slot.depositor != caller {
            return Err(Error::NotDepositor);
        }
        let config = Self::get_config(&e);
        Self::close_selection(&e, &mut slot)?;

        let position = slot.completed_links;
        let k = slot.total_pairs - 2;
        if position == 0 || position > k {
            return Err(Error::NotSkippable);
        }
        let now = e.ledger().sequence();
        if now <= slot.last_progress.saturating_add(config.selection.serve_timeout) {
            return Err(Error::ServeTimeoutNotReached);
        }
        let Some(next) = slot.claims.pop_front() else {
            return Err(Error::NoBackup);
        };

        let skipped = slot.pairs.get(position).unwrap();
        slot.pairs.set(position, next.pair.clone());
        let (bit_a, bit_b) = (1u32 << (2 * position), 1u32 << (2 * position + 1));
        slot.volunteers &= !(bit_a | bit_b);
        if next.volunteer_a {
            slot.volunteers |= bit_a;
        }
        if next.volunteer_b {
            slot.volunteers |= bit_b;
        }
        slot.last_progress = now;
        Self::save_slot(&e, &slot, &config);

        let fee = 2 * config.node_fee as i128;
        if fee > 0 {
            let client = token::Client::new(&e, &config.pay_token);
            client.transfer(&caller, &e.current_contract_address(), &fee);
            Self::burn(&e, slot_id, &config.pay_token, fee);
        }

        e.events().publish(
            (symbol_short!("PRINT"), symbol_short!("skip")),
            SkipEvent {
                slot_id,
                position,
                skipped,
                replacement: next.pair,
                fee,
            },
        );
        Ok(position)
    }

    pub fn cancel_print(e: Env, caller: Address, slot_id: u32) -> Result<i128, Error> {
        caller.require_auth();

        let slot = Self::load_slot(&e, slot_id).ok_or(Error::SlotNotFound)?;

        if slot.state != TokenState::Printing {
            return Err(Error::SlotNotPrinting);
        }

        if slot.depositor != caller {
            return Err(Error::NotDepositor);
        }

        // Pay for the links that were actually built, then refund the
        // rest. Abandoning a print is the depositor's right; doing it
        // after the nodes have worked is not free.
        let config = Self::get_config(&e);
        let fees = Self::settle_abandoned_slot(&e, &slot, &config);
        let forfeited = Self::forfeit(&e, &slot, &config, false);
        let refund = slot.amount - fees.total() - forfeited;

        // The print is over, so its record goes -- the same argument as
        // `register_token`, and it holds for an abandoned print exactly
        // as it does for a completed one. Every caller that reads a slot
        // first requires `Printing`, so absence refuses precisely where
        // a `Cancelled` state would: `cancel_print`,
        // `clear_expired_slot`, `register_token` and `confirm_link` all
        // answer `SlotNotFound` rather than `SlotNotPrinting`.
        //
        // Unlike redemption this leaves no marker. A redeemed note needs
        // one because a holder asking "was this spent?" must not be told
        // "no such thing" about a bearer instrument they are holding. An
        // abandoned print has no such holder: the escrow is already
        // settled and refunded, and the depositor's own client scans for
        // slots in `Printing`, which this never was again.
        //
        // `EventIdUsed` is deliberately left behind. A cancelled print
        // does not release its event id -- two prints answering to one
        // name is a reconciliation problem with no fix after the fact --
        // and that guard is a separate entry this does not touch.
        Self::remove_slot(&e, slot_id);

        Self::bump_instance(&e, threshold(&e));
        Self::bump_key(&e, &DataKey::Config, threshold(&e));

        let client = token::Client::new(&e, &config.pay_token);
        client.transfer(&e.current_contract_address(), &slot.depositor, &refund);

        e.events().publish(
            (symbol_short!("PRINT"), symbol_short!("cancel")),
            PrintCancelledEvent {
                slot_id,
                event_id: slot.event_id,
                refund,
                earned: fees.credited,
                burned: fees.burned,
                forfeited,
            },
        );

        Ok(refund)
    }

    // ── Chain Construction ──

    pub fn confirm_link(
        e: Env,
        caller: Address,
        slot_id: u32,
        link_index: u32,
        partial_public_key: BytesN<32>,
    ) -> Result<u32, Error> {
        caller.require_auth();

        let mut slot = Self::load_slot(&e, slot_id).ok_or(Error::SlotNotFound)?;

        if slot.state != TokenState::Printing {
            return Err(Error::SlotNotPrinting);
        }

        // Check expiration
        let config = Self::get_config(&e);
        if e.ledger().sequence() > Self::slot_expires_at(&slot, &config) {
            return Err(Error::SlotExpired);
        }
        if slot.lapsed {
            return Err(Error::DrawLapsed);
        }

        // Must confirm links in order
        if link_index != slot.completed_links {
            return Err(Error::LinkOutOfOrder);
        }

        if link_index >= slot.total_pairs {
            return Err(Error::PrintAlreadyComplete);
        }

        // Every link after the depositor's first waits for the draw. The
        // first interior confirmation is what closes it: the claim set is
        // fixed by then, so this only writes down what anyone could
        // already read off the slot.
        if link_index != 0 {
            Self::close_selection(&e, &mut slot)?;
        }

        // Caller must be one of the assigned pair
        let pair = slot.pairs.get(link_index).unwrap();
        if caller != pair.node_a && caller != pair.node_b {
            return Err(Error::NotAssignedPair);
        }

        // And, for an interior link, must still be on the roster.
        //
        // Membership is checked when a pair claims its position; without
        // this second check, a node that left or unbonded in between would
        // keep its place in the print. Roster membership is what a stake backs:
        // a node with no stake at risk is outside the arrangement that
        // makes misbehaviour cost something, and it should not be
        // building chains in it.
        //
        // The two end links are the depositor's, exempt here for the same
        // reason `request_print` exempts their pairs: the depositor posts
        // no bond and needs none, holding both ends by construction.
        // Checking it here would undo that exemption -- the slot
        // would reserve fine and then stall on its very first link.
        //
        // The price of the check that remains: a node that leaves the roster
        // during a print strands the slot at its link. The depositor
        // skips it for the runner-up (`skip_position`) or cancels, paying
        // settlement for the links already confirmed. The roster has no
        // admin, so only the node itself can do this. Neither redemption nor `claim_fees`
        // consults the roster.
        let is_end_link = link_index == 0 || link_index == slot.total_pairs - 1;
        if !is_end_link && !Self::check_roster_node(&e, &config.roster, &caller) {
            return Err(Error::NodeNotOnRoster);
        }

        // Record partial key and advance
        slot.partial_keys.push_back(partial_public_key.clone());
        slot.confirmers.push_back(caller.clone());
        slot.completed_links += 1;
        // The next position's serve time starts now.
        slot.last_progress = e.ledger().sequence();
        Self::save_slot(&e, &slot, &config);

        e.events().publish(
            (symbol_short!("LINK"), symbol_short!("confirm")),
            LinkConfirmedEvent {
                slot_id,
                link_index,
                completed_links: slot.completed_links,
                confirmer: caller,
                partial_public_key,
            },
        );

        Ok(slot.completed_links)
    }

    // ── Token Registration ──

    pub fn register_token(
        e: Env,
        caller: Address,
        slot_id: u32,
        ephemeral_key: BytesN<32>,
        chain_hash: BytesN<32>,
        mode: TokenMode,
        initial_owner_commitment: BytesN<32>,
        claim_pubkey: BytesN<32>,
    ) -> Result<bool, Error> {
        caller.require_auth();

        let slot = Self::load_slot(&e, slot_id).ok_or(Error::SlotNotFound)?;

        if slot.state != TokenState::Printing {
            return Err(Error::SlotNotPrinting);
        }

        if slot.depositor != caller {
            return Err(Error::NotDepositor);
        }

        if slot.completed_links != slot.total_pairs {
            return Err(Error::PrintNotComplete);
        }

        // An expired slot cannot be registered against.
        //
        // `confirm_link` enforces the deadline; if this did not, a
        // complete-but-expired slot would sit in a race: whoever moved first
        // between the depositor registering and anyone at all calling
        // `clear_expired_slot` would decide whether a note existed. Nobody
        // lost money either way -- the loser's deposit is refunded -- but
        // "did this note get minted" is not a question that should be
        // settled by transaction ordering.
        let config = Self::get_config(&e);
        if e.ledger().sequence() > Self::slot_expires_at(&slot, &config) {
            return Err(Error::SlotExpired);
        }
        // The participants are in the draw.
        if slot.lapsed {
            return Err(Error::DrawLapsed);
        }

        // One record per slot, ever.
        //
        // Not keyed by the caller-supplied `ephemeral_key`: with
        // registration refusing to overwrite, that would be a race. `ek` is
        // the sum of the partial keys `confirm_link` publishes, it is
        // computable by anyone before the depositor's separate
        // `register_token` lands, and "first to name it wins" would let a
        // parked slot claim a victim's key so the victim's print could
        // never be registered.
        //
        // A slot id is issued by this contract, so no caller can collide
        // with another's. Two slots that name the same `ek` are two
        // independent records -- separate escrow, chain hash and claim
        // key -- and a squatter risks only their own deposit, to whoever
        // actually holds that key.
        //
        // A slot cannot be registered twice: this function deletes the
        // slot, and slot ids are never reissued.
        //
        // Belt and braces, and known to be so: the slot checks above
        // already require a `Printing` slot, and this function removes
        // it, so a second registration fails as `SlotNotFound` before
        // reaching here. `TokenExists` is therefore unreachable. It stays
        // because it guards the nullifier directly rather than through
        // an invariant about another key, and on an immutable contract
        // that is the cheaper side to be wrong on.
        if e.storage().persistent().has(&DataKey::Token(slot_id)) {
            return Err(Error::TokenExists);
        }

        // Collect all participants
        let mut participants = Vec::new(&e);
        for i in 0..slot.total_pairs {
            let pair = slot.pairs.get(i).unwrap();
            participants.push_back(pair.node_a.clone());
            participants.push_back(pair.node_b.clone());
        }

        let token = TokenRecord {
            ephemeral_key: ephemeral_key.clone(),
            event_id: slot.event_id.clone(),
            chain_hash,
            slot_id,
            amount: slot.amount,
            node_fee: config.node_fee,
            participants,
            volunteers: slot.volunteers,
            state: TokenState::Active,
            created_at: slot.created_at,
            redeemed_at: 0,
            mode,
            owner_commitment: initial_owner_commitment,
            spend_nonce: 0,
            claim_pubkey,
        };

        e.storage()
            .persistent()
            .set(&DataKey::Token(slot_id), &token);

        // The print is finished, so its working state goes with it.
        //
        // `pairs`, `partial_keys` and `confirmers` are dead to this
        // contract from here: `participants` is already copied into the
        // token, and redemption never reads the slot. It is the
        // largest record a note owns -- 1,132 bytes for a three-pair
        // print, growing with pair count -- and keeping it live for the
        // whole life of the note would hold nothing anyone reads.
        //
        // Deleting it does not weaken the slot. `register_token`
        // requires `Printing` and then finds no slot at all, so a second
        // registration is refused the same way, and `cancel_print` and
        // `clear_expired_slot` likewise refuse with `SlotNotFound`
        // rather than `SlotNotPrinting`.
        //
        // What leaves the live state with it is `partial_keys`, whose
        // job is to let an observer sum them and check the note's key
        // matches its construction. That becomes an events-only query
        // (`LinkConfirmedEvent`), which is weaker for anything older
        // than an indexer's retention. The holder is unaffected: the
        // chain rides in their own container.
        Self::remove_slot(&e, slot_id);

        Self::bump_instance(&e, threshold(&e));
        Self::bump_key(&e, &DataKey::Config, threshold(&e));
        // A floor, not a life. How long this note should stay current is
        // the holder's call -- `bump_token` -- because only they know
        // whether it is being spent this afternoon or held for a year.
        Self::bump_key_to(
            &e,
            &DataKey::Token(slot_id),
            MIN_LIVE_LEDGERS,
            MIN_LIVE_LEDGERS,
        );

        e.events().publish(
            (symbol_short!("TOKEN"), symbol_short!("active")),
            TokenActiveEvent {
                slot_id,
                event_id: slot.event_id,
                ephemeral_key,
                amount: slot.amount,
                depositor: caller,
                mode: token.mode,
                chain_hash: token.chain_hash,
                claim_pubkey: token.claim_pubkey,
            },
        );

        Ok(true)
    }

    // ── Spend (ownership transfer, spend mode) ──

    /// Transfer ownership of a spend-mode token: move the owner pointer to
    /// `new_owner_commitment`, burning the current owner's claim.
    ///
    /// `caller.require_auth()` covers the tx fee only — **ownership is proven by
    /// the Ed25519 owner-key signature, not the tx source**, so any funded
    /// account may relay a spend. The current owner signs
    /// `SHA-256(SPEND_AUTH || contract_xdr || slot_id (u32 BE) ||
    /// ephemeral_key || current_commitment || new_commitment ||
    /// spend_nonce (u32 BE))` — the format in
    /// `docs/architecture/spend-mode.md`, which this must agree with letter
    /// for letter; a signer that signs the digest blind relies on it.
    ///
    /// Each field earns its place. Both commitments stop the spend being
    /// replayed against a moved state and stop an observer swapping the
    /// successor; the nonce makes the authorisation good for exactly one
    /// transfer, which the commitments alone do not, because a note that
    /// returns to a commitment it held before reproduces the old digest;
    /// the contract address stops a signature crossing deployments; the
    /// slot is the record's real key, so a signature made for one record
    /// cannot verify against another naming the same `ephemeral_key`. A
    /// second spend of the same state also fails the opening check, the
    /// live commitment now being the successor's.
    pub fn spend(
        e: Env,
        caller: Address,
        slot_id: u32,
        current_owner_pubkey: BytesN<32>,
        new_owner_commitment: BytesN<32>,
        signature: BytesN<64>,
    ) -> Result<(), Error> {
        caller.require_auth();

        // A redeemed note has no record at all -- redemption removes it
        // (see `DataKey::Redeemed`). Absence is what refuses the second
        // attempt; the marker only separates "already redeemed" from
        // "no such slot", so the caller is told which mistake they made.
        let mut token: TokenRecord = match e
            .storage()
            .persistent()
            .get(&DataKey::Token(slot_id))
        {
            Some(t) => t,
            None => {
                return Err(
                    if e.storage().persistent().has(&DataKey::Redeemed(slot_id)) {
                        Error::AlreadyRedeemed
                    } else {
                        Error::TokenNotFound
                    },
                )
            }
        };

        // Read from the record, never from the caller: the slot id is
        // what names a note, and the key it was registered with is
        // whatever that slot registered.
        let ephemeral_key = token.ephemeral_key.clone();

        if token.mode != TokenMode::Spend {
            return Err(Error::NotSpendMode);
        }
        if token.state != TokenState::Active {
            if token.state == TokenState::Redeemed {
                return Err(Error::AlreadyRedeemed);
            }
            return Err(Error::TokenNotActive);
        }

        // The revealed key must open the live commitment (proves current ownership).
        if Self::owner_commit(&e, &current_owner_pubkey) != token.owner_commitment {
            return Err(Error::OwnerCommitmentMismatch);
        }

        // Verify the owner authorized THIS transition. The signature covers the
        // 32-byte digest M = SHA-256(message), not the message itself, so that a
        // Keycard (whose signHash takes 32 bytes) and the software wallet produce
        // interchangeable signatures. ed25519_verify traps on a bad signature
        // (the tx reverts).
        // The nonce makes a signature good for one transfer only. Without
        // it the digest (ek, current, new) would repeat the moment a note
        // returns to a commitment it held before -- and the static pay
        // tag at owner index 0 is a reusable address, so a note coming
        // back as change or a refund does precisely that. The earlier
        // signature would then replay and a former payee could take the
        // note back.
        //
        // The contract address is in it too, so a signature cannot be
        // used against another deployment holding the same note.
        let mut msg = Bytes::new(&e);
        msg.extend_from_slice(SPEND_AUTH);
        msg.append(&e.current_contract_address().to_xdr(&e));
        msg.extend_from_array(&slot_id.to_be_bytes());
        msg.extend_from_array(&ephemeral_key.to_array());
        msg.extend_from_array(&token.owner_commitment.to_array());
        msg.extend_from_array(&new_owner_commitment.to_array());
        msg.extend_from_array(&token.spend_nonce.to_be_bytes());
        let digest: BytesN<32> = e.crypto().sha256(&msg).into();
        let signed = Bytes::from_array(&e, &digest.to_array());
        e.crypto()
            .ed25519_verify(&current_owner_pubkey, &signed, &signature);

        // Move the pointer (O(1) overwrite) and record the transfer.
        // Advancing the nonce is what spends the signature: the digest it
        // was made over can never be the live one again.
        token.owner_commitment = new_owner_commitment.clone();
        token.spend_nonce += 1;
        e.storage()
            .persistent()
            .set(&DataKey::Token(slot_id), &token);

        // No `Config` bump, and that is deliberate: this path never
        // reads it. The rule is bump what you read.
        Self::bump_instance(&e, threshold(&e));
        Self::bump_key_to(
            &e,
            &DataKey::Token(slot_id),
            MIN_LIVE_LEDGERS,
            MIN_LIVE_LEDGERS,
        );

        e.events().publish(
            (symbol_short!("SPEND"), symbol_short!("owner")),
            SpendEvent {
                slot_id,
                ephemeral_key,
                new_owner_commitment,
                spend_nonce: token.spend_nonce,
            },
        );

        Ok(())
    }

    // ── Redemption ──

    /// Path A (pure bearer): redeem by proving knowledge of the composed
    /// ephemeral secret. The holder signs
    /// `SHA-256(domain_tag || contract_xdr || slot_id (u32 BE) ||
    /// ephemeral_key || recipient_xdr)`.
    ///
    /// The recipient is in the digest because `require_auth()` does **not**
    /// bind it — that binds whoever submits the transaction, while the
    /// signature would otherwise be a standalone credential anyone could
    /// reuse. **Rejects spend-mode tokens** — those must use
    /// [`redeem_by_key_owned`](Self::redeem_by_key_owned).
    pub fn redeem_by_key(
        e: Env,
        holder: Address,
        recipient: Address,
        slot_id: u32,
        signature: BytesN<64>,
        claim_signature: BytesN<64>,
    ) -> Result<i128, Error> {
        Self::redeem_by_key_impl(
            e,
            holder,
            recipient,
            slot_id,
            signature,
            None,
            Some(claim_signature),
        )
    }

    /// Path A for spend-mode tokens: as [`redeem_by_key`](Self::redeem_by_key),
    /// plus the current owner opens the live `owner_commitment` and signs
    /// `SHA-256(SPEND_REDEEM || contract_xdr || slot_id (u32 BE) ||
    /// ephemeral_key || owner_commitment || spend_nonce (u32 BE) ||
    /// recipient_xdr)`.
    pub fn redeem_by_key_owned(
        e: Env,
        holder: Address,
        recipient: Address,
        slot_id: u32,
        signature: BytesN<64>,
        owner_pubkey: BytesN<32>,
        owner_signature: BytesN<64>,
    ) -> Result<i128, Error> {
        Self::redeem_by_key_impl(
            e,
            holder,
            recipient,
            slot_id,
            signature,
            Some((owner_pubkey, owner_signature)),
            // Spend mode: the owner proof is the possession proof, and
            // `enforce_owner` refuses `PureBearer` here.
            None,
        )
    }

    fn redeem_by_key_impl(
        e: Env,
        holder: Address,
        recipient: Address,
        slot_id: u32,
        signature: BytesN<64>,
        owner: Option<(BytesN<32>, BytesN<64>)>,
        claim_signature: Option<BytesN<64>>,
    ) -> Result<i128, Error> {
        // Only the holder authorises; see `redeem_by_chain_impl`.
        holder.require_auth();
        Self::reject_self(&e, &recipient)?;

        // A redeemed note has no record at all -- redemption removes it
        // (see `DataKey::Redeemed`). Absence is what refuses the second
        // attempt; the marker only separates "already redeemed" from
        // "no such slot", so the caller is told which mistake they made.
        let token: TokenRecord = match e
            .storage()
            .persistent()
            .get(&DataKey::Token(slot_id))
        {
            Some(t) => t,
            None => {
                return Err(
                    if e.storage().persistent().has(&DataKey::Redeemed(slot_id)) {
                        Error::AlreadyRedeemed
                    } else {
                        Error::TokenNotFound
                    },
                )
            }
        };

        // Read from the record, never from the caller: the slot id is
        // what names a note, and the key it was registered with is
        // whatever that slot registered.
        let ephemeral_key = token.ephemeral_key.clone();

        if token.state != TokenState::Active {
            if token.state == TokenState::Redeemed {
                return Err(Error::AlreadyRedeemed);
            }
            return Err(Error::TokenNotActive);
        }

        // Spend-mode ownership gate (the mode decides whether an owner proof is required).
        Self::enforce_owner(&e, &token, &ephemeral_key, &recipient, &owner)?;

        // domain_tag || contract || ephemeral_key || recipient, hashed.
        //
        // The recipient is in the digest so the signature says "pay this
        // note to *this* address", not merely "redeem this note".
        // `require_auth()` does not bind the holder: it binds whoever
        // submits the transaction, so a signature over only the tag and the
        // key would be a standalone credential. Anyone who saw one could
        // resubmit it with their own holder and recipient, and a
        // transaction that fails on-chain records its arguments permanently
        // while the note stays Active -- so a failed redemption would hand
        // the note away with no race to win.
        //
        // `enforce_owner` reasons the same way for spend mode.
        //
        // The contract address is included so a signature cannot be
        // replayed against another deployment of this contract holding a
        // note with the same key.
        let mut message = Bytes::new(&e);
        message.extend_from_slice(DOMAIN_TAG);
        message.append(&e.current_contract_address().to_xdr(&e));
        message.extend_from_array(&slot_id.to_be_bytes());
        message.extend_from_array(&ephemeral_key.to_array());
        message.append(&recipient.clone().to_xdr(&e));

        // Signed over the 32-byte digest, as the owner proof is.
        let digest: BytesN<32> = e.crypto().sha256(&message).into();
        let signed = Bytes::from_array(&e, &digest.to_array());

        // Proves knowledge of the composed ephemeral secret. Traps on a
        // bad signature, so the transaction reverts.
        e.crypto()
            .ed25519_verify(&ephemeral_key, &signed, &signature);

        // Pure bearer: the claim key as well, exactly as Path B requires
        // it.
        //
        // Knowing the ephemeral secret is not the same as holding the
        // note. `s = Σ shardᵢ`, and each shard is derivable by *either*
        // node of its pair -- so one node from each pair, colluding,
        // can compose it, and at `min_pairs = 1` a single node can. The
        // shard-release handler will serve a shard to anyone who signs
        // their own request, which makes the node network an oracle for
        // `s`.
        //
        // So the ephemeral signature proves construction, not
        // possession. Path A redeems the same escrow as Path B, so it
        // asks for the claim signature too; otherwise the invariant
        // would be optional.
        if let Some(sig) = claim_signature {
            let mut m = Bytes::new(&e);
            m.extend_from_slice(CLAIM_TAG);
            m.append(&e.current_contract_address().to_xdr(&e));
            m.extend_from_array(&slot_id.to_be_bytes());
            m.extend_from_array(&ephemeral_key.to_array());
            m.append(&recipient.clone().to_xdr(&e));
            let digest: BytesN<32> = e.crypto().sha256(&m).into();
            let signed = Bytes::from_array(&e, &digest.to_array());
            // Traps on a bad signature, so the transaction reverts.
            e.crypto().ed25519_verify(&token.claim_pubkey, &signed, &sig);
        }

        let config = Self::get_config(&e);

        let client = token::Client::new(&e, &config.pay_token);

        // Credit each participant's claimable balance instead of paying instantly,
        // so earnings are uniform across both redemption paths and survive node
        // churn (a node need not be reachable at the redemption moment).
        let fees = Self::accrue_node_fees(&e, &token, &config.pay_token);
        let holder_amount = token.amount - fees.total();

        // Pay holder remainder
        client.transfer(&e.current_contract_address(), &recipient, &holder_amount);

        // Pay out, then drop the record and leave a marker.
        //
        // Nothing reads a redeemed token again: the node fees have
        // already landed in `Accrued`, and a second redemption is
        // refused by the record's absence. Keeping ~450 bytes live to
        // say "spent" costs rent forever for a fact the slot counter
        // already enforces.
        let redeemed_at = e.ledger().sequence();
        e.storage().persistent().remove(&DataKey::Token(slot_id));
        e.storage()
            .persistent()
            .set(&DataKey::Redeemed(slot_id), &redeemed_at);

        // The marker is deliberately left to age. An on-chain read
        // restores it, so a double-redeem is refused forever; paying
        // rent to keep 90 bytes queryable off-ledger is exactly the cost
        // dropping the record avoids.
        Self::bump_instance(&e, threshold(&e));
        Self::bump_key(&e, &DataKey::Config, threshold(&e));

        e.events().publish(
            (symbol_short!("REDEEM"), symbol_short!("key")),
            RedeemByKeyEvent {
                slot_id,
                ephemeral_key,
                holder: holder.clone(),
                recipient: recipient.clone(),
                amount: holder_amount,
                node_fees_accrued: fees.credited,
                node_fees_burned: fees.burned,
            },
        );

        Ok(holder_amount)
    }

    /// Path B (pure bearer): redeem by submitting the full signature chain.
    /// On-chain verification of dual Ed25519 signatures + hash chain. Node fees
    /// accrue to participants. **Rejects spend-mode tokens** — those must use
    /// [`redeem_by_chain_owned`](Self::redeem_by_chain_owned).
    pub fn redeem_by_chain(
        e: Env,
        holder: Address,
        recipient: Address,
        slot_id: u32,
        chain_data: Bytes,
        claim_signature: BytesN<64>,
    ) -> Result<i128, Error> {
        Self::redeem_by_chain_impl(
            e,
            holder,
            recipient,
            slot_id,
            chain_data,
            None,
            Some(claim_signature),
        )
    }

    /// Path B for spend-mode tokens: as [`redeem_by_chain`](Self::redeem_by_chain),
    /// plus the current owner opens the live `owner_commitment` and signs
    /// `SHA-256(SPEND_REDEEM || contract_xdr || slot_id (u32 BE) ||
    /// ephemeral_key || owner_commitment || spend_nonce (u32 BE) ||
    /// recipient_xdr)`.
    pub fn redeem_by_chain_owned(
        e: Env,
        holder: Address,
        recipient: Address,
        slot_id: u32,
        chain_data: Bytes,
        owner_pubkey: BytesN<32>,
        owner_signature: BytesN<64>,
    ) -> Result<i128, Error> {
        // No claim signature: the owner proof is already recipient-bound,
        // so a spend-mode redemption is not liftable from the ledger.
        Self::redeem_by_chain_impl(
            e,
            holder,
            recipient,
            slot_id,
            chain_data,
            Some((owner_pubkey, owner_signature)),
            None,
        )
    }

    fn redeem_by_chain_impl(
        e: Env,
        holder: Address,
        recipient: Address,
        slot_id: u32,
        chain_data: Bytes,
        owner: Option<(BytesN<32>, BytesN<64>)>,
        claim_signature: Option<BytesN<64>>,
    ) -> Result<i128, Error> {
        // Only the holder authorises. The recipient does not need to: the
        // `from` side of the payout is this contract, and an address cannot
        // be harmed by being sent an asset it already trusts.
        holder.require_auth();
        Self::reject_self(&e, &recipient)?;

        // A redeemed note has no record at all -- redemption removes it
        // (see `DataKey::Redeemed`). Absence is what refuses the second
        // attempt; the marker only separates "already redeemed" from
        // "no such slot", so the caller is told which mistake they made.
        let token: TokenRecord = match e
            .storage()
            .persistent()
            .get(&DataKey::Token(slot_id))
        {
            Some(t) => t,
            None => {
                return Err(
                    if e.storage().persistent().has(&DataKey::Redeemed(slot_id)) {
                        Error::AlreadyRedeemed
                    } else {
                        Error::TokenNotFound
                    },
                )
            }
        };

        // Read from the record, never from the caller: the slot id is
        // what names a note, and the key it was registered with is
        // whatever that slot registered.
        let ephemeral_key = token.ephemeral_key.clone();

        if token.state != TokenState::Active {
            if token.state == TokenState::Redeemed {
                return Err(Error::AlreadyRedeemed);
            }
            return Err(Error::TokenNotActive);
        }

        // Spend-mode ownership gate (the mode decides whether an owner proof is required).
        Self::enforce_owner(&e, &token, &ephemeral_key, &recipient, &owner)?;

        // Bind the submitted chain to the commitment registered at mint time.
        // Without this, a chain can be forged from public data (the ephemeral
        // key, event_id, and pair count are all public) and the escrow drained
        // by a non-holder. See `docs/architecture/security-model.md`.
        let computed_hash: BytesN<32> = e.crypto().sha256(&chain_data).into();
        if computed_hash != token.chain_hash {
            return Err(Error::ChainVerificationFailed);
        }

        // Pure bearer: a signature from the note's claim key, naming the
        // recipient.
        //
        // The chain above is a *preimage*, so presenting it spends it:
        // every attempt publishes it, and an attempt that fails on-chain
        // publishes it while leaving the note Active. An observer could
        // then redeem at leisure -- no race, no mempool, just reading a
        // failed transaction. A recipient without a trustline is an
        // everyday way to produce one.
        //
        // The claim secret never comes here. It rides inside the note
        // container, and what reaches the contract is a signature over
        // this recipient, which is worthless to anyone else. Commit-reveal
        // would not help: once the chain is public and the note is
        // still live, an attacker simply commits their own and waits.
        //
        // The note stays bearer. The key is in the file rather than tied
        // to a person, so copying the file still copies the right to
        // redeem -- including photographing one off paper.
        if let Some(sig) = claim_signature {
            let mut m = Bytes::new(&e);
            m.extend_from_slice(CLAIM_TAG);
            m.append(&e.current_contract_address().to_xdr(&e));
            m.extend_from_array(&slot_id.to_be_bytes());
            m.extend_from_array(&ephemeral_key.to_array());
            m.append(&recipient.clone().to_xdr(&e));
            let digest: BytesN<32> = e.crypto().sha256(&m).into();
            let signed = Bytes::from_array(&e, &digest.to_array());
            // Traps on a bad signature, so the transaction reverts.
            e.crypto().ed25519_verify(&token.claim_pubkey, &signed, &sig);
        }

        let config = Self::get_config(&e);

        // Verify the chain on-chain (internal validity: signatures, hash chain).
        verify::verify_chain(&e, &chain_data, &token)?;

        let client = token::Client::new(&e, &config.pay_token);

        // Credit participants' claimable balances rather than burning the fees.
        // Path B is the churn path (redeemed with no nodes online), so accruing
        // here is exactly what lets dark construction nodes still earn. Safe only
        // because the chain is bound to the registered commitment (the
        // `chain_hash` check above); a forged chain can't reach here.
        let fees = Self::accrue_node_fees(&e, &token, &config.pay_token);
        let holder_amount = token.amount - fees.total();

        // Pay holder remainder
        client.transfer(&e.current_contract_address(), &recipient, &holder_amount);

        // Pay out, then drop the record and leave a marker.
        //
        // Nothing reads a redeemed token again: the node fees have
        // already landed in `Accrued`, and a second redemption is
        // refused by the record's absence. Keeping ~450 bytes live to
        // say "spent" costs rent forever for a fact the slot counter
        // already enforces.
        let redeemed_at = e.ledger().sequence();
        e.storage().persistent().remove(&DataKey::Token(slot_id));
        e.storage()
            .persistent()
            .set(&DataKey::Redeemed(slot_id), &redeemed_at);

        // The marker ages out -- see `redeem_by_key_impl`.
        Self::bump_instance(&e, threshold(&e));
        Self::bump_key(&e, &DataKey::Config, threshold(&e));

        e.events().publish(
            (symbol_short!("REDEEM"), symbol_short!("chain")),
            RedeemByChainEvent {
                slot_id,
                ephemeral_key,
                holder: holder.clone(),
                recipient: recipient.clone(),
                amount: holder_amount,
                node_fees_accrued: fees.credited,
                node_fees_burned: fees.burned,
            },
        );

        Ok(holder_amount)
    }

    // ── Node Fee Accrual ──

    /// Claim accrued node fees. Callable by any node holding a positive balance,
    /// at any time — earnings are decoupled from the redemption moment, so a node
    /// that was offline when its tokens were redeemed still collects when it next
    /// comes online.
    pub fn claim_fees(e: Env, node: Address) -> Result<i128, Error> {
        node.require_auth();

        let accrued: i128 = e
            .storage()
            .persistent()
            .get(&DataKey::Accrued(node.clone()))
            .unwrap_or(0);

        if accrued <= 0 {
            return Err(Error::NothingToClaim);
        }

        // Clear the balance before paying out. (Soroban token transfers don't
        // re-enter this contract, but clear-then-pay keeps the invariant obvious.)
        e.storage()
            .persistent()
            .remove(&DataKey::Accrued(node.clone()));

        Self::bump_instance(&e, threshold(&e));
        Self::bump_key(&e, &DataKey::Config, threshold(&e));

        let config = Self::get_config(&e);
        let client = token::Client::new(&e, &config.pay_token);
        client.transfer(&e.current_contract_address(), &node, &accrued);

        e.events().publish(
            (symbol_short!("FEES"), symbol_short!("claim")),
            FeesClaimedEvent {
                node: node.clone(),
                amount: accrued,
            },
        );

        Ok(accrued)
    }

    /// Accrued, unclaimed node-fee balance for `node` (0 if none).
    pub fn accrued_fees(e: Env, node: Address) -> i128 {
        e.storage()
            .persistent()
            .get(&DataKey::Accrued(node))
            .unwrap_or(0)
    }

    // ── Slot Expiration ──

    pub fn clear_expired_slot(e: Env, slot_id: u32) -> Result<i128, Error> {
        let slot = Self::load_slot(&e, slot_id).ok_or(Error::SlotNotFound)?;

        if slot.state != TokenState::Printing {
            return Err(Error::SlotNotPrinting);
        }

        let config = Self::get_config(&e);

        if e.ledger().sequence() <= Self::slot_expires_at(&slot, &config) {
            return Err(Error::SlotNotExpired);
        }

        // Same settlement as cancel: letting the clock run out is the
        // other way to abandon a print, so it must not be the cheaper one.
        // That includes the forfeit, or a depositor would re-roll a draw
        // by letting it lapse instead of cancelling it.
        let fees = Self::settle_abandoned_slot(&e, &slot, &config);
        let forfeited = Self::forfeit(&e, &slot, &config, true);
        let refund = slot.amount - fees.total() - forfeited;

        // The print is over, so its record goes -- the same argument as
        // `register_token`, and it holds for an abandoned print exactly
        // as it does for a completed one. Every caller that reads a slot
        // first requires `Printing`, so absence refuses precisely where
        // a `Cancelled` state would: `cancel_print`,
        // `clear_expired_slot`, `register_token` and `confirm_link` all
        // answer `SlotNotFound` rather than `SlotNotPrinting`.
        //
        // Unlike redemption this leaves no marker. A redeemed note needs
        // one because a holder asking "was this spent?" must not be told
        // "no such thing" about a bearer instrument they are holding. An
        // abandoned print has no such holder: the escrow is already
        // settled and refunded, and the depositor's own client scans for
        // slots in `Printing`, which this never was again.
        //
        // `EventIdUsed` is deliberately left behind. A cancelled print
        // does not release its event id -- two prints answering to one
        // name is a reconciliation problem with no fix after the fact --
        // and that guard is a separate entry this does not touch.
        Self::remove_slot(&e, slot_id);

        Self::bump_instance(&e, threshold(&e));
        Self::bump_key(&e, &DataKey::Config, threshold(&e));

        let client = token::Client::new(&e, &config.pay_token);
        client.transfer(&e.current_contract_address(), &slot.depositor, &refund);

        e.events().publish(
            (symbol_short!("SLOT"), symbol_short!("expired")),
            SlotExpiredEvent {
                slot_id,
                event_id: slot.event_id,
                refund,
                depositor: slot.depositor,
                earned: fees.credited,
                burned: fees.burned,
                forfeited,
            },
        );

        Ok(refund)
    }

    pub fn is_slot_expired(e: Env, slot_id: u32) -> bool {
        let core: Option<SlotCore> = e
            .storage()
            .persistent()
            .get(&DataKey::Slot(slot_id));

        match core {
            None => false,
            Some(c) => {
                if c.state != TokenState::Printing {
                    return false;
                }
                let config = Self::get_config(&e);
                e.ledger().sequence() > c.created_at.saturating_add(config.max_print_ledgers)
            }
        }
    }

    // ── Queries ──

    /// A print slot, assembled from its core and its draw. `lapsed` says
    /// the draw is gone.
    pub fn get_slot(e: Env, slot_id: u32) -> Option<PrintSlot> {
        Self::load_slot(&e, slot_id)
    }

    pub fn get_token(e: Env, slot_id: u32) -> Option<TokenRecord> {
        e.storage()
            .persistent()
            .get(&DataKey::Token(slot_id))
    }

    pub fn get_token_state(e: Env, slot_id: u32) -> Option<TokenState> {
        let token: Option<TokenRecord> = e
            .storage()
            .persistent()
            .get(&DataKey::Token(slot_id));
        if let Some(t) = token {
            return Some(t.state);
        }
        // No record, but a marker: the note was paid out and its record
        // removed. Without this the answer would be `None`, which reads
        // as "no such slot" about a note that very much existed.
        if e.storage().persistent().has(&DataKey::Redeemed(slot_id)) {
            return Some(TokenState::Redeemed);
        }
        None
    }

    /// Whether this slot has been redeemed.
    ///
    /// Informational, and it can lapse: the marker is not bumped, so
    /// once it archives this answers `false` about a note that was
    /// redeemed. Nothing safety-critical rests on it. A holder asking
    /// whether a note can still be cashed is answered by `get_token`,
    /// which returns nothing for a redeemed note and fails closed.
    pub fn is_redeemed(e: Env, slot_id: u32) -> bool {
        e.storage().persistent().has(&DataKey::Redeemed(slot_id))
    }

    /// The ledger a slot was redeemed on, if the marker is still live.
    pub fn redeemed_at(e: Env, slot_id: u32) -> Option<u32> {
        e.storage().persistent().get(&DataKey::Redeemed(slot_id))
    }

    pub fn node_fee(e: Env) -> u32 {
        Self::get_config(&e).node_fee
    }

    pub fn min_pairs(e: Env) -> u32 {
        Self::get_config(&e).min_pairs
    }

    pub fn max_pairs(e: Env) -> u32 {
        Self::get_config(&e).max_pairs
    }

    pub fn pay_token(e: Env) -> Address {
        Self::get_config(&e).pay_token
    }

    pub fn roster(e: Env) -> Address {
        Self::get_config(&e).roster
    }

    /// The last ledger at which a slot can still be worked on.
    ///
    /// Saturating, because `created_at + max_print_ledgers` is `u32` and
    /// `overflow-checks` is on in release: a mint deployed with a large
    /// window -- `u32::MAX` is the natural way to write "never expires" --
    /// would otherwise trap in every `confirm_link`, `clear_expired_slot`
    /// and `is_slot_expired`, so no token could ever be registered on it.
    /// The deposit would still be recoverable through `cancel_print`,
    /// making it a bricked mint rather than a theft, and an immutable one.
    ///
    /// Saturation gives that configuration the meaning it was reaching
    /// for: the deadline lands on the last ledger there is.
    fn slot_expires_at(slot: &PrintSlot, config: &MintConfig) -> u32 {
        slot.created_at.saturating_add(config.max_print_ledgers)
    }

    pub fn max_print_ledgers(e: Env) -> u32 {
        Self::get_config(&e).max_print_ledgers
    }

    /// The selection parameters: beacon, claim window, serve timeout and
    /// minimum node age.
    pub fn selection(e: Env) -> SelectionConfig {
        Self::get_config(&e).selection
    }

    // ── Internal ──

    /// A slot that exists, is printing and has not expired.
    fn live_slot(e: &Env, slot_id: u32) -> Result<PrintSlot, Error> {
        let slot = Self::load_slot(e, slot_id).ok_or(Error::SlotNotFound)?;
        if slot.state != TokenState::Printing {
            return Err(Error::SlotNotPrinting);
        }
        let config = Self::get_config(e);
        if e.ledger().sequence() > Self::slot_expires_at(&slot, &config) {
            return Err(Error::SlotExpired);
        }
        if slot.lapsed {
            return Err(Error::DrawLapsed);
        }
        Ok(slot)
    }

    /// Read a slot: its persistent core, and its temporary draw if that
    /// is still there.
    fn load_slot(e: &Env, slot_id: u32) -> Option<PrintSlot> {
        let c: SlotCore = e.storage().persistent().get(&DataKey::Slot(slot_id))?;
        let draw: Option<SlotDraw> = e.storage().temporary().get(&DataKey::Draw(slot_id));
        let lapsed = draw.is_none();
        let d = draw.unwrap_or_else(|| SlotDraw {
            pairs: vec![e, c.first_pair.clone(), c.last_pair.clone()],
            seed: None,
            claims: Vec::new(e),
            partial_keys: Vec::new(e),
            confirmers: Vec::new(e),
        });
        Some(PrintSlot {
            slot_id: c.slot_id,
            depositor: c.depositor,
            event_id: c.event_id,
            amount: c.amount,
            total_pairs: c.total_pairs,
            pairs: d.pairs,
            completed_links: c.completed_links,
            partial_keys: d.partial_keys,
            confirmers: d.confirmers,
            volunteers: c.volunteers,
            state: c.state,
            created_at: c.created_at,
            beacon_round: c.beacon_round,
            seed: d.seed,
            claim_deadline: c.claim_deadline,
            claims: d.claims,
            closed: c.closed,
            last_progress: c.last_progress,
            filled: c.filled,
            lapsed,
        })
    }

    /// Write a slot back as its two entries and keep both alive for the
    /// print window.
    ///
    /// **The core never changes size**: every field is fixed-width and the
    /// end pairs are the ones named at request. So after `request_print`
    /// no write pays persistent rent on growth, which on mainnet is 120
    /// days of it. Everything that grows is in the draw.
    ///
    /// The draw is extended to the full window on every write, so while
    /// the slot is live it exists, unless the window is longer than the
    /// network's `max_entry_ttl` and nothing writes for that long. A
    /// lapsed slot is never written back: only settlement reads one, and
    /// writing it would bring back an empty draw.
    fn save_slot(e: &Env, slot: &PrintSlot, config: &MintConfig) {
        let n = slot.pairs.len();
        let core = SlotCore {
            slot_id: slot.slot_id,
            depositor: slot.depositor.clone(),
            event_id: slot.event_id.clone(),
            amount: slot.amount,
            total_pairs: slot.total_pairs,
            first_pair: slot.pairs.get(0).unwrap(),
            last_pair: slot.pairs.get(n - 1).unwrap(),
            completed_links: slot.completed_links,
            volunteers: slot.volunteers,
            state: slot.state.clone(),
            created_at: slot.created_at,
            beacon_round: slot.beacon_round,
            claim_deadline: slot.claim_deadline,
            filled: slot.filled,
            closed: slot.closed,
            last_progress: slot.last_progress,
        };
        let slot_life = slot_ttl(e, slot.created_at, config.max_print_ledgers);
        e.storage()
            .persistent()
            .set(&DataKey::Slot(slot.slot_id), &core);
        if slot_life > 0 {
            Self::bump_key_to(e, &DataKey::Slot(slot.slot_id), slot_life, slot_life);
        }
        if !slot.lapsed {
            let draw = SlotDraw {
                pairs: slot.pairs.clone(),
                seed: slot.seed.clone(),
                claims: slot.claims.clone(),
                partial_keys: slot.partial_keys.clone(),
                confirmers: slot.confirmers.clone(),
            };
            let key = DataKey::Draw(slot.slot_id);
            e.storage().temporary().set(&key, &draw);
            if slot_life > 0 {
                e.storage().temporary().extend_ttl(&key, slot_life, slot_life);
            }
        }
        Self::bump_instance(e, threshold(e));
        Self::bump_key(e, &DataKey::Config, threshold(e));
    }

    /// Delete both entries of a finished slot.
    fn remove_slot(e: &Env, slot_id: u32) {
        e.storage().persistent().remove(&DataKey::Slot(slot_id));
        e.storage().temporary().remove(&DataKey::Draw(slot_id));
    }

    /// Record `seed`, open the claim window, and announce it. Shared by
    /// both ways of seeding, so a fallback-seeded slot is indistinguishable
    /// from a beacon-seeded one from here on.
    fn set_seed(e: &Env, slot: &mut PrintSlot, config: &MintConfig, seed: BytesN<32>) {
        let deadline = e
            .ledger()
            .sequence()
            .saturating_add(config.selection.claim_window);
        slot.seed = Some(seed.clone());
        slot.claim_deadline = deadline;
        Self::save_slot(e, slot, config);

        e.events().publish(
            (symbol_short!("PRINT"), symbol_short!("seeded")),
            PrintSeededEvent {
                slot_id: slot.slot_id,
                beacon_round: slot.beacon_round,
                seed,
                claim_deadline: deadline,
                positions: slot.total_pairs - 2,
            },
        );
    }

    /// The unix time at which `round` is published.
    fn round_time(sel: &SelectionConfig, round: u64) -> u64 {
        sel.beacon_genesis
            .saturating_add(round.saturating_sub(1).saturating_mul(sel.beacon_period))
    }

    /// The beacon round current at unix time `ts`. Round 1 is at genesis.
    fn round_at(sel: &SelectionConfig, ts: u64) -> u64 {
        (ts.saturating_sub(sel.beacon_genesis) / sel.beacon_period).saturating_add(1)
    }

    /// Whether `sig` is the beacon's signature for `round`: drand
    /// `bls-unchained-g1-rfc9380` signs `sha256(round as u64 BE)`, so the
    /// check is `e(sig, -g2) * e(H(m), pk) == 1`.
    fn beacon_verifies(e: &Env, sel: &SelectionConfig, round: u64, sig: &BytesN<96>) -> bool {
        let bls = e.crypto().bls12_381();
        let msg = e.crypto().sha256(&Bytes::from_array(e, &round.to_be_bytes()));
        let hm = bls.hash_to_g1(&msg.to_bytes().into(), &Bytes::from_slice(e, BEACON_DST));
        bls.pairing_check(
            vec![e, G1Affine::from_bytes(sig.clone()), hm],
            vec![
                e,
                G2Affine::from_bytes(BytesN::from_array(e, &NEG_G2)),
                G2Affine::from_bytes(sel.beacon_pk.clone()),
            ],
        )
    }

    /// A pair's score: `sha256(seed || lower || higher)` over the two
    /// addresses' XDR in bytewise order, so a pair cannot claim in both
    /// orders and keep the better one.
    fn score(e: &Env, seed: &BytesN<32>, a: &Address, b: &Address) -> BytesN<32> {
        let xa = a.clone().to_xdr(e);
        let xb = b.clone().to_xdr(e);
        let (lo, hi) = if xa <= xb { (xa, xb) } else { (xb, xa) };
        let mut m = Bytes::from_array(e, &seed.to_array());
        m.append(&lo);
        m.append(&hi);
        e.crypto().sha256(&m).to_bytes()
    }

    /// Fix the interior positions: the `k` lowest-scoring claims, in score
    /// order, become pairs `1..=k`, and the rest are kept as runners-up.
    /// A no-op on a slot already closed.
    fn close_selection(e: &Env, slot: &mut PrintSlot) -> Result<(), Error> {
        if slot.closed {
            return Ok(());
        }
        if slot.seed.is_none() {
            return Err(Error::NotSeeded);
        }
        let k = slot.total_pairs - 2;
        if e.ledger().sequence() <= slot.claim_deadline || slot.claims.len() < k {
            return Err(Error::SelectionNotReady);
        }
        let first = slot.pairs.get(0).unwrap();
        let last = slot.pairs.get(1).unwrap();
        let mut pairs = vec![e, first];
        let mut runners_up = Vec::new(e);
        let mut volunteers: u32 = 0;
        for (j, c) in slot.claims.iter().enumerate() {
            let j = j as u32;
            if j < k {
                let i = j + 1;
                if c.volunteer_a {
                    volunteers |= 1 << (2 * i);
                }
                if c.volunteer_b {
                    volunteers |= 1 << (2 * i + 1);
                }
                pairs.push_back(c.pair);
            } else {
                runners_up.push_back(c);
            }
        }
        pairs.push_back(last);
        slot.pairs = pairs;
        slot.claims = runners_up;
        slot.volunteers = volunteers;
        slot.closed = true;
        // Position 1's serve clock starts when the positions became fixed,
        // not when someone first writes them down: closing is lazy, and a
        // silent first pair never confirms, so it is usually the depositor's
        // skip that closes -- which must not reset the clock it is checking.
        // Fixed means the deadline, or the claim that filled a short list
        // after it, or link 0's confirmation if that came later still;
        // `last_progress` already holds the later two.
        slot.last_progress = slot.last_progress.max(slot.claim_deadline);
        e.events().publish(
            (symbol_short!("PRINT"), symbol_short!("selected")),
            PrintSelectedEvent {
                slot_id: slot.slot_id,
                pairs: slot.pairs.clone(),
            },
        );
        Ok(())
    }

    /// Burn `2 * node_fee` for every interior position abandoned after a
    /// draw, and return the total.
    ///
    /// **The draw exists once round `R` is public, not once someone posts
    /// it**: anyone can fetch the round and compute
    /// every score, so a depositor who declined to seed and cancelled
    /// would re-roll for two transaction fees. So the forfeit applies from
    /// the round's publication time, seeded or not.
    ///
    /// Free when there was nothing to throw away:
    /// - before the round is published;
    /// - a seeded window that closed short of `k` claims: the draw could
    ///   not complete;
    /// - an **unseeded slot that expires** (`expiring`): the case where
    ///   the beacon itself stalled, which must not cost the depositor.
    ///   A depositor who withholds the seed and waits for this
    ///   pays the whole print window, with the deposit locked, per re-roll.
    ///
    /// Anything else pays -- including a cancel inside the window, or of an
    /// unseeded slot whose round is out -- or the draw could be re-rolled.
    ///
    /// Inside the reserve `request_print` takes: settlement pays at most
    /// one fee per confirmed interior link and this two per unconfirmed
    /// position, so together at most `2 * node_fee * k`.
    fn forfeit(e: &Env, slot: &PrintSlot, config: &MintConfig, expiring: bool) -> i128 {
        let fee = config.node_fee as i128;
        if fee <= 0 {
            return 0;
        }
        let k = slot.total_pairs - 2;
        // Read from the core only (`claim_deadline` is 0 until seeded, and
        // `filled` stands for the claim count), so the forfeit is the same
        // whether or not the draw has lapsed.
        if slot.claim_deadline == 0 {
            let published = Self::round_time(&config.selection, slot.beacon_round);
            if expiring || e.ledger().timestamp() < published {
                return 0;
            }
        } else if !slot.closed && e.ledger().sequence() > slot.claim_deadline && !slot.filled {
            return 0;
        }
        let confirmed = slot.completed_links.saturating_sub(1).min(k);
        let positions = k - confirmed;
        let amount = 2 * fee * positions as i128;
        if amount > 0 {
            Self::burn(e, slot.slot_id, &config.pay_token, amount);
            e.events().publish(
                (symbol_short!("PRINT"), symbol_short!("forfeit")),
                ForfeitEvent {
                    slot_id: slot.slot_id,
                    positions,
                    amount,
                },
            );
        }
        amount
    }

    /// Credit the nodes of every link already confirmed on an abandoned
    /// slot, and report the total.
    ///
    /// Without this, cancelling or expiring would refund the deposit in
    /// full however much work had been done, so a depositor could request
    /// a print, let every pair derive its shard and confirm its link, then
    /// take the whole deposit back. That is free denial of service against
    /// node capacity, and it is simply not paying for work performed.
    /// Waiting for expiry is the same trick with a timer, so both paths
    /// settle here.
    ///
    /// Only *confirmed* links are paid: `completed_links` is advanced by
    /// `confirm_link` and nothing else, so a pair that did nothing earns
    /// nothing. `request_print` already refuses a deposit that cannot
    /// cover every pair's fee, so this can never exceed the deposit.
    fn settle_abandoned_slot(e: &Env, slot: &PrintSlot, config: &MintConfig) -> FeeSplit {
        let mut split = FeeSplit::default();
        let fee = config.node_fee as i128;
        if fee <= 0 {
            return split;
        }
        // The confirmer, and only the confirmer.
        //
        // Not both nodes of the pair: `confirm_link` takes either member,
        // and a shard is derivable by one of them alone, so the partner may
        // have done nothing at all -- the chain cannot tell.
        // One address put its name to the link; that is the whole of
        // what is provable, so that is who is paid.
        //
        // What this does not fix: a node can still confirm, withhold
        // the extended partial token, and collect when the depositor
        // gives up. It costs one fee rather than two. The roster has no
        // admin to remove such a node. This is an accepted limit: it takes
        // modified node software, gains one fee per print it stalls, and
        // costs the depositor what a cancelled print costs: the fees of
        // the links already built and a forfeit for each position after
        // it, never the escrow.
        // Paying only links whose
        // *successor* was confirmed would close it outright, but it
        // would also let a depositor stiff an honest last node by
        // cancelling, which is the same grief pointed the other way.
        // **The depositor's end links are skipped**, matching
        // `accrue_node_fees` and the reserve `request_print` takes.
        //
        // This is a trap to avoid, not an inefficiency. The precheck
        // reserves only `2 * fee * (pairs - 2)`; if settlement paid one fee
        // per confirmed link, end links included, it could exceed the
        // reserve: at `min_pairs = 3` with all three links confirmed and
        // `2*fee < amount < 3*fee`, `refund = amount - earned` would go
        // negative and both `cancel_print` and `clear_expired_slot` would
        // trap. Registration is refused after expiry, so the escrow would
        // be stranded with no way out and the interior node never paid.
        //
        // Skipping the ends keeps the invariant -- settlement is at
        // most `(pairs - 2) * fee`, inside the reserve for every pair
        // count -- and makes both exits pay the same parties. The
        // end links are still *required* by `confirm_link`: they order
        // the chain, they are simply not paid for.
        let last_link = slot.total_pairs.saturating_sub(1);
        // The confirmers were in the draw, and it has lapsed: their fees
        // are burned, not kept back, so the depositor's refund is what it
        // would have been and letting the draw lapse gains them nothing.
        if slot.lapsed {
            let mut unpaid = 0;
            for i in 0..slot.completed_links {
                if i != 0 && i < last_link {
                    unpaid += fee;
                }
            }
            if unpaid > 0 {
                e.events().publish(
                    (symbol_short!("FEE"), symbol_short!("lapsed")),
                    FeeLockedEvent {
                        slot_id: slot.slot_id,
                        amount: unpaid,
                    },
                );
                split.burned = unpaid;
                Self::burn(e, slot.slot_id, &config.pay_token, unpaid);
            }
            return split;
        }
        for i in 0..slot.completed_links {
            if i == 0 || i >= last_link {
                continue;
            }
            let Some(node) = slot.confirmers.get(i) else {
                // No confirmer recorded for this link. Paying
                // nothing is the safe reading: this only ever runs on
                // an abandoned print, and the alternative is paying an
                // address the record does not actually name.
                continue;
            };
            // Which half of pair `i` confirmed decides which bit to read:
            // the two members of a pair may be on different terms.
            let pair = slot.pairs.get(i).unwrap();
            let bit = if node == pair.node_a { 2 * i } else { 2 * i + 1 };
            if slot.volunteers & (1 << bit) != 0 {
                Self::record_burn(e, slot.slot_id, node, fee, &mut split);
                continue;
            }
            let prior: i128 = e
                .storage()
                .persistent()
                .get(&DataKey::Accrued(node.clone()))
                .unwrap_or(0);
            e.storage()
                .persistent()
                .set(&DataKey::Accrued(node.clone()), &(prior + fee));
            Self::bump_key(e, &DataKey::Accrued(node.clone()), threshold(e));
            // Say so. Nothing else announces this credit, and a node
            // cannot be expected to poll `get_accrued` against every
            // slot it ever confirmed on the chance one was abandoned.
            e.events().publish(
                (symbol_short!("FEE"), symbol_short!("accrued")),
                FeeAccruedEvent {
                    slot_id: slot.slot_id,
                    node,
                    amount: fee,
                },
            );
            split.credited += fee;
        }
        Self::burn(e, slot.slot_id, &config.pay_token, split.burned);
        split
    }

    /// Account for one volunteer's fee: count it toward the burn and say
    /// so. The burn itself is one call per settlement ([`Self::burn`]).
    fn record_burn(e: &Env, slot_id: u32, node: Address, fee: i128, split: &mut FeeSplit) {
        e.events().publish(
            (symbol_short!("FEE"), symbol_short!("burned")),
            FeeBurnedEvent {
                slot_id,
                node,
                amount: fee,
            },
        );
        split.burned += fee;
    }

    /// Destroy `amount` of this contract's own pay-token balance.
    ///
    /// The SAC's `burn` on the contract's own address: the escrow that
    /// held these fees is this contract's, and a contract authorises
    /// its own calls, so no signature is involved. Burning, not sending
    /// anywhere -- there is no address to send a volunteer's fee to that
    /// is not somebody's.
    ///
    /// **A refused burn must not trap the settlement.** `burn` is refused
    /// outright for native XLM, and an issuer's token could refuse it for reasons of its
    /// own. This mint is immutable and adminless, so a trapping burn
    /// would lock every note and abandoned slot naming a volunteer, the
    /// holder's whole payout with it, for good. So the burn is tried, and
    /// if the token refuses, the amount stays in this contract's balance:
    /// nothing in the mint can ever move it (it is no node's `Accrued`,
    /// no slot's escrow), so it is as unreachable as burned, and a
    /// `FEE locked` event says which of the two happened. The deploy
    /// script still refuses an XLM pay token, so the fallback is for the
    /// case nobody foresaw.
    fn burn(e: &Env, slot_id: u32, pay_token: &Address, amount: i128) {
        if amount <= 0 {
            return;
        }
        let client = token::Client::new(e, pay_token);
        if !matches!(client.try_burn(&e.current_contract_address(), &amount), Ok(Ok(()))) {
            e.events().publish(
                (symbol_short!("FEE"), symbol_short!("locked")),
                FeeLockedEvent { slot_id, amount },
            );
        }
    }

    /// Credit each interior node's claimable balance, and return what
    /// was deducted from the holder's payout.
    ///
    /// The on-ledger `participants` list recorded at `register_token` is
    /// the authenticated work record, so no node-side receipts are needed.
    /// Used by both redemption paths, so a node earns whether or not it
    /// is reachable at the redemption moment.
    ///
    /// **The depositor's end pairs are skipped.** Crediting them like any
    /// other participant would reduce the holder's payout by four fees
    /// handed back to the depositor -- a transfer from the person
    /// redeeming a note to the person who printed it, for work nobody
    /// did. Where those are the same party it merely cycles; where a note
    /// has changed hands, which is the entire point of a bearer
    /// instrument, it does not.
    ///
    /// It would also cost real money. Each credit is a persistent
    /// `Accrued(address)` entry, and the depositor's would store a
    /// balance worth less than the transaction fee to claim it -- so it
    /// would never be claimed, and the rent to strand it would be paid by
    /// the holder.
    ///
    /// **The entries take a floor, not 120 days.** Bumping them to
    /// `TTL_EXTEND` would be ~94% of the whole cost of redeeming a
    /// three-pair note, growing linearly with pair count -- so the price
    /// of redeeming a note would rise with the very parameter that makes
    /// it hard to collude against. A node
    /// topping up its own balance is the right payer; `claim_fees` is
    /// where that belongs.
    ///
    /// **Volunteers' fees are burned**: the
    /// holder's payout is the same either way, and the split says where
    /// the deducted part went.
    fn accrue_node_fees(e: &Env, token: &TokenRecord, pay_token: &Address) -> FeeSplit {
        let mut split = FeeSplit::default();
        let fee = token.node_fee as i128;
        if fee <= 0 {
            return split;
        }
        let num = token.participants.len();
        // Participants are flattened pairwise, so the opening pair is
        // 0..2 and the closing pair is the last two. Both are the
        // depositor's; everything between is a roster node.
        if num < 6 {
            return split;
        }
        for i in 2..(num - 2) {
            let node = token.participants.get(i).unwrap();
            if token.volunteers & (1 << i) != 0 {
                Self::record_burn(e, token.slot_id, node, fee, &mut split);
                continue;
            }
            let prior: i128 = e
                .storage()
                .persistent()
                .get(&DataKey::Accrued(node.clone()))
                .unwrap_or(0);
            e.storage()
                .persistent()
                .set(&DataKey::Accrued(node.clone()), &(prior + fee));
            Self::bump_key_to(
                e,
                &DataKey::Accrued(node),
                MIN_LIVE_LEDGERS,
                MIN_LIVE_LEDGERS,
            );
            split.credited += fee;
        }
        Self::burn(e, token.slot_id, pay_token, split.burned);
        split
    }

    /// Keep the contract instance -- and with it the Wasm code -- alive.
    ///
    /// Separate from the entry bumps: extending a `TokenRecord` does
    /// nothing for the code that reads it, and a contract whose code has
    /// archived costs every later caller a restore.
    fn bump_instance(e: &Env, min_remaining: u32) {
        e.storage()
            .instance()
            .extend_ttl(min_remaining, extend_to(e));
    }

    /// Extend one persistent entry. The key must exist -- `extend_ttl`
    /// panics otherwise -- so every call below follows a write, or a read
    /// that found something.
    fn bump_key(e: &Env, key: &DataKey, min_remaining: u32) {
        Self::bump_key_to(e, key, min_remaining, extend_to(e));
    }

    /// Extend one persistent entry to a stated life rather than to the
    /// contract's ceiling.
    ///
    /// The rule every call site follows is **bump what you read, for as
    /// long as it has to be readable**. `bump_key` is the case where
    /// that is "as long as the contract lives"; this is every other
    /// case, where the entry has a life of its own.
    fn bump_key_to(e: &Env, key: &DataKey, min_remaining: u32, until: u32) {
        e.storage().persistent().extend_ttl(key, min_remaining, until);
    }

    // ── Rent, paid from outside ──

    /// Pay this contract's storage rent without doing anything else.
    ///
    /// Takes no auth and names no caller. Topping up rent cannot harm
    /// anyone -- the caller spends their own fee to extend an entry
    /// nobody else is charged for -- and gating it behind a privileged
    /// key would mean a dormant contract could only be rescued by
    /// whoever still held that key.
    ///
    /// The internal bumps are lazy on purpose: they act only once an
    /// entry is within [`TTL_THRESHOLD`] of archival, so an ordinary
    /// caller almost never pays rent. The cost of that is a lottery.
    /// When the threshold is finally crossed the whole top-up lands on
    /// whichever transaction is next through the door, and because the
    /// instance bump carries the contract's code entry with it, that is
    /// the largest single entry here. Measured on the roster, whose wasm
    /// is half the size of this one: 21.79 XLM for the transaction that
    /// paid, 0.095 XLM for the next one.
    ///
    /// This is the other half of that design. A keeper calling `bump`
    /// tops the entries back up whatever their remaining life, so the
    /// cost tracks how often it is called -- a daily keeper pays a day
    /// of rent a day -- and the lazy threshold is never reached, so no
    /// depositor or redeemer ever meets the lump.
    ///
    /// Returns the ledger the core entries now live until.
    pub fn bump(e: Env) -> u32 {
        Self::bump_core(&e, keeper_threshold(&e));
        e.ledger().sequence().saturating_add(extend_to(&e))
    }

    /// The entries every call needs, whatever else it touches: the
    /// instance (which carries the code entry with it), and the two the
    /// constructor always writes.
    ///
    /// `Config` lives in persistent storage rather than the instance,
    /// so bumping the instance alone leaves it to archive -- and every
    /// redemption path reads it, which means the holder would pay to
    /// restore it at exactly the moment they were trying to be paid.
    fn bump_core(e: &Env, min_remaining: u32) {
        Self::bump_instance(e, min_remaining);
        Self::bump_key(e, &DataKey::Config, min_remaining);
        Self::bump_key(e, &DataKey::NextSlotId, min_remaining);
    }

    /// Pay one note's storage rent.
    ///
    /// A note is persistent entries that nothing touches between
    /// `register_token` and redemption, so a note simply *held* for
    /// longer than [`TTL_EXTEND`] is archived while its holder does
    /// nothing wrong. Protocol 23 restores it automatically, but hands
    /// the restore fee to whoever next touches the entry -- the holder,
    /// at redemption, which is the worst possible moment to surprise
    /// someone holding a bearer instrument.
    ///
    /// A wallet can call this instead, for the price of the days that
    /// have passed. No auth, for the same reason as [`Self::bump`], and
    /// one more: the holder of a bearer note is not an address this
    /// contract knows, so there is nobody to require auth *from*.
    ///
    /// The contract's own entries go with it ([`Self::bump_core`]). A
    /// note whose record is live inside a contract whose code or config
    /// has been archived is not redeemable, so paying for one and not
    /// the other buys nothing. With a keeper running, that part is
    /// already paid and costs nothing here.
    ///
    /// Returns false if the slot holds neither a print nor a token,
    /// which is how a caller learns it named a slot that never existed.
    pub fn bump_token(e: Env, slot_id: u32, ledgers: u32) -> bool {
        // The contract's own entries go to the ceiling regardless. A
        // note inside an archived contract is not redeemable, so paying
        // for one without the other buys nothing.
        Self::bump_core(&e, keeper_threshold(&e));

        // What the caller asked for, or what the network allows.
        let max = e.storage().max_ttl();
        let want = if ledgers < max { ledgers } else { max };

        let mut found = false;
        let core: Option<SlotCore> = e.storage().persistent().get(&DataKey::Slot(slot_id));
        if let Some(core) = core {
            // A slot is working state with a life of its own; a caller
            // cannot extend it past the print window, and has no reason
            // to want to.
            let config = Self::get_config(&e);
            let slot_life = slot_ttl(&e, core.created_at, config.max_print_ledgers);
            if slot_life > 0 {
                Self::bump_key_to(&e, &DataKey::Slot(slot_id), slot_life, slot_life);
                let draw = DataKey::Draw(slot_id);
                if e.storage().temporary().has(&draw) {
                    e.storage().temporary().extend_ttl(&draw, slot_life, slot_life);
                }
            }
            found = true;
        }
        if e.storage().persistent().has(&DataKey::Token(slot_id)) {
            // Asking for less than the note already has is a no-op, so
            // this is safe to call repeatedly and safe to call
            // optimistically.
            Self::bump_key_to(&e, &DataKey::Token(slot_id), want, want);
            found = true;
        }
        found
    }

    /// Refuse an address that is this contract.
    ///
    /// Paying the escrow to the mint consumes the note and leaves the
    /// money in the same balance with nothing recording whose it is:
    /// not theft, but unreachable, and the holder did it to themselves.
    /// Cheap to refuse, impossible to undo.
    ///
    /// Only the unauthenticated addresses need this. `cancel_print`
    /// and `clear_expired_slot` pay `slot.depositor`, `claim_fees`
    /// pays a `require_auth`'d node -- all of which had to sign, and
    /// this contract never calls its own entry points, so it cannot
    /// have. A `recipient` is different: redemption deliberately does
    /// not authenticate it, because the payer side is the contract and
    /// an address cannot be harmed by being sent an asset it trusts.
    fn reject_self(e: &Env, who: &Address) -> Result<(), Error> {
        if who == &e.current_contract_address() {
            return Err(Error::PayoutToSelf);
        }
        Ok(())
    }

    fn get_config(e: &Env) -> MintConfig {
        e.storage()
            .persistent()
            .get(&DataKey::Config)
            .expect("config")
    }

    /// The roster's `node_terms`: `None` if not selectable, else
    /// `Some(volunteer)`.
    fn roster_node_terms(e: &Env, roster: &Address, node: &Address) -> Option<bool> {
        e.invoke_contract::<Option<bool>>(
            roster,
            &Symbol::new(e, "node_terms"),
            (node.clone(),).into_val(e),
        )
    }

    /// When `node` joined the roster, if it is on it.
    fn roster_joined_at(e: &Env, roster: &Address, node: &Address) -> Option<u32> {
        e.invoke_contract::<Option<RosterNode>>(
            roster,
            &Symbol::new(e, "get_node"),
            (node.clone(),).into_val(e),
        )
        .map(|n| n.joined_at)
    }

    fn check_roster_node(e: &Env, roster: &Address, node: &Address) -> bool {
        e.invoke_contract::<bool>(
            roster,
            &Symbol::new(e, "is_node"),
            (node.clone(),).into_val(e),
        )
    }

    /// The owner commitment for an Ed25519 owner public key:
    /// `SHA-256("kntr_v1:spend:owner" || owner_pubkey)`. Must match
    /// `kenter_crypto::spend::owner_commitment`.
    fn owner_commit(e: &Env, owner_pubkey: &BytesN<32>) -> BytesN<32> {
        let mut m = Bytes::new(e);
        m.extend_from_slice(SPEND_OWNER_COMMIT);
        m.extend_from_array(&owner_pubkey.to_array());
        e.crypto().sha256(&m).into()
    }

    /// Enforce the spend-mode ownership invariant at redemption:
    /// a spend-mode token requires a valid owner proof; a pure-bearer token
    /// requires none. The four cases:
    /// - `Spend` + proof → verify the key opens the live commitment and signed
    ///   `SHA-256(SPEND_REDEEM || contract_xdr || slot_id (u32 BE) ||
    ///   ephemeral_key || owner_commitment || spend_nonce (u32 BE) ||
    ///   recipient_xdr)`. The recipient is in the digest so the proof says
    ///   *where* the escrow goes, not merely that it may be released; the
    ///   contract, slot and nonce are there for the reasons `spend` gives.
    /// - `Spend` + no proof → `SpendModeRequiresOwner` (caller used a plain path).
    /// - `PureBearer` + proof → `NotSpendMode` (caller used an owned path).
    /// - `PureBearer` + no proof → ok.
    fn enforce_owner(
        e: &Env,
        token: &TokenRecord,
        ephemeral_key: &BytesN<32>,
        recipient: &Address,
        owner: &Option<(BytesN<32>, BytesN<64>)>,
    ) -> Result<(), Error> {
        match (token.mode, owner) {
            (TokenMode::Spend, Some((owner_pubkey, owner_sig))) => {
                if Self::owner_commit(e, owner_pubkey) != token.owner_commitment {
                    return Err(Error::OwnerCommitmentMismatch);
                }
                let mut m = Bytes::new(e);
                m.extend_from_slice(SPEND_REDEEM);
                // Same two bindings as the spend digest, for the same
                // reasons: the nonce so a proof cannot outlive the
                // ownership state it was made for, and the contract so it
                // cannot cross deployments.
                m.append(&e.current_contract_address().to_xdr(e));
                m.extend_from_array(&token.slot_id.to_be_bytes());
                m.extend_from_array(&ephemeral_key.to_array());
                m.extend_from_array(&token.owner_commitment.to_array());
                m.extend_from_array(&token.spend_nonce.to_be_bytes());
                // The recipient is in the digest, so the owner's signature
                // says "pay this note's escrow to *this* address" rather
                // than merely "redeem this note". Without it, anyone holding
                // a valid proof could redirect the payout — bounded only by
                // `holder.require_auth()`, which is the wrong thing to rely
                // on once submitter and authoriser separate.
                m.append(&recipient.clone().to_xdr(e));
                // Signed over the 32-byte digest, not the message — see `spend`.
                let digest: BytesN<32> = e.crypto().sha256(&m).into();
                let signed = Bytes::from_array(e, &digest.to_array());
                // Traps on a bad signature (the tx reverts).
                e.crypto().ed25519_verify(owner_pubkey, &signed, owner_sig);
                Ok(())
            }
            (TokenMode::Spend, None) => Err(Error::SpendModeRequiresOwner),
            (TokenMode::PureBearer, Some(_)) => Err(Error::NotSpendMode),
            (TokenMode::PureBearer, None) => Ok(()),
        }
    }
}

mod test;
