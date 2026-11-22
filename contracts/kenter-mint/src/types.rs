use soroban_sdk::{contracttype, contracterror, Address, BytesN, String, Symbol, Vec};

// ── Storage Keys ──

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DataKey {
    Config,
    Slot(u32),
    /// A registered note, keyed by the **slot** that produced it.
    ///
    /// Not keyed by `ephemeral_key`: that is a caller-named value that is
    /// public before its owner registers it (`confirm_link` publishes the
    /// partial keys, and `ek` is their sum). With registration refusing to
    /// overwrite, an `ek` key would make it "first to name the key wins":
    /// anyone with a parked completed slot could claim a victim's key the
    /// moment it became computable, and the victim's print could never be
    /// registered at all.
    ///
    /// A slot id is issued by the contract, not chosen by a caller, so
    /// two prints cannot collide. Two slots naming the same `ek`
    /// are simply two records: each has its own escrow, chain hash and
    /// claim key, and a squatter only puts their own deposit within
    /// reach of whoever holds that key.
    Token(u32),
    NextSlotId,
    /// Claimable node-fee balance for a node address (churn-tolerant earnings).
    /// Credited at redemption (both paths), drained by `claim_fees`.
    Accrued(Address),
    /// Marks an `event_id` as spent, so no second print can claim it.
    ///
    /// The chain hash already binds a chain to its token, so this is not the thing standing between a forged chain and an
    /// escrow -- but an `event_id` is how every off-chain party names a
    /// print, and two prints answering to one name is a reconciliation
    /// problem nobody can fix after the fact. Written once per print and
    /// never removed.
    EventIdUsed(BytesN<32>),
    /// A redeemed slot, and the ledger it was redeemed on.
    ///
    /// This replaces the whole `TokenRecord` once a note is paid out.
    /// The record is not needed as the nullifier: a second redemption is refused because
    /// the record it needs is *absent*, not because it is present and
    /// says `Redeemed`. Slot ids come from `NextSlotId` and are never
    /// reused, so a deleted slot can never be resurrected -- the
    /// counter is the nullifier, and the ~450-byte record would only pay
    /// rent to restate what the counter already guarantees.
    ///
    /// What the marker buys back is the difference between "redeemed"
    /// and "never existed", which absence alone cannot express. It is
    /// deliberately *not* bumped: on-chain reads restore it
    /// automatically when a redemption attempt names it, so refusing a
    /// double-redeem stays correct forever, while the off-ledger
    /// convenience of `is_redeemed` lapses when it archives. Safety
    /// does not rest on it -- a holder asking "can I redeem this?" is
    /// answered by `get_token` returning nothing.
    Redeemed(u32),
    /// The pair an address is registered in, and when (`register_pair`).
    ///
    /// Pairs are fixed before a draw so an operator cannot choose which of
    /// its addresses to combine after the seed is public: a score is a hash
    /// of the combination, so free re-pairing let `n` staked addresses try
    /// `n(n-1)/2` pairings against every seed.
    PairOf(Address),
    /// The growing half of a print slot, in **temporary** storage
    /// (`docs/architecture/node-selection.md`, "Where a slot lives"): its
    /// pairs, seed, claims, partial keys and confirmers. `Slot(id)` keeps the escrow and every
    /// fixed-size fact, and never changes size after `request_print`.
    ///
    /// Rent is charged on an entry's growth for its whole remaining life,
    /// and a persistent entry lives at least 120 days on mainnet whatever
    /// the contract asks. Kept on the slot, a claim would cost a node
    /// ~0.045 XLM; here it rents at the temporary rate for the print window.
    Draw(u32),
}

/// An address's registered pair (`DataKey::PairOf`).
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegisteredPair {
    pub partner: Address,
    /// The ledger the pair was registered in. A pair may claim only on
    /// slots requested after it.
    pub registered_at: u32,
}

/// A pair registered (`registered`) or dissolved (`!registered`).
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PairEvent {
    pub node_a: Address,
    pub node_b: Address,
    pub registered: bool,
}

// ── Config ──

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MintConfig {
    pub symbol: Symbol,
    pub node_fee: u32,
    pub min_pairs: u32,
    pub max_pairs: u32,
    pub pay_token: Address,
    pub roster: Address,
    pub max_print_ledgers: u32,
    pub start_ledger: u32,
    /// How interior pairs are chosen.
    pub selection: SelectionConfig,
}

/// How nodes select themselves into a print
/// (`docs/architecture/node-selection.md`).
///
/// Immutable, like the rest of the config. The beacon fields name a drand
/// chain of scheme `bls-unchained-g1-rfc9380` (quicknet). The scheme
/// itself -- hash-to-curve DST, signature group, message -- is fixed in
/// the contract, so only the chain's own constants are parameters.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectionConfig {
    /// The beacon's group key: G2, uncompressed (Soroban's encoding).
    pub beacon_pk: BytesN<192>,
    /// Unix time of the beacon's round 1.
    pub beacon_genesis: u64,
    /// Seconds between rounds.
    pub beacon_period: u64,
    /// Rounds between a request and the round that seeds it. The round
    /// `round_at(request time) + beacon_lead` must not exist yet when the
    /// request lands, or a depositor could know the draw in advance.
    pub beacon_lead: u64,
    /// Ledgers after `seed_print` during which a lower score may still
    /// displace a higher one.
    pub claim_window: u32,
    /// Ledgers a selected pair has to confirm its link before the
    /// depositor may skip it.
    pub serve_timeout: u32,
    /// Ledgers a node must have been on the roster before it may claim
    /// 0 turns the check off.
    pub min_node_age: u32,
}

/// The roster's `Node` record, as `get_node` returns it, read here only
/// for `joined_at` (`min_node_age`).
///
/// A `contracttype` struct crosses contracts as a map keyed by field
/// name, so this must name the same fields with the same types as
/// `kenter-roster`'s `Node`. The roster is immutable, so it cannot drift
/// under a deployed mint; `test::the_mock_roster_node_matches` and the
/// system test against the real roster are what catch a mismatch here.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RosterNode {
    pub address: Address,
    pub name: String,
    pub tunnel_endpoint: String,
    pub staked: i128,
    pub joined_at: u32,
    pub last_heartbeat: u32,
    pub active: bool,
    pub unbonding_at: Option<u32>,
    pub volunteer: bool,
}

// ── Token State Machine ──

#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum TokenState {
    Printing = 0,
    Active = 1,
    Redeemed = 2,
    Cancelled = 3,
}

/// Per-token spend mode, fixed at `register_token`. See
/// `docs/architecture/spend-mode.md`.
///
/// - `PureBearer` — whoever holds the bytes can redeem;
///   `owner_commitment` is unused.
/// - `Spend` — an on-ledger owner pointer (`owner_commitment`) that the current
///   owner moves via `spend` (burning their claim) and that redemption requires
///   opening (the owner-checked redeem paths). Prevents payer double-spend.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum TokenMode {
    PureBearer = 0,
    Spend = 1,
}

// ── Print Slot ──

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PairEntry {
    pub node_a: Address,
    pub node_b: Address,
}

/// A pair's claim on a print, ranked by `score`.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Claim {
    /// `sha256(seed || lower || higher)` over the pair's two addresses'
    /// XDR, ordered bytewise. Computed by the mint, never supplied.
    pub score: BytesN<32>,
    pub pair: PairEntry,
    /// Each member's terms, from the roster at claim time.
    pub volunteer_a: bool,
    pub volunteer_b: bool,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrintSlot {
    pub slot_id: u32,
    pub depositor: Address,
    pub event_id: BytesN<32>,
    pub amount: i128,
    pub total_pairs: u32,
    /// The pairs in chain order, once selection closes.
    ///
    /// Until then it holds only the depositor's two end pairs,
    /// `[first, last]`: the interior positions are nobody's to name
    /// until the draw is in. Closing
    /// inserts the `k` winning claims between them, and a skip replaces
    /// one interior entry with a runner-up.
    pub pairs: Vec<PairEntry>,
    pub completed_links: u32,
    /// Each confirmed link's partial public key, in link order.
    ///
    /// **Published, not checked.** Nothing on-chain reads these: Soroban
    /// exposes no Curve25519 point addition, so the contract cannot sum
    /// them and compare against the `ephemeral_key` a depositor supplies
    /// to `register_token`. They are here so that anyone watching the
    /// ledger can do that sum themselves and confirm the key a note
    /// claims is the key its construction produced.
    ///
    /// They are therefore evidence for observers, not a constraint on
    /// the depositor. Their presence in the slot is not a binding, and
    /// an on-chain reader must not treat it as one.
    pub partial_keys: Vec<BytesN<32>>,
    /// Who confirmed each link, in link order.
    ///
    /// `confirm_link` accepts either member of the assigned pair, and a
    /// shard is derivable by one of them alone -- so "this pair worked"
    /// is not something the chain can see. Only "this address
    /// confirmed" is. Abandoned-slot settlement pays the confirmer and
    /// nobody else, because that is the whole of what is provable.
    pub confirmers: Vec<Address>,
    /// Which participants volunteer: bit `2i` is pair `i`'s `node_a`,
    /// bit `2i + 1` its `node_b`, the same order as
    /// `TokenRecord::participants`. A volunteer's fees are burned, not
    /// credited.
    ///
    /// Taken from the roster's `node_terms` once, when the pair claims
    /// (recorded in its [`Claim`]), and set here when selection closes or
    /// a skip brings in a runner-up. A node is paid on the terms it had
    /// when it claimed, and nothing after the print has to consult the
    /// roster. End pairs are never set: they are the depositor's and draw
    /// no fee.
    /// `MAX_REDEEMABLE_PAIRS = 12` is 24 participants, inside a `u32`.
    pub volunteers: u32,
    pub state: TokenState,
    pub created_at: u32,
    /// The beacon round that seeds this slot, fixed at request.
    pub beacon_round: u64,
    /// Set by `seed_print` from that round's verified signature.
    pub seed: Option<BytesN<32>>,
    /// The last ledger of the claim window; 0 until seeded.
    pub claim_deadline: u32,
    /// Before closing: every competitive claim, lowest score first,
    /// capped at `2k`. After: the runners-up only, in the order they
    /// replace skipped pairs.
    pub claims: Vec<Claim>,
    /// Whether the interior positions are fixed (`pairs` is complete).
    pub closed: bool,
    /// The ledger the current position became current: when selection
    /// closed, or when the previous link was confirmed or skipped. A skip
    /// is allowed `serve_timeout` ledgers after it.
    pub last_progress: u32,
    /// Whether the claim list ever held `k` claims. It never shrinks below
    /// `k` before closing, so this is the one fact about the claims the
    /// forfeit needs, kept where it outlives the draw.
    pub filled: bool,
    /// The draw (`DataKey::Draw`) has lapsed: `pairs` holds only the end
    /// pairs and `seed`, `claims`, `partial_keys` and `confirmers` are
    /// empty because they are gone, not because nothing happened. Only
    /// settlement works on such a slot.
    pub lapsed: bool,
}

/// What `DataKey::Slot` stores: the escrow and every fixed-size fact of a
/// print. Written at `request_print` and rewritten at the **same size**
/// after, so its 120-day mainnet rent is paid once, by the depositor.
/// Assembled with [`SlotDraw`] into the
/// [`PrintSlot`] every reader sees.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SlotCore {
    pub slot_id: u32,
    pub depositor: Address,
    pub event_id: BytesN<32>,
    pub amount: i128,
    pub total_pairs: u32,
    pub first_pair: PairEntry,
    pub last_pair: PairEntry,
    pub completed_links: u32,
    pub volunteers: u32,
    pub state: TokenState,
    pub created_at: u32,
    pub beacon_round: u64,
    /// 0 until seeded, so it also says whether the slot was seeded.
    pub claim_deadline: u32,
    pub filled: bool,
    pub closed: bool,
    pub last_progress: u32,
}

/// What `DataKey::Draw` stores, in temporary storage: the parts of a
/// print that grow as it is selected and built.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SlotDraw {
    pub pairs: Vec<PairEntry>,
    pub seed: Option<BytesN<32>>,
    pub claims: Vec<Claim>,
    pub partial_keys: Vec<BytesN<32>>,
    pub confirmers: Vec<Address>,
}

// ── Token Record ──

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenRecord {
    pub ephemeral_key: BytesN<32>,
    pub event_id: BytesN<32>,
    /// SHA-256 of the canonical Path-B `chain_data` blob, committed by the
    /// depositor at registration. Binds redemption to the real signed chain so
    /// a chain cannot be forged from public data (see
    /// `docs/architecture/security-model.md`).
    pub chain_hash: BytesN<32>,
    pub slot_id: u32,
    pub amount: i128,
    pub node_fee: u32,
    pub participants: Vec<Address>,
    /// Copied from the slot: which `participants` volunteer. See
    /// [`PrintSlot::volunteers`].
    pub volunteers: u32,
    pub state: TokenState,
    pub created_at: u32,
    pub redeemed_at: u32, // 0 = not redeemed
    /// Spend mode for this token (fixed at registration).
    pub mode: TokenMode,
    /// The current owner commitment `SHA-256("kntr_v1:spend:owner" || owner_pubkey)`.
    /// Overwritten each `spend`. Unused (and unchecked) when `mode == PureBearer`.
    pub owner_commitment: BytesN<32>,
    /// How many times this note has been spent on. Part of both owner
    /// digests, so a signature is good for exactly one transfer.
    ///
    /// Without it the digest would be `(ek, current_commitment,
    /// new_commitment)`, which repeats whenever a note returns to an
    /// owner commitment it held before — and the static pay tag (owner
    /// index 0) is a reusable address, so a note coming back as change
    /// or a refund does exactly that. The earlier signature would then
    /// replay, and a former payee could take the note back.
    pub spend_nonce: u32,
    /// Public half of the note's **claim key**, fixed at registration.
    ///
    /// The secret half travels inside the note container and is never sent
    /// to this contract. Path B redemption presents a signature from it
    /// rather than the chain preimage alone, which is what stops a
    /// redemption being lifted out of the ledger: `chain_data` is published
    /// by any attempt, successful or failed, and a failed one leaves the
    /// note Active with its secret in public view.
    ///
    /// This does not make the note non-bearer. The key is in the file, not
    /// tied to a person: copy the file and you copy the right to redeem.
    /// Spend mode is the opposite trade and is already recipient-bound, so
    /// it does not need one.
    pub claim_pubkey: BytesN<32>,
}

// ── Events ──

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrintRequestEvent {
    pub slot_id: u32,
    pub event_id: BytesN<32>,
    pub amount: i128,
    pub total_pairs: u32,
    /// The depositor's own end pairs. The interior is chosen by the draw.
    pub first_pair: PairEntry,
    pub last_pair: PairEntry,
    pub depositor: Address,
    /// The beacon round whose signature will seed the slot.
    pub beacon_round: u64,
}

/// The slot is seeded: pairs may claim until `claim_deadline`.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrintSeededEvent {
    pub slot_id: u32,
    pub beacon_round: u64,
    pub seed: BytesN<32>,
    pub claim_deadline: u32,
    /// Interior positions to fill (`k`).
    pub positions: u32,
}

/// A claim was accepted at `rank` (0 is the lowest score so far).
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimEvent {
    pub slot_id: u32,
    pub pair: PairEntry,
    pub score: BytesN<32>,
    pub rank: u32,
}

/// Selection closed: `pairs` is the chain, end pairs included.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrintSelectedEvent {
    pub slot_id: u32,
    pub pairs: Vec<PairEntry>,
}

/// The depositor skipped a selected pair that did not serve, and a
/// runner-up took its place. `fee` is what the depositor paid to do it,
/// burned.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SkipEvent {
    pub slot_id: u32,
    pub position: u32,
    pub skipped: PairEntry,
    pub replacement: PairEntry,
    pub fee: i128,
}

/// Positions abandoned after a draw, burned out of the escrow at cancel or
/// expiry.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForfeitEvent {
    pub slot_id: u32,
    pub positions: u32,
    pub amount: i128,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinkConfirmedEvent {
    pub slot_id: u32,
    pub link_index: u32,
    pub completed_links: u32,
    pub confirmer: Address,
    pub partial_public_key: BytesN<32>,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrintCancelledEvent {
    pub slot_id: u32,
    pub event_id: BytesN<32>,
    pub refund: i128,
    /// What the confirmers were paid out of the deposit. `refund +
    /// earned + burned` is the whole of it, which is the check a
    /// depositor following events needs.
    pub earned: i128,
    /// Volunteer confirmers' fees, destroyed rather than paid.
    pub burned: i128,
    /// Abandoned positions' fees, burned.
    /// `refund + earned + burned + forfeited` is the deposit.
    pub forfeited: i128,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenActiveEvent {
    pub slot_id: u32,
    pub event_id: BytesN<32>,
    pub ephemeral_key: BytesN<32>,
    /// The **gross** escrow. Node fees come off it at redemption, so
    /// this is not the figure a `Redeem*` event reports.
    pub amount: i128,
    /// Who registered it.
    pub depositor: Address,
    /// Spend mode, fixed at registration.
    pub mode: TokenMode,
    /// The chain commitment, and the claim key.
    ///
    /// Without these an indexer following events alone cannot tell
    /// which note a given `ephemeral_key` belongs to — and since
    /// records are keyed by slot, two of them may legitimately name
    /// the same key.
    pub chain_hash: BytesN<32>,
    pub claim_pubkey: BytesN<32>,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RedeemByKeyEvent {
    /// Which record was redeemed.
    ///
    /// The key does not identify one: records are keyed by slot, so two
    /// may legitimately name the same `ephemeral_key`. `TokenActive` and
    /// `Spend` carry it too; the redemption events need it most, since
    /// they are the ones that say where the money went.
    pub slot_id: u32,
    pub ephemeral_key: BytesN<32>,
    /// Who submitted the transaction.
    ///
    /// **Not who was paid.** `redeem_*` takes a separate `recipient`, so
    /// an indexer reading this as the payee is wrong every time the two
    /// differ -- which is the ordinary case for a redemption directed
    /// anywhere but the submitter's own account.
    pub holder: Address,
    /// Who the escrow was actually paid to.
    pub recipient: Address,
    pub amount: i128,
    /// Total node fees credited to participants' accrual balances (claimable
    /// via `claim_fees`), not paid instantly.
    pub node_fees_accrued: i128,
    /// Volunteers' fees, burned. `amount + node_fees_accrued +
    /// node_fees_burned` is the escrow.
    pub node_fees_burned: i128,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RedeemByChainEvent {
    /// Which record was redeemed — see [`RedeemByKeyEvent::slot_id`].
    pub slot_id: u32,
    pub ephemeral_key: BytesN<32>,
    /// Who submitted the transaction. **Not who was paid** -- see
    /// [`RedeemByKeyEvent::holder`].
    pub holder: Address,
    /// Who the escrow was actually paid to.
    pub recipient: Address,
    pub amount: i128,
    /// Total node fees credited to participants' accrual balances, claimable
    /// via `claim_fees`. Safe on Path B because the chain hash binds
    /// redemption to the real chain.
    pub node_fees_accrued: i128,
    /// Volunteers' fees, burned -- see [`RedeemByKeyEvent::node_fees_burned`].
    pub node_fees_burned: i128,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FeesClaimedEvent {
    pub node: Address,
    pub amount: i128,
}

/// Emitted on a spend-mode ownership transfer. Endpoints are opaque commitments;
/// an observer can see the token changed hands but not who to. Successive
/// spends of one token are linkable to each other; that per-token linkage
/// is accepted (see `docs/architecture/spend-mode.md`).
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpendEvent {
    /// Which record moved. The key alone does not identify one.
    pub slot_id: u32,
    pub ephemeral_key: BytesN<32>,
    pub new_owner_commitment: BytesN<32>,
    /// The nonce **after** this spend. An observer rebuilding owner
    /// history from events needs it to know where the next
    /// authorisation has to be made.
    pub spend_nonce: u32,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SlotExpiredEvent {
    pub slot_id: u32,
    pub event_id: BytesN<32>,
    pub refund: i128,
    pub depositor: Address,
    /// As on `PrintCancelledEvent`: the settled part of the deposit.
    pub earned: i128,
    /// As on `PrintCancelledEvent`.
    pub burned: i128,
    /// As on `PrintCancelledEvent`.
    pub forfeited: i128,
}

/// A volunteer's fee, destroyed instead of credited.
///
/// One per volunteer per settlement, redemption included, so anyone can
/// check from events alone that a volunteer was never paid for the
/// settlements it volunteered on.
///
/// Terms are per address and fixed when a print is requested. An
/// address that volunteered from its first join is never credited, so
/// its `Accrued` balance stays at zero. One that converted keeps what it
/// accrued while paid, and is still credited by prints requested before
/// it converted.
///
/// If the pay token refused the burn, the settlement also emits a
/// [`FeeLockedEvent`]: the amount stayed in the mint instead, where
/// nothing can move it.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FeeBurnedEvent {
    pub slot_id: u32,
    pub node: Address,
    pub amount: i128,
}

/// The pay token refused a settlement's burn, so the volunteers' fees
/// (`amount`, the settlement's total) stay in the mint's balance. No
/// entry point can move them: they are no node's `Accrued` and no slot's
/// escrow, so they are as unreachable as burned. A burn that traps
/// would instead have locked the holder's payout or the depositor's
/// refund forever.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FeeLockedEvent {
    pub slot_id: u32,
    pub amount: i128,
}

/// Emitted once per confirmer credited by an abandoned print.
///
/// Redemption reports its payouts in aggregate on the `Redeem*` events.
/// Without this, settling a cancelled or expired slot would publish
/// nothing, and a node that had earned a fee could learn of it only by
/// polling `get_accrued` against every slot it ever touched. The amount is what this settlement credited, not the running
/// balance.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FeeAccruedEvent {
    pub slot_id: u32,
    pub node: Address,
    pub amount: i128,
}

// ── Errors ──

#[contracterror]
#[derive(Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Error {
    // Print slots
    InvalidPairCount = 20,
    NodeNotOnRoster = 21,
    SlotNotFound = 22,
    SlotNotPrinting = 23,
    SlotExpired = 24,
    NotAssignedPair = 25,
    LinkOutOfOrder = 26,
    PrintAlreadyComplete = 27,
    NotDepositor = 28,
    PrintNotComplete = 29,
    SlotNotExpired = 30,

    /// A pair whose two nodes are the same address, or a node that
    /// appears in more than one pair of the same print.
    ///
    /// A "pair" of one node is not a pair: the two-party construction is
    /// what makes a shard take two parties to produce, and one operator
    /// holding both halves of a link -- or every link -- collapses that
    /// to a single point of trust while still looking like a chain.
    NodesNotDistinct = 31,

    /// This `event_id` has been used by an earlier print.
    EventIdInUse = 32,

    // Selection
    /// The slot's beacon round has not been posted yet.
    NotSeeded = 33,
    /// `seed_print` on a slot that already has its seed.
    AlreadySeeded = 34,
    /// The signature does not verify as the beacon's for this slot's round.
    BadBeacon = 35,
    /// No more claims: selection has closed, or the window has passed
    /// with every position filled.
    ClaimsClosed = 36,
    /// The claim list is full and this score is not lower than its last.
    ClaimNotCompetitive = 37,
    /// Interior links wait for selection: the window has not passed, or
    /// fewer pairs than positions have claimed.
    SelectionNotReady = 38,
    /// Every runner-up has been used.
    NoBackup = 39,

    // Tokens
    TokenNotFound = 40,
    TokenNotActive = 41,
    AlreadyRedeemed = 42,
    InvalidSignature = 43,
    ChainVerificationFailed = 44,
    /// A record already exists for this slot.
    ///
    /// **Unreachable in practice, and kept deliberately.** Registration
    /// must never write over an existing entry: `ephemeral_key` is the
    /// sum of the partial public keys `confirm_link` publishes, so anyone
    /// watching the ledger can compute one.
    ///
    /// Records are keyed by **slot**, and `register_token` requires a
    /// `Printing` slot and deletes it, so a second registration is
    /// refused as `SlotNotFound` before this check runs. The check stays because it
    /// guards the nullifier directly instead of relying on an invariant
    /// about a different key.
    ///
    /// Note what is *not* prevented: a redeemed `ephemeral_key` can be
    /// registered again under a **new slot**. That is a separate record
    /// with its own escrow, and it takes nothing from the first.
    TokenExists = 49,

    // Accrual
    NothingToClaim = 45,

    // Spend mode
    NotSpendMode = 46,           // spend/owned-redeem called on a pure-bearer token
    SpendModeRequiresOwner = 47, // plain redeem called on a spend-mode token
    OwnerCommitmentMismatch = 48, // revealed owner key does not open the live commitment
    /// A payout or a participant slot named this contract.
    ///
    /// The escrow would leave the books and arrive back in the same
    /// balance with nothing recording that it is owed to anyone -- not
    /// stolen, but unreachable, and the note consumed.
    PayoutToSelf = 50,

    // Payment
    InvalidAmount = 51,

    // Deployment
    /// The constructor was given parameters no print could ever satisfy.
    ///
    /// A mint is immutable, so a deployment that cannot mint is permanent:
    /// the only remedy is to deploy again and tell everyone the old address
    /// is dead. Rejecting at construction is the one chance to catch it.
    InvalidConfig = 52,

    // Selection, continued
    /// The pair at this position has not yet had `serve_timeout` ledgers.
    ServeTimeoutNotReached = 53,
    /// Only the next interior position can be skipped.
    NotSkippable = 54,
    /// A member of the pair joined the roster less than `min_node_age`
    /// ledgers ago.
    NodeTooNew = 55,
    /// One of the addresses is already in a registered pair; `unpair` first.
    AlreadyPaired = 56,
    /// The caller is in no registered pair.
    NotPaired = 57,
    /// The claim is not a pair registered before this slot was requested.
    PairNotRegistered = 58,
    /// The slot's draw (`DataKey::Draw`) has lapsed while the slot is
    /// still inside its window. Reachable only on a mint whose window is
    /// longer than the network's `max_entry_ttl`, after that long with no
    /// write. Cancel still settles it.
    DrawLapsed = 59,
}
