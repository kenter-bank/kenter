use soroban_sdk::{contracttype, Address, String, Symbol};

pub const MAX_STRING_LENGTH: u32 = 256;

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DataKey {
    Node(Address),
    Config,
    NodeCount,
    /// This address has volunteered. Written once and **never removed**.
    ///
    /// It outlives the `Node` record on purpose: `withdraw_stake`
    /// deletes the record, and a flag that lived only there would let
    /// an address volunteer for a while, leave, and come back as a
    /// paid node. `join` reads this, so a returning volunteer is a
    /// volunteer again whichever entry point it uses.
    ///
    /// `join` and `heartbeat` bump it alongside the record it governs.
    /// Even if it archives, it is restored automatically when a
    /// transaction lists it, and `join` lists it, so the guarantee holds;
    /// only an off-ledger read of the key can lapse, and `get_node`
    /// answers the same question for a node that is registered.
    Volunteer(Address),
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RosterConfig {
    pub symbol: Symbol,
    pub pay_token: Address,
    /// The bond, in stroops of `pay_token`.
    ///
    /// `i128`, not `u32`. A `u32` would cap one node's bond at
    /// 429.4967295 XLM -- a permanent ceiling on what a single roster
    /// identity could be made to cost, and the Sybil price is the
    /// whole point of the bond. Token amounts are `i128` everywhere
    /// else in Soroban, and the contract is immutable, so there is no
    /// later moment to widen it.
    pub min_stake: i128,
    pub start_ledger: u32,
    /// Ledgers a node must wait between `leave` and reclaiming its stake.
    ///
    /// This is what gives roster membership a *cost*. A stake returned on
    /// demand is a deposit, not a barrier: an attacker can register many
    /// identities, use them, and withdraw immediately, so the capital is never
    /// actually at risk and the Sybil price is transaction fees. A delay
    /// converts it into capital locked for a period, which is the standard
    /// Sybil lever and needs no fraud proofs — useful here precisely because
    /// node misbehaviour (failing to serve, or reconstructing a key off-chain)
    /// leaves no on-chain evidence to slash on. See
    /// `docs/architecture/security-model.md`.
    pub unbonding_ledgers: u32,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Node {
    pub address: Address,
    pub name: String,
    pub tunnel_endpoint: String,
    pub staked: i128,
    pub joined_at: u32,
    pub last_heartbeat: u32,
    pub active: bool,
    /// Ledger at which an unbonding stake becomes withdrawable; `None` when the
    /// node is not unbonding.
    ///
    /// An `Option` rather than a `0` sentinel: with a zero unbonding delay at a
    /// low ledger sequence the computed value *is* 0, which a sentinel would
    /// read as "not unbonding" and the withdrawal would be refused forever.
    pub unbonding_at: Option<u32>,
    /// A volunteer serves without pay: the mint burns its fees instead
    /// of crediting them. One way only --
    /// nothing sets this back to `false`.
    pub volunteer: bool,
}

// Events

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeJoinEvent {
    pub node: Address,
    pub name: String,
    pub tunnel_endpoint: String,
    pub staked: i128,
    /// Joined as a volunteer, whether through `volunteer` or through
    /// `join` by an address that had volunteered before.
    pub volunteer: bool,
}

/// A registered paid node has become a volunteer, permanently.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeVolunteerEvent {
    pub node: Address,
}

/// A node has begun unbonding: no longer selectable, stake not yet returned.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeUnbondEvent {
    pub node: Address,
    pub staked: i128,
    pub unbonding_at: u32,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeLeaveEvent {
    pub node: Address,
    pub stake_returned: i128,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeUpdateEvent {
    pub node: Address,
    pub tunnel_endpoint: String,
    pub active: bool,
}
