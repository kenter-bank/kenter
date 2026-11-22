#![no_std]

mod types;

use soroban_sdk::{
    contract, contractimpl, symbol_short, Address, Env, String, Symbol, token,
};

use types::*;

const KNTRROST: Symbol = symbol_short!("KNTRROST");

// ── State archival ──
//
// Every mutating entry point extends the TTLs it touches. Protocol 23
// restores an archived persistent entry automatically when the transaction
// lists it, so a node's record and its stake are never lost to archival --
// but without bumps the restore fee lands on whoever next touches the
// entry, which for a long-dormant node is the node itself, and an
// off-ledger read of an archived `Node` can answer "not registered" about
// a node that is.
//
// Reads do not bump: `is_node` is called by the mint on every
// `request_print`, and a query that wrote would bill that caller.

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

#[contract]
pub struct KenterRoster;

#[contractimpl]
impl KenterRoster {
    /// No admin, and no fee, because there is nobody to collect one.
    ///
    /// Nothing here can remove a node, forfeit a bond or redirect funds
    /// (see `docs/architecture/security-model.md`):
    ///
    /// - **There is nothing provable to punish on.** Failing to serve a
    ///   shard is not provable and reconstructing a key off-chain leaves
    ///   no trace, so a removal power would be confiscation on someone's
    ///   say-so, not punishment.
    /// - **A forfeit could not work anyway.** Burning a stake goes
    ///   through the SAC's `burn`, which Stellar refuses for the native
    ///   asset, so on an XLM-staked roster every forfeit would revert.
    /// - **It would be a liability to the mint.** `confirm_link` requires
    ///   live roster membership for interior links, so removing a node
    ///   during a print would strand the slot.
    /// - **No party can redirect funds.** Every stroop the contract holds
    ///   belongs to the node that posted it.
    ///
    /// The Sybil price is cost-to-enter and time-to-exit: `min_stake`
    /// locked for `unbonding_ledgers` past `leave`. That is the only
    /// lever that is enforceable on-chain.
    pub fn __constructor(
        e: Env,
        min_stake: i128,
        pay_token: Address,
        unbonding_ledgers: u32,
    ) {
        // A bond cannot be negative, and `i128` does not say so for us.
        // A negative bond would make joining free and record a node with
        // negative `staked`, which `withdraw_stake` has no business
        // meeting.
        //
        // Zero stays legal: a roster with no bond is a deliberate
        // configuration, and the tests use it.
        if min_stake < 0 {
            panic!("min_stake must not be negative");
        }

        let config = RosterConfig {
            symbol: KNTRROST,
            pay_token,
            min_stake,
            start_ledger: e.ledger().sequence(),
            unbonding_ledgers,
        };

        e.storage().persistent().set(&DataKey::Config, &config);
        e.storage().persistent().set(&DataKey::NodeCount, &0_u32);
    }

    // ── Node Lifecycle ──

    /// Keep the contract, its code, and the entries the constructor
    /// always writes alive. Every entry point that mutates calls this.
    fn bump_core(e: &Env, min_remaining: u32) {
        e.storage()
            .instance()
            .extend_ttl(min_remaining, extend_to(e));
        for key in [DataKey::Config, DataKey::NodeCount] {
            e.storage()
                .persistent()
                .extend_ttl(&key, min_remaining, extend_to(e));
        }
        // There is nothing else to keep alive. The config and the node
        // count are written by the constructor and always present, so
        // the loop above needs no conditionals. A singleton that exists
        // only sometimes would need a conditional bump here, because an
        // archived entry reads as its default.
    }

    /// Extend one persistent entry. `extend_ttl` panics on a missing key,
    /// so every call follows a write.
    fn bump_key(e: &Env, key: &DataKey, min_remaining: u32) {
        e.storage()
            .persistent()
            .extend_ttl(key, min_remaining, extend_to(e));
    }

    // ── Rent, paid from outside ──

    /// Pay this contract's storage rent without doing anything else.
    ///
    /// Takes no auth and names no caller. Topping up rent cannot harm
    /// anyone -- the caller spends their own fee to extend an entry
    /// nobody else is charged for -- and gating it behind an admin key
    /// would mean a dormant roster could only be rescued by an admin.
    ///
    /// The internal bumps are lazy on purpose: [`Self::bump_core`] acts
    /// only once an entry is within [`TTL_THRESHOLD`] of archival, so an
    /// ordinary caller almost never pays rent. The cost of that is a
    /// lottery. When the threshold is finally crossed the whole top-up
    /// lands on whichever transaction is next through the door, and
    /// because the instance bump carries the contract's code entry with
    /// it, that is the largest single entry here. Measured on this
    /// contract's own first `join`: 21.79 XLM for the transaction that
    /// paid it, 0.095 XLM for the next one, with byte-identical
    /// footprints.
    ///
    /// This is the other half of that design. A keeper calling `bump`
    /// tops the entries back up whatever their remaining life, so the
    /// cost tracks how often it is called -- a daily keeper pays a day
    /// of rent a day -- and the lazy threshold is never reached, so no
    /// node ever meets the lump.
    ///
    /// A node's own record is not bumped here: [`Self::heartbeat`]
    /// already does that, and it is the node's own business to stay
    /// alive on a roster it is being paid to serve.
    ///
    /// Returns the ledger the core entries now live until.
    pub fn bump(e: Env) -> u32 {
        Self::bump_core(&e, keeper_threshold(&e));
        e.ledger().sequence().saturating_add(extend_to(&e))
    }

    /// Join as an ordinary node, paid `node_fee` by the mint for its work.
    ///
    /// An address that has ever volunteered joins as a volunteer here
    /// too: the choice is permanent (see [`Self::volunteer`]).
    pub fn join(
        e: Env,
        caller: Address,
        name: String,
        tunnel_endpoint: String,
    ) -> Node {
        caller.require_auth();
        let marker = DataKey::Volunteer(caller.clone());
        let volunteer = e.storage().persistent().has(&marker);
        let node = Self::enroll(&e, caller, name, tunnel_endpoint, volunteer);
        if volunteer {
            // Keep the marker as live as the record it governs, rather
            // than resting permanence on how archived entries are read.
            Self::bump_key(&e, &marker, threshold(&e));
        }
        node
    }

    /// Serve without pay: join (or convert) as a node whose fees the
    /// mint burns rather than credits.
    ///
    /// **Why it exists.** The mint and this roster take nothing, but
    /// every interior node is paid `node_fee` on redemption. An operator
    /// that wants to show its nodes collect no fees needs a way to prove
    /// it on-chain. Open to anyone, so no list of addresses is fixed at
    /// deploy and the flag says "takes no fees", not whose node it is.
    ///
    /// **Burned, not waived.** A depositor pays the same whoever prints,
    /// so volunteers do not undercut paid operators -- they compete on
    /// equal terms and cannot profit.
    ///
    /// **Permanent.** The address is marked for good: a later `leave`,
    /// `withdraw_stake` and `join` comes back as a volunteer. Otherwise
    /// a node could volunteer for a while and switch to paid
    /// afterwards, which is the claim this exists to make checkable.
    ///
    /// A registered paid node converts in place: only the flag changes.
    /// `name` and `tunnel_endpoint` are used for a new enrollment and
    /// ignored on conversion, so converting cannot erase an endpoint the
    /// node recorded; `update_node` changes those.
    /// Calling it on a node that already volunteers panics, as `join`
    /// does on a node that is already registered.
    pub fn volunteer(
        e: Env,
        caller: Address,
        name: String,
        tunnel_endpoint: String,
    ) -> Node {
        caller.require_auth();

        if name.len() as u32 > MAX_STRING_LENGTH
            || tunnel_endpoint.len() as u32 > MAX_STRING_LENGTH
        {
            panic!("name and endpoint must be {} characters or less", MAX_STRING_LENGTH);
        }

        let marker = DataKey::Volunteer(caller.clone());
        let existing: Option<Node> = e
            .storage()
            .persistent()
            .get(&DataKey::Node(caller.clone()));

        let node = match existing {
            None => Self::enroll(&e, caller.clone(), name, tunnel_endpoint, true),
            Some(mut node) => {
                if node.volunteer {
                    panic!("already volunteering");
                }
                node.volunteer = true;
                e.storage()
                    .persistent()
                    .set(&DataKey::Node(caller.clone()), &node);
                Self::bump_core(&e, threshold(&e));
                Self::bump_key(&e, &DataKey::Node(caller.clone()), threshold(&e));
                e.events().publish(
                    (symbol_short!("VOLUNTEER"), symbol_short!("node")),
                    NodeVolunteerEvent {
                        node: caller.clone(),
                    },
                );
                node
            }
        };

        // Written after the record, and once: a second `volunteer` has
        // already panicked above, and `join` never writes it.
        e.storage().persistent().set(&marker, &true);
        Self::bump_key(&e, &marker, threshold(&e));

        node
    }

    /// Register `caller`, taking its bond. Shared by [`Self::join`] and
    /// [`Self::volunteer`]; auth is the caller's to have checked.
    fn enroll(
        e: &Env,
        caller: Address,
        name: String,
        tunnel_endpoint: String,
        volunteer: bool,
    ) -> Node {
        let e = e.clone();
        if name.len() as u32 > MAX_STRING_LENGTH
            || tunnel_endpoint.len() as u32 > MAX_STRING_LENGTH
        {
            panic!("name and endpoint must be {} characters or less", MAX_STRING_LENGTH);
        }

        let config: RosterConfig = e
            .storage()
            .persistent()
            .get(&DataKey::Config)
            .expect("config not found");

        if e.storage().persistent().has(&DataKey::Node(caller.clone())) {
            panic!("already registered");
        }

        // The bond, and nothing else: there is no join fee (see
        // `__constructor`). Everything this contract holds belongs to the node that posted it, which makes the solvency
        // invariant a single line: `balance == sum(staked)`.
        if config.min_stake > 0 {
            let client = token::Client::new(&e, &config.pay_token);
            client.transfer(&caller, &e.current_contract_address(), &config.min_stake);
        }

        let ledger = e.ledger().sequence();
        let node = Node {
            address: caller.clone(),
            name: name.clone(),
            tunnel_endpoint: tunnel_endpoint.clone(),
            staked: config.min_stake,
            joined_at: ledger,
            last_heartbeat: ledger,
            active: true,
            unbonding_at: None,
            volunteer,
        };

        e.storage()
            .persistent()
            .set(&DataKey::Node(caller.clone()), &node);

        // Increment node count
        let count: u32 = e
            .storage()
            .persistent()
            .get(&DataKey::NodeCount)
            .unwrap_or(0);
        e.storage()
            .persistent()
            .set(&DataKey::NodeCount, &(count + 1));

        Self::bump_core(&e, threshold(&e));
        Self::bump_key(&e, &DataKey::Node(caller.clone()), threshold(&e));

        // Emit join event
        e.events().publish(
            (symbol_short!("JOIN"), symbol_short!("node")),
            NodeJoinEvent {
                node: caller,
                name,
                tunnel_endpoint,
                staked: config.min_stake,
                volunteer,
            },
        );

        node
    }

    pub fn update_node(
        e: Env,
        caller: Address,
        name: Option<String>,
        tunnel_endpoint: Option<String>,
        active: Option<bool>,
    ) -> Node {
        caller.require_auth();

        let mut node: Node = e
            .storage()
            .persistent()
            .get(&DataKey::Node(caller.clone()))
            .expect("not registered");

        if let Some(n) = name {
            if n.len() as u32 > MAX_STRING_LENGTH {
                panic!("name must be {} characters or less", MAX_STRING_LENGTH);
            }
            node.name = n;
        }

        if let Some(ep) = tunnel_endpoint {
            if ep.len() as u32 > MAX_STRING_LENGTH {
                panic!("endpoint must be {} characters or less", MAX_STRING_LENGTH);
            }
            node.tunnel_endpoint = ep;
        }

        // Toggling `active` moves the node in or out of the selectable
        // pool, so it has to move `NodeCount` too. Leaving the count
        // untouched on deactivation would over-report the pool, and that
        // feeds anything that sizes selection on the count.
        //
        // An unbonding node is already out of the count, so toggling
        // `active` on one must not move it again.
        let was_counted = Self::counted(&node);
        if let Some(a) = active {
            node.active = a;
        }
        let now_counted = Self::counted(&node);

        e.storage()
            .persistent()
            .set(&DataKey::Node(caller.clone()), &node);

        if was_counted != now_counted {
            let count: u32 = e
                .storage()
                .persistent()
                .get(&DataKey::NodeCount)
                .unwrap_or(0);
            let next = if now_counted {
                count.saturating_add(1)
            } else {
                count.saturating_sub(1)
            };
            e.storage().persistent().set(&DataKey::NodeCount, &next);
        }

        Self::bump_core(&e, threshold(&e));
        Self::bump_key(&e, &DataKey::Node(caller.clone()), threshold(&e));

        // Emit update event
        e.events().publish(
            (symbol_short!("UPDATE"), symbol_short!("node")),
            NodeUpdateEvent {
                node: caller,
                tunnel_endpoint: node.tunnel_endpoint.clone(),
                active: node.active,
            },
        );

        node
    }

    pub fn heartbeat(e: Env, caller: Address) -> u32 {
        caller.require_auth();

        let mut node: Node = e
            .storage()
            .persistent()
            .get(&DataKey::Node(caller.clone()))
            .expect("not registered");

        let ledger = e.ledger().sequence();
        node.last_heartbeat = ledger;

        e.storage()
            .persistent()
            .set(&DataKey::Node(caller.clone()), &node);

        // The heartbeat is what a node that is doing nothing else still
        // sends, which makes it the call that keeps its record off the
        // archive queue.
        Self::bump_core(&e, threshold(&e));
        Self::bump_key(&e, &DataKey::Node(caller.clone()), threshold(&e));
        // And the volunteer marker with it, which outlives the record it
        // governs.
        if node.volunteer {
            Self::bump_key(&e, &DataKey::Volunteer(caller), threshold(&e));
        }

        ledger
    }

    /// Begin unbonding: stop being selectable immediately, reclaim the stake
    /// only after `unbonding_ledgers` have passed.
    ///
    /// Returns the ledger at which [`Self::withdraw_stake`] becomes callable.
    ///
    /// The delay is the point. Returning the stake on demand would make
    /// registration free in substance — an attacker could register a fleet,
    /// use it, and exit with the capital intact. Making exit slow is the only
    /// Sybil lever available here, because node misbehaviour produces no
    /// on-chain evidence to slash on.
    pub fn leave(e: Env, caller: Address) -> u32 {
        caller.require_auth();

        let mut node: Node = e
            .storage()
            .persistent()
            .get(&DataKey::Node(caller.clone()))
            .expect("not registered");

        if node.unbonding_at.is_some() {
            panic!("already unbonding");
        }

        let config: RosterConfig = e
            .storage()
            .persistent()
            .get(&DataKey::Config)
            .expect("config not found");

        // Saturating, for the reason the mint's print window is: this is
        // `u32` with overflow checks on in release, and `u32::MAX` is the
        // obvious way to write "unbonding is effectively permanent".
        // Plain addition would make that deployment trap in every
        // `leave`, so no node could begin unbonding and no stake could ever
        // be withdrawn -- on an immutable contract holding those stakes.
        // Saturating gives the configuration the meaning it was reaching
        // for: the release ledger lands on the last one there is.
        let unbonding_at = e
            .ledger()
            .sequence()
            .saturating_add(config.unbonding_ledgers);
        // Drop out of the active count now, not at withdrawal: an
        // unbonding node must not be selectable for new prints.
        //
        // Only if it was still counted. `update_node` can already have
        // taken a node out by deactivating it, and decrementing again
        // here would let any node shrink the roster's own idea of its
        // size for free. The count means one thing -- how many
        // nodes `is_node` would accept -- and only a change in that
        // answer may move it.
        let was_counted = Self::counted(&node);
        node.active = false;
        node.unbonding_at = Some(unbonding_at);
        e.storage()
            .persistent()
            .set(&DataKey::Node(caller.clone()), &node);

        if was_counted {
            let count: u32 = e
                .storage()
                .persistent()
                .get(&DataKey::NodeCount)
                .unwrap_or(1);
            e.storage()
                .persistent()
                .set(&DataKey::NodeCount, &count.saturating_sub(1));
        }

        // The record must outlive the unbonding period or the node pays to
        // restore it before it can withdraw its own stake.
        Self::bump_core(&e, threshold(&e));

        // The record has to still be there when the stake comes due, so
        // this replaces the ordinary bump rather than following it.
        //
        // The ordinary one carries an entry 120 days, which is shorter
        // than an `unbonding_ledgers` set beyond that -- the record would
        // archive before its own deadline and charge the node a restore
        // to collect its own stake. Ask for
        // whichever is longer, clamped to what the network allows.
        let needed = config
            .unbonding_ledgers
            .saturating_add(DAY_LEDGERS)
            .max(extend_to(&e));
        let ceiling = e.storage().max_ttl();
        let want = if needed < ceiling { needed } else { ceiling };
        e.storage().persistent().extend_ttl(
            &DataKey::Node(caller.clone()),
            want.saturating_sub(1),
            want,
        );

        e.events().publish(
            (symbol_short!("UNBOND"), symbol_short!("node")),
            NodeUnbondEvent {
                node: caller,
                staked: node.staked,
                unbonding_at,
            },
        );

        unbonding_at
    }

    /// Reclaim the stake once unbonding has elapsed, removing the node record.
    ///
    /// Returns the amount transferred back: the node's whole bond.
    pub fn withdraw_stake(e: Env, caller: Address) -> i128 {
        caller.require_auth();

        let node: Node = e
            .storage()
            .persistent()
            .get(&DataKey::Node(caller.clone()))
            .expect("not registered");

        let unbonding_at = match node.unbonding_at {
            Some(at) => at,
            None => panic!("not unbonding — call leave() first"),
        };
        if e.ledger().sequence() < unbonding_at {
            panic!("stake is still unbonding");
        }

        // The stake, whole, to the node that posted it.
        //
        // This is the contract's only outflow, and `caller.require_auth()`
        // above is the only key that opens it. Adminless does not mean the
        // funds are unreachable -- it means they are reachable by nobody
        // except their owner. Every stroop held belongs to some node and
        // is reclaimable by that node once its period elapses.
        //
        // The corollary, stated because it is permanent: a node that
        // loses its key strands its bond forever. There is no admin to
        // rescue it and no entry point that could.
        //
        // Nothing is added to it. Sharing forfeited bonds out among nodes
        // would need a divisor that tracks exactly the set able to claim;
        // any drift between the two leaves the contract owing more than
        // it holds and refusing whoever withdraws last. Nothing forfeits
        // a bond, so there is nothing to divide and nothing to drift.
        let payout = node.staked;
        if payout > 0 {
            let config: RosterConfig = e
                .storage()
                .persistent()
                .get(&DataKey::Config)
                .expect("config not found");
            let client = token::Client::new(&e, &config.pay_token);
            client.transfer(&e.current_contract_address(), &caller, &payout);
        }

        e.storage()
            .persistent()
            .remove(&DataKey::Node(caller.clone()));

        // The node's own record is gone; the roster's singletons stay.
        Self::bump_core(&e, threshold(&e));

        e.events().publish(
            (symbol_short!("LEAVE"), symbol_short!("node")),
            NodeLeaveEvent {
                node: caller,
                stake_returned: node.staked,
            },
        );

        payout
    }

    /// Whether this address is in the **selectable** pool.
    ///
    /// Record existence is not enough: an unbonding or deactivated node
    /// still has a record, and the mint gates prints on this call.
    /// Letting a node on its way out be named in a fresh print would
    /// hand a departing operator shards it has no further stake in.
    ///
    /// `NodeCount` is defined as the number of nodes for which this is
    /// true, and every path that can change the answer has to move the
    /// count with it. Stated as one predicate because the alternative --
    /// each entry point spelling the condition out again -- is how one
    /// path ends up decrementing for a node another path already removed
    /// from the count.
    fn counted(node: &Node) -> bool {
        node.active && node.unbonding_at.is_none()
    }

    pub fn is_node(e: Env, address: Address) -> bool {
        match e
            .storage()
            .persistent()
            .get::<DataKey, Node>(&DataKey::Node(address))
        {
            Some(node) => Self::counted(&node),
            None => false,
        }
    }

    /// [`Self::is_node`] and the node's terms in one read: `None` if the
    /// address is not in the selectable pool, otherwise `Some(volunteer)`.
    ///
    /// The mint calls this in place of `is_node` when a node claims a
    /// position (`claim_position`) or a pair registers (`register_pair`),
    /// and records the answer with the print -- so
    /// redemption never has to ask the roster anything, and a node's
    /// terms are the ones it had when it was named.
    pub fn node_terms(e: Env, address: Address) -> Option<bool> {
        match e
            .storage()
            .persistent()
            .get::<DataKey, Node>(&DataKey::Node(address))
        {
            Some(node) if Self::counted(&node) => Some(node.volunteer),
            _ => None,
        }
    }

    /// Whether this address has ever volunteered, registered or not.
    pub fn is_volunteer(e: Env, address: Address) -> bool {
        e.storage()
            .persistent()
            .has(&DataKey::Volunteer(address))
    }

    pub fn get_node(e: Env, address: Address) -> Option<Node> {
        e.storage()
            .persistent()
            .get(&DataKey::Node(address))
    }

    pub fn get_node_count(e: Env) -> u32 {
        e.storage()
            .persistent()
            .get(&DataKey::NodeCount)
            .unwrap_or(0)
    }

    pub fn lookup(e: Env, address: Address) -> Option<String> {
        let node: Option<Node> = e
            .storage()
            .persistent()
            .get(&DataKey::Node(address));
        node.map(|n| n.tunnel_endpoint)
    }

    pub fn get_config(e: Env) -> RosterConfig {
        e.storage()
            .persistent()
            .get(&DataKey::Config)
            .expect("config not found")
    }

    pub fn symbol(e: Env) -> Symbol {
        let config: RosterConfig = e
            .storage()
            .persistent()
            .get(&DataKey::Config)
            .expect("config not found");
        config.symbol
    }

    pub fn min_stake(e: Env) -> i128 {
        let config: RosterConfig = e
            .storage()
            .persistent()
            .get(&DataKey::Config)
            .expect("config not found");
        config.min_stake
    }
}

mod test;
