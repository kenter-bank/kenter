#![cfg(test)]

// The contract is `no_std`; its tests are not. `Vec` and `format!` keep
// the random walk's failure list readable, and none of this is compiled
// into the wasm.
extern crate std;

use crate::{KenterRoster, KenterRosterClient};
use soroban_sdk::{
    token, Address, Env, String, FromVal, Symbol, symbol_short,
    testutils::{Address as _, Events, Ledger},
    TryFromVal,
};

fn create_token_contract<'a>(
    e: &Env,
    admin: &Address,
) -> (token::Client<'a>, Address) {
    let token_address = e.register_stellar_asset_contract(admin.clone());
    let token = token::Client::new(e, &token_address);

    let admin_client = token::StellarAssetClient::new(e, &token_address);
    admin_client.mint(admin, &1_000_000_000);

    (token, token_address)
}

/// The **native** Stellar Asset Contract, deployed the way the network
/// deploys it — from `Asset::Native` rather than a generated issued asset.
///
/// `register_stellar_asset_contract_v2`, which every other test here uses,
/// always wraps a freshly issued `AlphaNum4`. That difference can hide a
/// real failure: the SAC's `burn` is allowed on an issued asset and
/// refused on the native one, and the roster is deployed staking XLM.
/// The SAC's own balance record, mirrored so a test can seed one.
///
/// The native asset has no `mint`, and for a **contract** address — which
/// is what `Address::generate` produces — the SAC keeps balances in its
/// own storage under `DataKey::Balance(addr)` rather than in a classic
/// account entry. These two types have to match
/// `soroban-env-host`'s `stellar_asset_contract::storage_types` field for
/// field, or the read comes back `UnexpectedType`.
#[soroban_sdk::contracttype]
pub struct SacBalance {
    pub amount: i128,
    pub authorized: bool,
    pub clawback: bool,
}

#[soroban_sdk::contracttype]
pub enum SacKey {
    Balance(Address),
}

fn native_sac(e: &Env) -> Address {
    use soroban_sdk::xdr::{Limits, WriteXdr};
    let serialized = soroban_sdk::xdr::Asset::Native
        .to_xdr(Limits::none())
        .expect("serialize Asset::Native");
    e.deployer()
        .with_stellar_asset(soroban_sdk::Bytes::from_slice(e, &serialized))
        .deploy()
}

fn mint_tokens(token_client: &token::Client, to: &Address, amount: &i128) {
    let admin_client = token::StellarAssetClient::new(&token_client.env, &token_client.address);
    admin_client.mint(to, amount);
}

/// Most tests predate unbonding and want the old behaviour, so this defaults
/// the delay to 0 (withdrawable immediately). Unbonding itself is covered by
/// the tests at the bottom, which use `setup_unbonding`.
fn setup(
    e: &Env,
    min_stake: i128,
) -> (KenterRosterClient, token::Client, Address) {
    setup_unbonding(e, min_stake, 0)
}

/// The third return is the **token** admin, which mints test balances.
/// The roster itself has no admin and takes none: see `__constructor`.
fn setup_unbonding(
    e: &Env,
    min_stake: i128,
    unbonding_ledgers: u32,
) -> (KenterRosterClient, token::Client, Address) {
    let token_admin = Address::generate(e);
    let (pay_token, pay_token_addr) = create_token_contract(e, &token_admin);

    let roster = KenterRosterClient::new(
        e,
        &e.register(
            KenterRoster,
            (min_stake, &pay_token_addr, unbonding_ledgers),
        ),
    );

    (roster, pay_token, token_admin)
}

/// Advance the ledger so an unbonding period can elapse.
fn advance_ledgers(e: &Env, n: u32) {
    let current = e.ledger().sequence();
    e.ledger().set_sequence_number(current + n);
}

// ── Constructor + Config ──

#[test]
fn test_constructor_sets_config() {
    let env = Env::default();
    env.mock_all_auths();

    let (roster, _, _) = setup(&env, 500);

    assert_eq!(roster.symbol(), symbol_short!("KNTRROST"));
    assert_eq!(roster.min_stake(), 500);
    assert_eq!(roster.get_config().unbonding_ledgers, 0);
    assert_eq!(roster.get_node_count(), 0);
}

// ── Join ──

#[test]
fn test_join() {
    let env = Env::default();
    env.mock_all_auths();

    let (roster, pay_token, _admin) = setup(&env, 500);
    let user = Address::generate(&env);
    mint_tokens(&pay_token, &user, &10000);

    let name = String::from_val(&env, &"NodeAlpha");
    let endpoint = String::from_val(&env, &"https://GABC.relay.example.org");

    assert_eq!(roster.is_node(&user), false);
    let node = roster.join(&user, &name, &endpoint);
    assert_eq!(roster.is_node(&user), true);
    assert_eq!(roster.get_node_count(), 1);
    assert_eq!(node.staked, 500);
    assert_eq!(node.active, true);

    // The bond and nothing else: there is no join fee to add to it, and
    // everything the contract holds belongs to the node that posted it.
    assert_eq!(pay_token.balance(&user), 9500);
    assert_eq!(pay_token.balance(&roster.address), 500);
}

#[test]
#[should_panic(expected = "already registered")]
fn test_double_join() {
    let env = Env::default();
    env.mock_all_auths();

    let (roster, pay_token, _) = setup(&env, 500);
    let user = Address::generate(&env);
    mint_tokens(&pay_token, &user, &10000);

    let name = String::from_val(&env, &"Node");
    let ep = String::from_val(&env, &"https://x.relay.example.org");

    roster.join(&user, &name, &ep);
    roster.join(&user, &name, &ep);
}

#[test]
fn test_multiple_nodes_join() {
    let env = Env::default();
    env.mock_all_auths();

    let (roster, pay_token, _) = setup(&env, 200);
    let user1 = Address::generate(&env);
    let user2 = Address::generate(&env);
    let user3 = Address::generate(&env);
    mint_tokens(&pay_token, &user1, &10000);
    mint_tokens(&pay_token, &user2, &10000);
    mint_tokens(&pay_token, &user3, &10000);

    let name1 = String::from_val(&env, &"Alpha");
    let name2 = String::from_val(&env, &"Beta");
    let name3 = String::from_val(&env, &"Gamma");
    let ep = String::from_val(&env, &"https://x.relay.example.org");

    roster.join(&user1, &name1, &ep);
    roster.join(&user2, &name2, &ep);
    roster.join(&user3, &name3, &ep);

    assert_eq!(roster.get_node_count(), 3);
    assert_eq!(roster.is_node(&user1), true);
    assert_eq!(roster.is_node(&user2), true);
    assert_eq!(roster.is_node(&user3), true);
}

// ── Update Node ──

#[test]
fn test_update_node() {
    let env = Env::default();
    env.mock_all_auths();

    let (roster, pay_token, _) = setup(&env, 0);
    let user = Address::generate(&env);
    mint_tokens(&pay_token, &user, &10000);

    let name = String::from_val(&env, &"OldName");
    let ep = String::from_val(&env, &"https://old.relay.example.org");
    roster.join(&user, &name, &ep);

    let new_name = String::from_val(&env, &"NewName");
    let new_ep = String::from_val(&env, &"https://new.relay.example.org");

    let updated = roster.update_node(
        &user,
        &Some(new_name.clone()),
        &Some(new_ep.clone()),
        &Some(false),
    );

    assert_eq!(updated.name, new_name);
    assert_eq!(updated.tunnel_endpoint, new_ep);
    assert_eq!(updated.active, false);

    // Verify persisted
    let fetched = roster.get_node(&user).unwrap();
    assert_eq!(fetched.active, false);
    assert_eq!(fetched.tunnel_endpoint, new_ep);
}

#[test]
#[should_panic(expected = "not registered")]
fn test_update_non_member() {
    let env = Env::default();
    env.mock_all_auths();

    let (roster, _, _) = setup(&env, 0);
    let user = Address::generate(&env);

    let name = String::from_val(&env, &"X");
    roster.update_node(&user, &Some(name), &None, &None);
}

// ── Heartbeat ──

#[test]
fn test_heartbeat() {
    let env = Env::default();
    env.mock_all_auths();

    let (roster, pay_token, _) = setup(&env, 0);
    let user = Address::generate(&env);
    mint_tokens(&pay_token, &user, &10000);

    let name = String::from_val(&env, &"Node");
    let ep = String::from_val(&env, &"https://x.relay.example.org");
    roster.join(&user, &name, &ep);

    let initial_hb = roster.get_node(&user).unwrap().last_heartbeat;

    // Advance ledger
    env.ledger().set_sequence_number(initial_hb + 100);

    let new_hb = roster.heartbeat(&user);
    assert_eq!(new_hb, initial_hb + 100);

    let node = roster.get_node(&user).unwrap();
    assert_eq!(node.last_heartbeat, initial_hb + 100);
}

// ── Leave ──

#[test]
fn test_leave_returns_stake() {
    let env = Env::default();
    env.mock_all_auths();

    let (roster, pay_token, _) = setup(&env, 500);
    let user = Address::generate(&env);
    mint_tokens(&pay_token, &user, &10000);

    let name = String::from_val(&env, &"Node");
    let ep = String::from_val(&env, &"https://x.relay.example.org");
    roster.join(&user, &name, &ep);

    assert_eq!(pay_token.balance(&user), 9500); // 10000 - the bond

    // With a zero unbonding delay the stake is withdrawable at once, but it is
    // now two steps: leave() stops selectability, withdraw_stake() pays out.
    roster.leave(&user);
    assert_eq!(roster.is_node(&user), false, "unbonding nodes are not selectable");
    assert_eq!(pay_token.balance(&user), 9500, "leave must not pay out");

    let returned = roster.withdraw_stake(&user);
    assert_eq!(returned, 500);

    // Whole, to the stroop. A node that serves out its unbonding period
    // keeps everything it posted: there is no fee to retain and nothing
    // that can forfeit a bond.
    //
    // So the price of a roster identity is **illiquidity, not loss** --
    // capital tied up from `join` until this call, of which the
    // unbonding period is only the tail that cannot be shortened. That
    // bounds how many identities one purse can hold at once, which is
    // the ordinary proof-of-stake Sybil lever. It is a smaller claim
    // than slashing would have been: an attacker with capital waits and
    // gets everything back.
    assert_eq!(pay_token.balance(&user), 10000);
    assert_eq!(roster.is_node(&user), false);
    assert_eq!(roster.get_node_count(), 0);
}

// -- NodeCount must mean what is_node says --
//
// `NodeCount` is the size
// of the selectable pool, and `is_node` defines membership of it as
// `active && unbonding_at.is_none()`. Every path that can change that
// answer has to move the count with it, or anything sizing selection on
// the count is working from a number that drifts.

fn joined(env: &Env, roster: &KenterRosterClient, pay_token: &token::Client) -> Address {
    let user = Address::generate(env);
    mint_tokens(pay_token, &user, &10000);
    let name = String::from_val(env, &"Node");
    let ep = String::from_val(env, &"https://x.relay.example.org");
    roster.join(&user, &name, &ep);
    user
}

/// Deactivating takes a node out of the pool, so it takes it out of the
/// count. Leaving the count untouched would over-report the pool -- a
/// double decrement's error in the opposite direction.
#[test]
fn deactivating_leaves_the_count() {
    let env = Env::default();
    env.mock_all_auths();
    let (roster, pay_token, _) = setup(&env, 500);

    let a = joined(&env, &roster, &pay_token);
    let _b = joined(&env, &roster, &pay_token);
    assert_eq!(roster.get_node_count(), 2);

    roster.update_node(&a, &None, &None, &Some(false));
    assert_eq!(roster.is_node(&a), false);
    assert_eq!(roster.get_node_count(), 1, "a deactivated node is not selectable");
}

/// And coming back puts it back.
#[test]
fn reactivating_rejoins_the_count() {
    let env = Env::default();
    env.mock_all_auths();
    let (roster, pay_token, _) = setup(&env, 500);

    let a = joined(&env, &roster, &pay_token);
    roster.update_node(&a, &None, &None, &Some(false));
    assert_eq!(roster.get_node_count(), 0);

    roster.update_node(&a, &None, &None, &Some(true));
    assert_eq!(roster.is_node(&a), true);
    assert_eq!(roster.get_node_count(), 1);
}

/// Setting `active` to the value it already has moves nothing.
#[test]
fn a_no_op_update_does_not_move_the_count() {
    let env = Env::default();
    env.mock_all_auths();
    let (roster, pay_token, _) = setup(&env, 500);

    let a = joined(&env, &roster, &pay_token);
    roster.update_node(&a, &None, &None, &Some(true));
    assert_eq!(roster.get_node_count(), 1);

    let name = String::from_val(&env, &"Renamed");
    roster.update_node(&a, &Some(name), &None, &None);
    assert_eq!(roster.get_node_count(), 1, "a rename is not a membership change");
}

/// An unbonding node is already out of the count, so toggling `active`
/// on one must not take it out twice.
#[test]
fn deactivating_an_unbonding_node_does_not_double_decrement() {
    let env = Env::default();
    env.mock_all_auths();
    let (roster, pay_token, _) = setup_unbonding(&env, 500, 1000);

    let a = joined(&env, &roster, &pay_token);
    let _b = joined(&env, &roster, &pay_token);
    roster.leave(&a);
    assert_eq!(roster.get_node_count(), 1);

    roster.update_node(&a, &None, &None, &Some(false));
    assert_eq!(roster.get_node_count(), 1, "leave already removed it");
}

// -- State archival, roster side --
//
// Same concern as the mint's. A node that is doing nothing but staying
// available sends heartbeats and nothing else, so the heartbeat is what
// has to keep its record -- and the stake behind it -- off the archive
// queue.

/// What a persistent entry gets with no bump at all, in the test env.
const UNBUMPED_TTL: u32 = 4096;

fn node_ttl(e: &Env, roster: &Address, who: &Address) -> u32 {
    use crate::DataKey;
    use soroban_sdk::testutils::storage::Persistent;
    e.as_contract(roster, || {
        e.storage().persistent().get_ttl(&DataKey::Node(who.clone()))
    })
}

#[test]
fn a_heartbeat_keeps_a_dormant_nodes_record_alive() {
    let env = Env::default();
    env.mock_all_auths();

    let (roster, pay_token, _) = setup(&env, 500);
    let user = Address::generate(&env);
    mint_tokens(&pay_token, &user, &10000);

    let name = String::from_val(&env, &"Node");
    let ep = String::from_val(&env, &"https://x.relay.example.org");
    roster.join(&user, &name, &ep);

    advance_ledgers(&env, 1000);
    roster.heartbeat(&user);

    let ttl = node_ttl(&env, &roster.address, &user);
    assert!(ttl > UNBUMPED_TTL * 10, "heartbeat did not carry the record: {ttl}");
}

/// Beginning to unbond must leave the record alive long enough for the
/// node to come back and withdraw its own stake.
#[test]
fn leaving_keeps_the_record_alive_through_unbonding() {
    let env = Env::default();
    env.mock_all_auths();

    let (roster, pay_token, _) = setup_unbonding(&env, 500, 1000);
    let user = Address::generate(&env);
    mint_tokens(&pay_token, &user, &10000);

    let name = String::from_val(&env, &"Node");
    let ep = String::from_val(&env, &"https://x.relay.example.org");
    roster.join(&user, &name, &ep);
    roster.leave(&user);

    let ttl = node_ttl(&env, &roster.address, &user);
    assert!(ttl > UNBUMPED_TTL * 10, "unbonding record was left to archive: {ttl}");
}

/// **Overflow, roster side.** A near-`u32::MAX` unbonding period is
/// a long wait, not a trap.
///
/// `sequence() + unbonding_ledgers` is `u32` with overflow checks on in
/// release, so with plain addition the obvious way to write "unbonding is
/// effectively permanent" would make every `leave` trap. The contract is
/// immutable and holds the stakes, so no node could begin unbonding and no
/// stake could ever be withdrawn. Same arithmetic as the mint's print
/// window, worse consequence: there, the deposit stays recoverable.
#[test]
fn leave_survives_an_unbonding_period_at_the_top_of_the_range() {
    let env = Env::default();
    env.mock_all_auths();

    let (roster, pay_token, _) = setup_unbonding(&env, 500, u32::MAX);
    let user = Address::generate(&env);
    mint_tokens(&pay_token, &user, &10000);

    let name = String::from_val(&env, &"Node");
    let ep = String::from_val(&env, &"https://x.relay.example.org");
    roster.join(&user, &name, &ep);

    // The call that would trap with plain addition.
    let unbonding_at = roster.leave(&user);
    assert_eq!(unbonding_at, u32::MAX, "the deadline lands on the last ledger");
    assert_eq!(roster.is_node(&user), false);
}

#[test]
#[should_panic(expected = "not registered")]
fn test_leave_not_member() {
    let env = Env::default();
    env.mock_all_auths();

    let (roster, _, _) = setup(&env, 0);
    let user = Address::generate(&env);
    roster.leave(&user);
}

// ── Lookup ──

#[test]
fn test_lookup() {
    let env = Env::default();
    env.mock_all_auths();

    let (roster, pay_token, _) = setup(&env, 0);
    let user = Address::generate(&env);
    mint_tokens(&pay_token, &user, &10000);

    let name = String::from_val(&env, &"Node");
    let ep = String::from_val(&env, &"https://GABC.relay.example.org");
    roster.join(&user, &name, &ep);

    let found = roster.lookup(&user);
    assert_eq!(found, Some(ep));

    let unknown = Address::generate(&env);
    assert_eq!(roster.lookup(&unknown), None);
}

// ── Admin: add / remove / is ──

// ── Admin: remove_node ──

/// Deactivating and then leaving is one departure, not two.
///
/// `update_node(active=false)` and `leave` both take a node out of
/// `NodeCount`. If `leave` did it unconditionally, any node could shrink
/// the roster's own idea of its size, for free, as often as it liked.
#[test]
fn deactivate_then_leave_decrements_once() {
    let env = Env::default();
    env.mock_all_auths();

    let (roster, pay_token, _) = setup(&env, 100);
    let (a, b) = (Address::generate(&env), Address::generate(&env));
    let name = String::from_val(&env, &"Node");
    let ep = String::from_val(&env, &"https://x.relay.example.org");
    for n in [&a, &b] {
        mint_tokens(&pay_token, n, &10_000);
        roster.join(n, &name, &ep);
    }
    assert_eq!(roster.get_node_count(), 2);

    roster.update_node(&a, &None, &None, &Some(false));
    assert_eq!(roster.get_node_count(), 1, "deactivating is one departure");

    roster.leave(&a);
    assert_eq!(
        roster.get_node_count(),
        1,
        "leaving a node that already left must not subtract it again"
    );
    assert_eq!(roster.is_node(&b), true, "and b is still selectable");
}

// ── Stats ──

// ── Events ──

#[test]
fn test_join_emits_event() {
    let env = Env::default();
    env.mock_all_auths();

    let (roster, pay_token, _) = setup(&env, 0);
    let user = Address::generate(&env);
    mint_tokens(&pay_token, &user, &10000);

    let name = String::from_val(&env, &"Node");
    let ep = String::from_val(&env, &"https://x.relay.example.org");
    roster.join(&user, &name, &ep);

    let events = env.events().all();
    let last = events.last().unwrap();
    let (_cid, topics, _data) = last;

    let topic0: Symbol =
        Symbol::try_from_val(&env, &topics.get_unchecked(0)).unwrap();
    let topic1: Symbol =
        Symbol::try_from_val(&env, &topics.get_unchecked(1)).unwrap();

    assert_eq!(topic0, symbol_short!("JOIN"));
    assert_eq!(topic1, symbol_short!("node"));
}

#[test]
fn test_leave_emits_event() {
    let env = Env::default();
    env.mock_all_auths();

    let (roster, pay_token, _) = setup(&env, 0);
    let user = Address::generate(&env);
    mint_tokens(&pay_token, &user, &10000);

    let name = String::from_val(&env, &"Node");
    let ep = String::from_val(&env, &"https://x.relay.example.org");
    roster.join(&user, &name, &ep);

    // leave() now announces unbonding...
    roster.leave(&user);
    let events = env.events().all();
    let (_cid, topics, _data) = events.last().unwrap();
    let topic0: Symbol =
        Symbol::try_from_val(&env, &topics.get_unchecked(0)).unwrap();
    assert_eq!(topic0, symbol_short!("UNBOND"));

    // ...and LEAVE marks the actual exit.
    roster.withdraw_stake(&user);
    let events = env.events().all();
    let (_cid, topics, _data) = events.last().unwrap();
    let topic0: Symbol =
        Symbol::try_from_val(&env, &topics.get_unchecked(0)).unwrap();
    assert_eq!(topic0, symbol_short!("LEAVE"));
}

#[test]
fn test_update_emits_event() {
    let env = Env::default();
    env.mock_all_auths();

    let (roster, pay_token, _) = setup(&env, 0);
    let user = Address::generate(&env);
    mint_tokens(&pay_token, &user, &10000);

    let name = String::from_val(&env, &"Node");
    let ep = String::from_val(&env, &"https://x.relay.example.org");
    roster.join(&user, &name, &ep);

    roster.update_node(&user, &None, &None, &Some(false));

    let events = env.events().all();
    let last = events.last().unwrap();
    let (_cid, topics, _data) = last;

    let topic0: Symbol =
        Symbol::try_from_val(&env, &topics.get_unchecked(0)).unwrap();
    assert_eq!(topic0, symbol_short!("UPDATE"));
}

// ── Edge Cases ──

#[test]
fn test_zero_fee_zero_stake() {
    let env = Env::default();
    env.mock_all_auths();

    let (roster, pay_token, _) = setup(&env, 0);
    let user = Address::generate(&env);
    mint_tokens(&pay_token, &user, &10000);

    let name = String::from_val(&env, &"FreeNode");
    let ep = String::from_val(&env, &"https://x.relay.example.org");
    let node = roster.join(&user, &name, &ep);

    assert_eq!(node.staked, 0);
    assert_eq!(pay_token.balance(&user), 10000); // no transfer

    let returned = roster.leave(&user);
    assert_eq!(returned, 0);
}

#[test]
fn test_join_leave_rejoin() {
    let env = Env::default();
    env.mock_all_auths();

    let (roster, pay_token, _) = setup(&env, 100);
    let user = Address::generate(&env);
    mint_tokens(&pay_token, &user, &10000);

    let name = String::from_val(&env, &"Node");
    let ep = String::from_val(&env, &"https://x.relay.example.org");

    roster.join(&user, &name, &ep);
    assert_eq!(roster.get_node_count(), 1);

    roster.leave(&user);
    assert_eq!(roster.get_node_count(), 0, "unbonding leaves the active set at once");
    assert_eq!(roster.is_node(&user), false);

    // The record persists until the stake is withdrawn, so rejoining means
    // finishing the exit first.
    roster.withdraw_stake(&user);

    // Rejoin should work
    roster.join(&user, &name, &ep);
    assert_eq!(roster.get_node_count(), 1);
    assert_eq!(roster.is_node(&user), true);
}

// ── Unbonding ──
//
// The point of the delay is that a stake returned on demand is a deposit, not
// a cost: an attacker could register a fleet, use it, and exit with the capital
// intact, making the Sybil price transaction fees. These pin the behaviour that
// stops that.

const UNBOND: u32 = 100;

fn joined_node(env: &Env) -> (KenterRosterClient, token::Client, Address) {
    let (roster, pay_token, _) = setup_unbonding(env, 500, UNBOND);
    let user = Address::generate(env);
    mint_tokens(&pay_token, &user, &10000);
    let name = String::from_val(env, &"Node");
    let ep = String::from_val(env, &"https://x.relay.example.org");
    roster.join(&user, &name, &ep);
    (roster, pay_token, user)
}

/// Leaving stops selectability immediately — a departing operator must not be
/// named in a fresh print it has no remaining stake in.
#[test]
fn unbonding_node_is_not_selectable() {
    let env = Env::default();
    env.mock_all_auths();
    let (roster, _pay, user) = joined_node(&env);

    assert!(roster.is_node(&user));
    let at = roster.leave(&user);
    assert_eq!(at, env.ledger().sequence() + UNBOND);
    assert!(!roster.is_node(&user), "must drop out of selection at once");
    assert_eq!(roster.get_node_count(), 0);
}

/// The capital stays locked for the whole period. This is the entire Sybil
/// barrier, so it is the assertion that matters most.
#[test]
#[should_panic(expected = "stake is still unbonding")]
fn stake_cannot_be_withdrawn_early() {
    let env = Env::default();
    env.mock_all_auths();
    let (roster, _pay, user) = joined_node(&env);

    roster.leave(&user);
    advance_ledgers(&env, UNBOND - 1);
    roster.withdraw_stake(&user);
}

#[test]
fn stake_is_withdrawable_once_the_period_elapses() {
    let env = Env::default();
    env.mock_all_auths();
    let (roster, pay_token, user) = joined_node(&env);
    let before = pay_token.balance(&user);

    roster.leave(&user);
    advance_ledgers(&env, UNBOND);
    assert_eq!(roster.withdraw_stake(&user), 500);
    assert_eq!(pay_token.balance(&user), before + 500);
    assert!(!roster.is_node(&user));
}

#[test]
#[should_panic(expected = "not unbonding")]
fn withdraw_requires_leaving_first() {
    let env = Env::default();
    env.mock_all_auths();
    let (roster, _pay, user) = joined_node(&env);
    roster.withdraw_stake(&user);
}

#[test]
#[should_panic(expected = "already unbonding")]
fn leave_is_not_repeatable() {
    let env = Env::default();
    env.mock_all_auths();
    let (roster, _pay, user) = joined_node(&env);
    roster.leave(&user);
    roster.leave(&user);
}

/// An unbonding node cannot re-register to dodge the delay: the record is still
/// there, so a fresh join is refused until the exit completes.
#[test]
#[should_panic(expected = "already registered")]
fn unbonding_node_cannot_rejoin_to_reset_the_clock() {
    let env = Env::default();
    env.mock_all_auths();
    let (roster, _pay, user) = joined_node(&env);
    roster.leave(&user);

    let name = String::from_val(&env, &"Node");
    let ep = String::from_val(&env, &"https://x.relay.example.org");
    roster.join(&user, &name, &ep);
}

// ── Rent paid from outside (`bump`) ──
//
// See the note on the mint's equivalent. The internal bumps wait until
// an entry is within `TTL_THRESHOLD` of archival, so the transaction
// that finally crosses it pays for the whole extension: this contract's
// own first `join` on testnet cost 21.79 XLM against 0.095 XLM for the
// second, with byte-identical footprints. `bump` exists so a keeper can
// pay that smoothly and no node ever draws the ticket.

/// A stranger -- not a node, not an admin -- can pay the roster's rent.
///
/// The constructor writes `Config` without bumping it, so a roster
/// nobody has joined yet is sitting on the default lifetime. That is
/// exactly the state a keeper should be able to fix before the first
/// node arrives and is handed the bill -- which is what happened on
/// testnet, where the first `join` paid 21.79 XLM.
#[test]
fn anyone_may_pay_the_rosters_rent() {
    let env = Env::default();
    env.mock_all_auths();
    let (roster, _pay_token, _) = setup(&env, 500);

    let fresh = config_ttl(&env, &roster.address);
    advance_ledgers(&env, 1000);
    assert_eq!(config_ttl(&env, &roster.address), fresh - 1000);

    roster.bump();

    assert!(
        config_ttl(&env, &roster.address) > UNBUMPED_TTL * 10,
        "bump did not carry the config entry"
    );
}

/// The difference that matters. A `heartbeat` is an ordinary mutating
/// call: it bumps with the lazy threshold, and a thousand ledgers is
/// nowhere near it, so it leaves the core entries exactly where they
/// were. `bump` tops them up regardless.
///
/// If the first assertion starts failing, the internal bumps have gone
/// eager and every node is paying rent on every heartbeat. If the
/// second one does, the keeper threshold has gone lazy and the lump is
/// back.
#[test]
fn an_ordinary_call_waits_where_bump_tops_up() {
    let env = Env::default();
    env.mock_all_auths();
    let (roster, pay_token, _) = setup(&env, 500);

    let user = Address::generate(&env);
    mint_tokens(&pay_token, &user, &10000);
    let name = String::from_val(&env, &"Node");
    let ep = String::from_val(&env, &"https://x.relay.example.org");
    roster.join(&user, &name, &ep);

    let full = config_ttl(&env, &roster.address);
    advance_ledgers(&env, 1000);

    roster.heartbeat(&user);
    assert_eq!(
        config_ttl(&env, &roster.address),
        full - 1000,
        "an ordinary call paid rent it did not need to pay"
    );

    roster.bump();
    assert_eq!(
        config_ttl(&env, &roster.address),
        full,
        "bump left the core entries short"
    );
}

fn config_ttl(e: &Env, roster: &Address) -> u32 {
    use crate::DataKey;
    use soroban_sdk::testutils::storage::Persistent;
    e.as_contract(roster, || {
        e.storage().persistent().get_ttl(&DataKey::Config)
    })
}


// ── A negative bond ──
//
// The bond is `i128`, so the type does not rule a negative one out; the
// constructor has to.

/// The constructor refuses it.
#[test]
#[should_panic(expected = "min_stake must not be negative")]
fn a_roster_cannot_be_deployed_with_a_negative_bond() {
    let env = Env::default();
    env.mock_all_auths();
    setup(&env, -200);
}

/// Zero is still legal. A roster with no bond is a configuration, not
/// a mistake, and several tests above rely on it.
#[test]
fn a_zero_bond_is_still_allowed() {
    let env = Env::default();
    env.mock_all_auths();
    let (roster, _pay_token, _) = setup(&env, 0);
    assert_eq!(roster.min_stake(), 0);
}

// ─────────────────────────────────────────────────────────────────────
// A deterministic random walk over every state-changing entry point.
//
// The rest of this file is targeted tests: each one pins one known
// behaviour. That is the right shape for a case that is understood,
// and the wrong shape for finding the next one — bookkeeping like this
// breaks on an *ordering* nobody wrote a test for, and a targeted test
// only ever covers the ordering its author imagined. The walk lives
// here, inside the build, so `cargo test` keeps it in step with the API.
//
// Two invariants, checked after every single step:
//
//   balance(roster) == Σ staked over live records
//   NodeCount       == #{records for which is_node() is true}
//
// The first is the whole solvency claim of an adminless roster. The
// second is what the mint gates selection on.
// ─────────────────────────────────────────────────────────────────────

/// xorshift64. A fixed sequence per seed, so a failure is reproducible
/// from the seed printed with it.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn pick(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

#[test]
fn a_random_walk_stays_solvent_and_counts_exactly() {
    const BOND: i128 = 100;
    const UNBONDING: u32 = 5;

    let mut failures = std::vec::Vec::new();

    for seed in 1..=24u64 {
        let env = Env::default();
        env.mock_all_auths();
        let (roster, pay_token, _) = setup_unbonding(&env, BOND, UNBONDING);

        let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
        let mut nodes: std::vec::Vec<Address> = std::vec::Vec::new();

        for step in 0..60 {
            match rng.pick(7) {
                // Join. Weighted at two slots in seven so the roster
                // grows faster than it drains and the later arms have
                // something to act on.
                0 | 1 => {
                    let a = Address::generate(&env);
                    mint_tokens(&pay_token, &a, &10_000);
                    let name = String::from_val(&env, &"N");
                    let ep = String::from_val(&env, &"https://n.relay.example.org");
                    roster.join(&a, &name, &ep);
                    nodes.push(a);
                }
                // Activate or deactivate, interleaved with `leave`: the
                // ordering that can double-count a departure.
                2 if !nodes.is_empty() => {
                    let a = nodes[rng.pick(nodes.len())].clone();
                    if roster.get_node(&a).is_some() {
                        let on = rng.pick(2) == 0;
                        roster.update_node(&a, &None, &None, &Some(on));
                    }
                }
                // Leave, if not already unbonding.
                3 if !nodes.is_empty() => {
                    let a = nodes[rng.pick(nodes.len())].clone();
                    if let Some(n) = roster.get_node(&a) {
                        if n.unbonding_at.is_none() {
                            roster.leave(&a);
                        }
                    }
                }
                // Withdraw anything due. A due withdrawal that bounces
                // is a finding on its own: the bond is the node's and
                // nothing may hold it past its period.
                4 if !nodes.is_empty() => {
                    let a = nodes[rng.pick(nodes.len())].clone();
                    if let Some(n) = roster.get_node(&a) {
                        if let Some(at) = n.unbonding_at {
                            if env.ledger().sequence() >= at {
                                let before = pay_token.balance(&a);
                                let got = roster.withdraw_stake(&a);
                                if got != BOND || pay_token.balance(&a) != before + BOND {
                                    failures.push(std::format!(
                                        "seed {seed} step {step}: due withdraw paid {got}"
                                    ));
                                }
                            }
                        }
                    }
                }
                // Heartbeat, which writes and bumps.
                5 if !nodes.is_empty() => {
                    let a = nodes[rng.pick(nodes.len())].clone();
                    if roster.get_node(&a).is_some() {
                        roster.heartbeat(&a);
                    }
                }
                // Let time pass, so unbonding periods elapse.
                6 => {
                    let n = rng.pick(4) as u32;
                    env.ledger().set_sequence_number(env.ledger().sequence() + n);
                }
                _ => {}
            }

            let mut staked = 0i128;
            let mut counted = 0u32;
            for a in nodes.iter() {
                if let Some(n) = roster.get_node(a) {
                    staked += n.staked;
                    if roster.is_node(a) {
                        counted += 1;
                    }
                }
            }
            let balance = pay_token.balance(&roster.address);
            if balance != staked || counted != roster.get_node_count() {
                failures.push(std::format!(
                    "seed {seed} step {step}: balance {balance} vs staked {staked}; \
                     count {} vs live {counted}",
                    roster.get_node_count()
                ));
                break;
            }
        }
    }

    assert!(failures.is_empty(), "{:#?}", failures);
}


// ── Volunteers ──

fn strs(e: &Env, name: &str) -> (String, String) {
    (
        String::from_val(e, &name),
        String::from_val(e, &"https://v.relay.example.org"),
    )
}

/// Volunteering is joining: same bond, same count, same selectability,
/// and the mint is told the node takes no fees.
#[test]
fn volunteering_joins_with_the_bond_and_says_so() {
    let env = Env::default();
    env.mock_all_auths();
    let (roster, pay_token, _) = setup(&env, 500);
    let v = Address::generate(&env);
    mint_tokens(&pay_token, &v, &10000);
    let (name, ep) = strs(&env, "Volunteer");

    assert_eq!(roster.node_terms(&v), None);
    let node = roster.volunteer(&v, &name, &ep);
    assert!(node.volunteer);
    assert_eq!(node.staked, 500);
    assert_eq!(pay_token.balance(&roster.address), 500);
    assert_eq!(roster.get_node_count(), 1);
    assert!(roster.is_node(&v));
    assert_eq!(roster.node_terms(&v), Some(true));
    assert!(roster.is_volunteer(&v));
}

/// An ordinary join answers `Some(false)`, and leaving the pool answers
/// `None` whatever the terms.
#[test]
fn node_terms_follow_selectability() {
    let env = Env::default();
    env.mock_all_auths();
    let (roster, pay_token, _) = setup(&env, 500);
    let p = Address::generate(&env);
    let v = Address::generate(&env);
    mint_tokens(&pay_token, &p, &10000);
    mint_tokens(&pay_token, &v, &10000);
    let (name, ep) = strs(&env, "N");
    roster.join(&p, &name, &ep);
    roster.volunteer(&v, &name, &ep);
    assert_eq!(roster.node_terms(&p), Some(false));
    assert!(!roster.is_volunteer(&p));

    roster.update_node(&v, &None, &None, &Some(false));
    assert_eq!(roster.node_terms(&v), None, "deactivated: not selectable");
    roster.update_node(&v, &None, &None, &Some(true));
    assert_eq!(roster.node_terms(&v), Some(true));
    roster.leave(&v);
    assert_eq!(roster.node_terms(&v), None, "unbonding: not selectable");
}

/// A paid node converts in place: stake and count untouched, name and
/// endpoint updated.
#[test]
fn a_paid_node_can_convert() {
    let env = Env::default();
    env.mock_all_auths();
    let (roster, pay_token, _) = setup(&env, 500);
    let n = Address::generate(&env);
    mint_tokens(&pay_token, &n, &10000);
    let (name, ep) = strs(&env, "Paid");
    roster.join(&n, &name, &ep);

    // Record an endpoint, as the node host does once it binds a relay.
    let recorded = String::from_str(&env, "https://GNODE.relay.example");
    roster.update_node(&n, &None, &Some(recorded.clone()), &None);

    let (name2, ep2) = strs(&env, "NowVolunteer");
    let node = roster.volunteer(&n, &name2, &ep2);
    assert!(node.volunteer);
    // Converting changes the flag and nothing else: the name and the
    // recorded endpoint survive.
    assert_eq!(node.name, name);
    assert_eq!(node.tunnel_endpoint, recorded);
    assert_eq!(roster.lookup(&n), Some(recorded));
    assert_eq!(node.staked, 500);
    assert_eq!(pay_token.balance(&n), 9500, "no second bond");
    assert_eq!(roster.get_node_count(), 1, "no second count");
    assert_eq!(roster.node_terms(&n), Some(true));
}

#[test]
#[should_panic(expected = "already volunteering")]
fn volunteering_twice_is_refused() {
    let env = Env::default();
    env.mock_all_auths();
    let (roster, pay_token, _) = setup(&env, 500);
    let v = Address::generate(&env);
    mint_tokens(&pay_token, &v, &10000);
    let (name, ep) = strs(&env, "V");
    roster.volunteer(&v, &name, &ep);
    roster.volunteer(&v, &name, &ep);
}

/// **The point of the flag.** Leave, take the stake back, and come back
/// through plain `join`: still a volunteer. Otherwise a node could
/// volunteer for a while and switch to paid afterwards.
#[test]
fn volunteering_survives_leaving_and_rejoining() {
    let env = Env::default();
    env.mock_all_auths();
    let (roster, pay_token, _) = setup_unbonding(&env, 500, 10);
    let v = Address::generate(&env);
    mint_tokens(&pay_token, &v, &10000);
    let (name, ep) = strs(&env, "V");
    roster.volunteer(&v, &name, &ep);

    roster.leave(&v);
    advance_ledgers(&env, 10);
    assert_eq!(roster.withdraw_stake(&v), 500);
    assert_eq!(roster.get_node(&v), None, "the record is gone");
    assert!(roster.is_volunteer(&v), "the marker is not");

    let node = roster.join(&v, &name, &ep);
    assert!(node.volunteer, "a returning volunteer joins as one");
    assert_eq!(roster.node_terms(&v), Some(true));
}

/// A paid node that converted keeps the flag through leaving too.
#[test]
fn a_converted_node_stays_converted() {
    let env = Env::default();
    env.mock_all_auths();
    let (roster, pay_token, _) = setup(&env, 500);
    let n = Address::generate(&env);
    mint_tokens(&pay_token, &n, &10000);
    let (name, ep) = strs(&env, "N");
    roster.join(&n, &name, &ep);
    roster.volunteer(&n, &name, &ep);
    roster.leave(&n);
    roster.withdraw_stake(&n);
    assert!(roster.join(&n, &name, &ep).volunteer);
}

/// The marker is kept as live as the record it governs: heartbeat and a
/// re-`join` extend it along with the record.
#[test]
fn the_volunteer_marker_lives_as_long_as_the_record() {
    use soroban_sdk::testutils::storage::Persistent as _;
    use soroban_sdk::testutils::{Ledger as _, LedgerInfo};
    let env = Env::default();
    env.mock_all_auths();
    let (roster, pay_token, _) = setup(&env, 500);
    let v = Address::generate(&env);
    mint_tokens(&pay_token, &v, &10000);
    let (name, ep) = strs(&env, "V");
    roster.volunteer(&v, &name, &ep);

    let ttls = |env: &Env| {
        env.as_contract(&roster.address, || {
            (
                env.storage().persistent().get_ttl(&crate::types::DataKey::Node(v.clone())),
                env.storage().persistent().get_ttl(&crate::types::DataKey::Volunteer(v.clone())),
            )
        })
    };

    // Let both run down, then heartbeat: both come back together.
    let (node_ttl, _) = ttls(&env);
    let info = env.ledger().get();
    env.ledger().set(LedgerInfo {
        sequence_number: info.sequence_number + node_ttl - 10,
        ..info
    });
    roster.heartbeat(&v);
    let (node_ttl, marker_ttl) = ttls(&env);
    assert!(node_ttl > 100, "heartbeat extended the record");
    assert!(marker_ttl >= node_ttl, "and the marker with it ({marker_ttl} < {node_ttl})");

    // Out and back in through plain `join`: still a volunteer, and the
    // marker extended again.
    roster.leave(&v);
    roster.withdraw_stake(&v);
    let info = env.ledger().get();
    env.ledger().set(LedgerInfo {
        sequence_number: info.sequence_number + marker_ttl - 10,
        ..info
    });
    assert!(roster.join(&v, &name, &ep).volunteer);
    let (_, marker_ttl) = ttls(&env);
    assert!(marker_ttl > 100, "join extended the marker");
}

/// The join event says which terms a node joined on.
#[test]
fn the_join_event_carries_the_terms() {
    let env = Env::default();
    env.mock_all_auths();
    let (roster, pay_token, _) = setup(&env, 500);
    let v = Address::generate(&env);
    mint_tokens(&pay_token, &v, &10000);
    let (name, ep) = strs(&env, "V");
    roster.volunteer(&v, &name, &ep);

    let mut seen = false;
    for (_cid, topics, data) in env.events().all().iter() {
        if topics.len() < 1 {
            continue;
        }
        if Symbol::try_from_val(&env, &topics.get_unchecked(0)).ok() == Some(symbol_short!("JOIN")) {
            let ev = crate::types::NodeJoinEvent::try_from_val(&env, &data).unwrap();
            assert!(ev.volunteer);
            seen = true;
        }
    }
    assert!(seen, "no JOIN event");
}