#![cfg(test)]

extern crate std;

use crate::{KenterMint, KenterMintClient};
use soroban_sdk::{
    token, Address, Bytes, BytesN, Env, Symbol, Vec, symbol_short,
    testutils::{Address as _, Events, Ledger},
    TryFromVal,
};

use crate::types::*;

// ── Fake Roster ──
// A minimal mock roster contract that just tracks registered nodes.

mod roster_contract {
    use soroban_sdk::{contract, contractimpl, contracttype, Address, Env, String, Vec};

    #[contracttype]
    #[derive(Clone)]
    pub enum DataKey {
        Nodes,
        Volunteers,
        Joined(Address),
    }

    #[contract]
    pub struct MockRoster;

    #[contractimpl]
    impl MockRoster {
        pub fn __constructor(e: Env) {
            let nodes: Vec<Address> = Vec::new(&e);
            e.storage().persistent().set(&DataKey::Nodes, &nodes);
        }

        pub fn add_node(e: Env, node: Address) {
            let mut nodes: Vec<Address> = e
                .storage()
                .persistent()
                .get(&DataKey::Nodes)
                .unwrap_or(Vec::new(&e));
            nodes.push_back(node.clone());
            e.storage().persistent().set(&DataKey::Nodes, &nodes);
            e.storage()
                .persistent()
                .set(&DataKey::Joined(node), &e.ledger().sequence());
        }

        /// The real roster's `get_node`, as far as the mint reads it: the
        /// record, with `joined_at` the ledger `add_node` ran in.
        pub fn get_node(e: Env, address: Address) -> Option<crate::types::RosterNode> {
            if !Self::is_node(e.clone(), address.clone()) {
                return None;
            }
            let joined_at: u32 = e
                .storage()
                .persistent()
                .get(&DataKey::Joined(address.clone()))
                .unwrap_or(0);
            Some(crate::types::RosterNode {
                address,
                name: String::from_str(&e, "mock"),
                tunnel_endpoint: String::from_str(&e, ""),
                staked: 0,
                joined_at,
                last_heartbeat: joined_at,
                active: true,
                unbonding_at: None,
                volunteer: false,
            })
        }

        /// Needed by the roster re-check tests: membership can change after a
        /// print has been requested, which is the whole point of
        /// re-checking it at confirm_link.
        pub fn remove_node(e: Env, node: Address) {
            let nodes: Vec<Address> = e
                .storage()
                .persistent()
                .get(&DataKey::Nodes)
                .unwrap_or(Vec::new(&e));
            let mut kept: Vec<Address> = Vec::new(&e);
            for n in nodes.iter() {
                if n != node {
                    kept.push_back(n);
                }
            }
            e.storage().persistent().set(&DataKey::Nodes, &kept);
        }

        pub fn is_node(e: Env, address: Address) -> bool {
            let nodes: Vec<Address> = e
                .storage()
                .persistent()
                .get(&DataKey::Nodes)
                .unwrap_or(Vec::new(&e));
            nodes.contains(address)
        }

        /// Mark a node a volunteer, as the real roster's `volunteer`
        /// does. Permanent there, and nothing here undoes it either.
        pub fn add_volunteer(e: Env, node: Address) {
            let mut v: Vec<Address> = e
                .storage()
                .persistent()
                .get(&DataKey::Volunteers)
                .unwrap_or(Vec::new(&e));
            v.push_back(node);
            e.storage().persistent().set(&DataKey::Volunteers, &v);
        }

        /// The real roster's contract: `None` off the roster, else
        /// `Some(volunteer)`.
        pub fn node_terms(e: Env, address: Address) -> Option<bool> {
            if !Self::is_node(e.clone(), address.clone()) {
                return None;
            }
            let v: Vec<Address> = e
                .storage()
                .persistent()
                .get(&DataKey::Volunteers)
                .unwrap_or(Vec::new(&e));
            Some(v.contains(address))
        }
    }
}

// ── Selection (docs/architecture/node-selection.md) ──
//
// Every print runs request, seed, claim, window. The fixture is a real
// drand quicknet round, the same one `contracts/drand-spike` verified on
// testnet; its points are uncompressed, as Soroban takes them.

/// quicknet's group key, G2 uncompressed.
const BEACON_PK: &str = "03cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a01a714f2edb74119a2f2b0d5a7c75ba902d163700a61bc224ededd8e63aef7be1aaf8e93d7a9718b047ccddb3eb5d68b0e5db2b6bfbb01c867749cadffca88b36c24f3012ba09fc4d3022c5c37dce0f977d3adb5d183c7477c442b1f04515273";
/// Round 33 971 844's signature, G1 uncompressed.
const BEACON_SIG: &str = "0414a8586cf92eaca970d9d177ff4a323506c409e65a2862df44dfb5a0959073bb989d31a2844fdb69043a918a2a0d6e0104bf3a1d2f71367e0d31e654fb0cce3d75cb50f22204c8c52c7aa741faedf428f8bbf151be33a8ad846a787a22d5fe";
const BEACON_ROUND: u64 = 33_971_844;
const BEACON_GENESIS: u64 = 1_692_803_367;
const BEACON_PERIOD: u64 = 3;
const BEACON_LEAD: u64 = 10;
/// Short, so the tests that use a five-ledger print window still fit one.
const CLAIM_WINDOW: u32 = 2;
const SERVE_TIMEOUT: u32 = 3;

fn unhex<const N: usize>(h: &str) -> [u8; N] {
    let mut out = [0u8; N];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&h[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}

fn test_selection(env: &Env) -> SelectionConfig {
    SelectionConfig {
        beacon_pk: BytesN::from_array(env, &unhex::<192>(BEACON_PK)),
        beacon_genesis: BEACON_GENESIS,
        beacon_period: BEACON_PERIOD,
        beacon_lead: BEACON_LEAD,
        claim_window: CLAIM_WINDOW,
        serve_timeout: SERVE_TIMEOUT,
        min_node_age: 0,
    }
}

fn beacon_sig(env: &Env) -> BytesN<96> {
    BytesN::from_array(env, &unhex::<96>(BEACON_SIG))
}

/// The ledger time at which a request is seeded by the fixture round.
fn fixture_time() -> u64 {
    BEACON_GENESIS + (BEACON_ROUND - BEACON_LEAD - 1) * BEACON_PERIOD
}

fn advance(env: &Env, ledgers: u32) {
    env.ledger().with_mut(|l| l.sequence_number += ledgers);
}

/// A print driven end to end: the end pairs are the depositor's, every
/// pair between them claims, and the window passes. Interior-pair
/// rejections -- distinctness, roster membership, this contract's own
/// address -- come from `claim_position`.
///
/// **Positions follow score, not the order given.** With one interior pair
/// that is the same thing; with more, use [`positions`] to learn who is
/// where.
trait PairsFlow {
    fn request_pairs(&self, d: &Address, eid: &BytesN<32>, amount: &i128, pairs: &Vec<PairEntry>) -> u32;
    fn try_request_pairs(
        &self,
        d: &Address,
        eid: &BytesN<32>,
        amount: &i128,
        pairs: &Vec<PairEntry>,
    ) -> Result<u32, ()>;
}

impl PairsFlow for KenterMintClient<'_> {
    fn request_pairs(&self, d: &Address, eid: &BytesN<32>, amount: &i128, pairs: &Vec<PairEntry>) -> u32 {
        let env = &self.env;
        env.ledger().set_timestamp(fixture_time());
        let n = pairs.len();
        let (first, last) = ends(d, pairs);
        register_pairs(self, pairs);
        let slot = self.request_print(d, eid, amount, &n, &first, &last);
        self.seed_print(&slot, &beacon_sig(env));
        for i in 1..n.saturating_sub(1) {
            let p = pairs.get(i).unwrap();
            self.claim_position(&slot, &p.node_a, &p.node_b);
        }
        advance(env, CLAIM_WINDOW + 1);
        slot
    }

    fn try_request_pairs(
        &self,
        d: &Address,
        eid: &BytesN<32>,
        amount: &i128,
        pairs: &Vec<PairEntry>,
    ) -> Result<u32, ()> {
        let env = &self.env;
        env.ledger().set_timestamp(fixture_time());
        let n = pairs.len();
        let (first, last) = ends(d, pairs);
        register_pairs(self, pairs);
        let slot = match self.try_request_print(d, eid, amount, &n, &first, &last) {
            Ok(Ok(slot)) => slot,
            _ => return Err(()),
        };
        self.seed_print(&slot, &beacon_sig(env));
        for i in 1..n.saturating_sub(1) {
            let p = pairs.get(i).unwrap();
            if !matches!(self.try_claim_position(&slot, &p.node_a, &p.node_b), Ok(Ok(_))) {
                return Err(());
            }
        }
        advance(env, CLAIM_WINDOW + 1);
        Ok(slot)
    }
}

/// Register every interior pair of `pairs` and move on a ledger, so they
/// predate the request (a pair registered after it cannot claim). A pair
/// already registered is left as it is; any other refusal is left for
/// `claim_position` to report, which checks distinctness, the roster and
/// this contract's own address first.
fn register_pairs(mint: &KenterMintClient, pairs: &Vec<PairEntry>) {
    for i in 1..pairs.len().saturating_sub(1) {
        let p = pairs.get(i).unwrap();
        let _ = mint.try_register_pair(&p.node_a, &p.node_b);
    }
    advance(&mint.env, 1);
}

/// The end pairs of `pairs`, or the depositor's own when it has none.
fn ends(d: &Address, pairs: &Vec<PairEntry>) -> (PairEntry, PairEntry) {
    let own = PairEntry {
        node_a: d.clone(),
        node_b: d.clone(),
    };
    let first = pairs.get(0).unwrap_or(own.clone());
    let last = pairs.get(pairs.len().saturating_sub(1)).unwrap_or(own);
    (first, last)
}

/// Request only: no seed, no claims. A print abandoned here had no draw,
/// so it is the one that refunds in full.
fn request_only(s: &TestSetup, d: &Address, eid: &BytesN<32>, amount: i128, pairs: &Vec<PairEntry>) -> u32 {
    s.env.ledger().set_timestamp(fixture_time());
    let (first, last) = ends(d, pairs);
    s.mint.request_print(d, eid, &amount, &pairs.len(), &first, &last)
}

/// Every pair in chain order: the depositor's first, the interior by
/// position, the depositor's last.
fn chain_order(s: &TestSetup, slot: u32) -> std::vec::Vec<PairEntry> {
    let sl = s.mint.get_slot(&slot).unwrap();
    let mut out = std::vec![sl.pairs.get(0).unwrap()];
    out.extend(positions(s, slot));
    out.push(sl.pairs.get(sl.pairs.len() - 1).unwrap());
    out
}

/// The interior pairs in position order, read off the slot: its claims
/// before selection closes, its `pairs` after.
fn positions(s: &TestSetup, slot: u32) -> std::vec::Vec<PairEntry> {
    let sl = s.mint.get_slot(&slot).unwrap();
    let k = sl.total_pairs - 2;
    if sl.closed {
        (1..=k).map(|i| sl.pairs.get(i).unwrap()).collect()
    } else {
        (0..k).map(|i| sl.claims.get(i).unwrap().pair).collect()
    }
}

// ── Helpers ──

fn create_token<'a>(e: &Env, admin: &Address) -> (token::Client<'a>, Address) {
    let addr = e.register_stellar_asset_contract(admin.clone());
    let client = token::Client::new(e, &addr);
    let admin_client = token::StellarAssetClient::new(e, &addr);
    admin_client.mint(admin, &1_000_000_000);
    (client, addr)
}

fn mint_tokens(tc: &token::Client, to: &Address, amount: i128) {
    let ac = token::StellarAssetClient::new(&tc.env, &tc.address);
    ac.mint(to, &amount);
}

struct TestSetup<'a> {
    env: Env,
    mint: KenterMintClient<'a>,
    pay_token: token::Client<'a>,
    pay_token_addr: Address,
    roster_addr: Address,
}

fn setup_with_config<'a>(
    node_fee: u32,
    min_pairs: u32,
    max_pairs: u32,
    max_print_ledgers: u32,
) -> TestSetup<'a> {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let (pay_token, pay_token_addr) = create_token(&env, &admin);

    // Deploy mock roster
    let roster_addr = env.register(
        roster_contract::MockRoster,
        (),
    );

    // Deploy mint contract
    let mint = KenterMintClient::new(
        &env,
        &env.register(
            KenterMint,
            (
                node_fee,
                min_pairs,
                max_pairs,
                &pay_token_addr,
                &roster_addr,
                max_print_ledgers,
                test_selection(&env),
            ),
        ),
    );

    TestSetup {
        env,
        mint,
        pay_token,
        pay_token_addr,
        roster_addr,
    }
}

fn setup<'a>() -> TestSetup<'a> {
    setup_with_config(10, 3, 5, 1000)
}

// -- The claim key on both redeem paths --

/// Knowing the ephemeral secret is not the same as holding the note.
///
/// The claim key exists so that publishing the chain is not enough to
/// take a note. Both Path A and Path B redeem the same escrow, so both
/// must demand it, or the invariant is optional.
///
/// It matters because `s = Σ shardᵢ` is not held only by the note.
/// Each shard is derivable by *either* node of its pair, so one node
/// from each pair, colluding, can compose it — and at `min_pairs = 1` a
/// single node can, alone. The shard-release handler serves a shard to
/// anyone who signs their own request, so the node network is an oracle
/// for `s`.
#[test]
#[should_panic(expected = "Error(Crypto, InvalidInput)")]
fn path_a_pure_bearer_needs_the_claim_key_too() {
    let (s, slot, ek, ek_sk, holder) = make_token(TokenMode::PureBearer, None);
    let eph = sig_ephemeral(&s.env, slot, &ek_sk, &ek, &s.mint.address, &holder);

    // Everything an outsider could assemble from the node network: a
    // valid ephemeral signature, naming themselves. No claim secret.
    let wrong = ed25519_dalek::SigningKey::from_bytes(&[0x77u8; 32]);
    let forged = {
        use ed25519_dalek::Signer;
        use sha2::{Digest, Sha256};
        use soroban_sdk::xdr::ToXdr;
        let xdr = |a: &Address| {
            let x = a.clone().to_xdr(&s.env);
            let mut buf = std::vec![0u8; x.len() as usize];
            x.copy_into_slice(&mut buf);
            buf
        };
        let mut m: std::vec::Vec<u8> = std::vec::Vec::new();
        m.extend_from_slice(b"kntr_v1:redeem:claim");
        m.extend_from_slice(&xdr(&s.mint.address));
        m.extend_from_slice(&ek.to_array());
        m.extend_from_slice(&xdr(&holder));
        let digest: [u8; 32] = Sha256::digest(&m).into();
        BytesN::from_array(&s.env, &wrong.sign(&digest).to_bytes())
    };

    s.mint.redeem_by_key(
        &holder,
        &holder,
        &slot, &eph, &forged);
}

/// And the honest holder, who has both, is still paid.
#[test]
fn path_a_pays_a_holder_with_both_proofs() {
    let (s, slot, ek, ek_sk, holder) = make_token(TokenMode::PureBearer, None);
    let eph = sig_ephemeral(&s.env, slot, &ek_sk, &ek, &s.mint.address, &holder);
    let claim = sig_claim(&s.env, slot, &ek, &s.mint.address, &holder);

    assert_eq!(s.mint.redeem_by_key(
        &holder,
        &holder,
        &slot, &eph, &claim), 980);
}

/// The Path A claim signature names its recipient, so one lifted off a
/// failed transaction cannot be pointed somewhere else — the same
/// property Path B has.
#[test]
#[should_panic(expected = "Error(Crypto, InvalidInput)")]
fn a_path_a_claim_signature_cannot_be_redirected() {
    let (s, slot, ek, ek_sk, holder) = make_token(TokenMode::PureBearer, None);
    let thief = Address::generate(&s.env);

    // Both proofs, as a failed transaction would have published them,
    // naming the intended recipient.
    let eph = sig_ephemeral(&s.env, slot, &ek_sk, &ek, &s.mint.address, &holder);
    let claim = sig_claim(&s.env, slot, &ek, &s.mint.address, &holder);

    // Replayed to the thief. The ephemeral proof is checked first and
    // binds the recipient too, so this traps on whichever comes first;
    // the point is that it traps.
    s.mint.redeem_by_key(
        &thief,
        &thief,
        &slot, &eph, &claim);
}

// -- Properties with no demonstrated theft --
//
// "No demonstrated theft" is not "harmless": pair distinctness is a
// security property (docs/architecture/security-model.md), and the mint
// is immutable, so there is exactly one chance at all of these.

/// A pair of one node is not a pair.
///
/// A shard takes both halves of a link to derive, so a link whose two
/// nodes are the same address is a shard one operator holds alone --
/// while still producing a well-formed link with two valid signatures
/// that nothing downstream can distinguish from an honest one.
#[test]
#[should_panic(expected = "Error(Contract, #31)")] // NodesNotDistinct
fn a_pair_cannot_be_one_node_twice() {
    let s = setup();
    let depositor = Address::generate(&s.env);
    let node = Address::generate(&s.env);
    mint_tokens(&s.pay_token, &depositor, 10000);
    register_node(&s.env, &s.roster_addr, &node);

    let mut pairs = Vec::new(&s.env);
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    pairs.push_back(make_pair(&s.env, &node, &node));
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    s.mint.request_pairs(&depositor, &random_event_id(&s.env), &1000, &pairs);
}

/// Nor can one node hold a place in several pairs of one print.
///
/// Otherwise a chain of n links can be a chain of one operator, which is
/// the same collapse spread out far enough to look like depth.
#[test]
#[should_panic(expected = "Error(Contract, #31)")] // NodesNotDistinct
fn a_node_cannot_appear_in_two_pairs_of_one_print() {
    let s = setup();
    let depositor = Address::generate(&s.env);
    let na = Address::generate(&s.env);
    let nb = Address::generate(&s.env);
    let nc = Address::generate(&s.env);
    mint_tokens(&s.pay_token, &depositor, 10000);
    for n in [&na, &nb, &nc] {
        register_node(&s.env, &s.roster_addr, n);
    }

    let mut pairs = Vec::new(&s.env);
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    pairs.push_back(make_pair(&s.env, &na, &nb));
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    pairs.push_back(make_pair(&s.env, &nb, &nc)); // nb twice
    s.mint.request_pairs(&depositor, &random_event_id(&s.env), &1000, &pairs);
}

/// **The depositor's own two pairs are exempt**, and that is what makes
/// `print-net` possible at all.
///
/// Distinctness applied to the end pairs demanded four funded,
/// roster-joined, separately bonded accounts before anyone could print
/// their own note -- a bond posted against misbehaviour that can only
/// harm its poster, since the depositor holds both ends by construction.
/// One unrostered address fills all four slots.
#[test]
fn the_depositors_end_pairs_need_no_roster_and_may_repeat() {
    let s = setup();
    let depositor = Address::generate(&s.env);
    let na = Address::generate(&s.env);
    let nb = Address::generate(&s.env);
    mint_tokens(&s.pay_token, &depositor, 10000);
    // Only the interior nodes join. The depositor never does.
    register_node(&s.env, &s.roster_addr, &na);
    register_node(&s.env, &s.roster_addr, &nb);

    let mut pairs = Vec::new(&s.env);
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    pairs.push_back(make_pair(&s.env, &na, &nb));
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    let slot = s.mint.request_pairs(&depositor, &random_event_id(&s.env), &1000, &pairs);

    // And the depositor can confirm its own links without membership,
    // which `confirm_link` has to agree with or the slot stalls on the
    // very first link.
    s.mint.confirm_link(&depositor, &slot, &0, &partial_key(&s.env, 90));
    s.mint.confirm_link(&na, &slot, &1, &partial_key(&s.env, 1));
    s.mint.confirm_link(&depositor, &slot, &2, &partial_key(&s.env, 91));
    assert_eq!(s.mint.get_slot(&slot).unwrap().completed_links, 3);
}

/// The exemption is for the *ends* only. An interior pair is still a
/// node pair, so a self-print cannot come back in through the middle.
#[test]
#[should_panic(expected = "Error(Contract, #31)")] // NodesNotDistinct
fn an_interior_pair_cannot_be_the_depositor_twice() {
    let s = setup();
    let depositor = Address::generate(&s.env);
    mint_tokens(&s.pay_token, &depositor, 10000);

    let mut pairs = Vec::new(&s.env);
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    s.mint.request_pairs(&depositor, &random_event_id(&s.env), &1000, &pairs);
}

/// Nor may an interior node also hold one of the end slots: the pair
/// count would overstate the independent parties again, which is the
/// loophole distinctness exists to close.
#[test]
#[should_panic(expected = "Error(Contract, #31)")] // NodesNotDistinct
fn an_interior_node_cannot_also_be_an_end_pair() {
    let s = setup();
    let depositor = Address::generate(&s.env);
    let nb = Address::generate(&s.env);
    mint_tokens(&s.pay_token, &depositor, 10000);
    register_node(&s.env, &s.roster_addr, &depositor);
    register_node(&s.env, &s.roster_addr, &nb);

    let mut pairs = Vec::new(&s.env);
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    pairs.push_back(make_pair(&s.env, &depositor, &nb));
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    s.mint.request_pairs(&depositor, &random_event_id(&s.env), &1000, &pairs);
}

/// **The floor is what makes the exemption safe.** A deployment that
/// allowed two-pair prints would be exempt end to end -- both pairs are
/// "the depositor's" -- so a self-print with no node in it would pass
/// every check. The constructor refuses such a mint outright, because
/// it has no admin and could never be corrected.
#[test]
#[should_panic(expected = "Error(Contract, #52)")] // InvalidConfig
fn a_mint_that_would_allow_a_two_pair_print_is_refused() {
    setup_with_config(10, 2, 5, 1000);
}

/// And four distinct nodes across two pairs is fine, so the rule does not
/// cost an honest print anything.
#[test]
fn two_pairs_of_four_distinct_nodes_are_accepted() {
    let s = setup();
    let depositor = Address::generate(&s.env);
    let na = Address::generate(&s.env);
    let nb = Address::generate(&s.env);
    let nc = Address::generate(&s.env);
    let nd = Address::generate(&s.env);
    mint_tokens(&s.pay_token, &depositor, 10000);
    for n in [&na, &nb, &nc, &nd] {
        register_node(&s.env, &s.roster_addr, n);
    }

    let mut pairs = Vec::new(&s.env);
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    pairs.push_back(make_pair(&s.env, &na, &nb));
    pairs.push_back(make_pair(&s.env, &nc, &nd));
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    let slot = s.mint.request_pairs(&depositor, &random_event_id(&s.env), &1000, &pairs);
    // Two node pairs, plus the depositor's two.
    assert_eq!(s.mint.get_slot(&slot).unwrap().total_pairs, 4);
}

/// An `event_id` names a print for every off-chain party, so two
/// prints must not answer to one name.
#[test]
#[should_panic(expected = "Error(Contract, #32)")] // EventIdInUse
fn an_event_id_cannot_be_used_by_two_prints() {
    let s = setup();
    let depositor = Address::generate(&s.env);
    let na = Address::generate(&s.env);
    let nb = Address::generate(&s.env);
    mint_tokens(&s.pay_token, &depositor, 10000);
    register_node(&s.env, &s.roster_addr, &na);
    register_node(&s.env, &s.roster_addr, &nb);

    let mut pairs = Vec::new(&s.env);
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    pairs.push_back(make_pair(&s.env, &na, &nb));

    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    let reused = random_event_id(&s.env);
    s.mint.request_pairs(&depositor, &reused, &1000, &pairs);
    s.mint.request_pairs(&depositor, &reused, &1000, &pairs);
}

/// Cancelling does not free the name either: a print that happened,
/// happened, and the record of it is what an observer reconciles against.
#[test]
#[should_panic(expected = "Error(Contract, #32)")] // EventIdInUse
fn a_cancelled_print_does_not_release_its_event_id() {
    let s = setup();
    let depositor = Address::generate(&s.env);
    let na = Address::generate(&s.env);
    let nb = Address::generate(&s.env);
    mint_tokens(&s.pay_token, &depositor, 10000);
    register_node(&s.env, &s.roster_addr, &na);
    register_node(&s.env, &s.roster_addr, &nb);

    let mut pairs = Vec::new(&s.env);
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    pairs.push_back(make_pair(&s.env, &na, &nb));

    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    let reused = random_event_id(&s.env);
    let slot = s.mint.request_pairs(&depositor, &reused, &1000, &pairs);
    s.mint.cancel_print(&depositor, &slot);
    s.mint.request_pairs(&depositor, &reused, &1000, &pairs);
}

/// Abandoning a print after the nodes have worked is not free.
///
/// A cancel that refunded the whole deposit however many links had been
/// confirmed would let a depositor spend every pair's effort and take
/// the money back -- denial of service against node capacity, and not
/// paying for work done.
#[test]
fn cancelling_pays_for_the_links_that_were_built() {
    let s = setup(); // node_fee 10
    let depositor = Address::generate(&s.env);
    let na = Address::generate(&s.env);
    let nb = Address::generate(&s.env);
    mint_tokens(&s.pay_token, &depositor, 10000);
    register_node(&s.env, &s.roster_addr, &na);
    register_node(&s.env, &s.roster_addr, &nb);

    let mut pairs = Vec::new(&s.env);
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    pairs.push_back(make_pair(&s.env, &na, &nb));
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    let slot = s.mint.request_pairs(&depositor, &random_event_id(&s.env), &1000, &pairs);
    s.mint.confirm_link(&depositor, &slot, &0, &partial_key(&s.env, 90));
    s.mint.confirm_link(&na, &slot, &1, &partial_key(&s.env, 1));

    let refund = s.mint.cancel_print(&depositor, &slot);
    assert_eq!(refund, 990, "one fee, for the one interior link confirmed");
    assert_eq!(s.mint.accrued_fees(&na), 10, "na confirmed, so na is paid");
    assert_eq!(
        s.mint.accrued_fees(&depositor),
        0,
        "the depositor's own end links are not paid for, here or at \
         redemption: crediting them would take money out of the refund to \
         hand straight back, store a balance worth less than the fee to \
         claim it, and let settlement exceed what `request_print` reserves, \
         which would strand the escrow"
    );
    assert_eq!(
        s.mint.accrued_fees(&nb),
        0,
        "nb put its name to nothing; a shard is derivable by one node alone, \
         so the chain cannot tell whether nb did anything at all"
    );
}

/// A print abandoned before anyone did anything still refunds in full.
#[test]
fn cancelling_an_untouched_print_refunds_everything() {
    let s = setup();
    let depositor = Address::generate(&s.env);
    let na = Address::generate(&s.env);
    let nb = Address::generate(&s.env);
    mint_tokens(&s.pay_token, &depositor, 10000);
    register_node(&s.env, &s.roster_addr, &na);
    register_node(&s.env, &s.roster_addr, &nb);

    let mut pairs = Vec::new(&s.env);
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    pairs.push_back(make_pair(&s.env, &na, &nb));
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    // Before the seed: no draw exists, so nothing is forfeited.
    let slot = request_only(&s, &depositor, &random_event_id(&s.env), 1000, &pairs);

    assert_eq!(s.mint.cancel_print(&depositor, &slot), 1000);
    assert_eq!(s.mint.accrued_fees(&na), 0);
}

/// Letting the clock run out is the other way to abandon a
/// print, so it must not be the cheaper one.
#[test]
fn expiry_pays_for_the_links_that_were_built() {
    let s = setup_with_config(10, 3, 5, 5);
    let depositor = Address::generate(&s.env);
    let na = Address::generate(&s.env);
    let nb = Address::generate(&s.env);
    mint_tokens(&s.pay_token, &depositor, 10000);
    register_node(&s.env, &s.roster_addr, &na);
    register_node(&s.env, &s.roster_addr, &nb);

    let mut pairs = Vec::new(&s.env);
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    pairs.push_back(make_pair(&s.env, &na, &nb));
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    let slot = s.mint.request_pairs(&depositor, &random_event_id(&s.env), &1000, &pairs);
    s.mint.confirm_link(&depositor, &slot, &0, &partial_key(&s.env, 90));
    s.mint.confirm_link(&na, &slot, &1, &partial_key(&s.env, 1));

    s.env.ledger().set_sequence_number(s.env.ledger().sequence() + 6);
    assert_eq!(
        s.mint.clear_expired_slot(&slot),
        990,
        "na's interior link; the depositor's end link is not paid for"
    );
    assert_eq!(s.mint.accrued_fees(&na), 10);
    assert_eq!(s.mint.accrued_fees(&nb), 0);
}

/// Settlement pays whoever confirmed, not whoever was assigned.
///
/// Paying both nodes of every confirmed pair would pay an address that
/// may have done nothing: `confirm_link` takes either
/// member of the pair, and a shard is derivable by one of them alone,
/// so cooperation is not a thing the chain can observe. Only the
/// confirmation is.
#[test]
fn settlement_follows_the_confirmer_not_the_pair() {
    let s = setup(); // node_fee 10
    let depositor = Address::generate(&s.env);
    let na = Address::generate(&s.env);
    let nb = Address::generate(&s.env);
    let nc = Address::generate(&s.env);
    let nd = Address::generate(&s.env);
    mint_tokens(&s.pay_token, &depositor, 10000);
    for n in [&na, &nb, &nc, &nd] {
        register_node(&s.env, &s.roster_addr, n);
    }

    let mut pairs = Vec::new(&s.env);
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    pairs.push_back(make_pair(&s.env, &na, &nb));
    pairs.push_back(make_pair(&s.env, &nc, &nd));
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    let slot = s.mint.request_pairs(&depositor, &random_event_id(&s.env), &1000, &pairs);

    // Different members confirm each link.
    s.mint.confirm_link(&depositor, &slot, &0, &partial_key(&s.env, 90));
    s.mint.confirm_link(&nb, &slot, &1, &partial_key(&s.env, 1));
    s.mint.confirm_link(&nc, &slot, &2, &partial_key(&s.env, 2));

    assert_eq!(
        s.mint.cancel_print(&depositor, &slot),
        980,
        "two interior links, two fees; the depositor's end link is unpaid"
    );
    assert_eq!(s.mint.accrued_fees(&nb), 10, "nb confirmed link 1");
    assert_eq!(s.mint.accrued_fees(&nc), 10, "nc confirmed link 2");
    assert_eq!(s.mint.accrued_fees(&na), 0, "na was assigned and did not confirm");
    assert_eq!(s.mint.accrued_fees(&nd), 0, "nor did nd");
}

/// A node that has left the roster stops building chains.
///
/// Membership is re-checked at `confirm_link`; checked only once, a node
/// that left or was removed would keep its place in every print it was
/// already assigned to. A stake is what backs membership; a node with
/// none at risk is outside the arrangement that makes misbehaviour cost
/// anything.
#[test]
#[should_panic(expected = "Error(Contract, #21)")] // NodeNotOnRoster
fn a_node_that_left_the_roster_cannot_confirm() {
    let s = setup();
    let depositor = Address::generate(&s.env);
    let na = Address::generate(&s.env);
    let nb = Address::generate(&s.env);
    mint_tokens(&s.pay_token, &depositor, 10000);
    register_node(&s.env, &s.roster_addr, &na);
    register_node(&s.env, &s.roster_addr, &nb);

    let mut pairs = Vec::new(&s.env);
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    pairs.push_back(make_pair(&s.env, &na, &nb));
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    let slot = s.mint.request_pairs(&depositor, &random_event_id(&s.env), &1000, &pairs);

    remove_roster_node(&s.env, &s.roster_addr, &na);
    s.mint.confirm_link(&depositor, &slot, &0, &partial_key(&s.env, 90));
    s.mint.confirm_link(&na, &slot, &1, &partial_key(&s.env, 1));
}

/// Registering against an expired slot is refused, rather than
/// racing whoever calls `clear_expired_slot` first.
///
/// Nobody lost money either way -- the loser's deposit is refunded --
/// but whether a note exists should not be settled by transaction
/// ordering.
#[test]
#[should_panic(expected = "Error(Contract, #24)")] // SlotExpired
fn an_expired_slot_cannot_be_registered_against() {
    let s = setup_with_config(10, 3, 5, 5);
    let depositor = Address::generate(&s.env);
    let na = Address::generate(&s.env);
    let nb = Address::generate(&s.env);
    mint_tokens(&s.pay_token, &depositor, 10000);
    register_node(&s.env, &s.roster_addr, &na);
    register_node(&s.env, &s.roster_addr, &nb);

    let mut pairs = Vec::new(&s.env);
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    pairs.push_back(make_pair(&s.env, &na, &nb));
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    let slot = s.mint.request_pairs(&depositor, &random_event_id(&s.env), &1000, &pairs);
    s.mint.confirm_link(&depositor, &slot, &0, &partial_key(&s.env, 90));
    s.mint.confirm_link(&na, &slot, &1, &partial_key(&s.env, 1));
    s.mint.confirm_link(&depositor, &slot, &2, &partial_key(&s.env, 91));

    s.env.ledger().set_sequence_number(s.env.ledger().sequence() + 6);
    s.mint.register_token(
        &depositor,
        &slot,
        &random_key(&s.env),
        &partial_key(&s.env, 200),
        &TokenMode::PureBearer,
        &BytesN::from_array(&s.env, &[0u8; 32]),
        &claim_pk(&s.env),
    );
}

// -- Entries must not drift into the archive --
//
// An entry nobody bumps ages toward archival, and the restore fee lands
// on whoever next touches it -- for a note, the holder redeeming it.
// Protocol 23 makes that a bill rather than a loss; it is still the wrong
// person paying, and an off-ledger `get_token` can answer "not found"
// about a note that exists.
//
// These assert the entry outlives the default lifetime a fresh write gets.
// A dropped bump fails them; the exact number does not matter, which is
// why the comparison is against that baseline and not a constant.

/// What a persistent entry gets with no bump at all, in the test env.
/// Anything the contract bumps must beat it by a wide margin.
const UNBUMPED_TTL: u32 = 4096;

/// Read a persistent entry's remaining TTL from outside the contract.
fn ttl_of(s: &TestSetup, key: &DataKey) -> u32 {
    use soroban_sdk::testutils::storage::Persistent;
    s.env
        .as_contract(&s.mint.address, || s.env.storage().persistent().get_ttl(key))
}

/// Registration is what puts a note on the ledger, so it is what has to
/// put the record somewhere it will still be when the holder redeems.
#[test]
fn registering_a_token_keeps_its_record_alive() {
    let (s, slot, ek, _ek_sk, _holder) = make_token(TokenMode::PureBearer, None);
    let ttl = ttl_of(&s, &DataKey::Token(slot));
    assert!(ttl > UNBUMPED_TTL * 10, "token record was left to archive: {ttl}");
    assert!(
        ttl_of(&s, &DataKey::Config) > UNBUMPED_TTL * 10,
        "config was left to archive"
    );
}

/// The record is not the nullifier. Redemption removes it and leaves a
/// marker, and what refuses the second attempt is the
/// record's *absence* -- slot ids come from a counter that never
/// reissues, so a deleted slot cannot come back.
#[test]
fn redeeming_removes_the_record_and_leaves_a_marker() {
    let (s, slot, ek, ek_sk, holder) = make_token(TokenMode::PureBearer, None);
    let eph = sig_ephemeral(&s.env, slot, &ek_sk, &ek, &s.mint.address, &holder);
    s.mint.redeem_by_key(
        &holder,
        &holder,
        &slot,
        &eph,
        &sig_claim(&s.env, slot, &ek, &s.mint.address, &holder),
    );

    assert!(s.mint.get_token(&slot).is_none(), "the record outlived the payout");
    assert!(s.mint.is_redeemed(&slot));
    assert_eq!(s.mint.get_token_state(&slot), Some(TokenState::Redeemed));
    assert!(s.mint.redeemed_at(&slot).is_some());
}

/// The point of the whole exercise: deleting the record must not make a
/// note redeemable twice. It does not, because the second attempt finds
/// nothing to redeem -- and the marker is what lets the contract say
/// `AlreadyRedeemed` rather than `TokenNotFound`.
#[test]
#[should_panic(expected = "Error(Contract, #42)")]
fn a_redeemed_note_cannot_be_redeemed_again_once_its_record_is_gone() {
    let (s, slot, ek, ek_sk, holder) = make_token(TokenMode::PureBearer, None);
    let eph = sig_ephemeral(&s.env, slot, &ek_sk, &ek, &s.mint.address, &holder);
    let claim = sig_claim(&s.env, slot, &ek, &s.mint.address, &holder);
    s.mint.redeem_by_key(&holder, &holder, &slot, &eph, &claim);
    s.mint.redeem_by_key(&holder, &holder, &slot, &eph, &claim);
}

/// A slot that never existed is a different mistake from one that was
/// redeemed, and the caller is told which.
#[test]
#[should_panic(expected = "Error(Contract, #40)")]
fn an_unknown_slot_is_not_reported_as_already_redeemed() {
    let (s, slot, ek, ek_sk, holder) = make_token(TokenMode::PureBearer, None);
    let eph = sig_ephemeral(&s.env, slot, &ek_sk, &ek, &s.mint.address, &holder);
    let claim = sig_claim(&s.env, slot, &ek, &s.mint.address, &holder);
    s.mint.redeem_by_key(&holder, &holder, &(slot + 999), &eph, &claim);
}

/// Registration is the end of the print, so the slot's working state --
/// the largest record a note owns -- goes with it.
#[test]
fn registering_a_token_retires_the_print_slot() {
    let (s, slot, _ek, _ek_sk, _holder) = make_token(TokenMode::PureBearer, None);
    assert!(
        s.mint.get_slot(&slot).is_none(),
        "the print slot outlived the print"
    );
    // ...and the note itself is live and unaffected.
    assert_eq!(s.mint.get_token(&slot).unwrap().state, TokenState::Active);
}

/// A spend is the one call a long-held note makes between receipt and
/// redemption, so it has to carry the record forward.
#[test]
fn spending_keeps_the_record_alive() {
    let alice = osk(1);
    let bob = osk(2);
    let (s, slot, ek, _ek_sk, holder) = make_token(TokenMode::Spend, Some(&alice));
    let alice_commit = ocommit(&s.env, &alice);
    let bob_commit = ocommit(&s.env, &bob);

    s.env.ledger().set_sequence_number(s.env.ledger().sequence() + 100);
    let sig = sig_spend(&s.env, &alice, slot, &ek, &alice_commit, &bob_commit, &s.mint.address, 0);
    s.mint.spend(&holder, &slot, &opk(&s.env, &alice), &bob_commit, &sig);

    let ttl = ttl_of(&s, &DataKey::Token(slot));
    assert!(ttl > UNBUMPED_TTL * 10, "spend did not carry the record: {ttl}");
}

/// A print in progress must not expire out from under the nodes
/// confirming its links.
#[test]
fn confirming_a_link_keeps_the_slot_alive() {
    let s = setup();
    let depositor = Address::generate(&s.env);
    let na = Address::generate(&s.env);
    let nb = Address::generate(&s.env);

    mint_tokens(&s.pay_token, &depositor, 10000);
    register_node(&s.env, &s.roster_addr, &na);
    register_node(&s.env, &s.roster_addr, &nb);
    let mut pairs = Vec::new(&s.env);
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    pairs.push_back(make_pair(&s.env, &na, &nb));
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    let slot_id = s.mint.request_pairs(&depositor, &random_event_id(&s.env), &1000, &pairs);
    s.mint.confirm_link(&depositor, &slot_id, &0, &partial_key(&s.env, 90));
    s.mint.confirm_link(&na, &slot_id, &1, &partial_key(&s.env, 1));

    // The slot is scoped to the print window, not to the 120-day
    // ceiling, so the invariant worth asserting is
    // that it outlives the window it belongs to -- not that it is big.
    let ttl = ttl_of(&s, &DataKey::Slot(slot_id));
    let window = s.mint.max_print_ledgers();
    assert!(
        ttl > window,
        "the slot will not outlive its own print window: {ttl} vs {window}"
    );
}

/// Asking for more than the network allows must not trap or overshoot:
/// `extend_ttl` is defined against the live maximum, which differs by
/// network and has been raised before.
#[test]
fn a_bump_is_clamped_to_the_network_maximum() {
    let s = setup();
    s.env.ledger().set_max_entry_ttl(50_000); // far below the 120 days asked for
    let depositor = Address::generate(&s.env);
    let na = Address::generate(&s.env);
    let nb = Address::generate(&s.env);

    mint_tokens(&s.pay_token, &depositor, 10000);
    register_node(&s.env, &s.roster_addr, &na);
    register_node(&s.env, &s.roster_addr, &nb);
    let mut pairs = Vec::new(&s.env);
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    pairs.push_back(make_pair(&s.env, &na, &nb));

    // The call that would trap if the contract asked for more than allowed.
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    let slot_id = s.mint.request_pairs(&depositor, &random_event_id(&s.env), &1000, &pairs);
    assert!(ttl_of(&s, &DataKey::Slot(slot_id)) <= 50_000);
}

// -- An immutable mint must not be deployable broken --
//
// A mint deployed with a near-u32::MAX print window must not trap on
// arithmetic in every expiry check, which would leave no token
// registrable on it. The window saturates, and parameter combinations
// that no print could satisfy are refused at construction instead of
// producing an address that is permanently dead.

/// A "never expires" window is a window, not a trap.
///
/// `created_at + max_print_ledgers` is `u32` with overflow checks on in
/// release, so `u32::MAX` -- the obvious way to write "no deadline" --
/// would trap in `confirm_link`, `clear_expired_slot` and
/// `is_slot_expired` alike without saturation. The deposit would stay
/// recoverable through `cancel_print`, so a bricked mint rather than a
/// theft, but the mint is immutable, so the only remedy is a new address.
#[test]
fn a_mint_with_no_practical_deadline_can_still_print() {
    let s = setup_with_config(10, 3, 5, u32::MAX);
    let depositor = Address::generate(&s.env);
    let na = Address::generate(&s.env);
    let nb = Address::generate(&s.env);

    mint_tokens(&s.pay_token, &depositor, 10000);
    register_node(&s.env, &s.roster_addr, &na);
    register_node(&s.env, &s.roster_addr, &nb);
    let mut pairs = Vec::new(&s.env);
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    pairs.push_back(make_pair(&s.env, &na, &nb));

    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    let slot_id = s.mint.request_pairs(&depositor, &random_event_id(&s.env), &1000, &pairs);
    // The call that traps without saturation.
    s.mint.confirm_link(&depositor, &slot_id, &0, &partial_key(&s.env, 90));
    s.mint.confirm_link(&na, &slot_id, &1, &partial_key(&s.env, 1));
    assert!(!s.mint.is_slot_expired(&slot_id));
}

/// A deadline that has in fact passed still expires the slot, so
/// saturation did not turn the check off.
#[test]
fn a_slot_past_its_window_is_still_expired() {
    let s = setup_with_config(10, 3, 5, 5);
    let depositor = Address::generate(&s.env);
    let na = Address::generate(&s.env);
    let nb = Address::generate(&s.env);

    mint_tokens(&s.pay_token, &depositor, 10000);
    register_node(&s.env, &s.roster_addr, &na);
    register_node(&s.env, &s.roster_addr, &nb);
    let mut pairs = Vec::new(&s.env);
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    pairs.push_back(make_pair(&s.env, &na, &nb));
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    let slot_id = s.mint.request_pairs(&depositor, &random_event_id(&s.env), &1000, &pairs);

    s.env.ledger().set_sequence_number(s.env.ledger().sequence() + 6);
    assert!(s.mint.is_slot_expired(&slot_id));
}

/// Zero pairs means no links, so nothing would ever sign the chain.
#[test]
#[should_panic(expected = "Error(Contract, #52)")] // InvalidConfig
fn a_mint_that_requires_no_pairs_is_refused() {
    setup_with_config(10, 0, 5, 1000);
}

/// An upper bound under the lower one admits no pair count at all, so
/// every `request_print` would fail on `InvalidPairCount`.
#[test]
#[should_panic(expected = "Error(Contract, #52)")] // InvalidConfig
fn a_mint_whose_pair_bounds_cross_is_refused() {
    setup_with_config(10, 4, 3, 1000);
}

/// A mint must not be able to issue notes Path B cannot redeem.
///
/// Past some pair count the chain verification stops fitting in the
/// instruction budget, and such a note is redeemable only through Path
/// A and the node network -- forfeiting the independence Path B exists
/// for, on a contract that cannot be changed to stop issuing them.
#[test]
#[should_panic(expected = "Error(Contract, #52)")] // InvalidConfig
fn a_mint_that_could_outgrow_path_b_is_refused() {
    setup_with_config(10, 3, crate::MAX_REDEEMABLE_PAIRS + 1, 1000);
}

/// The documented ceiling itself is accepted, so the rule does not cost
/// a legitimate deployment anything.
#[test]
fn a_mint_at_the_documented_ceiling_is_accepted() {
    let s = setup_with_config(10, 3, crate::MAX_REDEEMABLE_PAIRS, 1000);
    assert_eq!(s.mint.max_pairs(), crate::MAX_REDEEMABLE_PAIRS);
}

/// A zero-ledger window expires every slot in the ledger that created it.
#[test]
#[should_panic(expected = "Error(Contract, #52)")] // InvalidConfig
fn a_mint_with_a_zero_ledger_window_is_refused() {
    setup_with_config(10, 3, 5, 0);
}

fn register_node(env: &Env, roster: &Address, node: &Address) {
    let client = roster_contract::MockRosterClient::new(env, roster);
    client.add_node(node);
}

fn remove_roster_node(env: &Env, roster: &Address, node: &Address) {
    let client = roster_contract::MockRosterClient::new(env, roster);
    client.remove_node(node);
}

fn make_pair(_env: &Env, a: &Address, b: &Address) -> PairEntry {
    PairEntry {
        node_a: a.clone(),
        node_b: b.clone(),
    }
}

/// A distinct `event_id` per call.
///
/// `request_print` enforces event-id uniqueness, so a shared constant
/// would make "two prints" in a test two prints claiming one name, and
/// the suite would catch that rule rather than the code under test.
fn random_event_id(env: &Env) -> BytesN<32> {
    use core::sync::atomic::{AtomicU32, Ordering};
    static NEXT: AtomicU32 = AtomicU32::new(1);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let mut bytes = [0u8; 32];
    bytes[..4].copy_from_slice(&n.to_be_bytes());
    BytesN::from_array(env, &bytes)
}

fn random_key(env: &Env) -> BytesN<32> {
    BytesN::from_array(env, &[
        99, 98, 97, 96, 95, 94, 93, 92, 91, 90, 89, 88, 87, 86, 85, 84,
        83, 82, 81, 80, 79, 78, 77, 76, 75, 74, 73, 72, 71, 70, 69, 68,
    ])
}

fn partial_key(env: &Env, seed: u8) -> BytesN<32> {
    let mut arr = [0u8; 32];
    arr[0] = seed;
    BytesN::from_array(env, &arr)
}

// ── Constructor ──

#[test]
fn test_constructor() {
    let s = setup();

    assert_eq!(s.mint.node_fee(), 10);
    assert_eq!(s.mint.min_pairs(), 3);
    assert_eq!(s.mint.max_pairs(), 5);
    assert_eq!(s.mint.max_print_ledgers(), 1000);
    assert_eq!(s.mint.pay_token(), s.pay_token_addr);
    assert_eq!(s.mint.roster(), s.roster_addr);
}

// ── Request Print ──

#[test]
fn test_request_print() {
    let s = setup();
    let depositor = Address::generate(&s.env);
    let node_a = Address::generate(&s.env);
    let node_b = Address::generate(&s.env);

    mint_tokens(&s.pay_token, &depositor, 10000);
    register_node(&s.env, &s.roster_addr, &node_a);
    register_node(&s.env, &s.roster_addr, &node_b);

    let mut pairs = Vec::new(&s.env);
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    pairs.push_back(make_pair(&s.env, &node_a, &node_b));

    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    let event_id = random_event_id(&s.env);
    let slot_id = s.mint.request_pairs(&depositor, &event_id, &1000, &pairs);
    assert_eq!(slot_id, 0);

    // Escrow transferred
    assert_eq!(s.pay_token.balance(&depositor), 9000);
    assert_eq!(s.pay_token.balance(&s.mint.address), 1000);

    // Slot stored
    let slot = s.mint.get_slot(&0).unwrap();
    assert_eq!(slot.depositor, depositor);
    assert_eq!(slot.amount, 1000);
    assert_eq!(slot.total_pairs, 3);
    assert_eq!(slot.completed_links, 0);
    assert_eq!(slot.state, TokenState::Printing);
}

#[test]
fn test_request_print_increments_slot_id() {
    let s = setup();
    let depositor = Address::generate(&s.env);
    let node_a = Address::generate(&s.env);
    let node_b = Address::generate(&s.env);

    mint_tokens(&s.pay_token, &depositor, 100000);
    register_node(&s.env, &s.roster_addr, &node_a);
    register_node(&s.env, &s.roster_addr, &node_b);

    let mut pairs = Vec::new(&s.env);
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    pairs.push_back(make_pair(&s.env, &node_a, &node_b));

    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    let id0 = s.mint.request_pairs(&depositor, &random_event_id(&s.env), &1000, &pairs);
    let id1 = s.mint.request_pairs(&depositor, &random_event_id(&s.env), &2000, &pairs);

    assert_eq!(id0, 0);
    assert_eq!(id1, 1);
}

#[test]
#[should_panic(expected = "Error(Contract, #20)")]
fn test_request_print_too_few_pairs() {
    let s = setup();
    let depositor = Address::generate(&s.env);
    mint_tokens(&s.pay_token, &depositor, 10000);

    let pairs = Vec::new(&s.env); // 0 pairs, min is 3
    s.mint.request_pairs(&depositor, &random_event_id(&s.env), &1000, &pairs);
}

#[test]
#[should_panic(expected = "Error(Contract, #21)")]
fn test_request_print_unregistered_node() {
    let s = setup();
    let depositor = Address::generate(&s.env);
    let fake_a = Address::generate(&s.env);
    let fake_b = Address::generate(&s.env);

    mint_tokens(&s.pay_token, &depositor, 10000);

    let mut pairs = Vec::new(&s.env);
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    pairs.push_back(make_pair(&s.env, &fake_a, &fake_b));

    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    s.mint.request_pairs(&depositor, &random_event_id(&s.env), &1000, &pairs);
}

#[test]
#[should_panic(expected = "Error(Contract, #51)")]
fn test_request_print_amount_too_small_for_fees() {
    let s = setup_with_config(100, 3, 5, 1000); // node_fee=100, so 1 pair = 200 fees
    let depositor = Address::generate(&s.env);
    let node_a = Address::generate(&s.env);
    let node_b = Address::generate(&s.env);

    mint_tokens(&s.pay_token, &depositor, 10000);
    register_node(&s.env, &s.roster_addr, &node_a);
    register_node(&s.env, &s.roster_addr, &node_b);

    let mut pairs = Vec::new(&s.env);
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    pairs.push_back(make_pair(&s.env, &node_a, &node_b));

    // Amount 200 == total_fees (200), needs to be strictly greater
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    s.mint.request_pairs(&depositor, &random_event_id(&s.env), &200, &pairs);
}

// ── Confirm Link ──

#[test]
fn test_confirm_link() {
    let s = setup();
    let depositor = Address::generate(&s.env);
    let node_a = Address::generate(&s.env);
    let node_b = Address::generate(&s.env);

    mint_tokens(&s.pay_token, &depositor, 10000);
    register_node(&s.env, &s.roster_addr, &node_a);
    register_node(&s.env, &s.roster_addr, &node_b);

    let mut pairs = Vec::new(&s.env);
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    pairs.push_back(make_pair(&s.env, &node_a, &node_b));

    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    let slot_id = s.mint.request_pairs(&depositor, &random_event_id(&s.env), &1000, &pairs);

    let pk = partial_key(&s.env, 1);
    s.mint.confirm_link(&depositor, &slot_id, &0, &partial_key(&s.env, 90));
    let completed = s.mint.confirm_link(&node_a, &slot_id, &1, &pk);
    assert_eq!(completed, 2);

    let slot = s.mint.get_slot(&slot_id).unwrap();
    assert_eq!(slot.completed_links, 2);
    assert_eq!(slot.partial_keys.len(), 2);
}

#[test]
fn test_confirm_link_multi_pair() {
    let s = setup();
    let depositor = Address::generate(&s.env);
    let na1 = Address::generate(&s.env);
    let nb1 = Address::generate(&s.env);
    let na2 = Address::generate(&s.env);
    let nb2 = Address::generate(&s.env);

    mint_tokens(&s.pay_token, &depositor, 100000);
    register_node(&s.env, &s.roster_addr, &na1);
    register_node(&s.env, &s.roster_addr, &nb1);
    register_node(&s.env, &s.roster_addr, &na2);
    register_node(&s.env, &s.roster_addr, &nb2);

    let mut pairs = Vec::new(&s.env);
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    pairs.push_back(make_pair(&s.env, &na1, &nb1));
    pairs.push_back(make_pair(&s.env, &na2, &nb2));

    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    let slot_id = s.mint.request_pairs(&depositor, &random_event_id(&s.env), &1000, &pairs);

    // Pair 0 confirms
    s.mint.confirm_link(&depositor, &slot_id, &0, &partial_key(&s.env, 90));
    s.mint.confirm_link(&na1, &slot_id, &1, &partial_key(&s.env, 1));
    // Pair 1 confirms (node_b this time)
    s.mint.confirm_link(&nb2, &slot_id, &2, &partial_key(&s.env, 2));

    let slot = s.mint.get_slot(&slot_id).unwrap();
    assert_eq!(slot.completed_links, 3, "the depositor's opening link, and both node links");
}

#[test]
#[should_panic(expected = "Error(Contract, #25)")]
fn test_confirm_link_wrong_pair() {
    let s = setup();
    let depositor = Address::generate(&s.env);
    let na = Address::generate(&s.env);
    let nb = Address::generate(&s.env);
    let outsider = Address::generate(&s.env);

    mint_tokens(&s.pay_token, &depositor, 10000);
    register_node(&s.env, &s.roster_addr, &na);
    register_node(&s.env, &s.roster_addr, &nb);

    let mut pairs = Vec::new(&s.env);
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    pairs.push_back(make_pair(&s.env, &na, &nb));

    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    let slot_id = s.mint.request_pairs(&depositor, &random_event_id(&s.env), &1000, &pairs);

    // Outsider tries to confirm
    s.mint.confirm_link(&depositor, &slot_id, &0, &partial_key(&s.env, 90));
    s.mint.confirm_link(&outsider, &slot_id, &1, &partial_key(&s.env, 1));
}

#[test]
#[should_panic(expected = "Error(Contract, #26)")]
fn test_confirm_link_out_of_order() {
    let s = setup();
    let depositor = Address::generate(&s.env);
    let na1 = Address::generate(&s.env);
    let nb1 = Address::generate(&s.env);
    let na2 = Address::generate(&s.env);
    let nb2 = Address::generate(&s.env);

    mint_tokens(&s.pay_token, &depositor, 100000);
    register_node(&s.env, &s.roster_addr, &na1);
    register_node(&s.env, &s.roster_addr, &nb1);
    register_node(&s.env, &s.roster_addr, &na2);
    register_node(&s.env, &s.roster_addr, &nb2);

    let mut pairs = Vec::new(&s.env);
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    pairs.push_back(make_pair(&s.env, &na1, &nb1));
    pairs.push_back(make_pair(&s.env, &na2, &nb2));

    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    let slot_id = s.mint.request_pairs(&depositor, &random_event_id(&s.env), &1000, &pairs);

    // Try to confirm link 1 before link 0
    s.mint.confirm_link(&depositor, &slot_id, &0, &partial_key(&s.env, 90));
    s.mint.confirm_link(&na2, &slot_id, &2, &partial_key(&s.env, 1));
}

// ── Cancel Print ──

#[test]
fn test_cancel_print() {
    let s = setup();
    let depositor = Address::generate(&s.env);
    let na = Address::generate(&s.env);
    let nb = Address::generate(&s.env);

    mint_tokens(&s.pay_token, &depositor, 10000);
    register_node(&s.env, &s.roster_addr, &na);
    register_node(&s.env, &s.roster_addr, &nb);

    let mut pairs = Vec::new(&s.env);
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    pairs.push_back(make_pair(&s.env, &na, &nb));

    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    let slot_id = request_only(&s, &depositor, &random_event_id(&s.env), 1000, &pairs);
    assert_eq!(s.pay_token.balance(&depositor), 9000);

    let refund = s.mint.cancel_print(&depositor, &slot_id);
    assert_eq!(refund, 1000);
    assert_eq!(s.pay_token.balance(&depositor), 10000);

    // Cancelling retires the slot rather than parking it as Cancelled:
    // nothing reads an abandoned print, and the record is 956 bytes.
    assert!(s.mint.get_slot(&slot_id).is_none());
}

#[test]
#[should_panic(expected = "Error(Contract, #28)")]
fn test_cancel_print_not_depositor() {
    let s = setup();
    let depositor = Address::generate(&s.env);
    let other = Address::generate(&s.env);
    let na = Address::generate(&s.env);
    let nb = Address::generate(&s.env);

    mint_tokens(&s.pay_token, &depositor, 10000);
    register_node(&s.env, &s.roster_addr, &na);
    register_node(&s.env, &s.roster_addr, &nb);

    let mut pairs = Vec::new(&s.env);
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    pairs.push_back(make_pair(&s.env, &na, &nb));

    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    let slot_id = s.mint.request_pairs(&depositor, &random_event_id(&s.env), &1000, &pairs);

    // Other user tries to cancel
    s.mint.cancel_print(&other, &slot_id);
}

// ── Register Token ──

#[test]
fn test_register_token() {
    let s = setup();
    let depositor = Address::generate(&s.env);
    let na = Address::generate(&s.env);
    let nb = Address::generate(&s.env);

    mint_tokens(&s.pay_token, &depositor, 10000);
    register_node(&s.env, &s.roster_addr, &na);
    register_node(&s.env, &s.roster_addr, &nb);

    let mut pairs = Vec::new(&s.env);
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    pairs.push_back(make_pair(&s.env, &na, &nb));

    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    let slot_id = s.mint.request_pairs(&depositor, &random_event_id(&s.env), &1000, &pairs);

    // Confirm the link
    s.mint.confirm_link(&depositor, &slot_id, &0, &partial_key(&s.env, 90));
    s.mint.confirm_link(&na, &slot_id, &1, &partial_key(&s.env, 1));
    s.mint.confirm_link(&depositor, &slot_id, &2, &partial_key(&s.env, 91));

    // Register
    let ek = random_key(&s.env);
    let result = s.mint.register_token(&depositor, &slot_id, &ek, &partial_key(&s.env, 200), &TokenMode::PureBearer, &BytesN::from_array(&s.env, &[0u8; 32]), &claim_pk(&s.env));
    assert_eq!(result, true);

    // The print slot is retired by registration, not kept as Active.
    assert!(s.mint.get_slot(&slot_id).is_none());

    // Token record created
    let token = s.mint.get_token(&slot_id).unwrap();
    assert_eq!(token.state, TokenState::Active);
    assert_eq!(token.amount, 1000);
    // Both nodes, and the depositor's four end slots. The end pairs
    // are exempt from the roster and distinctness checks, not from the
    // participant list -- the fees they draw return to the depositor.
    assert_eq!(token.participants.len(), 6);
    assert_eq!(token.node_fee, 10);
}

/// Registration must never write over an existing token record.
///
/// Every check in `register_token` authorises the caller's *slot* — that
/// it exists, is printing, is theirs, and is complete. None of them
/// constrain which *token* the caller may name, and the ephemeral key is
/// a public identifier: `confirm_link` publishes each partial public key,
/// they sum to it, and it appears in the `TOKEN/active` event. So with
/// records keyed by key, completing any cheap print would let a caller
/// replace any live note's amount, participants, chain hash and owner
/// commitment. The victim's escrow would then be unreachable: their slot
/// stays `Active`, so `cancel_print` refuses, and no record points at the
/// deposit.
#[test]
fn a_squatted_key_writes_only_the_squatters_own_record() {
    let s = setup();
    let victim = Address::generate(&s.env);
    let attacker = Address::generate(&s.env);
    let accomplice = Address::generate(&s.env);
    let accomplice2 = Address::generate(&s.env);
    let na = Address::generate(&s.env);
    let nb = Address::generate(&s.env);

    mint_tokens(&s.pay_token, &victim, 10_000);
    mint_tokens(&s.pay_token, &attacker, 10_000);
    for n in [&na, &nb, &accomplice, &accomplice2] {
        register_node(&s.env, &s.roster_addr, n);
    }

    // The victim prints honestly and registers a note worth 1000.
    let mut pairs = Vec::new(&s.env);
    pairs.push_back(make_pair(&s.env, &victim, &victim));
    pairs.push_back(make_pair(&s.env, &na, &nb));
    pairs.push_back(make_pair(&s.env, &victim, &victim));
    let victim_slot = s
        .mint
        .request_pairs(&victim, &random_event_id(&s.env), &1000, &pairs);
    s.mint.confirm_link(&victim, &victim_slot, &0, &partial_key(&s.env, 90));
    s.mint.confirm_link(&na, &victim_slot, &1, &partial_key(&s.env, 1));
    s.mint.confirm_link(&victim, &victim_slot, &2, &partial_key(&s.env, 91));
    let ek = random_key(&s.env);
    let victim_chain = partial_key(&s.env, 200);
    s.mint.register_token(
        &victim,
        &victim_slot,
        &ek,
        &victim_chain,
        &TokenMode::PureBearer,
        &BytesN::from_array(&s.env, &[0u8; 32]),
        &claim_pk(&s.env),
    );

    // The attacker completes a cheap print of their own, then names the
    // victim's key — which they can read straight out of the event.
    //
    // The interior pair is attacker + accomplice rather than the
    // attacker twice: a self-pair in the interior is refused. That costs
    // the attack nothing — a
    // second address on the roster is cheap, and the point of this test
    // is the overwrite, not how the attacker got a slot. The attacker's
    // own end pairs are exempt, as any depositor's are.
    let mut apairs = Vec::new(&s.env);
    apairs.push_back(make_pair(&s.env, &attacker, &attacker));
    apairs.push_back(make_pair(&s.env, &accomplice, &accomplice2));
    apairs.push_back(make_pair(&s.env, &attacker, &attacker));
    let attacker_slot =
        s.mint
            .request_pairs(&attacker, &random_event_id(&s.env), &100, &apairs);
    s.mint
        .confirm_link(&attacker, &attacker_slot, &0, &partial_key(&s.env, 92));
    s.mint
        .confirm_link(&accomplice, &attacker_slot, &1, &partial_key(&s.env, 2));
    s.mint
        .confirm_link(&attacker, &attacker_slot, &2, &partial_key(&s.env, 93));

    // Naming the victim's key is *allowed*, and that is the point.
    //
    // Refusing it would turn the overwrite into a race the attacker wins:
    // `ek` is public before the victim's own `register_token` lands, so a
    // parked slot could claim it and the victim's print could never be
    // registered at all.
    //
    // Records are keyed by slot, so this writes the attacker's own
    // record and touches nothing of the victim's. All the squatter has
    // achieved is to put their own 100 within reach of whoever holds the
    // secret behind that key -- which is the victim.
    s.mint.register_token(
        &attacker,
        &attacker_slot,
        &ek,
        &partial_key(&s.env, 201),
        &TokenMode::PureBearer,
        &BytesN::from_array(&s.env, &[0u8; 32]),
        &claim_pk(&s.env),
    );

    // The victim's record is untouched: amount, chain commitment and slot.
    let token = s.mint.get_token(&victim_slot).unwrap();
    assert_eq!(token.amount, 1000, "the victim's amount was replaced");
    assert_eq!(token.chain_hash, victim_chain, "the chain commitment was replaced");
    assert_eq!(token.slot_id, victim_slot, "the record now points at another slot");

    // Two records, two escrows, no interference.
    let squat = s.mint.get_token(&attacker_slot).unwrap();
    assert_eq!(squat.amount, 100, "the squatter got their own escrow, not the victim's");
    assert_eq!(squat.ephemeral_key, token.ephemeral_key, "they do name the same key");
    assert_ne!(victim_slot, attacker_slot);

    // And one slot still cannot be registered twice.
    let again = s.mint.try_register_token(
        &attacker,
        &attacker_slot,
        &random_key(&s.env),
        &partial_key(&s.env, 202),
        &TokenMode::PureBearer,
        &BytesN::from_array(&s.env, &[0u8; 32]),
        &claim_pk(&s.env),
    );
    assert!(again.is_err(), "a slot registered twice");
}

/// A squatter cannot stop a print being registered.
///
/// With the record keyed by the caller-named `ek`, and `ek` public from
/// the `LINK/confirm` events before the depositor's separate
/// `register_token` transaction, whoever named it first would win. The
/// victim's key is determined by shards bound to their `event_id`, and
/// the `event_id` is burned, so there would be no second attempt --
/// minting could be denied at no cost, against every print on the mint,
/// forever.
#[test]
fn a_squatted_key_does_not_block_the_print_that_owns_it() {
    let s = setup();
    let victim = Address::generate(&s.env);
    let attacker = Address::generate(&s.env);
    let accomplice = Address::generate(&s.env);
    let accomplice2 = Address::generate(&s.env);
    let na = Address::generate(&s.env);
    let nb = Address::generate(&s.env);

    mint_tokens(&s.pay_token, &victim, 10_000);
    mint_tokens(&s.pay_token, &attacker, 10_000);
    for n in [&na, &nb, &accomplice, &accomplice2] {
        register_node(&s.env, &s.roster_addr, n);
    }

    // The attacker parks a completed cheap slot, waiting.
    let mut apairs = Vec::new(&s.env);
    apairs.push_back(make_pair(&s.env, &attacker, &attacker));
    apairs.push_back(make_pair(&s.env, &accomplice, &accomplice2));
    apairs.push_back(make_pair(&s.env, &attacker, &attacker));
    let attacker_slot =
        s.mint
            .request_pairs(&attacker, &random_event_id(&s.env), &100, &apairs);
    s.mint
        .confirm_link(&attacker, &attacker_slot, &0, &partial_key(&s.env, 92));
    s.mint
        .confirm_link(&accomplice, &attacker_slot, &1, &partial_key(&s.env, 2));
    s.mint
        .confirm_link(&attacker, &attacker_slot, &2, &partial_key(&s.env, 93));

    // The victim's print completes. Its key is computable by anyone
    // watching the ledger, and the victim has not registered yet.
    let mut pairs = Vec::new(&s.env);
    pairs.push_back(make_pair(&s.env, &victim, &victim));
    pairs.push_back(make_pair(&s.env, &na, &nb));
    pairs.push_back(make_pair(&s.env, &victim, &victim));
    let victim_slot = s
        .mint
        .request_pairs(&victim, &random_event_id(&s.env), &1000, &pairs);
    s.mint.confirm_link(&victim, &victim_slot, &0, &partial_key(&s.env, 90));
    s.mint.confirm_link(&na, &victim_slot, &1, &partial_key(&s.env, 1));
    s.mint.confirm_link(&victim, &victim_slot, &2, &partial_key(&s.env, 91));
    let ek = random_key(&s.env);

    // The attacker gets there first.
    s.mint.register_token(
        &attacker,
        &attacker_slot,
        &ek,
        &partial_key(&s.env, 201),
        &TokenMode::PureBearer,
        &BytesN::from_array(&s.env, &[0u8; 32]),
        &claim_pk(&s.env),
    );

    // The victim registers anyway. Keyed by `ek`, this would fail with
    // TokenExists, permanently.
    s.mint.register_token(
        &victim,
        &victim_slot,
        &ek,
        &partial_key(&s.env, 200),
        &TokenMode::PureBearer,
        &BytesN::from_array(&s.env, &[0u8; 32]),
        &claim_pk(&s.env),
    );

    let mine = s.mint.get_token(&victim_slot).unwrap();
    assert_eq!(mine.amount, 1000);
    assert_eq!(mine.state, TokenState::Active);
}

#[test]
#[should_panic(expected = "Error(Contract, #29)")]
fn test_register_token_not_complete() {
    let s = setup();
    let depositor = Address::generate(&s.env);
    let na = Address::generate(&s.env);
    let nb = Address::generate(&s.env);

    mint_tokens(&s.pay_token, &depositor, 10000);
    register_node(&s.env, &s.roster_addr, &na);
    register_node(&s.env, &s.roster_addr, &nb);

    let mut pairs = Vec::new(&s.env);
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    pairs.push_back(make_pair(&s.env, &na, &nb));

    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    let slot_id = s.mint.request_pairs(&depositor, &random_event_id(&s.env), &1000, &pairs);

    // Don't confirm any links — register should fail
    s.mint.register_token(&depositor, &slot_id, &random_key(&s.env), &partial_key(&s.env, 200), &TokenMode::PureBearer, &BytesN::from_array(&s.env, &[0u8; 32]), &claim_pk(&s.env));
}

#[test]
#[should_panic(expected = "Error(Contract, #28)")]
fn test_register_token_not_depositor() {
    let s = setup();
    let depositor = Address::generate(&s.env);
    let other = Address::generate(&s.env);
    let na = Address::generate(&s.env);
    let nb = Address::generate(&s.env);

    mint_tokens(&s.pay_token, &depositor, 10000);
    register_node(&s.env, &s.roster_addr, &na);
    register_node(&s.env, &s.roster_addr, &nb);

    let mut pairs = Vec::new(&s.env);
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    pairs.push_back(make_pair(&s.env, &na, &nb));

    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    let slot_id = s.mint.request_pairs(&depositor, &random_event_id(&s.env), &1000, &pairs);
    s.mint.confirm_link(&depositor, &slot_id, &0, &partial_key(&s.env, 90));
    s.mint.confirm_link(&na, &slot_id, &1, &partial_key(&s.env, 1));
    s.mint.confirm_link(&depositor, &slot_id, &2, &partial_key(&s.env, 91));

    // Wrong person tries to register
    s.mint.register_token(&other, &slot_id, &random_key(&s.env), &partial_key(&s.env, 200), &TokenMode::PureBearer, &BytesN::from_array(&s.env, &[0u8; 32]), &claim_pk(&s.env));
}

// ── Slot Expiration ──

#[test]
fn test_slot_expiration() {
    let s = setup_with_config(10, 3, 5, 100); // 100 ledgers max
    let depositor = Address::generate(&s.env);
    let na = Address::generate(&s.env);
    let nb = Address::generate(&s.env);

    mint_tokens(&s.pay_token, &depositor, 10000);
    register_node(&s.env, &s.roster_addr, &na);
    register_node(&s.env, &s.roster_addr, &nb);

    let mut pairs = Vec::new(&s.env);
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    pairs.push_back(make_pair(&s.env, &na, &nb));

    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    let slot_id = request_only(&s, &depositor, &random_event_id(&s.env), 1000, &pairs);

    // Not expired yet
    assert_eq!(s.mint.is_slot_expired(&slot_id), false);

    // Advance past expiration
    let created = s.env.ledger().sequence();
    s.env.ledger().set_sequence_number(created + 101);

    assert_eq!(s.mint.is_slot_expired(&slot_id), true);

    let refund = s.mint.clear_expired_slot(&slot_id);
    assert_eq!(refund, 1000);
    assert_eq!(s.pay_token.balance(&depositor), 10000);
}

#[test]
#[should_panic(expected = "Error(Contract, #30)")]
fn test_clear_slot_not_expired() {
    let s = setup_with_config(10, 3, 5, 1000);
    let depositor = Address::generate(&s.env);
    let na = Address::generate(&s.env);
    let nb = Address::generate(&s.env);

    mint_tokens(&s.pay_token, &depositor, 10000);
    register_node(&s.env, &s.roster_addr, &na);
    register_node(&s.env, &s.roster_addr, &nb);

    let mut pairs = Vec::new(&s.env);
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    pairs.push_back(make_pair(&s.env, &na, &nb));

    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    let slot_id = s.mint.request_pairs(&depositor, &random_event_id(&s.env), &1000, &pairs);

    // Try to clear when not expired
    s.mint.clear_expired_slot(&slot_id);
}

#[test]
#[should_panic(expected = "Error(Contract, #24)")]
fn test_confirm_link_expired_slot() {
    let s = setup_with_config(10, 3, 5, 100);
    let depositor = Address::generate(&s.env);
    let na = Address::generate(&s.env);
    let nb = Address::generate(&s.env);

    mint_tokens(&s.pay_token, &depositor, 10000);
    register_node(&s.env, &s.roster_addr, &na);
    register_node(&s.env, &s.roster_addr, &nb);

    let mut pairs = Vec::new(&s.env);
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    pairs.push_back(make_pair(&s.env, &na, &nb));

    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    let slot_id = s.mint.request_pairs(&depositor, &random_event_id(&s.env), &1000, &pairs);

    // Advance past expiration
    let created = s.env.ledger().sequence();
    s.env.ledger().set_sequence_number(created + 101);

    // Attempt confirm on expired slot
    s.mint.confirm_link(&depositor, &slot_id, &0, &partial_key(&s.env, 90));
    s.mint.confirm_link(&na, &slot_id, &1, &partial_key(&s.env, 1));
}

// ── Queries ──

#[test]
fn test_token_state_queries() {
    let s = setup();
    let depositor = Address::generate(&s.env);
    let na = Address::generate(&s.env);
    let nb = Address::generate(&s.env);

    mint_tokens(&s.pay_token, &depositor, 10000);
    register_node(&s.env, &s.roster_addr, &na);
    register_node(&s.env, &s.roster_addr, &nb);

    let mut pairs = Vec::new(&s.env);
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    pairs.push_back(make_pair(&s.env, &na, &nb));

    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    let slot_id = s.mint.request_pairs(&depositor, &random_event_id(&s.env), &1000, &pairs);
    s.mint.confirm_link(&depositor, &slot_id, &0, &partial_key(&s.env, 90));
    s.mint.confirm_link(&na, &slot_id, &1, &partial_key(&s.env, 1));
    s.mint.confirm_link(&depositor, &slot_id, &2, &partial_key(&s.env, 91));

    let ek = random_key(&s.env);
    s.mint.register_token(&depositor, &slot_id, &ek, &partial_key(&s.env, 200), &TokenMode::PureBearer, &BytesN::from_array(&s.env, &[0u8; 32]), &claim_pk(&s.env));

    assert_eq!(s.mint.get_token_state(&slot_id), Some(TokenState::Active));
    assert_eq!(s.mint.is_redeemed(&slot_id), false);

    // A slot nobody has registered.
    let unused_slot = 9_999u32;
    assert_eq!(s.mint.get_token_state(&unused_slot), None);
    assert_eq!(s.mint.is_redeemed(&unused_slot), false);
}

// ── Events ──

#[test]
fn test_print_request_event() {
    let s = setup();
    let depositor = Address::generate(&s.env);
    let na = Address::generate(&s.env);
    let nb = Address::generate(&s.env);

    mint_tokens(&s.pay_token, &depositor, 10000);
    register_node(&s.env, &s.roster_addr, &na);
    register_node(&s.env, &s.roster_addr, &nb);

    let mut pairs = Vec::new(&s.env);
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    pairs.push_back(make_pair(&s.env, &na, &nb));

    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    s.mint.request_pairs(&depositor, &random_event_id(&s.env), &1000, &pairs);

    let events = s.env.events().all();
    let last = events.last().unwrap();
    let (_cid, topics, _data) = last;

    let topic0: Symbol =
        Symbol::try_from_val(&s.env, &topics.get_unchecked(0)).unwrap();
    assert_eq!(topic0, symbol_short!("PRINT"));
}

#[test]
fn test_link_confirmed_event() {
    let s = setup();
    let depositor = Address::generate(&s.env);
    let na = Address::generate(&s.env);
    let nb = Address::generate(&s.env);

    mint_tokens(&s.pay_token, &depositor, 10000);
    register_node(&s.env, &s.roster_addr, &na);
    register_node(&s.env, &s.roster_addr, &nb);

    let mut pairs = Vec::new(&s.env);
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    pairs.push_back(make_pair(&s.env, &na, &nb));

    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    let slot_id = s.mint.request_pairs(&depositor, &random_event_id(&s.env), &1000, &pairs);
    s.mint.confirm_link(&depositor, &slot_id, &0, &partial_key(&s.env, 90));
    s.mint.confirm_link(&na, &slot_id, &1, &partial_key(&s.env, 1));

    let events = s.env.events().all();
    let last = events.last().unwrap();
    let (_cid, topics, _data) = last;

    let topic0: Symbol =
        Symbol::try_from_val(&s.env, &topics.get_unchecked(0)).unwrap();
    assert_eq!(topic0, symbol_short!("LINK"));
}

#[test]
fn test_token_active_event() {
    let s = setup();
    let depositor = Address::generate(&s.env);
    let na = Address::generate(&s.env);
    let nb = Address::generate(&s.env);

    mint_tokens(&s.pay_token, &depositor, 10000);
    register_node(&s.env, &s.roster_addr, &na);
    register_node(&s.env, &s.roster_addr, &nb);

    let mut pairs = Vec::new(&s.env);
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    pairs.push_back(make_pair(&s.env, &na, &nb));

    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    let slot_id = s.mint.request_pairs(&depositor, &random_event_id(&s.env), &1000, &pairs);
    s.mint.confirm_link(&depositor, &slot_id, &0, &partial_key(&s.env, 90));
    s.mint.confirm_link(&na, &slot_id, &1, &partial_key(&s.env, 1));
    s.mint.confirm_link(&depositor, &slot_id, &2, &partial_key(&s.env, 91));
    s.mint.register_token(&depositor, &slot_id, &random_key(&s.env), &partial_key(&s.env, 200), &TokenMode::PureBearer, &BytesN::from_array(&s.env, &[0u8; 32]), &claim_pk(&s.env));

    let events = s.env.events().all();
    let last = events.last().unwrap();
    let (_cid, topics, _data) = last;

    let topic0: Symbol =
        Symbol::try_from_val(&s.env, &topics.get_unchecked(0)).unwrap();
    assert_eq!(topic0, symbol_short!("TOKEN"));
}

// ── Full Lifecycle: Print → Confirm → Register ──

#[test]
fn test_full_print_lifecycle_3_pairs() {
    let s = setup_with_config(10, 3, 5, 1000);
    let depositor = Address::generate(&s.env);

    let na1 = Address::generate(&s.env);
    let nb1 = Address::generate(&s.env);
    let na2 = Address::generate(&s.env);
    let nb2 = Address::generate(&s.env);
    let na3 = Address::generate(&s.env);
    let nb3 = Address::generate(&s.env);

    mint_tokens(&s.pay_token, &depositor, 100000);
    for n in [&na1, &nb1, &na2, &nb2, &na3, &nb3] {
        register_node(&s.env, &s.roster_addr, n);
    }

    let mut pairs = Vec::new(&s.env);
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    pairs.push_back(make_pair(&s.env, &na1, &nb1));
    pairs.push_back(make_pair(&s.env, &na2, &nb2));
    pairs.push_back(make_pair(&s.env, &na3, &nb3));

    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    let event_id = random_event_id(&s.env);
    let slot_id = s.mint.request_pairs(&depositor, &event_id, &10000, &pairs);

    // Confirm all 3 links, in the order the draw put the pairs in, by
    // either member (the second link by its `node_b`).
    let order = chain_order(&s, slot_id);
    s.mint.confirm_link(&depositor, &slot_id, &0, &partial_key(&s.env, 90));
    s.mint.confirm_link(&order[1].node_a, &slot_id, &1, &partial_key(&s.env, 1));
    s.mint.confirm_link(&order[2].node_b, &slot_id, &2, &partial_key(&s.env, 2));
    s.mint.confirm_link(&order[3].node_a, &slot_id, &3, &partial_key(&s.env, 3));
    s.mint.confirm_link(&depositor, &slot_id, &4, &partial_key(&s.env, 91));

    let slot = s.mint.get_slot(&slot_id).unwrap();
    assert_eq!(slot.completed_links, 5, "three node links plus the depositor's two");

    // Register token
    let ek = random_key(&s.env);
    s.mint.register_token(&depositor, &slot_id, &ek, &partial_key(&s.env, 200), &TokenMode::PureBearer, &BytesN::from_array(&s.env, &[0u8; 32]), &claim_pk(&s.env));

    let token = s.mint.get_token(&slot_id).unwrap();
    assert_eq!(token.state, TokenState::Active);
    assert_eq!(token.participants.len(), 10); // 5 pairs × 2
    assert_eq!(token.amount, 10000);

    // Escrow still held
    assert_eq!(s.pay_token.balance(&s.mint.address), 10000);
}

// ── SECURITY: Path B chain-binding ──
// `redeem_by_chain` must reject any chain whose SHA-256 != the commitment
// registered at mint. Otherwise a chain forged from public data
// (ephemeral_key + event_id + pair count) drains the escrow.

const POC_CHAIN_DOMAIN_TAG: &[u8] = b"kntr_v1:chain:link";

/// Build a valid `chain_data` blob with `num_links` links, signed by Ed25519
/// keys derived from `seed`. This is the exact blob submitted to `redeem_by_chain`;
/// its SHA-256 is the registration commitment. Different `seed` → different chain.
fn build_chain(event_id: &[u8; 32], num_links: u16, seed: u8) -> std::vec::Vec<u8> {
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};

    let mut out: std::vec::Vec<u8> = std::vec::Vec::new();
    out.extend_from_slice(event_id);
    out.extend_from_slice(&num_links.to_le_bytes());

    let mut prev_hash = [0u8; 32]; // genesis
    for i in 0..num_links {
        let ka = SigningKey::from_bytes(&[seed.wrapping_add(i as u8); 32]);
        let kb = SigningKey::from_bytes(&[seed.wrapping_add(0x80).wrapping_add(i as u8); 32]);
        let node_a = ka.verifying_key().to_bytes();
        let node_b = kb.verifying_key().to_bytes();
        let partial = [0u8; 32];
        let commit = [0u8; 32];
        let idx_le = i.to_le_bytes();

        // signable = DOMAIN || node_a || node_b || partial || commit || prev_hash || idx_le || event_id
        let mut signable: std::vec::Vec<u8> = std::vec::Vec::new();
        signable.extend_from_slice(POC_CHAIN_DOMAIN_TAG);
        signable.extend_from_slice(&node_a);
        signable.extend_from_slice(&node_b);
        signable.extend_from_slice(&partial);
        signable.extend_from_slice(&commit);
        signable.extend_from_slice(&prev_hash);
        signable.extend_from_slice(&idx_le);
        signable.extend_from_slice(event_id);

        let sig_a = ka.sign(&signable).to_bytes();
        let sig_b = kb.sign(&signable).to_bytes();

        // 290-byte link: node_a||node_b||partial||commit||prev_hash||idx_le||sig_a||sig_b
        out.extend_from_slice(&node_a);
        out.extend_from_slice(&node_b);
        out.extend_from_slice(&partial);
        out.extend_from_slice(&commit);
        out.extend_from_slice(&prev_hash);
        out.extend_from_slice(&idx_le);
        out.extend_from_slice(&sig_a);
        out.extend_from_slice(&sig_b);

        // next prev_hash = SHA256(signable || sig_a || sig_b)
        let mut hasher = Sha256::new();
        hasher.update(&signable);
        hasher.update(sig_a);
        hasher.update(sig_b);
        prev_hash = hasher.finalize().into();
    }
    out
}

fn sha256_of(env: &Env, bytes: &[u8]) -> BytesN<32> {
    use sha2::{Digest, Sha256};
    let h: [u8; 32] = Sha256::digest(bytes).into();
    BytesN::from_array(env, &h)
}

/// FIX REGRESSION: a chain forged from public data is rejected, because its
/// SHA-256 does not match the commitment registered at mint.
#[test]
#[should_panic(expected = "Error(Contract, #44)")] // ChainVerificationFailed
fn pathb_forged_chain_is_rejected() {
    let s = setup();
    let depositor = Address::generate(&s.env);
    let na = Address::generate(&s.env);
    let nb = Address::generate(&s.env);
    let attacker = Address::generate(&s.env);

    mint_tokens(&s.pay_token, &depositor, 10000);
    register_node(&s.env, &s.roster_addr, &na);
    register_node(&s.env, &s.roster_addr, &nb);

    let mut pairs = Vec::new(&s.env);
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    pairs.push_back(make_pair(&s.env, &na, &nb));
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    let event_id = random_event_id(&s.env);
    let slot_id = s.mint.request_pairs(&depositor, &event_id, &1000, &pairs);
    s.mint.confirm_link(&depositor, &slot_id, &0, &partial_key(&s.env, 90));
    s.mint.confirm_link(&na, &slot_id, &1, &partial_key(&s.env, 1));
    s.mint.confirm_link(&depositor, &slot_id, &2, &partial_key(&s.env, 91));

    // Depositor commits to the REAL chain's hash.
    let real_chain = build_chain(&event_id.to_array(), 3, 0x33);
    let ek = random_key(&s.env);
    s.mint.register_token(&depositor, &slot_id, &ek, &sha256_of(&s.env, &real_chain), &TokenMode::PureBearer, &BytesN::from_array(&s.env, &[0u8; 32]), &claim_pk(&s.env));

    // Attacker forges a DIFFERENT chain from public data → different hash → rejected.
    let forged = build_chain(&event_id.to_array(), 1, 0x99);
    let chain_data = Bytes::from_slice(&s.env, &forged);
    s.mint.redeem_by_chain(
        &attacker,
        &attacker,
        &slot_id, &chain_data, &sig_claim(&s.env, slot_id, &ek, &s.mint.address, &attacker));
}

/// The genuinely committed chain still redeems (the binding does not break Path B).
#[test]
fn pathb_committed_chain_redeems() {
    let s = setup();
    let depositor = Address::generate(&s.env);
    let na = Address::generate(&s.env);
    let nb = Address::generate(&s.env);
    let holder = Address::generate(&s.env);

    mint_tokens(&s.pay_token, &depositor, 10000);
    register_node(&s.env, &s.roster_addr, &na);
    register_node(&s.env, &s.roster_addr, &nb);

    let mut pairs = Vec::new(&s.env);
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    pairs.push_back(make_pair(&s.env, &na, &nb));
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    let event_id = random_event_id(&s.env);
    let slot_id = s.mint.request_pairs(&depositor, &event_id, &1000, &pairs);
    s.mint.confirm_link(&depositor, &slot_id, &0, &partial_key(&s.env, 90));
    s.mint.confirm_link(&na, &slot_id, &1, &partial_key(&s.env, 1));
    s.mint.confirm_link(&depositor, &slot_id, &2, &partial_key(&s.env, 91));

    let chain = build_chain(&event_id.to_array(), 3, 0x33);
    let ek = random_key(&s.env);
    s.mint.register_token(&depositor, &slot_id, &ek, &sha256_of(&s.env, &chain), &TokenMode::PureBearer, &BytesN::from_array(&s.env, &[0u8; 32]), &claim_pk(&s.env));

    // Holder presents the committed chain → succeeds. Payout = 1000 - 10*6 = 980.
    let chain_data = Bytes::from_slice(&s.env, &chain);
    let payout = s.mint.redeem_by_chain(
        &holder,
        &holder,
        &slot_id, &chain_data, &sig_claim(&s.env, slot_id, &ek, &s.mint.address, &holder));
    assert_eq!(payout, 980);
    assert_eq!(s.pay_token.balance(&holder), 980);
    assert_eq!(s.mint.get_token_state(&slot_id), Some(TokenState::Redeemed));

    // Node fees are ACCRUED to the recorded participants, not burned (P1).
    // Only the interior pair is paid, so 20 stroops stay in escrow.
    assert_eq!(s.mint.accrued_fees(&na), 10);
    assert_eq!(s.mint.accrued_fees(&nb), 10);
    // The depositor's end pairs are not credited any more. They did no
    // node work, and crediting them took four fees out of the holder's
    // payout to hand back to whoever printed the note -- a transfer
    // between two different people once a note has changed hands,
    // which is the entire point of one. Each credit also cost a
    // persistent entry to store a balance worth less than the fee to
    // claim it.
    assert_eq!(s.mint.accrued_fees(&depositor), 0);
    assert_eq!(s.pay_token.balance(&s.mint.address), 20);

    // And the balances take a floor, not the 120-day ceiling. Bumping
    // them to `TTL_EXTEND` made `Accrued` 94% of the measured cost of
    // redeeming, growing linearly with pair count -- so a note got
    // dearer to cash the harder it was to collude against. A node
    // tops up its own earnings when it claims them.
    let ttl = ttl_of(&s, &DataKey::Accrued(na.clone()));
    assert!(ttl >= crate::MIN_LIVE_LEDGERS, "earnings below the floor: {ttl}");
    assert!(
        ttl < crate::TTL_EXTEND,
        "the redeemer is still prepaying 120 days on a node's balance: {ttl}"
    );
}

// ── Node Fee Accrual (P1) ──

/// Path B accrues to dark participants; each claims later (churn-tolerant).
#[test]
fn accrual_claim_pays_then_zeroes() {
    let s = setup();
    let depositor = Address::generate(&s.env);
    let na = Address::generate(&s.env);
    let nb = Address::generate(&s.env);
    let holder = Address::generate(&s.env);

    mint_tokens(&s.pay_token, &depositor, 10000);
    register_node(&s.env, &s.roster_addr, &na);
    register_node(&s.env, &s.roster_addr, &nb);

    let mut pairs = Vec::new(&s.env);
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    pairs.push_back(make_pair(&s.env, &na, &nb));
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    let event_id = random_event_id(&s.env);
    let slot_id = s.mint.request_pairs(&depositor, &event_id, &1000, &pairs);
    s.mint.confirm_link(&depositor, &slot_id, &0, &partial_key(&s.env, 90));
    s.mint.confirm_link(&na, &slot_id, &1, &partial_key(&s.env, 1));
    s.mint.confirm_link(&depositor, &slot_id, &2, &partial_key(&s.env, 91));

    let chain = build_chain(&event_id.to_array(), 3, 0x33);
    let ek = random_key(&s.env);
    s.mint.register_token(&depositor, &slot_id, &ek, &sha256_of(&s.env, &chain), &TokenMode::PureBearer, &BytesN::from_array(&s.env, &[0u8; 32]), &claim_pk(&s.env));
    let chain_data = Bytes::from_slice(&s.env, &chain);
    s.mint.redeem_by_chain(
        &holder,
        &holder,
        &slot_id, &chain_data, &sig_claim(&s.env, slot_id, &ek, &s.mint.address, &holder));

    // na was "dark" at redemption; it now comes online and claims.
    assert_eq!(s.mint.accrued_fees(&na), 10);
    let claimed = s.mint.claim_fees(&na);
    assert_eq!(claimed, 10);
    assert_eq!(s.pay_token.balance(&na), 10);
    // Balance is zeroed; a second claim has nothing.
    assert_eq!(s.mint.accrued_fees(&na), 0);
}

/// Path A also accrues node fees (uniform across both paths); nodes are not
/// paid instantly.
#[test]
fn redeem_by_key_accrues_fees() {
    use ed25519_dalek::SigningKey;

    let s = setup();
    let depositor = Address::generate(&s.env);
    let na = Address::generate(&s.env);
    let nb = Address::generate(&s.env);
    let holder = Address::generate(&s.env);

    mint_tokens(&s.pay_token, &depositor, 10000);
    register_node(&s.env, &s.roster_addr, &na);
    register_node(&s.env, &s.roster_addr, &nb);

    let mut pairs = Vec::new(&s.env);
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    pairs.push_back(make_pair(&s.env, &na, &nb));
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    let event_id = random_event_id(&s.env);
    let slot_id = s.mint.request_pairs(&depositor, &event_id, &1000, &pairs);
    s.mint.confirm_link(&depositor, &slot_id, &0, &partial_key(&s.env, 90));
    s.mint.confirm_link(&na, &slot_id, &1, &partial_key(&s.env, 1));
    s.mint.confirm_link(&depositor, &slot_id, &2, &partial_key(&s.env, 91));

    // ephemeral_key must be a real Ed25519 public key for Path A's ed25519_verify.
    let sk = SigningKey::from_bytes(&[0x42u8; 32]);
    let ek_bytes = sk.verifying_key().to_bytes();
    let ek = BytesN::from_array(&s.env, &ek_bytes);
    // chain_hash is irrelevant to Path A; commit a dummy.
    s.mint.register_token(&depositor, &slot_id, &ek, &partial_key(&s.env, 200), &TokenMode::PureBearer, &BytesN::from_array(&s.env, &[0u8; 32]), &claim_pk(&s.env));

    // Binds the recipient and the contract (see `sig_ephemeral`).
    let sig_b = sig_ephemeral(&s.env, slot_id, &sk, &ek, &s.mint.address, &holder);

    let payout = s.mint.redeem_by_key(
        &holder,
        &holder,
        &slot_id,
        &sig_b,
        &sig_claim(&s.env, slot_id, &ek, &s.mint.address, &holder),
    );
    assert_eq!(payout, 980);
    assert_eq!(s.pay_token.balance(&holder), 980);
    // Nodes accrued, NOT paid instantly.
    assert_eq!(s.mint.accrued_fees(&na), 10);
    assert_eq!(s.mint.accrued_fees(&nb), 10);
    assert_eq!(s.pay_token.balance(&na), 0);
}

// ── Volunteer nodes ──

/// A pay token that moves balances like any other but refuses every
/// burn (native XLM refuses burns; an issuer's token might too).
mod refusing_token {
    use soroban_sdk::{Address, Env, MuxedAddress, contract, contractimpl, contracttype};

    #[contracttype]
    pub enum Key {
        Bal(Address),
    }

    #[contract]
    pub struct RefusingToken;

    #[contractimpl]
    impl RefusingToken {
        pub fn mint(e: Env, to: Address, amount: i128) {
            let b = Self::balance(e.clone(), to.clone());
            e.storage().persistent().set(&Key::Bal(to), &(b + amount));
        }

        pub fn balance(e: Env, id: Address) -> i128 {
            e.storage().persistent().get(&Key::Bal(id)).unwrap_or(0)
        }

        pub fn transfer(e: Env, from: Address, to: MuxedAddress, amount: i128) {
            from.require_auth();
            let to = to.address();
            let fb = Self::balance(e.clone(), from.clone());
            if fb < amount {
                panic!("insufficient balance");
            }
            e.storage().persistent().set(&Key::Bal(from), &(fb - amount));
            let tb = Self::balance(e.clone(), to.clone());
            e.storage().persistent().set(&Key::Bal(to), &(tb + amount));
        }

        pub fn burn(_e: Env, _from: Address, _amount: i128) {
            panic!("this token refuses burns");
        }
    }
}

/// A pay token that refuses the burn does not trap the
/// settlement: the holder is paid in full, the paid pair is credited, and
/// the volunteers' fees stay in the mint, said so by `FEE locked`.
#[test]
fn a_refused_burn_locks_the_fee_instead_of_trapping_the_redemption() {
    let env = Env::default();
    env.mock_all_auths();
    let token_addr = env.register(refusing_token::RefusingToken, ());
    let token = refusing_token::RefusingTokenClient::new(&env, &token_addr);
    let roster_addr = env.register(roster_contract::MockRoster, ());
    let mint = KenterMintClient::new(
        &env,
        &env.register(
            KenterMint,
            (10u32, 3u32, 5u32, &token_addr, &roster_addr, 1000u32, test_selection(&env)),
        ),
    );

    let depositor = Address::generate(&env);
    let (va, vb, na, nb) = (
        Address::generate(&env),
        Address::generate(&env),
        Address::generate(&env),
        Address::generate(&env),
    );
    let holder = Address::generate(&env);
    token.mint(&depositor, &10000);
    for n in [&va, &vb, &na, &nb] {
        register_node(&env, &roster_addr, n);
    }
    add_volunteer(&env, &roster_addr, &va);
    add_volunteer(&env, &roster_addr, &vb);

    let mut pairs = Vec::new(&env);
    pairs.push_back(make_pair(&env, &depositor, &depositor));
    pairs.push_back(make_pair(&env, &va, &vb));
    pairs.push_back(make_pair(&env, &na, &nb));
    pairs.push_back(make_pair(&env, &depositor, &depositor));
    let event_id = random_event_id(&env);
    let slot_id = mint.request_pairs(&depositor, &event_id, &1000, &pairs);
    mint.confirm_link(&depositor, &slot_id, &0, &partial_key(&env, 90));
    mint.confirm_link(&va, &slot_id, &1, &partial_key(&env, 1));
    mint.confirm_link(&na, &slot_id, &2, &partial_key(&env, 2));
    mint.confirm_link(&depositor, &slot_id, &3, &partial_key(&env, 91));

    let chain = build_chain(&event_id.to_array(), 4, 0x44);
    let ek = random_key(&env);
    mint.register_token(&depositor, &slot_id, &ek, &sha256_of(&env, &chain), &TokenMode::PureBearer, &BytesN::from_array(&env, &[0u8; 32]), &claim_pk(&env));
    let payout = mint.redeem_by_chain(
        &holder,
        &holder,
        &slot_id,
        &Bytes::from_slice(&env, &chain),
        &sig_claim(&env, slot_id, &ek, &mint.address, &holder),
    );

    let mut locked = std::vec::Vec::new();
    for (_cid, topics, data) in env.events().all().iter() {
        if topics.len() < 2 {
            continue;
        }
        let t0 = Symbol::try_from_val(&env, &topics.get_unchecked(0)).ok();
        let t1 = Symbol::try_from_val(&env, &topics.get_unchecked(1)).ok();
        if t0 == Some(symbol_short!("FEE")) && t1 == Some(symbol_short!("locked")) {
            locked.push(FeeLockedEvent::try_from_val(&env, &data).unwrap());
        }
    }

    assert_eq!(payout, 960, "the holder is paid as if the burn had worked");
    assert_eq!(token.balance(&holder), 960);
    assert_eq!(mint.accrued_fees(&na), 10);
    assert_eq!(mint.accrued_fees(&va), 0, "a volunteer is still never credited");
    assert_eq!(
        token.balance(&mint.address),
        40,
        "the paid pair's 20 in escrow, plus the volunteers' 20 locked"
    );
    assert_eq!(locked, std::vec![FeeLockedEvent { slot_id, amount: 20 }]);
}

fn add_volunteer(env: &Env, roster: &Address, node: &Address) {
    roster_contract::MockRosterClient::new(env, roster).add_volunteer(node);
}

/// The `FeeBurned` events of the last invocation, as (node, amount).
fn burn_events(s: &TestSetup) -> std::vec::Vec<(Address, i128)> {
    let mut out = std::vec::Vec::new();
    for (_cid, topics, data) in s.env.events().all().iter() {
        // The token's own events carry addresses in their topics, so
        // anything that is not two symbols is simply not ours.
        if topics.len() < 2 {
            continue;
        }
        let t0 = Symbol::try_from_val(&s.env, &topics.get_unchecked(0)).ok();
        let t1 = Symbol::try_from_val(&s.env, &topics.get_unchecked(1)).ok();
        if t0 == Some(symbol_short!("FEE")) && t1 == Some(symbol_short!("burned")) {
            let ev = FeeBurnedEvent::try_from_val(&s.env, &data).unwrap();
            out.push((ev.node, ev.amount));
        }
    }
    out
}

/// Path B: a volunteer pair's fees are destroyed, a paid pair's
/// credited, and the holder is paid the same as if nobody volunteered.
#[test]
fn pathb_burns_volunteer_fees_and_credits_the_rest() {
    let s = setup(); // node_fee 10
    let depositor = Address::generate(&s.env);
    let (va, vb, na, nb) = (
        Address::generate(&s.env),
        Address::generate(&s.env),
        Address::generate(&s.env),
        Address::generate(&s.env),
    );
    let holder = Address::generate(&s.env);
    mint_tokens(&s.pay_token, &depositor, 10000);
    for n in [&va, &vb, &na, &nb] {
        register_node(&s.env, &s.roster_addr, n);
    }
    add_volunteer(&s.env, &s.roster_addr, &va);
    add_volunteer(&s.env, &s.roster_addr, &vb);

    let mut pairs = Vec::new(&s.env);
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    pairs.push_back(make_pair(&s.env, &va, &vb));
    pairs.push_back(make_pair(&s.env, &na, &nb));
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    let event_id = random_event_id(&s.env);
    let slot_id = s.mint.request_pairs(&depositor, &event_id, &1000, &pairs);
    s.mint.confirm_link(&depositor, &slot_id, &0, &partial_key(&s.env, 90));
    s.mint.confirm_link(&va, &slot_id, &1, &partial_key(&s.env, 1));
    s.mint.confirm_link(&na, &slot_id, &2, &partial_key(&s.env, 2));
    s.mint.confirm_link(&depositor, &slot_id, &3, &partial_key(&s.env, 91));

    let chain = build_chain(&event_id.to_array(), 4, 0x44);
    let ek = random_key(&s.env);
    s.mint.register_token(&depositor, &slot_id, &ek, &sha256_of(&s.env, &chain), &TokenMode::PureBearer, &BytesN::from_array(&s.env, &[0u8; 32]), &claim_pk(&s.env));
    let payout = s.mint.redeem_by_chain(
        &holder,
        &holder,
        &slot_id,
        &Bytes::from_slice(&s.env, &chain),
        &sig_claim(&s.env, slot_id, &ek, &s.mint.address, &holder),
    );
    let mut burned = burn_events(&s);

    assert_eq!(payout, 960, "four interior fees come off either way: burn, not waive");
    assert_eq!(s.pay_token.balance(&holder), 960);
    assert_eq!(s.mint.accrued_fees(&na), 10);
    assert_eq!(s.mint.accrued_fees(&nb), 10);
    assert_eq!(s.mint.accrued_fees(&va), 0, "a volunteer is never credited");
    assert_eq!(s.mint.accrued_fees(&vb), 0);
    assert_eq!(
        s.pay_token.balance(&s.mint.address),
        20,
        "only the paid pair's fees stay in escrow; the volunteers' 20 are gone"
    );
    burned.sort_by_key(|(_, a)| *a);
    assert_eq!(burned, std::vec![(va.clone(), 10), (vb.clone(), 10)]);
}

/// Path A, with the two members of one pair on different terms: the
/// bit is per participant, not per pair.
#[test]
fn path_a_splits_a_pair_whose_members_differ() {
    use ed25519_dalek::SigningKey;
    let s = setup();
    let depositor = Address::generate(&s.env);
    let va = Address::generate(&s.env);
    let nb = Address::generate(&s.env);
    let holder = Address::generate(&s.env);
    mint_tokens(&s.pay_token, &depositor, 10000);
    register_node(&s.env, &s.roster_addr, &va);
    register_node(&s.env, &s.roster_addr, &nb);
    add_volunteer(&s.env, &s.roster_addr, &va);

    let mut pairs = Vec::new(&s.env);
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    pairs.push_back(make_pair(&s.env, &va, &nb));
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    let slot_id = s.mint.request_pairs(&depositor, &random_event_id(&s.env), &1000, &pairs);
    s.mint.confirm_link(&depositor, &slot_id, &0, &partial_key(&s.env, 90));
    s.mint.confirm_link(&nb, &slot_id, &1, &partial_key(&s.env, 1));
    s.mint.confirm_link(&depositor, &slot_id, &2, &partial_key(&s.env, 91));
    let sk = SigningKey::from_bytes(&[0x42u8; 32]);
    let ek = BytesN::from_array(&s.env, &sk.verifying_key().to_bytes());
    s.mint.register_token(&depositor, &slot_id, &ek, &partial_key(&s.env, 200), &TokenMode::PureBearer, &BytesN::from_array(&s.env, &[0u8; 32]), &claim_pk(&s.env));

    let payout = s.mint.redeem_by_key(
        &holder,
        &holder,
        &slot_id,
        &sig_ephemeral(&s.env, slot_id, &sk, &ek, &s.mint.address, &holder),
        &sig_claim(&s.env, slot_id, &ek, &s.mint.address, &holder),
    );
    let burned = burn_events(&s);
    assert_eq!(payout, 980);
    assert_eq!(s.mint.accrued_fees(&nb), 10);
    assert_eq!(s.mint.accrued_fees(&va), 0);
    assert_eq!(s.pay_token.balance(&s.mint.address), 10);
    assert_eq!(burned, std::vec![(va.clone(), 10)]);
}

/// A cancelled print whose interior link a volunteer confirmed: the
/// depositor's refund is what it would be anyway, and the fee is burned.
#[test]
fn cancelling_burns_a_volunteer_confirmers_fee() {
    let s = setup();
    let depositor = Address::generate(&s.env);
    let va = Address::generate(&s.env);
    let nb = Address::generate(&s.env);
    mint_tokens(&s.pay_token, &depositor, 10000);
    register_node(&s.env, &s.roster_addr, &va);
    register_node(&s.env, &s.roster_addr, &nb);
    add_volunteer(&s.env, &s.roster_addr, &va);

    let mut pairs = Vec::new(&s.env);
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    pairs.push_back(make_pair(&s.env, &va, &nb));
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    let slot = s.mint.request_pairs(&depositor, &random_event_id(&s.env), &1000, &pairs);
    s.mint.confirm_link(&depositor, &slot, &0, &partial_key(&s.env, 90));
    s.mint.confirm_link(&va, &slot, &1, &partial_key(&s.env, 1));

    assert_eq!(s.mint.cancel_print(&depositor, &slot), 990);
    let burned = burn_events(&s);
    assert_eq!(s.mint.accrued_fees(&va), 0);
    assert_eq!(s.mint.accrued_fees(&nb), 0, "nb did not confirm");
    assert_eq!(s.pay_token.balance(&s.mint.address), 0, "nothing left in escrow");
    assert_eq!(s.pay_token.balance(&depositor), 9990);
    assert_eq!(burned, std::vec![(va.clone(), 10)]);
}

/// The same pair, but the paid member confirms: settlement reads the
/// confirmer's own bit, so the paid node is paid.
#[test]
fn settlement_reads_the_confirmers_terms_not_its_partners() {
    let s = setup_with_config(10, 3, 5, 5);
    let depositor = Address::generate(&s.env);
    let va = Address::generate(&s.env);
    let nb = Address::generate(&s.env);
    mint_tokens(&s.pay_token, &depositor, 10000);
    register_node(&s.env, &s.roster_addr, &va);
    register_node(&s.env, &s.roster_addr, &nb);
    add_volunteer(&s.env, &s.roster_addr, &va);

    let mut pairs = Vec::new(&s.env);
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    pairs.push_back(make_pair(&s.env, &va, &nb));
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    let slot = s.mint.request_pairs(&depositor, &random_event_id(&s.env), &1000, &pairs);
    s.mint.confirm_link(&depositor, &slot, &0, &partial_key(&s.env, 90));
    s.mint.confirm_link(&nb, &slot, &1, &partial_key(&s.env, 1));

    s.env.ledger().set_sequence_number(s.env.ledger().sequence() + 6);
    assert_eq!(s.mint.clear_expired_slot(&slot), 990);
    assert!(burn_events(&s).is_empty(), "nothing a volunteer did was settled");
    assert_eq!(s.mint.accrued_fees(&nb), 10);
    assert_eq!(s.mint.accrued_fees(&va), 0);
}

/// Terms are taken at `request_print`. A node that volunteers after it
/// was named in a print is still paid for that print -- the slot keeps
/// the terms the depositor saw, and redemption never asks the roster.
#[test]
fn terms_are_fixed_when_the_print_is_requested() {
    let s = setup();
    let depositor = Address::generate(&s.env);
    let na = Address::generate(&s.env);
    let nb = Address::generate(&s.env);
    mint_tokens(&s.pay_token, &depositor, 10000);
    register_node(&s.env, &s.roster_addr, &na);
    register_node(&s.env, &s.roster_addr, &nb);

    let mut pairs = Vec::new(&s.env);
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    pairs.push_back(make_pair(&s.env, &na, &nb));
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    let slot = s.mint.request_pairs(&depositor, &random_event_id(&s.env), &1000, &pairs);
    add_volunteer(&s.env, &s.roster_addr, &na);
    s.mint.confirm_link(&depositor, &slot, &0, &partial_key(&s.env, 90));
    s.mint.confirm_link(&na, &slot, &1, &partial_key(&s.env, 1));

    assert_eq!(s.mint.cancel_print(&depositor, &slot), 990);
    assert!(burn_events(&s).is_empty());
    assert_eq!(s.mint.accrued_fees(&na), 10, "named while paid, paid for this print");

    // The next print sees the new terms.
    let slot2 = s.mint.request_pairs(&depositor, &random_event_id(&s.env), &1000, &pairs);
    s.mint.confirm_link(&depositor, &slot2, &0, &partial_key(&s.env, 92));
    s.mint.confirm_link(&na, &slot2, &1, &partial_key(&s.env, 3));
    assert_eq!(s.mint.cancel_print(&depositor, &slot2), 990);
    assert_eq!(burn_events(&s), std::vec![(na.clone(), 10)]);
    assert_eq!(s.mint.accrued_fees(&na), 10, "nothing more credited");
}

/// Claiming with no balance fails with NothingToClaim.
#[test]
#[should_panic(expected = "Error(Contract, #45)")]
fn claim_fees_nothing_to_claim() {
    let s = setup();
    let stranger = Address::generate(&s.env);
    s.mint.claim_fees(&stranger);
}

// ── No Admin Functions ──

#[test]
fn test_no_admin_functions() {
    // This is a design test: the contract has NO admin functions.
    // All config is immutable. Verify by checking config values can't change.
    let s = setup_with_config(10, 3, 5, 1000);

    assert_eq!(s.mint.node_fee(), 10);
    assert_eq!(s.mint.min_pairs(), 3);
    assert_eq!(s.mint.max_pairs(), 5);
    assert_eq!(s.mint.max_print_ledgers(), 1000);
    // There is literally no function to change these. This test documents that fact.
}

// ── Spend mode (nullification, Realization A) ──

const T_SPEND_OWNER_COMMIT: &[u8] = b"kntr_v1:spend:owner";
const T_SPEND_AUTH: &[u8] = b"kntr_v1:spend:auth";
const T_SPEND_REDEEM: &[u8] = b"kntr_v1:spend:redeem";

/// The note's claim key. In production this is generated per note and its
/// secret half rides in the container; one fixed key is enough for tests.
fn claim_sk() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[0xC1; 32])
}
fn claim_pk(env: &Env) -> BytesN<32> {
    BytesN::from_array(env, &claim_sk().verifying_key().to_bytes())
}
/// A Path B claim proof, which binds the recipient and the contract.
fn sig_claim(
    env: &Env, slot: u32, ek: &BytesN<32>, contract: &Address, recipient: &Address,
) -> BytesN<64> {
    use ed25519_dalek::Signer;
    use sha2::{Digest, Sha256};
    use soroban_sdk::xdr::ToXdr;
    let xdr = |a: &Address| {
        let x = a.clone().to_xdr(env);
        let mut buf = std::vec![0u8; x.len() as usize];
        x.copy_into_slice(&mut buf);
        buf
    };
    let mut m: std::vec::Vec<u8> = std::vec::Vec::new();
    m.extend_from_slice(b"kntr_v1:redeem:claim");
    m.extend_from_slice(&xdr(contract));
    m.extend_from_slice(&slot.to_be_bytes());
    m.extend_from_slice(&ek.to_array());
    m.extend_from_slice(&xdr(recipient));
    let digest: [u8; 32] = Sha256::digest(&m).into();
    BytesN::from_array(env, &claim_sk().sign(&digest).to_bytes())
}

fn osk(seed: u8) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
}
fn opk(env: &Env, sk: &ed25519_dalek::SigningKey) -> BytesN<32> {
    BytesN::from_array(env, &sk.verifying_key().to_bytes())
}
fn ocommit(env: &Env, sk: &ed25519_dalek::SigningKey) -> BytesN<32> {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(T_SPEND_OWNER_COMMIT);
    h.update(&sk.verifying_key().to_bytes());
    BytesN::from_array(env, &h.finalize().into())
}
fn sig_spend(
    env: &Env, sk: &ed25519_dalek::SigningKey, slot: u32,
    ek: &BytesN<32>, cur: &BytesN<32>, new: &BytesN<32>,
    contract: &Address, nonce: u32,
) -> BytesN<64> {
    use ed25519_dalek::Signer;
    use sha2::{Digest, Sha256};
    use soroban_sdk::xdr::ToXdr;
    let x = contract.clone().to_xdr(env);
    let mut cx = std::vec![0u8; x.len() as usize];
    x.copy_into_slice(&mut cx);
    let mut m: std::vec::Vec<u8> = std::vec::Vec::new();
    m.extend_from_slice(T_SPEND_AUTH);
    m.extend_from_slice(&cx);
    m.extend_from_slice(&slot.to_be_bytes());
    m.extend_from_slice(&ek.to_array());
    m.extend_from_slice(&cur.to_array());
    m.extend_from_slice(&new.to_array());
    m.extend_from_slice(&nonce.to_be_bytes());
    // Owner authorizations sign the 32-byte digest, not the message (the card's
    // signHash takes 32 bytes). See kenter_crypto::spend.
    let digest: [u8; 32] = Sha256::digest(&m).into();
    BytesN::from_array(env, &sk.sign(&digest).to_bytes())
}
/// The owner's redemption signature, which binds the **recipient**.
///
/// Without the recipient the signature would say "redeem this note" rather
/// than "pay this note's escrow to this address", and anyone holding a valid
/// proof could redirect the payout.
fn sig_redeem_owner(
    env: &Env, sk: &ed25519_dalek::SigningKey, slot: u32,
    ek: &BytesN<32>, commit: &BytesN<32>,
    recipient: &Address, contract: &Address, nonce: u32,
) -> BytesN<64> {
    use ed25519_dalek::Signer;
    use sha2::{Digest, Sha256};
    use soroban_sdk::xdr::ToXdr;
    let cxdr = contract.clone().to_xdr(env);
    let mut cbuf = std::vec![0u8; cxdr.len() as usize];
    cxdr.copy_into_slice(&mut cbuf);
    let mut m: std::vec::Vec<u8> = std::vec::Vec::new();
    m.extend_from_slice(T_SPEND_REDEEM);
    m.extend_from_slice(&cbuf);
    m.extend_from_slice(&slot.to_be_bytes());
    m.extend_from_slice(&ek.to_array());
    m.extend_from_slice(&commit.to_array());
    m.extend_from_slice(&nonce.to_be_bytes());
    let x = recipient.clone().to_xdr(env);
    let mut buf = std::vec![0u8; x.len() as usize];
    x.copy_into_slice(&mut buf);
    m.extend_from_slice(&buf);
    let digest: [u8; 32] = Sha256::digest(&m).into();
    BytesN::from_array(env, &sk.sign(&digest).to_bytes())
}
/// The Path A proof, which binds the **recipient** and the **contract**.
///
/// Covering only the tag and the key would make it a standalone
/// credential: anyone who saw one could resubmit it naming themselves. A
/// transaction that fails on-chain keeps its arguments forever while the
/// note stays Active, so a failed redemption would give the note away.
fn sig_ephemeral(
    env: &Env,
    slot: u32,
    ek_sk: &ed25519_dalek::SigningKey,
    ek: &BytesN<32>,
    contract: &Address,
    recipient: &Address,
) -> BytesN<64> {
    use ed25519_dalek::Signer;
    use sha2::{Digest, Sha256};
    use soroban_sdk::xdr::ToXdr;
    let xdr = |a: &Address| {
        let x = a.clone().to_xdr(env);
        let mut buf = std::vec![0u8; x.len() as usize];
        x.copy_into_slice(&mut buf);
        buf
    };
    let mut m: std::vec::Vec<u8> = std::vec::Vec::new();
    m.extend_from_slice(b"kntr_v1:redeem:key");
    m.extend_from_slice(&xdr(contract));
    m.extend_from_slice(&slot.to_be_bytes());
    m.extend_from_slice(&ek.to_array());
    m.extend_from_slice(&xdr(recipient));
    let digest: [u8; 32] = Sha256::digest(&m).into();
    BytesN::from_array(env, &ek_sk.sign(&digest).to_bytes())
}

/// Register a token with the given mode, owned (spend mode) by `owner` if given.
/// Returns (setup, ephemeral key, ephemeral signing key, holder). node_fee=10,
/// amount=1000, 3 pairs → 6 participants → payout after fees = 980.
fn make_token<'a>(
    mode: TokenMode,
    owner: Option<&ed25519_dalek::SigningKey>,
) -> (TestSetup<'a>, u32, BytesN<32>, ed25519_dalek::SigningKey, Address) {
    let s = setup();
    let depositor = Address::generate(&s.env);
    let na = Address::generate(&s.env);
    let nb = Address::generate(&s.env);
    mint_tokens(&s.pay_token, &depositor, 10000);
    register_node(&s.env, &s.roster_addr, &na);
    register_node(&s.env, &s.roster_addr, &nb);
    let mut pairs = Vec::new(&s.env);
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    pairs.push_back(make_pair(&s.env, &na, &nb));
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    let slot_id = s.mint.request_pairs(&depositor, &random_event_id(&s.env), &1000, &pairs);
    s.mint.confirm_link(&depositor, &slot_id, &0, &partial_key(&s.env, 90));
    s.mint.confirm_link(&na, &slot_id, &1, &partial_key(&s.env, 1));
    s.mint.confirm_link(&depositor, &slot_id, &2, &partial_key(&s.env, 91));
    let ek_sk = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
    let ek = BytesN::from_array(&s.env, &ek_sk.verifying_key().to_bytes());
    let commit = match owner {
        Some(sk) => ocommit(&s.env, sk),
        None => BytesN::from_array(&s.env, &[0u8; 32]),
    };
    s.mint.register_token(&depositor, &slot_id, &ek, &partial_key(&s.env, 200), &mode, &commit, &claim_pk(&s.env));
    // A fresh payout recipient (not the depositor) so balance assertions are clean.
    let holder = Address::generate(&s.env);
    (s, slot_id, ek, ek_sk, holder)
}

#[test]
fn spend_moves_owner_pointer() {
    let alice = osk(1);
    let bob = osk(2);
    let (s, slot, ek, _ek, holder) = make_token(TokenMode::Spend, Some(&alice));
    let alice_commit = ocommit(&s.env, &alice);
    let bob_commit = ocommit(&s.env, &bob);
    let sig = sig_spend(&s.env, &alice, slot, &ek, &alice_commit, &bob_commit, &s.mint.address, 0);
    s.mint.spend(&holder, &slot, &opk(&s.env, &alice), &bob_commit, &sig);
    let token = s.mint.get_token(&slot).unwrap();
    assert_eq!(token.owner_commitment, bob_commit);
    assert_eq!(token.mode, TokenMode::Spend);
}

#[test]
#[should_panic(expected = "Error(Contract, #48)")] // OwnerCommitmentMismatch
fn spend_rejects_non_owner() {
    let alice = osk(1);
    let mallory = osk(9);
    let (s, slot, ek, _ek, holder) = make_token(TokenMode::Spend, Some(&alice));
    let alice_commit = ocommit(&s.env, &alice);
    let bob_commit = ocommit(&s.env, &osk(2));
    // Mallory signs with her own key; her pubkey doesn't open Alice's commitment.
    let sig = sig_spend(&s.env, &mallory, slot, &ek, &alice_commit, &bob_commit, &s.mint.address, 0);
    s.mint.spend(&holder, &slot, &opk(&s.env, &mallory), &bob_commit, &sig);
}

#[test]
#[should_panic(expected = "Error(Contract, #46)")] // NotSpendMode
fn spend_rejects_pure_bearer() {
    let (s, slot, ek, _ek, holder) = make_token(TokenMode::PureBearer, None);
    let alice = osk(1);
    let zero = BytesN::from_array(&s.env, &[0u8; 32]);
    let bob_commit = ocommit(&s.env, &osk(2));
    let sig = sig_spend(&s.env, &alice, slot, &ek, &zero, &bob_commit, &s.mint.address, 0);
    s.mint.spend(&holder, &slot, &opk(&s.env, &alice), &bob_commit, &sig);
}

#[test]
#[should_panic(expected = "Error(Contract, #48)")] // old owner can't spend again
fn spend_twice_by_old_owner_fails() {
    let alice = osk(1);
    let bob = osk(2);
    let carol = osk(3);
    let (s, slot, ek, _ek, holder) = make_token(TokenMode::Spend, Some(&alice));
    let alice_commit = ocommit(&s.env, &alice);
    let bob_commit = ocommit(&s.env, &bob);
    let carol_commit = ocommit(&s.env, &carol);
    // Alice → Bob (ok).
    let sig1 = sig_spend(&s.env, &alice, slot, &ek, &alice_commit, &bob_commit, &s.mint.address, 0);
    s.mint.spend(&holder, &slot, &opk(&s.env, &alice), &bob_commit, &sig1);
    // Alice tries to re-spend the token she paid away; live commitment is Bob's.
    let sig2 = sig_spend(&s.env, &alice, slot, &ek, &alice_commit, &carol_commit, &s.mint.address, 0);
    s.mint.spend(&holder, &slot, &opk(&s.env, &alice), &carol_commit, &sig2);
}

#[test]
#[should_panic(expected = "Error(Contract, #47)")] // SpendModeRequiresOwner
fn plain_redeem_rejects_spend_mode() {
    let alice = osk(1);
    let (s, slot, ek, ek_sk, holder) = make_token(TokenMode::Spend, Some(&alice));
    let eph = sig_ephemeral(&s.env, slot, &ek_sk, &ek, &s.mint.address, &holder);
    s.mint.redeem_by_key(
        &holder,
        &holder,
        &slot,
        &eph,
        &sig_claim(&s.env, slot, &ek, &s.mint.address, &holder),
    );
}

#[test]
fn owned_redeem_succeeds() {
    let alice = osk(1);
    let (s, slot, ek, ek_sk, holder) = make_token(TokenMode::Spend, Some(&alice));
    let alice_commit = ocommit(&s.env, &alice);
    let eph = sig_ephemeral(&s.env, slot, &ek_sk, &ek, &s.mint.address, &holder);
    let owner_sig = sig_redeem_owner(&s.env, &alice, slot, &ek, &alice_commit, &holder, &s.mint.address, 0);
    let payout = s.mint.redeem_by_key_owned(
        &holder,
        &holder,
        &slot, &eph, &opk(&s.env, &alice), &owner_sig);
    assert_eq!(payout, 980);
    assert_eq!(s.pay_token.balance(&holder), 980);
}

#[test]
#[should_panic(expected = "Error(Contract, #46)")] // NotSpendMode
fn owned_redeem_rejects_pure_bearer() {
    let (s, slot, ek, ek_sk, holder) = make_token(TokenMode::PureBearer, None);
    let alice = osk(1);
    let commit = ocommit(&s.env, &alice);
    let eph = sig_ephemeral(&s.env, slot, &ek_sk, &ek, &s.mint.address, &holder);
    let owner_sig = sig_redeem_owner(&s.env, &alice, slot, &ek, &commit, &holder, &s.mint.address, 0);
    s.mint.redeem_by_key_owned(
        &holder,
        &holder,
        &slot, &eph, &opk(&s.env, &alice), &owner_sig);
}

/// End-to-end: Alice pays Bob (spend), Bob (the new owner) redeems, and Alice —
/// who still holds a copy of the bytes — can no longer redeem.
#[test]
fn full_flow_new_owner_redeems() {
    let alice = osk(1);
    let bob = osk(2);
    let (s, slot, ek, ek_sk, holder) = make_token(TokenMode::Spend, Some(&alice));
    let alice_commit = ocommit(&s.env, &alice);
    let bob_commit = ocommit(&s.env, &bob);
    let sig = sig_spend(&s.env, &alice, slot, &ek, &alice_commit, &bob_commit, &s.mint.address, 0);
    s.mint.spend(&holder, &slot, &opk(&s.env, &alice), &bob_commit, &sig);
    let eph = sig_ephemeral(&s.env, slot, &ek_sk, &ek, &s.mint.address, &holder);
    let bob_sig = sig_redeem_owner(&s.env, &bob, slot, &ek, &bob_commit, &holder, &s.mint.address, 1);
    let payout = s.mint.redeem_by_key_owned(
        &holder,
        &holder,
        &slot, &eph, &opk(&s.env, &bob), &bob_sig);
    assert_eq!(payout, 980);
}

#[test]
#[should_panic(expected = "Error(Contract, #48)")] // payer no longer owns it
fn payer_cannot_redeem_after_paying() {
    let alice = osk(1);
    let bob = osk(2);
    let (s, slot, ek, ek_sk, holder) = make_token(TokenMode::Spend, Some(&alice));
    let alice_commit = ocommit(&s.env, &alice);
    let bob_commit = ocommit(&s.env, &bob);
    let sig = sig_spend(&s.env, &alice, slot, &ek, &alice_commit, &bob_commit, &s.mint.address, 0);
    s.mint.spend(&holder, &slot, &opk(&s.env, &alice), &bob_commit, &sig);
    // Alice tries to redeem with her own owner key — no longer opens the live commitment.
    let eph = sig_ephemeral(&s.env, slot, &ek_sk, &ek, &s.mint.address, &holder);
    let alice_sig = sig_redeem_owner(&s.env, &alice, slot, &ek, &alice_commit, &holder, &s.mint.address, 1);
    s.mint.redeem_by_key_owned(
        &holder,
        &holder,
        &slot, &eph, &opk(&s.env, &alice), &alice_sig);
}

// ── Owner authorizations sign a 32-byte digest ──
//
// Owner signatures cover M = SHA-256(message), because the Keycard applet's
// signHash takes 32 bytes and the spend/redeem messages are longer (158 and
// 172 bytes, with the contract address and spend nonce). The contract and
// the test helpers share the format, so without these two tests a change to
// it would be invisible to the suite — they pin a signature over the raw
// message as rejected.

/// A spend signature over the raw message (not its digest) must fail.
#[test]
#[should_panic(expected = "Error(Crypto, InvalidInput)")] // ed25519_verify trap
fn spend_rejects_raw_message_signature() {
    use ed25519_dalek::Signer;
    let alice = osk(1);
    let (s, slot, ek, _ek, holder) = make_token(TokenMode::Spend, Some(&alice));
    let alice_commit = ocommit(&s.env, &alice);
    let bob_commit = ocommit(&s.env, &osk(2));

    let mut m: std::vec::Vec<u8> = std::vec::Vec::new();
    m.extend_from_slice(T_SPEND_AUTH);
    m.extend_from_slice(&ek.to_array());
    m.extend_from_slice(&alice_commit.to_array());
    m.extend_from_slice(&bob_commit.to_array());
    let raw_sig = BytesN::from_array(&s.env, &alice.sign(&m).to_bytes());

    // Alice's key opens the commitment, so this gets past the ownership check and
    // fails on the signature itself — which is exactly the property under test.
    s.mint.spend(&holder, &slot, &opk(&s.env, &alice), &bob_commit, &raw_sig);
}

/// A redeem owner-proof over the raw message (not its digest) must fail.
#[test]
#[should_panic(expected = "Error(Crypto, InvalidInput)")] // ed25519_verify trap
fn redeem_owner_rejects_raw_message_signature() {
    use ed25519_dalek::Signer;
    let alice = osk(1);
    let (s, slot, ek, ek_sk, holder) = make_token(TokenMode::Spend, Some(&alice));
    let alice_commit = ocommit(&s.env, &alice);

    let mut m: std::vec::Vec<u8> = std::vec::Vec::new();
    m.extend_from_slice(T_SPEND_REDEEM);
    m.extend_from_slice(&ek.to_array());
    m.extend_from_slice(&alice_commit.to_array());
    let raw_sig = BytesN::from_array(&s.env, &alice.sign(&m).to_bytes());

    let eph = sig_ephemeral(&s.env, slot, &ek_sk, &ek, &s.mint.address, &holder);
    s.mint.redeem_by_key_owned(
        &holder,
        &holder,
        &slot, &eph, &opk(&s.env, &alice), &raw_sig);
}

// ── Path B cost scaling (measurement + multi-link coverage) ──
//
// These cover Path B with n > 1 links *and* measure what `redeem_by_chain` costs as the pair count
// grows, so the practical ceiling on pairs-per-token is a number rather than a
// guess. The cost is dominated by 2n `ed25519_verify` host calls plus the
// 34 + 290n bytes of `chain_data` carried in the transaction.
//
// Run: cargo test --offline bench_pathb_scaling -- --nocapture --include-ignored

/// The budget these tests hold themselves to. **Not the network's.**
///
/// The network's per-transaction ceiling is `tx_max_instructions` in
/// the `contract_compute_v0` config entry, **400,000,000** on both
/// testnet and mainnet at the time of writing. This 100M is the SDK test
/// budget's default, not the network limit; percentages this suite
/// prints are of 100M, four times what they are of the network's.
///
/// Kept at 100M deliberately, as a tripwire rather than a ceiling. A
/// redemption that needs more than a quarter of what the network
/// allows is worth looking at, and an assertion at the real limit
/// would not fire until the note was already unredeemable. What it
/// cannot do is tell you a redemption fits: see
/// `pathb_owned_at_the_ceiling_fits_the_budget_wasm` for why no figure
/// from this host can.
const TEST_BUDGET_INSTRUCTIONS: i64 = 100_000_000;

// The native harness (`env.register(KenterMint, ..)`) runs the contract as plain
// Rust, so it does not meter Wasm VM instantiation or Wasm-level execution — it
// undercounts. Building the real `.wasm` and registering *that* gives the number
// the network would actually charge. Gated behind a feature because it needs the
// wasm artifact on disk:
//
//   cargo build --target wasm32v1-none --release
//   cargo test --features wasm-bench bench_pathb_wasm -- --include-ignored --nocapture
//
// `--features wasm-bench` is not optional and its absence is quiet: the
// whole module is behind the cfg, so without it the name filter matches
// no test and cargo reports a clean run of zero tests.
#[cfg(feature = "wasm-bench")]
const MINT_WASM: &[u8] = include_bytes!("../target/wasm32v1-none/release/kenter_mint.wasm");

#[cfg(feature = "wasm-bench")]
fn setup_wasm<'a>(
    node_fee: u32,
    min_pairs: u32,
    max_pairs: u32,
    max_print_ledgers: u32,
) -> TestSetup<'a> {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let (pay_token, pay_token_addr) = create_token(&env, &admin);
    let roster_addr = env.register(roster_contract::MockRoster, ());
    let mint_addr = env.register(
        MINT_WASM,
        (
            node_fee,
            min_pairs,
            max_pairs,
            &pay_token_addr,
            &roster_addr,
            max_print_ledgers,
            test_selection(&env),
        ),
    );
    let mint = KenterMintClient::new(&env, &mint_addr);

    TestSetup {
        env,
        mint,
        pay_token,
        pay_token_addr,
        roster_addr,
    }
}

fn setup_for<'a>(
    use_wasm: bool,
    node_fee: u32,
    min_pairs: u32,
    max_pairs: u32,
    max_print_ledgers: u32,
) -> TestSetup<'a> {
    #[cfg(feature = "wasm-bench")]
    if use_wasm {
        return setup_wasm(node_fee, min_pairs, max_pairs, max_print_ledgers);
    }
    let _ = use_wasm;
    setup_with_config(node_fee, min_pairs, max_pairs, max_print_ledgers)
}

struct PathBCost {
    chain_bytes: usize,
    instructions: i64,
    mem_bytes: i64,
    fee_total: i64,
    payout: i128,
}

/// Drive a full print → register → `redeem_by_chain` cycle with `num_pairs`
/// pairs and report what the redemption cost.
fn measure_pathb(num_pairs: u32) -> PathBCost {
    measure_pathb_with(num_pairs, false)
}

fn measure_pathb_with(num_pairs: u32, use_wasm: bool) -> PathBCost {
    measure_pathb_mode(num_pairs, use_wasm, false)
}

/// Path B at `num_pairs`, optionally through the spend-mode entry point.
///
/// `redeem_by_chain_owned` does everything `redeem_by_chain` does and
/// then opens the owner commitment and verifies a second signature. It
/// is the dearest redemption there is, and the one that can strand a
/// note, so the budget tripwire is held against it.
fn measure_pathb_mode(num_pairs: u32, use_wasm: bool, owned: bool) -> PathBCost {
    // MAX_REDEEMABLE_PAIRS, not an arbitrary 64: the constructor
    // refuses anything higher, so the measurement cannot walk past the
    // cap. It does not need to -- the cost is linear in pairs, so a fit
    // over 2..=12 still predicts where Path B stops fitting the budget.
    // The network-measured slope puts that near 52 pairs, far above the
    // ceiling the card and paper set -- so the fit does not bound
    // anything a deployment can reach, and it is kept as a regression
    // tracker.
    let s = setup_for(use_wasm, 10, 3, crate::MAX_REDEEMABLE_PAIRS, 1000);
    let depositor = Address::generate(&s.env);
    let holder = Address::generate(&s.env);

    let amount: i128 = 10_000_000;
    mint_tokens(&s.pay_token, &depositor, amount * 2);

    // Every pair here is a real node pair, including the two on the
    // ends. The end pairs are *exempt* from the distinctness and roster
    // checks, not required to be degenerate, so a benchmark that wants
    // `num_pairs` genuine links still gets them.
    let mut pairs = Vec::new(&s.env);
    let mut first_of_pair: std::vec::Vec<Address> = std::vec::Vec::new();
    for _ in 0..num_pairs {
        let na = Address::generate(&s.env);
        let nb = Address::generate(&s.env);
        register_node(&s.env, &s.roster_addr, &na);
        register_node(&s.env, &s.roster_addr, &nb);
        pairs.push_back(make_pair(&s.env, &na, &nb));
        first_of_pair.push(na);
    }

    let event_id = random_event_id(&s.env);
    let slot_id = s.mint.request_pairs(&depositor, &event_id, &amount, &pairs);
    // Positions follow score, so the chain's order is read off the slot.
    let order = chain_order(&s, slot_id);
    let _ = &first_of_pair;
    for i in 0..num_pairs {
        s.mint.confirm_link(
            &order[i as usize].node_a,
            &slot_id,
            &i,
            &partial_key(&s.env, (i + 1) as u8),
        );
    }

    let chain = build_chain(&event_id.to_array(), num_pairs as u16, 0x33);
    let ek = random_key(&s.env);
    let owner = osk(201);
    let commit = if owned {
        ocommit(&s.env, &owner)
    } else {
        BytesN::from_array(&s.env, &[0u8; 32])
    };
    s.mint.register_token(
        &depositor,
        &slot_id,
        &ek,
        &sha256_of(&s.env, &chain),
        &if owned { TokenMode::Spend } else { TokenMode::PureBearer },
        &commit,
        &claim_pk(&s.env),
    );

    let chain_data = Bytes::from_slice(&s.env, &chain);

    // Lift the default limits so an over-budget n still yields a number instead
    // of aborting; we compare against TEST_BUDGET_INSTRUCTIONS ourselves.
    let mut budget = s.env.cost_estimate().budget();
    budget.reset_unlimited();

    let payout = if owned {
        let os = sig_redeem_owner(
            &s.env, &owner, slot_id, &ek, &commit, &holder, &s.mint.address, 0,
        );
        s.mint.redeem_by_chain_owned(
            &holder,
            &holder,
            &slot_id,
            &chain_data,
            &opk(&s.env, &owner),
            &os,
        )
    } else {
        s.mint.redeem_by_chain(
            &holder,
            &holder,
            &slot_id,
            &chain_data,
            &sig_claim(&s.env, slot_id, &ek, &s.mint.address, &holder),
        )
    };

    let r = s.env.cost_estimate().resources();
    let f = s.env.cost_estimate().fee();

    PathBCost {
        chain_bytes: chain.len(),
        instructions: r.instructions,
        mem_bytes: r.mem_bytes,
        fee_total: f.total,
        payout,
    }
}

/// Multi-link Path B redeems correctly for n = 3..=10.
#[test]
fn pathb_multi_link_chains_redeem() {
    for n in 3..=10u32 {
        let c = measure_pathb(n);
        // Interior pairs only: the depositor's opening and closing
        // pairs do no node work and are not credited.
        let expected = 10_000_000i128 - (10i128 * 2 * (n as i128 - 2));
        assert_eq!(c.payout, expected, "payout wrong at n={n}");
        assert_eq!(c.chain_bytes, 34 + 290 * n as usize, "chain size wrong at n={n}");
    }
}

#[test]
#[ignore = "measurement, not an assertion — run with --include-ignored --nocapture"]
fn bench_pathb_scaling() {
    std::println!(
        "\n{:>5}  {:>12}  {:>14}  {:>10}  {:>12}  {:>7}",
        "pairs", "chain_bytes", "instructions", "% of tx", "mem_bytes", "fee"
    );
    std::println!("{}", "-".repeat(72));
    // The mint takes 3..=MAX_REDEEMABLE_PAIRS; outside it there is no print to measure.
    for n in [3u32, 4, 5, 8, 10, 12] {
        let c = measure_pathb(n);
        let pct = (c.instructions as f64 / TEST_BUDGET_INSTRUCTIONS as f64) * 100.0;
        std::println!(
            "{:>5}  {:>12}  {:>14}  {:>9.1}%  {:>12}  {:>7}",
            n, c.chain_bytes, c.instructions, pct, c.mem_bytes, c.fee_total
        );
    }
    std::println!();
}

/// Same flow, but redeemed via Path A (`redeem_by_key`) — one signature instead
/// of the whole chain. The delta against `measure_pathb` is the price of
/// node-free redemption. Both paths still walk the participant list to accrue
/// node fees, so that O(n) term is common to both and cancels out.
fn measure_patha(num_pairs: u32) -> PathBCost {
    measure_patha_with(num_pairs, false)
}

fn measure_patha_with(num_pairs: u32, use_wasm: bool) -> PathBCost {
    use ed25519_dalek::SigningKey;

    // MAX_REDEEMABLE_PAIRS, not an arbitrary 64: the constructor
    // refuses anything higher, so the measurement cannot walk past the
    // cap. It does not need to -- the cost is linear in pairs, so a fit
    // over 2..=12 still predicts where Path B stops fitting the budget.
    // The network-measured slope puts that near 52 pairs, far above the
    // ceiling the card and paper set -- so the fit does not bound
    // anything a deployment can reach, and it is kept as a regression
    // tracker.
    let s = setup_for(use_wasm, 10, 3, crate::MAX_REDEEMABLE_PAIRS, 1000);
    let depositor = Address::generate(&s.env);
    let holder = Address::generate(&s.env);

    let amount: i128 = 10_000_000;
    mint_tokens(&s.pay_token, &depositor, amount * 2);

    // Every pair here is a real node pair, including the two on the
    // ends. The end pairs are *exempt* from the distinctness and roster
    // checks, not required to be degenerate, so a benchmark that wants
    // `num_pairs` genuine links still gets them.
    let mut pairs = Vec::new(&s.env);
    let mut first_of_pair: std::vec::Vec<Address> = std::vec::Vec::new();
    for _ in 0..num_pairs {
        let na = Address::generate(&s.env);
        let nb = Address::generate(&s.env);
        register_node(&s.env, &s.roster_addr, &na);
        register_node(&s.env, &s.roster_addr, &nb);
        pairs.push_back(make_pair(&s.env, &na, &nb));
        first_of_pair.push(na);
    }

    let event_id = random_event_id(&s.env);
    let slot_id = s.mint.request_pairs(&depositor, &event_id, &amount, &pairs);
    // Positions follow score, so the chain's order is read off the slot.
    let order = chain_order(&s, slot_id);
    let _ = &first_of_pair;
    for i in 0..num_pairs {
        s.mint.confirm_link(
            &order[i as usize].node_a,
            &slot_id,
            &i,
            &partial_key(&s.env, (i + 1) as u8),
        );
    }

    // The ephemeral key is a real Ed25519 key here — Path A proves possession of
    // its secret rather than presenting the chain.
    let sk = SigningKey::from_bytes(&[7u8; 32]);
    let ek_arr = sk.verifying_key().to_bytes();
    let ek = BytesN::from_array(&s.env, &ek_arr);

    let chain = build_chain(&event_id.to_array(), num_pairs as u16, 0x33);
    s.mint.register_token(
        &depositor,
        &slot_id,
        &ek,
        &sha256_of(&s.env, &chain),
        &TokenMode::PureBearer,
        &BytesN::from_array(&s.env, &[0u8; 32]),
        &claim_pk(&s.env),
    );

    let sig_b = sig_ephemeral(&s.env, slot_id, &sk, &ek, &s.mint.address, &holder);

    let mut budget = s.env.cost_estimate().budget();
    budget.reset_unlimited();

    let payout = s
        .mint
        .redeem_by_key(
        &holder,
        &holder,
        &slot_id,
            &sig_b,
            &sig_claim(&s.env, slot_id, &ek, &s.mint.address, &holder),
        );

    let r = s.env.cost_estimate().resources();
    let f = s.env.cost_estimate().fee();

    PathBCost {
        chain_bytes: 0,
        instructions: r.instructions,
        mem_bytes: r.mem_bytes,
        fee_total: f.total,
        payout,
    }
}

#[test]
#[ignore = "measurement, not an assertion — run with --include-ignored --nocapture"]
fn bench_redeem_paths_compared() {
    std::println!(
        "\n{:>5}  {:>13}  {:>13}  {:>8}  {:>11}  {:>11}  {:>9}",
        "pairs", "A instr", "B instr", "B/A", "A fee", "B fee", "B-A fee"
    );
    std::println!("{}", "-".repeat(84));
    for n in [3u32, 5, 8, 10, 12] {
        let a = measure_patha(n);
        let b = measure_pathb(n);
        std::println!(
            "{:>5}  {:>13}  {:>13}  {:>7.1}x  {:>11}  {:>11}  {:>9}",
            n,
            a.instructions,
            b.instructions,
            b.instructions as f64 / a.instructions as f64,
            a.fee_total,
            b.fee_total,
            b.fee_total - a.fee_total
        );
    }
    std::println!();
}

/// The same scaling curve, measured against the real compiled Wasm so VM
/// instantiation and Wasm execution are included. This is the number to quote.
#[cfg(feature = "wasm-bench")]
#[test]
#[ignore = "measurement — needs `cargo build --target wasm32v1-none --release` first"]
fn bench_pathb_wasm() {
    // The budget is an assertion, not a printout.
    //
    // `MAX_REDEEMABLE_PAIRS = 12` is set by what a card and a paper
    // sheet can carry, not by this budget -- but the budget still has
    // to hold at the ceiling, and that is what this asserts.
    //
    // Held against `redeem_by_chain_owned`, the dearest path, not the
    // plain one. The owner proof itself is cheap -- about 55k
    // instructions, measured at 24 pairs while that was the ceiling,
    // well under a tenth of a point -- but
    // that is a measured relationship between two code paths and not a
    // law, and the owned path is the one that can strand a note.
    //
    // If this starts failing, read the note on
    // `pathb_owned_at_the_ceiling_fits_the_budget_wasm` first. The figure
    // scales with how many entries the test ledger holds, at about 42k
    // instructions each, so a setup that funds a few more addresses
    // moves it without the contract changing.
    //
    // And note what it does not prove: the network is dearer than this
    // harness, by 32% at 3 pairs, so green here is not "the network
    // fits". It is a regression tripwire on the contract. The figure
    // that binds comes from `kenter redeem --dry-run`.
    //
    // 85% leaves the cost model room to drift between protocol
    // versions, which is the point: the mint is immutable, so a
    // redemption that outgrows the per-transaction budget cannot be
    // fixed once the notes are issued, and such a note is redeemable
    // only through Path A and the node network -- the dependency Path
    // B exists to avoid.
    const BUDGET_CEILING_PCT: f64 = 85.0;
    let mut worst: (u32, f64) = (0, 0.0);

    std::println!(
        "
{:>5}  {:>12}  {:>13}  {:>13}  {:>9}  {:>11}  {:>11}  {:>9}",
        "pairs", "chain_bytes", "A instr", "B instr", "B % budget", "A fee", "B fee",
        "owned %bud"
    );
    std::println!("{}", "-".repeat(86));
    // Inside the constructor's limits: a value outside them panics with
    // InvalidPairCount and measures nothing. Keep every value in
    // 3..=MAX_REDEEMABLE_PAIRS.
    for n in [3u32, 5, 8, 10, 12] {
        let a = measure_patha_with(n, true);
        let b = measure_pathb_with(n, true);
        let o = measure_pathb_mode(n, true, true);
        let pct = (b.instructions as f64 / TEST_BUDGET_INSTRUCTIONS as f64) * 100.0;
        let opct = (o.instructions as f64 / TEST_BUDGET_INSTRUCTIONS as f64) * 100.0;
        std::println!(
            "{:>5}  {:>12}  {:>13}  {:>13}  {:>8.1}%  {:>11}  {:>11}  {:>8.1}%",
            n, b.chain_bytes, a.instructions, b.instructions, pct,
            a.fee_total, b.fee_total, opct
        );
        // The owned path is the dearest and the one that can strand a
        // note, so it is what the ceiling is held against.
        if opct > worst.1 {
            worst = (n, opct);
        }
    }
    std::println!();

    assert!(
        worst.1 < BUDGET_CEILING_PCT,
        "redeem_by_chain_owned is at {:.1}% of the CPU budget at {} pairs, over the {BUDGET_CEILING_PCT}% ceiling. Either the cost model moved or verification grew; lower MAX_REDEEMABLE_PAIRS before deploying, because a note already issued above the budget can never be redeemed by chain.",
        worst.1,
        worst.0
    );
}

// ── Redeem to an address ──────────────────────────────
//
// A bearer note pays whoever the holder names, not the holder. That is
// the point of the parameter: paying someone who does not run a Kenter
// client does not mean redeem-then-send, with the value sitting in the
// redeemer's own account in between.

/// A spend authorization is good for one transfer.
///
/// A digest of only `(ek, current_commitment, new_commitment)` -- no
/// nonce, no contract -- repeats whenever a note comes back to a
/// commitment it held before, and the static pay tag at owner index 0 is
/// a *reusable* address, so a note returning as change or a refund does
/// exactly that. Alice pays Bob, Bob pays Alice back to the same tag,
/// and anyone could then resubmit Alice's first signature and hand the
/// note to Bob again — who still holds the key behind it, because it is
/// derived from his seed.
///
/// The submitter needs no relationship to either party, which is what
/// makes it more than a dispute between two people.
#[test]
#[should_panic(expected = "Error(Crypto, InvalidInput)")]
fn a_spend_authorization_cannot_be_replayed_when_a_commitment_recurs() {
    let alice = osk(1);
    let bob = osk(2);
    let (s, slot, ek, _ek_sk, _holder) = make_token(TokenMode::Spend, Some(&alice));
    let alice_commit = ocommit(&s.env, &alice);
    let bob_commit = ocommit(&s.env, &bob);
    // Anyone may submit a spend; the signature is what authorises it.
    let caller = Address::generate(&s.env);

    // Alice pays Bob. This is the signature that must not be reusable.
    let alice_to_bob = sig_spend(
        &s.env, &alice, slot, &ek, &alice_commit, &bob_commit, &s.mint.address, 0,
    );
    s.mint.spend(&caller, &slot, &opk(&s.env, &alice), &bob_commit, &alice_to_bob);

    // Bob pays it back to the same tag, so the note is at alice_commit
    // again — the state Alice's signature was made in.
    let bob_to_alice = sig_spend(
        &s.env, &bob, slot, &ek, &bob_commit, &alice_commit, &s.mint.address, 1,
    );
    s.mint.spend(&caller, &slot, &opk(&s.env, &bob), &alice_commit, &bob_to_alice);
    assert_eq!(s.mint.get_token(&slot).unwrap().owner_commitment, alice_commit);

    // Anyone replays Alice's first signature. The commitments match the
    // live state; only the nonce has moved on.
    s.mint.spend(&caller, &slot, &opk(&s.env, &alice), &bob_commit, &alice_to_bob);
}

/// And a fresh authorization at the current nonce still works, so the
/// binding costs the honest path nothing.
#[test]
fn a_note_can_be_paid_back_and_forth_with_fresh_authorizations() {
    let alice = osk(1);
    let bob = osk(2);
    let (s, slot, ek, _ek_sk, _holder) = make_token(TokenMode::Spend, Some(&alice));
    let alice_commit = ocommit(&s.env, &alice);
    let bob_commit = ocommit(&s.env, &bob);
    let caller = Address::generate(&s.env);

    for (n, (sk, from, to)) in [
        (&alice, &alice_commit, &bob_commit),
        (&bob, &bob_commit, &alice_commit),
        (&alice, &alice_commit, &bob_commit),
    ]
    .iter()
    .enumerate()
    {
        let sig = sig_spend(&s.env, sk, slot, &ek, from, to, &s.mint.address, n as u32);
        s.mint.spend(&caller, &slot, &opk(&s.env, sk), to, &sig);
        assert_eq!(&s.mint.get_token(&slot).unwrap().owner_commitment, *to);
    }
    assert_eq!(s.mint.get_token(&slot).unwrap().spend_nonce, 3);
}

/// Redeem side of the same rule. The owner's redeem proof carries the
/// nonce too, so it does not outlive the ownership state it was made in.
///
/// Binding only the commitment would leave the same hole a nonce-free
/// spend digest has: a note that comes back to a commitment it held before makes an old
/// proof live again. Here Alice signs a redemption, pays the note away,
/// and it returns to her tag — her earlier proof must still be refused,
/// even though every field but the nonce matches the live record.
#[test]
#[should_panic(expected = "Error(Crypto, InvalidInput)")]
fn a_redeem_proof_cannot_be_replayed_when_a_commitment_recurs() {
    let alice = osk(1);
    let bob = osk(2);
    let (s, slot, ek, ek_sk, holder) = make_token(TokenMode::Spend, Some(&alice));
    let alice_commit = ocommit(&s.env, &alice);
    let bob_commit = ocommit(&s.env, &bob);

    // Signed while the note sat at Alice's tag, nonce 0, but never posted.
    let stale =
        sig_redeem_owner(&s.env, &alice, slot, &ek, &alice_commit, &holder, &s.mint.address, 0);

    // Alice pays Bob, Bob pays it back to the same tag. The live record now
    // reads alice_commit again, at nonce 2.
    let out = sig_spend(&s.env, &alice, slot, &ek, &alice_commit, &bob_commit, &s.mint.address, 0);
    s.mint.spend(&holder, &slot, &opk(&s.env, &alice), &bob_commit, &out);
    let back = sig_spend(&s.env, &bob, slot, &ek, &bob_commit, &alice_commit, &s.mint.address, 1);
    s.mint.spend(&holder, &slot, &opk(&s.env, &bob), &alice_commit, &back);
    assert_eq!(s.mint.get_token(&slot).unwrap().owner_commitment, alice_commit);
    assert_eq!(s.mint.get_token(&slot).unwrap().spend_nonce, 2);

    let eph = sig_ephemeral(&s.env, slot, &ek_sk, &ek, &s.mint.address, &holder);
    s.mint.redeem_by_key_owned(
        &holder,
        &holder,
        &slot, &eph, &opk(&s.env, &alice), &stale);
}

/// And a proof written at the current nonce still redeems, so the binding
/// costs the honest path nothing here either.
#[test]
fn a_returned_note_redeems_with_a_fresh_proof() {
    let alice = osk(1);
    let bob = osk(2);
    let (s, slot, ek, ek_sk, holder) = make_token(TokenMode::Spend, Some(&alice));
    let alice_commit = ocommit(&s.env, &alice);
    let bob_commit = ocommit(&s.env, &bob);

    let out = sig_spend(&s.env, &alice, slot, &ek, &alice_commit, &bob_commit, &s.mint.address, 0);
    s.mint.spend(&holder, &slot, &opk(&s.env, &alice), &bob_commit, &out);
    let back = sig_spend(&s.env, &bob, slot, &ek, &bob_commit, &alice_commit, &s.mint.address, 1);
    s.mint.spend(&holder, &slot, &opk(&s.env, &bob), &alice_commit, &back);

    let eph = sig_ephemeral(&s.env, slot, &ek_sk, &ek, &s.mint.address, &holder);
    let fresh =
        sig_redeem_owner(&s.env, &alice, slot, &ek, &alice_commit, &holder, &s.mint.address, 2);
    let payout =
        s.mint.redeem_by_key_owned(
        &holder,
        &holder,
        &slot, &eph, &opk(&s.env, &alice), &fresh);
    assert_eq!(payout, 980);
}

/// Path B: publishing the chain is not the same as
/// handing over the note.
///
/// Path B's chain is a preimage, so every attempt publishes it — and an
/// attempt that fails on-chain publishes it while leaving the note Active.
/// An observer could then redeem at leisure: no race, no mempool, just
/// reading a failed transaction off the ledger. A recipient without a
/// trustline is an everyday way to produce one.
///
/// Commit-reveal does not fix this. Once the chain is public and the note
/// is still live, an attacker commits their own and reveals a ledger
/// later. What fixes it is changing *what the proof is*: a signature from
/// the note's claim key, whose secret never enters a transaction.
///
/// Still bearer — the claim secret rides in the note container, so copying
/// the file copies the right to redeem.
#[test]
#[should_panic(expected = "Error(Crypto, InvalidInput)")]
fn a_published_chain_cannot_be_redeemed_by_an_observer() {
    let s = setup();
    let depositor = Address::generate(&s.env);
    let na = Address::generate(&s.env);
    let nb = Address::generate(&s.env);
    let payee = Address::generate(&s.env);
    let thief = Address::generate(&s.env);

    mint_tokens(&s.pay_token, &depositor, 10000);
    register_node(&s.env, &s.roster_addr, &na);
    register_node(&s.env, &s.roster_addr, &nb);
    let mut pairs = Vec::new(&s.env);
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    pairs.push_back(make_pair(&s.env, &na, &nb));
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    let event_id = random_event_id(&s.env);
    let slot_id = s.mint.request_pairs(&depositor, &event_id, &1000, &pairs);
    s.mint.confirm_link(&depositor, &slot_id, &0, &partial_key(&s.env, 90));
    s.mint.confirm_link(&na, &slot_id, &1, &partial_key(&s.env, 1));
    s.mint.confirm_link(&depositor, &slot_id, &2, &partial_key(&s.env, 91));

    let chain = build_chain(&event_id.to_array(), 3, 0x33);
    let ek = random_key(&s.env);
    s.mint.register_token(
        &depositor, &slot_id, &ek, &sha256_of(&s.env, &chain),
        &TokenMode::PureBearer, &BytesN::from_array(&s.env, &[0u8; 32]),
        &claim_pk(&s.env),
    );

    // Exactly what a failed transaction leaves on the ledger: the chain,
    // and a claim proof naming the intended payee.
    let published_chain = Bytes::from_slice(&s.env, &chain);
    let published_proof = sig_claim(&s.env, slot_id, &ek, &s.mint.address, &payee);

    // The observer replays both, naming themselves. The proof does not
    // verify, because the recipient is inside it.
    s.mint.redeem_by_chain(
        &thief,
        &thief,
        &slot_id, &published_chain, &published_proof);
}

/// A Path A proof names its recipient, so seeing one is not the same as
/// being able to use it.
///
/// `require_auth()` does not bind the holder: it binds whoever submits
/// the transaction. A proof covering only the domain tag and the
/// ephemeral key would be a standalone credential, and there are two ways
/// to obtain one: watch a submission, or read a transaction that failed
/// on-chain, which keeps its arguments permanently while the note stays
/// Active. The second needs no race at all, and a recipient without a
/// trustline is an ordinary way to produce one.
///
/// This is not the bearer property. A bearer note may be redeemed by
/// whoever holds it; an observer who never held it is another matter.
#[test]
#[should_panic(expected = "Error(Crypto, InvalidInput)")]
fn a_path_a_proof_cannot_be_replayed_to_another_recipient() {
    let (s, slot, ek, ek_sk, _holder) = make_token(TokenMode::PureBearer, None);
    let payee = Address::generate(&s.env);
    let thief = Address::generate(&s.env);

    // The legitimate proof, as it would appear in a submitted — or failed —
    // transaction.
    let proof = sig_ephemeral(&s.env, slot, &ek_sk, &ek, &s.mint.address, &payee);

    // The observer copies it and names themselves. The signature does not
    // verify, because the recipient is inside it.
    s.mint.redeem_by_key(
        &thief,
        &thief,
        &slot,
        &proof,
        &sig_claim(&s.env, slot, &ek, &s.mint.address, &thief),
    );
}

/// The same proof still works for the recipient it names, so the binding
/// costs the honest path nothing.
#[test]
fn a_path_a_proof_still_works_for_the_recipient_it_names() {
    let (s, slot, ek, ek_sk, holder) = make_token(TokenMode::PureBearer, None);
    let payee = Address::generate(&s.env);
    let proof = sig_ephemeral(&s.env, slot, &ek_sk, &ek, &s.mint.address, &payee);

    // Anyone may submit it — `holder` here — but the money goes where the
    // signature says.
    let paid = s.mint.redeem_by_key(
        &holder,
        &payee,
        &slot,
        &proof,
        &sig_claim(&s.env, slot, &ek, &s.mint.address, &payee),
    );
    assert_eq!(paid, 980);
    assert_eq!(s.pay_token.balance(&payee), 980);
}

#[test]
fn bearer_redeem_pays_the_named_recipient() {
    let (s, slot, ek, ek_sk, holder) = make_token(TokenMode::PureBearer, None);
    let payee = Address::generate(&s.env);
    // The proof names the payee, not the submitter.
    let eph = sig_ephemeral(&s.env, slot, &ek_sk, &ek, &s.mint.address, &payee);

    let paid = s.mint.redeem_by_key(
        &holder,
        &payee,
        &slot,
        &eph,
        &sig_claim(&s.env, slot, &ek, &s.mint.address, &payee),
    );

    assert_eq!(paid, 980);
    assert_eq!(s.pay_token.balance(&payee), 980);
    // The escrow went past the redeemer entirely.
    assert_eq!(s.pay_token.balance(&holder), 0);
}

/// The owner's signature binds the recipient, so a valid proof cannot be
/// pointed somewhere else.
///
/// This is the attack the digest change exists to stop. Before it, an
/// owner's signature authorised "redeem this note" and said nothing about
/// where the money went, so anyone holding a valid proof could redirect the
/// payout — bounded only by `holder.require_auth()`, which stops being a
/// bound as soon as submitter and authoriser are separated.
#[test]
#[should_panic(expected = "Crypto, InvalidInput")]
fn an_owner_signature_cannot_be_redirected() {
    let alice = osk(1);
    let (s, slot, ek, ek_sk, holder) = make_token(TokenMode::Spend, Some(&alice));
    let alice_commit = ocommit(&s.env, &alice);
    let intended = Address::generate(&s.env);
    let attacker = Address::generate(&s.env);
    let eph = sig_ephemeral(&s.env, slot, &ek_sk, &ek, &s.mint.address, &holder);

    // Signed for `intended`, replayed against `attacker`.
    let sig = sig_redeem_owner(&s.env, &alice, slot, &ek, &alice_commit, &intended, &s.mint.address, 0);
    s.mint.redeem_by_key_owned(
        &holder,
        &attacker,
        &slot, &eph, &opk(&s.env, &alice), &sig);
}

/// The same signature, used for the address it names, works.
///
/// Without this the test above would pass for the wrong reason: a digest
/// that rejects everything is not a digest that binds a recipient.
#[test]
fn an_owner_signature_works_for_the_address_it_names() {
    let alice = osk(1);
    let (s, slot, ek, ek_sk, holder) = make_token(TokenMode::Spend, Some(&alice));
    let alice_commit = ocommit(&s.env, &alice);
    let intended = Address::generate(&s.env);
    let eph = sig_ephemeral(&s.env, slot, &ek_sk, &ek, &s.mint.address, &intended);

    let sig = sig_redeem_owner(&s.env, &alice, slot, &ek, &alice_commit, &intended, &s.mint.address, 0);
    let paid =
        s.mint.redeem_by_key_owned(
        &holder,
        &intended,
        &slot, &eph, &opk(&s.env, &alice), &sig);

    assert_eq!(paid, 980);
    assert_eq!(s.pay_token.balance(&intended), 980);
    assert_eq!(s.pay_token.balance(&holder), 0);
}

/// What `Address::to_xdr` actually produces, pinned.
///
/// The off-chain signer must reproduce these bytes exactly or every
/// spend-mode redemption fails on a live ledger — the signature would be
/// over a different message than the one the contract checks, and nothing
/// short of a real redemption would reveal it. `kenter-client` asserts the
/// same constant from the other side, so a divergence fails a unit test
/// here instead of a payment there.
///
/// `00000012` SCV_ADDRESS, `00000000` ACCOUNT, `00000000` ED25519, then the
/// 32-byte key.
#[test]
fn recipient_xdr_is_pinned() {
    use soroban_sdk::xdr::ToXdr;
    let env = Env::default();
    let a = Address::from_str(&env, "GALMHEXVYCGR3DIEJJGVF7DRP2Y5HSXAI7RTV6FBQIXW7LQ2YOKWP5LR");
    let x = a.to_xdr(&env);
    let mut buf = std::vec![0u8; x.len() as usize];
    x.copy_into_slice(&mut buf);
    let got: std::string::String =
        buf.iter().map(|b| std::format!("{b:02x}")).collect();
    assert_eq!(got, "00000012000000000000000016c392f5c08d1d8d044a4d52fc717eb1d3cae047e33af8a1822f6fae1ac39567");
}

// ── Rent paid from outside (`bump` / `bump_token`) ──
//
// The point of these entry points is not that they extend a TTL -- the
// internal bumps already do that. It is *when* they extend it. The
// internal ones wait until an entry is within `TTL_THRESHOLD` of
// archival, which keeps rent off an ordinary caller's bill but means
// the one transaction that finally crosses the threshold pays for the
// whole 90 days. Measured on testnet, on the roster: 21.79 XLM for that
// transaction, 0.095 XLM for the next one, byte-identical footprints.
//
// A keeper calling `bump` tops entries up whatever their remaining life,
// so the threshold is never reached and nobody ever draws that ticket.
// These tests pin that difference, because it is the whole design and
// nothing else in the suite would notice if it were lost.

/// A stranger -- no stake, no note, no auth -- can pay this contract's
/// rent. Nobody can be harmed by it, and a dormant contract has to be
/// rescuable by whoever notices.
///
/// The constructor writes `Config` without bumping it, so a mint nobody
/// has used yet is sitting on the default lifetime. That is exactly the
/// state a keeper should be able to fix before the first depositor
/// arrives and is handed the bill.
#[test]
fn anyone_may_pay_the_mints_rent() {
    let s = setup();
    let fresh = ttl_of(&s, &DataKey::Config);
    s.env.ledger().set_sequence_number(s.env.ledger().sequence() + 1000);
    assert_eq!(ttl_of(&s, &DataKey::Config), fresh - 1000);

    s.mint.bump();

    assert!(
        ttl_of(&s, &DataKey::Config) > UNBUMPED_TTL * 10,
        "bump did not carry the config entry"
    );
}

/// Registration leaves a floor, not a life.
///
/// Bumping the record to `TTL_EXTEND`, 120 days, would make
/// `register_token` 90% prepaid rent for a note that might be spent
/// the same afternoon. How long a note should stay current is the
/// holder's call, so registration only guarantees it is not born
/// nearly dead.
#[test]
fn registration_leaves_a_note_a_floor_not_a_life() {
    let (s, slot, _ek, _ek_sk, _holder) = make_token(TokenMode::PureBearer, None);
    let ttl = ttl_of(&s, &DataKey::Token(slot));

    assert!(
        ttl >= crate::MIN_LIVE_LEDGERS,
        "a note was born below the floor: {ttl}"
    );
    assert!(
        ttl < crate::TTL_EXTEND,
        "registration is still prepaying 120 days: {ttl}"
    );
}

/// A print slot gets the print window, not 120 days. It is deleted by
/// `register_token` seconds later, and rent is not refunded.
#[test]
fn a_print_slot_gets_the_print_window_not_the_ceiling() {
    let s = setup_with_config(10, 3, 5, 1000);
    let d = Address::generate(&s.env);
    let slot = open_print(&s, &d);

    let ttl = ttl_of(&s, &DataKey::Slot(slot));
    assert!(
        ttl < crate::TTL_EXTEND,
        "the slot is still being bumped to the ceiling: {ttl}"
    );
    assert!(
        ttl >= 1000,
        "the slot will not outlive its own print window: {ttl}"
    );
}

/// What `bump_token` is for: the holder names the life they want and
/// pays for exactly that, instead of the contract guessing.
#[test]
fn a_holder_chooses_how_long_a_note_stays_current() {
    let (s, slot, _ek, _ek_sk, _holder) = make_token(TokenMode::PureBearer, None);
    let floor = ttl_of(&s, &DataKey::Token(slot));

    let ninety = 90 * 17_280;
    assert!(s.mint.bump_token(&slot, &ninety));

    let ttl = ttl_of(&s, &DataKey::Token(slot));
    assert!(ttl > floor, "bump_token did not extend the note");
    assert_eq!(ttl, ninety, "the note did not get the life it paid for");
}

/// Asking for less than the note already has does nothing, so a wallet
/// can call this on a schedule without tracking what it already bought.
#[test]
fn asking_for_less_than_a_note_has_is_a_no_op() {
    let (s, slot, _ek, _ek_sk, _holder) = make_token(TokenMode::PureBearer, None);
    let ninety = 90 * 17_280;
    s.mint.bump_token(&slot, &ninety);

    s.mint.bump_token(&slot, &(7 * 17_280));

    assert_eq!(
        ttl_of(&s, &DataKey::Token(slot)),
        ninety,
        "a smaller request shortened the note"
    );
}

/// A request beyond what the network allows is clamped, not refused --
/// a wallet asking for "as long as possible" should get it, and
/// `extend_ttl` panics on a value above `max_entry_ttl`, so the clamp
/// is what stops that being a trap.
#[test]
fn a_life_beyond_the_network_ceiling_is_clamped() {
    let (s, slot, _ek, _ek_sk, _holder) = make_token(TokenMode::PureBearer, None);
    assert!(s.mint.bump_token(&slot, &u32::MAX));

    let ttl = ttl_of(&s, &DataKey::Token(slot));
    assert!(ttl > 90 * 17_280, "the clamp did not give a long life: {ttl}");
}

/// A note is only worth keeping if the contract that redeems it is
/// still there, so `bump_token` carries the instance -- and with it the
/// code entry, which is the expensive one.
#[test]
fn bump_token_carries_the_contract_with_the_note() {
    let (s, slot, _ek, _ek_sk, _holder) = make_token(TokenMode::PureBearer, None);
    let full = ttl_of(&s, &DataKey::Config);

    s.env.ledger().set_sequence_number(s.env.ledger().sequence() + 5000);
    assert!(s.mint.bump_token(&slot, &(30 * 17_280)));

    // `>=`, not `==`: `full` is read a few ledgers after the config was
    // last extended (the claim window passed in between), and a missing
    // bump would leave it 5000 short, not a few.
    assert!(
        ttl_of(&s, &DataKey::Config) >= full,
        "the note outlives the contract that would redeem it"
    );
}

/// Naming a slot that was never printed is not an error -- a wallet
/// sweeping its own records should not trap on a stale id -- but it has
/// to be distinguishable from having paid for something.
#[test]
fn bump_token_reports_a_slot_that_does_not_exist() {
    let s = setup();
    assert!(!s.mint.bump_token(&4242, &(30 * 17_280)));
}

/// A spend must not hand on a note that is about to archive, so it
/// re-establishes the floor without buying a life the new owner did
/// not ask for.
#[test]
fn a_spend_leaves_the_note_above_the_floor() {
    let alice = osk(1);
    let bob = osk(2);
    let (s, slot, ek, _ek_sk, holder) = make_token(TokenMode::Spend, Some(&alice));
    let alice_commit = ocommit(&s.env, &alice);
    let bob_commit = ocommit(&s.env, &bob);

    s.env.ledger().set_sequence_number(s.env.ledger().sequence() + 100);
    let sig = sig_spend(
        &s.env, &alice, slot, &ek, &alice_commit, &bob_commit, &s.mint.address, 0,
    );
    s.mint
        .spend(&holder, &slot, &opk(&s.env, &alice), &bob_commit, &sig);

    let ttl = ttl_of(&s, &DataKey::Token(slot));
    assert!(ttl >= crate::MIN_LIVE_LEDGERS, "spend left the note short: {ttl}");
    assert!(
        ttl < crate::TTL_EXTEND,
        "spend is still buying 120 days: {ttl}"
    );
}

/// A print that was requested and then abandoned, for the tests below.
/// Returns the slot id; the depositor is `d`.
fn open_print(s: &TestSetup, d: &Address) -> u32 {
    let na = Address::generate(&s.env);
    let nb = Address::generate(&s.env);
    mint_tokens(&s.pay_token, d, 10000);
    register_node(&s.env, &s.roster_addr, &na);
    register_node(&s.env, &s.roster_addr, &nb);

    let mut pairs = Vec::new(&s.env);
    pairs.push_back(make_pair(&s.env, d, d));
    pairs.push_back(make_pair(&s.env, &na, &nb));
    pairs.push_back(make_pair(&s.env, d, d));
    s.mint
        .request_pairs(d, &random_event_id(&s.env), &1000, &pairs)
}

/// An abandoned print is as dead as a completed one, so its record goes
/// the same way. The other half of
/// `registering_a_token_retires_the_print_slot`.
#[test]
fn cancelling_retires_the_print_slot() {
    let s = setup();
    let d = Address::generate(&s.env);
    let slot = open_print(&s, &d);
    assert!(s.mint.get_slot(&slot).is_some(), "the print should be open");

    s.mint.cancel_print(&d, &slot);

    assert!(
        s.mint.get_slot(&slot).is_none(),
        "a cancelled print kept its 956-byte record"
    );
}

/// Letting the clock run out is the other way to abandon a print, and
/// it must not be the one that leaves a record behind.
#[test]
fn clearing_an_expired_slot_retires_it() {
    let s = setup_with_config(10, 3, 5, 5);
    let d = Address::generate(&s.env);
    let slot = open_print(&s, &d);

    s.env
        .ledger()
        .set_sequence_number(s.env.ledger().sequence() + 6);
    s.mint.clear_expired_slot(&slot);

    assert!(
        s.mint.get_slot(&slot).is_none(),
        "an expired print kept its record"
    );
}

/// The guard that has to survive the deletion. `EventIdUsed` is a
/// separate entry and is never removed, so abandoning a print does not
/// hand its name back -- two prints answering to one event id is a
/// reconciliation problem with no fix after the fact.
#[test]
fn a_retired_slot_still_holds_its_event_id() {
    let s = setup();
    let d = Address::generate(&s.env);
    let na = Address::generate(&s.env);
    let nb = Address::generate(&s.env);
    mint_tokens(&s.pay_token, &d, 10000);
    register_node(&s.env, &s.roster_addr, &na);
    register_node(&s.env, &s.roster_addr, &nb);

    let mut pairs = Vec::new(&s.env);
    pairs.push_back(make_pair(&s.env, &d, &d));
    pairs.push_back(make_pair(&s.env, &na, &nb));
    pairs.push_back(make_pair(&s.env, &d, &d));
    let event_id = random_event_id(&s.env);
    let slot = s.mint.request_pairs(&d, &event_id, &1000, &pairs);
    s.mint.cancel_print(&d, &slot);
    assert!(s.mint.get_slot(&slot).is_none());

    // The slot is gone; the name is still taken.
    assert!(s
        .mint
        .try_request_pairs(&d, &event_id, &1000, &pairs)
        .is_err());
}


// ── Self-payout guards ──
//
// Paying the escrow to the mint consumes the note and leaves the money
// in the same balance with nothing recording whose it is. Not theft --
// the holder does it to themselves -- but the note is gone and the
// escrow is unreachable, and the contract is immutable.

/// A holder cannot redeem a note to the mint itself.
#[test]
#[should_panic(expected = "Error(Contract, #50)")]
fn redeeming_to_the_mint_itself_is_refused() {
    let (s, slot, ek, ek_sk, holder) = make_token(TokenMode::PureBearer, None);
    let mint_addr = s.mint.address.clone();
    let eph = sig_ephemeral(&s.env, slot, &ek_sk, &ek, &s.mint.address, &mint_addr);
    let claim = sig_claim(&s.env, slot, &ek, &s.mint.address, &mint_addr);
    s.mint.redeem_by_key(&holder, &mint_addr, &slot, &eph, &claim);
}

/// Nor name it as a participant, where its fee would be credited to an
/// address that can never claim.
#[test]
#[should_panic(expected = "Error(Contract, #50)")]
fn naming_the_mint_as_a_participant_is_refused() {
    let s = setup();
    let depositor = Address::generate(&s.env);
    let na = Address::generate(&s.env);
    let nb = Address::generate(&s.env);
    mint_tokens(&s.pay_token, &depositor, 10000);
    register_node(&s.env, &s.roster_addr, &na);
    register_node(&s.env, &s.roster_addr, &nb);

    let mut pairs = Vec::new(&s.env);
    // The mint in one of the depositor's own end slots -- the position
    // that is exempt from the roster check, so nothing else catches it.
    pairs.push_back(make_pair(&s.env, &s.mint.address, &depositor));
    pairs.push_back(make_pair(&s.env, &na, &nb));
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    s.mint
        .request_pairs(&depositor, &random_event_id(&s.env), &1000, &pairs);
}

/// An ordinary recipient is of course still paid; the guard is narrow.
#[test]
fn redeeming_to_anyone_else_still_works() {
    let (s, slot, ek, ek_sk, holder) = make_token(TokenMode::PureBearer, None);
    let payee = Address::generate(&s.env);
    let eph = sig_ephemeral(&s.env, slot, &ek_sk, &ek, &s.mint.address, &payee);
    let claim = sig_claim(&s.env, slot, &ek, &s.mint.address, &payee);
    assert_eq!(s.mint.redeem_by_key(&holder, &payee, &slot, &eph, &claim), 980);
}


/// Settlement must never exceed what
/// `request_print` reserved, or an abandoned print strands its escrow
/// with no way out.
///
/// The edge case: `min_pairs = 3`, `node_fee = 10`, so the reserve is
/// `2 * 10 * (3 - 2) = 20` and a deposit of 21 clears the floor by one
/// stroop. Confirm all three links, and a settlement paying one fee per
/// confirmed link, end links included, would pay 30 against a 21
/// deposit, so `refund = amount - earned` goes negative and the SAC
/// rejects the transfer. Both exits would trap, registration is refused
/// after expiry, and the escrow would be unreachable forever while the
/// interior node went unpaid.
#[test]
fn an_abandoned_print_at_the_fee_floor_still_refunds() {
    let s = setup_with_config(10, 3, 5, 5);
    let depositor = Address::generate(&s.env);
    let na = Address::generate(&s.env);
    let nb = Address::generate(&s.env);
    mint_tokens(&s.pay_token, &depositor, 10000);
    register_node(&s.env, &s.roster_addr, &na);
    register_node(&s.env, &s.roster_addr, &nb);

    let mut pairs = Vec::new(&s.env);
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    pairs.push_back(make_pair(&s.env, &na, &nb));
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));

    // One stroop above the reserve of 20.
    let slot = s.mint.request_pairs(&depositor, &random_event_id(&s.env), &21, &pairs);
    s.mint.confirm_link(&depositor, &slot, &0, &partial_key(&s.env, 90));
    s.mint.confirm_link(&na, &slot, &1, &partial_key(&s.env, 1));
    s.mint.confirm_link(&depositor, &slot, &2, &partial_key(&s.env, 91));

    // Settles at one interior fee, well inside the deposit.
    assert_eq!(s.mint.cancel_print(&depositor, &slot), 11);
    assert_eq!(s.mint.accrued_fees(&na), 10);
    assert_eq!(s.mint.accrued_fees(&depositor), 0);
}

/// The same invariant stated generally: settlement is bounded by the
/// reserve for every pair count the mint will accept, however many
/// links were confirmed.
#[test]
fn settlement_never_exceeds_what_the_print_reserved() {
    for n in 3..=5u32 {
        let s = setup_with_config(10, 3, 5, 5);
        let depositor = Address::generate(&s.env);
        mint_tokens(&s.pay_token, &depositor, 100_000);

        let mut pairs = Vec::new(&s.env);
        pairs.push_back(make_pair(&s.env, &depositor, &depositor));
        let mut nodes = std::vec::Vec::new();
        for _ in 1..(n - 1) {
            let a = Address::generate(&s.env);
            let b = Address::generate(&s.env);
            register_node(&s.env, &s.roster_addr, &a);
            register_node(&s.env, &s.roster_addr, &b);
            pairs.push_back(make_pair(&s.env, &a, &b));
            nodes.push(a);
        }
        pairs.push_back(make_pair(&s.env, &depositor, &depositor));

        let reserve = 10i128 * 2 * (n as i128 - 2);
        let amount = reserve + 1;
        let slot = s
            .mint
            .request_pairs(&depositor, &random_event_id(&s.env), &amount, &pairs);

        // Every link confirmed: the worst case for settlement.
        let order = chain_order(&s, slot);
        let _ = &nodes;
        s.mint.confirm_link(&depositor, &slot, &0, &partial_key(&s.env, 90));
        for k in 0..(n as usize - 2) {
            s.mint.confirm_link(
                &order[k + 1].node_a,
                &slot,
                &(k as u32 + 1),
                &partial_key(&s.env, k as u8 + 1),
            );
        }
        s.mint
            .confirm_link(&depositor, &slot, &(n - 1), &partial_key(&s.env, 91));

        let refund = s.mint.cancel_print(&depositor, &slot);
        assert!(refund >= 0, "negative refund at n={n}");
        let earned = amount - refund;
        assert!(
            earned <= reserve,
            "settlement {earned} exceeded the reserve {reserve} at n={n}"
        );
    }
}


/// **The same budget, measured a second way.**
///
/// Kept alongside `bench_pathb_wasm` rather than replacing it. It uses
/// the realistic composition -- the depositor at both ends, interior
/// node pairs between -- where the bench makes every pair a distinct
/// generated node pair.
///
/// # What this number actually depends on
///
/// **The size of the test ledger**, which is the thing most likely to
/// move it and has nothing to do with the contract.
///
/// In the test environment, redemption cost grows linearly with the
/// number of entries present, at roughly **42k instructions per
/// entry**, including entries the redemption never touches. Measured
/// at 24 pairs on the wasm: 72.3M with unfunded nodes, 74.2M once 44
/// SAC balance entries exist, 80.6M with 200 unrelated addresses, and
/// over the 100M test budget at 1,000. Funding addresses that take no
/// part in the redemption is enough to do it. The likely cause is
/// something metering a copy of the whole storage map per call frame;
/// that is a hypothesis and has not been traced in the host.
///
/// One consequence, and it is a trap: **a test-setup change can trip
/// these assertions with no contract change.** If one starts failing,
/// look first at what the setup added to the ledger, not at the
/// redemption path. Keep these setups minimal for that reason.
///
/// # These figures are not upper bounds
///
/// It is tempting to read them that way, on the reasoning that a
/// network transaction's storage holds only its footprint while the
/// harness bills the whole ledger, so the network must be cheaper.
/// **Measured, it is not.** At 3 pairs, identical 904-byte chain:
///
/// | | instructions |
/// |---|---|
/// | harness (`bench_pathb_wasm`) | 9,882,230 |
/// | network (`simulateTransaction`) | 13,052,010 |
///
/// The network is 32% dearer, and the per-entry term cannot explain
/// it -- that term only makes the harness dearer. Nor is it fixed
/// transaction overhead: a trivial call to the same contract costs
/// about 0.69M on the network (`bump` 714,604, `node_fee` 684,447),
/// against a gap of 3.17M. Most of the excess scales with the work.
/// The composition difference pushes the same way: the network print
/// had the depositor at both ends, so fewer distinct fee recipients
/// and fewer `Accrued` writes than the harness does here.
///
/// So **a green assertion here does not prove the network fits**, and
/// the 100M it is held against is this suite's own budget, not the
/// network's -- that is `tx_max_instructions`, 400,000,000 on both
/// testnet and mainnet at the time of writing. What these tests still
/// do is catch the contract growing: a regression shows up here first,
/// at a figure that moves with the same code.
///
/// The authoritative measurement is `kenter redeem --dry-run`, which
/// puts the real call through `simulateTransaction` against a live
/// mint and submits nothing (see docs/LEDGER_COSTS.md).
///
/// At `max_pairs = 8` the harness reads 24.5%, and even a 1.5x network
/// factor stays near 37%. The ceiling figure bounds only a deployment
/// configured near it, and such a deployment should be measured on a
/// network first.
///
/// Funding nodes alone moves this reading by about 2.0M, which is why
/// it differs from a harness that leaves them unfunded. The owner proof
/// costs about 55k instructions here -- under a tenth of a point.
///
/// **Neither harness is authoritative.** The network's limit is set by
/// `simulateTransaction`, and no harness is the network. Before
/// deploying, simulate a ceiling-sized `redeem_by_chain_owned` against
/// the live mint and take that figure.
#[test]
#[cfg(feature = "wasm-bench")]
#[ignore = "measurement — needs `cargo build --target wasm32v1-none --release` first"]
fn pathb_owned_at_the_ceiling_fits_the_budget_wasm() {
    ceiling_owned_redeem_fits(false);
}

/// The same reading with **every interior node a volunteer**: the
/// dearest shape, because each volunteer's fee adds an event and the
/// settlement adds one SAC `burn` call.
#[test]
#[cfg(feature = "wasm-bench")]
#[ignore = "measurement — needs `cargo build --target wasm32v1-none --release` first"]
fn pathb_owned_at_the_ceiling_fits_the_budget_with_volunteers_wasm() {
    ceiling_owned_redeem_fits(true);
}

#[cfg(feature = "wasm-bench")]
fn ceiling_owned_redeem_fits(volunteers: bool) {
    const BUDGET_CEILING_PCT: f64 = 85.0;
    const PAIRS: u32 = crate::MAX_REDEEMABLE_PAIRS;

    let s = setup_for(true, 10, 3, PAIRS, 1000);
    let depositor = Address::generate(&s.env);
    let holder = Address::generate(&s.env);
    let amount: i128 = 10_000_000;
    mint_tokens(&s.pay_token, &depositor, amount * 2);

    // The depositor holds both end pairs; everything between is a
    // distinct roster pair. This is the shape a real print has.
    let mut pairs = Vec::new(&s.env);
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));
    for _ in 1..(PAIRS - 1) {
        let na = Address::generate(&s.env);
        let nb = Address::generate(&s.env);
        register_node(&s.env, &s.roster_addr, &na);
        register_node(&s.env, &s.roster_addr, &nb);
        if volunteers {
            add_volunteer(&s.env, &s.roster_addr, &na);
            add_volunteer(&s.env, &s.roster_addr, &nb);
        }
        pairs.push_back(make_pair(&s.env, &na, &nb));
    }
    pairs.push_back(make_pair(&s.env, &depositor, &depositor));

    let event_id = random_event_id(&s.env);
    let slot_id = s.mint.request_pairs(&depositor, &event_id, &amount, &pairs);
    // Positions follow score, so the chain's order is read off the slot.
    let order = chain_order(&s, slot_id);
    for i in 0..PAIRS {
        let who = order[i as usize].node_a.clone();
        s.mint.confirm_link(&who, &slot_id, &i, &partial_key(&s.env, i as u8));
    }

    let chain = build_chain(&event_id.to_array(), PAIRS as u16, 0x33);
    let ek = random_key(&s.env);
    let owner = osk(202);
    let commit = ocommit(&s.env, &owner);
    s.mint.register_token(
        &depositor,
        &slot_id,
        &ek,
        &sha256_of(&s.env, &chain),
        &TokenMode::Spend,
        &commit,
        &claim_pk(&s.env),
    );

    let chain_data = Bytes::from_slice(&s.env, &chain);
    let os = sig_redeem_owner(
        &s.env, &owner, slot_id, &ek, &commit, &holder, &s.mint.address, 0,
    );

    // Build every argument before resetting, so the measurement covers
    // the call and not the fixture.
    let mut budget = s.env.cost_estimate().budget();
    budget.reset_unlimited();
    s.mint.redeem_by_chain_owned(
        &holder, &holder, &slot_id, &chain_data, &opk(&s.env, &owner), &os,
    );

    let used = s.env.cost_estimate().resources().instructions;
    let pct = (used as f64 / TEST_BUDGET_INSTRUCTIONS as f64) * 100.0;
    std::println!(
        "{PAIRS}-pair redeem_by_chain_owned (realistic composition, volunteers={volunteers}): {used} instr, {pct:.1}%"
    );
    assert!(
        pct < BUDGET_CEILING_PCT,
        "redeem_by_chain_owned is at {pct:.1}% of the CPU budget at {PAIRS} pairs, over the {BUDGET_CEILING_PCT}% ceiling."
    );
}

// ══ Node selection (docs/architecture/node-selection.md) ═════════════
//
// The print as designed: the depositor names its end pairs, a drand round
// seeds the slot, pairs claim and the lowest scores win. The tests are
// grouped by the stage of selection they hold the contract to.

/// A depositor, `k` interior pairs on the roster, and a funded setup.
fn sel_setup<'a>(k: u32) -> (TestSetup<'a>, Address, std::vec::Vec<PairEntry>) {
    let s = setup_with_config(10, 3, 8, 1000);
    let d = Address::generate(&s.env);
    mint_tokens(&s.pay_token, &d, 100_000);
    let mut ps = std::vec::Vec::new();
    for _ in 0..k {
        let a = Address::generate(&s.env);
        let b = Address::generate(&s.env);
        register_node(&s.env, &s.roster_addr, &a);
        register_node(&s.env, &s.roster_addr, &b);
        s.mint.register_pair(&a, &b);
        ps.push(make_pair(&s.env, &a, &b));
    }
    advance(&s.env, 1);
    (s, d, ps)
}

/// The depositor's own end pair.
fn own(d: &Address) -> PairEntry {
    PairEntry {
        node_a: d.clone(),
        node_b: d.clone(),
    }
}

/// Request a print of `total` pairs and seed it; nobody has claimed yet.
fn seeded(s: &TestSetup, d: &Address, total: u32) -> u32 {
    s.env.ledger().set_timestamp(fixture_time());
    let slot = s
        .mint
        .request_print(d, &random_event_id(&s.env), &1000, &total, &own(d), &own(d));
    s.mint.seed_print(&slot, &beacon_sig(&s.env));
    slot
}

/// The score as docs/architecture/node-selection.md defines it, computed here
/// independently of the contract, so the formula itself is under test.
fn expected_score(env: &Env, seed: &BytesN<32>, p: &PairEntry) -> BytesN<32> {
    use soroban_sdk::xdr::ToXdr;
    let xa = p.node_a.clone().to_xdr(env);
    let xb = p.node_b.clone().to_xdr(env);
    let (lo, hi) = if xa <= xb { (xa, xb) } else { (xb, xa) };
    let mut m = Bytes::from_array(env, &seed.to_array());
    m.append(&lo);
    m.append(&hi);
    env.crypto().sha256(&m).to_bytes()
}

/// The G1 generator, uncompressed: a valid point that is no signature.
const G1_GENERATOR: &str = "17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1";

// ── The depositor names only the ends ──

#[test]
fn a_request_names_only_the_end_pairs_and_fixes_its_round() {
    let (s, d, _) = sel_setup(1);
    s.env.ledger().set_timestamp(fixture_time());
    let slot = s
        .mint
        .request_print(&d, &random_event_id(&s.env), &1000, &3, &own(&d), &own(&d));
    let sl = s.mint.get_slot(&slot).unwrap();
    assert_eq!(sl.pairs.len(), 2, "only the two end pairs until the draw");
    assert_eq!(sl.beacon_round, BEACON_ROUND, "round_at(now) + lead");
    assert!(sl.seed.is_none() && !sl.closed && sl.claims.is_empty());
}

#[test]
fn the_round_is_the_lead_after_the_one_current_at_request() {
    let (s, d, _) = sel_setup(1);
    // Ten periods later, the round moves by ten.
    s.env.ledger().set_timestamp(fixture_time() + 10 * BEACON_PERIOD);
    let slot = s
        .mint
        .request_print(&d, &random_event_id(&s.env), &1000, &3, &own(&d), &own(&d));
    assert_eq!(s.mint.get_slot(&slot).unwrap().beacon_round, BEACON_ROUND + 10);
}

// ── The seed ──

#[test]
fn the_beacon_round_seeds_the_slot() {
    let (s, d, _) = sel_setup(1);
    let slot = seeded(&s, &d, 3);
    let sl = s.mint.get_slot(&slot).unwrap();
    assert!(sl.seed.is_some());
    assert_eq!(sl.claim_deadline, s.env.ledger().sequence() + CLAIM_WINDOW);
}

#[test]
fn a_slot_cannot_be_seeded_twice() {
    let (s, d, _) = sel_setup(1);
    let slot = seeded(&s, &d, 3);
    assert_eq!(
        s.mint.try_seed_print(&slot, &beacon_sig(&s.env)),
        Err(Ok(Error::AlreadySeeded))
    );
}

#[test]
fn another_rounds_signature_does_not_seed() {
    let (s, d, _) = sel_setup(1);
    // A request one period later wants round R + 1; the fixture is R.
    s.env.ledger().set_timestamp(fixture_time() + BEACON_PERIOD);
    let slot = s
        .mint
        .request_print(&d, &random_event_id(&s.env), &1000, &3, &own(&d), &own(&d));
    assert_eq!(
        s.mint.try_seed_print(&slot, &beacon_sig(&s.env)),
        Err(Ok(Error::BadBeacon))
    );
}

#[test]
fn a_valid_point_that_is_not_the_signature_does_not_seed() {
    let (s, d, _) = sel_setup(1);
    s.env.ledger().set_timestamp(fixture_time());
    let slot = s
        .mint
        .request_print(&d, &random_event_id(&s.env), &1000, &3, &own(&d), &own(&d));
    let g = BytesN::from_array(&s.env, &unhex::<96>(G1_GENERATOR));
    assert_eq!(s.mint.try_seed_print(&slot, &g), Err(Ok(Error::BadBeacon)));
}

#[test]
fn a_point_off_the_curve_traps() {
    let (s, d, _) = sel_setup(1);
    s.env.ledger().set_timestamp(fixture_time());
    let slot = s
        .mint
        .request_print(&d, &random_event_id(&s.env), &1000, &3, &own(&d), &own(&d));
    let mut sig = unhex::<96>(BEACON_SIG);
    sig[95] ^= 1;
    assert!(s
        .mint
        .try_seed_print(&slot, &BytesN::from_array(&s.env, &sig))
        .is_err());
    assert!(s.mint.get_slot(&slot).unwrap().seed.is_none());
}

#[test]
fn two_slots_seeded_by_one_round_draw_differently() {
    let (s, d, _) = sel_setup(1);
    let a = seeded(&s, &d, 3);
    let b = seeded(&s, &d, 3);
    let sa = s.mint.get_slot(&a).unwrap().seed.unwrap();
    let sb = s.mint.get_slot(&b).unwrap().seed.unwrap();
    assert_ne!(sa, sb, "the slot id is mixed into the seed");
}

#[test]
fn nobody_can_claim_before_the_seed() {
    let (s, d, ps) = sel_setup(1);
    s.env.ledger().set_timestamp(fixture_time());
    let slot = s
        .mint
        .request_print(&d, &random_event_id(&s.env), &1000, &3, &own(&d), &own(&d));
    assert_eq!(
        s.mint.try_claim_position(&slot, &ps[0].node_a, &ps[0].node_b),
        Err(Ok(Error::NotSeeded))
    );
}

// ── Claiming ──

#[test]
fn a_claim_needs_both_members_signatures() {
    let (s, d, ps) = sel_setup(1);
    let slot = seeded(&s, &d, 3);
    s.mint.claim_position(&slot, &ps[0].node_a, &ps[0].node_b);
    let signers: std::vec::Vec<Address> = s.env.auths().iter().map(|(a, _)| a.clone()).collect();
    assert!(signers.contains(&ps[0].node_a) && signers.contains(&ps[0].node_b));
}

#[test]
fn the_score_is_the_documented_hash() {
    let (s, d, ps) = sel_setup(1);
    let slot = seeded(&s, &d, 3);
    s.mint.claim_position(&slot, &ps[0].node_a, &ps[0].node_b);
    let sl = s.mint.get_slot(&slot).unwrap();
    let seed = sl.seed.unwrap();
    assert_eq!(sl.claims.get(0).unwrap().score, expected_score(&s.env, &seed, &ps[0]));
    // Unordered: the same pair named the other way round scores the same.
    let swapped = make_pair(&s.env, &ps[0].node_b, &ps[0].node_a);
    assert_eq!(expected_score(&s.env, &seed, &swapped), expected_score(&s.env, &seed, &ps[0]));
}

#[test]
fn claims_are_ranked_by_score_whatever_order_they_arrive_in() {
    let (s, d, ps) = sel_setup(4);
    let slot = seeded(&s, &d, 4); // k = 2, list holds 4
    for p in ps.iter().rev() {
        s.mint.claim_position(&slot, &p.node_a, &p.node_b);
    }
    let sl = s.mint.get_slot(&slot).unwrap();
    let scores: std::vec::Vec<BytesN<32>> = sl.claims.iter().map(|c| c.score).collect();
    let mut sorted = scores.clone();
    sorted.sort();
    assert_eq!(scores, sorted);
}

#[test]
fn a_lower_score_displaces_a_higher_one_and_a_higher_one_is_refused() {
    // k = 1, so the list holds two. Five pairs claim; the list must end
    // as the two lowest of the five, and every refusal must be a pair
    // that would not have made it.
    let (s, d, ps) = sel_setup(5);
    let slot = seeded(&s, &d, 3);
    let seed = s.mint.get_slot(&slot).unwrap().seed.unwrap();
    let mut refused = std::vec::Vec::new();
    for p in &ps {
        match s.mint.try_claim_position(&slot, &p.node_a, &p.node_b) {
            Ok(Ok(_)) => {}
            Err(Ok(Error::ClaimNotCompetitive)) => refused.push(p.clone()),
            other => panic!("unexpected {other:?}"),
        }
    }
    let mut all: std::vec::Vec<BytesN<32>> =
        ps.iter().map(|p| expected_score(&s.env, &seed, p)).collect();
    all.sort();
    let sl = s.mint.get_slot(&slot).unwrap();
    assert_eq!(sl.claims.len(), 2);
    assert_eq!(sl.claims.get(0).unwrap().score, all[0]);
    assert_eq!(sl.claims.get(1).unwrap().score, all[1]);
    for p in refused {
        assert!(expected_score(&s.env, &seed, &p) > all[1]);
    }
}

#[test]
fn a_claim_cannot_reuse_an_address_already_claimed() {
    let (s, d, ps) = sel_setup(2);
    let slot = seeded(&s, &d, 4);
    s.mint.claim_position(&slot, &ps[0].node_a, &ps[0].node_b);
    assert_eq!(
        s.mint.try_claim_position(&slot, &ps[0].node_a, &ps[1].node_b),
        Err(Ok(Error::NodesNotDistinct))
    );
}

#[test]
fn the_depositor_cannot_claim_an_interior_position_with_an_end_key() {
    let (s, d, ps) = sel_setup(1);
    register_node(&s.env, &s.roster_addr, &d);
    let slot = seeded(&s, &d, 3);
    assert_eq!(
        s.mint.try_claim_position(&slot, &d, &ps[0].node_b),
        Err(Ok(Error::NodesNotDistinct))
    );
}

#[test]
fn a_node_off_the_roster_cannot_claim() {
    let (s, d, _) = sel_setup(0);
    let a = Address::generate(&s.env);
    let b = Address::generate(&s.env);
    register_node(&s.env, &s.roster_addr, &a);
    let slot = seeded(&s, &d, 3);
    assert_eq!(
        s.mint.try_claim_position(&slot, &a, &b),
        Err(Ok(Error::NodeNotOnRoster))
    );
}

#[test]
fn the_mint_cannot_claim() {
    let (s, d, ps) = sel_setup(1);
    let slot = seeded(&s, &d, 3);
    assert_eq!(
        s.mint.try_claim_position(&slot, &s.mint.address, &ps[0].node_b),
        Err(Ok(Error::PayoutToSelf))
    );
}

#[test]
fn after_the_window_a_full_list_takes_no_more_claims() {
    let (s, d, ps) = sel_setup(2);
    let slot = seeded(&s, &d, 3);
    s.mint.claim_position(&slot, &ps[0].node_a, &ps[0].node_b);
    advance(&s.env, CLAIM_WINDOW + 1);
    assert_eq!(
        s.mint.try_claim_position(&slot, &ps[1].node_a, &ps[1].node_b),
        Err(Ok(Error::ClaimsClosed))
    );
}

#[test]
fn after_the_window_a_short_list_still_takes_claims() {
    // Section 4.2: an overestimated roster costs time, not the print.
    let (s, d, ps) = sel_setup(2);
    let slot = seeded(&s, &d, 4); // k = 2
    s.mint.claim_position(&slot, &ps[0].node_a, &ps[0].node_b);
    advance(&s.env, CLAIM_WINDOW + 1);
    s.mint.claim_position(&slot, &ps[1].node_a, &ps[1].node_b);
    assert_eq!(s.mint.get_slot(&slot).unwrap().claims.len(), 2);
}

#[test]
fn a_new_node_waits_out_min_node_age() {
    let env_sel = |env: &Env| SelectionConfig {
        min_node_age: 100,
        ..test_selection(env)
    };
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let (pay_token, pay_token_addr) = create_token(&env, &admin);
    let roster_addr = env.register(roster_contract::MockRoster, ());
    let mint = KenterMintClient::new(
        &env,
        &env.register(
            KenterMint,
            (10u32, 3u32, 5u32, &pay_token_addr, &roster_addr, 1000u32, env_sel(&env)),
        ),
    );
    let s = TestSetup { env, mint, pay_token, pay_token_addr, roster_addr };
    let d = Address::generate(&s.env);
    mint_tokens(&s.pay_token, &d, 10_000);
    let a = Address::generate(&s.env);
    let b = Address::generate(&s.env);
    s.env.ledger().set_sequence_number(1000);
    register_node(&s.env, &s.roster_addr, &a);
    register_node(&s.env, &s.roster_addr, &b);

    // Too new to register at all.
    assert_eq!(s.mint.try_register_pair(&a, &b), Err(Ok(Error::NodeTooNew)));

    s.env.ledger().set_sequence_number(1100);
    s.mint.register_pair(&a, &b);
    advance(&s.env, 1);
    let slot = seeded(&s, &d, 3);
    s.mint.claim_position(&slot, &a, &b);
}

/// `RosterNode` must name the same fields, in the same types, as the
/// roster's `Node`, or `get_node` fails to decode under a real roster.
/// Checked against the roster's source, which is what the deployed roster
/// was built from.
#[test]
fn roster_node_mirrors_the_rosters_node() {
    fn fields(src: &str, name: &str) -> std::vec::Vec<std::string::String> {
        let start = src.find(&std::format!("pub struct {name} {{")).expect(name);
        let body = &src[start..src[start..].find('}').unwrap() + start];
        body.lines()
            .map(str::trim)
            .filter(|l| l.starts_with("pub ") && l.contains(':'))
            .map(|l| l.trim_end_matches(',').replace(' ', ""))
            .collect()
    }
    let roster = include_str!("../../kenter-roster/src/types.rs");
    let mint = include_str!("types.rs");
    assert_eq!(fields(roster, "Node"), fields(mint, "RosterNode"));
}

// ── Closing ──

#[test]
fn interior_links_wait_for_the_window() {
    let (s, d, ps) = sel_setup(1);
    let slot = seeded(&s, &d, 3);
    s.mint.claim_position(&slot, &ps[0].node_a, &ps[0].node_b);
    s.mint.confirm_link(&d, &slot, &0, &partial_key(&s.env, 90));
    assert_eq!(
        s.mint
            .try_confirm_link(&ps[0].node_a, &slot, &1, &partial_key(&s.env, 1)),
        Err(Ok(Error::SelectionNotReady))
    );
    advance(&s.env, CLAIM_WINDOW + 1);
    s.mint.confirm_link(&ps[0].node_a, &slot, &1, &partial_key(&s.env, 1));
}

#[test]
fn interior_links_wait_for_every_position_to_be_claimed() {
    let (s, d, ps) = sel_setup(1);
    let slot = seeded(&s, &d, 4); // k = 2, only one claims
    s.mint.claim_position(&slot, &ps[0].node_a, &ps[0].node_b);
    advance(&s.env, CLAIM_WINDOW + 1);
    s.mint.confirm_link(&d, &slot, &0, &partial_key(&s.env, 90));
    assert_eq!(
        s.mint
            .try_confirm_link(&ps[0].node_a, &slot, &1, &partial_key(&s.env, 1)),
        Err(Ok(Error::SelectionNotReady))
    );
}

#[test]
fn closing_puts_the_lowest_scores_in_order_and_keeps_the_rest_as_runners_up() {
    let (s, d, ps) = sel_setup(4);
    let slot = seeded(&s, &d, 4); // k = 2
    for p in &ps {
        s.mint.claim_position(&slot, &p.node_a, &p.node_b);
    }
    let before = s.mint.get_slot(&slot).unwrap().claims;
    advance(&s.env, CLAIM_WINDOW + 1);
    s.mint.confirm_link(&d, &slot, &0, &partial_key(&s.env, 90));
    let first = before.get(0).unwrap().pair;
    s.mint.confirm_link(&first.node_a, &slot, &1, &partial_key(&s.env, 1));

    let sl = s.mint.get_slot(&slot).unwrap();
    assert!(sl.closed);
    assert_eq!(sl.pairs.len(), 4);
    assert_eq!(sl.pairs.get(1).unwrap(), before.get(0).unwrap().pair);
    assert_eq!(sl.pairs.get(2).unwrap(), before.get(1).unwrap().pair);
    assert_eq!(sl.claims.len(), 2, "the other two are runners-up");
    assert_eq!(sl.claims.get(0).unwrap(), before.get(2).unwrap());
}

#[test]
fn a_volunteers_terms_follow_it_into_its_position() {
    let (s, d, ps) = sel_setup(2);
    add_volunteer(&s.env, &s.roster_addr, &ps[1].node_b);
    let slot = seeded(&s, &d, 4);
    for p in &ps {
        s.mint.claim_position(&slot, &p.node_a, &p.node_b);
    }
    advance(&s.env, CLAIM_WINDOW + 1);
    let order = chain_order(&s, slot);
    s.mint.confirm_link(&d, &slot, &0, &partial_key(&s.env, 90));
    s.mint.confirm_link(&order[1].node_a, &slot, &1, &partial_key(&s.env, 1));
    let sl = s.mint.get_slot(&slot).unwrap();
    let pos = if order[1] == ps[1] { 1u32 } else { 2u32 };
    assert_eq!(sl.volunteers, 1 << (2 * pos + 1), "only ps[1].node_b, where it landed");
}

// ── Skipping a pair that does not serve ──

/// Two positions' worth of claims plus runners-up, closed, link 0 done.
fn at_position_one<'a>() -> (TestSetup<'a>, Address, u32, std::vec::Vec<PairEntry>) {
    let (s, d, ps) = sel_setup(4);
    let slot = seeded(&s, &d, 4);
    for p in &ps {
        s.mint.claim_position(&slot, &p.node_a, &p.node_b);
    }
    advance(&s.env, CLAIM_WINDOW + 1);
    s.mint.confirm_link(&d, &slot, &0, &partial_key(&s.env, 90));
    (s, d, slot, ps)
}

#[test]
fn a_pair_cannot_be_skipped_before_its_serve_timeout() {
    let (s, d, slot, _) = at_position_one();
    assert_eq!(
        s.mint.try_skip_position(&d, &slot),
        Err(Ok(Error::ServeTimeoutNotReached))
    );
}

#[test]
fn a_silent_pair_is_replaced_by_the_best_runner_up_at_the_depositors_cost() {
    let (s, d, slot, _) = at_position_one();
    let runner_up = s.mint.get_slot(&slot).unwrap().claims.get(2).unwrap().pair;
    let silent = s.mint.get_slot(&slot).unwrap().claims.get(0).unwrap().pair;
    advance(&s.env, SERVE_TIMEOUT + 1);
    let before_d = s.pay_token.balance(&d);
    let before_m = s.pay_token.balance(&s.mint.address);

    assert_eq!(s.mint.skip_position(&d, &slot), 1);

    let sl = s.mint.get_slot(&slot).unwrap();
    assert_eq!(sl.pairs.get(1).unwrap(), runner_up);
    assert_eq!(s.pay_token.balance(&d), before_d - 20, "one pair's fee");
    assert_eq!(
        s.pay_token.balance(&s.mint.address),
        before_m,
        "burned, and the escrow is untouched"
    );
    // The skipped pair is out; the runner-up serves.
    assert_eq!(
        s.mint
            .try_confirm_link(&silent.node_a, &slot, &1, &partial_key(&s.env, 1)),
        Err(Ok(Error::NotAssignedPair))
    );
    s.mint.confirm_link(&runner_up.node_b, &slot, &1, &partial_key(&s.env, 1));
}

#[test]
fn only_the_depositor_can_skip() {
    let (s, _d, slot, ps) = at_position_one();
    advance(&s.env, SERVE_TIMEOUT + 1);
    assert_eq!(
        s.mint.try_skip_position(&ps[0].node_a, &slot),
        Err(Ok(Error::NotDepositor))
    );
}

#[test]
fn the_depositors_own_links_cannot_be_skipped() {
    let (s, d, ps) = sel_setup(1);
    let slot = seeded(&s, &d, 3);
    s.mint.claim_position(&slot, &ps[0].node_a, &ps[0].node_b);
    advance(&s.env, CLAIM_WINDOW + SERVE_TIMEOUT + 2);
    // Position 0 is next: the depositor's own.
    assert_eq!(s.mint.try_skip_position(&d, &slot), Err(Ok(Error::NotSkippable)));
}

#[test]
fn when_the_runners_up_run_out_the_print_must_be_cancelled() {
    let (s, d, ps) = sel_setup(1);
    let slot = seeded(&s, &d, 3);
    s.mint.claim_position(&slot, &ps[0].node_a, &ps[0].node_b);
    advance(&s.env, CLAIM_WINDOW + 1);
    s.mint.confirm_link(&d, &slot, &0, &partial_key(&s.env, 90));
    advance(&s.env, SERVE_TIMEOUT + 1);
    assert_eq!(s.mint.try_skip_position(&d, &slot), Err(Ok(Error::NoBackup)));
}

#[test]
fn each_confirmation_restarts_the_serve_clock() {
    let (s, d, slot, _) = at_position_one();
    let order = chain_order(&s, slot);
    advance(&s.env, SERVE_TIMEOUT);
    s.mint.confirm_link(&order[1].node_a, &slot, &1, &partial_key(&s.env, 1));
    // Position 2 has only just become current.
    advance(&s.env, 1);
    assert_eq!(
        s.mint.try_skip_position(&d, &slot),
        Err(Ok(Error::ServeTimeoutNotReached))
    );
}

// ── Cancel, expiry and the re-roll ──

#[test]
fn cancel_before_the_seed_refunds_in_full() {
    let (s, d, _) = sel_setup(1);
    s.env.ledger().set_timestamp(fixture_time());
    let slot = s
        .mint
        .request_print(&d, &random_event_id(&s.env), &1000, &3, &own(&d), &own(&d));
    assert_eq!(s.mint.cancel_print(&d, &slot), 1000);
}

#[test]
fn cancel_inside_the_window_forfeits_every_position() {
    // The seed is public, so the draw can be computed: cancelling now is
    // a re-roll, and it is priced (section 6).
    let (s, d, _) = sel_setup(2);
    let slot = seeded(&s, &d, 4); // k = 2
    assert_eq!(s.mint.cancel_print(&d, &slot), 1000 - 2 * 10 * 2);
}

#[test]
fn a_draw_that_could_not_fill_refunds_in_full() {
    let (s, d, ps) = sel_setup(1);
    let slot = seeded(&s, &d, 4); // k = 2, one claim
    s.mint.claim_position(&slot, &ps[0].node_a, &ps[0].node_b);
    advance(&s.env, CLAIM_WINDOW + 1);
    assert_eq!(s.mint.cancel_print(&d, &slot), 1000);
}

#[test]
fn cancel_after_selection_pays_the_confirmed_and_forfeits_the_rest() {
    let (s, d, slot, _) = at_position_one();
    let order = chain_order(&s, slot);
    s.mint.confirm_link(&order[1].node_a, &slot, &1, &partial_key(&s.env, 1));
    // One interior link paid (one fee, to its confirmer), one position
    // forfeit (two fees).
    assert_eq!(s.mint.cancel_print(&d, &slot), 1000 - 10 - 20);
    assert_eq!(s.mint.accrued_fees(&order[1].node_a), 10);
}

#[test]
fn expiry_after_selection_settles_like_cancel() {
    let s = setup_with_config(10, 3, 8, 50);
    let d = Address::generate(&s.env);
    mint_tokens(&s.pay_token, &d, 10_000);
    let a = Address::generate(&s.env);
    let b = Address::generate(&s.env);
    register_node(&s.env, &s.roster_addr, &a);
    register_node(&s.env, &s.roster_addr, &b);
    s.mint.register_pair(&a, &b);
    advance(&s.env, 1);
    let slot = seeded(&s, &d, 3);
    s.mint.claim_position(&slot, &a, &b);
    let created = s.mint.get_slot(&slot).unwrap().created_at;
    s.env.ledger().set_sequence_number(created + 51);
    assert_eq!(s.mint.clear_expired_slot(&slot), 1000 - 20);
}

#[test]
fn settlement_and_forfeit_stay_inside_the_reserve() {
    // Every pair count, every number of confirmed interior links: what an
    // abandoned print takes is never more than `2 * fee * k`, the reserve.
    for total in 3..=8u32 {
        let k = total - 2;
        for confirmed in 0..=k {
            let (s, d, ps) = sel_setup(k);
            let reserve = 2 * 10 * k as i128;
            let amount = reserve + 1;
            s.env.ledger().set_timestamp(fixture_time());
            let slot = s.mint.request_print(
                &d,
                &random_event_id(&s.env),
                &amount,
                &total,
                &own(&d),
                &own(&d),
            );
            s.mint.seed_print(&slot, &beacon_sig(&s.env));
            for p in &ps {
                s.mint.claim_position(&slot, &p.node_a, &p.node_b);
            }
            advance(&s.env, CLAIM_WINDOW + 1);
            let order = chain_order(&s, slot);
            s.mint.confirm_link(&d, &slot, &0, &partial_key(&s.env, 90));
            for i in 1..=confirmed {
                s.mint
                    .confirm_link(&order[i as usize].node_a, &slot, &i, &partial_key(&s.env, i as u8));
            }
            let refund = s.mint.cancel_print(&d, &slot);
            assert!(refund >= 1, "total={total} confirmed={confirmed}: refund {refund}");
            assert!(amount - refund <= reserve);
        }
    }
}

// ── Construction ──

#[test]
fn a_mint_with_unusable_selection_parameters_is_refused() {
    let bad: [fn(&Env) -> SelectionConfig; 6] = [
        |e| SelectionConfig { beacon_period: 0, ..test_selection(e) },
        |e| SelectionConfig { beacon_lead: 0, ..test_selection(e) },
        |e| SelectionConfig { claim_window: 0, ..test_selection(e) },
        |e| SelectionConfig { serve_timeout: 0, ..test_selection(e) },
        |e| SelectionConfig { claim_window: 1000, ..test_selection(e) },
        // The G2 generator negated is a fine point, but not the beacon's
        // key; a key that is not even on the curve must also be refused.
        |e| {
            let mut pk = unhex::<192>(BEACON_PK);
            pk[191] ^= 1;
            SelectionConfig { beacon_pk: BytesN::from_array(e, &pk), ..test_selection(e) }
        },
    ];
    for (i, f) in bad.iter().enumerate() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let (_t, token_addr) = create_token(&env, &admin);
        let roster = env.register(roster_contract::MockRoster, ());
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            env.register(
                KenterMint,
                (10u32, 3u32, 5u32, &token_addr, &roster, 1000u32, f(&env)),
            );
        }));
        assert!(r.is_err(), "bad selection config {i} was accepted");
    }
}

// ── Cost ──

/// What the selection steps cost on the native host, printed for the
/// record. The wasm figures that matter are `bench_selection_wasm`.
fn measure_selection(use_wasm: bool) -> (u64, u64, u64) {
    let s = setup_for(use_wasm, 10, 3, crate::MAX_REDEEMABLE_PAIRS, 1000);
    let d = Address::generate(&s.env);
    mint_tokens(&s.pay_token, &d, 100_000);
    let total = crate::MAX_REDEEMABLE_PAIRS;
    let k = total - 2;
    let mut ps = std::vec::Vec::new();
    for _ in 0..(2 * k) {
        let a = Address::generate(&s.env);
        let b = Address::generate(&s.env);
        register_node(&s.env, &s.roster_addr, &a);
        register_node(&s.env, &s.roster_addr, &b);
        s.mint.register_pair(&a, &b);
        ps.push(make_pair(&s.env, &a, &b));
    }
    advance(&s.env, 1);
    s.env.ledger().set_timestamp(fixture_time());
    let slot = s
        .mint
        .request_print(&d, &random_event_id(&s.env), &10_000, &total, &own(&d), &own(&d));

    let mut budget = s.env.cost_estimate().budget();
    budget.reset_unlimited();
    s.mint.seed_print(&slot, &beacon_sig(&s.env));
    let seed_cpu = s.env.cost_estimate().budget().cpu_instruction_cost();

    // Fill the list to its cap, then measure one more claim into it: the
    // dearest claim there is.
    for p in &ps[..ps.len() - 1] {
        let _ = s.mint.try_claim_position(&slot, &p.node_a, &p.node_b);
    }
    let last = ps.last().unwrap();
    let mut budget = s.env.cost_estimate().budget();
    budget.reset_unlimited();
    let _ = s.mint.try_claim_position(&slot, &last.node_a, &last.node_b);
    let claim_cpu = s.env.cost_estimate().budget().cpu_instruction_cost();

    // The first interior link, which closes selection over a full list.
    advance(&s.env, CLAIM_WINDOW + 1);
    let order = chain_order(&s, slot);
    s.mint.confirm_link(&d, &slot, &0, &partial_key(&s.env, 90));
    let mut budget = s.env.cost_estimate().budget();
    budget.reset_unlimited();
    s.mint.confirm_link(&order[1].node_a, &slot, &1, &partial_key(&s.env, 1));
    let close_cpu = s.env.cost_estimate().budget().cpu_instruction_cost();
    (seed_cpu, claim_cpu, close_cpu)
}

#[test]
fn selection_fits_the_budget_native() {
    let (seed, claim, close) = measure_selection(false);
    std::println!("native at {} pairs: seed_print {seed}, full claim {claim}, closing confirm {close}",
        crate::MAX_REDEEMABLE_PAIRS);
    for (what, cpu) in [("seed_print", seed), ("claim", claim), ("closing confirm", close)] {
        assert!((cpu as i64) < TEST_BUDGET_INSTRUCTIONS, "{what}: {cpu}");
    }
}

#[cfg(feature = "wasm-bench")]
#[test]
fn bench_selection_wasm() {
    let (seed, claim, close) = measure_selection(true);
    std::println!("wasm at {} pairs: seed_print {seed}, full claim {claim}, closing confirm {close}",
        crate::MAX_REDEEMABLE_PAIRS);
    for (what, cpu) in [("seed_print", seed), ("claim", claim), ("closing confirm", close)] {
        assert!((cpu as i64) < TEST_BUDGET_INSTRUCTIONS / 2, "{what}: {cpu}");
    }
}

/// One fixed score, so off-chain code (`kenter_client::selection_score`)
/// can be held to the same bytes: a daemon that scores itself differently
/// from the mint misjudges every claim.
#[test]
fn the_score_matches_its_published_vector() {
    use soroban_sdk::String as SStr;
    let env = Env::default();
    let a = Address::from_string(&SStr::from_str(&env, "GABQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMBQHGPC"));
    let b = Address::from_string(&SStr::from_str(&env, "GACAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAJJHP"));
    let seed = BytesN::from_array(&env, &[7u8; 32]);
    let got = expected_score(&env, &seed, &make_pair(&env, &a, &b)).to_array();
    let hex: std::string::String = got.iter().map(|x| std::format!("{x:02x}")).collect();
    std::println!("SCORE_VECTOR {hex}");
    assert_eq!(hex, SCORE_VECTOR);
}
const SCORE_VECTOR: &str = "8d48c89eb1f7b0c75abd5db8bf365430f266ce2341d9d8997eae8cbcc0a8110f";


// ── Node selection: attacks on the draw ──

/// An operator with several staked addresses cannot try them in
/// every combination against a public seed: only the pair registered
/// before the request may claim.
#[test]
fn a_recombined_pair_cannot_claim() {
    let (s, d, ps) = sel_setup(2);
    let slot = seeded(&s, &d, 3);
    // Both addresses are staked and registered, but not with each other.
    assert_eq!(
        s.mint.try_claim_position(&slot, &ps[0].node_a, &ps[1].node_b),
        Err(Ok(Error::PairNotRegistered))
    );
}

#[test]
fn an_unregistered_pair_cannot_claim() {
    let (s, d, _) = sel_setup(0);
    let a = Address::generate(&s.env);
    let b = Address::generate(&s.env);
    register_node(&s.env, &s.roster_addr, &a);
    register_node(&s.env, &s.roster_addr, &b);
    let slot = seeded(&s, &d, 3);
    assert_eq!(s.mint.try_claim_position(&slot, &a, &b), Err(Ok(Error::PairNotRegistered)));
}

/// Registered in the request's own ledger is too late: the pair has to
/// predate the slot, and so the seed.
#[test]
fn a_pair_registered_with_the_request_cannot_claim_on_it() {
    let (s, d, _) = sel_setup(0);
    let a = Address::generate(&s.env);
    let b = Address::generate(&s.env);
    register_node(&s.env, &s.roster_addr, &a);
    register_node(&s.env, &s.roster_addr, &b);
    s.mint.register_pair(&a, &b);
    let slot = seeded(&s, &d, 3); // same ledger
    assert_eq!(s.mint.try_claim_position(&slot, &a, &b), Err(Ok(Error::PairNotRegistered)));
}

#[test]
fn an_address_is_in_at_most_one_pair() {
    let (s, _d, ps) = sel_setup(2);
    assert_eq!(
        s.mint.try_register_pair(&ps[0].node_a, &ps[1].node_b),
        Err(Ok(Error::AlreadyPaired))
    );
}

#[test]
fn registering_needs_the_roster_and_two_addresses() {
    let (s, _d, _) = sel_setup(0);
    let a = Address::generate(&s.env);
    let b = Address::generate(&s.env);
    register_node(&s.env, &s.roster_addr, &a);
    assert_eq!(s.mint.try_register_pair(&a, &b), Err(Ok(Error::NodeNotOnRoster)));
    assert_eq!(s.mint.try_register_pair(&a, &a), Err(Ok(Error::NodesNotDistinct)));
}

#[test]
fn registering_needs_both_signatures() {
    let (s, _d, _) = sel_setup(0);
    let a = Address::generate(&s.env);
    let b = Address::generate(&s.env);
    register_node(&s.env, &s.roster_addr, &a);
    register_node(&s.env, &s.roster_addr, &b);
    s.mint.register_pair(&a, &b);
    let signers: std::vec::Vec<Address> = s.env.auths().iter().map(|(x, _)| x.clone()).collect();
    assert!(signers.contains(&a) && signers.contains(&b));
}

/// Re-pairing is possible, and counts only from the next request on.
#[test]
fn unpairing_frees_both_addresses_for_later_prints_only() {
    let (s, d, ps) = sel_setup(2);
    let early = seeded(&s, &d, 3);
    // Either member dissolves it; the partner's record goes too.
    assert_eq!(s.mint.unpair(&ps[0].node_b), ps[0].node_a);
    assert!(s.mint.pair_of(&ps[0].node_a).is_none());
    assert_eq!(s.mint.try_unpair(&ps[0].node_a), Err(Ok(Error::NotPaired)));

    let c = Address::generate(&s.env);
    register_node(&s.env, &s.roster_addr, &c);
    s.mint.register_pair(&ps[0].node_a, &c);
    // Not on the slot requested before the new pair existed...
    assert_eq!(
        s.mint.try_claim_position(&early, &ps[0].node_a, &c),
        Err(Ok(Error::PairNotRegistered))
    );
    // ...and the old pair is gone from it too.
    assert_eq!(
        s.mint.try_claim_position(&early, &ps[0].node_a, &ps[0].node_b),
        Err(Ok(Error::PairNotRegistered))
    );
    // On a later one, the new pair claims.
    advance(&s.env, 1);
    let later = seeded(&s, &d, 3);
    s.mint.claim_position(&later, &ps[0].node_a, &c);
}

/// Once round `R` is public the draw is computable whether or
/// not anyone posted it, so cancelling an unseeded slot then is a re-roll
/// and pays.
#[test]
fn cancelling_after_the_round_is_out_forfeits_seeded_or_not() {
    let (s, d, _) = sel_setup(1);
    s.env.ledger().set_timestamp(fixture_time());
    let slot = s
        .mint
        .request_print(&d, &random_event_id(&s.env), &1000, &3, &own(&d), &own(&d));
    s.env
        .ledger()
        .set_timestamp(fixture_time() + BEACON_LEAD * BEACON_PERIOD);
    assert_eq!(s.mint.cancel_print(&d, &slot), 1000 - 20);
}

#[test]
fn cancelling_before_the_round_is_out_is_free() {
    let (s, d, _) = sel_setup(1);
    s.env.ledger().set_timestamp(fixture_time());
    let slot = s
        .mint
        .request_print(&d, &random_event_id(&s.env), &1000, &3, &own(&d), &own(&d));
    s.env
        .ledger()
        .set_timestamp(fixture_time() + BEACON_LEAD * BEACON_PERIOD - 1);
    assert_eq!(s.mint.cancel_print(&d, &slot), 1000);
}

/// The beacon stalled: a slot nobody could seed expires with a full refund
/// (section 7.6), even though its round's time has long passed.
#[test]
fn an_unseeded_slot_that_expires_refunds_in_full() {
    let s = setup_with_config(10, 3, 8, 50);
    let d = Address::generate(&s.env);
    mint_tokens(&s.pay_token, &d, 10_000);
    s.env.ledger().set_timestamp(fixture_time());
    let slot = s
        .mint
        .request_print(&d, &random_event_id(&s.env), &1000, &3, &own(&d), &own(&d));
    s.env.ledger().set_timestamp(fixture_time() + 3600);
    let created = s.mint.get_slot(&slot).unwrap().created_at;
    s.env.ledger().set_sequence_number(created + 51);
    assert_eq!(s.mint.clear_expired_slot(&slot), 1000);
}

/// The seed hashes the signature's bytes as submitted, so the
/// host must refuse every other encoding of the same point -- or the
/// poster could choose between seeds. Each flag bit, and each coordinate
/// with the field modulus added.
#[test]
fn no_other_encoding_of_the_signature_seeds() {
    /// BLS12-381's base field modulus, big-endian.
    const P: &str = "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab";
    fn add_p(x: &[u8]) -> std::vec::Vec<u8> {
        let p = unhex::<48>(P);
        let mut out = std::vec![0u8; 48];
        let mut carry = 0u16;
        for i in (0..48).rev() {
            let v = x[i] as u16 + p[i] as u16 + carry;
            out[i] = v as u8;
            carry = v >> 8;
        }
        assert_eq!(carry, 0);
        out
    }
    let sig = unhex::<96>(BEACON_SIG);
    let mut variants: std::vec::Vec<[u8; 96]> = std::vec::Vec::new();
    for bit in [0x80u8, 0x40, 0x20] {
        let mut v = sig;
        v[0] |= bit;
        variants.push(v);
    }
    for half in [0usize, 48] {
        let bumped = add_p(&sig[half..half + 48]);
        // Only meaningful if the result leaves the flag bits clear, which
        // is the encoding a careless parser would read as this point.
        assert_eq!(bumped[0] & 0xe0, 0, "x + p must fit under the flags to be a real test");
        let mut v = sig;
        v[half..half + 48].copy_from_slice(&bumped);
        variants.push(v);
    }
    for (i, v) in variants.iter().enumerate() {
        let (s, d, _) = sel_setup(1);
        s.env.ledger().set_timestamp(fixture_time());
        let slot = s
            .mint
            .request_print(&d, &random_event_id(&s.env), &1000, &3, &own(&d), &own(&d));
        assert!(
            s.mint.try_seed_print(&slot, &BytesN::from_array(&s.env, v)).is_err(),
            "encoding variant {i} seeded the slot"
        );
        assert!(s.mint.get_slot(&slot).unwrap().seed.is_none());
    }
}

/// The identity is in the subgroup, and under it every round
/// "verifies".
#[test]
fn the_identity_is_refused_as_the_beacon_key() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let (_t, token_addr) = create_token(&env, &admin);
    let roster = env.register(roster_contract::MockRoster, ());
    let mut identity = [0u8; 192];
    identity[0] = 0x40;
    let sel = SelectionConfig {
        beacon_pk: BytesN::from_array(&env, &identity),
        ..test_selection(&env)
    };
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        env.register(KenterMint, (10u32, 3u32, 5u32, &token_addr, &roster, 1000u32, sel));
    }));
    assert!(r.is_err());
}

#[test]
fn a_pair_registered_after_the_request_cannot_claim_on_it() {
    let (s, d, _) = sel_setup(0);
    let a = Address::generate(&s.env);
    let b = Address::generate(&s.env);
    register_node(&s.env, &s.roster_addr, &a);
    register_node(&s.env, &s.roster_addr, &b);
    let slot = seeded(&s, &d, 3);
    advance(&s.env, 1);
    s.mint.register_pair(&a, &b);
    assert_eq!(s.mint.try_claim_position(&slot, &a, &b), Err(Ok(Error::PairNotRegistered)));
}

/// The seed `seed_print` sets, recomputed from the documented formula, and
/// published as a vector so off-chain code (`kenter_client::selection_seed`)
/// is held to the same bytes: a daemon that derives the seed differently
/// from the mint seeds the wrong slots.
#[test]
fn the_seed_matches_its_published_vector() {
    use soroban_sdk::xdr::ToXdr;
    let (s, d, _) = sel_setup(0);
    let slot = seeded(&s, &d, 3);
    let got = s.mint.get_slot(&slot).unwrap().seed.unwrap();

    let mut m = Bytes::from_slice(&s.env, b"kenter:select:v1");
    m.append(&s.mint.address.clone().to_xdr(&s.env));
    m.extend_from_array(&slot.to_be_bytes());
    m.extend_from_array(&s.env.crypto().sha256(&Bytes::from_array(&s.env, &unhex::<96>(BEACON_SIG))).to_array());
    assert_eq!(got, s.env.crypto().sha256(&m).to_bytes());

    let addr = s.mint.address.to_string();
    let mut buf = [0u8; 56];
    addr.copy_into_slice(&mut buf);
    let hex: std::string::String = got.to_array().iter().map(|x| std::format!("{x:02x}")).collect();
    std::println!("SEED_VECTOR mint={} slot={slot} seed={hex}", std::str::from_utf8(&buf).unwrap());
    assert_eq!(std::str::from_utf8(&buf).unwrap(), "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAITA4");
    assert_eq!((slot, hex.as_str()), (0, "082624f288319fb4b4aee6f05d5d8cecbaa76623b2592c2a3c5c5a6e892b2950"));
}

/// What one claim adds to a slot, and how a claim's cost grows with the
/// list, for the contention margin a co-signed claim declares. Printed
/// for the record; the bound it feeds is asserted.
fn measure_claim_growth(use_wasm: bool) -> (u32, u64, u64) {
    use soroban_sdk::xdr::ToXdr;
    let s = setup_for(use_wasm, 10, 3, crate::MAX_REDEEMABLE_PAIRS, 1000);
    let d = Address::generate(&s.env);
    mint_tokens(&s.pay_token, &d, 100_000);
    let total = crate::MAX_REDEEMABLE_PAIRS;
    let k = total - 2;
    let mut ps = std::vec::Vec::new();
    for _ in 0..(2 * k) {
        let a = Address::generate(&s.env);
        let b = Address::generate(&s.env);
        register_node(&s.env, &s.roster_addr, &a);
        register_node(&s.env, &s.roster_addr, &b);
        s.mint.register_pair(&a, &b);
        ps.push(make_pair(&s.env, &a, &b));
    }
    advance(&s.env, 1);
    s.env.ledger().set_timestamp(fixture_time());
    let slot = s.mint.request_print(&d, &random_event_id(&s.env), &10_000, &total, &own(&d), &own(&d));
    s.mint.seed_print(&slot, &beacon_sig(&s.env));

    let before = s.mint.get_slot(&slot).unwrap().to_xdr(&s.env).len();
    let mut budget = s.env.cost_estimate().budget();
    budget.reset_unlimited();
    s.mint.claim_position(&slot, &ps[0].node_a, &ps[0].node_b);
    let first = s.env.cost_estimate().budget().cpu_instruction_cost();
    let after = s.mint.get_slot(&slot).unwrap().to_xdr(&s.env).len();
    let entry = after - before;

    for p in &ps[1..ps.len() - 1] {
        let _ = s.mint.try_claim_position(&slot, &p.node_a, &p.node_b);
    }
    let last = ps.last().unwrap();
    let mut budget = s.env.cost_estimate().budget();
    budget.reset_unlimited();
    let _ = s.mint.try_claim_position(&slot, &last.node_a, &last.node_b);
    let full = s.env.cost_estimate().budget().cpu_instruction_cost();
    (entry, first, full)
}

#[test]
fn a_claim_entry_and_its_growth_are_measured() {
    let (entry, first, full) = measure_claim_growth(false);
    std::println!("CLAIM_GROWTH native: entry {entry} bytes, claim into empty list {first}, into a full list {full}");
    // The client's margin (`kenter_client::tx::CLAIM_ENTRY_BYTES`, 300)
    // assumes an entry no larger than this; 260 measured.
    assert!(entry <= 300, "claim entry is {entry} bytes");
    // And no more than 40,000 instructions per entry already in the list
    // (`CLAIM_ENTRY_INSTRUCTIONS`); about 34,000 measured on the wasm.
    let per_entry = (full - first) / (2 * (crate::MAX_REDEEMABLE_PAIRS as u64 - 2) - 1);
    assert!(per_entry <= 40_000, "{per_entry} instructions per entry");
}

#[cfg(feature = "wasm-bench")]
#[test]
fn bench_claim_growth_wasm() {
    let (entry, first, full) = measure_claim_growth(true);
    std::println!("CLAIM_GROWTH wasm: entry {entry} bytes, claim into empty list {first}, into a full list {full}");
}

// -- The slot split --

/// The persistent half of a slot, as stored.
fn core_of(s: &TestSetup, slot: u32) -> Option<SlotCore> {
    s.env.as_contract(&s.mint.address, || {
        s.env.storage().persistent().get(&DataKey::Slot(slot))
    })
}

fn core_bytes(s: &TestSetup, slot: u32) -> u32 {
    use soroban_sdk::xdr::ToXdr;
    core_of(s, slot).unwrap().to_xdr(&s.env).len()
}

fn draw_exists(s: &TestSetup, slot: u32) -> bool {
    s.env.as_contract(&s.mint.address, || {
        s.env.storage().temporary().has(&DataKey::Draw(slot))
    })
}

/// What a protocol-23 auto-restore, or a keeper, does for a persistent
/// entry the test is about to outlive: keep the core readable while the
/// draw is left to lapse.
fn keep_core(s: &TestSetup, slot: u32, ledgers: u32) {
    s.env.as_contract(&s.mint.address, || {
        s.env
            .storage()
            .persistent()
            .extend_ttl(&DataKey::Slot(slot), ledgers, ledgers)
    });
}

/// **The point of the split.** Rent is charged on an entry's growth for
/// its whole remaining life, and on mainnet a persistent entry lives 120
/// days. So nothing after `request_print` may grow the persistent core:
/// not the seed, not a claim, not closing, not a link.
#[test]
fn the_slot_core_never_grows_after_the_request() {
    let s = setup_with_config(10, 3, 5, 1000);
    let d = Address::generate(&s.env);
    mint_tokens(&s.pay_token, &d, 10000);
    let mut interior = std::vec::Vec::new();
    for _ in 0..3 {
        let a = Address::generate(&s.env);
        let b = Address::generate(&s.env);
        register_node(&s.env, &s.roster_addr, &a);
        register_node(&s.env, &s.roster_addr, &b);
        s.mint.register_pair(&a, &b);
        interior.push(make_pair(&s.env, &a, &b));
    }
    advance(&s.env, 1);
    s.env.ledger().set_timestamp(fixture_time());
    let own = make_pair(&s.env, &d, &d);
    let slot = s.mint.request_print(&d, &random_event_id(&s.env), &1000, &4, &own, &own);
    let size = core_bytes(&s, slot);
    let mut sizes = std::vec![("request", size)];

    s.mint.seed_print(&slot, &beacon_sig(&s.env));
    sizes.push(("seed", core_bytes(&s, slot)));
    for p in &interior {
        s.mint.claim_position(&slot, &p.node_a, &p.node_b);
        sizes.push(("claim", core_bytes(&s, slot)));
    }
    advance(&s.env, CLAIM_WINDOW + 1);
    let chain = chain_order(&s, slot);
    for (i, p) in chain.iter().enumerate() {
        s.mint.confirm_link(&p.node_a, &slot, &(i as u32), &partial_key(&s.env, i as u8 + 1));
        sizes.push(("link", core_bytes(&s, slot)));
    }
    let sl = s.mint.get_slot(&slot).unwrap();
    assert!(sl.closed && sl.filled && sl.completed_links == 4 && !sl.lapsed);
    assert_eq!(sl.claims.len(), 1, "one runner-up kept in the draw");
    for (step, n) in &sizes {
        assert_eq!(*n, size, "the core grew at `{step}`: {sizes:?}");
    }
}

/// The draw is temporary storage, it exists while the slot does, and it
/// goes when the slot does.
#[test]
fn the_draw_is_temporary_and_goes_with_the_slot() {
    let s = setup();
    let d = Address::generate(&s.env);
    let na = Address::generate(&s.env);
    let nb = Address::generate(&s.env);
    mint_tokens(&s.pay_token, &d, 10000);
    register_node(&s.env, &s.roster_addr, &na);
    register_node(&s.env, &s.roster_addr, &nb);
    let mut pairs = Vec::new(&s.env);
    pairs.push_back(make_pair(&s.env, &d, &d));
    pairs.push_back(make_pair(&s.env, &na, &nb));
    pairs.push_back(make_pair(&s.env, &d, &d));
    let slot = s.mint.request_pairs(&d, &random_event_id(&s.env), &1000, &pairs);
    assert!(draw_exists(&s, slot) && core_of(&s, slot).is_some());
    s.mint.cancel_print(&d, &slot);
    assert!(!draw_exists(&s, slot), "the draw outlived its slot");
    assert!(core_of(&s, slot).is_none());

    // A registered note retires both as well.
    let (s, slot, _ek, _sk, _holder) = make_token(TokenMode::PureBearer, None);
    assert!(!draw_exists(&s, slot) && core_of(&s, slot).is_none());
}

/// Two identical abandoned prints, one settled while its draw is live and
/// one after it lapsed. **The depositor gets the same refund**, so letting
/// the draw lapse buys nothing; the confirmer's fee is burned instead of
/// credited, because the draw that named the confirmer is gone.
#[test]
fn a_lapsed_draw_settles_to_the_same_refund() {
    let settle = |lapse: bool| -> (i128, i128, bool) {
        let s = setup_with_config(10, 3, 5, 5);
        let d = Address::generate(&s.env);
        mint_tokens(&s.pay_token, &d, 10000);
        let mut pairs = Vec::new(&s.env);
        pairs.push_back(make_pair(&s.env, &d, &d));
        for _ in 0..2 {
            let a = Address::generate(&s.env);
            let b = Address::generate(&s.env);
            register_node(&s.env, &s.roster_addr, &a);
            register_node(&s.env, &s.roster_addr, &b);
            pairs.push_back(make_pair(&s.env, &a, &b));
        }
        pairs.push_back(make_pair(&s.env, &d, &d));
        let slot = s.mint.request_pairs(&d, &random_event_id(&s.env), &1000, &pairs);
        let chain = chain_order(&s, slot);
        s.mint.confirm_link(&d, &slot, &0, &partial_key(&s.env, 90));
        let confirmer = chain[1].node_a.clone();
        s.mint.confirm_link(&confirmer, &slot, &1, &partial_key(&s.env, 1));

        if lapse {
            keep_core(&s, slot, 100_000);
            advance(&s.env, 5 + 17_280 + 10);
            assert!(!draw_exists(&s, slot), "the draw should have lapsed");
            assert!(s.mint.get_slot(&slot).unwrap().lapsed);
        } else {
            advance(&s.env, 6);
        }
        let refund = s.mint.clear_expired_slot(&slot);
        let gone = core_of(&s, slot).is_none() && !draw_exists(&s, slot);
        (refund, s.mint.accrued_fees(&confirmer), gone)
    };
    let (live_refund, live_paid, live_gone) = settle(false);
    let (lapsed_refund, lapsed_paid, lapsed_gone) = settle(true);
    // One interior link paid (10), one position forfeited (2 * 10).
    assert_eq!(live_refund, 970);
    assert_eq!(lapsed_refund, live_refund, "a lapsed draw changed the refund");
    assert_eq!(live_paid, 10);
    assert_eq!(lapsed_paid, 0, "nobody left to pay: the fee is burned");
    assert!(live_gone && lapsed_gone);
}

/// A draw can lapse inside the window only when the window is longer than
/// the network's longest entry life. Every live call then refuses, and
/// cancel still settles.
#[test]
fn a_draw_lapsed_inside_the_window_refuses_and_still_cancels() {
    let s = setup_with_config(10, 3, 5, u32::MAX);
    s.env.ledger().set_max_entry_ttl(20_000);
    let d = Address::generate(&s.env);
    let na = Address::generate(&s.env);
    let nb = Address::generate(&s.env);
    mint_tokens(&s.pay_token, &d, 10000);
    register_node(&s.env, &s.roster_addr, &na);
    register_node(&s.env, &s.roster_addr, &nb);
    let mut pairs = Vec::new(&s.env);
    pairs.push_back(make_pair(&s.env, &d, &d));
    pairs.push_back(make_pair(&s.env, &na, &nb));
    pairs.push_back(make_pair(&s.env, &d, &d));
    let slot = s.mint.request_pairs(&d, &random_event_id(&s.env), &1000, &pairs);
    s.mint.confirm_link(&d, &slot, &0, &partial_key(&s.env, 90));
    s.mint.confirm_link(&na, &slot, &1, &partial_key(&s.env, 1));

    s.env.ledger().set_max_entry_ttl(1_000_000);
    keep_core(&s, slot, 500_000);
    advance(&s.env, 25_000);
    assert!(!s.mint.is_slot_expired(&slot), "still inside the window");
    assert!(!draw_exists(&s, slot));

    let sl = s.mint.get_slot(&slot).unwrap();
    assert!(sl.lapsed && sl.completed_links == 2 && sl.pairs.len() == 2);
    assert_eq!(
        s.mint.try_confirm_link(&d, &slot, &2, &partial_key(&s.env, 91)),
        Err(Ok(Error::DrawLapsed))
    );
    assert_eq!(s.mint.try_skip_position(&d, &slot), Err(Ok(Error::DrawLapsed)));
    assert_eq!(s.mint.cancel_print(&d, &slot), 990, "na's fee comes out of the refund...");
    assert_eq!(s.mint.accrued_fees(&na), 0, "...and is burned, not credited");
}

/// Extending the draw to a full window from each write would make a write
/// late in the window pay rent on the whole draw for every ledger since
/// the last one. Both entries live to one fixed end,
/// `created_at + max_print_ledgers + 1 day`, and a later write leaves
/// that end where it was.
#[test]
fn a_slot_lives_to_a_fixed_end_however_late_it_is_written() {
    use soroban_sdk::testutils::storage::{Persistent, Temporary};
    let s = setup_with_config(10, 3, 5, 1000);
    let d = Address::generate(&s.env);
    let na = Address::generate(&s.env);
    let nb = Address::generate(&s.env);
    mint_tokens(&s.pay_token, &d, 10000);
    register_node(&s.env, &s.roster_addr, &na);
    register_node(&s.env, &s.roster_addr, &nb);
    let mut pairs = Vec::new(&s.env);
    pairs.push_back(make_pair(&s.env, &d, &d));
    pairs.push_back(make_pair(&s.env, &na, &nb));
    pairs.push_back(make_pair(&s.env, &d, &d));
    let slot = s.mint.request_pairs(&d, &random_event_id(&s.env), &1000, &pairs);
    let end = s.mint.get_slot(&slot).unwrap().created_at + 1000 + 17_280;
    let live_until = |s: &TestSetup| {
        let now = s.env.ledger().sequence();
        s.env.as_contract(&s.mint.address, || {
            (
                now + s.env.storage().temporary().get_ttl(&DataKey::Draw(slot)),
                now + s.env.storage().persistent().get_ttl(&DataKey::Slot(slot)),
            )
        })
    };
    let (draw, _) = live_until(&s);
    assert_eq!(draw, end, "the draw does not end at the slot's fixed end");

    // A write well into the window moves neither end.
    advance(&s.env, 600);
    s.mint.confirm_link(&d, &slot, &0, &partial_key(&s.env, 90));
    s.mint.bump_token(&slot, &5_000);
    let (draw_after, core_after) = live_until(&s);
    assert_eq!(draw_after, end, "a late write re-extended the draw");
    assert!(core_after >= end, "the core ends before its draw");
}
