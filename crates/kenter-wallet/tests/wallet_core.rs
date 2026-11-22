//! Wallet-core behaviour: store round-trip, reconciliation, and balance math.
//! Uses a mock `ChainRead` and synthetic `HeldToken`s (real tokens require the
//! full mint flow; the import→verify round-trip is covered separately once a
//! token fixture is available).

use std::collections::HashMap;

/// Stands in for a recipient address's XDR. The redeem digest binds
/// the payout destination, so the tests have to name one.
const RECIPIENT: &[u8] = b"\x00\x00\x00\x12recipient";

use kenter_wallet::models::{BackupRecord, OnChainToken, PendingReceive, ReconciledToken};
use kenter_wallet::ports::{ChainRead, Store};
use kenter_wallet::{
    Balance, Gate, HeldToken, MemoryStore, TokenStatus, TokenWallet, WalletError,
    FIRST_FRESH_INDEX, STATIC_RECEIVE_INDEX, note_id,
};
use kenter_wallet::models::ReconciledToken as RT;

fn held(seed: u8, amount: u64) -> HeldToken {
    HeldToken {
        id: format!("G{seed:0>55}"),
        // One slot per seed, so two notes in a test are two records.
        slot_id: seed as u32,
        ephemeral_public_key: [seed; 32],
        event_id: [0u8; 32],
        amount,
        blob: vec![],
        imported_at: 0,
        // Bound: these fixtures stand for notes this wallet has already
        // seen confirmed. An unbound note is a separate case with its
        // own tests (a slot id alone does not say which mint confirmed it).
        mint: Some(MINT_A.to_string()),
        label: None,
        owner_index: None,
        owner_commitment: None,
        spent_away: false,
        exports: Default::default(),
        marked_spent: false,
    }
}

/// A ChainRead that returns canned statuses keyed by print slot.
struct MockChain {
    statuses: HashMap<u32, OnChainToken>,
    /// Which mint these answers are about. Slot ids restart at zero per
    /// deployment, so a test about two mints needs to say which is
    /// speaking.
    mint: String,
}

impl ChainRead for MockChain {
    async fn token_status(&self, slot_id: u32) -> kenter_wallet::Result<OnChainToken> {
        Ok(self
            .statuses
            .get(&slot_id)
            .copied()
            .unwrap_or(OnChainToken {
                chain_hash: None,
                status: TokenStatus::NotFound,
                amount: None,
                owner_commitment: None,
                spend_nonce: None,
                claim_pubkey: None,
                ephemeral_key: None,
                event_id: None,
                participants_len: None,
            }))
    }

    fn ledger_source(&self) -> String {
        "a test ledger".into()
    }

    fn mint_contract_xdr(&self) -> Vec<u8> {
        // Any stable value: these tests check what the digest is built from,
        // not which mint it names.
        b"test-mint".to_vec()
    }

    fn mint_id(&self) -> String {
        self.mint.clone()
    }
}

/// The mint every fixture speaks for unless it says otherwise.
const MINT_A: &str = "CMINTAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const MINT_B: &str = "CMINTBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

#[test]
fn balance_partitions_by_status() {
    let reconciled = vec![
        ReconciledToken { held: held(1, 100), status: TokenStatus::Active, on_chain_amount: Some(100) },
        ReconciledToken { held: held(2, 50), status: TokenStatus::Active, on_chain_amount: Some(50) },
        ReconciledToken { held: held(3, 25), status: TokenStatus::Redeemed, on_chain_amount: Some(25) },
        ReconciledToken { held: held(4, 7), status: TokenStatus::Unknown, on_chain_amount: None },
    ];
    let b = Balance::from_reconciled(&reconciled);
    assert_eq!(
        b,
        Balance {
            spendable: 150,
            redeemed: 25,
            unverified: 7,
            spent_away: 0,
            total_held: 182,
            disputed: 0,
        }
    );
}

#[test]
fn store_roundtrip() {
    pollster::block_on(async {
        let mut store = MemoryStore::new();
        store.put(held(1, 100)).await.unwrap();
        store.put(held(2, 200)).await.unwrap();

        assert_eq!(store.all().await.unwrap().len(), 2);
        assert_eq!(store.get(&held(1, 100).id).await.unwrap().unwrap().amount, 100);

        store.remove(&held(1, 100).id).await.unwrap();
        assert_eq!(store.all().await.unwrap().len(), 1);
        assert!(store.get(&held(1, 100).id).await.unwrap().is_none());
    });
}

#[test]
fn reconcile_and_balance() {
    pollster::block_on(async {
        let mut store = MemoryStore::new();
        store.put(held(1, 100)).await.unwrap();
        store.put(held(2, 40)).await.unwrap();
        store.put(held(3, 9)).await.unwrap(); // no chain entry → NotFound

        let mut statuses = HashMap::new();
        statuses.insert(1,
            OnChainToken { status: TokenStatus::Active, chain_hash: None, amount: Some(100), owner_commitment: None, spend_nonce: Some(0) , claim_pubkey: None, ephemeral_key: None, event_id: None, participants_len: None},
        );
        statuses.insert(2,
            OnChainToken { status: TokenStatus::Redeemed, chain_hash: None, amount: Some(40), owner_commitment: None, spend_nonce: Some(0) , claim_pubkey: None, ephemeral_key: None, event_id: None, participants_len: None},
        );
        let chain = MockChain { statuses, mint: MINT_A.to_string() };

        let mut wallet = TokenWallet::new(chain, store);
        let reconciled = wallet.reconcile().await.unwrap();
        assert_eq!(reconciled.len(), 3);

        let b = wallet.balance().await.unwrap();
        assert_eq!(b.spendable, 100);
        assert_eq!(b.redeemed, 40);
        assert_eq!(b.unverified, 9); // the NotFound token
        assert_eq!(b.total_held, 149);
    });
}

// ── Owner-key association (docs/architecture/custody.md) ──

fn empty_chain() -> MockChain {
    MockChain { statuses: HashMap::new(), mint: MINT_A.to_string() }
}

/// A chain holding one live note at `nonce`.
///
/// Owner authorizations need it: the digest covers the spend count the mint
/// currently holds, and the wallet reads that itself rather than taking it
/// from the caller, so a note the mint has never heard of cannot be signed
/// for at all.
fn chain_holding(slot_id: u32, nonce: u32) -> MockChain {
    let mut statuses = HashMap::new();
    statuses.insert(
        slot_id,
        OnChainToken {
            status: TokenStatus::Active,
            amount: Some(100),
            chain_hash: None,
            owner_commitment: None,
            spend_nonce: Some(nonce),
            claim_pubkey: None,
            ephemeral_key: None,
            event_id: None,
            participants_len: None,
        },
    );
    MockChain { statuses, mint: MINT_A.to_string() }
}

/// A receive reserves an index and records it *before* the payer is told the
/// commitment, so a crash mid-handshake cannot lose which index was promised.
#[test]
fn begin_receive_reserves_and_records() {
    pollster::block_on(async {
        let mut wallet = TokenWallet::new(empty_chain(), MemoryStore::new());

        let first = wallet.begin_receive([9u8; 32], 100).await.unwrap();
        assert_eq!(first.index, FIRST_FRESH_INDEX);
        assert_ne!(first.index, STATIC_RECEIVE_INDEX);
        assert_eq!(first.commitment, [9u8; 32]);

        let second = wallet.begin_receive([8u8; 32], 101).await.unwrap();
        assert_eq!(second.index, first.index + 1, "indices are never reused");

        let pending = wallet.pending().await.unwrap();
        assert_eq!(pending, vec![first, second]);
    });
}

/// Binding is the association the model rests on: the token records the index,
/// and the pending record that reserved it is consumed.
#[test]
fn bind_owner_sets_the_index_and_consumes_the_pending_record() {
    pollster::block_on(async {
        let mut store = MemoryStore::new();
        let t = held(1, 100);
        store.put(t.clone()).await.unwrap();
        let mut wallet = TokenWallet::new(empty_chain(), store);

        let p = wallet.begin_receive([3u8; 32], 5).await.unwrap();
        assert_eq!(wallet.pending().await.unwrap().len(), 1);

        let bound = wallet.bind_owner(&t.id, p.index).await.unwrap();
        assert_eq!(bound.owner_index, Some(p.index));

        // Survives a re-read, and the pending record is gone.
        let again = wallet.held().await.unwrap();
        assert_eq!(again[0].owner_index, Some(p.index));
        assert!(wallet.pending().await.unwrap().is_empty());
    });
}

#[test]
fn bind_owner_rejects_an_unheld_token() {
    pollster::block_on(async {
        let mut wallet = TokenWallet::new(empty_chain(), MemoryStore::new());
        let err = wallet.bind_owner("GNOPE", 1).await.unwrap_err();
        assert!(
            matches!(err, kenter_wallet::WalletError::NotHeld(_)),
            "got {err:?}"
        );
    });
}

/// An abandoned receive leaves a gap, which is the intended trade.
#[test]
fn an_abandoned_receive_burns_its_index() {
    pollster::block_on(async {
        let mut wallet = TokenWallet::new(empty_chain(), MemoryStore::new());
        let abandoned = wallet.begin_receive([1u8; 32], 1).await.unwrap();
        wallet.record_pending(abandoned.clone()).await.unwrap();

        let next = wallet.reserve_owner_index().await.unwrap();
        assert_eq!(next, abandoned.index + 1, "the burnt index is not handed out again");
    });
}

/// Imported tokens are unowned until bound - a pure-bearer token, or someone
/// else's, must not look like ours.
#[test]
fn a_freshly_stored_token_has_no_owner_index() {
    pollster::block_on(async {
        let mut store = MemoryStore::new();
        store.put(held(2, 10)).await.unwrap();
        let mut wallet = TokenWallet::new(empty_chain(), store);
        assert_eq!(wallet.held().await.unwrap()[0].owner_index, None);
    });
}

// ── Receive gates G1–G4 (docs/architecture/spend-mode.md) ──
//
// These mint real tokens with kenter-crypto rather than synthesising HeldTokens,
// because G1 is a genuine structural check — a fake would prove nothing about it.

use kenter_crypto::container::serialize_bearer_token;
use kenter_crypto::container::deserialize_bearer_token;
use kenter_crypto::keypair::StellarKeypair;
use kenter_crypto::spend::owner_commitment;
use kenter_crypto::token::{assemble_bearer_token, PartialToken};
use kenter_vault::{DerivingVault, Result as VaultResult};

/// A deterministic stand-in for a real `DerivingVault`: index → keypair.
struct MockVault {
    credential: Vec<u8>,
}

impl MockVault {
    fn new() -> Self {
        MockVault { credential: b"pass".to_vec() }
    }
    fn keypair(&self, index: u32) -> StellarKeypair {
        let mut secret = [0u8; 32];
        secret[..4].copy_from_slice(&index.to_be_bytes());
        secret[31] = 0x5a;
        StellarKeypair::from_raw_secret(&secret)
    }
}

impl DerivingVault for MockVault {
    fn derive_public(&mut self, index: u32, credential: &[u8]) -> VaultResult<[u8; 32]> {
        assert_eq!(credential, self.credential, "credential must reach the vault");
        Ok(self.keypair(index).raw_public())
    }
    fn sign_derived(
        &mut self,
        index: u32,
        message: &[u8],
        credential: &[u8],
    ) -> VaultResult<[u8; 64]> {
        assert_eq!(credential, self.credential);
        Ok(self.keypair(index).sign(message).to_bytes())
    }
}

/// Mint a real bearer token in-process; returns its container bytes, ephemeral
/// key and denomination.
fn mint_bytes(denom: u64) -> (Vec<u8>, u32, u64) {
    static NEXT_SLOT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);
    let slot_id = NEXT_SLOT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let event_id = [3u8; 32];
    let requestor = StellarKeypair::random();
    let (a, b) = (StellarKeypair::random(), StellarKeypair::random());
    let (partial, _shard) =
        PartialToken::initiate(event_id, 1_700_000_000, Some(denom), 2, &a, &b, vec![]).unwrap();
    let partner = StellarKeypair::random();
    let token =
        assemble_bearer_token(&partial, &requestor, &partner, slot_id, None).unwrap();
    let bytes = serialize_bearer_token(&token, &requestor).unwrap();
    (bytes, slot_id, denom)
}

fn chain_with(slot_id: u32, t: OnChainToken) -> MockChain {
    let mut statuses = HashMap::new();
    statuses.insert(slot_id, t);
    MockChain { statuses, mint: MINT_A.to_string() }
}

const PASS: &[u8] = b"pass";

/// Assert a gate rejection, including whether waiting could change the answer.
/// The retry flag is the one a polling client branches on, so it is worth
/// pinning: getting it wrong either abandons a payment about to settle or waits
/// forever on one that never will.
#[track_caller]
fn assert_gate(err: &WalletError, want_gate: Gate, want_retryable: bool) {
    match err {
        WalletError::ReceiveGate { gate, retryable, detail } => {
            assert_eq!(*gate, want_gate, "wrong gate ({detail})");
            assert_eq!(*retryable, want_retryable, "wrong retryable ({detail})");
        }
        other => panic!("expected a gate failure, got {other:?}"),
    }
}

#[test]
fn start_receive_derives_the_commitment_and_records_it_first() {
    pollster::block_on(async {
        let mut w = TokenWallet::with_vault(empty_chain(), MemoryStore::new(), MockVault::new());
        let p = w.start_receive(PASS, 42).await.unwrap();

        assert_eq!(p.index, FIRST_FRESH_INDEX);
        assert_ne!(p.index, STATIC_RECEIVE_INDEX);
        assert_eq!(p.created_at, 42);
        // The commitment is the one a payer would spend to for this index.
        assert_eq!(p.commitment, w.owner_commitment_for(p.index, PASS).unwrap());
        // Recorded before anyone could have been shown it.
        assert_eq!(w.pending().await.unwrap(), vec![p]);
    });
}

/// The chain commitment the mint would have recorded for this container.
///
/// G2 compares the ledger's record against the chain actually in hand, so a
/// fixture that wants a receive to succeed has to agree with itself.
/// A counterfeit in the billfold is not shown as money.
///
/// `import` verifies a container offline and stores it — deliberately,
/// so a note can be taken now and checked later. Reconciliation must then
/// stop it displaying as Active at the ledger's amount, which is the one
/// number an attacker controls. The receive gates catch a forgery; the
/// CLI's `import` does not go through them.
#[test]
fn reconcile_refuses_to_call_a_counterfeit_live() {
    pollster::block_on(async {
        let (bytes, slot, denom) = mint_bytes(7_000);

        // The ledger has a live record for this slot, and it committed
        // to a different chain.
        let chain = chain_with(
            slot,
            OnChainToken {
                status: TokenStatus::Active,
                amount: Some(denom as i128),
                chain_hash: Some([0xAB; 32]),
                owner_commitment: None,
                spend_nonce: Some(0),
                claim_pubkey: None,
                ephemeral_key: None,
                event_id: None,
                participants_len: None,
            },
        );
        let mut w = TokenWallet::new(chain, MemoryStore::new());
        w.import(bytes, 1).await.expect("import verifies offline and stores");

        let r = w.reconcile().await.unwrap();
        assert_eq!(r[0].status, TokenStatus::Counterfeit);
        assert_eq!(
            w.balance().await.unwrap().spendable,
            0,
            "a note the ledger does not describe is not spendable"
        );
    });
}

/// A pure-bearer note whose claim key is not the
/// registered one is a note its holder cannot redeem.
///
/// The container is self-signed by whoever assembled it, so a payer can
/// hand over the real chain with a claim secret they kept. Every other
/// check passes: the chain is genuine, the escrow is real and live.
#[test]
fn reconcile_catches_a_swapped_claim_key() {
    pollster::block_on(async {
        let (bytes, slot, denom) = mint_bytes(7_000);
        let real_hash = chain_hash_of(&bytes);

        let chain = chain_with(
            slot,
            OnChainToken {
                status: TokenStatus::Active,
                amount: Some(denom as i128),
                // The genuine chain...
                chain_hash: Some(real_hash),
                owner_commitment: None,
                // ...registered against a claim key this container does
                // not hold the secret for.
                claim_pubkey: Some([0xCD; 32]),
                ephemeral_key: Some(key_of(&bytes)),
                event_id: shape_of(&bytes).0,
                participants_len: shape_of(&bytes).1,
                spend_nonce: Some(0),
            },
        );
        let mut w = TokenWallet::new(chain, MemoryStore::new());
        w.import(bytes, 1).await.expect("the container itself is valid");

        let r = w.reconcile().await.unwrap();
        assert_eq!(
            r[0].status,
            TokenStatus::Counterfeit,
            "the chain is real but the holder cannot redeem it"
        );
    });
}

/// And a genuine note still reconciles as live, so the check costs an
/// honest holder nothing.
#[test]
fn reconcile_still_calls_a_genuine_note_live() {
    pollster::block_on(async {
        let (bytes, slot, denom) = mint_bytes(7_000);
        let token =
            kenter_crypto::container::deserialize_bearer_token(&bytes).unwrap();

        let chain = chain_with(
            slot,
            OnChainToken {
                status: TokenStatus::Active,
                amount: Some(denom as i128),
                chain_hash: Some(chain_hash_of(&bytes)),
                owner_commitment: None,
                claim_pubkey: Some(token.claim_public_key()),
                ephemeral_key: Some(token.ephemeral_public_key),
                event_id: Some(token.header.event_id),
                participants_len: Some((token.chain.links.len() * 2) as u32),
                spend_nonce: Some(0),
            },
        );
        let mut w = TokenWallet::new(chain, MemoryStore::new());
        w.import(bytes, 1).await.unwrap();

        let r = w.reconcile().await.unwrap();
        assert_eq!(r[0].status, TokenStatus::Active);
        assert_eq!(w.balance().await.unwrap().spendable, denom);
    });
}

/// A record naming someone else's ephemeral key is not this note's record.
///
/// Records are keyed by slot, not by ephemeral key, so the two do not agree
/// by construction: the key is just another field the depositor chose — so a payer can register the
/// note's real chain hash and real claim key beside a *different*
/// ephemeral key. Every other check passes.
///
/// Nothing is stolen: the payee can still redeem by chain. What they lose
/// is Path A, the route that needs no node network, and they lose it
/// silently. Reconciliation says so instead.
#[test]
fn reconcile_catches_a_record_naming_another_key() {
    pollster::block_on(async {
        let (bytes, slot, denom) = mint_bytes(7_000);
        let token =
            kenter_crypto::container::deserialize_bearer_token(&bytes).unwrap();

        let chain = chain_with(
            slot,
            OnChainToken {
                status: TokenStatus::Active,
                amount: Some(denom as i128),
                // Genuine chain, genuine claim key...
                chain_hash: Some(chain_hash_of(&bytes)),
                owner_commitment: None,
                claim_pubkey: Some(token.claim_public_key()),
                // ...and a key that is not this note's.
                ephemeral_key: Some([0x11; 32]),
                event_id: shape_of(&bytes).0,
                participants_len: shape_of(&bytes).1,
                spend_nonce: Some(0),
            },
        );
        let mut w = TokenWallet::new(chain, MemoryStore::new());
        w.import(bytes, 1).await.expect("the container itself is valid");

        let r = w.reconcile().await.unwrap();
        assert_eq!(
            r[0].status,
            TokenStatus::Counterfeit,
            "the record does not describe this note, so Path A is gone"
        );
    });
}

/// Two containers for one print: same chain, same ephemeral key, and
/// therefore the same wallet id — but different claim keys.
///
/// This is the shape a payer can hand over: the claim key is generated
/// inside `assemble_bearer_token`, so assembling the same partial twice
/// produces two containers that are identical where it is checked and
/// differ where it matters. Only the one whose claim key the mint
/// registered can be redeemed.
fn mint_twins(denom: u64) -> (Vec<u8>, Vec<u8>, u32, u64) {
    static NEXT_SLOT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(9_000);
    let slot_id = NEXT_SLOT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let event_id = [5u8; 32];
    let requestor = StellarKeypair::random();
    let (a, b) = (StellarKeypair::random(), StellarKeypair::random());
    let (partial, _shard) =
        PartialToken::initiate(event_id, 1_700_000_000, Some(denom), 2, &a, &b, vec![]).unwrap();
    let partner = StellarKeypair::random();

    let real = assemble_bearer_token(&partial, &requestor, &partner, slot_id, None).unwrap();
    let decoy = assemble_bearer_token(&partial, &requestor, &partner, slot_id, None).unwrap();
    assert_eq!(
        real.ephemeral_public_key, decoy.ephemeral_public_key,
        "same chain, so the same id"
    );
    assert_ne!(
        real.claim_public_key(),
        decoy.claim_public_key(),
        "and a different claim key, which is the whole difference"
    );
    (
        serialize_bearer_token(&real, &requestor).unwrap(),
        serialize_bearer_token(&decoy, &requestor).unwrap(),
        slot_id,
        denom,
    )
}

/// The ledger as it would be for the genuine twin.
fn chain_for(slot: u32, bytes: &[u8], denom: u64) -> MockChain {
    let token = kenter_crypto::container::deserialize_bearer_token(bytes).unwrap();
    chain_with(
        slot,
        OnChainToken {
            status: TokenStatus::Active,
            amount: Some(denom as i128),
            chain_hash: Some(chain_hash_of(bytes)),
            owner_commitment: None,
            claim_pubkey: Some(token.claim_public_key()),
            ephemeral_key: Some(token.ephemeral_public_key),
            event_id: Some(token.header.event_id),
            participants_len: Some((token.chain.links.len() * 2) as u32),
            spend_nonce: Some(0),
        },
    )
}

/// A copy that arrives first does not lock the real payment out.
///
/// If dedup were "first wins" on the ephemeral address, a payer who handed
/// over a container with a claim key they kept (the swapped-claim-key case
/// above) could get it into the payee's wallet and have the genuine
/// note refused as a duplicate afterwards. Nothing is stolen; the payee
/// simply cannot take delivery of their own money.
#[test]
fn a_copy_that_arrives_first_does_not_block_the_genuine_note() {
    pollster::block_on(async {
        let (real, decoy, slot, denom) = mint_twins(7_000);
        let mut w = TokenWallet::new(chain_for(slot, &real, denom), MemoryStore::new());

        // The decoy lands first. `import` is offline by design, so
        // nothing has contradicted it yet.
        w.import(decoy, 1).await.expect("the decoy is a valid container");

        let got = w.import(real.clone(), 2).await.expect("the genuine note is taken");
        assert_eq!(got.blob, real, "the wallet kept the note the ledger describes");

        let held = w.held().await.unwrap();
        assert_eq!(held.len(), 1, "one note, not two");
        assert_eq!(held[0].blob, real);
    });
}

/// And a copy arriving *second* does not displace the real note.
#[test]
fn a_copy_arriving_second_is_refused() {
    pollster::block_on(async {
        let (real, decoy, slot, denom) = mint_twins(7_000);
        let mut w = TokenWallet::new(chain_for(slot, &real, denom), MemoryStore::new());

        w.import(real.clone(), 1).await.unwrap();
        assert!(w.import(decoy, 2).await.is_err(), "the copy must not win");
        assert_eq!(w.held().await.unwrap()[0].blob, real);
    });
}

/// The same bytes twice is still a duplicate. There is nothing to choose
/// between them, and the holder should hear that they already have it.
#[test]
fn importing_the_same_bytes_twice_is_still_refused() {
    pollster::block_on(async {
        let (real, _decoy, slot, denom) = mint_twins(7_000);
        let mut w = TokenWallet::new(chain_for(slot, &real, denom), MemoryStore::new());

        w.import(real.clone(), 1).await.unwrap();
        assert!(matches!(
            w.import(real, 2).await,
            Err(kenter_wallet::WalletError::Duplicate(_))
        ));
        assert_eq!(w.held().await.unwrap().len(), 1);
    });
}

/// The ephemeral key a container actually carries.
/// The claim key a fixture container actually carries.
fn claim_of(bytes: &[u8]) -> [u8; 32] {
    deserialize_bearer_token(bytes)
        .expect("fixture container")
        .claim_public_key()
}

fn key_of(bytes: &[u8]) -> [u8; 32] {
    kenter_crypto::container::deserialize_bearer_token(bytes)
        .unwrap()
        .ephemeral_public_key
}

/// What the mint's record says about a genuine chain's shape: its event
/// id, and twice its link count.
///
/// `verify_chain` checks both, so a fixture leaving them `None` describes
/// a note the contract would refuse -- which is the point of the gate
/// these feed (a note whose chain the contract will never verify), and not what most of these tests are about.
fn shape_of(bytes: &[u8]) -> (Option<[u8; 32]>, Option<u32>) {
    let t = deserialize_bearer_token(bytes).expect("fixture container");
    (
        Some(t.header.event_id),
        Some((t.chain.links.len() * 2) as u32),
    )
}

fn chain_hash_of(bytes: &[u8]) -> [u8; 32] {
    let t = deserialize_bearer_token(bytes).expect("fixture container");
    kenter_crypto::chain_data::token_chain_hash(&t).expect("fixture chain hash")
}

/// A note registered under another slot naming the same
/// ephemeral key -- which anyone can do, the key being public once a print
/// completes -- arrives first. The genuine note must still be taken: on the
/// mint they are two records, so in the wallet they are two rows.
#[test]
fn a_decoy_on_another_slot_does_not_block_the_real_note() {
    pollster::block_on(async {
        let (bytes, slot, denom) = mint_bytes(5_000);
        let vault = MockVault::new();
        let commitment = owner_commitment(&vault.keypair(FIRST_FRESH_INDEX).raw_public());
        let chain = chain_with(
            slot,
            OnChainToken {
                chain_hash: Some(chain_hash_of(&bytes)),
                status: TokenStatus::Active,
                amount: Some(denom as i128),
                owner_commitment: Some(commitment),
                spend_nonce: Some(0),
                claim_pubkey: None,
                ephemeral_key: Some(key_of(&bytes)),
                event_id: shape_of(&bytes).0,
                participants_len: shape_of(&bytes).1,
            },
        );
        // Already held: the decoy, same key, its own slot.
        let decoy = held_from(&bytes, slot + 7, 1);
        let mut store = MemoryStore::new();
        store.put(decoy.clone()).await.unwrap();

        let mut w = TokenWallet::with_vault(chain, store, vault);
        w.start_receive(PASS, 3).await.unwrap();
        let real = w
            .complete_receive(bytes, 4)
            .await
            .expect("the real note is not a duplicate of a decoy on another slot");

        assert_eq!(real.slot_id, slot);
        assert_ne!(real.id, decoy.id, "one key, two slots, two ids");
        assert_eq!(w.held().await.unwrap().len(), 2, "both rows kept");
    });
}

/// A note paid away and paid back can be received again.
///
/// If `complete_receive` refused any id the store already knew, including
/// one marked `spent_away`, a note that came back — as change, as a
/// refund, or because the person you paid paid you — would be rejected on
/// the strength of the wallet's own stale bookkeeping, and the value
/// stranded: `sync` will not re-bind a note it believes was given
/// away.
///
/// The gates have already proved the ledger says it is ours again, at
/// an index this wallet owns. That is a better authority than the
/// record.
#[test]
fn a_note_paid_away_can_be_received_back() {
    pollster::block_on(async {
        let (bytes, slot, denom) = mint_bytes(5_000);
        let vault = MockVault::new();
        let commitment = owner_commitment(&vault.keypair(FIRST_FRESH_INDEX).raw_public());
        let chain = chain_with(
            slot,
            OnChainToken {
                chain_hash: Some(chain_hash_of(&bytes)),
                status: TokenStatus::Active,
                amount: Some(denom as i128),
                owner_commitment: Some(commitment),
                spend_nonce: Some(0),
                claim_pubkey: None,
                ephemeral_key: Some(key_of(&bytes)),
                event_id: shape_of(&bytes).0,
                participants_len: shape_of(&bytes).1,
            },
        );
        // The wallet already holds this note, marked as paid away --
        // which is what `verify_ownership` writes when the ledger shows
        // it moved to someone else.
        let token = kenter_crypto::container::deserialize_bearer_token(&bytes).unwrap();
        let mut gone = held(1, denom);
        gone.id = note_id(&token.ephemeral_address(), slot);
        gone.slot_id = slot;
        gone.ephemeral_public_key = token.ephemeral_public_key;
        gone.blob = bytes.clone();
        gone.spent_away = true;
        let mut store = MemoryStore::new();
        store.put(gone).await.unwrap();

        let mut w = TokenWallet::with_vault(chain, store, vault);
        assert_eq!(
            w.balance().await.unwrap().spendable,
            0,
            "paid away, so not money"
        );

        // It comes back. The ledger says it is ours again, so the only
        // thing refusing it was our own note-to-self that we had spent
        // it.
        w.start_receive(PASS, 3).await.unwrap();
        let again = w
            .complete_receive(bytes, 4)
            .await
            .expect("a note that came back is still a payment");

        assert!(!again.spent_away, "the record describes the new ownership");
        assert_eq!(again.amount, denom);
        assert_eq!(w.held().await.unwrap().len(), 1, "one note, rebound");
        assert_eq!(
            w.balance().await.unwrap().spendable,
            denom,
            "and it counts as money again"
        );
    });
}

#[test]
fn complete_receive_binds_the_index_and_consumes_the_pending_record() {
    pollster::block_on(async {
        let (bytes, slot, denom) = mint_bytes(5_000);
        let vault = MockVault::new();
        let commitment = owner_commitment(&vault.keypair(FIRST_FRESH_INDEX).raw_public());
        let chain = chain_with(
            slot,
            OnChainToken {
                chain_hash: Some(chain_hash_of(&bytes)),
                status: TokenStatus::Active,
                amount: Some(denom as i128),
                owner_commitment: Some(commitment),
                spend_nonce: Some(0),
                claim_pubkey: None,
                ephemeral_key: Some(key_of(&bytes)),
                event_id: shape_of(&bytes).0,
                participants_len: shape_of(&bytes).1,
            },
        );
        let mut w = TokenWallet::with_vault(chain, MemoryStore::new(), vault);

        let p = w.start_receive(PASS, 1).await.unwrap();
        let held = w.complete_receive(bytes, 2).await.unwrap();

        assert_eq!(held.owner_index, Some(p.index));
        assert_eq!(held.amount, denom);
        assert_eq!(w.held().await.unwrap().len(), 1);
        assert!(w.pending().await.unwrap().is_empty(), "pending record consumed");
    });
}

/// A pay tag is good for one payment, but handing it to two payers is the
/// ordinary mistake, and the second payment is still theirs-to-us. The first
/// consumes the pending record; the commitment survives on the bound token,
/// which is the whole point of matching against every index we can open.
#[test]
fn a_note_paid_to_an_index_already_used_is_still_ours() {
    pollster::block_on(async {
        let (first_bytes, first_slot, denom) = mint_bytes(5_000);
        let (second_bytes, second_slot, _) = mint_bytes(5_000);
        let vault = MockVault::new();
        let commitment = owner_commitment(&vault.keypair(FIRST_FRESH_INDEX).raw_public());
        // A record each, because a record now names the chain it was
        // registered with and these are two different notes. One shared
        // record would describe at most one of them.
        let paid = |bytes: &[u8]| OnChainToken {
            status: TokenStatus::Active,
            amount: Some(denom as i128),
            chain_hash: Some(chain_hash_of(bytes)),
            owner_commitment: Some(commitment),
            spend_nonce: Some(0),
            claim_pubkey: None,
            ephemeral_key: Some(key_of(bytes)),
            event_id: shape_of(bytes).0,
            participants_len: shape_of(bytes).1,
        };
        let mut statuses = HashMap::new();
        statuses.insert(first_slot, paid(&first_bytes));
        statuses.insert(second_slot, paid(&second_bytes));
        let mut w = TokenWallet::with_vault(MockChain { statuses, mint: MINT_A.to_string() }, MemoryStore::new(), vault);

        let p = w.start_receive(PASS, 1).await.unwrap();
        w.complete_receive(first_bytes, 2).await.unwrap();
        assert!(w.pending().await.unwrap().is_empty(), "the tag was used up");

        // Nothing is pending now, so a rule that matched only pending
        // records would refuse this.
        let held = w.complete_receive(second_bytes, 3).await.unwrap();
        assert_eq!(held.owner_index, Some(p.index));
        assert_eq!(w.held().await.unwrap().len(), 2);
    });
}

/// A note whose chain the contract will never accept is refused at
/// receive, not at redemption.
///
/// `verify_chain` checks three things about the chain behind
/// `chain_hash`: that it hashes to the commitment, that its event id
/// equals the record's, and that its link count equals
/// `participants / 2`. The client must gate all three.
///
/// If it gated only the first, a payer could register a chain signed by their own sybil keys
/// carrying the wrong event id, or one link too many, hand the note
/// over, and watch every gate pass. Path B then returns error 44
/// forever, and Path A needs the ephemeral secret only the payer can
/// compose. The payer burns the full face value doing it -- sabotage,
/// not theft -- but the payee has taken a note that pays nothing in
/// exchange for something real.
#[test]
fn a_chain_the_contract_would_refuse_is_refused_at_receive() {
    pollster::block_on(async {
        let (bytes, slot, denom) = mint_bytes(5_000);
        let vault = MockVault::new();
        let commitment = owner_commitment(&vault.keypair(STATIC_RECEIVE_INDEX).raw_public());
        let (good_event, good_len) = shape_of(&bytes);

        // Right hash, wrong event id.
        let wrong_event = chain_with(
            slot,
            OnChainToken {
                status: TokenStatus::Active,
                amount: Some(denom as i128),
                chain_hash: Some(chain_hash_of(&bytes)),
                owner_commitment: Some(commitment),
                claim_pubkey: Some(claim_of(&bytes)),
                ephemeral_key: Some(key_of(&bytes)),
                event_id: Some([0x77; 32]),
                participants_len: good_len,
                spend_nonce: Some(0),
            },
        );
        let mut w = TokenWallet::with_vault(wrong_event, MemoryStore::new(), MockVault::new());
        w.start_receive(PASS, 1).await.unwrap();
        let err = w
            .complete_receive(bytes.clone(), 2)
            .await
            .expect_err("a chain with the wrong event id pays nothing");
        assert!(
            format!("{err:?}").contains("event id"),
            "refused for the wrong reason: {err:?}"
        );

        // Right hash and event id, wrong number of participants.
        let wrong_count = chain_with(
            slot,
            OnChainToken {
                status: TokenStatus::Active,
                amount: Some(denom as i128),
                chain_hash: Some(chain_hash_of(&bytes)),
                owner_commitment: Some(commitment),
                claim_pubkey: Some(claim_of(&bytes)),
                ephemeral_key: Some(key_of(&bytes)),
                event_id: good_event,
                participants_len: good_len.map(|n| n + 2),
                spend_nonce: Some(0),
            },
        );
        let mut w = TokenWallet::with_vault(wrong_count, MemoryStore::new(), vault);
        w.start_receive(PASS, 1).await.unwrap();
        let err = w
            .complete_receive(bytes, 2)
            .await
            .expect_err("a chain with the wrong link count pays nothing");
        assert!(
            format!("{err:?}").contains("links"),
            "refused for the wrong reason: {err:?}"
        );
    });
}

/// The standing tag (the reusable receive address at index 0) is published ahead of the payer and
/// meant to be used more than once, so being paid must not retire it. The
/// rotating tags are one-shot and must still be consumed.
#[test]
fn being_paid_on_the_standing_tag_does_not_retire_it() {
    pollster::block_on(async {
        let (bytes, slot, denom) = mint_bytes(5_000);
        let vault = MockVault::new();
        let commitment = owner_commitment(&vault.keypair(STATIC_RECEIVE_INDEX).raw_public());
        let chain = chain_with(
            slot,
            OnChainToken {
                chain_hash: Some(chain_hash_of(&bytes)),
                status: TokenStatus::Active,
                amount: Some(denom as i128),
                owner_commitment: Some(commitment),
                spend_nonce: Some(0),
                claim_pubkey: None,
                ephemeral_key: Some(key_of(&bytes)),
                event_id: shape_of(&bytes).0,
                participants_len: shape_of(&bytes).1,
            },
        );
        let mut w = TokenWallet::with_vault(chain, MemoryStore::new(), vault);
        w.record_pending(kenter_wallet::PendingReceive {
            index: STATIC_RECEIVE_INDEX,
            commitment,
            created_at: 1,
        })
        .await
        .unwrap();

        let held = w.complete_receive(bytes, 2).await.unwrap();
        assert_eq!(held.owner_index, Some(STATIC_RECEIVE_INDEX));
        let left = w.pending().await.unwrap();
        assert_eq!(left.len(), 1, "the published address stopped being watched");
        assert_eq!(left[0].index, STATIC_RECEIVE_INDEX);
    });
}

/// G1: bytes that are not a valid token must be refused before any chain read.
#[test]
fn g1_rejects_malformed_bytes() {
    pollster::block_on(async {
        let mut w = TokenWallet::with_vault(empty_chain(), MemoryStore::new(), MockVault::new());
        let _p = w.start_receive(PASS, 1).await.unwrap();
        let err = w.complete_receive(b"not a token".to_vec(), 2).await.unwrap_err();
        // Malformed bytes never become well-formed.
        assert_gate(&err, Gate::Structure, false);
    });
}

/// G2: the ledger must say Active. A token with no on-chain record is not paid.
#[test]
fn g2_rejects_a_token_that_is_not_active() {
    pollster::block_on(async {
        let (bytes, _slot, _d) = mint_bytes(5_000);
        let mut w = TokenWallet::with_vault(empty_chain(), MemoryStore::new(), MockVault::new());
        let _p = w.start_receive(PASS, 1).await.unwrap();
        let err = w.complete_receive(bytes, 2).await.unwrap_err();
        // No record yet may just mean the payer's spend has not landed.
        assert_gate(&err, Gate::Ledger, true);
    });
}

/// G2 must compare the ledger's chain commitment with the chain actually in
/// hand.
///
/// Everything else a payee checks can be reconstructed from public ledger
/// data. `confirm_link` publishes each partial public key and they sum to the
/// ephemeral key, so somebody holding no note at all can build a container
/// that verifies structurally and names a real, live, correctly-valued
/// escrow — and hand it out as payment. It would show as received and only
/// fail at redemption, by which point the goods are gone.
///
/// The commitment is the one thing they cannot produce: the full links are
/// never published, only their 32-byte public parts, and the mint recorded
/// the digest of the real ones.
#[test]
fn g2_rejects_a_note_whose_chain_the_ledger_never_registered() {
    pollster::block_on(async {
        let (bytes, slot, denom) = mint_bytes(5_000);
        let (other_bytes, _, _) = mint_bytes(5_000);
        let vault = MockVault::new();
        let commitment = owner_commitment(&vault.keypair(FIRST_FRESH_INDEX).raw_public());

        // A convincing record: right key, Active, right amount, and an owner
        // commitment this wallet can open. Only the chain differs.
        let chain = chain_with(
            slot,
            OnChainToken {
                status: TokenStatus::Active,
                amount: Some(denom as i128),
                chain_hash: Some(chain_hash_of(&other_bytes)),
                owner_commitment: Some(commitment),
                spend_nonce: Some(0),
                claim_pubkey: None,
                ephemeral_key: Some(key_of(&other_bytes)),
                event_id: None,
                participants_len: None,
            },
        );
        let mut w = TokenWallet::with_vault(chain, MemoryStore::new(), vault);
        let _p = w.start_receive(PASS, 1).await.unwrap();

        let err = w.complete_receive(bytes, 2).await.unwrap_err();
        // Never retryable: the ledger will not change which chain it recorded.
        assert_gate(&err, Gate::Ledger, false);
        assert!(w.held().await.unwrap().is_empty(), "the forgery was stored");
    });
}

/// A record this build cannot check is refused rather than trusted.
///
/// Accepting an uncheckable record would restore exactly the hole the
/// commitment comparison exists to close, so the conservative read is the
/// safe one.
#[test]
fn g2_rejects_a_record_with_no_chain_commitment() {
    pollster::block_on(async {
        let (bytes, slot, denom) = mint_bytes(5_000);
        let vault = MockVault::new();
        let commitment = owner_commitment(&vault.keypair(FIRST_FRESH_INDEX).raw_public());
        let chain = chain_with(
            slot,
            OnChainToken {
                status: TokenStatus::Active,
                amount: Some(denom as i128),
                chain_hash: None,
                owner_commitment: Some(commitment),
                spend_nonce: Some(0),
                claim_pubkey: None,
                ephemeral_key: None,
                event_id: None,
                participants_len: None,
            },
        );
        let mut w = TokenWallet::with_vault(chain, MemoryStore::new(), vault);
        let _p = w.start_receive(PASS, 1).await.unwrap();

        let err = w.complete_receive(bytes, 2).await.unwrap_err();
        assert_gate(&err, Gate::Ledger, false);
    });
}

/// G2: an already-redeemed token is final, and waiting must not be offered.
#[test]
fn g2_rejects_an_already_redeemed_token_permanently() {
    pollster::block_on(async {
        let (bytes, slot, denom) = mint_bytes(5_000);
        let chain = chain_with(
            slot,
            OnChainToken {
                chain_hash: Some(chain_hash_of(&bytes)),
                status: TokenStatus::Redeemed,
                amount: Some(denom as i128),
                owner_commitment: None,
                spend_nonce: Some(0),
                claim_pubkey: None,
                ephemeral_key: Some(key_of(&bytes)),
                event_id: shape_of(&bytes).0,
                participants_len: shape_of(&bytes).1,
            },
        );
        let mut w = TokenWallet::with_vault(chain, MemoryStore::new(), MockVault::new());
        let _p = w.start_receive(PASS, 1).await.unwrap();
        let err = w.complete_receive(bytes, 2).await.unwrap_err();
        assert_gate(&err, Gate::Ledger, false);
    });
}

/// G2: a token whose face value disagrees with the escrow is not what was agreed.
#[test]
fn g2_rejects_an_amount_mismatch() {
    pollster::block_on(async {
        let (bytes, slot, denom) = mint_bytes(5_000);
        let vault = MockVault::new();
        let commitment = owner_commitment(&vault.keypair(FIRST_FRESH_INDEX).raw_public());
        let chain = chain_with(
            slot,
            OnChainToken {
                chain_hash: Some(chain_hash_of(&bytes)),
                status: TokenStatus::Active,
                amount: Some(denom as i128 - 1),
                owner_commitment: Some(commitment),
                spend_nonce: Some(0),
                claim_pubkey: None,
                ephemeral_key: Some(key_of(&bytes)),
                event_id: shape_of(&bytes).0,
                participants_len: shape_of(&bytes).1,
            },
        );
        let mut w = TokenWallet::with_vault(chain, MemoryStore::new(), vault);
        let _p = w.start_receive(PASS, 1).await.unwrap();
        let err = w.complete_receive(bytes, 2).await.unwrap_err();
        // The escrow will not change to match the bytes.
        assert_gate(&err, Gate::Ledger, false);
    });
}

/// G3: the live owner must be us. Holding the bytes is not being paid.
#[test]
fn g3_rejects_a_token_owned_by_someone_else() {
    pollster::block_on(async {
        let (bytes, slot, denom) = mint_bytes(5_000);
        let chain = chain_with(
            slot,
            OnChainToken {
                chain_hash: Some(chain_hash_of(&bytes)),
                status: TokenStatus::Active,
                amount: Some(denom as i128),
                owner_commitment: Some([0xAB; 32]), // somebody else's,
                spend_nonce: Some(0),
                claim_pubkey: None,
                ephemeral_key: Some(key_of(&bytes)),
                event_id: shape_of(&bytes).0,
                participants_len: shape_of(&bytes).1,
            },
        );
        let mut w = TokenWallet::with_vault(chain, MemoryStore::new(), MockVault::new());
        let _p = w.start_receive(PASS, 1).await.unwrap();
        let err = w.complete_receive(bytes, 2).await.unwrap_err();
        // The pointer may still move to us, so this one is worth waiting on.
        assert_gate(&err, Gate::Ownership, true);
        assert!(w.held().await.unwrap().is_empty(), "nothing may be stored as ours");
    });
}

/// G3: a pure-bearer token carries no ownership proof, so a spend-mode receive
/// cannot be completed against it.
#[test]
fn g3_rejects_a_pure_bearer_token() {
    pollster::block_on(async {
        let (bytes, slot, denom) = mint_bytes(5_000);
        let claim = kenter_crypto::container::deserialize_bearer_token(&bytes)
            .unwrap()
            .claim_public_key();
        let chain = chain_with(slot, bearer_record(&bytes, denom, Some(claim)));
        let mut w = TokenWallet::with_vault(chain, MemoryStore::new(), MockVault::new());
        let _p = w.start_receive(PASS, 1).await.unwrap();
        let err = w.complete_receive(bytes, 2).await.unwrap_err();
        // Mode is fixed at registration: it will never acquire an owner.
        assert_gate(&err, Gate::Ownership, false);
    });
}

/// A pure-bearer note whose record names another claim key can only ever be
/// redeemed by whoever kept that key's secret -- the payer. Refused at the
/// ledger gate rather than reaching the ownership answer the GUI imports on
/// -- such a note must never be shown as held. A missing claim key is refused the same way: the mint
/// requires one at registration.
#[test]
fn a_pure_bearer_note_with_someone_elses_claim_key_is_refused() {
    pollster::block_on(async {
        for recorded in [Some([0xCD; 32]), None] {
            let (bytes, slot, denom) = mint_bytes(5_000);
            let chain = chain_with(slot, bearer_record(&bytes, denom, recorded));
            let mut w = TokenWallet::with_vault(chain, MemoryStore::new(), MockVault::new());
            let _p = w.start_receive(PASS, 1).await.unwrap();
            let err = w.complete_receive(bytes, 2).await.unwrap_err();
            assert_gate(&err, Gate::Ledger, false);
        }
    });
}

/// A live pure-bearer record for `bytes`, with the claim key given.
fn bearer_record(bytes: &[u8], denom: u64, claim: Option<[u8; 32]>) -> OnChainToken {
    OnChainToken {
        chain_hash: Some(chain_hash_of(bytes)),
        status: TokenStatus::Active,
        amount: Some(denom as i128),
        owner_commitment: None,
        spend_nonce: Some(0),
        claim_pubkey: claim,
        ephemeral_key: Some(key_of(bytes)),
        event_id: shape_of(bytes).0,
        participants_len: shape_of(bytes).1,
    }
}

/// Owner authorizations sign the 32-byte digest, and the signature verifies
/// under the derived owner key.
#[test]
fn authorize_redeem_signs_the_digest_under_the_owner_key() {
    pollster::block_on(async {
        let vault = MockVault::new();
        let index = 3u32;
        let pubkey = vault.keypair(index).raw_public();
        let commitment = owner_commitment(&pubkey);
        let ek = [7u8; 32];
        let slot = 7u32;
        let nonce = 3u32;

        let mut w =
            TokenWallet::with_vault(chain_holding(slot, nonce), MemoryStore::new(), vault);
        let proof = w
            .authorize_redeem(index, slot, &ek, &commitment, RECIPIENT, PASS)
            .await
            .unwrap();

        assert_eq!(proof.owner_pubkey, pubkey);
        let contract = w.chain().mint_contract_xdr();
        let digest = kenter_crypto::spend::redeem_owner_digest(
            &contract,
            slot,
            &ek,
            &commitment,
            nonce,
            RECIPIENT,
        );
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&pubkey).unwrap();
        assert!(vk
            .verify_strict(&digest, &ed25519_dalek::Signature::from_bytes(&proof.signature))
            .is_ok());
        // And the crypto crate's own verifier accepts it.
        assert!(kenter_crypto::spend::verify_redeem_owner(
            &contract,
            slot,
            &ek,
            &commitment,
            nonce,
            RECIPIENT,
            &proof
        )
        .is_ok());
    });
}

/// The nonce comes from the ledger, not from the caller.
///
/// A note the mint has no record of has no spend count, and signing against
/// a guessed one would produce a proof that is either rejected on-chain or —
/// worse, if the guess were a stale real value — replayable. Failing here
/// keeps that unrepresentable.
#[test]
fn authorizing_a_note_the_mint_does_not_know_fails_before_signing() {
    pollster::block_on(async {
        let vault = MockVault::new();
        let index = 3u32;
        let commitment = owner_commitment(&vault.keypair(index).raw_public());

        let mut w = TokenWallet::with_vault(empty_chain(), MemoryStore::new(), vault);
        let err = w
            .authorize_redeem(index, 7, &[7u8; 32], &commitment, RECIPIENT, PASS)
            .await
            .unwrap_err();
        assert!(matches!(err, WalletError::Chain(_)), "got {err:?}");
    });
}

/// Signing with an index that does not own the token fails locally rather than
/// as an on-chain revert.
#[test]
fn authorizing_with_the_wrong_index_fails_before_submission() {
    pollster::block_on(async {
        let vault = MockVault::new();
        let commitment = owner_commitment(&vault.keypair(3).raw_public());
        let mut w =
            TokenWallet::with_vault(chain_holding(7, 0), MemoryStore::new(), vault);

        let err = w.authorize_redeem(4, 7, &[7u8; 32], &commitment, RECIPIENT, PASS).await.unwrap_err();
        assert!(matches!(err, WalletError::Vault(_)), "got {err:?}");
    });
}

#[test]
fn authorize_spend_is_accepted_by_the_crypto_verifier() {
    pollster::block_on(async {
        let vault = MockVault::new();
        let index = 2u32;
        let current = owner_commitment(&vault.keypair(index).raw_public());
        let next = owner_commitment(&vault.keypair(99).raw_public());
        let ek = [11u8; 32];
        let slot = 11u32;
        let nonce = 5u32;

        let mut w =
            TokenWallet::with_vault(chain_holding(slot, nonce), MemoryStore::new(), vault);
        let auth = w
            .authorize_spend(index, slot, &ek, &current, &next, PASS)
            .await
            .unwrap();

        assert_eq!(auth.new_owner_commitment, next);
        let contract = w.chain().mint_contract_xdr();
        assert!(
            kenter_crypto::spend::verify_spend(&contract, slot, &ek, &current, nonce, &auth).is_ok()
        );
        // And only at that nonce: the authorization dies when the note is
        // spent on, which is what stops an old one being re-posted after the
        // note comes back to this owner.
        assert!(
            kenter_crypto::spend::verify_spend(&contract, slot, &ek, &current, nonce + 1, &auth)
                .is_err()
        );
    });
}

// ── sync: auto-bind and spent-away (docs/architecture/custody.md) ──

/// A receive that crashed between showing the commitment and storing the token
/// leaves a pending record and an unbound token. sync repairs that.
#[test]
fn sync_binds_a_token_matching_a_pending_commitment() {
    pollster::block_on(async {
        let vault = MockVault::new();
        let commitment = owner_commitment(&vault.keypair(FIRST_FRESH_INDEX).raw_public());
        // Real bytes: sync acts only on a record that describes the note,
        // so a forged record cannot rewrite what the wallet believes.
        let (bytes, slot, denom) = mint_bytes(500);
        let mut t = held_from(&bytes, slot, denom);
        t.owner_index = None; // never bound

        let mut store = MemoryStore::new();
        store.put(t.clone()).await.unwrap();
        let chain = chain_with(slot, spend_record(&bytes, denom, commitment));
        let mut w = TokenWallet::with_vault(chain, store, vault);
        let p = w.start_receive(PASS, 1).await.unwrap();
        assert_eq!(p.commitment, commitment);

        let report = w.sync().await.unwrap();
        assert_eq!(report.bound, vec![(t.id.clone(), p.index)]);
        assert!(report.spent_away.is_empty());

        let after = w.held().await.unwrap();
        assert_eq!(after[0].owner_index, Some(p.index));
        assert_eq!(after[0].owner_commitment, Some(commitment));
        assert!(w.pending().await.unwrap().is_empty(), "pending consumed");
    });
}

/// One wrong owner answer must not mark a note paid away for good. When
/// the ledger again names this wallet's commitment, sync clears
/// it and the note counts as money.
#[test]
fn sync_clears_paid_away_when_the_ledger_says_ours_again() {
    pollster::block_on(async {
        let mine = [0x11u8; 32];
        let (bytes, slot, denom) = mint_bytes(900);
        let mut t = held_from(&bytes, slot, denom);
        t.owner_index = Some(4);
        t.owner_commitment = Some(mine);
        t.spent_away = true; // what one wrong answer left behind

        let mut store = MemoryStore::new();
        store.put(t.clone()).await.unwrap();
        let chain = chain_with(slot, spend_record(&bytes, denom, mine));
        let mut w = TokenWallet::new(chain, store);

        let report = w.sync().await.unwrap();
        assert_eq!(report.returned, vec![t.id.clone()]);
        assert!(!w.held().await.unwrap()[0].spent_away);
        assert_eq!(w.balance().await.unwrap().spendable, denom);
    });
}

/// A token paid away is still Active on the ledger. Without the flag it would
/// keep counting as spendable in our own balance - overstating it by exactly
/// the amount we just gave away.
#[test]
fn sync_flags_a_token_paid_away_and_balance_stops_counting_it() {
    pollster::block_on(async {
        let mine = [0x11u8; 32];
        let theirs = [0x22u8; 32];
        let (bytes, slot, denom) = mint_bytes(900);
        let mut t = held_from(&bytes, slot, denom);
        t.owner_index = Some(4);
        t.owner_commitment = Some(mine);

        let mut store = MemoryStore::new();
        store.put(t.clone()).await.unwrap();
        // Still Active - that is the point.
        let chain = chain_with(slot, spend_record(&bytes, denom, theirs));
        let mut w = TokenWallet::new(chain, store); // no vault needed

        // Even before sync the balance does not count it: the ledger
        // names an owner this wallet cannot open.
        assert_eq!(w.balance().await.unwrap().spendable, 0);

        let report = w.sync().await.unwrap();
        assert_eq!(report.spent_away, vec![t.id.clone()]);

        let b = w.balance().await.unwrap();
        assert_eq!(b.spendable, 0, "paid-away value is not spendable");
        assert_eq!(b.spent_away, 900);
        assert_eq!(b.total_held, 900, "still held, just not ours");
    });
}

/// sync must be idempotent and must not disturb a token we still own.
#[test]
fn sync_leaves_an_owned_token_alone_and_repeats_cleanly() {
    pollster::block_on(async {
        let mine = [0x33u8; 32];
        let mut t = held(3, 100);
        t.owner_index = Some(2);
        t.owner_commitment = Some(mine);

        let mut store = MemoryStore::new();
        store.put(t.clone()).await.unwrap();
        let chain = chain_with(
            t.slot_id,
            OnChainToken {
                chain_hash: None,
                status: TokenStatus::Active,
                amount: Some(100),
                owner_commitment: Some(mine),
                spend_nonce: Some(0),
                claim_pubkey: None,
                ephemeral_key: None,
                event_id: None,
                participants_len: None,
            },
        );
        let mut w = TokenWallet::new(chain, store);

        assert!(w.sync().await.unwrap().is_empty());
        assert!(w.sync().await.unwrap().is_empty(), "second pass reports nothing new");
        assert!(!w.held().await.unwrap()[0].spent_away);
        assert_eq!(w.balance().await.unwrap().spendable, 100);
    });
}

/// A pure-bearer token has no owner pointer, so sync must not touch it.
#[test]
fn sync_ignores_pure_bearer_tokens() {
    pollster::block_on(async {
        let t = held(4, 10);
        let mut store = MemoryStore::new();
        store.put(t.clone()).await.unwrap();
        let chain = chain_with(
            t.slot_id,
            OnChainToken {
                chain_hash: None,
                status: TokenStatus::Active,
                amount: Some(10),
                owner_commitment: None,
                spend_nonce: Some(0),
                claim_pubkey: None,
                ephemeral_key: None,
                event_id: None,
                participants_len: None,
            },
        );
        let mut w = TokenWallet::new(chain, store);
        assert!(w.sync().await.unwrap().is_empty());
        assert_eq!(w.balance().await.unwrap().spendable, 10);
        let _ = RT { held: t, status: TokenStatus::Active, on_chain_amount: Some(10) };
    });
}

// ---------------------------------------------------------------------------
// verify_ownership: the last place a restored record was believed
// ---------------------------------------------------------------------------

/// Build a wallet holding one spend note that *claims* `index` with
/// `stored`, where the ledger says `live` owns it.
fn owned_setup(
    index: u32,
    stored: [u8; 32],
    live: Option<[u8; 32]>,
) -> TokenWallet<MockChain, MemoryStore, MockVault> {
    let mut held = kenter_wallet::testing::note(9, 1_000);
    held.owner_index = Some(index);
    held.owner_commitment = Some(stored);

    let mut statuses = HashMap::new();
    statuses.insert(
        held.slot_id,
        OnChainToken {
            chain_hash: None,
            status: TokenStatus::Active,
            amount: Some(1_000),
            owner_commitment: live,
            spend_nonce: Some(0),
            claim_pubkey: None,
            ephemeral_key: None,
            event_id: None,
            participants_len: None,
        },
    );

    let mut store = MemoryStore::new();
    pollster::block_on(store.put(held)).unwrap();
    TokenWallet::with_vault(MockChain { statuses, mint: MINT_A.to_string() }, store, MockVault::new())
}

/// What the vault derives at `index` — the truth the record is checked
/// against.
fn derived_at(index: u32) -> [u8; 32] {
    let mut v = MockVault::new();
    kenter_wallet::owner::commitment_for(&mut v, index, b"pass").unwrap()
}

#[test]
fn an_honest_claim_is_confirmed_and_left_alone() {
    pollster::block_on(async {
        let mut w = owned_setup(4, derived_at(4), Some(derived_at(4)));
        let report = w.verify_ownership(b"pass").await.unwrap();

        assert_eq!(report.confirmed, 1);
        assert!(report.is_clean());
        assert_eq!(w.store().all().await.unwrap()[0].owner_index, Some(4));
    });
}

/// The record rotted but the index is right: the ledger agrees with the
/// derived key, so this is a repair rather than a doubt.
#[test]
fn a_wrong_stored_commitment_is_corrected_from_the_ledger() {
    pollster::block_on(async {
        let mut w = owned_setup(4, [0xBB; 32], Some(derived_at(4)));
        let report = w.verify_ownership(b"pass").await.unwrap();

        assert_eq!(report.corrected, vec![(w.store().all().await.unwrap()[0].id.clone(), 4)]);
        assert!(report.disowned.is_empty());
        let back = &w.store().all().await.unwrap()[0];
        assert_eq!(back.owner_index, Some(4), "the index was right all along");
        assert_eq!(back.owner_commitment, Some(derived_at(4)));
    });
}

/// Not ours at that index. The claim goes; the note stays.
#[test]
fn a_claim_this_wallet_cannot_open_is_stripped_but_the_note_is_kept() {
    pollster::block_on(async {
        let mut w = owned_setup(4, [0xBB; 32], Some([0xCC; 32]));
        let report = w.verify_ownership(b"pass").await.unwrap();

        assert_eq!(report.disowned.len(), 1);
        assert!(report.disowned[0].1.contains("cannot open"), "{:?}", report.disowned[0]);

        let all = w.store().all().await.unwrap();
        assert_eq!(all.len(), 1, "the bytes are the holder's, whatever the claim said");
        assert_eq!(all[0].owner_index, None);
        assert_eq!(all[0].owner_commitment, None);
    });
}

/// A fabricated claim on a note the ledger has never heard of.
#[test]
fn a_claim_with_no_ledger_record_is_stripped() {
    pollster::block_on(async {
        let mut w = owned_setup(4, [0xBB; 32], None);
        let report = w.verify_ownership(b"pass").await.unwrap();

        assert_eq!(report.disowned.len(), 1);
        assert!(report.disowned[0].1.contains("no owner for it"), "{:?}", report.disowned[0]);
        assert_eq!(w.store().all().await.unwrap()[0].owner_index, None);
    });
}

/// A pure bearer note claims nothing, so there is nothing to check.
#[test]
fn a_bearer_note_is_not_touched() {
    pollster::block_on(async {
        let held = kenter_wallet::testing::note(11, 500);
        let mut store = MemoryStore::new();
        store.put(held).await.unwrap();
        let mut w = TokenWallet::with_vault(
            MockChain { statuses: HashMap::new(), mint: MINT_A.to_string() },
            store,
            MockVault::new(),
        );

        let report = w.verify_ownership(b"pass").await.unwrap();
        assert_eq!(report.confirmed, 0);
        assert_eq!(report.unchecked, 0);
        assert!(report.is_clean());
    });
}

// ── A note belongs to the mint that confirmed it ──
//
// Records are addressed by slot, and slot ids restart at zero on every
// deployment. Without binding, a wallet reconciles every note against
// whichever mint it is pointed at, and a `Redeemed(0)` marker -- which
// holds a ledger number and nothing about which note was paid --
// answers for a note from a different ledger entirely.
//
// The damage is not an overstated balance. It is that a live note reads
// `redeemed`, and a holder who believes that runs `forget`, which
// deletes the only copy of a bearer instrument.

/// A note bound to one mint is not read against another, and above all
/// is not reported as redeemed because the other mint's slot of the
/// same id happens to be.
#[test]
fn a_note_bound_to_another_mint_is_not_reported_redeemed() {
    pollster::block_on(async {
        let (bytes, slot, denom) = mint_bytes(5_000);
        let mut store = MemoryStore::new();

        // Live on mint A, and bound to it.
        let mut held = held_from(&bytes, slot, denom);
        held.mint = Some(MINT_A.to_string());
        store.put(held).await.unwrap();

        // Mint B's slot of the same id was redeemed. Different note.
        let mut chain = chain_with(
            slot,
            OnChainToken {
                status: TokenStatus::Redeemed,
                amount: None,
                chain_hash: None,
                owner_commitment: None,
                claim_pubkey: None,
                ephemeral_key: None,
                event_id: None,
                participants_len: None,
                spend_nonce: None,
            },
        );
        chain.mint = MINT_B.to_string();

        let mut w = TokenWallet::new(chain, store);
        let r = w.reconcile().await.unwrap();
        assert_eq!(r[0].status, TokenStatus::OtherMint);

        let b = w.balance().await.unwrap();
        assert_eq!(b.redeemed, 0, "a live note was written off as spent");
        assert_eq!(b.unverified, denom);
    });
}

/// An unbound note against a `Redeemed` marker reads `Unbound`. The
/// marker is content-free, so it is evidence about nothing.
#[test]
fn an_unbound_note_against_a_marker_reads_unbound() {
    pollster::block_on(async {
        let (bytes, slot, denom) = mint_bytes(5_000);
        let mut store = MemoryStore::new();
        store.put(held_from(&bytes, slot, denom)).await.unwrap();

        let chain = chain_with(
            slot,
            OnChainToken {
                status: TokenStatus::Redeemed,
                amount: None,
                chain_hash: None,
                owner_commitment: None,
                claim_pubkey: None,
                ephemeral_key: None,
                event_id: None,
                participants_len: None,
                spend_nonce: None,
            },
        );

        let mut w = TokenWallet::new(chain, store);
        let r = w.reconcile().await.unwrap();
        assert_eq!(r[0].status, TokenStatus::Unbound);
        assert_eq!(w.balance().await.unwrap().redeemed, 0);
    });
}

/// The one answer that *is* about this note's content binds it: `Active`
/// with the record describing these bytes.
#[test]
fn an_active_record_that_describes_the_note_binds_it() {
    pollster::block_on(async {
        let (bytes, slot, denom) = mint_bytes(5_000);
        let mut store = MemoryStore::new();
        store.put(held_from(&bytes, slot, denom)).await.unwrap();

        let mut w = TokenWallet::new(chain_for(slot, &bytes, denom), store);
        let r = w.reconcile().await.unwrap();
        assert_eq!(r[0].status, TokenStatus::Active);

        let after = w.held().await.unwrap();
        assert_eq!(
            after[0].mint.as_deref(),
            Some(MINT_A),
            "an Active record describing the note did not bind it"
        );
    });
}

/// Importing bytes is not a ledger confirming them. Whatever a container
/// carries, the binding comes from the wallet's own configured mint.
#[test]
fn importing_does_not_bind_a_note() {
    pollster::block_on(async {
        let (bytes, slot, denom) = mint_bytes(5_000);
        let mut w = TokenWallet::new(chain_for(slot, &bytes, denom), MemoryStore::new());
        w.import(bytes, 1).await.unwrap();

        let held = w.held().await.unwrap();
        assert!(
            held[0].mint.is_none(),
            "import bound a note the ledger had not yet confirmed"
        );
    });
}

/// What the mint records for a live spend-mode note owned by `owner`.
fn spend_record(bytes: &[u8], denom: u64, owner: [u8; 32]) -> OnChainToken {
    OnChainToken {
        chain_hash: Some(chain_hash_of(bytes)),
        status: TokenStatus::Active,
        amount: Some(denom as i128),
        owner_commitment: Some(owner),
        spend_nonce: Some(0),
        claim_pubkey: None,
        ephemeral_key: Some(key_of(bytes)),
        event_id: shape_of(bytes).0,
        participants_len: shape_of(bytes).1,
    }
}

/// A held note carrying real container bytes, so `describes()` has
/// something to compare against.
fn held_from(bytes: &[u8], slot: u32, denom: u64) -> HeldToken {
    let t = deserialize_bearer_token(bytes).expect("fixture container");
    HeldToken {
        id: note_id(&t.ephemeral_address(), slot),
        slot_id: slot,
        ephemeral_public_key: t.ephemeral_public_key,
        event_id: t.header.event_id,
        amount: denom,
        blob: bytes.to_vec(),
        imported_at: 0,
        mint: None,
        label: None,
        owner_index: None,
        owner_commitment: None,
        spent_away: false,
        exports: Default::default(),
        marked_spent: false,
    }
}

/// Binding must not write back a stale snapshot.
///
/// `reconcile` reads every record, awaits an RPC per note, then writes
/// the binding. Writing the pre-RPC record back whole would undo
/// anything that landed in that window -- and the desktop app and the
/// CLI share a wallet directory by design.
///
/// `marked_spent` is the field that makes this expensive. It is the only
/// record that a pure-bearer note was handed over, because the ledger
/// cannot see a handover. Lose it and a note the holder already gave
/// away is spendable again; the second payee passes G2 because the note
/// really is still Active, and whoever redeems first is paid.
#[test]
fn binding_does_not_undo_a_write_that_landed_during_the_read() {
    pollster::block_on(async {
        let (bytes, slot, denom) = mint_bytes(5_000);
        let shared = SharedStore::new();
        shared.blocking_put(held_from(&bytes, slot, denom));
        let id = note_id(&deserialize_bearer_token(&bytes).unwrap().ephemeral_address(), slot);

        // The ledger read is where the other writer gets its window.
        let chain = MutatingChain {
            inner: chain_for(slot, &bytes, denom),
            store: shared.clone(),
            id: id.clone(),
        };

        let mut w = TokenWallet::new(chain, shared.clone());
        let r = w.reconcile().await.unwrap();

        assert_eq!(r[0].status, TokenStatus::Active);
        let after = shared.blocking_get(&id).expect("the note is still there");
        assert_eq!(
            after.mint.as_deref(),
            Some(MINT_A),
            "the binding was not recorded"
        );
        assert!(
            after.marked_spent,
            "binding undid a hand-over recorded during the ledger read"
        );
    });
}

/// A note deleted while reconcile was reading stays deleted. Writing the
/// snapshot back would resurrect it.
#[test]
fn binding_does_not_resurrect_a_note_deleted_during_the_read() {
    pollster::block_on(async {
        let (bytes, slot, denom) = mint_bytes(5_000);
        let shared = SharedStore::new();
        shared.blocking_put(held_from(&bytes, slot, denom));
        let id = note_id(&deserialize_bearer_token(&bytes).unwrap().ephemeral_address(), slot);

        let chain = DeletingChain {
            inner: chain_for(slot, &bytes, denom),
            store: shared.clone(),
            id: id.clone(),
        };

        let mut w = TokenWallet::new(chain, shared.clone());
        let r = w.reconcile().await.unwrap();

        assert!(
            shared.blocking_get(&id).is_none(),
            "a note deleted during the read came back"
        );
        // And it is out of this run's answer, not just the store. A
        // just-forgotten note reported Active is counted as spendable
        // one last time.
        assert!(
            r.is_empty(),
            "a note deleted during the read was still reported: {:?}",
            r.iter().map(|x| x.status).collect::<Vec<_>>()
        );
    });
}

/// A `MemoryStore` two handles share, standing in for the wallet
/// directory the CLI and the desktop app both open.
#[derive(Clone, Default)]
struct SharedStore(std::rc::Rc<std::cell::RefCell<MemoryStore>>);

impl SharedStore {
    fn new() -> Self {
        Self::default()
    }

    fn blocking_put(&self, t: HeldToken) {
        pollster::block_on(self.0.borrow_mut().put(t)).unwrap();
    }

    fn blocking_get(&self, id: &str) -> Option<HeldToken> {
        pollster::block_on(self.0.borrow().get(id)).unwrap()
    }
}

impl Store for SharedStore {
    async fn put(&mut self, token: HeldToken) -> kenter_wallet::Result<()> {
        self.0.borrow_mut().put(token).await
    }
    async fn get(&self, id: &str) -> kenter_wallet::Result<Option<HeldToken>> {
        self.0.borrow().get(id).await
    }
    async fn all(&self) -> kenter_wallet::Result<Vec<HeldToken>> {
        self.0.borrow().all().await
    }
    async fn remove(&mut self, id: &str) -> kenter_wallet::Result<()> {
        self.0.borrow_mut().remove(id).await
    }
    async fn allocate_owner_index(&mut self) -> kenter_wallet::Result<u32> {
        self.0.borrow_mut().allocate_owner_index().await
    }
    async fn advance_owner_index(&mut self, to: u32) -> kenter_wallet::Result<u32> {
        self.0.borrow_mut().advance_owner_index(to).await
    }
    async fn put_pending(&mut self, p: PendingReceive) -> kenter_wallet::Result<()> {
        self.0.borrow_mut().put_pending(p).await
    }
    async fn pending(&self) -> kenter_wallet::Result<Vec<PendingReceive>> {
        self.0.borrow().pending().await
    }
    async fn remove_pending(&mut self, index: u32) -> kenter_wallet::Result<()> {
        self.0.borrow_mut().remove_pending(index).await
    }
    async fn last_backup(&self) -> kenter_wallet::Result<Option<BackupRecord>> {
        self.0.borrow().last_backup().await
    }
    async fn record_backup(&mut self, r: BackupRecord) -> kenter_wallet::Result<()> {
        self.0.borrow_mut().record_backup(r).await
    }
}

/// Marks the note handed over while the ledger is being read.
struct MutatingChain {
    inner: MockChain,
    store: SharedStore,
    id: String,
}

impl ChainRead for MutatingChain {
    async fn token_status(&self, slot_id: u32) -> kenter_wallet::Result<OnChainToken> {
        if let Some(mut t) = self.store.blocking_get(&self.id) {
            t.marked_spent = true;
            self.store.blocking_put(t);
        }
        self.inner.token_status(slot_id).await
    }
    fn ledger_source(&self) -> String {
        self.inner.ledger_source()
    }
    fn mint_contract_xdr(&self) -> Vec<u8> {
        self.inner.mint_contract_xdr()
    }
    fn mint_id(&self) -> String {
        self.inner.mint_id()
    }
}

/// Deletes the note while the ledger is being read.
struct DeletingChain {
    inner: MockChain,
    store: SharedStore,
    id: String,
}

impl ChainRead for DeletingChain {
    async fn token_status(&self, slot_id: u32) -> kenter_wallet::Result<OnChainToken> {
        pollster::block_on(self.store.0.borrow_mut().remove(&self.id)).ok();
        self.inner.token_status(slot_id).await
    }
    fn ledger_source(&self) -> String {
        self.inner.ledger_source()
    }
    fn mint_contract_xdr(&self) -> Vec<u8> {
        self.inner.mint_contract_xdr()
    }
    fn mint_id(&self) -> String {
        self.inner.mint_id()
    }
}

// ─────────────────────────────────────────────────────────────────────
// The store lock, over a real FileStore.
//
// Everything above drives the wallet over `MemoryStore`, whose `lock` is
// the no-op default. These are the tests that exercise the locking path:
// the serialization it exists for, and the deadlock it could cause. The
// lock is an OS lock on a `.write-lock` file in the wallet directory,
// shared by the desktop app and the CLI.
// ─────────────────────────────────────────────────────────────────────

/// Owner indices must be unique across concurrent allocators.
///
/// This is the sharpest property the lock buys, because the consequence
/// is not a lost write but a **reused owner commitment**. The custody model
/// (docs/architecture/custody.md) requires indices to be monotonic and never reused: two payments under
/// one commitment are linkable, which is the privacy the index exists to
/// provide. `allocate_owner_index` reads `state.json`, increments and
/// writes it back, so two unsynchronized allocators can read the same
/// value and both take it.
///
/// Two threads, each with its **own** `FileStore` on one directory — the
/// shape the desktop GUI actually has, where eleven stores are opened
/// across its job threads.
#[cfg(feature = "fs")]
#[test]
fn concurrent_allocators_never_hand_out_the_same_owner_index() {
    use kenter_wallet::{FileStore, StoreCredentials};

    const PER_THREAD: u32 = 25;

    let dir = std::env::temp_dir().join(format!("kenter-lock-idx-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);

    let creds = || StoreCredentials {
        aead: zeroize::Zeroizing::new([3u8; 32]),
        name: zeroize::Zeroizing::new([4u8; 32]),
    };

    let mut handles = Vec::new();
    for _ in 0..2 {
        let dir = dir.clone();
        handles.push(std::thread::spawn(move || {
            // Each thread owns its runtime and its store, as a GUI job does.
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async {
                let store = FileStore::open(&dir, creds()).unwrap();
                let mut wallet = TokenWallet::new(empty_chain(), store);
                let mut mine = Vec::new();
                for _ in 0..PER_THREAD {
                    mine.push(wallet.reserve_owner_index().await.unwrap());
                }
                mine
            })
        }));
    }

    let mut all: Vec<u32> = Vec::new();
    for h in handles {
        all.extend(h.join().expect("an allocator thread panicked"));
    }

    let mut sorted = all.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(
        sorted.len(),
        all.len(),
        "an owner index was handed out twice: {all:?}"
    );
    assert!(
        !all.contains(&STATIC_RECEIVE_INDEX),
        "index 0 is reserved for the static receive address"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// The whole read-modify-write surface runs over a `FileStore` without
/// deadlocking.
///
/// The lock is **not re-entrant** — it locks per open handle and opens a
/// fresh one each call, which is what makes it exclude two threads of one
/// process. So a method that takes it and then calls another that takes
/// it hangs forever. `TokenWallet::balance` is the live instance of that
/// shape: it delegates to `reconcile`, so it must not lock. This walks
/// the writers, and `balance` with them, and would hang rather than fail
/// if that were ever got wrong.
#[cfg(feature = "fs")]
#[test]
fn the_write_surface_does_not_deadlock_on_a_real_store() {
    use kenter_wallet::{FileStore, StoreCredentials};

    let dir = std::env::temp_dir().join(format!("kenter-lock-rmw-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let mut store = FileStore::open(
            &dir,
            StoreCredentials {
                aead: zeroize::Zeroizing::new([5u8; 32]),
                name: zeroize::Zeroizing::new([6u8; 32]),
            },
        )
        .unwrap();
        let token = held(1, 1_000);
        let id = token.id.clone();
        store.put(token).await.unwrap();

        let mut wallet = TokenWallet::new(empty_chain(), store);

        // One call each, in an order a client could actually take.
        wallet.reserve_owner_index().await.unwrap();
        wallet
            .record_pending(kenter_wallet::PendingReceive {
                index: FIRST_FRESH_INDEX,
                commitment: [8u8; 32],
                created_at: 1,
            })
            .await
            .unwrap();
        wallet.forget_pending(FIRST_FRESH_INDEX).await.unwrap();
        wallet.mark_spent(&id, true).await.unwrap();
        wallet.mark_spent(&id, false).await.unwrap();
        wallet.reconcile().await.unwrap();
        wallet.sync().await.unwrap();
        // The delegating one, last: it reconciles, and would deadlock if
        // it took the lock itself.
        wallet.balance().await.unwrap();
        wallet.forget(&id).await.unwrap();

        assert!(wallet.held().await.unwrap().is_empty());
    });

    let _ = std::fs::remove_dir_all(&dir);
}

/// While the ledger is being read, the wallet lock is free: a second
/// handle on the same directory can take it. Holding it across the round
/// trip would stall every other writer behind a slow RPC.
#[cfg(feature = "fs")]
mod lock_is_not_held_across_rpc {
    use super::*;
    use kenter_wallet::FileStore;
    use std::cell::Cell;
    use std::path::PathBuf;

    struct ProbingChain {
        inner: MockChain,
        dir: PathBuf,
        held_during_read: Cell<u32>,
    }

    impl ChainRead for ProbingChain {
        async fn token_status(&self, slot_id: u32) -> kenter_wallet::Result<OnChainToken> {
            // `FileStore::lock` waits, so probe with a raw handle and
            // `try_lock`, which says at once whether someone holds it.
            let f = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(self.dir.join(".write-lock"))
                .unwrap();
            if f.try_lock().is_err() {
                self.held_during_read.set(self.held_during_read.get() + 1);
            }
            self.inner.token_status(slot_id).await
        }
        fn ledger_source(&self) -> String {
            self.inner.ledger_source()
        }
        fn mint_contract_xdr(&self) -> Vec<u8> {
            self.inner.mint_contract_xdr()
        }
        fn mint_id(&self) -> String {
            self.inner.mint_id()
        }
    }

    fn creds() -> kenter_wallet::StoreCredentials {
        kenter_wallet::StoreCredentials {
            aead: zeroize::Zeroizing::new([7u8; 32]),
            name: zeroize::Zeroizing::new([9u8; 32]),
        }
    }

    #[test]
    fn reconcile_and_sync_read_the_ledger_unlocked() {
        // FileStore reads through tokio::fs, which needs a runtime.
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            let dir = std::env::temp_dir().join(format!("kenter-lockprobe-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            let (bytes, slot, denom) = mint_bytes(900);
            let mut store = FileStore::open(&dir, creds()).unwrap();
            store.put(held_from(&bytes, slot, denom)).await.unwrap();

            let chain = ProbingChain {
                inner: chain_with(slot, spend_record(&bytes, denom, [0x22; 32])),
                dir: dir.clone(),
                held_during_read: Cell::new(0),
            };
            let mut w = TokenWallet::new(chain, store);
            w.reconcile().await.unwrap();
            w.sync().await.unwrap();

            assert_eq!(
                w.chain().held_during_read.get(),
                0,
                "the wallet lock was held while the ledger was read"
            );
            let _ = std::fs::remove_dir_all(&dir);
        });
    }
}
