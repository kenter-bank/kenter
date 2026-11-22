//! Phase 6 Integration Test: Full Token Lifecycle
//!
//! End-to-end flow exercising all layers:
//!   1. Print: initiate chain → relay through network handlers → assemble bearer token
//!   2. Path A Redemption: shard requests through handlers → collect → compose → sign
//!   3. Path B Chain Data: serialize chain in contract wire format → validate structure
//!
//! All crypto is real (kenter-crypto). Network transport is simulated through
//! direct handler calls (kenter-network handlers). Contract interactions are
//! mock (Soroban contracts are #![no_std] and can't link into regular tests).

use sha2::{Digest, Sha256};

use kenter_crypto::{
    compose::verify_chain_public_key_from_links,
    container::{
        deserialize_bearer_token, serialize_bearer_token, verify_bearer_signature,
    },
    keypair::StellarKeypair,
    redemption::{contribute_shard, RedemptionRequest, RedemptionSession},
    shard::ChainLink,
    token::{assemble_bearer_token, PartialToken},
};

use kenter_network::handlers::{
    build_extend_request, build_shard_request, handle_extend_request, handle_shard_request,
    parse_extend_response, parse_shard_response, ExtendNodeContext, PairNodeContext,
    ShardRateLimiter,
};

/// Any slot id: these exercise the handler, not the chain.
const TEST_SLOT_ID: u32 = 1;

// ── Helpers ──

const TEST_TIME: i64 = 1741800000;

/// Simulates a mock on-chain state tracker for the mint contract.
struct MockMintState {
    slots: Vec<MockPrintSlot>,
    tokens: Vec<MockTokenRecord>,
}

struct MockPrintSlot {
    _depositor: String,
    event_id: [u8; 32],
    amount: i128,
    pairs: Vec<(String, String)>,
    completed_links: usize,
    partial_keys: Vec<[u8; 32]>,
    state: &'static str,
}

struct MockTokenRecord {
    ephemeral_key: [u8; 32],
    _event_id: [u8; 32],
    amount: i128,
    node_fee: i128,
    participants: Vec<String>,
    state: &'static str,
}

impl MockMintState {
    fn new() -> Self {
        Self {
            slots: vec![],
            tokens: vec![],
        }
    }

    fn request_print(
        &mut self,
        depositor: &str,
        event_id: [u8; 32],
        amount: i128,
        pairs: Vec<(&StellarKeypair, &StellarKeypair)>,
    ) -> usize {
        let slot_id = self.slots.len();
        self.slots.push(MockPrintSlot {
            _depositor: depositor.into(),
            event_id,
            amount,
            pairs: pairs
                .iter()
                .map(|(a, b)| (a.stellar_address(), b.stellar_address()))
                .collect(),
            completed_links: 0,
            partial_keys: vec![],
            state: "Printing",
        });
        slot_id
    }

    fn confirm_link(&mut self, slot_id: usize, link_index: usize, partial_key: [u8; 32]) {
        let slot = &mut self.slots[slot_id];
        assert_eq!(slot.state, "Printing");
        assert_eq!(slot.completed_links, link_index);
        slot.partial_keys.push(partial_key);
        slot.completed_links += 1;
    }

    fn register_token(&mut self, slot_id: usize, ephemeral_key: [u8; 32], node_fee: i128) {
        let slot = &mut self.slots[slot_id];
        assert_eq!(slot.state, "Printing");
        assert_eq!(slot.completed_links, slot.pairs.len());
        slot.state = "Active";

        let mut participants = vec![];
        for (a, b) in &slot.pairs {
            participants.push(a.clone());
            participants.push(b.clone());
        }

        self.tokens.push(MockTokenRecord {
            ephemeral_key,
            _event_id: slot.event_id,
            amount: slot.amount,
            node_fee,
            participants,
            state: "Active",
        });
    }

    fn redeem_by_key(&mut self, ephemeral_key: &[u8; 32]) -> (i128, i128) {
        let token = self
            .tokens
            .iter_mut()
            .find(|t| &t.ephemeral_key == ephemeral_key)
            .expect("token not found");
        assert_eq!(token.state, "Active");

        let total_node_fees = token.node_fee * token.participants.len() as i128;
        let holder_amount = token.amount - total_node_fees;
        token.state = "Redeemed";

        (holder_amount, total_node_fees)
    }

    fn redeem_by_chain(&mut self, ephemeral_key: &[u8; 32]) -> (i128, i128) {
        let token = self
            .tokens
            .iter_mut()
            .find(|t| &t.ephemeral_key == ephemeral_key)
            .expect("token not found");
        assert_eq!(token.state, "Active");

        let total_node_fees = token.node_fee * token.participants.len() as i128;
        let holder_amount = token.amount - total_node_fees;
        token.state = "Redeemed";

        // Fees burned, not paid to nodes
        (holder_amount, total_node_fees)
    }
}

/// Build chain_data bytes in the contract wire format for Path B verification.
fn build_chain_data(event_id: &[u8; 32], links: &[ChainLink]) -> Vec<u8> {
    let mut data = Vec::new();
    // event_id: 32 bytes
    data.extend_from_slice(event_id);
    // link_count: 2 bytes LE
    data.extend_from_slice(&(links.len() as u16).to_le_bytes());
    // Each ChainLink: 290 bytes
    for link in links {
        data.extend_from_slice(&link.node_a_public);       // 32
        data.extend_from_slice(&link.node_b_public);        // 32
        data.extend_from_slice(&link.partial_public_key);   // 32
        data.extend_from_slice(&link.shard_commitment);     // 32
        data.extend_from_slice(&link.prev_link_hash);       // 32
        data.extend_from_slice(&link.link_index.to_le_bytes()); // 2
        data.extend_from_slice(&link.signature_a);          // 64
        data.extend_from_slice(&link.signature_b);          // 64
    }
    data
}

/// Verify chain_data structure matches the on-chain verification format.
fn verify_chain_data_structure(data: &[u8], expected_event_id: &[u8; 32], expected_links: usize) {
    assert!(data.len() >= 34, "chain_data too short");

    // Parse event_id
    let event_id: [u8; 32] = data[0..32].try_into().unwrap();
    assert_eq!(&event_id, expected_event_id, "event_id mismatch");

    // Parse link_count
    let link_count = u16::from_le_bytes([data[32], data[33]]) as usize;
    assert_eq!(link_count, expected_links, "link_count mismatch");

    // Verify total length
    let expected_len = 34 + link_count * 290;
    assert_eq!(data.len(), expected_len, "chain_data length mismatch");

    // Walk links and verify structure
    let mut prev_hash = [0u8; 32];
    for i in 0..link_count {
        let base = 34 + i * 290;

        // Extract prev_link_hash (offset 128 within link)
        let link_prev: [u8; 32] = data[base + 128..base + 160].try_into().unwrap();
        assert_eq!(link_prev, prev_hash, "hash chain broken at link {i}");

        // Extract link_index (offset 160)
        let link_index = u16::from_le_bytes([data[base + 160], data[base + 161]]);
        assert_eq!(link_index as usize, i, "link_index out of sequence at {i}");

        // Compute link hash for chain: SHA256(signable_bytes || sig_a || sig_b)
        // signable = domain_tag || link_data[0..160] || link_index(2 LE) || event_id
        let domain_tag = b"kntr_v1:chain:link";
        let mut signable = Vec::new();
        signable.extend_from_slice(domain_tag);
        signable.extend_from_slice(&data[base..base + 160]);
        signable.extend_from_slice(&data[base + 160..base + 162]);
        signable.extend_from_slice(expected_event_id);

        let sig_a = &data[base + 162..base + 226];
        let sig_b = &data[base + 226..base + 290];

        let mut hash_input = signable;
        hash_input.extend_from_slice(sig_a);
        hash_input.extend_from_slice(sig_b);
        prev_hash = Sha256::digest(&hash_input).into();
    }
}

// ═══════════════════════════════════════════════════════════════════
// Test 1: Full lifecycle — Print → Assemble → Path A Redemption
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_full_lifecycle_print_and_redeem_path_a() {
    // ── Setup: 6 nodes + 1 depositor/holder ──
    let depositor = StellarKeypair::random();
    let node_1 = StellarKeypair::random();
    let node_2 = StellarKeypair::random();
    let node_3 = StellarKeypair::random();
    let node_4 = StellarKeypair::random();
    let node_5 = StellarKeypair::random();
    let node_6 = StellarKeypair::random();

    let event_id = [0xAA; 32];
    let denomination = 50_000_000i128; // 5 USDC (7 decimals)
    let node_fee = 100_000i128; // 0.01 USDC per node

    // ── Mock contract: request_print ──
    let mut mint = MockMintState::new();
    let slot_id = mint.request_print(
        &depositor.stellar_address(),
        event_id,
        denomination,
        vec![
            (&node_1, &node_2),
            (&node_3, &node_4),
            (&node_5, &node_6),
        ],
    );

    // ═══════════════════════════════════════════
    // PHASE 1: Printing — daisy-chain construction
    // ═══════════════════════════════════════════

    // Step 1: Pair 0 (node_1 + node_2) initiates the chain
    let (partial, _shard_0) = PartialToken::initiate(
        event_id,
        TEST_TIME,
        Some(denomination as u64),
        3,
        &node_1,
        &node_2,
        vec![], // VRF proof placeholder
    )
    .unwrap();

    assert_eq!(partial.chain.links.len(), 1);
    assert_eq!(partial.remaining_pairs, 2);
    partial.verify_chain_integrity().unwrap();

    // Mock: node_1 confirms link 0 on-chain
    mint.confirm_link(slot_id, 0, partial.chain.links[0].partial_public_key);

    // Step 2: Relay to Pair 1 (node_3 + node_4) via network handler
    let extend_req = build_extend_request(&partial, TEST_SLOT_ID).unwrap();
    let extend_ctx = ExtendNodeContext {
        own_keypair: node_3.clone(),
        partner_keypair: node_4.clone(),
    };
    let extend_resp = handle_extend_request(&extend_ctx, &extend_req);
    assert_eq!(extend_resp.status, "ok");

    let partial = parse_extend_response(&extend_resp).unwrap();
    assert_eq!(partial.chain.links.len(), 2);
    assert_eq!(partial.remaining_pairs, 1);
    partial.verify_chain_integrity().unwrap();

    // Mock: node_3 confirms link 1 on-chain
    mint.confirm_link(slot_id, 1, partial.chain.links[1].partial_public_key);

    // Step 3: Depositor assembles with Pair 2 (node_5 + node_6)
    let bearer_token = assemble_bearer_token(
        &partial,
        &node_5,
        &node_6,
        7,
        None, // no expiration — bearer tokens don't expire
    )
    .unwrap();

    assert_eq!(bearer_token.chain.links.len(), 3);
    bearer_token.verify_chain_integrity().unwrap();
    verify_chain_public_key_from_links(
        &bearer_token.chain.links,
        &bearer_token.ephemeral_public_key,
    )
    .unwrap();

    // Mock: node_5 confirms link 2 on-chain
    mint.confirm_link(slot_id, 2, bearer_token.chain.links[2].partial_public_key);

    // ═══════════════════════════════════════════
    // Token transfer: depositor → buyer (serialize, transfer, deserialize)
    // ═══════════════════════════════════════════

    let container_bytes = serialize_bearer_token(&bearer_token, &node_5).unwrap();
    verify_bearer_signature(&container_bytes, &node_5.raw_public()).unwrap();

    // Mock: depositor registers token on-chain
    mint.register_token(slot_id, bearer_token.ephemeral_public_key, node_fee);

    // Buyer receives the serialized token
    let buyer_token = deserialize_bearer_token(&container_bytes).unwrap();
    buyer_token.verify_chain_integrity().unwrap();
    assert_eq!(
        buyer_token.ephemeral_public_key,
        bearer_token.ephemeral_public_key
    );

    // ═══════════════════════════════════════════
    // PHASE 2: Path A Redemption — shard collection through handlers
    // ═══════════════════════════════════════════

    let combiner = StellarKeypair::random();
    let combiner_secret = combiner.raw_secret();
    let combiner_public = combiner.raw_public();

    // Buyer creates a signed redemption request. The redemption timestamp must be
    // current: pair nodes check shard-request freshness against their wall clock
    // (SHARD_REQUEST_MAX_AGE_SECS), and the timestamp is bound by the holder sig.
    let token_hash: [u8; 32] = Sha256::digest(&container_bytes).into();
    let chain_links: Vec<ChainLink> = buyer_token.chain.links.clone();
    let redeem_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let request = RedemptionRequest::new(
        buyer_token,
        token_hash,
        &depositor, // holder signs the request
        combiner_public,
        redeem_time,
    );
    request.verify_holder_signature().unwrap();

    // ── Shard requests: combiner → each pair node via handler ──

    // Pair 0: request from node_1
    let shard_req_0 = build_shard_request(
        &chain_links[0],
        &event_id,
        &combiner_public,
        &request.holder_address,
        &token_hash,
        &request.nonce,
        &request.holder_signature,
        request.timestamp,
    );
    let pair_ctx_0 = PairNodeContext {
        own_keypair: node_1.clone(),
        rate_limiter: ShardRateLimiter::new(),
    };
    let shard_resp_0 = handle_shard_request(&pair_ctx_0, &shard_req_0);
    assert_eq!(shard_resp_0.status, "ok");
    let enc_shard_0 = parse_shard_response(&shard_resp_0).unwrap();

    // Pair 1: request from node_3
    let shard_req_1 = build_shard_request(
        &chain_links[1],
        &event_id,
        &combiner_public,
        &request.holder_address,
        &token_hash,
        &request.nonce,
        &request.holder_signature,
        request.timestamp,
    );
    let pair_ctx_1 = PairNodeContext {
        own_keypair: node_3.clone(),
        rate_limiter: ShardRateLimiter::new(),
    };
    let shard_resp_1 = handle_shard_request(&pair_ctx_1, &shard_req_1);
    assert_eq!(shard_resp_1.status, "ok");
    let enc_shard_1 = parse_shard_response(&shard_resp_1).unwrap();

    // Pair 2: request from node_5
    let shard_req_2 = build_shard_request(
        &chain_links[2],
        &event_id,
        &combiner_public,
        &request.holder_address,
        &token_hash,
        &request.nonce,
        &request.holder_signature,
        request.timestamp,
    );
    let pair_ctx_2 = PairNodeContext {
        own_keypair: node_5.clone(),
        rate_limiter: ShardRateLimiter::new(),
    };
    let shard_resp_2 = handle_shard_request(&pair_ctx_2, &shard_req_2);
    assert_eq!(shard_resp_2.status, "ok");
    let enc_shard_2 = parse_shard_response(&shard_resp_2).unwrap();

    // ── Combiner: collect shards → compose → sign ──

    let ephemeral_key = request.token.ephemeral_public_key;
    let combiner_for_session = StellarKeypair::from_raw_secret(&combiner_secret);
    let mut session = RedemptionSession::new(request, combiner_for_session).unwrap();

    assert_eq!(session.total_count(), 3);
    assert_eq!(session.received_count(), 0);

    session
        .receive_shard(&enc_shard_0, &node_1.verifying_key())
        .unwrap();
    session
        .receive_shard(&enc_shard_1, &node_3.verifying_key())
        .unwrap();
    session
        .receive_shard(&enc_shard_2, &node_5.verifying_key())
        .unwrap();

    assert!(session.is_complete());

    // Sign the redemption message
    let redeem_msg = b"stellar:redeem:txhash:abc123";
    let (signature, public_bytes) = session.compose_and_sign(redeem_msg).unwrap();

    // Verify: signature is valid standard Ed25519 under the ephemeral key
    assert_eq!(public_bytes, ephemeral_key);
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&public_bytes).unwrap();
    vk.verify_strict(redeem_msg, &signature)
        .expect("redemption signature must be valid standard Ed25519");

    // Mock: contract distributes funds (Path A — nodes paid)
    let (holder_amount, node_fees) = mint.redeem_by_key(&ephemeral_key);
    assert_eq!(holder_amount, denomination - (node_fee * 6)); // 6 participants
    assert_eq!(node_fees, node_fee * 6);
}

// ═══════════════════════════════════════════════════════════════════
// Test 2: Path B Redemption — chain data format + burn
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_path_b_chain_data_and_burn() {
    let node_1 = StellarKeypair::random();
    let node_2 = StellarKeypair::random();
    let node_3 = StellarKeypair::random();
    let node_4 = StellarKeypair::random();
    let node_5 = StellarKeypair::random();
    let node_6 = StellarKeypair::random();

    let event_id = [0xBB; 32];

    // Build a 3-pair token
    let (mut partial, _) = PartialToken::initiate(
        event_id, TEST_TIME, Some(10_000_000), 3,
        &node_1, &node_2, vec![],
    )
    .unwrap();

    let _ = partial.extend(&node_3, &node_4).unwrap();
    let token = assemble_bearer_token(&partial, &node_5, &node_6, 7, None).unwrap();
    token.verify_chain_integrity().unwrap();

    // Build chain_data in the contract wire format
    let chain_data = build_chain_data(&event_id, &token.chain.links);

    // Verify structure
    verify_chain_data_structure(&chain_data, &event_id, 3);

    // Verify exact size: 32 (event_id) + 2 (count) + 3 * 290 (links) = 904
    assert_eq!(chain_data.len(), 904);

    // Verify each link's Ed25519 signatures (same as contract would do)
    for (i, link) in token.chain.links.iter().enumerate() {
        let signable = link.signable_bytes(&event_id);

        // Verify sig_a with node_a
        let vk_a = ed25519_dalek::VerifyingKey::from_bytes(&link.node_a_public).unwrap();
        let sig_a = ed25519_dalek::Signature::from_bytes(&link.signature_a);
        vk_a.verify_strict(&signable, &sig_a)
            .unwrap_or_else(|_| panic!("link {i} sig_a verification failed"));

        // Verify sig_b with node_b
        let vk_b = ed25519_dalek::VerifyingKey::from_bytes(&link.node_b_public).unwrap();
        let sig_b = ed25519_dalek::Signature::from_bytes(&link.signature_b);
        vk_b.verify_strict(&signable, &sig_b)
            .unwrap_or_else(|_| panic!("link {i} sig_b verification failed"));
    }

    // Verify hash chain
    let mut prev_hash = [0u8; 32];
    for link in &token.chain.links {
        assert_eq!(link.prev_link_hash, prev_hash);
        prev_hash = link.link_hash(&event_id);
    }

    // Mock Path B redemption: fees burned, holder paid
    let mut mint = MockMintState::new();
    let node_fee = 100_000i128;
    mint.tokens.push(MockTokenRecord {
        ephemeral_key: token.ephemeral_public_key,
        _event_id: event_id,
        amount: 10_000_000,
        node_fee,
        participants: vec![
            node_1.stellar_address(),
            node_2.stellar_address(),
            node_3.stellar_address(),
            node_4.stellar_address(),
            node_5.stellar_address(),
            node_6.stellar_address(),
        ],
        state: "Active",
    });

    let (holder_amount, burned) = mint.redeem_by_chain(&token.ephemeral_public_key);
    assert_eq!(burned, node_fee * 6);
    assert_eq!(holder_amount, 10_000_000 - burned);
}

// ═══════════════════════════════════════════════════════════════════
// Test 3: Multi-hop relay through handlers then redeem
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_multi_hop_relay_then_redeem() {
    // 5-pair chain: initiate → 3 relays via handlers → assemble → redeem
    let kps: Vec<StellarKeypair> = (0..10).map(|_| StellarKeypair::random()).collect();

    let event_id = [0xCC; 32];

    // Pair 0 initiates
    let (partial, _) = PartialToken::initiate(
        event_id, TEST_TIME, Some(100_000_000), 5,
        &kps[0], &kps[1], vec![],
    )
    .unwrap();
    assert_eq!(partial.remaining_pairs, 4);

    // Relay through pairs 1, 2, 3 via handlers
    let mut current = partial;
    for i in 1..4 {
        let req = build_extend_request(&current, TEST_SLOT_ID).unwrap();
        let ctx = ExtendNodeContext {
            own_keypair: kps[i * 2].clone(),
            partner_keypair: kps[i * 2 + 1].clone(),
        };
        let resp = handle_extend_request(&ctx, &req);
        assert_eq!(resp.status, "ok", "relay {i} failed");
        current = parse_extend_response(&resp).unwrap();
        current.verify_chain_integrity().unwrap();
    }

    assert_eq!(current.chain.links.len(), 4);
    assert_eq!(current.remaining_pairs, 1);

    // Assemble with pair 4
    let token = assemble_bearer_token(&current, &kps[8], &kps[9], 7, None).unwrap();
    assert_eq!(token.chain.links.len(), 5);
    token.verify_chain_integrity().unwrap();

    // Verify ephemeral key is valid
    verify_chain_public_key_from_links(
        &token.chain.links,
        &token.ephemeral_public_key,
    )
    .unwrap();

    // Redeem via Path A: collect shards from all 5 pairs
    let combiner = StellarKeypair::random();
    let combiner_secret = combiner.raw_secret();
    let combiner_public = combiner.raw_public();

    let container_bytes = serialize_bearer_token(&token, &kps[8]).unwrap();
    let token_hash: [u8; 32] = Sha256::digest(&container_bytes).into();
    let chain_links: Vec<ChainLink> = token.chain.links.clone();
    let holder = StellarKeypair::random(); // buyer

    let request = RedemptionRequest::new(
        token,
        token_hash,
        &holder,
        combiner_public,
        TEST_TIME,
    );

    let ephemeral_key = request.token.ephemeral_public_key;
    let combiner_for_session = StellarKeypair::from_raw_secret(&combiner_secret);
    let mut session = RedemptionSession::new(request, combiner_for_session).unwrap();
    assert_eq!(session.total_count(), 5);

    // Collect shards from one node per pair
    for i in 0..5 {
        let contributor = &kps[i * 2]; // node_a from each pair
        let partner = &kps[i * 2 + 1];

        let enc = contribute_shard(
            contributor,
            &partner.verifying_key(),
            &chain_links[i],
            &combiner_public,
            &event_id,
            TEST_TIME,
            TEST_TIME,
        )
        .unwrap();

        session
            .receive_shard(&enc, &contributor.verifying_key())
            .unwrap();
    }

    assert!(session.is_complete());

    let redeem_msg = b"stellar:redeem:5pair";
    let (sig, pub_bytes) = session.compose_and_sign(redeem_msg).unwrap();

    let vk = ed25519_dalek::VerifyingKey::from_bytes(&pub_bytes).unwrap();
    vk.verify_strict(redeem_msg, &sig).unwrap();
    assert_eq!(pub_bytes, ephemeral_key);
}

// ═══════════════════════════════════════════════════════════════════
// Test 4: Rate limiting across shard requests
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_shard_request_rate_limiting() {
    let node_1 = StellarKeypair::random();
    let node_2 = StellarKeypair::random();
    let combiner = StellarKeypair::random();
    let event_id = [0xDD; 32];

    let shard = kenter_crypto::shard::derive_shard(
        &node_1,
        &node_2.verifying_key(),
        &event_id,
    )
    .unwrap();
    let link = ChainLink::create(&node_1, &node_2, &shard, [0; 32], 0, &event_id);

    // Holder authorization (valid signature binding the combiner key). Uses a
    // current timestamp so it passes the pair node's freshness window.
    let holder = StellarKeypair::random();
    let token_hash = [0x11u8; 32];
    let nonce = [0x22u8; 32];
    let redeem_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let holder_sig = {
        let signable = kenter_crypto::redemption::holder_signable_bytes(
            &token_hash,
            &holder.stellar_address(),
            &combiner.raw_public(),
            &nonce,
            redeem_time,
        );
        holder.sign(&signable).to_bytes()
    };
    let request = build_shard_request(
        &link,
        &event_id,
        &combiner.raw_public(),
        &holder.stellar_address(),
        &token_hash,
        &nonce,
        &holder_sig,
        redeem_time,
    );

    // Shared rate limiter across requests (simulates a long-running node)
    let rate_limiter = ShardRateLimiter::new();
    let ctx = PairNodeContext {
        own_keypair: node_1.clone(),
        rate_limiter,
    };

    // First request succeeds
    let resp1 = handle_shard_request(&ctx, &request);
    assert_eq!(resp1.status, "ok");

    // Second request for same (event_id, link_index) refused
    let resp2 = handle_shard_request(&ctx, &request);
    assert_eq!(resp2.status, "refused");

    // Different event_id succeeds (different token)
    let event_id_2 = [0xEE; 32];
    let shard_2 = kenter_crypto::shard::derive_shard(
        &node_1,
        &node_2.verifying_key(),
        &event_id_2,
    )
    .unwrap();
    let link_2 = ChainLink::create(&node_1, &node_2, &shard_2, [0; 32], 0, &event_id_2);
    let req_2 = build_shard_request(
        &link_2,
        &event_id_2,
        &combiner.raw_public(),
        &holder.stellar_address(),
        &token_hash,
        &nonce,
        &holder_sig,
        redeem_time,
    );
    let resp3 = handle_shard_request(&ctx, &req_2);
    assert_eq!(resp3.status, "ok");
}

// ═══════════════════════════════════════════════════════════════════
// Test 5: Tampered chain data detected
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_tampered_chain_link_detected() {
    let kp1 = StellarKeypair::random();
    let kp2 = StellarKeypair::random();
    let kp3 = StellarKeypair::random();
    let kp4 = StellarKeypair::random();
    let kp5 = StellarKeypair::random();
    let kp6 = StellarKeypair::random();

    let event_id = [0xFF; 32];

    let (mut partial, _) = PartialToken::initiate(
        event_id, TEST_TIME, None, 3,
        &kp1, &kp2, vec![],
    )
    .unwrap();
    let _ = partial.extend(&kp3, &kp4).unwrap();
    let mut token = assemble_bearer_token(&partial, &kp5, &kp6, 7, None).unwrap();

    // Valid chain
    token.verify_chain_integrity().unwrap();

    // Tamper with signature → should fail
    token.chain.links[1].signature_a[0] ^= 0xFF;
    assert!(
        token.verify_chain_integrity().is_err(),
        "tampered signature must be detected"
    );

    // Restore and tamper with hash chain
    token.chain.links[1].signature_a[0] ^= 0xFF; // restore
    token.verify_chain_integrity().unwrap(); // sanity

    token.chain.links[2].prev_link_hash[0] ^= 0xFF;
    assert!(
        token.verify_chain_integrity().is_err(),
        "broken hash chain must be detected"
    );
}
