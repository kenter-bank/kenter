//! Integration test: full daisy-chain bearer token construction and verification.

use kenter_crypto::{
    compose::{verify_chain_public_key_from_links, CompositionBuilder},
    container::{
        deserialize_bearer_token, deserialize_partial_token, is_symtoken,
        serialize_bearer_token, serialize_partial_token, verify_bearer_signature,
        SYMTOKEN_VERSION,
    },
    keypair::StellarKeypair,
    shard::{derive_shard, PairInfo},
    token::{assemble_bearer_token, PartialToken, TokenType},
};

/// Simulate a complete 3-pair daisy chain with authenticated ChainLinks:
///   Pair 0: (Node_1, Node_2)     ← genesis link
///   Pair 1: (Node_3, Node_4)     ← chained to pair 0
///   Pair 2: (Requestor, Node_5)  ← requestor assembles final token
#[test]
fn test_full_daisy_chain_3_pairs() {
    // Network nodes
    let node_1 = StellarKeypair::random();
    let node_2 = StellarKeypair::random();
    let node_3 = StellarKeypair::random();
    let node_4 = StellarKeypair::random();
    let node_5 = StellarKeypair::random();
    let requestor = StellarKeypair::random();

    let event_id = [0xAA; 32];
    let vrf_proof = vec![0x01, 0x02, 0x03, 0x04]; // placeholder VRF proof

    // ========================================
    // Step 1: Node_1 initiates the chain
    // ========================================
    let (partial, _shard_1) = PartialToken::initiate(
        event_id,
        1741737600,
        Some(50_000_000), // 5 XLM
        3,                // 3 pairs total
        &node_1,
        &node_2,
        vrf_proof.clone(),
    )
    .unwrap();

    assert_eq!(partial.chain.links.len(), 1);
    assert_eq!(partial.remaining_pairs, 2);
    partial.verify_chain_integrity().unwrap();

    // Serialize and "gossip" the partial token
    let partial_bytes = serialize_partial_token(&partial).unwrap();
    assert!(is_symtoken(&partial_bytes));

    // ========================================
    // Step 2: Node_3 picks it up, extends with pair (Node_3, Node_4)
    // ========================================
    let mut partial = deserialize_partial_token(&partial_bytes).unwrap();
    // Chain integrity verified automatically during extend()
    let _shard_2 = partial.extend(&node_3, &node_4).unwrap();

    assert_eq!(partial.chain.links.len(), 2);
    assert_eq!(partial.remaining_pairs, 1);
    partial.verify_chain_integrity().unwrap();

    // Verify hash chain
    let link_0_hash = partial.chain.links[0].link_hash(&event_id);
    assert_eq!(partial.chain.links[1].prev_link_hash, link_0_hash);

    // Serialize and "gossip" again
    let partial_bytes = serialize_partial_token(&partial).unwrap();

    // ========================================
    // Step 3: Requestor receives partial, assembles final token
    // ========================================
    let partial = deserialize_partial_token(&partial_bytes).unwrap();

    // Assembly: no prior shard scalars needed — ephemeral key computed from public data
    let bearer_token = assemble_bearer_token(
        &partial,
        &requestor,
        &node_5, // requestor pairs with node_5
        7,                // slot id
        Some(1741824000), // expiration
    )
    .unwrap();

    // ========================================
    // Verification
    // ========================================

    // 1. Token type is Bearer
    assert_eq!(bearer_token.header.token_type, TokenType::Bearer);
    assert_eq!(bearer_token.header.denomination, Some(50_000_000));

    // 2. Chain has 3 links
    assert_eq!(bearer_token.chain.links.len(), 3);
    assert_eq!(bearer_token.chain.total_pairs, 3);
    assert_eq!(bearer_token.chain.required_pairs, 3); // n-of-n

    // 3. Chain consistency: partial keys sum to ephemeral key
    bearer_token.verify_chain().unwrap();
    verify_chain_public_key_from_links(
        &bearer_token.chain.links,
        &bearer_token.ephemeral_public_key,
    )
    .unwrap();

    // 4. Full chain integrity: signatures + hash chain + key consistency
    bearer_token.verify_chain_integrity().unwrap();

    // 5. Ephemeral address is valid Stellar address
    let addr = bearer_token.ephemeral_address();
    assert!(addr.starts_with('G'));
    assert_eq!(addr.len(), 56);

    // 6. Verify the ephemeral key matches independent composition
    //    (re-derive all shards with both keypairs to verify)
    let shard_1_rederived = derive_shard(&node_1, &node_2.verifying_key(), &event_id).unwrap();
    let shard_2_rederived = derive_shard(&node_3, &node_4.verifying_key(), &event_id).unwrap();
    let shard_3_rederived = derive_shard(&requestor, &node_5.verifying_key(), &event_id).unwrap();

    let info_1 = PairInfo::from_shard(&shard_1_rederived, node_1.stellar_address(), node_2.stellar_address());
    let info_2 = PairInfo::from_shard(&shard_2_rederived, node_3.stellar_address(), node_4.stellar_address());
    let info_3 = PairInfo::from_shard(&shard_3_rederived, requestor.stellar_address(), node_5.stellar_address());

    let mut builder = CompositionBuilder::new();
    builder.add_shard(shard_1_rederived, info_1);
    builder.add_shard(shard_2_rederived, info_2);
    builder.add_shard(shard_3_rederived, info_3);
    let (composed, _) = builder.build().unwrap();

    assert_eq!(
        bearer_token.ephemeral_public_key,
        composed.public_bytes(),
        "ephemeral key from assembly must match full composition"
    );

    // 7. Composed keypair can sign and verify (standard Ed25519)
    let test_msg = b"redeem this token";
    let sig = composed.sign(test_msg);
    composed
        .verifying_key()
        .verify_strict(test_msg, &sig)
        .expect("composed signature must be standard Ed25519");

    // 8. Serialize to SYMTOKEN container and roundtrip
    let container_bytes = serialize_bearer_token(&bearer_token, &requestor).unwrap();
    assert!(is_symtoken(&container_bytes));

    let parsed = deserialize_bearer_token(&container_bytes).unwrap();
    assert_eq!(parsed.header.event_id, bearer_token.header.event_id);
    assert_eq!(
        parsed.ephemeral_public_key,
        bearer_token.ephemeral_public_key
    );
    assert_eq!(parsed.chain.links.len(), 3);
    parsed.verify_chain().unwrap();
    parsed.verify_chain_integrity().unwrap();

    // 9. Signature verification
    verify_bearer_signature(&container_bytes, &requestor.raw_public()).unwrap();

    // 10. Wrong signer fails
    let wrong_signer = StellarKeypair::random();
    assert!(verify_bearer_signature(&container_bytes, &wrong_signer.raw_public()).is_err());

    // 11. The note carries no biscuit.
    //
    // Nothing needs one: no receive gate would parse it, no redemption
    // path would consult it, and the ledger answers every question it
    // could claim to. What it would do is put the requestor's Stellar
    // address inside every circulating note, which is an identity in a
    // bearer instrument. SYMTOKEN v4 and later carry none.
    //
    // Pinned as a test because a removed field is the kind of change that
    // comes back: the container is a byte format, and a reader that
    // expects a section the writer does not emit fails in a way that
    // looks like corruption.
    assert_eq!(parsed.header.version, SYMTOKEN_VERSION);
    // v4 dropped the biscuit section; v5 added the slot id, because the
    // mint keys its records by slot rather than by the ephemeral key
    // (a public value anyone could name first); v6 added the mint binding, so a note says
    // which deployment issued it and what it pays out in. Each is a
    // format change, and this is the assertion that makes a reader
    // notice one.
    assert_eq!(SYMTOKEN_VERSION, 6);
}

/// Test a 2-pair chain (minimum for daisy-chain).
#[test]
fn test_two_pair_bearer_token() {
    let node_1 = StellarKeypair::random();
    let node_2 = StellarKeypair::random();
    let requestor = StellarKeypair::random();
    let partner = StellarKeypair::random();

    let (partial, _shard_1) = PartialToken::initiate(
        [0x22; 32],
        1741737600,
        Some(1_000_000),
        2,
        &node_1,
        &node_2,
        vec![],
    )
    .unwrap();

    let token = assemble_bearer_token(
        &partial,
        &requestor,
        &partner,
        7,
        Some(1741824000),
    )
    .unwrap();

    let data = serialize_bearer_token(&token, &requestor).unwrap();
    let parsed = deserialize_bearer_token(&data).unwrap();
    parsed.verify_chain().unwrap();
    parsed.verify_chain_integrity().unwrap();
    verify_bearer_signature(&data, &requestor.raw_public()).unwrap();
}

/// Test that tampered container bytes fail signature verification.
#[test]
fn test_container_integrity() {
    let kp1 = StellarKeypair::random();
    let kp2 = StellarKeypair::random();
    let requestor = StellarKeypair::random();
    let kp3 = StellarKeypair::random();

    let (partial, _shard1) = PartialToken::initiate(
        [0x33; 32],
        1741737600,
        Some(100),
        2,
        &kp1,
        &kp2,
        vec![],
    )
    .unwrap();

    let token = assemble_bearer_token(
        &partial,
        &requestor,
        &kp3,
        7,
        None,
    )
    .unwrap();

    let mut data = serialize_bearer_token(&token, &requestor).unwrap();

    // Flip every byte position and verify failure
    for i in [12, 44, 100, data.len() / 2] {
        if i < data.len() - 64 {
            let original = data[i];
            data[i] ^= 0xFF;
            assert!(
                verify_bearer_signature(&data, &requestor.raw_public()).is_err(),
                "tampered byte at position {i} should fail verification"
            );
            data[i] = original; // restore
        }
    }
}

/// Test that chain link tampering is detected by verify_chain_integrity.
#[test]
fn test_chain_link_tampering_detected() {
    let kp1 = StellarKeypair::random();
    let kp2 = StellarKeypair::random();
    let kp3 = StellarKeypair::random();
    let kp4 = StellarKeypair::random();
    let requestor = StellarKeypair::random();
    let kp5 = StellarKeypair::random();

    let (mut partial, _) = PartialToken::initiate(
        [0x44; 32],
        1741737600,
        None,
        3,
        &kp1,
        &kp2,
        vec![],
    )
    .unwrap();

    let _ = partial.extend(&kp3, &kp4).unwrap();

    let mut token = assemble_bearer_token(
        &partial,
        &requestor,
        &kp5,
        7,
        None,
    )
    .unwrap();

    // Should verify cleanly
    token.verify_chain_integrity().unwrap();

    // Tamper with a ChainLink signature
    token.chain.links[1].signature_a[0] ^= 0xFF;
    assert!(token.verify_chain_integrity().is_err());
}
