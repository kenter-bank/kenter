//! WASM bridge for the Kenter PWA wallet spike.
//!
//! Thin façade over `kenter-crypto`. The purpose of this crate is to answer one
//! question before any UI is built: does the native Rust crypto compile to
//! `wasm32-unknown-unknown`, load in a browser, and round-trip a real operation
//! at an acceptable bundle size on a low-end phone?
//!
//! This is deliberately minimal. It exposes just enough real crypto — keypair
//! generation (which drives `rand`/`getrandom` through the wasm boundary) and a
//! sign→verify round-trip — to make the compiled artifact meaningful. Depending
//! on `kenter-crypto` at all forces its dependency tree to compile for wasm,
//! which is the real unknown.

use kenter_crypto::compose::CompositionBuilder;
use kenter_crypto::container::{deserialize_bearer_token, serialize_bearer_token};
use kenter_crypto::keypair::StellarKeypair;
use kenter_crypto::shard::{derive_shard, PairInfo};
use kenter_crypto::token::{assemble_bearer_token, PartialToken};
use wasm_bindgen::prelude::*;

/// A generated wallet keypair, exposed to JS as `{ address, secret }`.
#[wasm_bindgen(getter_with_clone)]
pub struct WalletKeypair {
    /// Stellar public address (G...).
    pub address: String,
    /// Stellar secret key (S...). Software-only custody in the PWA.
    pub secret: String,
}

/// Generate a fresh random keypair. Drives `rand::rngs::OsRng` →
/// `getrandom` → the browser's `crypto.getRandomValues` on wasm.
#[wasm_bindgen]
pub fn generate_keypair() -> WalletKeypair {
    let kp = StellarKeypair::random();
    WalletKeypair {
        address: kp.stellar_address(),
        secret: kp.stellar_secret().to_string(),
    }
}

/// Derive the Stellar address from a secret key (S...). Round-trips strkey
/// encode/decode — errors surface to JS as a thrown exception.
#[wasm_bindgen]
pub fn address_from_secret(secret: &str) -> Result<String, JsError> {
    let kp = StellarKeypair::from_stellar_secret(secret)
        .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(kp.stellar_address())
}

/// Sign a message and verify it back, end-to-end, returning whether the
/// signature verified. Exercises ed25519 sign + verify through wasm.
#[wasm_bindgen]
pub fn sign_verify_roundtrip(secret: &str, message: &[u8]) -> Result<bool, JsError> {
    let kp = StellarKeypair::from_stellar_secret(secret)
        .map_err(|e| JsError::new(&e.to_string()))?;
    let sig = kp.sign(message);
    Ok(StellarKeypair::verify(&kp.verifying_key(), message, &sig).is_ok())
}

/// Structured result of the full-loop self-test, exposed to JS.
#[wasm_bindgen(getter_with_clone)]
pub struct LoopResult {
    /// Size of the serialized SYMTOKEN container in bytes.
    pub container_bytes: usize,
    /// Number of authenticated chain links (== pairs) in the assembled token.
    pub chain_links: usize,
    /// Stellar address (G...) derived from the token's ephemeral public key.
    pub ephemeral_address: String,
    /// The independently-composed keypair reproduces the token's ephemeral key.
    pub composed_key_matches: bool,
    /// serialize → deserialize preserved the ephemeral key + all chain links.
    pub roundtrip_ok: bool,
    /// The composed keypair signs and verifies a redemption message.
    pub sign_verify_ok: bool,
    /// The container carries no biscuit section (SYMTOKEN v4).
    ///
    /// Kept as a probe rather than dropped with the field: this harness
    /// exists to catch a wasm build that silently diverges from native,
    /// and a format version is exactly the sort of thing that can.
    pub version_ok: bool,
}

/// Run the full bearer-token loop end-to-end **inside wasm**: a 3-pair daisy
/// chain (initiate → gossip/serialize → extend → assemble), container
/// serialize→deserialize round-trip, independent shard re-composition, and a
/// sign→verify over the composed keypair. This exercises the heavy paths at
/// *runtime*, not just compile-time.
///
/// Mirrors the native `test_full_daisy_chain_3_pairs` integration test, but
/// returns a structured result instead of asserting, so a browser harness can
/// display and time it. Errors surface to JS as thrown exceptions.
#[wasm_bindgen]
pub fn full_loop_selftest() -> Result<LoopResult, JsError> {
    let err = |e: kenter_crypto::error::CryptoError| JsError::new(&e.to_string());

    // Participants.
    let node_1 = StellarKeypair::random();
    let node_2 = StellarKeypair::random();
    let node_3 = StellarKeypair::random();
    let node_4 = StellarKeypair::random();
    let node_5 = StellarKeypair::random();
    let requestor = StellarKeypair::random();

    let event_id = [0xAA; 32];
    let denom = 50_000_000u64;

    // Pair 0 — initiate.
    let (mut partial, _s1) = PartialToken::initiate(
        event_id, 1_741_737_600, Some(denom), 3, &node_1, &node_2, vec![1, 2, 3, 4],
    )
    .map_err(err)?;
    // Pair 1 — extend (gossip hop).
    let _s2 = partial.extend(&node_3, &node_4).map_err(err)?;
    // Pair 2 — requestor assembles the final bearer token.
    let token = assemble_bearer_token(&partial, &requestor, &node_5, 7, Some(1_741_824_000))
        .map_err(err)?;

    let ephemeral_address = token.ephemeral_address();
    let chain_links = token.chain.links.len();

    // Container serialize → deserialize round-trip.
    let container = serialize_bearer_token(&token, &requestor).map_err(err)?;
    let parsed = deserialize_bearer_token(&container).map_err(err)?;
    parsed.verify_chain_integrity().map_err(err)?;
    let roundtrip_ok = parsed.ephemeral_public_key == token.ephemeral_public_key
        && parsed.chain.links.len() == chain_links;

    // Independently re-compose the ephemeral keypair from the three shards.
    let s1 = derive_shard(&node_1, &node_2.verifying_key(), &event_id).map_err(err)?;
    let s2 = derive_shard(&node_3, &node_4.verifying_key(), &event_id).map_err(err)?;
    let s3 = derive_shard(&requestor, &node_5.verifying_key(), &event_id).map_err(err)?;
    let i1 = PairInfo::from_shard(&s1, node_1.stellar_address(), node_2.stellar_address());
    let i2 = PairInfo::from_shard(&s2, node_3.stellar_address(), node_4.stellar_address());
    let i3 = PairInfo::from_shard(&s3, requestor.stellar_address(), node_5.stellar_address());
    let mut builder = CompositionBuilder::new();
    builder.add_shard(s1, i1);
    builder.add_shard(s2, i2);
    builder.add_shard(s3, i3);
    let (composed, _) = builder.build().map_err(err)?;
    let composed_key_matches = composed.public_bytes() == token.ephemeral_public_key;

    // The composed keypair signs a redemption message and verifies it.
    let msg = b"redeem this token";
    let sig = composed.sign(msg);
    let sign_verify_ok = composed.verifying_key().verify_strict(msg, &sig).is_ok();

    let version_ok =
        parsed.header.version == kenter_crypto::container::SYMTOKEN_VERSION;

    Ok(LoopResult {
        container_bytes: container.len(),
        chain_links,
        ephemeral_address,
        composed_key_matches,
        roundtrip_ok,
        sign_verify_ok,
        version_ok,
    })
}

/// Crate version probe — confirms the module loaded and is callable from JS.
#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
