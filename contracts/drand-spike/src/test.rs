//! Fixtures are a real quicknet round, fetched from two
//! independent mirrors (api.drand.sh and drand.cloudflare.com), which
//! agreed byte for byte. No test reaches the network.
//!
//!   cargo test -- --nocapture                      native host (undercounts)
//!   cargo build --target wasm32v1-none --release
//!   cargo test --features wasm-bench -- --nocapture  the real wasm

extern crate std;
use std::{println, vec::Vec as StdVec};

use ark_ec::AffineRepr;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use soroban_sdk::{BytesN, Env};

use crate::{DrandSpike, DrandSpikeClient, Error, NEG_G2};

/// quicknet's group key (G2, compressed), from `/info`.
const PK: &str = "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a";
const ROUND: u64 = 33_971_844;
/// That round's signature (G1, compressed).
const SIG: &str = "8414a8586cf92eaca970d9d177ff4a323506c409e65a2862df44dfb5a0959073bb989d31a2844fdb69043a918a2a0d6e";
/// drand's published `randomness` for it: sha256 of the compressed signature.
const RANDOMNESS: &str = "316fbbf2f6372c3663d6510cdba40c7048f22e2cb6175c4e66f8d5a4bde70045";

const TX_LIMIT: u64 = 100_000_000;

#[cfg(feature = "wasm-bench")]
const SPIKE_WASM: &[u8] = include_bytes!("../target/wasm32v1-none/release/drand_spike.wasm");

/// Compressed (as drand publishes) to uncompressed (as Soroban takes). This
/// is the wallet's job in the real flow.
fn g1_uncompressed(hex_c: &str) -> [u8; 96] {
    let p = ark_bls12_381::G1Affine::deserialize_compressed(&hex::decode(hex_c).unwrap()[..]).unwrap();
    let mut out = StdVec::new();
    p.serialize_uncompressed(&mut out).unwrap();
    out.try_into().unwrap()
}

fn g2_uncompressed(hex_c: &str) -> [u8; 192] {
    let p = ark_bls12_381::G2Affine::deserialize_compressed(&hex::decode(hex_c).unwrap()[..]).unwrap();
    let mut out = StdVec::new();
    p.serialize_uncompressed(&mut out).unwrap();
    out.try_into().unwrap()
}

fn setup(env: &Env, wasm: bool) -> DrandSpikeClient<'_> {
    let pk = BytesN::from_array(env, &g2_uncompressed(PK));
    #[cfg(feature = "wasm-bench")]
    if wasm {
        return DrandSpikeClient::new(env, &env.register(SPIKE_WASM, (pk,)));
    }
    let _ = wasm;
    DrandSpikeClient::new(env, &env.register(DrandSpike, (pk,)))
}

fn sha256(b: &[u8]) -> [u8; 32] {
    let env = Env::default();
    env.crypto()
        .sha256(&soroban_sdk::Bytes::from_slice(&env, b))
        .to_array()
}

#[test]
fn neg_g2_is_the_negated_generator() {
    let g = -ark_bls12_381::G2Affine::generator();
    let mut out = StdVec::new();
    g.serialize_uncompressed(&mut out).unwrap();
    assert_eq!(out.as_slice(), &NEG_G2[..]);
}

#[test]
fn the_fixture_is_drands_own_round() {
    // drand's randomness is sha256(compressed sig): if this holds, the
    // fixture is the round drand published, not a transcription error.
    assert_eq!(hex::encode(sha256(&hex::decode(SIG).unwrap())), RANDOMNESS);
}

fn verify_and_measure(wasm: bool) -> (u64, u64) {
    let env = Env::default();
    let c = setup(&env, wasm);
    let sig = g1_uncompressed(SIG);
    let mut budget = env.cost_estimate().budget();
    budget.reset_unlimited();
    let seed = c.verify(&ROUND, &BytesN::from_array(&env, &sig));
    let cpu = env.cost_estimate().budget().cpu_instruction_cost();
    let mem = env.cost_estimate().budget().memory_bytes_cost();
    assert_eq!(seed.to_array(), sha256(&sig), "seed is sha256 of the uncompressed signature");
    (cpu, mem)
}

#[test]
fn a_real_round_verifies_native() {
    let (cpu, mem) = verify_and_measure(false);
    println!("native: {cpu} instructions ({:.1}% of {TX_LIMIT}), {mem} bytes", cpu as f64 * 100.0 / TX_LIMIT as f64);
    assert!(cpu < TX_LIMIT);
}

#[cfg(feature = "wasm-bench")]
#[test]
fn a_real_round_verifies_wasm() {
    let (cpu, mem) = verify_and_measure(true);
    println!("wasm:   {cpu} instructions ({:.1}% of {TX_LIMIT}), {mem} bytes", cpu as f64 * 100.0 / TX_LIMIT as f64);
    assert!(cpu < TX_LIMIT / 2, "must leave room for seed_print's own work");
}

#[test]
fn the_wrong_round_is_refused() {
    let env = Env::default();
    let c = setup(&env, false);
    let sig = BytesN::from_array(&env, &g1_uncompressed(SIG));
    assert_eq!(
        c.try_verify(&(ROUND + 1), &sig),
        Err(Ok(Error::BadBeacon)),
    );
}

#[test]
fn another_valid_point_is_refused() {
    // A well-formed G1 point that is not the signature: the generator.
    let env = Env::default();
    let c = setup(&env, false);
    let mut g = StdVec::new();
    ark_bls12_381::G1Affine::generator().serialize_uncompressed(&mut g).unwrap();
    let g: [u8; 96] = g.try_into().unwrap();
    assert_eq!(
        c.try_verify(&ROUND, &BytesN::from_array(&env, &g)),
        Err(Ok(Error::BadBeacon)),
    );
}

#[test]
fn a_point_off_the_curve_traps() {
    // Flip one bit of y: no longer on the curve. The host refuses the
    // input before any pairing, so this is a trap, not BadBeacon.
    let env = Env::default();
    let c = setup(&env, false);
    let mut sig = g1_uncompressed(SIG);
    sig[95] ^= 1;
    assert!(c.try_verify(&ROUND, &BytesN::from_array(&env, &sig)).is_err());
}

#[test]
fn the_negated_signature_is_refused() {
    // -sig is on the curve and in the subgroup, so it passes the host's
    // checks; only the pairing can refuse it.
    let env = Env::default();
    let c = setup(&env, false);
    let p = ark_bls12_381::G1Affine::deserialize_compressed(&hex::decode(SIG).unwrap()[..]).unwrap();
    let mut out = StdVec::new();
    (-p).serialize_uncompressed(&mut out).unwrap();
    let neg: [u8; 96] = out.try_into().unwrap();
    assert_eq!(
        c.try_verify(&ROUND, &BytesN::from_array(&env, &neg)),
        Err(Ok(Error::BadBeacon)),
    );
}

/// The uncompressed fixtures, for invoking a deployed spike by hand.
#[test]
fn print_uncompressed_fixtures() {
    println!("PK_U {}", hex::encode(g2_uncompressed(PK)));
    println!("SIG_U {}", hex::encode(g1_uncompressed(SIG)));
}
