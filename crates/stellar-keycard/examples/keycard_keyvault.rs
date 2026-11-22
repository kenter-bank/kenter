//! Prove `StellarKeycard` is a real `kenter_vault::KeyVault` backend — the same
//! trait `SoftVault` implements — driven against the jcardsim `SimServer`.
//!
//! connect → init → load SEP-0005 seed → then use ONLY the KeyVault trait
//! (`stellar_address`, `sign`, `public_key`, `list_keys`) and cross-check the
//! address against SEP-0005 and the signature with ed25519-dalek.
//!
//! Prereq: `gradlew simServer` on 127.0.0.1:21345.
//! Run: cargo run -p stellar-keycard --example keycard_keyvault

use hmac::{Hmac, Mac};
use kenter_vault::KeyVault;
use sha2::{Digest, Sha512};

use stellar_keycard::{
    DEFAULT_SIM_ADDR, DuressPin, InitParams, SimTransport, StellarKeycard, verify_ed25519,
};

const MNEMONIC: &str = "illness spike retreat truth genius clock brain pass fit cave bargain toe";
const EXPECTED_G: &str = "GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6";
// Not all-zeros. With an inherited duress PIN the card takes the PUK's
// first six digits as one, and INIT refuses a duress PIN equal to the
// PIN — so "000000" with a zero PUK never installed at all. Chosen
// values, and an explicit duress PIN, which is what anything real sends.
const PIN: &[u8] = b"123456";
const PUK: &[u8] = b"987654321098";
const DURESS: &[u8] = b"654321";

fn main() {
    if let Err(e) = run() {
        println!("FAILED: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut sim = SimTransport::connect(DEFAULT_SIM_ADDR)
        .map_err(|e| format!("connect (simServer running?): {e}"))?;
    sim.reset().map_err(|e| e.to_string())?;

    let mut kc = StellarKeycard::connect(sim).map_err(|e| format!("SELECT/connect: {e}"))?;
    kc.init(&InitParams::new(PIN, PUK, DuressPin::Chosen(DURESS)))
        .map_err(|e| format!("init: {e}"))?;
    kc.load_bip39_seed(&bip39_seed(MNEMONIC), PIN)
        .map_err(|e| format!("load seed: {e}"))?;
    println!("provisioned (SEP-0005 seed on card)");

    // From here on: only the KeyVault trait.
    let vault: &mut dyn KeyVault = &mut kc;

    let addr = vault.stellar_address(0).map_err(|e| e.to_string())?;
    println!("  KeyVault::stellar_address(0) = {addr}");
    if addr != EXPECTED_G {
        return Err(format!("address mismatch: {addr} != {EXPECTED_G}"));
    }
    println!("✓ address matches SEP-0005 vector 1 (no PIN — served from cache)");

    let hash: [u8; 32] = sha2::Sha256::digest(b"kenter keyvault trait sign").into();
    let sig = vault.sign(0, &hash, PIN).map_err(|e| e.to_string())?;
    let pk = vault.public_key(0).map_err(|e| e.to_string())?;
    if !verify_ed25519(&pk, &hash, &sig) {
        return Err("ed25519-dalek rejected KeyVault::sign output".into());
    }
    println!("✓ KeyVault::sign(0, hash) verified with ed25519-dalek");

    let keys = vault.list_keys().map_err(|e| e.to_string())?;
    println!(
        "  KeyVault::list_keys = {:?}",
        keys.iter().map(|k| &k.label).collect::<Vec<_>>()
    );

    // Signing helper: produce a Stellar DecoratedSignature for a transaction hash.
    // (The host builds the tx XDR via an SDK; here we stand in a placeholder.)
    let nid = stellar_keycard::network_id("Test SDF Network ; September 2015");
    let tx_hash = stellar_keycard::transaction_hash(&nid, b"<transaction xdr from a Stellar SDK>");
    let ds = kc
        .sign_stellar_tx(0, &tx_hash, PIN)
        .map_err(|e| e.to_string())?;
    if !verify_ed25519(&pk, &tx_hash, &ds.signature) {
        return Err("DecoratedSignature failed ed25519 verification".into());
    }
    if ds.hint != pk[28..32] {
        return Err("DecoratedSignature hint != last 4 bytes of pubkey".into());
    }
    println!(
        "✓ sign_stellar_tx → DecoratedSignature (hint {}, {} XDR bytes)",
        hex::encode(ds.hint),
        ds.to_xdr().len()
    );
    println!("  base64: {}", ds.to_base64());

    println!("\nStellarKeycard IS a KeyVault backend — same trait as SoftVault, on hardware.");
    Ok(())
}

/// BIP-39 seed = PBKDF2-HMAC-SHA512(mnemonic, "mnemonic", 2048) → 64 bytes.
fn bip39_seed(mnemonic: &str) -> [u8; 64] {
    type H = Hmac<Sha512>;
    let mut u: [u8; 64] = {
        let mut m = <H as Mac>::new_from_slice(mnemonic.as_bytes()).unwrap();
        m.update(b"mnemonic");
        m.update(&1u32.to_be_bytes());
        m.finalize().into_bytes().into()
    };
    let mut out = u;
    for _ in 1..2048 {
        let mut m = <H as Mac>::new_from_slice(mnemonic.as_bytes()).unwrap();
        m.update(&u);
        let next: [u8; 64] = m.finalize().into_bytes().into();
        u = next;
        for (o, b) in out.iter_mut().zip(next.iter()) {
            *o ^= b;
        }
    }
    out
}
