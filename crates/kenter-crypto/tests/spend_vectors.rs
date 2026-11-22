//! Spend-mode byte layouts, pinned for the other implementations.
//!
//! Unlike `cross_language.rs`, which checks Rust against vectors produced
//! elsewhere, this file runs the other way: **`kenter-crypto` is the source of
//! truth**, and the consumers are a C firmware (`keycard-shell`) and a
//! JavaCard applet (`kenter-keycard`, a fork of Status's keycard) that must
//! reproduce these bytes exactly or their signatures will not verify on-chain.
//!
//! Those repos cannot depend on this crate. Pinning the layouts by
//! transcribing them into prose fails silently: a prose description can lag
//! a new field and nothing anywhere fails. This test is the thing that fails.
//!
//! # Changing a layout
//!
//! Deliberate changes are blessed, not edited:
//!
//! ```text
//! KENTER_BLESS_VECTORS=1 cargo test -p kenter-crypto --test spend_vectors
//! ```
//!
//! which rewrites `tests/vectors/spend_vectors.json`. The diff is then a
//! review item, and the consumers listed in the file's `consumers` field are
//! what the reviewer has to go and update.

use kenter_crypto::domain::DomainSeparation;
use kenter_crypto::keypair::StellarKeypair;
use kenter_crypto::spend::{
    authorize_redeem, authorize_spend, owner_commitment, redeem_owner_digest,
    redeem_owner_signable_bytes, spend_auth_digest, spend_signable_bytes, verify_redeem_owner,
    verify_spend,
};
use serde_json::{json, Value};

/// Where the committed vectors live, relative to the workspace root.
const VECTORS: &str = "../../tests/vectors/spend_vectors.json";

/// Fixed seeds, so the whole file is a pure function of the layouts. Nothing
/// here is secret or reachable — a vector file with a random key in it would
/// churn on every run and teach everyone to ignore the diff.
fn owner(seed: u8) -> StellarKeypair {
    StellarKeypair::from_raw_secret(&[seed; 32])
}

/// The address whose XDR the redeem vector signs over.
const RECIPIENT_ADDRESS: &str = "GALMHEXVYCGR3DIEJJGVF7DRP2Y5HSXAI7RTV6FBQIXW7LQ2YOKWP5LR";

/// A recipient as the contract sees it: `Address::to_xdr`, which is an
/// **ScVal**, not a bare account id.
///
/// `00000012` SCV_ADDRESS, `00000000` SC_ADDRESS_TYPE_ACCOUNT, `00000000`
/// PUBLIC_KEY_TYPE_ED25519, then the 32-byte key — **44 bytes**. The same
/// value `kenter-mint`'s `recipient_xdr_is_pinned` asserts.
///
/// **Not 36 bytes**, a bare `KEY_TYPE_ED25519 || key`, which is the easy
/// mistake. Kenter's own path is right regardless because it calls
/// `kenter_client::tx::address_xdr`, so the mistake would break nothing
/// in-tree — but any external signer built from this file would sign the
/// wrong message and be rejected on-chain, which is the single failure this
/// file exists to prevent.
///
/// Still literal bytes, because the point is to fix what the *signature*
/// covers. What stops it drifting again is not care: `kenter-client`'s
/// `vectors_recipient_matches_address_xdr` re-derives it from
/// [`RECIPIENT_ADDRESS`] with the real encoder and fails if they disagree.
const RECIPIENT_XDR: [u8; 44] = [
    0x00, 0x00, 0x00, 0x12, // ScVal: SCV_ADDRESS
    0x00, 0x00, 0x00, 0x00, // ScAddress: SC_ADDRESS_TYPE_ACCOUNT
    0x00, 0x00, 0x00, 0x00, // PublicKey: PUBLIC_KEY_TYPE_ED25519
    0x16, 0xc3, 0x92, 0xf5, 0xc0, 0x8d, 0x1d, 0x8d, 0x04, 0x4a, 0x4d, 0x52, 0xfc, 0x71, 0x7e, 0xb1,
    0xd3, 0xca, 0xe0, 0x47, 0xe3, 0x3a, 0xf8, 0xa1, 0x82, 0x2f, 0x6f, 0xae, 0x1a, 0xc3, 0x95, 0x67,
];

/// The mint whose address every owner digest covers.
const CONTRACT_ADDRESS: &str = "CARCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEVQO";

/// `Address::to_xdr` for a **contract**: `00000012` SCV_ADDRESS,
/// `00000001` SC_ADDRESS_TYPE_CONTRACT, then the 32-byte id - **40 bytes**,
/// four shorter than an account, because a contract id is the payload itself
/// rather than a typed public key.
///
/// Signatures are bound to it so one written against a testnet mint cannot
/// drain a mainnet one holding escrow for the same ephemeral key. Derived,
/// not transcribed: `kenter-client`'s `vectors_contract_matches_address_xdr`
/// re-computes it from [`CONTRACT_ADDRESS`] with the real encoder.
const CONTRACT_XDR: [u8; 40] = [
    0x00, 0x00, 0x00, 0x12, // ScVal: SCV_ADDRESS
    0x00, 0x00, 0x00, 0x01, // ScAddress: SC_ADDRESS_TYPE_CONTRACT
    0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
    0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
];

/// The note has been spent on twice already. Deliberately not zero: a nonce
/// that is always zero in the vectors is a nonce a consumer can omit and
/// still match.
const SPEND_NONCE: u32 = 2;
/// The slot the note was registered under. Non-zero for the same reason
/// the nonce is: a field that is always zero is a field a consumer can
/// omit and still match.
const SLOT: u32 = 9;


fn build() -> Value {
    let ephemeral_key = [0x11u8; 32];

    // Owner commitments, the thing every other layout is built out of.
    let alice = owner(0xA1);
    let bob = owner(0xB2);
    let alice_commit = owner_commitment(&alice.raw_public());
    let bob_commit = owner_commitment(&bob.raw_public());

    // Spend: Alice hands the note to Bob.
    let spend_bytes = spend_signable_bytes(
        &CONTRACT_XDR,
        SLOT,
        &ephemeral_key,
        &alice_commit,
        &bob_commit,
        SPEND_NONCE,
    );
    let spend_digest = spend_auth_digest(
        &CONTRACT_XDR,
        SLOT,
        &ephemeral_key,
        &alice_commit,
        &bob_commit,
        SPEND_NONCE,
    );
    let spend_auth = authorize_spend(
        &alice,
        &CONTRACT_XDR,
        SLOT,
        &ephemeral_key,
        &alice_commit,
        &bob_commit,
        SPEND_NONCE,
    );

    // Redeem: Bob cashes it out to an address that is not his own.
    let redeem_bytes = redeem_owner_signable_bytes(
        &CONTRACT_XDR,
        SLOT,
        &ephemeral_key,
        &bob_commit,
        SPEND_NONCE,
        &RECIPIENT_XDR,
    );
    let redeem_digest = redeem_owner_digest(
        &CONTRACT_XDR,
        SLOT,
        &ephemeral_key,
        &bob_commit,
        SPEND_NONCE,
        &RECIPIENT_XDR,
    );
    let redeem_proof = authorize_redeem(
        &bob,
        &CONTRACT_XDR,
        SLOT,
        &ephemeral_key,
        &bob_commit,
        SPEND_NONCE,
        &RECIPIENT_XDR,
    );

    // A key of all zeroes is not a valid Ed25519 public key, but the
    // commitment is a plain hash and must not special-case it. Pinned so
    // nobody "helpfully" adds a check here.
    let zero = [0u8; 32];
    let zero_case = json!({
        "label": "all-zero pubkey (hash only, not a valid key)",
        "owner_pubkey_hex": hex::encode(zero),
        "commitment_hex": hex::encode(owner_commitment(&zero)),
    });

    json!({
        "_comment":
            "Generated by crates/kenter-crypto/tests/spend_vectors.rs. Do not hand-edit: \
             regenerate with KENTER_BLESS_VECTORS=1 cargo test -p kenter-crypto --test \
             spend_vectors. kenter-crypto is the source of truth for these bytes.",
        "consumers": [
            "keycard-shell — app/crypto/ (C, STM32H5). Builds these \
             messages and hashes them, so the layouts below are its contract.",
            "kenter-keycard — signs the 32-byte digest it is handed and never sees the \
             layout, so it depends on the digest convention here rather than on byte order. \
             Its shared layout is SLIP-0010 derivation: tests/vectors/owner_key_vectors.json."
        ],
        "notes": {
            "digest": "Owner authorizations sign SHA-256(message), never the message, so a \
                       card that can only signHash(32 bytes) produces the same signature as \
                       software. See docs/architecture/spend-mode.md.",
            "signatures": "Ed25519 is deterministic (RFC 8032), so these are reproducible \
                           from the secret alone — a consumer can check its signer, not just \
                           its byte layout."
        },
        "domain_tags": {
            "spend_owner_commit": ascii(DomainSeparation::SPEND_OWNER_COMMIT),
            "spend_auth": ascii(DomainSeparation::SPEND_AUTH),
            "spend_redeem": ascii(DomainSeparation::SPEND_REDEEM),
        },
        "owner_commitment": {
            "layout": "SHA-256( \"kntr_v1:spend:owner\" || owner_pubkey[32] )",
            "cases": [
                commitment_case("alice", &alice),
                commitment_case("bob", &bob),
                zero_case,
            ],
        },
        "spend_auth": {
            "layout": "\"kntr_v1:spend:auth\" || contract_xdr[variable] || slot_id[4, BE] \
                       || ephemeral_key[32] || current_commitment[32] \
                       || new_commitment[32] \
                       || spend_nonce[4, BE]",
            "signed": "SHA-256(layout)",
            "binding_note":
                "contract_xdr and spend_nonce are both required. The contract address \
                 stops an authorisation written for one deployment draining another holding \
                 escrow for the same ephemeral key. The nonce makes an authorisation good \
                 for exactly one transfer: without it the digest repeats whenever a note \
                 returns to a commitment it has held before - and the static pay tag is a \
                 reusable address, so change and refunds do exactly that, letting a former \
                 payee re-post an old authorisation and take the note back.",
            "case": {
                "label": "alice spends to bob",
                "contract_address": CONTRACT_ADDRESS,
                "contract_xdr_hex": hex::encode(CONTRACT_XDR),
                "contract_xdr_len": CONTRACT_XDR.len(),
                "slot_id": SLOT,
                "spend_nonce": SPEND_NONCE,
                "ephemeral_key_hex": hex::encode(ephemeral_key),
                "current_commitment_hex": hex::encode(alice_commit),
                "new_commitment_hex": hex::encode(bob_commit),
                "signable_hex": hex::encode(&spend_bytes),
                "signable_len": spend_bytes.len(),
                "digest_hex": hex::encode(spend_digest),
                "signer_raw_secret_hex": hex::encode([0xA1u8; 32]),
                "signer_pubkey_hex": hex::encode(alice.raw_public()),
                "signature_hex": hex::encode(spend_auth.signature),
            },
        },
        "redeem_owner": {
            "layout": "\"kntr_v1:spend:redeem\" || contract_xdr[variable] || slot_id[4, BE] \
                       || ephemeral_key[32] || owner_commitment[32] \
                       || spend_nonce[4, BE] \
                       || recipient_xdr[variable]",
            "signed": "SHA-256(layout)",
            "recipient_note":
                "recipient_xdr is NOT fixed-length and NOT optional. It binds the payout \
                 to an address; without it a proof authorises \
                 'redeem this note' rather than 'pay this note to this address', and anyone \
                 holding it could redirect the payout. It is `Address::to_xdr`, an ScVal \
                 (SCV_ADDRESS, SC_ADDRESS_TYPE_ACCOUNT, PUBLIC_KEY_TYPE_ED25519, key) and \
                 44 bytes for an account, NOT a bare 36-byte account id. Derive it, do \
                 not transcribe it.",
            "case": {
                "label": "bob redeems to a third address",
                "contract_address": CONTRACT_ADDRESS,
                "contract_xdr_hex": hex::encode(CONTRACT_XDR),
                "contract_xdr_len": CONTRACT_XDR.len(),
                "slot_id": SLOT,
                "spend_nonce": SPEND_NONCE,
                "ephemeral_key_hex": hex::encode(ephemeral_key),
                "owner_commitment_hex": hex::encode(bob_commit),
                "recipient_address": RECIPIENT_ADDRESS,
                "recipient_xdr_hex": hex::encode(RECIPIENT_XDR),
                "recipient_xdr_len": RECIPIENT_XDR.len(),
                "signable_hex": hex::encode(&redeem_bytes),
                "signable_len": redeem_bytes.len(),
                "digest_hex": hex::encode(redeem_digest),
                "signer_raw_secret_hex": hex::encode([0xB2u8; 32]),
                "signer_pubkey_hex": hex::encode(bob.raw_public()),
                "signature_hex": hex::encode(redeem_proof.signature),
            },
        },
    })
}

fn ascii(tag: &[u8]) -> Value {
    json!({
        "ascii": String::from_utf8_lossy(tag),
        "hex": hex::encode(tag),
        "len": tag.len(),
    })
}

fn commitment_case(label: &str, kp: &StellarKeypair) -> Value {
    json!({
        "label": label,
        "owner_pubkey_hex": hex::encode(kp.raw_public()),
        "commitment_hex": hex::encode(owner_commitment(&kp.raw_public())),
    })
}

/// The committed file still describes what this crate does.
///
/// A failure here is not a broken test — it is a layout change that has not
/// reached the firmware or the applet yet.
#[test]
fn the_committed_vectors_match_this_crate() {
    let built = serde_json::to_string_pretty(&build()).expect("serializing vectors") + "\n";

    if std::env::var_os("KENTER_BLESS_VECTORS").is_some() {
        std::fs::write(VECTORS, &built).expect("writing vectors");
        return;
    }

    let committed = std::fs::read_to_string(VECTORS).unwrap_or_else(|e| {
        panic!("{VECTORS}: {e}\nGenerate it with KENTER_BLESS_VECTORS=1")
    });

    // Compared as parsed JSON, so re-indentation is not a failure and a real
    // change cannot hide behind one.
    let a: Value = serde_json::from_str(&committed).expect("committed vectors are not JSON");
    let b: Value = serde_json::from_str(&built).unwrap();
    if a == b {
        return;
    }

    // Name the sections that moved rather than printing both files. A diff of
    // two 5KB JSON blobs in a test log is a thing people scroll past, and the
    // whole point of this test is to be read.
    let moved: Vec<&str> = b
        .as_object()
        .expect("vectors are an object")
        .keys()
        .filter(|k| a.get(k.as_str()) != b.get(k.as_str()))
        .map(String::as_str)
        .collect();

    panic!(
        "\n\nThe spend-mode byte layouts changed: {moved:?}\n\n\
         keycard-shell builds these messages and will produce \
         signatures the mint rejects until it is updated.\n\n\
         If the change is intended, bless it and update them in the same change:\n\
         \x20 KENTER_BLESS_VECTORS=1 cargo test -p kenter-crypto --test spend_vectors\n\
         then read the diff on {VECTORS}.\n"
    );
}

/// The vectors are only worth pinning if they are self-consistent: a consumer
/// that reproduces the bytes and the signature should also pass the check the
/// mint performs.
#[test]
fn the_pinned_signatures_verify() {
    let ephemeral_key = [0x11u8; 32];
    let alice = owner(0xA1);
    let bob = owner(0xB2);
    let alice_commit = owner_commitment(&alice.raw_public());
    let bob_commit = owner_commitment(&bob.raw_public());

    let auth = authorize_spend(
        &alice,
        &CONTRACT_XDR,
        SLOT,
        &ephemeral_key,
        &alice_commit,
        &bob_commit,
        SPEND_NONCE,
    );
    assert!(
        verify_spend(&CONTRACT_XDR, SLOT, &ephemeral_key, &alice_commit, SPEND_NONCE, &auth).is_ok(),
        "the spend vector does not pass the check the mint makes"
    );

    let proof = authorize_redeem(
        &bob,
        &CONTRACT_XDR,
        SLOT,
        &ephemeral_key,
        &bob_commit,
        SPEND_NONCE,
        &RECIPIENT_XDR,
    );
    assert!(
        verify_redeem_owner(
            &CONTRACT_XDR,
            SLOT,
            &ephemeral_key,
            &bob_commit,
            SPEND_NONCE,
            &RECIPIENT_XDR,
            &proof,
        )
        .is_ok(),
        "the redeem vector does not pass the check the mint makes"
    );

    // And the recipient is actually covered: the same proof against a
    // different payout address must fail. This is the property the field was
    // added for, so it is the one worth a test of its own.
    let mut elsewhere = RECIPIENT_XDR;
    elsewhere[35] ^= 0x01;
    assert!(
        verify_redeem_owner(
            &CONTRACT_XDR,
            SLOT,
            &ephemeral_key,
            &bob_commit,
            SPEND_NONCE,
            &elsewhere,
            &proof,
        )
        .is_err(),
        "the owner proof did not bind the recipient — the payout can be redirected"
    );

    // Same for the nonce: the pinned signature is good for exactly the spend
    // count it was written against, so a consumer that omits the field will
    // match the vector by accident at nonce 0 and nowhere else.
    assert!(
        verify_spend(
            &CONTRACT_XDR,
            SLOT,
            &ephemeral_key,
            &alice_commit,
            SPEND_NONCE + 1,
            &auth
        )
        .is_err(),
        "the spend authorization did not bind the nonce"
    );
}
