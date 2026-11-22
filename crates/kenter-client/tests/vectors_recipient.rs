//! The redeem vector's recipient must be what the contract actually hashes.
//!
//! `tests/vectors/spend_vectors.json` exists so that `keycard-shell` and the
//! applet do not have to transcribe Kenter's byte layouts by hand. The
//! recipient field was then itself transcribed by hand, as a bare 36-byte
//! account id, when the mint hashes `Address::to_xdr` — an **ScVal**, 44
//! bytes. Kenter's own path was unaffected, because it calls `address_xdr`;
//! anything built from the file was not.
//!
//! This test lives here rather than beside the vectors because this is the
//! crate that owns the encoder. Re-deriving beats re-reading: a comment
//! saying "44 bytes" is checked by nobody, and this is.

use kenter_client::tx::address_xdr;

const VECTORS: &str = "../../tests/vectors/spend_vectors.json";

#[test]
fn vectors_recipient_matches_address_xdr() {
    let raw =
        std::fs::read_to_string(VECTORS).unwrap_or_else(|e| panic!("{VECTORS}: {e}"));
    let v: serde_json::Value = serde_json::from_str(&raw).expect("vectors are not JSON");
    let case = &v["redeem_owner"]["case"];

    let address = case["recipient_address"].as_str().expect("recipient_address");
    let pinned = case["recipient_xdr_hex"].as_str().expect("recipient_xdr_hex");

    let derived = hex::encode(address_xdr(address).expect("address_xdr"));
    assert_eq!(
        derived, pinned,
        "\n\nthe redeem vector's recipient is not what the contract hashes.\n\
         Anything built from this file signs the wrong message and is rejected \
         on-chain, which is the one failure the vectors exist to prevent.\n\
         Re-bless with KENTER_BLESS_VECTORS=1 after fixing RECIPIENT_XDR.\n"
    );

    // The shape, stated once so a wrong-but-same-length value is still caught:
    // SCV_ADDRESS, SC_ADDRESS_TYPE_ACCOUNT, PUBLIC_KEY_TYPE_ED25519, key.
    assert_eq!(case["recipient_xdr_len"].as_u64(), Some(44));
    assert!(derived.starts_with("000000120000000000000000"), "{derived}");
}

/// The same for the mint's own address, which both owner digests now cover.
///
/// A contract address encodes four bytes shorter than an account -- the id is
/// the payload, not a typed public key -- so a consumer that reuses the
/// recipient's shape here signs the wrong length and is rejected on-chain.
#[test]
fn vectors_contract_matches_address_xdr() {
    let raw = std::fs::read_to_string(VECTORS).unwrap_or_else(|e| panic!("{VECTORS}: {e}"));
    let v: serde_json::Value = serde_json::from_str(&raw).expect("vectors are not JSON");

    for section in ["spend_auth", "redeem_owner"] {
        let case = &v[section]["case"];
        let address = case["contract_address"].as_str().expect("contract_address");
        let pinned = case["contract_xdr_hex"].as_str().expect("contract_xdr_hex");

        let derived = hex::encode(address_xdr(address).expect("address_xdr"));
        assert_eq!(
            derived, pinned,
            "{section}: the pinned contract XDR is not what the mint hashes. \
             Re-bless with KENTER_BLESS_VECTORS=1 after fixing CONTRACT_XDR."
        );

        assert_eq!(case["contract_xdr_len"].as_u64(), Some(40), "{section}");
        // SCV_ADDRESS, SC_ADDRESS_TYPE_CONTRACT, then the raw id.
        assert!(derived.starts_with("0000001200000001"), "{section}: {derived}");
        // A nonce of zero in the vectors is a nonce a consumer can omit and
        // still match, which defeats the point of pinning it.
        assert!(case["spend_nonce"].as_u64().expect("spend_nonce") > 0, "{section}");
    }
}
