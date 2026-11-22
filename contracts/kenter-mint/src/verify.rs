use soroban_sdk::{Bytes, BytesN, Env};

use crate::types::{Error, TokenRecord};

const CHAIN_LINK_SIZE: u32 = 290;
const DOMAIN_TAG: &[u8] = b"kntr_v1:chain:link";

/// Verify a full signature chain on-chain (Path B redemption).
///
/// chain_data layout:
///   event_id:    32 bytes
///   link_count:  2 bytes (u16 LE)
///   links:       link_count x 290 bytes each
///
/// ChainLink (290 bytes):
///   node_a_public:       32 bytes
///   node_b_public:       32 bytes
///   partial_public_key:  32 bytes
///   shard_commitment:    32 bytes
///   prev_link_hash:      32 bytes
///   link_index:          2 bytes (u16 LE)
///   signature_a:         64 bytes
///   signature_b:         64 bytes
///
/// Verifies: signatures valid, hash chain intact, indices sequential,
/// `event_id` matches, link count matches participant count.
///
/// **It does not check the roster, and deliberately takes no roster
/// argument.** Membership is checked at `request_print` and again by
/// `confirm_link`. An argument a function ignores reads, to anyone
/// skimming, as a check the function makes, and wiring one up would add
/// nothing: the signatures in a submitted chain are checked against the
/// keys embedded in that same chain, so a roster lookup here would
/// constrain nothing an attacker controls.
///
/// What actually binds a chain to its token is `chain_hash`, committed
/// at registration and compared before any payout, plus a signature from
/// the note's claim key. Neither is in this
/// function. Do not read a passing `verify_chain` as "this chain belongs
/// to this note".
pub fn verify_chain(
    e: &Env,
    chain_data: &Bytes,
    token: &TokenRecord,
) -> Result<(), Error> {
    let data_len = chain_data.len();

    // Minimum: 32 (event_id) + 2 (link_count) + 290 (at least 1 link)
    if data_len < 324 {
        return Err(Error::ChainVerificationFailed);
    }

    // Parse event_id (first 32 bytes)
    let event_id = slice_bytes_n::<32>(e, chain_data, 0);
    if event_id != token.event_id {
        return Err(Error::ChainVerificationFailed);
    }

    // Parse link_count (2 bytes LE at offset 32)
    let lc_low = chain_data.get(32).unwrap() as u32;
    let lc_high = chain_data.get(33).unwrap() as u32;
    let link_count = lc_low | (lc_high << 8);

    // Verify link count matches participants / 2
    let expected_links = token.participants.len() / 2;
    if link_count != expected_links {
        return Err(Error::ChainVerificationFailed);
    }

    // Verify total data length
    let expected_len = 34 + link_count * CHAIN_LINK_SIZE;
    if data_len != expected_len {
        return Err(Error::ChainVerificationFailed);
    }

    let mut prev_link_hash = BytesN::<32>::from_array(e, &[0u8; 32]);

    for i in 0..link_count {
        let base = 34 + i * CHAIN_LINK_SIZE;

        // Extract fields
        let node_a_pub = slice_bytes_n::<32>(e, chain_data, base);
        let node_b_pub = slice_bytes_n::<32>(e, chain_data, base + 32);
        let link_prev_hash = slice_bytes_n::<32>(e, chain_data, base + 128);

        // link_index: 2 bytes at base + 160
        let li_low = chain_data.get(base + 160).unwrap() as u32;
        let li_high = chain_data.get(base + 161).unwrap() as u32;
        let link_index = li_low | (li_high << 8);

        let sig_a = slice_bytes_n::<64>(e, chain_data, base + 162);
        let sig_b = slice_bytes_n::<64>(e, chain_data, base + 226);

        // Verify sequential link index
        if link_index != i {
            return Err(Error::ChainVerificationFailed);
        }

        // Verify hash chain (genesis link has prev_hash = [0; 32])
        if link_prev_hash != prev_link_hash {
            return Err(Error::ChainVerificationFailed);
        }

        // Build signable_bytes:
        //   domain_tag || node_a(32) || node_b(32) || partial(32) || commit(32)
        //   || prev_hash(32) || link_index(2 LE) || event_id(32)
        let mut signable = Bytes::new(e);
        signable.extend_from_slice(DOMAIN_TAG);
        // Append 160 bytes of link data (node_a through prev_hash)
        for j in 0..160u32 {
            signable.push_back(chain_data.get(base + j).unwrap());
        }
        signable.push_back(li_low as u8);
        signable.push_back(li_high as u8);
        signable.extend_from_array(&event_id.to_array());

        // Verify dual Ed25519 signatures
        e.crypto()
            .ed25519_verify(&node_a_pub, &signable, &sig_a);
        e.crypto()
            .ed25519_verify(&node_b_pub, &signable, &sig_b);

        // Compute link hash for chain: SHA256(signable || sig_a || sig_b)
        let mut hash_input = signable;
        hash_input.extend_from_array(&sig_a.to_array());
        hash_input.extend_from_array(&sig_b.to_array());
        prev_link_hash = e.crypto().sha256(&hash_input).into();
    }

    Ok(())
}

fn slice_bytes_n<const N: usize>(e: &Env, data: &Bytes, offset: u32) -> BytesN<N> {
    let mut arr = [0u8; N];
    for j in 0..N {
        arr[j] = data.get(offset + j as u32).unwrap();
    }
    BytesN::from_array(e, &arr)
}
