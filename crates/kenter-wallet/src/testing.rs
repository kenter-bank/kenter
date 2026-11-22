//! Real notes, for tests and demos.
//!
//! Available to this crate's own tests always, and to anything that asks for
//! the `testing` feature — which is how `kenter-ui`'s tests, its integration
//! tests and its restore demo all get the same notes without four copies of
//! this file drifting apart.
//!
//! # Why a note has to be real
//!
//! A hand-built [`HeldToken`] with a blob of repeated bytes looks like a
//! fixture, but a restore test built on it restores something that is not a
//! note. [`crate::backup::check`] parses the blob, and a fixture that cannot
//! survive it is not testing what it claims to.
//!
//! # What these are, and are not
//!
//! **Cryptographically genuine**: the chain verifies, the signature
//! verifies, and the ephemeral address derives from the container. No
//! network is needed for any of that — the nodes in a print are keypairs
//! contributing chain links, and one process can play all of them.
//!
//! **Not registered on-chain.** No mint printed these and no escrow backs
//! them, so a ledger lookup returns `NotFound` and the billfold will call
//! them stalled. That is correct, and it is the half a local fixture cannot
//! fake: it needs a real deposit through a real mint.

use kenter_crypto::container::{deserialize_bearer_token, serialize_bearer_token};
use kenter_crypto::keypair::StellarKeypair;
use kenter_crypto::token::{assemble_bearer_token, PartialToken};

use crate::models::HeldToken;

/// A genuine note worth `amount` stroops, reproducible from `seed`.
///
/// Deterministic: the same seed is the same note, every time and in every
/// process, so a failure is reproducible and two fixtures can agree on what
/// "note 1" means.
pub fn note(seed: u8, amount: u64) -> HeldToken {
    // All four roles played locally. In a print these are separate nodes
    // gossiping a partial token; nothing about the cryptography cares.
    let kp = |role: u8| {
        let mut raw = [0u8; 32];
        raw[0] = seed;
        raw[1] = role;
        raw[2] = 0x5b;
        StellarKeypair::from_raw_secret(&raw)
    };

    // Two pairs is the shortest real chain: `initiate` lays the first link
    // and `assemble` requires exactly one pair outstanding.
    let (partial, _) = PartialToken::initiate(
        [seed.wrapping_add(1); 32],
        1_700_000_000 + seed as i64,
        Some(amount),
        2,
        &kp(0),
        &kp(1),
        vec![seed, 0x02, 0x03, 0x04],
    )
    .expect("initiate");
    let requestor = kp(2);
    let assembled = assemble_bearer_token(&partial, &requestor, &kp(3), seed as u32, None).expect("assemble");

    // Through the container and back, as a real import does: the signature
    // is applied during serialization, so the in-memory token is not yet
    // the thing that gets stored.
    let blob = serialize_bearer_token(&assembled, &requestor).expect("serialize");
    let parsed = deserialize_bearer_token(&blob).expect("deserialize");

    HeldToken::from_bearer(&parsed, blob, 1_700_000_000 + seed as i64)
}

/// [`note`] in spend mode: carrying an owner index and a commitment.
///
/// The commitment is a stand-in rather than a derived one — deriving it
/// needs a vault, and the things this fixture serves (backup, restore, the
/// store) never open it. Anything testing ownership has to build its own.
pub fn spend_note(seed: u8, amount: u64, owner_index: u32) -> HeldToken {
    let mut held = note(seed, amount);
    held.owner_index = Some(owner_index);
    held.owner_commitment = Some([seed.wrapping_add(2); 32]);
    held
}

/// A record that looks plausible and is not a note: the fixture everything
/// here used before notes had to be real.
///
/// Kept, because refusing it is now a thing worth testing. This is the
/// shape of a counterfeit in a backup someone hands you.
pub fn fabricated(seed: u8, amount: u64) -> HeldToken {
    HeldToken {
        id: format!("G{seed:0>55}"),
        // Distinct per seed, like everything else here: a fabricated
        // note must not collide with another one'''s record.
        slot_id: seed as u32,
        ephemeral_public_key: [seed; 32],
        event_id: [seed; 32],
        amount,
        blob: vec![seed; 96],
        imported_at: 1_700_000_000 + seed as i64,
        mint: None,
        label: None,
        owner_index: None,
        owner_commitment: None,
        spent_away: false,
        exports: Default::default(),
        marked_spent: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_notes_are_real_and_the_fabrication_is_not() {
        for seed in [1u8, 2, 7, 200] {
            let t = note(seed, 1_000 + seed as u64);
            crate::backup::check(&t)
                .unwrap_or_else(|e| panic!("fixture note {seed} does not verify: {e}"));
            assert_eq!(t.amount, 1_000 + seed as u64);
            assert!(t.id.starts_with('G'));
        }
        assert!(crate::backup::check(&fabricated(9, 1)).is_err());
    }

    #[test]
    fn notes_are_deterministic_and_distinct() {
        assert_eq!(note(5, 100).id, note(5, 100).id);
        assert_ne!(note(5, 100).id, note(6, 100).id);
        // The id is the **seed**, not the amount: an ephemeral key is the
        // sum of the chain's partial public keys, and the denomination is
        // carried in the signed header beside it. So two notes built from
        // one seed share an id and would collide in a store - give each
        // fixture note its own seed.
        assert_eq!(note(5, 100).id, note(5, 200).id);
        assert_ne!(note(5, 100).amount, note(5, 200).amount);
    }

    #[test]
    fn a_spend_note_carries_its_index() {
        let t = spend_note(3, 500, 42);
        assert_eq!(t.owner_index, Some(42));
        assert!(t.owner_commitment.is_some());
        crate::backup::check(&t).unwrap();
    }
}
