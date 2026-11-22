//! Spend-mode (nullification) primitives. See `docs/architecture/spend-mode.md`.
//!
//! # What this is
//!
//! Pure bearer tokens are copyable: after Bob pays Alice, Bob still holds valid
//! bytes and can race her to redemption. **Spend mode** closes that single-hop
//! fraud by attaching an **owner pointer** to the on-ledger token record. Each
//! transfer is an authorized on-ledger transition that (a) proves the *current*
//! owner consents, (b) rebinds the record to the *next* owner, and (c) makes the
//! payer's retained copy worthless — because after the transition the payer is no
//! longer the current owner and cannot authorize a second one.
//!
//! It is a per-token **mode**, opt-in at `register_token`; pure-bearer tokens are
//! unaffected and skip every check here.
//!
//! # The owner key
//!
//! - The owner key is an **independent Ed25519 keypair, orthogonal to the token's
//!   ephemeral/composed secret** — it is the holder's wallet key. A **fresh owner
//!   key is used per receipt** (like a fresh receive address), so
//!   commitments don't link a holder across tokens.
//! - The on-ledger record stores only a 32-byte **commitment** to that key,
//!   `commitment = SHA-256(SPEND_OWNER_COMMIT || owner_pubkey)`, hiding the key
//!   while the token is held. Ed25519 is used everywhere (software wallet *and*
//!   the on-card owner key), so the mint verifies with the `ed25519_verify` host
//!   function — no Curve25519 point math, for which Soroban has no host
//!   function.
//!
//! # The two authorizations
//!
//! **Spend (transfer).** The current owner signs
//!
//! ```text
//! SPEND_AUTH || contract_xdr || slot_id (u32 BE) || ephemeral_key
//!            || current_commitment || new_commitment || spend_nonce (u32 BE)
//! ```
//!
//! Binding *both* commitments prevents (1) replaying the spend against a
//! now-different state, and (2) swapping the successor — an attacker who
//! observes the transfer can't redirect it without the current owner's key.
//! The `spend_nonce` is what makes an authorisation good for exactly one
//! transfer: the commitments alone repeat whenever a note returns to one it
//! held before, and the static pay tag at owner index 0 is a reusable
//! address, so change and refunds do exactly that. `contract_xdr` keeps a
//! signature from crossing deployments, and `slot_id` is the record's real
//! key — the mint keys by slot, so two records may name the same
//! `ephemeral_key`. The mint `spend` entry point opens `current_commitment`
//! with the revealed key, verifies this signature, overwrites the record's
//! commitment with `new_commitment`, and advances the nonce.
//!
//! **Redeem.** For spend-mode tokens the mint requires, *in addition* to the
//! usual ephemeral/chain proof, that the redeemer open the **current** owner
//! commitment. The current owner signs
//!
//! ```text
//! SPEND_REDEEM || contract_xdr || slot_id (u32 BE) || ephemeral_key
//!              || owner_commitment || spend_nonce (u32 BE) || recipient_xdr
//! ```
//!
//! This keeps the "can't spend after paying" lock enforced by the immutable
//! contract, not by node honesty — nodes contributing shards never
//! arbitrate ownership.
//!
//! The **recipient is part of the message**.
//! Without it the signature would authorise "redeem this note" rather than
//! "pay this note's escrow to *this* address", and anyone holding a valid
//! proof could redirect the payout. The byte layouts here are pinned for the
//! firmware and applet that must reproduce them, in
//! `tests/vectors/spend_vectors.json`; change one and
//! `crates/kenter-crypto/tests/spend_vectors.rs` fails and names the
//! consumers to update.
//!
//! # Signing a 32-byte digest (card interoperability)
//!
//! Owner authorizations sign **`M = SHA-256(message)`**, never the message
//! itself. The Keycard applet's `signHash` takes a 32-byte input, while the
//! spend/redeem messages are 162 and 176 bytes — so signing raw would make
//! card-produced and software-produced signatures non-interchangeable, and the
//! card could not be the owner signer at all. Hashing first makes them identical.
//!
//! The `*_signable_bytes` helpers still build the preimage — the Shell needs the
//! layout in order to hash it — and the `*_digest` helpers return the 32 bytes
//! actually handed to the signer. The mint verifies over the same digest.
//!
//! This applies only to *owner* authorizations. The ephemeral-key redemption
//! signature (`kntr_v1:redeem:key || contract_xdr || slot_id || ephemeral_key
//! || recipient_xdr`) is produced by the combiner
//! in software, never by a card, and is unaffected.
//!
//! # On-ledger vs in-token
//!
//! This module is the **on-ledger** minimal side: a 32-byte pointer + two signed
//! transitions. The rich, in-token custody chain (a signed `prev_owner →
//! new_commitment` link per hop, disclosed only at redemption, bounded by a
//! rolling window) is decorative in Realization A — prevention is the on-ledger
//! pointer — and is layered separately.

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::domain::DomainSeparation;
use crate::error::{CryptoError, Result};
use crate::keypair::StellarKeypair;

/// Compute the on-ledger owner commitment for an Ed25519 owner public key:
/// `SHA-256(SPEND_OWNER_COMMIT || owner_pubkey)`.
pub fn owner_commitment(owner_pubkey: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(DomainSeparation::SPEND_OWNER_COMMIT);
    h.update(owner_pubkey);
    h.finalize().into()
}

/// Whether `owner_pubkey` opens `commitment`.
pub fn opens_commitment(commitment: &[u8; 32], owner_pubkey: &[u8; 32]) -> bool {
    &owner_commitment(owner_pubkey) == commitment
}

/// Generate a fresh owner keypair and its commitment — a recipient calls this to
/// mint the "new owner" side of a transfer (fresh key per receipt). The keypair
/// **must** be persisted by the recipient: a bearer token cannot be reissued, so
/// losing the owner key makes the token unspendable/unredeemable.
pub fn new_owner() -> (StellarKeypair, [u8; 32]) {
    let kp = StellarKeypair::random();
    let commitment = owner_commitment(&kp.raw_public());
    (kp, commitment)
}

// ── Spend (transfer) authorization ──────────────────────────────────────────

/// The bytes a current owner signs to authorize a transfer of the whole token to
/// `new_owner_commitment`. Binds the token and both the spent and successor
/// states (see module docs).
pub fn spend_signable_bytes(
    contract_xdr: &[u8],
    slot_id: u32,
    ephemeral_key: &[u8; 32],
    current_owner_commitment: &[u8; 32],
    new_owner_commitment: &[u8; 32],
    spend_nonce: u32,
) -> Vec<u8> {
    let tag = DomainSeparation::SPEND_AUTH;
    let mut buf = Vec::with_capacity(tag.len() + contract_xdr.len() + 100);
    buf.extend_from_slice(tag);
    buf.extend_from_slice(contract_xdr);
    buf.extend_from_slice(&slot_id.to_be_bytes());
    buf.extend_from_slice(ephemeral_key);
    buf.extend_from_slice(current_owner_commitment);
    buf.extend_from_slice(new_owner_commitment);
    buf.extend_from_slice(&spend_nonce.to_be_bytes());
    buf
}

/// The 32 bytes actually signed to authorize a transfer: `SHA-256` of
/// [`spend_signable_bytes`]. This is what a Keycard's `signHash` receives.
pub fn spend_auth_digest(
    contract_xdr: &[u8],
    slot_id: u32,
    ephemeral_key: &[u8; 32],
    current_owner_commitment: &[u8; 32],
    new_owner_commitment: &[u8; 32],
    spend_nonce: u32,
) -> [u8; 32] {
    Sha256::digest(spend_signable_bytes(
        contract_xdr,
        slot_id,
        ephemeral_key,
        current_owner_commitment,
        new_owner_commitment,
        spend_nonce,
    ))
    .into()
}

/// A signed transfer authorization, submitted to the mint's `spend` entry point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpendAuthorization {
    /// The current owner's Ed25519 public key (opens the live commitment).
    pub current_owner_pubkey: [u8; 32],
    /// Commitment to the next owner's key.
    pub new_owner_commitment: [u8; 32],
    /// Ed25519 signature by the current owner over [`spend_auth_digest`].
    pub signature: [u8; 64],
}

/// Build a [`SpendAuthorization`]. `current_owner_commitment` must be the token's
/// live on-ledger commitment (`owner_commitment(current_owner.raw_public())`).
pub fn authorize_spend(
    current_owner: &StellarKeypair,
    contract_xdr: &[u8],
    slot_id: u32,
    ephemeral_key: &[u8; 32],
    current_owner_commitment: &[u8; 32],
    new_owner_commitment: &[u8; 32],
    spend_nonce: u32,
) -> SpendAuthorization {
    let digest = spend_auth_digest(
        contract_xdr,
        slot_id,
        ephemeral_key,
        current_owner_commitment,
        new_owner_commitment,
        spend_nonce,
    );
    SpendAuthorization {
        current_owner_pubkey: current_owner.raw_public(),
        new_owner_commitment: *new_owner_commitment,
        signature: current_owner.sign(&digest).to_bytes(),
    }
}

/// Verify a [`SpendAuthorization`] against the token's live commitment — mirrors
/// exactly what the mint's `spend` entry point enforces: (1) the revealed key
/// opens the live commitment, (2) the signature covers (ephemeral_key, current
/// commitment, new commitment). On success the caller overwrites the record's
/// commitment with `auth.new_owner_commitment`.
pub fn verify_spend(
    contract_xdr: &[u8],
    slot_id: u32,
    ephemeral_key: &[u8; 32],
    current_owner_commitment: &[u8; 32],
    spend_nonce: u32,
    auth: &SpendAuthorization,
) -> Result<()> {
    if !opens_commitment(current_owner_commitment, &auth.current_owner_pubkey) {
        return Err(CryptoError::OwnerCommitmentMismatch);
    }
    let vk = VerifyingKey::from_bytes(&auth.current_owner_pubkey)
        .map_err(|_| CryptoError::SignatureVerificationFailed)?;
    let digest = spend_auth_digest(
        contract_xdr,
        slot_id,
        ephemeral_key,
        current_owner_commitment,
        &auth.new_owner_commitment,
        spend_nonce,
    );
    vk.verify_strict(&digest, &Signature::from_bytes(&auth.signature))
        .map_err(|_| CryptoError::SignatureVerificationFailed)
}

// ── Redemption authorization (spend-mode tokens) ────────────────────────────

/// The bytes a current owner signs to authorize redemption of a spend-mode token.
///
/// `recipient_xdr` is the payout destination as the mint encodes it — the
/// XDR of its `Address`, which `kenter_client::tx::address_xdr` produces and
/// both sides pin in tests. It is in the message so the signature says "pay
/// this note's escrow to *this* address" rather than merely "redeem this
/// note": without it, anyone holding a valid proof could redirect the
/// payout.
///
/// Raw bytes rather than an address type because this crate deliberately
/// knows nothing about XDR; the caller that owns the encoding passes it in.
pub fn redeem_owner_signable_bytes(
    contract_xdr: &[u8],
    slot_id: u32,
    ephemeral_key: &[u8; 32],
    owner_commitment: &[u8; 32],
    spend_nonce: u32,
    recipient_xdr: &[u8],
) -> Vec<u8> {
    let tag = DomainSeparation::SPEND_REDEEM;
    let mut buf =
        Vec::with_capacity(tag.len() + contract_xdr.len() + 68 + recipient_xdr.len());
    buf.extend_from_slice(tag);
    buf.extend_from_slice(contract_xdr);
    buf.extend_from_slice(&slot_id.to_be_bytes());
    buf.extend_from_slice(ephemeral_key);
    buf.extend_from_slice(owner_commitment);
    buf.extend_from_slice(&spend_nonce.to_be_bytes());
    buf.extend_from_slice(recipient_xdr);
    buf
}

/// The 32 bytes actually signed to authorize redemption: `SHA-256` of
/// [`redeem_owner_signable_bytes`].
pub fn redeem_owner_digest(
    contract_xdr: &[u8],
    slot_id: u32,
    ephemeral_key: &[u8; 32],
    owner_commitment: &[u8; 32],
    spend_nonce: u32,
    recipient_xdr: &[u8],
) -> [u8; 32] {
    Sha256::digest(redeem_owner_signable_bytes(
        contract_xdr,
        slot_id,
        ephemeral_key,
        owner_commitment,
        spend_nonce,
        recipient_xdr,
    ))
    .into()
}

/// The current owner's redemption authorization, checked by the mint in addition
/// to the ephemeral/chain proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedeemOwnerProof {
    pub owner_pubkey: [u8; 32],
    pub signature: [u8; 64],
}

/// Build a [`RedeemOwnerProof`] with the current owner's keypair.
pub fn authorize_redeem(
    current_owner: &StellarKeypair,
    contract_xdr: &[u8],
    slot_id: u32,
    ephemeral_key: &[u8; 32],
    owner_commitment: &[u8; 32],
    spend_nonce: u32,
    recipient_xdr: &[u8],
) -> RedeemOwnerProof {
    let digest = redeem_owner_digest(
        contract_xdr,
        slot_id,
        ephemeral_key,
        owner_commitment,
        spend_nonce,
        recipient_xdr,
    );
    RedeemOwnerProof {
        owner_pubkey: current_owner.raw_public(),
        signature: current_owner.sign(&digest).to_bytes(),
    }
}

/// Verify a [`RedeemOwnerProof`] against the token's live commitment.
pub fn verify_redeem_owner(
    contract_xdr: &[u8],
    slot_id: u32,
    ephemeral_key: &[u8; 32],
    owner_commitment: &[u8; 32],
    spend_nonce: u32,
    recipient_xdr: &[u8],
    proof: &RedeemOwnerProof,
) -> Result<()> {
    if !opens_commitment(owner_commitment, &proof.owner_pubkey) {
        return Err(CryptoError::OwnerCommitmentMismatch);
    }
    let vk = VerifyingKey::from_bytes(&proof.owner_pubkey)
        .map_err(|_| CryptoError::SignatureVerificationFailed)?;
    let digest = redeem_owner_digest(
        contract_xdr,
        slot_id,
        ephemeral_key,
        owner_commitment,
        spend_nonce,
        recipient_xdr,
    );
    vk.verify_strict(&digest, &Signature::from_bytes(&proof.signature))
        .map_err(|_| CryptoError::SignatureVerificationFailed)
}

#[cfg(test)]
mod tests {
    /// Stands in for an address's XDR. The real bytes come from
    /// `kenter_client::tx::address_xdr`; this crate only cares that they
    /// are in the message.
    const RECIPIENT: &[u8] = b"   recipient-one";
    const OTHER_RECIPIENT: &[u8] = b"   recipient-two";

    /// A proof authorises a payout to ONE address. Reusing it for another
    /// is the attack the recipient binding exists to stop — without it,
    /// anyone holding a valid proof could redirect the money.
    #[test]
    fn a_redeem_proof_cannot_be_pointed_at_another_recipient() {
        let owner = StellarKeypair::random();
        let commit = owner_commitment(&owner.raw_public());
        let proof = authorize_redeem(&owner, CONTRACT, SLOT, &EK, &commit, NONCE, RECIPIENT);

        verify_redeem_owner(CONTRACT, SLOT, &EK, &commit, NONCE, RECIPIENT, &proof).expect("its own recipient");
        assert!(matches!(
            verify_redeem_owner(CONTRACT, SLOT, &EK, &commit, NONCE, OTHER_RECIPIENT, &proof),
            Err(CryptoError::SignatureVerificationFailed)
        ));
    }

    use super::*;

    const EK: [u8; 32] = [7u8; 32];

    /// Stands in for the mint's own address XDR, which every digest covers so
    /// a signature cannot be replayed against another deployment.
    /// The slot the note was registered under. In the digests because
    /// the mint keys records by slot, so a signature made for one record
    /// must not verify against another that names the same key.
    const SLOT: u32 = 3;
    const CONTRACT: &[u8] = b"      mint-one";
    const OTHER_CONTRACT: &[u8] = b"      mint-two";

    /// The spend count the mint holds for a note. Fixed here so the digests
    /// are stable; the replay tests below are the ones that vary it.
    const NONCE: u32 = 0;

    #[test]
    fn commitment_is_deterministic_and_opens() {
        let (kp, commit) = new_owner();
        assert_eq!(commit, owner_commitment(&kp.raw_public()));
        assert!(opens_commitment(&commit, &kp.raw_public()));
        // A different key does not open it.
        let other = StellarKeypair::random();
        assert!(!opens_commitment(&commit, &other.raw_public()));
    }

    #[test]
    fn spend_roundtrip_verifies() {
        let (alice, alice_commit) = new_owner();
        let (_bob, bob_commit) = new_owner();
        let auth = authorize_spend(&alice, CONTRACT, SLOT, &EK, &alice_commit, &bob_commit, NONCE);
        verify_spend(CONTRACT, SLOT, &EK, &alice_commit, NONCE, &auth).expect("valid spend");
    }

    #[test]
    fn spend_rejects_wrong_current_commitment() {
        // Alice authorizes against her real commitment, but the token's live
        // commitment is someone else's → opening fails (this is the second-spend
        // guard: after a transfer the live commitment is the successor's).
        let (alice, alice_commit) = new_owner();
        let (_bob, bob_commit) = new_owner();
        let (_carol, carol_commit) = new_owner();
        let auth = authorize_spend(&alice, CONTRACT, SLOT, &EK, &alice_commit, &bob_commit, NONCE);
        let err = verify_spend(CONTRACT, SLOT, &EK, &carol_commit, NONCE, &auth).unwrap_err();
        assert!(matches!(err, CryptoError::OwnerCommitmentMismatch));
    }

    #[test]
    fn spend_rejects_successor_swap() {
        // An attacker who sees the transfer tries to redirect it to their key by
        // swapping new_owner_commitment — the signature no longer covers it.
        let (alice, alice_commit) = new_owner();
        let (_bob, bob_commit) = new_owner();
        let (_mallory, mallory_commit) = new_owner();
        let mut auth = authorize_spend(&alice, CONTRACT, SLOT, &EK, &alice_commit, &bob_commit, NONCE);
        auth.new_owner_commitment = mallory_commit;
        let err = verify_spend(CONTRACT, SLOT, &EK, &alice_commit, NONCE, &auth).unwrap_err();
        assert!(matches!(err, CryptoError::SignatureVerificationFailed));
    }

    #[test]
    fn spend_rejects_forged_signer() {
        // Mallory opens nothing: she can't produce a key that opens Alice's
        // commitment, and signing with her own key fails the opening check.
        let (_alice, alice_commit) = new_owner();
        let (mallory, _mallory_commit) = new_owner();
        let (_bob, bob_commit) = new_owner();
        let auth = authorize_spend(&mallory, CONTRACT, SLOT, &EK, &alice_commit, &bob_commit, NONCE);
        let err = verify_spend(CONTRACT, SLOT, &EK, &alice_commit, NONCE, &auth).unwrap_err();
        assert!(matches!(err, CryptoError::OwnerCommitmentMismatch));
    }

    #[test]
    fn two_hop_transfer_burns_the_payer() {
        // Alice → Bob → Carol. After each hop the live commitment moves on, and
        // the previous owner can no longer authorize a spend of the new state.
        let (alice, alice_commit) = new_owner();
        let (bob, bob_commit) = new_owner();
        let (_carol, carol_commit) = new_owner();

        // Hop 1: Alice spends to Bob. Live commitment := bob_commit.
        let a1 = authorize_spend(&alice, CONTRACT, SLOT, &EK, &alice_commit, &bob_commit, NONCE);
        verify_spend(CONTRACT, SLOT, &EK, &alice_commit, NONCE, &a1).unwrap();

        // Hop 2: Bob spends to Carol against the new live commitment.
        let a2 = authorize_spend(&bob, CONTRACT, SLOT, &EK, &bob_commit, &carol_commit, NONCE);
        verify_spend(CONTRACT, SLOT, &EK, &bob_commit, NONCE, &a2).unwrap();

        // Alice tries to re-spend the token she already paid away: her old
        // authorization does not open the live (bob) commitment.
        let stale = authorize_spend(&alice, CONTRACT, SLOT, &EK, &alice_commit, &alice_commit, NONCE);
        assert!(matches!(
            verify_spend(CONTRACT, SLOT, &EK, &bob_commit, NONCE, &stale).unwrap_err(),
            CryptoError::OwnerCommitmentMismatch
        ));
    }

    #[test]
    fn digest_is_what_gets_signed_card_interop() {
        // A Keycard only ever receives M = SHA-256(message) and signs that. This
        // reproduces the card's view with a raw signer: if a signature produced
        // over the digest alone verifies, card- and software-produced signatures
        // are interchangeable.
        use sha2::{Digest, Sha256};

        let (alice, alice_commit) = new_owner();
        let (_bob, bob_commit) = new_owner();

        let preimage = spend_signable_bytes(CONTRACT, SLOT, &EK, &alice_commit, &bob_commit, NONCE);
        let m: [u8; 32] = Sha256::digest(&preimage).into();
        assert_eq!(m, spend_auth_digest(CONTRACT, SLOT, &EK, &alice_commit, &bob_commit, NONCE));
        assert!(
            preimage.len() > 32,
            "preimage must exceed the card's 32-byte signHash input, else this change is moot"
        );

        // Sign the digest directly, as the card would.
        let card_sig = alice.sign(&m).to_bytes();
        let auth = SpendAuthorization {
            current_owner_pubkey: alice.raw_public(),
            new_owner_commitment: bob_commit,
            signature: card_sig,
        };
        verify_spend(CONTRACT, SLOT, &EK, &alice_commit, NONCE, &auth).expect("card-style signature must verify");

        // Same for the redeem proof.
        let rm: [u8; 32] = Sha256::digest(redeem_owner_signable_bytes(CONTRACT, SLOT, &EK, &alice_commit, NONCE, RECIPIENT)).into();
        assert_eq!(rm, redeem_owner_digest(CONTRACT, SLOT, &EK, &alice_commit, NONCE, RECIPIENT));
        let proof = RedeemOwnerProof {
            owner_pubkey: alice.raw_public(),
            signature: alice.sign(&rm).to_bytes(),
        };
        verify_redeem_owner(CONTRACT, SLOT, &EK, &alice_commit, NONCE, RECIPIENT, &proof).expect("card-style redeem proof");
    }

    #[test]
    fn redeem_owner_roundtrip_and_rejections() {
        let (owner, commit) = new_owner();
        let proof = authorize_redeem(&owner, CONTRACT, SLOT, &EK, &commit, NONCE, RECIPIENT);
        verify_redeem_owner(CONTRACT, SLOT, &EK, &commit, NONCE, RECIPIENT, &proof).expect("valid redeem proof");

        // Wrong token (ephemeral key) → signature fails.
        let other_ek = [9u8; 32];
        assert!(matches!(
            verify_redeem_owner(CONTRACT, SLOT, &other_ek, &commit, NONCE, RECIPIENT, &proof).unwrap_err(),
            CryptoError::SignatureVerificationFailed
        ));

        // Someone who isn't the owner can't prove it.
        let (mallory, _mc) = new_owner();
        let forged = authorize_redeem(&mallory, CONTRACT, SLOT, &EK, &commit, NONCE, RECIPIENT);
        assert!(matches!(
            verify_redeem_owner(CONTRACT, SLOT, &EK, &commit, NONCE, RECIPIENT, &forged).unwrap_err(),
            CryptoError::OwnerCommitmentMismatch
        ));
    }

    /// A spend authorisation is good for exactly one transfer.
    ///
    /// Without the nonce the digest repeated whenever a note returned to a
    /// commitment it had held before — and the static pay tag is a reusable
    /// address, so change and refunds did exactly that. A former payee could
    /// then re-post the old authorisation and take the note back.
    #[test]
    fn a_spend_authorization_does_not_survive_the_nonce_advancing() {
        let (alice, alice_commit) = new_owner();
        let (_bob, bob_commit) = new_owner();
        let auth = authorize_spend(&alice, CONTRACT, SLOT, &EK, &alice_commit, &bob_commit, 4);

        verify_spend(CONTRACT, SLOT, &EK, &alice_commit, 4, &auth).expect("its own nonce");
        assert!(matches!(
            verify_spend(CONTRACT, SLOT, &EK, &alice_commit, 5, &auth),
            Err(CryptoError::SignatureVerificationFailed)
        ));
    }

    /// The same for a redeem proof.
    #[test]
    fn a_redeem_proof_does_not_survive_the_nonce_advancing() {
        let (owner, commit) = new_owner();
        let proof = authorize_redeem(&owner, CONTRACT, SLOT, &EK, &commit, 4, RECIPIENT);

        verify_redeem_owner(CONTRACT, SLOT, &EK, &commit, 4, RECIPIENT, &proof).expect("its own nonce");
        assert!(matches!(
            verify_redeem_owner(CONTRACT, SLOT, &EK, &commit, 5, RECIPIENT, &proof),
            Err(CryptoError::SignatureVerificationFailed)
        ));
    }

    /// Two deployments of this contract can hold escrow for the same
    /// ephemeral key — a testnet mint and a mainnet one, or an old mint and
    /// its replacement. Binding the address keeps an authorisation written
    /// for one from draining the other.
    #[test]
    fn an_authorization_is_bound_to_the_mint_it_was_written_for() {
        let (alice, alice_commit) = new_owner();
        let (_bob, bob_commit) = new_owner();
        let auth = authorize_spend(&alice, CONTRACT, SLOT, &EK, &alice_commit, &bob_commit, NONCE);
        assert!(matches!(
            verify_spend(OTHER_CONTRACT, SLOT, &EK, &alice_commit, NONCE, &auth),
            Err(CryptoError::SignatureVerificationFailed)
        ));

        let proof = authorize_redeem(&alice, CONTRACT, SLOT, &EK, &alice_commit, NONCE, RECIPIENT);
        assert!(matches!(
            verify_redeem_owner(OTHER_CONTRACT, SLOT, &EK, &alice_commit, NONCE, RECIPIENT, &proof),
            Err(CryptoError::SignatureVerificationFailed)
        ));
    }
}
