//! `KeycardVault` — the high-level hardware custody backend.
//!
//! Wraps the full Status Keycard lifecycle (connect → SELECT → INIT → PAIR →
//! per-operation OPEN → VERIFY PIN → op) behind a small API. Pairs once and
//! reuses the pairing across operations; each operation opens a fresh secure
//! channel (re-SELECT + OPEN) so sessions never go stale.
//!
//! Design note: this is a *concrete* type (secp256k1 ECDSA over 32-byte hashes),
//! NOT a `kenter_vault` trait — and deliberately so. This applet (v3.1) is
//! secp256k1-only; sign_p2=0x01 silently returns ECDSA, not Ed25519 (verified
//! via `examples/probe_eddsa.rs`), so the card cannot sign Stellar Ed25519 keys
//! and is not an interchangeable backend for `SoftVault`.
//!
//! **What it is not: the spend-mode owner-key anchor.** The mint does not
//! verify a secp256k1 signature (there is no Soroban `secp256k1_recover` in
//! it). `spend` and `enforce_owner` take `current_owner_pubkey: BytesN<32>`
//! and call `ed25519_verify`; a compressed secp256k1 key is 33 bytes and
//! cannot be passed. The owner key is Ed25519, so the hardware owner key is
//! the **Ed25519 applet fork**, not this. See `docs/architecture/custody.md`.
//!
//! What remains here is a working secp256k1 signer and, more usefully, the
//! transport, secure channel and lifecycle that the Ed25519 backend will reuse.

use crate::error::{KeycardError, Result};
use crate::secure_channel::{
    CardSignature, Pairing, SecureChannel, init_card, pair, pairing_secret_from_password,
};
use crate::transport::Transport;

/// A connected Status Keycard, ready to init / pair / sign.
pub struct KeycardVault {
    transport: Transport,
    card_pub: Vec<u8>,
    initialized: bool,
    pairing: Option<Pairing>,
}

impl KeycardVault {
    /// Connect to the first card on any reader and SELECT the applet.
    pub fn connect() -> Result<Self> {
        let mut transport = Transport::connect()?;
        let info = transport.select_keycard()?;
        Ok(Self {
            transport,
            card_pub: info.secure_channel_public_key,
            initialized: info.initialized,
            pairing: None,
        })
    }

    /// Whether the card has been INIT'd.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// The card's static secure-channel public key (secp256k1, 65 bytes).
    pub fn card_public_key(&self) -> &[u8] {
        &self.card_pub
    }

    /// INIT a blank card with a PIN, PUK, and pairing password. Quasi-permanent.
    pub fn init(&mut self, pin: &str, puk: &str, pairing_password: &str) -> Result<()> {
        let secret = pairing_secret_from_password(pairing_password);
        init_card(&mut self.transport, &self.card_pub, pin, puk, &secret)?;
        // Refresh state (SELECT after INIT).
        let info = self.transport.select_keycard()?;
        self.initialized = info.initialized;
        Ok(())
    }

    /// Establish (once) a pairing using the pairing password, and cache it.
    pub fn ensure_paired(&mut self, pairing_password: &str) -> Result<()> {
        if self.pairing.is_none() {
            let secret = pairing_secret_from_password(pairing_password);
            self.pairing = Some(pair(&mut self.transport, &secret)?);
        }
        Ok(())
    }

    /// Open a fresh secure channel for one operation (re-SELECT then OPEN).
    fn open(&mut self) -> Result<SecureChannel<'_>> {
        let pairing = self
            .pairing
            .clone()
            .ok_or_else(|| KeycardError::SecureChannel("not paired — call ensure_paired".into()))?;
        self.transport.select_keycard()?;
        SecureChannel::open(&mut self.transport, &self.card_pub, &pairing)
    }

    /// Generate a fresh on-card secp256k1 master key. Returns the key UID.
    /// Requires PIN.
    pub fn generate_key(&mut self, pin: &str) -> Result<Vec<u8>> {
        let mut sc = self.open()?;
        sc.verify_pin(pin)?;
        sc.generate_key()
    }

    /// Sign a 32-byte hash with the current key (ECDSA secp256k1). Requires PIN.
    pub fn sign_ecdsa(&mut self, pin: &str, hash: &[u8; 32]) -> Result<CardSignature> {
        let mut sc = self.open()?;
        sc.verify_pin(pin)?;
        sc.sign_ecdsa(hash)
    }
}
