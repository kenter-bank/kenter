//! `StellarKeycard` — the on-card **Ed25519 / Stellar** custody backend.
//!
//! Speaks Secure Channel V2 to the forked applet's Ed25519 commands (SLIP-0010,
//! RFC 8032) over any [`CardTransport`] — the jcardsim `SimServer` today, a
//! real card over PC/SC once hardware is flashed.
//!
//! # Two traits, and only one of them is Kenter's
//!
//! This type implements both of `kenter_vault`'s backends, because the applet
//! fork is a **general-purpose Stellar hardware signer** and not only Kenter's:
//!
//! - [`KeyVault`] — slot-based Stellar **account** keys. A "slot" maps to the
//!   SLIP-0010 account index, so slot *n* is `m/44'/148'/n'`.
//! - [`DerivingVault`] — spend-mode **owner** keys, which the owner-key model
//!   also places at `m/44'/148'/n'` (see `docs/architecture/custody.md`).
//!
//! **Those are the same path.** On this card a `KeyVault` slot and a
//! `DerivingVault` index at the same number are therefore *the same key* —
//! unlike `SoftVault`, where account keys are independent random keys in slots
//! and only owner keys are HD.
//!
//! **Kenter uses `DerivingVault` only.** The
//! submitting Stellar account stays a software key. Wiring both to one card
//! would put the account at index 0 — which the owner-key model reserves for the
//! standing pay tag — making that tag's commitment a hash of an account the
//! ledger already names as depositor and redeemer, so anyone could recognise
//! every payment made to it. The account key is a fee-paying hot key and gains
//! nothing from a secure element; leaving it in software costs nothing and
//! keeps the two-factor shape where neither key alone moves a note.

use std::collections::BTreeMap;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use kenter_vault::{
    Bip85, DerivingVault, KeySlotInfo, KeyVault, Result as VaultResult, SlotId, VaultError,
};
use zeroize::Zeroizing;

use crate::secure_channel_v2::{
    CaPublicKey, SecureChannelV2, card_identity_certificate, card_identity_pubkey,
    verify_identity_certificate_any,
};
use crate::transport::CardTransport;

const SELECT_AID: &[u8] = &[
    0x00, 0xA4, 0x04, 0x00, 0x09, 0xA0, 0x00, 0x00, 0x08, 0x04, 0x00, 0x01, 0x01, 0x01,
];

// Applet INS / params.
const INS_INIT: u8 = 0xFE;
const INS_VERIFY_PIN: u8 = 0x20;
const INS_GENERATE_KEY: u8 = 0xD4;
const INS_REMOVE_KEY: u8 = 0xD3;
const INS_LOAD_KEY: u8 = 0xD0;
const INS_SIGN: u8 = 0xC0;
const INS_EXPORT_KEY: u8 = 0xC2;
const INS_EXPORT_BIP85: u8 = 0xC4;
const LOAD_KEY_P1_SEED: u8 = 0x03;
const SIGN_P1_DERIVE: u8 = 0x01;
const SIGN_P2_ED25519: u8 = 0x01;
const EXPORT_P2_ED25519_PUBLIC: u8 = 0x03;
const DERIVE_P1_SOURCE_MASTER: u8 = 0x00;
const INS_CHANGE_PIN: u8 = 0x21;
const INS_UNBLOCK_PIN: u8 = 0x22;
const INS_GENERATE_MNEMONIC: u8 = 0xD2;
const INS_NOTE_NEXT_INDEX: u8 = 0xB8;
const INS_NOTE_ADVANCE_INDEX: u8 = 0xB9;
const INS_FACTORY_RESET: u8 = 0xFD;
const CHANGE_PIN_P1_USER: u8 = 0x00;
const CHANGE_PIN_P1_PUK: u8 = 0x01;
const FACTORY_RESET_P1_MAGIC: u8 = 0xAA;
const FACTORY_RESET_P2_MAGIC: u8 = 0x55;

/// Exactly, as the applet counts them.
pub const PIN_LEN: usize = 6;
pub const PUK_LEN: usize = 12;

/// Retry limits the applet will accept (`processInit`).
pub const PIN_RETRIES: std::ops::RangeInclusive<u8> = 2..=10;
pub const PUK_RETRIES: std::ops::RangeInclusive<u8> = 3..=12;

fn hw<E: std::fmt::Display>(e: E) -> VaultError {
    VaultError::Hardware(e.to_string())
}

/// A 4-byte big-endian counter, or a clear complaint about its shape.
fn be_u32(d: &[u8], what: &str) -> VaultResult<u32> {
    let b: [u8; 4] = d
        .try_into()
        .map_err(|_| VaultError::Hardware(format!("{what}: expected 4 bytes, got {}", d.len())))?;
    Ok(u32::from_be_bytes(b))
}

/// Reject a PIN or PUK the card would reject, with a sentence rather than a
/// status word.
fn check_digits(label: &str, v: &[u8], want: usize) -> VaultResult<()> {
    if v.len() != want || !v.iter().all(|b| b.is_ascii_digit()) {
        return Err(VaultError::Hardware(format!(
            "the {label} must be exactly {want} digits"
        )));
    }
    Ok(())
}

/// Map a VERIFY PIN failure onto the credential errors callers already branch
/// on.
///
/// This is not cosmetic. `SessionAuthorizer` re-prompts on
/// [`VaultError::BadCredential`] and gives up on anything else
/// (`kenter_wallet::authz`, and the retry loops in the desktop's receive and
/// pay flows). A mistyped PIN arriving as a generic hardware error would dead
/// end instead of asking again — and the holder, seeing no retry, would
/// reasonably try the whole operation again, burning another of the card's
/// very few attempts.
///
/// The card answers a wrong PIN with `63Cx`, where `x` is the attempts left,
/// so `63C0` means none: blocked. Blocked must **not** map to
/// `BadCredential`, because asking again cannot help and the loop would spin.
fn pin_err(e: crate::error::KeycardError) -> VaultError {
    match e {
        crate::error::KeycardError::Apdu { sw } if sw & 0xFFF0 == 0x63C0 => {
            match (sw & 0x000F) as u8 {
                0 => VaultError::Hardware(
                    "the card's PIN is blocked — unblock it with the PUK".into(),
                ),
                left => {
                    tracing::warn!(attempts_left = left, "card PIN rejected");
                    VaultError::BadCredential
                }
            }
        }
        // 6983 is the ISO "authentication method blocked" the applet uses once
        // the PUK is exhausted too.
        crate::error::KeycardError::Apdu { sw: 0x6983 } => {
            VaultError::Hardware("the card is locked: PIN and PUK are both exhausted".into())
        }
        other => hw(other),
    }
}

/// SLIP-0010 Stellar path `m/44'/148'/n'` (all hardened, 4-byte BE elements).
///
/// One function for both roles, which is the whole of why the module docs warn
/// about mixing them: `n` is a `KeyVault` account slot *or* a `DerivingVault`
/// owner index, and the card cannot tell the difference. Public so a test can
/// assert the bytes against `tests/vectors/owner_key_vectors.json` without a
/// card present.
pub fn stellar_path(n: u32) -> [u8; 12] {
    let mut p = [
        0x80, 0x00, 0x00, 0x2C, 0x80, 0x00, 0x00, 0x94, 0x00, 0x00, 0x00, 0x00,
    ];
    p[8..12].copy_from_slice(&(0x8000_0000u32 | n).to_be_bytes());
    p
}

/// Find the first primitive TLV with `tag` inside a (possibly BER long-form)
/// `0xA0`/`0xA1` template, tolerant of the applet's off-by-one outer length.
fn tlv_value(resp: &[u8], tag: u8) -> Option<Vec<u8>> {
    let body = match resp.first()? {
        0xA0 | 0xA1 => {
            let (_len, hdr) = ber_len(&resp[1..])?;
            resp.get(1 + hdr..)?
        }
        _ => resp,
    };
    let mut i = 0;
    while i + 2 <= body.len() {
        let t = body[i];
        let (len, hdr) = ber_len(&body[i + 1..])?;
        let start = i + 1 + hdr;
        let val = body.get(start..start + len)?;
        if t == tag {
            return Some(val.to_vec());
        }
        i = start + len;
    }
    None
}

fn ber_len(data: &[u8]) -> Option<(usize, usize)> {
    let first = *data.first()?;
    if first & 0x80 == 0 {
        return Some((first as usize, 1));
    }
    let n = (first & 0x7f) as usize;
    if n == 0 || n > 3 || data.len() < 1 + n {
        return None;
    }
    let mut len = 0usize;
    for &b in &data[1..1 + n] {
        len = (len << 8) | b as usize;
    }
    Some((len, 1 + n))
}

fn addr_of(pubkey: &[u8; 32]) -> String {
    stellar_strkey::ed25519::PublicKey(*pubkey)
        .to_string()
        .as_str()
        .to_owned()
}

// -- V2-channel command helpers --

fn export_pubkey<T: CardTransport>(
    sc: &mut SecureChannelV2<'_, T>,
    account: u32,
) -> VaultResult<[u8; 32]> {
    let resp = sc
        .send(
            0x80,
            INS_EXPORT_KEY,
            DERIVE_P1_SOURCE_MASTER,
            EXPORT_P2_ED25519_PUBLIC,
            &stellar_path(account),
        )
        .map_err(hw)?;
    let pk = tlv_value(&resp, 0x80).ok_or_else(|| hw("export: no pubkey TLV"))?;
    pk.try_into().map_err(|_| hw("export: pubkey length != 32"))
}

fn sign_hash<T: CardTransport>(
    sc: &mut SecureChannelV2<'_, T>,
    account: u32,
    hash: &[u8; 32],
) -> VaultResult<([u8; 32], [u8; 64])> {
    let mut data = hash.to_vec();
    data.extend_from_slice(&stellar_path(account));
    let resp = sc
        .send(0x80, INS_SIGN, SIGN_P1_DERIVE, SIGN_P2_ED25519, &data)
        .map_err(hw)?;
    let pk: [u8; 32] = tlv_value(&resp, 0x80)
        .ok_or_else(|| hw("sign: no pubkey TLV"))?
        .try_into()
        .map_err(|_| hw("sign: pubkey length != 32"))?;
    let sig: [u8; 64] = tlv_value(&resp, 0x88)
        .ok_or_else(|| hw("sign: no signature TLV"))?
        .try_into()
        .map_err(|_| hw("sign: signature length != 64"))?;
    Ok((pk, sig))
}

/// Which duress PIN a card is being given.
///
/// **There is no "no duress PIN".** The applet checks the duress PIN first on
/// every unlock, and with none configured it is the PUK's first six digits
/// (`processInit`). So this is a choice between two values, never between
/// having one and not — and it is an enum rather than an `Option` so that
/// inheriting the PUK prefix has to be *named*. An `Option::None` would be
/// read as "no duress PIN" by every caller who had not read the applet, and
/// the card would quietly give them one anyway.
///
/// The wallet uses [`Chosen`](DuressPin::Chosen):
/// the situation a duress PIN exists for is one where the holder cannot go
/// and read their backup sheet, so a credential they never picked and have
/// never typed is not one they can use under pressure.
#[derive(Debug, Clone, Copy)]
pub enum DuressPin<'a> {
    /// Chosen by the holder. Sends `INIT`'s 26-byte form.
    Chosen(&'a [u8]),
    /// Inherited: the first six digits of the PUK. Sends the 18- or 20-byte
    /// form. Deliberate, documented, and not the default.
    PukPrefix,
}

/// Everything `INIT` sets, in one place.
///
/// A struct rather than five positional arguments because four of the five
/// are six-to-twelve digit strings, and a transposed PIN and PUK is a card
/// nobody can unblock.
#[derive(Debug, Clone, Copy)]
pub struct InitParams<'a> {
    /// Exactly [`PIN_LEN`] ASCII digits.
    pub pin: &'a [u8],
    /// Exactly [`PUK_LEN`] ASCII digits.
    pub puk: &'a [u8],
    pub duress: DuressPin<'a>,
    /// Wrong-PIN attempts before the card blocks. `None` is the applet's
    /// default of 3; otherwise must be in [`PIN_RETRIES`].
    pub pin_retries: Option<u8>,
    /// Wrong-PUK attempts before the card is bricked. `None` is the applet's
    /// default of 5; otherwise must be in [`PUK_RETRIES`].
    pub puk_retries: Option<u8>,
}

impl<'a> InitParams<'a> {
    /// The wallet's shape: a chosen duress PIN and default retry limits.
    pub fn new(pin: &'a [u8], puk: &'a [u8], duress: DuressPin<'a>) -> Self {
        InitParams {
            pin,
            puk,
            duress,
            pin_retries: None,
            puk_retries: None,
        }
    }

    /// The `INIT` payload, or why these values cannot make one.
    ///
    /// Every check here is one the card would also make, done early so the
    /// caller gets a sentence instead of `6A80` — **except** the digit check
    /// on a chosen duress PIN, which the applet does *not* make. Its
    /// `allDigits` covers `PIN ‖ PUK` only, so a non-digit duress PIN is
    /// accepted by `INIT` and can then never be entered through any numeric
    /// keypad. That one is ours alone.
    fn encode(&self) -> VaultResult<Vec<u8>> {
        let digits = |label: &str, v: &[u8], want: usize| -> VaultResult<()> {
            if v.len() != want {
                return Err(VaultError::Hardware(format!(
                    "the {label} must be exactly {want} digits, got {}",
                    v.len()
                )));
            }
            if !v.iter().all(|b| b.is_ascii_digit()) {
                return Err(VaultError::Hardware(format!("the {label} must be digits")));
            }
            Ok(())
        };
        digits("PIN", self.pin, PIN_LEN)?;
        digits("PUK", self.puk, PUK_LEN)?;

        // The applet refuses a duress PIN equal to the main PIN, because it
        // checks duress first and every unlock would take that path. Caught
        // here so the two cases read differently: a chosen duress PIN that
        // clashes is the holder's to fix, while a PUK whose prefix clashes is
        // ours — the wallet generates PUKs and must not make
        // one that collides.
        let duress = match self.duress {
            DuressPin::Chosen(d) => {
                digits("duress PIN", d, PIN_LEN)?;
                if d == self.pin {
                    return Err(VaultError::Hardware(
                        "the duress PIN must differ from the PIN - the card checks duress \
                         first, so an identical one would make every unlock a duress unlock"
                            .into(),
                    ));
                }
                Some(d)
            }
            DuressPin::PukPrefix => {
                if &self.puk[..PIN_LEN] == self.pin {
                    return Err(VaultError::Hardware(
                        "this PUK starts with the PIN, which the card would take as a duress \
                         PIN equal to the PIN - generate another"
                            .into(),
                    ));
                }
                None
            }
        };

        let limits = match (self.pin_retries, self.puk_retries) {
            (None, None) if duress.is_none() => None,
            (p, k) => {
                let p = p.unwrap_or(3);
                let k = k.unwrap_or(5);
                if !PIN_RETRIES.contains(&p) {
                    return Err(VaultError::Hardware(format!(
                        "PIN retries must be {}-{}, got {p}",
                        PIN_RETRIES.start(),
                        PIN_RETRIES.end()
                    )));
                }
                if !PUK_RETRIES.contains(&k) {
                    return Err(VaultError::Hardware(format!(
                        "PUK retries must be {}-{}, got {k}",
                        PUK_RETRIES.start(),
                        PUK_RETRIES.end()
                    )));
                }
                Some((p, k))
            }
        };

        // 18 / 20 / 26 bytes. The applet dispatches on the length alone, so
        // a duress PIN cannot be sent without the limits that precede it.
        let mut data = Vec::with_capacity(26);
        data.extend_from_slice(self.pin);
        data.extend_from_slice(self.puk);
        if let Some((p, k)) = limits {
            data.push(p);
            data.push(k);
        }
        if let Some(d) = duress {
            data.extend_from_slice(d);
        }
        Ok(data)
    }
}

/// Ed25519/Stellar hardware vault over a card transport.
pub struct StellarKeycard<T: CardTransport> {
    t: T,
    id_pubkey: Vec<u8>,
    /// The identity this handle is pinned to, if it was opened with one.
    ///
    /// `SELECT` resets the secure channel, so every PIN-bearing
    /// operation re-reads the identity. Re-reading is not checking:
    /// without somewhere to compare it to, a device is free to answer
    /// the first SELECT with the real card's key and the next with its
    /// own.
    expected_id: Option<Vec<u8>>,
    /// account index → (pubkey, G-address), populated at provision/sign time.
    cache: BTreeMap<SlotId, ([u8; 32], String)>,
}

impl<T: CardTransport> StellarKeycard<T> {
    /// Connect over an established transport: SELECT and read the identity key.
    ///
    /// **Takes the card's word for who it is.** Nothing here checks a CA
    /// signature, and nothing pins the identity across the SELECTs that
    /// follow, so this must not be used on a path that will send a PIN
    /// or trust a derived key. It is kept for provisioning — where there
    /// is no recorded identity yet to expect — and for the probes.
    /// Everything else wants [`Self::connect_expecting`].
    pub fn connect(mut t: T) -> VaultResult<Self> {
        let select = t.transmit(SELECT_AID).map_err(hw)?;
        let id_pubkey = card_identity_pubkey(&select).map_err(hw)?;
        Ok(Self {
            t,
            id_pubkey,
            expected_id: None,
            cache: BTreeMap::new(),
        })
    }

    /// Connect and refuse anything that is not the card we mean.
    ///
    /// `expected_id` is the compressed identity key recorded when the
    /// wallet was provisioned. Two things are checked, and both matter:
    ///
    /// 1. The certificate is signed by `ca`, so the key is one that CA
    ///    issued rather than one the device invented.
    /// 2. The key is the one this wallet was set up against — read on
    ///    **this** connection, the same one that will carry the PIN.
    ///
    /// The second is what closes the time-of-check/time-of-use gap. The
    /// identity check belongs here, not in `presence()`, which runs on a
    /// separate PC/SC connection: a device could answer honestly there and
    /// substitute itself here. Checking on another connection answers a
    /// question about another conversation.
    pub fn connect_expecting(mut t: T, expected_id: &[u8], cas: &[CaPublicKey]) -> VaultResult<Self> {
        let select = t.transmit(SELECT_AID).map_err(hw)?;
        let id_pubkey = Self::checked_identity(&select, expected_id, cas)?;
        Ok(Self {
            t,
            id_pubkey,
            expected_id: Some(expected_id.to_vec()),
            cache: BTreeMap::new(),
        })
    }

    /// Connect to a card we have no recorded identity for yet, but
    /// still insist the CA issued it.
    ///
    /// This is provisioning: the identity read here is the one that
    /// gets written into the vault record, so it is the moment that
    /// decides what every later session will be pinned to. Recording a
    /// substitute card's key here would make the substitution permanent
    /// and invisible, which is why the CA check matters more here than
    /// anywhere else -- it is the only check available before there is
    /// anything to compare against.
    pub fn connect_certified(mut t: T, cas: &[CaPublicKey]) -> VaultResult<Self> {
        let select = t.transmit(SELECT_AID).map_err(hw)?;
        let cert = card_identity_certificate(&select).map_err(hw)?;
        let id_pubkey = verify_identity_certificate_any(&cert, cas).map_err(|_| {
            VaultError::Hardware(
                "the card's identity certificate is not signed by the expected authority".into(),
            )
        })?;
        // Pinned from here on, so the identity cannot change between
        // now and the PIN that provisioning is about to send.
        let expected_id = Some(id_pubkey.clone());
        Ok(Self {
            t,
            id_pubkey,
            expected_id,
            cache: BTreeMap::new(),
        })
    }

    /// Verify a SELECT response against the pinned CA and identity.
    fn checked_identity(
        select: &[u8],
        expected_id: &[u8],
        cas: &[CaPublicKey],
    ) -> VaultResult<Vec<u8>> {
        let cert = card_identity_certificate(select).map_err(hw)?;
        let id_pubkey = verify_identity_certificate_any(&cert, cas).map_err(|_| {
            VaultError::Hardware(
                "the card's identity certificate is not signed by the expected authority"
                    .into(),
            )
        })?;
        if id_pubkey != expected_id {
            return Err(VaultError::Hardware(
                "this is a different card from the one this wallet was set up with".into(),
            ));
        }
        Ok(id_pubkey)
    }

    /// Open a fresh secure channel (SELECT resets it) and verify the PIN.
    ///
    /// The SELECT here is a fresh read of the card's identity, so where
    /// this handle was opened with an expectation it is re-checked
    /// before the PIN goes anywhere. A PIN must never cross a channel
    /// whose far end was identified on some other connection, or at some
    /// earlier moment.
    fn open_verified(&mut self, pin: &[u8]) -> VaultResult<SecureChannelV2<'_, T>> {
        let select = self.t.transmit(SELECT_AID).map_err(hw)?;
        if let Some(expected) = self.expected_id.clone() {
            let id = card_identity_pubkey(&select).map_err(hw)?;
            if id != expected {
                return Err(VaultError::Hardware(
                    "the card changed identity mid-session; refusing to send the PIN".into(),
                ));
            }
        }
        let mut sc = SecureChannelV2::open(&mut self.t, &self.id_pubkey).map_err(hw)?;
        sc.send(0x80, INS_VERIFY_PIN, 0x00, 0x00, pin)
            .map_err(pin_err)?;
        Ok(sc)
    }

    /// INIT a blank card: PIN, PUK, duress PIN and retry limits.
    ///
    /// Best-effort — an already-initialized card errors and we continue, which
    /// is what makes this safe to call on a card that may already be set up.
    /// Runs over a freshly opened channel.
    ///
    /// **Sending `pin || puk` and nothing else** is the applet's 18-byte
    /// form, the one that leaves the duress PIN as the PUK's first six
    /// digits — a card provisioned that way has a duress PIN its holder never
    /// chose and cannot change without a factory reset. [`DuressPin`] makes
    /// that outcome something a caller asks for by name.
    pub fn init(&mut self, params: &InitParams) -> VaultResult<()> {
        let data = params.encode()?;
        self.t.transmit(SELECT_AID).map_err(hw)?;
        {
            let mut sc = SecureChannelV2::open(&mut self.t, &self.id_pubkey).map_err(hw)?;
            let _ = sc.send(0x80, INS_INIT, 0x00, 0x00, &data); // ignore "already initialized"
        }

        // Re-read the identity: INIT is the operation that can establish it,
        // so the key cached at `connect` may now be stale. Every later
        // `open` authenticates the card by verifying the transcript signature
        // against this key, so a stale copy fails as `AuthFailed` on the
        // *next* call rather than here — which reads as "the card rejected
        // us" when in fact we are checking against the wrong key.
        // `KeycardVault`, the V1 client, has always re-selected here.
        let select = self.t.transmit(SELECT_AID).map_err(hw)?;
        self.id_pubkey = card_identity_pubkey(&select).map_err(hw)?;
        Ok(())
    }

    /// Load a 64-byte BIP-39 seed (the card computes the SLIP-0010 master), then
    /// cache account 0. This is the native provisioning path for a specific seed
    /// (the trait's 32-byte `import_seed` does not fit the card's HD model).
    pub fn load_bip39_seed(&mut self, seed: &[u8; 64], pin: &[u8]) -> VaultResult<()> {
        let pk = {
            let mut sc = self.open_verified(pin)?;
            sc.send(0x80, INS_LOAD_KEY, LOAD_KEY_P1_SEED, 0x00, seed)
                .map_err(hw)?;
            export_pubkey(&mut sc, 0)?
        };
        self.cache.insert(0, (pk, addr_of(&pk)));
        Ok(())
    }

    /// Ask the card to invent a BIP-39 phrase, as word indexes.
    ///
    /// `words` must be 12, 15, 18, 21 or 24; the applet takes the **checksum
    /// length** (4-8) rather than the word count, and `words / 3` is it.
    ///
    /// **The card keeps nothing.** `generateMnemonic` draws entropy from the
    /// card's RNG, converts it to indexes, returns them and ends — it does
    /// not derive a seed and it does not load one. The host maps indexes to
    /// words, shows them, computes the 64-byte seed and sends it back with
    /// [`load_bip39_seed`](Self::load_bip39_seed).
    ///
    /// Two consequences worth knowing before building a flow on this:
    ///
    /// - The phrase and the seed both cross the host. "Generated on the card"
    ///   is true of the entropy and of nothing else, and the copy shown to a
    ///   holder must not claim more.
    /// - Stopping between this call and `load_bip39_seed` leaves the card
    ///   **untouched**, so there is no half-provisioned state to detect or
    ///   repair. That is worth keeping: confirm the written words *before*
    ///   loading, and a mis-transcription then costs a retry rather than a
    ///   wallet.
    ///
    /// Needs an open secure channel and an initialized card, but **not** a
    /// verified PIN — the applet's dispatch requires only that `pin != null`.
    pub fn generate_mnemonic(&mut self, words: u8) -> VaultResult<Vec<u16>> {
        if !matches!(words, 12 | 15 | 18 | 21 | 24) {
            return Err(VaultError::Hardware(format!(
                "a BIP-39 phrase is 12, 15, 18, 21 or 24 words, not {words}"
            )));
        }
        let checksum_len = words / 3;
        self.require_initialized("generating a phrase")?;
        self.t.transmit(SELECT_AID).map_err(hw)?;
        let out = {
            let mut sc = SecureChannelV2::open(&mut self.t, &self.id_pubkey).map_err(hw)?;
            sc.send(0x80, INS_GENERATE_MNEMONIC, checksum_len, 0x00, &[])
                .map_err(hw)?
        };
        if out.len() != words as usize * 2 {
            return Err(VaultError::Hardware(format!(
                "expected {} bytes of word indexes for {words} words, got {}",
                words as usize * 2,
                out.len()
            )));
        }
        let indexes: Vec<u16> = out
            .chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        // 2048-word list. An out-of-range index is a framing error, and
        // mapping it would panic on the wordlist lookup instead.
        if let Some(bad) = indexes.iter().find(|i| **i > 2047) {
            return Err(VaultError::Hardware(format!(
                "the card returned word index {bad}, outside the BIP-39 list"
            )));
        }
        Ok(indexes)
    }

    /// Change the PIN. Needs the current one.
    ///
    /// The applet refuses a new main PIN equal to the **duress** PIN, for the
    /// same reason `INIT` does. It does not offer that check to a duress
    /// session, because there it would be an oracle for the main PIN — set a
    /// candidate, see whether it is refused.
    pub fn change_pin(&mut self, current: &[u8], new: &[u8]) -> VaultResult<()> {
        check_digits("new PIN", new, PIN_LEN)?;
        self.require_initialized("changing the PIN")?;
        let mut sc = self.open_verified(current)?;
        sc.send(0x80, INS_CHANGE_PIN, CHANGE_PIN_P1_USER, 0x00, new)
            .map_err(pin_err)?;
        Ok(())
    }

    /// Change the PUK. Needs the PIN, not the old PUK.
    pub fn change_puk(&mut self, pin: &[u8], new_puk: &[u8]) -> VaultResult<()> {
        check_digits("new PUK", new_puk, PUK_LEN)?;
        self.require_initialized("changing the PUK")?;
        let mut sc = self.open_verified(pin)?;
        sc.send(0x80, INS_CHANGE_PIN, CHANGE_PIN_P1_PUK, 0x00, new_puk)
            .map_err(pin_err)?;
        Ok(())
    }

    /// Unblock a blocked PIN with the PUK, setting a new PIN.
    ///
    /// **Only works on a card that is actually blocked** — the applet answers
    /// `6985` while attempts remain, which is a confusing thing to show
    /// someone who came here to change their PIN, so the message names the
    /// call they wanted instead. A wrong PUK comes back as `63Cx` like a wrong
    /// PIN, and `pin_err` turns a surviving attempt into `BadCredential` so a
    /// prompt loop re-asks; at zero the card is bricked and it does not.
    pub fn unblock_pin(&mut self, puk: &[u8], new_pin: &[u8]) -> VaultResult<()> {
        check_digits("PUK", puk, PUK_LEN)?;
        check_digits("new PIN", new_pin, PIN_LEN)?;
        self.require_initialized("unblocking the PIN")?;
        let mut data = puk.to_vec();
        data.extend_from_slice(new_pin);

        self.t.transmit(SELECT_AID).map_err(hw)?;
        let mut sc = SecureChannelV2::open(&mut self.t, &self.id_pubkey).map_err(hw)?;
        match sc.send(0x80, INS_UNBLOCK_PIN, 0x00, 0x00, &data) {
            Ok(_) => Ok(()),
            Err(crate::error::KeycardError::Apdu { sw: 0x6985 }) => Err(VaultError::Hardware(
                "this card's PIN is not blocked - use change_pin, which needs the current PIN"
                    .into(),
            )),
            Err(e) => Err(pin_err(e)),
        }
    }

    /// Wipe the card: keys, notes, PINs, PUK and pairing.
    ///
    /// **Sent in plain, not through the secure channel.** The applet handles
    /// `FACTORY RESET` in `process()` *before* the secure-channel dispatch,
    /// and its own comment says why: "an open secure channel would wrap a
    /// refusal in an encrypted response with an outer 9000, indistinguishable
    /// from success." Wrapped in `INS_SECURED_APDU` it never reaches the
    /// handler at all, so the status word here is the card's own.
    ///
    /// Allowed when the card has never been initialized, when the active PIN
    /// is verified — main **or** duress — or when PIN and PUK are both
    /// exhausted (`factoryResetAllowed`). So `pin` is `Some` only for the
    /// middle case; the other two have no PIN to give.
    ///
    /// There is no undo and nothing is kept on the way out. Notes on the card
    /// are bearer instruments — the bytes are the money, and this deletes
    /// them. The wallet keeps it behind a typed confirmation and reachable
    /// from exactly two screens.
    pub fn factory_reset(&mut self, pin: Option<&[u8]>) -> VaultResult<()> {
        // Verifying the PIN needs the channel; the reset itself must not use
        // it. `factoryResetAllowed` reads `pin.isValidated()`, which survives
        // the channel being done with — but not a re-SELECT, so nothing may
        // SELECT between these two steps.
        if let Some(pin) = pin {
            let _ = self.open_verified(pin)?;
        }

        let apdu = [
            0x80,
            INS_FACTORY_RESET,
            FACTORY_RESET_P1_MAGIC,
            FACTORY_RESET_P2_MAGIC,
            0x00,
        ];
        let resp = self.t.transmit(&apdu).map_err(hw)?;
        let sw = match resp.len() {
            0 | 1 => {
                return Err(VaultError::Hardware(
                    "truncated FACTORY RESET response".into(),
                ));
            }
            n => u16::from_be_bytes([resp[n - 2], resp[n - 1]]),
        };
        match sw {
            0x9000 => Ok(()),
            0x6985 => Err(VaultError::Hardware(
                "this card will not reset without its PIN - supply one, or exhaust the PIN \
                 and PUK first"
                    .into(),
            )),
            other => Err(VaultError::Hardware(format!(
                "FACTORY RESET refused: {other:04X}"
            ))),
        }?;

        // Everything cached describes a card that no longer exists, and the
        // identity key is re-established on the next INIT, so re-read it for
        // the same reason `init` does.
        self.cache.clear();
        let select = self.t.transmit(SELECT_AID).map_err(hw)?;
        self.id_pubkey = card_identity_pubkey(&select).map_err(hw)?;
        Ok(())
    }

    /// Take the next owner index, and advance the counter.
    ///
    /// **This allocates.** The card is the sole owner-index allocator for a
    /// card-backed wallet, and this is that allocation: call it when an
    /// index is actually being assigned to a receive, never to find out what
    /// the counter says. Use [`owner_index`](Self::owner_index) for that — a
    /// read-only tool calling this would spend an index on every run.
    ///
    /// The counter survives `FACTORY_RESET` and duress by design: a re-seeded card restarting at 1 would hand out
    /// indices the holder has already used, relinking their history.
    pub fn next_owner_index(&mut self, pin: &[u8]) -> VaultResult<u32> {
        self.require_initialized("taking an owner index")?;
        let mut sc = self.open_verified(pin)?;
        let d = sc
            .send(0x80, INS_NOTE_NEXT_INDEX, 0x00, 0x00, &[])
            .map_err(pin_err)?;
        be_u32(&d, "NEXT INDEX")
    }

    /// Read the counter without spending an index.
    ///
    /// `ADVANCE INDEX` raises the counter to *at least* the value given and
    /// returns the result, so zero raises it to nothing and reads it.
    pub fn owner_index(&mut self, pin: &[u8]) -> VaultResult<u32> {
        self.advance_owner_index(0, pin)
    }

    /// Raise the counter to at least `to`, and return where it ended up.
    ///
    /// This is the restore path. After reinstalling the store package — the
    /// one event that *does* reset the counter, and the same one that loses
    /// the notes — the host advances past the maximum of the backup's
    /// `next_owner_index` and `1 + max(owner_index)` over every held token,
    /// plus a margin of 20. The margin covers the
    /// case neither term sees: an index the Shell issued, somebody paid, and
    /// whose note bytes never arrived.
    pub fn advance_owner_index(&mut self, to: u32, pin: &[u8]) -> VaultResult<u32> {
        if to > 0x8000_0000 {
            return Err(VaultError::Hardware(format!(
                "owner index {to} is above the applet's limit of 0x80000000"
            )));
        }
        self.require_initialized("reading the owner index")?;
        let mut sc = self.open_verified(pin)?;
        let d = sc
            .send(0x80, INS_NOTE_ADVANCE_INDEX, 0x00, 0x00, &to.to_be_bytes())
            .map_err(pin_err)?;
        be_u32(&d, "ADVANCE INDEX")
    }

    /// Refuse a secured command that a blank card would silently swallow.
    ///
    /// `processSecured` handles only `INIT` and `GET CHALLENGE` while
    /// `pin == null`, and for anything else it **returns without setting a
    /// status word** — so the applet answers an empty `9000` and the client
    /// reads a success that did nothing. Inherited from upstream (Status's
    /// applet), so the contract is ours to enforce rather than theirs to
    /// change.
    ///
    /// The individual commands keep their own response-shape checks as a
    /// backstop: this costs a SELECT, and a check that can be skipped by a
    /// future caller is not one to rely on alone.
    fn require_initialized(&mut self, what: &str) -> VaultResult<()> {
        if self.application_info()?.initialized {
            return Ok(());
        }
        Err(VaultError::Hardware(format!(
            "this card has not been set up, so {what} would do nothing - run INIT first"
        )))
    }

    /// Re-SELECT and report what the card says about itself.
    ///
    /// Chiefly: has it been `INIT`ed. A provisioning flow needs that before
    /// it does anything else — a blank card
    /// takes `INIT`, an initialized one silently ignores it, so acting on a
    /// guess means a flow that believes it set a PIN it did not set.
    ///
    /// [`crate::Transport::select_keycard`] answers the same question but is
    /// PC/SC only, so nothing driving the simulator could ask it.
    pub fn application_info(&mut self) -> VaultResult<crate::ApplicationInfo> {
        let resp = self.t.transmit(SELECT_AID).map_err(hw)?;
        // Strip SW, which the parser does not expect.
        let body = resp.get(..resp.len().saturating_sub(2)).unwrap_or(&[]);
        crate::transport::parse_application_info(body).map_err(hw)
    }

    /// The card's identity public key (from the SELECT certificate).
    pub fn identity_pubkey(&self) -> &[u8] {
        &self.id_pubkey
    }

    /// Sign a Stellar **transaction hash** on-card and return a
    /// [`DecoratedSignature`] ready to attach to the transaction envelope.
    ///
    /// The host builds the transaction and computes `tx_hash` (see
    /// [`transaction_hash`]); the card only signs the 32-byte hash. The hint is
    /// the last 4 bytes of the signing account's public key.
    pub fn sign_stellar_tx(
        &mut self,
        account: u32,
        tx_hash: &[u8; 32],
        pin: &[u8],
    ) -> VaultResult<DecoratedSignature> {
        let (pk, signature) = {
            let mut sc = self.open_verified(pin)?;
            sign_hash(&mut sc, account, tx_hash)?
        };
        self.cache
            .entry(account)
            .or_insert_with(|| (pk, addr_of(&pk)));
        let mut hint = [0u8; 4];
        hint.copy_from_slice(&pk[28..32]);
        Ok(DecoratedSignature { hint, signature })
    }
}

/// A Stellar `DecoratedSignature`: a 4-byte key hint plus the 64-byte signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecoratedSignature {
    /// Last 4 bytes of the signer's Ed25519 public key.
    pub hint: [u8; 4],
    /// The 64-byte Ed25519 signature (R‖S).
    pub signature: [u8; 64],
}

impl DecoratedSignature {
    /// XDR encoding: `hint(4) || u32(len=64) || signature(64)` (72 bytes) — the
    /// `DecoratedSignature` a caller pushes onto `Transaction.signatures`.
    pub fn to_xdr(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(4 + 4 + 64);
        v.extend_from_slice(&self.hint);
        v.extend_from_slice(&64u32.to_be_bytes());
        v.extend_from_slice(&self.signature);
        v
    }

    /// The XDR bytes, base64-encoded.
    pub fn to_base64(&self) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(self.to_xdr())
    }
}

/// Stellar network id = `SHA-256(network passphrase)`.
///
/// Testnet: `"Test SDF Network ; September 2015"`.
/// Mainnet: `"Public Global Stellar Network ; September 2015"`.
pub fn network_id(passphrase: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(passphrase.as_bytes()).into()
}

/// The 32-byte hash a Stellar signer signs, per the `TransactionSignaturePayload`:
/// `SHA-256(network_id || ENVELOPE_TYPE_TX(2, u32 BE) || transaction_xdr)`.
///
/// `transaction_xdr` is the serialized `Transaction` (the tagged payload's inner
/// value) — produced by a Stellar SDK; this crate does not build XDR.
pub fn transaction_hash(network_id: &[u8; 32], transaction_xdr: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(network_id);
    h.update(2u32.to_be_bytes()); // ENVELOPE_TYPE_TX
    h.update(transaction_xdr);
    h.finalize().into()
}

impl<T: CardTransport> KeyVault for StellarKeycard<T> {
    fn generate_key(&mut self, _label: &str, credential: &[u8]) -> VaultResult<SlotId> {
        // A PUK of twelve zeros, so the duress PIN this card inherits is
        // "000000" (`DuressPin::PukPrefix`). That is as bad as it sounds, and
        // it is left alone only because Kenter does not wire `KeyVault` at
        // all - this path provisions nothing
        // a holder keeps. Anything that ships has to come through
        // `InitParams` with a chosen duress PIN. Note it also fails outright
        // if the caller's PIN is "000000", which the card refuses as a duress
        // collision.
        self.init(&InitParams::new(
            credential,
            b"000000000000",
            DuressPin::PukPrefix,
        ))?;
        let pk = {
            let mut sc = self.open_verified(credential)?;
            sc.send(0x80, INS_GENERATE_KEY, 0x00, 0x00, &[])
                .map_err(hw)?;
            export_pubkey(&mut sc, 0)?
        };
        self.cache.insert(0, (pk, addr_of(&pk)));
        Ok(0)
    }

    fn import_seed(
        &mut self,
        _seed: &[u8; 32],
        _label: &str,
        _credential: &[u8],
    ) -> VaultResult<SlotId> {
        Err(VaultError::Unsupported(
            "card uses a 64-byte BIP-39 seed + SLIP-0010; use load_bip39_seed()".into(),
        ))
    }

    fn sign(&mut self, slot: SlotId, message: &[u8], credential: &[u8]) -> VaultResult<[u8; 64]> {
        let hash: [u8; 32] = message.try_into().map_err(|_| {
            VaultError::Unsupported("card signs a 32-byte hash, not arbitrary messages".into())
        })?;
        let (pk, sig) = {
            let mut sc = self.open_verified(credential)?;
            sign_hash(&mut sc, slot, &hash)?
        };
        self.cache.entry(slot).or_insert_with(|| (pk, addr_of(&pk)));
        Ok(sig)
    }

    fn public_key(&self, slot: SlotId) -> VaultResult<[u8; 32]> {
        self.cache
            .get(&slot)
            .map(|(pk, _)| *pk)
            .ok_or(VaultError::LockedMetadata)
    }

    fn stellar_address(&self, slot: SlotId) -> VaultResult<String> {
        self.cache
            .get(&slot)
            .map(|(_, a)| a.clone())
            .ok_or(VaultError::LockedMetadata)
    }

    fn list_keys(&self) -> VaultResult<Vec<KeySlotInfo>> {
        Ok(self
            .cache
            .iter()
            .map(|(slot, (_, addr))| KeySlotInfo {
                slot: *slot,
                label: format!("stellar/{slot}"),
                stellar_address: addr.clone(),
                created_at: 0,
            })
            .collect())
    }

    fn remove_key(&mut self, _slot: SlotId, credential: &[u8]) -> VaultResult<()> {
        {
            let mut sc = self.open_verified(credential)?;
            sc.send(0x80, INS_REMOVE_KEY, 0x00, 0x00, &[]).map_err(hw)?;
        }
        self.cache.clear(); // REMOVE KEY wipes the seed → all HD accounts gone
        Ok(())
    }
}

/// Spend-mode **owner** keys — the role Kenter uses (see the module docs).
///
/// `credential` is the card **PIN**, where `SoftVault` takes a passphrase. The
/// trait says so; it is restated here because passing a passphrase to a card
/// burns a PIN attempt, and a card has very few.
impl<T: CardTransport> DerivingVault for StellarKeycard<T> {
    fn derive_public(&mut self, index: u32, credential: &[u8]) -> VaultResult<[u8; 32]> {
        // Not served from `cache`: that is populated by the `KeyVault` side and
        // keyed by slot, and conflating the two caches is exactly the mix-up
        // the module docs warn about. An owner key is cheap to re-export and
        // the card is the authority on it.
        let mut sc = self.open_verified(credential)?;
        export_pubkey(&mut sc, index)
    }

    fn sign_derived(
        &mut self,
        index: u32,
        message: &[u8],
        credential: &[u8],
    ) -> VaultResult<[u8; 64]> {
        // The card signs 32 bytes and nothing else. Owner authorizations are
        // already digests by the time they reach a vault (see
        // `docs/architecture/spend-mode.md`),
        // so a wrong length here is a caller passing a preimage — worth saying
        // rather than letting the card refuse it opaquely.
        let hash: [u8; 32] = message.try_into().map_err(|_| {
            VaultError::Unsupported(format!(
                "the card signs a 32-byte digest; got {} bytes. Owner authorizations \
                 sign SHA-256(message), not the message",
                message.len()
            ))
        })?;
        let mut sc = self.open_verified(credential)?;
        let (pk, sig) = sign_hash(&mut sc, index, &hash)?;

        // The applet returns the public key alongside the signature. Checking
        // it against the index we asked for turns a derivation mismatch into a
        // local error instead of an on-chain revert: a signature under the
        // wrong key verifies nowhere, and the holder would see only
        // `OwnerCommitmentMismatch` from the mint with nothing to act on.
        if !verify_ed25519(&pk, &hash, &sig) {
            return Err(VaultError::Hardware(format!(
                "the card's signature for owner index {index} does not verify under the \
                 key it returned"
            )));
        }
        Ok(sig)
    }
}

/// BIP85 on-card (`kenter_vault::bip85`) — how a card produces the wallet's
/// symmetric keys without ever exporting its seed.
///
/// Derived from the card's **BIP32/secp256k1** master, which is a different
/// tree from the SLIP-0010 one the owner keys come from. Both are set from one
/// BIP-39 seed by `LOAD KEY P1=SEED`; a card provisioned any other way has a
/// master with no seed behind it, and its BIP85 values are reproducible by no
/// phrase. First run must refuse such a card.
impl<T: CardTransport> Bip85 for StellarKeycard<T> {
    fn bip85_entropy(
        &mut self,
        path: &[u32],
        len: usize,
        credential: &[u8],
    ) -> VaultResult<Zeroizing<Vec<u8>>> {
        if !(1..=64).contains(&len) {
            return Err(VaultError::Crypto2(format!(
                "BIP85 output length {len} is outside 1..=64"
            )));
        }
        // All-hardened, 4-byte big-endian elements — the same encoding the
        // owner-key path uses. The applet refuses anything not under
        // m/83696968', so a wrong path fails on the card rather than
        // returning something plausible.
        let mut data = Vec::with_capacity(path.len() * 4);
        for &element in path {
            data.extend_from_slice(&(0x8000_0000u32 | element).to_be_bytes());
        }
        let mut sc = self.open_verified(credential)?;
        let resp = sc
            .send(0x80, INS_EXPORT_BIP85, len as u8, 0x00, &data)
            .map_err(hw)?;
        if resp.len() < len {
            return Err(VaultError::Hardware(format!(
                "BIP85 returned {} bytes, asked for {len}",
                resp.len()
            )));
        }
        Ok(Zeroizing::new(resp[..len].to_vec()))
    }
}

/// Verify an Ed25519 signature over a 32-byte hash (helper for callers/tests).
pub fn verify_ed25519(pubkey: &[u8; 32], hash: &[u8; 32], sig: &[u8; 64]) -> bool {
    match (VerifyingKey::from_bytes(pubkey), Signature::from_slice(sig)) {
        (Ok(vk), Ok(s)) => vk.verify(hash, &s).is_ok(),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testnet_network_id() {
        // Well-known Stellar testnet network id.
        assert_eq!(
            hex::encode(network_id("Test SDF Network ; September 2015")),
            "cee0302d59844d32bdca915c8203dd44b33fbb7edc19051ea37abedf28ecd472"
        );
    }

    #[test]
    fn stellar_path_hardened() {
        // m/44'/148'/0'
        assert_eq!(
            stellar_path(0),
            [
                0x80, 0x00, 0x00, 0x2C, 0x80, 0x00, 0x00, 0x94, 0x80, 0x00, 0x00, 0x00
            ]
        );
        // m/44'/148'/5'
        assert_eq!(&stellar_path(5)[8..], &[0x80, 0x00, 0x00, 0x05]);
    }

    #[test]
    fn decorated_signature_xdr() {
        let ds = DecoratedSignature {
            hint: [1, 2, 3, 4],
            signature: [0xAA; 64],
        };
        let xdr = ds.to_xdr();
        assert_eq!(xdr.len(), 72);
        assert_eq!(&xdr[..4], &[1, 2, 3, 4]); // hint
        assert_eq!(&xdr[4..8], &[0, 0, 0, 64]); // opaque length = 64
        assert_eq!(&xdr[8..], &[0xAA; 64]); // signature
    }

    #[test]
    fn transaction_hash_shape() {
        let nid = network_id("Test SDF Network ; September 2015");
        let h1 = transaction_hash(&nid, b"tx-a");
        let h2 = transaction_hash(&nid, b"tx-b");
        assert_ne!(h1, h2);
        // Deterministic.
        assert_eq!(h1, transaction_hash(&nid, b"tx-a"));
    }
}
#[cfg(test)]
mod init_params_tests {
    use super::*;

    const PIN: &[u8] = b"123456";
    const PUK: &[u8] = b"987654321098";

    fn chosen(duress: &'static [u8]) -> InitParams<'static> {
        InitParams::new(PIN, PUK, DuressPin::Chosen(duress))
    }

    /// The applet dispatches on data length alone, so the three forms have to
    /// come out at exactly 18, 20 and 26 bytes or it reads the wrong fields.
    #[test]
    fn the_three_init_forms_are_the_lengths_the_applet_switches_on() {
        let inherited = InitParams::new(PIN, PUK, DuressPin::PukPrefix);
        assert_eq!(inherited.encode().unwrap().len(), 18);

        let limited = InitParams {
            pin_retries: Some(5),
            ..InitParams::new(PIN, PUK, DuressPin::PukPrefix)
        };
        assert_eq!(limited.encode().unwrap().len(), 20);

        assert_eq!(chosen(b"654321").encode().unwrap().len(), 26);
    }

    /// A chosen duress PIN cannot be sent without the retry limits in front
    /// of it, because position is all the applet has to find it by.
    #[test]
    fn a_chosen_duress_pin_carries_the_default_limits_with_it() {
        let data = chosen(b"654321").encode().unwrap();
        assert_eq!(&data[..6], PIN);
        assert_eq!(&data[6..18], PUK);
        assert_eq!(data[18], 3, "default PIN retries");
        assert_eq!(data[19], 5, "default PUK retries");
        assert_eq!(&data[20..26], b"654321");
    }

    /// The card checks duress first, so an equal pair makes every unlock a
    /// duress unlock. It answers 6A80; we would rather say why.
    #[test]
    fn a_duress_pin_equal_to_the_pin_is_refused_here_not_by_the_card() {
        let err = chosen(PIN).encode().unwrap_err().to_string();
        assert!(err.contains("must differ"), "{err}");
    }

    /// Same collision, reached the other way: with no explicit duress PIN the
    /// card takes the PUK's first six digits, so this PUK is unusable with
    /// this PIN. We generate PUKs, so this is our bug to avoid, not the
    /// holder's.
    #[test]
    fn a_puk_beginning_with_the_pin_is_refused() {
        let params = InitParams::new(PIN, b"123456789012", DuressPin::PukPrefix);
        let err = params.encode().unwrap_err().to_string();
        assert!(err.contains("starts with the PIN"), "{err}");
    }

    /// ...and is fine once an explicit duress PIN displaces it, because then
    /// the card never looks at the prefix.
    #[test]
    fn the_same_puk_is_fine_with_a_chosen_duress_pin() {
        let params = InitParams::new(PIN, b"123456789012", DuressPin::Chosen(b"654321"));
        assert_eq!(params.encode().unwrap().len(), 26);
    }

    /// The applet's `allDigits` covers PIN and PUK only, so a non-digit
    /// duress PIN would be accepted and could then never be typed on a
    /// numeric keypad. This check exists nowhere else.
    #[test]
    fn a_non_digit_duress_pin_is_caught_here_because_the_card_does_not_look() {
        let err = chosen(b"abcdef").encode().unwrap_err().to_string();
        assert!(err.contains("must be digits"), "{err}");
    }

    #[test]
    fn lengths_are_exact() {
        let short = InitParams::new(b"12345", PUK, DuressPin::PukPrefix);
        assert!(short.encode().unwrap_err().to_string().contains("6 digits"));

        let long_puk = InitParams::new(PIN, b"9876543210987", DuressPin::PukPrefix);
        assert!(
            long_puk
                .encode()
                .unwrap_err()
                .to_string()
                .contains("12 digits")
        );
    }

    /// Out-of-range limits are rejected by the applet with the same
    /// SW_WRONG_DATA it uses for a malformed PIN, which would be an
    /// impossible error to act on.
    #[test]
    fn retry_limits_outside_the_applets_range_are_refused() {
        let too_few = InitParams {
            pin_retries: Some(1),
            ..InitParams::new(PIN, PUK, DuressPin::PukPrefix)
        };
        assert!(too_few.encode().unwrap_err().to_string().contains("2-10"));

        let too_many = InitParams {
            puk_retries: Some(13),
            ..InitParams::new(PIN, PUK, DuressPin::PukPrefix)
        };
        assert!(too_many.encode().unwrap_err().to_string().contains("3-12"));
    }
}
