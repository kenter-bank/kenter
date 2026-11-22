//! **Status Keycard** secure channel V1 (secp256k1 · AES-256-CBC · AES-CBC-MAC).
//!
//! Ported from the official `keycard-tech/keycard-rs` (`src/secure_channel/v1.rs`
//! + `pairing.rs`) and Status's keycard applet. See
//! `docs/architecture/custody.md`. The card is a genuine Status Keycard, *not*
//! Cryptnox — the reader brand ("Cryptnox NFC") is irrelevant.
//!
//! Lifecycle for a blank card: SELECT → INIT → PAIR → OPEN SECURE CHANNEL →
//! MUTUALLY AUTHENTICATE → (protected commands: VERIFY PIN, SIGN, …).
//!
//! Key facts (all from keycard-rs):
//! - **INIT** (plain, one-shot): ephemeral ECDH with the card's *static* SC key →
//!   AES-256-CBC(ISO-7816-4 pad) encrypt `PIN ‖ PUK ‖ pairing_secret`. Wire form:
//!   `[len]‖client_pub(65)‖iv(16)‖ciphertext`.
//! - **pairing_secret** = PBKDF2-HMAC-SHA256(password, "Keycard Pairing Password
//!   Salt", 50000, 32). Default password `"KeycardDefaultPairing"`.
//! - **PAIR**: client_challenge → card returns `SHA256(secret‖client_chal) ‖
//!   card_chal`; client replies `SHA256(secret‖card_chal)`; card returns
//!   `index ‖ salt`; `pairing_key = SHA256(secret ‖ salt)`.
//! - **OPEN**: `80 10 <index> 00 <client_pub(65)>` → `salt(32) ‖ seed_iv(16)`.
//!   `SHA-512(ecdh ‖ pairing_key ‖ salt)` → `enc_key[0..32] ‖ mac_key[32..64]`;
//!   initial IV = `seed_iv`.
//! - **Wrapping**: AES-256-CBC(enc_key, iv) + ISO-7816-4 pad; MAC = AES-CBC-MAC
//!   (mac_key, IV=0) over `meta(16) ‖ ciphertext`, and the MAC *becomes* the IV.
//!   Command meta = `[cla,ins,p1,p2, lc, 0…]`; response meta = `[resp_len, 0…]`.

use aes::Aes256;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use hmac::{Hmac, Mac};
use k256::ecdh::diffie_hellman;
use k256::elliptic_curve::Generate;
use k256::elliptic_curve::sec1::ToSec1Point;
use k256::{PublicKey, SecretKey};
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroize;

use crate::apdu::{SW_OK, parse_sw, response_data};
use crate::error::{KeycardError, Result};
use crate::transport::Transport;

const CLA: u8 = 0x80;
const INS_INIT: u8 = 0xFE;
const INS_OPEN_SECURE_CHANNEL: u8 = 0x10;
const INS_MUTUALLY_AUTHENTICATE: u8 = 0x11;
const INS_PAIR: u8 = 0x12;
const INS_VERIFY_PIN: u8 = 0x20;
const INS_GENERATE_KEY: u8 = 0xD4;
const INS_SIGN: u8 = 0xC0;

const SIGN_P1_CURRENT_KEY: u8 = 0x00;
const SIGN_P2_ECDSA: u8 = 0x00;
const SIGN_P2_EDDSA_ED25519: u8 = 0x01;

const TLV_SIGNATURE_TEMPLATE: u8 = 0xA0;
const TLV_PUB_KEY: u8 = 0x80;
const TLV_ECDSA_SEQUENCE: u8 = 0x30;

const PAIR_P1_FIRST: u8 = 0x00;
const PAIR_P1_LAST: u8 = 0x01;
const PAIR_P2_ANY: u8 = 0x00;

const BLOCK: usize = 16;

/// PBKDF2 salt for the Status Keycard pairing password.
pub const PAIRING_PASSWORD_SALT: &[u8] = b"Keycard Pairing Password Salt";
/// PBKDF2 iteration count for the pairing password.
pub const PAIRING_PBKDF2_ITERATIONS: u32 = 50_000;
/// The out-of-the-box default pairing password on a Status Keycard.
pub const DEFAULT_PAIRING_PASSWORD: &str = "KeycardDefaultPairing";

type HmacSha256 = Hmac<Sha256>;

// ---- AES-256-CBC + CBC-MAC + ISO-7816-4 padding ----

fn cbc_encrypt(key: &[u8; 32], iv: &[u8; 16], data: &[u8]) -> Vec<u8> {
    debug_assert_eq!(data.len() % BLOCK, 0);
    let cipher = Aes256::new(GenericArray::from_slice(key));
    let mut prev = *iv;
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(BLOCK) {
        let mut b = [0u8; 16];
        for i in 0..BLOCK {
            b[i] = chunk[i] ^ prev[i];
        }
        let mut ga = GenericArray::clone_from_slice(&b);
        cipher.encrypt_block(&mut ga);
        prev.copy_from_slice(&ga);
        out.extend_from_slice(&ga);
    }
    out
}

fn cbc_decrypt(key: &[u8; 32], iv: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let cipher = Aes256::new(GenericArray::from_slice(key));
    let mut prev = *iv;
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(BLOCK) {
        let mut ga = GenericArray::clone_from_slice(chunk);
        cipher.decrypt_block(&mut ga);
        for i in 0..BLOCK {
            out.push(ga[i] ^ prev[i]);
        }
        prev.copy_from_slice(chunk);
    }
    out
}

/// AES-CBC-MAC with a zero IV: last CBC block of `data` (must be a 16-multiple).
fn cbc_mac(key: &[u8; 32], data: &[u8]) -> [u8; 16] {
    let ct = cbc_encrypt(key, &[0u8; 16], data);
    let mut mac = [0u8; 16];
    mac.copy_from_slice(&ct[ct.len() - BLOCK..]);
    mac
}

/// ISO-7816-4 padding: append 0x80, then 0x00 up to a 16-byte multiple.
fn pad(data: &[u8]) -> Vec<u8> {
    let mut v = data.to_vec();
    v.push(0x80);
    while v.len() % BLOCK != 0 {
        v.push(0x00);
    }
    v
}

fn unpad(data: &[u8]) -> Result<Vec<u8>> {
    let mut i = data.len();
    while i > 0 && data[i - 1] == 0x00 {
        i -= 1;
    }
    if i == 0 || data[i - 1] != 0x80 {
        return Err(KeycardError::SecureChannel("bad ISO-7816-4 padding".into()));
    }
    Ok(data[..i - 1].to_vec())
}

/// PBKDF2-HMAC-SHA256 → 32 bytes (single output block).
fn pbkdf2_sha256_32(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
    let mut u: [u8; 32] = {
        let mut m = <HmacSha256 as Mac>::new_from_slice(password).expect("hmac key");
        m.update(salt);
        m.update(&1u32.to_be_bytes());
        m.finalize().into_bytes().into()
    };
    let mut out = u;
    for _ in 1..iterations {
        let mut m = <HmacSha256 as Mac>::new_from_slice(password).expect("hmac key");
        m.update(&u);
        let next: [u8; 32] = m.finalize().into_bytes().into();
        u = next;
        for (o, b) in out.iter_mut().zip(next.iter()) {
            *o ^= b;
        }
    }
    u.zeroize();
    out
}

/// Derive the 32-byte pairing secret from a pairing password.
pub fn pairing_secret_from_password(password: &str) -> [u8; 32] {
    pbkdf2_sha256_32(
        password.as_bytes(),
        PAIRING_PASSWORD_SALT,
        PAIRING_PBKDF2_ITERATIONS,
    )
}

/// A fresh ephemeral keypair + the ECDH secret with the card's static SC key.
struct Ephemeral {
    public: Vec<u8>, // uncompressed, 65 bytes
    secret: [u8; 32],
}

fn ephemeral_ecdh(card_static_pub: &[u8]) -> Result<Ephemeral> {
    let card_pub = PublicKey::from_sec1_bytes(card_static_pub)
        .map_err(|e| KeycardError::SecureChannel(format!("card pubkey parse: {e}")))?;
// k256 0.14: encoding is `ToSec1Point`, and key generation is
// `Generate`. `generate()` takes the system RNG itself, so the ephemeral
// key does not depend on this crate and `rand` agreeing on a version of
// `CryptoRng`.
    let eph = SecretKey::generate();
    let public = eph.public_key().to_sec1_point(false).as_bytes().to_vec();
    let sk = eph.to_nonzero_scalar();
    let shared = diffie_hellman(&sk, card_pub.as_affine());
    let mut secret = [0u8; 32];
    secret.copy_from_slice(shared.raw_secret_bytes());
    Ok(Ephemeral { public, secret })
}

/// Client-side pairing material (index + derived key).
#[derive(Clone)]
pub struct Pairing {
    pub index: u8,
    pub key: [u8; 32],
}

impl Drop for Pairing {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

/// INIT a blank card: set PIN, PUK, and the pairing secret. Plain one-shot APDU.
/// Quasi-permanent (needs a factory reset to redo).
pub fn init_card(
    t: &mut Transport,
    card_static_pub: &[u8],
    pin: &str,
    puk: &str,
    pairing_secret: &[u8; 32],
) -> Result<()> {
    let mut eph = ephemeral_ecdh(card_static_pub)?;
    let iv: [u8; 16] = rand::random();

    let mut init_data = Vec::new();
    init_data.extend_from_slice(pin.as_bytes());
    init_data.extend_from_slice(puk.as_bytes());
    init_data.extend_from_slice(pairing_secret);

    let enc = cbc_encrypt(&eph.secret, &iv, &pad(&init_data));
    eph.secret.zeroize();
    init_data.zeroize();

    // wire: [len]‖pub(65)‖iv(16)‖ciphertext ; LC = 1+65+16 + |ct| = 82 + |ct|
    let lc = 82 + enc.len();
    if lc > 255 {
        return Err(KeycardError::SecureChannel("INIT payload too large".into()));
    }
    let mut apdu = vec![CLA, INS_INIT, 0x00, 0x00, lc as u8, eph.public.len() as u8];
    apdu.extend_from_slice(&eph.public);
    apdu.extend_from_slice(&iv);
    apdu.extend_from_slice(&enc);

    let resp = t.transmit(&apdu)?;
    let sw = parse_sw(&resp);
    if sw != SW_OK {
        return Err(KeycardError::Apdu { sw });
    }
    Ok(())
}

/// PAIR with the card (plaintext challenge-response) → client-side [`Pairing`].
pub fn pair(t: &mut Transport, pairing_secret: &[u8; 32]) -> Result<Pairing> {
    let client_challenge: [u8; 32] = rand::random();

    // Step 1: send client challenge; card returns cryptogram(32) ‖ challenge(32).
    let mut a1 = vec![CLA, INS_PAIR, PAIR_P1_FIRST, PAIR_P2_ANY, 32];
    a1.extend_from_slice(&client_challenge);
    let r1 = t.transmit(&a1)?;
    let sw1 = parse_sw(&r1);
    if sw1 != SW_OK {
        return Err(KeycardError::Apdu { sw: sw1 });
    }
    let d1 = response_data(&r1);
    if d1.len() < 64 {
        return Err(KeycardError::PairingFailed(
            "step-1 response too short".into(),
        ));
    }
    let card_cryptogram = &d1[..32];
    let card_challenge = &d1[32..64];

    // Verify card cryptogram = SHA256(secret ‖ client_challenge).
    let mut h = Sha256::new();
    h.update(pairing_secret);
    h.update(client_challenge);
    if h.finalize().as_slice() != card_cryptogram {
        return Err(KeycardError::PairingFailed(
            "card cryptogram mismatch (wrong pairing secret?)".into(),
        ));
    }

    // Step 2: reply with SHA256(secret ‖ card_challenge); card returns index ‖ salt.
    let mut h = Sha256::new();
    h.update(pairing_secret);
    h.update(card_challenge);
    let client_cryptogram = h.finalize();
    let mut a2 = vec![CLA, INS_PAIR, PAIR_P1_LAST, 0x00, 32];
    a2.extend_from_slice(&client_cryptogram);
    let r2 = t.transmit(&a2)?;
    let sw2 = parse_sw(&r2);
    if sw2 != SW_OK {
        return Err(KeycardError::Apdu { sw: sw2 });
    }
    let d2 = response_data(&r2);
    if d2.len() < 33 {
        return Err(KeycardError::PairingFailed(
            "step-2 response too short".into(),
        ));
    }
    let index = d2[0];
    let salt = &d2[1..33];

    // pairing_key = SHA256(secret ‖ salt).
    let mut h = Sha256::new();
    h.update(pairing_secret);
    h.update(salt);
    let mut key = [0u8; 32];
    key.copy_from_slice(h.finalize().as_slice());
    Ok(Pairing { index, key })
}

/// An open V1 secure-channel session.
pub struct SecureChannel<'a> {
    t: &'a mut Transport,
    enc_key: [u8; 32],
    mac_key: [u8; 32],
    iv: [u8; 16],
}

impl Drop for SecureChannel<'_> {
    fn drop(&mut self) {
        self.enc_key.zeroize();
        self.mac_key.zeroize();
    }
}

impl<'a> SecureChannel<'a> {
    /// OPEN SECURE CHANNEL + MUTUALLY AUTHENTICATE (the channel self-test).
    pub fn open(t: &'a mut Transport, card_static_pub: &[u8], pairing: &Pairing) -> Result<Self> {
        let eph = ephemeral_ecdh(card_static_pub)?;

        let mut apdu = vec![
            CLA,
            INS_OPEN_SECURE_CHANNEL,
            pairing.index,
            0x00,
            eph.public.len() as u8,
        ];
        apdu.extend_from_slice(&eph.public);
        let resp = t.transmit(&apdu)?;
        let sw = parse_sw(&resp);
        if sw != SW_OK {
            return Err(KeycardError::Apdu { sw });
        }
        let data = response_data(&resp);
        if data.len() < 32 + BLOCK {
            return Err(KeycardError::SecureChannel(format!(
                "OPEN response too short: {} bytes",
                data.len()
            )));
        }
        let salt = &data[..32];
        let seed_iv = &data[32..48];

        // key_data = SHA-512(ecdh ‖ pairing_key ‖ salt) → enc_key ‖ mac_key
        let mut hasher = Sha512::new();
        hasher.update(eph.secret);
        hasher.update(pairing.key);
        hasher.update(salt);
        let key_data = hasher.finalize();
        let mut enc_key = [0u8; 32];
        let mut mac_key = [0u8; 32];
        enc_key.copy_from_slice(&key_data[..32]);
        mac_key.copy_from_slice(&key_data[32..64]);

        let mut iv = [0u8; 16];
        iv.copy_from_slice(seed_iv);

        let mut sc = SecureChannel {
            t,
            enc_key,
            mac_key,
            iv,
        };

        let challenge: [u8; 32] = rand::random();
        let received =
            sc.send_encrypted(&[CLA, INS_MUTUALLY_AUTHENTICATE, 0x00, 0x00], &challenge)?;
        if received.len() != 32 {
            return Err(KeycardError::SecureChannel(format!(
                "mutual auth returned {} bytes (expected 32)",
                received.len()
            )));
        }
        Ok(sc)
    }

    /// Send a protected command; returns the decrypted response (inner SW checked).
    pub fn send_encrypted(&mut self, header: &[u8; 4], data: &[u8]) -> Result<Vec<u8>> {
        let encrypted = cbc_encrypt(&self.enc_key, &self.iv, &pad(data));
        let lc = encrypted.len() + BLOCK;
        if lc > 255 {
            return Err(KeycardError::SecureChannel(
                "command payload too large".into(),
            ));
        }

        // meta = [cla,ins,p1,p2, lc, 0…16] ; MAC over meta ‖ ciphertext, becomes IV.
        let mut meta = [0u8; 16];
        meta[..4].copy_from_slice(header);
        meta[4] = lc as u8;
        let mut mac_input = Vec::with_capacity(16 + encrypted.len());
        mac_input.extend_from_slice(&meta);
        mac_input.extend_from_slice(&encrypted);
        let cmd_mac = cbc_mac(&self.mac_key, &mac_input);
        self.iv = cmd_mac;

        // APDU = header ‖ LC ‖ MAC(16) ‖ ciphertext
        let mut apdu = header.to_vec();
        apdu.push(lc as u8);
        apdu.extend_from_slice(&cmd_mac);
        apdu.extend_from_slice(&encrypted);

        let rep = self.t.transmit(&apdu)?;
        let outer_sw = parse_sw(&rep);
        if outer_sw != SW_OK {
            return Err(KeycardError::Apdu { sw: outer_sw });
        }
        let body = response_data(&rep);
        if body.len() < BLOCK || (body.len() - BLOCK) % BLOCK != 0 {
            return Err(KeycardError::SecureChannel(format!(
                "malformed secure response ({} bytes)",
                body.len()
            )));
        }
        let resp_mac = &body[..BLOCK];
        let resp_enc = &body[BLOCK..];

        // Decrypt under the command MAC (current IV).
        let plain = unpad(&cbc_decrypt(&self.enc_key, &self.iv, resp_enc))?;

        // Verify response MAC: meta = [resp_len, 0…], MAC over meta ‖ ciphertext.
        let mut meta = [0u8; 16];
        meta[0] = body.len() as u8;
        let mut mac_input = Vec::with_capacity(16 + resp_enc.len());
        mac_input.extend_from_slice(&meta);
        mac_input.extend_from_slice(resp_enc);
        let calc = cbc_mac(&self.mac_key, &mac_input);
        if calc != resp_mac {
            return Err(KeycardError::SecureChannel("invalid response MAC".into()));
        }
        self.iv = calc; // chain for the next command

        if plain.len() < 2 {
            return Err(KeycardError::SecureChannel(
                "response missing status word".into(),
            ));
        }
        let n = plain.len();
        let inner_sw = ((plain[n - 2] as u16) << 8) | plain[n - 1] as u16;
        if inner_sw != SW_OK {
            return Err(KeycardError::Apdu { sw: inner_sw });
        }
        Ok(plain[..n - 2].to_vec())
    }

    /// VERIFY PIN over the channel — unlocks protected key operations.
    /// Maps a wrong-PIN status to [`KeycardError::WrongPin`].
    pub fn verify_pin(&mut self, pin: &str) -> Result<()> {
        match self.send_encrypted(&[CLA, INS_VERIFY_PIN, 0x00, 0x00], pin.as_bytes()) {
            Ok(_) => Ok(()),
            // 0x63CX: PIN wrong, X attempts remaining.
            Err(KeycardError::Apdu { sw }) if (sw & 0xFFF0) == 0x63C0 => {
                Err(KeycardError::WrongPin {
                    attempts_remaining: (sw & 0x000F) as u8,
                })
            }
            Err(e) => Err(e),
        }
    }

    /// GENERATE KEY — create a fresh secp256k1 master key on-card. Returns the
    /// key UID (SHA-256 of the public key).
    pub fn generate_key(&mut self) -> Result<Vec<u8>> {
        self.send_encrypted(&[CLA, INS_GENERATE_KEY, 0x00, 0x00], &[])
    }

    /// SIGN a 32-byte hash with the current key (ECDSA over secp256k1).
    pub fn sign_ecdsa(&mut self, hash: &[u8; 32]) -> Result<CardSignature> {
        let resp =
            self.send_encrypted(&[CLA, INS_SIGN, SIGN_P1_CURRENT_KEY, SIGN_P2_ECDSA], hash)?;
        parse_signature_template(&resp)
    }

    /// SIGN a 32-byte hash with the current key using EdDSA (Ed25519), if the
    /// applet supports it. Returns the raw response for the caller to interpret.
    pub fn sign_eddsa(&mut self, hash: &[u8; 32]) -> Result<Vec<u8>> {
        self.send_encrypted(
            &[CLA, INS_SIGN, SIGN_P1_CURRENT_KEY, SIGN_P2_EDDSA_ED25519],
            hash,
        )
    }
}

/// A signature parsed from a Keycard SIGN response template.
#[derive(Debug, Clone)]
pub struct CardSignature {
    /// Uncompressed secp256k1 public key of the signing key (65 bytes).
    pub public_key: Vec<u8>,
    /// The ECDSA signature as a DER-encoded SEQUENCE (`0x30 …`).
    pub der: Vec<u8>,
}

/// Read a BER-TLV length; returns `(value_len, header_len_after_tag)`.
fn ber_len(data: &[u8]) -> Result<(usize, usize)> {
    let first = *data
        .first()
        .ok_or_else(|| KeycardError::SecureChannel("truncated TLV length".into()))?;
    if first & 0x80 == 0 {
        return Ok((first as usize, 1));
    }
    let n = (first & 0x7f) as usize;
    if n == 0 || n > 3 || data.len() < 1 + n {
        return Err(KeycardError::SecureChannel("bad TLV length".into()));
    }
    let mut len = 0usize;
    for &b in &data[1..1 + n] {
        len = (len << 8) | b as usize;
    }
    Ok((len, 1 + n))
}

/// Parse a Keycard ECDSA SIGN response: `A0 { 80 pubkey, 30 <DER ecdsa> }`.
pub fn parse_signature_template(resp: &[u8]) -> Result<CardSignature> {
    if resp.first() != Some(&TLV_SIGNATURE_TEMPLATE) {
        return Err(KeycardError::SecureChannel(format!(
            "expected signature template 0xA0, got {:#04x?}",
            resp.first()
        )));
    }
    let (tlen, thdr) = ber_len(&resp[1..])?;
    let inner = resp
        .get(1 + thdr..1 + thdr + tlen)
        .ok_or_else(|| KeycardError::SecureChannel("signature template truncated".into()))?;

    if inner.first() != Some(&TLV_PUB_KEY) {
        return Err(KeycardError::SecureChannel(
            "missing public key in signature".into(),
        ));
    }
    let (plen, phdr) = ber_len(&inner[1..])?;
    let public_key = inner
        .get(1 + phdr..1 + phdr + plen)
        .ok_or_else(|| KeycardError::SecureChannel("public key truncated".into()))?
        .to_vec();

    let rest = &inner[1 + phdr + plen..];
    if rest.first() != Some(&TLV_ECDSA_SEQUENCE) {
        return Err(KeycardError::SecureChannel(
            "missing ECDSA DER sequence".into(),
        ));
    }
    Ok(CardSignature {
        public_key,
        der: rest.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padding_roundtrip() {
        for len in [0usize, 1, 15, 16, 31, 32] {
            let d: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let p = pad(&d);
            assert_eq!(p.len() % 16, 0);
            assert_eq!(unpad(&p).unwrap(), d);
        }
    }

    #[test]
    fn cbc_roundtrip() {
        let key = [9u8; 32];
        let iv = [4u8; 16];
        let pt = pad(b"status keycard v1");
        assert_eq!(cbc_decrypt(&key, &iv, &cbc_encrypt(&key, &iv, &pt)), pt);
    }

    // PBKDF2-HMAC-SHA256 known-answer (P="password", S="salt", c=2).
    #[test]
    fn pbkdf2_kat() {
        let dk = pbkdf2_sha256_32(b"password", b"salt", 2);
        assert_eq!(
            hex::encode(dk),
            "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"
        );
    }
}
