//! **Secure Channel V2** (the forked applet / production cards).
//!
//! ECDHE on secp256k1 → HKDF-SHA256 → AES-128-CCM, with the card authenticated by
//! an ECDSA signature over the key-exchange transcript (verified against the
//! identity key carried in the SELECT certificate). No pairing.
//! Authoritative applet source: `SecureChannelV2.java` in the kenter-keycard applet.
//!
//! Flow:
//! - OPEN: `80 10 00 00 <Lc> salt(32) ‖ client_eph_pub(65)` → `card_eph_pub(65) ‖ DER-ECDSA`.
//! - `shared = ECDH(client_eph, card_eph).x`; `OKM = HKDF-SHA256(salt, shared, "sc_v2_ccm")`;
//!   `key_h2c = OKM[0..16]`, `key_c2h = OKM[16..32]`.
//! - transcript = `SHA-256("sc_v2_ccm" ‖ salt ‖ client_pub ‖ card_pub)`, ECDSA-signed by the card
//!   identity key (from the SELECT cert, tag `0x8A`: compressed id pubkey(33) ‖ CA sig).
//! - Secured APDU `80 18 00 00 <Lc> <CCM(inner_apdu)>`; nonce = 13-byte counter from 0, tag 8 B,
//!   same nonce for a command and its response, +1 after each response.

use aes::Aes128;
use ccm::Ccm;
use ccm::aead::generic_array::GenericArray;
use ccm::aead::{Aead, KeyInit, Payload};
use ccm::consts::{U8, U13};
use hkdf::Hkdf;
use k256::ecdh::diffie_hellman;
use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::{Signature as EcdsaSig, VerifyingKey};
use k256::elliptic_curve::Generate;
use k256::elliptic_curve::sec1::ToSec1Point;
use k256::{PublicKey, SecretKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::apdu::{SW_OK, parse_sw, response_data};
use crate::error::{KeycardError, Result};
use crate::transport::CardTransport;

type AesCcm = Ccm<Aes128, U8, U13>;

const CLA: u8 = 0x80;
const INS_OPEN_SECURE_CHANNEL: u8 = 0x10;
const INS_SECURED_APDU: u8 = 0x18;
const PROTOCOL_LABEL: &[u8] = b"sc_v2_ccm";
const CERT_TAG: u8 = 0x8A;
const PUBKEY_LEN: usize = 65;
const ID_PUBKEY_LEN: usize = 33; // compressed secp256k1
/// Recoverable ECDSA: `r(32) || s(32) || v(1)`.
const CERT_SIG_LEN: usize = 65;
const CERT_LEN: usize = ID_PUBKEY_LEN + CERT_SIG_LEN;

/// The CA public key a card certificate is checked against, compressed
/// secp256k1 (33 bytes).
///
/// Pinned by the caller rather than read from the card, which is the
/// whole point: a certificate that carried its own CA would authenticate
/// nothing.
pub type CaPublicKey = [u8; ID_PUBKEY_LEN];

/// The CA this repository's own tooling personalises cards with.
///
/// **Development only, and the private key is in the repository**
/// (the kenter-keycard applet's `SimServer.java`). It is here so the simulator
/// and the dev cards can be verified by the same code path that will
/// verify production ones -- not because it is trustworthy. Anyone can
/// sign a certificate with it.
///
/// Production cards are stock JavaCards personalised with a CA whose
/// private key never leaves an offline machine, and the build that
/// ships to users must pin that key here instead. While the dev key is
/// pinned, the certificate check proves a card came from this workbench
/// and nothing more.
pub const DEV_CA_PUBLIC_KEY: CaPublicKey = [
    0x02, 0x58, 0x77, 0x22, 0x0a, 0xaa, 0xe6, 0xe5, 0x4a, 0x6f, 0x97, 0x46, 0x02, 0xd5, 0x99, 0x5c,
    0x0f, 0xe2, 0x4a, 0x3e, 0xa7, 0xdd, 0xab, 0xd8, 0x64, 0x4b, 0xec, 0x79, 0x5b, 0x9d, 0xa0, 0x07,
    0x43,
];

/// Extract the card's identity public key (compressed, 33 bytes) from the SELECT
/// response certificate (tag `0x8A` = id pubkey(33) ‖ CA signature).
///
/// **Self-asserted.** This reads the key the card claims and checks no
/// signature over it. Use [`verify_identity_certificate`] wherever the
/// answer has to mean something; this remains for the probes and for
/// display, where it does not.
pub fn card_identity_pubkey(select_resp: &[u8]) -> Result<Vec<u8>> {
    let data = response_data(select_resp);
    // Enter the 0xA4 application-info template if present. NOTE: the applet's
    // SELECT response currently declares an A4 length one byte short of its actual
    // content (the cert TLV runs to the true end), so we walk the *remaining*
    // bytes after the template header rather than trusting the declared length.
    let body = if data.first() == Some(&0xA4) {
        let (_len, hdr) = ber_len(&data[1..])?;
        data.get(1 + hdr..)
            .ok_or_else(|| KeycardError::SecureChannel("SELECT template truncated".into()))?
    } else {
        data
    };
    let mut i = 0;
    while i + 2 <= body.len() {
        let tag = body[i];
        let (len, hdr) = ber_len(&body[i + 1..])?;
        let start = i + 1 + hdr;
        let val = body
            .get(start..start + len)
            .ok_or_else(|| KeycardError::SecureChannel("SELECT TLV truncated".into()))?;
        if tag == CERT_TAG {
            if val.len() < ID_PUBKEY_LEN {
                return Err(KeycardError::SecureChannel("certificate too short".into()));
            }
            return Ok(val[..ID_PUBKEY_LEN].to_vec());
        }
        i = start + len;
    }
    Err(KeycardError::SecureChannel(
        "no identity certificate (tag 0x8A) in SELECT response".into(),
    ))
}

/// The whole `0x8A` certificate: identity key ‖ CA signature.
pub fn card_identity_certificate(select_resp: &[u8]) -> Result<Vec<u8>> {
    let data = response_data(select_resp);
    let body = if data.first() == Some(&0xA4) {
        let (_len, hdr) = ber_len(&data[1..])?;
        data.get(1 + hdr..)
            .ok_or_else(|| KeycardError::SecureChannel("SELECT template truncated".into()))?
    } else {
        data
    };
    let mut i = 0;
    while i + 2 <= body.len() {
        let tag = body[i];
        let (len, hdr) = ber_len(&body[i + 1..])?;
        let start = i + 1 + hdr;
        let val = body
            .get(start..start + len)
            .ok_or_else(|| KeycardError::SecureChannel("SELECT TLV truncated".into()))?;
        if tag == CERT_TAG {
            return Ok(val.to_vec());
        }
        i = start + len;
    }
    Err(KeycardError::SecureChannel(
        "no identity certificate (tag 0x8A) in SELECT response".into(),
    ))
}

/// Verify a card's identity certificate against a pinned CA, returning
/// the identity key only if the CA signed it.
///
/// Without this the identity key is whatever the device in the reader
/// says it is. A substitute card, a malicious reader or an emulator
/// presents its own key, completes the handshake, and receives the
/// VERIFY PIN that follows.
///
/// The certificate is `id_pubkey(33) ‖ r(32) ‖ s(32) ‖ v(1)` and the CA
/// signs `SHA-256(id_pubkey)`. `v` is a recovery id, which this does not
/// need -- the CA key is pinned, so the signature is verified against it
/// directly rather than recovered and then trusted.
///
/// `s` is normalised first. JavaCard's ECDSA does not produce low-S and
/// RustCrypto refuses high-S on sight, which is the same coin-flip
/// failure the channel transcript hit. Malleability buys an attacker
/// nothing here: `(r, n-s)` is a signature by the same CA over the same
/// certificate, and the certificate is not an identifier.
/// [`verify_identity_certificate`] against a *set* of pinned CA keys: the
/// certificate is accepted if any one of them signed it.
///
/// A client pins more than one key so that a CA can be retired without
/// stranding the cards it certified: an active key, and a sealed spare
/// to move to if the active one is lost or leaked. An empty set accepts
/// nothing.
pub fn verify_identity_certificate_any(cert: &[u8], cas: &[CaPublicKey]) -> Result<Vec<u8>> {
    let mut last = KeycardError::AuthFailed;
    for ca in cas {
        match verify_identity_certificate(cert, ca) {
            Ok(id) => return Ok(id),
            Err(e) => last = e,
        }
    }
    Err(last)
}

pub fn verify_identity_certificate(cert: &[u8], ca: &CaPublicKey) -> Result<Vec<u8>> {
    use k256::ecdsa::signature::hazmat::PrehashVerifier;

    if cert.len() < CERT_LEN {
        return Err(KeycardError::SecureChannel(format!(
            "identity certificate is {} bytes, expected at least {CERT_LEN}",
            cert.len()
        )));
    }
    let (id_pubkey, sig_bytes) = cert.split_at(ID_PUBKEY_LEN);

    let ca_key = VerifyingKey::from_sec1_bytes(ca)
        .map_err(|e| KeycardError::SecureChannel(format!("pinned CA key: {e}")))?;
    let sig = EcdsaSig::from_slice(&sig_bytes[..64])
        .map_err(|e| KeycardError::SecureChannel(format!("certificate signature: {e}")))?;
    let sig = sig.normalize_s();

    let digest: [u8; 32] = Sha256::digest(id_pubkey).into();
    ca_key
        .verify_prehash(&digest, &sig)
        .map_err(|_| KeycardError::AuthFailed)?;

    Ok(id_pubkey.to_vec())
}

/// An open V2 secure-channel session bound to a transport.
pub struct SecureChannelV2<'a, T: CardTransport> {
    t: &'a mut T,
    key_h2c: [u8; 16],
    key_c2h: [u8; 16],
    nonce: [u8; 13],
}

impl<T: CardTransport> Drop for SecureChannelV2<'_, T> {
    fn drop(&mut self) {
        self.key_h2c.zeroize();
        self.key_c2h.zeroize();
    }
}

impl<'a, T: CardTransport> SecureChannelV2<'a, T> {
    /// Open a secure channel. `id_pubkey` is the card identity pubkey from
    /// [`card_identity_pubkey`]; the card's transcript signature is verified
    /// against it (this authenticates the card).
    pub fn open(t: &'a mut T, id_pubkey: &[u8]) -> Result<Self> {
        // k256 0.14: encoding is `ToSec1Point`, and key generation is
        // `Generate`. `generate()` takes the system RNG itself, so the ephemeral
        // key does not depend on this crate and `rand` agreeing on a version of
        // `CryptoRng`.
        let eph = SecretKey::generate();
        let client_pub = eph.public_key().to_sec1_point(false).as_bytes().to_vec(); // 65
        let salt: [u8; 32] = rand::random();

        // OPEN SECURE CHANNEL
        let mut apdu = vec![
            CLA,
            INS_OPEN_SECURE_CHANNEL,
            0x00,
            0x00,
            (32 + PUBKEY_LEN) as u8,
        ];
        apdu.extend_from_slice(&salt);
        apdu.extend_from_slice(&client_pub);
        let resp = t.transmit(&apdu)?;
        let sw = parse_sw(&resp);
        if sw != SW_OK {
            return Err(KeycardError::Apdu { sw });
        }
        let body = response_data(&resp);
        if body.len() < PUBKEY_LEN + 8 {
            return Err(KeycardError::SecureChannel(format!(
                "OPEN response too short: {} bytes",
                body.len()
            )));
        }
        let card_pub = &body[..PUBKEY_LEN];
        let sig_der = &body[PUBKEY_LEN..];

        // ECDH → shared X
        let card_public = PublicKey::from_sec1_bytes(card_pub)
            .map_err(|e| KeycardError::SecureChannel(format!("card eph pubkey: {e}")))?;
        let shared = diffie_hellman(&eph.to_nonzero_scalar(), card_public.as_affine());
        let shared_x = shared.raw_secret_bytes();

        // HKDF-SHA256 → session keys
        let hk = Hkdf::<Sha256>::new(Some(&salt), shared_x);
        let mut okm = [0u8; 32];
        hk.expand(PROTOCOL_LABEL, &mut okm)
            .map_err(|_| KeycardError::SecureChannel("hkdf expand".into()))?;
        let mut key_h2c = [0u8; 16];
        let mut key_c2h = [0u8; 16];
        key_h2c.copy_from_slice(&okm[..16]);
        key_c2h.copy_from_slice(&okm[16..]);
        okm.zeroize();

        // Authenticate the card: verify ECDSA(transcript) against the identity key.
        let mut h = Sha256::new();
        h.update(PROTOCOL_LABEL);
        h.update(salt);
        h.update(&client_pub);
        h.update(card_pub);
        let transcript = h.finalize();
        let vk = VerifyingKey::from_sec1_bytes(id_pubkey)
            .map_err(|e| KeycardError::SecureChannel(format!("identity pubkey: {e}")))?;
        let sig = EcdsaSig::from_der(sig_der)
            .map_err(|e| KeycardError::SecureChannel(format!("transcript sig DER: {e}")))?;
        // The applet signs with JavaCard's ECDSA, which does not normalise `s`,
        // so about half of all channel opens come back with `s > n/2`.
        // RustCrypto rejects those on sight: secp256k1 verification enforces
        // low-S, a Bitcoin rule against malleability. Here the signature
        // authenticates one ephemeral channel — used once, never stored, never
        // an identifier — so malleability is not a property anything depends
        // on, and `(r, n-s)` is as valid a signature by the same key over the
        // same transcript. Normalising before verifying accepts both.
        //
        // Without this the channel opens on a coin flip, which is exactly how
        // it presented: the same call failing on one run and not the next.
        // 0.14 returns the normalised signature directly; 0.13
        // returned `None` when it was already low-S.
        let sig = sig.normalize_s();
        vk.verify_prehash(&transcript, &sig)
            .map_err(|_| KeycardError::AuthFailed)?;

        Ok(Self {
            t,
            key_h2c,
            key_c2h,
            nonce: [0u8; 13],
        })
    }

    /// Send a command over the channel; returns the decrypted response data
    /// (inner SW checked). `data` is the command payload.
    pub fn send(&mut self, cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8]) -> Result<Vec<u8>> {
        // Inner APDU (plaintext): CLA INS P1 P2 LC data
        let mut inner = vec![cla, ins, p1, p2, data.len() as u8];
        inner.extend_from_slice(data);

        let nonce = GenericArray::from_slice(&self.nonce);
        let cipher_h2c = AesCcm::new(GenericArray::from_slice(&self.key_h2c));
        let ct = cipher_h2c
            .encrypt(
                nonce,
                Payload {
                    msg: &inner,
                    aad: &[],
                },
            )
            .map_err(|_| KeycardError::SecureChannel("CCM encrypt".into()))?;

        let mut outer = vec![CLA, INS_SECURED_APDU, 0x00, 0x00, ct.len() as u8];
        outer.extend_from_slice(&ct);
        let resp = self.t.transmit(&outer)?;
        let sw = parse_sw(&resp);
        if sw != SW_OK {
            return Err(KeycardError::Apdu { sw });
        }
        let body = response_data(&resp);

        let cipher_c2h = AesCcm::new(GenericArray::from_slice(&self.key_c2h));
        let mut plain = cipher_c2h
            .decrypt(
                nonce,
                Payload {
                    msg: body,
                    aad: &[],
                },
            )
            .map_err(|_| KeycardError::SecureChannel("CCM decrypt / bad tag".into()))?;

        self.increment_nonce();

        if plain.len() < 2 {
            plain.zeroize();
            return Err(KeycardError::SecureChannel(
                "response missing status word".into(),
            ));
        }
        let n = plain.len();
        let inner_sw = ((plain[n - 2] as u16) << 8) | plain[n - 1] as u16;
        if inner_sw != SW_OK {
            plain.zeroize();
            return Err(KeycardError::Apdu { sw: inner_sw });
        }
        plain.truncate(n - 2);
        Ok(plain)
    }

    fn increment_nonce(&mut self) {
        for byte in self.nonce.iter_mut().rev() {
            *byte = byte.wrapping_add(1);
            if *byte != 0 {
                break;
            }
        }
    }
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

#[cfg(test)]
mod identity_tests {
    use super::*;

    /// A real SELECT response from a development card, captured with
    /// `cargo run -p stellar-keycard --example probe_cert`.
    ///
    /// A fixture rather than a constructed one on purpose: the applet
    /// declares the `0xA4` template one byte short of its own content,
    /// so a certificate assembled to spec would not exercise the parser
    /// the way a card does.
    const REAL_SELECT: &str = "a48190020204008c01158e20e9897e20ffeb47ecd3993aed1d01043d95ea9ef\
f91fb4b3ed652c3ab7e408c2b8d011f8a62039a2ca11e21c53e46c73ed1f7eb1e74add3b5a8fd960f0247783f8aa511\
f447e9fbc52d7f51a6c9beff7ba426e3c710d1f21d9a80b8cdb4b43b89d9c929a6fad8b1048ae3c3ba3deaf310ed7af\
2681df526a63b7b711d452946122c69b2684b79019000";

    const REAL_ID: &str = "039a2ca11e21c53e46c73ed1f7eb1e74add3b5a8fd960f0247783f8aa511f447e9";

    fn select() -> Vec<u8> {
        hex::decode(REAL_SELECT).unwrap()
    }

    /// **Custody C1 regression.** A card the pinned CA signed is
    /// accepted, and the key returned is the card's own.
    #[test]
    fn a_ca_signed_certificate_verifies() {
        let cert = card_identity_certificate(&select()).unwrap();
        assert_eq!(cert.len(), CERT_LEN, "33-byte key plus a 65-byte signature");
        let id = verify_identity_certificate(&cert, &DEV_CA_PUBLIC_KEY).unwrap();
        assert_eq!(hex::encode(&id), REAL_ID);
    }

    /// The signature is high-S, as JavaCard produces. Verification has
    /// to normalise or it fails on roughly half of all cards — the same
    /// coin flip the channel transcript hit.
    #[test]
    fn the_real_signature_is_high_s() {
        let cert = card_identity_certificate(&select()).unwrap();
        let s_first = cert[ID_PUBKEY_LEN + 32];
        assert!(s_first > 0x7F, "fixture should exercise the high-S path");
    }

    /// **The check that makes the others mean something.** A different
    /// CA does not verify this card.
    #[test]
    fn another_ca_does_not_verify_it() {
        let cert = card_identity_certificate(&select()).unwrap();
        let mut wrong = DEV_CA_PUBLIC_KEY;
        wrong[1] ^= 0xFF;
        assert!(verify_identity_certificate(&cert, &wrong).is_err());
    }

    /// Nor does a card that signed its own certificate — which is what
    /// an impostor would present, and what the old code accepted
    /// without looking.
    #[test]
    fn a_self_asserted_certificate_is_refused() {
        let cert = card_identity_certificate(&select()).unwrap();
        let mut own = [0u8; ID_PUBKEY_LEN];
        own.copy_from_slice(&cert[..ID_PUBKEY_LEN]);
        assert!(
            verify_identity_certificate(&cert, &own).is_err(),
            "the card's own key must not pass as the CA"
        );
    }

    /// A tampered identity key invalidates the signature over it.
    #[test]
    fn a_swapped_identity_key_is_refused() {
        let mut cert = card_identity_certificate(&select()).unwrap();
        cert[1] ^= 0xFF;
        assert!(verify_identity_certificate(&cert, &DEV_CA_PUBLIC_KEY).is_err());
    }

    /// A set of pinned keys accepts a card any one of them signed, in any
    /// position, and an empty set accepts none.
    #[test]
    fn any_pinned_ca_in_a_set_verifies() {
        let cert = card_identity_certificate(&select()).unwrap();
        let mut other = DEV_CA_PUBLIC_KEY;
        other[1] ^= 0xFF;
        let id = verify_identity_certificate_any(&cert, &[other, DEV_CA_PUBLIC_KEY]).unwrap();
        assert_eq!(hex::encode(&id), REAL_ID);
        assert!(verify_identity_certificate_any(&cert, &[other]).is_err());
        assert!(verify_identity_certificate_any(&cert, &[]).is_err());
    }

    /// And a truncated certificate is an error, not a panic.
    #[test]
    fn a_short_certificate_is_refused() {
        let cert = card_identity_certificate(&select()).unwrap();
        for n in [0usize, 33, 50, CERT_LEN - 1] {
            assert!(verify_identity_certificate(&cert[..n], &DEV_CA_PUBLIC_KEY).is_err());
        }
    }
}
