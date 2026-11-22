use std::io::{Cursor, Read, Write};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use crate::error::{CryptoError, Result};
use crate::keypair::StellarKeypair;
use crate::shard::ChainLink;
use crate::token::*;

/// SYMTOKEN magic bytes (8 bytes).
pub const SYMTOKEN_MAGIC: &[u8; 8] = b"SYMTOKEN";
/// Current container format version.
///
/// v2 added authenticated ChainLinks; v3 adds the claim secret, without
/// which a note cannot be redeemed by chain. **v6 adds the mint
/// binding** -- the issuing contract and the asset it escrows -- so a
/// note says which deployment to ask and what it pays out in. Before
/// it, that lived only in the receiving wallet's own record, which is
/// no help to a payee handed a bare file.
///
/// An older note is not readable here and not redeemable by the
/// current mint -- reprint it.
pub const SYMTOKEN_VERSION: u16 = 6;

/// Check if data starts with SYMTOKEN magic.
pub fn is_symtoken(data: &[u8]) -> bool {
    data.len() >= 8 && &data[..8] == SYMTOKEN_MAGIC
}

/// Serialize a BearerToken to the binary container format.
///
/// The token is signed by the requestor's keypair. The signature covers
/// all bytes from magic through the last caveat byte.
pub fn serialize_bearer_token(
    token: &BearerToken,
    signer: &StellarKeypair,
) -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(2048);

    // -- Preamble --
    buf.write_all(SYMTOKEN_MAGIC)?;
    buf.write_all(&SYMTOKEN_VERSION.to_le_bytes())?;
    buf.write_all(&[token.header.token_type as u8])?;
    buf.write_all(&[0u8])?; // flags (reserved)

    // -- Header Section --
    buf.write_all(&token.header.event_id)?;
    buf.write_all(&token.header.print_timestamp.to_le_bytes())?;
    match token.header.denomination {
        Some(d) => {
            buf.write_all(&[0x01])?;
            buf.write_all(&d.to_le_bytes())?;
        }
        None => {
            buf.write_all(&[0x00])?;
        }
    }

    // -- Slot --
    // Which print produced this note. The mint keys its records by slot
    // (not by the public ephemeral key, which anyone could name first), so
    // this is what a redemption names, and it is
    // inside the signed range like everything else that identifies the
    // note.
    buf.write_all(&token.slot_id.to_le_bytes())?;

    // -- Mint Binding --
    // Inside the signed range, like everything else that says what this
    // note is. A binding an attacker could rewrite would point the payee
    // at a contract of the attacker's choosing.
    match &token.mint_binding {
        Some(b) => {
            buf.write_all(&[0x01])?;
            buf.write_all(&b.mint)?;
            buf.write_all(&b.pay_token)?;
        }
        None => {
            buf.write_all(&[0x00])?;
        }
    }

    // -- Ephemeral Key --
    buf.write_all(&token.ephemeral_public_key)?;

    // -- Claim Secret --
    // Inside the signed range: a note whose claim key was swapped is a
    // different note, and the requestor signature says so.
    buf.write_all(&token.claim_secret)?;

    // -- Chain Section --
    buf.write_all(&token.chain.total_pairs.to_le_bytes())?;
    buf.write_all(&token.chain.required_pairs.to_le_bytes())?;
    for link in &token.chain.links {
        write_chain_link(&mut buf, link)?;
    }

    // -- Initiation Proof Section --
    buf.write_all(&token.initiation_proof.initiator_public_key)?;
    let vrf_len = token.initiation_proof.vrf_proof.len() as u16;
    buf.write_all(&vrf_len.to_le_bytes())?;
    buf.write_all(&token.initiation_proof.vrf_proof)?;

    // -- Caveats Section --
    let num_caveats = token.caveats.len() as u16;
    buf.write_all(&num_caveats.to_le_bytes())?;
    for caveat in &token.caveats {
        write_caveat(&mut buf, caveat)?;
    }

    // -- Signature --
    let signature = signer.sign(&buf);
    buf.write_all(&signature.to_bytes())?;

    Ok(buf)
}

/// Deserialize a BearerToken from the binary container format.
pub fn deserialize_bearer_token(data: &[u8]) -> Result<BearerToken> {
    if data.len() < 8 + 2 + 1 + 1 + 32 + 8 + 1 + 4 + 1 + 32 + 32 + 64 {
        return Err(CryptoError::InvalidToken("data too short".into()));
    }

    // Signature is the last 64 bytes
    let sig_offset = data.len() - 64;
    let payload = &data[..sig_offset];
    let sig_bytes = &data[sig_offset..];
    let signature: [u8; 64] = sig_bytes.try_into().map_err(|_| {
        CryptoError::InvalidToken("invalid signature length".into())
    })?;

    let mut cursor = Cursor::new(payload);

    // -- Preamble --
    let mut magic = [0u8; 8];
    cursor.read_exact(&mut magic)?;
    if &magic != SYMTOKEN_MAGIC {
        return Err(CryptoError::InvalidToken("invalid magic bytes".into()));
    }

    let version = read_u16_le(&mut cursor)?;
    if version != SYMTOKEN_VERSION {
        return Err(CryptoError::InvalidToken(format!(
            "unsupported version: {version}"
        )));
    }

    let type_byte = read_u8(&mut cursor)?;
    let token_type = TokenType::from_u8(type_byte)?;
    if token_type != TokenType::Bearer {
        return Err(CryptoError::InvalidToken(format!(
            "expected Bearer, got {type_byte:#x}"
        )));
    }

    let _flags = read_u8(&mut cursor)?;

    // -- Header --
    let mut event_id = [0u8; 32];
    cursor.read_exact(&mut event_id)?;

    let print_timestamp = read_i64_le(&mut cursor)?;

    let has_denomination = read_u8(&mut cursor)?;
    let denomination = if has_denomination == 0x01 {
        Some(read_u64_le(&mut cursor)?)
    } else {
        None
    };

    // -- Slot --
    let slot_id = read_u32_le(&mut cursor)?;

    // -- Mint Binding --
    let mint_binding = if read_u8(&mut cursor)? == 0x01 {
        let mut mint = [0u8; 32];
        cursor.read_exact(&mut mint)?;
        let mut pay_token = [0u8; 32];
        cursor.read_exact(&mut pay_token)?;
        Some(MintBinding { mint, pay_token })
    } else {
        None
    };

    // -- Ephemeral Key --
    let mut ephemeral_public_key = [0u8; 32];
    cursor.read_exact(&mut ephemeral_public_key)?;

    // -- Claim Secret --
    let mut claim_secret = [0u8; 32];
    cursor.read_exact(&mut claim_secret)?;

    // -- Chain Section --
    let total_pairs = read_u16_le(&mut cursor)?;
    let required_pairs = read_u16_le(&mut cursor)?;
    let mut links = Vec::with_capacity(total_pairs as usize);
    for _ in 0..total_pairs {
        links.push(read_chain_link(&mut cursor)?);
    }

    // -- Initiation Proof --
    let mut initiator_public_key = [0u8; 32];
    cursor.read_exact(&mut initiator_public_key)?;
    let vrf_len = read_u16_le(&mut cursor)?;
    let mut vrf_proof = vec![0u8; vrf_len as usize];
    cursor.read_exact(&mut vrf_proof)?;

    // -- Caveats --
    let num_caveats = read_u16_le(&mut cursor)?;
    let mut caveats = Vec::with_capacity(num_caveats as usize);
    for _ in 0..num_caveats {
        caveats.push(read_caveat(&mut cursor)?);
    }

    Ok(BearerToken {
        mint_binding,
        header: TokenHeader {
            version,
            token_type,
            event_id,
            print_timestamp,
            denomination,
        },
        slot_id,
        ephemeral_public_key,
        claim_secret,
        chain: ChainSection {
            links,
            total_pairs,
            required_pairs,
        },
        initiation_proof: InitiationProof {
            initiator_public_key,
            vrf_proof,
        },
        caveats,
        signature,
    })
}

/// Verify the signature on a serialized bearer token.
///
/// The `signer_public_key` should be the issuer's Ed25519 public key.
pub fn verify_bearer_signature(data: &[u8], signer_public_key: &[u8; 32]) -> Result<()> {
    if data.len() < 64 {
        return Err(CryptoError::InvalidToken("data too short for signature".into()));
    }

    let sig_offset = data.len() - 64;
    let payload = &data[..sig_offset];
    let sig_bytes = &data[sig_offset..];

    let signature = Signature::from_slice(sig_bytes)
        .map_err(|_| CryptoError::SignatureVerificationFailed)?;
    let vk = VerifyingKey::from_bytes(signer_public_key)
        .map_err(|e| CryptoError::InvalidStellarAddress(e.to_string()))?;

    vk.verify(payload, &signature)
        .map_err(|_| CryptoError::SignatureVerificationFailed)
}

/// Serialize a PartialToken (no signature, used during chain construction).
pub fn serialize_partial_token(token: &PartialToken) -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(1024);

    // -- Preamble --
    buf.write_all(SYMTOKEN_MAGIC)?;
    buf.write_all(&SYMTOKEN_VERSION.to_le_bytes())?;
    buf.write_all(&[TokenType::Partial as u8])?;
    buf.write_all(&[0u8])?; // flags

    // -- Header --
    buf.write_all(&token.header.event_id)?;
    buf.write_all(&token.header.print_timestamp.to_le_bytes())?;
    match token.header.denomination {
        Some(d) => {
            buf.write_all(&[0x01])?;
            buf.write_all(&d.to_le_bytes())?;
        }
        None => {
            buf.write_all(&[0x00])?;
        }
    }

    // -- Running Public Key --
    buf.write_all(&token.running_public_key)?;

    // -- Chain Section --
    buf.write_all(&token.chain.total_pairs.to_le_bytes())?;
    let links_collected = token.chain.links.len() as u16;
    buf.write_all(&links_collected.to_le_bytes())?;
    buf.write_all(&token.remaining_pairs.to_le_bytes())?;
    for link in &token.chain.links {
        write_chain_link(&mut buf, link)?;
    }

    // -- Initiation Proof --
    buf.write_all(&token.initiation_proof.initiator_public_key)?;
    let vrf_len = token.initiation_proof.vrf_proof.len() as u16;
    buf.write_all(&vrf_len.to_le_bytes())?;
    buf.write_all(&token.initiation_proof.vrf_proof)?;

    Ok(buf)
}

/// Deserialize a PartialToken from binary format.
pub fn deserialize_partial_token(data: &[u8]) -> Result<PartialToken> {
    let mut cursor = Cursor::new(data);

    // -- Preamble --
    let mut magic = [0u8; 8];
    cursor.read_exact(&mut magic)?;
    if &magic != SYMTOKEN_MAGIC {
        return Err(CryptoError::InvalidToken("invalid magic bytes".into()));
    }

    let version = read_u16_le(&mut cursor)?;
    if version != SYMTOKEN_VERSION {
        return Err(CryptoError::InvalidToken(format!(
            "unsupported version: {version}"
        )));
    }

    let type_byte = read_u8(&mut cursor)?;
    if type_byte != TokenType::Partial as u8 {
        return Err(CryptoError::InvalidToken(format!(
            "expected Partial, got {type_byte:#x}"
        )));
    }

    let _flags = read_u8(&mut cursor)?;

    // -- Header --
    let mut event_id = [0u8; 32];
    cursor.read_exact(&mut event_id)?;
    let print_timestamp = read_i64_le(&mut cursor)?;
    let has_denomination = read_u8(&mut cursor)?;
    let denomination = if has_denomination == 0x01 {
        Some(read_u64_le(&mut cursor)?)
    } else {
        None
    };

    // -- Running Public Key --
    let mut running_public_key = [0u8; 32];
    cursor.read_exact(&mut running_public_key)?;

    // -- Chain Section --
    let total_pairs = read_u16_le(&mut cursor)?;
    let links_collected = read_u16_le(&mut cursor)?;
    let remaining_pairs = read_u16_le(&mut cursor)?;
    let mut links = Vec::with_capacity(links_collected as usize);
    for _ in 0..links_collected {
        links.push(read_chain_link(&mut cursor)?);
    }

    // -- Initiation Proof --
    let mut initiator_public_key = [0u8; 32];
    cursor.read_exact(&mut initiator_public_key)?;
    let vrf_len = read_u16_le(&mut cursor)?;
    let mut vrf_proof = vec![0u8; vrf_len as usize];
    cursor.read_exact(&mut vrf_proof)?;

    Ok(PartialToken {
        header: TokenHeader {
            version,
            token_type: TokenType::Partial,
            event_id,
            print_timestamp,
            denomination,
        },
        running_public_key,
        chain: ChainSection {
            links,
            total_pairs,
            required_pairs: total_pairs, // n-of-n Phase 1
        },
        initiation_proof: InitiationProof {
            initiator_public_key,
            vrf_proof,
        },
        remaining_pairs,
    })
}

// ============================================================
// Internal helpers
// ============================================================

/// Write a ChainLink to binary format (290 bytes per link).
///
/// Layout: node_a_public(32) + node_b_public(32) + partial_public_key(32)
///       + shard_commitment(32) + prev_link_hash(32) + link_index(2 LE)
///       + signature_a(64) + signature_b(64) = 290 bytes
fn write_chain_link<W: Write>(w: &mut W, link: &ChainLink) -> Result<()> {
    w.write_all(&link.node_a_public)?;
    w.write_all(&link.node_b_public)?;
    w.write_all(&link.partial_public_key)?;
    w.write_all(&link.shard_commitment)?;
    w.write_all(&link.prev_link_hash)?;
    w.write_all(&link.link_index.to_le_bytes())?;
    w.write_all(&link.signature_a)?;
    w.write_all(&link.signature_b)?;
    Ok(())
}

fn read_chain_link<R: Read>(r: &mut R) -> Result<ChainLink> {
    let mut node_a_public = [0u8; 32];
    let mut node_b_public = [0u8; 32];
    let mut partial_public_key = [0u8; 32];
    let mut shard_commitment = [0u8; 32];
    let mut prev_link_hash = [0u8; 32];
    let mut signature_a = [0u8; 64];
    let mut signature_b = [0u8; 64];

    r.read_exact(&mut node_a_public)?;
    r.read_exact(&mut node_b_public)?;
    r.read_exact(&mut partial_public_key)?;
    r.read_exact(&mut shard_commitment)?;
    r.read_exact(&mut prev_link_hash)?;
    let link_index = read_u16_le(r)?;
    r.read_exact(&mut signature_a)?;
    r.read_exact(&mut signature_b)?;

    Ok(ChainLink {
        node_a_public,
        node_b_public,
        partial_public_key,
        shard_commitment,
        prev_link_hash,
        link_index,
        signature_a,
        signature_b,
    })
}

fn write_caveat<W: Write>(w: &mut W, caveat: &TokenCaveat) -> Result<()> {
    w.write_all(&[caveat.type_byte()])?;
    match caveat {
        TokenCaveat::Expiration(ts) => {
            let data = ts.to_le_bytes();
            w.write_all(&(data.len() as u16).to_le_bytes())?;
            w.write_all(&data)?;
        }
        TokenCaveat::MaxRedemptions(n) => {
            let data = n.to_le_bytes();
            w.write_all(&(data.len() as u16).to_le_bytes())?;
            w.write_all(&data)?;
        }
        TokenCaveat::Custom(key, value) => {
            let key_bytes = key.as_bytes();
            let val_bytes = value.as_bytes();
            let total_len = 2 + key_bytes.len() + 2 + val_bytes.len();
            w.write_all(&(total_len as u16).to_le_bytes())?;
            w.write_all(&(key_bytes.len() as u16).to_le_bytes())?;
            w.write_all(key_bytes)?;
            w.write_all(&(val_bytes.len() as u16).to_le_bytes())?;
            w.write_all(val_bytes)?;
        }
    }
    Ok(())
}

fn read_caveat<R: Read>(r: &mut R) -> Result<TokenCaveat> {
    let type_byte = read_u8(r)?;
    let data_len = read_u16_le(r)? as usize;

    match type_byte {
        0x01 => {
            if data_len != 8 {
                return Err(CryptoError::InvalidToken("invalid Expiration caveat length".into()));
            }
            let ts = read_i64_le(r)?;
            Ok(TokenCaveat::Expiration(ts))
        }
        0x02 => {
            if data_len != 4 {
                return Err(CryptoError::InvalidToken("invalid MaxRedemptions caveat length".into()));
            }
            let n = read_u32_le(r)?;
            Ok(TokenCaveat::MaxRedemptions(n))
        }
        0x03 => {
            let key_len = read_u16_le(r)? as usize;
            let mut key_bytes = vec![0u8; key_len];
            r.read_exact(&mut key_bytes)?;
            let val_len = read_u16_le(r)? as usize;
            let mut val_bytes = vec![0u8; val_len];
            r.read_exact(&mut val_bytes)?;
            let key = String::from_utf8(key_bytes)
                .map_err(|e| CryptoError::InvalidToken(format!("invalid caveat key: {e}")))?;
            let value = String::from_utf8(val_bytes)
                .map_err(|e| CryptoError::InvalidToken(format!("invalid caveat value: {e}")))?;
            Ok(TokenCaveat::Custom(key, value))
        }
        _ => Err(CryptoError::InvalidToken(format!(
            "unknown caveat type: {type_byte:#x}"
        ))),
    }
}

fn read_u8<R: Read>(r: &mut R) -> Result<u8> {
    let mut buf = [0u8; 1];
    r.read_exact(&mut buf)?;
    Ok(buf[0])
}

fn read_u16_le<R: Read>(r: &mut R) -> Result<u16> {
    let mut buf = [0u8; 2];
    r.read_exact(&mut buf)?;
    Ok(u16::from_le_bytes(buf))
}

fn read_u32_le<R: Read>(r: &mut R) -> Result<u32> {
    let mut buf = [0u8; 4];
    r.read_exact(&mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

fn read_u64_le<R: Read>(r: &mut R) -> Result<u64> {
    let mut buf = [0u8; 8];
    r.read_exact(&mut buf)?;
    Ok(u64::from_le_bytes(buf))
}

fn read_i64_le<R: Read>(r: &mut R) -> Result<i64> {
    let mut buf = [0u8; 8];
    r.read_exact(&mut buf)?;
    Ok(i64::from_le_bytes(buf))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token::{assemble_bearer_token, PartialToken};

    fn make_test_bearer_token() -> (BearerToken, StellarKeypair) {
        let kp1 = StellarKeypair::random();
        let kp2 = StellarKeypair::random();
        let requestor = StellarKeypair::random();
        let kp3 = StellarKeypair::random();

        let (partial, _shard1) = PartialToken::initiate(
            [0xEE; 32],
            1741737600,
            Some(10_000_000),
            2,
            &kp1,
            &kp2,
            vec![0x01, 0x02],
        )
        .unwrap();

        let token = assemble_bearer_token(
            &partial,
            &requestor,
            &kp3,
            7,
            Some(1741824000),
        )
        .unwrap();

        (token, requestor)
    }

    #[test]
    fn test_bearer_container_roundtrip() {
        let (token, requestor) = make_test_bearer_token();
        let data = serialize_bearer_token(&token, &requestor).unwrap();

        assert!(is_symtoken(&data));

        let parsed = deserialize_bearer_token(&data).unwrap();
        assert_eq!(parsed.header.version, SYMTOKEN_VERSION);
        assert_eq!(parsed.header.token_type, TokenType::Bearer);
        assert_eq!(parsed.header.event_id, token.header.event_id);
        assert_eq!(parsed.header.print_timestamp, token.header.print_timestamp);
        assert_eq!(parsed.header.denomination, token.header.denomination);
        assert_eq!(parsed.ephemeral_public_key, token.ephemeral_public_key);
        assert_eq!(parsed.chain.total_pairs, token.chain.total_pairs);
        assert_eq!(parsed.chain.required_pairs, token.chain.required_pairs);
        assert_eq!(parsed.chain.links.len(), token.chain.links.len());
        assert_eq!(parsed.caveats.len(), token.caveats.len());

        // Verify chain link roundtrip
        for (a, b) in parsed.chain.links.iter().zip(token.chain.links.iter()) {
            assert_eq!(a.node_a_public, b.node_a_public);
            assert_eq!(a.node_b_public, b.node_b_public);
            assert_eq!(a.partial_public_key, b.partial_public_key);
            assert_eq!(a.shard_commitment, b.shard_commitment);
            assert_eq!(a.prev_link_hash, b.prev_link_hash);
            assert_eq!(a.link_index, b.link_index);
            assert_eq!(a.signature_a, b.signature_a);
            assert_eq!(a.signature_b, b.signature_b);
        }

        // Verify chain consistency
        parsed.verify_chain().unwrap();

        // Verify full chain integrity (signatures + hash chain)
        parsed.verify_chain_integrity().unwrap();
    }

    #[test]
    fn test_bearer_signature_verification() {
        let (token, requestor) = make_test_bearer_token();
        let data = serialize_bearer_token(&token, &requestor).unwrap();

        // Should verify with correct key
        verify_bearer_signature(&data, &requestor.raw_public()).unwrap();

        // Should fail with wrong key
        let wrong = StellarKeypair::random();
        assert!(verify_bearer_signature(&data, &wrong.raw_public()).is_err());
    }

    #[test]
    fn test_bearer_signature_detects_tampering() {
        let (token, requestor) = make_test_bearer_token();
        let mut data = serialize_bearer_token(&token, &requestor).unwrap();

        // Tamper with a byte in the middle
        let mid = data.len() / 2;
        data[mid] ^= 0xFF;

        assert!(verify_bearer_signature(&data, &requestor.raw_public()).is_err());
    }

    #[test]
    fn test_partial_container_roundtrip() {
        let kp1 = StellarKeypair::random();
        let kp2 = StellarKeypair::random();

        let (partial, _) = PartialToken::initiate(
            [0xFF; 32],
            1741737600,
            Some(5_000_000),
            3,
            &kp1,
            &kp2,
            vec![0xAA, 0xBB],
        )
        .unwrap();

        let data = serialize_partial_token(&partial).unwrap();
        assert!(is_symtoken(&data));

        let parsed = deserialize_partial_token(&data).unwrap();
        assert_eq!(parsed.header.version, SYMTOKEN_VERSION);
        assert_eq!(parsed.header.token_type, TokenType::Partial);
        assert_eq!(parsed.header.event_id, partial.header.event_id);
        assert_eq!(parsed.header.denomination, partial.header.denomination);
        assert_eq!(parsed.running_public_key, partial.running_public_key);
        assert_eq!(parsed.chain.total_pairs, partial.chain.total_pairs);
        assert_eq!(parsed.chain.links.len(), partial.chain.links.len());
        assert_eq!(parsed.remaining_pairs, partial.remaining_pairs);
        assert_eq!(
            parsed.initiation_proof.vrf_proof,
            partial.initiation_proof.vrf_proof
        );

        // Verify chain link integrity after roundtrip
        parsed.verify_chain_integrity().unwrap();
    }

    #[test]
    fn test_magic_detection() {
        assert!(is_symtoken(b"SYMTOKEN rest of data"));
        assert!(!is_symtoken(b"KNTRTOKN rest of data"));
        assert!(!is_symtoken(b"short"));
    }

    #[test]
    fn test_invalid_magic_rejected() {
        let mut data = vec![0u8; 200];
        data[..8].copy_from_slice(b"NOTVALID");
        assert!(deserialize_bearer_token(&data).is_err());
        assert!(deserialize_partial_token(&data).is_err());
    }

    #[test]
    fn test_no_denomination_roundtrip() {
        let kp1 = StellarKeypair::random();
        let kp2 = StellarKeypair::random();
        let requestor = StellarKeypair::random();
        let kp3 = StellarKeypair::random();

        let (partial, _shard1) = PartialToken::initiate(
            [0x11; 32],
            1741737600,
            None, // no denomination
            2,
            &kp1,
            &kp2,
            vec![],
        )
        .unwrap();

        let token = assemble_bearer_token(
            &partial,
            &requestor,
            &kp3,
            7,
            None,
        )
        .unwrap();

        let data = serialize_bearer_token(&token, &requestor).unwrap();
        let parsed = deserialize_bearer_token(&data).unwrap();
        assert_eq!(parsed.header.denomination, None);
    }

    #[test]
    fn test_chain_link_size() {
        // Each ChainLink is exactly 290 bytes in binary
        let kp1 = StellarKeypair::random();
        let kp2 = StellarKeypair::random();

        let (partial, _) = PartialToken::initiate(
            [0x22; 32],
            1741737600,
            Some(100),
            2,
            &kp1,
            &kp2,
            vec![],
        )
        .unwrap();

        let mut buf = Vec::new();
        write_chain_link(&mut buf, &partial.chain.links[0]).unwrap();
        assert_eq!(buf.len(), 290, "ChainLink should be 290 bytes");
    }
}
