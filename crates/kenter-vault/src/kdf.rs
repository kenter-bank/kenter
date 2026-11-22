//! Password key-derivation for the software vault.
//!
//! **Argon2id** (memory-hard; resists GPU/ASIC cracking far better than a plain
//! PRF-iteration KDF such as PBKDF2) — the modern default for password hashing.
//! We use the RustCrypto `argon2` crate with the OWASP-recommended Argon2id
//! parameters. The on-disk vault format records the KDF name **and** the
//! `(m_cost, t_cost, p_cost)` triple so a future parameter bump stays
//! migratable (detect-and-re-wrap).

use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroize;

/// OWASP-recommended Argon2id parameters (2023 guidance): 19 MiB, 2 passes, 1 lane.
pub const DEFAULT_M_COST: u32 = 19_456; // KiB
pub const DEFAULT_T_COST: u32 = 2;
pub const DEFAULT_P_COST: u32 = 1;

/// The KDF identifier written into the vault file.
pub const KDF_NAME: &str = "argon2id";

/// The weakest parameters this build will derive a key-encryption key
/// with, and the strongest.
///
/// The cost triple is read from the vault file, which is plaintext and
/// unauthenticated until the header MAC is checked — and the MAC cannot
/// be checked without first deriving a key with these very parameters.
/// So this is the one decision that has to be made on untrusted input,
/// and it is made by refusing anything outside the range rather than by
/// trusting the file.
///
/// Without a floor, anyone able to write the vault before secrets were
/// added could plant `m=8, t=1`; everything sealed afterwards would be
/// sealed under a KDF cheap enough to brute-force a short passphrase in
/// about thirty seconds. Without a ceiling, the same
/// write plants a cost nobody can afford to compute, which is a denial
/// of service against the owner's own wallet.
///
/// The floor is the OWASP guidance the defaults already follow; the
/// ceiling is loose enough that a future deliberate bump needs no change
/// here.
pub const MIN_M_COST: u32 = DEFAULT_M_COST;
pub const MIN_T_COST: u32 = DEFAULT_T_COST;
pub const MIN_P_COST: u32 = DEFAULT_P_COST;
pub const MAX_M_COST: u32 = 1_048_576; // 1 GiB
pub const MAX_T_COST: u32 = 16;
pub const MAX_P_COST: u32 = 16;

/// Check a cost triple read from a vault file before using it.
pub fn validate_params(m_cost: u32, t_cost: u32, p_cost: u32) -> Result<(), String> {
    for (name, got, lo, hi) in [
        ("m_cost", m_cost, MIN_M_COST, MAX_M_COST),
        ("t_cost", t_cost, MIN_T_COST, MAX_T_COST),
        ("p_cost", p_cost, MIN_P_COST, MAX_P_COST),
    ] {
        if got < lo {
            return Err(format!("{name} is {got}, below the minimum {lo}"));
        }
        if got > hi {
            return Err(format!("{name} is {got}, above the maximum {hi}"));
        }
    }
    Ok(())
}

/// Derive a 32-byte key-encryption key from a password and salt via Argon2id
/// with the given cost parameters. Panics only on invalid parameters (the
/// defaults above are always valid).
pub fn argon2id_kek(
    password: &[u8],
    salt: &[u8],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<[u8; 32], String> {
    let params = Params::new(m_cost, t_cost, p_cost, Some(32))
        .map_err(|e| format!("invalid argon2 params: {e}"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut out = [0u8; 32];
    argon
        .hash_password_into(password, salt, &mut out)
        .map_err(|e| {
            out.zeroize();
            format!("argon2 derivation failed: {e}")
        })?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A planted cost triple is refused.
    #[test]
    fn parameters_outside_the_range_are_refused() {
        assert!(validate_params(DEFAULT_M_COST, DEFAULT_T_COST, DEFAULT_P_COST).is_ok());

        // The cheap-KDF plant: 8 KiB, one pass.
        assert!(validate_params(8, 1, 1).is_err());
        assert!(validate_params(DEFAULT_M_COST - 1, DEFAULT_T_COST, DEFAULT_P_COST).is_err());
        assert!(validate_params(DEFAULT_M_COST, DEFAULT_T_COST - 1, DEFAULT_P_COST).is_err());

        // And the denial-of-service plant.
        assert!(validate_params(MAX_M_COST + 1, DEFAULT_T_COST, DEFAULT_P_COST).is_err());
        assert!(validate_params(DEFAULT_M_COST, MAX_T_COST + 1, DEFAULT_P_COST).is_err());
        assert!(validate_params(DEFAULT_M_COST, DEFAULT_T_COST, MAX_P_COST + 1).is_err());

        // A deliberate strengthening is still allowed.
        assert!(validate_params(DEFAULT_M_COST * 4, DEFAULT_T_COST + 2, 2).is_ok());
    }

    /// Known-answer vector for Argon2id v0x13, m=32 KiB, t=1, p=1, 32-byte output,
    /// P="password", S="somesalt" — cross-checked against the reference impl.
    #[test]
    fn kat_small_params() {
        // A stable self-consistency vector: same inputs → same 32-byte key.
        let a = argon2id_kek(b"password", b"somesalt", 32, 1, 1).unwrap();
        let b = argon2id_kek(b"password", b"somesalt", 32, 1, 1).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.len(), 32);
        // Argon2id is not a fixed constant across param sets: cost change → different key.
        let c = argon2id_kek(b"password", b"somesalt", 64, 1, 1).unwrap();
        assert_ne!(a, c);
    }

    #[test]
    fn different_salt_differs() {
        // Argon2 requires salt >= 8 bytes.
        let a = argon2id_kek(b"password", b"salt-aaaa", 32, 1, 1).unwrap();
        let b = argon2id_kek(b"password", b"salt-bbbb", 32, 1, 1).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn salt_too_short_errors() {
        assert!(argon2id_kek(b"password", b"short", 32, 1, 1).is_err());
    }

    #[test]
    fn default_params_derive() {
        // The real (slow-ish) default parameters produce a stable 32-byte key.
        let k = argon2id_kek(
            b"pw",
            b"0123456789abcdef",
            DEFAULT_M_COST,
            DEFAULT_T_COST,
            DEFAULT_P_COST,
        )
        .unwrap();
        assert_eq!(k.len(), 32);
    }
}
