use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::error::{CryptoError, Result};

/// Supported caveat types for data tokens.
#[derive(Debug, Clone)]
pub enum Caveat {
    /// Maximum file size in bytes.
    MaxFileSize(u64),
    /// Allowed file type (extension without dot).
    FileType(String),
    /// Expected SHA-256 hex digest.
    FileHash(String),
    /// Custom key-value caveat.
    Custom(String, String),
}

/// Verifies caveats against actual file properties.
pub struct CaveatVerifier {
    caveats: Vec<Caveat>,
}

impl CaveatVerifier {
    pub fn new(caveats: Vec<Caveat>) -> Self {
        Self { caveats }
    }

    /// Verify all caveats against file data and metadata.
    pub fn verify_all(&self, file_bytes: &[u8], filename: Option<&str>) -> Result<()> {
        for caveat in &self.caveats {
            match caveat {
                Caveat::MaxFileSize(max) => {
                    let actual = file_bytes.len() as u64;
                    if actual > *max {
                        return Err(CryptoError::CaveatFailed(format!(
                            "File size ({actual}) exceeds limit ({max})"
                        )));
                    }
                }
                Caveat::FileType(expected) => {
                    if let Some(name) = filename {
                        let ext = name
                            .rsplit('.')
                            .next()
                            .unwrap_or("");
                        if !ext.eq_ignore_ascii_case(expected) {
                            return Err(CryptoError::CaveatFailed(format!(
                                "File type '{ext}' != '{expected}'"
                            )));
                        }
                    }
                }
                Caveat::FileHash(expected_hex) => {
                    let actual_hash = Sha256::digest(file_bytes);
                    let actual_hex = hex::encode(actual_hash);
                    // Constant-time comparison
                    if actual_hex.as_bytes().ct_eq(expected_hex.as_bytes()).into() {
                        // match — continue
                    } else {
                        return Err(CryptoError::HashMismatch);
                    }
                }
                Caveat::Custom(_, _) => {
                    // Custom caveats are application-specific; pass through
                }
            }
        }
        Ok(())
    }
}
