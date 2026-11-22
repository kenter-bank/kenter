use serde::{Deserialize, Serialize};
use std::io::{Read, Write};

use crate::error::{CryptoError, Result};

/// KNTR file format magic bytes.
pub const MAGIC: &[u8; 8] = b"KNTRTOKN";
pub const VERSION_MAJOR: u16 = 1;
pub const VERSION_MINOR: u16 = 0;

pub const MAX_FILE_SIZE: u64 = 100 * 1024 * 1024; // 100 MB
pub const WARN_FILE_SIZE: u64 = 50 * 1024 * 1024; // 50 MB
pub const CHUNK_SIZE: usize = 2 * 1024 * 1024; // 2 MB

/// JSON header embedded in .kntr files.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KntrHeader {
    pub version: String,
    pub created_at: String,
    pub original_filename: String,
    pub file_size: u64,
    pub file_hash: String,
    pub token_type: String,
}

/// Write KNTR file header to a writer.
///
/// Binary layout (little-endian):
/// - 8 bytes: magic (KNTRTOKN)
/// - 2 bytes: version major
/// - 2 bytes: version minor
/// - 2 bytes: flags (reserved, 0)
/// - 4 bytes: JSON header length
/// - N bytes: JSON header (compact, no whitespace)
pub fn write_header<W: Write>(writer: &mut W, header: &KntrHeader) -> Result<()> {
    // JSON with compact separators (matches Python's separators=(',', ':'))
    let json_bytes = serde_json::to_vec(header)
        .map_err(|e| CryptoError::InvalidKntrFile(e.to_string()))?;

    writer.write_all(MAGIC)?;
    writer.write_all(&VERSION_MAJOR.to_le_bytes())?;
    writer.write_all(&VERSION_MINOR.to_le_bytes())?;
    writer.write_all(&0u16.to_le_bytes())?; // flags
    writer.write_all(&(json_bytes.len() as u32).to_le_bytes())?;
    writer.write_all(&json_bytes)?;

    Ok(())
}

/// Read and validate KNTR file header from a reader.
pub fn read_header<R: Read>(reader: &mut R) -> Result<KntrHeader> {
    // Magic
    let mut magic = [0u8; 8];
    reader
        .read_exact(&mut magic)
        .map_err(|_| CryptoError::InvalidKntrFile("failed to read magic bytes".into()))?;
    if &magic != MAGIC {
        return Err(CryptoError::InvalidKntrFile("magic bytes mismatch".into()));
    }

    // Version
    let mut version_buf = [0u8; 2];
    reader.read_exact(&mut version_buf)?;
    let _version_major = u16::from_le_bytes(version_buf);

    reader.read_exact(&mut version_buf)?;
    let _version_minor = u16::from_le_bytes(version_buf);

    // Flags
    reader.read_exact(&mut version_buf)?;
    let _flags = u16::from_le_bytes(version_buf);

    // Header length
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf)?;
    let header_len = u32::from_le_bytes(len_buf) as usize;

    // Sanity check
    if header_len > 1024 * 1024 {
        return Err(CryptoError::InvalidKntrFile("header too large".into()));
    }

    // JSON header
    let mut json_buf = vec![0u8; header_len];
    reader.read_exact(&mut json_buf)?;

    let header: KntrHeader = serde_json::from_slice(&json_buf)
        .map_err(|e| CryptoError::InvalidKntrFile(format!("invalid JSON header: {e}")))?;

    Ok(header)
}

/// Check if a byte slice starts with the KNTR magic bytes.
pub fn is_kntr_format(data: &[u8]) -> bool {
    data.len() >= 8 && &data[..8] == MAGIC
}
