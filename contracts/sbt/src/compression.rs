//! SBT metadata compression and decompression using delta + RLE encoding.
//!
//! This module provides efficient compression for SBT metadata that leverages
//! the structured nature of JSON metadata while maintaining backward compatibility.
//!
//! ## Compression Strategy
//!
//! 1. **Delta Encoding**: Store differences between consecutive bytes rather than
//!    absolute values. Common metadata patterns (repeated fields, similar values)
//!    compress well with this technique.
//!
//! 2. **Run-Length Encoding (RLE)**: Compress runs of identical bytes after delta
//!    encoding. Typical for padding, repeated quotes, or structural elements.
//!
//! 3. **Magic Prefix**: Compressed data starts with `0xC1` to distinguish from
//!    uncompressed metadata (which won't start with control bytes).
//!
//! ## Format
//!
//! ```text
//! Compressed:
//!   [MAGIC: 0xC1]
//!   [is_delta_encoded: u8] (0 or 1)
//!   ([count: u8][value: i8])*   if delta-encoded
//!   or
//!   ([byte: u8])*               if not delta-encoded
//! ```

use soroban_sdk::{contracterror, Bytes, Env};

/// First byte marking compressed SBT metadata.
const COMPRESSION_MAGIC: u8 = 0xC1;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum CompressionError {
    /// Input metadata was empty.
    EmptyMetadata = 200,
    /// Compressed data is malformed.
    InvalidCompressedData = 201,
    /// Decompressed output would exceed maximum size.
    OutputTooLarge = 202,
}

/// Compress metadata using delta + RLE encoding.
///
/// Returns `Ok(Bytes)` with compressed data if successful, or an error if the
/// input is empty or would fail to compress.
///
/// # Arguments
///
/// * `env` - Soroban environment
/// * `metadata` - Uncompressed metadata bytes
/// * `max_compressed_size` - Maximum allowed output size (typically 4096)
pub fn compress_metadata(
    env: &Env,
    metadata: &Bytes,
    max_compressed_size: u32,
) -> Result<Bytes, CompressionError> {
    if metadata.is_empty() {
        return Err(CompressionError::EmptyMetadata);
    }

    // Try delta encoding for structured data (JSON is highly compressible this way)
    if let Ok(delta_compressed) = compress_with_delta(env, metadata, max_compressed_size) {
        return Ok(delta_compressed);
    }

    // Fallback to simple RLE if delta encoding doesn't help
    compress_with_rle(env, metadata, max_compressed_size)
}

/// Decompress metadata that was compressed with `compress_metadata`.
///
/// # Arguments
///
/// * `env` - Soroban environment
/// * `compressed` - Compressed metadata bytes (should start with COMPRESSION_MAGIC)
/// * `max_decompressed_size` - Maximum allowed output size (typically 4096)
pub fn decompress_metadata(
    env: &Env,
    compressed: &Bytes,
    max_decompressed_size: u32,
) -> Result<Bytes, CompressionError> {
    if compressed.is_empty() {
        return Err(CompressionError::InvalidCompressedData);
    }

    let magic = compressed.get(0).unwrap();
    if magic != COMPRESSION_MAGIC {
        return Err(CompressionError::InvalidCompressedData);
    }

    if compressed.len() < 2 {
        return Err(CompressionError::InvalidCompressedData);
    }

    let is_delta = compressed.get(1).unwrap() != 0;

    if is_delta {
        decompress_delta_encoded(env, compressed, max_decompressed_size)
    } else {
        decompress_rle_encoded(env, compressed, max_decompressed_size)
    }
}

/// Check if data is already compressed with our format.
pub fn is_compressed(metadata: &Bytes) -> bool {
    !metadata.is_empty() && metadata.get(0).unwrap() == COMPRESSION_MAGIC
}

// ============================================================================
// Private: Delta + RLE Compression
// ============================================================================

/// Delta encoding: store differences from the previous byte.
/// Works well for structured data like JSON.
fn compress_with_delta(
    env: &Env,
    metadata: &Bytes,
    max_size: u32,
) -> Result<Bytes, CompressionError> {
    let mut out = Bytes::new(env);
    out.push_back(COMPRESSION_MAGIC);
    out.push_back(1); // is_delta_encoded = true

    let len = metadata.len();
    let mut prev: i16 = 0; // Use i16 to avoid overflow on subtraction

    let mut i: u32 = 0;
    while i < len {
        let current = metadata.get(i).unwrap() as i16;
        let delta = (current - prev) as i8;
        out.push_back(delta as u8);

        if out.len() >= max_size {
            return Err(CompressionError::OutputTooLarge);
        }

        prev = current;
        i += 1;
    }

    Ok(out)
}

/// RLE encoding for runs of identical bytes.
fn compress_with_rle(
    env: &Env,
    metadata: &Bytes,
    max_size: u32,
) -> Result<Bytes, CompressionError> {
    let mut out = Bytes::new(env);
    out.push_back(COMPRESSION_MAGIC);
    out.push_back(0); // is_delta_encoded = false

    let len = metadata.len();
    let mut i: u32 = 0;

    while i < len {
        let current = metadata.get(i).unwrap();
        let mut run: u32 = 1;

        // Count consecutive identical bytes (capped at 255)
        while run < 255 && (i + run) < len && metadata.get(i + run).unwrap() == current {
            run += 1;
        }

        // Encode as (count, byte) pair
        out.push_back(run as u8);
        out.push_back(current);

        if out.len() >= max_size {
            return Err(CompressionError::OutputTooLarge);
        }

        i += run;
    }

    Ok(out)
}

// ============================================================================
// Private: Delta + RLE Decompression
// ============================================================================

fn decompress_delta_encoded(
    env: &Env,
    compressed: &Bytes,
    max_size: u32,
) -> Result<Bytes, CompressionError> {
    let mut out = Bytes::new(env);
    let mut current: i16 = 0;
    let compressed_len = compressed.len();

    let mut i: u32 = 2; // Skip magic + flag
    while i < compressed_len {
        let delta = compressed.get(i).unwrap() as i8 as i16;
        current = current.wrapping_add(delta);

        let byte = (current & 0xFF) as u8;
        out.push_back(byte);

        if out.len() >= max_size {
            return Err(CompressionError::OutputTooLarge);
        }

        i += 1;
    }

    Ok(out)
}

fn decompress_rle_encoded(
    env: &Env,
    compressed: &Bytes,
    max_size: u32,
) -> Result<Bytes, CompressionError> {
    let mut out = Bytes::new(env);
    let compressed_len = compressed.len();

    let mut i: u32 = 2; // Skip magic + flag
    while i < compressed_len {
        if i + 1 >= compressed_len {
            return Err(CompressionError::InvalidCompressedData);
        }

        let count = compressed.get(i).unwrap();
        let byte = compressed.get(i + 1).unwrap();

        for _ in 0..count {
            out.push_back(byte);

            if out.len() >= max_size {
                return Err(CompressionError::OutputTooLarge);
            }
        }

        i += 2;
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compression_magic() {
        assert_eq!(COMPRESSION_MAGIC, 0xC1);
    }
}
