//! Public key canonicalization
//!
//! This module handles converting public keys to their canonical format:
//! - Legacy/SegWit: Always 33-byte compressed format
//! - Taproot: 32-byte x-only format (no conversion needed)

use anyhow::{anyhow, Result};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

/// Canonical public key representation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonicalPubkey {
    /// Legacy/SegWit compressed public key (33 bytes)
    Legacy([u8; 33]),
    /// Taproot x-only public key (32 bytes)
    Taproot([u8; 32]),
}

impl CanonicalPubkey {
    /// Get the raw bytes of the public key
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            CanonicalPubkey::Legacy(bytes) => bytes,
            CanonicalPubkey::Taproot(bytes) => bytes,
        }
    }

    /// Get the length of the public key
    pub fn len(&self) -> u8 {
        match self {
            CanonicalPubkey::Legacy(_) => 33,
            CanonicalPubkey::Taproot(_) => 32,
        }
    }

    /// Check if the public key is empty (never true for valid keys)
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Compute HASH160 of the public key
    /// HASH160 = RIPEMD160(SHA256(pubkey))
    pub fn hash160(&self) -> [u8; 20] {
        let sha256_hash = Sha256::digest(self.as_bytes());
        let ripemd_hash = Ripemd160::digest(&sha256_hash);
        let mut result = [0u8; 20];
        result.copy_from_slice(&ripemd_hash);
        result
    }

    /// Convert to fixed-size byte array for storage (33 bytes)
    /// Taproot keys are padded with a leading zero byte
    pub fn to_storage_bytes(&self) -> [u8; 33] {
        match self {
            CanonicalPubkey::Legacy(bytes) => *bytes,
            CanonicalPubkey::Taproot(bytes) => {
                let mut result = [0u8; 33];
                result[1..33].copy_from_slice(bytes);
                result
            }
        }
    }
}

/// Canonicalize a raw public key to its standard format
///
/// - 65-byte uncompressed keys are converted to 33-byte compressed format
/// - 33-byte compressed keys are kept as-is
/// - 32-byte x-only keys are kept as-is (Taproot)
pub fn canonicalize(raw: &[u8]) -> Result<CanonicalPubkey> {
    match raw.len() {
        65 => {
            // Uncompressed public key -> convert to compressed
            let compressed = compress_pubkey(raw)?;
            Ok(CanonicalPubkey::Legacy(compressed))
        }
        33 => {
            // Already compressed
            let mut bytes = [0u8; 33];
            bytes.copy_from_slice(raw);
            Ok(CanonicalPubkey::Legacy(bytes))
        }
        32 => {
            // X-only (Taproot)
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(raw);
            Ok(CanonicalPubkey::Taproot(bytes))
        }
        _ => Err(anyhow!("Invalid public key length: {}", raw.len())),
    }
}

/// Compress an uncompressed public key (65 bytes) to compressed format (33 bytes)
fn compress_pubkey(uncompressed: &[u8]) -> Result<[u8; 33]> {
    if uncompressed.len() != 65 {
        return Err(anyhow!("Expected 65-byte uncompressed pubkey"));
    }

    if uncompressed[0] != 0x04 {
        return Err(anyhow!("Invalid uncompressed pubkey prefix: expected 0x04"));
    }

    // Use secp256k1 library to properly compress the key
    let pk = secp256k1::PublicKey::from_slice(uncompressed)?;
    Ok(pk.serialize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canonicalize_compressed() {
        let mut compressed = [0u8; 33];
        compressed[0] = 0x02;
        compressed[1..].copy_from_slice(&[0xab; 32]);

        let result = canonicalize(&compressed).unwrap();
        match result {
            CanonicalPubkey::Legacy(bytes) => {
                assert_eq!(bytes, compressed);
            }
            _ => panic!("Expected Legacy variant"),
        }
    }

    #[test]
    fn test_canonicalize_taproot() {
        let xonly = [0xcd; 32];

        let result = canonicalize(&xonly).unwrap();
        match result {
            CanonicalPubkey::Taproot(bytes) => {
                assert_eq!(bytes, xonly);
            }
            _ => panic!("Expected Taproot variant"),
        }
    }

    #[test]
    fn test_hash160() {
        let mut compressed = [0u8; 33];
        compressed[0] = 0x02;
        compressed[1..].copy_from_slice(&[0xab; 32]);

        let pk = CanonicalPubkey::Legacy(compressed);
        let hash = pk.hash160();

        assert_eq!(hash.len(), 20);
    }

    #[test]
    fn test_invalid_length() {
        let invalid = [0u8; 40];
        assert!(canonicalize(&invalid).is_err());
    }
}

