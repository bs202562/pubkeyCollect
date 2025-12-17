//! FP64 (64-bit Fingerprint) table for GPU lookup
//!
//! Binary format:
//! Header (16 bytes):
//!   magic: u32 = 0x46503634 ("FP64")
//!   version: u32 = 1
//!   num_elements: u64
//!
//! Data:
//!   fingerprints: [u64; num_elements]  # Sorted ascending

use anyhow::{Context, Result};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
use std::path::Path;

/// Magic bytes for FP64 file
const FP64_MAGIC: u32 = 0x46503634; // "FP64"
const FP64_VERSION: u32 = 1;

/// FP64 table for GPU-compatible fast lookup
pub struct Fp64Table {
    /// Sorted array of 64-bit fingerprints
    fingerprints: Vec<u64>,
}

impl Fp64Table {
    /// Create a new FP64 table from a list of HASH160 values
    ///
    /// Fingerprint: fp64 = SHA256(HASH160)[0..8] as u64 little-endian
    pub fn new(hash160s: &[[u8; 20]]) -> Result<Self> {
        log::info!("Creating FP64 table with {} elements", hash160s.len());

        // Generate fingerprints in parallel
        let mut fingerprints: Vec<u64> = hash160s
            .par_iter()
            .map(|h| Self::compute_fingerprint(h))
            .collect();

        // Sort for binary search
        log::info!("Sorting FP64 table...");
        fingerprints.par_sort_unstable();

        log::info!(
            "Created FP64 table: {} fingerprints, {:.2} MB",
            fingerprints.len(),
            fingerprints.len() as f64 * 8.0 / 1024.0 / 1024.0
        );

        Ok(Self { fingerprints })
    }

    /// Compute 64-bit fingerprint from HASH160
    /// fp64 = SHA256(HASH160)[0..8] as u64 little-endian
    pub fn compute_fingerprint(hash160: &[u8; 20]) -> u64 {
        let hash = Sha256::digest(hash160);
        u64::from_le_bytes(hash[0..8].try_into().unwrap())
    }

    /// Check if a fingerprint exists in the table using binary search
    pub fn contains(&self, hash160: &[u8; 20]) -> bool {
        let fp = Self::compute_fingerprint(hash160);
        self.fingerprints.binary_search(&fp).is_ok()
    }

    /// Get the number of fingerprints
    pub fn len(&self) -> usize {
        self.fingerprints.len()
    }

    /// Check if the table is empty
    pub fn is_empty(&self) -> bool {
        self.fingerprints.is_empty()
    }

    /// Get the size of the table in MB
    pub fn size_mb(&self) -> f64 {
        (self.fingerprints.len() * 8) as f64 / 1024.0 / 1024.0
    }

    /// Save the FP64 table to a binary file
    pub fn save(&self, path: &Path) -> Result<()> {
        let file = File::create(path)
            .with_context(|| format!("Failed to create FP64 file: {:?}", path))?;
        let mut writer = BufWriter::new(file);

        // Write header
        writer.write_u32::<LittleEndian>(FP64_MAGIC)?;
        writer.write_u32::<LittleEndian>(FP64_VERSION)?;
        writer.write_u64::<LittleEndian>(self.fingerprints.len() as u64)?;

        // Write fingerprints
        for &fp in &self.fingerprints {
            writer.write_u64::<LittleEndian>(fp)?;
        }

        writer.flush()?;

        log::info!(
            "Saved FP64 table: {} fingerprints, {:.2} MB",
            self.fingerprints.len(),
            self.size_mb()
        );

        Ok(())
    }

    /// Load an FP64 table from a binary file
    pub fn load(path: &Path) -> Result<Self> {
        let file = File::open(path)
            .with_context(|| format!("Failed to open FP64 file: {:?}", path))?;
        let mut reader = BufReader::new(file);

        // Read header
        let magic = reader.read_u32::<LittleEndian>()?;
        if magic != FP64_MAGIC {
            anyhow::bail!("Invalid FP64 magic: expected 0x{:08X}, got 0x{:08X}", FP64_MAGIC, magic);
        }

        let version = reader.read_u32::<LittleEndian>()?;
        if version != FP64_VERSION {
            anyhow::bail!("Unsupported FP64 version: {}", version);
        }

        let num_elements = reader.read_u64::<LittleEndian>()? as usize;

        // Read fingerprints
        let mut fingerprints = Vec::with_capacity(num_elements);
        for _ in 0..num_elements {
            fingerprints.push(reader.read_u64::<LittleEndian>()?);
        }

        Ok(Self { fingerprints })
    }

    /// Get a slice of the fingerprints (for mmap-like access)
    pub fn as_slice(&self) -> &[u64] {
        &self.fingerprints
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_fp64_table() {
        let hash160s: Vec<[u8; 20]> = (0..1000)
            .map(|i| {
                let mut h = [0u8; 20];
                h[0..8].copy_from_slice(&(i as u64).to_le_bytes());
                h
            })
            .collect();

        let table = Fp64Table::new(&hash160s).unwrap();

        // Test that all inserted elements are found
        for h in &hash160s {
            assert!(table.contains(h), "Element should be found in FP64 table");
        }

        // Test that the table is sorted
        for i in 1..table.fingerprints.len() {
            assert!(
                table.fingerprints[i - 1] <= table.fingerprints[i],
                "Table should be sorted"
            );
        }
    }

    #[test]
    fn test_fp64_save_load() {
        let tmp_dir = TempDir::new().unwrap();
        let path = tmp_dir.path().join("fp64.bin");

        let hash160s: Vec<[u8; 20]> = (0..100)
            .map(|i| {
                let mut h = [0u8; 20];
                h[0..8].copy_from_slice(&(i as u64).to_le_bytes());
                h
            })
            .collect();

        let table = Fp64Table::new(&hash160s).unwrap();
        table.save(&path).unwrap();

        let loaded = Fp64Table::load(&path).unwrap();

        assert_eq!(table.len(), loaded.len());

        // Test that loaded table works
        for h in &hash160s {
            assert!(loaded.contains(h));
        }
    }

    #[test]
    fn test_fingerprint_computation() {
        let hash160 = [0xab; 20];
        let fp = Fp64Table::compute_fingerprint(&hash160);

        // Fingerprint should be deterministic
        let fp2 = Fp64Table::compute_fingerprint(&hash160);
        assert_eq!(fp, fp2);

        // Different inputs should (very likely) have different fingerprints
        let hash160_2 = [0xcd; 20];
        let fp3 = Fp64Table::compute_fingerprint(&hash160_2);
        assert_ne!(fp, fp3);
    }
}

