//! Bloom Filter for GPU high-speed filtering
//!
//! Binary format:
//! Header (16 bytes):
//!   magic: u32 = 0x424C4F4D ("BLOM")
//!   version: u32 = 1
//!   num_elements: u64
//!
//! Params (16 bytes):
//!   bit_size: u64
//!   num_hashes: u32
//!   padding: u32
//!
//! Data:
//!   bits: [u8; bit_size / 8]

use anyhow::{Context, Result};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;

/// Magic bytes for Bloom filter file
const BLOOM_MAGIC: u32 = 0x424C4F4D; // "BLOM"
const BLOOM_VERSION: u32 = 1;

/// Bloom filter for GPU-compatible high-speed filtering
pub struct BloomFilter {
    /// Bit array
    bits: Vec<u8>,
    /// Number of bits in the filter
    bit_size: u64,
    /// Number of hash functions
    num_hashes: u32,
    /// Number of elements inserted
    num_elements: u64,
}

impl BloomFilter {
    /// Create a new Bloom filter from a list of HASH160 values
    ///
    /// Target false positive rate: 1e-7
    /// Using formula: m = -n * ln(p) / (ln(2)^2)
    ///                k = (m/n) * ln(2)
    pub fn new(hash160s: &[[u8; 20]]) -> Result<Self> {
        let n = hash160s.len() as f64;
        let p: f64 = 1e-7; // Target false positive rate

        // Calculate optimal parameters
        let ln2 = std::f64::consts::LN_2;
        let ln2_sq = ln2 * ln2;

        // m = number of bits
        let m = (-n * p.ln() / ln2_sq).ceil() as u64;
        // Ensure m is a multiple of 8 for byte alignment
        let m = ((m + 7) / 8) * 8;

        // k = number of hash functions (capped at 8 per spec)
        let k = ((m as f64 / n) * ln2).round() as u32;
        let k = k.clamp(6, 8);

        log::info!(
            "Creating Bloom filter: {} elements, {} bits ({:.2} MB), {} hashes",
            hash160s.len(),
            m,
            m as f64 / 8.0 / 1024.0 / 1024.0,
            k
        );

        let mut filter = Self {
            bits: vec![0u8; (m / 8) as usize],
            bit_size: m,
            num_hashes: k,
            num_elements: hash160s.len() as u64,
        };

        // Insert all elements
        for hash160 in hash160s {
            filter.insert(hash160);
        }

        Ok(filter)
    }

    /// Insert an element into the Bloom filter
    fn insert(&mut self, hash160: &[u8; 20]) {
        let (h1, h2) = self.get_hash_pair(hash160);

        for i in 0..self.num_hashes {
            let bit_index = self.get_bit_index(h1, h2, i);
            let byte_index = (bit_index / 8) as usize;
            let bit_offset = (bit_index % 8) as u8;
            self.bits[byte_index] |= 1 << bit_offset;
        }
    }

    /// Test if an element might be in the Bloom filter
    pub fn contains(&self, hash160: &[u8; 20]) -> bool {
        let (h1, h2) = self.get_hash_pair(hash160);

        for i in 0..self.num_hashes {
            let bit_index = self.get_bit_index(h1, h2, i);
            let byte_index = (bit_index / 8) as usize;
            let bit_offset = (bit_index % 8) as u8;
            if (self.bits[byte_index] & (1 << bit_offset)) == 0 {
                return false;
            }
        }

        true
    }

    /// Get hash pair for double hashing
    /// Uses SHA256 to generate two 64-bit hashes
    fn get_hash_pair(&self, hash160: &[u8; 20]) -> (u64, u64) {
        let hash = Sha256::digest(hash160);
        let h1 = u64::from_le_bytes(hash[0..8].try_into().unwrap());
        let h2 = u64::from_le_bytes(hash[8..16].try_into().unwrap());
        (h1, h2)
    }

    /// Get bit index using double hashing: h(i) = h1 + i * h2
    fn get_bit_index(&self, h1: u64, h2: u64, i: u32) -> u64 {
        let combined = h1.wrapping_add((i as u64).wrapping_mul(h2));
        combined % self.bit_size
    }

    /// Get the size of the Bloom filter in MB
    pub fn size_mb(&self) -> f64 {
        self.bits.len() as f64 / 1024.0 / 1024.0
    }

    /// Save the Bloom filter to a binary file
    pub fn save(&self, path: &Path) -> Result<()> {
        let file = File::create(path)
            .with_context(|| format!("Failed to create Bloom filter file: {:?}", path))?;
        let mut writer = BufWriter::new(file);

        // Write header
        writer.write_u32::<LittleEndian>(BLOOM_MAGIC)?;
        writer.write_u32::<LittleEndian>(BLOOM_VERSION)?;
        writer.write_u64::<LittleEndian>(self.num_elements)?;

        // Write params
        writer.write_u64::<LittleEndian>(self.bit_size)?;
        writer.write_u32::<LittleEndian>(self.num_hashes)?;
        writer.write_u32::<LittleEndian>(0)?; // padding

        // Write bit array
        writer.write_all(&self.bits)?;

        writer.flush()?;

        log::info!(
            "Saved Bloom filter: {} elements, {:.2} MB",
            self.num_elements,
            self.size_mb()
        );

        Ok(())
    }

    /// Load a Bloom filter from a binary file
    pub fn load(path: &Path) -> Result<Self> {
        let file = File::open(path)
            .with_context(|| format!("Failed to open Bloom filter file: {:?}", path))?;
        let mut reader = BufReader::new(file);

        // Read header
        let magic = reader.read_u32::<LittleEndian>()?;
        if magic != BLOOM_MAGIC {
            anyhow::bail!("Invalid Bloom filter magic: expected 0x{:08X}, got 0x{:08X}", BLOOM_MAGIC, magic);
        }

        let version = reader.read_u32::<LittleEndian>()?;
        if version != BLOOM_VERSION {
            anyhow::bail!("Unsupported Bloom filter version: {}", version);
        }

        let num_elements = reader.read_u64::<LittleEndian>()?;

        // Read params
        let bit_size = reader.read_u64::<LittleEndian>()?;
        let num_hashes = reader.read_u32::<LittleEndian>()?;
        let _padding = reader.read_u32::<LittleEndian>()?;

        // Read bit array
        let byte_size = (bit_size / 8) as usize;
        let mut bits = vec![0u8; byte_size];
        reader.read_exact(&mut bits)?;

        Ok(Self {
            bits,
            bit_size,
            num_hashes,
            num_elements,
        })
    }

    /// Get the number of elements
    pub fn num_elements(&self) -> u64 {
        self.num_elements
    }

    /// Get the number of hash functions
    pub fn num_hashes(&self) -> u32 {
        self.num_hashes
    }

    /// Get the bit size
    pub fn bit_size(&self) -> u64 {
        self.bit_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_bloom_filter() {
        let hash160s: Vec<[u8; 20]> = (0..1000)
            .map(|i| {
                let mut h = [0u8; 20];
                h[0..8].copy_from_slice(&(i as u64).to_le_bytes());
                h
            })
            .collect();

        let bloom = BloomFilter::new(&hash160s).unwrap();

        // Test that all inserted elements are found
        for h in &hash160s {
            assert!(bloom.contains(h), "Element should be found in Bloom filter");
        }

        // Test that most non-inserted elements are not found
        let mut false_positives = 0;
        for i in 1000..2000 {
            let mut h = [0u8; 20];
            h[0..8].copy_from_slice(&(i as u64).to_le_bytes());
            if bloom.contains(&h) {
                false_positives += 1;
            }
        }

        // False positive rate should be very low
        assert!(false_positives < 10, "Too many false positives: {}", false_positives);
    }

    #[test]
    fn test_bloom_save_load() {
        let tmp_dir = TempDir::new().unwrap();
        let path = tmp_dir.path().join("bloom.bin");

        let hash160s: Vec<[u8; 20]> = (0..100)
            .map(|i| {
                let mut h = [0u8; 20];
                h[0..8].copy_from_slice(&(i as u64).to_le_bytes());
                h
            })
            .collect();

        let bloom = BloomFilter::new(&hash160s).unwrap();
        bloom.save(&path).unwrap();

        let loaded = BloomFilter::load(&path).unwrap();

        assert_eq!(bloom.num_elements(), loaded.num_elements());
        assert_eq!(bloom.num_hashes(), loaded.num_hashes());
        assert_eq!(bloom.bit_size(), loaded.bit_size());

        // Test that loaded filter works
        for h in &hash160s {
            assert!(loaded.contains(h));
        }
    }
}

