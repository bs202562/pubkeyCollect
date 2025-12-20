//! Known Brain Wallets Storage
//!
//! This module provides storage for known brain wallet records to avoid
//! duplicate queries and keep track of all discovered brain wallets.
//!
//! Storage format: JSON Lines (one JSON object per line)
//! Index: Uses HASH160 as the primary key for fast lookups

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

/// A known brain wallet record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnownBrainWallet {
    /// The original passphrase
    pub passphrase: String,
    /// Private key as hex string
    pub private_key_hex: String,
    /// Private key in WIF format
    pub private_key_wif: String,
    /// Compressed public key as hex string (33 bytes)
    pub public_key_hex: String,
    /// HASH160 as hex string (20 bytes) - used as primary key
    pub hash160_hex: String,
    /// P2PKH address (Legacy, starts with "1")
    pub address_p2pkh: String,
    /// P2WPKH address (Native SegWit, starts with "bc1q")
    pub address_p2wpkh: String,
    /// P2SH-P2WPKH address (Nested SegWit, starts with "3")
    pub address_p2sh_p2wpkh: String,
    /// First seen block height (from blockchain)
    pub first_seen_height: u32,
    /// Pubkey type (e.g., "Legacy", "P2WPKH")
    pub pubkey_type: String,
    /// Timestamp when this record was added to the dataset
    #[serde(default)]
    pub added_timestamp: u64,
    /// Optional notes
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

/// Known Brain Wallets Database
///
/// Uses a HashMap indexed by HASH160 for O(1) lookups.
/// Persists to a JSON Lines file for durability.
pub struct KnownBrainWalletsDb {
    /// Path to the storage file
    path: PathBuf,
    /// In-memory index: HASH160 (hex) -> record
    records: HashMap<String, KnownBrainWallet>,
    /// Whether there are unsaved changes
    dirty: bool,
}

impl KnownBrainWalletsDb {
    /// Default filename for the known brain wallets database
    pub const DEFAULT_FILENAME: &'static str = "known_brainwallets.jsonl";

    /// Create a new database at the specified path
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
            records: HashMap::new(),
            dirty: false,
        }
    }

    /// Open an existing database or create a new one
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();

        if !path.exists() {
            log::info!("Creating new known brain wallets database at {:?}", path);
            return Ok(Self::new(path));
        }

        log::info!("Loading known brain wallets database from {:?}", path);
        let file = File::open(&path)
            .with_context(|| format!("Failed to open {:?}", path))?;
        let reader = BufReader::new(file);

        let mut records = HashMap::new();
        let mut line_num = 0;

        for line in reader.lines() {
            line_num += 1;
            let line = line.with_context(|| format!("Failed to read line {}", line_num))?;

            if line.trim().is_empty() {
                continue;
            }

            match serde_json::from_str::<KnownBrainWallet>(&line) {
                Ok(record) => {
                    records.insert(record.hash160_hex.clone(), record);
                }
                Err(e) => {
                    log::warn!("Failed to parse line {}: {}", line_num, e);
                }
            }
        }

        log::info!("Loaded {} known brain wallet records", records.len());

        Ok(Self {
            path,
            records,
            dirty: false,
        })
    }

    /// Get the number of records
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Check if the database is empty
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Check if a HASH160 exists in the database
    pub fn contains(&self, hash160_hex: &str) -> bool {
        self.records.contains_key(hash160_hex)
    }

    /// Check if a HASH160 (as bytes) exists in the database
    pub fn contains_bytes(&self, hash160: &[u8; 20]) -> bool {
        let hash160_hex = hex::encode(hash160);
        self.contains(&hash160_hex)
    }

    /// Get a record by HASH160
    pub fn get(&self, hash160_hex: &str) -> Option<&KnownBrainWallet> {
        self.records.get(hash160_hex)
    }

    /// Get a record by HASH160 (as bytes)
    pub fn get_bytes(&self, hash160: &[u8; 20]) -> Option<&KnownBrainWallet> {
        let hash160_hex = hex::encode(hash160);
        self.get(&hash160_hex)
    }

    /// Insert a new record. Returns true if it was newly inserted, false if it already existed.
    pub fn insert(&mut self, record: KnownBrainWallet) -> bool {
        let hash160_hex = record.hash160_hex.clone();

        if self.records.contains_key(&hash160_hex) {
            return false;
        }

        self.records.insert(hash160_hex, record);
        self.dirty = true;
        true
    }

    /// Get all records
    pub fn all_records(&self) -> impl Iterator<Item = &KnownBrainWallet> {
        self.records.values()
    }

    /// Save the database to disk
    pub fn save(&mut self) -> Result<()> {
        if !self.dirty && self.path.exists() {
            log::debug!("No changes to save");
            return Ok(());
        }

        log::info!("Saving {} records to {:?}", self.records.len(), self.path);

        let file = File::create(&self.path)
            .with_context(|| format!("Failed to create {:?}", self.path))?;
        let mut writer = BufWriter::new(file);

        for record in self.records.values() {
            let json = serde_json::to_string(record)
                .context("Failed to serialize record")?;
            writeln!(writer, "{}", json)?;
        }

        writer.flush()?;
        self.dirty = false;

        log::info!("Saved successfully");
        Ok(())
    }

    /// Append a single record to the file (more efficient for incremental updates)
    pub fn append_record(&mut self, record: KnownBrainWallet) -> Result<bool> {
        let hash160_hex = record.hash160_hex.clone();

        if self.records.contains_key(&hash160_hex) {
            return Ok(false);
        }

        // Append to file
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .with_context(|| format!("Failed to open {:?} for appending", self.path))?;
        let mut writer = BufWriter::new(file);

        let json = serde_json::to_string(&record)
            .context("Failed to serialize record")?;
        writeln!(writer, "{}", json)?;
        writer.flush()?;

        // Update in-memory index
        self.records.insert(hash160_hex, record);

        Ok(true)
    }

    /// Get the database file path
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Get current timestamp
    fn current_timestamp() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// Create a record with current timestamp
    pub fn create_record(
        passphrase: String,
        private_key_hex: String,
        private_key_wif: String,
        public_key_hex: String,
        hash160_hex: String,
        address_p2pkh: String,
        address_p2wpkh: String,
        address_p2sh_p2wpkh: String,
        first_seen_height: u32,
        pubkey_type: String,
    ) -> KnownBrainWallet {
        KnownBrainWallet {
            passphrase,
            private_key_hex,
            private_key_wif,
            public_key_hex,
            hash160_hex,
            address_p2pkh,
            address_p2wpkh,
            address_p2sh_p2wpkh,
            first_seen_height,
            pubkey_type,
            added_timestamp: Self::current_timestamp(),
            notes: None,
        }
    }
}

/// Statistics about the known brain wallets database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnownBrainWalletsStats {
    pub total_records: usize,
    pub unique_passphrases: usize,
    pub earliest_block_height: u32,
    pub latest_block_height: u32,
}

impl KnownBrainWalletsDb {
    /// Calculate statistics about the database
    pub fn stats(&self) -> KnownBrainWalletsStats {
        let total_records = self.records.len();

        let unique_passphrases = self
            .records
            .values()
            .map(|r| &r.passphrase)
            .collect::<std::collections::HashSet<_>>()
            .len();

        let (earliest, latest) = self.records.values().fold(
            (u32::MAX, 0u32),
            |(min, max), record| {
                (
                    min.min(record.first_seen_height),
                    max.max(record.first_seen_height),
                )
            },
        );

        KnownBrainWalletsStats {
            total_records,
            unique_passphrases,
            earliest_block_height: if total_records > 0 { earliest } else { 0 },
            latest_block_height: latest,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_create_and_insert() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.jsonl");

        let mut db = KnownBrainWalletsDb::new(&path);
        assert!(db.is_empty());

        let record = KnownBrainWalletsDb::create_record(
            "test passphrase".to_string(),
            "abcd1234".to_string(),
            "5Jtest".to_string(),
            "02abcd".to_string(),
            "1234567890abcdef1234567890abcdef12345678".to_string(),
            "1Address".to_string(),
            "bc1qtest".to_string(),
            "3Address".to_string(),
            100000,
            "Legacy".to_string(),
        );

        assert!(db.insert(record.clone()));
        assert!(!db.insert(record)); // Duplicate

        assert_eq!(db.len(), 1);
        assert!(db.contains("1234567890abcdef1234567890abcdef12345678"));
    }

    #[test]
    fn test_save_and_load() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.jsonl");

        // Create and save
        {
            let mut db = KnownBrainWalletsDb::new(&path);

            let record = KnownBrainWalletsDb::create_record(
                "hello world".to_string(),
                "privkey".to_string(),
                "wif".to_string(),
                "pubkey".to_string(),
                "aabbccdd00112233445566778899aabbccddeeff".to_string(),
                "1Test".to_string(),
                "bc1qtest".to_string(),
                "3Test".to_string(),
                200000,
                "SegWit".to_string(),
            );

            db.insert(record);
            db.save().unwrap();
        }

        // Load and verify
        {
            let db = KnownBrainWalletsDb::open(&path).unwrap();
            assert_eq!(db.len(), 1);

            let record = db.get("aabbccdd00112233445566778899aabbccddeeff").unwrap();
            assert_eq!(record.passphrase, "hello world");
        }
    }
}

