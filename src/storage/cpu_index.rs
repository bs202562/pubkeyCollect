//! CPU-side RocksDB storage for precise public key queries
//!
//! Key: HASH160(pubkey) - 20 bytes
//! Value: PubkeyRecord - 39 bytes

use crate::extractor::canonical::CanonicalPubkey;
use crate::PubkeyType;
use anyhow::{Context, Result};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use rocksdb::{IteratorMode, Options, WriteBatch, DB};
use std::io::Cursor;
use std::path::Path;

/// Metadata key prefix
const META_PREFIX: &[u8] = b"__meta__";
const LAST_HEIGHT_KEY: &[u8] = b"__meta__last_height";

/// Public key record stored in RocksDB
#[derive(Debug, Clone)]
pub struct PubkeyRecord {
    /// Type of public key (0=legacy, 1=segwit, 2=taproot)
    pub pubkey_type: PubkeyType,
    /// Length of the public key (32 or 33)
    pub pubkey_len: u8,
    /// Raw public key bytes (33 bytes, taproot padded with leading zero)
    pub pubkey_raw: [u8; 33],
    /// First seen block height
    pub first_seen_height: u32,
}

impl PubkeyRecord {
    /// Create a new record
    pub fn new(pubkey: &CanonicalPubkey, pubkey_type: PubkeyType, height: u32) -> Self {
        Self {
            pubkey_type,
            pubkey_len: pubkey.len(),
            pubkey_raw: pubkey.to_storage_bytes(),
            first_seen_height: height,
        }
    }

    /// Serialize record to bytes (39 bytes total)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(39);
        bytes.push(self.pubkey_type as u8);
        bytes.push(self.pubkey_len);
        bytes.extend_from_slice(&self.pubkey_raw);
        bytes.write_u32::<LittleEndian>(self.first_seen_height).unwrap();
        bytes
    }

    /// Deserialize record from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() != 39 {
            anyhow::bail!("Invalid record length: expected 39, got {}", data.len());
        }

        let pubkey_type = PubkeyType::from(data[0]);
        let pubkey_len = data[1];
        let mut pubkey_raw = [0u8; 33];
        pubkey_raw.copy_from_slice(&data[2..35]);

        let mut cursor = Cursor::new(&data[35..39]);
        let first_seen_height = cursor.read_u32::<LittleEndian>()?;

        Ok(Self {
            pubkey_type,
            pubkey_len,
            pubkey_raw,
            first_seen_height,
        })
    }
}

/// RocksDB-based CPU index for public keys
pub struct CpuIndex {
    db: DB,
}

impl CpuIndex {
    /// Open or create a RocksDB database
    pub fn open(path: &Path) -> Result<Self> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.set_max_open_files(256);
        opts.set_write_buffer_size(64 * 1024 * 1024); // 64MB write buffer
        opts.set_max_write_buffer_number(3);
        opts.set_target_file_size_base(64 * 1024 * 1024); // 64MB SST files
        opts.set_level_zero_file_num_compaction_trigger(4);
        opts.set_compression_type(rocksdb::DBCompressionType::Lz4);

        let db = DB::open(&opts, path)
            .with_context(|| format!("Failed to open RocksDB at {:?}", path))?;

        Ok(Self { db })
    }

    /// Insert a public key if it doesn't exist, or update if new height is lower
    /// Returns true if a new key was inserted
    pub fn insert_if_new(
        &mut self,
        hash160: &[u8; 20],
        pubkey: &CanonicalPubkey,
        pubkey_type: PubkeyType,
        height: u32,
    ) -> Result<bool> {
        // Check if key exists
        if let Some(existing_data) = self.db.get(hash160)? {
            let existing = PubkeyRecord::from_bytes(&existing_data)?;
            
            // Only update if new height is lower
            if height < existing.first_seen_height {
                let record = PubkeyRecord::new(pubkey, pubkey_type, height);
                self.db.put(hash160, record.to_bytes())?;
            }
            return Ok(false); // Not a new key
        }

        // Insert new key
        let record = PubkeyRecord::new(pubkey, pubkey_type, height);
        self.db.put(hash160, record.to_bytes())?;
        Ok(true)
    }

    /// Get a public key record by HASH160
    pub fn get(&self, hash160: &[u8; 20]) -> Result<Option<PubkeyRecord>> {
        match self.db.get(hash160)? {
            Some(data) => Ok(Some(PubkeyRecord::from_bytes(&data)?)),
            None => Ok(None),
        }
    }

    /// Get all HASH160 keys from the database
    pub fn get_all_hash160s(&self) -> Result<Vec<[u8; 20]>> {
        let mut result = Vec::new();

        let iter = self.db.iterator(IteratorMode::Start);
        for item in iter {
            let (key, _) = item?;
            // Skip metadata keys
            if key.starts_with(META_PREFIX) {
                continue;
            }
            if key.len() == 20 {
                let mut hash160 = [0u8; 20];
                hash160.copy_from_slice(&key);
                result.push(hash160);
            }
        }

        Ok(result)
    }

    /// Get the last processed block height
    pub fn get_last_height(&self) -> Result<u32> {
        match self.db.get(LAST_HEIGHT_KEY)? {
            Some(data) => {
                let mut cursor = Cursor::new(&data);
                Ok(cursor.read_u32::<LittleEndian>()?)
            }
            None => Ok(0),
        }
    }

    /// Set the last processed block height
    pub fn set_last_height(&mut self, height: u32) -> Result<()> {
        let mut bytes = Vec::with_capacity(4);
        bytes.write_u32::<LittleEndian>(height)?;
        self.db.put(LAST_HEIGHT_KEY, bytes)?;
        Ok(())
    }

    /// Count public keys by type
    pub fn count_by_type(&self) -> Result<(u64, u64, u64)> {
        let mut legacy_count = 0u64;
        let mut segwit_count = 0u64;
        let mut taproot_count = 0u64;

        let iter = self.db.iterator(IteratorMode::Start);
        for item in iter {
            let (key, value) = item?;
            // Skip metadata keys
            if key.starts_with(META_PREFIX) {
                continue;
            }
            if value.len() >= 1 {
                match PubkeyType::from(value[0]) {
                    PubkeyType::Legacy => legacy_count += 1,
                    PubkeyType::Segwit => segwit_count += 1,
                    PubkeyType::Taproot => taproot_count += 1,
                }
            }
        }

        Ok((legacy_count, segwit_count, taproot_count))
    }

    /// Get the approximate size of the database in MB
    pub fn size_mb(&self) -> Result<f64> {
        let property = self.db.property_value("rocksdb.total-sst-files-size")?;
        match property {
            Some(size_str) => {
                let size_bytes: u64 = size_str.parse().unwrap_or(0);
                Ok(size_bytes as f64 / (1024.0 * 1024.0))
            }
            None => Ok(0.0),
        }
    }

    /// Batch insert multiple records
    pub fn batch_insert(&mut self, records: &[(&[u8; 20], &CanonicalPubkey, PubkeyType, u32)]) -> Result<u32> {
        let mut batch = WriteBatch::default();
        let mut inserted = 0u32;

        for (hash160, pubkey, pubkey_type, height) in records {
            // Check if key exists
            if let Some(existing_data) = self.db.get(*hash160)? {
                let existing = PubkeyRecord::from_bytes(&existing_data)?;
                if *height < existing.first_seen_height {
                    let record = PubkeyRecord::new(pubkey, *pubkey_type, *height);
                    batch.put(*hash160, record.to_bytes());
                }
            } else {
                let record = PubkeyRecord::new(pubkey, *pubkey_type, *height);
                batch.put(*hash160, record.to_bytes());
                inserted += 1;
            }
        }

        self.db.write(batch)?;
        Ok(inserted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_record_serialization() {
        let mut pubkey_raw = [0u8; 33];
        pubkey_raw[0] = 0x02;
        pubkey_raw[1..].copy_from_slice(&[0xab; 32]);

        let pk = CanonicalPubkey::Legacy(pubkey_raw);
        let record = PubkeyRecord::new(&pk, PubkeyType::Legacy, 100000);

        let bytes = record.to_bytes();
        assert_eq!(bytes.len(), 39);

        let restored = PubkeyRecord::from_bytes(&bytes).unwrap();
        assert_eq!(restored.pubkey_type as u8, PubkeyType::Legacy as u8);
        assert_eq!(restored.pubkey_len, 33);
        assert_eq!(restored.first_seen_height, 100000);
    }

    #[test]
    fn test_cpu_index() {
        let tmp_dir = TempDir::new().unwrap();
        let db_path = tmp_dir.path().join("test.rocksdb");

        let mut index = CpuIndex::open(&db_path).unwrap();

        let mut pubkey_raw = [0u8; 33];
        pubkey_raw[0] = 0x02;
        pubkey_raw[1..].copy_from_slice(&[0xcd; 32]);

        let pk = CanonicalPubkey::Legacy(pubkey_raw);
        let hash160 = pk.hash160();

        // Insert
        let inserted = index.insert_if_new(&hash160, &pk, PubkeyType::Legacy, 500000).unwrap();
        assert!(inserted);

        // Get
        let record = index.get(&hash160).unwrap().unwrap();
        assert_eq!(record.first_seen_height, 500000);

        // Insert same key with higher height - should not update
        let inserted = index.insert_if_new(&hash160, &pk, PubkeyType::Legacy, 600000).unwrap();
        assert!(!inserted);
        let record = index.get(&hash160).unwrap().unwrap();
        assert_eq!(record.first_seen_height, 500000);

        // Insert same key with lower height - should update
        let inserted = index.insert_if_new(&hash160, &pk, PubkeyType::Legacy, 400000).unwrap();
        assert!(!inserted);
        let record = index.get(&hash160).unwrap().unwrap();
        assert_eq!(record.first_seen_height, 400000);
    }
}

