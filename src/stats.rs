//! Statistics and reporting module

use crate::storage::{bloom::BloomFilter, cpu_index::CpuIndex, fp64::Fp64Table};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Statistics about the collected public keys
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Stats {
    /// Total number of unique public keys
    pub total_pubkeys: u64,
    /// Number of legacy public keys (P2PK/P2PKH)
    pub legacy_count: u64,
    /// Number of SegWit public keys (P2WPKH)
    pub segwit_count: u64,
    /// Number of Taproot public keys (P2TR)
    pub taproot_count: u64,
    /// Last processed block height
    pub last_height: u32,
    /// RocksDB size in MB
    pub rocksdb_size_mb: f64,
    /// Bloom filter size in MB
    pub bloom_size_mb: f64,
    /// FP64 table size in MB
    pub fp64_size_mb: f64,
}

impl Stats {
    /// Generate statistics from the storage components
    pub fn generate(cpu_index: &CpuIndex, bloom: &BloomFilter, fp64: &Fp64Table) -> Result<Self> {
        let counts = cpu_index.count_by_type()?;
        let last_height = cpu_index.get_last_height()?;

        Ok(Stats {
            total_pubkeys: counts.0 + counts.1 + counts.2,
            legacy_count: counts.0,
            segwit_count: counts.1,
            taproot_count: counts.2,
            last_height,
            rocksdb_size_mb: cpu_index.size_mb()?,
            bloom_size_mb: bloom.size_mb(),
            fp64_size_mb: fp64.size_mb(),
        })
    }

    /// Save statistics to a JSON file
    pub fn save(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }
}
