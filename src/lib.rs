//! Bitcoin on-chain public key collector library
//!
//! This library provides functionality to collect all public keys that have
//! appeared on the Bitcoin mainnet and generate two storage formats:
//! - CPU/RocksDB format for precise queries
//! - GPU format (Bloom Filter + FP64 table) for high-speed filtering

pub mod block;
pub mod extractor;
pub mod storage;
pub mod stats;

pub use block::reader::BlockReader;
pub use extractor::canonical::CanonicalPubkey;
pub use storage::cpu_index::CpuIndex;
pub use storage::bloom::BloomFilter;
pub use storage::fp64::Fp64Table;
pub use stats::Stats;

/// Magic bytes for Bitcoin mainnet
pub const MAINNET_MAGIC: u32 = 0xD9B4BEF9;

/// Public key types
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum PubkeyType {
    /// Legacy P2PK/P2PKH (from scriptPubKey or scriptSig)
    Legacy = 0,
    /// SegWit P2WPKH (from witness)
    Segwit = 1,
    /// Taproot P2TR (x-only pubkey from scriptPubKey)
    Taproot = 2,
}

impl From<u8> for PubkeyType {
    fn from(value: u8) -> Self {
        match value {
            0 => PubkeyType::Legacy,
            1 => PubkeyType::Segwit,
            2 => PubkeyType::Taproot,
            _ => PubkeyType::Legacy,
        }
    }
}
