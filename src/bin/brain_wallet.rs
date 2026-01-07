//! Brain Wallet Collision Scanner
//!
//! This program attempts to find brain wallet collisions by:
//! 1. Taking various text inputs (passphrases)
//! 2. Hashing them with SHA256 to generate private keys
//! 3. Deriving public keys from the private keys
//! 4. Checking if the public keys exist in the collected database
//!
//! Query path (optimized for speed):
//! 1. Bloom filter check (very fast)
//! 2. FP64 table lookup (fast binary search)
//! 3. RocksDB precise lookup (only for confirmed hits)
//!
//! Progress checkpoint support:
//! - Use --resume to continue from last checkpoint
//! - Progress is saved automatically every N seconds or lines
//! - Graceful shutdown on Ctrl+C saves progress

use anyhow::{Context, Result};
use bitcoin::address::Address;
use bitcoin::key::CompressedPublicKey;
use bitcoin::Network;
use clap::{Parser, Subcommand, ValueEnum};
use collect_pubkey::storage::bloom::BloomFilter;
use collect_pubkey::storage::cpu_index::{CpuIndex, PubkeyRecord};
use collect_pubkey::storage::fp64::Fp64Table;
use collect_pubkey::storage::known_brainwallets::KnownBrainWalletsDb;
use indicatif::{ProgressBar, ProgressStyle};
use md5::Md5;
use ripemd::Ripemd160;
use secp256k1::{Secp256k1, SecretKey, PublicKey};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};
use std::collections::HashSet;
use std::fmt;
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;
use rayon::prelude::*;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as TokioBufReader};
use tokio::net::TcpStream;

/// Supported hash algorithms for brain wallet derivation
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HashAlgorithm {
    /// SHA-256 (standard brain wallet)
    Sha256,
    /// SHA-512 (first 32 bytes used)
    Sha512,
    /// SHA-1 (padded to 32 bytes with zeros)
    Sha1,
    /// MD5 (padded to 32 bytes with zeros)
    Md5,
    /// RIPEMD-160 (padded to 32 bytes with zeros)
    Ripemd160,
}

impl fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HashAlgorithm::Sha256 => write!(f, "sha256"),
            HashAlgorithm::Sha512 => write!(f, "sha512"),
            HashAlgorithm::Sha1 => write!(f, "sha1"),
            HashAlgorithm::Md5 => write!(f, "md5"),
            HashAlgorithm::Ripemd160 => write!(f, "ripemd160"),
        }
    }
}

impl FromStr for HashAlgorithm {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "sha256" => Ok(HashAlgorithm::Sha256),
            "sha512" => Ok(HashAlgorithm::Sha512),
            "sha1" => Ok(HashAlgorithm::Sha1),
            "md5" => Ok(HashAlgorithm::Md5),
            "ripemd160" => Ok(HashAlgorithm::Ripemd160),
            _ => Err(format!("Unknown hash algorithm: {}", s)),
        }
    }
}

impl HashAlgorithm {
    /// Compute the hash of input data and return as 32-byte array
    /// For algorithms with shorter output, pads with zeros
    /// For algorithms with longer output, truncates to 32 bytes
    fn hash(&self, data: &[u8]) -> [u8; 32] {
        let mut result = [0u8; 32];
        match self {
            HashAlgorithm::Sha256 => {
                let hash = Sha256::digest(data);
                result.copy_from_slice(&hash);
            }
            HashAlgorithm::Sha512 => {
                let hash = Sha512::digest(data);
                result.copy_from_slice(&hash[..32]); // Use first 32 bytes
            }
            HashAlgorithm::Sha1 => {
                let hash = Sha1::digest(data);
                result[..20].copy_from_slice(&hash); // 20 bytes, rest zeros
            }
            HashAlgorithm::Md5 => {
                let hash = Md5::digest(data);
                result[..16].copy_from_slice(&hash); // 16 bytes, rest zeros
            }
            HashAlgorithm::Ripemd160 => {
                let hash = Ripemd160::digest(data);
                result[..20].copy_from_slice(&hash); // 20 bytes, rest zeros
            }
        }
        result
    }

    /// Perform multiple iterations of hashing
    fn hash_iterations(&self, data: &[u8], iterations: u32) -> [u8; 32] {
        let mut current = self.hash(data);
        for _ in 1..iterations {
            current = self.hash(&current);
        }
        current
    }
}

/// Multi-hash configuration for brain wallet scanning
#[derive(Debug, Clone, Serialize, Deserialize)]
struct MultiHashConfig {
    /// Enable multi-hash iteration mode
    enabled: bool,
    /// Hash algorithms to try
    algorithms: Vec<HashAlgorithm>,
    /// Maximum number of iterations per algorithm
    max_iterations: u32,
}

impl Default for MultiHashConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            algorithms: vec![HashAlgorithm::Sha256],
            max_iterations: 1,
        }
    }
}

/// Progress checkpoint for resumable scanning
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ScanProgress {
    /// Index of current file being processed (0-based)
    current_file_index: usize,
    /// Byte offset in current file (for seeking)
    current_file_offset: u64,
    /// Line number in current file (for display/verification)
    current_line_number: u64,
    /// Total lines processed across all files
    total_lines_processed: u64,
    /// Total passphrases checked
    total_checked: u64,
    /// Known brain wallets skipped
    known_skipped: u64,
    /// Bloom filter hits
    bloom_hits: u64,
    /// FP64 hits
    fp64_hits: u64,
    /// Matches found
    matches_found: u64,
    /// New matches added to known DB
    new_matches: u64,
    /// Input files (for verification)
    input_files: Vec<String>,
    /// Timestamp of last save
    last_save_timestamp: u64,
    /// Whether variations mode is enabled
    with_variations: bool,
    /// Multi-hash configuration
    #[serde(default)]
    multi_hash_config: MultiHashConfig,
}

impl ScanProgress {
    fn save(&self, path: &PathBuf) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    fn load(path: &PathBuf) -> Result<Self> {
        let json = std::fs::read_to_string(path)?;
        let progress: ScanProgress = serde_json::from_str(&json)?;
        Ok(progress)
    }

    fn verify_input_files(&self, input_files: &[PathBuf]) -> bool {
        if self.input_files.len() != input_files.len() {
            return false;
        }
        for (i, path) in input_files.iter().enumerate() {
            if path.to_string_lossy() != self.input_files[i] {
                return false;
            }
        }
        true
    }
}

/// Brain Wallet Collision Scanner
#[derive(Parser)]
#[command(name = "brain-wallet")]
#[command(about = "Scan for brain wallet collisions against collected public keys")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan text files for brain wallet collisions
    Scan {
        /// Input file(s) containing passphrases (one per line)
        #[arg(short, long, required = true)]
        input: Vec<PathBuf>,

        /// Directory containing the public key database
        #[arg(short, long, default_value = "output")]
        data_dir: PathBuf,

        /// Output file for found matches
        #[arg(short, long, default_value = "matches.txt")]
        output: PathBuf,

        /// Number of threads to use (default: number of CPUs)
        #[arg(short, long)]
        threads: Option<usize>,

        /// Skip Bloom filter (use FP64 only for faster loading)
        #[arg(long)]
        skip_bloom: bool,

        /// Generate variations of each passphrase
        #[arg(long)]
        with_variations: bool,

        /// Electrs server address for balance queries (e.g., 192.168.1.19:50001)
        #[arg(long)]
        electrs: Option<String>,

        /// Output file for matches with balance (only used with --electrs)
        #[arg(long, default_value = "matches_with_balance.txt")]
        balance_output: PathBuf,

        /// Path to known brain wallets database (skip known records, auto-add new ones)
        #[arg(long, default_value = "known_brainwallets.jsonl")]
        known_db: PathBuf,

        /// Disable known brain wallets tracking
        #[arg(long)]
        no_known_db: bool,

        /// Batch size for processing (useful for large files with --with-variations)
        /// When set, processes passphrases in batches to reduce memory usage
        #[arg(long)]
        batch_size: Option<usize>,

        /// Resume from previous progress checkpoint
        #[arg(long)]
        resume: bool,

        /// Progress file path for checkpoint (default: .brain_wallet_progress.json)
        #[arg(long, default_value = ".brain_wallet_progress.json")]
        progress_file: PathBuf,

        /// Save progress every N seconds (default: 30)
        #[arg(long, default_value = "30")]
        save_interval: u64,

        /// Enable multi-hash iteration mode (try multiple hash algorithms and iterations)
        #[arg(long)]
        multi_hash: bool,

        /// Hash algorithms to try (comma-separated: sha256,sha512,sha1,md5,ripemd160)
        /// Default: sha256 when --multi-hash is enabled
        #[arg(long, value_delimiter = ',', default_value = "sha256")]
        hash_algorithms: Vec<HashAlgorithm>,

        /// Maximum number of consecutive hash iterations to try per algorithm
        /// For each passphrase, will try hash(pass), hash(hash(pass)), etc. up to N times
        #[arg(long, default_value = "1")]
        max_iterations: u32,
    },

    /// Generate passphrases from a text file (split by sentences, phrases, etc.)
    Generate {
        /// Input text file (e.g., Bible, dictionary)
        #[arg(short, long)]
        input: PathBuf,

        /// Output file for generated passphrases
        #[arg(short, long)]
        output: PathBuf,

        /// Minimum passphrase length
        #[arg(long, default_value = "3")]
        min_len: usize,

        /// Maximum passphrase length
        #[arg(long, default_value = "100")]
        max_len: usize,

        /// Include word combinations (slower, more comprehensive)
        #[arg(long)]
        word_combos: bool,

        /// Maximum words for combinations
        #[arg(long, default_value = "4")]
        max_words: usize,
    },

    /// Test a single passphrase
    Test {
        /// The passphrase to test
        passphrase: String,

        /// Directory containing the public key database
        #[arg(short, long, default_value = "output")]
        data_dir: PathBuf,

        /// Electrs server address for balance queries (e.g., 192.168.1.19:50001)
        #[arg(long)]
        electrs: Option<String>,

        /// Hash algorithm to use (sha256, sha512, sha1, md5, ripemd160)
        #[arg(long, default_value = "sha256")]
        hash_algorithm: HashAlgorithm,

        /// Number of hash iterations (1 = single hash, 2 = hash(hash(pass)), etc.)
        #[arg(long, default_value = "1")]
        iterations: u32,
    },

    /// Import records from matches.txt into the known brain wallets database
    Import {
        /// Input file (matches.txt format)
        #[arg(short, long, default_value = "matches.txt")]
        input: PathBuf,

        /// Path to the known brain wallets database
        #[arg(short, long, default_value = "known_brainwallets.jsonl")]
        database: PathBuf,
    },

    /// List all known brain wallets
    List {
        /// Path to the known brain wallets database
        #[arg(short, long, default_value = "known_brainwallets.jsonl")]
        database: PathBuf,

        /// Output format: table, json, csv
        #[arg(short, long, default_value = "table")]
        format: String,

        /// Maximum number of records to show (0 = all)
        #[arg(short, long, default_value = "50")]
        limit: usize,
    },

    /// Show statistics about the known brain wallets database
    Stats {
        /// Path to the known brain wallets database
        #[arg(short, long, default_value = "known_brainwallets.jsonl")]
        database: PathBuf,
    },

    /// Export known brain wallets to a file
    Export {
        /// Path to the known brain wallets database
        #[arg(short, long, default_value = "known_brainwallets.jsonl")]
        database: PathBuf,

        /// Output file path
        #[arg(short, long)]
        output: PathBuf,

        /// Output format: json, csv, txt
        #[arg(short, long, default_value = "txt")]
        format: String,
    },
}

/// Bitcoin addresses derived from a public key
#[derive(Clone)]
struct BitcoinAddresses {
    /// P2PKH address (Legacy, starts with "1")
    p2pkh: String,
    /// P2WPKH address (Native SegWit, starts with "bc1q")
    p2wpkh: String,
    /// P2SH-P2WPKH address (Nested SegWit, starts with "3")
    p2sh_p2wpkh: String,
}

/// Balance information from Electrum server
#[derive(Clone, Debug, Default)]
struct BalanceInfo {
    /// Confirmed balance in satoshis
    confirmed: u64,
    /// Unconfirmed balance in satoshis
    unconfirmed: i64,
}

impl BalanceInfo {
    fn total_btc(&self) -> f64 {
        (self.confirmed as i64 + self.unconfirmed) as f64 / 100_000_000.0
    }
}

/// Electrum client for querying balances via electrs
struct ElectrumClient {
    addr: String,
}

impl ElectrumClient {
    fn new(addr: &str) -> Self {
        Self {
            addr: addr.to_string(),
        }
    }

    /// Calculate scripthash for P2PKH (Legacy address)
    fn scripthash_p2pkh(hash160: &[u8; 20]) -> String {
        // P2PKH scriptPubKey: OP_DUP OP_HASH160 <20-byte-hash> OP_EQUALVERIFY OP_CHECKSIG
        // = 76 a9 14 <hash160> 88 ac
        let mut script = vec![0x76, 0xa9, 0x14];
        script.extend_from_slice(hash160);
        script.push(0x88);
        script.push(0xac);

        // SHA256 and reverse
        let hash = Sha256::digest(&script);
        let mut reversed = hash.to_vec();
        reversed.reverse();
        hex::encode(reversed)
    }

    /// Calculate scripthash for P2WPKH (Native SegWit)
    fn scripthash_p2wpkh(hash160: &[u8; 20]) -> String {
        // P2WPKH scriptPubKey: OP_0 <20-byte-hash>
        // = 00 14 <hash160>
        let mut script = vec![0x00, 0x14];
        script.extend_from_slice(hash160);

        // SHA256 and reverse
        let hash = Sha256::digest(&script);
        let mut reversed = hash.to_vec();
        reversed.reverse();
        hex::encode(reversed)
    }

    /// Calculate scripthash for P2SH-P2WPKH (Nested SegWit)
    fn scripthash_p2sh_p2wpkh(hash160: &[u8; 20]) -> String {
        // First, create the witness script: OP_0 <20-byte-hash>
        let mut witness_script = vec![0x00, 0x14];
        witness_script.extend_from_slice(hash160);

        // Hash it with HASH160 to get the P2SH hash
        let sha256_hash = Sha256::digest(&witness_script);
        let ripemd_hash = Ripemd160::digest(&sha256_hash);

        // P2SH scriptPubKey: OP_HASH160 <20-byte-hash> OP_EQUAL
        // = a9 14 <hash160> 87
        let mut script = vec![0xa9, 0x14];
        script.extend_from_slice(&ripemd_hash);
        script.push(0x87);

        // SHA256 and reverse
        let hash = Sha256::digest(&script);
        let mut reversed = hash.to_vec();
        reversed.reverse();
        hex::encode(reversed)
    }

    /// Connect to electrs and return reader/writer
    async fn connect(&self) -> Result<(
        tokio::io::BufReader<tokio::net::tcp::OwnedReadHalf>,
        tokio::net::tcp::OwnedWriteHalf,
    )> {
        let stream = TcpStream::connect(&self.addr)
            .await
            .with_context(|| format!("Failed to connect to electrs at {}", self.addr))?;

        let (reader, writer) = stream.into_split();
        Ok((TokioBufReader::new(reader), writer))
    }

    /// Parse a balance response from JSON
    fn parse_balance_response(response: &str) -> Result<BalanceInfo> {
        let json: serde_json::Value = serde_json::from_str(response)
            .with_context(|| format!("Failed to parse electrs response: {}", response))?;

        if let Some(error) = json.get("error") {
            if !error.is_null() {
                anyhow::bail!("Electrs error: {}", error);
            }
        }

        let result = json.get("result").context("No result in electrs response")?;
        let confirmed = result.get("confirmed").and_then(|v| v.as_u64()).unwrap_or(0);
        let unconfirmed = result.get("unconfirmed").and_then(|v| v.as_i64()).unwrap_or(0);

        Ok(BalanceInfo {
            confirmed,
            unconfirmed,
        })
    }

    /// Query all balances for a hash160 using a single connection
    async fn get_all_balances(&self, hash160: &[u8; 20]) -> AllBalances {
        let mut result = AllBalances::default();

        // Try to connect with retry
        let connection = {
            let mut attempts = 0;
            loop {
                match self.connect().await {
                    Ok(conn) => break Some(conn),
                    Err(e) => {
                        attempts += 1;
                        if attempts >= 3 {
                            log::warn!("Failed to connect after 3 attempts: {}", e);
                            break None;
                        }
                        // Wait before retry (short delay)
                        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
                    }
                }
            }
        };

        let Some((mut reader, mut writer)) = connection else {
            return result;
        };

        // Prepare all scripthashes
        let scripthash_p2pkh = Self::scripthash_p2pkh(hash160);
        let scripthash_p2wpkh = Self::scripthash_p2wpkh(hash160);
        let scripthash_p2sh_p2wpkh = Self::scripthash_p2sh_p2wpkh(hash160);

        // Send all 3 requests in batch (JSON-RPC allows pipelining)
        let requests = format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"blockchain.scripthash.get_balance","params":["{}"]}}
{{"jsonrpc":"2.0","id":2,"method":"blockchain.scripthash.get_balance","params":["{}"]}}
{{"jsonrpc":"2.0","id":3,"method":"blockchain.scripthash.get_balance","params":["{}"]}}
"#,
            scripthash_p2pkh, scripthash_p2wpkh, scripthash_p2sh_p2wpkh
        );

        if let Err(e) = writer.write_all(requests.as_bytes()).await {
            log::warn!("Failed to send requests: {}", e);
            return result;
        }
        if let Err(e) = writer.flush().await {
            log::warn!("Failed to flush: {}", e);
            return result;
        }

        // Read 3 responses
        let mut response = String::new();

        // Response 1: P2PKH
        response.clear();
        if reader.read_line(&mut response).await.is_ok() {
            match Self::parse_balance_response(&response) {
                Ok(balance) => result.p2pkh = Some(balance),
                Err(e) => log::warn!("Failed to parse P2PKH response: {}", e),
            }
        }

        // Response 2: P2WPKH
        response.clear();
        if reader.read_line(&mut response).await.is_ok() {
            match Self::parse_balance_response(&response) {
                Ok(balance) => result.p2wpkh = Some(balance),
                Err(e) => log::warn!("Failed to parse P2WPKH response: {}", e),
            }
        }

        // Response 3: P2SH-P2WPKH
        response.clear();
        if reader.read_line(&mut response).await.is_ok() {
            match Self::parse_balance_response(&response) {
                Ok(balance) => result.p2sh_p2wpkh = Some(balance),
                Err(e) => log::warn!("Failed to parse P2SH-P2WPKH response: {}", e),
            }
        }

        result
    }

}

/// All balances for different address types
#[derive(Default, Clone)]
struct AllBalances {
    p2pkh: Option<BalanceInfo>,
    p2wpkh: Option<BalanceInfo>,
    p2sh_p2wpkh: Option<BalanceInfo>,
}

impl AllBalances {
    fn total_confirmed(&self) -> u64 {
        let mut total = 0u64;
        if let Some(ref b) = self.p2pkh {
            total += b.confirmed;
        }
        if let Some(ref b) = self.p2wpkh {
            total += b.confirmed;
        }
        if let Some(ref b) = self.p2sh_p2wpkh {
            total += b.confirmed;
        }
        total
    }

    fn total_btc(&self) -> f64 {
        self.total_confirmed() as f64 / 100_000_000.0
    }

    fn has_balance(&self) -> bool {
        self.total_confirmed() > 0
    }

    fn format(&self) -> String {
        let mut lines = vec![];

        if let Some(ref b) = self.p2pkh {
            lines.push(format!(
                "    P2PKH:       {} BTC (confirmed: {}, unconfirmed: {})",
                b.total_btc(),
                b.confirmed,
                b.unconfirmed
            ));
        }

        if let Some(ref b) = self.p2wpkh {
            lines.push(format!(
                "    P2WPKH:      {} BTC (confirmed: {}, unconfirmed: {})",
                b.total_btc(),
                b.confirmed,
                b.unconfirmed
            ));
        }

        if let Some(ref b) = self.p2sh_p2wpkh {
            lines.push(format!(
                "    P2SH-P2WPKH: {} BTC (confirmed: {}, unconfirmed: {})",
                b.total_btc(),
                b.confirmed,
                b.unconfirmed
            ));
        }

        if lines.is_empty() {
            "    (unable to query balances)".to_string()
        } else {
            lines.push(format!("    TOTAL:       {} BTC", self.total_btc()));
            lines.join("\n")
        }
    }
}

/// Derive Bitcoin addresses from a compressed public key
fn derive_addresses(pubkey_bytes: &[u8; 33]) -> Result<BitcoinAddresses> {
    // Parse the compressed public key
    let compressed_pubkey = CompressedPublicKey::from_slice(pubkey_bytes)
        .context("Failed to parse compressed public key")?;

    // P2PKH (Legacy address starting with "1")
    let p2pkh = Address::p2pkh(compressed_pubkey, Network::Bitcoin);

    // P2WPKH (Native SegWit address starting with "bc1q")
    let p2wpkh = Address::p2wpkh(&compressed_pubkey, Network::Bitcoin);

    // P2SH-P2WPKH (Nested SegWit address starting with "3")
    let p2sh_p2wpkh = Address::p2shwpkh(&compressed_pubkey, Network::Bitcoin);

    Ok(BitcoinAddresses {
        p2pkh: p2pkh.to_string(),
        p2wpkh: p2wpkh.to_string(),
        p2sh_p2wpkh: p2sh_p2wpkh.to_string(),
    })
}

/// Brain wallet derivation: passphrase -> private key -> public key -> HASH160
/// Uses default SHA256 algorithm with single iteration (standard brain wallet)
#[allow(dead_code)]
fn derive_brain_wallet(passphrase: &str) -> Result<([u8; 32], [u8; 33], [u8; 20], BitcoinAddresses)> {
    derive_brain_wallet_with_hash(passphrase, HashAlgorithm::Sha256, 1)
}

/// Brain wallet derivation with configurable hash algorithm and iterations
/// algorithm: The hash algorithm to use
/// iterations: Number of times to apply the hash (1 = single hash, 2 = hash of hash, etc.)
fn derive_brain_wallet_with_hash(
    passphrase: &str,
    algorithm: HashAlgorithm,
    iterations: u32,
) -> Result<([u8; 32], [u8; 33], [u8; 20], BitcoinAddresses)> {
    // Step 1: Apply hash algorithm N times to get 32-byte private key
    let private_key_bytes = algorithm.hash_iterations(passphrase.as_bytes(), iterations);

    // Validate that this produces a valid secp256k1 private key
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&private_key_bytes)
        .context("Failed to create secret key (invalid private key from hash)")?;
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);

    // Step 3: Get compressed public key (33 bytes)
    let pubkey_bytes = public_key.serialize();

    // Step 4: Compute HASH160 = RIPEMD160(SHA256(pubkey))
    let sha256_hash = Sha256::digest(&pubkey_bytes);
    let ripemd_hash = Ripemd160::digest(&sha256_hash);
    let mut hash160 = [0u8; 20];
    hash160.copy_from_slice(&ripemd_hash);

    // Step 5: Derive Bitcoin addresses
    let addresses = derive_addresses(&pubkey_bytes)?;

    Ok((private_key_bytes, pubkey_bytes, hash160, addresses))
}

/// Hash derivation info for tracking which method was used to find a match
#[derive(Clone, Debug)]
struct HashDerivationInfo {
    algorithm: HashAlgorithm,
    iterations: u32,
}

impl HashDerivationInfo {
    fn format(&self) -> String {
        if self.iterations == 1 {
            format!("{}(passphrase)", self.algorithm)
        } else {
            format!("{}^{}(passphrase)", self.algorithm, self.iterations)
        }
    }
}

/// Generate variations of a passphrase
fn generate_variations(passphrase: &str) -> Vec<String> {
    let mut variations = vec![passphrase.to_string()];

    // Lowercase
    let lower = passphrase.to_lowercase();
    if lower != passphrase {
        variations.push(lower);
    }

    // Uppercase
    let upper = passphrase.to_uppercase();
    if upper != passphrase {
        variations.push(upper);
    }

    // Trimmed
    let trimmed = passphrase.trim().to_string();
    if trimmed != passphrase {
        variations.push(trimmed);
    }

    // With common prefixes/suffixes
    let common_additions = ["1", "123", "!", ".", " ", "0", "bitcoin", "Bitcoin"];
    for add in common_additions {
        variations.push(format!("{}{}", passphrase, add));
        variations.push(format!("{}{}", add, passphrase));
    }

    // Remove duplicates while preserving order
    let mut seen = HashSet::new();
    variations.retain(|v| seen.insert(v.clone()));

    variations
}

/// Collision scanner with pre-loaded data structures
struct CollisionScanner {
    bloom: Option<BloomFilter>,
    fp64: Fp64Table,
    cpu_index: CpuIndex,
}

impl CollisionScanner {
    fn new(data_dir: &PathBuf, skip_bloom: bool) -> Result<Self> {
        log::info!("Loading data structures from {:?}...", data_dir);

        let bloom = if !skip_bloom {
            let bloom_path = data_dir.join("bloom.bin");
            log::info!("Loading Bloom filter from {:?}...", bloom_path);
            let start = Instant::now();
            let bloom = BloomFilter::load(&bloom_path)
                .context("Failed to load Bloom filter")?;
            log::info!(
                "Bloom filter loaded: {:.2} MB, {} elements, took {:?}",
                bloom.size_mb(),
                bloom.num_elements(),
                start.elapsed()
            );
            Some(bloom)
        } else {
            log::info!("Skipping Bloom filter...");
            None
        };

        let fp64_path = data_dir.join("fp64.bin");
        log::info!("Loading FP64 table from {:?}...", fp64_path);
        let start = Instant::now();
        let fp64 = Fp64Table::load(&fp64_path)
            .context("Failed to load FP64 table")?;
        log::info!(
            "FP64 table loaded: {:.2} MB, {} fingerprints, took {:?}",
            fp64.size_mb(),
            fp64.len(),
            start.elapsed()
        );

        let rocksdb_path = data_dir.join("pubkey.rocksdb");
        log::info!("Opening RocksDB from {:?}...", rocksdb_path);
        let start = Instant::now();
        let cpu_index = CpuIndex::open(&rocksdb_path)
            .context("Failed to open RocksDB")?;
        log::info!("RocksDB opened, took {:?}", start.elapsed());

        Ok(Self {
            bloom,
            fp64,
            cpu_index,
        })
    }

    /// Check if a HASH160 exists in the database
    /// Returns (bloom_hit, fp64_hit, record)
    fn check(&self, hash160: &[u8; 20]) -> (bool, bool, Option<PubkeyRecord>) {
        // Step 1: Bloom filter check (if available)
        if let Some(ref bloom) = self.bloom {
            if !bloom.contains(hash160) {
                return (false, false, None);
            }
        }

        // Step 2: FP64 table lookup
        if !self.fp64.contains(hash160) {
            return (true, false, None);
        }

        // Step 3: RocksDB precise lookup
        match self.cpu_index.get(hash160) {
            Ok(record) => (true, true, record),
            Err(_) => (true, true, None),
        }
    }
}

/// Match result
#[derive(Clone)]
struct MatchResult {
    passphrase: String,
    private_key: [u8; 32],
    public_key: [u8; 33],
    hash160: [u8; 20],
    addresses: BitcoinAddresses,
    record: PubkeyRecord,
    balances: Option<AllBalances>,
    /// Hash derivation method used (algorithm and iterations)
    derivation: Option<HashDerivationInfo>,
}

impl MatchResult {
    fn format(&self) -> String {
        let balance_section = if let Some(ref balances) = self.balances {
            format!(
                "\nBalances:\n{}\n",
                balances.format()
            )
        } else {
            String::new()
        };

        let derivation_section = if let Some(ref derivation) = self.derivation {
            format!("Hash Derivation: {}\n", derivation.format())
        } else {
            String::new()
        };

        format!(
            "=== MATCH FOUND ===\n\
             Passphrase: {}\n\
             {}\
             Private Key (hex): {}\n\
             Private Key (WIF): {}\n\
             Public Key: {}\n\
             HASH160: {}\n\
             \n\
             Addresses:\n\
               P2PKH (Legacy):      {}\n\
               P2WPKH (SegWit):     {}\n\
               P2SH-P2WPKH (Nested):{}\n\
             {}\
             First Seen Height: {}\n\
             Pubkey Type: {:?}\n\
             ==================\n",
            self.passphrase,
            derivation_section,
            hex::encode(self.private_key),
            private_key_to_wif(&self.private_key),
            hex::encode(self.public_key),
            hex::encode(self.hash160),
            self.addresses.p2pkh,
            self.addresses.p2wpkh,
            self.addresses.p2sh_p2wpkh,
            balance_section,
            self.record.first_seen_height,
            self.record.pubkey_type,
        )
    }

    fn has_balance(&self) -> bool {
        self.balances.as_ref().map(|b| b.has_balance()).unwrap_or(false)
    }
}

/// Convert private key bytes to WIF (Wallet Import Format)
fn private_key_to_wif(privkey: &[u8; 32]) -> String {
    // WIF format: 0x80 + privkey + 0x01 (compressed) + checksum
    let mut data = vec![0x80]; // Mainnet prefix
    data.extend_from_slice(privkey);
    data.push(0x01); // Compressed pubkey flag
    
    // Double SHA256 for checksum
    let hash1 = Sha256::digest(&data);
    let hash2 = Sha256::digest(&hash1);
    
    // Append first 4 bytes of checksum
    data.extend_from_slice(&hash2[..4]);
    
    // Base58 encode
    bs58::encode(data).into_string()
}

/// Process a batch of passphrases in parallel
fn process_batch(
    batch: &[String],
    scanner: &Arc<CollisionScanner>,
    known_db: &Option<Arc<RwLock<KnownBrainWalletsDb>>>,
    electrum_client: &Option<Arc<ElectrumClient>>,
    results: &Arc<Mutex<Vec<MatchResult>>>,
    pending_matches: &Arc<Mutex<Vec<MatchResult>>>,
    checked: &AtomicU64,
    bloom_hits: &AtomicU64,
    fp64_hits: &AtomicU64,
    matches_found: &AtomicU64,
    known_skipped: &AtomicU64,
    new_matches: &AtomicU64,
    progress: &ProgressBar,
    multi_hash_config: &MultiHashConfig,
) {
    batch.par_iter().for_each(|passphrase| {
        // Generate hash derivation combinations to try
        let derivations: Vec<(HashAlgorithm, u32)> = if multi_hash_config.enabled {
            // Try all combinations of algorithms and iterations
            multi_hash_config
                .algorithms
                .iter()
                .flat_map(|&algo| {
                    (1..=multi_hash_config.max_iterations).map(move |iter| (algo, iter))
                })
                .collect()
        } else {
            // Standard mode: just SHA256 with 1 iteration
            vec![(HashAlgorithm::Sha256, 1)]
        };

        let derivations_count = derivations.len() as u64;

        for (algorithm, iterations) in derivations {
            // Derive brain wallet with specified algorithm and iterations
            match derive_brain_wallet_with_hash(passphrase, algorithm, iterations) {
                Ok((privkey, pubkey, hash160, addresses)) => {
                    // Check if this is a known brain wallet (skip if already in database)
                    if let Some(ref known_db) = known_db {
                        if known_db.read().unwrap().contains_bytes(&hash160) {
                            known_skipped.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                    }

                    let (bloom_hit, fp64_hit, record) = scanner.check(&hash160);

                    checked.fetch_add(1, Ordering::Relaxed);

                    if bloom_hit {
                        bloom_hits.fetch_add(1, Ordering::Relaxed);
                    }

                    if fp64_hit {
                        fp64_hits.fetch_add(1, Ordering::Relaxed);
                    }

                    if let Some(record) = record {
                        // MATCH FOUND!
                        matches_found.fetch_add(1, Ordering::Relaxed);

                        let derivation_info = HashDerivationInfo { algorithm, iterations };

                        let result = MatchResult {
                            passphrase: passphrase.clone(),
                            private_key: privkey,
                            public_key: pubkey,
                            hash160,
                            addresses: addresses.clone(),
                            record: record.clone(),
                            balances: None, // Will be filled later if electrs is configured
                            derivation: Some(derivation_info),
                        };

                        // Add to known brain wallets database
                        if let Some(ref known_db) = known_db {
                            let known_record = KnownBrainWalletsDb::create_record(
                                passphrase.clone(),
                                hex::encode(privkey),
                                private_key_to_wif(&privkey),
                                hex::encode(pubkey),
                                hex::encode(hash160),
                                addresses.p2pkh.clone(),
                                addresses.p2wpkh.clone(),
                                addresses.p2sh_p2wpkh.clone(),
                                record.first_seen_height,
                                format!("{:?}", record.pubkey_type),
                            );

                            if let Ok(mut db) = known_db.write() {
                                if let Ok(true) = db.append_record(known_record) {
                                    new_matches.fetch_add(1, Ordering::Relaxed);
                                    log::debug!("Added new brain wallet to database: {}", hex::encode(hash160));
                                }
                            }
                        }

                        // Print immediately (without balance for now)
                        eprintln!("\n{}", result.format());

                        // Store for later
                        if electrum_client.is_some() {
                            pending_matches.lock().unwrap().push(result);
                        } else {
                            results.lock().unwrap().push(result);
                        }
                    }
                }
                Err(_) => {
                    // Skip invalid derivations (e.g., those that produce invalid private keys)
                }
            }
        }

        // Increment progress by the number of derivations tried for this passphrase
        progress.inc(derivations_count);
    });
}

fn run_scan(
    input_files: Vec<PathBuf>,
    data_dir: PathBuf,
    output_path: PathBuf,
    threads: Option<usize>,
    skip_bloom: bool,
    with_variations: bool,
    electrs_addr: Option<String>,
    balance_output_path: PathBuf,
    known_db_path: PathBuf,
    no_known_db: bool,
    batch_size: Option<usize>,
    resume: bool,
    progress_file: PathBuf,
    save_interval: u64,
    multi_hash: bool,
    hash_algorithms: Vec<HashAlgorithm>,
    max_iterations: u32,
) -> Result<()> {
    // Build multi-hash config
    let multi_hash_config = Arc::new(MultiHashConfig {
        enabled: multi_hash,
        algorithms: if hash_algorithms.is_empty() {
            vec![HashAlgorithm::Sha256]
        } else {
            hash_algorithms.clone()
        },
        max_iterations: max_iterations.max(1),
    });

    if multi_hash_config.enabled {
        let total_derivations = multi_hash_config.algorithms.len() * multi_hash_config.max_iterations as usize;
        log::info!(
            "Multi-hash mode enabled: {} algorithm(s) × {} iterations = {} derivations per passphrase",
            multi_hash_config.algorithms.len(),
            multi_hash_config.max_iterations,
            total_derivations
        );
        log::info!("Algorithms: {:?}", multi_hash_config.algorithms);
    }
    // Set thread count
    if let Some(t) = threads {
        rayon::ThreadPoolBuilder::new()
            .num_threads(t)
            .build_global()
            .ok();
    }

    // Setup Ctrl+C handler for graceful shutdown
    let shutdown_flag = Arc::new(AtomicBool::new(false));
    let shutdown_flag_clone = shutdown_flag.clone();
    ctrlc::set_handler(move || {
        log::warn!("Received Ctrl+C, initiating graceful shutdown...");
        shutdown_flag_clone.store(true, Ordering::SeqCst);
    }).expect("Failed to set Ctrl+C handler");

    // Check for resume mode
    let mut start_file_index: usize = 0;
    let mut start_file_offset: u64 = 0;
    let mut start_line_number: u64 = 0;
    let mut initial_checked: u64 = 0;
    let mut initial_known_skipped: u64 = 0;
    let mut initial_bloom_hits: u64 = 0;
    let mut initial_fp64_hits: u64 = 0;
    let mut initial_matches_found: u64 = 0;
    let mut initial_new_matches: u64 = 0;
    let mut initial_total_processed: u64 = 0;

    if resume && progress_file.exists() {
        log::info!("Attempting to resume from {:?}...", progress_file);
        match ScanProgress::load(&progress_file) {
            Ok(progress) => {
                // Verify input files match
                if !progress.verify_input_files(&input_files) {
                    log::error!("Input files don't match the progress file. Cannot resume.");
                    log::error!("Expected: {:?}", progress.input_files);
                    log::error!("Got: {:?}", input_files.iter().map(|p| p.to_string_lossy().to_string()).collect::<Vec<_>>());
                    anyhow::bail!("Input files mismatch. Use different progress file or remove --resume");
                }

                // Verify variations mode matches
                if progress.with_variations != with_variations {
                    log::error!("Variations mode doesn't match. Progress: {}, Current: {}", progress.with_variations, with_variations);
                    anyhow::bail!("Variations mode mismatch. Use same --with-variations setting or remove --resume");
                }

                // Verify multi-hash config matches
                if progress.multi_hash_config.enabled != multi_hash {
                    log::error!("Multi-hash mode doesn't match. Progress: {}, Current: {}", 
                        progress.multi_hash_config.enabled, multi_hash);
                    anyhow::bail!("Multi-hash mode mismatch. Use same --multi-hash setting or remove --resume");
                }
                if multi_hash {
                    let saved_algos: Vec<_> = progress.multi_hash_config.algorithms.iter().map(|a| a.to_string()).collect();
                    let current_algos: Vec<_> = hash_algorithms.iter().map(|a| a.to_string()).collect();
                    if saved_algos != current_algos {
                        log::error!("Hash algorithms don't match. Progress: {:?}, Current: {:?}", saved_algos, current_algos);
                        anyhow::bail!("Hash algorithms mismatch. Use same --hash-algorithms setting or remove --resume");
                    }
                    if progress.multi_hash_config.max_iterations != max_iterations {
                        log::error!("Max iterations don't match. Progress: {}, Current: {}", 
                            progress.multi_hash_config.max_iterations, max_iterations);
                        anyhow::bail!("Max iterations mismatch. Use same --max-iterations setting or remove --resume");
                    }
                }

                start_file_index = progress.current_file_index;
                start_file_offset = progress.current_file_offset;
                start_line_number = progress.current_line_number;
                initial_checked = progress.total_checked;
                initial_known_skipped = progress.known_skipped;
                initial_bloom_hits = progress.bloom_hits;
                initial_fp64_hits = progress.fp64_hits;
                initial_matches_found = progress.matches_found;
                initial_new_matches = progress.new_matches;
                initial_total_processed = progress.total_lines_processed;

                log::info!("Resuming from file {}/{} at line {}", 
                    start_file_index + 1, input_files.len(), start_line_number);
                log::info!("Previous progress: {} checked, {} matches found", 
                    initial_checked, initial_matches_found);
            }
            Err(e) => {
                log::warn!("Failed to load progress file: {}. Starting from beginning.", e);
            }
        }
    } else if resume {
        log::info!("No progress file found at {:?}. Starting from beginning.", progress_file);
    }

    // Load known brain wallets database
    let known_db = if !no_known_db {
        log::info!("Loading known brain wallets database from {:?}...", known_db_path);
        let db = KnownBrainWalletsDb::open(&known_db_path)?;
        log::info!("Loaded {} known brain wallet records", db.len());
        Some(Arc::new(RwLock::new(db)))
    } else {
        log::info!("Known brain wallets tracking disabled");
        None
    };

    // Load scanner
    let scanner = Arc::new(CollisionScanner::new(&data_dir, skip_bloom)?);

    // Counters (initialized from resume state if applicable)
    let checked = AtomicU64::new(initial_checked);
    let bloom_hits = AtomicU64::new(initial_bloom_hits);
    let fp64_hits = AtomicU64::new(initial_fp64_hits);
    let matches_found = AtomicU64::new(initial_matches_found);
    let known_skipped = AtomicU64::new(initial_known_skipped);
    let new_matches = AtomicU64::new(initial_new_matches);
    let total_processed = AtomicU64::new(initial_total_processed);

    // Progress tracking for checkpoint saves
    let current_file_index = Arc::new(AtomicU64::new(start_file_index as u64));
    let current_file_offset = Arc::new(AtomicU64::new(start_file_offset));
    let current_line_number = Arc::new(AtomicU64::new(start_line_number));
    let last_save_time = Arc::new(Mutex::new(Instant::now()));

    // Electrs client (if configured)
    let electrum_client = electrs_addr.as_ref().map(|addr| {
        log::info!("Electrs server configured: {}", addr);
        Arc::new(ElectrumClient::new(addr))
    });

    // Results collector (with hash160 for later balance queries)
    let results: Arc<Mutex<Vec<MatchResult>>> = Arc::new(Mutex::new(Vec::new()));
    // Pending matches that need balance queries
    let pending_matches: Arc<Mutex<Vec<MatchResult>>> = Arc::new(Mutex::new(Vec::new()));

    // Global dedup set for streaming mode (persists across batches)
    let global_seen: Arc<RwLock<HashSet<String>>> = Arc::new(RwLock::new(HashSet::new()));

    let start = Instant::now();

    // Determine processing mode
    let use_batch_mode = batch_size.is_some();
    let batch_sz = batch_size.unwrap_or(1_000_000);

    if use_batch_mode {
        log::info!("Using batch processing mode with batch size: {}", batch_sz);
    }

    // Count total lines first for progress bar (quick scan)
    log::info!("Counting lines in input files...");
    let mut total_lines: u64 = 0;
    for input_path in &input_files {
        let file = File::open(input_path)
            .with_context(|| format!("Failed to open {:?}", input_path))?;
        let reader = BufReader::new(file);
        total_lines += reader.lines().count() as u64;
    }
    
    // Calculate derivations per passphrase based on multi-hash config
    let derivations_per_passphrase = if multi_hash_config.enabled {
        multi_hash_config.algorithms.len() as u64 * multi_hash_config.max_iterations as u64
    } else {
        1u64
    };

    // Estimate total with variations (rough estimate: ~15 variations per line)
    // and multiply by derivations per passphrase for multi-hash mode
    let estimated_passphrases = if with_variations {
        total_lines * 15
    } else {
        total_lines
    };
    let estimated_total = estimated_passphrases * derivations_per_passphrase;
    
    log::info!("Total lines: {}, estimated passphrases: {}, derivations per passphrase: {}, estimated total derivations: {}", 
        total_lines, estimated_passphrases, derivations_per_passphrase, estimated_total);

    // Progress bar
    let progress = ProgressBar::new(estimated_total);
    progress.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({per_sec}) {msg}")
            .unwrap()
            .progress_chars("#>-"),
    );

    // Helper function to save progress checkpoint
    let multi_hash_config_for_save = (*multi_hash_config).clone();
    let save_progress = |file_idx: usize, file_offset: u64, line_num: u64| -> Result<()> {
        let progress_data = ScanProgress {
            current_file_index: file_idx,
            current_file_offset: file_offset,
            current_line_number: line_num,
            total_lines_processed: total_processed.load(Ordering::Relaxed),
            total_checked: checked.load(Ordering::Relaxed),
            known_skipped: known_skipped.load(Ordering::Relaxed),
            bloom_hits: bloom_hits.load(Ordering::Relaxed),
            fp64_hits: fp64_hits.load(Ordering::Relaxed),
            matches_found: matches_found.load(Ordering::Relaxed),
            new_matches: new_matches.load(Ordering::Relaxed),
            input_files: input_files.iter().map(|p| p.to_string_lossy().to_string()).collect(),
            last_save_timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            with_variations,
            multi_hash_config: multi_hash_config_for_save.clone(),
        };
        progress_data.save(&progress_file)?;
        log::info!("Progress saved: file {}/{}, line {}, checked {}, matches {}",
            file_idx + 1, input_files.len(), line_num,
            checked.load(Ordering::Relaxed), matches_found.load(Ordering::Relaxed));
        Ok(())
    };

    // Process files in streaming/batch mode
    let mut batch: Vec<String> = Vec::with_capacity(batch_sz);
    let mut batch_num = 0u64;
    let mut shutdown_requested = false;

    'file_loop: for (file_idx, input_path) in input_files.iter().enumerate() {
        // Skip files before resume point
        if file_idx < start_file_index {
            log::debug!("Skipping already processed file: {:?}", input_path);
            continue;
        }

        current_file_index.store(file_idx as u64, Ordering::Relaxed);
        log::info!("Processing file {}/{}: {:?}", file_idx + 1, input_files.len(), input_path);
        
        let mut file = File::open(input_path)
            .with_context(|| format!("Failed to open {:?}", input_path))?;
        
        // Seek to resume position if this is the resume file
        let mut local_line_number: u64 = 0;
        if file_idx == start_file_index && start_file_offset > 0 {
            log::info!("Seeking to byte offset {} in file", start_file_offset);
            file.seek(SeekFrom::Start(start_file_offset))?;
            local_line_number = start_line_number;
        }
        
        let mut reader = BufReader::new(file);
        let mut current_offset = if file_idx == start_file_index { start_file_offset } else { 0 };

        let mut line_buf = String::new();
        loop {
            // Check for shutdown
            if shutdown_flag.load(Ordering::SeqCst) {
                log::warn!("Shutdown requested, saving progress...");
                shutdown_requested = true;
                break 'file_loop;
            }

            line_buf.clear();
            let bytes_read = reader.read_line(&mut line_buf)?;
            if bytes_read == 0 {
                break; // EOF
            }

            let line_start_offset = current_offset;
            current_offset += bytes_read as u64;
            local_line_number += 1;
            current_line_number.store(local_line_number, Ordering::Relaxed);
            current_file_offset.store(current_offset, Ordering::Relaxed);

            let line = line_buf.trim();
            if line.is_empty() {
                continue;
            }

            // Generate variations if needed
            let phrases: Vec<String> = if with_variations {
                generate_variations(line)
            } else {
                vec![line.to_string()]
            };

            for phrase in phrases {
                // Quick dedup check for batch mode
                if use_batch_mode {
                    // Check global seen set
                    let seen_read = global_seen.read().unwrap();
                    if seen_read.contains(&phrase) {
                        continue;
                    }
                    drop(seen_read);
                }

                batch.push(phrase);

                // Process batch when full
                if batch.len() >= batch_sz {
                    batch_num += 1;
                    
                    // Dedup within batch
                    let mut batch_seen = HashSet::new();
                    batch.retain(|p| batch_seen.insert(p.clone()));

                    // Also dedup against global seen (for batch mode)
                    if use_batch_mode {
                        let mut seen_write = global_seen.write().unwrap();
                        batch.retain(|p| seen_write.insert(p.clone()));
                    }

                    let batch_size_actual = batch.len();
                    log::debug!("Processing batch {} with {} passphrases", batch_num, batch_size_actual);

                    // Process this batch in parallel
                    process_batch(
                        &batch,
                        &scanner,
                        &known_db,
                        &electrum_client,
                        &results,
                        &pending_matches,
                        &checked,
                        &bloom_hits,
                        &fp64_hits,
                        &matches_found,
                        &known_skipped,
                        &new_matches,
                        &progress,
                        &multi_hash_config,
                    );

                    total_processed.fetch_add(batch_size_actual as u64, Ordering::Relaxed);
                    batch.clear();

                    // Check if we should save progress (time-based)
                    let should_save = {
                        let last_save = last_save_time.lock().unwrap();
                        last_save.elapsed().as_secs() >= save_interval
                    };
                    if should_save {
                        save_progress(file_idx, line_start_offset, local_line_number)?;
                        *last_save_time.lock().unwrap() = Instant::now();
                    }
                }
            }
        }
    }

    // Process remaining batch
    if !batch.is_empty() && !shutdown_requested {
        batch_num += 1;
        
        // Dedup within batch
        let mut batch_seen = HashSet::new();
        batch.retain(|p| batch_seen.insert(p.clone()));

        // Also dedup against global seen (for batch mode)
        if use_batch_mode {
            let mut seen_write = global_seen.write().unwrap();
            batch.retain(|p| seen_write.insert(p.clone()));
        }

        let batch_size_actual = batch.len();
        log::debug!("Processing final batch {} with {} passphrases", batch_num, batch_size_actual);

        process_batch(
            &batch,
            &scanner,
            &known_db,
            &electrum_client,
            &results,
            &pending_matches,
            &checked,
            &bloom_hits,
            &fp64_hits,
            &matches_found,
            &known_skipped,
            &new_matches,
            &progress,
            &multi_hash_config,
        );

        total_processed.fetch_add(batch_size_actual as u64, Ordering::Relaxed);
    }

    progress.finish();

    // Save final progress if shutdown was requested
    if shutdown_requested {
        let file_idx = current_file_index.load(Ordering::Relaxed) as usize;
        let file_offset = current_file_offset.load(Ordering::Relaxed);
        let line_num = current_line_number.load(Ordering::Relaxed);
        save_progress(file_idx, file_offset, line_num)?;
        log::warn!("Scan interrupted. Use --resume to continue from saved progress.");
    } else {
        // Delete progress file on successful completion
        if progress_file.exists() {
            std::fs::remove_file(&progress_file).ok();
            log::info!("Scan completed. Progress file removed.");
        }
    }

    log::info!("Processed {} batches, {} total unique passphrases", batch_num, total_processed.load(Ordering::Relaxed));

    // Query balances for matches if electrs is configured
    let final_results = if let Some(ref client) = electrum_client {
        let pending = pending_matches.lock().unwrap().clone();
        if !pending.is_empty() {
            log::info!("Querying balances for {} matches via electrs...", pending.len());

            // Create tokio runtime for async queries
            let rt = tokio::runtime::Runtime::new()?;

            // Extract all hash160s for batch query
            let hash160s: Vec<[u8; 20]> = pending.iter().map(|m| m.hash160).collect();

            // Progress bar for balance queries
            let balance_progress = ProgressBar::new(hash160s.len() as u64);
            balance_progress.set_style(
                ProgressStyle::default_bar()
                    .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} querying balances...")
                    .unwrap()
                    .progress_chars("#>-"),
            );

            // Query balances in batch with progress updates
            let balances = rt.block_on(async {
                let mut results = Vec::with_capacity(hash160s.len());

                for hash160 in hash160s.iter() {
                    let balance = client.get_all_balances(hash160).await;
                    results.push(balance);
                    balance_progress.inc(1);
                }

                results
            });

            balance_progress.finish();

            // Combine results
            let mut results_with_balances = Vec::new();
            for (mut match_result, balance) in pending.into_iter().zip(balances.into_iter()) {
                match_result.balances = Some(balance);

                if match_result.has_balance() {
                    eprintln!("\n🎉 MATCH WITH BALANCE:\n{}", match_result.format());
                }

                results_with_balances.push(match_result);
            }

            results_with_balances
        } else {
            Vec::new()
        }
    } else {
        results.lock().unwrap().clone()
    };

    let elapsed = start.elapsed();
    let total_checked = checked.load(Ordering::Relaxed);
    let rate = total_checked as f64 / elapsed.as_secs_f64();

    log::info!("=== Scan Complete ===");
    log::info!("Total checked: {}", total_checked);
    log::info!("Known skipped: {}", known_skipped.load(Ordering::Relaxed));
    log::info!("Bloom hits: {}", bloom_hits.load(Ordering::Relaxed));
    log::info!("FP64 hits: {}", fp64_hits.load(Ordering::Relaxed));
    log::info!("Matches found: {}", matches_found.load(Ordering::Relaxed));
    log::info!("New matches added to known DB: {}", new_matches.load(Ordering::Relaxed));
    log::info!("Time elapsed: {:?}", elapsed);
    log::info!("Rate: {:.2} passphrases/sec", rate);

    // Count matches with balance and write to separate file
    if electrum_client.is_some() {
        let matches_with_balance: Vec<_> = final_results.iter().filter(|r| r.has_balance()).collect();
        log::info!("Matches with balance: {}", matches_with_balance.len());

        // Write matches with balance to separate file
        if !matches_with_balance.is_empty() {
            let file = File::create(&balance_output_path)?;
            let mut writer = BufWriter::new(file);

            for result in matches_with_balance.iter() {
                writeln!(writer, "{}", result.format())?;
            }

            log::info!("🎉 Matches with balance written to {:?}", balance_output_path);
        }
    }

    // Write all results to file
    if !final_results.is_empty() {
        let file = File::create(&output_path)?;
        let mut writer = BufWriter::new(file);

        for result in final_results.iter() {
            writeln!(writer, "{}", result.format())?;
        }

        log::info!("All results written to {:?}", output_path);
    }

    Ok(())
}

fn run_generate(
    input_path: PathBuf,
    output_path: PathBuf,
    min_len: usize,
    max_len: usize,
    word_combos: bool,
    max_words: usize,
) -> Result<()> {
    log::info!("Generating passphrases from {:?}...", input_path);

    let content = std::fs::read_to_string(&input_path)
        .with_context(|| format!("Failed to read {:?}", input_path))?;

    let mut passphrases: HashSet<String> = HashSet::new();

    // Split by common sentence delimiters
    let sentence_delimiters = ['.', '!', '?', '\n', ';', ':'];

    // Extract sentences
    let mut current = String::new();
    for ch in content.chars() {
        if sentence_delimiters.contains(&ch) {
            let sentence = current.trim().to_string();
            if sentence.len() >= min_len && sentence.len() <= max_len {
                passphrases.insert(sentence);
            }
            current.clear();
        } else {
            current.push(ch);
        }
    }

    // Don't forget the last segment
    let sentence = current.trim().to_string();
    if sentence.len() >= min_len && sentence.len() <= max_len {
        passphrases.insert(sentence);
    }

    log::info!("Found {} sentences/phrases", passphrases.len());

    // Extract individual lines
    for line in content.lines() {
        let line = line.trim();
        if line.len() >= min_len && line.len() <= max_len {
            passphrases.insert(line.to_string());
        }
    }

    log::info!("Total after lines: {} unique phrases", passphrases.len());

    // Word combinations
    if word_combos {
        log::info!("Generating word combinations (max {} words)...", max_words);

        // Extract words
        let words: Vec<&str> = content
            .split(|c: char| !c.is_alphanumeric())
            .filter(|w| w.len() >= 2)
            .collect();

        let unique_words: HashSet<_> = words.iter().copied().collect();
        let unique_words: Vec<_> = unique_words.into_iter().collect();

        log::info!("Found {} unique words", unique_words.len());

        // Generate 2-word, 3-word, ... combinations (limited for performance)
        let max_combos = 1_000_000usize;
        let mut combo_count = 0;

        // Single words
        for word in &unique_words {
            if word.len() >= min_len && word.len() <= max_len {
                passphrases.insert(word.to_string());
                combo_count += 1;
                if combo_count >= max_combos {
                    break;
                }
            }
        }

        // Two-word combinations (space separated)
        if max_words >= 2 && combo_count < max_combos {
            'outer: for i in 0..unique_words.len().min(1000) {
                for j in 0..unique_words.len().min(1000) {
                    if i != j {
                        let combo = format!("{} {}", unique_words[i], unique_words[j]);
                        if combo.len() >= min_len && combo.len() <= max_len {
                            passphrases.insert(combo);
                            combo_count += 1;
                            if combo_count >= max_combos {
                                break 'outer;
                            }
                        }
                    }
                }
            }
        }

        log::info!("Generated {} word combinations", combo_count);
    }

    // Write output
    log::info!("Writing {} passphrases to {:?}...", passphrases.len(), output_path);

    let file = File::create(&output_path)?;
    let mut writer = BufWriter::new(file);

    for phrase in &passphrases {
        writeln!(writer, "{}", phrase)?;
    }

    log::info!("Done!");

    Ok(())
}

fn run_test(
    passphrase: String,
    data_dir: PathBuf,
    electrs_addr: Option<String>,
    hash_algorithm: HashAlgorithm,
    iterations: u32,
) -> Result<()> {
    println!("Testing passphrase: \"{}\"", passphrase);
    println!();

    // Show derivation method
    let derivation_info = HashDerivationInfo {
        algorithm: hash_algorithm,
        iterations,
    };
    println!("Derivation method: {}", derivation_info.format());
    println!();

    // Derive brain wallet with specified algorithm and iterations
    let (privkey, pubkey, hash160, addresses) = derive_brain_wallet_with_hash(
        &passphrase,
        hash_algorithm,
        iterations,
    )?;

    println!("Private Key (hex): {}", hex::encode(privkey));
    println!("Private Key (WIF): {}", private_key_to_wif(&privkey));
    println!("Public Key:        {}", hex::encode(pubkey));
    println!("HASH160:           {}", hex::encode(hash160));
    println!();
    println!("Addresses:");
    println!("  P2PKH (Legacy):       {}", addresses.p2pkh);
    println!("  P2WPKH (SegWit):      {}", addresses.p2wpkh);
    println!("  P2SH-P2WPKH (Nested): {}", addresses.p2sh_p2wpkh);
    println!();

    // Load scanner
    println!("Loading database...");
    let scanner = CollisionScanner::new(&data_dir, false)?;

    // Check
    let (bloom_hit, fp64_hit, record) = scanner.check(&hash160);

    println!("Bloom filter: {}", if bloom_hit { "HIT" } else { "MISS" });
    println!("FP64 table:   {}", if fp64_hit { "HIT" } else { "MISS" });

    if let Some(record) = record {
        println!();
        println!("=== MATCH FOUND! ===");
        println!("First Seen Height: {}", record.first_seen_height);
        println!("Pubkey Type: {:?}", record.pubkey_type);
        println!("This passphrase corresponds to a real Bitcoin address!");
    } else {
        println!();
        println!("No match found in the database.");
    }

    // Query balance via electrs if configured
    if let Some(addr) = electrs_addr {
        println!();
        println!("Querying balances via electrs ({})...", addr);

        let client = ElectrumClient::new(&addr);
        let rt = tokio::runtime::Runtime::new()?;
        let balances = rt.block_on(client.get_all_balances(&hash160));

        println!();
        println!("Balances:");
        println!("{}", balances.format());

        if balances.has_balance() {
            println!();
            println!("🎉 THIS ADDRESS HAS BALANCE!");
        }
    }

    Ok(())
}

/// Import brain wallet records from matches.txt format
fn run_import(input_path: PathBuf, database_path: PathBuf) -> Result<()> {
    log::info!("Importing brain wallet records from {:?}...", input_path);

    let mut db = KnownBrainWalletsDb::open(&database_path)?;
    let initial_count = db.len();

    let content = std::fs::read_to_string(&input_path)
        .with_context(|| format!("Failed to read {:?}", input_path))?;

    // Parse matches.txt format
    let mut imported = 0;
    let mut duplicates = 0;

    // Temporary fields for building a record
    let mut passphrase = String::new();
    let mut private_key_hex = String::new();
    let mut private_key_wif = String::new();
    let mut public_key_hex = String::new();
    let mut hash160_hex = String::new();
    let mut address_p2pkh = String::new();
    let mut address_p2wpkh = String::new();
    let mut address_p2sh_p2wpkh = String::new();
    let mut first_seen_height: u32 = 0;
    let mut pubkey_type = String::new();

    for line in content.lines() {
        let line = line.trim();

        if line.starts_with("=== MATCH FOUND ===") {
            // Start of a new record - save previous if exists
            if !hash160_hex.is_empty() {
                let record = KnownBrainWalletsDb::create_record(
                    passphrase.clone(),
                    private_key_hex.clone(),
                    private_key_wif.clone(),
                    public_key_hex.clone(),
                    hash160_hex.clone(),
                    address_p2pkh.clone(),
                    address_p2wpkh.clone(),
                    address_p2sh_p2wpkh.clone(),
                    first_seen_height,
                    pubkey_type.clone(),
                );
                if db.insert(record) {
                    imported += 1;
                } else {
                    duplicates += 1;
                }
            }

            // Reset for new record
            passphrase.clear();
            private_key_hex.clear();
            private_key_wif.clear();
            public_key_hex.clear();
            hash160_hex.clear();
            address_p2pkh.clear();
            address_p2wpkh.clear();
            address_p2sh_p2wpkh.clear();
            first_seen_height = 0;
            pubkey_type.clear();
        } else if let Some(value) = line.strip_prefix("Passphrase: ") {
            passphrase = value.to_string();
        } else if let Some(value) = line.strip_prefix("Private Key (hex): ") {
            private_key_hex = value.to_string();
        } else if let Some(value) = line.strip_prefix("Private Key (WIF): ") {
            private_key_wif = value.to_string();
        } else if let Some(value) = line.strip_prefix("Public Key: ") {
            public_key_hex = value.to_string();
        } else if let Some(value) = line.strip_prefix("HASH160: ") {
            hash160_hex = value.to_string();
        } else if let Some(value) = line.strip_prefix("P2PKH (Legacy):") {
            address_p2pkh = value.trim().to_string();
        } else if let Some(value) = line.strip_prefix("P2WPKH (SegWit):") {
            address_p2wpkh = value.trim().to_string();
        } else if let Some(value) = line.strip_prefix("P2SH-P2WPKH (Nested):") {
            address_p2sh_p2wpkh = value.trim().to_string();
        } else if let Some(value) = line.strip_prefix("First Seen Height: ") {
            first_seen_height = value.parse().unwrap_or(0);
        } else if let Some(value) = line.strip_prefix("Pubkey Type: ") {
            pubkey_type = value.to_string();
        }
    }

    // Don't forget the last record
    if !hash160_hex.is_empty() {
        let record = KnownBrainWalletsDb::create_record(
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
        );
        if db.insert(record) {
            imported += 1;
        } else {
            duplicates += 1;
        }
    }

    db.save()?;

    log::info!("=== Import Complete ===");
    log::info!("Initial records in database: {}", initial_count);
    log::info!("New records imported: {}", imported);
    log::info!("Duplicates skipped: {}", duplicates);
    log::info!("Total records in database: {}", db.len());

    Ok(())
}

/// List known brain wallets
fn run_list(database_path: PathBuf, format: String, limit: usize) -> Result<()> {
    let db = KnownBrainWalletsDb::open(&database_path)?;

    if db.is_empty() {
        println!("No known brain wallets in database.");
        return Ok(());
    }

    let records: Vec<_> = if limit == 0 {
        db.all_records().collect()
    } else {
        db.all_records().take(limit).collect()
    };

    match format.as_str() {
        "json" => {
            for record in &records {
                println!("{}", serde_json::to_string(record)?);
            }
        }
        "csv" => {
            println!("passphrase,hash160,address_p2pkh,first_seen_height,pubkey_type");
            for record in &records {
                println!(
                    "{},{},{},{},{}",
                    record.passphrase.replace(',', "\\,"),
                    record.hash160_hex,
                    record.address_p2pkh,
                    record.first_seen_height,
                    record.pubkey_type
                );
            }
        }
        _ => {
            // Table format
            println!("{:=<100}", "");
            println!("{:<40} {:>15} {:>35}", "Passphrase", "Height", "P2PKH Address");
            println!("{:=<100}", "");
            for record in &records {
                let passphrase_display = if record.passphrase.len() > 38 {
                    format!("{}...", &record.passphrase[..35])
                } else {
                    record.passphrase.clone()
                };
                println!(
                    "{:<40} {:>15} {:>35}",
                    passphrase_display,
                    record.first_seen_height,
                    record.address_p2pkh
                );
            }
            println!("{:=<100}", "");
            println!("Total: {} records", db.len());
            if limit > 0 && db.len() > limit {
                println!("(Showing first {} of {} records, use --limit 0 to show all)", limit, db.len());
            }
        }
    }

    Ok(())
}

/// Show statistics about known brain wallets database
fn run_stats(database_path: PathBuf) -> Result<()> {
    let db = KnownBrainWalletsDb::open(&database_path)?;
    let stats = db.stats();

    println!("=== Known Brain Wallets Database Statistics ===");
    println!("Database path: {:?}", database_path);
    println!("Total records: {}", stats.total_records);
    println!("Unique passphrases: {}", stats.unique_passphrases);
    if stats.total_records > 0 {
        println!("Earliest block height: {}", stats.earliest_block_height);
        println!("Latest block height: {}", stats.latest_block_height);
    }

    Ok(())
}

/// Export known brain wallets to a file
fn run_export(database_path: PathBuf, output_path: PathBuf, format: String) -> Result<()> {
    let db = KnownBrainWalletsDb::open(&database_path)?;

    if db.is_empty() {
        log::warn!("No records to export.");
        return Ok(());
    }

    log::info!("Exporting {} records to {:?}...", db.len(), output_path);

    let file = File::create(&output_path)?;
    let mut writer = BufWriter::new(file);

    match format.as_str() {
        "json" => {
            let records: Vec<_> = db.all_records().collect();
            let json = serde_json::to_string_pretty(&records)?;
            writeln!(writer, "{}", json)?;
        }
        "csv" => {
            writeln!(writer, "passphrase,private_key_hex,private_key_wif,public_key_hex,hash160,address_p2pkh,address_p2wpkh,address_p2sh_p2wpkh,first_seen_height,pubkey_type")?;
            for record in db.all_records() {
                writeln!(
                    writer,
                    "\"{}\",{},{},{},{},{},{},{},{},{}",
                    record.passphrase.replace('"', "\"\""),
                    record.private_key_hex,
                    record.private_key_wif,
                    record.public_key_hex,
                    record.hash160_hex,
                    record.address_p2pkh,
                    record.address_p2wpkh,
                    record.address_p2sh_p2wpkh,
                    record.first_seen_height,
                    record.pubkey_type
                )?;
            }
        }
        _ => {
            // txt format (matches.txt compatible)
            for record in db.all_records() {
                writeln!(writer, "=== MATCH FOUND ===")?;
                writeln!(writer, "Passphrase: {}", record.passphrase)?;
                writeln!(writer, "Private Key (hex): {}", record.private_key_hex)?;
                writeln!(writer, "Private Key (WIF): {}", record.private_key_wif)?;
                writeln!(writer, "Public Key: {}", record.public_key_hex)?;
                writeln!(writer, "HASH160: {}", record.hash160_hex)?;
                writeln!(writer)?;
                writeln!(writer, "Addresses:")?;
                writeln!(writer, "  P2PKH (Legacy):       {}", record.address_p2pkh)?;
                writeln!(writer, "  P2WPKH (SegWit):      {}", record.address_p2wpkh)?;
                writeln!(writer, "  P2SH-P2WPKH (Nested): {}", record.address_p2sh_p2wpkh)?;
                writeln!(writer)?;
                writeln!(writer, "First Seen Height: {}", record.first_seen_height)?;
                writeln!(writer, "Pubkey Type: {}", record.pubkey_type)?;
                writeln!(writer, "==================")?;
                writeln!(writer)?;
            }
        }
    }

    writer.flush()?;
    log::info!("Export complete.");

    Ok(())
}

fn main() -> Result<()> {
    // Initialize logger
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_millis()
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            input,
            data_dir,
            output,
            threads,
            skip_bloom,
            with_variations,
            electrs,
            balance_output,
            known_db,
            no_known_db,
            batch_size,
            resume,
            progress_file,
            save_interval,
            multi_hash,
            hash_algorithms,
            max_iterations,
        } => {
            run_scan(
                input,
                data_dir,
                output,
                threads,
                skip_bloom,
                with_variations,
                electrs,
                balance_output,
                known_db,
                no_known_db,
                batch_size,
                resume,
                progress_file,
                save_interval,
                multi_hash,
                hash_algorithms,
                max_iterations,
            )?;
        }
        Commands::Generate {
            input,
            output,
            min_len,
            max_len,
            word_combos,
            max_words,
        } => {
            run_generate(input, output, min_len, max_len, word_combos, max_words)?;
        }
        Commands::Test { passphrase, data_dir, electrs, hash_algorithm, iterations } => {
            run_test(passphrase, data_dir, electrs, hash_algorithm, iterations)?;
        }
        Commands::Import { input, database } => {
            run_import(input, database)?;
        }
        Commands::List { database, format, limit } => {
            run_list(database, format, limit)?;
        }
        Commands::Stats { database } => {
            run_stats(database)?;
        }
        Commands::Export { database, output, format } => {
            run_export(database, output, format)?;
        }
    }

    Ok(())
}

