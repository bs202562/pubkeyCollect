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

use anyhow::{Context, Result};
use bitcoin::address::Address;
use bitcoin::key::CompressedPublicKey;
use bitcoin::Network;
use clap::{Parser, Subcommand};
use collect_pubkey::storage::bloom::BloomFilter;
use collect_pubkey::storage::cpu_index::{CpuIndex, PubkeyRecord};
use collect_pubkey::storage::fp64::Fp64Table;
use indicatif::{ProgressBar, ProgressStyle};
use ripemd::Ripemd160;
use secp256k1::{Secp256k1, SecretKey, PublicKey};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use rayon::prelude::*;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as TokioBufReader};
use tokio::net::TcpStream;

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
                        // Wait before retry
                        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
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
fn derive_brain_wallet(passphrase: &str) -> Result<([u8; 32], [u8; 33], [u8; 20], BitcoinAddresses)> {
    // Step 1: SHA256(passphrase) -> 32-byte private key
    let private_key_bytes: [u8; 32] = Sha256::digest(passphrase.as_bytes()).into();

    // Step 2: Derive public key using secp256k1
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&private_key_bytes)
        .context("Failed to create secret key")?;
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

        format!(
            "=== MATCH FOUND ===\n\
             Passphrase: {}\n\
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

fn run_scan(
    input_files: Vec<PathBuf>,
    data_dir: PathBuf,
    output_path: PathBuf,
    threads: Option<usize>,
    skip_bloom: bool,
    with_variations: bool,
    electrs_addr: Option<String>,
    balance_output_path: PathBuf,
) -> Result<()> {
    // Set thread count
    if let Some(t) = threads {
        rayon::ThreadPoolBuilder::new()
            .num_threads(t)
            .build_global()
            .ok();
    }

    // Load scanner
    let scanner = Arc::new(CollisionScanner::new(&data_dir, skip_bloom)?);

    // Collect all passphrases
    log::info!("Reading passphrases from input files...");
    let mut passphrases: Vec<String> = Vec::new();

    for input_path in &input_files {
        let file = File::open(input_path)
            .with_context(|| format!("Failed to open {:?}", input_path))?;
        let reader = BufReader::new(file);

        for line in reader.lines() {
            let line = line?;
            if !line.is_empty() {
                if with_variations {
                    passphrases.extend(generate_variations(&line));
                } else {
                    passphrases.push(line);
                }
            }
        }
    }

    // Remove duplicates
    let original_count = passphrases.len();
    let mut seen = HashSet::new();
    passphrases.retain(|p| seen.insert(p.clone()));
    log::info!(
        "Loaded {} unique passphrases (from {} total)",
        passphrases.len(),
        original_count
    );

    // Progress bar
    let progress = ProgressBar::new(passphrases.len() as u64);
    progress.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({per_sec}) {msg}")
            .unwrap()
            .progress_chars("#>-"),
    );

    // Counters
    let checked = AtomicU64::new(0);
    let bloom_hits = AtomicU64::new(0);
    let fp64_hits = AtomicU64::new(0);
    let matches_found = AtomicU64::new(0);

    // Electrs client (if configured)
    let electrum_client = electrs_addr.as_ref().map(|addr| {
        log::info!("Electrs server configured: {}", addr);
        Arc::new(ElectrumClient::new(addr))
    });

    // Results collector (with hash160 for later balance queries)
    let results: Arc<Mutex<Vec<MatchResult>>> = Arc::new(Mutex::new(Vec::new()));
    // Pending matches that need balance queries
    let pending_matches: Arc<Mutex<Vec<MatchResult>>> = Arc::new(Mutex::new(Vec::new()));

    // Process in parallel
    let start = Instant::now();

    passphrases.par_iter().for_each(|passphrase| {
        // Derive brain wallet
        match derive_brain_wallet(passphrase) {
            Ok((privkey, pubkey, hash160, addresses)) => {
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

                    let result = MatchResult {
                        passphrase: passphrase.clone(),
                        private_key: privkey,
                        public_key: pubkey,
                        hash160,
                        addresses,
                        record,
                        balances: None, // Will be filled later if electrs is configured
                    };

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
                // Skip invalid passphrases (e.g., those that produce invalid private keys)
            }
        }

        progress.inc(1);
    });

    progress.finish();

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

                for (i, hash160) in hash160s.iter().enumerate() {
                    let balance = client.get_all_balances(hash160).await;
                    results.push(balance);
                    balance_progress.inc(1);

                    // Add small delay every 10 queries to avoid overwhelming the server
                    if (i + 1) % 10 == 0 {
                        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
                    }
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
    log::info!("Bloom hits: {}", bloom_hits.load(Ordering::Relaxed));
    log::info!("FP64 hits: {}", fp64_hits.load(Ordering::Relaxed));
    log::info!("Matches found: {}", matches_found.load(Ordering::Relaxed));
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

fn run_test(passphrase: String, data_dir: PathBuf, electrs_addr: Option<String>) -> Result<()> {
    println!("Testing passphrase: \"{}\"", passphrase);
    println!();

    // Derive brain wallet
    let (privkey, pubkey, hash160, addresses) = derive_brain_wallet(&passphrase)?;

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
        } => {
            run_scan(input, data_dir, output, threads, skip_bloom, with_variations, electrs, balance_output)?;
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
        Commands::Test { passphrase, data_dir, electrs } => {
            run_test(passphrase, data_dir, electrs)?;
        }
    }

    Ok(())
}

