//! Export all public keys and addresses from the database as a wordlist
//!
//! This program exports:
//! 1. Public key hex strings
//! 2. HASH160 hex strings
//! 3. P2PKH addresses (Legacy, starts with "1")
//! 4. P2WPKH addresses (Native SegWit, starts with "bc1q")
//! 5. P2SH-P2WPKH addresses (Nested SegWit, starts with "3")
//!
//! These can be used as a wordlist to test if someone used an address/pubkey as a brain wallet passphrase.

use anyhow::{Context, Result};
use bitcoin::address::Address;
use bitcoin::key::CompressedPublicKey;
use bitcoin::Network;
use clap::Parser;
use collect_pubkey::storage::cpu_index::{CpuIndex, PubkeyRecord};
use collect_pubkey::PubkeyType;
use indicatif::{ProgressBar, ProgressStyle};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "export-addresses")]
#[command(about = "Export all public keys and addresses from the database as a wordlist")]
struct Cli {
    /// Directory containing the public key database
    #[arg(short, long, default_value = "output")]
    data_dir: PathBuf,

    /// Output file for the wordlist
    #[arg(short, long, default_value = "wordlists/addresses_wordlist.txt")]
    output: PathBuf,

    /// Exclude public key hex strings
    #[arg(long)]
    no_pubkey: bool,

    /// Exclude HASH160 hex strings
    #[arg(long)]
    no_hash160: bool,

    /// Exclude P2PKH addresses (Legacy)
    #[arg(long)]
    no_p2pkh: bool,

    /// Exclude P2WPKH addresses (SegWit)
    #[arg(long)]
    no_p2wpkh: bool,

    /// Exclude P2SH-P2WPKH addresses (Nested SegWit)
    #[arg(long)]
    no_p2sh: bool,

    /// Include case variations (uppercase, lowercase)
    #[arg(long)]
    include_case_variations: bool,

    /// Only export Legacy (compressed) public keys
    #[arg(long)]
    legacy_only: bool,

    /// Maximum number of records to export (0 = all)
    #[arg(long, default_value = "0")]
    limit: usize,
}

/// Derive Bitcoin addresses from a compressed public key
fn derive_addresses(pubkey_bytes: &[u8; 33]) -> Result<(String, String, String)> {
    let compressed_pubkey = CompressedPublicKey::from_slice(pubkey_bytes)
        .context("Failed to parse compressed public key")?;

    // P2PKH (Legacy address starting with "1")
    let p2pkh = Address::p2pkh(compressed_pubkey, Network::Bitcoin);

    // P2WPKH (Native SegWit address starting with "bc1q")
    let p2wpkh = Address::p2wpkh(&compressed_pubkey, Network::Bitcoin);

    // P2SH-P2WPKH (Nested SegWit address starting with "3")
    let p2sh_p2wpkh = Address::p2shwpkh(&compressed_pubkey, Network::Bitcoin);

    Ok((p2pkh.to_string(), p2wpkh.to_string(), p2sh_p2wpkh.to_string()))
}

/// Compute HASH160 from public key bytes
fn compute_hash160(pubkey: &[u8]) -> [u8; 20] {
    let sha256_hash = Sha256::digest(pubkey);
    let ripemd_hash = Ripemd160::digest(&sha256_hash);
    let mut hash160 = [0u8; 20];
    hash160.copy_from_slice(&ripemd_hash);
    hash160
}

fn main() -> Result<()> {
    // Initialize logger
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_millis()
        .init();

    let cli = Cli::parse();

    log::info!("Opening RocksDB from {:?}...", cli.data_dir);
    let rocksdb_path = cli.data_dir.join("pubkey.rocksdb");
    let index = CpuIndex::open(&rocksdb_path)?;

    log::info!("Fetching all HASH160 keys...");
    let all_hash160s = index.get_all_hash160s()?;
    let total_records = all_hash160s.len();
    log::info!("Found {} records in database", total_records);

    let limit = if cli.limit > 0 { cli.limit } else { total_records };
    let records_to_process = total_records.min(limit);
    log::info!("Will process {} records", records_to_process);

    // Create output directory if needed
    if let Some(parent) = cli.output.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let file = File::create(&cli.output)?;
    let mut writer = BufWriter::new(file);

    // Use HashSet for deduplication
    let mut seen: HashSet<String> = HashSet::new();
    let mut exported_count = 0u64;

    // Progress bar
    let progress = ProgressBar::new(records_to_process as u64);
    progress.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({per_sec})")
            .unwrap()
            .progress_chars("#>-"),
    );

    for (i, hash160) in all_hash160s.iter().enumerate() {
        if i >= records_to_process {
            break;
        }

        // Get the record
        let record = match index.get(hash160)? {
            Some(r) => r,
            None => {
                progress.inc(1);
                continue;
            }
        };

        // Filter by type if legacy_only
        if cli.legacy_only && record.pubkey_type != PubkeyType::Legacy {
            progress.inc(1);
            continue;
        }

        // Get public key bytes based on length
        let pubkey_bytes: Vec<u8> = if record.pubkey_len == 33 {
            record.pubkey_raw.to_vec()
        } else if record.pubkey_len == 32 {
            // Taproot x-only pubkey, skip for address derivation
            progress.inc(1);
            continue;
        } else {
            progress.inc(1);
            continue;
        };

        // Convert to array for address derivation
        let mut pubkey_array = [0u8; 33];
        pubkey_array.copy_from_slice(&pubkey_bytes);

        // Derive addresses
        let (p2pkh, p2wpkh, p2sh_p2wpkh) = match derive_addresses(&pubkey_array) {
            Ok(addrs) => addrs,
            Err(_) => {
                progress.inc(1);
                continue;
            }
        };

        // Collect entries to export
        let mut entries: Vec<String> = Vec::new();

        // Public key hex
        if !cli.no_pubkey {
            let pubkey_hex = hex::encode(&pubkey_bytes);
            entries.push(pubkey_hex.clone());
            if cli.include_case_variations {
                entries.push(pubkey_hex.to_uppercase());
            }
        }

        // HASH160 hex
        if !cli.no_hash160 {
            let hash160_hex = hex::encode(hash160);
            entries.push(hash160_hex.clone());
            if cli.include_case_variations {
                entries.push(hash160_hex.to_uppercase());
            }
        }

        // P2PKH address
        if !cli.no_p2pkh {
            entries.push(p2pkh.clone());
            if cli.include_case_variations {
                entries.push(p2pkh.to_lowercase());
                entries.push(p2pkh.to_uppercase());
            }
        }

        // P2WPKH address (already lowercase)
        if !cli.no_p2wpkh {
            entries.push(p2wpkh.clone());
            if cli.include_case_variations {
                entries.push(p2wpkh.to_uppercase());
            }
        }

        // P2SH-P2WPKH address
        if !cli.no_p2sh {
            entries.push(p2sh_p2wpkh.clone());
            if cli.include_case_variations {
                entries.push(p2sh_p2wpkh.to_lowercase());
                entries.push(p2sh_p2wpkh.to_uppercase());
            }
        }

        // Write unique entries
        for entry in entries {
            if seen.insert(entry.clone()) {
                writeln!(writer, "{}", entry)?;
                exported_count += 1;
            }
        }

        progress.inc(1);
    }

    progress.finish();
    writer.flush()?;

    log::info!("=== Export Complete ===");
    log::info!("Records processed: {}", records_to_process);
    log::info!("Unique entries exported: {}", exported_count);
    log::info!("Output file: {:?}", cli.output);

    // Show file size
    let file_size = std::fs::metadata(&cli.output)?.len();
    log::info!("Output file size: {:.2} MB", file_size as f64 / (1024.0 * 1024.0));

    Ok(())
}

