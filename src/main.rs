//! Bitcoin on-chain public key collector CLI

use anyhow::Result;
use clap::{Parser, Subcommand};
use collect_pubkey::{BlockReader, BloomFilter, CpuIndex, Fp64Table, Stats};
use indicatif::{ProgressBar, ProgressStyle};
use log::{error, info};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "collect-pubkey")]
#[command(about = "Bitcoin on-chain public key collector with CPU/GPU storage formats")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Full scan of blockchain from genesis
    Scan {
        /// Path to Bitcoin blocks directory (containing blk*.dat files)
        #[arg(short, long)]
        blocks_dir: PathBuf,

        /// Output directory for generated files
        #[arg(short, long, default_value = "./output")]
        output: PathBuf,

        /// Start height (default: 0)
        #[arg(long, default_value = "0")]
        start_height: u32,

        /// End height (default: latest)
        #[arg(long)]
        end_height: Option<u32>,
    },

    /// Incremental update from last processed height
    Update {
        /// Path to Bitcoin blocks directory
        #[arg(short, long)]
        blocks_dir: PathBuf,

        /// Output directory
        #[arg(short, long, default_value = "./output")]
        output: PathBuf,
    },

    /// Rebuild GPU formats (Bloom Filter + FP64) from RocksDB
    RebuildGpu {
        /// Output directory
        #[arg(short, long, default_value = "./output")]
        output: PathBuf,
    },

    /// Query a public key by HASH160
    Query {
        /// HASH160 in hex format
        #[arg(long)]
        hash160: String,

        /// Output directory
        #[arg(short, long, default_value = "./output")]
        output: PathBuf,
    },

    /// Display statistics
    Stats {
        /// Output directory
        #[arg(short, long, default_value = "./output")]
        output: PathBuf,
    },
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            blocks_dir,
            output,
            start_height,
            end_height,
        } => {
            info!("Starting full scan from height {}", start_height);
            run_scan(&blocks_dir, &output, start_height, end_height)?;
        }
        Commands::Update { blocks_dir, output } => {
            info!("Starting incremental update");
            run_update(&blocks_dir, &output)?;
        }
        Commands::RebuildGpu { output } => {
            info!("Rebuilding GPU formats");
            run_rebuild_gpu(&output)?;
        }
        Commands::Query { hash160, output } => {
            run_query(&hash160, &output)?;
        }
        Commands::Stats { output } => {
            run_stats(&output)?;
        }
    }

    Ok(())
}

fn run_scan(
    blocks_dir: &PathBuf,
    output: &PathBuf,
    start_height: u32,
    end_height: Option<u32>,
) -> Result<()> {
    // Create output directory
    std::fs::create_dir_all(output)?;

    // Initialize storage
    let db_path = output.join("pubkey.rocksdb");
    let mut cpu_index = CpuIndex::open(&db_path)?;

    // Initialize block reader
    let reader = BlockReader::new(blocks_dir)?;
    let max_height = end_height.unwrap_or_else(|| reader.get_max_height());

    info!(
        "Scanning blocks from {} to {}",
        start_height, max_height
    );

    // Create progress bar
    let pb = ProgressBar::new((max_height - start_height + 1) as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} blocks ({eta})")?
            .progress_chars("#>-"),
    );

    // Collect pubkeys for GPU formats
    let mut all_hash160s: Vec<[u8; 20]> = Vec::new();

    // Process blocks
    for height in start_height..=max_height {
        if let Some(block) = reader.read_block(height)? {
            let pubkeys = collect_pubkey::extractor::extract_pubkeys_from_block(&block, height)?;

            for (canonical_pubkey, pubkey_type, seen_height) in pubkeys {
                let hash160 = canonical_pubkey.hash160();

                // Insert into RocksDB (only if new or lower height)
                if cpu_index.insert_if_new(&hash160, &canonical_pubkey, pubkey_type, seen_height)? {
                    all_hash160s.push(hash160);
                }
            }
        }

        pb.inc(1);
    }

    pb.finish_with_message("Block scanning complete");

    // Update last processed height
    cpu_index.set_last_height(max_height)?;

    info!("Collected {} unique public keys", all_hash160s.len());

    // Build GPU formats
    info!("Building Bloom filter...");
    let bloom = BloomFilter::new(&all_hash160s)?;
    bloom.save(&output.join("bloom.bin"))?;

    info!("Building FP64 table...");
    let fp64 = Fp64Table::new(&all_hash160s)?;
    fp64.save(&output.join("fp64.bin"))?;

    // Generate stats
    let stats = Stats::generate(&cpu_index, &bloom, &fp64)?;
    stats.save(&output.join("stats.json"))?;

    info!("Scan complete. Stats: {:?}", stats);

    Ok(())
}

fn run_update(blocks_dir: &PathBuf, output: &PathBuf) -> Result<()> {
    let db_path = output.join("pubkey.rocksdb");
    let mut cpu_index = CpuIndex::open(&db_path)?;

    let last_height = cpu_index.get_last_height()?;
    let start_height = last_height + 1;

    let reader = BlockReader::new(blocks_dir)?;
    let max_height = reader.get_max_height();

    if start_height > max_height {
        info!("Already up to date at height {}", last_height);
        return Ok(());
    }

    info!(
        "Updating from height {} to {}",
        start_height, max_height
    );

    let pb = ProgressBar::new((max_height - start_height + 1) as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} blocks ({eta})")?
            .progress_chars("#>-"),
    );

    let mut new_hash160s: Vec<[u8; 20]> = Vec::new();

    for height in start_height..=max_height {
        if let Some(block) = reader.read_block(height)? {
            let pubkeys = collect_pubkey::extractor::extract_pubkeys_from_block(&block, height)?;

            for (canonical_pubkey, pubkey_type, seen_height) in pubkeys {
                let hash160 = canonical_pubkey.hash160();
                if cpu_index.insert_if_new(&hash160, &canonical_pubkey, pubkey_type, seen_height)? {
                    new_hash160s.push(hash160);
                }
            }
        }

        pb.inc(1);
    }

    pb.finish_with_message("Update complete");

    cpu_index.set_last_height(max_height)?;

    info!("Added {} new public keys", new_hash160s.len());

    // Rebuild GPU formats
    info!("Rebuilding GPU formats...");
    run_rebuild_gpu(output)?;

    Ok(())
}

fn run_rebuild_gpu(output: &PathBuf) -> Result<()> {
    let db_path = output.join("pubkey.rocksdb");
    let cpu_index = CpuIndex::open(&db_path)?;

    info!("Loading all HASH160s from RocksDB...");
    let all_hash160s = cpu_index.get_all_hash160s()?;

    info!("Loaded {} HASH160s", all_hash160s.len());

    info!("Building Bloom filter...");
    let bloom = BloomFilter::new(&all_hash160s)?;
    bloom.save(&output.join("bloom.bin"))?;

    info!("Building FP64 table...");
    let fp64 = Fp64Table::new(&all_hash160s)?;
    fp64.save(&output.join("fp64.bin"))?;

    // Update stats
    let stats = Stats::generate(&cpu_index, &bloom, &fp64)?;
    stats.save(&output.join("stats.json"))?;

    info!("GPU formats rebuilt successfully");

    Ok(())
}

fn run_query(hash160_hex: &str, output: &PathBuf) -> Result<()> {
    let hash160_bytes = hex::decode(hash160_hex)?;
    if hash160_bytes.len() != 20 {
        error!("HASH160 must be 20 bytes (40 hex chars)");
        return Ok(());
    }

    let mut hash160 = [0u8; 20];
    hash160.copy_from_slice(&hash160_bytes);

    let db_path = output.join("pubkey.rocksdb");
    let cpu_index = CpuIndex::open(&db_path)?;

    match cpu_index.get(&hash160)? {
        Some(record) => {
            println!("Found public key:");
            println!("  Type: {:?}", record.pubkey_type);
            println!("  Length: {} bytes", record.pubkey_len);
            println!("  Pubkey: {}", hex::encode(&record.pubkey_raw[..record.pubkey_len as usize]));
            println!("  First seen at height: {}", record.first_seen_height);
        }
        None => {
            println!("Public key not found for HASH160: {}", hash160_hex);
        }
    }

    Ok(())
}

fn run_stats(output: &PathBuf) -> Result<()> {
    let stats_path = output.join("stats.json");
    
    if !stats_path.exists() {
        error!("Stats file not found. Run scan first.");
        return Ok(());
    }

    let stats: Stats = serde_json::from_str(&std::fs::read_to_string(&stats_path)?)?;

    println!("=== Bitcoin Pubkey Collection Statistics ===");
    println!("Total public keys: {}", stats.total_pubkeys);
    println!("Legacy (P2PK/P2PKH): {}", stats.legacy_count);
    println!("SegWit (P2WPKH): {}", stats.segwit_count);
    println!("Taproot (P2TR): {}", stats.taproot_count);
    println!("Last processed height: {}", stats.last_height);
    println!();
    println!("Storage sizes:");
    println!("  RocksDB: {} MB", stats.rocksdb_size_mb);
    println!("  Bloom filter: {} MB", stats.bloom_size_mb);
    println!("  FP64 table: {} MB", stats.fp64_size_mb);

    Ok(())
}
