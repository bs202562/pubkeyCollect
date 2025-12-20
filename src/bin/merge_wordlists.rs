//! Wordlist Merger - Merge and deduplicate password files
//!
//! This tool scans a directory for password/wordlist files,
//! merges them, removes duplicates, and outputs a single file.

use anyhow::{Context, Result};
use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::path::PathBuf;
use walkdir::WalkDir;

/// Wordlist Merger - Merge and deduplicate password files
#[derive(Parser)]
#[command(name = "merge-wordlists")]
#[command(about = "Merge and deduplicate password/wordlist files from a directory")]
struct Cli {
    /// Input directory containing password files
    #[arg(short, long)]
    input: PathBuf,

    /// Output file for merged wordlist
    #[arg(short, long, default_value = "merged_wordlist.txt")]
    output: PathBuf,

    /// File extensions to include (comma-separated, e.g., "txt,lst,dic")
    /// If not specified, includes common wordlist extensions
    #[arg(short, long)]
    extensions: Option<String>,

    /// Minimum line length to include (default: 1)
    #[arg(long, default_value = "1")]
    min_len: usize,

    /// Maximum line length to include (default: 256)
    #[arg(long, default_value = "256")]
    max_len: usize,

    /// Sort output alphabetically
    #[arg(long)]
    sort: bool,

    /// Sort by line length
    #[arg(long)]
    sort_by_length: bool,

    /// Skip binary files (files with null bytes)
    #[arg(long, default_value = "true")]
    skip_binary: bool,

    /// Show progress
    #[arg(long, default_value = "true")]
    progress: bool,

    /// Trim whitespace from lines
    #[arg(long, default_value = "true")]
    trim: bool,

    /// Skip empty lines
    #[arg(long, default_value = "true")]
    skip_empty: bool,
}

/// Default extensions to look for
const DEFAULT_EXTENSIONS: &[&str] = &[
    "txt", "lst", "dic", "wordlist", "words", "passwords", "pass", "pwd",
];

/// Check if a file is likely binary by looking for null bytes
fn is_binary_file(path: &PathBuf) -> bool {
    if let Ok(file) = File::open(path) {
        let mut reader = BufReader::new(file);
        // Check first 8KB for null bytes
        let mut buffer = [0u8; 8192];
        if let Ok(bytes_read) = reader.read(&mut buffer) {
            return buffer[..bytes_read].contains(&0);
        }
    }
    false
}

/// Get file extension in lowercase
fn get_extension(path: &PathBuf) -> Option<String> {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_lowercase())
}

fn main() -> Result<()> {
    // Initialize logger
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_millis()
        .init();

    let cli = Cli::parse();

    log::info!("Wordlist Merger");
    log::info!("===============");
    log::info!("Input directory: {:?}", cli.input);
    log::info!("Output file: {:?}", cli.output);

    // Parse extensions
    let extensions: HashSet<String> = if let Some(ref ext_str) = cli.extensions {
        ext_str
            .split(',')
            .map(|s| s.trim().to_lowercase())
            .collect()
    } else {
        DEFAULT_EXTENSIONS.iter().map(|s| s.to_string()).collect()
    };

    log::info!("Extensions to include: {:?}", extensions);

    // Collect all matching files
    log::info!("Scanning directory for wordlist files...");
    let mut files: Vec<PathBuf> = Vec::new();

    for entry in WalkDir::new(&cli.input)
        .follow_links(true)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path().to_path_buf();

        // Skip directories
        if path.is_dir() {
            continue;
        }

        // Check extension
        if let Some(ext) = get_extension(&path) {
            if extensions.contains(&ext) || extensions.is_empty() {
                files.push(path);
            }
        } else if extensions.is_empty() {
            // Include files without extension if no specific extensions are set
            files.push(path);
        }
    }

    log::info!("Found {} files to process", files.len());

    if files.is_empty() {
        log::warn!("No files found matching the criteria.");
        return Ok(());
    }

    // Progress bar for file processing
    let progress = if cli.progress {
        let pb = ProgressBar::new(files.len() as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} files ({msg})")
                .unwrap()
                .progress_chars("#>-"),
        );
        Some(pb)
    } else {
        None
    };

    // Collect all unique lines
    let mut unique_lines: HashSet<String> = HashSet::new();
    let mut total_lines: u64 = 0;
    let mut skipped_files: u64 = 0;
    let mut processed_files: u64 = 0;

    for file_path in &files {
        if let Some(ref pb) = progress {
            pb.set_message(format!("{} unique", unique_lines.len()));
        }

        // Skip binary files if requested
        if cli.skip_binary && is_binary_file(file_path) {
            log::debug!("Skipping binary file: {:?}", file_path);
            skipped_files += 1;
            if let Some(ref pb) = progress {
                pb.inc(1);
            }
            continue;
        }

        // Try to read the file
        let file = match File::open(file_path) {
            Ok(f) => f,
            Err(e) => {
                log::warn!("Failed to open {:?}: {}", file_path, e);
                skipped_files += 1;
                if let Some(ref pb) = progress {
                    pb.inc(1);
                }
                continue;
            }
        };

        let reader = BufReader::new(file);

        for line in reader.lines() {
            match line {
                Ok(mut line_content) => {
                    total_lines += 1;

                    // Trim if requested
                    if cli.trim {
                        line_content = line_content.trim().to_string();
                    }

                    // Skip empty lines if requested
                    if cli.skip_empty && line_content.is_empty() {
                        continue;
                    }

                    // Check length constraints
                    if line_content.len() >= cli.min_len && line_content.len() <= cli.max_len {
                        unique_lines.insert(line_content);
                    }
                }
                Err(e) => {
                    // Skip lines with encoding errors (common in binary files)
                    log::trace!("Skipping line with encoding error in {:?}: {}", file_path, e);
                }
            }
        }

        processed_files += 1;
        if let Some(ref pb) = progress {
            pb.inc(1);
        }
    }

    if let Some(ref pb) = progress {
        pb.finish_with_message(format!("{} unique lines", unique_lines.len()));
    }

    log::info!("=== Processing Summary ===");
    log::info!("Files processed: {}", processed_files);
    log::info!("Files skipped: {}", skipped_files);
    log::info!("Total lines read: {}", total_lines);
    log::info!("Unique lines: {}", unique_lines.len());
    log::info!(
        "Duplicates removed: {}",
        total_lines.saturating_sub(unique_lines.len() as u64)
    );

    // Convert to vec for sorting
    let mut lines: Vec<String> = unique_lines.into_iter().collect();

    // Sort if requested
    if cli.sort_by_length {
        log::info!("Sorting by line length...");
        lines.sort_by(|a, b| a.len().cmp(&b.len()));
    } else if cli.sort {
        log::info!("Sorting alphabetically...");
        lines.sort();
    }

    // Write output
    log::info!("Writing output to {:?}...", cli.output);

    // Create parent directories if needed
    if let Some(parent) = cli.output.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create directory {:?}", parent))?;
        }
    }

    let file = File::create(&cli.output)
        .with_context(|| format!("Failed to create output file {:?}", cli.output))?;
    let mut writer = BufWriter::with_capacity(1024 * 1024, file); // 1MB buffer

    // Progress bar for writing
    let write_progress = if cli.progress && lines.len() > 100000 {
        let pb = ProgressBar::new(lines.len() as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} writing...")
                .unwrap()
                .progress_chars("#>-"),
        );
        Some(pb)
    } else {
        None
    };

    for (i, line) in lines.iter().enumerate() {
        writeln!(writer, "{}", line)?;
        if let Some(ref pb) = write_progress {
            if i % 10000 == 0 {
                pb.set_position(i as u64);
            }
        }
    }

    writer.flush()?;

    if let Some(pb) = write_progress {
        pb.finish();
    }

    // Get output file size
    let output_size = fs::metadata(&cli.output)?.len();
    let size_mb = output_size as f64 / (1024.0 * 1024.0);

    log::info!("=== Complete ===");
    log::info!("Output file: {:?}", cli.output);
    log::info!("Total lines: {}", lines.len());
    log::info!("File size: {:.2} MB", size_mb);

    Ok(())
}

