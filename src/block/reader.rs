//! Block reader for blk*.dat files
//!
//! This module provides functionality to read and parse Bitcoin blocks
//! directly from the blk*.dat files using memory mapping.

use anyhow::{Context, Result};
use bitcoin::consensus::Decodable;
use bitcoin::Block;
use byteorder::{LittleEndian, ReadBytesExt};
use log::{debug, warn};
use memmap2::Mmap;
use std::cell::RefCell;
use std::collections::HashMap;
use std::fs::File;
use std::io::Cursor;
use std::path::{Path, PathBuf};

use crate::MAINNET_MAGIC;

/// Block location in blk*.dat files
#[derive(Debug, Clone)]
pub struct BlockLocation {
    /// File number (blkXXXXX.dat)
    pub file_num: u32,
    /// Offset within the file
    pub offset: u64,
    /// Block size in bytes
    pub size: u32,
}

/// Block reader that parses blk*.dat files
pub struct BlockReader {
    /// Path to the blocks directory
    blocks_dir: PathBuf,
    /// Memory-mapped blk files (interior mutability for caching)
    mmap_cache: RefCell<HashMap<u32, Mmap>>,
    /// Block index: height -> location
    block_index: HashMap<u32, BlockLocation>,
    /// Maximum known block height
    max_height: u32,
}

impl BlockReader {
    /// Create a new block reader
    pub fn new(blocks_dir: &Path) -> Result<Self> {
        let blocks_dir = blocks_dir.to_path_buf();

        // Build block index by scanning blk*.dat files
        let (block_index, max_height) = Self::build_block_index(&blocks_dir)?;

        Ok(Self {
            blocks_dir,
            mmap_cache: RefCell::new(HashMap::new()),
            block_index,
            max_height,
        })
    }

    /// Get the maximum block height available
    pub fn get_max_height(&self) -> u32 {
        self.max_height
    }

    /// Read a block at the given height
    pub fn read_block(&self, height: u32) -> Result<Option<Block>> {
        let location = match self.block_index.get(&height) {
            Some(loc) => loc.clone(),
            None => return Ok(None),
        };

        // Ensure mmap is loaded
        self.ensure_mmap_loaded(location.file_num)?;

        let cache = self.mmap_cache.borrow();
        let mmap = cache.get(&location.file_num).unwrap();

        let start = location.offset as usize;
        let end = start + location.size as usize;

        if end > mmap.len() {
            warn!("Block at height {} exceeds file bounds", height);
            return Ok(None);
        }

        let block_data = &mmap[start..end];
        let mut cursor = Cursor::new(block_data);

        let block = Block::consensus_decode(&mut cursor)
            .with_context(|| format!("Failed to decode block at height {}", height))?;

        Ok(Some(block))
    }

    /// Ensure mmap is loaded for the given file
    fn ensure_mmap_loaded(&self, file_num: u32) -> Result<()> {
        let mut cache = self.mmap_cache.borrow_mut();
        
        if !cache.contains_key(&file_num) {
            let file_path = self.blk_file_path(file_num);
            let file = File::open(&file_path)
                .with_context(|| format!("Failed to open {:?}", file_path))?;
            let mmap = unsafe { Mmap::map(&file)? };
            cache.insert(file_num, mmap);
        }

        Ok(())
    }

    /// Get the path to a blk file
    fn blk_file_path(&self, file_num: u32) -> PathBuf {
        self.blocks_dir.join(format!("blk{:05}.dat", file_num))
    }

    /// Build block index by scanning all blk*.dat files
    fn build_block_index(blocks_dir: &Path) -> Result<(HashMap<u32, BlockLocation>, u32)> {
        let mut index = HashMap::new();
        let mut max_height = 0u32;
        let mut file_num = 0u32;

        // Track blocks by hash for ordering
        let mut blocks_by_hash: HashMap<[u8; 32], (u32, BlockLocation, [u8; 32])> = HashMap::new();
        let mut genesis_hash: Option<[u8; 32]> = None;

        loop {
            let file_path = blocks_dir.join(format!("blk{:05}.dat", file_num));
            if !file_path.exists() {
                break;
            }

            debug!("Scanning {:?}", file_path);

            let file = File::open(&file_path)?;
            let mmap = unsafe { Mmap::map(&file)? };

            let mut offset = 0usize;

            while offset + 8 < mmap.len() {
                // Read magic bytes
                let mut cursor = Cursor::new(&mmap[offset..offset + 8]);
                let magic = cursor.read_u32::<LittleEndian>()?;

                if magic != MAINNET_MAGIC {
                    offset += 1;
                    continue;
                }

                let block_size = cursor.read_u32::<LittleEndian>()?;

                if offset + 8 + block_size as usize > mmap.len() {
                    break;
                }

                let block_start = offset + 8;
                let block_data = &mmap[block_start..block_start + block_size as usize];

                // Parse block header to get hash and prev_hash
                if block_data.len() >= 80 {
                    let mut header_cursor = Cursor::new(&block_data[..80]);

                    // Skip version (4 bytes)
                    let _version = header_cursor.read_u32::<LittleEndian>()?;

                    // Read prev_block_hash (32 bytes)
                    let mut prev_hash = [0u8; 32];
                    std::io::Read::read_exact(&mut header_cursor, &mut prev_hash)?;

                    // Calculate block hash
                    let header_bytes = &block_data[..80];
                    let hash = Self::double_sha256(header_bytes);

                    let location = BlockLocation {
                        file_num,
                        offset: block_start as u64,
                        size: block_size,
                    };

                    // Check if this is genesis block (prev_hash is all zeros)
                    if prev_hash == [0u8; 32] {
                        genesis_hash = Some(hash);
                    }

                    blocks_by_hash.insert(hash, (file_num, location, prev_hash));
                }

                offset = block_start + block_size as usize;
            }

            file_num += 1;
        }

        // Build height index by following the chain from genesis
        if let Some(genesis) = genesis_hash {
            // Build reverse index: prev_hash -> block_hash
            let mut next_blocks: HashMap<[u8; 32], Vec<[u8; 32]>> = HashMap::new();
            for (hash, (_, _, prev_hash)) in &blocks_by_hash {
                next_blocks.entry(*prev_hash).or_default().push(*hash);
            }

            // BFS from genesis
            let mut current_hash = genesis;
            let mut height = 0u32;

            loop {
                if let Some((_, location, _)) = blocks_by_hash.get(&current_hash) {
                    index.insert(height, location.clone());
                    max_height = height;
                } else {
                    break;
                }

                // Find next block
                let next = next_blocks.get(&current_hash);
                match next {
                    Some(candidates) if !candidates.is_empty() => {
                        // In case of forks, take the first one (simplified)
                        current_hash = candidates[0];
                        height += 1;
                    }
                    _ => break,
                }
            }
        }

        debug!("Indexed {} blocks up to height {}", index.len(), max_height);

        Ok((index, max_height))
    }

    /// Double SHA256 hash
    fn double_sha256(data: &[u8]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let first = Sha256::digest(data);
        let second = Sha256::digest(&first);
        let mut result = [0u8; 32];
        result.copy_from_slice(&second);
        result
    }
}
