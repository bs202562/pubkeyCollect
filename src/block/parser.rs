//! Block and transaction parsing utilities
//!
//! This module provides additional parsing utilities for blocks and transactions.

use bitcoin::{Block, Transaction};

/// Get all transactions from a block
pub fn get_transactions(block: &Block) -> &[Transaction] {
    &block.txdata
}

/// Check if a transaction is a coinbase transaction
pub fn is_coinbase(tx: &Transaction) -> bool {
    tx.is_coinbase()
}
