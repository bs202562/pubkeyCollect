//! Script decoding utilities
//!
//! This module provides utilities for decoding Bitcoin scripts.

use bitcoin::script::Instruction;
use bitcoin::Script;

/// Get all push data from a script
pub fn get_push_data(script: &Script) -> Vec<Vec<u8>> {
    let mut result = Vec::new();

    for instruction in script.instructions() {
        if let Ok(Instruction::PushBytes(bytes)) = instruction {
            result.push(bytes.as_bytes().to_vec());
        }
    }

    result
}

/// Check if a script is a P2PK script
/// Format: <pubkey> OP_CHECKSIG
pub fn is_p2pk(script: &Script) -> bool {
    let bytes = script.as_bytes();
    
    // Check for uncompressed pubkey (65 bytes)
    if bytes.len() == 67 && bytes[0] == 0x41 && bytes[66] == 0xac {
        return true;
    }
    
    // Check for compressed pubkey (33 bytes)
    if bytes.len() == 35 && bytes[0] == 0x21 && bytes[34] == 0xac {
        return true;
    }

    false
}

/// Check if a script is a P2TR script
/// Format: OP_1 <32-byte-pubkey>
pub fn is_p2tr(script: &Script) -> bool {
    let bytes = script.as_bytes();
    bytes.len() == 34 && bytes[0] == 0x51 && bytes[1] == 0x20
}

/// Check if script data is likely a public key based on length and prefix
pub fn is_likely_pubkey(data: &[u8]) -> bool {
    match data.len() {
        33 => data[0] == 0x02 || data[0] == 0x03, // Compressed
        65 => data[0] == 0x04,                      // Uncompressed
        _ => false,
    }
}
