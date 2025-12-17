//! P2PK (Pay-to-Public-Key) public key extraction
//!
//! P2PK scripts have the format: <pubkey> OP_CHECKSIG
//! The public key is directly visible in the scriptPubKey.

use bitcoin::Script;

/// Extract public key from P2PK scriptPubKey
///
/// P2PK format:
/// - Uncompressed: 0x41 <65-byte-pubkey> OP_CHECKSIG (0xac)
/// - Compressed: 0x21 <33-byte-pubkey> OP_CHECKSIG (0xac)
pub fn extract_from_script_pubkey(script: &Script) -> Option<Vec<u8>> {
    let bytes = script.as_bytes();

    // Check for uncompressed pubkey (65 bytes)
    // Format: 0x41 (push 65 bytes) + 65 bytes + 0xac (OP_CHECKSIG)
    if bytes.len() == 67 && bytes[0] == 0x41 && bytes[66] == 0xac {
        let pubkey = &bytes[1..66];
        // Validate uncompressed pubkey prefix
        if pubkey[0] == 0x04 {
            return Some(pubkey.to_vec());
        }
    }

    // Check for compressed pubkey (33 bytes)
    // Format: 0x21 (push 33 bytes) + 33 bytes + 0xac (OP_CHECKSIG)
    if bytes.len() == 35 && bytes[0] == 0x21 && bytes[34] == 0xac {
        let pubkey = &bytes[1..34];
        // Validate compressed pubkey prefix
        if pubkey[0] == 0x02 || pubkey[0] == 0x03 {
            return Some(pubkey.to_vec());
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::ScriptBuf;

    #[test]
    fn test_extract_compressed_p2pk() {
        // Compressed P2PK: 0x21 + 33-byte pubkey + 0xac
        let mut script_bytes = vec![0x21];
        script_bytes.push(0x02); // Compressed prefix
        script_bytes.extend_from_slice(&[0xab; 32]); // Rest of pubkey
        script_bytes.push(0xac); // OP_CHECKSIG

        let script = ScriptBuf::from_bytes(script_bytes);
        let result = extract_from_script_pubkey(&script);

        assert!(result.is_some());
        let pubkey = result.unwrap();
        assert_eq!(pubkey.len(), 33);
        assert_eq!(pubkey[0], 0x02);
    }

    #[test]
    fn test_extract_uncompressed_p2pk() {
        // Uncompressed P2PK: 0x41 + 65-byte pubkey + 0xac
        let mut script_bytes = vec![0x41];
        script_bytes.push(0x04); // Uncompressed prefix
        script_bytes.extend_from_slice(&[0xab; 64]); // Rest of pubkey
        script_bytes.push(0xac); // OP_CHECKSIG

        let script = ScriptBuf::from_bytes(script_bytes);
        let result = extract_from_script_pubkey(&script);

        assert!(result.is_some());
        let pubkey = result.unwrap();
        assert_eq!(pubkey.len(), 65);
        assert_eq!(pubkey[0], 0x04);
    }
}

