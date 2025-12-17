//! P2TR (Pay-to-Taproot) public key extraction
//!
//! P2TR uses x-only public keys (32 bytes) directly in the scriptPubKey.
//! Only key-path outputs are extracted; script-path branches are excluded.

use bitcoin::Script;

/// Extract x-only public key from P2TR scriptPubKey
///
/// P2TR format: OP_1 (0x51) + OP_PUSHBYTES_32 (0x20) + <32-byte x-only pubkey>
pub fn extract_from_script_pubkey(script: &Script) -> Option<[u8; 32]> {
    let bytes = script.as_bytes();

    // P2TR script is exactly 34 bytes:
    // - OP_1 (0x51)
    // - OP_PUSHBYTES_32 (0x20)
    // - 32 bytes x-only pubkey
    if bytes.len() != 34 {
        return None;
    }

    if bytes[0] != 0x51 || bytes[1] != 0x20 {
        return None;
    }

    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(&bytes[2..34]);

    Some(pubkey)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::ScriptBuf;

    #[test]
    fn test_extract_p2tr() {
        // Create a valid P2TR scriptPubKey
        let mut script_bytes = vec![0x51, 0x20]; // OP_1 + OP_PUSHBYTES_32
        script_bytes.extend_from_slice(&[0xab; 32]); // x-only pubkey

        let script = ScriptBuf::from_bytes(script_bytes);
        let result = extract_from_script_pubkey(&script);

        assert!(result.is_some());
        let pubkey = result.unwrap();
        assert_eq!(pubkey.len(), 32);
        assert!(pubkey.iter().all(|&b| b == 0xab));
    }

    #[test]
    fn test_invalid_p2tr() {
        // Wrong opcode (OP_2 instead of OP_1)
        let mut script_bytes = vec![0x52, 0x20];
        script_bytes.extend_from_slice(&[0xab; 32]);
        let script = ScriptBuf::from_bytes(script_bytes);
        assert!(extract_from_script_pubkey(&script).is_none());

        // Wrong length (33 bytes instead of 32)
        let mut script_bytes = vec![0x51, 0x21];
        script_bytes.extend_from_slice(&[0xab; 33]);
        let script = ScriptBuf::from_bytes(script_bytes);
        assert!(extract_from_script_pubkey(&script).is_none());
    }
}

