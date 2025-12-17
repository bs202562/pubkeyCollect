//! P2PKH (Pay-to-Public-Key-Hash) and P2WPKH (Pay-to-Witness-Public-Key-Hash) extraction
//!
//! For P2PKH, the public key is extracted from scriptSig.
//! For P2WPKH, the public key is extracted from the witness data.

use bitcoin::{Script, Witness};

/// Extract public key from P2PKH scriptSig
///
/// P2PKH scriptSig format: <signature> <pubkey>
/// The pubkey is the last push data in the script.
pub fn extract_from_script_sig(script: &Script) -> Option<Vec<u8>> {
    let bytes = script.as_bytes();
    
    if bytes.is_empty() {
        return None;
    }

    // Parse from the end to find the pubkey
    // scriptSig format: <sig> <pubkey>
    // We need to find the last push operation which should be the pubkey

    let mut offset = 0;
    let mut last_push: Option<(usize, usize)> = None; // (start, len)

    while offset < bytes.len() {
        let opcode = bytes[offset];

        match opcode {
            // OP_PUSHBYTES_0 to OP_PUSHBYTES_75
            0x00..=0x4b => {
                let len = opcode as usize;
                if offset + 1 + len <= bytes.len() {
                    last_push = Some((offset + 1, len));
                    offset += 1 + len;
                } else {
                    break;
                }
            }
            // OP_PUSHDATA1
            0x4c => {
                if offset + 1 >= bytes.len() {
                    break;
                }
                let len = bytes[offset + 1] as usize;
                if offset + 2 + len <= bytes.len() {
                    last_push = Some((offset + 2, len));
                    offset += 2 + len;
                } else {
                    break;
                }
            }
            // OP_PUSHDATA2
            0x4d => {
                if offset + 2 >= bytes.len() {
                    break;
                }
                let len = u16::from_le_bytes([bytes[offset + 1], bytes[offset + 2]]) as usize;
                if offset + 3 + len <= bytes.len() {
                    last_push = Some((offset + 3, len));
                    offset += 3 + len;
                } else {
                    break;
                }
            }
            // OP_PUSHDATA4
            0x4e => {
                if offset + 4 >= bytes.len() {
                    break;
                }
                let len = u32::from_le_bytes([
                    bytes[offset + 1],
                    bytes[offset + 2],
                    bytes[offset + 3],
                    bytes[offset + 4],
                ]) as usize;
                if offset + 5 + len <= bytes.len() {
                    last_push = Some((offset + 5, len));
                    offset += 5 + len;
                } else {
                    break;
                }
            }
            // Other opcodes - skip
            _ => {
                offset += 1;
            }
        }
    }

    // Check if the last push is a valid pubkey
    if let Some((start, len)) = last_push {
        let data = &bytes[start..start + len];
        if is_valid_pubkey(data) {
            return Some(data.to_vec());
        }
    }

    None
}

/// Extract public key from P2WPKH witness
///
/// P2WPKH witness format: [<signature>, <pubkey>]
/// The pubkey is the second element (index 1) in the witness.
pub fn extract_from_witness(witness: &Witness) -> Option<Vec<u8>> {
    // P2WPKH has exactly 2 witness elements: signature and pubkey
    if witness.len() != 2 {
        return None;
    }

    let pubkey_data = witness.nth(1)?;
    
    // Validate it's a proper compressed pubkey (33 bytes)
    if pubkey_data.len() == 33 && (pubkey_data[0] == 0x02 || pubkey_data[0] == 0x03) {
        return Some(pubkey_data.to_vec());
    }

    None
}

/// Check if data is a valid public key based on length and prefix
fn is_valid_pubkey(data: &[u8]) -> bool {
    match data.len() {
        33 => data[0] == 0x02 || data[0] == 0x03, // Compressed
        65 => data[0] == 0x04,                     // Uncompressed
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::ScriptBuf;

    #[test]
    fn test_extract_from_witness() {
        // Create a witness with signature and compressed pubkey
        let sig = vec![0x30; 71]; // DER signature placeholder
        let mut pubkey = vec![0x02]; // Compressed prefix
        pubkey.extend_from_slice(&[0xab; 32]);

        let witness = Witness::from_slice(&[&sig, &pubkey]);
        let result = extract_from_witness(&witness);

        assert!(result.is_some());
        let extracted = result.unwrap();
        assert_eq!(extracted.len(), 33);
        assert_eq!(extracted[0], 0x02);
    }

    #[test]
    fn test_extract_from_script_sig() {
        // Create a simple scriptSig: <sig> <pubkey>
        let mut script_bytes = Vec::new();
        
        // Push 71-byte signature
        script_bytes.push(71);
        script_bytes.extend_from_slice(&[0x30; 71]);
        
        // Push 33-byte compressed pubkey
        script_bytes.push(33);
        script_bytes.push(0x03); // Compressed prefix
        script_bytes.extend_from_slice(&[0xcd; 32]);

        let script = ScriptBuf::from_bytes(script_bytes);
        let result = extract_from_script_sig(&script);

        assert!(result.is_some());
        let extracted = result.unwrap();
        assert_eq!(extracted.len(), 33);
        assert_eq!(extracted[0], 0x03);
    }
}

