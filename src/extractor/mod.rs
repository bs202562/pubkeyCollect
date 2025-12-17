//! Public key extraction module

pub mod p2pk;
pub mod p2pkh;
pub mod p2tr;
pub mod canonical;

use crate::PubkeyType;
use anyhow::Result;
use bitcoin::Block;
use canonical::CanonicalPubkey;

/// Extract all public keys from a block
pub fn extract_pubkeys_from_block(
    block: &Block,
    height: u32,
) -> Result<Vec<(CanonicalPubkey, PubkeyType, u32)>> {
    let mut pubkeys = Vec::new();

    for tx in block.txdata.iter() {
        // Extract from outputs (P2PK and P2TR)
        for output in tx.output.iter() {
            // P2PK: direct pubkey in scriptPubKey
            if let Some(pk) = p2pk::extract_from_script_pubkey(&output.script_pubkey) {
                if let Ok(canonical) = canonical::canonicalize(&pk) {
                    pubkeys.push((canonical, PubkeyType::Legacy, height));
                }
            }

            // P2TR: x-only pubkey from scriptPubKey
            if let Some(pk) = p2tr::extract_from_script_pubkey(&output.script_pubkey) {
                let canonical = CanonicalPubkey::Taproot(pk);
                pubkeys.push((canonical, PubkeyType::Taproot, height));
            }
        }

        // Extract from inputs (P2PKH from scriptSig, P2WPKH from witness)
        for input in tx.input.iter() {
            // P2PKH: pubkey from scriptSig
            if let Some(pk) = p2pkh::extract_from_script_sig(&input.script_sig) {
                if let Ok(canonical) = canonical::canonicalize(&pk) {
                    pubkeys.push((canonical, PubkeyType::Legacy, height));
                }
            }

            // P2WPKH: pubkey from witness
            if let Some(pk) = p2pkh::extract_from_witness(&input.witness) {
                if let Ok(canonical) = canonical::canonicalize(&pk) {
                    pubkeys.push((canonical, PubkeyType::Segwit, height));
                }
            }
        }
    }

    Ok(pubkeys)
}
