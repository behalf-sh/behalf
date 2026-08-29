//! The Week-1 hand-rolled hash chain (contract §1.3).
//!
//! `chain_start = SHA-256("behalf.sh/chain/v1\n" + log_origin)`;
//! `chain_i = SHA-256(chain_{i-1} || leaf_hash_i_raw)` over the 32 raw bytes
//! of each leaf hash. Week 2 swaps Tessera in underneath; this module is the
//! placeholder reader-side of that plan and contains no Merkle material.

use crate::util::sha256;

/// Domain-separation prefix for the chain start value.
pub const CHAIN_DOMAIN_PREFIX: &str = "behalf.sh/chain/v1\n";

/// `chain_start` for a log origin.
#[must_use]
pub fn chain_start(log_origin: &str) -> [u8; 32] {
    let mut input = Vec::with_capacity(CHAIN_DOMAIN_PREFIX.len() + log_origin.len());
    input.extend_from_slice(CHAIN_DOMAIN_PREFIX.as_bytes());
    input.extend_from_slice(log_origin.as_bytes());
    sha256(&input)
}

/// One fold step: `SHA-256(prev || leaf_hash_raw)`.
#[must_use]
pub fn chain_step(prev: &[u8; 32], leaf_hash_raw: &[u8; 32]) -> [u8; 32] {
    let mut input = [0u8; 64];
    input[..32].copy_from_slice(prev);
    input[32..].copy_from_slice(leaf_hash_raw);
    sha256(&input)
}

/// Full chain over leaf hashes in order. With no leaves this is `chain_start`.
#[must_use]
pub fn compute_chain(log_origin: &str, leaf_hashes: &[[u8; 32]]) -> [u8; 32] {
    let mut acc = chain_start(log_origin);
    for h in leaf_hashes {
        acc = chain_step(&acc, h);
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::hex_encode;

    #[test]
    fn chain_known_answer() {
        // Independently computed: origin "example.org/log",
        // leaves sha256("leaf0") and sha256("leaf1").
        assert_eq!(
            hex_encode(&chain_start("example.org/log")),
            "2f21ad71bc7fea2b2a11b8f53bab4aabaf151b682b45c26ca664228d1fec6e6d"
        );
        let leaves = [sha256(b"leaf0"), sha256(b"leaf1")];
        assert_eq!(
            hex_encode(&compute_chain("example.org/log", &leaves)),
            "7f567a30e30a0b0f72421c8ef3b36b674d9e798ff5ef35ffa12c20f5a125ffd1"
        );
    }

    #[test]
    fn empty_chain_is_the_start_value() {
        assert_eq!(
            compute_chain("example.org/log", &[]),
            chain_start("example.org/log")
        );
    }

    #[test]
    fn origin_is_domain_separated() {
        assert_ne!(chain_start("a"), chain_start("b"));
        // The newline in the prefix separates prefix from origin.
        assert_ne!(chain_start("x"), sha256(b"behalf.sh/chain/v1x"));
    }
}
