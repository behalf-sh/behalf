//! RFC 6962 tree computation over the vendored azul `tlog_core` crate
//! (an attributed port of Go's `sumdb/tlog`; see `vendor/azul/VENDOR.md`).
//!
//! [`HashStore`] replays the append-time stored-hash scheme in memory: leaf
//! hashes go in one at a time via [`HashStore::push_leaf`], and
//! [`HashStore::root_at`] then computes the root of any prefix of the tree
//! — which is exactly what checkpoint comparison (current size) and the
//! `--latest-known` consistency check (an earlier size) both need.

use crate::tlog_core::{
    record_hash, stored_hash_index, stored_hashes_for_record_hash, tree_hash, Hash, HashReader,
    TlogError,
};

/// RFC 6962 leaf hash of stored envelope bytes: `SHA-256(0x00 || data)`.
#[must_use]
pub fn leaf_hash(data: &[u8]) -> [u8; 32] {
    record_hash(data).0
}

/// An in-memory stored-hash log, filled by appending leaf hashes in order.
#[derive(Default)]
pub struct HashStore {
    hashes: Vec<Hash>,
    leaves: u64,
}

impl HashStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of leaves appended so far.
    #[must_use]
    pub fn leaf_count(&self) -> u64 {
        self.leaves
    }

    /// Append the next leaf hash (leaf index = current [`Self::leaf_count`]).
    pub fn push_leaf(&mut self, leaf: [u8; 32]) -> Result<(), TlogError> {
        debug_assert_eq!(
            stored_hash_index(0, self.leaves),
            self.hashes.len() as u64,
            "stored-hash bookkeeping out of sync"
        );
        let new = stored_hashes_for_record_hash(self.leaves, Hash(leaf), self)?;
        self.hashes.extend(new);
        self.leaves += 1;
        Ok(())
    }

    /// Root hash of the tree over the first `n` leaves (`n == 0` is the
    /// RFC 6962 empty-tree hash). Errors if `n` exceeds the appended count.
    pub fn root_at(&self, n: u64) -> Result<[u8; 32], TlogError> {
        if n > self.leaves {
            return Err(TlogError::IndexesNotInTree);
        }
        Ok(tree_hash(n, self)?.0)
    }
}

impl HashReader for HashStore {
    fn read_hashes(&self, indexes: &[u64]) -> Result<Vec<Hash>, TlogError> {
        indexes
            .iter()
            .map(|&i| {
                usize::try_from(i)
                    .ok()
                    .and_then(|i| self.hashes.get(i).copied())
                    .ok_or(TlogError::IndexesNotInTree)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::{hex_encode, sha256};

    /// The RFC 6962 test leaves from the C2SP / Certificate Transparency /
    /// sumdb cross-implementation corpus (d0..d7).
    fn corpus_leaves() -> Vec<Vec<u8>> {
        [
            "", "00", "10", "2021", "3031", "40414243", "5051525354555657",
            "606162636465666768696a6b6c6d6e6f",
        ]
        .iter()
        .map(|h| crate::util::hex_decode(h).expect("valid hex"))
        .collect()
    }

    fn root_over(leaves: &[Vec<u8>]) -> String {
        let mut store = HashStore::new();
        for l in leaves {
            store.push_leaf(leaf_hash(l)).expect("push");
        }
        hex_encode(&store.root_at(store.leaf_count()).expect("root"))
    }

    #[test]
    fn rfc6962_known_answer_roots() {
        // Known answers from the corpus (independently recomputed; the
        // 1/2/3/7/8-leaf roots are the classic CT test vectors).
        let leaves = corpus_leaves();
        let cases: [(usize, &str); 6] = [
            (0, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            (1, "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"),
            (2, "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125"),
            (3, "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77"),
            (7, "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c"),
            (8, "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328"),
        ];
        for (n, want) in cases {
            assert_eq!(root_over(&leaves[..n]), want, "tree size {n}");
        }
    }

    #[test]
    fn leaf_hash_is_domain_separated_sha256() {
        // RFC 6962 §2.1: leaf hash = SHA-256(0x00 || data).
        assert_eq!(leaf_hash(b""), sha256(&[0x00]));
        let mut input = vec![0x00];
        input.extend_from_slice(b"envelope bytes");
        assert_eq!(leaf_hash(b"envelope bytes"), sha256(&input));
    }

    #[test]
    fn prefix_roots_match_independent_builds() {
        // root_at(m) over a longer store equals the root of a store built
        // from only the first m leaves — the --latest-known consistency
        // check depends on exactly this.
        let leaves = corpus_leaves();
        let mut full = HashStore::new();
        for l in &leaves {
            full.push_leaf(leaf_hash(l)).expect("push");
        }
        for m in 0..=leaves.len() {
            let prefix_root = root_over(&leaves[..m]);
            assert_eq!(
                hex_encode(&full.root_at(m as u64).expect("prefix root")),
                prefix_root,
                "prefix {m}"
            );
        }
    }

    #[test]
    fn root_beyond_leaf_count_errors() {
        let store = HashStore::new();
        assert!(store.root_at(1).is_err());
        let mut store = HashStore::new();
        store.push_leaf([7u8; 32]).expect("push");
        assert!(store.root_at(2).is_err());
        assert!(store.root_at(1).is_ok());
    }

    #[test]
    fn ninety_four_leaf_tessera_interop_shape() {
        // Same shape as the demo log the Go side writes (94 leaves): the
        // root over 94 distinct leaves must differ from the root over 47,
        // and both must be stable across recomputation.
        let mut store = HashStore::new();
        for i in 0..94u64 {
            store.push_leaf(leaf_hash(&i.to_be_bytes())).expect("push");
        }
        let r94 = store.root_at(94).expect("root");
        let r47 = store.root_at(47).expect("root");
        assert_ne!(r94, r47);
        assert_eq!(store.root_at(94).expect("root"), r94);
    }
}
