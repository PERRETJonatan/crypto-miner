//! Double SHA-256 over an 80-byte Bitcoin-style block header.
//!
//! The first 64 bytes of the header don't contain the nonce, so their
//! compression (the "midstate") is computed once per header. Each nonce then
//! costs two compressions instead of three.

use super::{meets_target, Algorithm, NonceHasher};
use anyhow::{ensure, Result};
use primitive_types::U256;
use sha2::compress256;
use sha2::digest::generic_array::GenericArray;

const HEADER_LEN: usize = 80;
const NONCE_OFFSET: usize = 76;

const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

pub struct Sha256d;

impl Algorithm for Sha256d {
    fn name(&self) -> &'static str {
        "sha256d"
    }

    fn hasher(&self, header: &[u8], nonce_offset: usize) -> Result<Box<dyn NonceHasher>> {
        ensure!(header.len() == HEADER_LEN, "sha256d expects an {HEADER_LEN}-byte header");
        ensure!(nonce_offset == NONCE_OFFSET, "sha256d expects the nonce at offset {NONCE_OFFSET}");

        let mut midstate = H0;
        compress256(&mut midstate, &[*GenericArray::from_slice(&header[..64])]);

        // Second block of the first hash: header tail + padding for 640 bits.
        let mut tail = [0u8; 64];
        tail[..16].copy_from_slice(&header[64..80]);
        tail[16] = 0x80;
        tail[56..].copy_from_slice(&640u64.to_be_bytes());

        // Only block of the second hash: 32-byte digest + padding for 256 bits.
        let mut second = [0u8; 64];
        second[32] = 0x80;
        second[56..].copy_from_slice(&256u64.to_be_bytes());

        Ok(Box::new(Sha256dHasher { midstate, tail, second }))
    }
}

struct Sha256dHasher {
    midstate: [u32; 8],
    tail: [u8; 64],
    second: [u8; 64],
}

impl Sha256dHasher {
    #[inline(always)]
    fn digest(&mut self, nonce: u32) -> [u8; 32] {
        self.tail[12..16].copy_from_slice(&nonce.to_le_bytes());
        let mut state = self.midstate;
        compress256(&mut state, &[*GenericArray::from_slice(&self.tail)]);

        for (i, word) in state.iter().enumerate() {
            self.second[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        let mut state = H0;
        compress256(&mut state, &[*GenericArray::from_slice(&self.second)]);

        let mut out = [0u8; 32];
        for (i, word) in state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }
}

impl NonceHasher for Sha256dHasher {
    fn scan(&mut self, start: u32, count: u32, target: &U256, on_found: &mut dyn FnMut(u32, [u8; 32])) {
        // Cheap pre-filter on the most significant 32 bits of the hash.
        let top = (target >> 224).low_u32();
        let end = start as u64 + count as u64;
        for nonce in start as u64..end {
            let nonce = nonce as u32;
            let hash = self.digest(nonce);
            let hi = u32::from_le_bytes([hash[28], hash[29], hash[30], hash[31]]);
            if hi <= top && meets_target(&hash, target) {
                on_found(nonce, hash);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::work::{hash_to_hex, sha256d};

    // Bitcoin block 125552.
    fn header_125552() -> Vec<u8> {
        let mut h = Vec::new();
        h.extend_from_slice(&1u32.to_le_bytes());
        let mut prev = hex::decode("00000000000008a3a41b85b8b29ad444def299fee21793cd8b9e567eab02cd81").unwrap();
        prev.reverse();
        h.extend_from_slice(&prev);
        let mut root = hex::decode("2b12fcf1b09288fcaff797d71e950e71ae42b91e8bdb2304758dfcffc2b620e3").unwrap();
        root.reverse();
        h.extend_from_slice(&root);
        h.extend_from_slice(&1305998791u32.to_le_bytes());
        h.extend_from_slice(&0x1a44b9f2u32.to_le_bytes());
        h.extend_from_slice(&2504433986u32.to_le_bytes());
        h
    }

    #[test]
    fn midstate_matches_plain_sha256d() {
        let header = header_125552();
        let mut hasher = Sha256d.hasher(&header, 76).unwrap();
        let mut found = Vec::new();
        hasher.scan(2504433986, 1, &U256::MAX, &mut |n, h| found.push((n, h)));
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].1, sha256d(&header));
        assert_eq!(
            hash_to_hex(&found[0].1),
            "00000000000000001e8d6829a8a21adc5d38d0a473b144b6765798e61f98bd1d"
        );
    }

    #[test]
    fn finds_real_nonce_at_network_target() {
        let header = header_125552();
        let target = crate::work::compact_to_target(0x1a44b9f2);
        let mut hasher = Sha256d.hasher(&header, 76).unwrap();
        let mut found = Vec::new();
        hasher.scan(2504433986 - 1000, 2000, &target, &mut |n, _| found.push(n));
        assert_eq!(found, vec![2504433986]);
    }
}
