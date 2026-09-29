//! Work units exchanged between backends (pool / node) and the mining engine.

use crate::algo::AlgorithmKind;
use primitive_types::U256;
use sha2::{Digest, Sha256};
use std::sync::Arc;

/// Something that can produce block headers to hash.
///
/// A backend turns whatever it received (a Stratum job, a block template...)
/// into a `WorkTemplate`. The engine then asks it for headers, one per
/// "extranonce roll", and scans the nonce space of each header.
pub trait WorkTemplate: Send + Sync {
    fn algorithm(&self) -> AlgorithmKind;
    /// Hashes at or below this target are reported as solutions.
    fn target(&self) -> U256;
    fn nonce_offset(&self) -> usize;
    /// Header for extranonce roll `n` (nonce field zeroed). Returns `None`
    /// once the template cannot produce more distinct headers.
    fn header(&self, extranonce: u64) -> Option<Vec<u8>>;
}

#[derive(Clone)]
pub struct Work {
    /// Unique per work unit, used by the backend to match solutions to jobs.
    pub id: u64,
    pub template: Arc<dyn WorkTemplate>,
}

#[derive(Debug, Clone)]
pub struct Solution {
    pub work_id: u64,
    pub extranonce: u64,
    pub nonce: u32,
    pub hash: [u8; 32],
}

pub fn sha256d(data: &[u8]) -> [u8; 32] {
    Sha256::digest(Sha256::digest(data)).into()
}

/// Hash in the conventional display order (byte-reversed), e.g. block hashes.
pub fn hash_to_hex(hash: &[u8; 32]) -> String {
    let mut h = *hash;
    h.reverse();
    hex::encode(h)
}

/// Fold a leaf up a merkle branch (leaf is always the left-most node).
pub fn merkle_root(leaf: [u8; 32], branch: &[[u8; 32]]) -> [u8; 32] {
    branch.iter().fold(leaf, |acc, sibling| {
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(&acc);
        buf[32..].copy_from_slice(sibling);
        sha256d(&buf)
    })
}

/// Merkle branch for index 0 (the coinbase), given the other txids in order.
pub fn merkle_branch(txids: &[[u8; 32]]) -> Vec<[u8; 32]> {
    // `None` stands for the (not yet known) node on the coinbase path.
    let mut level: Vec<Option<[u8; 32]>> = std::iter::once(None).chain(txids.iter().copied().map(Some)).collect();
    let mut branch = Vec::new();
    while level.len() > 1 {
        branch.push(level[1].expect("only index 0 is unknown"));
        if level.len() % 2 == 1 {
            level.push(*level.last().unwrap());
        }
        let mut next = vec![None];
        for pair in level[2..].chunks(2) {
            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(&pair[0].unwrap());
            buf[32..].copy_from_slice(&pair[1].unwrap());
            next.push(Some(sha256d(&buf)));
        }
        level = next;
    }
    branch
}

/// Bitcoin "difficulty 1" target (0x00000000FFFF0000...).
pub fn diff1_target() -> U256 {
    U256::from(0xFFFFu64) << 208
}

/// Pool share difficulty to target. Supports fractional difficulties.
pub fn difficulty_to_target(difficulty: f64) -> U256 {
    if !(difficulty > 0.0) {
        return U256::MAX;
    }
    // target = diff1 / difficulty, computed with 32 fractional bits.
    let scaled = (difficulty * 4294967296.0).max(1.0).min(u128::MAX as f64) as u128;
    (diff1_target() << 32) / U256::from(scaled)
}

pub fn target_to_difficulty(target: &U256) -> f64 {
    if target.is_zero() {
        return f64::INFINITY;
    }
    u256_to_f64(&diff1_target()) / u256_to_f64(target)
}

/// Difficulty a hash would satisfy (for logging share quality).
pub fn hash_difficulty(hash: &[u8; 32]) -> f64 {
    target_to_difficulty(&U256::from_little_endian(hash))
}

/// Decode a compact "nBits" value into a full target.
pub fn compact_to_target(bits: u32) -> U256 {
    let exponent = bits >> 24;
    let mantissa = U256::from(bits & 0x007f_ffff);
    if exponent <= 3 {
        mantissa >> (8 * (3 - exponent))
    } else {
        mantissa << (8 * (exponent - 3))
    }
}

fn u256_to_f64(v: &U256) -> f64 {
    v.0.iter().rev().fold(0.0, |acc, &w| acc * 18446744073709551616.0 + w as f64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn difficulty_one_is_diff1() {
        assert_eq!(difficulty_to_target(1.0), diff1_target());
        assert_eq!(difficulty_to_target(2.0), diff1_target() / 2);
        assert!((target_to_difficulty(&difficulty_to_target(1234.5)) - 1234.5).abs() < 1e-6);
    }

    #[test]
    fn compact_roundtrip_diff1() {
        assert_eq!(compact_to_target(0x1d00ffff), diff1_target());
    }

    #[test]
    fn branch_matches_full_tree() {
        let leaves: Vec<[u8; 32]> = (0u8..7).map(|i| sha256d(&[i])).collect();
        // Full tree computation, Bitcoin style.
        let mut level = leaves.clone();
        while level.len() > 1 {
            if level.len() % 2 == 1 {
                level.push(*level.last().unwrap());
            }
            level = level
                .chunks(2)
                .map(|p| sha256d(&[p[0].as_slice(), p[1].as_slice()].concat()))
                .collect();
        }
        let branch = merkle_branch(&leaves[1..]);
        assert_eq!(merkle_root(leaves[0], &branch), level[0]);
        assert!(merkle_branch(&[]).is_empty());
    }
}
