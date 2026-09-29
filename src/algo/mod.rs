//! Proof-of-work algorithms.
//!
//! Every algorithm is exposed through the [`Algorithm`] trait so the mining
//! engine never needs to know which hash function it is running. Adding a new
//! algorithm means implementing the trait and adding a variant to
//! [`AlgorithmKind`].

mod sha256d;

pub use sha256d::Sha256d;

use anyhow::Result;
use primitive_types::U256;
use serde::{Deserialize, Serialize};

/// A proof-of-work hash function.
pub trait Algorithm: Send + Sync {
    fn name(&self) -> &'static str;

    /// Build a hasher for one header. The hasher may precompute everything
    /// that does not depend on the nonce (e.g. a SHA-256 midstate).
    fn hasher(&self, header: &[u8], nonce_offset: usize) -> Result<Box<dyn NonceHasher>>;
}

/// Hashes one header over a range of nonces.
pub trait NonceHasher: Send {
    /// Hash `count` nonces starting at `start` and call `on_found` for every
    /// digest that meets `target`. Digests are raw hash output and are
    /// compared as little-endian 256-bit integers.
    fn scan(&mut self, start: u32, count: u32, target: &U256, on_found: &mut dyn FnMut(u32, [u8; 32]));
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AlgorithmKind {
    Sha256d,
}

impl AlgorithmKind {
    pub fn build(self) -> Box<dyn Algorithm> {
        match self {
            Self::Sha256d => Box::new(Sha256d),
        }
    }
}

/// Whether a digest (little-endian integer) is at or below `target`.
pub fn meets_target(hash: &[u8; 32], target: &U256) -> bool {
    U256::from_little_endian(hash) <= *target
}
