//! Deterministic native hash digests for optional CosmWasm host functions.
//!
//! **Not GPU-accelerated.** Consensus host functions must be pure functions of
//! their inputs (bit-identical across validators). GPU kernels break that
//! contract — see plan `zkvm-bn254-multicurve-hash-vote.md` §4.
//!
//! `blake2b_256` is `blake2b_simd`: runtime AVX2 or SSE4.1 on x86_64, portable
//! on other hosts, same digest either way. `blake2b_512` stays RustCrypto
//! `blake2` 0.10. Neither function takes a personalization block. Do not
//! extend the public signature for ZAP1.
//!
//! Enable with feature `hash-blake`.

#![cfg(feature = "hash-blake")]

mod b2b_256;
mod b2b_512;
mod b3;

pub use b2b_256::blake2b_256;
pub use b2b_512::blake2b_512;
pub use b3::blake3_256;
