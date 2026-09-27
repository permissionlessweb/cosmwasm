//! BN254 (alt_bn128) host primitives.
//!
//! EIP-196 / EIP-197 / EIP-1108. Compiled only with the `bn254` feature so a
//! Wasm guest does not pull `ark-bn254` unless it calls these hosts.

mod bn254;
pub mod errors;
pub mod gas;

pub use bn254::{bn254_add, bn254_pairing_equality, bn254_scalar_mul};
pub use errors::Bn254Error;

/// Size of a BN254 base-field element in bytes (big-endian).
pub const FQ_BYTES: usize = 32;
/// Size of a BN254 scalar-field element in bytes (big-endian).
pub const FR_BYTES: usize = 32;
/// Size of a BN254 G1 point in uncompressed affine form.
pub const G1_BYTES: usize = 64;
/// Size of a BN254 G2 point in uncompressed affine form.
pub const G2_BYTES: usize = 128;
/// Size of one `(G1, G2)` pair in the pairing-equality input.
pub const PAIR_BYTES: usize = G1_BYTES + G2_BYTES;
