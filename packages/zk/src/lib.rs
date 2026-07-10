//! Zk-CosmWasm: zk-struct specific for interacting with zk-circuit binaries
pub mod circuits;
pub mod curves;
pub mod footer;

pub mod errors;
pub use errors::{ZkError, ZkResult};

pub use {
    circuits::{AnyInstance, AnyVerifyingKey, CircuitType, Proof, SerializedCircuitData},
    curves::ZkCurve,
    footer::CircuitFooter,
};

pub(crate) use circuits::{
    CosmwasmCircuit, CsBlueprint, CsBlueprintGuard, CwInstance, CwProvingKey, CwVerifyingKey,
};


// Key prefixes (must match Go exactly)
// TODO: terrible fragile hack, must define some sort of enum for prefix keep aligned, OR have some sort of ffi test to ensure lined up with latest key verison
pub const VK_PARAM_KEY_PREFIX: &[u8] = b"\x12";
pub const VK_KEY_PREFIX: &[u8] = b"\x13";      
pub const CIRCUIT_KEY_PREFIX: &[u8] = b"\x16"; 
pub const CIRCUIT_INFO_KEY_PREFIX: &[u8] = b"\x16";
pub const KEY_SEQUENCE_CIRCUIT_ID: &[u8] = b"lastPlonkishCircuit";