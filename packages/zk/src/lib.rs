//! Zk-CosmWasm: zk-struct specific for interacting with zk-circuit binaries
pub mod circuits;
pub mod curves;
pub mod footer;

pub mod errors;
pub use errors::{ZkError, ZkResult};

pub use {
    circuits::{AnyInstance, AnyVerifyingKey, CircuitType, Proof, SerializedPlonkishCircuitData},
    curves::ZkCurve,
    footer::CircuitFooter,
};

pub(crate) use circuits::{
    CosmwasmCircuit, CsBlueprint, CsBlueprintGuard, CwInstance, CwProvingKey, CwVerifyingKey,
};
