//! Zk-CosmWasm: zk-struct specific for interacting with zk-circuit binaries
pub mod cosmwasm_circuit;
pub use cosmwasm_circuit::{
    CircuitType, ConstraintSystemMetadata, CosmwasmCircuit, CosmwasmCircuitFor, DynamicCircuit,
    DynamicCircuitConfig, Instance, PinnedCircuit, PlonkishCircuitMetadata, Proof, ProvingKey,
    SerializedPlonkishCircuitData, VerifyingKey,
};

pub mod errors;
pub use errors::{ZkError, ZkResult};

pub mod footer;
pub use footer::CircuitFooter;
