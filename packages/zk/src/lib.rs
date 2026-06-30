//! Zk-CosmWasm: zk-struct specific for interacting with zk-circuit binaries
pub mod cosmwasm_circuit;
pub use cosmwasm_circuit::{
    CircuitType, CosmwasmCircuit, DynamicCircuit, Instance, PinnedCircuit, Proof, ProvingKey,
    VerifyingKey,SerializedPlonkishCircuitData,
};

pub mod errors;
pub use errors::{ZkError, ZkResult};

pub mod footer;
pub use footer::CircuitFooter;
