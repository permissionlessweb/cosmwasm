//! Zk-CosmWasm: zk-struct specific for interacting with zk-circuit binaries
pub mod cosmwasm_circuit;
pub use cosmwasm_circuit::{
    CircuitType, DynamicCircuit, Instance, Proof, ProvingKey, SerializedPlonkishCircuitData,
    VerifyingKey,
};

pub mod errors;
pub use errors::{ZkError, ZkResult};

pub mod footer;
pub use footer::CircuitFooter;
