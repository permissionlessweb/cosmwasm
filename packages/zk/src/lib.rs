//! Zk-CosmWasm: zk-struct specific for interacting with zk-circuoit binaries
pub mod cosmwasm_circuit;
pub use cosmwasm_circuit::{
    CircuitFooter, CircuitType, ConstraintSystemMetadata, CosmwasmCircuit, CosmwasmCircuitFor,
    DynamicCircuit, DynamicCircuitConfig, Instance, PinnedCircuit, PlonkishCircuitMetadata, Proof,
    ProvingKey, SerializedPlonkishCircuitData, VerifyingKey,
};

pub mod errors;
pub use errors::{ZkError, ZkResult};

#[cfg(feature = "zk-tests")]
pub mod example_circuits;

#[cfg(feature = "interface")]
pub mod suite;
#[cfg(feature = "interface")]
pub use suite::{
    TerpTestPressConfig, TestPressBitwiseInstance, TestPressLaunchpadInstance, TestPressSuite,
};

#[cfg(feature = "zk-tests")]
pub mod testing;
