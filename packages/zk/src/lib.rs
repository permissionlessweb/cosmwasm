//! Zk-CosmWasm: zk-struct specific for interacting with zk-circuoit binaries
pub mod cosmwasm_circuit;
pub use cosmwasm_circuit::{
    CircuitType, CosmwasmCircuit, Instance, PinnedCircuit, Proof, ProvingKey, VerifyingKey as VK,
};

pub mod errors;
pub use errors::{ZkError, ZkResult};

#[cfg(feature = "zk-tests")]
pub mod example_circuits;

#[cfg(feature = "interface")]
pub mod suite;
#[cfg(feature = "interface")]
pub use suite::{
    TerpTestPressConfig, TestPressBitwiseInstance, TestPressIpfsInstance,
    TestPressLaunchpadInstance, TestPressSuite,
};

#[cfg(feature = "zk-tests")]
pub mod testing;
