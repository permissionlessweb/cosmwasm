mod vesta;
pub(crate) use vesta::{VestaInstance, VestaVerifyingKey};

#[cfg(feature = "bn254")]
mod bn254;
#[cfg(feature = "bn254")]
pub use bn254::{
    build_bn254_circuit_blob, encode_public_inputs_be, serialize_ark_proof, serialize_ark_vk,
    Bn254Instance, Bn254Scalar, Bn254VerifyingKey,
};

#[cfg(feature = "bn254")]
pub mod snarkjs;
#[cfg(feature = "bn254")]
pub use snarkjs::{
    convert_snarkjs_proof_json, convert_snarkjs_public_json, convert_snarkjs_vkey_json,
    verify_snarkjs_fixtures, SnarkjsProof, SnarkjsVerifyingKey,
};

mod vote;
mod stwo;
pub use stwo::{StwoInstance, StwoVerifyingKey, verify_stwo_proof, STWO_CURVE_ID, STWO_HOST_VERIFY, STWO_PROVER_ID};
pub use vote::{VoteVerifyingKey, VoteInstance, VoteCircuitId};

use crate::{ZkError, ZkResult};

pub trait ConstraintSystemTrait: Send + Sync + std::fmt::Debug + 'static {

    fn write(&self) -> ZkResult<()>;
}
pub trait VerifyingKeyTrait: Send + Sync + 'static {
    fn curve_id(&self) -> u32;
    // fn cs(&self) -> impl ConstraintSystemTrait;
    fn verify(
        &self,
        proof: &crate::Proof,
        instances: &[impl Into<crate::AnyInstance>],
    ) -> ZkResult<()>;
    // fn to_bytes(&self) -> ZkResult<Vec<u8>>;
    fn read() -> ZkResult<()>;
    fn write(&self) -> ZkResult<()>;
}

pub trait InstanceTrait: Send + Sync + std::fmt::Debug + 'static {
    fn curve_id(&self) -> u32;
    fn to_bytes(&self) -> Vec<u8>;
}

/// Generic curve trait for the zk-wasmvm.
///
/// Bounds are intentionally minimal — `Scalar` and `Affine` do not require
/// `group::ff::PrimeField` or `pasta_curves::arithmetic::CurveAffine`, so
/// any curve library (arkworks, pasta, etc.) can implement it without
/// adapting to a specific framework's trait hierarchy.
///
/// Concrete methods (verify, scalar_from_bytes, etc.) live in the impl
/// blocks, not on the trait — generic code dispatches through
/// `AnyVerifyingKey` / `AnyInstance` enum variants, not through trait
/// methods on `ZkCurve`.
pub trait ZkCurve: 'static + Clone + Copy + Send + Sync + std::fmt::Debug {
    /// Scalar field element type. Must implement `Clone + Debug` for
    /// `CwInstance<Self>` which derives both.
    type Scalar: Send + Sync + 'static + Clone + std::fmt::Debug;
    /// Affine curve point type. No supertraits required — the concrete
    /// impl handles all curve operations.
    type Affine: Send + Sync + 'static;

    type Params: std::fmt::Debug + Clone;
    type Instance: std::fmt::Debug + Clone;
    type VerifyingKey: std::fmt::Debug + Clone;
    type ProvingKey: std::fmt::Debug;
    type ConstraintSystem: std::fmt::Debug;

    const ID: u32;

    fn scalar_from_bytes(bytes: &[u8; 32]) -> Option<Self::Scalar>;
    fn scalar_to_bytes(s: &Self::Scalar) -> [u8; 32];
}

/// Curve identifier — the sole routing key for VK dispatch.
///
/// Each distinct circuit/curve combination gets its own unique ID, making
/// the `curve_id` field in `CircuitFooter` informationally self-describing.
/// A reader can look at `curve_id` alone and know exactly which circuit
/// and curve the footer refers to.
///
/// | ID | Curve | Circuit | Proving system |
/// |----|-------|---------|---------------|
/// | 0  | Pasta | Generic Plonkish | Plonkish (Halo2) |
/// | 1  | Pasta | Vote delegation (ZKP #1) | Plonkish (Halo2) |
/// | 2  | Pasta | Vote commitment (ZKP #2) | Plonkish (Halo2) |
/// | 3  | Pasta | Share reveal (ZKP #3) | Plonkish (Halo2) |
/// | 4  | BN254 | Generic Groth16 | Groth16 |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CurveType {
    /// Pasta curve, generic Plonkish (Vesta).
    Pasta = 0,
    /// Pasta curve, vote delegation circuit (ZKP #1).
    VoteDelegation = 1,
    /// Pasta curve, vote commitment circuit (ZKP #2).
    VoteCommitment = 2,
    /// Pasta curve, share reveal circuit (ZKP #3).
    ShareReveal = 3,
    /// BN254 curve (alt_bn128), Groth16.
    #[cfg(feature = "bn254")]
    Bn254 = 4,
    /// M31 / Circle STARK (Stwo).
    M31 = 5,
}

impl TryFrom<u8> for CurveType {
    type Error = ZkError;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(CurveType::Pasta),
            1 => Ok(CurveType::VoteDelegation),
            2 => Ok(CurveType::VoteCommitment),
            3 => Ok(CurveType::ShareReveal),
            #[cfg(feature = "bn254")]
            4 => Ok(CurveType::Bn254),
            5 => Ok(CurveType::M31),
            _ => Err(ZkError::new_err("bad CurveType")),
        }
    }
}
impl Into<u8> for CurveType {
    fn into(self) -> u8 {
        match self {
            CurveType::Pasta => 0,
            CurveType::VoteDelegation => 1,
            CurveType::VoteCommitment => 2,
            CurveType::ShareReveal => 3,
            #[cfg(feature = "bn254")]
            CurveType::Bn254 => 4,
            CurveType::M31 => 5,
        }
    }
}