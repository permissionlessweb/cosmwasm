use crate::{
    curves::{VestaInstance, VestaVerifyingKey, ZkCurve},
    CircuitFooter, ZkError, ZkResult,
};
use halo2_proofs::{
    circuit::Layouter,
    plonk::{self, Circuit, ConstraintSystem},
    COSMWASM_FOOTER_LENGTH,
};
use std::cell::RefCell;

/// A proof of circuit validity.
#[derive(Clone)]
pub struct Proof(pub(crate) Vec<u8>);
impl Proof {
    pub fn new(bytes: Vec<u8>) -> Self {
        Proof(bytes)
    }
    pub fn verify(&self, vk: &AnyVerifyingKey, i: &[AnyInstance]) -> Result<(), ZkError> {
        vk.verify(&self, i)
    }
}
/// Public inputs.
#[derive(Clone, Debug)]
pub struct CwInstance<C: ZkCurve> {
    pub(crate) i: Vec<C::Scalar>,
    pub(crate) size: usize,
}

/// A verifying key for the zk-wasmvm.
#[derive(Debug, Clone)]
pub struct CwCircuit<C: ZkCurve> {
    /// IPA commitment scheme params
    pub params: C::Params,
    pub vk: C::VerifyingKey,
    pub footer: crate::CircuitFooter,
}

/// The proving key.
#[derive(Debug)]
pub struct CwProvingKey<C: ZkCurve> {
    // pub(crate) params: C::Params,
    pub(crate) _pk: C::ProvingKey,
}

/// A verifying key for the zk-wasmvm.
#[derive(Debug, Clone)]
pub struct CwVerifyingKey<C: ZkCurve> {
    pub(crate) params: C::Params,
    pub vk: C::VerifyingKey,
    pub footer: CircuitFooter,
}

/// The circuit params
#[derive(Debug)]
pub struct CwCircuitParam<C: ZkCurve> {
    pub(crate) params: C::Params,
}

/// The circuit constraint system
#[derive(Debug)]
pub struct CwConstraintSystem<C: ZkCurve> {
    pub(crate) cs: C::ConstraintSystem,
}

#[derive(Debug, Clone)]
pub enum AnyVerifyingKey {
    Vesta(VestaVerifyingKey),
}

impl TryFrom<&[u8]> for AnyVerifyingKey {
    type Error = ZkError;
    /// try_from for AnyVerifyingKey expects the bytes to contain:
    /// [0..param.len()] - circuit constraint system parameter bytes
    /// [cs_param..cs_len()] - constraint system
    /// [..bytes.len()-COSMWASM_FOOTER] - verifying key bytes
    /// [bytes.len()-COSMWASM_FOOTER..] -
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() < COSMWASM_FOOTER_LENGTH {
            return Err(ZkError::new_err("Data too short for footer"));
        }

        let footer =
            crate::CircuitFooter::from_bytes(&bytes[bytes.len() - COSMWASM_FOOTER_LENGTH..])?;

        // get specific circuit identifier for proper methods
        match footer.appstate_key() {
            pasta_curves::vesta::Affine::ID => {
                Ok(AnyVerifyingKey::Vesta(VestaVerifyingKey::try_from(bytes)?))
            }
            _ => Err(ZkError::UnsupportedCurve(footer.appstate_key())),
        }
    }
}

impl AnyVerifyingKey {
    pub fn to_bytes_with_params(&self) -> crate::ZkResult<Vec<u8>> {
        match self {
            AnyVerifyingKey::Vesta(vk) => Ok(vk.to_bytes_with_params()?),
        }
    }
    pub fn from_bytes(bytes: &[u8]) -> crate::ZkResult<Self> {
        let footer =
            crate::CircuitFooter::from_bytes(&bytes[bytes.len() - COSMWASM_FOOTER_LENGTH..])?;
        match footer.appstate_key() {
            pasta_curves::vesta::Affine::ID => Ok(AnyVerifyingKey::Vesta(
                VestaVerifyingKey::from_bytes_with_params(bytes)?,
            )),
            _ => Err(ZkError::UnsupportedCurve(footer.appstate_key())),
        }
    }

    pub fn verify(&self, proof: &Proof, i: &[AnyInstance]) -> crate::ZkResult<()> {
        match (self, i) {
            (AnyVerifyingKey::Vesta(vk), [AnyInstance::Vesta(i), ..]) => vk
                .verify(proof, std::slice::from_ref(i))
                .map_err(Into::into),
            _ => Err(ZkError::CurveMismatch),
        }
    }
}

pub enum AnyInstance {
    Vesta(crate::curves::VestaInstance),
}

// / Circuit type identifier for VK deserialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum CircuitType {
    #[default]
    Plonkish = 0,
}

impl TryFrom<AnyVerifyingKey> for CircuitType {
    type Error = ZkError;

    fn try_from(value: AnyVerifyingKey) -> Result<Self, Self::Error> {
        match value {
            AnyVerifyingKey::Vesta(_) => Ok(CircuitType::Plonkish),
        }
    }
}

impl TryFrom<u8> for CircuitType {
    type Error = ZkError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            _ => Ok(CircuitType::Plonkish),
        }
    }
}

impl Into<u8> for CircuitType {
    fn into(self) -> u8 {
        match self {
            CircuitType::Plonkish => 0,
        }
    }
}

impl AnyInstance {
    pub fn try_from_bytes(id: impl Into<u32>, bytes: &[u8]) -> ZkResult<Self> {
        match id.into() {
            0u32 => Ok(AnyInstance::Vesta(VestaInstance::try_from(bytes)?)),
            _ => Err(ZkError::CurveMismatch),
        }
    }
}

/// Custom section name for embedded verifying keys
/// Contracts can embed their VK in a WASM custom section with this name
pub const VK_CUSTOM_SECTION_NAME: &str = "cosmwasm_zk_vk";

#[derive(Debug, Clone)]
pub struct CsBlueprint {
    pub num_fixed_columns: u8,
    pub num_advice_columns: u8,
    pub num_instance_columns: u8,
    pub num_selectors: u32,
    pub permutation_columns: Vec<plonk::Column<plonk::Any>>,
}

#[derive(Clone, Debug)]
pub struct SerializedCircuitData {
    pub body: Vec<u8>,
    pub footer: Vec<u8>,
}

impl SerializedCircuitData {
    pub fn new(body: &[u8], footer: &[u8]) -> Self {
        Self {
            body: body.to_vec(),
            footer: footer.to_vec(),
        }
    }
    pub fn serialized_to_vec(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.body);
        buf.extend_from_slice(&self.footer);
        buf
    }
}

thread_local! {
    static CS_BLUEPRINT: RefCell<Option<CsBlueprint>> = RefCell::new(None);
}

// // / RAII Guard for DynamicCircuit thread-local configuration.
// // /
// // / Automatically clears the thread-local config when dropped, preventing leaks
// // / and reentrancy issues in concurrent scenarios.
#[must_use = "guard should be held for the entire operation"]
pub struct CsBlueprintGuard;

impl CsBlueprintGuard {
    pub fn install(blueprint: CsBlueprint) -> Self {
        println!("cw::vm::zk::cs_blueprint::install::{:#?}", blueprint);
        CS_BLUEPRINT.with(|bp| *bp.borrow_mut() = Some(blueprint));
        Self
    }
}

impl Drop for CsBlueprintGuard {
    fn drop(&mut self) {
        CS_BLUEPRINT.with(|bp| *bp.borrow_mut() = None);
    }
}

/// Generic circuit that implements `Circuit<vesta::Scalar>` dynamically.
///
/// Used for VK deserialization without needing the original Rust circuit type.
/// In v2 format, the serialized CS is included alongside the VK, so this only
/// needs to match the column structure — gates and lookups come from the CS.
#[derive(Debug, Clone)]
pub struct DynamicCircuit<F: group::ff::PrimeField> {
    _z: std::marker::PhantomData<F>,
}

impl<F: group::ff::PrimeField> DynamicCircuit<F> {
    pub fn new() -> Self {
        Self {
            _z: std::marker::PhantomData,
        }
    }
}

impl<F: group::ff::PrimeField> Circuit<F> for DynamicCircuit<F> {
    type Config = ();
    type FloorPlanner = halo2_proofs::circuit::SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::new()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        CS_BLUEPRINT.with(|bp_cell| {
            if let Some(blueprint) = &*bp_cell.borrow() {
                // Re-create the exact column structure
                for _ in 0..blueprint.num_fixed_columns {
                    let col = meta.fixed_column();
                    meta.enable_equality(col);
                }
                for _ in 0..blueprint.num_advice_columns {
                    let col = meta.advice_column();
                    meta.enable_equality(col);
                }
                for _ in 0..blueprint.num_instance_columns {
                    let col = meta.instance_column();
                    meta.enable_equality(col);
                }
                for _ in 0..blueprint.num_selectors {
                    meta.selector();
                }

                // Re-apply permutation columns (critical for correct VK read)
                for &col in &blueprint.permutation_columns {
                    meta.enable_equality(col);
                }
            } else {
                eprintln!("Warning: DynamicCircuit::configure called without CsBlueprint");
            }
        });
        ()
    }

    fn synthesize(
        &self,
        _config: Self::Config,
        _layouter: impl Layouter<F>,
    ) -> Result<(), plonk::Error> {
        // unimplemented as vm does not support proof creation
        Ok(())
    }
}

/// A struct defining a circuit compatible with the zk-wasmvm.
#[derive(Debug)]
pub struct CosmwasmCircuit<C> {
    pub(crate) circuit: C,
}

impl<C> CosmwasmCircuit<C> {
    pub fn new(circuit: C) -> Self {
        Self { circuit }
    }
}

impl<C, F> halo2_proofs::plonk::Circuit<F> for CosmwasmCircuit<C>
where
    C: Circuit<F>,
    F: group::ff::Field,
{
    type Config = C::Config;
    type FloorPlanner = C::FloorPlanner;

    fn without_witnesses(&self) -> Self {
        CosmwasmCircuit {
            circuit: self.circuit.without_witnesses(),
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        C::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        layouter: impl Layouter<F>,
    ) -> Result<(), plonk::Error> {
        self.circuit.synthesize(config, layouter)
    }
}

impl core::fmt::Debug for Proof {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if f.alternate() {
            f.debug_tuple("Proof").field(&self.0).finish()
        } else {
            f.debug_tuple("Proof")
                .field(&format_args!("{} bytes", self.0.len()))
                .finish()
        }
    }
}
