use crate::errors::{ZkError, ZkResult};
use crate::CircuitFooter;
use group::ff::PrimeField;
use halo2_proofs::COSMWASM_FOOTER_LENGTH;
use halo2_proofs::{
    circuit::Layouter,
    plonk::{self, Circuit, ConstraintSystem},
};
use pasta_curves::vesta;
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::io::{self, Cursor};

/// Custom section name for embedded verifying keys
/// Contracts can embed their VK in a WASM custom section with this name
pub const VK_CUSTOM_SECTION_NAME: &str = "cosmwasm_zk_vk";

/// Thread-safe handle to a pinned verifying key
pub type PinnedCircuit = VerifyingKey;

#[derive(Debug, Clone)]
pub struct CsBlueprint {
    pub num_fixed_columns: u8,
    pub num_advice_columns: u8,
    pub num_instance_columns: u8,
    pub num_selectors: u32,
    pub permutation_columns: Vec<plonk::Column<plonk::Any>>,
}

#[derive(Clone, Debug)]
pub struct SerializedPlonkishCircuitData {
    pub body: Vec<u8>,
    pub footer: Vec<u8>,
}

impl SerializedPlonkishCircuitData {
    pub fn new(bytes: &[u8], footer: &[u8]) -> Self {
        Self {
            body: bytes.to_vec(),
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
    static CS_BLUEPRINT: RefCell<Option<CsBlueprint>> = const { RefCell::new(None) };
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
pub struct DynamicCircuit;

impl DynamicCircuit {
    /// Create a new dynamic circuit with the specified column structure.
    pub fn new() -> Self {
        Self {}
    }

    // /// Get the current thread-local configuration.
    // fn current_config() -> Option<CsBlueprint> {
    //     CS_BLUEPRINT.with(|cfg| <Option<CsBlueprint> as Clone>::clone(&*cfg.borrow()))
    // }

    // /// Clear the thread-local configuration.
    // pub fn clear_current() {
    //     CS_BLUEPRINT.with(|bp| *bp.borrow_mut() = None);
    // }
}

impl Circuit<vesta::Scalar> for DynamicCircuit {
    type Config = ();
    type FloorPlanner = halo2_proofs::circuit::SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::new()
    }

    fn configure(meta: &mut ConstraintSystem<vesta::Scalar>) -> Self::Config {
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
        
    }

    fn synthesize(
        &self,
        _config: Self::Config,
        _layouter: impl Layouter<vesta::Scalar>,
    ) -> Result<(), plonk::Error> {
        // unimplemented as vm does not support proof creation
        Ok(())
    }
}

//

/// Circuit type identifier for VK deserialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[derive(Default)]
pub enum CircuitType {
    #[default]
    Plonkish = 0,
}


impl CircuitType {
    pub fn from_u8(_value: u8) -> Option<Self> {
        Some(CircuitType::Plonkish)
    }

    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

/// A verifying key for the zk-wasmvm.
#[derive(Debug, Clone)]
pub struct VerifyingKey {
    pub params: halo2_proofs::poly::commitment::Params<vesta::Affine>,
    pub vk: plonk::VerifyingKey<vesta::Affine>,
    pub footer: CircuitFooter,
}

impl VerifyingKey {
    /// Create with existing params (use when deserializing).
    pub fn new(
        params: halo2_proofs::poly::commitment::Params<vesta::Affine>,
        vk: plonk::VerifyingKey<vesta::Affine>,
        footer: CircuitFooter,
    ) -> Self {
        VerifyingKey { params, vk, footer }
    }
}

impl VerifyingKey {
    /// Build a verifying key and serialize to v2 format in one shot.
    /// needs for circuit-agnostic verification. The footer is generated
    /// automatically from the circuit's constraint system.
    ///
    /// # Arguments
    /// * `c` — circuit instance (used for keygen; consumed)
    /// * `k` — circuit size parameter (log2 of number of rows)
    /// * `instance_count` — number of public input scalars
    pub fn build<C>(c: C, k: u32, i: usize) -> io::Result<Vec<u8>>
    where
        C: Circuit<<pasta_curves::EqAffine as group::prime::PrimeCurveAffine>::Scalar>,
    {
        let params = halo2_proofs::poly::commitment::Params::<vesta::Affine>::new(k);
        let vk = plonk::keygen_vk(&params, &c).unwrap();

        let mut buf1: Vec<u8> = Vec::new();
        let mut buf2 = Vec::new();
        let mut buf3 = Vec::new();

        params.write(&mut buf1)?;
        vk.cs().write(&mut buf2)?;
        vk.write(&mut buf3)?;

        let param_len = buf1.len();
        let cs_len = buf2.len();
        let vk_len = buf3.len();

        let param_checksum = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&buf1));
        let cs_checksum = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&buf2));
        let vk_checksum = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&buf3));

        println!(
            "cw::vm::BUILD::param::(len::{},checksum::{})",
            param_len, param_checksum
        );
        println!(
            "cw::vm::BUILD::cs::(len::{},checksum::{})",
            cs_len, cs_checksum
        );
        println!(
            "cw::vm::BUILD::vk::(len::{},checksum::{})",
            vk_len, vk_checksum
        );

        let mut output = Vec::with_capacity(param_len + cs_len + vk_len + COSMWASM_FOOTER_LENGTH);

        output.extend_from_slice(&buf1);
        output.extend_from_slice(&buf2);
        output.extend_from_slice(&buf3);

        let footer = CircuitFooter::new(
            CircuitType::Plonkish,
            i as u8,
            param_len as u32,
            cs_len as u32,
            vk_len as u32,
            Sha256::digest(&output).into(), // does not hash footer content
        );

        output.extend_from_slice(&footer.to_bytes());

        Ok(output)
    }

    /// The embedded CS is deserialized and used for VK reconstruction,
    /// giving exact circuit-agnostic verification without the original Rust type.
    pub fn from_bytes(bytes: &[u8]) -> ZkResult<Self> {
        let footer_bytes = &bytes[bytes.len() - COSMWASM_FOOTER_LENGTH..];
        let footer = crate::CircuitFooter::from_bytes(footer_bytes)?;

        let mut reader = Cursor::new(bytes);
        let params = halo2_proofs::poly::commitment::Params::<vesta::Affine>::read(&mut reader)?;

        let cs: ConstraintSystem<vesta::Scalar> = ConstraintSystem::read(&mut reader)?;

        let _guard = CsBlueprintGuard::install(CsBlueprint {
            num_fixed_columns: cs.get_num_fixed_columns(),
            num_advice_columns: cs.get_num_advice_columns(),
            num_instance_columns: cs.get_num_instance_columns(),
            num_selectors: cs.get_num_selectors(),
            permutation_columns: cs.get_permutation_columns(),
        });

        let empty_selectors: Vec<Vec<bool>> = vec![];
        let vk = halo2_proofs::plonk::VerifyingKey::read_with_cs::<std::io::Cursor<&[u8]>>(
            &mut reader,
            &params,
            cs,
            empty_selectors,
        )
        .map_err(|e| {
            ZkError::new_io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("{:?}", e),
            ))
        })?;

        Ok(VerifyingKey::new(params, vk, footer))
    }

    pub fn to_bytes(&self) -> io::Result<Vec<u8>> {
        let mut buf1 = Vec::new();
        let mut buf2 = Vec::new();
        let mut buf3 = Vec::new();

        self.params.write(&mut buf1)?;
        self.vk.cs().write(&mut buf2)?;
        self.vk.write(&mut buf3)?;

        println!(
            "cw::vm::vk::from_bytes::params::(len::{},checksum::{})",
            buf1.len(),
            hex::encode(Sha256::digest(&buf1)),
        );
        println!(
            "cw::vm::vk::from_bytes::cs::(len::{},checksum::{})",
            buf2.len(),
            hex::encode(Sha256::digest(&buf2)),
        );
        println!(
            "cw::vm::vk::from_bytes::(len::{},checksum::{})",
            buf3.len(),
            hex::encode(Sha256::digest(&buf3)),
        );

        let mut output = Vec::new();
        output.extend_from_slice(&buf1);
        output.extend_from_slice(&buf2);
        output.extend_from_slice(&buf3);
        output.extend_from_slice(&self.footer.to_bytes());

        Ok(output)
    }
}

/// The proving key.
#[derive(Debug)]
pub struct ProvingKey {
    params: halo2_proofs::poly::commitment::Params<vesta::Affine>,
    _pk: plonk::ProvingKey<vesta::Affine>,
}

impl ProvingKey {
    // /// Build from a given circuit.
    // pub fn build<C>(k: u32, circuit: C) -> Self
    // where
    //     C: Circuit<<pasta_curves::EqAffine as group::prime::PrimeCurveAffine>::Scalar>,
    // {
    //     let params = halo2_proofs::poly::commitment::Params::new(k);
    //     let wrapped_circuit = CosmwasmCircuit { circuit };
    //     let vk = plonk::keygen_vk(&params, &wrapped_circuit).unwrap();
    //     let pk = plonk::keygen_pk(&params, vk, &wrapped_circuit).unwrap();
    //     ProvingKey { params, _pk: pk }
    // }

    pub fn params(&self) -> halo2_proofs::poly::commitment::Params<vesta::Affine> {
        self.params.clone()
    }
}

/// Public inputs.
#[derive(Clone, Debug)]
pub struct Instance {
    pub(crate) i: Vec<vesta::Scalar>,
    size: usize,
}

impl Instance {
    pub fn new(i: Vec<vesta::Scalar>) -> Self {
        Self {
            i: i.to_vec(),
            size: i.len(),
        }
    }

    pub fn new_from_vm(i: Vec<u8>) -> ZkResult<Self> {
        const SCALAR_SIZE: usize = 32;
        if i.len() % SCALAR_SIZE != 0 {
            return Err(ZkError::new_err(format!(
                "bytes length must be multiple of {SCALAR_SIZE}"
            )));
        }
        let is = i
            .chunks_exact(SCALAR_SIZE)
            .map(|chunk| {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(chunk);
                vesta::Scalar::from_repr(arr).expect("invalid scalar bytes")
            })
            .collect::<Vec<_>>();
        let size = is.len();
        Ok(Self { i: is, size })
    }

    pub fn get_size(&self) -> usize {
        self.size
    }
}

/// A proof of circuit validity.
#[derive(Clone)]
pub struct Proof(Vec<u8>);

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

impl Proof {
    pub fn new(bytes: Vec<u8>) -> Self {
        Proof(bytes)
    }

    // /// Create a proof for the given circuits and instances.
    // pub fn create<C: halo2_proofs::plonk::Circuit<pasta_curves::Fp>>(
    //     pk: &ProvingKey,
    //     circuits: &[crate::CosmwasmCircuit<C>],
    //     i: &[Instance],
    //     mut rng: impl rand::RngCore,
    // ) -> Result<Self, plonk::Error> {
    //     let converted_columns: Vec<Vec<pasta_curves::Fp>> = i
    //         .iter()
    //         .map(|i| {
    //             i.i.iter()
    //                 .map(|&s| Into::<pasta_curves::Fp>::into(s))
    //                 .collect()
    //         })
    //         .collect();

    //     let column_slices: Vec<&[pasta_curves::Fp]> =
    //         converted_columns.iter().map(|v| v.as_slice()).collect();

    //     let instances_arg: &[&[&[pasta_curves::Fp]]] = &[column_slices.as_slice()];

    //     let mut transcript =
    //         halo2_proofs::transcript::Blake2bWrite::<_, vesta::Affine, _>::init(vec![]);
    //     plonk::create_proof(
    //         &pk.params,
    //         &pk.pk,
    //         circuits,
    //         instances_arg,
    //         &mut rng,
    //         &mut transcript,
    //     )?;
    //     Ok(Proof(transcript.finalize()))
    // }

    /// Verify this proof with the given instances.
    pub fn verify(&self, vk: &VerifyingKey, i: &[Instance]) -> Result<(), plonk::Error> {
        let instances: Vec<Vec<pasta_curves::Fp>> = i
            .iter()
            .map(|inst| inst.i.iter().copied().collect())
            .collect();

        let column_refs: Vec<&[pasta_curves::Fp]> =
            instances.iter().map(|v| v.as_slice()).collect();

        let instances_arg: &[&[&[pasta_curves::Fp]]] = &[&column_refs];

        let strategy = plonk::SingleVerifier::new(&vk.params);
        let mut transcript = halo2_proofs::transcript::Blake2bRead::init(&self.0[..]);

        plonk::verify_proof(&vk.params, &vk.vk, strategy, instances_arg, &mut transcript)
    }
}
