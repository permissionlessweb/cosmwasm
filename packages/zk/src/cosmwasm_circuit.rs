use std::io::{self, Cursor};

use group::ff::{Field, PrimeField};
use halo2_proofs::{
    circuit::Layouter,
    plonk::{self, Circuit, ConstraintSystem},
    poly, COSMWASM_METADATA_LENGTH,
};
use pasta_curves::vesta;

use crate::errors::{ZkError, ZkResult};

/// Minimal marker circuit for generic VK deserialization
#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultCircuit;

/// Thread-safe handle to a pinned verifying key
pub type PinnedCircuit = Arc<VerifyingKey>;

impl Circuit<vesta::Scalar> for DefaultCircuit {
    type Config = ();
    type FloorPlanner = halo2_proofs::circuit::SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        DefaultCircuit
    }

    fn configure(_meta: &mut ConstraintSystem<vesta::Scalar>) -> Self::Config {}

    fn synthesize(
        &self,
        _config: Self::Config,
        _layouter: impl Layouter<vesta::Scalar>,
    ) -> Result<(), plonk::Error> {
        Ok(())
    }
}

/// Trait implemented by circuits derived with #[cosmwasm_circuit]
/// Provides metadata and helper methods for VM-compatible circuits
pub trait CosmwasmCircuitFor<C: Circuit<vesta::Scalar>> {
    type PlonkishCircuitMetadata;
    type CircuitType;
    type VerifyingKey;

    /// Get metadata about the circuit
    fn circuit_metadata(&self) -> Self::PlonkishCircuitMetadata;

    /// Build the verifying key
    fn verifying_key(&self) -> Self::VerifyingKey;

    /// Get the circuit type
    fn ct(&self) -> Self::CircuitType;

    /// Get the instance count
    fn instance_count(&self) -> u8;

    /// Validate instance compatibility
    fn is_compatible(i: &[vesta::Scalar]) -> bool;
}

/// Circuit type identifier for VK deserialization
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CircuitType {
    /// Plonkish circuit type (currently halo2)
    Plonkish = 0,
}

impl Default for CircuitType {
    fn default() -> Self {
        CircuitType::Plonkish
    }
}

impl CircuitType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            _ => Some(CircuitType::Plonkish),
        }
    }

    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

/// A struct defining a circuit compatible with the zk-wasmvm.
#[derive(Debug)]
pub struct CosmwasmCircuit<C> {
    circuit: C,
}

/// implement minimal halo2-circuit trait for field-element.
impl<C, F> halo2_proofs::plonk::Circuit<F> for CosmwasmCircuit<C>
where
    C: Circuit<F>,
    F: Field,
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

impl<C: halo2_proofs::plonk::Circuit<pasta_curves::Fp>> CosmwasmCircuitFor<C>
    for CosmwasmCircuit<C>
{
    type PlonkishCircuitMetadata = ();
    type CircuitType = ();
    type VerifyingKey = ();

    fn circuit_metadata(&self) -> Self::PlonkishCircuitMetadata {
        ()
    }

    fn verifying_key(&self) -> Self::VerifyingKey {
        ()
    }

    fn ct(&self) -> Self::CircuitType {
        ()
    }

    fn instance_count(&self) -> u8 {
        0
    }

    fn is_compatible(i: &[vesta::Scalar]) -> bool {
        true
    }
}

/// A verifying key implementing the defualt params and vk definitions for a circuit compatible with this vm-layer.
#[derive(Debug)]
pub struct VerifyingKey {
    pub params: poly::commitment::Params<vesta::Affine>,
    pub vk: plonk::VerifyingKey<vesta::Affine>,
    pub i: usize,
}

impl VerifyingKey {
    /// Builds the verifying key from an existing VK.
    pub fn new(vk: plonk::VerifyingKey<vesta::Affine>, k: u32, i: usize) -> Self {
        VerifyingKey {
            params: poly::commitment::Params::new(k),
            vk,
            i,
        }
    }

    /// Builds the verifying key from a concrete circuit.
    pub fn build<C>(c: C, k: u32, i: usize) -> Self
    where
        C: Circuit<<pasta_curves::EqAffine as group::prime::PrimeCurveAffine>::Scalar>,
    {
        let params = halo2_proofs::poly::commitment::Params::new(k);
        let vk = plonk::keygen_vk(&params, &c).unwrap();
        VerifyingKey { params, vk, i }
    }
}

impl VerifyingKey {
    /// Estimate memory footprint for gas/resource accounting
    /// This provides a rough estimate based on the circuit size parameter k
    pub fn estimate_memory_size(k: u32) -> usize {
        let n = 1usize << k;
        // Params: g (n points) + g_lagrange (n points) + w + u
        // Each point is ~64 bytes (compressed)
        let params_size = (2 * n + 2) * 64;
        // VK: fixed_commitments + permutation + selectors (variable)
        // Rough estimate
        let vk_size = n * 32;
        params_size + vk_size
    }

    /// Get actual memory footprint by serializing
    /// This is more accurate but requires serialization
    pub fn actual_size_bytes(&self) -> usize {
        self.to_bytes().map(|b| b.len()).unwrap_or(0)
    }

    /// Deserialize from raw bytes
    /// Format: [params_len (8 bytes LE)][params bytes][vk bytes]
    pub fn from_bytes(bytes: &[u8]) -> ZkResult<Self> {
        eprintln!("📦 from_bytes called with {} bytes total", bytes.len());
        eprintln!(
            "   First 30 bytes of buffer: {:02x?}",
            &bytes[..30.min(bytes.len())]
        );
        eprintln!(
            "   Last 20 bytes of buffer: {:02x?}",
            &bytes[bytes.len().saturating_sub(20)..]
        );
        if bytes.len() < COSMWASM_METADATA_LENGTH {
            return Err(ZkError::new_err("VK data too short"));
        }

        // the last two bytes are the zk-vm version and any vm-aware metadata specified for circuit types
        // Extract the last 2 bytes as V and I
        // Extract footer (last 10 bytes)
        let footer_start = bytes.len() - COSMWASM_METADATA_LENGTH;
        eprintln!(
            "   footer_start index: {} (for {} byte buffer)",
            footer_start,
            bytes.len()
        );
        eprintln!("   Footer bytes: {:02x?}", &bytes[footer_start..]);

        // define all values for metadata params
        let v = CircuitType::from_u8(bytes[footer_start]).ok_or_else(|| {
            ZkError::new_err("LVK::from_bytes: Invalid circuit type in VK footer")
        })?;

        let i = bytes[footer_start + 1];
        let params_len = u32::from_le_bytes([
            bytes[footer_start + 2],
            bytes[footer_start + 3],
            bytes[footer_start + 4],
            bytes[footer_start + 5],
        ]) as usize;
        let vk_len = u32::from_le_bytes([
            bytes[footer_start + 6],
            bytes[footer_start + 7],
            bytes[footer_start + 8],
            bytes[footer_start + 9],
        ]) as usize;

        eprintln!(
            "v={:?}, i={}, params_len={}, vk_len={}",
            v, i, params_len, vk_len
        );

        // Extract params and vk sections
        let params_bytes = &bytes[..params_len];
        let vk_bytes = &bytes[params_len..params_len + vk_len];

        eprintln!(
            "   Params bytes (first 20): {:02x?}",
            &params_bytes[..20.min(params_bytes.len())]
        );
        eprintln!(
            "   VK bytes (first 20): {:02x?}",
            &vk_bytes[..20.min(vk_bytes.len())]
        );

        // Deserialize params
        let mut params_reader = Cursor::new(params_bytes);
        let p = poly::commitment::Params::<vesta::Affine>::read(&mut params_reader)?;

        // Deserialize vk 
        let mut vk_reader = Cursor::new(vk_bytes);
        let vk = halo2_proofs::plonk::VerifyingKey::<vesta::Affine>::read::<_, DefaultCircuit>(
            &mut vk_reader,
            &p,
        )?;

        Ok(VerifyingKey::new(vk, p.k(), i.into()))
    }

    /// Serialize to bytes for storage
    pub fn to_bytes(&self) -> io::Result<Vec<u8>> {
        let mut output = Vec::new();
        let mut params_buf = Vec::new();

        // Call the write function for
        self.params.write(&mut params_buf)?;
        // Write params length prefix
        output.extend_from_slice(&(params_buf.len() as u64).to_le_bytes());
        output.extend_from_slice(&params_buf);

        // // Write VK
        // self.vk().vk.write(&mut output)?;

        Ok(output)
    }
}

/// The proving key for the Orchard Action circuit.
#[derive(Debug)]
pub struct ProvingKey {
    params: halo2_proofs::poly::commitment::Params<vesta::Affine>,
    pk: plonk::ProvingKey<vesta::Affine>,
}

impl ProvingKey {
    /// Builds the proving key from a given circuit.
    pub fn build<C>(k: u32, circuit: C) -> Self
    where
        C: Circuit<<pasta_curves::EqAffine as group::prime::PrimeCurveAffine>::Scalar>,
    {
        let params = halo2_proofs::poly::commitment::Params::new(k);
        let wrapped_circuit = CosmwasmCircuit { circuit };
        let vk = plonk::keygen_vk(&params, &wrapped_circuit).unwrap();
        let pk = plonk::keygen_pk(&params, vk, &wrapped_circuit).unwrap();
        ProvingKey { params, pk }
    }

    /// Builds pk & vk, writes to file
    pub fn build_and_write(
        path: std::path::PathBuf,
        k: u32,
        circuit: impl Circuit<<pasta_curves::EqAffine as group::prime::PrimeCurveAffine>::Scalar>,
    ) -> io::Result<()> {
        let mut writer = io::BufWriter::new(std::fs::File::create(path)?);
        let pk = Self::build(k, circuit);
        pk.params.write(&mut writer)?;
        pk.pk.get_vk().write(&mut writer)?;
        io::Write::flush(&mut writer)
    }
    /// retrieve a clone of the params
    pub fn params(&self) -> halo2_proofs::poly::commitment::Params<vesta::Affine> {
        self.params.clone()
    }
}

/// Public inputs to the Headstash Action circuit.
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
            return Err(ZkError::new_err("bytes length must be multiple of 32"));
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
}

/// A proof of the validity of an Orchard [`Bundle`].
///
/// [`Bundle`]: crate::bundle::Bundle
#[derive(Clone)]
pub struct Proof(Vec<u8>);

impl core::fmt::Debug for Proof {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if f.alternate() {
            f.debug_tuple("Proof").field(&self.0).finish()
        } else {
            // By default, only show the proof length, not its contents.
            f.debug_tuple("Proof")
                .field(&format_args!("{} bytes", self.0.len()))
                .finish()
        }
    }
}

impl Proof {
    /// Constructs a new Proof value.
    pub fn new(bytes: Vec<u8>) -> Self {
        Proof(bytes)
    }
    /// Creates a proof for the given circuits and instances.
    pub fn create<C: halo2_proofs::plonk::Circuit<pasta_curves::Fp>>(
        pk: &ProvingKey,
        circuits: &[crate::CosmwasmCircuit<C>],
        i: &[Instance],
        mut rng: impl rand::RngCore,
    ) -> Result<Self, plonk::Error> {
        for (circuit, instance) in circuits.iter().zip(i) {
            // TODO: additional circuit instance validation
            // let expected_length = circuit.circuit.required_input_length();
            // if instance.instances.len() != expected_length {
            //     return Err(plonk::Error::InstanceTooLarge {});
            // }
        }
        let converted_columns: Vec<Vec<pasta_curves::Fp>> = i
            .iter()
            .map(|i| {
                i.i.iter()
                    .map(|&s| Into::<pasta_curves::Fp>::into(s))
                    .collect()
            })
            .collect();

        // Collect slices referencing these vectors.
        let column_slices: Vec<&[pasta_curves::Fp]> =
            converted_columns.iter().map(|v| v.as_slice()).collect();

        // Wrap for verify_proof: a single proof, potentially multiple instance columns.
        let instances_arg: &[&[&[pasta_curves::Fp]]] = &[column_slices.as_slice()];

        let mut transcript =
            halo2_proofs::transcript::Blake2bWrite::<_, vesta::Affine, _>::init(vec![]);
        plonk::create_proof(
            &pk.params,
            &pk.pk,
            circuits,
            instances_arg,
            &mut rng,
            &mut transcript,
        )?;
        Ok(Proof(transcript.finalize()))
    }

    /// Verifies this proof with the given instances.
    pub fn verify(&self, vk: &VerifyingKey, i: &[Instance]) -> Result<(), plonk::Error> {
        // Convert each Instance to a vector of pasta_curves::Fp, ensuring ownership.
        let converted_columns: Vec<Vec<pasta_curves::Fp>> = i
            .iter()
            .map(|i| {
                i.i.iter()
                    .map(|&s| Into::<pasta_curves::Fp>::into(s))
                    .collect()
            })
            .collect();

        // Collect slices referencing these vectors.
        let column_slices: Vec<&[pasta_curves::Fp]> =
            converted_columns.iter().map(|v| v.as_slice()).collect();

        // Wrap for verify_proof: a single proof, potentially multiple instance columns.
        let instances_arg: &[&[&[pasta_curves::Fp]]] = &[column_slices.as_slice()];

        let strategy = plonk::SingleVerifier::new(&vk.params);
        let mut transcript = halo2_proofs::transcript::Blake2bRead::init(&self.0[..]);
        plonk::verify_proof(&vk.params, &vk.vk, strategy, instances_arg, &mut transcript)
    }

    // /// Adds this proof to the given batch for verification with the given instances.
    // ///
    // /// Use this API if you want more control over how proof batches are processed. If you
    // /// just want to batch-validate Orchard bundles, use [`bundle::BatchValidator`].
    // ///
    // /// [`bundle::BatchValidator`]: crate::bundle::BatchValidator
    // pub fn add_to_batch(&self, batch: &mut BatchVerifier<vesta::Affine>, i: Vec<Instance>) {
    //     let instances = instances
    //         .iter()
    //         .map(|i| {
    //             i.to_halo2_instance()
    //                 .into_iter()
    //                 .map(|c| c.into_iter().collect())
    //                 .collect()
    //         })
    //         .collect();

    //     batch.add_proof(instances, self.0.clone());
    // }
}

// packages/vm/src/zk.rs - Zero-knowledge proof support for CosmWasm

use std::sync::Arc;
use wasmer::wasmparser::{Parser, Payload};

/// Custom section name for embedded verifying keys
/// Contracts can embed their VK in a WASM custom section with this name
pub const VK_CUSTOM_SECTION_NAME: &str = "cosmwasm_zk_vk";
pub const VK_VERSION: i32 = 0x01;

/// Metadata about a circuit in use of Plonk (Halo2 is our default) compatible with the CosmWasm VM
#[derive(Debug, Clone, Copy)]
pub struct PlonkishCircuitMetadata {
    pub ct: CircuitType,
    pub i: u8,
    pub vkpl: usize,
    pub vkl: usize,
}

impl PlonkishCircuitMetadata {
    pub fn new(ct: CircuitType, i: u8, vkpl: usize, vkl: usize) -> Self {
        Self { ct, i, vkpl, vkl }
    }
    /// Extract params bytes from the full VK file
    pub fn params_bytes<'a>(&self, full_bytes: &'a [u8]) -> &'a [u8] {
        &full_bytes[..self.vkpl]
    }

    /// Extract VK bytes from the full VK file
    pub fn vk_bytes<'a>(&self, full_bytes: &'a [u8]) -> &'a [u8] {
        &full_bytes[self.vkpl..self.vkpl + self.vkl]
    }

    /// Extract metadata/footer bytes from the full VK file
    pub fn metadata_bytes<'a>(&self, full_bytes: &'a [u8]) -> &'a [u8] {
        // take just COSMWASM_METADATA_LENGTH
        &full_bytes[self.vkpl + self.vkl..]
    }

    /// Total expected file size
    pub fn total_size(&self) -> usize {
        self.vkpl + self.vkl + COSMWASM_METADATA_LENGTH
    }

    /// Validate that the file size matches expected
    pub fn validate_size(&self, actual_size: usize) -> io::Result<()> {
        let expected = self.total_size();
        if actual_size != expected {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Size mismatch: got {} bytes, expected {}",
                    actual_size, expected
                ),
            ));
        }
        Ok(())
    }

    /// writes the plonkish circuit metadata footer to its own array of bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.ct.to_u8());
        bytes.extend_from_slice(&self.i.to_le_bytes());
        bytes.extend_from_slice(&(self.vkpl as u64).to_le_bytes());
        bytes.extend_from_slice(&(self.vkl as u64).to_le_bytes());
        bytes
    }
}
