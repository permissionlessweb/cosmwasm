// packages/vm/src/zk.rs - Zero-knowledge proof support for CosmWasm

use group::ff::PrimeField;
use halo2_proofs::{
    arithmetic::Field,
    circuit::Layouter,
    plonk::{self, Circuit, ConstraintSystem},
    poly,
};
use pasta_curves::vesta;
use sha2::{Digest, Sha256};
use std::io::{self, Cursor, Read};
use std::sync::Arc;
use wasmer::wasmparser::{Parser, Payload};

use crate::VmError;

/// Custom section name for embedded verifying keys
/// Contracts can embed their VK in a WASM custom section with this name
pub const VK_CUSTOM_SECTION_NAME: &str = "cosmwasm_zk_vk";

pub type CosmwasmCircuitFp = CosmwasmCircuit<GenericCircuit>;

/// A struct defining a circuit compatible with the zk-wasmvm.
#[derive(Debug)]
pub struct CosmwasmCircuit<C> {
    circuit: C,
}

impl<C, F> Circuit<F> for CosmwasmCircuit<C>
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
    pub(crate) instances: Vec<vesta::Scalar>,
    size: usize,
}

impl Instance {
    pub fn new(i: Vec<vesta::Scalar>) -> Self {
        Self {
            instances: i.to_vec(),
            size: i.len(),
        }
    }
    pub fn new_from_vm(i: Vec<u8>) -> Result<Self, VmError> {
        const SCALAR_SIZE: usize = 32;
        if i.len() % SCALAR_SIZE != 0 {
            return Err(VmError::generic_err("bytes length must be multiple of 32"));
        }
        let instances = i
            .chunks_exact(SCALAR_SIZE)
            .map(|chunk| {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(chunk);
                vesta::Scalar::from_repr(arr).expect("invalid scalar bytes")
            })
            .collect::<Vec<_>>();
        let size = instances.len();
        Ok(Self { instances, size })
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
        circuits: &[CosmwasmCircuit<C>],
        instances: &[Instance],
        mut rng: impl rand::RngCore,
    ) -> Result<Self, plonk::Error> {
        for (circuit, instance) in circuits.iter().zip(instances) {
            // TODO: additional circuit instance validation
            // let expected_length = circuit.circuit.required_input_length();
            // if instance.instances.len() != expected_length {
            //     return Err(plonk::Error::InstanceTooLarge {});
            // }
        }
        let converted_columns: Vec<Vec<pasta_curves::Fp>> = instances
            .iter()
            .map(|i| {
                i.instances
                    .iter()
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
    pub fn verify(&self, vk: &VerifyingKey, instances: &[Instance]) -> Result<(), plonk::Error> {
        // Convert each Instance to a vector of pasta_curves::Fp, ensuring ownership.
        let converted_columns: Vec<Vec<pasta_curves::Fp>> = instances
            .iter()
            .map(|i| {
                i.instances
                    .iter()
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
    // pub fn add_to_batch(&self, batch: &mut BatchVerifier<vesta::Affine>, instances: Vec<Instance>) {
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

/// Circuit type identifier for VK deserialization
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CircuitType {
    /// Generic circuit type (works for any circuit)
    Generic = 0,
}

impl CircuitType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(CircuitType::Generic),
            _ => None,
        }
    }

    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

/// Code bundle containing WASM and optional verifying key
#[derive(Clone, Debug)]
pub struct CodeBundle {
    pub wasm: Vec<u8>,
    pub verifying_key: Option<SerializedVK>,
}

impl CodeBundle {
    pub fn wasm_only(wasm: Vec<u8>) -> Self {
        CodeBundle {
            wasm,
            verifying_key: None,
        }
    }

    pub fn with_vk(wasm: Vec<u8>, vk_bytes: Vec<u8>) -> Self {
        Self::with_vk_and_type(wasm, vk_bytes, CircuitType::Generic)
    }

    pub fn with_vk_and_type(wasm: Vec<u8>, vk_bytes: Vec<u8>, circuit_type: CircuitType) -> Self {
        let size_bytes = vk_bytes.len();
        let hash = {
            let mut hasher = Sha256::new();
            hasher.update(&vk_bytes);
            let result = hasher.finalize();
            let mut hash: [u8; 32] = [0u8; 32];
            hash.copy_from_slice(&result);
            hash
        };

        CodeBundle {
            wasm,
            verifying_key: Some(SerializedVK {
                bytes: vk_bytes,
                hash,
                circuit_type,
                size_bytes,
            }),
        }
    }
}

/// Serialized verifying key bundle that gets stored alongside WASM
#[derive(Clone, Debug)]
pub struct SerializedVK {
    /// Raw bytes of the serialized params + vk
    pub bytes: Vec<u8>,
    /// SHA256 hash of the bytes for integrity checking
    pub hash: [u8; 32],
    /// Circuit type for deserialization
    pub circuit_type: CircuitType,
    /// Size in bytes (for memory accounting)
    pub size_bytes: usize,
}

/// Deserialized verifying key ready for proof verification
/// This is what gets cached in memory when a contract needs it
#[derive(Debug)]
pub struct LoadedVerifyingKey(pub VerifyingKey);
/// Thread-safe handle to a pinned verifying key
pub type PinnedVK = Arc<LoadedVerifyingKey>;

impl LoadedVerifyingKey {
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
    pub fn vk(&self) -> &VerifyingKey {
        &self.0
    }

    /// Get actual memory footprint by serializing
    /// This is more accurate but requires serialization
    pub fn actual_size_bytes(&self) -> usize {
        self.to_bytes().map(|b| b.len()).unwrap_or(0)
    }

    /// Deserialize from raw bytes
    /// Format: [params_len (8 bytes LE)][params bytes][vk bytes]
    pub fn from_bytes(bytes: &[u8]) -> io::Result<Self> {
        if bytes.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Vk empty"));
        }

        // Read params length prefix
        let mut reader = Cursor::new(bytes);
        let mut params_len_bytes = [0u8; 8];
        let original_size = bytes.len();

        // Read instance lenth compiled in binary
        let i_len = bytes.len();

        reader.read_exact(&mut params_len_bytes)?;
        let params_len = u64::from_le_bytes(params_len_bytes) as usize;

        // Read params
        let mut params_bytes = vec![0u8; params_len];
        reader.read_exact(&mut params_bytes)?;

        // TODO: integrate circuit manifold middleware for marketplace of circuit use
        // Deserialize the circuit param bytes to be able to deserialize the verifying key from the param struct object.
        let params =
            poly::commitment::Params::<vesta::Affine>::read(&mut Cursor::new(params_bytes))?;
        let vk = halo2_proofs::plonk::VerifyingKey::<vesta::Affine>::read::<_, CosmwasmCircuitFp>(
            &mut reader,
            &params,
        )?;

        Ok(LoadedVerifyingKey(VerifyingKey::new(vk, params.k(), i_len)))
    }

    /// Serialize to bytes for storage
    pub fn to_bytes(&self) -> io::Result<Vec<u8>> {
        let mut output = Vec::new();
        let mut params_buf = Vec::new();

        // Call the write function for
        self.vk().params.write(&mut params_buf)?;
        // Write params length prefix
        output.extend_from_slice(&(params_buf.len() as u64).to_le_bytes());
        output.extend_from_slice(&params_buf);

        // Write VK
        self.vk().vk.write(&mut output)?;

        Ok(output)
    }
}

/// Validates that a VK blob can be deserialized
/// We use a generic circuit marker to avoid needing the actual circuit at validation time

/// Validates that a combined params+VK blob matches expected structure
/// This validates the file format written by `build_and_write`
pub fn validate_vk_bytes(bytes: &[u8]) -> io::Result<()> {
    if bytes.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "VK bytes cannot be empty",
        ));
    }

    let mut reader = Cursor::new(bytes);

    // Step 1: Read and validate params
    let params = halo2_proofs::poly::commitment::Params::<vesta::Affine>::read(&mut reader)
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to read params: {:?}", e),
            )
        })?;

    // Validate params k value is reasonable (typically 11-20 for circuits)
    let k = params.k();
    if k < 5 || k > 30 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Invalid k value: {}. Expected range [5, 30]", k),
        ));
    }

    // Step 2: Validate VK structure
    let current_pos = reader.position();
    let remaining = bytes.len() as u64 - current_pos;

    if remaining == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "No VK data after params",
        ));
    }

    // VK starts with version byte (0x01)
    let mut version = [0u8; 1];
    reader.read_exact(&mut version)?;
    if version[0] != 0x01 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Invalid VK version byte: expected 0x01, got 0x{:02x}",
                version[0]
            ),
        ));
    }

    // Read fixed_commitments count
    let mut count_bytes = [0u8; 4];
    reader.read_exact(&mut count_bytes)?;
    let fixed_commitments_count = u32::from_le_bytes(count_bytes);

    // Sanity check: circuits typically have 1-1000 fixed commitments
    if fixed_commitments_count > 10000 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Suspicious fixed_commitments count: {}",
                fixed_commitments_count
            ),
        ));
    }

    // Validate we have enough bytes for commitments
    // Each vesta::Affine commitment is 32 bytes
    let expected_commitment_bytes = (fixed_commitments_count as usize) * 32;
    let remaining_after_count = bytes.len() as u64 - reader.position();

    if remaining_after_count < expected_commitment_bytes as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Not enough bytes for {} commitments",
                fixed_commitments_count
            ),
        ));
    }

    // Skip past commitments (we've validated the count and size)
    reader.set_position(reader.position() + expected_commitment_bytes as u64);

    // The permutation structure follows, but its exact size is complex
    // At minimum, check we haven't exhausted the bytes
    if reader.position() >= bytes.len() as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Truncated VK: missing permutation data",
        ));
    }

    Ok(())
}

/// Extracts a verifying key from WASM custom sections
///
/// This function parses the WASM binary and looks for a custom section named
/// `cosmwasm_zk_vk`. If found, it extracts and validates the VK.
///
/// # Arguments
/// * `wasm` - The WASM binary to parse
///
/// # Returns
/// * `Ok(Some(SerializedVK))` - VK found and extracted
/// * `Ok(None)` - No VK custom section found (not an error)
/// * `Err(_)` - Invalid VK data or parsing error
pub fn extract_vk_from_wasm(wasm: &[u8]) -> io::Result<Option<SerializedVK>> {
    let parser = Parser::new(0);

    for payload in parser.parse_all(wasm) {
        match payload {
            Ok(Payload::CustomSection(reader)) => {
                if reader.name() == VK_CUSTOM_SECTION_NAME {
                    // Found the VK custom section
                    let vk_data = reader.data();

                    if vk_data.is_empty() {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "VK custom section is empty",
                        ));
                    }

                    // First byte is circuit type
                    let circuit_type = CircuitType::from_u8(vk_data[0]).ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "Invalid circuit type in VK")
                    })?;

                    // Remaining bytes are the VK
                    let vk_bytes = vk_data[1..].to_vec();
                    let size_bytes = vk_bytes.len();

                    // Validate VK format
                    validate_vk_bytes(&vk_bytes)?;

                    // Compute hash
                    let hash = {
                        let mut hasher = Sha256::new();
                        hasher.update(&vk_bytes);
                        let result = hasher.finalize();
                        let mut hash = [0u8; 32];
                        hash.copy_from_slice(&result);
                        hash
                    };

                    return Ok(Some(SerializedVK {
                        bytes: vk_bytes,
                        hash,
                        circuit_type,
                        size_bytes,
                    }));
                }
            }
            Ok(_) => continue,
            Err(e) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Failed to parse WASM: {}", e),
                ))
            }
        }
    }

    // No VK custom section found - this is OK
    Ok(None)
}

/// Minimal circuit for VK deserialization and testing
/// This satisfies the Circuit trait bounds without requiring a full circuit implementation
pub struct GenericCircuit;

impl halo2_proofs::plonk::Circuit<vesta::Scalar> for GenericCircuit {
    type Config = ();
    type FloorPlanner = halo2_proofs::circuit::SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        GenericCircuit
    }

    fn configure(_meta: &mut halo2_proofs::plonk::ConstraintSystem<vesta::Scalar>) -> Self::Config {
        ()
    }

    fn synthesize(
        &self,
        _config: Self::Config,
        _layouter: impl halo2_proofs::circuit::Layouter<vesta::Scalar>,
    ) -> Result<(), halo2_proofs::plonk::Error> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_empty() {
        assert!(validate_vk_bytes(&[]).is_err());
    }

    #[test]
    fn test_validate_truncated() {
        // Just a version byte, nothing else
        assert!(validate_vk_bytes(&[0x01]).is_err());
    }

    #[test]
    fn circuit_type_conversion() {
        assert_eq!(CircuitType::Generic.to_u8(), 0);
        assert_eq!(CircuitType::from_u8(0), Some(CircuitType::Generic));
        assert_eq!(CircuitType::from_u8(255), None);
    }

    #[test]
    fn code_bundle_wasm_only() {
        let wasm = vec![0u8; 100];
        let bundle = CodeBundle::wasm_only(wasm.clone());
        assert_eq!(bundle.wasm, wasm);
        assert!(bundle.verifying_key.is_none());
    }

    #[test]
    fn code_bundle_with_vk() {
        let wasm = vec![0u8; 100];
        let vk = vec![1u8; 200];
        let bundle = CodeBundle::with_vk(wasm.clone(), vk.clone());

        assert_eq!(bundle.wasm, wasm);
        assert!(bundle.verifying_key.is_some());

        let vk_data = bundle.verifying_key.unwrap();
        assert_eq!(vk_data.bytes, vk);
        assert_eq!(vk_data.circuit_type, CircuitType::Generic);
        assert_eq!(vk_data.size_bytes, 200);
        // Hash should be deterministic
        assert_ne!(vk_data.hash, [0u8; 32]);
    }

    // #[test]
    // fn memory_estimation() {
    //     // For k=11, we expect a reasonably sized VK
    //     let size = LoadedVerifyingKey::estimate_memory_size(11);
    //     // Should be in the range of megabytes
    //     assert!(size > 100_000); // > 100 KB
    //     assert!(size < 100_000_000); // < 100 MB

    //     // Larger k should give larger estimate
    //     let size_small = LoadedVerifyingKey::estimate_memory_size(8);
    //     let size_large = LoadedVerifyingKey::estimate_memory_size(14);
    //     assert!(size_large > size_small);
    // }

    #[test]
    fn validate_empty_vk_bytes() {
        let result = validate_vk_bytes(&[]);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("VK bytes cannot be empty"));
    }

    /// Helper to create a minimal valid WASM module with a custom section
    fn create_wasm_with_custom_section(section_name: &str, section_data: &[u8]) -> Vec<u8> {
        use wasm_encoder::{CustomSection, Module};

        let mut module = Module::new();

        // Add custom section
        let custom = CustomSection {
            name: std::borrow::Cow::Borrowed(section_name),
            data: std::borrow::Cow::Borrowed(section_data),
        };
        module.section(&custom);

        module.finish()
    }

    #[test]
    fn extract_vk_from_wasm_no_custom_section() {
        // Create a simple WASM without VK
        let wasm = wat::parse_str("(module)").unwrap();

        let result = extract_vk_from_wasm(&wasm).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn extract_vk_from_wasm_with_vk_section() {
        // Create VK data: [circuit_type][vk_bytes]
        let test_vk = b"test_vk_data_for_extraction";
        let mut vk_section_data = vec![CircuitType::Generic.to_u8()];
        vk_section_data.extend_from_slice(test_vk);

        // Create WASM with VK custom section
        let wasm = create_wasm_with_custom_section(VK_CUSTOM_SECTION_NAME, &vk_section_data);

        let result = extract_vk_from_wasm(&wasm).unwrap();
        assert!(result.is_some());

        let vk = result.unwrap();
        assert_eq!(vk.bytes, test_vk);
        assert_eq!(vk.circuit_type, CircuitType::Generic);
        assert_eq!(vk.size_bytes, test_vk.len());
    }

    #[test]
    fn extract_vk_from_wasm_empty_section() {
        // Create WASM with empty VK section
        let wasm = create_wasm_with_custom_section(VK_CUSTOM_SECTION_NAME, &[]);

        let result = extract_vk_from_wasm(&wasm);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("VK custom section is empty"));
    }

    #[test]
    fn extract_vk_from_wasm_invalid_circuit_type() {
        // Create VK data with invalid circuit type (255)
        let vk_section_data = vec![255u8, 1, 2, 3];

        // Create WASM with VK custom section
        let wasm = create_wasm_with_custom_section(VK_CUSTOM_SECTION_NAME, &vk_section_data);

        let result = extract_vk_from_wasm(&wasm);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid circuit type"));
    }

    #[test]
    fn extract_vk_from_wasm_wrong_section_name() {
        // Create WASM with different custom section name
        let test_vk = b"test_vk";
        let mut vk_section_data = vec![CircuitType::Generic.to_u8()];
        vk_section_data.extend_from_slice(test_vk);

        let wasm = create_wasm_with_custom_section("other_section", &vk_section_data);

        let result = extract_vk_from_wasm(&wasm).unwrap();
        assert!(result.is_none()); // Should not find VK with wrong section name
    }
}
