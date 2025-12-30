// packages/vm/src/zk.rs - Zero-knowledge proof support for CosmWasm

use cosmwasm_std::Checksum;
use group::ff::PrimeField;
use halo2_proofs::{
    arithmetic::Field,
    circuit::Layouter,
    plonk::{self, Circuit, ConstraintSystem},
    poly, COSMWASM_METADATA_LENGTH,
};
use pasta_curves::{pallas, vesta};
use sha2::{Digest, Sha256};
use std::io::{self, Cursor, Read};
use std::sync::Arc;
use wasmer::wasmparser::{Parser, Payload};
use zk_headstash::example_circuits::no_rick::NoRickCircuit;

use crate::{VmError, VmResult};

/// Custom section name for embedded verifying keys
/// Contracts can embed their VK in a WASM custom section with this name
pub const VK_CUSTOM_SECTION_NAME: &str = "cosmwasm_zk_vk";
pub const VK_VERSION: i32 = 0x01;

pub type CosmwasmCircuitFp = CosmwasmCircuit<NoRickCircuit<pallas::Base>>;

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

/// Metadata extracted from a verified VK blob
#[derive(Debug, Clone)]
pub struct ZkMetadata {
    pub circuit_type: CircuitType,
    pub instances: u8,
    pub params_len: usize,
    pub vk_len: usize,
}

impl ZkMetadata {
    /// Extract params bytes from the full VK file
    pub fn params_bytes<'a>(&self, full_bytes: &'a [u8]) -> &'a [u8] {
        &full_bytes[..self.params_len]
    }

    /// Extract VK bytes from the full VK file
    pub fn vk_bytes<'a>(&self, full_bytes: &'a [u8]) -> &'a [u8] {
        &full_bytes[self.params_len..self.params_len + self.vk_len]
    }

    /// Extract metadata/footer bytes from the full VK file
    pub fn metadata_bytes<'a>(&self, full_bytes: &'a [u8]) -> &'a [u8] {
        // take just COSMWASM_METADATA_LENGTH
        &full_bytes[self.params_len + self.vk_len..]
    }

    /// Total expected file size
    pub fn total_size(&self) -> usize {
        self.params_len + self.vk_len + COSMWASM_METADATA_LENGTH
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

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.circuit_type.to_u8());
        bytes.extend_from_slice(&self.instances.to_le_bytes());
        bytes.extend_from_slice(&(self.params_len as u64).to_le_bytes());
        bytes.extend_from_slice(&(self.vk_len as u64).to_le_bytes());
        bytes
    }

    /// Hash the verifying key bytes using the same method as halo2
    /// halo2 uses Blake2b-256 for circuit hashing
    pub fn hash_vk(&self, full_bytes: &[u8]) -> Checksum {
        Checksum::generate(&self.vk_bytes(full_bytes))
    }

    /// Validate that the VK hash matches expected
    pub fn validate_vk_hash(&self, full_bytes: &[u8], expected_hash: &[u8; 32]) -> io::Result<()> {
        let computed_hash = self.hash_vk(full_bytes);
        if computed_hash != <[u8; 32] as Into<Checksum>>::into(*expected_hash) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "VK hash mismatch: got {:?}, expected {:?}",
                    computed_hash, expected_hash
                ),
            ));
        }
        Ok(())
    }
}

/// Circuit type identifier for VK deserialization
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CircuitType {
    /// Generic circuit type (works for any circuit)
    Generic = 0,
}

impl Default for CircuitType {
    fn default() -> Self {
        CircuitType::Generic
    }
}

impl CircuitType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            _ => Some(CircuitType::Generic),
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

    /// validates binary structure, returns hash of just verifying key (mimics release specification of halo2 circuits for interoperability)
    pub fn with_vk(wasm: Vec<u8>, vk_bytes: Vec<u8>) -> io::Result<Self> {
        let (vk, hash) = check_vk(&vk_bytes)?;
        Ok(Self::with_vk_and_type(wasm, vk_bytes, &vk, hash))
    }

    pub fn with_vk_and_type(
        wasm: Vec<u8>,
        vk_bytes: Vec<u8>,
        metadata: &ZkMetadata,
        hash: Checksum,
    ) -> Self {
        CodeBundle {
            wasm,
            verifying_key: Some(SerializedVK::new(&vk_bytes, &hash, metadata)),
        }
    }
}

/// Serialized verifying key bundle that gets stored alongside WASM
#[derive(Clone, Debug)]
pub struct SerializedVK {
    /// Raw bytes of the serialized params + vk
    pub bytes: Vec<u8>,
    /// SHA256 hash of the bytes for integrity checking
    pub hash: Checksum,
    /// Circuit metadata
    pub metadata: ZkMetadata,
}

impl SerializedVK {
    pub fn new(bytes: &[u8], hash: &Checksum, metadata: &ZkMetadata) -> Self {
        Self {
            bytes: bytes.into(),
            hash: *hash,
            metadata: metadata.clone(),
        }
    }
}

impl From<Vec<u8>> for SerializedVK {
    fn from(value: Vec<u8>) -> Self {
        let mut offset = 0;

        // Circuit type (1 byte)
        let ct = CircuitType::from_u8(value[offset]).unwrap_or_default();
        offset += 1;

        // Instances (1 byte)
        let i = value[offset];
        offset += 1;

        // Params len (8 bytes)
        let vkpl = u64::from_le_bytes([
            value[offset],
            value[offset + 1],
            value[offset + 2],
            value[offset + 3],
            value[offset + 4],
            value[offset + 5],
            value[offset + 6],
            value[offset + 7],
        ]) as usize;
        offset += 8;

        // VK len (8 bytes)
        let vk_len = u64::from_le_bytes([
            value[offset],
            value[offset + 1],
            value[offset + 2],
            value[offset + 3],
            value[offset + 4],
            value[offset + 5],
            value[offset + 6],
            value[offset + 7],
        ]) as usize;
        offset += 8;

        // Hash (32 bytes)
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&value[offset..offset + 32]);
        offset += 32;

        // Bytes (remaining)
        let bytes = value[offset..].to_vec();

        SerializedVK {
            bytes,
            hash: hash.into(),
            metadata: ZkMetadata {
                circuit_type: ct,
                instances: i,
                params_len: vkpl,
                vk_len,
            },
        }
    }
}

impl Into<Vec<u8>> for SerializedVK {
    fn into(self) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend_from_slice(&self.bytes);
        result.extend_from_slice(&self.hash.as_slice());
        result.extend_from_slice(&self.metadata.to_bytes());
        result
    }
}

/// Deserialized verifying key ready for proof verification
/// This is what gets cached in memory when a contract needs it
#[derive(Debug)]
pub struct LoadedVerifyingKey(pub VerifyingKey);
/// Thread-safe handle to a pinned verifying key
pub type PinnedCircuit = Arc<LoadedVerifyingKey>;

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
    pub fn from_bytes(bytes: &[u8]) -> VmResult<Self> {
        eprintln!("📦 from_bytes called with {} bytes total", bytes.len());
        eprintln!(
            "   First 30 bytes of buffer: {:02x?}",
            &bytes[..30.min(bytes.len())]
        );
        eprintln!(
            "   Last 20 bytes of buffer: {:02x?}",
            &bytes[bytes.len().saturating_sub(20)..]
        );
        if bytes.len() < 10 {
            return Err(VmError::generic_err(
                "VK data too short - need at least 2 header bytes + 4 byte K",
            ));
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
            VmError::generic_err("LVK::from_bytes: Invalid circuit type in VK footer")
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
        let p = poly::commitment::Params::<vesta::Affine>::read(&mut params_reader)
            .map_err(|e| VmError::generic_err(e.to_string()))?;

        // Deserialize vk
        let mut vk_reader = Cursor::new(vk_bytes);
        let vk = halo2_proofs::plonk::VerifyingKey::<vesta::Affine>::read::<_, CosmwasmCircuitFp>(
            &mut vk_reader,
            &p,
        )
        .map_err(|e| VmError::generic_err(e.to_string()))?;

        Ok(LoadedVerifyingKey(VerifyingKey::new(vk, p.k(), i.into())))
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

        // // Write VK
        // self.vk().vk.write(&mut output)?;

        Ok(output)
    }
}

/// Validates that a VK blob can be deserialized
/// We use a generic circuit marker to avoid needing the actual circuit at validation time

/// Validates that a combined params+VK blob matches expected structure
/// This validates the file format written by `build_and_write`
pub fn check_vk(bytes: &[u8]) -> io::Result<(ZkMetadata, Checksum)> {
    if bytes.len() < COSMWASM_METADATA_LENGTH {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "VK bytes too short - need at least {} bytes for footer",
                COSMWASM_METADATA_LENGTH
            ),
        ));
    }

    // Step 1: Parse the COSMWASM_METADATA_LENGTH-byte footer (last 10 bytes)
    let footer_start = bytes.len() - COSMWASM_METADATA_LENGTH;

    let v = CircuitType::from_u8(bytes[footer_start]).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Invalid circuit type in VK footer: 0x{:02x}",
                bytes[footer_start]
            ),
        )
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

    // Step 2: Validate file structure
    let expected_total = params_len + vk_len + COSMWASM_METADATA_LENGTH;
    if bytes.len() != expected_total {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "VK file size mismatch: got {} bytes, expected {} (params:{} + vk:{} + footer:{})",
                bytes.len(),
                expected_total,
                params_len,
                vk_len,
                COSMWASM_METADATA_LENGTH
            ),
        ));
    }

    // Step 4: Validate VK exists and has minimum content
    if vk_len == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "VK length cannot be 0",
        ));
    }

    let vk_bytes = &bytes[params_len..params_len + vk_len];

    // VK bytes should exists
    if vk_bytes.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("No VK bytes recognized"),
        ));
    }

    eprintln!("✓ VK structure validated: version=0x01");

    let zk = ZkMetadata {
        circuit_type: v,
        instances: i,
        params_len,
        vk_len,
    };
    let hash = zk.hash_vk(bytes);
    Ok((zk, hash))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_empty() {
        assert!(check_vk(&[]).is_err());
    }

    #[test]
    fn test_validate_truncated() {
        // Just a version byte, nothing else
        assert!(check_vk(&[0x01]).is_err());
    }

    #[test]
    fn circuit_type_conversion() {
        assert_eq!(CircuitType::Generic.to_u8(), 0);
        assert_eq!(CircuitType::from_u8(0), Some(CircuitType::Generic));
        assert_eq!(CircuitType::from_u8(255), Some(CircuitType::Generic));
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

        // Define sizes
        let vkp_len: u32 = 90;
        let vk_len: u32 = 100; // The actual vk portion
        let footer_len: u32 = 10;
        // Total = 90 + 100 + 10 = 200 bytes
        //
        // Build footer (10 bytes)
        let mut footer = [0u8; 10];
        footer[0] = 0x01; // Version
        footer[1] = 0x02; // # public instances
        footer[2..6].copy_from_slice(&vkp_len.to_le_bytes());
        footer[6..10].copy_from_slice(&vk_len.to_le_bytes());
        // Build the full vk blob
        let mut vk_blob = Vec::new();
        vk_blob.extend(vec![0xAA; vkp_len as usize]); // vk_params (90 bytes)
        vk_blob.extend(vec![0xBB; vk_len as usize]); // vk data (100 bytes)
        vk_blob.extend_from_slice(&footer); // footer (10 bytes)

        assert_eq!(vk_blob.len(), 200); // Sanity check

        let bundle = CodeBundle::with_vk(wasm.clone(), vk_blob.clone()).unwrap();

        assert_eq!(bundle.wasm, wasm);
        assert!(bundle.verifying_key.is_some());

        let vk_data = bundle.verifying_key.unwrap();

        assert_eq!(vk_data.bytes, vk_blob);
        assert_eq!(vk_data.metadata.circuit_type, CircuitType::Generic);
        assert_eq!(vk_data.metadata.vk_len, 100); // Total blob length
        assert_ne!(vk_data.hash, Checksum::from([0u8; 32]));
    }

    #[test]
    fn validate_empty_vk_bytes() {
        let result = check_vk(&[]);
        println!("{:#?}", result);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("VK bytes too short - need at least 10 bytes for footer"));
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
}
