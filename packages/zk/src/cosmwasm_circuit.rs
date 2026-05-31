use std::io::{self, Cursor};
use std::sync::Arc;

use crate::{
    errors::{ZkError, ZkResult},
    CircuitFooter,
};
use group::ff::{Field, PrimeField};
use halo2_proofs::{
    circuit::Layouter,
    plonk::{self, Circuit, ConstraintSystem},
    poly,
};
use pasta_curves::vesta;

/// Custom section name for embedded verifying keys
/// Contracts can embed their VK in a WASM custom section with this name
pub const VK_CUSTOM_SECTION_NAME: &str = "cosmwasm_zk_vk";

/// Thread-safe handle to a pinned verifying key
pub type PinnedCircuit = Arc<VerifyingKey>;

/// Footer flags bit definitions
pub mod footer_flags {
    /// Constraint system section is present (must be 1 for v2)
    pub const HAS_CS: u8 = 0b0000_0001;
    /// Circuit contains lookup arguments
    pub const HAS_LOOKUPS: u8 = 0b0000_0010;
}

/// Basic metadata about a Plonkish circuit
#[derive(Debug, Clone, Copy)]
pub struct PlonkishCircuitMetadata {
    /// Circuit type identifier
    pub ct: CircuitType,
    /// Number of public inputs (instance count)
    pub i: u8,
    /// Circuit name (for debugging)
    pub name: &'static str,
}

impl PlonkishCircuitMetadata {
    /// Create new metadata
    pub const fn new(ct: CircuitType, i: u8, name: &'static str) -> Self {
        Self { ct, i, name }
    }
}

/// Metadata about a circuit's constraint system
///
/// Dynamically extracted from the circuit's `configure()` method.
#[derive(Debug, Clone)]
pub struct ConstraintSystemMetadata {
    /// Number of fixed columns in the constraint system
    pub num_fixed_columns: u32,
    /// Number of advice (witness) columns in the constraint system
    pub num_advice_columns: u32,
    /// Number of instance (public) columns in the constraint system
    pub num_instance_columns: u32,
    /// Number of selectors in the constraint system
    pub num_selectors: u32,
    /// Number of gates in the constraint system
    pub num_gates: u32,
    /// Maximum polynomial degree across all constraints
    pub degree: u8,
    /// Whether the circuit contains lookup arguments
    pub has_lookups: bool,
    /// Columns that participate in copy constraints (permutation)
    pub permutation_columns: Vec<plonk::Column<plonk::Any>>,
}

impl Default for ConstraintSystemMetadata {
    fn default() -> Self {
        Self {
            num_fixed_columns: 0,
            num_advice_columns: 0,
            num_instance_columns: 0,
            num_selectors: 0,
            num_gates: 0,
            degree: 0,
            has_lookups: false,
            permutation_columns: Vec::new(),
        }
    }
}

/// Dynamic circuit configuration (v2: column counts only, CS is serialized separately)
#[derive(Debug, Clone, Copy)]
pub struct DynamicCircuitConfig {
    pub num_fixed_columns: u8,
    pub num_advice_columns: u8,
    pub num_instance_columns: u8,
    pub num_selectors: u32,
}

// Thread-local storage for circuit config during keygen
thread_local! {
    static DYNAMIC_CIRCUIT_CONFIG: std::cell::RefCell<Option<DynamicCircuitConfig>> =
        std::cell::RefCell::new(None);
}

/// RAII Guard for DynamicCircuit thread-local configuration.
///
/// Automatically clears the thread-local config when dropped, preventing leaks
/// and reentrancy issues in concurrent scenarios.
#[must_use = "guard should be held for the entire operation"]
pub struct DynamicCircuitGuard;

impl DynamicCircuitGuard {
    fn new() -> Self {
        Self
    }
}

impl Drop for DynamicCircuitGuard {
    fn drop(&mut self) {
        DynamicCircuit::clear_current();
    }
}

/// Generic circuit that implements `Circuit<vesta::Scalar>` dynamically.
///
/// Used for VK deserialization without needing the original Rust circuit type.
/// In v2 format, the serialized CS is included alongside the VK, so this only
/// needs to match the column structure — gates and lookups come from the CS.
///
/// # Usage
/// ```ignore
/// let circuit = DynamicCircuit::from_footer(&footer);
/// let _guard = circuit.set_as_current_guarded();
/// // halo2::VerifyingKey::read can now use it
/// ```
#[derive(Debug, Clone)]
pub struct DynamicCircuit {
    config: DynamicCircuitConfig,
}

impl DynamicCircuit {
    /// Create a new dynamic circuit with the specified column structure.
    pub fn new(
        num_fixed_columns: u8,
        num_advice_columns: u8,
        num_instance_columns: u8,
        num_selectors: u32,
    ) -> Self {
        Self {
            config: DynamicCircuitConfig {
                num_fixed_columns,
                num_advice_columns,
                num_instance_columns,
                num_selectors,
            },
        }
    }

    /// Create from a v2 circuit footer.
    pub fn from_footer(footer: &CircuitFooter) -> Self {
        Self {
            config: DynamicCircuitConfig {
                num_fixed_columns: footer.num_fixed_columns,
                num_advice_columns: footer.num_advice_columns,
                num_instance_columns: footer.num_instance_columns,
                num_selectors: footer.num_selectors,
            },
        }
    }

    /// Set config and return an RAII guard for automatic cleanup.
    pub fn set_as_current_guarded(&self) -> DynamicCircuitGuard {
        DYNAMIC_CIRCUIT_CONFIG.with(|cfg| {
            *cfg.borrow_mut() = Some(self.config);
        });
        DynamicCircuitGuard::new()
    }

    /// Get the current thread-local configuration.
    fn current_config() -> Option<DynamicCircuitConfig> {
        DYNAMIC_CIRCUIT_CONFIG.with(|cfg| *cfg.borrow())
    }

    /// Clear the thread-local configuration.
    pub fn clear_current() {
        DYNAMIC_CIRCUIT_CONFIG.with(|cfg| {
            *cfg.borrow_mut() = None;
        });
    }
}

impl Circuit<vesta::Scalar> for DynamicCircuit {
    type Config = ();
    type FloorPlanner = halo2_proofs::circuit::SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        let _ = self.set_as_current_guarded();
        self.clone()
    }

    fn configure(meta: &mut ConstraintSystem<vesta::Scalar>) -> Self::Config {
        let config = Self::current_config().expect(
            "DynamicCircuit::configure called without setting thread-local config. \
             Call circuit.set_as_current() before keygen operations.",
        );

        // Fixed columns — enable equality on all (conservative; the real CS
        // is deserialized separately in v2).
        for _ in 0..config.num_fixed_columns {
            let col = meta.fixed_column();
            meta.enable_equality(col);
        }

        // Advice columns — all with equality
        for _ in 0..config.num_advice_columns {
            let col = meta.advice_column();
            meta.enable_equality(col);
        }

        // Instance columns — all with equality
        for _ in 0..config.num_instance_columns {
            let col = meta.instance_column();
            meta.enable_equality(col);
        }

        // Selectors
        for _ in 0..config.num_selectors {
            meta.selector();
        }
    }

    fn synthesize(
        &self,
        _config: Self::Config,
        _layouter: impl Layouter<vesta::Scalar>,
    ) -> Result<(), plonk::Error> {
        Ok(())
    }
}

//

/// Circuit type identifier for VK deserialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CircuitType {
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

impl<C> CosmwasmCircuit<C> {
    pub fn new(circuit: C) -> Self {
        Self { circuit }
    }
}

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

/// Serialized circuit data: `[params][vk][cs][footer(32)]`
#[derive(Clone, Debug)]
pub struct SerializedPlonkishCircuitData {
    pub bytes: Vec<u8>,
    pub hash: [u8; 32],
    pub footer: Vec<u8>,
}

impl SerializedPlonkishCircuitData {
    pub fn new(bytes: &[u8], hash: &[u8], footer: &[u8]) -> Self {
        Self {
            bytes: bytes.into(),
            hash: hash.try_into().expect("hash checksum"),
            footer: footer.into(),
        }
    }

    /// Parse from combined format: `[params][vk][cs][footer(32)]`
    pub fn from_combined(value: &[u8]) -> ZkResult<Self> {
        const FOOTER_SIZE: usize = 32;

        if value.len() < FOOTER_SIZE {
            return Err(ZkError::new_err("SerializedPlonkishCircuitData too short"));
        }

        let footer_bytes = &value[value.len() - FOOTER_SIZE..];
        let footer = CircuitFooter::from_bytes(footer_bytes)?;

        let params_len = footer.params_len as usize;
        let vk_len = footer.vk_len as usize;
        let cs_len = footer.cs_len as usize;

        if params_len + vk_len + cs_len + FOOTER_SIZE != value.len() {
            return Err(ZkError::new_err(
                "SerializedPlonkishCircuitData size mismatch",
            ));
        }

        Ok(Self {
            bytes: value.into(),
            hash: [0u8; 32],
            footer: footer_bytes.to_vec(),
        })
    }
}

/// A verifying key for the zk-wasmvm.
#[derive(Debug)]
pub struct VerifyingKey {
    pub params: poly::commitment::Params<vesta::Affine>,
    pub vk: plonk::VerifyingKey<vesta::Affine>,
    pub i: usize,
}

impl VerifyingKey {
    /// Create from an existing VK.
    /// WARNING: creates new random params — only for fresh key generation.
    pub fn new(vk: plonk::VerifyingKey<vesta::Affine>, k: u32, i: usize) -> Self {
        VerifyingKey {
            params: poly::commitment::Params::new(k),
            vk,
            i,
        }
    }

    /// Create with existing params (use when deserializing).
    pub fn new_with_params(
        params: poly::commitment::Params<vesta::Affine>,
        vk: plonk::VerifyingKey<vesta::Affine>,
        i: usize,
    ) -> Self {
        VerifyingKey { params, vk, i }
    }

    /// Build from a concrete circuit.
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
    /// Estimate memory footprint for gas/resource accounting.
    pub fn estimate_memory_size(k: u32) -> usize {
        let n = 1usize << k;
        let params_size = (2 * n + 2) * 64;
        let vk_size = n * 32;
        params_size + vk_size
    }

    /// Get actual memory footprint by serializing.
    pub fn actual_size_bytes(&self) -> usize {
        self.to_bytes().map(|b| b.len()).unwrap_or(0)
    }

    /// Parse and validate structure without deserializing.
    ///
    /// Format: `[params][vk][cs][footer(32)]`
    pub fn parse_bytes(bytes: &[u8]) -> ZkResult<SerializedPlonkishCircuitData> {
        if bytes.len() < 32 {
            return Err(ZkError::new_err(
                "VK data too short - need at least 32 bytes for footer",
            ));
        }

        let footer_bytes = &bytes[bytes.len() - 32..];
        let footer = CircuitFooter::from_bytes(footer_bytes)?;

        let params_len = footer.params_len as usize;
        let vk_len = footer.vk_len as usize;
        let cs_len = footer.cs_len as usize;

        if params_len + vk_len + cs_len + 32 != bytes.len() {
            return Err(ZkError::new_err(format!(
                "VK file size mismatch: {}+{}+{}+32 != {}",
                params_len,
                vk_len,
                cs_len,
                bytes.len()
            )));
        }

        Ok(SerializedPlonkishCircuitData::new(
            bytes,
            &[0u8; 32],
            footer_bytes,
        ))
    }

    /// Deserialize from v2 format: `[params][vk][cs][footer(32)]`.
    ///
    /// The embedded CS is deserialized and used for VK reconstruction,
    /// giving exact circuit-agnostic verification without the original Rust type.
    pub fn from_bytes(bytes: &[u8]) -> ZkResult<Self> {
        if bytes.len() < 32 {
            return Err(ZkError::new_err(
                "VK data too short - need at least 32 bytes for footer",
            ));
        }

        let footer_bytes = &bytes[bytes.len() - 32..];
        let footer = CircuitFooter::from_bytes(footer_bytes)?;

        let params_len = footer.params_len as usize;
        let vk_len = footer.vk_len as usize;
        let cs_len = footer.cs_len as usize;

        let expected_len = params_len + vk_len + cs_len + 32;
        if expected_len != bytes.len() {
            return Err(ZkError::new_err(format!(
                "V2 file size mismatch: {}+{}+{}+32 = {} != {}",
                params_len,
                vk_len,
                cs_len,
                expected_len,
                bytes.len()
            )));
        }

        // Extract sections
        let params_bytes = &bytes[..params_len];
        let vk_bytes = &bytes[params_len..params_len + vk_len];
        let cs_bytes = &bytes[params_len + vk_len..params_len + vk_len + cs_len];

        // Deserialize params
        let mut params_reader = Cursor::new(params_bytes);
        let params = poly::commitment::Params::<vesta::Affine>::read(&mut params_reader)?;

        // Deserialize constraint system
        let mut cs_reader = Cursor::new(cs_bytes);
        let cs = ConstraintSystem::<vesta::Scalar>::read(&mut cs_reader)
            .map_err(|e| ZkError::from_io(e))?;

        // Deserialize VK using the deserialized CS
        let empty_selectors: Vec<Vec<bool>> = vec![];
        let mut vk_reader = Cursor::new(vk_bytes);
        let vk = halo2_proofs::plonk::VerifyingKey::<vesta::Affine>::read_with_cs(
            &mut vk_reader,
            &params,
            cs,
            empty_selectors,
        )
        .map_err(|e| {
            ZkError::from_io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("{:?}", e),
            ))
        })?;

        Ok(VerifyingKey::new_with_params(
            params,
            vk,
            footer.instance_count as usize,
        ))
    }

    /// Deserialize using a concrete circuit type (legacy helper).
    pub fn from_bytes_with_circuit<C: Circuit<vesta::Scalar>>(bytes: &[u8]) -> ZkResult<Self> {
        if bytes.len() < 32 {
            return Err(ZkError::new_err("VK data too short"));
        }

        let footer_bytes = &bytes[bytes.len() - 32..];
        let footer = CircuitFooter::from_bytes(footer_bytes)?;

        let params_len = footer.params_len as usize;
        let vk_len = footer.vk_len as usize;

        let params_bytes = &bytes[..params_len];
        let vk_bytes = &bytes[params_len..params_len + vk_len];

        let mut params_reader = Cursor::new(params_bytes);
        let params = poly::commitment::Params::<vesta::Affine>::read(&mut params_reader)?;

        let mut vk_reader = Cursor::new(vk_bytes);
        let vk = halo2_proofs::plonk::VerifyingKey::<vesta::Affine>::read::<_, C>(
            &mut vk_reader,
            &params,
        )?;

        Ok(VerifyingKey::new_with_params(
            params,
            vk,
            footer.instance_count as usize,
        ))
    }

    /// Serialize to v2 format: `[params][vk][cs][footer(32)]`.
    pub fn to_bytes_with_footer(
        &self,
        cs: &ConstraintSystem<vesta::Scalar>,
        footer: &CircuitFooter,
    ) -> io::Result<Vec<u8>> {
        let mut params_buf = Vec::new();
        self.params.write(&mut params_buf)?;

        let mut vk_buf = Vec::new();
        self.vk.write(&mut vk_buf)?;

        let mut cs_buf = Vec::new();
        cs.write(&mut cs_buf)?;

        let mut output = Vec::with_capacity(params_buf.len() + vk_buf.len() + cs_buf.len() + 32);
        output.extend_from_slice(&params_buf);
        output.extend_from_slice(&vk_buf);
        output.extend_from_slice(&cs_buf);
        output.extend_from_slice(&footer.to_bytes());

        Ok(output)
    }

    /// Serialize params + VK only (no footer, no CS).
    pub fn to_bytes(&self) -> io::Result<Vec<u8>> {
        let mut output = Vec::new();
        let mut params_buf = Vec::new();
        self.params.write(&mut params_buf)?;
        output.extend_from_slice(&params_buf);

        let mut vk_buf = Vec::new();
        self.vk.write(&mut vk_buf)?;
        output.extend_from_slice(&vk_buf);

        Ok(output)
    }
    /// Extract constraint system metadata from a circuit type.
    ///
    /// Runs `C::configure()` on a fresh `ConstraintSystem` to capture
    /// column counts, gate count, degree, and lookup presence.
    /// Returns the serialized CS bytes and the metadata needed for the footer.
    pub(crate) fn extract_cs_metadata<C>() -> io::Result<(Vec<u8>, ConstraintSystemMetadata)>
    where
        C: Circuit<vesta::Scalar>,
    {
        let mut cs = ConstraintSystem::<vesta::Scalar>::default();
        let _ = C::configure(&mut cs);

        let mut cs_buf = Vec::new();
        cs.write(&mut cs_buf)?;

        let meta = ConstraintSystemMetadata {
            num_fixed_columns: cs.get_num_fixed_columns() as u32,
            num_advice_columns: cs.get_num_advice_columns() as u32,
            num_instance_columns: cs.get_num_instance_columns() as u32,
            num_selectors: cs.get_num_selectors(),
            num_gates: cs.get_gate_count() as u32,
            degree: cs.degree() as u8,
            has_lookups: cs.has_lookups(),
            permutation_columns: cs.get_permutation_columns(),
        };

        Ok((cs_buf, meta))
    }

    /// Build a verifying key and serialize to v2 format in one shot.
    ///
    /// Produces `[params][vk][cs][footer(32)]` — the minimal file the VM
    /// needs for circuit-agnostic verification. The footer is generated
    /// automatically from the circuit's constraint system.
    ///
    /// # Arguments
    /// * `c` — circuit instance (used for keygen; consumed)
    /// * `k` — circuit size parameter (log2 of number of rows)
    /// * `instance_count` — number of public input scalars
    pub fn build_v2<C>(c: C, k: u32, instance_count: usize) -> io::Result<Vec<u8>>
    where
        C: Circuit<vesta::Scalar>,
    {
        // 1. Generate params + VK
        let params = poly::commitment::Params::<vesta::Affine>::new(k);
        let vk = plonk::keygen_vk(&params, &c).unwrap();

        // 2. Capture CS by re-running configure
        let (cs_buf, meta) = Self::extract_cs_metadata::<C>()?;

        // 3. Serialize params + VK
        let mut params_buf = Vec::new();
        params.write(&mut params_buf)?;

        let mut vk_buf = Vec::new();
        vk.write(&mut vk_buf)?;

        // 4. Build footer from metadata + section lengths
        let footer = CircuitFooter::new(
            CircuitType::Plonkish,
            instance_count as u8,
            meta.num_fixed_columns as u8,
            meta.num_advice_columns as u8,
            meta.num_instance_columns as u8,
            meta.degree,
            params_buf.len() as u32,
            vk_buf.len() as u32,
            cs_buf.len() as u32,
            meta.num_selectors,
            meta.num_gates,
            meta.has_lookups,
            0, // CRC32 (reserved)
        );

        // 5. Concatenate: [params][vk][cs][footer(32)]
        let mut output = Vec::with_capacity(params_buf.len() + vk_buf.len() + cs_buf.len() + 32);
        output.extend_from_slice(&params_buf);
        output.extend_from_slice(&vk_buf);
        output.extend_from_slice(&cs_buf);
        output.extend_from_slice(&footer.to_bytes());

        Ok(output)
    }

    /// Build a verifying key, serialize to v2 format, and write to file.
    ///
    /// Convenience wrapper around `build_v2` that writes directly to disk.
    pub fn build_v2_and_write<C>(
        path: std::path::PathBuf,
        c: C,
        k: u32,
        instance_count: usize,
    ) -> io::Result<()>
    where
        C: Circuit<vesta::Scalar>,
    {
        let bytes = Self::build_v2(c, k, instance_count)?;
        std::fs::write(path, bytes)
    }
}

/// The proving key.
#[derive(Debug)]
pub struct ProvingKey {
    params: halo2_proofs::poly::commitment::Params<vesta::Affine>,
    pk: plonk::ProvingKey<vesta::Affine>,
}

impl ProvingKey {
    /// Build from a given circuit.
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

    /// Build and write to file.
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

    pub fn params(&self) -> halo2_proofs::poly::commitment::Params<vesta::Affine> {
        self.params.clone()
    }
    /// Build proving key and also write a v2 verifying key file.
    ///
    /// This is the recommended way to generate circuit keys: it produces
    /// both a proving key (for proof generation) and a minimal v2 VK file
    /// `[params][vk][cs][footer(32)]` ready for VM upload.
    ///
    /// The VK file is self-describing — the VM can deserialize and verify
    /// proofs without the original circuit type.
    pub fn build_with_vk_v2<C>(
        k: u32,
        circuit: C,
        instance_count: usize,
    ) -> io::Result<(Self, Vec<u8>)>
    where
        C: Circuit<vesta::Scalar>,
    {
        // Capture CS before consuming the circuit for keygen
        let (cs_buf, meta) = VerifyingKey::extract_cs_metadata::<C>()?;

        // Build PK (which includes the VK internally)
        let params = poly::commitment::Params::<vesta::Affine>::new(k);
        let wrapped = CosmwasmCircuit::new(circuit);
        let vk = plonk::keygen_vk(&params, &wrapped).unwrap();
        let pk = plonk::keygen_pk(&params, vk, &wrapped).unwrap();

        // Serialize VK from the PK
        let mut params_buf = Vec::new();
        params.write(&mut params_buf)?;

        let mut vk_buf = Vec::new();
        pk.get_vk().write(&mut vk_buf)?;

        // Build footer
        let footer = CircuitFooter::new(
            CircuitType::Plonkish,
            instance_count as u8,
            meta.num_fixed_columns as u8,
            meta.num_advice_columns as u8,
            meta.num_instance_columns as u8,
            meta.degree,
            params_buf.len() as u32,
            vk_buf.len() as u32,
            cs_buf.len() as u32,
            meta.num_selectors,
            meta.num_gates,
            meta.has_lookups,
            0,
        );

        // Assemble v2 VK bytes
        let mut vk_v2 = Vec::with_capacity(params_buf.len() + vk_buf.len() + cs_buf.len() + 32);
        vk_v2.extend_from_slice(&params_buf);
        vk_v2.extend_from_slice(&vk_buf);
        vk_v2.extend_from_slice(&cs_buf);
        vk_v2.extend_from_slice(&footer.to_bytes());

        Ok((ProvingKey { params, pk }, vk_v2))
    }

    /// Build proving key, write it to `pk_path`, and write a v2 VK to `vk_path`.
    pub fn build_and_write_v2(
        pk_path: std::path::PathBuf,
        vk_path: std::path::PathBuf,
        k: u32,
        circuit: impl Circuit<vesta::Scalar>,
        instance_count: usize,
    ) -> io::Result<()> {
        let (pk, vk_bytes) = Self::build_with_vk_v2(k, circuit, instance_count)?;

        // Write PK
        let mut writer = io::BufWriter::new(std::fs::File::create(&pk_path)?);
        pk.params.write(&mut writer)?;
        pk.pk.get_vk().write(&mut writer)?;
        io::Write::flush(&mut writer)?;

        // Write v2 VK
        std::fs::write(&vk_path, vk_bytes)?;

        Ok(())
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

    /// Create a proof for the given circuits and instances.
    pub fn create<C: halo2_proofs::plonk::Circuit<pasta_curves::Fp>>(
        pk: &ProvingKey,
        circuits: &[crate::CosmwasmCircuit<C>],
        i: &[Instance],
        mut rng: impl rand::RngCore,
    ) -> Result<Self, plonk::Error> {
        let converted_columns: Vec<Vec<pasta_curves::Fp>> = i
            .iter()
            .map(|i| {
                i.i.iter()
                    .map(|&s| Into::<pasta_curves::Fp>::into(s))
                    .collect()
            })
            .collect();

        let column_slices: Vec<&[pasta_curves::Fp]> =
            converted_columns.iter().map(|v| v.as_slice()).collect();

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

    /// Verify this proof with the given instances.
    pub fn verify(&self, vk: &VerifyingKey, i: &[Instance]) -> Result<(), plonk::Error> {
        let instances: Vec<Vec<pasta_curves::Fp>> = i
            .iter()
            .map(|inst| inst.i.iter().map(|&s| pasta_curves::Fp::from(s)).collect())
            .collect();

        let column_refs: Vec<&[pasta_curves::Fp]> =
            instances.iter().map(|v| v.as_slice()).collect();

        let instances_arg: &[&[&[pasta_curves::Fp]]] = &[&column_refs];

        let strategy = plonk::SingleVerifier::new(&vk.params);
        let mut transcript = halo2_proofs::transcript::Blake2bRead::init(&self.0[..]);

        plonk::verify_proof(&vk.params, &vk.vk, strategy, instances_arg, &mut transcript)
    }
}
