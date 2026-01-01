use std::io::{self, Cursor};
use std::sync::Arc;

use group::ff::{Field, PrimeField};
use halo2_proofs::{
    circuit::Layouter,
    plonk::{self, Circuit, ConstraintSystem},
    poly, COSMWASM_METADATA_LENGTH,
};
use pasta_curves::vesta;

use crate::errors::{ZkError, ZkResult};

/// Thread-safe handle to a pinned verifying key
pub type PinnedCircuit = Arc<VerifyingKey>;

/// Circuit footer metadata - 32 bytes containing complete constraint system specification
/// This enables generic deserialization via DynamicCircuit without needing the original circuit type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CircuitFooter {
    /// Circuit type identifier (currently only Plonkish=0)
    pub circuit_type: CircuitType,
    /// Number of public input scalars required by this circuit
    pub instance_count: u8,
    /// Number of fixed columns in the constraint system
    pub num_fixed_columns: u8,
    /// Number of advice (witness) columns in the constraint system
    pub num_advice_columns: u8,
    /// Number of instance (public) columns in the constraint system
    pub num_instance_columns: u8,
    /// Maximum gate degree in the constraint system (typically 2-4)
    pub degree: u8,
    /// Footer format version (currently 1)
    pub footer_version: u8,
    /// Feature flags for compression, custom gates, etc.
    pub flags: u8,
    /// Length of serialized params section (u32 LE)
    pub params_len: u32,
    /// Length of serialized verifying key section (u32 LE)
    pub vk_len: u32,
    /// Number of selectors in the constraint system
    pub num_selectors: u32,
    /// Reserved for future extensions
    pub reserved_2: u32,
    /// Reserved for future extensions
    pub reserved_3: u32,
    /// CRC32 checksum of params+vk bytes (optional validation)
    pub crc32: u32,
}

impl CircuitFooter {
    /// Create a new circuit footer
    pub fn new(
        circuit_type: CircuitType,
        instance_count: u8,
        num_fixed_columns: u8,
        num_advice_columns: u8,
        num_instance_columns: u8,
        degree: u8,
        params_len: u32,
        vk_len: u32,
        num_selectors: u32,
        crc32: u32,
    ) -> Self {
        Self {
            circuit_type,
            instance_count,
            num_fixed_columns,
            num_advice_columns,
            num_instance_columns,
            degree,
            footer_version: 1,
            flags: 0,
            params_len,
            vk_len,
            num_selectors,
            reserved_2: 0,
            reserved_3: 0,
            crc32,
        }
    }

    /// Serialize footer to exactly 32 bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes[0] = self.circuit_type.to_u8();
        bytes[1] = self.instance_count;
        bytes[2] = self.num_fixed_columns;
        bytes[3] = self.num_advice_columns;
        bytes[4] = self.num_instance_columns;
        bytes[5] = self.degree;
        bytes[6] = self.footer_version;
        bytes[7] = self.flags;
        bytes[8..12].copy_from_slice(&self.params_len.to_le_bytes());
        bytes[12..16].copy_from_slice(&self.vk_len.to_le_bytes());
        bytes[16..20].copy_from_slice(&self.num_selectors.to_le_bytes());
        bytes[20..24].copy_from_slice(&self.reserved_2.to_le_bytes());
        bytes[24..28].copy_from_slice(&self.reserved_3.to_le_bytes());
        bytes[28..32].copy_from_slice(&self.crc32.to_le_bytes());
        bytes
    }

    /// Parse footer from exactly 32 bytes
    pub fn from_bytes(bytes: &[u8]) -> ZkResult<Self> {
        if bytes.len() != 32 {
            return Err(ZkError::new_err(format!(
                "CircuitFooter must be exactly 32 bytes, got {}",
                bytes.len()
            )));
        }

        let circuit_type = CircuitType::from_u8(bytes[0])
            .ok_or_else(|| ZkError::new_err("Invalid circuit type in footer"))?;

        let footer_version = bytes[6];
        if footer_version != 1 {
            return Err(ZkError::new_err(format!(
                "Unsupported footer version: {}",
                footer_version
            )));
        }

        Ok(Self {
            circuit_type,
            instance_count: bytes[1],
            num_fixed_columns: bytes[2],
            num_advice_columns: bytes[3],
            num_instance_columns: bytes[4],
            degree: bytes[5],
            footer_version,
            flags: bytes[7],
            params_len: u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
            vk_len: u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]),
            num_selectors: u32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]),
            reserved_2: u32::from_le_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]),
            reserved_3: u32::from_le_bytes([bytes[24], bytes[25], bytes[26], bytes[27]]),
            crc32: u32::from_le_bytes([bytes[28], bytes[29], bytes[30], bytes[31]]),
        })
    }
}

/// Dynamic circuit configuration metadata stored in thread-local
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

/// Generic circuit that implements Circuit<vesta::Scalar> dynamically
/// Configured at runtime using footer metadata to match any constraint system
///
/// This enables deserialization of verifying keys without knowing the original circuit type.
/// The key insight: we only need to match the column structure; gates come from the deserialized VK.
///
/// Usage:
/// ```ignore
/// let circuit = DynamicCircuit::from_footer(&footer);
/// circuit.set_as_current();  // Set thread-local for configure() to use
/// // Now halo2::keygen_vk or VerifyingKey::read can use it
/// ```
#[derive(Debug, Clone)]
pub struct DynamicCircuit {
    config: DynamicCircuitConfig,
}

impl DynamicCircuit {
    /// Create a new dynamic circuit with the specified column structure
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

    /// Create from circuit footer metadata
    pub fn from_footer(footer: &CircuitFooter) -> Self {
        Self::new(
            footer.num_fixed_columns,
            footer.num_advice_columns,
            footer.num_instance_columns,
            footer.num_selectors,
        )
    }

    /// Set this circuit's config as the current thread-local for use in configure()
    /// Must be called before halo2 operations that invoke configure()
    pub fn set_as_current(&self) {
        DYNAMIC_CIRCUIT_CONFIG.with(|cfg| {
            *cfg.borrow_mut() = Some(self.config);
        });
    }

    /// Get the current thread-local configuration
    fn current_config() -> Option<DynamicCircuitConfig> {
        DYNAMIC_CIRCUIT_CONFIG.with(|cfg| *cfg.borrow())
    }

    /// Clear the thread-local configuration
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
        // Ensure our config is available in the thread-local when needed
        self.set_as_current();
        self.clone()
    }

    fn configure(meta: &mut ConstraintSystem<vesta::Scalar>) -> Self::Config {
        // Get config from thread-local that was set by set_as_current()
        let config = Self::current_config().expect(
            "DynamicCircuit::configure called without setting thread-local config. \
             Call circuit.set_as_current() before keygen operations.",
        );

        // Add fixed columns to match the deserialized circuit
        let mut fixed_cols = Vec::new();
        for _ in 0..config.num_fixed_columns {
            fixed_cols.push(meta.fixed_column());
        }

        // Add advice columns and enable equality
        let mut advice_cols = Vec::new();
        for _ in 0..config.num_advice_columns {
            let col = meta.advice_column();
            meta.enable_equality(col);
            advice_cols.push(col);
        }

        // Add instance column and enable equality if needed
        if config.num_instance_columns > 0 {
            let col = meta.instance_column();
            meta.enable_equality(col);
        }

        // Enable constant column for lookups/gates
        if !fixed_cols.is_empty() {
            meta.enable_constant(fixed_cols[0]);
        }

        // Create selectors to match the deserialized circuit
        for _ in 0..config.num_selectors {
            let _selector = meta.selector();
        }

        // Note: We don't recreate gates here because:
        // 1. The deserialized VerifyingKey already contains all gate definitions
        // 2. halo2's VerifyingKey::read validates gates against this constraint system
        // 3. We only need the column structure to match
        ()
    }

    fn synthesize(
        &self,
        _config: Self::Config,
        _layouter: impl Layouter<vesta::Scalar>,
    ) -> Result<(), plonk::Error> {
        // This is not used for deserialization - the circuit is read-only
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

/// Serialized circuit data stored with WASM code
/// Format: [params bytes][vk bytes][footer (10 bytes)]
/// Footer: [circuit_type (1)][instance_count (1)][params_len (4 LE u32)][vk_len (4 LE u32)]
#[derive(Clone, Debug)]
pub struct SerializedPlonkishCircuitData {
    /// Raw bytes of the serialized params + vk + footer
    pub bytes: Vec<u8>,
    /// SHA256 hash of just the params+vk bytes (without footer) for integrity checking
    pub hash: [u8; 32],
    /// Circuit metadata footer
    pub metadata: Vec<u8>,
}

impl SerializedPlonkishCircuitData {
    /// Create from raw components
    pub fn new(bytes: &[u8], hash: &[u8], metadata: &[u8]) -> Self {
        Self {
            bytes: bytes.into(),
            hash: hash.try_into().expect("hash checksumF"),
            metadata: metadata.into(),
        }
    }

    /// Parse from a combined format: [params_bytes][vk_bytes][footer (32 bytes)]
    pub fn from_combined(value: &[u8]) -> ZkResult<Self> {
        const FOOTER_SIZE: usize = 32;

        if value.len() < FOOTER_SIZE {
            return Err(ZkError::new_err("SerializedPlonkishCircuitData too short"));
        }

        // Extract and parse the 32-byte footer
        let footer_bytes = &value[value.len() - FOOTER_SIZE..];
        let footer = CircuitFooter::from_bytes(footer_bytes)?;

        let params_len = footer.params_len as usize;
        let vk_len = footer.vk_len as usize;

        // Validate structure
        if params_len + vk_len + FOOTER_SIZE != value.len() {
            return Err(ZkError::new_err(
                "SerializedPlonkishCircuitData size mismatch",
            ));
        }

        let metadata = PlonkishCircuitMetadata::new(
            footer.circuit_type,
            footer.instance_count,
            params_len,
            vk_len,
        )
        .to_bytes();

        // For hash, we need to compute it from the params+vk bytes
        // This is a simplified approach - the actual hash should be provided
        let mut hash = [0u8; 32];
        // In practice, this should be computed via Blake2b of just the vk portion

        Ok(Self {
            bytes: value.into(),
            hash,
            metadata,
        })
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

    /// Parse circuit data from bytes, validating structure without requiring circuit type
    /// This is useful for loading and validating the binary structure without needing
    /// the actual circuit implementation available
    ///
    /// Format: [params bytes][vk bytes][footer (32 bytes)]
    /// Footer contains complete constraint system metadata for DynamicCircuit
    pub fn parse_bytes(bytes: &[u8]) -> ZkResult<SerializedPlonkishCircuitData> {
        eprintln!("📦 parse_bytes called with {} bytes total", bytes.len());
        eprintln!(
            "   First 30 bytes of buffer: {:02x?}",
            &bytes[..30.min(bytes.len())]
        );
        eprintln!(
            "   Last 32 bytes of buffer: {:02x?}",
            &bytes[bytes.len().saturating_sub(32)..]
        );

        if bytes.len() < 32 {
            return Err(ZkError::new_err(
                "VK data too short - need at least 32 bytes for footer",
            ));
        }

        // Extract footer (last 32 bytes) using CircuitFooter
        let footer_bytes = &bytes[bytes.len() - 32..];
        let footer = CircuitFooter::from_bytes(footer_bytes)?;

        eprintln!(
            "✓ Parsed footer: circuit_type={:?}, instance_count={}, params_len={}, vk_len={}",
            footer.circuit_type, footer.instance_count, footer.params_len, footer.vk_len
        );

        let params_len = footer.params_len as usize;
        let vk_len = footer.vk_len as usize;

        // Validate structure
        if params_len + vk_len + 32 != bytes.len() {
            return Err(ZkError::new_err(format!(
                "VK file size mismatch: {}+{}+32 != {}",
                params_len,
                vk_len,
                bytes.len()
            )));
        }

        // Store as SerializedPlonkishCircuitData with the raw bytes
        let metadata = PlonkishCircuitMetadata::new(
            footer.circuit_type,
            footer.instance_count,
            params_len,
            vk_len,
        );
        Ok(SerializedPlonkishCircuitData::new(
            bytes,
            &[0u8; 32],
            &metadata.to_bytes(),
        ))
    }

    /// Deserialize a VerifyingKey from raw bytes using DynamicCircuit
    /// This works with ANY circuit - the constraint system structure is embedded in the footer
    pub fn from_bytes(bytes: &[u8]) -> ZkResult<Self> {
        eprintln!("📦 from_bytes called with {} bytes total", bytes.len());

        if bytes.len() < 32 {
            return Err(ZkError::new_err(
                "VK data too short - need at least 32 bytes for footer",
            ));
        }

        // Extract and parse the 32-byte footer
        let footer_bytes = &bytes[bytes.len() - 32..];
        let footer = CircuitFooter::from_bytes(footer_bytes)?;

        eprintln!(
            "✓ Footer parsed: instance_count={}, fixed={}, advice={}, instance={}, degree={}",
            footer.instance_count,
            footer.num_fixed_columns,
            footer.num_advice_columns,
            footer.num_instance_columns,
            footer.degree
        );

        let params_len = footer.params_len as usize;
        let vk_len = footer.vk_len as usize;

        // Validate structure
        if params_len + vk_len + 32 != bytes.len() {
            return Err(ZkError::new_err(format!(
                "VK file size mismatch: {}+{}+32 != {}",
                params_len,
                vk_len,
                bytes.len()
            )));
        }

        // Extract params and vk sections
        let params_bytes = &bytes[..params_len];
        let vk_bytes = &bytes[params_len..params_len + vk_len];

        // Deserialize params
        eprintln!("🔄 Deserializing params ({} bytes)...", params_len);
        let mut params_reader = Cursor::new(params_bytes);
        let params = poly::commitment::Params::<vesta::Affine>::read(&mut params_reader)?;
        eprintln!("✓ Params deserialized (k={})", params.k());

        // Create DynamicCircuit from footer metadata
        eprintln!("🔧 Creating DynamicCircuit from footer...");
        let circuit = DynamicCircuit::from_footer(&footer);
        circuit.set_as_current();

        // Deserialize vk using DynamicCircuit
        eprintln!(
            "🔑 Deserializing VK ({} bytes) with DynamicCircuit...",
            vk_len
        );
        let mut vk_reader = Cursor::new(vk_bytes);
        let vk = halo2_proofs::plonk::VerifyingKey::<vesta::Affine>::read::<_, DynamicCircuit>(
            &mut vk_reader,
            &params,
        )
        .map_err(|e| {
            eprintln!("❌ VK deserialization failed: {:?}", e);
            ZkError::from_io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("{:?}", e),
            ))
        })?;
        eprintln!("✓ VK deserialized successfully");

        DynamicCircuit::clear_current();

        Ok(VerifyingKey::new(
            vk,
            params.k(),
            footer.instance_count as usize,
        ))
    }

    /// Deserialize a VerifyingKey from raw bytes using a concrete circuit type
    /// The circuit must have the same constraint system as when the VK was created
    /// (Legacy method - prefer from_bytes() which uses DynamicCircuit)
    pub fn from_bytes_with_circuit<C: Circuit<vesta::Scalar>>(
        bytes: &[u8],
        circuit: &C,
    ) -> ZkResult<Self> {
        eprintln!(
            "📦 from_bytes_with_circuit called with {} bytes total",
            bytes.len()
        );
        if bytes.len() < 32 {
            return Err(ZkError::new_err("VK data too short"));
        }

        // Extract footer (last 32 bytes)
        let footer_bytes = &bytes[bytes.len() - 32..];
        let footer = CircuitFooter::from_bytes(footer_bytes)?;

        let params_len = footer.params_len as usize;
        let vk_len = footer.vk_len as usize;

        // Extract params and vk sections
        let params_bytes = &bytes[..params_len];
        let vk_bytes = &bytes[params_len..params_len + vk_len];

        // Deserialize params
        let mut params_reader = Cursor::new(params_bytes);
        let params = poly::commitment::Params::<vesta::Affine>::read(&mut params_reader)?;

        // Deserialize vk using the provided circuit type
        // This requires the circuit to have the same constraint system as when it was created
        let mut vk_reader = Cursor::new(vk_bytes);
        let vk = halo2_proofs::plonk::VerifyingKey::<vesta::Affine>::read::<_, C>(
            &mut vk_reader,
            &params,
        )?;

        Ok(VerifyingKey::new(
            vk,
            params.k(),
            footer.instance_count as usize,
        ))
    }

    /// Serialize to bytes with extended footer metadata
    /// This requires providing the constraint system dimensions so DynamicCircuit can deserialize
    pub fn to_bytes_with_footer(
        &self,
        num_fixed_columns: u8,
        num_advice_columns: u8,
        num_instance_columns: u8,
        degree: u8,
    ) -> io::Result<Vec<u8>> {
        let mut params_buf = Vec::new();
        self.params.write(&mut params_buf)?;

        let mut vk_buf = Vec::new();
        self.vk.write(&mut vk_buf)?;

        // Create footer with all metadata
        let footer = CircuitFooter::new(
            CircuitType::Plonkish,
            self.i as u8,
            num_fixed_columns,
            num_advice_columns,
            num_instance_columns,
            degree,
            params_buf.len() as u32,
            vk_buf.len() as u32,
            1,
            0, // CRC32 - can be computed if needed
        );

        let mut output = Vec::new();
        output.extend_from_slice(&params_buf);
        output.extend_from_slice(&vk_buf);
        output.extend_from_slice(&footer.to_bytes());

        eprintln!(
            "✓ Serialized VK: params={} bytes, vk={} bytes, total={} bytes",
            params_buf.len(),
            vk_buf.len(),
            output.len()
        );

        Ok(output)
    }

    /// Serialize to bytes for storage (deprecated - use to_bytes_with_footer)
    pub fn to_bytes(&self) -> io::Result<Vec<u8>> {
        let mut output = Vec::new();
        let mut params_buf = Vec::new();

        // Call the write function for params
        self.params.write(&mut params_buf)?;
        output.extend_from_slice(&params_buf);

        // Write VK
        let mut vk_buf = Vec::new();
        self.vk.write(&mut vk_buf)?;
        output.extend_from_slice(&vk_buf);

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
        // Footer is always 32 bytes
        const FOOTER_SIZE: usize = 32;
        &full_bytes[self.vkpl + self.vkl..]
    }

    /// Total expected file size
    pub fn total_size(&self) -> usize {
        const FOOTER_SIZE: usize = 32;
        self.vkpl + self.vkl + FOOTER_SIZE
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
    /// Format: [ct (1)][i (1)][vkpl (4)][vkl (4)] = 10 bytes total
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.ct.to_u8());
        bytes.push(self.i);
        bytes.extend_from_slice(&(self.vkpl as u32).to_le_bytes());
        bytes.extend_from_slice(&(self.vkl as u32).to_le_bytes());
        bytes
    }
}
