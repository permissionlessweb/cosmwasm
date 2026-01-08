use std::io::{self, Cursor};
use std::sync::Arc;

use crate::errors::{ZkError, ZkResult};
use group::ff::{Field, PrimeField};
use halo2_proofs::{
    circuit::Layouter,
    plonk::{self, Circuit, ConstraintSystem},
    poly, COSMWASM_METADATA_LENGTH,
};
use pasta_curves::vesta;

/// Custom section name for embedded verifying keys
/// Contracts can embed their VK in a WASM custom section with this name
pub const VK_CUSTOM_SECTION_NAME: &str = "cosmwasm_zk_vk";

/// Thread-safe handle to a pinned verifying key
pub type PinnedCircuit = Arc<VerifyingKey>;

/// Footer flags bit definitions
pub mod footer_flags {
    /// Constraint system section is present (must be 1 for version 2)
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
/// This is dynamically extracted from the circuit's `configure()` method
/// and provides detailed information about the constraint system structure.
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

/// Circuit footer metadata - 32 bytes containing complete constraint system specification
/// This enables generic deserialization via DynamicCircuit without needing the original circuit type
///
/// ## Version History
/// - **Version 1**: Original format with fixed_equality_mask and advice_query_counts
/// - **Version 2**: CS-inclusive format with cs_len and num_gates fields
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
    /// Footer format version (1 = original, 2 = CS-inclusive)
    pub footer_version: u8,
    /// Feature flags (bit 0: HAS_CS, bit 1: HAS_LOOKUPS)
    pub flags: u8,
    /// Length of serialized params section (u32 LE)
    pub params_len: u32,
    /// Length of serialized verifying key section (u32 LE)
    pub vk_len: u32,
    /// Version 2: Length of serialized constraint system section (u32 LE)
    /// Version 1: Number of selectors in the constraint system
    pub cs_len_or_num_selectors: u32,
    /// Version 2: Number of selectors in the constraint system (quick reference)
    /// Version 1: Bitmask indicating which fixed columns have equality enabled
    pub num_selectors_or_fixed_mask: u32,
    /// Version 2: Number of gates in the constraint system (quick reference)
    /// Version 1: Packed advice query counts per column
    pub num_gates_or_advice_counts: u32,
    /// CRC32 checksum of params+vk+cs bytes (optional validation)
    pub crc32: u32,
}

impl CircuitFooter {
    /// Create a new version 1 circuit footer (backward compatibility)
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
        fixed_equality_mask: u32,
        advice_query_counts: u32,
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
            cs_len_or_num_selectors: num_selectors,
            num_selectors_or_fixed_mask: fixed_equality_mask,
            num_gates_or_advice_counts: advice_query_counts,
            crc32,
        }
    }

    /// Create a new version 2 circuit footer (CS-inclusive format)
    pub fn new_v2(
        circuit_type: CircuitType,
        instance_count: u8,
        num_fixed_columns: u8,
        num_advice_columns: u8,
        num_instance_columns: u8,
        degree: u8,
        params_len: u32,
        vk_len: u32,
        cs_len: u32,
        num_selectors: u32,
        num_gates: u32,
        has_lookups: bool,
        crc32: u32,
    ) -> Self {
        let mut flags = footer_flags::HAS_CS;
        if has_lookups {
            flags |= footer_flags::HAS_LOOKUPS;
        }
        Self {
            circuit_type,
            instance_count,
            num_fixed_columns,
            num_advice_columns,
            num_instance_columns,
            degree,
            footer_version: 2,
            flags,
            params_len,
            vk_len,
            cs_len_or_num_selectors: cs_len,
            num_selectors_or_fixed_mask: num_selectors,
            num_gates_or_advice_counts: num_gates,
            crc32,
        }
    }

    /// Check if this footer is version 2 (CS-inclusive)
    pub fn is_v2(&self) -> bool {
        self.footer_version >= 2
    }

    /// Check if constraint system section is present
    pub fn has_cs(&self) -> bool {
        self.flags & footer_flags::HAS_CS != 0
    }

    /// Get the constraint system length (version 2 only)
    pub fn cs_len(&self) -> Option<u32> {
        if self.is_v2() {
            Some(self.cs_len_or_num_selectors)
        } else {
            None
        }
    }

    /// Get the number of selectors
    pub fn num_selectors(&self) -> u32 {
        if self.is_v2() {
            self.num_selectors_or_fixed_mask
        } else {
            self.cs_len_or_num_selectors
        }
    }

    /// Get the number of gates (version 2 only)
    pub fn num_gates(&self) -> Option<u32> {
        if self.is_v2() {
            Some(self.num_gates_or_advice_counts)
        } else {
            None
        }
    }

    /// Get the fixed equality mask (version 1 only)
    pub fn fixed_equality_mask(&self) -> Option<u32> {
        if !self.is_v2() {
            Some(self.num_selectors_or_fixed_mask)
        } else {
            None
        }
    }

    /// Get the advice query counts (version 1 only)
    pub fn advice_query_counts(&self) -> Option<u32> {
        if !self.is_v2() {
            Some(self.num_gates_or_advice_counts)
        } else {
            None
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
        bytes[16..20].copy_from_slice(&self.cs_len_or_num_selectors.to_le_bytes());
        bytes[20..24].copy_from_slice(&self.num_selectors_or_fixed_mask.to_le_bytes());
        bytes[24..28].copy_from_slice(&self.num_gates_or_advice_counts.to_le_bytes());
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
        if footer_version != 1 && footer_version != 2 {
            return Err(ZkError::new_err(format!(
                "Unsupported footer version: {} (supported: 1, 2)",
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
            cs_len_or_num_selectors: u32::from_le_bytes([
                bytes[16], bytes[17], bytes[18], bytes[19],
            ]),
            num_selectors_or_fixed_mask: u32::from_le_bytes([
                bytes[20], bytes[21], bytes[22], bytes[23],
            ]),
            num_gates_or_advice_counts: u32::from_le_bytes([
                bytes[24], bytes[25], bytes[26], bytes[27],
            ]),
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
    pub fixed_equality_mask: u32,
    /// Packed advice query counts per column (each nibble = query count for one column)
    pub advice_query_counts: u32,
}

// Thread-local storage for circuit config during keygen
thread_local! {
    static DYNAMIC_CIRCUIT_CONFIG: std::cell::RefCell<Option<DynamicCircuitConfig>> =
        std::cell::RefCell::new(None);
}

/// RAII Guard for DynamicCircuit thread-local configuration
///
/// Automatically clears the thread-local config when dropped, preventing leaks
/// and reentrancy issues in concurrent scenarios. Ensures cleanup even if panic occurs.
///
/// # Safety
/// This guard must be held for the entire duration of VK deserialization/keygen.
/// Dropping it will clear the thread-local config.
#[must_use = "guard should be held for the entire operation"]
pub struct DynamicCircuitGuard;

impl DynamicCircuitGuard {
    /// Create a new guard - should only be created after set_as_current()
    fn new() -> Self {
        Self
    }
}

impl Drop for DynamicCircuitGuard {
    fn drop(&mut self) {
        // Automatically cleanup the thread-local on scope exit
        DynamicCircuit::clear_current();
    }
}

/// Generic circuit that implements Circuit<vesta::Scalar> dynamically
/// Configured at runtime using footer metadata to match any constraint system
///
/// This enables deserialization of verifying keys without needing the original circuit type.
/// The key insight: we only need to match the column structure; gates come from the deserialized VK.
///
/// For version 2, can be initialized with a pinned constraint system for accurate metadata extraction.
///
/// Usage:
/// ```ignore
/// let circuit = DynamicCircuit::from_footer(&footer, None);  // v1
/// let circuit = DynamicCircuit::from_footer(&footer, Some(Arc::new(cs)));  // v2
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
        fixed_equality_mask: u32,
        advice_query_counts: u32,
    ) -> Self {
        Self {
            config: DynamicCircuitConfig {
                num_fixed_columns,
                num_advice_columns,
                num_instance_columns,
                num_selectors,
                fixed_equality_mask,
                advice_query_counts,
            },
        }
    }

    /// Create from circuit footer metadata, optionally with pinned constraint system
    pub fn from_footer(footer: &CircuitFooter) -> Self {
        // Always use footer metadata, as it's derived from the CS during serialization
        // The pinned_cs is stored for potential future use or verification
        Self {
            config: DynamicCircuitConfig {
                num_fixed_columns: footer.num_fixed_columns,
                num_advice_columns: footer.num_advice_columns,
                num_instance_columns: footer.num_instance_columns,
                num_selectors: footer.num_selectors(),
                fixed_equality_mask: footer.fixed_equality_mask().unwrap_or(0),
                advice_query_counts: footer.advice_query_counts().unwrap_or(0),
            },
        }
    }

    /// Set this circuit's config as the current thread-local for use in configure()
    /// Must be called before halo2 operations that invoke configure()

    /// Set config and return an RAII guard for automatic cleanup
    ///
    /// The guard ensures cleanup happens automatically even if panic occurs.
    /// This is the preferred method for safe VK deserialization.
    ///
    /// # Usage
    /// ```ignore
    /// let circuit = DynamicCircuit::from_footer(&footer);
    /// let _guard = circuit.set_as_current_guarded();
    /// // halo2::VerifyingKey::read can now use the circuit
    /// // Guard automatically cleans up when _guard goes out of scope
    /// ```
    pub fn set_as_current_guarded(&self) -> DynamicCircuitGuard {
        DYNAMIC_CIRCUIT_CONFIG.with(|cfg| {
            *cfg.borrow_mut() = Some(self.config);
        });
        DynamicCircuitGuard::new()
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
        let _ = self.set_as_current_guarded();
        self.clone()
    }

    fn configure(meta: &mut ConstraintSystem<vesta::Scalar>) -> Self::Config {
        // Get config from thread-local that was set by set_as_current()
        let config = Self::current_config().expect(
            "DynamicCircuit::configure called without setting thread-local config. \
             Call circuit.set_as_current() before keygen operations.",
        );

        // --------------------------------------------------------------------
        // Fixed columns
        // --------------------------------------------------------------------
        // IMPORTANT:
        // - These correspond ONLY to meta.fixed_column() calls
        // - Selectors are NOT included here
        // - Equality is enabled selectively via fixed_equality_mask
        let mut fixed_cols = Vec::with_capacity(config.num_fixed_columns as usize);
        for i in 0..config.num_fixed_columns {
            let col = meta.fixed_column();
            // Enable equality on this fixed column if requested by the footer
            if (config.fixed_equality_mask & (1u32 << i)) != 0 {
                meta.enable_equality(col);
            }
            fixed_cols.push(col);
        }
        // --------------------------------------------------------------------
        // Advice columns
        // --------------------------------------------------------------------
        // Convention: ALL advice columns have equality enabled
        let mut advice_cols = Vec::with_capacity(config.num_advice_columns as usize);
        for _ in 0..config.num_advice_columns {
            let col = meta.advice_column();
            meta.enable_equality(col);
            advice_cols.push(col);
        }

        // --------------------------------------------------------------------
        // Create dummy gate to generate advice queries at correct rotations
        // --------------------------------------------------------------------
        // The advice_query_counts is a packed u32 where each nibble (4 bits) represents
        // the number of queries for that advice column. Nibble 0 = column 0, etc.
        // We create a dummy gate that queries each column the required number of times
        // at sequential rotations starting from Rotation(0).
        //
        // Example: advice_query_counts = 0x12 means:
        //   - Column 0: 2 queries (Rotation(0), Rotation(1))
        //   - Column 1: 1 query (Rotation(0))
        let advice_query_counts = config.advice_query_counts;
        let has_dummy_gate = advice_query_counts != 0;
        if has_dummy_gate {
            use halo2_proofs::poly::Rotation;
            // Create a selector for our dummy gate (uses one of the circuit's selectors)
            let dummy_selector = meta.selector();

            meta.create_gate("dynamic_queries", |meta| {
                let s = meta.query_selector(dummy_selector);

                // Query each advice column the required number of times
                for (col_idx, col) in advice_cols.iter().enumerate() {
                    // Extract query count for this column from the packed nibbles
                    let query_count = ((advice_query_counts >> (col_idx * 4)) & 0xF) as i32;

                    // Create queries at sequential rotations: 0, 1, 2, ...
                    for rotation in 0..query_count {
                        let _ = meta.query_advice(*col, Rotation(rotation));
                    }
                }

                // Return a trivial "always satisfied" constraint: s * 0 = 0
                // The selector is never enabled during synthesis, so this constraint
                // is never checked. It exists only to register the queries above.
                vec![s * plonk::Expression::Constant(vesta::Scalar::zero())]
            });
        }

        // --------------------------------------------------------------------
        // Instance columns
        // --------------------------------------------------------------------
        // Convention: ALL instance columns have equality enabled
        let mut instance_cols = Vec::with_capacity(config.num_instance_columns as usize);

        for _ in 0..config.num_instance_columns {
            let col = meta.instance_column();
            meta.enable_equality(col);
            instance_cols.push(col);
        }

        // --------------------------------------------------------------------
        // Constant column
        // --------------------------------------------------------------------
        // Halo2 convention:
        // - First fixed column is the constant column *if one exists*
        // - enable_constant implicitly relies on equality having been enabled
        if let Some(constant_col) = fixed_cols.first() {
            meta.enable_constant(*constant_col);
        }
        // --------------------------------------------------------------------
        // Selectors
        // --------------------------------------------------------------------
        // Selectors are NOT fixed columns and must be recreated explicitly
        // If we created a dummy gate above, it used one selector, so create one fewer
        let selectors_to_create = if has_dummy_gate {
            config.num_selectors.saturating_sub(1)
        } else {
            config.num_selectors
        };
        for _ in 0..selectors_to_create {
            meta.selector();
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

impl<C> CosmwasmCircuit<C> {
    pub fn new(circuit: C) -> Self {
        Self { circuit }
    }
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
    pub footer: Vec<u8>,
}

impl SerializedPlonkishCircuitData {
    /// Create from raw components
    pub fn new(bytes: &[u8], hash: &[u8], footer: &[u8]) -> Self {
        Self {
            bytes: bytes.into(),
            hash: hash.try_into().expect("hash checksum"),
            footer: footer.into(),
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

        // For hash, we need to compute it from the params+vk bytes
        // This is a simplified approach - the actual hash should be provided
        let mut hash = [0u8; 32];
        // In practice, this should be computed via Blake2b of just the vk portion

        Ok(Self {
            bytes: value.into(),
            hash,
            footer: footer_bytes.to_vec(),
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
    /// WARNING: This creates new random params - only use for fresh key generation.
    /// For deserialization, use `new_with_params` to preserve the original params.
    pub fn new(vk: plonk::VerifyingKey<vesta::Affine>, k: u32, i: usize) -> Self {
        VerifyingKey {
            params: poly::commitment::Params::new(k),
            vk,
            i,
        }
    }

    /// Builds the verifying key with existing params.
    /// Use this when deserializing to preserve the original params used during proving.
    pub fn new_with_params(
        params: poly::commitment::Params<vesta::Affine>,
        vk: plonk::VerifyingKey<vesta::Affine>,
        i: usize,
    ) -> Self {
        VerifyingKey { params, vk, i }
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
            eprintln!("validation structure error");
            return Err(ZkError::new_err(format!(
                "VK: Circuit file size mismatch: {}+{}+32 != {}",
                params_len,
                vk_len,
                bytes.len()
            )));
        }

        Ok(SerializedPlonkishCircuitData::new(
            bytes,
            &[0u8; 32],
            &footer_bytes,
        ))
    }

    /// Deserialize a VerifyingKey from raw bytes
    ///
    /// Supports two formats:
    /// - **Version 1**: `[params][vk][footer]` - uses DynamicCircuit to reconstruct CS
    /// - **Version 2**: `[params][vk][cs][footer]` - uses serialized CS for circuit-agnostic verification
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
            "✓ Footer parsed: version={}, instance_count={}, fixed={}, advice={}, instance={}, degree={}",
            footer.footer_version,
            footer.instance_count,
            footer.num_fixed_columns,
            footer.num_advice_columns,
            footer.num_instance_columns,
            footer.degree
        );

        let params_len = footer.params_len as usize;
        let vk_len = footer.vk_len as usize;

        // Handle version 2 with embedded constraint system
        if footer.is_v2() && footer.has_cs() {
            return Self::from_bytes_v2(bytes, &footer);
        }

        // Version 1: Validate structure for [params][vk][footer]
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
        eprintln!("🔧 Creating DynamicCircuit from footer (v1)...");
        let circuit = DynamicCircuit::from_footer(&footer);

        // RAII guard ensures cleanup even if deserialization panics
        let _guard = circuit.set_as_current_guarded();

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

        // Guard automatically cleans up when dropped at scope end
        drop(_guard);

        // IMPORTANT: Use new_with_params to preserve the deserialized params!
        // Using new() would create new random params, causing verification to fail.
        Ok(VerifyingKey::new_with_params(
            params,
            vk,
            footer.instance_count as usize,
        ))
    }

    /// Deserialize a VerifyingKey from version 2 format with embedded constraint system
    /// Format: `[params][vk][cs][footer]`
    fn from_bytes_v2(bytes: &[u8], footer: &CircuitFooter) -> ZkResult<Self> {
        eprintln!("📦 from_bytes_v2: using embedded constraint system");

        let params_len = footer.params_len as usize;
        let vk_len = footer.vk_len as usize;
        let cs_len = footer
            .cs_len()
            .ok_or_else(|| ZkError::new_err("Version 2 footer missing cs_len"))?
            as usize;

        // Validate structure for [params][vk][cs][footer]
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
        eprintln!("🔄 Deserializing params ({} bytes)...", params_len);
        let mut params_reader = Cursor::new(params_bytes);
        let params = poly::commitment::Params::<vesta::Affine>::read(&mut params_reader)?;
        eprintln!("✓ Params deserialized (k={})", params.k());

        // Deserialize constraint system
        eprintln!("🔧 Deserializing constraint system ({} bytes)...", cs_len);
        let mut cs_reader = Cursor::new(cs_bytes);
        let cs = ConstraintSystem::<vesta::Scalar>::read(&mut cs_reader)
            .map_err(|e| ZkError::from_io(e))?;
        eprintln!(
            "✓ CS deserialized: gates={}, selectors={}",
            cs.get_gate_count(),
            cs.get_num_selectors()
        );

        // For now, we pass empty selectors - the actual selector assignments
        // are in the VK's selector section
        let empty_selectors: Vec<Vec<bool>> = vec![];

        // Deserialize vk using the pre-built constraint system
        eprintln!(
            "🔑 Deserializing VK ({} bytes) with read_with_cs...",
            vk_len
        );
        let mut vk_reader = Cursor::new(vk_bytes);
        let vk = halo2_proofs::plonk::VerifyingKey::<vesta::Affine>::read_with_cs(
            &mut vk_reader,
            &params,
            cs,
            empty_selectors,
        )
        .map_err(|e| {
            eprintln!("❌ VK deserialization failed: {:?}", e);
            ZkError::from_io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("{:?}", e),
            ))
        })?;
        eprintln!("✓ VK deserialized successfully (v2)");

        Ok(VerifyingKey::new_with_params(
            params,
            vk,
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

        // IMPORTANT: Use new_with_params to preserve the deserialized params!
        Ok(VerifyingKey::new_with_params(
            params,
            vk,
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
        fixed_equality_mask: u8,
        advice_query_counts: u8,
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
            fixed_equality_mask.into(),
            advice_query_counts as u32,
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
    // TODO: support flexibility in instance scalar_size
    pub fn new_from_vm(i: Vec<u8>) -> ZkResult<Self> {
        const SCALAR_SIZE: usize = 32;
        if !i.len().is_multiple_of(SCALAR_SIZE) {
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
