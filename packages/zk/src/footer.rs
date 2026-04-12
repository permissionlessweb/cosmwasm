use crate::cosmwasm_circuit::{footer_flags, CircuitType};
use crate::errors::{ZkError, ZkResult};

/// Circuit footer metadata - 32 bytes containing complete constraint system specification.
/// V2 CS-inclusive format: enables generic deserialization via DynamicCircuit
/// without needing the original circuit type.
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
    /// Footer format version (always 2)
    pub footer_version: u8,
    /// Feature flags (bit 0: HAS_CS, bit 1: HAS_LOOKUPS)
    pub flags: u8,
    /// Length of serialized params section (u32 LE)
    pub params_len: u32,
    /// Length of serialized verifying key section (u32 LE)
    pub vk_len: u32,
    /// Length of serialized constraint system section (u32 LE)
    pub cs_len: u32,
    /// Number of selectors in the constraint system
    pub num_selectors: u32,
    /// Number of gates in the constraint system
    pub num_gates: u32,
    /// CRC32 checksum of params+vk+cs bytes (optional validation)
    pub crc32: u32,
}

impl CircuitFooter {
    /// Create a new v2 circuit footer (CS-inclusive format).
    pub fn new(
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
            cs_len,
            num_selectors,
            num_gates,
            crc32,
        }
    }

    /// Check if constraint system section is present
    pub fn has_cs(&self) -> bool {
        self.flags & footer_flags::HAS_CS != 0
    }

    /// Check if circuit uses lookup arguments
    pub fn has_lookups(&self) -> bool {
        self.flags & footer_flags::HAS_LOOKUPS != 0
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
        bytes[16..20].copy_from_slice(&self.cs_len.to_le_bytes());
        bytes[20..24].copy_from_slice(&self.num_selectors.to_le_bytes());
        bytes[24..28].copy_from_slice(&self.num_gates.to_le_bytes());
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
        if footer_version != 2 {
            return Err(ZkError::new_err(format!(
                "Unsupported footer version: {} (only v2 supported)",
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
            cs_len: u32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]),
            num_selectors: u32::from_le_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]),
            num_gates: u32::from_le_bytes([bytes[24], bytes[25], bytes[26], bytes[27]]),
            crc32: u32::from_le_bytes([bytes[28], bytes[29], bytes[30], bytes[31]]),
        })
    }
}
