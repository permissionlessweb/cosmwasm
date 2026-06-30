use halo2_proofs::COSMWASM_FOOTER_LENGTH;

use crate::cosmwasm_circuit::CircuitType;
use crate::errors::{ZkError, ZkResult};

/// Circuit footer metadata - [[COSMWASM_FOOTER_LENGTH]] bytes containing complete constraint system specification.
/// V2 CS-inclusive format: enables generic deserialization via DynamicCircuit
/// without needing the original circuit type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CircuitFooter {
    /// Circuit type identifier (currently only Plonkish=0)
    pub circuit_type: CircuitType,
    /// Number of public input scalars required by this circuit
    pub instance_count: u8,
    /// byte length of params
    pub param_len: u32,
    /// byte length of constraint systems
    pub cs_len: u32,
    /// byte length of vk
    pub vk_len: u32,
    /// checksums
    pub checksum: [u8; 32],
}

impl std::fmt::Display for CircuitFooter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!("{:#?},", self.circuit_type.to_u8()))?;
        f.write_str(&format!("{:#?}", self.instance_count))?;
        f.write_str(&format!("{:#?}", self.param_len))?;
        f.write_str(&format!("{:#?}", self.cs_len))?;
        f.write_str(&format!("{:#?}", self.vk_len))?;
        f.write_str(&format!("{:#?}", hex::encode(self.checksum)))
    }
}

impl Into<[u8; COSMWASM_FOOTER_LENGTH]> for CircuitFooter {
    fn into(self) -> [u8; COSMWASM_FOOTER_LENGTH] {
        self.to_bytes()
    }
}

impl TryFrom<&[u8]> for CircuitFooter {
    type Error = ZkError;
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Self::from_bytes(&bytes)
    }
}

impl CircuitFooter {
    pub fn checksum_to_hex(&self) -> String {
        hex::encode(self.checksum)
    }
    /// Create a new v2 circuit footer (CS-inclusive format).
    pub fn new(
        circuit_type: CircuitType,
        instance_count: u8,
        param_len: u32,
        cs_len: u32,
        vk_len: u32,
        hash: [u8; 32],
    ) -> Self {
        Self {
            circuit_type,
            instance_count,
            checksum: hash,
            param_len,
            cs_len,
            vk_len,
        }
    }

    /// Serialize footer to exactly [COSMWASM_FOOTER_LENGTH] bytes.
    /// Layout:
    /// - [0]: circuit_type (1 byte)
    /// - [1]: instance_count (1 byte)
    /// - [2..6]: param_len (4 bytes, u32 LE)
    /// - [10..14]: vk_len (4 bytes, u32 LE)
    /// - [14..14]: vk_len (4 bytes, u32 LE)
    /// - [21..53]: checksum (32 bytes,  )
    pub fn to_bytes(&self) -> [u8; COSMWASM_FOOTER_LENGTH] {
        let mut bytes = [0u8; COSMWASM_FOOTER_LENGTH];
        bytes[0] = self.circuit_type.to_u8();
        bytes[1] = self.instance_count;
        bytes[2..6].copy_from_slice(&self.param_len.to_le_bytes());
        bytes[6..10].copy_from_slice(&self.cs_len.to_le_bytes());
        bytes[10..14].copy_from_slice(&self.vk_len.to_le_bytes());
        bytes[14..COSMWASM_FOOTER_LENGTH].copy_from_slice(&self.checksum.as_slice());
        bytes
    }

    /// Parse footer from exactly [[COSMWASM_FOOTER_LENGTH]] bytes
    pub fn from_bytes(bytes: &[u8]) -> ZkResult<Self> {
        if bytes.len() != COSMWASM_FOOTER_LENGTH {
            return Err(ZkError::new_err(format!(
                "CircuitFooter must be exactly {} bytes, got {}",
                COSMWASM_FOOTER_LENGTH,
                bytes.len()
            )));
        }
        Ok(Self {
            circuit_type: CircuitType::from_u8(bytes[0])
                .ok_or_else(|| ZkError::new_err("Invalid circuit type in footer"))?,
            instance_count: bytes[1],
            param_len: u32::from_le_bytes(bytes[2..6].try_into()?),
            cs_len: u32::from_le_bytes(bytes[6..10].try_into()?),
            vk_len: u32::from_le_bytes(bytes[10..14].try_into()?),
            checksum: bytes[bytes.len() - 32..] // checksum is ALWAYS the last 32 bytes
                .try_into()
                .map_err(|_| ZkError::new_err("Failed to parse checksum"))?,
        })
    }
}
