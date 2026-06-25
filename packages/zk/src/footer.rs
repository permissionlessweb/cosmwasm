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
    /// checksums
    pub checksum: [u8; 32],
}

impl std::fmt::Display for CircuitFooter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!("{:#?},", self.circuit_type.to_u8()))?;
        f.write_str(&format!("{:#?}", self.instance_count))?;
        f.write_str(&format!(
            "{:#?}, self.circuit_type.to_u8()",
            hex::encode(self.checksum)
        ))
    }
}

impl CircuitFooter {
    pub fn checksum_to_hex(&self) -> String {
        hex::encode(self.checksum)
    }
    /// Create a new v2 circuit footer (CS-inclusive format).
    pub fn new(circuit_type: CircuitType, instance_count: u8, hash: [u8; 32]) -> Self {
        Self {
            circuit_type,
            instance_count,
            checksum: hash,
        }
    }

    /// Serialize footer to exactly [[COSMWASM_FOOTER_LENGTH]] bytes
    pub fn to_bytes(&self) -> [u8; COSMWASM_FOOTER_LENGTH] {
        let mut bytes = [0u8; COSMWASM_FOOTER_LENGTH];
        bytes[0] = self.circuit_type.to_u8();
        bytes[1] = self.instance_count;
        bytes[2..COSMWASM_FOOTER_LENGTH].copy_from_slice(&self.checksum.as_slice());
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
        let circuit_type = CircuitType::from_u8(bytes[0])
            .ok_or_else(|| ZkError::new_err("Invalid circuit type in footer"))?;

        let checksum: [u8; 32] = bytes[2..COSMWASM_FOOTER_LENGTH]
            .try_into()
            .map_err(|_| ZkError::new_err("Failed to parse checksum"))?;

        Ok(Self {
            circuit_type,
            instance_count: bytes[1],
            checksum,
        })
    }
}
