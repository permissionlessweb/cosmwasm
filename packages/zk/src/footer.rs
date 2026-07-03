use halo2_proofs::COSMWASM_FOOTER_LENGTH;

use crate::curves::CurveType;
use crate::errors::{ZkError, ZkResult};
use crate::CircuitType;

/// Circuit footer metadata - [[COSMWASM_FOOTER_LENGTH]] bytes containing complete constraint system specification.
/// V2 CS-inclusive format: enables generic deserialization via DynamicCircuit
/// without needing the original circuit type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CircuitFooter {
    /// Circuit proving type identifier (currently only Plonkish=0)
    pub prover_id: u8,
    /// Circuit constraint system curve identifier (Currently only Pasta)
    pub curve_id: u8,
    /// K element in circuit constraint system.
    pub k: u8,
    /// Number of public input scalars required by this circuit
    pub i_len: u8,
    /// byte length of constraint systems
    pub cs_len: u32,
    /// byte length of vk
    pub vk_len: u32,
    /// checksums
    pub checksum: [u8; 32],
}

impl CircuitFooter {
    /// Merges prover_id, param_id, k, and i_len into a single u64 key.
    /// Layout: [0, 0, 0, 0, prover_id, param_id, k, i_len] (Big-Endian)
    pub fn to_appstate_key(&self) -> u32 {
        // Construct a 8-byte array.
        // We place the 4 fields in the lower 4 bytes.
        // The upper 4 bytes are padded with 0.
        let bytes = [self.prover_id, self.curve_id, self.k, self.i_len];

        // Convert the byte array to u64.
        // from_be_bytes interprets the first element as the most significant byte.
        u32::from_be_bytes(bytes)
    }
}

impl std::fmt::Display for CircuitFooter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!("{:#?},", self.prover_id))?;
        f.write_str(&format!("{:#?}", self.curve_id))?;
        f.write_str(&format!("{:#?}", self.k))?;
        f.write_str(&format!("{:#?}", self.i_len))?;
        f.write_str(&format!("{:#?}", self.cs_len))?;
        f.write_str(&format!("{:#?}", self.vk_len))?;
        f.write_str(&format!("{:#?}", hex::encode(self.checksum)))
    }
}

impl From<CircuitFooter> for [u8; COSMWASM_FOOTER_LENGTH] {
    fn from(val: CircuitFooter) -> Self {
        val.to_bytes()
    }
}

impl TryFrom<&[u8]> for CircuitFooter {
    type Error = ZkError;
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Self::from_bytes(bytes)
    }
}

impl CircuitFooter {
    pub fn checksum_to_hex(&self) -> String {
        hex::encode(self.checksum)
    }
    /// Create a new v2 circuit footer (CS-inclusive format).
    pub fn new(
        prover_id: CircuitType,
        curve_id: CurveType,
        k: u8,
        i_len: u8,
        cs_len: u32,
        vk_len: u32,
        hash: [u8; 32],
    ) -> Self {
        Self {
            prover_id: prover_id.into(),
            curve_id: curve_id.into(),
            k,
            i_len,
            checksum: hash,
            cs_len,
            vk_len,
        }
    }

    /// Serialize footer to exactly [COSMWASM_FOOTER_LENGTH] bytes.
    pub fn to_bytes(&self) -> [u8; COSMWASM_FOOTER_LENGTH] {
        let mut bytes = [0u8; COSMWASM_FOOTER_LENGTH];
        bytes[0] = self.prover_id;
        bytes[1] = self.curve_id;
        bytes[2] = self.k;
        bytes[3] = self.i_len;
        bytes[4..8].copy_from_slice(&self.cs_len.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.vk_len.to_le_bytes());
        bytes[12..COSMWASM_FOOTER_LENGTH].copy_from_slice(self.checksum.as_slice());
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
            prover_id: bytes[0],
            curve_id: bytes[1],
            k: bytes[2],
            i_len: bytes[3],
            cs_len: u32::from_le_bytes(bytes[7..11].try_into()?),
            vk_len: u32::from_le_bytes(bytes[11..15].try_into()?),
            checksum: bytes[bytes.len() - 32..] // checksum is ALWAYS the last 32 bytes
                .try_into()
                .map_err(|_| ZkError::new_err("Failed to parse checksum"))?,
        })
    }
}
