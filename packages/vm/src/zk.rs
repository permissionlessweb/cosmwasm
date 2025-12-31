use std::io;

use cosmwasm_std::Checksum;

pub use zk_cosmwasm::cosmwasm_circuit::{
    CircuitType, CosmwasmCircuit, CosmwasmCircuitFor, DefaultCircuit, PinnedCircuit,
    PlonkishCircuitMetadata, Proof, ProvingKey, VerifyingKey,
};
/// re-export zk-cosmwasm into vm library
pub use zk_cosmwasm::*;

/// Code bundle containing WASM and optional verifying key
#[derive(Clone, Debug)]
pub struct CodeBundle {
    pub wasm: Vec<u8>,
    pub verifying_key: Option<SerializedPlonkishCircuitData>,
}

impl CodeBundle {
    pub fn wasm_only(wasm: Vec<u8>) -> Self {
        CodeBundle {
            wasm,
            verifying_key: None,
        }
    }

    /// validates binary structure, returns hash of just verifying key (mimics release specification of halo2 circuits for interoperability)
    pub fn with_vk(wasm: Vec<u8>, vk_bytes: Vec<u8>) -> ZkResult<Self> {
        let (vk, hash) = check_circuit(&vk_bytes)?;
        Ok(Self::with_vk_and_type(wasm, vk_bytes, &vk, hash))
    }

    pub fn with_vk_and_type(
        wasm: Vec<u8>,
        vk_bytes: Vec<u8>,
        metadata: &crate::PlonkishCircuitMetadata,
        hash: cosmwasm_std::Checksum,
    ) -> Self {
        let vk =
            SerializedPlonkishCircuitData::new(&vk_bytes, &hash.as_slice(), &metadata.to_bytes());
        CodeBundle {
            wasm,
            verifying_key: Some(vk),
        }
    }

    // true - wasm; false - && circuit
    pub fn bundle_has_circuit(&self) -> bool {
        self.verifying_key.is_some()
    }

    // Helper: Compute checksums without persisting
    pub fn compute_checksums(&self) -> [Checksum; 2] {
        match (self.wasm.len() > 0, &self.verifying_key) {
            (true, None) => [Checksum::generate(&self.wasm), self.dummy_checksum()],
            (true, Some(vk)) => [Checksum::generate(&self.wasm), vk.hash.into()],
            (false, None) => [self.dummy_checksum(), self.dummy_checksum()],
            (false, Some(vk)) => [self.dummy_checksum(), Checksum::generate(&vk.bytes)],
        }
    }

    // Helper to produce a dummy checksum (same as used for missing VK)
    fn dummy_checksum(&self) -> Checksum {
        Checksum::generate(&[])
    }
}

/// Hash the verifying key bytes using the same method as halo2
/// halo2 uses Blake2b-256 for circuit hashing
pub fn hash_circuit(cmd: PlonkishCircuitMetadata, full_bytes: &[u8]) -> Checksum {
    Checksum::generate(&cmd.vk_bytes(full_bytes))
}

/// Validates that a VK blob can be deserialized
/// We use a generic circuit marker to avoid needing the actual circuit at validation time

/// Validates that a combined params+VK blob matches expected structure
/// This validates the file format written by `build_and_write`
pub fn check_circuit(bytes: &[u8]) -> ZkResult<(PlonkishCircuitMetadata, Checksum)> {
    use halo2_proofs::COSMWASM_METADATA_LENGTH;

    if bytes.len() < COSMWASM_METADATA_LENGTH {
        return Err(ZkError::new_err(format!(
            "VK bytes too short - need at least {} bytes for footer",
            COSMWASM_METADATA_LENGTH
        )));
    }

    // Step 1: Parse the COSMWASM_METADATA_LENGTH-byte footer (last 10 bytes)
    let footer_start = bytes.len() - COSMWASM_METADATA_LENGTH;

    let ct = CircuitType::from_u8(bytes[footer_start]).ok_or_else(|| {
        ZkError::from_io(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Invalid circuit type in VK footer: 0x{:02x}",
                bytes[footer_start]
            ),
        ))
    })?;

    let i = bytes[footer_start + 1];
    let vkpl = u32::from_le_bytes([
        bytes[footer_start + 2],
        bytes[footer_start + 3],
        bytes[footer_start + 4],
        bytes[footer_start + 5],
    ]) as usize;

    let vkl = u32::from_le_bytes([
        bytes[footer_start + 6],
        bytes[footer_start + 7],
        bytes[footer_start + 8],
        bytes[footer_start + 9],
    ]) as usize;

    // Step 2: Validate file structure
    let expected_total = vkpl + vkl + COSMWASM_METADATA_LENGTH;
    if bytes.len() != expected_total {
        return Err(ZkError::from_io(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "VK file size mismatch: got {} bytes, expected {} (params:{} + vk:{} + footer:{})",
                bytes.len(),
                expected_total,
                vkpl,
                vkl,
                COSMWASM_METADATA_LENGTH
            ),
        )));
    }

    // Step 4: Validate VK exists and has minimum content
    if vkl == 0 {
        return Err(ZkError::from_io(io::Error::new(
            io::ErrorKind::InvalidData,
            "VK length cannot be 0",
        )));
    }

    let vk_bytes = &bytes[vkpl..vkpl + vkl];

    // VK bytes should exists
    if vk_bytes.is_empty() {
        return Err(ZkError::from_io(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("No VK bytes recognized"),
        )));
    }

    let zk = cosmwasm_circuit::PlonkishCircuitMetadata::new(ct, i, vkpl, vkl);

    Ok((zk, hash_circuit(zk, bytes)))
}

/// Serialized verifying key bundle that gets stored alongside WASM
#[derive(Clone, Debug)]
pub struct SerializedPlonkishCircuitData {
    /// Raw bytes of the serialized params + vk
    pub bytes: Vec<u8>,
    /// SHA256 hash of the bytes for integrity checking
    pub hash: Checksum,
    /// Circuit metadata
    pub metadata: Vec<u8>,
}

impl SerializedPlonkishCircuitData {
    pub fn new(bytes: &[u8], hash: &[u8], metadata: &[u8]) -> Self {
        Self {
            bytes: bytes.into(),
            hash: Checksum::try_from(hash).expect("checksum"),
            metadata: metadata.into(),
        }
    }
}

impl From<Vec<u8>> for SerializedPlonkishCircuitData {
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
        let vkl = u64::from_le_bytes([
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

        SerializedPlonkishCircuitData {
            bytes,
            hash: hash.into(),
            metadata: cosmwasm_circuit::PlonkishCircuitMetadata::new(ct, i, vkpl, vkl).to_bytes(),
        }
    }
}

impl Into<Vec<u8>> for SerializedPlonkishCircuitData {
    fn into(self) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend_from_slice(&self.bytes);
        result.extend_from_slice(&self.hash.as_slice());
        result.extend_from_slice(&self.metadata);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zk_cosmwasm::cosmwasm_circuit::PlonkishCircuitMetadata;

    #[test]
    fn test_validate_empty() {
        assert!(check_circuit(&[]).is_err());
    }

    #[test]
    fn test_validate_truncated() {
        // Just a version byte, nothing else
        assert!(check_circuit(&[0x01]).is_err());
    }

    #[test]
    fn circuit_type_conversion() {
        assert_eq!(CircuitType::Plonkish.to_u8(), 0);
        assert_eq!(CircuitType::from_u8(0), Some(CircuitType::Plonkish));
        assert_eq!(CircuitType::from_u8(255), Some(CircuitType::Plonkish));
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
        // params
        vk_blob.extend(vec![0xAA; vkp_len as usize]);
        // vk
        vk_blob.extend(vec![0xBB; vk_len as usize]);
        // footer
        vk_blob.extend_from_slice(&footer); 
        assert_eq!(vk_blob.len(), 200); // Sanity check

        let bundle = CodeBundle::with_vk(wasm.clone(), vk_blob.clone()).unwrap();

        assert_eq!(bundle.wasm, wasm);
        assert!(bundle.verifying_key.is_some());

        let vk_data = bundle.verifying_key.unwrap();

        assert_eq!(vk_data.bytes, vk_blob);

        assert_eq!(vk_data.metadata.len(), 10);
        // assert_eq!(CircuitType::Plonkish);
        assert_eq!(vk_data.bytes.len(), 200); // Total blob length

        assert_ne!(vk_data.hash, cosmwasm_std::Checksum::from([0u8; 32]));
    }

    #[test]
    fn validate_empty_vk_bytes() {
        let result = check_circuit(&[]);
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
