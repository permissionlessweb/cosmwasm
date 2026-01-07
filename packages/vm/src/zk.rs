use std::io;

use cosmwasm_std::Checksum;

use halo2_proofs::COSMWASM_METADATA_LENGTH;
pub use zk_cosmwasm::cosmwasm_circuit::{
    CircuitFooter, CircuitType, CosmwasmCircuit, CosmwasmCircuitFor, DynamicCircuit,
    DynamicCircuitConfig, PinnedCircuit, Proof, ProvingKey, SerializedPlonkishCircuitData,
    VerifyingKey,
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
        let (footer, hash) = check_circuit(&vk_bytes)?;
        Ok(Self::with_vk_and_type(
            wasm,
            vk_bytes,
            footer,
            hash.as_slice().to_vec(),
        ))
    }

    pub fn with_vk_and_type(
        wasm: Vec<u8>,
        vk_bytes: Vec<u8>,
        footer: CircuitFooter,
        hash: Vec<u8>,
    ) -> Self {
        let vk = SerializedPlonkishCircuitData::new(&vk_bytes, hash.as_slice(), &footer.to_bytes());
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

/// Serializes SerializedPlonkishCircuitData into a complete binary format for FFI transmission
///
/// Binary format:
/// - Bytes 0-3: u32 LE - length of circuit bytes (params + vk + footer)
/// - Bytes 4 to 4+N: circuit bytes
/// - Bytes 4+N to 4+N+32: 32-byte hash
/// - Bytes 4+N+32 to 4+N+32+3: u32 LE - length of metadata
/// - Bytes 4+N+32+4 to end: metadata bytes
pub fn serialize_circuit_data(vk_data: &SerializedPlonkishCircuitData) -> Vec<u8> {
    let mut result = Vec::new();
    result.extend_from_slice(&(vk_data.bytes.len() as u32).to_le_bytes());
    result.extend_from_slice(&vk_data.bytes);
    result.extend_from_slice(&vk_data.hash);
    result.extend_from_slice(&(vk_data.footer.len() as u32).to_le_bytes());
    result.extend_from_slice(&vk_data.footer);
    result
}

/// Deserializes circuit data from the FFI binary format back into SerializedPlonkishCircuitData
pub fn deserialize_circuit_data(data: &[u8]) -> ZkResult<SerializedPlonkishCircuitData> {
    if data.len() < 4 + COSMWASM_METADATA_LENGTH + 4 {
        return Err(ZkError::new_err(
            "Circuit data too short for deserialization",
        ));
    }

    let mut offset = 0;

    // Read circuit bytes length and data
    let circuit_len = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
    offset += 4;

    if offset + circuit_len > data.len() {
        return Err(ZkError::new_err(
            "Invalid circuit data length in deserialization",
        ));
    }

    let circuit_bytes = data[offset..offset + circuit_len].to_vec();
    offset += circuit_len;

    // Read hash (always 32 bytes)
    if offset + 32 > data.len() {
        return Err(ZkError::new_err("Invalid hash length in deserialization"));
    }

    let mut hash = [0u8; 32];
    hash.copy_from_slice(&data[offset..offset + 32]);
    offset += 32;

    // Read metadata length and data
    if offset + 4 > data.len() {
        return Err(ZkError::new_err(
            "Invalid metadata length marker in deserialization",
        ));
    }

    let metadata_len = u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]) as usize;
    offset += 4;

    if offset + metadata_len > data.len() {
        return Err(ZkError::new_err(
            "Invalid metadata length in deserialization",
        ));
    }

    let metadata = data[offset..offset + metadata_len].to_vec();

    Ok(SerializedPlonkishCircuitData::new(
        &circuit_bytes,
        &hash,
        &metadata,
    ))
}

/// Hash the verifying key bytes using the same method as halo2
/// halo2 uses Blake2b-256 for circuit hashing

/// Validates that a VK blob can be deserialized
/// We use a generic circuit marker to avoid needing the actual circuit at validation time

/// Validates that a combined params+VK blob matches expected structure
/// This validates the file format written by `build_and_write`
/// Validates that a combined params+VK+footer blob matches the expected structure
/// and extracts the actual CircuitFooter metadata.
///
/// This is used both at runtime (in the VM) and during build/validation to ensure
/// the file format is correct and can be used generically without knowing the circuit type.
pub fn check_circuit(bytes: &[u8]) -> ZkResult<(CircuitFooter, Checksum)> {
    const FOOTER_SIZE: usize = 32;

    if bytes.len() < FOOTER_SIZE {
        return Err(ZkError::new_err(format!(
            "Circuit file too short: {} bytes, need at least {} for footer",
            bytes.len(),
            FOOTER_SIZE
        )));
    }

    // Extract the footer (last 32 bytes)
    let footer_bytes = &bytes[bytes.len() - FOOTER_SIZE..];
    let footer = CircuitFooter::from_bytes(footer_bytes)
        .map_err(|e| ZkError::new_err(format!("Failed to parse CircuitFooter: {}", e)))?;

    eprintln!(
        "✓ Parsed CircuitFooter: instance_count={}, fixed={}, advice={}, instance={}, degree={}, selectors={}",
        footer.instance_count,
        footer.num_fixed_columns,
        footer.num_advice_columns,
        footer.num_instance_columns,
        footer.degree,
        footer.num_selectors()
    );

    let params_len = footer.params_len as usize;
    let vk_len = footer.vk_len as usize;

    // Validate total length matches declared sections
    let expected_total = params_len + vk_len + FOOTER_SIZE;
    if bytes.len() != expected_total {
        return Err(ZkError::new_err(format!(
            "Circuit file size mismatch: got {} bytes, expected {} (params: {} + vk: {} + footer: {})",
            bytes.len(),
            expected_total,
            params_len,
            vk_len,
            FOOTER_SIZE
        )));
    }

    // Basic sanity checks
    if params_len == 0 {
        return Err(ZkError::new_err("Params section cannot be empty"));
    }
    if vk_len == 0 {
        return Err(ZkError::new_err("Verifying key section cannot be empty"));
    }

    // Extract VK bytes for checksum
    let vk_bytes = &bytes[params_len..params_len + vk_len];

    // Optional: additional validation (e.g., version, circuit type)
    if footer.circuit_type != CircuitType::Plonkish {
        return Err(ZkError::new_err(format!(
            "Unsupported circuit type: {:?}",
            footer.circuit_type
        )));
    }

    if footer.footer_version != 1 {
        return Err(ZkError::new_err(format!(
            "Unsupported footer version: {}",
            footer.footer_version
        )));
    }

    let checksum = Checksum::generate(vk_bytes);

    Ok((footer, checksum))
}

#[cfg(test)]
mod tests {
    use super::*;

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
        // Define sizes for 32-byte footer format
        let params_len: u32 = 90;
        let vk_len: u32 = 100;
        // Total = 90 + 100 + 32 = 222 bytes

        // Build 32-byte footer using CircuitFooter
        let footer = CircuitFooter::new(
            CircuitType::Plonkish,
            2, // instance_count
            2, // num_fixed_columns
            1, // num_advice_columns
            1, // num_instance_columns
            3, // degree
            params_len,
            vk_len,
            0, // num_selectors
            1, // num_selectors
            1,
            0, // crc32
        );

        // Build the full vk blob
        let mut vk_blob = Vec::new();
        // params
        vk_blob.extend(vec![0xAA; params_len as usize]);
        // vk
        vk_blob.extend(vec![0xBB; vk_len as usize]);
        // footer (32 bytes)
        vk_blob.extend_from_slice(&footer.to_bytes());
        assert_eq!(vk_blob.len(), 222); // Sanity check: 90 + 100 + 32

        let bundle = CodeBundle::with_vk(wasm.clone(), vk_blob.clone()).unwrap();

        assert_eq!(bundle.wasm, wasm);
        assert!(bundle.verifying_key.is_some());

        let vk_data = bundle.verifying_key.unwrap();

        assert_eq!(vk_data.bytes, vk_blob);

        // Metadata should contain circuit info (typically 10 bytes for PlonkishCircuitMetadata)
        assert!(!vk_data.footer.is_empty());
        assert_eq!(vk_data.bytes.len(), 222); // Total blob length with 32-byte footer

        // Hash should not be empty
        assert_ne!(
            vk_data.hash.to_vec(),
            cosmwasm_std::Checksum::from([0u8; 32]).as_slice()
        );
    }

    #[test]
    fn validate_empty_vk_bytes() {
        let result = check_circuit(&[]);
        println!("{:#?}", result);
        assert!(result.is_err());
        // New 32-byte footer format requires at least 32 bytes
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("VK file too short: need at least 32 bytes for footer"));
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
