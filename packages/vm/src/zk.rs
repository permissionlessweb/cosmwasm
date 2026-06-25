use cosmwasm_std::Checksum;

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

    /// validates binary structure, returns hash of just verifying key.
    ///  (mimics release specification of halo2 circuits for interoperability)
    pub fn with_vk(wasm: Vec<u8>, vk_bytes: Vec<u8>) -> ZkResult<Self> {
        let footer = check_circuit(&vk_bytes)?;
        Ok(Self::with_vk_and_type(wasm, vk_bytes, footer))
    }

    pub fn with_vk_and_type(wasm: Vec<u8>, vk_bytes: Vec<u8>, footer: CircuitFooter) -> Self {
        let vk = SerializedPlonkishCircuitData::new(&vk_bytes, &footer.to_bytes());
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
            (true, Some(vk)) => [
                Checksum::generate(&self.wasm),
                Checksum::generate(&vk.bytes),
            ],
            (false, None) => [self.dummy_checksum(), self.dummy_checksum()],
            (false, Some(vk)) => [self.dummy_checksum(), Checksum::generate(&vk.bytes)],
        }
    }

    // Helper to produce a dummy checksum (same as used for missing VK)
    fn dummy_checksum(&self) -> Checksum {
        Checksum::generate(&[])
    }
}

use halo2_proofs::COSMWASM_FOOTER_LENGTH;

/// Serializes SerializedPlonkishCircuitData into a complete binary format for FFI transmission.
pub fn serialize_circuit_data(vk_data: &SerializedPlonkishCircuitData) -> Vec<u8> {
    let mut result = Vec::new();
    result.extend_from_slice(&vk_data.bytes);
    result.extend_from_slice(&vk_data.footer);
    result
}

/// Deserializes circuit data from the FFI binary format back into SerializedPlonkishCircuitData
pub fn deserialize_circuit_data(data: &[u8]) -> ZkResult<SerializedPlonkishCircuitData> {
    let length = data.len();
    if length < COSMWASM_FOOTER_LENGTH {
        return Err(ZkError::new_err("Circuit data too short"));
    }
    let circuit_len = length - COSMWASM_FOOTER_LENGTH;
    Ok(SerializedPlonkishCircuitData::new(
        &data[0..circuit_len].to_vec(),
        &data[circuit_len..].to_vec(),
    ))
}

pub fn check_circuit(bytes: &[u8]) -> ZkResult<CircuitFooter> {
    let footer_bytes = &bytes[bytes.len() - COSMWASM_FOOTER_LENGTH..];
    let body_bytes = &bytes[0..bytes.len() - COSMWASM_FOOTER_LENGTH];
    let footer = CircuitFooter::from_bytes(footer_bytes)
        .map_err(|e| ZkError::new_err(format!("Failed to parse CircuitFooter: {}", e)))?;
    tracing::debug!("✓ Parsed CircuitFooter: {}", footer);
    assert_eq!(
        &Checksum::generate(&body_bytes).as_slice(),
        &footer.checksum
    );

    Ok(footer)
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
        let params_len: u32 = 90;
        let vk_len: u32 = 100;
        // Total = 90 + 100 + 32 = 222 bytes

        // Build 32-byte footer using CircuitFooter
        let footer = CircuitFooter::new(CircuitType::Plonkish, 2, [0u8; 32]);

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
    }

    #[test]
    fn code_bundle_with_vk_v2() {
        let wasm = vec![0u8; 100];
        // Define sizes for v2 format with CS
        let params_len: u32 = 90;
        let vk_len: u32 = 100;
        let cs_len: u32 = 50;
        // Total = 90 + 100 + 50 + 32 = 272 bytes

        // Build 32-byte footer using CircuitFooter::new
        let footer = CircuitFooter::new(
            CircuitType::Plonkish,
            2, // instance_count
            [0u8; 32],
        );

        // Build the full vk blob for v2: params + vk + cs + footer
        let mut vk_blob = Vec::new();
        // params
        vk_blob.extend(vec![0xAA; params_len as usize]);
        // vk
        vk_blob.extend(vec![0xBB; vk_len as usize]);
        // cs
        vk_blob.extend(vec![0xCC; cs_len as usize]);
        // footer (32 bytes)
        vk_blob.extend_from_slice(&footer.to_bytes());
        assert_eq!(vk_blob.len(), 272); // Sanity check: 90 + 100 + 50 + 32

        let bundle = CodeBundle::with_vk(wasm.clone(), vk_blob.clone()).unwrap();

        assert_eq!(bundle.wasm, wasm);
        assert!(bundle.verifying_key.is_some());

        let vk_data = bundle.verifying_key.unwrap();

        assert_eq!(vk_data.bytes, vk_blob);

        // Metadata should contain circuit info
        assert!(!vk_data.footer.is_empty());
        assert_eq!(vk_data.bytes.len(), 272); // Total blob length with 32-byte footer

        // Hash should not be empty
        // assert_ne!(
        //     vk_data.hash.to_vec(),
        //     cosmwasm_std::Checksum::from([0u8; 32]).as_slice()
        // );
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
