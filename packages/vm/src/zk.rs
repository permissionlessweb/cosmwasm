use cosmwasm_std::Checksum;

pub use zk_cosmwasm::*;

/// Code bundle containing WASM and optional verifying key
#[derive(Clone, Debug)]
pub struct CodeBundle {
    pub wasm: Vec<u8>,
    pub vk: Option<SerializedPlonkishCircuitData>,
}

impl CodeBundle {
    pub fn wasm_only(wasm: Vec<u8>) -> Self {
        CodeBundle { wasm, vk: None }
    }
    pub fn with_vk(wasm: Vec<u8>, vk_bytes: Vec<u8>) -> ZkResult<Self> {
        let footer = check_circuit(&vk_bytes)?;
        tracing::debug!("Original vk_bytes len: {}", vk_bytes.len());
        tracing::debug!(
            "Body len passed to new(): {}",
            vk_bytes.len() - COSMWASM_FOOTER_LENGTH
        );

        let bundle = Self::with_vk_and_type(wasm, vk_bytes, footer);

        if let Some(vk) = &bundle.vk {
            tracing::debug!("After new() - vk.bytes len: {}", vk.body.len());
            tracing::debug!(
                "vk checksum: {:02x?}",
                Checksum::generate(&vk.body).as_slice()
            );
            tracing::debug!("Stored footer checksum: {:02x?}", footer.checksum);
        }

        Ok(bundle)
    }

    pub fn with_vk_and_type(wasm: Vec<u8>, vk_bytes: Vec<u8>, footer: CircuitFooter) -> Self {
        let body_len = vk_bytes.len() - COSMWASM_FOOTER_LENGTH;
        let body = &vk_bytes[0..body_len]; // ← explicit slice

        let vk = SerializedPlonkishCircuitData::new(body, &footer.to_bytes()); // ← pass body only!

        CodeBundle { wasm, vk: Some(vk) }
    }

    // true - wasm; false - && circuit
    pub fn bundle_has_circuit(&self) -> bool {
        self.vk.is_some()
    }

    // Helper: Compute checksums without persisting
    pub fn compute_checksums(&self) -> [Checksum; 2] {
        match (self.wasm.len() > 0, &self.vk) {
            (true, None) => [Checksum::generate(&self.wasm), self.dummy_checksum()],
            (true, Some(vk)) => [Checksum::generate(&self.wasm), Checksum::generate(&vk.body)],
            (false, None) => [self.dummy_checksum(), self.dummy_checksum()],
            (false, Some(vk)) => [self.dummy_checksum(), Checksum::generate(&vk.body)],
        }
    }

    // Helper to produce a dummy checksum (same as used for missing VK)
    fn dummy_checksum(&self) -> Checksum {
        Checksum::generate(&[])
    }

    pub fn vk_body_checksum(&self) -> Option<Checksum> {
        self.vk.as_ref().map(|vk| Checksum::generate(&vk.body))
    }
}

use halo2_proofs::COSMWASM_FOOTER_LENGTH;

/// Serializes SerializedPlonkishCircuitData into a complete binary format for FFI transmission.
pub fn serialize_circuit_data(vk_data: &SerializedPlonkishCircuitData) -> Vec<u8> {
    let mut result = Vec::new();
    result.extend_from_slice(&vk_data.body);
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
    let total_len = bytes.len();
    tracing::debug!(total_len);
    if total_len < COSMWASM_FOOTER_LENGTH {
        return Err(ZkError::new_err(format!(
            "bad circuit size. got: {}",
            total_len
        )));
    };
    let footer_bytes = &bytes[total_len - COSMWASM_FOOTER_LENGTH..];
    let body_bytes = &bytes[..total_len - footer_bytes.len()];

    println!(
        "Total len: {}, COSMWASM_FOOTER_LENGTH: {}, footer_bytes.len(): {}, body_bytes.len(): {}",
        total_len,
        COSMWASM_FOOTER_LENGTH,
        footer_bytes.len(),
        body_bytes.len()
    );

    let footer = CircuitFooter::from_bytes(footer_bytes)
        .map_err(|e| ZkError::new_err(format!("Failed to parse CircuitFooter: {}", e)))?;

    let computed = Checksum::generate(body_bytes);

    println!("Parsed  : {:02x?}", footer.checksum);
    println!("Computed: {:02x?}", computed.as_slice());
    match &computed.as_slice() == &footer.checksum {
        true => Ok(footer),
        false => return Err(ZkError::IntegrityErr {}),
    }
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
        assert!(bundle.vk.is_none());
    }

    #[test]
    fn code_bundle_with_vk() {
        let wasm = vec![0u8; 100];
        // Define sizes for v2 format with CS
        let params_len: u32 = 90;
        let vk_len: u32 = 100;
        let cs_len: u32 = 50;

        let mut vk_blob: Vec<u8> = Vec::new();
        vk_blob.extend(vec![0xAA; params_len as usize]);
        vk_blob.extend(vec![0xCC; cs_len as usize]);
        vk_blob.extend(vec![0xBB; vk_len as usize]);

        let footer = CircuitFooter::new(
            CircuitType::Plonkish,
            2, // instance_count
            params_len as u32,
            cs_len as u32,
            vk_len as u32,
            Checksum::generate(&vk_blob)
                .as_slice()
                .try_into()
                .expect("msg"),
        );
        vk_blob.extend_from_slice(&footer.to_bytes());

        assert_eq!(
            vk_blob.len() as u32,
            (params_len + cs_len + vk_len + COSMWASM_FOOTER_LENGTH as u32)
        );

        let bundle = CodeBundle::with_vk(wasm.clone(), vk_blob.clone()).unwrap();
        let [wasm_ck, vk_ck] = bundle.compute_checksums();

        assert_eq!(wasm_ck, Checksum::generate(&wasm));
        assert_eq!(
            vk_ck,
            Checksum::generate(&vk_blob[..vk_blob.len() - COSMWASM_FOOTER_LENGTH])
        );

        assert_eq!(bundle.wasm, wasm);
        assert!(bundle.vk.is_some());

        let vk_data = bundle.vk.unwrap();
        assert_eq!(
            &vk_data.body,
            &vk_blob[..vk_blob.len() - COSMWASM_FOOTER_LENGTH]
        );

        // Metadata should contain circuit info
        assert!(!vk_data.footer.is_empty());
        assert_eq!(
            vk_data.body.len() as u32,
            (params_len + cs_len + vk_len as u32)
        ); // Total blob length with 32-byte footer
    }

    #[test]
    fn validate_empty_vk_bytes() {
        let result = check_circuit(&[]);
        println!("{:#?}", result);
        assert!(result.is_err());
        // New 32-byte footer format requires at least 32 bytes
        assert!(result.unwrap_err().to_string().contains("bad circuit size"));
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
