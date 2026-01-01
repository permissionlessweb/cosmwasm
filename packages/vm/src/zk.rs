use std::io;

use cosmwasm_std::Checksum;

pub use zk_cosmwasm::cosmwasm_circuit::{
    CircuitFooter, CircuitType, CosmwasmCircuit, CosmwasmCircuitFor, DynamicCircuit,
    DynamicCircuitConfig, PinnedCircuit, PlonkishCircuitMetadata, Proof, ProvingKey,
    SerializedPlonkishCircuitData, VerifyingKey,
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
        Ok(Self::with_vk_and_type(wasm, vk_bytes, &vk, hash.into()))
    }

    pub fn with_vk_and_type(
        wasm: Vec<u8>,
        vk_bytes: Vec<u8>,
        metadata: &crate::PlonkishCircuitMetadata,
        hash: Vec<u8>,
    ) -> Self {
        let vk =
            SerializedPlonkishCircuitData::new(&vk_bytes, hash.as_slice(), &metadata.to_bytes());
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
    const FOOTER_SIZE: usize = 32; // New 32-byte footer format

    if bytes.len() < FOOTER_SIZE {
        return Err(ZkError::new_err(format!(
            "VK file too short: need at least {} bytes for footer",
            FOOTER_SIZE
        )));
    }

    // Extract and parse the 32-byte footer
    let footer_bytes = &bytes[bytes.len() - FOOTER_SIZE..];
    let footer = CircuitFooter::from_bytes(footer_bytes)?;

    let p_len = footer.params_len as usize;
    let v_len = footer.vk_len as usize;

    // Validate file structure
    let expected_total = p_len + v_len + FOOTER_SIZE;
    if bytes.len() != expected_total {
        return Err(ZkError::from_io(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "VK file size mismatch: got {} bytes, expected {} (params:{} + vk:{} + footer:{})",
                bytes.len(),
                expected_total,
                p_len,
                v_len,
                FOOTER_SIZE
            ),
        )));
    }

    // Validate VK exists and has minimum content
    if v_len == 0 {
        return Err(ZkError::from_io(io::Error::new(
            io::ErrorKind::InvalidData,
            "VK length cannot be 0",
        )));
    }

    let vk_bytes = &bytes[p_len..p_len + v_len];

    // VK bytes should exist
    if vk_bytes.is_empty() {
        return Err(ZkError::from_io(io::Error::new(
            io::ErrorKind::InvalidData,
            "No VK bytes recognized",
        )));
    }

    let zk = cosmwasm_circuit::PlonkishCircuitMetadata::new(
        footer.circuit_type,
        footer.instance_count,
        p_len,
        v_len,
    );

    Ok((zk, hash_circuit(zk, bytes)))
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
