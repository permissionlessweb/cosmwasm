use cosmwasm_std::Checksum;

// keys.rs
pub const VK_PARAM_KEY_PREFIX: &[u8] = b"\x12";
pub const VK_KEY_PREFIX: &[u8] = b"\x13";
pub const CIRCUIT_KEY_PREFIX: &[u8] = b"\x16";

pub fn get_vk_param_key(param_id: u64) -> Vec<u8> {
    let mut k = VK_PARAM_KEY_PREFIX.to_vec();
    k.extend_from_slice(&param_id.to_be_bytes());
    k
}

pub fn get_vk_key(vk_id: u64) -> Vec<u8> {
    let mut k = VK_KEY_PREFIX.to_vec();
    k.extend_from_slice(&vk_id.to_be_bytes());
    k
}

pub fn get_circuit_key(zk_id: u64) -> Vec<u8> {
    let mut k = CIRCUIT_KEY_PREFIX.to_vec();
    k.extend_from_slice(&zk_id.to_be_bytes());
    k
}

pub use zk_cosmwasm::*;

use halo2_proofs::COSMWASM_FOOTER_LENGTH;

/// Serializes SerializedCircuitData into a complete binary format for FFI transmission.
pub fn serialize_circuit_data(vk_data: &SerializedCircuitData) -> Vec<u8> {
    let mut result = Vec::new();
    result.extend_from_slice(&vk_data.body);
    result.extend_from_slice(&vk_data.footer);
    result
}

/// Deserializes circuit data from the FFI binary format back into SerializedCircuitData
pub fn deserialize_circuit_data(data: &[u8]) -> ZkResult<SerializedCircuitData> {
    let length = data.len();
    if length < COSMWASM_FOOTER_LENGTH {
        return Err(ZkError::new_err("Circuit data too short"));
    }
    let circuit_len = length - COSMWASM_FOOTER_LENGTH;
    Ok(SerializedCircuitData::new(
        &data[0..circuit_len],
        &data[circuit_len..],
    ))
}

pub fn check_circuit(bytes: &[u8]) -> ZkResult<CircuitFooter> {
    let total_len = bytes.len();
    if total_len < COSMWASM_FOOTER_LENGTH {
        return Err(ZkError::new_err(format!(
            "vm::zk::bad circuit size::length::{}",
            total_len
        )));
    };
    let footer_bytes = &bytes[total_len - COSMWASM_FOOTER_LENGTH..];
    let body_bytes = &bytes[..total_len - footer_bytes.len()];
    let footer = CircuitFooter::from_bytes(footer_bytes)
        .map_err(|e| ZkError::new_err(format!("Failed to parse CircuitFooter: {}", e)))?;

    let computed = Checksum::generate(body_bytes);

    match computed.as_slice() == footer.vk_checksum {
        true => Ok(footer),
        false => Err(ZkError::IntegrityErr {}),
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
        assert_eq!(CircuitType::try_from(0).unwrap(), CircuitType::Plonkish);
        assert_eq!(CircuitType::try_from(255).unwrap(), CircuitType::Plonkish);
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
