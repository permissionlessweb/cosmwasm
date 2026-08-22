//! Stwo / M31 host arm (`prover_id=2`, `curve_id=5`).
//!
//! Path A: `proof_instance_verify(zkid, proof, instances)` loads a footer-only
//! VK (`curve_id=5`) and verifies DummyStwo (DSTW) or STWO-magic proofs of
//! `c = 3a+5b+7` over M31. Same statement Lean LNPR already uses.
//! Not `CircuitType::Stark`.

use std::sync::OnceLock;

use halo2_proofs::COSMWASM_FOOTER_LENGTH;
use sha2::{Digest, Sha256};

use crate::{CircuitFooter, CircuitType, Proof, ZkError, ZkResult};

use super::CurveType;

/// zk-wasmvm installs real S-two verify here. Dummy DSTW is rejected by that host.
pub static STWO_HOST_VERIFY: OnceLock<fn(&[u8], &[u8]) -> ZkResult<()>> = OnceLock::new();

/// Footer `prover_id` for this arm.
pub const STWO_PROVER_ID: u8 = CircuitType::Stwo as u8;
/// Footer / proof `curve_id` (M31 Circle).
pub const STWO_CURVE_ID: u8 = 5;

const M31_P: u32 = (1 << 31) - 1;
const DSTW: &[u8; 4] = b"DSTW";
const STWO: &[u8; 4] = b"STWO";
const DUMMY_LEN: usize = 18;

/// Empty-param Stwo VK: footer only (`param_len=0`, `cs_len=0`).
#[derive(Debug, Clone)]
pub struct StwoVerifyingKey {
    pub footer: CircuitFooter,
}

/// Raw public inputs (period|weight|subject or empty).
#[derive(Debug, Clone)]
pub struct StwoInstance {
    pub bytes: Vec<u8>,
}

impl StwoInstance {
    pub fn public_input_count(&self) -> usize {
        1
    }
}

impl StwoVerifyingKey {
    pub fn lean_default() -> Self {
        let empty = Sha256::digest([]);
        Self {
            footer: CircuitFooter::new(
                CircuitType::Stwo,
                CurveType::M31,
                0,
                1,
                0,
                0,
                0,
                empty.into(),
                empty.into(),
            ),
        }
    }

    pub fn to_blob(&self) -> Vec<u8> {
        self.footer.to_bytes().to_vec()
    }

    pub fn try_from_bytes(bytes: &[u8]) -> ZkResult<Self> {
        if bytes.len() < COSMWASM_FOOTER_LENGTH {
            return Err(ZkError::new_err("stwo vk: short"));
        }
        let footer = CircuitFooter::from_bytes(&bytes[bytes.len() - COSMWASM_FOOTER_LENGTH..])?;
        if footer.curve_id != STWO_CURVE_ID {
            return Err(ZkError::UnsupportedCurve(footer.appstate_key()));
        }
        if footer.prover_id != STWO_PROVER_ID {
            return Err(ZkError::new_err("stwo vk: prover_id must be 2"));
        }
        Ok(Self { footer })
    }

    pub fn from_split_bytes(
        _param: &[u8],
        _vk_body: &[u8],
        footer: CircuitFooter,
    ) -> ZkResult<Self> {
        if footer.curve_id != STWO_CURVE_ID || footer.prover_id != STWO_PROVER_ID {
            return Err(ZkError::UnsupportedCurve(footer.appstate_key()));
        }
        Ok(Self { footer })
    }

    pub fn verify(&self, proof: &Proof, instances: &StwoInstance) -> ZkResult<()> {
        verify_stwo_proof(&proof.0, &instances.bytes)
    }
}

impl TryFrom<&[u8]> for StwoVerifyingKey {
    type Error = ZkError;
    fn try_from(bytes: &[u8]) -> ZkResult<Self> {
        Self::try_from_bytes(bytes)
    }
}

fn dummy_m31_hash(a: u32, b: u32) -> u32 {
    ((3u64 * u64::from(a) + 5u64 * u64::from(b) + 7) % u64::from(M31_P)) as u32
}

fn le_u32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

fn be_u64(b: &[u8]) -> u64 {
    u64::from_be_bytes(b.try_into().unwrap())
}

fn be_i64(b: &[u8]) -> i64 {
    i64::from_be_bytes(b.try_into().unwrap())
}

fn seeds_bound(period: u64, subject: &[u8], weight: i64) -> (u32, u32) {
    let a = (period % u64::from(M31_P)) as u32;
    let mut mix: u32 = 0;
    let wb = weight.to_be_bytes();
    for (i, x) in wb.iter().enumerate() {
        mix ^= u32::from(*x) << (8 * (i % 4));
    }
    for (i, x) in subject.iter().enumerate() {
        mix ^= u32::from(*x) << (8 * (i % 4));
    }
    (a, mix % M31_P)
}

/// Host-side Stwo statement (DSTW or STWO 18-byte dummy AIR).
pub fn verify_stwo_proof(proof: &[u8], instances: &[u8]) -> ZkResult<()> {
    if proof.len() > 2 * 1024 * 1024 {
        return Err(ZkError::new_err("stwo: proof too large"));
    }
    if let Some(host) = STWO_HOST_VERIFY.get() {
        return host(proof, instances);
    }
    if proof.len() < DUMMY_LEN {
        return Err(ZkError::new_err("stwo: truncated"));
    }
    let mag = &proof[0..4];
    if mag != DSTW && mag != STWO {
        return Err(ZkError::VerifyFailed);
    }
    if proof[4] != STWO_PROVER_ID {
        return Err(ZkError::new_err("stwo: bad prover_id"));
    }
    if proof[5] != STWO_CURVE_ID {
        return Err(ZkError::new_err("stwo: bad curve_id"));
    }
    let a = le_u32(&proof[6..10]);
    let b = le_u32(&proof[10..14]);
    let c = le_u32(&proof[14..18]);
    if a >= M31_P || b >= M31_P || c >= M31_P {
        return Err(ZkError::VerifyFailed);
    }
    if dummy_m31_hash(a, b) != c {
        return Err(ZkError::VerifyFailed);
    }
    if instances.len() >= 16 {
        let period = be_u64(&instances[0..8]);
        let weight = be_i64(&instances[8..16]);
        let subj = &instances[16..];
        let (ea, eb) = seeds_bound(period, subj, weight);
        if a != ea || b != eb {
            return Err(ZkError::VerifyFailed);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AnyInstance, AnyVerifyingKey, CircuitType};

    fn dstw(a: u32, b: u32) -> Vec<u8> {
        let c = dummy_m31_hash(a, b);
        let mut o = vec![0u8; DUMMY_LEN];
        o[0..4].copy_from_slice(DSTW);
        o[4] = STWO_PROVER_ID;
        o[5] = STWO_CURVE_ID;
        o[6..10].copy_from_slice(&a.to_le_bytes());
        o[10..14].copy_from_slice(&b.to_le_bytes());
        o[14..18].copy_from_slice(&c.to_le_bytes());
        o
    }

    #[test]
    fn circuit_type_stwo_is_two() {
        assert_eq!(CircuitType::from_u8(2), Some(CircuitType::Stwo));
        assert_eq!(CircuitType::Stwo as u8, 2);
        assert!(CircuitType::from_u8(99).is_none());
    }

    #[test]
    fn footer_curve_5_loads_stwo_vk() {
        let vk = StwoVerifyingKey::lean_default();
        let blob = vk.to_blob();
        let loaded = AnyVerifyingKey::try_from(blob.as_slice()).expect("load");
        assert_eq!(loaded.prover_id(), 2);
        assert_eq!(loaded.curve_id(), 5);
        assert!(matches!(loaded, AnyVerifyingKey::Stwo(_)));
    }

    #[test]
    fn proof_instance_verify_dstw_ok_and_bitflip() {
        let vk = AnyVerifyingKey::Stwo(StwoVerifyingKey::lean_default());
        let p = Proof::new(dstw(3, 5));
        let i = AnyInstance::Stwo(StwoInstance { bytes: vec![] });
        vk.verify(&p, std::slice::from_ref(&i)).expect("ok");
        let mut bad = dstw(3, 5);
        bad[14] ^= 1;
        let e = vk.verify(&Proof::new(bad), std::slice::from_ref(&i));
        assert!(e.unwrap_err().is_verify_failed());
    }

    #[test]
    fn wrong_prover_id_in_proof_fails() {
        let mut p = dstw(1, 1);
        p[4] = 0;
        let vk = StwoVerifyingKey::lean_default();
        assert!(vk
            .verify(&Proof::new(p), &StwoInstance { bytes: vec![] })
            .is_err());
    }
}
