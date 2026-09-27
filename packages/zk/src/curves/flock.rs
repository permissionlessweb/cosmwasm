//! Flock host arm (`prover_id=3`, `curve_id=7`).
//!
//! A circuit blob is `[canonical PcsParams | registry bytes | footer]`.
//! `vk_len` is 0, or 32 when the registry bytes are followed by
//! `Registry::digest`. Those 32 bytes are the circuit id. They are not a
//! Halo2 verifying key and are never passed to `VerifyingKey::read`.
//!
//! **Verify is fail-closed** unless zk-wasmvm installs [`FLOCK_HOST_VERIFY`]
//! (`host::flock` / `flock_core::verify_ligerito`) (single-thread pool). The
//! 72-byte BLAKE3 digest blob is **not** a proof.
//!
//! Not `CircuitType::Stwo`. Not Axiom KZG. `param_len = 0` is only the
//! footer-only dispatch stub ([`FlockVerifyingKey::lean_default`]); it is not
//! a `PcsParams` value.

use std::sync::OnceLock;

use blake3::Hasher;
use crate::COSMWASM_FOOTER_LENGTH;
use sha2::{Digest, Sha256};

use crate::{CircuitFooter, CircuitType, Proof, ZkError, ZkResult};

use super::CurveType;

/// zk-wasmvm installs `flock-core` `verify_ligerito` here. Digest stubs are
/// rejected. Hook keeps `flock-core` (edition 2024 / rayon) off CosmWasm guest
/// wasm32 builds.
/// `(proof, instances, stored circuit)`. `None` is the identity-circuit path.
pub static FLOCK_HOST_VERIFY: OnceLock<
    fn(&[u8], &[u8], Option<&FlockVerifyingKey>) -> ZkResult<()>,
> = OnceLock::new();

/// Footer `prover_id` — [`CircuitType::Flock`].
pub const FLOCK_PROVER_ID: u8 = CircuitType::Flock as u8;
/// Footer `curve_id` — Blake3 / Flock (no pairing curve).
pub const FLOCK_CURVE_ID: u8 = 7;

const FLCK: &[u8; 4] = b"FLCK";
const VERSION: u8 = 1;
/// `FLCK|ids|blake3(instances)|blake3(domain||instances)`
pub const FLOCK_PROOF_LEN: usize = 4 + 4 + 32 + 32;
const DOMAIN: &[u8] = b"terp-flock/v1";

/// Flock circuit loaded from a CosmWasm footer.
///
/// `param_bytes` are canonical `PcsParams` (empty only for the dispatch stub).
/// `cs_bytes` are the encoded registry, cached by [`Self::registry_digest`].
/// There is no Halo2 verifying key.
#[derive(Debug, Clone)]
pub struct FlockVerifyingKey {
    pub footer: CircuitFooter,
    pub param_bytes: Vec<u8>,
    pub cs_bytes: Vec<u8>,
    /// `Some` iff `footer.vk_len == 32`. The circuit id, not a curve key.
    pub registry_digest: Option<[u8; 32]>,
}

/// Raw public inputs (typically 128-byte zk-jwt layout; last 32 = action).
#[derive(Debug, Clone)]
pub struct FlockInstance {
    pub bytes: Vec<u8>,
}

impl FlockInstance {
    pub fn public_input_count(&self) -> usize {
        self.bytes.len().div_ceil(32).max(1)
    }
}

/// Footer for a Flock blob.
///
/// `k` is the Halo2 row-budget byte. Flock leaves it unused (`0`); `m` lives
/// in the param bytes. `registry_digest` is `None` (`vk_len = 0`) or the
/// 32-byte `Registry::digest` (`vk_len = 32`). `param_checksum` is SHA-256 of
/// `param_bytes`.
pub fn flock_circuit_footer(
    k: u8,
    i: u8,
    param_bytes: &[u8],
    cs_bytes: &[u8],
    registry_digest: Option<[u8; 32]>,
) -> CircuitFooter {
    let mut vk_body = Vec::with_capacity(cs_bytes.len() + registry_digest.map_or(0, |_| 32));
    vk_body.extend_from_slice(cs_bytes);
    if let Some(digest) = &registry_digest {
        vk_body.extend_from_slice(digest);
    }
    let param_checksum: [u8; 32] = Sha256::digest(param_bytes).into();
    let vk_checksum: [u8; 32] = Sha256::digest(&vk_body).into();
    CircuitFooter::new(
        CircuitType::Flock,
        CurveType::FlockBlake3,
        k,
        i,
        param_bytes.len() as u32,
        cs_bytes.len() as u32,
        registry_digest.map_or(0, |_| 32),
        param_checksum,
        vk_checksum,
    )
}

/// `[param_bytes | cs_bytes | optional digest | footer]`.
pub fn flock_circuit_blob(
    k: u8,
    i: u8,
    param_bytes: &[u8],
    cs_bytes: &[u8],
    registry_digest: Option<[u8; 32]>,
) -> Vec<u8> {
    let footer = flock_circuit_footer(k, i, param_bytes, cs_bytes, registry_digest);
    let mut out =
        Vec::with_capacity(param_bytes.len() + cs_bytes.len() + COSMWASM_FOOTER_LENGTH + 32);
    out.extend_from_slice(param_bytes);
    out.extend_from_slice(cs_bytes);
    if let Some(digest) = &registry_digest {
        out.extend_from_slice(digest);
    }
    out.extend_from_slice(&footer.to_bytes());
    out
}

impl FlockVerifyingKey {
    pub fn default_footer() -> CircuitFooter {
        flock_circuit_footer(0, 4, &[], &[], None)
    }

    /// Footer-only dispatch stub. Not a `PcsParams` blob.
    pub fn lean_default() -> Self {
        Self {
            footer: Self::default_footer(),
            param_bytes: Vec::new(),
            cs_bytes: Vec::new(),
            registry_digest: None,
        }
    }

    pub fn to_blob(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            self.param_bytes.len()
                + self.cs_bytes.len()
                + self.registry_digest.map_or(0, |_| 32)
                + COSMWASM_FOOTER_LENGTH,
        );
        out.extend_from_slice(&self.param_bytes);
        out.extend_from_slice(&self.cs_bytes);
        if let Some(digest) = &self.registry_digest {
            out.extend_from_slice(digest);
        }
        out.extend_from_slice(&self.footer.to_bytes());
        out
    }

    pub fn try_from_bytes(bytes: &[u8]) -> ZkResult<Self> {
        if bytes.len() < COSMWASM_FOOTER_LENGTH {
            return Err(ZkError::new_err("flock vk: short"));
        }
        let footer = CircuitFooter::from_bytes(&bytes[bytes.len() - COSMWASM_FOOTER_LENGTH..])?;
        let body_end = bytes.len() - COSMWASM_FOOTER_LENGTH;
        let param_len = footer.param_len as usize;
        if param_len > body_end {
            return Err(ZkError::new_err(format!(
                "flock param_len {param_len} exceeds body {body_end}"
            )));
        }
        Self::from_split_bytes(&bytes[..param_len], &bytes[param_len..body_end], footer)
    }

    /// Split load. `vk_body` is the registry encoding, plus 32 digest bytes
    /// when `footer.vk_len == 32`. It is not parsed as a Halo2 verifying key.
    pub fn from_split_bytes(
        param_bytes: &[u8],
        vk_body: &[u8],
        footer: CircuitFooter,
    ) -> ZkResult<Self> {
        if footer.curve_id != FLOCK_CURVE_ID {
            return Err(ZkError::UnsupportedCurve(footer.appstate_key()));
        }
        if footer.prover_id != FLOCK_PROVER_ID {
            return Err(ZkError::new_err("flock vk: prover_id must be 3"));
        }
        if footer.vk_len != 0 && footer.vk_len != 32 {
            return Err(ZkError::new_err(
                "flock vk_len must be 0 or 32 (Registry::digest); it is not a Halo2 verifying key",
            ));
        }
        if param_bytes.len() as u32 != footer.param_len {
            return Err(ZkError::new_err(format!(
                "flock param bytes length {} != footer.param_len {}",
                param_bytes.len(),
                footer.param_len
            )));
        }
        let expected_body = (footer.cs_len as usize).saturating_add(footer.vk_len as usize);
        if vk_body.len() != expected_body {
            return Err(ZkError::new_err(format!(
                "flock cs+digest length {} != cs_len+vk_len {}",
                vk_body.len(),
                expected_body
            )));
        }
        let param_checksum: [u8; 32] = Sha256::digest(param_bytes).into();
        if param_checksum != footer.param_checksum {
            return Err(ZkError::IntegrityErr {});
        }
        let vk_checksum: [u8; 32] = Sha256::digest(vk_body).into();
        if vk_checksum != footer.vk_checksum {
            return Err(ZkError::IntegrityErr {});
        }
        let cs_len = footer.cs_len as usize;
        let registry_digest = if footer.vk_len == 32 {
            let mut digest = [0u8; 32];
            digest.copy_from_slice(&vk_body[cs_len..]);
            Some(digest)
        } else {
            None
        };
        Ok(Self {
            footer,
            param_bytes: param_bytes.to_vec(),
            cs_bytes: vk_body[..cs_len].to_vec(),
            registry_digest,
        })
    }

    pub fn verify(&self, proof: &Proof, instances: &FlockInstance) -> ZkResult<()> {
        if proof.0.len() > 2 * 1024 * 1024 {
            return Err(ZkError::new_err("flock: proof too large"));
        }
        if let Some(host) = FLOCK_HOST_VERIFY.get() {
            return host(&proof.0, &instances.bytes, Some(self));
        }
        Err(ZkError::new_err(
            "flock: host verifier required (digest stub is not a proof)",
        ))
    }
}

impl TryFrom<&[u8]> for FlockVerifyingKey {
    type Error = ZkError;
    fn try_from(bytes: &[u8]) -> ZkResult<Self> {
        Self::try_from_bytes(bytes)
    }
}

/// BLAKE3 of the public action / instance blob (VM-side hash).
pub fn flock_action_digest(instances: &[u8]) -> [u8; 32] {
    *Hasher::new().update(instances).finalize().as_bytes()
}

pub fn flock_domain_digest(instances: &[u8]) -> [u8; 32] {
    *Hasher::new()
        .update(DOMAIN)
        .update(instances)
        .finalize()
        .as_bytes()
}

/// Legacy digest blob (not a SNARK). Kept so tests can assert rejection.
pub fn prove_flock(instances: &[u8]) -> Vec<u8> {
    let mut o = vec![0u8; FLOCK_PROOF_LEN];
    o[0..4].copy_from_slice(FLCK);
    o[4] = FLOCK_PROVER_ID;
    o[5] = FLOCK_CURVE_ID;
    o[6] = VERSION;
    o[7] = 0;
    o[8..40].copy_from_slice(&flock_action_digest(instances));
    o[40..72].copy_from_slice(&flock_domain_digest(instances));
    o
}

pub fn verify_flock_proof(proof: &[u8], instances: &[u8]) -> ZkResult<()> {
    if proof.len() > 2 * 1024 * 1024 {
        return Err(ZkError::new_err("flock: proof too large"));
    }
    if let Some(host) = FLOCK_HOST_VERIFY.get() {
        return host(proof, instances, None);
    }
    Err(ZkError::new_err(
        "flock: host verifier required (digest stub is not a proof)",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AnyInstance, AnyVerifyingKey, CircuitFooter, CircuitType};
    use sha2::{Digest, Sha256};

    #[test]
    fn flock_digest_stub_rejected_without_host() {
        let action = [7u8; 128];
        let proof = prove_flock(&action);
        assert!(verify_flock_proof(&proof, &action).is_err());
    }

    #[test]
    fn flock_vk_dispatches_curve_7() {
        let vk = FlockVerifyingKey::lean_default();
        let blob = vk.to_blob();
        let any = AnyVerifyingKey::try_from(blob.as_slice()).expect("dispatch");
        assert_eq!(any.curve_id(), FLOCK_CURVE_ID);
        assert_eq!(any.prover_id(), FLOCK_PROVER_ID);
        assert_eq!(CircuitType::try_from(any).unwrap(), CircuitType::Flock);
        let inst = AnyInstance::try_from_bytes(FLOCK_CURVE_ID as u32, &[1u8; 32]).unwrap();
        matches!(inst, AnyInstance::Flock(_));
    }

    #[test]
    fn flock_footer_round_trips_param_checksum_and_halo2_param_key_differs() {
        let k = 0u8;
        let params = b"PCSP\x01canonical-pcs-params";
        let cs = b"registry-bytes";
        let digest = [0xab; 32];
        let blob = flock_circuit_blob(k, 1, params, cs, Some(digest));
        let loaded = FlockVerifyingKey::try_from_bytes(&blob).expect("load");
        let again = CircuitFooter::from_bytes(&loaded.footer.to_bytes()).expect("footer");
        assert_eq!(loaded.footer, again);
        assert_eq!(loaded.to_blob(), blob);
        let param_checksum: [u8; 32] = Sha256::digest(params).into();
        assert_eq!(loaded.footer.param_checksum, param_checksum);
        assert_eq!(loaded.param_bytes, params);
        assert_eq!(loaded.cs_bytes, cs);
        assert_eq!(loaded.footer.vk_len, 32);
        assert_eq!(loaded.registry_digest, Some(digest));

        let without = flock_circuit_blob(k, 1, params, cs, None);
        let bare = FlockVerifyingKey::try_from_bytes(&without).expect("vk_len 0");
        assert_eq!(bare.footer.vk_len, 0);
        assert_eq!(bare.registry_digest, None);
        assert_eq!(bare.footer.param_checksum, param_checksum);

        let halo = CircuitFooter::new(
            CircuitType::Plonkish,
            CurveType::Pasta,
            loaded.footer.k,
            loaded.footer.i,
            loaded.footer.param_len,
            0,
            0,
            loaded.footer.param_checksum,
            [0u8; 32],
        );
        assert_eq!(halo.k, loaded.footer.k);
        assert_eq!(halo.param_checksum, loaded.footer.param_checksum);
        assert_ne!(
            halo.to_param_key(),
            loaded.footer.to_param_key(),
            "halo2 and flock param keys differ"
        );
        assert_ne!(halo.param_filename(), loaded.footer.param_filename());
    }

    #[test]
    fn flock_rejects_halo2_sized_vk_len() {
        let params = b"params";
        let vk = vec![0u8; 64];
        let footer = CircuitFooter::new(
            CircuitType::Flock,
            CurveType::FlockBlake3,
            0,
            1,
            params.len() as u32,
            0,
            vk.len() as u32,
            Sha256::digest(params).into(),
            Sha256::digest(&vk).into(),
        );
        let mut blob = params.to_vec();
        blob.extend_from_slice(&vk);
        blob.extend_from_slice(&footer.to_bytes());
        let err = FlockVerifyingKey::try_from_bytes(&blob).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("not a Halo2 verifying key"),
            "unexpected err: {msg}"
        );
    }
}
