//! Path A Flock host: `flock_core::verifier::verify_ligerito` (1-thread pool).
//!
//! Circuit blobs load through `CircuitFooter`: param bytes are canonical
//! `PcsParams` (cached by `param_checksum`), constraint-system bytes are the
//! encoded registry (cached by `Registry::digest`). `vk_len` is 0 or that
//! 32-byte digest. Neither object is a Halo2 verifying key.

use flock_core::merkle::HashKind;
use flock_core::pcs::ligerito::LigeritoProfile;
use flock_core::{
    challenger::FsChallenger,
    pcs::{Commitment, PcsParams},
    proof::R1csProofLigerito,
    r1cs::{BlockR1cs, SparseBinaryMatrix, WitnessLayout},
    schedule::{IoDirection, IoWord, Registry, TableClass, TableType, MAX_K_LOG},
    verifier::verify_ligerito,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use zk_cosmwasm::curves::FlockVerifyingKey;
use zk_cosmwasm::{ZkError, ZkResult};

const PCS_MAGIC: &[u8; 4] = b"PCSP";
const PCS_VERSION: u8 = 1;
const REG_MAGIC: &[u8; 4] = b"FLRG";
const REG_VERSION: u8 = 1;

const FLCK: &[u8; 4] = b"FLCK";
const VERSION_LIGERITO: u8 = 2;
const HEADER: usize = 8;
const STUB_LEN: usize = 72;
const DOMAIN_PREFIX: &[u8] = b"terp-flock/ligerito/v1";

const M: usize = 22;
const K_LOG: usize = 6;
const K_SKIP: usize = 6;

#[derive(Serialize, Deserialize)]
struct LigeritoBody {
    commitment: Commitment,
    proof: R1csProofLigerito,
}

pub fn install() {
    let _ = zk_cosmwasm::FLOCK_HOST_VERIFY.set(host_verify);
}

pub fn host_verify(
    proof: &[u8],
    instances: &[u8],
    vk: Option<&FlockVerifyingKey>,
) -> ZkResult<()> {
    if proof.len() == STUB_LEN && proof.starts_with(FLCK) && proof.get(6) == Some(&1) {
        return Err(ZkError::new_err("flock: digest stub rejected"));
    }
    if proof.len() < HEADER + 8 {
        return Err(ZkError::new_err("flock: truncated"));
    }
    if &proof[0..4] != FLCK {
        return Err(ZkError::new_err("flock: bad magic"));
    }
    if proof[4] != 3 {
        return Err(ZkError::new_err("flock: prover_id must be 3"));
    }
    if proof[5] != 7 {
        return Err(ZkError::new_err("flock: curve_id must be 7"));
    }
    if proof[6] != VERSION_LIGERITO {
        return Err(ZkError::new_err("flock: want ligerito version 2"));
    }
    let body: LigeritoBody =
        bincode::deserialize(&proof[HEADER..]).map_err(|_| ZkError::new_err("flock: bincode"))?;
    let r1cs = canonical_identity_r1cs();
    let pcs_params = canonical_pcs_params();
    if let Some(vk) = vk {
        if !vk.cs_bytes.is_empty() {
            return Err(ZkError::new_err(
                "flock: stored registry is not the identity circuit this host verifies",
            ));
        }
        if !vk.param_bytes.is_empty() {
            let stored = decode_pcs_params(&vk.param_bytes)?;
            if stored != canonical_pcs_params() {
                return Err(ZkError::new_err(
                    "flock: stored PcsParams are not this host's circuit",
                ));
            }
            if body.commitment.params != stored {
                return Err(ZkError::new_err("flock: proof pcs params != stored circuit"));
            }
        }
    }
    if body.commitment.params != pcs_params {
        return Err(ZkError::new_err("flock: pcs params mismatch"));
    }
    let lc = r1cs.sparse_lincheck_circuit();
    let mut ch = FsChallenger::new(&fs_domain(instances));
    verify_ligerito(
        &r1cs,
        &body.commitment,
        &body.proof,
        &lc,
        &pcs_params,
        &mut ch,
    )
    .map_err(|e| ZkError::new_err(format!("flock: {e:?}")))?;
    Ok(())
}

fn fs_domain(instances: &[u8]) -> Vec<u8> {
    let mut d = DOMAIN_PREFIX.to_vec();
    d.extend_from_slice(blake3::hash(instances).as_bytes());
    d
}

fn identity_matrix(k: usize) -> SparseBinaryMatrix {
    SparseBinaryMatrix::new(k, k, (0..k).map(|i| vec![i]).collect())
}

fn canonical_identity_r1cs() -> BlockR1cs {
    let k = 1usize << K_LOG;
    BlockR1cs {
        m: M,
        k_log: K_LOG,
        k_skip: K_SKIP,
        useful_bits: k,
        a_0: identity_matrix(k),
        b_0: identity_matrix(k),
        c_0: identity_matrix(k),
        layout: WitnessLayout::RowMajor,
        const_pin: None,
        digest_cache: OnceLock::new(),
        csc_cache: OnceLock::new(),
    }
}

fn canonical_pcs_params() -> PcsParams {
    PcsParams {
        m: M,
        log_inv_rate: 1,
        log_batch_size: 6,
        profile: Default::default(),
        num_lanes: None,
        merkle_hash: Default::default(),
    }
}

/// Same six reusable fields as `p`. A second circuit copies these, not a key.
fn pcs_with_same_fields(p: &PcsParams) -> PcsParams {
    PcsParams {
        m: p.m,
        log_inv_rate: p.log_inv_rate,
        log_batch_size: p.log_batch_size,
        profile: p.profile,
        num_lanes: p.num_lanes,
        merkle_hash: p.merkle_hash,
    }
}

struct ByteCursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> ByteCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    fn take(&mut self, n: usize) -> ZkResult<&'a [u8]> {
        let end = self
            .at
            .checked_add(n)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| ZkError::new_err("flock: truncated canonical bytes"))?;
        let out = &self.bytes[self.at..end];
        self.at = end;
        Ok(out)
    }

    fn u8(&mut self) -> ZkResult<u8> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> ZkResult<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into()?))
    }

    fn u64(&mut self) -> ZkResult<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into()?))
    }

    fn finish(self) -> ZkResult<()> {
        if self.at != self.bytes.len() {
            return Err(ZkError::new_err("flock: trailing canonical bytes"));
        }
        Ok(())
    }
}

fn push_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn push_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn u32_usize(v: usize, what: &str) -> ZkResult<u32> {
    u32::try_from(v).map_err(|_| ZkError::new_err(format!("flock: {what} exceeds u32")))
}

fn profile_byte(profile: LigeritoProfile) -> u8 {
    match profile {
        LigeritoProfile::Fast => 0,
        LigeritoProfile::Fast100 => 1,
        LigeritoProfile::Slim => 2,
        LigeritoProfile::Slim100 => 3,
        LigeritoProfile::Secure => 4,
    }
}

fn profile_from_byte(b: u8) -> ZkResult<LigeritoProfile> {
    match b {
        0 => Ok(LigeritoProfile::Fast),
        1 => Ok(LigeritoProfile::Fast100),
        2 => Ok(LigeritoProfile::Slim),
        3 => Ok(LigeritoProfile::Slim100),
        4 => Ok(LigeritoProfile::Secure),
        _ => Err(ZkError::new_err("flock: bad ligerito profile")),
    }
}

fn hash_byte(hash: HashKind) -> u8 {
    match hash {
        HashKind::Sha256 => 0,
        HashKind::Blake3 => 1,
    }
}

fn hash_from_byte(b: u8) -> ZkResult<HashKind> {
    match b {
        0 => Ok(HashKind::Sha256),
        1 => Ok(HashKind::Blake3),
        _ => Err(ZkError::new_err("flock: bad merkle hash")),
    }
}

/// Fixed little-endian encoding of the six reusable `PcsParams` fields.
/// Not Halo2 `Params` (those start with a `k` header, not `PCSP`).
pub fn encode_pcs_params(p: &PcsParams) -> ZkResult<Vec<u8>> {
    let (lanes_tag, lanes) = match p.num_lanes {
        None => (0u8, 0u32),
        Some(n) => (1u8, u32_usize(n, "num_lanes")?),
    };
    let mut out = Vec::with_capacity(24);
    out.extend_from_slice(PCS_MAGIC);
    out.push(PCS_VERSION);
    out.push(profile_byte(p.profile));
    out.push(hash_byte(p.merkle_hash));
    out.push(lanes_tag);
    push_u32(&mut out, u32_usize(p.m, "m")?);
    push_u32(&mut out, u32_usize(p.log_inv_rate, "log_inv_rate")?);
    push_u32(&mut out, u32_usize(p.log_batch_size, "log_batch_size")?);
    push_u32(&mut out, lanes);
    Ok(out)
}

pub fn decode_pcs_params(bytes: &[u8]) -> ZkResult<PcsParams> {
    let mut c = ByteCursor::new(bytes);
    if c.take(4)? != PCS_MAGIC.as_slice() {
        return Err(ZkError::new_err(
            "flock: param bytes are not canonical PcsParams",
        ));
    }
    if c.u8()? != PCS_VERSION {
        return Err(ZkError::new_err("flock: bad PcsParams version"));
    }
    let profile = profile_from_byte(c.u8()?)?;
    let merkle_hash = hash_from_byte(c.u8()?)?;
    let lanes_tag = c.u8()?;
    let m = c.u32()? as usize;
    let log_inv_rate = c.u32()? as usize;
    let log_batch_size = c.u32()? as usize;
    let lanes = c.u32()? as usize;
    c.finish()?;
    if profile.log_inv_rate() != log_inv_rate {
        return Err(ZkError::new_err(
            "flock: PcsParams profile does not match log_inv_rate",
        ));
    }
    let num_lanes = match lanes_tag {
        0 => {
            if lanes != 0 {
                return Err(ZkError::new_err("flock: num_lanes tag/value mismatch"));
            }
            None
        }
        1 => {
            if log_batch_size >= usize::BITS as usize {
                return Err(ZkError::new_err("flock: log_batch_size too large"));
            }
            let max = 1usize << log_batch_size;
            if lanes == 0 || lanes > max {
                return Err(ZkError::new_err("flock: num_lanes out of range"));
            }
            Some(lanes)
        }
        _ => return Err(ZkError::new_err("flock: bad num_lanes tag")),
    };
    Ok(PcsParams {
        m,
        log_inv_rate,
        log_batch_size,
        profile,
        num_lanes,
        merkle_hash,
    })
}

fn encode_matrix(out: &mut Vec<u8>, matrix: &SparseBinaryMatrix) -> ZkResult<()> {
    push_u32(out, u32_usize(matrix.num_rows, "matrix rows")?);
    push_u32(out, u32_usize(matrix.num_cols, "matrix cols")?);
    if matrix.rows.len() != matrix.num_rows {
        return Err(ZkError::new_err("flock: matrix row count mismatch"));
    }
    for row in matrix.rows.iter() {
        push_u32(out, u32_usize(row.len(), "matrix nnz")?);
        for &col in row {
            push_u32(out, u32_usize(col, "matrix col")?);
        }
    }
    Ok(())
}

fn decode_matrix(c: &mut ByteCursor<'_>) -> ZkResult<SparseBinaryMatrix> {
    let num_rows = c.u32()? as usize;
    let num_cols = c.u32()? as usize;
    let mut rows = Vec::with_capacity(num_rows);
    for _ in 0..num_rows {
        let nnz = c.u32()? as usize;
        let mut row = Vec::with_capacity(nnz);
        for _ in 0..nnz {
            let col = c.u32()? as usize;
            if col >= num_cols {
                return Err(ZkError::new_err("flock: matrix column out of range"));
            }
            row.push(col);
        }
        rows.push(row);
    }
    Ok(SparseBinaryMatrix::new(num_rows, num_cols, rows))
}

/// Boolean registry bytes. Element tables are rejected: this cache is the
/// constraint system, not a witness.
pub fn encode_registry(registry: &Registry) -> ZkResult<Vec<u8>> {
    let mut out = Vec::new();
    out.extend_from_slice(REG_MAGIC);
    out.push(REG_VERSION);
    push_u32(&mut out, u32_usize(registry.nu(), "nu")?);
    push_u32(&mut out, u32_usize(registry.num_types(), "type count")?);
    for ty in registry.types() {
        if ty.is_element() {
            return Err(ZkError::new_err(
                "flock: element registries are not in this cache codec",
            ));
        }
        push_u32(&mut out, u32_usize(ty.k_log, "k_log")?);
        push_u64(
            &mut out,
            u64::try_from(ty.useful_bits)
                .map_err(|_| ZkError::new_err("flock: useful_bits exceeds u64"))?,
        );
        match ty.const_pin {
            Some(col) => {
                out.push(1);
                push_u64(
                    &mut out,
                    u64::try_from(col).map_err(|_| ZkError::new_err("flock: const_pin exceeds u64"))?,
                );
            }
            None => {
                out.push(0);
                push_u64(&mut out, 0);
            }
        }
        encode_matrix(&mut out, &ty.a_0)?;
        encode_matrix(&mut out, &ty.b_0)?;
        encode_matrix(&mut out, &ty.c_0)?;
        push_u32(&mut out, u32_usize(ty.io_schema.len(), "io schema")?);
        for word in &ty.io_schema {
            push_u32(&mut out, u32_usize(word.word_col, "io word")?);
            let dir = match word.dir {
                IoDirection::In => 0u8,
                IoDirection::Out => 1u8,
            };
            out.push(dir);
        }
    }
    Ok(out)
}

pub fn decode_registry(bytes: &[u8]) -> ZkResult<Registry> {
    let mut c = ByteCursor::new(bytes);
    if c.take(4)? != REG_MAGIC.as_slice() {
        return Err(ZkError::new_err("flock: cs bytes are not a registry"));
    }
    if c.u8()? != REG_VERSION {
        return Err(ZkError::new_err("flock: bad registry version"));
    }
    let nu = c.u32()? as usize;
    let n_types = c.u32()? as usize;
    if n_types == 0 {
        return Err(ZkError::new_err("flock: empty registry"));
    }
    let mut types = Vec::with_capacity(n_types);
    for _ in 0..n_types {
        let k_log = c.u32()? as usize;
        let useful_bits = usize::try_from(c.u64()?)
            .map_err(|_| ZkError::new_err("flock: useful_bits does not fit usize"))?;
        if !(7..=MAX_K_LOG).contains(&k_log) || k_log >= usize::BITS as usize {
            return Err(ZkError::new_err("flock: k_log out of range"));
        }
        if useful_bits > (1usize << k_log) {
            return Err(ZkError::new_err("flock: useful_bits exceed the block"));
        }
        let present = c.u8()?;
        let pin_value = c.u64()?;
        let const_pin = match present {
            0 => {
                if pin_value != 0 {
                    return Err(ZkError::new_err("flock: const_pin tag/value mismatch"));
                }
                None
            }
            1 => Some(
                usize::try_from(pin_value)
                    .map_err(|_| ZkError::new_err("flock: const_pin does not fit usize"))?,
            ),
            _ => return Err(ZkError::new_err("flock: bad const_pin tag")),
        };
        let a_0 = decode_matrix(&mut c)?;
        let b_0 = decode_matrix(&mut c)?;
        let c_0 = decode_matrix(&mut c)?;
        let n_io = c.u32()? as usize;
        let used_cols = useful_bits.div_ceil(128);
        let mut seen = std::collections::HashSet::with_capacity(n_io);
        let mut io_schema = Vec::with_capacity(n_io);
        for _ in 0..n_io {
            let word_col = c.u32()? as usize;
            if word_col >= used_cols || !seen.insert(word_col) {
                return Err(ZkError::new_err("flock: io word out of range"));
            }
            let dir = match c.u8()? {
                0 => IoDirection::In,
                1 => IoDirection::Out,
                _ => return Err(ZkError::new_err("flock: bad io direction")),
            };
            io_schema.push(IoWord { word_col, dir });
        }
        types.push(
            TableType {
                k_log,
                useful_bits,
                a_0,
                b_0,
                c_0,
                const_pin,
                class: TableClass::Boolean,
                io_schema: Vec::new(),
            }
            .with_io_schema(io_schema),
        );
    }
    c.finish()?;
    Ok(Registry::new(types, nu))
}

struct CsCache {
    params: HashMap<[u8; 32], Vec<u8>>,
    registries: HashMap<[u8; 32], Vec<u8>>,
}

fn cs_cache() -> &'static Mutex<CsCache> {
    static CACHE: OnceLock<Mutex<CsCache>> = OnceLock::new();
    CACHE.get_or_init(|| {
        Mutex::new(CsCache {
            params: HashMap::new(),
            registries: HashMap::new(),
        })
    })
}

fn remember(map: &mut HashMap<[u8; 32], Vec<u8>>, key: [u8; 32], bytes: &[u8]) -> ZkResult<()> {
    match map.get(&key) {
        Some(existing) if existing.as_slice() == bytes => Ok(()),
        Some(_) => Err(ZkError::new_err("flock: cache collision")),
        None => {
            map.insert(key, bytes.to_vec());
            Ok(())
        }
    }
}

/// Param bytes cached by SHA-256 (`CircuitFooter::param_checksum`).
pub fn cached_pcs_params(param_checksum: &[u8; 32]) -> Option<Vec<u8>> {
    cs_cache()
        .lock()
        .expect("flock param cache")
        .params
        .get(param_checksum)
        .cloned()
}

/// Constraint-system bytes cached by `Registry::digest`.
pub fn cached_constraint_system(digest: &[u8; 32]) -> Option<Vec<u8>> {
    cs_cache()
        .lock()
        .expect("flock cs cache")
        .registries
        .get(digest)
        .cloned()
}

pub struct LoadedFlockCircuit {
    pub params: PcsParams,
    pub registry_digest: [u8; 32],
}

/// Load `[PcsParams | registry | optional digest | footer]`.
///
/// Does not read a Halo2 verifying key. A claimed digest (`vk_len == 32`)
/// must equal `Registry::digest`.
pub fn load_flock_circuit(blob: &[u8]) -> ZkResult<LoadedFlockCircuit> {
    let vk = FlockVerifyingKey::try_from_bytes(blob)?;
    let params = decode_pcs_params(&vk.param_bytes)?;
    let registry = decode_registry(&vk.cs_bytes)?;
    let digest = registry.digest();
    if let Some(claimed) = vk.registry_digest {
        if claimed != digest {
            return Err(ZkError::new_err("flock: vk digest is not Registry::digest"));
        }
    }
    {
        let mut cache = cs_cache().lock().expect("flock circuit cache");
        remember(&mut cache.params, vk.footer.param_checksum, &vk.param_bytes)?;
        remember(&mut cache.registries, digest, &vk.cs_bytes)?;
    }
    Ok(LoadedFlockCircuit {
        params,
        registry_digest: digest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use zk_cosmwasm::{prove_flock, verify_flock_proof};

    #[test]
    fn host_rejects_digest_stub() {
        install();
        let action = [7u8; 128];
        let stub = prove_flock(&action);
        assert!(host_verify(&stub, &action, None).is_err());
        assert!(verify_flock_proof(&stub, &action).is_err());
    }

    #[test]
    fn host_rejects_truncated_ligerito() {
        install();
        let mut p = vec![0u8; HEADER];
        p[0..4].copy_from_slice(FLCK);
        p[4] = 3;
        p[5] = 7;
        p[6] = VERSION_LIGERITO;
        assert!(host_verify(&p, &[], None).is_err());
    }

    use flock_core::schedule::Instance;
    use sha2::{Digest, Sha256};
    use zk_cosmwasm::curves::{flock_circuit_blob, CurveType};
    use zk_cosmwasm::{CircuitFooter, CircuitType};

    fn tiny_registry(flip: bool) -> Registry {
        let k = 1usize << 7;
        let mut rows: Vec<Vec<usize>> = (0..k).map(|i| vec![i]).collect();
        if flip {
            rows[0] = vec![1];
        }
        let ty = TableType {
            k_log: 7,
            useful_bits: k,
            a_0: SparseBinaryMatrix::new(k, k, rows),
            b_0: identity_matrix(k),
            c_0: identity_matrix(k),
            const_pin: None,
            class: TableClass::Boolean,
            io_schema: Vec::new(),
        };
        Registry::new(vec![ty], 1)
    }

    #[test]
    fn flock_footer_round_trips_param_checksum_and_halo2_param_key_differs() {
        let first = encode_pcs_params(&canonical_pcs_params()).unwrap();
        let second = encode_pcs_params(&pcs_with_same_fields(&canonical_pcs_params())).unwrap();
        assert_eq!(first, second);
        assert_eq!(decode_pcs_params(&first).unwrap(), canonical_pcs_params());
        assert!(decode_pcs_params(&14u32.to_le_bytes()).is_err());

        let registry = tiny_registry(false);
        let digest = registry.digest();
        let _fewer = Instance::new(&registry, vec![0]);
        let _full = Instance::new(&registry, vec![1usize << registry.nu()]);
        assert_eq!(registry.digest(), digest);
        assert_ne!(tiny_registry(true).digest(), digest);

        let cs = encode_registry(&registry).unwrap();
        assert_eq!(decode_registry(&cs).unwrap().digest(), digest);

        let k = 0u8;
        let blob = flock_circuit_blob(k, 1, &first, &cs, Some(digest));
        let loaded = load_flock_circuit(&blob).unwrap();
        assert_eq!(loaded.params, canonical_pcs_params());
        assert_eq!(loaded.registry_digest, digest);

        let vk = FlockVerifyingKey::try_from_bytes(&blob).unwrap();
        let again = CircuitFooter::from_bytes(&vk.footer.to_bytes()).unwrap();
        assert_eq!(vk.footer, again);
        let param_checksum: [u8; 32] = Sha256::digest(&first).into();
        assert_eq!(vk.footer.param_checksum, param_checksum);
        assert_eq!(
            cached_pcs_params(&param_checksum).as_deref(),
            Some(first.as_slice())
        );
        assert_eq!(
            cached_constraint_system(&digest).as_deref(),
            Some(cs.as_slice())
        );

        let halo = CircuitFooter::new(
            CircuitType::Plonkish,
            CurveType::Pasta,
            vk.footer.k,
            vk.footer.i,
            vk.footer.param_len,
            0,
            0,
            vk.footer.param_checksum,
            [0u8; 32],
        );
        assert_eq!(halo.k, vk.footer.k);
        assert_eq!(halo.param_checksum, vk.footer.param_checksum);
        assert_ne!(
            halo.to_param_key(),
            vk.footer.to_param_key(),
            "halo2 and flock param keys differ"
        );
        assert_ne!(halo.param_filename(), vk.footer.param_filename());

        let other = tiny_registry(true);
        let other_cs = encode_registry(&other).unwrap();
        let other_blob = flock_circuit_blob(k, 1, &first, &other_cs, None);
        let other_loaded = load_flock_circuit(&other_blob).unwrap();
        assert_eq!(other_loaded.registry_digest, other.digest());
        assert_ne!(other_loaded.registry_digest, digest);
        assert_eq!(other_loaded.params, canonical_pcs_params());
        assert_eq!(
            cached_pcs_params(&param_checksum).as_deref(),
            Some(first.as_slice())
        );
        assert_eq!(
            cached_constraint_system(&other.digest()).as_deref(),
            Some(other_cs.as_slice())
        );
        assert_eq!(
            cached_constraint_system(&digest).as_deref(),
            Some(cs.as_slice())
        );

        let claimed = [0u8; 32];
        assert_ne!(claimed, digest);
        let bad = flock_circuit_blob(k, 1, &first, &cs, Some(claimed));
        assert!(load_flock_circuit(&bad).is_err());
    }
}
