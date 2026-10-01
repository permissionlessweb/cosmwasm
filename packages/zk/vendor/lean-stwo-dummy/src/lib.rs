//! DummyStwo — first Lean host arm (v1 gate).
//!
//! One AIR: public inputs `(a, b)` in M31; statement `c = dummy_m31_hash(a, b)`.
//! This is **not** an always-true production stub: a one-bit flip of the proof
//! must reject. Not Lean balance-walk. Not zkids 1–6.
//!
//! Footer: `prover_id = 2` (`CircuitType::Stwo`), `curve_id = 5` (`M31`).
//!
//! Host (x/leanval FinalizeBlock) should charge
//! `ConsumeGas(STWO_DUMMY_VERIFY_GAS, "stwo dummy verify")` **before** calling
//! [`Verifier::verify_dummy`]. Proofs larger than [`MAX_PROOF_BYTES`] are invalid
//! and must not enter the dummy AIR.

/// Matches `CircuitType::Stwo` in the vm footer table (PROVER-IDS.md).
pub const CIRCUIT_TYPE_STWO: u8 = 2;

/// Matches `CurveType::M31` / Circle field (`p = 2^31 − 1`).
pub const CURVE_TYPE_M31: u8 = 5;

/// Mersenne-31 prime.
pub const M31_P: u32 = (1 << 31) - 1;

/// Host cap: too-big proof → invalid, no verify (DUMMY-STWO.md).
pub const MAX_PROOF_BYTES: usize = 2 * 1024 * 1024;

/// Placeholder gas units until a bench on a pinned `stwo` rev fills a real number.
/// Charge this **before** the rust call (`ConsumeGas(..., "stwo dummy verify")`).
pub const STWO_DUMMY_VERIFY_GAS: u64 = 150_000;

/// Wire magic so a random blob is not silently accepted.
const MAGIC: &[u8; 4] = b"DSTW";

/// Real S-two wire prefix. Must not equal Dummy `DSTW`.
pub const STWO_MAGIC: &[u8; 4] = b"STWO";

/// Fixed dummy-proof body length (header + two M31 + claimed hash).
pub const DUMMY_PROOF_LEN: usize = 4 + 1 + 1 + 4 + 4 + 4;

/// `CircuitType` — one verifier binary + one wire format. Fail-closed `from_u8`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CircuitType {
    Plonkish = 0,
    Groth16 = 1,
    Stwo = 2,
}

impl CircuitType {
    pub fn from_u8(v: u8) -> Result<Self, VerifyError> {
        match v {
            0 => Ok(Self::Plonkish),
            1 => Ok(Self::Groth16),
            2 => Ok(Self::Stwo),
            _ => Err(VerifyError::UnsupportedCircuitType(v)),
        }
    }

    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

/// Curve / field id. `5` is M31 / Circle, not another Pasta circuit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CurveType {
    Pasta = 0,
    Bn254 = 4,
    M31 = 5,
}

impl CurveType {
    pub fn from_u8(v: u8) -> Result<Self, VerifyError> {
        match v {
            0 => Ok(Self::Pasta),
            4 => Ok(Self::Bn254),
            5 => Ok(Self::M31),
            _ => Err(VerifyError::UnsupportedCurve(v)),
        }
    }

    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

/// VK arm for the dummy host. Real S-two params land when the crate is pinned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AnyVerifyingKey {
    Stwo(DummyStwoVk),
}

/// Instance arm: public `(a, b, c)` over M31.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AnyInstance {
    Stwo { a: M31, b: M31, c: M31 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DummyStwoVk {
    pub prover_id: u8,
    pub curve_id: u8,
}

impl Default for DummyStwoVk {
    fn default() -> Self {
        Self {
            prover_id: CIRCUIT_TYPE_STWO,
            curve_id: CURVE_TYPE_M31,
        }
    }
}

/// M31 field element (`0 .. 2^31-1`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct M31(pub u32);

impl M31 {
    pub fn new(raw: u32) -> Result<Self, VerifyError> {
        if raw >= M31_P {
            return Err(VerifyError::NotInM31(raw));
        }
        Ok(Self(raw))
    }

    pub fn from_le_bytes(b: [u8; 4]) -> Result<Self, VerifyError> {
        Self::new(u32::from_le_bytes(b))
    }

    pub fn to_le_bytes(self) -> [u8; 4] {
        self.0.to_le_bytes()
    }

    fn add(self, other: Self) -> Self {
        let s = (self.0 as u64 + other.0 as u64) % (M31_P as u64);
        Self(s as u32)
    }

    fn mul(self, other: Self) -> Self {
        let p = ((self.0 as u64) * (other.0 as u64)) % (M31_P as u64);
        Self(p as u32)
    }
}

/// Domain-separated mix: `c = α·a + β·b + γ` in M31 (odd constants, not identity).
/// Named DummyStwo so this is never confused with a production always-true stub.
pub fn dummy_m31_hash(a: M31, b: M31) -> M31 {
    const ALPHA: M31 = M31(3);
    const BETA: M31 = M31(5);
    const GAMMA: M31 = M31(7);
    ALPHA.mul(a).add(BETA.mul(b)).add(GAMMA)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyError {
    ProofTooLarge { len: usize },
    BadMagic,
    Truncated,
    UnsupportedCircuitType(u8),
    UnsupportedCurve(u8),
    WrongProverId { got: u8 },
    WrongCurveId { got: u8 },
    NotInM31(u32),
    PublicInputMismatch,
    StatementFalse,
    StwoVerify,
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ProofTooLarge { len } => write!(f, "proof too large: {len} > {MAX_PROOF_BYTES}"),
            Self::BadMagic => write!(f, "bad DummyStwo magic"),
            Self::Truncated => write!(f, "truncated DummyStwo proof"),
            Self::UnsupportedCircuitType(v) => write!(f, "unsupported CircuitType {v}"),
            Self::UnsupportedCurve(v) => write!(f, "UnsupportedCurve {v}"),
            Self::WrongProverId { got } => write!(f, "wrong prover_id {got} (want 2/Stwo)"),
            Self::WrongCurveId { got } => write!(f, "wrong curve_id {got} (want 5/M31)"),
            Self::NotInM31(v) => write!(f, "{v} not in M31"),
            Self::PublicInputMismatch => write!(f, "public inputs do not match proof"),
            Self::StatementFalse => write!(f, "c != dummy_m31_hash(a,b)"),
            Self::StwoVerify => write!(f, "stwo verify failed"),
        }
    }
}

impl std::error::Error for VerifyError {}

/// Matches `x/leanval/keeper/abci.go` `Verifier::VerifyDummy`.
///
/// Host 0 / `Ok(true)` = valid dummy proof.
/// Host 1 / `Ok(false)` or `Err` = reject (block invalid if required inject).
pub trait Verifier {
    fn verify_dummy(
        &self,
        proof: &[u8],
        a: u32,
        b: u32,
        claimed_hash: u32,
    ) -> Result<bool, VerifyError>;
}

/// DummyStwo verifier: CPU only. Not always-true.
#[derive(Clone, Copy, Debug, Default)]
pub struct DummyStwo;

impl DummyStwo {
    /// Bind period + weight + subject into (a,b). Forged weight fails verify if instances checked.
    pub fn prove_bound(period: u64, subject: &[u8], weight: i64) -> Vec<u8> {
        let a = M31((period as u32) % M31_P);
        let mut mix: u32 = 0;
        let wb = weight.to_be_bytes();
        for (i, x) in wb.iter().enumerate() {
            mix ^= (*x as u32) << (8 * (i % 4));
        }
        for (i, x) in subject.iter().enumerate() {
            mix ^= (*x as u32) << (8 * (i % 4));
        }
        let b = M31(mix % M31_P);
        Self::prove(a, b)
    }

    pub fn prove(a: M31, b: M31) -> Vec<u8> {
        let c = dummy_m31_hash(a, b);
        let mut out = Vec::with_capacity(DUMMY_PROOF_LEN);
        out.extend_from_slice(MAGIC);
        out.push(CIRCUIT_TYPE_STWO);
        out.push(CURVE_TYPE_M31);
        out.extend_from_slice(&a.to_le_bytes());
        out.extend_from_slice(&b.to_le_bytes());
        out.extend_from_slice(&c.to_le_bytes());
        out
    }
}

impl Verifier for DummyStwo {
    fn verify_dummy(
        &self,
        proof: &[u8],
        a: u32,
        b: u32,
        claimed_hash: u32,
    ) -> Result<bool, VerifyError> {
        if proof.len() > MAX_PROOF_BYTES {
            return Err(VerifyError::ProofTooLarge { len: proof.len() });
        }
        if proof.len() < DUMMY_PROOF_LEN {
            return Err(VerifyError::Truncated);
        }
        if &proof[0..4] != MAGIC {
            return Err(VerifyError::BadMagic);
        }

        let prover_id = proof[4];
        let curve_id = proof[5];

        // Fail-closed: wrong prover_id is never Ok(true).
        match CircuitType::from_u8(prover_id) {
            Ok(CircuitType::Stwo) => {}
            Ok(_) => return Err(VerifyError::WrongProverId { got: prover_id }),
            Err(e) => return Err(e),
        }
        match CurveType::from_u8(curve_id) {
            Ok(CurveType::M31) => {}
            Ok(_) => return Err(VerifyError::WrongCurveId { got: curve_id }),
            Err(e) => return Err(e),
        }

        let pa = M31::from_le_bytes(proof[6..10].try_into().unwrap())?;
        let pb = M31::from_le_bytes(proof[10..14].try_into().unwrap())?;
        let pc = M31::from_le_bytes(proof[14..18].try_into().unwrap())?;

        let pub_a = M31::new(a)?;
        let pub_b = M31::new(b)?;
        let pub_c = M31::new(claimed_hash)?;

        if pa != pub_a || pb != pub_b || pc != pub_c {
            return Err(VerifyError::PublicInputMismatch);
        }

        if dummy_m31_hash(pa, pb) != pc {
            return Ok(false);
        }
        Ok(true)
    }
}

#[cfg(feature = "real-stwo")]
mod real;

#[cfg(feature = "real-stwo")]
mod balance;

#[cfg(feature = "real-stwo")]
mod valset;

#[cfg(feature = "real-stwo")]
mod fold;

#[cfg(feature = "real-stwo")]
pub use real::{prove_ab_hash, verify_ab_hash, RealStwo};

#[cfg(feature = "real-stwo")]
pub use balance::{prove_balance, verify_balance};

#[cfg(feature = "real-stwo")]
pub use valset::{prove_valset, valset_instance_bytes, verify_valset, VALSET_STATE_LEN};

#[cfg(feature = "real-stwo")]
pub use fold::{prove_fold, reject_dummy_n, verify_fold, FOLD_KIND};

#[cfg(feature = "real-stwo")]
mod ssle;

#[cfg(feature = "real-stwo")]
pub use ssle::{prove_ssle, ssle_ticket, verify_ssle, SSLE_KIND, SSLE_PI_LEN, TICKET_LEN};

#[cfg(feature = "real-stwo")]
mod daily;

#[cfg(feature = "real-stwo")]
pub use daily::{daily_key, prove_daily, verify_daily, DAILY_KIND, DAILY_PI_LEN, DAY_KEY_LEN};

#[cfg(feature = "real-stwo")]
mod withdraw;

#[cfg(feature = "real-stwo")]
pub use withdraw::{
    no_withdraw_acc, partial_new_commit, prove_no_withdraw, prove_partial_withdraw,
    verify_no_withdraw, verify_partial_withdraw, withdraw_commit, COMMIT_LEN, NWDA_KIND,
    PWDW_KIND, WITHDRAW_PI_LEN,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn circuit_type_stwo_is_two() {
        assert_eq!(CircuitType::Stwo.to_u8(), 2);
        assert_eq!(CircuitType::from_u8(2).unwrap(), CircuitType::Stwo);
        assert!(CircuitType::from_u8(99).is_err());
    }

    #[test]
    fn curve_type_m31_is_five() {
        assert_eq!(CurveType::M31.to_u8(), 5);
        assert_eq!(CurveType::from_u8(5).unwrap(), CurveType::M31);
        assert!(matches!(
            CurveType::from_u8(3),
            Err(VerifyError::UnsupportedCurve(3))
        ));
    }

    /// Valid dummy proof → Ok(true) (host 0).
    #[test]
    fn dummy_stwo_valid_ok() {
        let a = M31::new(11).unwrap();
        let b = M31::new(22).unwrap();
        let c = dummy_m31_hash(a, b);
        let proof = DummyStwo::prove(a, b);
        assert_eq!(
            DummyStwo.verify_dummy(&proof, a.0, b.0, c.0).unwrap(),
            true
        );
    }

    /// Flip one proof byte → Ok(false) or Err (never Ok(true)).
    #[test]
    fn dummy_stwo_bitflip_fail() {
        let a = M31::new(11).unwrap();
        let b = M31::new(22).unwrap();
        let c = dummy_m31_hash(a, b);
        let mut proof = DummyStwo::prove(a, b);
        // Flip a low bit of claimed `c` inside the proof (byte 14).
        proof[14] ^= 1;
        let flipped_c = u32::from_le_bytes(proof[14..18].try_into().unwrap());
        let res = DummyStwo.verify_dummy(&proof, a.0, b.0, flipped_c);
        match res {
            Ok(false) => {}
            Err(_) => {}
            Ok(true) => panic!("bitflip must not verify"),
        }
        // Public inputs still the honest ones: mismatch or false statement.
        let res2 = DummyStwo.verify_dummy(&proof, a.0, b.0, c.0);
        assert!(res2 != Ok(true), "honest pubs + flipped proof must reject");
    }

    /// Wrong prover_id blob → fail closed (not Ok(true)).
    #[test]
    fn dummy_stwo_wrong_prover_id_fail_closed() {
        let a = M31::new(1).unwrap();
        let b = M31::new(2).unwrap();
        let c = dummy_m31_hash(a, b);
        let mut proof = DummyStwo::prove(a, b);
        proof[4] = 0; // Plonkish
        let err = DummyStwo
            .verify_dummy(&proof, a.0, b.0, c.0)
            .unwrap_err();
        assert!(matches!(err, VerifyError::WrongProverId { got: 0 }));

        proof[4] = 99;
        let err = DummyStwo
            .verify_dummy(&proof, a.0, b.0, c.0)
            .unwrap_err();
        assert!(matches!(err, VerifyError::UnsupportedCircuitType(99)));
    }

    #[test]
    fn dummy_stwo_oversize_proof_rejected() {
        let huge = vec![0u8; MAX_PROOF_BYTES + 1];
        assert!(matches!(
            DummyStwo.verify_dummy(&huge, 1, 2, 3),
            Err(VerifyError::ProofTooLarge { .. })
        ));
    }

    /// Dummy DSTW wire is not the real S-two prefix.
    #[test]
    fn test_dummy_and_stwo_not_same_wire() {
        assert_ne!(&MAGIC[..], &STWO_MAGIC[..]);
        let a = M31::new(11).unwrap();
        let b = M31::new(22).unwrap();
        let dummy = DummyStwo::prove(a, b);
        assert_eq!(&dummy[0..4], b"DSTW");
        assert_ne!(&dummy[0..4], STWO_MAGIC);
    }

    #[cfg(feature = "real-stwo")]
    #[test]
    fn test_stwo_prove_verify_ab_hash() {
        let a = M31::new(11).unwrap();
        let b = M31::new(22).unwrap();
        let c = dummy_m31_hash(a, b);
        let proof = crate::prove_ab_hash(a, b).expect("prove");
        assert_eq!(&proof[0..4], STWO_MAGIC);
        crate::verify_ab_hash(&proof, a, b, c).expect("verify");
    }

    #[cfg(feature = "real-stwo")]
    #[test]
    fn test_stwo_bitflip_rejects() {
        let a = M31::new(11).unwrap();
        let b = M31::new(22).unwrap();
        let c = dummy_m31_hash(a, b);
        let mut proof = crate::prove_ab_hash(a, b).expect("prove");
        let i = proof.len() / 2;
        proof[i] ^= 1;
        assert!(crate::verify_ab_hash(&proof, a, b, c).is_err());
    }

    #[cfg(feature = "real-stwo")]
    #[test]
    fn test_wrong_prover_id_rejects() {
        let a = M31::new(11).unwrap();
        let b = M31::new(22).unwrap();
        let c = dummy_m31_hash(a, b);
        let mut proof = crate::prove_ab_hash(a, b).expect("prove");
        proof[4] = 0;
        let err = crate::verify_ab_hash(&proof, a, b, c).unwrap_err();
        assert!(matches!(err, VerifyError::WrongProverId { got: 0 }));
    }

    #[cfg(feature = "real-stwo")]
    #[test]
    fn test_not_dstw_magic() {
        let a = M31::new(11).unwrap();
        let b = M31::new(22).unwrap();
        let c = dummy_m31_hash(a, b);
        let real = crate::prove_ab_hash(a, b).expect("prove");
        assert_ne!(&real[0..4], b"DSTW");
        assert!(DummyStwo.verify_dummy(&real, a.0, b.0, c.0).is_err());
        let dummy = DummyStwo::prove(a, b);
        assert!(crate::verify_ab_hash(&dummy, a, b, c).is_err());
    }

    #[cfg(feature = "real-stwo")]
    #[test]
    fn test_balance_air_prove_verify() {
        let period = 7u64;
        let subject = b"lean-subject-ed25519-pk-32bytes!";
        let weight = 21i64;
        let proof = crate::prove_balance(period, subject, weight, weight).expect("prove");
        assert_eq!(&proof[0..4], STWO_MAGIC);
        crate::verify_balance(&proof, period, subject, weight, weight).expect("verify");
    }

    #[cfg(feature = "real-stwo")]
    #[test]
    fn test_balance_air_fine_mismatch_rejects() {
        let period = 7u64;
        let subject = b"lean-subject-ed25519-pk-32bytes!";
        assert!(crate::prove_balance(period, subject, 21, 20).is_err());
    }

    #[cfg(feature = "real-stwo")]
    #[test]
    fn test_valset_air_prove_verify() {
        let period = 3u64;
        let idx = [0u8, 0, 0, 0, 42];
        let eb = 32u8;
        let inst = crate::valset_instance_bytes(period, idx, eb);
        assert_eq!(inst.len(), 8 + crate::VALSET_STATE_LEN);
        let proof = crate::prove_valset(period, idx, eb).expect("prove");
        assert_eq!(&proof[0..4], STWO_MAGIC);
        assert_ne!(&proof[0..4], b"DSTW");
        crate::verify_valset(&proof, period, idx, eb).expect("verify");
    }

    #[cfg(feature = "real-stwo")]
    #[test]
    fn test_valset_air_wrong_index_rejects() {
        let period = 3u64;
        let idx = [0u8, 0, 0, 0, 42];
        let eb = 32u8;
        let proof = crate::prove_valset(period, idx, eb).expect("prove");
        let other = [0u8, 0, 0, 0, 43];
        assert!(crate::verify_valset(&proof, period, other, eb).is_err());
    }

    #[cfg(feature = "real-stwo")]
    #[test]
    fn test_valset_air_wrong_eb_rejects() {
        let period = 3u64;
        let idx = [0u8, 0, 0, 0, 7];
        let proof = crate::prove_valset(period, idx, 32).expect("prove");
        assert!(crate::verify_valset(&proof, period, idx, 31).is_err());
    }

    #[cfg(feature = "real-stwo")]
    #[test]
    fn test_valset_air_bitflip_rejects() {
        let period = 3u64;
        let idx = [0u8, 0, 0, 0, 42];
        let mut proof = crate::prove_valset(period, idx, 32).expect("prove");
        let i = proof.len() / 2;
        proof[i] ^= 1;
        assert!(crate::verify_valset(&proof, period, idx, 32).is_err());
    }

    #[cfg(feature = "real-stwo")]
    #[test]
    fn test_fold_binds_bitfield_root() {
        let mut bf = [0u8; 32];
        bf[0] = 0xab;
        let dep = [1u8; 32];
        let eb = [2u8; 32];
        let proof = crate::prove_fold(bf, dep, eb).expect("prove fold");
        assert_eq!(&proof[0..4], STWO_MAGIC);
        assert_eq!(&proof[6..10], crate::FOLD_KIND);
        assert_eq!(&proof[10..42], &bf);
        crate::verify_fold(&proof, bf, dep, eb).expect("one verify");
    }

    #[cfg(feature = "real-stwo")]
    #[test]
    fn test_fold_dummy_n_fails() {
        let a = M31::new(1).unwrap();
        let b = M31::new(2).unwrap();
        let d1 = DummyStwo::prove(a, b);
        let d2 = DummyStwo::prove(M31::new(3).unwrap(), M31::new(4).unwrap());
        let mut concat = d1.clone();
        concat.extend_from_slice(&d2);
        let z = [0u8; 32];
        assert!(crate::verify_fold(&concat, z, z, z).is_err(), "Dummy-N must FAIL");
        assert!(crate::reject_dummy_n(&concat).is_err());
    }

    #[cfg(feature = "real-stwo")]
    #[test]
    fn test_fold_wrong_root_rejects() {
        let bf = [3u8; 32];
        let dep = [4u8; 32];
        let eb = [5u8; 32];
        let proof = crate::prove_fold(bf, dep, eb).expect("prove");
        let other = [9u8; 32];
        assert!(crate::verify_fold(&proof, other, dep, eb).is_err());
    }

    #[cfg(feature = "real-stwo")]
    #[test]
    fn test_fold_bitflip_rejects() {
        let bf = [11u8; 32];
        let dep = [22u8; 32];
        let eb = [33u8; 32];
        let mut proof = crate::prove_fold(bf, dep, eb).expect("prove");
        let i = proof.len() / 2;
        proof[i] ^= 1;
        assert!(crate::verify_fold(&proof, bf, dep, eb).is_err());
    }

    #[cfg(feature = "real-stwo")]
    #[test]
    fn test_ssle_ticket_not_proposer_and_dummy_fails() {
        let proposer = [0x11u8; 32];
        let (ticket, proof) = crate::prove_ssle(3, 42, &proposer).expect("prove");
        assert_ne!(&ticket, &proposer, "ticket must not be the proposer id");
        crate::verify_ssle(&proof, 3, 42, &ticket).expect("verify");
        assert!(!proof.windows(4).any(|w| w == b"DSTW"));
        assert_eq!(&proof[6..10], crate::SSLE_KIND);
        assert!(crate::verify_ssle(b"DSTWDSTW", 3, 42, &ticket).is_err());
        let mut bad = proof.clone();
        bad[proof.len() / 2] ^= 1;
        assert!(crate::verify_ssle(&bad, 3, 42, &ticket).is_err());
    }

    #[cfg(feature = "real-stwo")]
    #[test]
    fn test_daily_key_not_identity_and_dummy_fails() {
        let identity = [0xcd; 32];
        let prev = [0u8; 32];
        let (key, proof) = crate::prove_daily(7, &identity, &prev).expect("prove");
        crate::verify_daily(&proof, 7, &key, &prev).expect("verify");
        assert_ne!(&key[..], &identity[..]);
        assert!(!proof.windows(4).any(|w| w == b"DSTW"));
        assert_eq!(&proof[0..4], crate::STWO_MAGIC);
        assert_eq!(proof[4], crate::CIRCUIT_TYPE_STWO);
        assert_eq!(proof[5], crate::CURVE_TYPE_M31);
        assert_eq!(&proof[6..10], crate::DAILY_KIND);
        assert!(crate::verify_daily(b"DSTWDSTW", 7, &key, &prev).is_err());
        let mut bad = proof.clone();
        bad[proof.len() / 2] ^= 1;
        assert!(crate::verify_daily(&bad, 7, &key, &prev).is_err());
        let other = crate::daily_key(8, &identity);
        assert_ne!(key, other);
    }

    #[cfg(feature = "real-stwo")]
    #[test]
    fn test_hidden_withdraw_dummy_fails_and_partial_is_separate() {
        let addr = [0x11u8; 20];
        let secret = [0x22u8; 32];
        let commit = crate::withdraw_commit(&addr, &secret);
        assert_ne!(&commit[..20], &addr[..]);
        let prev = [0u8; 32];
        let (acc, proof) = crate::prove_no_withdraw(4, &prev, &commit).expect("nw prove");
        crate::verify_no_withdraw(&proof, 4, &acc, &prev).expect("nw verify");
        assert_eq!(&proof[0..4], crate::STWO_MAGIC);
        assert_eq!(proof[4], crate::CIRCUIT_TYPE_STWO);
        assert_eq!(proof[5], crate::CURVE_TYPE_M31);
        assert_eq!(&proof[6..10], crate::NWDA_KIND);
        assert!(!proof.windows(4).any(|w| w == b"DSTW"));
        assert!(crate::verify_no_withdraw(b"DSTWDSTW", 4, &acc, &prev).is_err());
        let (next, pw) = crate::prove_partial_withdraw(4, &commit, 7).expect("pw prove");
        crate::verify_partial_withdraw(&pw, 4, &commit, &next).expect("pw verify");
        assert_eq!(&pw[6..10], crate::PWDW_KIND);
        assert!(crate::verify_no_withdraw(&pw, 4, &acc, &prev).is_err());
        assert!(crate::verify_partial_withdraw(&proof, 4, &commit, &next).is_err());
        let mut bad = proof.clone();
        bad[proof.len() / 2] ^= 1;
        assert!(crate::verify_no_withdraw(&bad, 4, &acc, &prev).is_err());
    }

    #[cfg(feature = "real-stwo")]
    #[test]
    fn test_fold_air_not_dummy_hash() {
        let src = include_str!("fold.rs");
        assert!(!src.contains("dummy_m31_hash"), "fold AIR must not call dummy_m31_hash");
        assert!(
            !src.contains("from_u32_unchecked(3)") || !src.contains("from_u32_unchecked(5)"),
            "fold AIR must not be c=3a+5b+7"
        );
        assert!(src.contains("col - want"), "expected limb reconstruction constraint");
    }
}
