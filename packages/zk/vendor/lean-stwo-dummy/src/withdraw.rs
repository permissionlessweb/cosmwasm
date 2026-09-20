//! LEAN-7 hidden withdrawals: H(addr, secret) off the consensus row (EIP-8222 analog).
//! Daily no-withdraw accumulator is a named STWO AIR (kind NWDA).
//! Partial withdraw is a *separate* proof (kind PWDW). Dummy DSTW is rejected.
//! BondedSet/bitfield remains power SoT; JOIN/LEAV stay LNPR subjects.

use itertools::Itertools;
use num_traits::Zero;
use sha2::{Digest, Sha256};
use stwo::core::channel::{Blake2sChannel, Channel};
use stwo::core::fields::m31::{BaseField, M31 as StwoM31};
use stwo::core::fields::qm31::QM31;
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::proof::StarkProof;
use stwo::core::vcs_lifted::blake2_merkle::{Blake2sMerkleChannel, Blake2sMerkleHasher};
use stwo::core::verifier::verify;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::backend::simd::column::BaseColumn;
use stwo::prover::backend::simd::m31::LOG_N_LANES;
use stwo::prover::poly::BitReversedOrder;
use stwo::prover::poly::circle::{CircleEvaluation, PolyOps};
use stwo::prover::{CommitmentSchemeProver, prove};
use stwo_constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval, InfoEvaluator, PREPROCESSED_TRACE_IDX,
    TraceLocationAllocator,
};

use crate::{CIRCUIT_TYPE_STWO, CURVE_TYPE_M31, MAX_PROOF_BYTES, STWO_MAGIC, VerifyError};

/// Daily no-withdraw accumulator kind.
pub const NWDA_KIND: &[u8; 4] = b"NWDA";
/// Partial-withdraw kind — must not collide with NWDA.
pub const PWDW_KIND: &[u8; 4] = b"PWDW";

pub const COMMIT_LEN: usize = 32;
pub const ACC_LEN: usize = 32;
/// period(8) || left(32) || right(32)
pub const WITHDRAW_PI_LEN: usize = 8 + 32 + 32;
const LIMB_BYTES: usize = 3;
const N_LIMBS: usize = WITHDRAW_PI_LEN / LIMB_BYTES;

type WdComponent = FrameworkComponent<WdEval>;

fn pack_limbs(pi: &[u8; WITHDRAW_PI_LEN]) -> [u32; N_LIMBS] {
    let mut out = [0u32; N_LIMBS];
    for (i, limb) in out.iter_mut().enumerate() {
        let o = i * LIMB_BYTES;
        *limb = u32::from(pi[o]) | (u32::from(pi[o + 1]) << 8) | (u32::from(pi[o + 2]) << 16);
    }
    out
}

/// EIP-8222 analog: withdrawal credential is H(addr, secret), not the address.
pub fn withdraw_commit(addr: &[u8], secret: &[u8]) -> [u8; COMMIT_LEN] {
    let mut h = Sha256::new();
    h.update(b"leanval/withdraw/commit/v1");
    h.update(addr);
    h.update(secret);
    h.finalize().into()
}

/// Daily accumulator when the validator does *not* withdraw this period.
pub fn no_withdraw_acc(
    period: u64,
    prev_acc: &[u8; ACC_LEN],
    commit: &[u8; COMMIT_LEN],
) -> [u8; ACC_LEN] {
    let mut h = Sha256::new();
    h.update(b"leanval/withdraw/nwacc/v1");
    h.update(period.to_be_bytes());
    h.update(prev_acc);
    h.update(commit);
    h.finalize().into()
}

/// Remaining commitment after a partial withdraw of `amount` (separate statement).
pub fn partial_new_commit(period: u64, old_commit: &[u8; COMMIT_LEN], amount: u64) -> [u8; COMMIT_LEN] {
    let mut h = Sha256::new();
    h.update(b"leanval/withdraw/partial/v1");
    h.update(period.to_be_bytes());
    h.update(old_commit);
    h.update(amount.to_be_bytes());
    h.finalize().into()
}

fn pack_pi(period: u64, left: &[u8; 32], right: &[u8; 32]) -> [u8; WITHDRAW_PI_LEN] {
    let mut pi = [0u8; WITHDRAW_PI_LEN];
    pi[0..8].copy_from_slice(&period.to_be_bytes());
    pi[8..40].copy_from_slice(left);
    pi[40..72].copy_from_slice(right);
    pi
}

#[derive(Clone)]
struct WdEval {
    log_n_rows: u32,
    limbs: [u32; N_LIMBS],
}

impl FrameworkEval for WdEval {
    fn log_size(&self) -> u32 {
        self.log_n_rows
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_n_rows + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        for expected in self.limbs {
            let col = eval.next_trace_mask();
            let want = E::F::from(BaseField::from_u32_unchecked(expected));
            eval.add_constraint(col - want);
        }
        eval
    }
}

const LOG_N_ROWS: u32 = LOG_N_LANES;

fn log_sizes(limbs: [u32; N_LIMBS]) -> stwo::core::pcs::TreeVec<Vec<u32>> {
    let info = WdEval {
        log_n_rows: LOG_N_ROWS,
        limbs,
    }
    .evaluate(InfoEvaluator::empty());
    let mut sizes = info.mask_offsets.as_cols_ref().map_cols(|_| LOG_N_ROWS);
    sizes[PREPROCESSED_TRACE_IDX] = vec![];
    sizes
}

fn gen_trace(
    limbs: [u32; N_LIMBS],
) -> Vec<CircleEvaluation<SimdBackend, StwoM31, BitReversedOrder>> {
    let n = 1usize << LOG_N_ROWS;
    let domain = CanonicCoset::new(LOG_N_ROWS).circle_domain();
    limbs
        .into_iter()
        .map(|v| {
            let cell = StwoM31::from_u32_unchecked(v);
            let col = vec![cell; n];
            CircleEvaluation::<SimdBackend, _, BitReversedOrder>::new(
                domain,
                BaseColumn::from_iter(col),
            )
        })
        .collect_vec()
}

fn mix_public(channel: &mut Blake2sChannel, pi: &[u8; WITHDRAW_PI_LEN]) {
    for chunk in pi.chunks_exact(8) {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(chunk);
        channel.mix_u64(u64::from_le_bytes(buf));
    }
}

fn header(kind: &[u8; 4], pi: &[u8; WITHDRAW_PI_LEN]) -> Vec<u8> {
    let mut out = Vec::with_capacity(10 + WITHDRAW_PI_LEN);
    out.extend_from_slice(STWO_MAGIC);
    out.push(CIRCUIT_TYPE_STWO);
    out.push(CURVE_TYPE_M31);
    out.extend_from_slice(kind);
    out.extend_from_slice(pi);
    out
}

fn parse_header(proof: &[u8], kind: &[u8; 4]) -> Result<([u8; WITHDRAW_PI_LEN], usize), VerifyError> {
    if proof.len() > MAX_PROOF_BYTES {
        return Err(VerifyError::ProofTooLarge { len: proof.len() });
    }
    let hdr = 10 + WITHDRAW_PI_LEN;
    if proof.len() < hdr {
        return Err(VerifyError::Truncated);
    }
    if &proof[0..4] != STWO_MAGIC {
        return Err(VerifyError::BadMagic);
    }
    if proof.windows(4).any(|w| w == b"DSTW") {
        return Err(VerifyError::BadMagic);
    }
    if proof[4] != CIRCUIT_TYPE_STWO {
        return Err(VerifyError::WrongProverId { got: proof[4] });
    }
    if proof[5] != CURVE_TYPE_M31 {
        return Err(VerifyError::WrongCurveId { got: proof[5] });
    }
    if &proof[6..10] != kind {
        return Err(VerifyError::BadMagic);
    }
    let mut pi = [0u8; WITHDRAW_PI_LEN];
    pi.copy_from_slice(&proof[10..hdr]);
    Ok((pi, hdr))
}

fn prove_kind(
    kind: &[u8; 4],
    period: u64,
    left: &[u8; 32],
    right: &[u8; 32],
) -> Result<Vec<u8>, VerifyError> {
    let pi = pack_pi(period, left, right);
    let limbs = pack_limbs(&pi);
    let config = PcsConfig::default();
    let twiddles = SimdBackend::precompute_twiddles(
        CanonicCoset::new(LOG_N_ROWS + config.fri_config.log_blowup_factor + 1)
            .circle_domain()
            .half_coset,
    );
    let channel = &mut Blake2sChannel::default();
    config.mix_into(channel);
    let mut commitment_scheme =
        CommitmentSchemeProver::<_, Blake2sMerkleChannel>::new(config, &twiddles);

    let tree_builder = commitment_scheme.tree_builder();
    tree_builder.commit(channel);
    mix_public(channel, &pi);
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(gen_trace(limbs));
    tree_builder.commit(channel);

    let component = WdComponent::new(
        &mut TraceLocationAllocator::default(),
        WdEval {
            log_n_rows: LOG_N_ROWS,
            limbs,
        },
        QM31::zero(),
    );
    let stark_proof =
        prove(&[&component], channel, commitment_scheme).map_err(|_| VerifyError::StwoVerify)?;
    let body = bincode::serialize(&stark_proof).map_err(|_| VerifyError::StwoVerify)?;
    let mut out = header(kind, &pi);
    out.extend_from_slice(&body);
    if out.len() > MAX_PROOF_BYTES {
        return Err(VerifyError::ProofTooLarge { len: out.len() });
    }
    Ok(out)
}

fn verify_kind(
    proof: &[u8],
    kind: &[u8; 4],
    period: u64,
    left: &[u8; 32],
    right: &[u8; 32],
) -> Result<(), VerifyError> {
    let (got, hdr) = parse_header(proof, kind)?;
    let want = pack_pi(period, left, right);
    if got != want {
        return Err(VerifyError::PublicInputMismatch);
    }
    let limbs = pack_limbs(&got);
    let stark_proof: StarkProof<Blake2sMerkleHasher> =
        bincode::deserialize(&proof[hdr..]).map_err(|_| VerifyError::StwoVerify)?;
    let pcs_config = stark_proof.config;
    let channel = &mut Blake2sChannel::default();
    pcs_config.mix_into(channel);
    let commitment_scheme = &mut CommitmentSchemeVerifier::<Blake2sMerkleChannel>::new(pcs_config);
    let sizes = log_sizes(limbs);
    commitment_scheme.commit(stark_proof.commitments[0], &sizes[0], channel);
    mix_public(channel, &got);
    commitment_scheme.commit(stark_proof.commitments[1], &sizes[1], channel);
    let component = WdComponent::new(
        &mut TraceLocationAllocator::default(),
        WdEval {
            log_n_rows: LOG_N_ROWS,
            limbs,
        },
        QM31::zero(),
    );
    verify(&[&component], channel, commitment_scheme, stark_proof)
        .map_err(|_| VerifyError::StwoVerify)
}

pub fn prove_no_withdraw(
    period: u64,
    prev_acc: &[u8; ACC_LEN],
    commit: &[u8; COMMIT_LEN],
) -> Result<([u8; ACC_LEN], Vec<u8>), VerifyError> {
    let acc = no_withdraw_acc(period, prev_acc, commit);
    let proof = prove_kind(NWDA_KIND, period, &acc, prev_acc)?;
    Ok((acc, proof))
}

pub fn verify_no_withdraw(
    proof: &[u8],
    period: u64,
    acc: &[u8; ACC_LEN],
    prev_acc: &[u8; ACC_LEN],
) -> Result<(), VerifyError> {
    verify_kind(proof, NWDA_KIND, period, acc, prev_acc)
}

pub fn prove_partial_withdraw(
    period: u64,
    old_commit: &[u8; COMMIT_LEN],
    amount: u64,
) -> Result<([u8; COMMIT_LEN], Vec<u8>), VerifyError> {
    let next = partial_new_commit(period, old_commit, amount);
    let proof = prove_kind(PWDW_KIND, period, old_commit, &next)?;
    Ok((next, proof))
}

pub fn verify_partial_withdraw(
    proof: &[u8],
    period: u64,
    old_commit: &[u8; COMMIT_LEN],
    new_commit: &[u8; COMMIT_LEN],
) -> Result<(), VerifyError> {
    verify_kind(proof, PWDW_KIND, period, old_commit, new_commit)
}
