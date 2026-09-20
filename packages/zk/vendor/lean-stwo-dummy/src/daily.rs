//! LEAN-6 daily re-anon key AIR: public inputs are period||day_key||prev_root (72 bytes).
//! Day key is not the persistent JOIN/LEAV subject. BondedSet/bitfield stays power SoT.
//! Dummy DSTW is rejected.

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

pub const DAILY_KIND: &[u8; 4] = b"DAYK";
pub const DAY_KEY_LEN: usize = 32;
pub const PREV_ROOT_LEN: usize = 32;
/// period(8) || day_key(32) || prev_root(32)
pub const DAILY_PI_LEN: usize = 8 + DAY_KEY_LEN + PREV_ROOT_LEN;
const LIMB_BYTES: usize = 3;
const N_LIMBS: usize = DAILY_PI_LEN / LIMB_BYTES;

type DailyComponent = FrameworkComponent<DailyEval>;

fn pack_limbs(pi: &[u8; DAILY_PI_LEN]) -> [u32; N_LIMBS] {
    let mut out = [0u32; N_LIMBS];
    for (i, limb) in out.iter_mut().enumerate() {
        let o = i * LIMB_BYTES;
        *limb = u32::from(pi[o]) | (u32::from(pi[o + 1]) << 8) | (u32::from(pi[o + 2]) << 16);
    }
    out
}

/// Fresh M31-domain daily pubkey: SHA256(leanval/daily/key/v1 || period || identity).
/// Identity is the persistent JOIN/LEAV subject; the day key is not that subject.
pub fn daily_key(period: u64, identity: &[u8]) -> [u8; DAY_KEY_LEN] {
    let mut h = Sha256::new();
    h.update(b"leanval/daily/key/v1");
    h.update(period.to_be_bytes());
    h.update(identity);
    h.finalize().into()
}

fn pack_pi(period: u64, day_key: &[u8; DAY_KEY_LEN], prev_root: &[u8; PREV_ROOT_LEN]) -> [u8; DAILY_PI_LEN] {
    let mut pi = [0u8; DAILY_PI_LEN];
    pi[0..8].copy_from_slice(&period.to_be_bytes());
    pi[8..40].copy_from_slice(day_key);
    pi[40..72].copy_from_slice(prev_root);
    pi
}

#[derive(Clone)]
struct DailyEval {
    log_n_rows: u32,
    limbs: [u32; N_LIMBS],
}

impl FrameworkEval for DailyEval {
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
    let info = DailyEval {
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

fn mix_public(channel: &mut Blake2sChannel, pi: &[u8; DAILY_PI_LEN]) {
    for chunk in pi.chunks_exact(8) {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(chunk);
        channel.mix_u64(u64::from_le_bytes(buf));
    }
}

fn header(pi: &[u8; DAILY_PI_LEN]) -> Vec<u8> {
    let mut out = Vec::with_capacity(10 + DAILY_PI_LEN);
    out.extend_from_slice(STWO_MAGIC);
    out.push(CIRCUIT_TYPE_STWO);
    out.push(CURVE_TYPE_M31);
    out.extend_from_slice(DAILY_KIND);
    out.extend_from_slice(pi);
    out
}

fn parse_header(proof: &[u8]) -> Result<([u8; DAILY_PI_LEN], usize), VerifyError> {
    if proof.len() > MAX_PROOF_BYTES {
        return Err(VerifyError::ProofTooLarge { len: proof.len() });
    }
    let hdr = 10 + DAILY_PI_LEN;
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
    if &proof[6..10] != DAILY_KIND {
        return Err(VerifyError::BadMagic);
    }
    let mut pi = [0u8; DAILY_PI_LEN];
    pi.copy_from_slice(&proof[10..hdr]);
    Ok((pi, hdr))
}

pub fn prove_daily(
    period: u64,
    identity: &[u8],
    prev_root: &[u8; PREV_ROOT_LEN],
) -> Result<([u8; DAY_KEY_LEN], Vec<u8>), VerifyError> {
    let key = daily_key(period, identity);
    let pi = pack_pi(period, &key, prev_root);
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

    let component = DailyComponent::new(
        &mut TraceLocationAllocator::default(),
        DailyEval {
            log_n_rows: LOG_N_ROWS,
            limbs,
        },
        QM31::zero(),
    );
    let stark_proof =
        prove(&[&component], channel, commitment_scheme).map_err(|_| VerifyError::StwoVerify)?;
    let body = bincode::serialize(&stark_proof).map_err(|_| VerifyError::StwoVerify)?;
    let mut out = header(&pi);
    out.extend_from_slice(&body);
    if out.len() > MAX_PROOF_BYTES {
        return Err(VerifyError::ProofTooLarge { len: out.len() });
    }
    Ok((key, out))
}

pub fn verify_daily(
    proof: &[u8],
    period: u64,
    day_key: &[u8; DAY_KEY_LEN],
    prev_root: &[u8; PREV_ROOT_LEN],
) -> Result<(), VerifyError> {
    let (got, hdr) = parse_header(proof)?;
    let want = pack_pi(period, day_key, prev_root);
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
    let component = DailyComponent::new(
        &mut TraceLocationAllocator::default(),
        DailyEval {
            log_n_rows: LOG_N_ROWS,
            limbs,
        },
        QM31::zero(),
    );
    verify(&[&component], channel, commitment_scheme, stark_proof)
        .map_err(|_| VerifyError::StwoVerify)
}
