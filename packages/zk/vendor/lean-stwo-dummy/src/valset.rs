//! Phase 1A valset AIR (LEAN-3): 5-byte deposit index + 1-byte EB.
//! Real Stwo (CPU / Blake2s). Not DummyStwo / DSTW.

use itertools::Itertools;
use num_traits::Zero;
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

use crate::{
    dummy_m31_hash, CIRCUIT_TYPE_STWO, CURVE_TYPE_M31, M31, M31_P, MAX_PROOF_BYTES, STWO_MAGIC,
    VerifyError,
};

pub const VALSET_INDEX_LEN: usize = 5;
pub const VALSET_EB_LEN: usize = 1;
pub const VALSET_STATE_LEN: usize = VALSET_INDEX_LEN + VALSET_EB_LEN;

const LOG_N_ROWS: u32 = LOG_N_LANES;

type ValsetComponent = FrameworkComponent<ValsetEval>;

#[derive(Clone)]
struct ValsetEval {
    log_n_rows: u32,
}

impl FrameworkEval for ValsetEval {
    fn log_size(&self) -> u32 {
        self.log_n_rows
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_n_rows + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let period = eval.next_trace_mask();
        let idx = eval.next_trace_mask();
        let claimed = eval.next_trace_mask();
        let three = E::F::from(BaseField::from_u32_unchecked(3));
        let five = E::F::from(BaseField::from_u32_unchecked(5));
        let seven = E::F::from(BaseField::from_u32_unchecked(7));
        eval.add_constraint(claimed - period * three - idx * five - seven);
        eval
    }
}

fn log_sizes() -> stwo::core::pcs::TreeVec<Vec<u32>> {
    let info = ValsetEval {
        log_n_rows: LOG_N_ROWS,
    }
    .evaluate(InfoEvaluator::empty());
    let mut sizes = info.mask_offsets.as_cols_ref().map_cols(|_| LOG_N_ROWS);
    sizes[PREPROCESSED_TRACE_IDX] = vec![];
    sizes
}

pub fn valset_instance_bytes(period: u64, deposit_index: [u8; 5], eb: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + VALSET_STATE_LEN);
    out.extend_from_slice(&period.to_be_bytes());
    out.extend_from_slice(&deposit_index);
    out.push(eb);
    out
}

fn packed_m31(deposit_index: [u8; 5], eb: u8) -> M31 {
    let mut mix: u32 = eb as u32;
    for (i, x) in deposit_index.iter().enumerate() {
        mix ^= (*x as u32) << (8 * (i % 4));
    }
    M31(mix % M31_P)
}

fn seeds(period: u64, deposit_index: [u8; 5], eb: u8) -> (M31, M31) {
    (M31((period as u32) % M31_P), packed_m31(deposit_index, eb))
}

fn gen_trace(
    period: M31,
    idx: M31,
    claimed: M31,
) -> Vec<CircleEvaluation<SimdBackend, StwoM31, BitReversedOrder>> {
    let n = 1usize << LOG_N_ROWS;
    let domain = CanonicCoset::new(LOG_N_ROWS).circle_domain();
    let z = StwoM31::from_u32_unchecked(0);
    let pad_c = StwoM31::from_u32_unchecked(dummy_m31_hash(M31(0), M31(0)).0);
    let mut col_p = vec![z; n];
    let mut col_i = vec![z; n];
    let mut col_c = vec![pad_c; n];
    col_p[0] = StwoM31::from_u32_unchecked(period.0);
    col_i[0] = StwoM31::from_u32_unchecked(idx.0);
    col_c[0] = StwoM31::from_u32_unchecked(claimed.0);
    [col_p, col_i, col_c]
        .into_iter()
        .map(|col| {
            CircleEvaluation::<SimdBackend, _, BitReversedOrder>::new(
                domain,
                BaseColumn::from_iter(col),
            )
        })
        .collect_vec()
}

fn mix_public(channel: &mut Blake2sChannel, period: M31, idx: M31, claimed: M31) {
    channel.mix_u64(period.0 as u64);
    channel.mix_u64(idx.0 as u64);
    channel.mix_u64(claimed.0 as u64);
}

fn header(period: M31, idx: M31, claimed: M31) -> Vec<u8> {
    let mut out = Vec::with_capacity(18);
    out.extend_from_slice(STWO_MAGIC);
    out.push(CIRCUIT_TYPE_STWO);
    out.push(CURVE_TYPE_M31);
    out.extend_from_slice(&period.to_le_bytes());
    out.extend_from_slice(&idx.to_le_bytes());
    out.extend_from_slice(&claimed.to_le_bytes());
    out
}

pub fn prove_valset(period: u64, deposit_index: [u8; 5], eb: u8) -> Result<Vec<u8>, VerifyError> {
    let (a, idx) = seeds(period, deposit_index, eb);
    let claimed = dummy_m31_hash(a, idx);
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
    mix_public(channel, a, idx, claimed);
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(gen_trace(a, idx, claimed));
    tree_builder.commit(channel);

    let component = ValsetComponent::new(
        &mut TraceLocationAllocator::default(),
        ValsetEval {
            log_n_rows: LOG_N_ROWS,
        },
        QM31::zero(),
    );
    let stark_proof =
        prove(&[&component], channel, commitment_scheme).map_err(|_| VerifyError::StwoVerify)?;
    let body = bincode::serialize(&stark_proof).map_err(|_| VerifyError::StwoVerify)?;
    let mut out = header(a, idx, claimed);
    out.extend_from_slice(&body);
    if out.len() > MAX_PROOF_BYTES {
        return Err(VerifyError::ProofTooLarge { len: out.len() });
    }
    Ok(out)
}

pub fn verify_valset(
    proof: &[u8],
    period: u64,
    deposit_index: [u8; 5],
    eb: u8,
) -> Result<(), VerifyError> {
    if proof.len() > MAX_PROOF_BYTES {
        return Err(VerifyError::ProofTooLarge { len: proof.len() });
    }
    if proof.len() < 18 {
        return Err(VerifyError::Truncated);
    }
    if &proof[0..4] != STWO_MAGIC {
        return Err(VerifyError::BadMagic);
    }
    match crate::CircuitType::from_u8(proof[4]) {
        Ok(crate::CircuitType::Stwo) => {}
        Ok(_) => return Err(VerifyError::WrongProverId { got: proof[4] }),
        Err(e) => return Err(e),
    }
    match crate::CurveType::from_u8(proof[5]) {
        Ok(crate::CurveType::M31) => {}
        Ok(_) => return Err(VerifyError::WrongCurveId { got: proof[5] }),
        Err(e) => return Err(e),
    }
    let (a, idx) = seeds(period, deposit_index, eb);
    let claimed = dummy_m31_hash(a, idx);
    let pa = M31::from_le_bytes(proof[6..10].try_into().unwrap())?;
    let pi = M31::from_le_bytes(proof[10..14].try_into().unwrap())?;
    let pc = M31::from_le_bytes(proof[14..18].try_into().unwrap())?;
    if pa != a || pi != idx || pc != claimed {
        return Err(VerifyError::PublicInputMismatch);
    }
    let stark_proof: StarkProof<Blake2sMerkleHasher> =
        bincode::deserialize(&proof[18..]).map_err(|_| VerifyError::StwoVerify)?;
    let pcs_config = stark_proof.config;
    let channel = &mut Blake2sChannel::default();
    pcs_config.mix_into(channel);
    let commitment_scheme = &mut CommitmentSchemeVerifier::<Blake2sMerkleChannel>::new(pcs_config);
    let sizes = log_sizes();
    commitment_scheme.commit(stark_proof.commitments[0], &sizes[0], channel);
    mix_public(channel, a, idx, claimed);
    commitment_scheme.commit(stark_proof.commitments[1], &sizes[1], channel);
    let component = ValsetComponent::new(
        &mut TraceLocationAllocator::default(),
        ValsetEval {
            log_n_rows: LOG_N_ROWS,
        },
        QM31::zero(),
    );
    verify(&[&component], channel, commitment_scheme, stark_proof).map_err(|_| VerifyError::StwoVerify)
}
