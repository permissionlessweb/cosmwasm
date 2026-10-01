//! Smallest real S-two AIR: public `(a, b)` and `c = dummy_m31_hash(a, b)` over M31.
//! CPU / Blake2s only. Feature-gated so default crate stays Dummy for Go.

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
    dummy_m31_hash, CIRCUIT_TYPE_STWO, CURVE_TYPE_M31, M31, MAX_PROOF_BYTES, STWO_MAGIC,
    VerifyError,
};

/// SIMD lane floor: smallest power-of-two trace Stwo's SimdBackend accepts.
const LOG_N_ROWS: u32 = LOG_N_LANES;

type HashComponent = FrameworkComponent<HashEval>;

#[derive(Clone)]
struct HashEval {
    log_n_rows: u32,
}

impl FrameworkEval for HashEval {
    fn log_size(&self) -> u32 {
        self.log_n_rows
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_n_rows + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let a = eval.next_trace_mask();
        let b = eval.next_trace_mask();
        let c = eval.next_trace_mask();
        let three = E::F::from(BaseField::from_u32_unchecked(3));
        let five = E::F::from(BaseField::from_u32_unchecked(5));
        let seven = E::F::from(BaseField::from_u32_unchecked(7));
        // c = 3a + 5b + 7  (same statement as dummy_m31_hash)
        eval.add_constraint(c - a * three - b * five - seven);
        eval
    }
}

fn log_sizes() -> stwo::core::pcs::TreeVec<Vec<u32>> {
    let info = HashEval {
        log_n_rows: LOG_N_ROWS,
    }
    .evaluate(InfoEvaluator::empty());
    let mut sizes = info.mask_offsets.as_cols_ref().map_cols(|_| LOG_N_ROWS);
    sizes[PREPROCESSED_TRACE_IDX] = vec![];
    sizes
}

fn gen_trace(
    a: M31,
    b: M31,
    c: M31,
) -> Vec<CircleEvaluation<SimdBackend, StwoM31, BitReversedOrder>> {
    let n = 1usize << LOG_N_ROWS;
    let domain = CanonicCoset::new(LOG_N_ROWS).circle_domain();
    let pad_a = StwoM31::from_u32_unchecked(0);
    let pad_b = StwoM31::from_u32_unchecked(0);
    let pad_c = StwoM31::from_u32_unchecked(dummy_m31_hash(M31(0), M31(0)).0);
    let mut col_a = vec![pad_a; n];
    let mut col_b = vec![pad_b; n];
    let mut col_c = vec![pad_c; n];
    col_a[0] = StwoM31::from_u32_unchecked(a.0);
    col_b[0] = StwoM31::from_u32_unchecked(b.0);
    col_c[0] = StwoM31::from_u32_unchecked(c.0);
    [col_a, col_b, col_c]
        .into_iter()
        .map(|col| {
            CircleEvaluation::<SimdBackend, _, BitReversedOrder>::new(
                domain,
                BaseColumn::from_iter(col),
            )
        })
        .collect_vec()
}

fn mix_public(channel: &mut Blake2sChannel, a: M31, b: M31, c: M31) {
    channel.mix_u64(a.0 as u64);
    channel.mix_u64(b.0 as u64);
    channel.mix_u64(c.0 as u64);
}

fn header(a: M31, b: M31, c: M31) -> Vec<u8> {
    let mut out = Vec::with_capacity(18);
    out.extend_from_slice(STWO_MAGIC);
    out.push(CIRCUIT_TYPE_STWO);
    out.push(CURVE_TYPE_M31);
    out.extend_from_slice(&a.to_le_bytes());
    out.extend_from_slice(&b.to_le_bytes());
    out.extend_from_slice(&c.to_le_bytes());
    out
}

pub struct RealStwo;

impl RealStwo {
    pub fn prove(a: M31, b: M31) -> Result<Vec<u8>, VerifyError> {
        prove_ab_hash(a, b)
    }

    pub fn verify(proof: &[u8], a: M31, b: M31, c: M31) -> Result<(), VerifyError> {
        verify_ab_hash(proof, a, b, c)
    }
}

pub fn prove_ab_hash(a: M31, b: M31) -> Result<Vec<u8>, VerifyError> {
    let c = dummy_m31_hash(a, b);
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

    mix_public(channel, a, b, c);

    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(gen_trace(a, b, c));
    tree_builder.commit(channel);

    let component = HashComponent::new(
        &mut TraceLocationAllocator::default(),
        HashEval {
            log_n_rows: LOG_N_ROWS,
        },
        QM31::zero(),
    );

    let stark_proof = prove(&[&component], channel, commitment_scheme).map_err(|_| VerifyError::StwoVerify)?;
    let body = bincode::serialize(&stark_proof).map_err(|_| VerifyError::StwoVerify)?;
    let mut out = header(a, b, c);
    out.extend_from_slice(&body);
    if out.len() > MAX_PROOF_BYTES {
        return Err(VerifyError::ProofTooLarge { len: out.len() });
    }
    Ok(out)
}

pub fn verify_ab_hash(proof: &[u8], a: M31, b: M31, c: M31) -> Result<(), VerifyError> {
    if proof.len() > MAX_PROOF_BYTES {
        return Err(VerifyError::ProofTooLarge { len: proof.len() });
    }
    if proof.len() < 18 {
        return Err(VerifyError::Truncated);
    }
    if &proof[0..4] != STWO_MAGIC {
        return Err(VerifyError::BadMagic);
    }
    let prover_id = proof[4];
    let curve_id = proof[5];
    match crate::CircuitType::from_u8(prover_id) {
        Ok(crate::CircuitType::Stwo) => {}
        Ok(_) => return Err(VerifyError::WrongProverId { got: prover_id }),
        Err(e) => return Err(e),
    }
    match crate::CurveType::from_u8(curve_id) {
        Ok(crate::CurveType::M31) => {}
        Ok(_) => return Err(VerifyError::WrongCurveId { got: curve_id }),
        Err(e) => return Err(e),
    }
    let pa = M31::from_le_bytes(proof[6..10].try_into().unwrap())?;
    let pb = M31::from_le_bytes(proof[10..14].try_into().unwrap())?;
    let pc = M31::from_le_bytes(proof[14..18].try_into().unwrap())?;
    if pa != a || pb != b || pc != c {
        return Err(VerifyError::PublicInputMismatch);
    }
    if dummy_m31_hash(pa, pb) != pc {
        return Err(VerifyError::StatementFalse);
    }

    let stark_proof: StarkProof<Blake2sMerkleHasher> =
        bincode::deserialize(&proof[18..]).map_err(|_| VerifyError::StwoVerify)?;

    let pcs_config = stark_proof.config;
    let channel = &mut Blake2sChannel::default();
    pcs_config.mix_into(channel);
    let commitment_scheme = &mut CommitmentSchemeVerifier::<Blake2sMerkleChannel>::new(pcs_config);
    let sizes = log_sizes();
    commitment_scheme.commit(stark_proof.commitments[0], &sizes[0], channel);
    mix_public(channel, a, b, c);
    commitment_scheme.commit(stark_proof.commitments[1], &sizes[1], channel);

    let component = HashComponent::new(
        &mut TraceLocationAllocator::default(),
        HashEval {
            log_n_rows: LOG_N_ROWS,
        },
        QM31::zero(),
    );
    verify(&[&component], channel, commitment_scheme, stark_proof).map_err(|_| VerifyError::StwoVerify)
}
