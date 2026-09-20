//! Same-statement fold: public inputs are the 96-byte object roots
//! (bitfield || deposit || EB). Trace limbs reconstruct those roots;
//! the same bytes are mixed into Fiat-Shamir. Not Dummy-N / DSTW.

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

use crate::{CIRCUIT_TYPE_STWO, CURVE_TYPE_M31, MAX_PROOF_BYTES, STWO_MAGIC, VerifyError};

/// Wire kind: same-statement fold over object roots.
pub const FOLD_KIND: &[u8; 4] = b"FOLD";

pub const ROOT_LEN: usize = 32;
pub const OBJECT_ROOTS_LEN: usize = ROOT_LEN * 3;
/// Three bytes per M31 limb (24-bit, uniquely reconstructs the 96-byte PI).
pub const LIMB_BYTES: usize = 3;
pub const N_LIMBS: usize = OBJECT_ROOTS_LEN / LIMB_BYTES;

type FoldComponent = FrameworkComponent<FoldEval>;

/// Pack 96 root bytes into 32 M31 limbs (LE 24-bit groups).
pub fn pack_root_limbs(roots: &[u8; OBJECT_ROOTS_LEN]) -> [u32; N_LIMBS] {
    let mut out = [0u32; N_LIMBS];
    for (i, limb) in out.iter_mut().enumerate() {
        let o = i * LIMB_BYTES;
        *limb = u32::from(roots[o])
            | (u32::from(roots[o + 1]) << 8)
            | (u32::from(roots[o + 2]) << 16);
    }
    out
}

#[derive(Clone)]
struct FoldEval {
    log_n_rows: u32,
    /// Expected 24-bit limbs of bitfield||deposit||EB (public).
    limbs: [u32; N_LIMBS],
}

impl FrameworkEval for FoldEval {
    fn log_size(&self) -> u32 {
        self.log_n_rows
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_n_rows + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        // limb_i - pack3(roots[3i..3i+3]) = 0  (trace reconstructs FS-mixed roots)
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
    let info = FoldEval {
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

fn mix_public(channel: &mut Blake2sChannel, roots: &[u8; OBJECT_ROOTS_LEN]) {
    for chunk in roots.chunks_exact(8) {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(chunk);
        channel.mix_u64(u64::from_le_bytes(buf));
    }
}

fn header(roots: &[u8; OBJECT_ROOTS_LEN]) -> Vec<u8> {
    let mut out = Vec::with_capacity(10 + OBJECT_ROOTS_LEN);
    out.extend_from_slice(STWO_MAGIC);
    out.push(CIRCUIT_TYPE_STWO);
    out.push(CURVE_TYPE_M31);
    out.extend_from_slice(FOLD_KIND);
    out.extend_from_slice(roots);
    out
}

fn parse_header(proof: &[u8]) -> Result<([u8; OBJECT_ROOTS_LEN], usize), VerifyError> {
    if proof.len() > MAX_PROOF_BYTES {
        return Err(VerifyError::ProofTooLarge { len: proof.len() });
    }
    let hdr = 10 + OBJECT_ROOTS_LEN;
    if proof.len() < hdr {
        return Err(VerifyError::Truncated);
    }
    if &proof[0..4] != STWO_MAGIC {
        return Err(VerifyError::BadMagic);
    }
    if proof.windows(4).any(|w| w == b"DSTW") {
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
    if &proof[6..10] != FOLD_KIND {
        return Err(VerifyError::BadMagic);
    }
    let mut roots = [0u8; OBJECT_ROOTS_LEN];
    roots.copy_from_slice(&proof[10..hdr]);
    Ok((roots, hdr))
}

pub fn prove_fold(bitfield: [u8; 32], deposit: [u8; 32], eb: [u8; 32]) -> Result<Vec<u8>, VerifyError> {
    let mut roots = [0u8; OBJECT_ROOTS_LEN];
    roots[..32].copy_from_slice(&bitfield);
    roots[32..64].copy_from_slice(&deposit);
    roots[64..96].copy_from_slice(&eb);
    let limbs = pack_root_limbs(&roots);
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
    mix_public(channel, &roots);
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(gen_trace(limbs));
    tree_builder.commit(channel);

    let component = FoldComponent::new(
        &mut TraceLocationAllocator::default(),
        FoldEval {
            log_n_rows: LOG_N_ROWS,
            limbs,
        },
        QM31::zero(),
    );

    let stark_proof =
        prove(&[&component], channel, commitment_scheme).map_err(|_| VerifyError::StwoVerify)?;
    let body = bincode::serialize(&stark_proof).map_err(|_| VerifyError::StwoVerify)?;
    let mut out = header(&roots);
    out.extend_from_slice(&body);
    if out.len() > MAX_PROOF_BYTES {
        return Err(VerifyError::ProofTooLarge { len: out.len() });
    }
    Ok(out)
}

pub fn verify_fold(
    proof: &[u8],
    bitfield: [u8; 32],
    deposit: [u8; 32],
    eb: [u8; 32],
) -> Result<(), VerifyError> {
    let (got, hdr) = parse_header(proof)?;
    if got[..32] != bitfield || got[32..64] != deposit || got[64..96] != eb {
        return Err(VerifyError::PublicInputMismatch);
    }
    let limbs = pack_root_limbs(&got);
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

    let component = FoldComponent::new(
        &mut TraceLocationAllocator::default(),
        FoldEval {
            log_n_rows: LOG_N_ROWS,
            limbs,
        },
        QM31::zero(),
    );
    verify(&[&component], channel, commitment_scheme, stark_proof)
        .map_err(|_| VerifyError::StwoVerify)
}

/// Reject Dummy-N (concatenated DSTW) as an aggregate. Always Err.
pub fn reject_dummy_n(blob: &[u8]) -> Result<(), VerifyError> {
    if blob.windows(4).any(|w| w == b"DSTW") {
        return Err(VerifyError::BadMagic);
    }
    Err(VerifyError::StwoVerify)
}
