//! SSLE ticket AIR (LEAN-8): public inputs are period||height||ticket (48 bytes).
//! Ticket is *not* a consensus address. Proposer id is only in the block
//! that reveals it. Trace limbs reconstruct the ticket object; FS mixes the
//! same bytes. Dummy-N / DSTW is rejected.

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

/// Wire kind: hide-until-block SSLE ticket.
pub const SSLE_KIND: &[u8; 4] = b"SSLE";

pub const TICKET_LEN: usize = 32;
/// period(8) || height(8) || ticket(32)
pub const SSLE_PI_LEN: usize = 8 + 8 + TICKET_LEN;
const LIMB_BYTES: usize = 3;
const N_LIMBS: usize = SSLE_PI_LEN / LIMB_BYTES;

type SsleComponent = FrameworkComponent<SsleEval>;

fn pack_limbs(pi: &[u8; SSLE_PI_LEN]) -> [u32; N_LIMBS] {
    let mut out = [0u32; N_LIMBS];
    for (i, limb) in out.iter_mut().enumerate() {
        let o = i * LIMB_BYTES;
        *limb = u32::from(pi[o]) | (u32::from(pi[o + 1]) << 8) | (u32::from(pi[o + 2]) << 16);
    }
    out
}

/// Ticket = SHA256(leanval/ssle/ticket/v1 || period || height || proposer).
/// Not an ed25519 address; callers must not treat it as one.
pub fn ssle_ticket(period: u64, height: i64, proposer: &[u8]) -> [u8; TICKET_LEN] {
    let mut h = Sha256::new();
    h.update(b"leanval/ssle/ticket/v1");
    h.update(period.to_be_bytes());
    h.update((height as u64).to_be_bytes());
    h.update(proposer);
    h.finalize().into()
}

fn pack_pi(period: u64, height: i64, ticket: &[u8; TICKET_LEN]) -> [u8; SSLE_PI_LEN] {
    let mut pi = [0u8; SSLE_PI_LEN];
    pi[0..8].copy_from_slice(&period.to_be_bytes());
    pi[8..16].copy_from_slice(&(height as u64).to_be_bytes());
    pi[16..48].copy_from_slice(ticket);
    pi
}

#[derive(Clone)]
struct SsleEval {
    log_n_rows: u32,
    limbs: [u32; N_LIMBS],
}

impl FrameworkEval for SsleEval {
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
    let info = SsleEval {
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

fn mix_public(channel: &mut Blake2sChannel, pi: &[u8; SSLE_PI_LEN]) {
    for chunk in pi.chunks_exact(8) {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(chunk);
        channel.mix_u64(u64::from_le_bytes(buf));
    }
}

fn header(pi: &[u8; SSLE_PI_LEN]) -> Vec<u8> {
    let mut out = Vec::with_capacity(10 + SSLE_PI_LEN);
    out.extend_from_slice(STWO_MAGIC);
    out.push(CIRCUIT_TYPE_STWO);
    out.push(CURVE_TYPE_M31);
    out.extend_from_slice(SSLE_KIND);
    out.extend_from_slice(pi);
    out
}

fn parse_header(proof: &[u8]) -> Result<([u8; SSLE_PI_LEN], usize), VerifyError> {
    if proof.len() > MAX_PROOF_BYTES {
        return Err(VerifyError::ProofTooLarge { len: proof.len() });
    }
    let hdr = 10 + SSLE_PI_LEN;
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
    if &proof[6..10] != SSLE_KIND {
        return Err(VerifyError::BadMagic);
    }
    let mut pi = [0u8; SSLE_PI_LEN];
    pi.copy_from_slice(&proof[10..hdr]);
    Ok((pi, hdr))
}

/// Prove an SSLE ticket for (period, height, proposer). Returns (ticket, proof).
pub fn prove_ssle(
    period: u64,
    height: i64,
    proposer: &[u8],
) -> Result<([u8; TICKET_LEN], Vec<u8>), VerifyError> {
    let ticket = ssle_ticket(period, height, proposer);
    let pi = pack_pi(period, height, &ticket);
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

    let component = SsleComponent::new(
        &mut TraceLocationAllocator::default(),
        SsleEval {
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
    Ok((ticket, out))
}

pub fn verify_ssle(
    proof: &[u8],
    period: u64,
    height: i64,
    ticket: &[u8; TICKET_LEN],
) -> Result<(), VerifyError> {
    let (got, hdr) = parse_header(proof)?;
    let want = pack_pi(period, height, ticket);
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
    let component = SsleComponent::new(
        &mut TraceLocationAllocator::default(),
        SsleEval {
            log_n_rows: LOG_N_ROWS,
            limbs,
        },
        QM31::zero(),
    );
    verify(&[&component], channel, commitment_scheme, stark_proof)
        .map_err(|_| VerifyError::StwoVerify)
}
