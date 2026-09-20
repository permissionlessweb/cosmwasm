# Locked decisions for Phase B + C (verifiable exercise)

**Date:** 2026-07-20  
**Authority:** Product/orchestrator (authenticator suite + Headscale path awareness)  
**Supersedes open questions in** `PLAN-PHASE-B-C-BN254-ZKJWT-E2E.md` § open questions  
**Implementer:** execute against these; do not re-litigate without a new decision note.

---

## D1. Fr limb endianness → **BE (big-endian)**

- Host instances = concat of 32-byte **big-endian** Fr limbs, circuit public order.
- Reject non-canonical Fr (≥ r) on auth path.
- Rationale: snarkjs/Ethereum public.json, matches terp-zkjwt “32-byte limb” DX.
- Conversion at verify: BE → `ark_bn254::Fr` via `from_be_bytes_mod_order` with range check.

## D2. claim_commitment mapping (demo codec v1)

Stock circom `jwt-auth` has **no** single `claim_commitment` signal. Contract policy still needs a 32-byte claim limb for RegisterClaim.

| Policy field | Demo source (v1) | Notes |
|--------------|------------------|-------|
| `nullifier` | `jwtNullifier` public Fr → BE 32 bytes | Circuit-bound |
| `claim_commitment` | `accountSalt` public Fr → BE 32 bytes | Demo binding; document as **codec v1**, not production Poseidon(iss‖sub‖salt) |
| Future | Replace with circuit Poseidon commitment when circuit extended | JWT_AUTH_FLOW.md long-term |

For **tiny golden** (square/multiplier) e2e that does not use JWT:

- Use PI layout that host verifies as full Fr vector.
- Contract suite path may use a **minimal wrapper Authenticate** only if needed; primary flex is Path A unit/import tests + suite mock registry with square circuit.

## D3. inclusion_set_root / msg_bind → **policy optional for first ship**

Stock circuit does **not** prove inclusion root or msg_bind.

**First verifiable exercise:**

- Issuer for BN254 demo: `inclusion_set_root: None` (no root check).
- Do **not** put msg_bind in public_inputs unless the golden circuit exposes it.
- Document clearly: Headscale-grade membership root + tx bind = **circuit extension (later)**; first e2e proves **VM curve + host Groth16 + nullifier spend path**.

Structural suite tests that use inclusion root remain on **structural** verifier (default features).

## D4. Format errors vs crypto false → **split mapping**

| Failure | Host → contract |
|---------|-----------------|
| Parse / format / Fr≥r / PI length mismatch | `VmError` / host Err → contract sees error (not silent accept) |
| Valid parse, Groth16 returns false | `Ok(1)` (invalid proof) |
| Valid parse, Groth16 true | `Ok(0)` |

Rationale: contracts and tests can distinguish “broken client” from “wrong witness”.

## D5. Registration scope → **suite/mock + cosmwasm-vm first; wasmd later**

- **In scope now:** cosmwasm-vm Path A tests + terp-authenticator-suite mock CircuitInfo/Circuit + circuit_loader.
- **Out of scope now:** wasmd genesis StoreCircuit (WP10 later).

## D6. Primary verify engine → **host ark-groth16**

- Precompiles (ADR-001) = B.5 gas follow-up only.
- No pure-Wasm Groth16 in authenticator.

## D7. Instance routing → **footer.curve_id (mandatory in Phase B)**

- After VK load, `AnyInstance::try_from_bytes(vk.curve_id(), …)`.
- Test with **zkid=42**, curve_id=4.

## D8. What “green verifiable exercise” means (ship bar)

### Must have (implement now)

1. **Phase B**
   - Real `Bn254VerifyingKey::verify` (no stub success path)
   - Golden **tiny** circuit (square or multiplier2): store Phase A blob, Path A load, verify true; bit-flip false
   - Instance routing zkid≠4
   - Halo2 regression green

2. **Phase C light (workflow flex)**
   - Mock circuit registry for suite/vm so `proof_instance_verify` can succeed
   - At least one end-to-end test that is **not** “unregistered zkid fails”:
     - Preferred: cosmwasm-vm `do_proof_instance_verify` integration test with mock querier + golden
     - Plus: suite `zk-host` test that registers golden BN254 circuit and either:
       - calls host verify via zk-jwt Authenticate with adapted PI, **or**
       - if full JWT fixtures are too heavy, document suite test that exercises host verify with **square golden** through a thin test hook / mock IssuerConfig zkid
   - Default `cargo test -p terp-authenticator-suite` still green (structural)

### Nice if low-cost, else follow-up

- Circom jwt-auth-test fixtures + codec extracting nullifier/accountSalt
- Full jwt-auth size circuit

### Explicitly not required for this ship

- Production trusted setup
- wasmd chain registration
- Circuit proving inclusion root / msg_bind
- Claiming Headscale production security

---

## Implementation priority (best strategy)

```text
WP1 → WP3 (parallel WP2 golden) → WP4 light gas
     → WP6 mock registry
     → Path A e2e (vm + suite zk-host happy path on square golden)
     → [optional] WP7/WP8 JWT test-circuit codec if fixtures fit time
```

**Integrity:** only Path A call graph; empty-param footer `(prover_id=1,curve_id=4,k=0)`; production keys via `store_circuit` / `store_param_with_meta(1,4,0)`.

---

## Circom codec L1 shipped (2026-07-20)

Gateway-style pyramid twin in `terp-zkjwt`:

- `claim_is_sound` / `MIN_SOUND_CLAIM_RICHNESS` (8)
- fixtures: full vs sparse fail-closed
- suite: `--test zk_jwt_circom_codec`
- docs: `terp-zkjwt/CIRCOM_CODEC_PYRAMID.md`

Real snarkjs proof bytes still optional (L2 crypto = square Path A; L3 = o-line HS).

## Review commands (after implement)

```bash
cd .
cargo test -p zk-cosmwasm --features bn254 --lib
cargo test -p cosmwasm-vm --features zk,bn254 --lib bn254_
cargo test -p cosmwasm-vm --features zk,bn254 --lib proof_instance_verify_bn254
cargo test -p cosmwasm-vm --features zk --lib halo2_store_circuit
cargo test -p cosmwasm-vm --features zk --lib load_circuit

cd terp-rs
cargo test -p terp-authenticator-suite
cargo test -p terp-authenticator-suite --features zk-host --test zk_host
```

## Phase B ship status (2026-07-20)

- [x] Real ark-groth16 `Bn254VerifyingKey::verify` (D6)
- [x] BE Fr + reject ≥ r (D1)
- [x] Format → Err / VerifyFailed → Ok(1) / true → Ok(0) (D4)
- [x] Instance routing by `vk.curve_id()`; zkid=42 Path A tests (D7)
- [x] Golden fixtures `packages/zk/testdata/square_*.bin`
- [x] Suite `zk-host` happy path via `register_test_circuit` (mock registry; real crypto in cosmwasm-vm)
- [ ] Circom jwt-auth fixtures (deferred)
- [ ] wasmd registration (deferred)
