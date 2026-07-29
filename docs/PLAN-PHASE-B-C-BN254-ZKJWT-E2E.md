# Plan: Phase B (BN254 Groth16 verify) + Phase C (circom ZK-JWT e2e)

**Status:** Design / implementation plan (not code)  
**Date:** 2026-07-20  
**Depends on:** Phase A accepted (`CircuitType::Groth16`, empty-param Path A, `param_len=0` store/load)  
**Branch base:** `feat/zk-v2` @ `crates/cosmwasm`  
**Hard constraint:** Preserve Path A proof API integrity — no parallel verify path, no pure-Wasm Groth16 as primary authenticator path.

---

## 0. Executive summary (10 lines)

1. Phase A already lets BN254 circuits land in the host circuit cache with empty params and honest `prover_id=Groth16`.
2. Phase B fills `Bn254VerifyingKey::verify` with **host-side ark-groth16** (primary), keeping the same `proof_instance_verify` import.
3. Instance parsing must stop using `zkid as curve_id`; route from **loaded VK footer.curve_id** (or CircuitInfo metadata).
4. VK/proof wire formats are frozen: ark/snarkjs-compatible compressed layout documented below; footer still Phase A empty-param.
5. Registration remains wasmd/x/wasm: store circuit blob → assign **any** app `zkid` → CircuitInfo returns 72-byte `circuit_key`.
6. Phase C bridges circom JWT **public signals** (multi-Fr) into `terp-zkjwt`’s fixed 32-byte limb layout via an explicit codec.
7. Headscale-relevant fields (nullifier, claim, inclusion root, msg_bind) are split into **circuit-bound** vs **contract-policy-only**.
8. E2e: first a tiny square/multiplier golden through Path A unit tests; then suite `zk-host` with registered mock zkid + real circom fixtures.
9. Precompile host functions (bn254_add/mul/pairing) are a **future gas optimization**, not the Phase B primary verify path.
10. Success = green Path A golden + suite Authenticate happy path + documented PI map — still no claim of “production JWT security” until crypto review of nullifier/claim binding.

---

## 1. Proof API integrity invariants (non-negotiable)

These rules must hold after B and C. Any PR that breaks one is a reject.

### 1.1 Call graph (Path A only)

```text
contract (terp-zkjwt, feature zk-host)
  deps.api.proof_instance_verify(zkid, proof, instances)
    → host import do_proof_instance_verify
      → WasmQuery::CircuitInfo { zk_id } → CircuitInfoResponse.circuit_key [72]
      → Environment.circuit_loader(circuit_key)
            pinned → LRU → FS → split reconstruct (empty-param OK)
      → cold WasmQuery::Circuit only on miss
      → NEVER contract sandboxed KV for VK/circuit bytes
      → AnyInstance::parse(…, instances)   // MUST NOT require zkid == curve_id
      → AnyVerifyingKey::verify(proof, instances)
      → return 0 (ok) / 1 (fail)
```

**Source of truth today:** `packages/vm/src/imports.rs` (`do_proof_instance_verify`).

### 1.2 Keys and identity

| Concept | Size | Owner | Notes |
|---------|------|-------|-------|
| `zkid` | `u64` (host import currently `u32`) | wasmd AppState | App-assigned; **independent of curve_id** |
| `circuit_key` | 72 B | derived from footer | `param_key(36) ‖ vk_key(36)` |
| `param_key` / `vk_key` | 36 B | footer | `appstate_key_le ‖ SHA256(...)` |
| `appstate_key` | u32 BE | footer | `[prover_id, curve_id, k, 0]` |

**Production empty-param keys must use footer metadata:**
- `prover_id = 1` (Groth16), `curve_id = 4` (Bn254), `k = 0`
- `param_checksum = SHA256([])`
- Prefer `store_circuit(full_blob)` or `store_param_with_meta(&[], 1, 4, 0)` — **never** bare `store_param(&[])` zeros in genesis/prod.

### 1.3 Footer empty-param convention (Phase A, still binding)

```text
prover_id      = 1 (CircuitType::Groth16)
curve_id       = 4 (CurveType::Bn254)
k              = 0
i              = public Fr count (footer metadata; must match PI limbs for policy)
param_len      = 0
cs_len         = 0
vk_len         = |vk_body|
param_checksum = SHA256([])
vk_checksum    = SHA256(vk_body)
blob           = [vk_body | 80-byte footer]
```

### 1.4 What contracts may / must not do

| Allowed | Forbidden as primary path |
|---------|---------------------------|
| Host `proof_instance_verify` | Contract-local pure-Wasm Groth16 verify for auth |
| Structural envelope checks (`terp-zkjwt` instances layout) | Storing full VK in contract storage for verify |
| Policy on nullifier/claim/root after host returns true | Bypassing CircuitInfo / cache with ad-hoc host hooks |

### 1.5 Halo2 Path A regression

Pasta/Vesta (`curve_id=0`) and vote suite (`1|2|3`) remain on Plonkish. Phase B/C changes must be feature-gated (`bn254`) and not alter Halo2 deserialize/verify.

---

## 2. Phase B — Real BN254 Groth16 verify in the VM stack

### 2.1 Goal

Replace the stub in `packages/zk/src/curves/bn254.rs`:

```text
Err("BN254 verify not yet implemented")
```

with deterministic Groth16 verification that runs **inside** `AnyVerifyingKey::Bn254(...).verify`, so Path A automatically works for any registered BN254 circuit.

### 2.2 Primary recommendation: ark-groth16 on host

| Option | Pros | Cons | Decision |
|--------|------|------|----------|
| **A. ark-groth16 + ark-bn254 in `zk-cosmwasm` (host)** | One stack; matches snarkjs export tools; simple tests; already ark-bn254 on feature | Larger native binary; gas is wall-clock-based until tuned | **Primary for Phase B** |
| **B. Compose EIP-196/197 precompiles** (`bn254_add` / `scalar_mul` / `pairing_equality`) | Gas-aligned with ADR-001; differential testing later | Groth16 verify is multi-MSM + multi-pairing assembly; more code; contracts could call precompiles but **must not** become auth path | **Phase B.5 / gas follow-up** |
| **C. Pure-Wasm in contract** | No host work | ~370k gas; breaks integrity invariant | **Rejected** |

**Implement B as pure host crypto.** Precompiles stay available for contracts that need EC ops; they are **not** the Path A JWT verify engine until a separate gas-opt project reimplements ark-groth16 pairing product via precompiles **still behind the same host import**.

### 2.3 Where code lives (file-level)

| Layer | File | Work |
|-------|------|------|
| Crypto core | `packages/zk/src/curves/bn254.rs` | Parse VK/proof/PI; call ark-groth16; map errors |
| Dispatch | `packages/zk/src/circuits.rs` | Keep `AnyVerifyingKey::Bn254` → `vk.verify`; fix instance routing |
| Features | `packages/zk/Cargo.toml` | `bn254 = ["dep:ark-bn254", "dep:ark-groth16", "dep:ark-snark", "dep:ark-ff", "dep:ark-ec", "dep:ark-serialize"]` (pin ark 0.5 to match crypto-bn254) |
| VM import | `packages/vm/src/imports.rs` | Instance parse from **footer**, not zkid; optional gas schedule split |
| Gas | `packages/vm/src/environment.rs` | Add `bn254_proof_instance_verify_cost` (or scale existing linear cost by PI count + curve tag) |
| VM feature | `packages/vm/Cargo.toml` | Already: `bn254 = […, "zk-cosmwasm?/bn254"]` |
| Fixtures | `packages/zk/testdata/` + README | Golden square/multiplier VK+proof+publics + empty-param blob |
| Export tool | `packages/zk/src/bin/export_vk.rs` (or new `export_groth16_blob`) | Wrap snarkjs/ark VK into Phase A footer blob |

**Do not** change `do_proof_instance_verify`’s external ABI (`zkid, proof_ptr, instances_ptr`).

### 2.4 Wire formats (freeze early)

#### 2.4.1 Proof bytes (`payload.proof` / host `proof`)

**Recommended Phase B canonical format: ark-serialize compressed Groth16 proof**

```text
proof = ark_compress( A: G1 ) || ark_compress( B: G2 ) || ark_compress( C: G1 )
```

- Match `ark_groth16::Proof::<Bn254>::serialize_compressed`
- Reject uncompressed unless a version byte is introduced later

**Importer bridge (tooling, not on-chain):** snarkjs `proof.json` `{pi_a, pi_b, pi_c}` → convert with a small Rust/TS utility into ark compressed bytes. Document endianness: snarkjs uses big-endian field strings; ark uses little-endian Montgomery — conversion must use known-good paths (`ark-circom` / hand-tested vectors).

Optional later versioning:

```text
[0x01][ark_compressed_proof…]   // v1
```

Phase B can ship unversioned ark compressed if fixtures are monorepo-controlled; add version byte before external client reliance.

#### 2.4.2 Public inputs / instances bytes

**Host instances for BN254 = concatenation of 32-byte Fr limbs**, one per public signal, **in circuit declaration order**.

```text
instances = Fr_0 || Fr_1 || … || Fr_{n-1}
each Fr   = 32 bytes, big-endian scalar in [0, r)   // RECOMMEND BE for chain/JSON friendliness
```

**Endianness decision (product/crypto must confirm before coding):**

| Choice | Rationale |
|--------|-----------|
| **BE 32-byte Fr (recommended)** | Matches Ethereum/snarkjs `public.json` uint256 strings as fixed 32-byte BE; matches `terp-zkjwt` “32-byte limbs” mental model |
| LE ark native | Slightly less conversion at verify, worse DX for clients |

Plan assumes **BE**. Verifier converts BE → `ark_bn254::Fr` via `Fr::from_be_bytes_mod_order` (reject if ≥ r if we want strict Ethereum semantics — prefer **reject non-canonical** for auth).

`Bn254Instance::from_bytes` today accepts any 32-byte chunks without range check — **Phase B must enforce Fr < r**.

#### 2.4.3 VK body bytes (inside circuit blob)

**Recommended:** ark-serialize compressed `PreparedVerifyingKey` **or** raw `VerifyingKey` (prepare on first verify / on load).

| Approach | Pros | Cons |
|----------|------|------|
| Store raw `VerifyingKey`, prepare on load | Smaller tools surface | Prepare cost on cold path |
| Store `PreparedVerifyingKey` | Fast verify | Larger / less portable |

**Phase B pick:** store **raw** ark-compressed `VerifyingKey<Bn254>` as `vk_body`; prepare lazily and optionally cache inside `Bn254VerifyingKey` after first load (memory only — not required on disk).

Layout:

```text
vk_body = serialize_compressed(VerifyingKey {
  alpha_g1, beta_g2, gamma_g2, delta_g2, gamma_abc_g1[]
})
```

`footer.i` = `gamma_abc_g1.len() - 1` (public input count) — validate against `instances.len()/32` at verify.

#### 2.4.4 Circuit blob assembly (Phase A footer)

```text
blob = vk_body || footer_80
footer: prover_id=1, curve_id=4, k=0, i=n_public,
        param_len=0, cs_len=0, vk_len=|vk_body|,
        param_checksum=SHA256([]), vk_checksum=SHA256(vk_body)
circuit_key = footer.to_circuit_key()   // appstate BE([1,4,0,0]) …
```

Registration: `Cache::store_circuit(blob, true)` → returns `circuit_key` → wasmd maps `zkid → circuit_key`.

### 2.5 Instance routing fix (Phase A residual — **must** land in Phase B)

**Bug today** (`imports.rs` ~1123):

```rust
let i = AnyInstance::try_from_bytes(zkid, instances_bytes.as_slice())?;
```

This forces app `zkid == 4` for BN254. Production issuers will use arbitrary zkids (e.g. 42).

#### Concrete API change (preferred)

1. After VK is loaded (cache or cold path), read curve from the enum / footer:

```text
curve_id = match &vk {
  Vesta(_) => 0,
  Vote(v) => v.footer.curve_id,
  Bn254(b) => b.footer.curve_id, // always 4 for generic BN254
}
// or: vk.footer().curve_id via small trait
```

2. Replace call with:

```rust
AnyInstance::try_from_bytes(curve_id, instances_bytes)
// rename later to try_from_curve_bytes for clarity
```

3. Optionally extend `CircuitInfoResponse` (wasmd + std) with:

```rust
// optional additive fields (non_exhaustive already)
pub curve_id: Option<u8>,
pub prover_id: Option<u8>,
pub public_input_count: Option<u8>,
```

Use these only as **hints / validation** against loaded footer; **never** trust alone without footer check.

**Wasmd impact:** optional for Phase B unit tests (mock querier can ignore). Full chain: additive proto fields later; Path A works without them if footer is authoritative.

4. Add helper on `AnyVerifyingKey`:

```rust
fn curve_id(&self) -> u8;
fn prover_id(&self) -> u8;
fn public_input_count(&self) -> u8; // from footer.i
```

### 2.6 Verify algorithm (host)

```text
Bn254VerifyingKey::verify(proof, &[Bn254Instance]):
  1. Deserialize self.vk_bytes → VerifyingKey<Bn254>
  2. Prepare → PreparedVerifyingKey (or cache)
  3. Deserialize proof.0 → Proof<Bn254>
  4. Convert instance Fr limbs (BE) → Vec<Fr>; len must == footer.i
  5. Groth16::<Bn254, …>::verify_proof(&pvk, &proof, &public_inputs)
  6. Ok(()) if true else Err(VerifyFailed)
```

Error mapping:

| Failure | Host return to WASM |
|---------|---------------------|
| Parse / format errors | Prefer `VmError::zk_err` **or** map to `1` (invalid) — **pick one** and document. Recommendation: format errors → `VmError` (contract sees Err); crypto false → `Ok(1)`. |
| Valid parse, verify false | `Ok(1)` as today |
| Valid parse, verify true | `Ok(0)` |

**Do not** silently accept stub.

### 2.7 Gas accounting

Today (`GasConfig::halo2_proof_instance_verify_cost`): placeholder `base=1000, per_item=163` — **not** real for Halo2 or Groth16.

Phase B:

1. Rename conceptually to `proof_instance_verify_cost` **or** add parallel `bn254_groth16_verify_cost`.
2. Charge **before** crypto work (already pattern for host calls).
3. Suggested interim schedule (tune with criterion later):

```text
bn254_groth16_verify:
  base: ~2_000 * GAS_PER_US   // ~2ms class on M2 for tiny circuit — measure
  per_public_input: small additive
```

4. ADR precompile path (future): if verify is reimplemented via pairing_equality, gas becomes  
   `pairing_base + pairing_per_pair * N` with N≈(1 + public-dependent MSM still native).  
   **Not required for Phase B green.**

5. Document that SDK gas multiplier (wasmd ×100) applies outside cosmwasm-vm constants.

### 2.8 Registration path (wasmd / chain)

| Environment | How zkid is registered |
|-------------|------------------------|
| **Unit tests (cosmwasm-vm)** | Direct `Cache::store_circuit`; mock `CircuitInfo` returns computed `circuit_key`; optional install `circuit_loader` on `Environment` |
| **cw-orch / suite Mock** | Extend MockApi / MockQuerier to answer `WasmQuery::CircuitInfo` + `Circuit` with registered blob (today suite only asserts failure on unregistered zkid) |
| **Full chain (wasmd)** | Governance/keeper `StoreCircuit` (or existing ZK msg) stores blob; assigns next `zkid`; persists `zkid → circuit_key` in consensus state; node FS gets split files via wasmvm cache on store |

**Phase B alone does not require wasmd PR** if unit tests inject Path A. Phase C suite happy path **does** need mock CircuitInfo registry.

Concrete wasmd ownership (honest boundary):

- **In cosmwasm packages:** format, verify, cache, import, std query types.
- **In wasmd/x/wasm:** durable zkid index, genesis circuits, querier backends for Circuit/CircuitInfo.
- **In terp-rs suite:** mock registration helpers for e2e without full node.

### 2.9 Unit tests — Phase B success criteria

#### B-T1. Golden tiny circuit (mandatory)

Use a minimal R1CS (e.g. `x^2 === y` or snarkjs `multiplier2`):

1. Offline: generate `vk`, `proof`, `public.json` (1–2 publics).
2. Build Phase A blob; `store_circuit`.
3. `circuit_loader(key)` → `AnyVerifyingKey::Bn254`.
4. `verify` → **Ok** on golden; **Err/false** on flipped proof byte / wrong PI.
5. Second load hits pinned/memory (regression from Phase A).

#### B-T2. Instance routing (mandatory)

1. Register BN254 circuit under **zkid=42** (not 4).
2. Mock CircuitInfo returns correct 72-byte key.
3. `do_proof_instance_verify(42, proof, instances)` succeeds.
4. Prove that `try_from_bytes(42, …)` is **not** used as curve dispatch.

#### B-T3. Halo2 regression (mandatory)

`cargo test -p cosmwasm-vm --features zk --lib load_circuit`  
`halo2_store_circuit_still_uses_nonempty_params` still green.

#### B-T4. Negative format (mandatory)

- Truncated proof → fail  
- PI length ≠ `footer.i` → fail  
- Fr ≥ r → fail  
- Wrong curve footer with BN254 body → fail at deserialize

#### Phase B exit checklist

- [ ] `Bn254VerifyingKey::verify` real; no stub string in success path  
- [ ] Instance routing by footer.curve_id  
- [ ] Golden proof green via Path A (cache + import test)  
- [ ] zkid ≠ 4 works  
- [ ] Empty-param footer keys use `(1,4,0)`  
- [ ] Halo2 Path A green  
- [ ] Gas constant documented (even if provisional)  
- [ ] **No** claim that JWT circuit is integrated (that is Phase C)

---

## 3. Phase C — circom ZK-JWT → terp-zkjwt → e2e

### 3.1 Goal

Exercise a **real circom Groth16 JWT proof** (from `crates/zk-jwt`) through:

```text
prover artifacts → Phase A blob + proof + instances
  → host Path A verify
  → terp-zkjwt Authenticate (zk-host)
  → terp-authenticator-suite e2e (happy + negatives)
```

### 3.2 Product / crypto tension (must resolve in codec)

Two layouts exist:

**A. Circom JWT public signals** (order from `jwt-auth.circom` outputs + Solidity verifier; ~31 Fr for production params):

| Index (illustrative from JwtVerifier.t.sol) | Signal |
|---------------------------------------------|--------|
| 0 | `kid` |
| 1..ISS_FIELDS | `iss[]` packed |
| … | `publicKeyHash` |
| … | `jwtNullifier` |
| … | `timestamp` |
| … | `maskedCommand[]` |
| … | `accountSalt` |
| … | `azp[]` |
| … | `domainName[]` (circuit) / or packed into domain string off-circuit |
| last | `isCodeExist` |

Exact index map **must be generated from the compiled circuit’s `public` declaration** (snarkjs `verification_key.json` / r1cs), not only Solidity test comments — parameters (`maxCommandLength`, etc.) change field counts.

**B. terp-zkjwt contract PI** (`instances.rs` frozen for policy):

```text
nullifier(32) || claim_commitment(32)
  || [inclusion_set_root(32)]
  || [msg_bind(32)]
  || rest…
```

These are **not the same**. Phase C chooses one of:

| Strategy | Description | Recommendation |
|----------|-------------|----------------|
| **C1. Dual-layer instances** | Host verifies **full circom public vector**; contract policy reads **prefix** of same bytes **or** a parallel “policy view” | Prefer **host verifies full vector**; contract keeps parsing **its** layout from a **policy codec** of the same bytes |
| **C2. Wrapper circuit** | New circom that exposes only nullifier/claim/root/msg_bind as publics and keeps JWT internals private | Cleanest long-term; large engineering |
| **C3. Contract-only map** | Host verifies flattened Frs; contract maps selected Frs → nullifier/claim for nullifier store | Practical near-term if host sees full PI |

**Recommendation: C1+C3 hybrid**

1. **Host / Path A** always verifies **canonical circom public vector** as BE Fr limbs in circuit order (`footer.i = nPublic`).
2. **Contract** does not invent a second proof. It:
   - Calls `proof_instance_verify(zkid, proof, public_inputs)` with the **same** `public_inputs` bytes used for host verify.
   - Applies **policy codec** `CircomJwtPublics::decode(public_inputs)` → extracts nullifier, claim, optional root/msg_bind for storage checks.
3. Document that current `build_public_inputs(nullifier, claim, root, msg_bind)` is the **v1 policy layout** and may be a **subset/projection** only if a wrapper circuit is used; for stock `jwt-auth.circom`, replace builders with **circom-flat encoder**.

### 3.3 PI layout bridge (codec table)

Define in code (suggested new module):

`terp-zkjwt/src/circom_pi.rs` **or** shared `zk-jwt-codec` crate under cosmwasm/zk-jwt:

#### 3.3.1 Circom → host bytes

```text
public_inputs_host =
  concat_{j=0..nPublic-1}  be32( publicSignals[j] mod r )
```

#### 3.3.2 Policy extraction (stock jwt-auth — **illustrative; re-derive from build**)

| Policy field | Source signal(s) | Encoding into 32-byte limb |
|--------------|------------------|----------------------------|
| `nullifier` | `jwtNullifier` | BE Fr as 32 bytes (already field element) |
| `claim_commitment` | **Product decision** — not a native single signal | Options: (a) hash of `accountSalt` or `Poseidon(iss‖sub‖salt)` if circuit added; (b) temporary: `accountSalt` or `SHA256(domainName fields)` **off-circuit agreed**; (c) extend circuit |
| `inclusion_set_root` | **Not in stock jwt-auth** | Contract-only until circuit proves membership; optional PI append **not** verified by Groth16 unless circuit includes it |
| `msg_bind` | **Not in stock jwt-auth** | Same: policy-only **or** add to circuit / nonce command |
| `rest` | remaining Fr limbs | passed through for host |

**Headscale-relevant binding honesty:**

| Concern | Circuit-bound (Groth16) | Contract-only (policy) |
|---------|-------------------------|-------------------------|
| JWT signed by issuer keys | Yes (RSA verify in circuit) | — |
| Nullifier uniqueness | Yes (`jwtNullifier`) | Spend list `NULLIFIERS` |
| Email/domain membership | Partial (`domainName`, `azp`, `iss`) | Issuer allowlist strings |
| Inclusion set root (mesh ACL epoch) | **No in stock circuit** | `IssuerConfig.inclusion_set_root` check is **unauthenticated** unless circuit proves membership against that root |
| msg_bind (tx binding) | **No in stock circuit** | Host-computed bind compared to PI only if present; **forgeable** without circuit bind |
| claim_commitment owner link | Depends on definition | `CLAIMS` map + `require_registered_claim` |

**Product decision required:** either (1) accept Phase C demo with **nullifier + structural claim** only, documenting inclusion/msg_bind as policy-not-circuit; or (2) schedule a **circuit extension** (wrapper) before claiming Headscale-grade auth.

### 3.4 Artifact pipeline

```text
crates/zk-jwt/packages/circuits
  yarn / circom compile jwt-auth (or test circuit jwt-auth-test)
  snarkjs groth16 setup (powers of tau + zkey)   [trusted setup ceremony note]
  snarkjs zkey export verificationkey → vk.json
  input: helpers gen-input / tests fixtures
  snarkjs groth16 prove → proof.json + public.json
        ↓
Rust/TS converter (new):
  vk.json → ark VerifyingKey → Phase A blob (footer Groth16/BN254)
  proof.json → ark compressed proof bytes
  public.json → BE Fr limbs concat
        ↓
fixtures committed under:
  packages/zk/testdata/jwt_auth_*.{bin,proof,pub}
  and/or terp-authenticator-suite/tests/fixtures/zkjwt/
```

**CI practicality:** full jwt-auth is heavy. Prefer:

1. Phase C-demo: **jwt-auth-test.circom** (smaller) golden in CI.  
2. Nightly/manual: full jwt-auth.

Trusted setup: document that monorepo zkeys are **dev only**; production needs ceremony.

### 3.5 Contract / suite wiring

#### 3.5.1 terp-zkjwt

| Change | Detail |
|--------|--------|
| `IssuerConfig.zkid` | Already; use real registered id |
| `HostZkJwtVerifier` | Unchanged API; relies on host |
| `instances.rs` | Add `CircomPublicCodec` + version flag `pi_version: "circom-jwt-v1"` **or** keep layout and document projection |
| `circuit_ids` | Map `zkjwt.membership.v1` → expected nPublic / codec profile |
| Auth attributes | Emit `curve=bn254`, `prover=groth16`, `zkid`, `cache` if available |

Avoid dual verify: structural envelope still runs; crypto only via host.

#### 3.5.2 Mock registration for suite

Extend suite Mock / cw-orch backend:

```text
register_circuit(zkid, blob) 
  → MockQuerier CircuitInfo { circuit_key }
  → optional Circuit cold blob
  → install host circuit_loader backed by in-process Cache
```

Without this, `zk_host.rs` can only test **negative** unregistered paths (current state).

#### 3.5.3 E2e matrix

| Case | Expected |
|------|----------|
| Happy: valid proof, registered zkid, matching claim policy | Authenticate Ok; nullifier stored |
| Bad proof (bit flip) | InvalidProof |
| Wrong public signal | InvalidProof |
| Wrong inclusion root (if policy enforced) | InvalidProof / policy err |
| Claim mismatch (`CLAIMS`) when required | fail |
| Nullifier replay | fail |
| Unregistered zkid | fail (existing) |
| Halo2 zkid still works in parallel suite (if present) | no cross-talk |

### 3.6 What “flexes” the new curve in demos

- Logs/attrs: `prover_id=groth16`, `curve_id=4`, `circuit_key` hex prefix  
- Cache stats: first verify cold reconstruct; second verify pinned hit  
- Feature flags: chain capability `bn254` + `zk`  
- Metrics: gas for `proof_instance_verify` vs Halo2 baseline  
- Explicitly show **zkid=42** with curve_id=4 to demo decoupling

### 3.7 Phase C success criteria

- [ ] Fixture pipeline documented + at least one committed golden (test circuit)  
- [ ] Codec table code + tests (signal index → policy field)  
- [ ] Suite `zk-host` happy Authenticate with host verify true  
- [ ] Negatives above  
- [ ] Path A integrity still holds (no contract-side Groth16)  
- [ ] README honesty: which fields are circuit-bound  
- [ ] Halo2 / structural suite default still green without `zk-host`

---

## 4. Ordered work packages

Complexity: **S** < 1d, **M** 2–4d, **L** 1–2w (one engineer familiar with stack).

| # | Package | Phase | Deps | Size | Parallel? |
|---|---------|-------|------|------|-----------|
| **WP0** | Freeze formats doc (this file + testdata README endianness/PI) | B | Phase A | S | — |
| **WP1** | ark deps + `Bn254VerifyingKey` parse VK/proof + verify | B | WP0 | M | — |
| **WP2** | Tiny golden circuit fixtures + unit tests in `zk-cosmwasm` / `cosmwasm-vm` | B | WP1 | M | After WP1 skeleton |
| **WP3** | Instance routing fix (`footer.curve_id`) + zkid≠4 import test | B | WP1 | S | **Parallel with WP2** |
| **WP4** | Gas constant + optional `curve_id` on CircuitInfo (std only if needed) | B | WP3 | S | Parallel |
| **WP5** | Export tool: snarkjs/ark → Phase A blob | B/C | WP1 | M | Parallel with WP2 |
| **WP6** | Mock CircuitInfo + circuit_loader registration in suite/MockApi | C | WP3 | M | After B green |
| **WP7** | Circom PI codec + terp-zkjwt policy extraction | C | WP0 product decision | M | Parallel with WP6 |
| **WP8** | Circom fixture generation (test circuit) + convert | C | WP5, WP7 | M–L | — |
| **WP9** | Suite e2e happy + negatives | C | WP6–8 | M | — |
| **WP10** | Optional: wasmd StoreCircuit genesis wiring for chain demo | C+ | WP5 | L | Separate track |
| **WP11** | Optional: precompile-backed verify / gas tighten | B.5 | WP1, ADR | L | After demo |

### Suggested PR / commit series (no PR opened by this plan)

1. `feat(zk): ark-groth16 Bn254VerifyingKey::verify + golden square`  
2. `fix(vm): instance parse by footer.curve_id (zkid decoupling)`  
3. `feat(zk): export_groth16_blob tool + empty-param footer`  
4. `feat(suite): mock circuit registry for zk-host`  
5. `feat(zkjwt): circom public codec + fixtures`  
6. `test(suite): zk-host e2e Authenticate BN254 JWT (test circuit)`  
7. (later) wasmd / genesis  
8. (later) gas + precompile composition

---

## 5. Risks & integrity traps

| Risk | Impact | Mitigation |
|------|--------|------------|
| **Wrong Fr endianness** | Accept invalid / reject valid proofs | Golden vectors from snarkjs; cross-check Solidity verifier accept set |
| **PI reordering** | Silent wrong policy binding | Generate index map from compiled r1cs; freeze in codec version |
| **zkid==curve_id coupling left in** | Production zkid registration broken | WP3 mandatory; test zkid=42 |
| **`store_param(&[])` zero appstate** | Key mismatch vs footer `(1,4,0)` | Only `store_circuit` / `store_param_with_meta(1,4,0)` in docs & genesis |
| **Structural path “success” mistaken for crypto** | False demo | Suite asserts host return true with bit-flip negative |
| **Contract-only inclusion root** | Policy thinks membership proved | Document; plan circuit extension |
| **msg_bind not in circuit** | Replay across messages | Document; optional circuit nonce bind |
| **Trusted setup** | Security | Dev zkeys labeled; prod ceremony checklist |
| **ark version skew** | Serialize mismatch | Pin ark 0.5 everywhere (crypto-bn254, zk-cosmwasm) |
| **Gas DoS** | Underpriced verify | Measure; conservative base until benchmark |
| **Cold path pulls full Circuit over querier** | Performance | Ensure pin after first verify; suite checks cache hits |
| **Footer.i mismatch** | Ambiguous PI count | Enforce `instances.len()/32 == footer.i` |
| **Halo2 breakage** | Regressions | Always run feature `zk` without `bn254` tests in CI |
| **Double verification semantics** | `Ok(1)` vs `Err` inconsistency | Document mapping table §2.6 |

---

## 6. How orchestrator / product will review

### 6.1 Commands (Phase B)

```bash
cd /Users/returniflost/abstract/terp-core/crates/cosmwasm

# BN254 verify + golden
cargo test -p zk-cosmwasm --features bn254 --lib bn254
cargo test -p cosmwasm-vm --features zk,bn254 --lib bn254_

# Instance routing / Path A import (once tests exist)
cargo test -p cosmwasm-vm --features zk,bn254 --lib proof_instance

# Halo2 regression
cargo test -p cosmwasm-vm --features zk --lib load_circuit
cargo test -p cosmwasm-vm --features zk --lib halo2_store_circuit
```

### 6.2 Commands (Phase C)

```bash
# Suite host wiring + e2e (after mock registry)
cargo test -p terp-authenticator-suite --features zk-host --test zk_host

# Structural suite must stay default-green
cargo test -p terp-authenticator-suite

# Optional fixture rebuild (document exact script in WP8)
# cd crates/zk-jwt/packages/circuits && yarn test / circom ...
```

### 6.3 Fixtures expected

| Path | Content |
|------|---------|
| `packages/zk/testdata/README.md` | Endianness, footer, PI rules |
| `packages/zk/testdata/square_vk.bin` (name TBD) | Phase A blob Groth16 |
| `packages/zk/testdata/square_proof.bin` | ark compressed proof |
| `packages/zk/testdata/square_public.bin` | BE Fr limbs |
| Suite fixtures (Phase C) | JWT test-circuit proof+pub+blob |

### 6.4 Definition of “green e2e”

1. Authenticate with real Groth16 JWT **test-circuit** proof returns success under `zk-host`.  
2. Same proof with one flipped byte fails.  
3. Nullifier replay fails.  
4. Host path used (attrs / error strings not structural-only).  
5. Cache second call does not depend on contract KV.  
6. Halo2 and default structural suite still pass.

### 6.5 What is **not** required for “green e2e”

- Mainnet trusted setup  
- Full production jwt-auth size in CI  
- wasmd genesis (nice for chain demo, WP10)  
- Precompile gas parity with Ethereum  

---

## 7. Open questions (product / crypto before coding)

1. **Public Fr endianness:** confirm **BE** vs ark LE for host instances.  
2. **claim_commitment definition** for stock circom JWT: which signal(s) / hash?  
3. **inclusion_set_root / msg_bind:** policy-only for demo, or block on circuit extension?  
4. **nPublic / parameter set:** which compiled `jwt-auth` config is “v1” (max lengths)?  
5. **Error semantics:** format errors → `VmError` vs `Ok(1)`?  
6. **Proof versioning:** unversioned ark compressed OK for monorepo-only Phase B?  
7. **Wasmd timeline:** is chain demo in scope of first e2e or suite-mock only?  
8. **ark-circom vs hand conversion** for snarkjs JSON?  
9. **zkid type width:** host uses `u32` today; std/wasmd use `u64` — align?  
10. **PreparedVerifyingKey on disk vs raw VK** final choice after fixture size check.

---

## 8. First concrete command for the next implementer

After reading this plan, start **WP1 skeleton** by confirming ark deps resolve on the branch:

```bash
cd /Users/returniflost/abstract/terp-core/crates/cosmwasm
# Read stub + Path A import once more, then add ark-groth16 to packages/zk and try:
cargo check -p zk-cosmwasm --features bn254
```

If that fails on ark feature resolution, fix `packages/zk/Cargo.toml` before writing verify logic. Next code change after green check: implement `Bn254VerifyingKey::verify` against a hand-built tiny golden (WP1–WP2), **then** WP3 instance routing so e2e is not stuck on zkid=4.

---

## 9. Traceability

| Residual from Phase A | Addressed in |
|-----------------------|--------------|
| Instance routing by zkid | §2.5 WP3 |
| Empty param keys / meta | §1.2, §2.4.4 |
| PI layout bridge | §3.2–3.3 WP7 |
| Path A integrity | §1 entire |
| Stub verify | §2 WP1–2 |
| Circom wire | §3 WP5–9 |

**Related docs:**

- `docs/HANDOFF-BN254-PARAM-CACHE-PHASE-A.md`  
- `ZK_PROOF_VERIFICATION_ARCHITECTURE.md`  
- `packages/zk/testdata/README.md` (empty-param footer)  
- `terp-zkjwt/JWT_AUTH_FLOW.md`  
- `crates/junoclaw/docs/ADR-001-BN254-PRECOMPILE.md`  

---

*End of plan. Implementers should update checkboxes in §2.9 and §3.7 as work lands; do not expand scope into authenticator matrix redesign or pure-Wasm verify.*
