# Handoff: BN254 / empty-param cache modularity (Phase A)

**Date:** 2026-07-20  
**From:** Authenticator-suite + zk-jwt integration checkpoint (terp-rs session)  
**To:** CosmWasm VM / zkcw-params team (`feat/zk-v2`, prior session `zkcw-params` / `019f4cd9-…`)  
**Review:** After Phase A lands, orchestrator reviews diff + tests — **do not start full circom JWT wire yet**

---

## Why this handoff exists

Authenticator suite is stable through Headscale policy + host-path smoke:

- `require_registered_claim` e2e
- eth personal_sign goldens
- `zk-host` feature → `proof_instance_verify` wiring

**Next product demo:** real **circom ZK-JWT** (`crates/zk-jwt`, BN254 Groth16) through the custom VM.

That will fail for the wrong reasons unless the **circuit parameter cache is modular enough for curves that do not share Halo2-style reusable params**. You already built Path A (host cache + CircuitInfo 72-byte key). Teammates already flagged:

> `store_param` builds `appstate_key = [0, 0, k, 0]` which only matches Plonkish+Pasta. Another proving system or curve needs `prover_id` + `curve_id` (or empty-param path).

That flag is now the **blocker**. Fix it before wiring `crates/zk-jwt`.

---

## Prior conversation / branch map (resume from here)

| Artifact | Location |
|----------|----------|
| Params worktree session | `~/.grok/sessions/.../modules-crates%2Fzkcw-params/019f4cd9-c2f2-7923-9509-09ef0ee788b9` (cwd: `~/.grok/worktrees/modules-crates/zkcw-params`) |
| CosmWasm cache tuning session | `.../crates%2Fcosmwasm/019f6488-d74b-72a1-b581-fa8f926c8061` — title **ZK Cache Tuning Task** |
| Branch | `feat/zk-v2` @ cosmwasm (`13104fd6c proof instance verify`, prior: `6c90f9042 checkpoint: grok tune footer + cache for params`) |
| Upstream monorepo branch | `zkvm-multicurve` (terp-core) — BN254 host wiring tasks |
| Cache tuning task doc | `docs/ZK-CACHE-TUNING-TASK.md` |
| Architecture | `ZK_PROOF_VERIFICATION_ARCHITECTURE.md` |
| NEW_SUPPORT notes | `packages/zk/NEW_SUPPORT.md` (reuse params, avoid double storage) |
| ADR BN254 precompiles | `crates/junoclaw/docs/ADR-001-BN254-PRECOMPILE.md` |
| Circom JWT source (later) | `crates/zk-jwt` (zk-email jwt-tx-builder) |
| Contract host consumer | `terp-rs/.../terp-zkjwt` + suite feature `zk-host` |

**Do not re-open authenticator matrix work.** Suite is the consumer; **you own VM + zk-cosmwasm cache/dispatch.**

---

## Halo2 vs BN254 (exact friction)

### Halo2 / Plonkish (curve_id 0–3) — what you built

```text
circuit blob = [params | cs+vk body | footer]
circuit_key  = param_key(36) || vk_key(36)     // 72 bytes
param_key    = appstate_key_le(4) || SHA256(params)
appstate_key = BE([prover_id, curve_id, k, 0])
store_param()  ← assumes halo2 k in first 4 bytes (u32 LE)  ⚠️
```

Reusable IPA params are large and correctly split into `zk_param/` + `zk_vk/` + monolithic `zk_circuit/`.

### BN254 / Groth16 (curve_id 4) — circom JWT

| Halo2 assumption | Groth16 reality |
|------------------|-----------------|
| Shared reusable `Params` | **No** Halo2-style param blob |
| CS serialized into VK body | Circuit-specific Groth16 VK only |
| `store_param` needs `k` header | **No** `k` in VK bytes |
| `Params = halo2::Params` | Today: `Params = ()` in `packages/zk/src/curves/bn254.rs` |
| `CircuitType::Plonkish` only | BN254 still mis-tagged as Plonkish |

Current stub:

```rust
// packages/zk/src/curves/bn254.rs
// verify → Err("BN254 verify not yet implemented")
// type Params = ();
// from_split_bytes: concatenates param||vk_body into raw vk_bytes
```

**Phase A does NOT require implementing Groth16 verify.** It requires store/load of curve_id=4 with **empty params** through the same cache Path A uses.

---

## Phase A — implement now (scope lock)

### A1. Footer / CircuitType honesty

- Add `CircuitType::Groth16` (or equivalent non-Plonkish prover_id).
- Stop mapping `AnyVerifyingKey::Bn254` → `CircuitType::Plonkish`.
- Document footer convention for Groth16:

```text
prover_id  = Groth16
curve_id   = 4
k          = 0 (unused)
i          = public input field-element count
param_len  = 0
cs_len     = 0
vk_len     = |vk_bytes|
param_checksum = SHA256(empty)  // or fixed sentinel — pick one, document, test
vk_checksum    = SHA256(vk_bytes)
```

### A2. Make param store curve-aware / empty-param safe

**Problem:** `Cache::store_param` only works for Halo2 k-header → `appstate_key = [0,0,k,0]`.

**Fix options (prefer explicit):**

1. **Preferred:** `store_param` takes footer-derived metadata (`prover_id`, `curve_id`, `k`) or accepts a full 36-byte `param_key` already derived from footer.
2. **Minimal:** When storing a circuit with `param_len == 0`:
   - Write empty (or sentinel) file under `zk_param/{param_key}.bin`
   - Skip halo2 k parse entirely
   - `from_split_bytes` / circuit_loader treat empty params as valid for curve_id=4

Do **not** force BN254 to invent fake 4-byte k headers.

### A3. circuit_loader + cold path

File: `packages/vm/src/cache.rs` (`circuit_loader`, split-file reconstruct).

- If `footer.param_len == 0`: allow missing **or** empty param file; do not error on “param too short for k header”.
- `AnyVerifyingKey::from_split_bytes(param, vk_body, footer)` for curve 4 already concatenates — keep that; ensure empty param works.
- Warm memory/pinned caches after reconstruct.

### A4. Instance dispatch note (fix if easy, file if not)

`AnyInstance::try_from_bytes` currently keys on **zkid** cast to curve id (`4u32` → Bn254). That is fragile if app assigns zkid≠4 for a BN254 circuit.

**Better:** instance parse from footer.curve_id (or CircuitInfo metadata), not zkid. If out of scope for Phase A, leave a clear TODO and use zkid=4 only in tests.

### A5. Tests (must pass for handoff acceptance)

In `packages/vm` and/or `packages/zk` with features `zk` + `bn254`:

1. **Build synthetic BN254 footer** with `param_len=0`, random/nonempty vk body, correct checksums.
2. **store_circuit** (or split store) succeeds.
3. **circuit_loader(circuit_key)** returns `AnyVerifyingKey::Bn254`.
4. **Second load hits memory/pinned** (cache warm).
5. **verify** may still return stub error `"BN254 verify not yet implemented"` — assert dispatch, **not** crypto success.
6. Regression: existing Halo2/toy/no_rick path still stores with **non-empty** params.

### A6. Explicitly out of scope (do later)

| Phase | Work |
|-------|------|
| **B** | Implement `Bn254VerifyingKey::verify` (ark-groth16 or precompile composition) + tiny golden proof |
| **C** | Wire `crates/zk-jwt` circom PI → `terp-zkjwt` public_inputs layout + suite e2e |

Do not expand into wasmd genesis unless required for unit tests. Path A host cache is enough for Phase A.

---

## Known residual from prior audits (fix if you touch those lines)

From `docs/ZK-CACHE-TUNING-TASK.md`:

- 🔴 `remove_circuit` must delete split `zk_param/` + `zk_vk/` files  
- 🔴 Document pinned-circuit eviction / keeper must unpin  
- 🟡 Avoid double `check_circuit`  
- Prefer `VmError::zk_err` for ZK failures  

If timeboxed, Phase A empty-param path **before** full audit cleanup.

---

## Stack reminder (Path A — already decided)

```text
proof_instance_verify(zkid, proof, instances)
  → WasmQuery::CircuitInfo → 72-byte circuit_key
  → host CircuitLoader (pinned → LRU → FS → split reconstruct)
  → cold WasmQuery::Circuit only on miss
  → NEVER contract sandboxed KV for circuit bytes
```

Hot path must not pull full circuit over querier when cache hits. Empty-param BN254 must still participate in this path.

---

## Success criteria (review gate)

- [x] `CircuitType` distinguishes Groth16 (or prover_id ≠ Plonkish for BN254)
- [x] `param_len=0` BN254 circuit store/load via Path A without Halo2 k parse
- [x] Unit tests green: `cargo test -p cosmwasm-vm --features zk,bn254 …` (and zk-cosmwasm bn254)
- [x] Halo2 regression still green
- [x] Short note in `docs/` or PR description: footer convention for empty params
- [x] **No** claim that Groth16 verify works (stub OK)

### Empty-param footer (documented in `packages/zk/testdata/README.md` + `footer.rs`)

```text
prover_id=1 (Groth16), curve_id=4, k=0, param_len=0, cs_len=0
param_checksum = SHA256([])
vk_checksum    = SHA256(vk_bytes)
```

### Residual TODO

- `AnyInstance::try_from_bytes` still keys on zkid cast to curve id — prefer
  footer.curve_id / CircuitInfo for instance parse (filed in `circuits.rs`).

When done: report paths changed + test commands + any open questions on instance/zkid coupling. Orchestrator will review before Phase B.

---

## Suggested first commits

1. `feat(zk): CircuitType::Groth16 + footer docs for empty params`  
2. `fix(vm): store/load circuits with param_len=0 (BN254 path)`  
3. `test(vm): bn254 empty-param cache round-trip`

---

## Consumer context (do not block on this)

`terp-zkjwt` Authenticate with `IssuerConfig.zkid` calls host verify. Suite:

```bash
cargo test -p terp-authenticator-suite
cargo test -p terp-authenticator-suite --features zk-host --test zk_host
```

Structural suite stays default. Real circom proof is Phase C after your Phase A (+ later Phase B).
