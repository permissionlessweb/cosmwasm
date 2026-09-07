# Gnat Re-Proposal Readiness Report

> **Date:** 2026-07-15  
> **Strategy:** Fix audit findings → build minimal demo → submit with working code  
> **Related:** `ZK-CACHE-TUNING-TASK.md`, `zk-cache-benchmark-review.md`

---

## Executive Summary

| Phase | Status | Block proposal? |
|-------|--------|-----------------|
| **1. Fix 🔴 audit findings** (ZK cache) | ✅ **Done** | No |
| **2. Minimal Crosslink demo** | ⚠️ **Partial** — e2e test exists, not wired to zebra + relayer | **Yes** |
| **3. Benchmark evidence** | ⚠️ **Partial** — harness + initial numbers; full clean run pending | No (strengthens) |
| **4. Write proposal** | 🔲 Not started | — |

**Recommendation:** Do **not** submit until Phase 2 demo is runnable end-to-end. Phase 1 is complete and should be committed before submission.

---

## Phase 1: ZK Cache Audit Fixes ✅

Both critical bugs that would fail code review are **fixed** on `feat/zk-v2`:

### 🔴 `remove_circuit` split-file cleanup

- **Was:** Only removed `zk_circuit/{key}.bin`; `zk_param/` and `zk_vk/` orphaned forever.
- **Now:** Extracts `param_key` / `vk_key` from 72-byte circuit key; removes all three on-disk artifacts.
- **Test:** `remove_circuit_works` asserts param, vk, and circuit paths absent after removal.

### 🔴 Pinned memory unbounded growth

- **Was:** `HashMap` with no eviction — circuits pinned until manual `unpin_circuit`.
- **Now:** LRU eviction at **100 circuits** or **100 MiB** total pinned circuit size.
- **File:** `packages/vm/src/modules/pinned_memory_cache.rs`

### Medium fixes (bonus credibility)

- Eliminated duplicate `check_circuit` on store path
- Standardized `VmError::zk_err` for ZK load failures

**Action:** Commit and merge `feat/zk-v2` audit fixes before proposal links to the repo.

---

## Phase 2: Minimal Crosslink Demo ⚠️

The committee rejected the first proposal as speculative. The re-proposal needs: *we already built it; funding productionizes it.*

### Target demo (Milestone 1 scope)

**Updated strategy (2026-07-15):** Extend **Mercury** + **IBCv2 relayer** instead of a standalone `crosslink-relayer` binary. Design choices are adopted only when verifiable via existing or new tests.

```
zebrad (crosslink) ──light blocks──► Mercury (extended)
                                        │
                    IBCv2 relayer ◄──────┘  client-update path
                         │
                         ▼
              terpd (08-wasm crosslink LC)
              MsgCreateClient / MsgUpdateClient
```

Hermes/CosmosRly remain for Cosmos↔Cosmos **packet** relay. Crosslink **client updates** ride the IBCv2 relayer + Mercury pipeline.

### Relayer extension points (test-backed)

| Layer | Location | Tests today | Crosslink extension |
|-------|----------|-------------|---------------------|
| `Relayer` trait | `ict-rs/ict-rs/src/relayer/mod.rs` | `relayer_tests.rs` (Hermes, CosmosRly cmd wiring) | Add `update_wasm_client()` or IBCv2 client-update hook |
| `RelayerSuite` | `terp-rs/tests/src/suite/relayer.rs` | Used in multichain IBC tests | Plug Mercury/IBCv2 sidecar into `TerpSidecar` registry |
| IBCv2 example | `ict-rs/examples/ibc_v2.rs` | Stub (1-line) | Implement client.v2 update flow |
| Wasm LC example | `ict-rs/examples/ibc_wasm_lc.rs` | Stub | Wire `MsgUpdateClient` for 08-wasm |
| Crosslink e2e | `terp-rs/tests/tests/crosslink_light_client.rs` | 5 scenarios, `#[ignore]` | Ground truth for header bytes + client state |
| IBCv2 chain API | `terp-rs/api/zod/ibc-core-client-v2.ts` | Proto types + `allowed_relayers` | Permissioned relayer list for crosslink updates |

**Verification principle:** No new relayer behavior ships without a test that proves it — unit test in `crosslink-light-client`, e2e in `crosslink_light_client.rs`, or integration test in `ict-rs` extending `relayer_tests.rs`.

### What exists in `terp-rs`

| Component | Path | Status |
|-----------|------|--------|
| Light client library | `crates/crosslink/light-client/` | ✅ Unit tested |
| 08-wasm contract | `contracts/light-clients/cw-ics08-wasm-crosslink/` | ✅ Built artifact |
| Wasm checksum | `33d506ee481a06a14668bc5f79cc0a1363cf1f3bcc214e82deaf2a69b11f7d33` | ✅ In `TEST.md` |
| E2E test (5 scenarios) | `tests/tests/crosslink_light_client.rs` | ✅ `#[ignore]` — needs Docker |
| Real ed25519 signing | `signed_header_update()` | ✅ Fixed (fat_pointer placement) |
| Zebra test vectors | `load_test_block` / `deserialize_pos_test_block` | ❌ **Planned in `_plans/` but not in code** |
| Demo orchestration script | — | ❌ Missing |
| Mercury + IBCv2 relayer extension | New strategy | 🔲 **Design phase** — extend, don't greenfield |

### What exists in `zebra-crosslink`

| Component | Path | Status |
|-----------|------|--------|
| Local demo (terpd + zebrad + viz) | `scripts/spawn-local-demo.sh` | ✅ Visualization only |
| Test vectors | `crosslink-test-data/test_pos_block_*.bin` | ✅ |
| Zebra integration tests | `zebrad/tests/crosslink.rs` | ✅ |

### What Hermes covers (and does not)

Hermes in `tests/tsh/polytone/` handles **Cosmos ↔ Cosmos IBC packet relay**. Crosslink **client updates** go through **Mercury → IBCv2 relayer**, not Hermes. Proposal language should distinguish packet relay from client-update relay.

### Gap checklist (2-week demo sprint)

- [ ] **Wire zebra test vectors** into `crosslink_light_client.rs` (`deserialize_pos_test_block` from `crosslink-test-data/`)
- [ ] **Un-ignore e2e** and confirm green: `cargo test -p terp-scripts --test crosslink_light_client -- --ignored --nocapture`
- [ ] **Extend Mercury** with zebra light-block ingestion (poll/fetch → `CrosslinkHeader`)
- [ ] **Extend IBCv2 relayer** with wasm client update path (`MsgUpdateClient` for `10-wasm-*`)
- [ ] **Add ict-rs test** extending `relayer_tests.rs` or new `crosslink_relayer_test.rs` proving update round-trip
- [ ] **Flesh out** `ict-rs/examples/ibc_wasm_lc.rs` as runnable demo (currently stub)
- [ ] **Demo script** tying `spawn-local-demo.sh` + Mercury + IBCv2 relayer + create-client
- [ ] **Record demo**: screen capture or log output for proposal appendix

### Run commands (today)

```bash
# Rebuild wasm (optimizer 1.86 only)
cd crates/terp-rs && ./scripts/build-crosslink-wasm.sh

# E2E (Docker Terp, synthetic headers + real ed25519 sigs)
cd crates/terp-rs/tests
cargo test -p terp-scripts --test crosslink_light_client -- --ignored --nocapture

# Local zebra + terp viz (no IBC client lifecycle)
cd crates/zebra-crosslink
./scripts/spawn-local-demo.sh build-zebra && ./scripts/spawn-local-demo.sh start
```

---

## Phase 3: Benchmark Evidence ⚠️

See **`docs/zk-cache-benchmark-review.md`** for full detail.

**Captured today (release, `no_rick`):**

| Metric | Value | Target |
|--------|-------|--------|
| Hot load (pinned) | 3.14 µs | < 1 µs |
| Warm load (LRU) | 4.71 µs | < 5 µs ✅ |
| Cold load (first touch) | 16.60 ms | ms-scale OK (pinned at store) |
| Store (persist + pin) | 35.64 ms | one-time upload |
| 100 tx / 1 circuit | 319 µs (~3.2 µs/tx) | steady-state OK |
| Memory per circuit | 66,169 bytes | ~66 KB ✅ |
| Audit fixes verified | ✅ tests pass | — |

**Before submission:** Run full `cargo bench --features zk --bench zk_circuit`; strip debug `println!` from cache paths; update benchmark review with all medians.

---

## Proposed Timeline (aligned with committee feedback)

| Week | Work | Cost | Submit? |
|------|------|------|---------|
| **Now** | Commit ZK audit fixes | $0 | No |
| **Week 1–2** | Crosslink demo: zebra vectors + relayer + demo script | $0 | No |
| **Week 2** | Full benchmark run + polish docs | $0 | No |
| **Week 3** | Write proposal linking demo + benchmarks | $0 | **Yes** |
| **If funded** | Demo hardening, audit, docs (Milestones 2–3) | $45K | — |

### Funding ask reframing

| Milestone | Original | Re-proposal framing |
|-----------|----------|---------------------|
| M1 ($30K) PoC | Build from scratch | **Pre-built before submission** — demo proves concept |
| M2 ($30K) Demo hardening | — | Fund: CI, zebra vector coverage, relayer hardening |
| M3 ($15K) Audit | — | Fund: external audit + production docs |

---

## Proposal Appendix Checklist

When writing the Gnat proposal, attach:

1. Link to **working demo** (video or reproducible script)
2. `docs/zk-cache-benchmark-review.md` — performance evidence
3. `tests/tests/crosslink_light_client.rs` — e2e test reference
4. Explicit statement: 🔴 audit findings **resolved** (not "known issues")
5. Architecture diagram: zebra → Mercury → IBCv2 relayer → 08-wasm → Terp IBC client
6. Test matrix: which existing tests prove each layer (cite `relayer_tests.rs`, `crosslink_light_client.rs`)

---

## Open Questions (for team before submit)

1. **Public zebra testnet** vs local regtest for demo video?
2. **Relayer language:** Rust in `terp-rs/tools/` or extend existing infra?
3. **Hermes mention:** Clarify it's for Cosmos packet path, not crosslink client updates?
4. **ZK + Crosslink:** Same proposal or separate? ZK cache is production-ready; crosslink demo is the gating item.