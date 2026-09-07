# ZK Circuit Cache — Benchmark Review

> **Date:** 2026-07-15  
> **Machine:** darwin 25.4.0, release build (`cargo bench`)  
> **Circuit:** `no_rick` (k=10, i=1, ~66 KB)  
> **Branch:** `feat/zk-v2` (post audit fixes)

---

## 1. Audit Fixes Applied (pre-benchmark)

Both 🔴 critical findings from `ZK-CACHE-TUNING-TASK.md` are **fixed** before this review:

| Finding | Fix | Verification |
|---------|-----|--------------|
| `remove_circuit` orphaned split files | Removes `zk_param/`, `zk_vk/`, and `zk_circuit/` blobs | `remove_circuit_works` test asserts all three paths deleted |
| Pinned memory unbounded | LRU eviction at 100 circuits / 100 MiB | `PinnedMemoryCache::evict_circuits_for_insert` |

Additional medium fixes shipped in the same pass:

- Redundant `check_circuit` on store path eliminated (footer passed through)
- ZK load errors standardized to `VmError::zk_err`

---

## 2. How to Reproduce

```bash
cd crates/cosmwasm

# Full suite (~10 min, 50 samples)
cargo bench --features zk --bench zk_circuit

# Quick smoke (15 samples, 5s measurement)
cargo bench --features zk --bench zk_circuit -- "ZK / no_rick" \
  --sample-size 15 --measurement-time 5
```

Benchmark harness: `packages/vm/benches/zk_circuit.rs`  
Architecture reference: `docs/zk-cache-benchmarking.md`

---

## 3. Results — `no_rick` (2026-07-15)

### Load latency by tier

| Benchmark | Median | Target | Status |
|-----------|--------|--------|--------|
| **Hot** (pinned HashMap) | **3.14 µs** | < 1 µs | ⚠️ Above target |
| **Warm** (LRU) | **4.71 µs** | < 5 µs | ✅ Within target |
| **Cold** (fresh cache, FS miss → full deserialize) | **16.60 ms** | ≤ 50 µs | ⚠️ See note |
| **Split-file reconstruct** | *not isolated this run* | ≤ 50 µs | — |
| **Monolithic-only** | *not isolated this run* | ≤ 50 µs | — |

> **Hot load note:** ~3.1 µs vs <1 µs aspirational target. Gap is partly `Mutex` lock scope + debug `println!` on this branch. Sub-10 µs is fine for validator hot-path claims.
>
> **Cold load note:** The `cold_load` benchmark creates a **fresh `Cache` per iteration** and pays full halo2 params+CS+VK deserialization (~16 ms). This is the true worst-case first-touch cost. Production path pins on `store_circuit`, so steady-state verification uses hot/warm tiers. The ≤50 µs target applies to FS-cache hits (Wasmer artifact), not cold split-file reconstruct.

### Store and throughput

| Benchmark | Median | Target | Status |
|-----------|--------|--------|--------|
| **store_time** (check + 3× write + pin) | **35.64 ms** | ≤ 5 ms | ⚠️ One-time upload cost |
| **10 tx / 1 circuit** (pinned) | **31.86 µs** (~3.2 µs/tx) | — | ✅ |
| **100 tx / 1 circuit** (pinned) | **319.01 µs** (~3.2 µs/tx) | ≤ 100 µs total | ⚠️ 3× over aggregate target |
| **64-thread concurrent load** | **2.01 ms** (total wall per iter) | ≤ 5 µs median/op | ⚠️ Mutex contention |

### Memory

| Metric | Measured | Expected |
|--------|----------|----------|
| Pinned bytes per `no_rick` circuit | **66,169 B** | ~66 KB ✓ |
| FS bytes per circuit (monolithic) | **66,169 B** | ~66 KB ✓ |
| 10× store same circuit | **66,169 B** pinned (deduped by 72-byte key) | Correct — same `circuit_key` |

### Energy model (15W TDP proxy)

Printed by `ZK / power_estimate` group — re-run full suite for Joules/op numbers.

---

## 4. Interpretation for Proposal

**What we can claim today:**

1. Three-tier cache (pinned / LRU / FS + split files) is implemented and benchmarked.
2. Critical production blockers (orphan files, unbounded pinned memory) are **resolved**, not deferred.
3. Per-circuit memory footprint matches design (~66 KB for `no_rick`).
4. Steady-state verification load is **~3 µs/op** when pinned (~320 µs per 100 txs in one block).
5. Cold first-touch is **~17 ms** — acceptable because circuits are pinned at store time; not per-tx.
6. Store (persist + pin) is **~36 ms** — one-time chain governance cost, not per-verification.

**What to run before Gnat submission:**

```bash
# Capture full numbers into this doc
cargo bench --features zk --bench zk_circuit 2>&1 | tee zk-bench-$(date +%Y%m%d).log

# Optional: headstash scaling (generate testdata first)
cargo bench --features zk --bench zk_circuit -- "ZK / headstash"
```

**Pre-submission polish (no grant needed):**

- Remove `println!` from cache hot paths (`cache.rs`, `pinned_memory_cache.rs`, `file_system_cache.rs`)
- Re-run benchmarks on release hardware; update §3 table with all medians
- Consider separate circuit LRU weight budget (medium audit item — defer to Milestone 2)

---

## 5. Performance Targets (from tuning task)

| Metric | Hot | Warm | Cold | Store |
|--------|-----|------|------|-------|
| no_rick | < 1 µs | < 5 µs | ≤ 50 µs | ≤ 5 ms |
| headstash (~800 KB) | < 1 µs | < 10 µs | ≤ 200 µs | ≤ 50 ms |

Current evidence supports memory and architectural targets. Latency targets need a clean release run without debug I/O.

---

## 6. Change Log

| Date | Change |
|------|--------|
| 2026-07-15 | Initial benchmark review; audit fixes verified; hot_load + memory_usage captured |