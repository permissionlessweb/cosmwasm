# ZK Circuit Cache — Benchmarking & Tuning Guide

**Audience:** Team member implementing cache tuning for the ZK wasmvm  
**Status:** Benchmarks written, audits complete, tuning not yet started  
**Files:** `crates/cosmwasm/packages/vm/benches/zk_circuit.rs`, `docs/zk-cache-benchmarking.md`

---

## 1. What We Have

The ZK wasmvm extends CosmWasm's VM cache with three tiers for halo2 circuit data:

```
PinnedMemoryCache (hot, never evicted)  →  HashMap<[u8;72], InstrumentedCircuit>
InMemoryCache (warm, LRU)               →  CLruCache<CacheKey, CacheEntry>
FileSystemCache (cold, disk)            →  split files under state/wasm/{zk_param,zk_vk,zk_circuit}/
```

Circuit data is stored in three directories per circuit:

| Directory | Contents | Key Size |
|-----------|----------|----------|
| `zk_param/{param_key}.bin` | hal02 params bytes only | 36 bytes |
| `zk_vk/{vk_key}.bin` | constraint system + verifying key | 36 bytes |
| `zk_circuit/{circuit_key}.bin` | full blob (params + cs + vk + 80-byte footer) | 72 bytes |

### Circuit Types

| Circuit | k | i | Size | Use Case |
|---------|---|----|------|----------|
| **no_rick** | 10 | 1 | ~66 KB | Simple proof-of-concept, used in testdata |
| **headstash** | 18 | 6 | ~800 KB | Production ZK circuit (shielded transfers) |

### Circuit Footer (80 bytes)

```
[0]   prover_id       (1)  — CircuitType (Plonkish=0)
[1]   curve_id        (1)  — CurveType (Pasta=0)
[2]   k               (1)  — K element
[3]   i               (1)  — Public input count
[4..8]   param_len    (4)  — LE u32
[8..12]  cs_len       (4)  — LE u32
[12..16] vk_len       (4)  — LE u32
[16..48] param_checksum (32) — SHA-256 of params_bytes
[48..80] vk_checksum    (32) — SHA-256 of cs_bytes + vk_bytes
```

---

## 2. Key Derivation (for cw-orch integration)

```
circuit_key = [param_key (36)][vk_key (36)] = 72 bytes

param_key  = [appstate_key LE (4)][SHA256(params) (32)]
vk_key     = [appstate_key LE (4)][SHA256(cs+vk) (32)]
appstate_key = u32::from_be_bytes([prover_id, curve_id, k, 0])
```

**Important for cw-orch:** The circuit key is `[u8; 72]` (binary), NOT `Checksum` (32 bytes). The `ZkCwEnv` trait must accept `[u8; 72]` for all circuit operations. WASM modules use 32-byte Checksums; ZK circuits use 72-byte keys because they encode curve type, circuit size, and dual checksums in the key itself.

---

## 3. Audit Findings (must fix before tuning)

### 🔴 Critical: `remove_circuit` does not clean up split files

**File:** `packages/vm/src/cache.rs` line 840

`remove_circuit()` only removes the monolithic `zk_circuit/*.bin` file. It does NOT remove the split files in `zk_param/` and `zk_vk/`. Orphaned split files accumulate on disk forever.

**Fix needed:** Add cleanup of `zk_param/{param_key}.bin` and `zk_vk/{vk_key}.bin` in `remove_circuit()`. The `circuit_file_key` is `[param_key][vk_key]` = 72 bytes, so `param_key = circuit_file_key[..36]` and `vk_key = circuit_file_key[36..]`.

Commented-out code at line 813-819 suggests this was known but not implemented.

### 🔴 Critical: Pinned circuits never auto-evict

`pin_circuit()` stores in `PinnedMemoryCache` (a `HashMap`). The only way to remove is `unpin_circuit()`. If the caller forgets, circuits accumulate forever. There is no limit on the pinned cache size.

**Fix needed:** Either:
- (a) Add a maximum size to `PinnedMemoryCache` with LRU eviction for pinned entries (defeats the purpose of "pinned")
- (b) Add a `pinned_generation` counter so unpinning stale circuits is automatic
- (c) Document that the keeper MUST call `unpin_circuit` when circuits are removed from chain state

### 🟡 Medium: Redundant `check_circuit` call

In the store path, `check_circuit()` is called twice:
1. In `store_circuit()` (line 794)
2. Implicitly in `save_circuit_to_disk()` → `CircuitFooter::from_bytes()` (line 824)

**Fix:** Pass the already-parsed `CircuitFooter` from `store_circuit` into `save_circuit_to_disk` instead of re-parsing it.

### 🟡 Medium: `circuit_loader` re-parses keys every time

The `circuit_loader` closure (line 495) splits `circuit_key` into `param_key` and `vk_key` on every call. These are just `[0:36]` and `[36:72]` slices — trivially cacheable.

### 🟡 Medium: Circuits share LRU weight budget with WASM modules

The `WeightScale` implementation sums both module and circuit `size_estimate` values. A large circuit (~800KB for headstash) can evict WASM modules from the shared LRU. Consider separate weight scales or a dedicated circuit LRU.

### 🟢 Low: Error type inconsistency

Some `ZkError` results are wrapped in `VmError::generic_err` (losing structured error type), others in `VmError::zk_err` (preserving it). Standardize on `zk_err` for all ZK operations.

---

## 4. Benchmark Infrastructure

### Running the benchmarks

```bash
cd ~/abstract/terp-core/crates/cosmwasm

# All ZK benchmarks (no_rick circuit)
cargo bench --features zk --bench zk_circuit

# Specific groups
cargo bench --features zk --bench zk_circuit -- "ZK / no_rick"
cargo bench --features zk --bench zk_circuit -- "ZK / multi_tx"
cargo bench --features zk --bench zk_circuit -- "ZK / concurrent_load"

# Memory usage (prints to stdout)
cargo bench --features zk --bench zk_circuit -- "ZK / memory_usage"

# Power estimate (CPU time × 15W model)
cargo bench --features zk --bench zk_circuit -- "ZK / power_estimate"

# Headstash benchmarks (generate testdata first — see section 5)
cargo bench --features zk --bench zk_circuit -- "ZK / headstash"
```

### Benchmark file: `benches/zk_circuit.rs`

10 benchmark groups, each in its own `{ }` scope with independent TempDir:

| # | Group | Measures | Batch Mode |
|---|-------|----------|------------|
| 1 | cold_load | Fresh cache per iter, disk read + deserialize | `iter_batched` |
| 2 | hot_load | Pinned memory, HashMap lookup | `iter` |
| 3 | warm_load | LRU memory, CLruCache weight update | `iter` |
| 4 | store_time | check_circuit + 3x file write + pin | `iter_batched` |
| 5 | split_vs_monolithic | Split files vs monolithic blob | `iter_batched` |
| 6 | multi_tx_single_circuit | 10/100 tx, same circuit, pinned | `iter` |
| 7 | multi_tx_multi_circuit | 10/100 tx, 10 circuits round-robin | `iter` |
| 8 | memory_usage | Pinned + FS bytes per N circuits | manual print |
| 9 | power_estimate | CPU time × 15W → Joules | `iter_custom` |
| 10 | concurrent_load | 64 threads, Mutex contention | `iter_custom` |

### Existing benchmark file: `benches/main.rs`

Already has WASM cache benchmarks (save/load/analyze/instantiate). The ZK benchmarks are in a separate file to avoid feature-gating the entire existing suite.

---

## 5. Before You Run

### Generate headstash testdata

```bash
cd ~/abstract/terp-core/crates/headstash
cargo run --release -p test-press -- --keys ./test-press/artifacts

# Copy to cosmwasm testdata
cp test-press/artifacts/headstash_vk.bin \
   ../cosmwasm/packages/vm/testdata/headstash_vk.bin
```

### Verify no_rick testdata exists

```bash
ls -la ~/abstract/terp-core/crates/cosmwasm/packages/vm/testdata/norick_vk.bin
# Expected: ~66 KB, present
```

---

## 6. Tuning Tasks (in priority order)

### Task 1: Fix split file cleanup in `remove_circuit`

**File:** `packages/vm/src/cache.rs` line 840

```rust
pub fn remove_circuit(&self, circuit_file_key: &[u8; 72]) -> VmResult<()> {
    let mut cache = self.inner.lock().unwrap();
    // Extract param_key and vk_key from the 72-byte circuit key
    let param_key: [u8; 36] = circuit_file_key[..36].try_into().expect("36");
    let vk_key: [u8; 36] = circuit_file_key[36..].try_into().expect("36");

    // Remove split files
    let param_path = cache.param_path().join(hex::encode(param_key)).with_extension("bin");
    let vk_path = cache.vk_path().join(hex::encode(vk_key)).with_extension("bin");
    let _ = std::fs::remove_file(&param_path);
    let _ = std::fs::remove_file(&vk_path);

    // Remove from caches and monolithic
    cache.fs_cache.remove_circuit(circuit_file_key)?;
    cache.pinned_memory_cache.remove_circuit(circuit_file_key)?;
    self.remove_circuit_from_disk(&cache.circuit_path(), circuit_file_key)?;
    Ok(())
}
```

**Verify:** Run `cargo bench --features zk --bench zk_circuit -- "ZK / no_rick / split_vs_monolithic"` — split file path should still work after removal of monolithic.

### Task 2: Add pinned memory cache size limit

**File:** `packages/vm/src/modules/pinned_memory_cache.rs`

Add a `max_size: Option<usize>` field to `PinnedMemoryCache`. When `pin_circuit` is called and the cache exceeds `max_size`, evict the oldest pinned circuit (or return an error).

**Alternate approach:** Add a `pinned_circuits: Vec<[u8; 72]>` tracking list to `CacheInner` so the keeper can query all pinned circuits and unpin stale ones.

### Task 3: Eliminate redundant `check_circuit` call

**File:** `packages/vm/src/cache.rs` lines 793-811

Change `store_circuit` to pass the parsed `CircuitFooter` into `save_circuit_to_disk`:

```rust
pub fn store_circuit(&self, zk: &[u8], persist: bool) -> VmResult<[u8; 72]> {
    let foot = check_circuit(zk)?;
    if persist {
        let (filename, circuitname) = self.save_circuit_to_disk(zk, &foot)?;
        // ...
    }
    // ...
}

fn save_circuit_to_disk(&self, c: &[u8], cf: &CircuitFooter) -> VmResult<...> {
    // Use cf directly instead of re-parsing from bytes
    save_circuit_parts(&cache.param_path(), &cache.vk_path(), &cache.circuit_path(), c, *cf)
}
```

### Task 4: Standardize error types

**Files:** `packages/vm/src/cache.rs`, `packages/vm/src/zk.rs`

Search for all `VmError::generic_err` wrapping `ZkError` and replace with `VmError::zk_err`. The `ZkError` type carries structured information (checksum mismatch, length error, unsupported curve) that gets lost in `generic_err`.

### Task 5: Tune cache sizes based on benchmarks

Run the benchmarks, then adjust these constants in `packages/vm/src/config.rs`:

| Parameter | File | Current | Suggested |
|-----------|------|---------|-----------|
| `memory_cache_size_bytes` | `config.rs` | 200 MiB | TBD from benchmark |
| `PinnedMemoryCache` max size | `pinned_memory_cache.rs` | unlimited | 100 circuits or 100 MiB |
| Circuit LRU weight scale | `cached_module.rs` | shared with WASM | separate or 10x WASM weight |

### Task 6: Implement cw-orch `ZkCwEnv` trait

**Reference:** `docs/zk-cache-benchmarking.md` section 7

The trait must accept `[u8; 72]` keys:

```rust
pub trait ZkCwEnv {
    fn store_circuit(&self, blob: &[u8], persist: bool) -> Result<[u8; 72], Error>;
    fn load_circuit(&self, key: &[u8; 72]) -> Result<Option<CachedCircuit>, Error>;
    fn pin_circuit(&self, key: &[u8; 72]) -> Result<(), Error>;
    fn unpin_circuit(&self, key: &[u8; 72]) -> Result<(), Error>;
}
```

The `CachedCircuit` type is re-exported from `cosmwasm_vm` as:
```rust
#[cfg(feature = "zk")]
pub use crate::modules::CachedCircuit;
```

---

## 7. Performance Targets

After tuning, aim for:

| Metric | Hot (pinned) | Warm (LRU) | Cold (FS) | Target |
|--------|-------------|------------|-----------|--------|
| no_rick load time | < 1 µs | < 5 µs | < 100 µs | ≤ 50 µs cold |
| headstash load time | < 1 µs | < 10 µs | < 500 µs | ≤ 200 µs cold |
| Store time (no_rick) | — | — | — | ≤ 5 ms |
| Store time (headstash) | — | — | — | ≤ 50 ms |
| Memory per circuit (pinned) | ~66 KB | — | — | no_rick |
| Memory per circuit (pinned) | ~800 KB | — | — | headstash |
| 100 tx, 1 circuit (pinned) | — | — | — | ≤ 100 µs total |
| 100 tx, 10 circuits (pinned) | — | — | — | ≤ 1 ms total |
| Pinned cache limit | — | — | — | 100 MiB or 100 circuits |
| Concurrent (64 threads, hot) | — | — | — | ≤ 5 µs median |

---

## 8. Key Files Reference

| File | Purpose |
|------|---------|
| `packages/vm/src/cache.rs` | Main cache — `store_circuit`, `load_circuit`, `remove_circuit`, `pin_circuit`, `unpin_circuit`, `circuit_loader` |
| `packages/vm/src/zk.rs` | `check_circuit()`, `serialize_circuit_data()`, `deserialize_circuit_data()` |
| `packages/zk/src/footer.rs` | `CircuitFooter` — 80-byte metadata, `to_bytes()`, `from_bytes()`, key derivation |
| `packages/zk/src/circuits.rs` | `AnyVerifyingKey` — `try_from`, `from_split_bytes`, `verify` |
| `packages/zk/src/curves/vesta.rs` | `VestaVerifyingKey` — `from_split_bytes` with `CsBlueprintGuard` RAII |
| `packages/vm/src/modules/pinned_memory_cache.rs` | `PinnedMemoryCache` — HashMap-backed, no eviction |
| `packages/vm/src/modules/in_memory_cache.rs` | `InMemoryCache` — CLruCache-backed, weight-based LRU |
| `packages/vm/src/modules/file_system_cache.rs` | `FileSystemCache` — disk-backed serialized circuits |
| `packages/vm/src/modules/cached_module.rs` | `CachedCircuit`, `CachedParam`, `InstrumentedCircuit` |
| `packages/vm/benches/zk_circuit.rs` | ZK benchmark suite (10 groups) |
| `packages/vm/benches/main.rs` | Existing WASM cache benchmarks |
| `docs/zk-cache-benchmarking.md` | Full documentation with architecture, footer spec, ops tuning |
| `packages/vm/src/lib.rs` | Re-exports `CachedCircuit` behind `#[cfg(feature = "zk")]` |
| `packages/vm/Cargo.toml` | `[[bench]]` entry for `zk_circuit` with `required-features = ["zk"]` |

---

## 9. Verification Checklist

After implementing each task, verify:

- [ ] `cargo check --features zk --package cosmwasm-vm --benches` passes
- [ ] `cargo check --package cosmwasm-vm --benches` passes (without zk feature)
- [ ] `cargo check --features zk --package cosmwasm-vm` passes (library)
- [ ] `cargo bench --features zk --bench zk_circuit -- "ZK / no_rick / cold_load"` runs and produces reasonable numbers
- [ ] `cargo bench --features zk --bench zk_circuit -- "ZK / memory_usage"` reports growing memory with N circuits
- [ ] `cargo bench --features zk --bench zk_circuit -- "ZK / concurrent_load"` completes without panics

### For the `remove_circuit` fix specifically:

- [ ] `remove_circuit` removes `zk_circuit/{key}.bin`
- [ ] `remove_circuit` removes `zk_param/{param_key}.bin`
- [ ] `remove_circuit` removes `zk_vk/{vk_key}.bin`
- [ ] `remove_circuit` removes from `pinned_memory_cache`
- [ ] `remove_circuit` removes from `fs_cache`
- [ ] After `remove_circuit`, `load_circuit` returns `None` (not an error)
- [ ] `store_circuit` after `remove_circuit` works (idempotent re-store)

---

## 10. Open Questions for the Team

1. **Pinned cache limit:** Should we add a hard limit (evict oldest) or soft limit (warn but allow)? The keeper can't control all circuits — some are pinned by contract execution.

2. **Separate circuit LRU:** Should circuits share the WASM module LRU weight budget, or have their own dedicated LRU? Sharing means large circuits evict WASM modules.

3. **Headstash circuit generation:** The proving key takes ~30s to generate. Should we check in a smaller test circuit for CI, or generate on the fly?

4. **cw-orch ownership:** Who implements the `ZkCwEnv` trait — the cw-orch team or the wasmvm team? The trait lives in cw-orch but depends on types from cosmwasm-vm.

5. **Power model:** The 15W per core TDP is a rough estimate. Should we use RAPL counters (Linux) or `mach_absolute_time` (macOS) for more accurate energy measurements?