# Storage And Caching

How the VM stores circuit material and serves hot verifying keys without re-deserializing on every tx.

Source: `ZK_STORAGE_AND_CACHING.md`.

## What is actually shared

Reusable Halo2 params are shared **on disk**, not as one in-memory object across circuits.

- `zk_param/<36-hex>.bin` is content-addressed. Two circuits with the same param bytes and the same `(prover_id, curve_id, k)` write the same file.
- `zk_vk/<36-hex>.bin` is that circuit's cs+vk only.
- `zk_circuit/<72-hex>.bin` is the full blob, including another copy of the params. The split file is the shared copy. The monolithic blob is not.
- A verify hit returns a `CachedCircuit` whose `AnyVerifyingKey` already contains its own deserialized params. Two circuits that share a param file still hold two deserialized copies.
- `store_param` / `load_param` keep raw param bytes in the pinned map and the LRU. The verify loader does not call `load_param`. A circuit miss reads `zk_param` from disk and deserializes again.
- `param_len = 0` (BN254 / Groth16) stores an empty param file and skips the Halo2 `k` header. There is no reusable param blob on that path.

## Why tiers exist

The tiers avoid re-reading a circuit that is already deserialized. They do not deduplicate deserialized params across circuit keys.

## Cache hierarchy

| Tier | Key | Eviction | Persistence |
|------|-----|----------|-------------|
| Pinned memory | 72-byte circuit / 36-byte param | Circuits: oldest-first once 100 circuits or 100 MiB. Params: none | Lost on process restart |
| In-memory LRU | Unified `CacheKey` (module / partial / circuit) | Weight-based LRU | Lost on restart |
| File system | Hex filenames under `zk_*` | Manual remove | Survives restart |

Unified LRU entries:

```rust
// Conceptual — see packages/vm cache module
enum CacheKey {
    Checksum(Checksum),   // Wasm modules
    PartialKey([u8; 36]), // param or vk body
    CircuitKey([u8; 72]), // full circuit
}
```

## On-disk layout

```
base_dir/state/wasm/
  <checksum>.wasm
  zk_param/<36-hex>.bin
  zk_vk/<36-hex>.bin
  zk_circuit/<72-hex>.bin
base_dir/cache/modules/<version>/<target>/<checksum>.module
```

Keys derive from the footer (`to_param_key`, `to_vk_key`, `to_circuit_key`).

## Lifecycle

### Store

```
serialized [params|cs|vk|footer]
  → check_circuit()  (dual SHA-256)
  → save_circuit_parts() → zk_param + zk_vk + zk_circuit
  → pin_circuit(circuit_key)  (typical default after store)
```

### Load

```
pinned circuit hit  → clone that circuit's CachedCircuit
LRU circuit hit     → clone that circuit's CachedCircuit
FS circuit hit      → deserialize, promote to LRU
miss                → read zk_param + zk_vk from disk (not the param LRU),
                      or the monolithic zk_circuit blob
```

### Pin / unpin / remove

| Call | Effect |
|------|--------|
| `pin_circuit` | Ensure deserialized VK is in pinned map (idempotent) |
| `unpin_circuit` | Drop pinned entry (disk may remain) |
| `remove_circuit` | Unpin and delete circuit artifacts as implemented |

Exact semantics of unpin vs FS module removal are implementation-defined in the cache module; do not assume unpin alone deletes all three on-disk parts without checking current `packages/vm` behavior.

## Memory accounting

| Level | Use |
|-------|-----|
| Per-VK `size_estimate` | Weighting, metrics |
| Pinned / LRU totals | Observability, optional limits |
| Global pinned circuit memory | Optional host limits |

Pinned circuits evict oldest-first at 100 entries or 100 MiB. Pinned param bytes do not. A pin is still the hot path, and it stores one deserialized VK per circuit key.

## Operator tips

1. After restart, re-pin circuits that appear on every block.  
2. Watch pinned hit rate vs FS loads (deserialization is expensive).  
3. The split `zk_param` file is what circuits with the same `k` share. Memory still holds one deserialized copy per circuit.
4. Keep consensus `zkid` mappings correct; cache cannot invent missing registry entries.

## Metrics (illustrative)

Hosts expose cache stats (hits on pinned/FS, misses, sizes). Use them when tuning memory limits for nodes that verify many distinct circuits.
