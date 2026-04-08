# Virtual Memory Cache Layer for Halo2 Circuit Keys in CosmWasm VM

---

## Introduction

This document describes the virtual memory caching architecture implemented in CosmWasm VM to support Halo2 zero-knowledge proof circuit binary keys. By extending the existing multi-tier caching infrastructure, we enable efficient storage and retrieval of cryptographic verification keys alongside compiled WebAssembly modules.

Zero-knowledge proofs require verification keys (VKs) that can be computationally expensive to deserialize. Our caching strategy draws inspiration from operating system virtual memory principles—particularly demand paging and tiered memory hierarchies—to minimize latency while managing memory constraints effectively.

---

## Virtual Memory Foundations

### Memory Hierarchy Principles

Just as operating systems manage physical memory through virtual memory abstractions, our caching layer abstracts the storage and retrieval of circuit keys across multiple tiers. The fundamental insight from virtual memory systems is that not all data needs to reside in fast storage simultaneously—*demand paging* loads data only when accessed.

Our implementation mirrors this through a three-tier hierarchy:

1. **Pinned Memory Cache**: Analogous to wired/pinned pages in OS memory management, these entries are never evicted and remain instantly accessible.

2. **File System Cache**: Serves as backing store (similar to swap space), providing persistent storage with higher access latency.

<!-- 2. **In-Memory LRU Cache**: Functions like the page cache, holding recently-used entries with automatic eviction based on access patterns. -->

### Checksum-Based Addressing

Virtual memory systems translate virtual addresses to physical addresses through page tables. Our cache uses a similar indirection mechanism: each circuit key is identified by a **Checksum**—a content-addressed hash that serves as the unique identifier across all cache tiers.

This design provides integrity verification (analogous to page table validity bits) and enables content deduplication when multiple contracts reference identical verification keys.

---

## Cache Architecture

### Cache Hierarchy Overview

The cache infrastructure consists of three distinct layers, each optimized for different access patterns and persistence requirements. Both WASM modules and Halo2 circuit keys flow through this unified hierarchy.

| Layer | Speed | Eviction Policy | Persistence |
|-------|-------|-----------------|-------------|
| **Pinned Memory** | Fastest | Manual only | Until node restart |
| **File System** | Slower | Manual only | Survives restart |
<!-- | **In-Memory (LRU)** | Fast | LRU automatic | Until node restart | -->

### Pinned Memory Cache

The `PinnedMemoryCache` provides the fastest access tier for both WASM modules and circuit keys. Entries in this cache are never automatically evicted, making it ideal for frequently-accessed verification keys that must be available with minimal latency.

**Key characteristics:**

- Separate HashMaps for modules and circuits enable independent management
- Hit counters track access frequency for observability and optimization decisions
- Size computation aggregates both module estimates and actual circuit byte sizes
- Thread-safe access through parent Cache's Mutex wrapper

#### Data Structures

The cache wraps circuit entries in an `InstrumentedCircuit` struct that tracks usage metrics:

```rust
pub struct InstrumentedCircuit {
    /// Number of loads from memory this module received
    pub hits: u32,
    /// The actual cached circuit
    pub circuit: zk_cosmwasm::PinnedCircuit,
}
```

The `PinnedMemoryCache` maintains parallel storage for modules and circuits:

```rust
pub struct PinnedMemoryCache {
    modules: HashMap<Checksum, InstrumentedModule>,
    circuits: HashMap<Checksum, InstrumentedCircuit>,
}
```

#### Core Operations

| Operation | Description |
|-----------|-------------|
| `store_circuit()` | Insert a deserialized VK with initial hit count of 0 |
| `load_circuit()` | Retrieve VK and increment hit counter (saturating add) |
| `remove()` | Remove entry by checksum, with `zk` flag selecting circuits vs modules |
| `has()` | Check existence without loading |
| `size()` | Aggregate memory footprint across all entries |
<!-- 
### In-Memory LRU Cache

The `InMemoryCache` implements a bounded cache with Least Recently Used (LRU) eviction semantics. This tier automatically manages memory pressure by evicting cold entries when capacity limits are reached.

Currently, this layer caches WASM modules with weight-based capacity management. The cache uses a custom `SizeScale` implementation to track actual memory consumption rather than entry count, ensuring memory budgets are respected accurately.

```rust
struct SizeScale;

impl WeightScale<Checksum, CachedModule> for SizeScale {
    fn weight(&self, key: &Checksum, value: &CachedModule) -> usize {
        std::mem::size_of_val(key) + value.size_estimate
    }
}
``` -->

**Design considerations for circuit integration:**

- Circuit keys vary significantly in size based on proof system complexity
- Weight-based eviction prevents a few large circuits from monopolizing cache
<!-- - The CLruCache implementation provides O(1) access and eviction -->

### File System Cache

The `FileSystemCache` provides persistent storage that survives node restarts. This tier acts as the authoritative backing store—analogous to swap space in virtual memory systems—from which higher tiers are populated on demand.

**Circuit key storage:**

- Files named by checksum hex with `.bin` extension
- First byte encodes circuit type metadata
- Remaining bytes contain serialized verification key
- Versioned directory structure enables cache invalidation on upgrades

```rust
/// Stores a serialized verifying key to the file system.
pub fn store_circuit(&mut self, checksum: &Checksum, vk: &[u8]) -> VmResult<usize> {
    mkdir_p(&self.modules_path)
        .map_err(|_e| VmError::cache_err("Error creating circuits directory"))?;

    let path = self.circuit_file(checksum);
    fs::write(&path, vk)
        .map_err(|e| VmError::cache_err(format!("Error writing circuit to disk: {e}")))?;

    Ok(vk.len())
}
```

---

## Circuit Key Lifecycle

### Storage Flow

When a contract with ZK capabilities is instantiated, both WASM bytecode and verification keys are stored through a unified flow. The `store_code_with_circuit` method orchestrates this process:

```
┌─────────────────┐
│  CodeBundle     │
│  (wasm + vk)    │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   Validation    │──── check_wasm() + check_circuit()
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│    Checksum     │──── Content-addressed hash generation
│   Generation    │
└────────┬────────┘
         │
    ┌────┴────┐
    ▼         ▼
┌───────┐ ┌───────┐
│ WASM  │ │  VK   │
│ Store │ │ Store │
└───┬───┘ └───┬───┘
    │         │
    ▼         ▼
┌─────────────────┐
│  File System    │──── Persistent backing store
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Pinned Memory   │──── Immediate availability
│    Cache        │
└─────────────────┘
```

**Step-by-step:**

1. **Validation**: Both WASM and VK undergo integrity checks when checked mode is enabled
2. **Checksum Generation**: Content-addressed hashes computed for both artifacts
3. **Disk Persistence**: Both artifacts written to versioned file system paths
4. **Cache Population**: VK deserialized and pinned in memory for immediate availability
5. **Memory Tracking**: Cache size metrics updated to reflect new entry

### Retrieval Strategy

Circuit key retrieval follows a tiered lookup strategy mirroring page fault handling in virtual memory:

```
┌──────────────────┐
│  get_pinned_     │
│  circuit()       │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐     ┌─────────────┐
│  Pinned Cache    │────▶│   Return    │ HIT
│     Lookup       │     │  Arc<VK>    │
└────────┬─────────┘     └─────────────┘
         │ MISS
         ▼
┌──────────────────┐     ┌─────────────┐
│  File System     │────▶│ Deserialize │ HIT
│     Load         │     │  & Pin      │
└────────┬─────────┘     └─────────────┘
         │ MISS
         ▼
┌──────────────────┐
│     Error:       │
│  VK not found    │
└──────────────────┘
```

- **Pinned cache hit**: Return immediately, increment hit counter
- **Pinned cache miss**: Load from file system ("page fault")
- **File system hit**: Deserialize VK, optionally pin to memory
- **File system miss**: Error—VK must be stored before use

The `get_pinned_circuit` method returns an `Arc<LoadedVk>`, enabling zero-copy sharing across concurrent proof verifications without cloning the underlying cryptographic data.

### Pin and Unpin Operations

The pinning mechanism provides explicit control over memory residency, similar to `mlockall()` in POSIX systems. Pinned entries bypass LRU eviction, guaranteeing availability for latency-sensitive operations.

**pin_circuit:**

```rust
fn pin_circuit(&self, checksum: &Checksum) -> VmResult<()> {
    let mut cache = self.inner.lock().unwrap();
    
    // Idempotent: skip if already pinned
    if cache.pinned_circuit_cache.contains_key(checksum) {
        return Ok(());
    }
    
    // Load from disk and deserialize
    if let Some(serialized_vk) = self.load_circuit_from_disk(&cache.wasm_path, checksum)? {
        let loaded_vk = LoadedVk::from_bytes(&serialized_vk.bytes)?;
        let vk_size = loaded_vk.actual_size_bytes();
        
        // Update memory tracking
        cache.pinned_circuit_memory += vk_size;
        cache.pinned_circuit_cache.insert(*checksum, Arc::new(loaded_vk));
        Ok(())
    } else {
        Err(VmError::generic_err("No VK found for checksum"))
    }
}
```

**unpin_circuit:**

- Removes entry from pinned cache
- Decrements memory usage counter
- Does not remove from file system (can be re-pinned later)

---

## Memory Management

### Size Tracking

Accurate memory accounting is essential for preventing out-of-memory conditions. The cache tracks size at multiple levels:

| Level | Method | Description |
|-------|--------|-------------|
| Per-entry | `actual_size_bytes()` | Exact memory footprint of LoadedVk |
| Per-cache | `size()` | Aggregates all entries with checksum overhead |
| Global | `pinned_circuit_memory` | Total pinned circuit memory across cache |

The `PinnedMemoryCache::size()` implementation:

```rust
pub fn size(&self) -> usize {
    let module_size: usize = self.modules.iter()
        .map(|(key, module)| std::mem::size_of_val(key) + module.module.size_estimate)
        .sum();

    let circuit_size: usize = self.circuits.iter()
        .map(|(key, zk)| std::mem::size_of_val(key) + zk.circuit.actual_size_bytes())
        .sum();

    module_size + circuit_size
}
```

### Metrics and Observability

The `Stats` and `Metrics` structs provide visibility into cache behavior:

```rust
pub struct Stats {
    pub hits_pinned_memory_cache: u32,
    pub hits_memory_cache: u32,
    pub hits_fs_cache: u32,
    pub misses: u32,
}

pub struct Metrics {
    pub stats: Stats,
    pub elements_pinned_memory_cache: usize,
    pub elements_memory_cache: usize,
    pub size_pinned_memory_cache: usize,
    pub size_memory_cache: usize,
}
```

These metrics enable operators to monitor cache efficiency and tune configuration parameters.

---

## Thread Safety

All cache operations are protected by a `Mutex<CacheInner>` to ensure thread-safe access in concurrent blockchain execution environments:

```rust
pub struct Cache<A: BackendApi, S: Storage, Q: Querier> {
    available_capabilities: HashSet<String>,
    inner: Mutex<CacheInner>,
    instance_memory_limit: Size,
    // ... type markers
    instantiation_lock: Mutex<()>,
    wasm_limits: WasmLimits,
}
```

The `Arc` wrapper on `LoadedVk` enables shared ownership across threads without cloning expensive cryptographic data structures.

---

## Relationship to Virtual Memory Concepts

| Virtual Memory Concept | Cache Implementation |
|------------------------|---------------------|
| Page Table | HashMap<Checksum, Entry> |
| Virtual Address | Checksum (content hash) |
| Physical Frame | Actual bytes in memory |
| Demand Paging | Load from FS on cache miss |
| Page Fault | Cache miss triggers disk load |
| Wired/Pinned Pages | PinnedMemoryCache entries |
| Page Cache | InMemoryCache (LRU) |
| Swap Space | FileSystemCache |
| Valid/Invalid Bit | `has()` check |
| RSS (Resident Set Size) | `size_pinned_memory_cache` |
| VSZ (Virtual Size) | Total stored on disk |

---

## Summary

The CosmWasm VM cache layer for Halo2 circuit keys provides a unified, multi-tier storage architecture that balances access speed against memory constraints. By applying virtual memory principles to cryptographic key management, we achieve:

- **Low latency**: Pinned cache provides instant access for hot verification keys
- **Memory efficiency**: size tracking prevent unbounded growth
- **Persistence**: File system backing ensures keys survive node restarts
- **Observability**: Hit counters and metrics enable operational tuning
- **Thread safety**: Mutex protection and Arc sharing support concurrent access

This architecture enables efficient zero-knowledge proof verification in blockchain smart contracts while maintaining the deterministic execution guarantees required by consensus systems.

## Research

- <https://nghiant3223.github.io/2025/05/29/fundamental_of_virtual_memory.html>
- <https://github.com/cosmwasm/wasmd>
- <https://github.com/cosmwasm/wasmvm>
