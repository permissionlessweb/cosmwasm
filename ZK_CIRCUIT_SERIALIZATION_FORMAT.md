# CosmWasm ZK Circuit Serialization Format

## Overview

The serialization format defines how halo2 verifying keys are encoded for storage in CosmWasm contracts. This format enables full programmability of the circuit layer by embedding complete constraint system metadata, allowing deserialization without knowing the original circuit implementation.

## Design Principles

- **Self-Describing**: All metadata needed for deserialization is embedded in the binary
- **Single Serialization Path**: One canonical way to serialize and deserialize
- **Programmable**: Works with any `Circuit<vesta::Scalar>` implementation via `DynamicCircuit`
- **Extensible**: Reserved bytes accommodate future enhancements
- **Validated**: Footer CRC and structure validation prevent corruption

## Complete Binary Format

```
┌─────────────────────────────────────────────────────┐
│ Halo2 Commitment Parameters (Variable Size)         │
│ - k (circuit size parameter)                        │
│ - g (generator commitments)                         │
│ - g_lagrange                                        │
│ - w, u (window/u parameters)                        │
│ Typical size: 60-70 KB for k=10                     │
└─────────────────────────────────────────────────────┘
         params_len bytes (from footer)

┌─────────────────────────────────────────────────────┐
│ Halo2 Verifying Key (Variable Size)                 │
│ - Fixed column commitments                          │
│ - Permutation verifying key                         │
│ - Circuit metadata (gates, lookups, etc.)           │
│ Typical size: 300-500 bytes                         │
└─────────────────────────────────────────────────────┘
         vk_len bytes (from footer)

┌─────────────────────────────────────────────────────┐
│ CosmWasm ZK Footer Metadata (32 bytes)              │
│ Complete constraint system specification            │
└─────────────────────────────────────────────────────┘
```

## Footer Metadata Structure (32 Bytes)

The footer is a single unified metadata object that contains all information needed for generic deserialization and reconstruction of the constraint system via `DynamicCircuit`.

### Byte Layout

| Offset | Size | Field | Type | Purpose |
|--------|------|-------|------|---------|
| 0 | 1 | `circuit_type` | `u8` enum | Identifies Plonkish/Halo2 variant (0 = Plonkish) |
| 1 | 1 | `instance_count` | `u8` | Number of scalar public inputs required |
| 2 | 1 | `num_fixed_columns` | `u8` | Number of fixed columns in constraint system (includes selectors) |
| 3 | 1 | `num_advice_columns` | `u8` | Number of advice (witness) columns in constraint system |
| 4 | 1 | `num_instance_columns` | `u8` | Number of instance (public input) columns in constraint system |
| 5 | 1 | `degree` | `u8` | Maximum gate degree in constraint system (typically 2-4) |
| 6 | 1 | `footer_version` | `u8` | Footer format version (currently 1) |
| 7 | 1 | `flags` | `u8` | Feature flags for future extensions (currently unused) |
| 8-11 | 4 | `params_len` | `u32` LE | Byte length of halo2 params section |
| 12-15 | 4 | `vk_len` | `u32` LE | Byte length of halo2 verifying key section |
| 16-19 | 4 | `num_selectors` | `u32` LE | Number of selectors (compiled into fixed columns during keygen) |
| 20-23 | 4 | `reserved_2` | `u32` | Reserved for future extensions |
| 24-27 | 4 | `reserved_3` | `u32` | Reserved for future extensions |
| 28-31 | 4 | `crc32` | `u32` LE | CRC32 checksum of params+vk bytes (optional validation) |

**Total Footer Size: 32 bytes exactly**

## Serialization and Deserialization

### Serialization Process

When writing a circuit's verifying key for CosmWasm storage:

1. Generate verifying key using `plonk::keygen_vk(&params, &circuit)`
2. Serialize params to byte buffer
3. Serialize verifying key to byte buffer
4. Extract constraint system metadata from the circuit:
   - num_fixed_columns (from constraint system)
   - num_advice_columns (from constraint system)
   - num_instance_columns (from constraint system)
   - num_selectors (from constraint system)
   - degree (maximum polynomial degree)
   - instance_count (number of public input scalars)
5. Compute optional CRC32 checksum of params || vk bytes
6. Create CircuitFooter with all metadata
7. Concatenate: params_bytes || vk_bytes || footer_bytes (32 bytes)
8. Store combined file

### Deserialization Process

When loading a circuit's verifying key from CosmWasm storage:

1. Read entire file into memory
2. Extract and parse footer from last 32 bytes using `CircuitFooter::from_bytes()`
3. Validate footer structure and version
4. Extract params and vk byte ranges using lengths from footer
5. Deserialize params using halo2::Params::read()
6. Create DynamicCircuit configured with footer metadata
7. Deserialize verifying key using halo2::VerifyingKey::read() with DynamicCircuit
8. Return complete VerifyingKey ready for proof verification

## Core Data Structures

### CircuitFooter

The `CircuitFooter` struct encodes all constraint system metadata in 32 bytes and is located in:
- **Location**: `packages/zk/src/cosmwasm_circuit.rs`
- **Struct Name**: `CircuitFooter`
- **Key Methods**:
  - `new()`: Create footer with all metadata
  - `to_bytes()`: Serialize to exactly 32 bytes
  - `from_bytes()`: Deserialize from 32 bytes

**Fields**:
- `circuit_type: CircuitType` - Circuit variant identifier
- `instance_count: u8` - Number of public input scalars
- `num_fixed_columns: u8` - Count of fixed columns (includes selectors)
- `num_advice_columns: u8` - Count of advice columns
- `num_instance_columns: u8` - Count of instance columns
- `degree: u8` - Maximum polynomial degree
- `footer_version: u8` - Format version (currently 1)
- `flags: u8` - Feature flags (reserved for future use)
- `params_len: u32` - Byte length of params section
- `vk_len: u32` - Byte length of verifying key section
- `num_selectors: u32` - Count of selector columns (compiled into fixed columns)
- `reserved_2: u32` - Reserved for future extensions
- `reserved_3: u32` - Reserved for future extensions
- `crc32: u32` - Optional checksum of params+vk bytes

### DynamicCircuit

The `DynamicCircuit` struct implements `Circuit<vesta::Scalar>` and is configured at runtime using `CircuitFooter` metadata. This enables deserialization of ANY verifying key without needing the original circuit implementation.

- **Location**: `packages/zk/src/cosmwasm_circuit.rs`
- **Struct Name**: `DynamicCircuit`
- **Type Parameters**: Configured for `vesta::Scalar` field
- **Key Methods**:
  - `new()`: Create with column counts and selector count
  - `from_footer()`: Create from CircuitFooter metadata
  - `set_as_current()`: Store in thread-local for constraint system setup
  - `configure()`: Automatically create columns, enable equality, and add selectors matching footer metadata

**Behavior**:
- Dynamically creates fixed columns, advice columns, instance columns, and selectors during `configure()`
- Enables equality constraints on all columns for permutation support
- Validates that deserialized verifying key matches the configured column structure
- Does NOT recreate gates (they come from deserialized verifying key)

### SerializedPlonkishCircuitData

Wrapper for complete circuit data with integrity information.

- **Location**: `packages/zk/src/cosmwasm_circuit.rs`
- **Struct Name**: `SerializedPlonkishCircuitData`
- **Fields**:
  - `bytes: Vec<u8>` - Complete serialized data (params + vk + footer)
  - `hash: [u8; 32]` - SHA256 hash for integrity checking
  - `metadata: Vec<u8>` - Serialized footer metadata

### VerifyingKey

The complete verifying key ready for proof verification.

- **Location**: `packages/zk/src/cosmwasm_circuit.rs`
- **Struct Name**: `VerifyingKey`
- **Fields**:
  - `params: Params<vesta::Affine>` - Halo2 commitment parameters
  - `vk: plonk::VerifyingKey<vesta::Affine>` - Halo2 verifying key
  - `i: usize` - Instance count
- **Key Methods**:
  - `from_bytes()`: Deserialize from combined file with DynamicCircuit
  - `to_bytes_with_footer()`: Serialize with full CircuitFooter metadata
  - `parse_bytes()`: Parse and validate without full deserialization

## Validation Checklist

The `VerifyingKey::from_bytes()` method validates:
- ✓ File size is at least 32 bytes for footer
- ✓ Footer structure is valid 32 bytes
- ✓ Footer version is 1 (current)
- ✓ Total size == params_len + vk_len + 32
- ✓ Params and VK sections both have non-zero length
- ✓ CircuitFooter parses successfully via `from_bytes()`
- ✓ DynamicCircuit creation succeeds with footer metadata
- ✓ Params deserialization succeeds with halo2::Params::read()
- ✓ VK deserialization succeeds with halo2::VerifyingKey::read()
- ✓ Column and selector counts match between footer and deserialized VK

## Related Code Locations

| Component | Location |
|-----------|----------|
| `CircuitFooter` struct and implementation | `packages/zk/src/cosmwasm_circuit.rs:40-162` |
| `DynamicCircuit` struct and implementation | `packages/zk/src/cosmwasm_circuit.rs:190-297` |
| `DynamicCircuitConfig` | `packages/zk/src/cosmwasm_circuit.rs:165-172` |
| `SerializedPlonkishCircuitData` | `packages/zk/src/cosmwasm_circuit.rs:398-467` |
| `VerifyingKey` | `packages/zk/src/cosmwasm_circuit.rs:470-630` |
| `check_circuit()` validation function | `packages/vm/src/zk.rs:80-139` |
| `CodeBundle` wrapper | `packages/vm/src/zk.rs:13-67` |
| Test data generation | `packages/zk/src/suite.rs:198-305` |

## Performance Characteristics

| Operation | Typical Time | Notes |
|-----------|------|-------|
| Parse footer | <1 μs | Last 32 bytes only |
| Validate structure | <1 μs | Checksum comparison |
| Create DynamicCircuit | <1 ms | Thread-local config setup |
| Deserialize params | 10-100 ms | k-dependent (k=10 ≈ 65KB) |
| Deserialize VK | 50-200 ms | Column/permutation dependent |
| **Total (first load)** | **~100-400 ms** | End-to-end deserialization |
| **Cached loads** | <1 μs | From pinned memory cache |

## Future Extensions

Reserved bytes and flags provide room for:
- Extended circuit metadata (num_gates, num_lookups, etc.)
- Compression algorithm metadata (params/vk compression)
- Custom circuit-specific data storage
- Circuit name/type hashing for verification
- Extended version field for backward compatibility
- Additional constraint system properties
