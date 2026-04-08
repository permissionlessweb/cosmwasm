# CosmWasm ZK Circuit Serialization Format

## Overview

The serialization format defines how halo2 verifying keys and constraint systems are encoded for storage in CosmWasm contracts. This format enables full programmability of the circuit layer by embedding the **complete constraint system** (including gates and polynomial expressions), allowing deserialization and verification without knowing the original circuit implementation.

## Design Principles

- **Self-Describing**: All metadata needed for deserialization is embedded in the binary
- **Complete CS**: The full `PinnedConstraintSystem` is serialized, including gates and polynomial expressions
- **Circuit-Agnostic Verification**: Proofs can be verified using only the serialized data
- **Single Serialization Path**: One canonical way to serialize and deserialize
- **Extensible**: Reserved bytes and variable-length sections accommodate future enhancements
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
│ Typical size: 300-500 bytes                         │
└─────────────────────────────────────────────────────┘
         vk_len bytes (from footer)

┌─────────────────────────────────────────────────────┐
│ Serialized Constraint System (Variable Size)        │
│ - Column counts and queries                         │
│ - Gates with polynomial expressions                 │
│ - Lookups                                           │
│ - Permutation argument                              │
│ - Selector map                                      │
│ Typical size: 200-2000 bytes depending on circuit   │
└─────────────────────────────────────────────────────┘
         cs_len bytes (from footer)

┌─────────────────────────────────────────────────────┐
│ CosmWasm ZK Footer Metadata (32 bytes)              │
│ Section lengths and circuit metadata                │
└─────────────────────────────────────────────────────┘
```

## Footer Metadata Structure (32 Bytes)

The footer is a single unified metadata object that contains section lengths and basic circuit metadata.

### Byte Layout (Version 2)

| Offset | Size | Field | Type | Purpose |
|--------|------|-------|------|---------|
| 0 | 1 | `circuit_type` | `u8` enum | Identifies Plonkish/Halo2 variant (0 = Plonkish) |
| 1 | 1 | `instance_count` | `u8` | Number of scalar public inputs required |
| 2 | 1 | `num_fixed_columns` | `u8` | Number of fixed columns (quick reference, also in CS) |
| 3 | 1 | `num_advice_columns` | `u8` | Number of advice columns (quick reference, also in CS) |
| 4 | 1 | `num_instance_columns` | `u8` | Number of instance columns (quick reference, also in CS) |
| 5 | 1 | `degree` | `u8` | Maximum gate degree in constraint system (typically 2-4) |
| 6 | 1 | `footer_version` | `u8` | Footer format version (**2** for CS-inclusive format) |
| 7 | 1 | `flags` | `u8` | Feature flags (bit 0: CS section present) |
| 8-11 | 4 | `params_len` | `u32` LE | Byte length of halo2 params section |
| 12-15 | 4 | `vk_len` | `u32` LE | Byte length of halo2 verifying key section |
| 16-19 | 4 | `cs_len` | `u32` LE | Byte length of serialized constraint system section |
| 20-23 | 4 | `num_selectors` | `u32` LE | Number of selectors (quick reference) |
| 24-27 | 4 | `num_gates` | `u32` LE | Number of gates (quick reference) |
| 28-31 | 4 | `crc32` | `u32` LE | CRC32 checksum of params+vk+cs bytes |

<!-- 
```
╔═══════════════════════════════════════════════════════════════════╗
║                         Byte Layout (Version 2)                   ║
╠═════════════╦═════════════════════════════════════════════════════╣
║  0          ║ circuit_type (1 byte)                               ║
╠═════════════╬═════════════════════════════════════════════════════╣
║  1          ║ instance_count (1 byte)                             ║
╠═════════════╬═════════════════════════════════════════════════════╣
║  2          ║ num_fixed_columns (1 byte)                          ║
╠═════════════╬═════════════════════════════════════════════════════╣
║  3          ║ num_advice_columns (1 byte)                         ║
╠═════════════╬═════════════════════════════════════════════════════╣
║  4          ║ num_instance_columns (1 byte)                       ║
╠═════════════╬═════════════════════════════════════════════════════╣
║  5          ║ degree (1 byte)                                     ║
╠═════════════╬═════════════════════════════════════════════════════╣
║  6          ║ footer_version (1 byte)                             ║
╠═════════════╬═════════════════════════════════════════════════════╣
║  7          ║ flags (1 byte)                                      ║
╠═════════════╬═════════════════════════════════════════════════════╣
║  8  - 11    ║ params_len (4 bytes, LE)                            ║
╠═════════════╬═════════════════════════════════════════════════════╣
║  12 - 15    ║ vk_len (4 bytes, LE)                                ║
╠═════════════╬═════════════════════════════════════════════════════╣
║  16 - 19    ║ cs_len (4 bytes, LE)                                ║
╠═════════════╬═════════════════════════════════════════════════════╣
║  20 - 23    ║ num_selectors (4 bytes, LE)                         ║
╠═════════════╬═════════════════════════════════════════════════════╣
║  24 - 27    ║ num_gates (4 bytes, LE)                             ║
╠═════════════╬═════════════════════════════════════════════════════╣
║  28 - 31    ║ crc32 (4 bytes, LE)                                 ║
╚═════════════╩═════════════════════════════════════════════════════╝

``` -->

> **Total Footer Size: 32 bytes exactly**

### Footer Flags (byte 7)

| Bit | Name | Description |
|-----|------|-------------|
| 0 | `HAS_CS` | Constraint system section is present (must be 1 for version 2) |
| 1 | `HAS_LOOKUPS` | Circuit contains lookup arguments |
| 2-7 | Reserved | Reserved for future use |

## Constraint System Serialization Format

The constraint system section contains the complete `PinnedConstraintSystem` data needed for verification. This enables circuit-agnostic proof verification.

### CS Section Overview

```
┌─────────────────────────────────────────────────────┐
│ CS Header (16 bytes)                                │
│ - Column counts, selector count, gate count         │
└─────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────┐
│ Selector Map (variable)                             │
│ - Maps selectors to fixed column combinations       │
└─────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────┐
│ Gates (variable)                                    │
│ - Gate names, constraints, polynomial expressions   │
└─────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────┐
│ Queries (variable)                                  │
│ - Advice, instance, and fixed column queries        │
└─────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────┐
│ Permutation Argument (variable)                     │
│ - Columns participating in copy constraints         │
└─────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────┐
│ Lookups (variable, optional)                        │
│ - Lookup argument definitions                       │
└─────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────┐
│ Constants (variable)                                │
│ - Fixed columns used for constants                  │
└─────────────────────────────────────────────────────┘
```

### CS Header (16 bytes)

| Offset | Size | Field | Type | Description |
|--------|------|-------|------|-------------|
| 0-3 | 4 | `num_fixed_columns` | `u32` LE | Number of fixed columns |
| 4-7 | 4 | `num_advice_columns` | `u32` LE | Number of advice columns |
| 8-11 | 4 | `num_instance_columns` | `u32` LE | Number of instance columns |
| 12-13 | 2 | `num_selectors` | `u16` LE | Number of selectors |
| 14-15 | 2 | `num_gates` | `u16` LE | Number of gates |

### Selector Map Serialization

The selector map defines how simple selectors are combined into fixed columns.

```
[num_selectors: u16 LE]
For each selector:
  [num_combinations: u16 LE]
  For each combination:
    [fixed_column_index: u16 LE]
    [is_negated: u8] (0 = false, 1 = true)
```

### Gate Serialization

Each gate contains a name, constraint names, polynomial expressions, and query information.

```
[num_gates: u16 LE]
For each gate:
  [name_len: u16 LE]
  [name: UTF-8 bytes]
  [num_constraints: u16 LE]
  For each constraint:
    [constraint_name_len: u16 LE]
    [constraint_name: UTF-8 bytes]
    [expression: Expression] (see Expression Serialization)
  [num_queried_selectors: u16 LE]
  For each queried selector:
    [selector_index: u16 LE]
    [is_simple: u8] (0 = false, 1 = true)
  [num_queried_cells: u16 LE]
  For each queried cell:
    [column: Column] (see Column Serialization)
    [rotation: i32 LE]
```

### Expression Serialization (Recursive Tree)

Expressions are serialized using a tag byte followed by variant-specific data:

| Tag | Variant | Data |
|-----|---------|------|
| 0x00 | `Constant(F)` | `[scalar: 32 bytes LE]` |
| 0x01 | `Selector(Selector)` | `[index: u16 LE][is_simple: u8]` |
| 0x02 | `Fixed(QueryIndex)` | `[query_index: u16 LE]` |
| 0x03 | `Advice(QueryIndex)` | `[query_index: u16 LE]` |
| 0x04 | `Instance(QueryIndex)` | `[query_index: u16 LE]` |
| 0x05 | `Negated(Box<Expr>)` | `[inner: Expression]` |
| 0x06 | `Sum(Box<Expr>, Box<Expr>)` | `[left: Expression][right: Expression]` |
| 0x07 | `Product(Box<Expr>, Box<Expr>)` | `[left: Expression][right: Expression]` |
| 0x08 | `Scaled(Box<Expr>, F)` | `[inner: Expression][scalar: 32 bytes LE]` |

**Scalar Encoding**: Field elements (vesta::Scalar) are serialized as 32-byte little-endian representations using `to_repr()`.

### Column Serialization

```
[column_type: u8]  // 0 = Fixed, 1 = Advice, 2 = Instance
[column_index: u16 LE]
```

### Query Serialization

```
// Advice Queries
[num_advice_queries: u16 LE]
For each query:
  [column_index: u16 LE]
  [rotation: i32 LE]

// Instance Queries
[num_instance_queries: u16 LE]
For each query:
  [column_index: u16 LE]
  [rotation: i32 LE]

// Fixed Queries
[num_fixed_queries: u16 LE]
For each query:
  [column_index: u16 LE]
  [rotation: i32 LE]
```

### Permutation Argument Serialization

```
[num_permutation_columns: u16 LE]
For each column:
  [column_type: u8]  // 0 = Fixed, 1 = Advice, 2 = Instance
  [column_index: u16 LE]
```

### Lookup Argument Serialization

```
[num_lookups: u16 LE]
For each lookup:
  [name_len: u16 LE]
  [name: UTF-8 bytes]
  [num_input_expressions: u16 LE]
  For each input:
    [expression: Expression]
  [num_table_expressions: u16 LE]
  For each table:
    [expression: Expression]
```

### Constants Serialization

```
[num_constants: u16 LE]
For each constant column:
  [column_index: u16 LE]
```

### Minimum Degree (Optional)

```
[has_minimum_degree: u8]  // 0 = None, 1 = Some
If has_minimum_degree == 1:
  [minimum_degree: u32 LE]
```

## Serialization and Deserialization

### Serialization Process (Version 2)

When writing a circuit's verifying key and constraint system for CosmWasm storage:

1. Generate verifying key using `plonk::keygen_vk(&params, &circuit)`
2. Get the constraint system via `circuit.configure()` and extract `PinnedConstraintSystem`
3. Serialize params to byte buffer using `params.write()`
4. Serialize verifying key to byte buffer using `vk.write()`
5. **Serialize constraint system** to byte buffer using `ConstraintSystem::write()`:
   - Write CS header (column counts, selector count, gate count)
   - Write selector map
   - Write gates with polynomial expressions (recursive tree format)
   - Write advice, instance, and fixed queries
   - Write permutation argument columns
   - Write lookup arguments (if any)
   - Write constant columns
   - Write minimum degree (if set)
6. Compute CRC32 checksum of params || vk || cs bytes
7. Create CircuitFooter with:
   - `params_len`, `vk_len`, `cs_len`
   - `footer_version = 2`
   - `flags` with `HAS_CS` bit set
   - Quick reference fields (column counts, gate count)
8. Concatenate: `params_bytes || vk_bytes || cs_bytes || footer_bytes (32 bytes)`
9. Store combined file

### Deserialization Process (Version 2)

When loading a circuit's verifying key from CosmWasm storage:

1. Read entire file into memory
2. Extract and parse footer from last 32 bytes using `CircuitFooter::from_bytes()`
3. Validate footer version (must be 2) and flags (HAS_CS must be set)
4. Extract section byte ranges using lengths from footer:
   - `params_bytes = data[0..params_len]`
   - `vk_bytes = data[params_len..params_len+vk_len]`
   - `cs_bytes = data[params_len+vk_len..params_len+vk_len+cs_len]`
5. Deserialize params using `halo2::Params::read()`
6. **Deserialize constraint system** using `ConstraintSystem::read()`:
   - Read CS header
   - Read selector map
   - Read gates with polynomial expressions
   - Read all queries
   - Read permutation argument
   - Read lookups
   - Read constants
   - Read minimum degree
7. Deserialize verifying key using `halo2::VerifyingKey::read_with_cs()` passing the deserialized CS
8. Return complete VerifyingKey with proper constraint system ready for proof verification

### Backward Compatibility

Files with `footer_version = 1` (no CS section) can still be read but will require `DynamicCircuit` for deserialization. These files cannot support circuit-agnostic verification.

## Core Data Structures

### CircuitFooter (Version 2)

The `CircuitFooter` struct encodes section lengths and quick-reference metadata in 32 bytes.

- **Location**: `packages/zk/src/cosmwasm_circuit.rs`
- **Struct Name**: `CircuitFooter`
- **Key Methods**:
  - `new()`: Create footer with all metadata
  - `to_bytes()`: Serialize to exactly 32 bytes
  - `from_bytes()`: Deserialize from 32 bytes

**Fields (Version 2)**:

- `circuit_type: CircuitType` - Circuit variant identifier
- `instance_count: u8` - Number of public input scalars
- `num_fixed_columns: u8` - Quick reference (also in CS)
- `num_advice_columns: u8` - Quick reference (also in CS)
- `num_instance_columns: u8` - Quick reference (also in CS)
- `degree: u8` - Maximum polynomial degree
- `footer_version: u8` - Format version (**2** for CS-inclusive)
- `flags: u8` - Feature flags (bit 0: HAS_CS)
- `params_len: u32` - Byte length of params section
- `vk_len: u32` - Byte length of verifying key section
- `cs_len: u32` - Byte length of constraint system section
- `num_selectors: u32` - Quick reference
- `num_gates: u32` - Quick reference
- `crc32: u32` - Checksum of params+vk+cs bytes

### ConstraintSystem Serialization (halo2 extension)

New methods added to `halo2_proofs::plonk::ConstraintSystem`:

- **Location**: `halo2_proofs/src/plonk/circuit.rs`
- **New Methods**:
  - `write<W: Write>(&self, writer: &mut W) -> io::Result<()>`: Serialize complete CS
  - `read<R: Read, F: Field>(reader: &mut R) -> io::Result<Self>`: Deserialize CS

**Serialization includes**:

- All column counts
- Selector map (selector → fixed column combinations)
- Gates with full polynomial expressions (recursive tree)
- All query vectors (advice, instance, fixed)
- Permutation argument columns
- Lookup arguments with expressions
- Constant columns
- Minimum degree

### VerifyingKey Extensions (halo2 extension)

New method added to `halo2_proofs::plonk::VerifyingKey`:

- **Location**: `halo2_proofs/src/plonk/keygen.rs`
- **New Method**:
  - `read_with_cs<R: Read>(reader: &mut R, params: &Params<C>, cs: ConstraintSystem<C::Scalar>) -> io::Result<Self>`

This method deserializes the VK using a pre-built constraint system instead of calling `Circuit::configure()`.

### DynamicCircuit (Deprecated for Version 2)

For `footer_version = 2` files, `DynamicCircuit` is no longer needed because the constraint system is deserialized directly. It remains available for backward compatibility with version 1 files.

- **Location**: `packages/zk/src/cosmwasm_circuit.rs`
- **Status**: Used only for version 1 backward compatibility
- **Limitation**: Cannot support circuit-agnostic verification (gates not preserved)

### SerializedPlonkishCircuitData

Wrapper for complete circuit data with integrity information.

- **Location**: `packages/zk/src/cosmwasm_circuit.rs`
- **Struct Name**: `SerializedPlonkishCircuitData`
- **Fields**:
  - `bytes: Vec<u8>` - Complete serialized data (params + vk + cs + footer)
  - `hash: [u8; 32]` - SHA256 hash for integrity checking
  - `metadata: Vec<u8>` - Serialized footer metadata

### VerifyingKey

The complete verifying key ready for proof verification.

- **Location**: `packages/zk/src/cosmwasm_circuit.rs`
- **Struct Name**: `VerifyingKey`
- **Fields**:
  - `params: Params<vesta::Affine>` - Halo2 commitment parameters
  - `vk: plonk::VerifyingKey<vesta::Affine>` - Halo2 verifying key (with correct CS)
  - `i: usize` - Instance count
- **Key Methods**:
  - `from_bytes()`: Deserialize from combined file (version 2 with CS)
  - `from_bytes_v1()`: Legacy deserialize using DynamicCircuit (version 1)
  - `to_bytes_with_cs()`: Serialize with constraint system (version 2)
  - `parse_bytes()`: Parse and validate without full deserialization

## Validation Checklist (Version 2)

The `VerifyingKey::from_bytes()` method validates:

- ✓ File size is at least 32 bytes for footer
- ✓ Footer structure is valid 32 bytes
- ✓ Footer version is 2 (CS-inclusive format)
- ✓ HAS_CS flag is set in footer.flags
- ✓ Total size == params_len + vk_len + cs_len + 32
- ✓ All sections have non-zero length
- ✓ CircuitFooter parses successfully via `from_bytes()`
- ✓ Params deserialization succeeds with halo2::Params::read()
- ✓ **Constraint system deserialization succeeds with ConstraintSystem::read()**
- ✓ VK deserialization succeeds with halo2::VerifyingKey::read_with_cs()
- ✓ CS column counts match footer quick-reference values
- ✓ CRC32 checksum validates (if non-zero)

## Related Code Locations

| Component | Location |
|-----------|----------|
| **zk-cosmwasm (consumer)** | |
| `CircuitFooter` struct and implementation | `packages/zk/src/cosmwasm_circuit.rs` |
| `DynamicCircuit` (v1 compat) | `packages/zk/src/cosmwasm_circuit.rs` |
| `SerializedPlonkishCircuitData` | `packages/zk/src/cosmwasm_circuit.rs` |
| `VerifyingKey` wrapper | `packages/zk/src/cosmwasm_circuit.rs` |
| `check_circuit()` validation | `packages/vm/src/zk.rs` |
| Test data generation | `packages/zk/src/suite.rs` |
| **halo2 (modifications required)** | |
| `ConstraintSystem::write()` | `halo2_proofs/src/plonk/circuit.rs` (NEW) |
| `ConstraintSystem::read()` | `halo2_proofs/src/plonk/circuit.rs` (NEW) |
| `Expression::write()` | `halo2_proofs/src/plonk/circuit.rs` (NEW) |
| `Expression::read()` | `halo2_proofs/src/plonk/circuit.rs` (NEW) |
| `VerifyingKey::read_with_cs()` | `halo2_proofs/src/plonk/keygen.rs` (NEW) |
| `Gate::write()/read()` | `halo2_proofs/src/plonk/circuit.rs` (NEW) |
| `Lookup::write()/read()` | `halo2_proofs/src/plonk/lookup.rs` (NEW) |

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

## FFI Binary Format (for wasmvm integration)

When circuit data is transmitted via FFI (C/Rust/Go boundary), the `SerializedPlonkishCircuitData` is serialized into a length-prefixed binary format:

### FFI Transmission Format

```
[circuit_len: 4 bytes u32 LE]
[circuit_bytes: N bytes]
[hash: 32 bytes]
[metadata_len: 4 bytes u32 LE]
[metadata: M bytes]
```

### FFI Format Breakdown

| Offset | Size | Field | Type | Description |
|--------|------|-------|------|-------------|
| 0-3 | 4 | `circuit_len` | `u32` LE | Length of complete circuit data (params + vk + 32-byte footer) |
| 4 | N | `circuit_bytes` | `[u8; N]` | Raw circuit bytes matching the file format |
| 4+N | 32 | `hash` | `[u8; 32]` | SHA256 hash of circuit bytes for integrity verification |
| 4+N+32 | 4 | `metadata_len` | `u32` LE | Length of metadata section |
| 4+N+32+4 | M | `metadata` | `[u8; M]` | Serialized PlonkishCircuitMetadata (typically 10 bytes) |

### Rust FFI Functions

**Serialization** (Rust → FFI):

- **Function**: `cosmwasm_vm::zk::serialize_circuit_data()`
- **Location**: `packages/vm/src/zk.rs:69-92`
- **Input**: `&SerializedPlonkishCircuitData`
- **Output**: `Vec<u8>` in FFI format

**Deserialization** (FFI → Rust):

- **Function**: `cosmwasm_vm::zk::deserialize_circuit_data()`
- **Location**: `packages/vm/src/zk.rs:94-154`
- **Input**: `&[u8]` in FFI format
- **Output**: `ZkResult<SerializedPlonkishCircuitData>`

### Go Parsing Example

```go
import "encoding/binary"

func ParseCircuitData(data []byte) (circuitBytes []byte, hash [32]byte, metadata []byte, err error) {
    if len(data) < 40 { // Minimum: 4 + 0 + 32 + 4
        return nil, [32]byte{}, nil, fmt.Errorf("circuit data too short")
    }

    // Read circuit length
    circuitLen := binary.LittleEndian.Uint32(data[0:4])
    offset := 4

    // Read circuit bytes
    if offset+int(circuitLen) > len(data) {
        return nil, [32]byte{}, nil, fmt.Errorf("invalid circuit length")
    }
    circuitBytes = data[offset : offset+int(circuitLen)]
    offset += int(circuitLen)

    // Read hash (always 32 bytes)
    if offset+32 > len(data) {
        return nil, [32]byte{}, nil, fmt.Errorf("missing hash")
    }
    copy(hash[:], data[offset:offset+32])
    offset += 32

    // Read metadata length
    if offset+4 > len(data) {
        return nil, [32]byte{}, nil, fmt.Errorf("missing metadata length")
    }
    metadataLen := binary.LittleEndian.Uint32(data[offset : offset+4])
    offset += 4

    // Read metadata
    if offset+int(metadataLen) > len(data) {
        return nil, [32]byte{}, nil, fmt.Errorf("invalid metadata length")
    }
    metadata = data[offset : offset+int(metadataLen)]

    return circuitBytes, hash, metadata, nil
}
```

### Usage in wasmvm GetCircuit

The `load_circuit` FFI function uses this format:

**Rust side** (`libwasmvm/src/cache.rs`):

```rust
fn do_load_circuit(
    cache: &mut Cache<GoApi, GoStorage, GoQuerier>,
    checksum: ByteSliceView,
) -> Result<Vec<u8>, Error> {
    let checksum: Checksum = checksum.read()?;

    Ok(match cache.load_circuit(&checksum)? {
        Some(vk_data) => cosmwasm_vm::zk::serialize_circuit_data(&vk_data),
        None => Default::default(),  // Empty vector if not found
    })
}
```

**Go side** (`wasmvm.go`):

```go
func GetCircuit(cache Cache, checksum []byte) ([]byte, error) {
    cs := makeView(checksum)
    defer runtime.KeepAlive(checksum)
    errmsg := uninitializedUnmanagedVector()
    wasm, err := C.load_circuit(cache.ptr, cs, &errmsg)
    if err != nil {
        return nil, errorWithMessage(err, errmsg)
    }
    return copyAndDestroyUnmanagedVector(wasm), nil
}
```

### FFI Format Advantages

- **Simple**: No external dependencies, direct binary format
- **Efficient**: Length-prefixed fields allow skipping unknown sections
- **Complete**: Transmits circuit bytes, hash, and metadata in one call
- **Extensible**: New fields can be added by Go and Rust without breaking compatibility
- **Reversible**: Can be deserialized back to full struct if needed

## Implementation Checklist: halo2 Modifications

The following modifications are required in `halo2_proofs` to support version 2 format:

### Required New Methods

| Type | Method | Location | Purpose |
|------|--------|----------|---------|
| `Expression<F>` | `write()` | `src/plonk/circuit.rs` | Serialize expression tree |
| `Expression<F>` | `read()` | `src/plonk/circuit.rs` | Deserialize expression tree |
| `Gate<F>` | `write()` | `src/plonk/circuit.rs` | Serialize gate (name, polys, queries) |
| `Gate<F>` | `read()` | `src/plonk/circuit.rs` | Deserialize gate |
| `ConstraintSystem<F>` | `write()` | `src/plonk/circuit.rs` | Serialize complete CS |
| `ConstraintSystem<F>` | `read()` | `src/plonk/circuit.rs` | Deserialize complete CS |
| `VerifyingKey<C>` | `read_with_cs()` | `src/plonk/keygen.rs` | Deserialize VK with pre-built CS |
| `lookup::Argument<F>` | `write()` | `src/plonk/lookup.rs` | Serialize lookup argument |
| `lookup::Argument<F>` | `read()` | `src/plonk/lookup.rs` | Deserialize lookup argument |
| `permutation::Argument` | `write()` | `src/plonk/permutation.rs` | Serialize permutation columns |
| `permutation::Argument` | `read()` | `src/plonk/permutation.rs` | Deserialize permutation columns |

### Implementation Order

1. **Expression serialization** - Foundation for gate polynomial serialization
2. **Column/Query serialization** - Simple fixed-size structures
3. **Gate serialization** - Depends on Expression
4. **Lookup serialization** - Depends on Expression
5. **Permutation serialization** - Column list serialization
6. **ConstraintSystem serialization** - Orchestrates all above
7. **VerifyingKey::read_with_cs** - Uses deserialized CS instead of configure()

### Testing Requirements

- Round-trip tests for each serializable type
- Bit-exact comparison of serialized output
- Cross-version compatibility (v1 files with DynamicCircuit fallback)
- End-to-end proof verification with serialized CS
