#!/usr/bin/env bash
# Rebuild a rustc wasm32 guest (memcpy lowers to memory.copy) and run the
# VM tests that feed bulk-memory, SIMD, and env.blake3_256 through compile().
set -euo pipefail
root="$(cd "$(dirname "$0")/../../.." && pwd)"
vm="$root/packages/vm"
guest="$vm/testdata/bulk_copy_guest.rs"
out="$vm/testdata/bulk_copy_rustc.wasm"
rustc --target wasm32-unknown-unknown --crate-type cdylib -O -o "$out" "$guest"
python3 - "$out" << 'PY'
import sys
b = open(sys.argv[1], "rb").read()
# 0xFC is the bulk-memory prefix rustc emits for memcpy/memset.
if b.count(bytes([0xFC])) < 1:
    raise SystemExit("bulk_copy_rustc.wasm has no 0xFC prefix")
print(f"bulk_copy_rustc.wasm {len(b)} bytes, 0xFC count {b.count(bytes([0xFC]))}")
PY
cd "$root"
cargo test -p cosmwasm-vm --lib wasm_backend::compile::tests:: -- --test-threads=8
