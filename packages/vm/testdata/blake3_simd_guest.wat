;; Contract-shaped guest. Same import as cosmwasm_std::Api::blake3_256
;; (env.blake3_256 : region ptr, region ptr -> i32).
;; The digest is the host BLAKE3 (native SIMD). Guest SIMD stays out of
;; this module: the engine gatekeeper rejects 0xFD.
(module
  (import "env" "blake3_256" (func $blake3_256 (param i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 100) "terp")
  (func (export "ping") (result i32) (i32.const 7))
  (func (export "hash") (result i32)
    ;; input Region { offset: 100, capacity: 4, length: 4 }
    (i32.store (i32.const 0) (i32.const 100))
    (i32.store (i32.const 4) (i32.const 4))
    (i32.store (i32.const 8) (i32.const 4))
    ;; output Region { offset: 200, capacity: 32, length: 32 }
    (i32.store (i32.const 16) (i32.const 200))
    (i32.store (i32.const 20) (i32.const 32))
    (i32.store (i32.const 24) (i32.const 32))
    (call $blake3_256 (i32.const 0) (i32.const 16)))
)
