;; Bulk-memory prefix 0xFC. Store one byte, then memory.copy it.
(module
  (memory (export "memory") 1)
  (func (export "go") (result i32)
    (i32.store8 (i32.const 0) (i32.const 0x11))
    (memory.copy (i32.const 8) (i32.const 0) (i32.const 1))
    (i32.load8_u (i32.const 8)))
)
