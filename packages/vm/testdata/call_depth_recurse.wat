;; Call-depth boundary contract.
;; go(n) places n Wasm function activations on the stack, including itself.
;; MAX_WASM_CALL_DEPTH is 1024: go(1023) and go(1024) succeed, go(1025) traps
;; CallDepthExceeded. The same trap must occur on x86_64 and aarch64.
(module
  (func (export "go") (param i32)
    local.get 0
    i32.const 1
    i32.le_s
    if
      return
    end
    local.get 0
    i32.const 1
    i32.sub
    call 0))
