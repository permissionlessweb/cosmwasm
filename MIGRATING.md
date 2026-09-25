## Wasm call depth

`MAX_WASM_CALL_DEPTH` (1024) is the maximum number of Wasm function activations
on one stack, including the exported entry. It is the same on every
architecture. 1024 succeeds. 1025 traps with `CallDepthExceeded`.

Recursion deeper than that is invalid. Use a loop or an explicit heap stack.
Gas still meters work. The native stack guard is only a process backstop.

For details on smart contract migration, refer to the [CosmWasm documentation].

[CosmWasm documentation]: https://cosmwasm.github.io/core/migrating
