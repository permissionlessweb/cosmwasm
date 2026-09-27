## Wasm stack height

`MAX_WASM_STACK_HEIGHT` (4096) is the operand-stack budget. A function's cost
is its local count plus its maximum operand-stack height. The counter is
injected into the Wasm bytes, so the trap is the same on every architecture.
The native stack guard remains a process backstop.

For details on smart contract migration, refer to the [CosmWasm documentation].

[CosmWasm documentation]: https://cosmwasm.github.io/core/migrating
