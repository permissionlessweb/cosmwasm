# Capabilities

Capabilities are a mechanism to negotiate functionality between a contract and
an environment (i.e. the chain that embeds cosmwasm-vm/[wasmvm]) in a very
primitive way. The contract defines required capabilities. The environment
defines its capabilities. If the required capabilities are all available, the
contract can be used. Doing this check when the contract is first stored ensures
missing capabilities are detected early and not when a user tries to execute a
certain code path.

Note that capabilities are _not_ suitable to prevent contracts from accessing
functionality. Their purpose is to signal to the contract that some
functionality is available. Contracts are free to ignore this fact and attempt
to use unavailable functionality anyway. Therefore, not enabling a capability on
the host is _not_ a way of preventing a contract from using that functionality.

## Origin and Disambiguation

Before August 2022, we had two types of "features": app level features in the
CosmWasm VM and Cargo's build system features. In order to avoid the confusion,
the former have been renamed to capabilities.

Capabilities can be implemented in any language that compiles to Wasm whereas
features are Rust build system specific.

## Required capabilities

The contract defines required capabilities using marker export functions that
take no arguments and return no value. The name of the export needs to start
with "requires\_" followed by the name of the capability.

An example of such markers in cosmwasm-std are those:

```rust
#[cfg(feature = "iterator")]
#[no_mangle]
extern "C" fn requires_iterator() -> () {}

#[cfg(feature = "staking")]
#[no_mangle]
extern "C" fn requires_staking() -> () {}

#[cfg(feature = "stargate")]
#[no_mangle]
extern "C" fn requires_stargate() -> () {}
```

which in Wasm compile to this:

```
# ...
  (export "requires_staking" (func 181))
  (export "requires_stargate" (func 181))
  (export "requires_iterator" (func 181))
# ...
  (func (;181;) (type 12)
    nop)
# ...
  (type (;12;) (func))
```

As mentioned above, the Cargo features are independent of the capabilities we
talk about and it is perfectly fine to have a requires\_\* export that is
unconditional in a library or a contract.

The marker export functions can be executed, but the VM does not require such a
call to succeed. So a contract can use no-op implementation or crashing
implementation.

## Available capabilities

An instance of the main `Cache` has `available_capabilities` in its
`CacheOptions`. This value is set in the caller, such as
[here](https://github.com/CosmWasm/wasmvm/blob/v1.0.0-rc.0/libwasmvm/src/cache.rs#L75)
and
[here](https://github.com/CosmWasm/wasmvm/blob/v1.0.0-rc.0/libwasmvm/src/cache.rs#L62).
`capabilities_from_csv` takes a comma separated list and returns a set of
capabilities. This capabilities list is set
[in keeper.go](https://github.com/CosmWasm/wasmd/blob/v0.27.0-rc0/x/wasm/keeper/keeper.go#L100)
and
[in app.go](https://github.com/CosmWasm/wasmd/blob/v0.27.0-rc0/app/app.go#L475-L496).

## Format

The capability name needs to be allowed as a Wasm export name and be a legal
function name in Rust and other CosmWasm smart contract languages such as Go. By
convention, the name should be short and all lower ASCII alphanumerical plus
underscores.

## Built-in capabilities

Here is a list of all [built-in capabilities](CAPABILITIES-BUILT-IN.md).

## What's a good capability?

A good capability makes sense to be disabled. The examples above explain why the
capability is not present in some environments.

Also when the environment adds new functionality in a way that does not break
existing contracts (such as new queries), capabilities can be used to ensure the
contract checks the availability early on.

When functionality is always present in the VM (such as a new import implemented
directly in the VM, see [#1299]), we should not use capability. They just create
fragmentation in the CosmWasm ecosystem and increase the barrier to adoption.
Instead the `check_wasm_imports` check is used to validate this when the
contract is stored.

[wasmvm]: https://github.com/CosmWasm/wasmvm
[#1299]: https://github.com/CosmWasm/cosmwasm/pull/1299


## Built-in capabilities

Since capabilities can be created between contract and environment, we don't
know them all in the VM. This is a list of all built-in capabilities, but chains
might define others.

- `iterator` is for storage backends that allow range queries. Not all types of
  databases do that. There are trees that don't allow it and Secret Network does
  not support iterators for other technical reasons.
- `stargate` is for messages and queries that came with the Cosmos SDK upgrade
  "Stargate". It primarily includes protobuf messages and IBC support.
- `staking` is for chains with the Cosmos SDK staking module. There are Cosmos
  chains that don't use this (e.g. Tgrade).
- `ibc2` is for messages and queries that came with the Cosmos SDK upgrade
  "Ibc2".
- `cosmwasm_1_1` enables the `BankQuery::Supply` query. Only chains running
  CosmWasm `1.1.0` or higher support this.
- `cosmwasm_1_2` enables the `GovMsg::VoteWeighted` and `WasmMsg::Instantiate2`
  messages. Only chains running CosmWasm `1.2.0` or higher support this.
- `cosmwasm_1_3` enables the `BankQuery::AllDenomMetadata`,
  `BankQuery::DenomMetadata` and `DistributionQuery::DelegatorWithdrawAddress`
  queries, as well as `DistributionMsg::FundCommunityPool`. Only chains running
  CosmWasm `1.3.0` or higher support this.
- `cosmwasm_1_4` enables the `DistributionQuery::DelegationRewards`,
  `DistributionQuery::DelegationTotalRewards` and
  `DistributionQuery::DelegatorValidators` queries. Only chains running CosmWasm
  `1.4.0` or higher support this.
- `cosmwasm_2_0` enables `CosmosMsg::Any` and `QueryRequest::Grpc`. Only chains
  running CosmWasm `2.0.0` or higher support this.
- `cosmwasm_2_1` enables `IbcMsg::WriteAcknowledgement`. Only chains running
  CosmWasm `2.1.0` or higher support this.
- `cosmwasm_2_2` enables an optional additional `MigrateInfo` parameter for the
  `migrate` entrypoint, as well as IBC Fees support with `IbcMsg::PayPacketFee`,
  `IbcMsg::PayPacketFeeAsync` and `IbcQuery::FeeEnabledChannel`. Only chains
  running CosmWasm `2.2.0` or higher support this.
- `cosmwasm_3_0` enables `WasmQuery::RawRange`. Only chains running CosmWasm
  `3.0.0` or higher support this.
- `bn254` is the BN256 / alt_bn128 host: `bn254_add`, `bn254_scalar_mul`,
  `bn254_pairing_equality`. It is a default feature of this VM, and
  `wasmkeeper.BuiltInCapabilities` advertises it.
- `hash_blake` is BLAKE2b-256 and BLAKE3-256 (`blake2b_256`, `blake3_256`).
  It is a default feature of this VM. The capability name is `hash_blake`,
  with an underscore.
- `hash_poseidon` is Poseidon on Pasta (`poseidon_hash_pallas`,
  `poseidon_hash_vesta`) and `poseidon377_hash`. It is a default feature of
  this VM.
- `redpallas` is RedPallas and RedJubjub spend-auth and binding verify. It is
  a default feature of this VM.
