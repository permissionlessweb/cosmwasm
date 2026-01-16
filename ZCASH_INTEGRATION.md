# ZK-CosmWasm: Sovereign Appchains  
**Settling to Zcash via Crosslink**  
**L2 Infrastructure with Native Zcash Interoperability**

## Executive Summary

This proposal reframes ZK-CosmWasm as an independent L2/appchain product that settles state transitions to Zcash via Crosslink's deterministic finality, rather than embedding a VM into Zcash's core protocol.  

This architectural separation preserves Zcash's minimalist consensus layer while enabling a rich ecosystem of privacy-preserving smart contract applications.

The key innovation is an **opt-in validator market** where Crosslink PoS validators can choose to participate in L2 consensus, earning additional yield while extending Zcash's security guarantees to appchains.  

State commitments are anchored to Zcash L1 through simple, auditable settlement transactions — **no VM execution** on the base layer.

## Architectural Principles

- Separation of Concerns
- Layer Separation Model
- Settlement Model

### What Gets Posted to Zcash L1

The L2 posts **minimal, fixed-size data** to Zcash — no contract execution, no variable computation.

| Item                          | Size     | Description                                      |
|-------------------------------|----------|--------------------------------------------------|
| State root / commitment       | ~32 bytes| Merkle root of L2 state                          |
| Validity proof (Halo2)        | ~1.2 KB  | Succinct proof of correct state transition       |
| Validator signatures / quorum | ~1 KB    | Aggregated signatures or quorum certificate      |
| Metadata (chain_id, height)   | ~100 bytes| Basic context for verification                   |
| **Total per settlement**      | **~2.5 KB** | Fits comfortably in one Zcash transaction     |

## Opt-in Validator Market

### How Crosslink Validators Participate

Crosslink validators can optionally run L2 validator software alongside their Zcash node:

| Step              | Description                                                                                     |
|-------------------|-------------------------------------------------------------------------------------------------|
| **Registration**  | Post registration tx on Zcash with L2 pubkey + list of appchains they will validate            |
| **Stake Extension**| Existing Crosslink stake used as slashable collateral for L2 misbehavior (no extra stake needed)|
| **L2 Consensus**  | Run Malachite BFT → participate in block proposal and finality voting on chosen L2s            |
| **Settlement**    | Any participating validator can submit final L2 batch settlement tx to Zcash L1                |

**Economic note**: L2 rewards are **additive** — validators earn from L2s **on top of** their normal Crosslink L1 staking rewards.

## Proposed L2 Contract Functions

These functions live **only on L2 appchains** (not on Zcash L1):

| Category                     | Functions                              | Purpose                                          |
|------------------------------|----------------------------------------|--------------------------------------------------|
| Cross-Chain Settlement       | `verify_zcash_finality()`<br>`verify_shielded_deposit()` | Verify Zcash finality & shielded asset inflows   |
| IBC Light Client             | `update_zcash_client()`<br>`verify_ibc_packet()` | Maintain & verify IBC connection to Zcash        |
| ZK Verification Primitives   | Generic ZK verify functions            | Allow any L2 contract to verify Halo2/zk-SNARKs  |

## Minimal Zcash L1 Changes

| Change                        | Estimated Code | Description                                                  |
|-------------------------------|----------------|--------------------------------------------------------------|
| New Memo Type                 | ~500 lines     | `OP_L2_SETTLE` — parses & validates settlement transactions  |
| Halo2 Verifier                | Already exists | Reuse existing Orchard/Halo2 verifier circuit                |
| L2 Registry                   | ~200 lines     | Simple key-value: `chain_id → verification_key`              |
| Validator Registration Memo   | ~100 lines     | Lets validators signal L2 participation                      |
| **Total estimated changes**   | **~800 lines** | **No VM, no contract execution, no state bloat**             |

## Value Proposition

### For the Zcash Ecosystem

| Benefit                        | Description                                                                 |
|--------------------------------|-----------------------------------------------------------------------------|
| Minimal L1 Risk                | No VM execution — Zcash stays clean, auditable settlement layer             |
| Programmability Without Bloat  | Smart contracts run on L2, inherit Zcash finality                           |
| IBC Connectivity               | Native connection to 100+ Cosmos chains via IBC                             |
| Validator Yield Enhancement    | Crosslink validators earn extra revenue from L2 participation               |

### For L2 Appchain Builders

| Benefit                        | Description                                                                 |
|--------------------------------|-----------------------------------------------------------------------------|
| Privacy-First Settlement       | Settle to a chain with native shielded transactions                         |
| Shared Security                | Use Crosslink validators — no need to bootstrap new validator set           |
| CosmWasm Ecosystem             | Battle-tested VM, mature tooling, large developer community                 |
| ZK Native                      | Built-in ZK proof verification primitives for privacy-preserving apps       |

## Conclusion

This revised architecture positions ZK-CosmWasm as an **independent L2/appchain product** that settles to Zcash via Crosslink — without embedding complexity into Zcash core.

**Key innovations**:

- Settlement-only L1: Zcash stores only roots + proofs — **no VM execution**
- Opt-in validator market: Crosslink validators earn extra yield for L2 work
- Native IBC: Direct connection to the Cosmos ecosystem
- ZK verification layer: Native support for privacy-preserving smart contracts

This delivers **programmable privacy** to the Zcash ecosystem while preserving the simplicity, auditability, and minimalist philosophy of the base layer — a true win-win separation of concerns.