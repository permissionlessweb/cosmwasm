# Advisory bumps (`security/advisory-bumps`)

Local only. Wasmer stays `7.5.0` with `wasmer-compiler-singlepass` at git rev
`e1edbf4ff55b0e0ccb61015ee1015d8283689fd5`. Zakura Halo2/pasta/reddsa stay on
the `../zakura-common` path patch, requirement `=5.0.0`, reddsa feature
`pallas-pasta`. No crates.io Halo2.

`cargo audit --file` was run on all 19 `Cargo.lock` files outside `target/`.
Counts are the sum of each file's `vulnerabilities found` and `allowed warnings`
lines. The same advisory is counted once per lock that still contains it.

| | vulnerabilities | allowed warnings | unique IDs |
| --- | ---: | ---: | ---: |
| before | 275 | 126 | 33 |
| after | 274 | 126 | 33 |

Workspace `./Cargo.lock` went from 3 vulnerabilities / 6 warnings to 2 / 6.
`cargo check -p cosmwasm-vm --features 'ibc2,iterator,staking,stargate,zk,bn254,hash-blake,hash-poseidon,redpallas'` exited 0.

## Cleared

- **RUSTSEC-2026-0344** (`ruzstd`) on the workspace lock. `object 0.40.0` had `ruzstd 0.9.0`. `cargo update -p ruzstd --precise 0.9.1` applies, and the vm check still builds. The advisory remains in the excluded contract locks (see below), so the ID is still in the union.

- **RUSTSEC-2026-0204** (`crossbeam-epoch`) was already clear on the workspace lock (`0.9.21`, patched `>= 0.9.20`). No update. Contract locks are still `0.9.18`.

## Requested bumps left in place

- **RUSTSEC-2026-0387** (`crypto-bigint 0.5.5`). Patched versions are `>= 0.7.6`. `cargo update -p crypto-bigint --precise 0.7.6` does not select: `elliptic-curve 0.13.8` (via `ecdsa 0.16.9` / `k256` and `p256` on the cosmwasm-crypto signature stack) requires `crypto-bigint ^0.5`. `0.7.6` is also yanked. A 0.7 major would change that stack, so 0.5.5 stays. Signature API was not edited.

- **rustls `>= 0.23.46`**, **rustls-webpki `>= 0.103.16`**, **webpki-roots / webpki-root-certs `>= 1.0.10`**. None of these crates are in the workspace lock. They appear only in excluded `contracts/*/Cargo.lock` files, pulled by stale `wasmer 5.0.6` → `ureq 2.12.1` (`rustls 0.23.22`, `rustls-webpki 0.102.8`, `webpki-roots 0.26.8`). `cargo update -p` in those packages fails before version selection: the contract manifests are outside the workspace, so they do not inherit `[patch.crates-io]` and cannot resolve `zakura-halo2-proofs =5.0.0`. Locks were not hand-edited. IDs still reported from those locks: RUSTSEC-2026-0285, RUSTSEC-2026-0346, RUSTSEC-2026-0348, RUSTSEC-2026-0349, RUSTSEC-2026-0049, RUSTSEC-2026-0098, RUSTSEC-2026-0099, RUSTSEC-2026-0104, RUSTSEC-2026-0382, RUSTSEC-2026-0381. `webpki-root-certs` is not in any lock (RUSTSEC-2026-0383 does not apply). `webpki-roots 0.26.11` is an unaffected point release, but the same resolve failure blocks it.

- **quinn-proto `>= 0.11.18`**, **h2 `>= 0.4.16`**. Not in any lock.

- **zip `>= 9.0.0`**. No `zip` crate in any lock, and no direct user in a `Cargo.toml`.

- **protobuf `>= 3.7.2`**. No `protobuf` crate. The tree does not use the 2.x `protobuf` crate API (only a comment about stargate raw protobuf messages).

- **pyo3 `>= 0.29.0`**. No Python bindings and no `pyo3` crate.

- **zstd-safe `>= 8.2.0`**, **zstd-sys `>= 2.1.2`**. Not in any lock. Workspace `ruzstd` does not depend on them.

- **pulldown-cmark `>= 0.13.5`**. Not in any lock.

- **ruzstd** in contract locks stays `0.5.0` (`wasmer-compiler 5.0.6` → `object 0.32.2`). That requirement cannot take `0.9.1`, and those locks cannot be regenerated without the zakura patch (same failure as rustls). RUSTSEC-2026-0344 remains there. RUSTSEC-2024-0400 does not apply (`unaffected < 0.7.0`).

## Other IDs still reported

Not in the bump list. Left unchanged.

Workspace `./Cargo.lock` after the bump: 2 vulnerabilities and 6 warnings.

- Vulnerabilities: RUSTSEC-2026-0387 (`crypto-bigint 0.5.5`), RUSTSEC-2026-0186 (`memmap2 0.6.2`).
- Warnings: RUSTSEC-2025-0055 (`tracing-subscriber 0.2.25`), RUSTSEC-2025-0141 (`bincode 1.3.3`), RUSTSEC-2024-0388 (`derivative 2.2.0`), RUSTSEC-2024-0436 (`paste 1.0.15`), RUSTSEC-2026-0173 (`proc-macro-error2 2.0.1`), RUSTSEC-2024-0449 (`unsafe-libyaml 0.2.11`).

Contract locks also still report, unchanged: RUSTSEC-2024-0370, RUSTSEC-2024-0436, RUSTSEC-2025-0056, RUSTSEC-2026-0001, RUSTSEC-2026-0007, RUSTSEC-2026-0012 (`keccak`, crypto-verify only), RUSTSEC-2026-0067, RUSTSEC-2026-0068, RUSTSEC-2026-0097, RUSTSEC-2026-0122, RUSTSEC-2026-0173, RUSTSEC-2026-0186, RUSTSEC-2026-0190 (`anyhow`, nested-contracts only), RUSTSEC-2026-0204, RUSTSEC-2026-0233, RUSTSEC-2026-0234, RUSTSEC-2026-0235, RUSTSEC-2026-0387, plus the rustls / webpki / ruzstd IDs above.

Raw logs: `/tmp/cosmwasm-audit-before.txt`, `/tmp/cosmwasm-audit-after.txt`.
