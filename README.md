# solana-groth16-program: on-chain Groth16 verification for Solana

A circuit-agnostic Groth16 (BN254) verifier deployed as a single Solana SBF
program, written with [Pinocchio] and tuned for compute-unit cost.

One program instance verifies proofs for **any** circuit. A circuit is
identified by a verifying-key account whose address is the hash of the key
itself, so a caller pins a circuit by hardcoding one 32-byte address.

[Pinocchio]: https://github.com/anza-xyz/pinocchio

## Build and test

Host toolchain is pinned to stable `1.93.1` in `rust-toolchain.toml`. SBF
builds use `cargo build-sbf` from solana-cli `3.1.x` (platform-tools `v1.52`),
which supports SBF archs up to `v2`; `make SBF_ARCH=v3 …` works on newer
toolchains.

CI (`.github/workflows/main.yml`) runs the
[solana-program/actions](https://github.com/solana-program/actions) reusable
workflow, which drives per-package Makefile targets: `format-check-<pkg>`,
`clippy-<pkg>`, `build-doc-<pkg>` and `powerset-<pkg>` on the nightly pinned in
the Makefile, `build-sbf-<pkg>` for the SBF programs, `test-<pkg>` for every
package, plus `audit` and `spellcheck` (dictionary in
`.config/spellcheck.dic`, audit ignores in `.cargo/audit.toml`). Every one of
these runs locally with the same `make` invocation.

## License

Apache-2.0. See [LICENSE](LICENSE).
