# solana-groth16-program: on-chain Groth16 verification for Solana

A circuit-agnostic Groth16 (BN254) verifier deployed as a single Solana SBF
program, written with [Pinocchio] and tuned for compute-unit cost.

One program instance verifies proofs for **any** circuit. A circuit is
identified by a verifying-key account whose address is the hash of the key
itself, so a caller pins a circuit by hardcoding one 32-byte address.

[Pinocchio]: https://github.com/anza-xyz/pinocchio

## Layout

This repository currently holds the workspace, toolchain pins, Makefile and CI.
The crates arrive in follow-up PRs, in the layout the Makefile and CI matrix
already expect:

| Path                    | Kind             | Purpose                                                                 |
| ----------------------- | ---------------- | ----------------------------------------------------------------------- |
| `groth16-verify/`       | `rlib`, `no_std` | `solana-groth16-verify`: the verifier itself and client instruction builders |
| `program/`              | `cdylib`         | `solana-groth16-program`: Pinocchio SBF program; Mollusk tests under `tests/` |
| `tools/convert/`        | `rlib`, `std`    | `groth16-convert`: host-side bridge from gnark and arkworks serialization   |
| `tools/bench/`          | `cdylib`         | `groth16-bench`: instrumented SBF program isolating each stage's CU cost    |
| `tools/fixtures/gnark/` | data + Go        | A gnark key, proof and public witness, and the generator that produced them |

`groth16-verify` and `program` are what a consumer depends on; everything under
`tools/` is host-side development tooling.

## Build and test

Host toolchain is pinned to stable `1.93.1` in `rust-toolchain.toml`. SBF
builds use `cargo build-sbf` from solana-cli `3.1.x` (platform-tools `v1.52`),
which supports SBF archs up to `v2`; `make SBF_ARCH=v3 …` works on newer
toolchains. Both versions, and the nightly used for rustfmt and clippy, live at
the top of the `Makefile` and are read from there by CI.

```sh
make test-host           # host-only tests: solana-groth16-verify + groth16-convert
make build-sbf           # target/deploy/solana_groth16_program.so and groth16_bench.so
make test                # the above two, then every Mollusk test
make cu                  # the CU breakdown tables
make coverage            # host line coverage via cargo-llvm-cov
make fixtures            # regenerate tools/fixtures/gnark/*.bin (needs Go)
make clippy format-check # nightly clippy and rustfmt over the whole workspace
```

CI (`.github/workflows/main.yml`) runs the
[solana-program/actions](https://github.com/solana-program/actions) reusable
workflow, which drives per-package Makefile targets: `format-check-<pkg>`,
`clippy-<pkg>`, `build-doc-<pkg>` and `powerset-<pkg>` on the nightly pinned in
the Makefile, `build-sbf-<pkg>` for the SBF programs, `test-<pkg>` for every
package, plus `audit` and `spellcheck` (dictionary in
`.config/spellcheck.dic`, audit ignores in `.cargo/audit.toml`). Every one of
these runs locally with the same `make` invocation. The package lists at the top
of the workflow are empty until the crates land, so only `audit` and
`spellcheck` run today.

## License

Apache-2.0. See [LICENSE](LICENSE).
