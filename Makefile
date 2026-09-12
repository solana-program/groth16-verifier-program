RUST_TOOLCHAIN_NIGHTLY = nightly-2026-01-22
SOLANA_CLI_VERSION = v3.1.10
# v3 needs platform-tools newer than the v1.52 shipped with solana-cli 3.1.x;
# v2 is the newest arch that toolchain builds. Override with `make SBF_ARCH=v3`.
SBF_ARCH = v2
SBF_OUT_DIR = $(PWD)/target/deploy

nightly = +${RUST_TOOLCHAIN_NIGHTLY}

# Package name -> manifest directory. Every package lives in a directory of
# the same name, so the CI matrix entries are also the paths.
make-path = $1

.PHONY: rust-toolchain-nightly solana-cli-version audit spellcheck \
	build-sbf test test-host cu fixtures coverage clippy format-check generate-clients

# Read by .github/workflows/main.yml so the versions live in one place.
rust-toolchain-nightly:
	@echo ${RUST_TOOLCHAIN_NIGHTLY}

solana-cli-version:
	@echo ${SOLANA_CLI_VERSION}

audit:
	cargo audit $(ARGS)

spellcheck:
	cargo spellcheck --code 1 $(ARGS)

# Per-package targets driven by the solana-program/actions reusable workflow:
# `make <target>-<package>` for package in program, bench, groth16-verify,
# groth16-convert.

clippy-%:
	cargo $(nightly) clippy --manifest-path $(call make-path,$*)/Cargo.toml \
		--all-targets \
		--all-features \
		-- \
		--deny=warnings $(ARGS)

format-check-%:
	cargo $(nightly) fmt --check --manifest-path $(call make-path,$*)/Cargo.toml $(ARGS)

powerset-%:
	cargo $(nightly) hack check \
		--feature-powerset \
		--all-targets \
		--manifest-path $(call make-path,$*)/Cargo.toml \
		$(ARGS)

build-doc-%:
	RUSTDOCFLAGS="--cfg docsrs -D warnings" cargo $(nightly) doc \
		--all-features \
		--no-deps \
		--manifest-path $(call make-path,$*)/Cargo.toml \
		$(ARGS)

# SBF artifacts. `groth16-program` and `groth16-bench` are the crate names, so
# the outputs are target/deploy/groth16_program.so and groth16_bench.so.
build-sbf-%:
	cargo build-sbf --arch $(SBF_ARCH) --manifest-path $(call make-path,$*)/Cargo.toml -- --locked $(ARGS)

# The Mollusk tests in `program` skip unless SBF_OUT_DIR holds both .so files;
# run `make build-sbf` first (CI restores them from the build job).
test-%:
	SBF_OUT_DIR=$(SBF_OUT_DIR) cargo test \
		--locked \
		--manifest-path $(call make-path,$*)/Cargo.toml \
		$(ARGS)

# Local convenience targets.

build-sbf: build-sbf-program build-sbf-bench

# Host-only tests: the verifier's host path, the converters, the gnark fixture.
test-host:
	cargo test --locked -p groth16-verify -p groth16-convert --all-features $(ARGS)

# Everything: build both SBF artifacts, then every test including Mollusk.
test: build-sbf test-host test-program

# The CU breakdown from docs/cu-budget.md.
cu: build-sbf
	SBF_OUT_DIR=$(SBF_OUT_DIR) cargo test --locked --manifest-path program/Cargo.toml --test cu -- --nocapture $(ARGS)

# Regenerate fixtures/gnark/*.bin (needs Go).
fixtures:
	cd fixtures/gnark/gen && go run .

# Host line coverage (needs `cargo install cargo-llvm-cov` and the
# `llvm-tools-preview` component). `program/src` and `bench/src` only execute
# inside the SBF VM, so they are excluded; their behaviour is covered by the
# Mollusk tests, whose host-side effects on the library crates are counted.
coverage: build-sbf
	SBF_OUT_DIR=$(SBF_OUT_DIR) cargo llvm-cov --workspace --all-features \
		--ignore-filename-regex '(program|bench)/src' $(ARGS)

clippy:
	cargo $(nightly) clippy --workspace --all-targets --all-features -- --deny=warnings $(ARGS)

format-check:
	cargo $(nightly) fmt --all --check $(ARGS)

# No generated clients in this repository; the reusable workflow still probes it.
generate-clients:
	exit 0
