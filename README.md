# groth16-program: on-chain Groth16 verification for Solana

> Every instruction below exists and
> every test in [Tests](#tests) passes under Mollusk against the SBF artifact.
> The declared program id is a placeholder keypair; generate your own before
> deploying, and read [Trust assumptions](#trust-assumptions) first. Not
> audited.

A circuit-agnostic Groth16 (BN254) verifier deployed as a single Solana SBF
program, written with [Pinocchio] and tuned for compute-unit cost.

One program instance verifies proofs for **any** circuit. A circuit is
identified by a verifying-key account whose address is the hash of the key
itself, so a caller pins a circuit by hardcoding one 32-byte address — the same
role a deployed verifier contract address plays on Ethereum, without a redeploy
per circuit.

[Pinocchio]: https://github.com/anza-xyz/pinocchio

## Layout

| Path                | Kind             | Purpose                                                                     |
| ------------------- | ---------------- | --------------------------------------------------------------------------- |
| `groth16-verify/`   | `rlib`, `no_std` | The verifier itself: zero-copy views over proof/VK bytes, MSM, pairing check, account layouts, client instruction builders |
| `groth16-convert/`  | `rlib`, `std`    | Host-side bridge from gnark and arkworks serialization to the on-chain form  |
| `program/`          | `cdylib`         | Pinocchio SBF program: VK registry + `Verify`; Mollusk tests under `tests/`  |
| `bench/`            | `cdylib`         | Instrumented SBF program that isolates each stage's CU cost                  |
| `fixtures/gnark/`   | data + Go        | A gnark key, proof and public witness, and the generator that produced them  |

`groth16-verify` has no dependency on the Solana runtime error types and no
allocator on the on-chain path. A program that wants to verify inline — without
a CPI — depends on it directly. Off-chain it runs the same group operations
through `solana-bn254`'s host implementation, so the verifier is unit-testable
natively and a client can pre-check a proof before paying for a transaction.

## Verification

Groth16 verification over BN254 checks

```text
e(A, B) = e(α, β) · e(L, γ) · e(C, δ)
```

where `L = IC₀ + Σᵢ aᵢ·ICᵢ` over the public inputs `a₁..aₙ`. The program
evaluates it as a single 4-term product-of-pairings equal to one:

```text
e(A, B) · e(α, −β) · e(L, −γ) · e(C, −δ) = 1
```

`−β`, `−γ` and `−δ` are stored pre-negated in the verifying-key account, so
assembling the 768-byte pairing input on-chain is byte copying and no field
arithmetic. See [docs/design.md](docs/design.md) for why the negation sits on
the G2 side.

Two syscalls do the work:

| Syscall                   | Used for                                     |
| ------------------------- | -------------------------------------------- |
| `sol_alt_bn128_group_op`  | `ALT_BN128_G1_MUL_BE`, `ALT_BN128_G1_ADD_BE` — the public-input MSM |
| `sol_alt_bn128_group_op`  | `ALT_BN128_PAIRING_BE` — the 4-pair check    |

The pairing syscall deserializes every point with arkworks' `Validate::Yes`,
which performs the on-curve and prime-order-subgroup checks. The program does
not repeat them.

## On-chain wire format

Everything on-chain is **uncompressed, big-endian**, exactly as the syscalls
consume it. Compression is a client-side concern: decompressing a single G2
point on-chain costs 13,610 CU, more than a sixth of an entire verification.

| Element    | Size  | Encoding                                    |
| ---------- | ----- | ------------------------------------------- |
| `Fq`       | 32    | big-endian                                  |
| `Fq2`      | 64    | `c1 ‖ c0`, matching the syscall's field order |
| `G1`       | 64    | `x ‖ y`                                     |
| `G2`       | 128   | `x ‖ y`                                     |
| `Fr`       | 32    | big-endian, canonical (`< r`)               |

### Proof

256 bytes of instruction data, `A ‖ B ‖ C`:

```text
[0   ..  64]   A   (G1)
[64  .. 192]   B   (G2)
[192 .. 256]   C   (G1)
```

`A ‖ B` is contiguous because it is also the first pairing slot.

### Public inputs

`n × 32` bytes, big-endian canonical field elements, in circuit order. `IC₀` is
implicit — do not include the constant-one term.

### Verifying-key account

The canonical account exists only in finalized form — see
[Registration](#registration) — so it has no in-progress state to record.

```text
[0   ..   1]   discriminator  (1 = verifying key)
[1   ..   2]   bump           (canonical, from find_program_address)
[2   ..   4]   num_public_inputs (u16, little-endian)
[4   ..   8]   reserved
[8   ..  72]   α      (G1)          ┐
[72  .. 200]   −β     (G2)          │
[200 .. 328]   −γ     (G2)          │  body — the bytes the address commits to
[328 .. 456]   −δ     (G2)          │
[456 ..     ]  IC₀..ICₙ  ((n+1) × 64, G1)  ┘
```

Total `456 + 64·(n+1)` bytes. The body length is fully determined by `n`, and
`Publish` requires the account length to equal it exactly. `α ‖ −β` spans
`[8..200]` as one contiguous 192-byte pairing slot.

**`n ≤ 151`.** `Publish` grows the canonical account from zero inside a CPI,
and the runtime caps how much an account may grow during one top-level
instruction, measured from its length when that instruction began, at
`MAX_PERMITTED_DATA_INCREASE = 10,240` bytes. `456 + 64·152 = 10,184` fits;
`n = 152` needs 10,248 and does not. `InitializeStaging` rejects `n > 151` up
front rather than letting an upload proceed to a `Publish` that cannot succeed.
The staging account is not subject to this cap (the client creates it with a
top-level `create_account`), but that does not help: the limit is on the
canonical account, and growing it in steps would reintroduce the intermediate
state that [Registration](#registration) exists to rule out.

### Staging account

Keys are uploaded into a staging account, then published. The staging account
is created by the client through the system program with this program as
owner; the program never allocates it.

```text
[0   ..   1]   discriminator  (2 = staging)
[1   ..   2]   reserved
[2   ..   4]   num_public_inputs (u16, little-endian)
[4   ..   8]   reserved
[8   ..  40]   authority
[40  ..    ]   body, identical layout to the canonical body
```

Total `40 + 448 + 64·(n+1)` bytes, checked exactly at `InitializeStaging`.

## Instructions

| Tag | Instruction         | Accounts                                          | Signer            | Notes |
| --- | ------------------- | ------------------------------------------------- | ----------------- | ----- |
| `0` | `InitializeStaging` | authority (s), staging (w)                        | authority         | Data `num_public_inputs: u16`, rejected if `n > 151`. Requires the account be owned by the program, uninitialized, and exactly `40 + 448 + 64·(n+1)` bytes. Writes the header. **Must be in the same transaction as the `create_account` that made the staging account** — see [Registration](#registration) |
| `1` | `Write`             | authority (s), staging (w)                        | stored authority  | Data `offset: u32 ‖ bytes`. `offset` is relative to the **body**; the write must satisfy `offset + len ≤ body_len` with overflow-checked arithmetic. The header is never writable |
| `2` | `Publish`           | authority (s,w), payer (s,w), staging (w), vk PDA (w), system | stored authority | No instruction data. Validates the staging body, derives the canonical PDA from `sha256(body)`, brings it into existence at its exact final size, copies the body, writes the header — all in one instruction. Closes staging, refunding its rent to authority (which is why authority is writable) |
| `3` | `Verify`            | vk PDA (r)                                        | none              | `proof ‖ public_inputs`; the hot path |
| `4` | `CloseStaging`      | authority (s,w), staging (w)                      | stored authority  | Refunds staging rent. Canonical accounts cannot be closed |

### Registration

The canonical key PDA is derived from the key's own hash:

```text
seeds = [b"vk", sha256(vk_body)]
```

and it is only ever created by `Publish`, which allocates it and fills it in
the same instruction. There is no instruction that writes to an existing
canonical account, so the address can never exist in an unfinished or
partially-written state, and no party can create it with the wrong size, the
wrong `n`, or contents that don't hash to its address.

`Publish` checks, in order:

1. staging is owned by the program, carries the staging discriminator, and the
   signer is its recorded `authority`;
2. the staging body decodes: every G1 and G2 point is on the curve and in the
   prime-order subgroup (all-zero bytes, the syscall encoding of the identity,
   are accepted for `ICᵢ` and rejected for `α`, `−β`, `−γ`, `−δ`);
3. `find_program_address([b"vk", sha256(body)])` — the **canonical** bump,
   computed on-chain, never supplied by the caller — yields the vk PDA account's
   address, and that account is not yet owned by the program;
4. then it brings the PDA into existence with `payer` funding rent, sized
   exactly `456 + 64·(n+1)`, copies the body, writes the header (including the
   bump), and closes staging.

Step 4 does not assume the address is untouched. Anyone can transfer lamports to
a not-yet-existing address, and a plain `create_account` fails on an account
with a nonzero balance — a one-lamport transfer would otherwise be enough to
block a key from ever being published. `Publish` therefore accepts a target that
is system-owned with zero data, whatever its balance, and builds the account
piecewise: transfer the shortfall to rent-exemption (if any), `allocate`,
`assign` to the program, each signed with the PDA seeds. A target owned by the
program already is the "already published" case and fails; a target owned by
anything else is unreachable for a PDA and fails.

`Publish` costs `61,299 + 334·n` CU in point validation plus roughly 15,000 in
hashing, address derivation and CPIs; the full registration chain for the
largest key (`n = 151`) measures about 140,000 CU, inside the default budget.
Publishing clients should still simulate rather than assume. See
[docs/cu-budget.md](docs/cu-budget.md#publish).

Using the canonical bump matters for the same reason the hash does. A PDA's
seeds admit several valid bumps, and if `Publish` accepted any bump that derived
*some* program address, one key could be published at several addresses.
Callers derive with `find_program_address` and get the one the program insists
on.

The upload itself follows the BPF upgradeable loader's buffer pattern: a
private, authority-gated staging account that nobody else can write to, and
that its authority can abandon and reclaim at any time. Two uploaders working on
the same key don't interact until `Publish`, and whichever publishes second
fails harmlessly on step 3 — the key is already available at its address.

One client-side rule keeps the staging account private: **`create_account` and
`InitializeStaging` go in the same transaction.** `InitializeStaging` can only
check that the account is program-owned and blank; it has no way to know who
paid for it. An account created in one transaction and initialized in the next
can be initialized by a third party in between, who then owns its rent through
`CloseStaging`. The subsequent `Write`s may be spread over as many transactions
as the key needs. Small keys fit `create_account ‖ InitializeStaging ‖ Write ‖
Publish` in one transaction; large ones take several, with no window in which a
third party can affect the outcome.

The consequence is that **the address is a commitment to the verifying key**. A
program CPI-ing into the verifier hardcodes the expected PDA:

```rust
const PAYMENT_CIRCUIT_VK: Address = address!("...");

// The verifier checks the account is owned by it and carries the key
// discriminator; the caller checks the address is the circuit it meant.
// Together that is equivalent to a per-circuit deployed contract.
```

A different verifying key is a different address. There is no upgrade path for
a key, by design — upgrading a circuit means publishing a new key at its new
address and pointing callers at it.

### Trust assumptions

The commitment above holds only as long as the program's own code holds. The
intended deployment is **immutable**: deployed with the upgrade authority set to
`None` (`solana program deploy --final`, or `set-upgrade-authority --final`
afterwards), so that neither the verification logic nor the "no instruction
writes to a canonical account" property can change under a caller.

If a deployment keeps its upgrade authority — for instance during audit — then
every caller is trusting that authority not to replace the program with one that
verifies differently or rewrites key accounts. Callers should check the
program's upgrade authority before hardcoding anything, exactly as they would
check a proxy admin on Ethereum.

### `Verify` semantics

Returns `Ok(())` when the proof verifies. Verification and layout failures
surface as `ProgramError::Custom(code)` with stable codes (see
[program/src/error.rs](program/src/error.rs)): `6` is "well-formed proof that
does not verify", `5` is "a proof point failed the curve or subgroup check",
`3` is a public-input count mismatch, `4` a non-canonical scalar. Account-level
failures use the standard variants (`InvalidAccountOwner`, `InvalidArgument`
for a wrong account count).

`Verify` performs no PDA re-derivation: hashing the key and running the
off-curve derivation on every verification would cost compute units to
re-establish something the caller already asserted by choosing the address. It
checks only that the account is owned by the program and carries the key
discriminator. Both are sufficient because the program creates key accounts
through exactly one path, `Publish`, which enforces everything else.

## Compute units

Syscall costs are fixed by the runtime; the program's job is to invoke the
minimum number of them and add as little SBF overhead as possible. Measured
end-to-end under Mollusk (`make cu`), random public inputs:

| `n` | Syscall floor | `Verify` end-to-end | Overhead |
| --- | ------------- | ------------------- | -------- |
| 0   | 73,612        | 74,037              | 425      |
| 1   | 77,786        | 78,444              | 658      |
| 2   | 81,960        | 82,851              | 891      |
| 8   | 106,996       | 109,293             | 2,297    |
| 16  | 140,396       | 144,549             | 4,153    |
| 32  | 207,180       | 215,061             | 7,881    |

The floor is `73,612 + 4,174·n` (one 4-pair pairing, one G1 multiply and one
G1 add per input). Everything above it is SBF: about 400 CU fixed — entrypoint,
account checks, buffer assembly, result decode — plus about 233 per public
input. Reading the key from an account measures no more expensive than reading
it from instruction data. Inputs equal to `0` or `1` skip the multiply: with all
eight inputs zero, `n = 8` verifies in 74,733 CU.

The pairing dominates for small circuits — 95% of the cost at `n = 1`. The MSM
overtakes it past roughly 18 public inputs. Full derivation, the measurement
methodology, and the stage-by-stage tables are in
[docs/cu-budget.md](docs/cu-budget.md).

## Tests

| Test                                       | What it covers                                                     |
| ------------------------------------------ | ------------------------------------------------------------------ |
| `groth16-verify` unit tests                | Scalar comparisons, key length inference, account header round-trips |
| `groth16-convert` unit tests + `tests/gnark_fixture.rs` | Point encoding round-trips, gnark decompression of both roots and the identity, and the fixture parsed from both compressed and raw encodings, verified by arkworks and by the verifier's host path |
| `program/tests/gnark.rs`                   | The gnark fixture registered through the real instruction flow and verified on SBF; wrong input, tampered proof, wrong input count and non-canonical scalar each rejected with the right code |
| `program/tests/arkworks.rs`                | Fresh random arkworks setups and proofs every run for `n ∈ {0, 1, 2, 5, 8}`; inputs of exactly `0` and `1` through the skip paths; a proof under the wrong key |
| `program/tests/registry.rs`                | Every registration guarantee from `docs/design.md §2`: pre-funded target, payer ≠ authority, non-canonical bump, body/address mismatch, invalid and identity points, republish, `n = 151` and `n = 152`, `Write` bounds, staging authority, `Verify` account checks |
| `program/tests/malformed.rs`               | Every early-rejection path: unknown tag, empty data, short proof, key account length/header mismatch, missing signers, wrong owners, read-only accounts, short payloads, uninitialized staging, wrong publisher |
| `program/tests/cu.rs`                      | The CU breakdown from `docs/cu-budget.md`, asserting every stage delta is at or above its syscall floor |

The SBF tests skip unless `SBF_OUT_DIR` is set; `make test` builds the
artifacts and sets it (`make test-program` alone sets it and expects the
artifacts to exist, which is how CI runs it). Both end-to-end tests go through
`groth16-convert`, so the serialization bridge is exercised on every run.

`make coverage` reports host line coverage for `groth16-verify` and
`groth16-convert` (`cargo-llvm-cov`), counting what the Mollusk tests drive
through them from the host side; it stands at about 97%. `program/src` and
`bench/src` run only inside the SBF VM and cannot be line-profiled — their
coverage is the behavioural matrix above, where every instruction's success
path and every documented rejection has a test that pins the returned error.

## Build and test

Host toolchain is pinned to stable `1.93.1` in `rust-toolchain.toml`. SBF
builds use `cargo build-sbf` from solana-cli `3.1.x` (platform-tools `v1.52`),
which supports SBF archs up to `v2`; `make SBF_ARCH=v3 …` works on newer
toolchains. Regenerating the gnark fixture needs Go 1.24.

```sh
make test-host           # groth16-verify + groth16-convert, including the gnark fixture
make build-sbf           # target/deploy/groth16_program.so and groth16_bench.so
make test                # the above two, then every Mollusk test
make cu                  # the CU breakdown tables
make fixtures            # regenerate fixtures/gnark/*.bin (new trusted setup each time)
make clippy format-check # nightly clippy and rustfmt over the whole workspace
```

CI (`.github/workflows/main.yml`) runs the
[solana-program/actions](https://github.com/solana-program/actions) reusable
workflow, which drives per-package Makefile targets: `format-check-<pkg>`,
`clippy-<pkg>`, `build-doc-<pkg>` and `powerset-<pkg>` on the nightly pinned in
the Makefile, `build-sbf-<pkg>` for `program` and `bench`, `test-<pkg>` for
every package, plus `audit` and `spellcheck` (dictionary in
`.config/spellcheck.dic`, audit ignores in `.cargo/audit.toml`). Every one of
these runs locally with the same `make` invocation.
