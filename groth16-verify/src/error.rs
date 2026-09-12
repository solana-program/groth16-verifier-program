/// Errors from Groth16 verification and from parsing the on-chain layouts.
///
/// A plain enum with no dependency on Solana runtime error types, so that a
/// consumer outside a Solana program is not forced into `ProgramError`. The SBF
/// program maps these onto `ProgramError` at its boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Groth16Error {
    /// The proof is not exactly [`PROOF_SIZE`](crate::constants::PROOF_SIZE)
    /// bytes.
    InvalidProofLength,
    /// The verifying-key body length is not `448 + 64·(n+1)` for any `n`, or
    /// implies `n > MAX_PUBLIC_INPUTS`.
    InvalidKeyLength,
    /// `num_public_inputs` exceeds
    /// [`MAX_PUBLIC_INPUTS`](crate::constants::MAX_PUBLIC_INPUTS).
    TooManyPublicInputs,
    /// The public-input byte length is not `32 · n` for the key's `n`.
    PublicInputCountMismatch,
    /// A public input is not a canonical scalar (`≥ r`).
    NonCanonicalScalar,
    /// A group-operation syscall rejected its input: a point is not on the
    /// curve or not in the prime-order subgroup, or the input was malformed.
    /// On the verification path this means `A`, `B` or `C` is invalid — the
    /// key's points were validated at publish time.
    InvalidPoint,
    /// Every input decoded and every point validated, but the pairing product
    /// is not one: the proof does not verify.
    ProofInvalid,
    /// An account's data is too short for its header, or its declared `n`
    /// disagrees with its length.
    InvalidAccountData,
    /// An account's discriminator is not the one expected.
    WrongDiscriminator,
}
