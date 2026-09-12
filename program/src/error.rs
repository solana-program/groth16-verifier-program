//! Error surface of the program.
//!
//! Verification and layout errors from [`solana_groth16_verify`] are exposed as
//! `ProgramError::Custom(code)` with the codes below, so a CPI caller can tell
//! "proof did not verify" apart from "malformed input". Registry-level
//! failures use the standard `ProgramError` variants that describe them.

use {pinocchio::error::ProgramError, solana_groth16_verify::Groth16Error};

/// Custom error codes. Stable; append only.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Groth16ProgramError {
    // 0..=9 mirror `Groth16Error` in declaration order.
    InvalidProofLength = 0,
    InvalidKeyLength = 1,
    TooManyPublicInputs = 2,
    PublicInputCountMismatch = 3,
    NonCanonicalScalar = 4,
    InvalidPoint = 5,
    ProofInvalid = 6,
    InvalidAccountData = 7,
    WrongDiscriminator = 8,

    // Registry.
    /// The supplied key account is not the canonical address for the staged
    /// key body (`find_program_address([b"vk", sha256(body)])`).
    KeyAddressMismatch = 100,
    /// The canonical key account already exists (is owned by this program).
    KeyAlreadyPublished = 101,
    /// The staging account's length does not match `40 + 448 + 64·(n+1)`.
    StagingSizeMismatch = 102,
    /// A `Write` would extend past the end of the staging body.
    WriteOutOfBounds = 103,
    /// A verifying-key element that must not be the identity is the identity.
    IdentityKeyElement = 104,
}

impl From<Groth16ProgramError> for ProgramError {
    fn from(e: Groth16ProgramError) -> Self {
        ProgramError::Custom(e as u32)
    }
}

pub fn map_groth16(e: Groth16Error) -> ProgramError {
    use Groth16ProgramError as P;
    let code = match e {
        Groth16Error::InvalidProofLength => P::InvalidProofLength,
        Groth16Error::InvalidKeyLength => P::InvalidKeyLength,
        Groth16Error::TooManyPublicInputs => P::TooManyPublicInputs,
        Groth16Error::PublicInputCountMismatch => P::PublicInputCountMismatch,
        Groth16Error::NonCanonicalScalar => P::NonCanonicalScalar,
        Groth16Error::InvalidPoint => P::InvalidPoint,
        Groth16Error::ProofInvalid => P::ProofInvalid,
        Groth16Error::InvalidAccountData => P::InvalidAccountData,
        Groth16Error::WrongDiscriminator => P::WrongDiscriminator,
    };
    code.into()
}
