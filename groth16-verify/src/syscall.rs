//! Thin, allocation-free wrappers over `sol_alt_bn128_group_op`.
//!
//! On-chain, each function issues the raw syscall into a caller-provided
//! stack buffer. Off-chain, the same functions run the host implementation
//! from `solana-bn254` so that the verifier can be unit-tested natively and
//! the client can pre-validate before spending a transaction. Both paths share
//! error semantics: a failed syscall — malformed input, off-curve or
//! out-of-subgroup point — is [`Groth16Error::InvalidPoint`].

use crate::{
    constants::{
        ALT_BN128_G1_ADD_BE, ALT_BN128_G1_MUL_BE, ALT_BN128_PAIRING_BE, FR_SIZE, G1_ADD_INPUT_SIZE,
        G1_MUL_INPUT_SIZE, G1_SIZE, PAIRING_ELEMENT_SIZE, PAIRING_OUTPUT_SIZE,
    },
    error::Groth16Error,
};

/// `a + b` in G1.
#[inline]
pub fn g1_add(a: &[u8; G1_SIZE], b: &[u8; G1_SIZE]) -> Result<[u8; G1_SIZE], Groth16Error> {
    let mut input = [0u8; G1_ADD_INPUT_SIZE];
    input[..G1_SIZE].copy_from_slice(a);
    input[G1_SIZE..].copy_from_slice(b);
    let mut out = [0u8; G1_SIZE];
    group_op(ALT_BN128_G1_ADD_BE, &input, &mut out)?;
    Ok(out)
}

/// `scalar · p` in G1. The scalar is big-endian and must be canonical; callers
/// check that before reaching here.
#[inline]
pub fn g1_mul(p: &[u8; G1_SIZE], scalar: &[u8; FR_SIZE]) -> Result<[u8; G1_SIZE], Groth16Error> {
    let mut input = [0u8; G1_MUL_INPUT_SIZE];
    input[..G1_SIZE].copy_from_slice(p);
    input[G1_SIZE..].copy_from_slice(scalar);
    let mut out = [0u8; G1_SIZE];
    group_op(ALT_BN128_G1_MUL_BE, &input, &mut out)?;
    Ok(out)
}

/// Product-of-pairings check over `input.len() / 192` pairs.
///
/// Returns `Ok(true)` when the product is one, `Ok(false)` when every point
/// decoded but the product is not one, and `Err(InvalidPoint)` when the
/// syscall rejected a point or `input` is not a whole number of pairs. The
/// length is checked here, before the syscall, so that an incomplete input
/// fails the same way in every build profile and on every backend.
#[inline]
pub fn pairing_is_one(input: &[u8]) -> Result<bool, Groth16Error> {
    if !input.len().is_multiple_of(PAIRING_ELEMENT_SIZE) {
        return Err(Groth16Error::InvalidPoint);
    }
    let mut out = [0u8; PAIRING_OUTPUT_SIZE];
    group_op(ALT_BN128_PAIRING_BE, input, &mut out)?;
    // A big-endian 0 or 1: the last byte carries it, everything else is zero.
    Ok(out[PAIRING_OUTPUT_SIZE - 1] == 1)
}

/// Runs the syscall as a pure validity check: succeeds iff `input` is a whole
/// number of pairs and every point in it deserializes with the runtime's
/// on-curve and subgroup checks. The pairing result is discarded. Used at
/// publish time.
#[inline]
pub fn pairing_validate_points(input: &[u8]) -> Result<(), Groth16Error> {
    pairing_is_one(input).map(|_| ())
}

#[cfg(target_os = "solana")]
#[inline]
fn group_op(op: u64, input: &[u8], out: &mut [u8]) -> Result<(), Groth16Error> {
    // SAFETY: `input` and `out` are valid for the lengths passed, and the
    // syscall writes exactly `out.len()` bytes for the given `op`.
    let rc = unsafe {
        pinocchio::syscalls::sol_alt_bn128_group_op(
            op,
            input.as_ptr(),
            input.len() as u64,
            out.as_mut_ptr(),
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(Groth16Error::InvalidPoint)
    }
}

#[cfg(not(target_os = "solana"))]
fn group_op(op: u64, input: &[u8], out: &mut [u8]) -> Result<(), Groth16Error> {
    use solana_bn254::prelude::{
        alt_bn128_g1_addition_be, alt_bn128_g1_multiplication_be, alt_bn128_pairing_be,
    };
    let result = match op {
        ALT_BN128_G1_ADD_BE => alt_bn128_g1_addition_be(input),
        ALT_BN128_G1_MUL_BE => alt_bn128_g1_multiplication_be(input),
        ALT_BN128_PAIRING_BE => alt_bn128_pairing_be(input),
        _ => unreachable!("unsupported alt_bn128 opcode {op}"),
    }
    .map_err(|_| Groth16Error::InvalidPoint)?;
    out.copy_from_slice(&result);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An input that is not a whole number of pairs is an error, not a panic,
    /// from both helpers: one byte short of a pair and one byte past it.
    #[test]
    fn incomplete_pairing_input_is_an_error() {
        for len in [1, PAIRING_ELEMENT_SIZE - 1, PAIRING_ELEMENT_SIZE + 1] {
            let input = std::vec![0u8; len];
            assert_eq!(
                pairing_is_one(&input),
                Err(Groth16Error::InvalidPoint),
                "pairing_is_one, len {len}"
            );
            assert_eq!(
                pairing_validate_points(&input),
                Err(Groth16Error::InvalidPoint),
                "pairing_validate_points, len {len}"
            );
        }
    }

    /// Whole pairs still reach the backend: a pair of identity points is a
    /// valid input whose product is one.
    #[test]
    fn complete_pairing_input_reaches_the_backend() {
        let input = [0u8; PAIRING_ELEMENT_SIZE];
        assert_eq!(pairing_is_one(&input), Ok(true));
        assert_eq!(pairing_validate_points(&input), Ok(()));
    }
}
