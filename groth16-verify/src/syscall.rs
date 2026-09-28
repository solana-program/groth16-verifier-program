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
/// syscall rejected a point.
#[inline]
pub fn pairing_is_one(input: &[u8]) -> Result<bool, Groth16Error> {
    debug_assert!(input.len().is_multiple_of(PAIRING_ELEMENT_SIZE));
    let mut out = [0u8; PAIRING_OUTPUT_SIZE];
    group_op(ALT_BN128_PAIRING_BE, input, &mut out)?;
    // A big-endian 0 or 1: the last byte carries it, everything else is zero.
    Ok(out[PAIRING_OUTPUT_SIZE - 1] == 1)
}

/// Runs the syscall as a pure validity check: succeeds iff every point in
/// `input` deserializes with the runtime's on-curve and subgroup checks. The
/// pairing result is discarded. Used at publish time.
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
