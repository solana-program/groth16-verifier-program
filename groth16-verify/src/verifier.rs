//! The verification itself, split into the stages the benchmark measures:
//! public-input preparation (the MSM), pairing-input assembly, and the pairing
//! check. [`verify`] runs all three.
//!
//! The equation checked is
//!
//! ```text
//! e(A, B) · e(α, −β) · e(L, −γ) · e(C, −δ) = 1,    L = IC₀ + Σᵢ aᵢ·ICᵢ
//! ```
//!
//! with the G2 negations pre-applied in the key, so this module performs no
//! field arithmetic of its own — only the syscalls and byte copies.

use crate::{
    constants::{
        FR_SIZE, G1_SIZE, PAIRING_INPUT_SIZE, PAIRING_SLOT_AB_OFFSET,
        PAIRING_SLOT_ALPHA_BETA_OFFSET, PAIRING_SLOT_C_OFFSET, PAIRING_SLOT_DELTA_OFFSET,
        PAIRING_SLOT_GAMMA_OFFSET, PAIRING_SLOT_L_OFFSET,
    },
    error::Groth16Error,
    proof::Proof,
    scalar,
    syscall::{g1_add, g1_mul, pairing_is_one},
    vk::VerifyingKey,
};

/// Verifies `proof` against `vk` for `public_inputs` (`n × 32` big-endian
/// canonical scalars, no leading constant-one term).
///
/// `Ok(())` means the proof verifies. See [`Groth16Error`] for the failure
/// modes; note that [`Groth16Error::InvalidPoint`] on this path means one of
/// `A`, `B`, `C` failed the syscall's curve or subgroup check.
#[inline]
pub fn verify(vk: &VerifyingKey, proof: &Proof, public_inputs: &[u8]) -> Result<(), Groth16Error> {
    let l = prepare_inputs(vk, public_inputs)?;
    let input = assemble_pairing_input(vk, proof, &l);
    check_pairing(&input)
}

/// Stage 1: `L = IC₀ + Σᵢ aᵢ·ICᵢ`.
///
/// Checks the input count and every scalar's canonicity before touching a
/// syscall. Inputs equal to `0` contribute nothing and are skipped entirely;
/// inputs equal to `1` skip the multiplication. Both are safe to special-case
/// because public inputs are public — the CU cost this makes data-dependent
/// leaks nothing.
pub fn prepare_inputs(
    vk: &VerifyingKey,
    public_inputs: &[u8],
) -> Result<[u8; G1_SIZE], Groth16Error> {
    let n = vk.num_public_inputs();
    if public_inputs.len() != n * FR_SIZE {
        return Err(Groth16Error::PublicInputCountMismatch);
    }

    // Reject any bad scalar before spending compute on the ones before it.
    for chunk in public_inputs.chunks_exact(FR_SIZE) {
        let s: &[u8; FR_SIZE] = chunk.try_into().unwrap();
        if !scalar::is_canonical(s) {
            return Err(Groth16Error::NonCanonicalScalar);
        }
    }

    let mut acc = *vk.ic(0);
    for (i, chunk) in public_inputs.chunks_exact(FR_SIZE).enumerate() {
        let s: &[u8; FR_SIZE] = chunk.try_into().unwrap();
        if scalar::is_zero(s) {
            continue;
        }
        let ic = vk.ic(i + 1);
        if scalar::is_one(s) {
            acc = g1_add(&acc, ic)?;
        } else {
            let term = g1_mul(ic, s)?;
            acc = g1_add(&acc, &term)?;
        }
    }
    Ok(acc)
}

/// Stage 2: lay out the four pairs. Pure copying; cannot fail.
#[inline]
pub fn assemble_pairing_input(
    vk: &VerifyingKey,
    proof: &Proof,
    l: &[u8; G1_SIZE],
) -> [u8; PAIRING_INPUT_SIZE] {
    let mut input = [0u8; PAIRING_INPUT_SIZE];
    write_pairing_input(&mut input, vk, proof, l);
    input
}

/// [`assemble_pairing_input`] into a caller-provided buffer.
#[inline]
pub fn write_pairing_input(
    input: &mut [u8; PAIRING_INPUT_SIZE],
    vk: &VerifyingKey,
    proof: &Proof,
    l: &[u8; G1_SIZE],
) {
    let a_b = proof.a_b();
    let alpha_beta = vk.alpha_neg_beta();
    let neg_gamma = vk.neg_gamma();
    let c = proof.c();
    let neg_delta = vk.neg_delta();

    input[PAIRING_SLOT_AB_OFFSET..PAIRING_SLOT_AB_OFFSET + a_b.len()].copy_from_slice(a_b);
    input[PAIRING_SLOT_ALPHA_BETA_OFFSET..PAIRING_SLOT_ALPHA_BETA_OFFSET + alpha_beta.len()]
        .copy_from_slice(alpha_beta);
    input[PAIRING_SLOT_L_OFFSET..PAIRING_SLOT_L_OFFSET + G1_SIZE].copy_from_slice(l);
    input[PAIRING_SLOT_GAMMA_OFFSET..PAIRING_SLOT_GAMMA_OFFSET + neg_gamma.len()]
        .copy_from_slice(neg_gamma);
    input[PAIRING_SLOT_C_OFFSET..PAIRING_SLOT_C_OFFSET + G1_SIZE].copy_from_slice(c);
    input[PAIRING_SLOT_DELTA_OFFSET..PAIRING_SLOT_DELTA_OFFSET + neg_delta.len()]
        .copy_from_slice(neg_delta);
}

/// Stage 3: the 4-pair check.
#[inline]
pub fn check_pairing(input: &[u8; PAIRING_INPUT_SIZE]) -> Result<(), Groth16Error> {
    if pairing_is_one(input)? {
        Ok(())
    } else {
        Err(Groth16Error::ProofInvalid)
    }
}
