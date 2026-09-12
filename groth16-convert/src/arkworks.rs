//! `ark_groth16` types → on-chain bytes, and back for cross-checking.

use {
    crate::{
        wire::{public_inputs_to_bytes, OnChainKey, OnChainProof},
        ConvertError,
    },
    ark_bn254::{Bn254, Fr},
    ark_groth16::{Proof, VerifyingKey},
    groth16_verify::constants::FR_SIZE,
};

/// Converts an arkworks verifying key. `gamma_abc_g1` is `IC₀..ICₙ`.
pub fn key(vk: &VerifyingKey<Bn254>) -> Result<OnChainKey, ConvertError> {
    OnChainKey::new(
        &vk.alpha_g1,
        &vk.beta_g2,
        &vk.gamma_g2,
        &vk.delta_g2,
        &vk.gamma_abc_g1,
    )
}

/// Converts an arkworks proof.
pub fn proof(proof: &Proof<Bn254>) -> OnChainProof {
    OnChainProof::new(&proof.a, &proof.b, &proof.c)
}

/// Encodes arkworks public inputs (the same slice `ark_groth16::verify_proof`
/// takes — without the constant-one term).
pub fn public_inputs(inputs: &[Fr]) -> Vec<[u8; FR_SIZE]> {
    public_inputs_to_bytes(inputs)
}

/// Rebuilds an arkworks verifying key from an on-chain body, undoing the
/// negations. Lets a test verify the same proof with `ark_groth16` against
/// exactly the bytes the program will see.
pub fn key_from_on_chain(key: &OnChainKey) -> Result<VerifyingKey<Bn254>, ConvertError> {
    let (alpha_g1, beta_g2, gamma_g2, delta_g2, gamma_abc_g1) = key.elements()?;
    Ok(VerifyingKey {
        alpha_g1,
        beta_g2,
        gamma_g2,
        delta_g2,
        gamma_abc_g1,
    })
}

/// Rebuilds an arkworks proof from on-chain bytes.
pub fn proof_from_on_chain(proof: &OnChainProof) -> Result<Proof<Bn254>, ConvertError> {
    let (a, b, c) = proof.elements()?;
    Ok(Proof { a, b, c })
}
