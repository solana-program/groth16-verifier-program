//! End-to-end: the gnark fixture under `fixtures/gnark/` — key registered
//! through the real instruction flow, proof verified by the SBF program.

mod common;

use {
    common::{assert_custom_error, assert_success, code, harness},
    groth16_convert::{arkworks, gnark, OnChainKey, OnChainProof},
};

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/../fixtures/gnark/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {path}: {e}"))
}

fn load() -> (OnChainKey, OnChainProof, Vec<[u8; 32]>) {
    let key = gnark::parse_verifying_key(&fixture("vk.bin")).unwrap();
    let proof = gnark::parse_proof(&fixture("proof.bin")).unwrap();
    let inputs = gnark::parse_public_witness(&fixture("public.bin")).unwrap();
    (key, proof, arkworks::public_inputs(&inputs))
}

#[test]
fn gnark_proof_verifies_on_sbf() {
    let Some(h) = harness() else { return };
    let (key, proof, inputs) = load();
    let key_account = h.register(&key);

    let result = h.verify(&key_account, &proof.0, &inputs);
    assert_success(&result);
    println!(
        "gnark e2e: n = {}, {} CUs",
        key.num_public_inputs(),
        result.compute_units_consumed
    );
}

#[test]
fn gnark_wrong_public_input_is_rejected() {
    let Some(h) = harness() else { return };
    let (key, proof, mut inputs) = load();
    let key_account = h.register(&key);

    // 3 · 5 ≠ 16.
    inputs[2][31] = 16;
    assert_custom_error(
        &h.verify(&key_account, &proof.0, &inputs),
        code::PROOF_INVALID,
    );
}

#[test]
fn gnark_tampered_proof_is_rejected() {
    let Some(h) = harness() else { return };
    let (key, proof, inputs) = load();
    let key_account = h.register(&key);

    // Flip a bit in A's y: no longer on the curve, so the syscall rejects it.
    let mut off_curve = proof.0;
    off_curve[63] ^= 1;
    assert_custom_error(
        &h.verify(&key_account, &off_curve, &inputs),
        code::INVALID_POINT,
    );

    // Swap A and C: valid points, wrong equation.
    let mut swapped = proof.0;
    swapped[..64].copy_from_slice(&proof.0[192..]);
    swapped[192..].copy_from_slice(&proof.0[..64]);
    assert_custom_error(
        &h.verify(&key_account, &swapped, &inputs),
        code::PROOF_INVALID,
    );
}

#[test]
fn gnark_wrong_input_count_and_shape_are_rejected() {
    let Some(h) = harness() else { return };
    let (key, proof, inputs) = load();
    let key_account = h.register(&key);

    assert_custom_error(
        &h.verify(&key_account, &proof.0, &inputs[..2]),
        code::PUBLIC_INPUT_COUNT_MISMATCH,
    );
    let mut four = inputs.clone();
    four.push([0u8; 32]);
    assert_custom_error(
        &h.verify(&key_account, &proof.0, &four),
        code::PUBLIC_INPUT_COUNT_MISMATCH,
    );

    let mut non_canonical = inputs.clone();
    non_canonical[0] = groth16_verify::constants::FR_MODULUS;
    assert_custom_error(
        &h.verify(&key_account, &proof.0, &non_canonical),
        code::NON_CANONICAL_SCALAR,
    );
}
