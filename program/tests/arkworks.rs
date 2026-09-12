//! End-to-end: a fresh arkworks setup and proof every run, verified by the
//! SBF program. Seeds are printed so any failure can be replayed with
//! `Instance::with_seed`.

mod common;

use {
    ark_bn254::Fr,
    common::{assert_custom_error, assert_success, circuit::Instance, code, harness},
};

#[test]
fn random_circuits_verify_on_sbf() {
    let Some(h) = harness() else { return };
    for n in [0usize, 1, 2, 5, 8] {
        let inst = Instance::random(n);
        let key_account = h.register(&inst.key);
        let result = h.verify(&key_account, &inst.proof.0, &inst.input_bytes);
        assert_success(&result);
        println!(
            "arkworks e2e: n = {n}, {} CUs",
            result.compute_units_consumed
        );
    }
}

#[test]
fn zero_and_one_inputs_take_the_skip_paths_and_still_verify() {
    let Some(h) = harness() else { return };
    // p = w², so w ∈ {0, 1} gives public inputs 0 and 1 exactly.
    let inst = Instance::with_witnesses(vec![
        Fr::from(0u64),
        Fr::from(1u64),
        Fr::from(0u64),
        Fr::from(7u64),
        Fr::from(1u64),
    ]);
    assert_eq!(inst.input_bytes[0], [0u8; 32]);
    assert_eq!(inst.input_bytes[1][31], 1);
    let key_account = h.register(&inst.key);
    let result = h.verify(&key_account, &inst.proof.0, &inst.input_bytes);
    assert_success(&result);
    println!(
        "arkworks e2e with trivial scalars: n = 5, {} CUs",
        result.compute_units_consumed
    );

    // Flipping a zero input to one must break the proof, proving the skipped
    // multiplications still contribute correctly to the equation.
    let mut wrong = inst.input_bytes.clone();
    wrong[0][31] = 1;
    assert_custom_error(
        &h.verify(&key_account, &inst.proof.0, &wrong),
        code::PROOF_INVALID,
    );
}

#[test]
fn proof_for_one_key_does_not_verify_under_another() {
    let Some(h) = harness() else { return };
    let a = Instance::random(2);
    let b = Instance::random(2);
    let key_b = h.register(&b.key);
    assert_custom_error(
        &h.verify(&key_b, &a.proof.0, &a.input_bytes),
        code::PROOF_INVALID,
    );
}
