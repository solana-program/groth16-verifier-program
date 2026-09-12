//! The compute-unit breakdown from `docs/cu-budget.md § Benchmark
//! methodology`, printed as a table. Run with `make cu`.
//!
//! Uses the `bench` program (stage-isolating, runtime inputs) and the real
//! program's `Verify`, both under Mollusk.

mod common;

use {
    ark_bn254::Fr,
    common::{assert_success, circuit::Instance, harness_with, BENCH_SO, PROGRAM_SO},
    groth16_bench::{
        instruction_data, TAG_ASSEMBLE, TAG_BASELINE, TAG_MSM, TAG_NULL, TAG_PAIRING, TAG_VERIFY,
    },
    groth16_verify::scalar,
    mollusk_svm::Mollusk,
    solana_address::Address,
    solana_instruction::Instruction,
};

const PAIRING_CU: u64 = 73_612;
const G1_MUL_CU: u64 = 3_840;
const G1_ADD_CU: u64 = 334;

struct Row {
    label: String,
    n: usize,
    s_msm: u64,
    null: u64,
    baseline: u64,
    assemble: u64,
    msm: u64,
    pairing: u64,
    core: u64,
    e2e: u64,
}

fn s_msm(inputs: &[[u8; 32]]) -> u64 {
    let mut cost = 0;
    for s in inputs {
        if scalar::is_zero(s) {
            continue;
        }
        cost += G1_ADD_CU;
        if !scalar::is_one(s) {
            cost += G1_MUL_CU;
        }
    }
    cost
}

fn measure(mollusk: &Mollusk, bench_id: &Address, inst: &Instance, tag: u8) -> u64 {
    let flat: Vec<u8> = inst.input_bytes.concat();
    let data = instruction_data(tag, inst.key.body(), &inst.proof.0, &flat, &inst.l());
    let result =
        mollusk.process_instruction(&Instruction::new_with_bytes(*bench_id, &data, vec![]), &[]);
    assert_success(&result);
    if tag != TAG_NULL {
        assert_eq!(
            result.return_data.len(),
            groth16_bench::RETURN_DATA_LEN,
            "tag {tag}"
        );
    }
    if tag == TAG_PAIRING || tag == TAG_VERIFY {
        assert_eq!(
            result.return_data[0], 1,
            "tag {tag} should report a valid proof"
        );
    }
    result.compute_units_consumed
}

fn row(h: &common::Harness, bench_id: &Address, label: &str, inst: &Instance) -> Row {
    let m = |tag| measure(&h.mollusk, bench_id, inst, tag);
    let key_account = h.register(&inst.key);
    let e2e = h.verify(&key_account, &inst.proof.0, &inst.input_bytes);
    assert_success(&e2e);
    Row {
        label: label.to_string(),
        n: inst.key.num_public_inputs(),
        s_msm: s_msm(&inst.input_bytes),
        null: m(TAG_NULL),
        baseline: m(TAG_BASELINE),
        assemble: m(TAG_ASSEMBLE),
        msm: m(TAG_MSM),
        pairing: m(TAG_PAIRING),
        core: m(TAG_VERIFY),
        e2e: e2e.compute_units_consumed,
    }
}

#[test]
fn cu_breakdown() {
    let Some(mut h) = harness_with(&[PROGRAM_SO, BENCH_SO]) else {
        return;
    };
    let bench_id = Address::new_unique();
    h.mollusk.add_program(&bench_id, BENCH_SO);
    h.mollusk.compute_budget.compute_unit_limit = 1_400_000;

    let mut rows = Vec::new();
    for n in [0usize, 1, 2, 4, 8, 16, 32] {
        rows.push(row(&h, &bench_id, "random", &Instance::random(n)));
    }
    rows.push(row(
        &h,
        &bench_id,
        "all zero",
        &Instance::with_witnesses(vec![Fr::from(0u64); 8]),
    ));
    rows.push(row(
        &h,
        &bench_id,
        "all one",
        &Instance::with_witnesses(vec![Fr::from(1u64); 8]),
    ));

    println!();
    println!("Raw measurements (CU):");
    println!(
        "{:<9} {:>3} {:>7} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8}",
        "inputs", "n", "M(∅)", "M(0)", "M(1)", "M(2)", "M(3)", "M(4)", "E2E"
    );
    for r in &rows {
        println!(
            "{:<9} {:>3} {:>7} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8}",
            r.label, r.n, r.null, r.baseline, r.assemble, r.msm, r.pairing, r.core, r.e2e
        );
    }

    println!();
    println!("Derived (CU), per docs/cu-budget.md:");
    println!(
        "{:<9} {:>3} {:>6} {:>9} {:>8} {:>8} {:>8} {:>9} {:>9} {:>9}",
        "inputs", "n", "R", "S_msm", "assemble", "MSM", "pairing", "core", "overhead", "plumbing"
    );
    for r in &rows {
        let ret = r.baseline - r.null;
        let assemble = r.assemble - r.baseline;
        let msm = r.msm - r.baseline;
        let pairing = r.pairing - r.baseline;
        let core = r.core - r.baseline;
        let overhead = core as i64 - PAIRING_CU as i64 - r.s_msm as i64;
        let plumbing = r.e2e as i64 - (r.core as i64 - ret as i64);
        println!(
            "{:<9} {:>3} {:>6} {:>9} {:>8} {:>8} {:>8} {:>9} {:>9} {:>9}",
            r.label, r.n, ret, r.s_msm, assemble, msm, pairing, core, overhead, plumbing
        );
        // Stage deltas are lower-bounded by the syscall floors.
        assert!(
            pairing >= PAIRING_CU + assemble,
            "pairing stage below floor at n = {}",
            r.n
        );
        assert!(msm >= r.s_msm, "MSM stage below floor at n = {}", r.n);
        assert!(overhead >= 0, "core below syscall floor at n = {}", r.n);
    }
    println!();
}
