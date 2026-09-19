//! The registration path's guarantees, each with a test that tries to break
//! it. See `docs/design.md §2` and `§10`.

mod common;

use {
    ark_bn254::{G1Projective, G2Projective},
    ark_ec::CurveGroup,
    ark_ff::UniformRand,
    ark_std::rand::SeedableRng,
    common::{
        account_of, assert_custom_error, assert_program_error, assert_success, circuit::Instance,
        code, harness, RegisterRequest, SYSTEM_PROGRAM_ID,
    },
    groth16_convert::OnChainKey,
    mollusk_svm::program::keyed_account_for_system_program,
    rand_chacha::ChaCha20Rng,
    solana_account::Account,
    solana_address::Address,
    solana_groth16_verify::{
        constants::MAX_PUBLIC_INPUTS,
        instruction::{self as ix, find_key_address},
        state::{key_account_len, staging_account_len, VK_SEED_PREFIX},
    },
    solana_program_error::ProgramError,
};

/// A key made of random valid points — no circuit behind it, but `Publish`
/// only validates points, so it registers like any other.
fn synthetic_key(n: usize, seed: u64) -> OnChainKey {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let g1 = |rng: &mut ChaCha20Rng| G1Projective::rand(rng).into_affine();
    let g2 = |rng: &mut ChaCha20Rng| G2Projective::rand(rng).into_affine();
    let alpha = g1(&mut rng);
    let beta = g2(&mut rng);
    let gamma = g2(&mut rng);
    let delta = g2(&mut rng);
    let ic: Vec<_> = (0..=n).map(|_| g1(&mut rng)).collect();
    OnChainKey::new(&alpha, &beta, &gamma, &delta, &ic).unwrap()
}

#[test]
fn publish_onto_a_prefunded_address_succeeds() {
    let Some(h) = harness() else { return };
    let key = synthetic_key(2, 1);
    let authority = h.wallet(10_000_000_000);
    let prefunded = Account {
        lamports: 1,
        data: vec![],
        owner: SYSTEM_PROGRAM_ID,
        executable: false,
        rent_epoch: 0,
    };
    let (result, key_pda) = h.register_chain(RegisterRequest {
        key_target: prefunded,
        ..RegisterRequest::new(&key, &authority)
    });
    assert_success(&result);
    let account = account_of(&result, &key_pda);
    assert_eq!(account.owner, h.program_id);
    assert_eq!(account.data.len(), key_account_len(2));
    assert!(account.lamports >= h.rent_exempt(key_account_len(2)));
}

#[test]
fn payer_and_authority_may_differ_and_refunds_go_to_authority() {
    let Some(h) = harness() else { return };
    let key = synthetic_key(1, 2);
    let authority = h.wallet(1_000_000_000);
    let payer = h.wallet(1_000_000_000);
    let (result, key_pda) = h.register_chain(RegisterRequest {
        payer: Some(&payer),
        ..RegisterRequest::new(&key, &authority)
    });
    assert_success(&result);

    let key_rent = h.rent_exempt(key_account_len(1));
    // Authority funded the staging account and got it back on close: net zero.
    assert_eq!(
        account_of(&result, &authority.0).lamports,
        authority.1.lamports
    );
    // Payer funded exactly the key account's rent.
    assert_eq!(
        account_of(&result, &payer.0).lamports,
        payer.1.lamports - key_rent
    );
    assert_eq!(account_of(&result, &key_pda).lamports, key_rent);
}

#[test]
fn zero_public_inputs_publishes_and_verifies() {
    let Some(h) = harness() else { return };
    let inst = Instance::random(0);
    let key_account = h.register(&inst.key);
    assert_success(&h.verify(&key_account, &inst.proof.0, &[]));
}

#[test]
fn non_canonical_bump_is_rejected() {
    let Some(h) = harness() else { return };
    let key = synthetic_key(1, 3);
    let hash = key.hash();
    let (canonical, canonical_bump) = find_key_address(&h.program_id, &hash);

    // Find another bump that also yields a valid program address.
    let other = (0..canonical_bump)
        .rev()
        .find_map(|bump| {
            Address::create_program_address(&[VK_SEED_PREFIX, &hash, &[bump]], &h.program_id).ok()
        })
        .expect("some lower bump derives a valid address");
    assert_ne!(other, canonical);

    let authority = h.wallet(10_000_000_000);
    let (result, _) = h.register_chain(RegisterRequest {
        key_pda: Some(other),
        ..RegisterRequest::new(&key, &authority)
    });
    assert_custom_error(&result, code::KEY_ADDRESS_MISMATCH);
}

#[test]
fn body_not_matching_the_address_is_rejected() {
    let Some(h) = harness() else { return };
    let key = synthetic_key(1, 4);
    let mut body = key.body().to_vec();
    // Swap IC₀ and IC₁: still valid points, different key, different hash.
    let ic0 = body[448..512].to_vec();
    let ic1 = body[512..576].to_vec();
    body[448..512].copy_from_slice(&ic1);
    body[512..576].copy_from_slice(&ic0);

    let authority = h.wallet(10_000_000_000);
    let (result, _) = h.register_chain(RegisterRequest {
        body_override: Some(body),
        ..RegisterRequest::new(&key, &authority)
    });
    assert_custom_error(&result, code::KEY_ADDRESS_MISMATCH);
}

#[test]
fn invalid_points_in_the_body_are_rejected() {
    let Some(h) = harness() else { return };
    let key = synthetic_key(1, 5);
    let authority = h.wallet(10_000_000_000);

    // The address check runs before point validation, so each corrupted body
    // is published at *its own* canonical address; otherwise every case below
    // would stop at KEY_ADDRESS_MISMATCH without reaching the point checks.
    let publish_corrupted = |body: Vec<u8>| {
        let (pda, _) = find_key_address(&h.program_id, &ix::vk_hash(&body));
        h.register_chain(RegisterRequest {
            body_override: Some(body),
            key_pda: Some(pda),
            ..RegisterRequest::new(&key, &authority)
        })
        .0
    };

    // Off-curve IC₁.
    let mut body = key.body().to_vec();
    body[575] ^= 1;
    assert_custom_error(&publish_corrupted(body), code::INVALID_POINT);

    // Off-curve −β (only the pairing path catches G2).
    let mut body = key.body().to_vec();
    body[191] ^= 1;
    assert_custom_error(&publish_corrupted(body), code::INVALID_POINT);

    // Identity α.
    let mut body = key.body().to_vec();
    body[..64].fill(0);
    assert_custom_error(&publish_corrupted(body), code::IDENTITY_KEY_ELEMENT);
}

#[test]
fn address_is_checked_before_points_are_validated() {
    let Some(h) = harness() else { return };
    let key = synthetic_key(1, 6);
    let authority = h.wallet(10_000_000_000);

    // A body that is both off-curve *and* published at the wrong address (the
    // real key's) fails on the address: the cheap check runs first, so a
    // wrong target never pays for the validation pairing.
    let mut body = key.body().to_vec();
    body[575] ^= 1;
    let (result, _) = h.register_chain(RegisterRequest {
        body_override: Some(body),
        ..RegisterRequest::new(&key, &authority)
    });
    assert_custom_error(&result, code::KEY_ADDRESS_MISMATCH);
}

#[test]
fn republishing_fails_and_leaves_the_first_intact() {
    let Some(h) = harness() else { return };
    let key = synthetic_key(1, 6);
    let (key_pda, published) = h.register(&key);

    let authority = h.wallet(10_000_000_000);
    let (result, _) = h.register_chain(RegisterRequest {
        key_target: published.clone(),
        ..RegisterRequest::new(&key, &authority)
    });
    assert_custom_error(&result, code::KEY_ALREADY_PUBLISHED);
    assert_eq!(account_of(&result, &key_pda), published);
}

#[test]
fn max_size_key_publishes_with_a_raised_budget_and_one_more_is_refused() {
    let Some(mut h) = harness() else { return };
    let key = synthetic_key(MAX_PUBLIC_INPUTS, 7);
    h.mollusk.compute_budget.compute_unit_limit = 1_400_000;
    let authority = h.wallet(10_000_000_000);
    let (result, key_pda) = h.register_chain(RegisterRequest::new(&key, &authority));
    assert_success(&result);
    assert_eq!(
        account_of(&result, &key_pda).data.len(),
        key_account_len(MAX_PUBLIC_INPUTS)
    );
    println!(
        "publish n = {MAX_PUBLIC_INPUTS}: {} CUs for the whole chain",
        result.compute_units_consumed
    );

    // n = 152 is refused at InitializeStaging.
    let staging = Address::new_unique();
    let too_big = MAX_PUBLIC_INPUTS + 1;
    let result = h.mollusk.process_instruction_chain(
        &[
            h.create_account_ix(
                &authority.0,
                &staging,
                staging_account_len(too_big),
                &h.program_id,
            ),
            ix::initialize_staging(&h.program_id, &authority.0, &staging, too_big as u16),
        ],
        &[
            authority.clone(),
            (staging, Account::default()),
            keyed_account_for_system_program(),
        ],
    );
    assert_custom_error(&result, code::TOO_MANY_PUBLIC_INPUTS);
}

#[test]
fn initialize_staging_checks_size_and_refuses_reinitialization() {
    let Some(h) = harness() else { return };
    let authority = h.wallet(10_000_000_000);
    let staging = Address::new_unique();

    // Wrong size for n = 1.
    let result = h.mollusk.process_instruction_chain(
        &[
            h.create_account_ix(
                &authority.0,
                &staging,
                staging_account_len(2),
                &h.program_id,
            ),
            ix::initialize_staging(&h.program_id, &authority.0, &staging, 1),
        ],
        &[
            authority.clone(),
            (staging, Account::default()),
            keyed_account_for_system_program(),
        ],
    );
    assert_custom_error(&result, code::STAGING_SIZE_MISMATCH);

    // Twice.
    let result = h.mollusk.process_instruction_chain(
        &[
            h.create_account_ix(
                &authority.0,
                &staging,
                staging_account_len(1),
                &h.program_id,
            ),
            ix::initialize_staging(&h.program_id, &authority.0, &staging, 1),
            ix::initialize_staging(&h.program_id, &authority.0, &staging, 1),
        ],
        &[
            authority.clone(),
            (staging, Account::default()),
            keyed_account_for_system_program(),
        ],
    );
    assert_program_error(&result, ProgramError::AccountAlreadyInitialized);
}

#[test]
fn write_is_bounded_to_the_body_and_gated_on_authority() {
    let Some(h) = harness() else { return };
    let authority = h.wallet(10_000_000_000);
    let stranger = h.wallet(10_000_000_000);
    let staging = Address::new_unique();
    let n = 1;
    let body_len = solana_groth16_verify::constants::vk_body_len(n);

    let setup = |h: &common::Harness| {
        vec![
            h.create_account_ix(
                &authority.0,
                &staging,
                staging_account_len(n),
                &h.program_id,
            ),
            ix::initialize_staging(&h.program_id, &authority.0, &staging, n as u16),
        ]
    };
    let accounts = vec![
        authority.clone(),
        stranger.clone(),
        (staging, Account::default()),
        keyed_account_for_system_program(),
    ];

    // Exactly to the end: fine.
    let mut ixs = setup(&h);
    ixs.push(ix::write(
        &h.program_id,
        &authority.0,
        &staging,
        (body_len - 1) as u32,
        &[0],
    ));
    assert_success(&h.mollusk.process_instruction_chain(&ixs, &accounts));

    // One past the end.
    let mut ixs = setup(&h);
    ixs.push(ix::write(
        &h.program_id,
        &authority.0,
        &staging,
        (body_len - 1) as u32,
        &[0, 0],
    ));
    assert_custom_error(
        &h.mollusk.process_instruction_chain(&ixs, &accounts),
        code::WRITE_OUT_OF_BOUNDS,
    );

    // Offset that would overflow.
    let mut ixs = setup(&h);
    ixs.push(ix::write(
        &h.program_id,
        &authority.0,
        &staging,
        u32::MAX,
        &[0, 0],
    ));
    assert_custom_error(
        &h.mollusk.process_instruction_chain(&ixs, &accounts),
        code::WRITE_OUT_OF_BOUNDS,
    );

    // Someone else.
    let mut ixs = setup(&h);
    ixs.push(ix::write(&h.program_id, &stranger.0, &staging, 0, &[0]));
    assert_program_error(
        &h.mollusk.process_instruction_chain(&ixs, &accounts),
        ProgramError::IncorrectAuthority,
    );
}

#[test]
fn close_staging_refunds_the_authority_only() {
    let Some(h) = harness() else { return };
    let authority = h.wallet(1_000_000_000);
    let stranger = h.wallet(1_000_000_000);
    let staging = Address::new_unique();
    let n = 3;
    let accounts = vec![
        authority.clone(),
        stranger.clone(),
        (staging, Account::default()),
        keyed_account_for_system_program(),
    ];

    let result = h.mollusk.process_instruction_chain(
        &[
            h.create_account_ix(
                &authority.0,
                &staging,
                staging_account_len(n),
                &h.program_id,
            ),
            ix::initialize_staging(&h.program_id, &authority.0, &staging, n as u16),
            ix::close_staging(&h.program_id, &stranger.0, &staging),
        ],
        &accounts,
    );
    assert_program_error(&result, ProgramError::IncorrectAuthority);

    let result = h.mollusk.process_instruction_chain(
        &[
            h.create_account_ix(
                &authority.0,
                &staging,
                staging_account_len(n),
                &h.program_id,
            ),
            ix::initialize_staging(&h.program_id, &authority.0, &staging, n as u16),
            ix::close_staging(&h.program_id, &authority.0, &staging),
        ],
        &accounts,
    );
    assert_success(&result);
    assert_eq!(
        account_of(&result, &authority.0).lamports,
        authority.1.lamports
    );
    assert_eq!(account_of(&result, &staging).lamports, 0);
}

#[test]
fn verify_rejects_accounts_that_are_not_published_keys() {
    let Some(h) = harness() else { return };
    let inst = Instance::random(1);

    // Right bytes, wrong owner.
    let (key_pda, mut published) = h.register(&inst.key);
    published.owner = SYSTEM_PROGRAM_ID;
    assert_program_error(
        &h.verify(
            &(key_pda, published.clone()),
            &inst.proof.0,
            &inst.input_bytes,
        ),
        ProgramError::InvalidAccountOwner,
    );

    // Our account, but a staging account rather than a key.
    let mut staging = Account {
        lamports: 1,
        data: vec![0u8; staging_account_len(1)],
        owner: h.program_id,
        executable: false,
        rent_epoch: 0,
    };
    staging.data[0] = solana_groth16_verify::state::DISCRIMINATOR_STAGING;
    assert_custom_error(
        &h.verify(
            &(Address::new_unique(), staging),
            &inst.proof.0,
            &inst.input_bytes,
        ),
        code::WRONG_DISCRIMINATOR,
    );

    // Extra accounts are refused.
    let ix = {
        let mut ix = ix::verify(&h.program_id, &key_pda, &inst.proof.0, &inst.input_bytes);
        ix.accounts
            .push(solana_instruction::AccountMeta::new_readonly(
                Address::new_unique(),
                false,
            ));
        ix
    };
    published.owner = h.program_id;
    let extra = (ix.accounts[1].pubkey, Account::default());
    assert_program_error(
        &h.mollusk
            .process_instruction(&ix, &[(key_pda, published), extra]),
        ProgramError::InvalidArgument,
    );
}
