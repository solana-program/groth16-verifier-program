//! Malformed instructions and accounts: every "reject before doing anything"
//! path that the happy-path and registry tests do not reach. Each case pins
//! the exact error the program returns.

mod common;

use {
    common::{
        assert_custom_error, assert_program_error, circuit::Instance, code, harness, Harness,
        SYSTEM_PROGRAM_ID,
    },
    groth16_verify::{
        instruction as ix,
        state::{staging_account_len, write_staging_header, StagingHeader, STAGING_HEADER_LEN},
    },
    mollusk_svm::program::keyed_account_for_system_program,
    solana_account::Account,
    solana_address::Address,
    solana_instruction::{AccountMeta, Instruction},
    solana_program_error::ProgramError,
};

/// A program-owned staging account as `create_account` leaves it: right size,
/// all zeros, not yet initialized.
fn blank_staging(h: &Harness, n: usize) -> Account {
    Account {
        lamports: h.rent_exempt(staging_account_len(n)),
        data: vec![0u8; staging_account_len(n)],
        owner: h.program_id,
        executable: false,
        rent_epoch: 0,
    }
}

/// An initialized staging account with `body` written and `authority` recorded.
fn staged(h: &Harness, authority: &Address, body: &[u8]) -> Account {
    let n = groth16_verify::VerifyingKey::from_body(body)
        .unwrap()
        .num_public_inputs();
    let mut account = blank_staging(h, n);
    write_staging_header(
        &mut account.data,
        StagingHeader {
            num_public_inputs: n,
            authority: *authority.as_array(),
        },
    );
    account.data[STAGING_HEADER_LEN..].copy_from_slice(body);
    account
}

fn raw(h: &Harness, data: &[u8], accounts: Vec<AccountMeta>) -> Instruction {
    Instruction::new_with_bytes(h.program_id, data, accounts)
}

#[test]
fn dispatch_rejects_unknown_tags_and_empty_data() {
    let Some(h) = harness() else { return };
    assert_program_error(
        &h.mollusk.process_instruction(&raw(&h, &[], vec![]), &[]),
        ProgramError::InvalidInstructionData,
    );
    assert_program_error(
        &h.mollusk.process_instruction(&raw(&h, &[9], vec![]), &[]),
        ProgramError::InvalidInstructionData,
    );
}

#[test]
fn verify_rejects_short_proofs_and_wrong_account_counts() {
    let Some(h) = harness() else { return };
    let inst = Instance::random(1);
    let (key_pda, key_account) = h.register(&inst.key);

    // 100 bytes where a 256-byte proof should be.
    let mut data = vec![ix::Tag::Verify as u8];
    data.extend_from_slice(&inst.proof.0[..100]);
    let short = raw(&h, &data, vec![AccountMeta::new_readonly(key_pda, false)]);
    assert_custom_error(
        &h.mollusk
            .process_instruction(&short, &[(key_pda, key_account.clone())]),
        code::INVALID_PROOF_LENGTH,
    );

    // No accounts at all.
    let mut none = ix::verify(&h.program_id, &key_pda, &inst.proof.0, &inst.input_bytes);
    none.accounts.clear();
    assert_program_error(
        &h.mollusk.process_instruction(&none, &[]),
        ProgramError::InvalidArgument,
    );
}

#[test]
fn verify_rejects_key_accounts_whose_length_disagrees_with_n() {
    let Some(h) = harness() else { return };
    let inst = Instance::random(2);
    let (key_pda, key_account) = h.register(&inst.key);

    // Header says n = 2 but one IC point is missing.
    let mut truncated = key_account.clone();
    truncated.data.truncate(truncated.data.len() - 64);
    assert_custom_error(
        &h.verify(&(key_pda, truncated), &inst.proof.0, &inst.input_bytes),
        code::INVALID_KEY_LENGTH,
    );

    // Not even a full header.
    let mut stub = key_account;
    stub.data.truncate(3);
    assert_custom_error(
        &h.verify(&(key_pda, stub), &inst.proof.0, &inst.input_bytes),
        code::INVALID_ACCOUNT_DATA,
    );
}

#[test]
fn initialize_staging_checks_signer_owner_writability_and_payload() {
    let Some(h) = harness() else { return };
    let authority = h.wallet(1_000_000_000);
    let staging = Address::new_unique();
    let accounts = vec![authority.clone(), (staging, blank_staging(&h, 1))];

    // Authority did not sign.
    let mut unsigned = ix::initialize_staging(&h.program_id, &authority.0, &staging, 1);
    unsigned.accounts[0].is_signer = false;
    assert_program_error(
        &h.mollusk.process_instruction(&unsigned, &accounts),
        ProgramError::MissingRequiredSignature,
    );

    // Staging not writable.
    let mut readonly = ix::initialize_staging(&h.program_id, &authority.0, &staging, 1);
    readonly.accounts[1].is_writable = false;
    assert_program_error(
        &h.mollusk.process_instruction(&readonly, &accounts),
        ProgramError::InvalidArgument,
    );

    // Staging owned by the system program, not by us.
    let mut foreign = blank_staging(&h, 1);
    foreign.owner = SYSTEM_PROGRAM_ID;
    assert_program_error(
        &h.mollusk.process_instruction(
            &ix::initialize_staging(&h.program_id, &authority.0, &staging, 1),
            &[authority.clone(), (staging, foreign)],
        ),
        ProgramError::InvalidAccountOwner,
    );

    // Payload is one byte instead of a u16.
    let one_byte = raw(
        &h,
        &[ix::Tag::InitializeStaging as u8, 1],
        vec![
            AccountMeta::new_readonly(authority.0, true),
            AccountMeta::new(staging, false),
        ],
    );
    assert_program_error(
        &h.mollusk.process_instruction(&one_byte, &accounts),
        ProgramError::InvalidInstructionData,
    );
}

#[test]
fn write_rejects_uninitialized_staging_and_short_payloads() {
    let Some(h) = harness() else { return };
    let authority = h.wallet(1_000_000_000);
    let staging = Address::new_unique();
    let accounts = vec![authority.clone(), (staging, blank_staging(&h, 1))];

    // Created but never initialized: discriminator is still 0.
    assert_custom_error(
        &h.mollusk.process_instruction(
            &ix::write(&h.program_id, &authority.0, &staging, 0, &[1, 2, 3]),
            &accounts,
        ),
        code::WRONG_DISCRIMINATOR,
    );

    // Three bytes: not even a full offset.
    let short = raw(
        &h,
        &[ix::Tag::Write as u8, 0, 0, 0],
        vec![
            AccountMeta::new_readonly(authority.0, true),
            AccountMeta::new(staging, false),
        ],
    );
    assert_program_error(
        &h.mollusk.process_instruction(&short, &accounts),
        ProgramError::InvalidInstructionData,
    );
}

#[test]
fn close_staging_requires_the_authority_to_sign() {
    let Some(h) = harness() else { return };
    let authority = h.wallet(1_000_000_000);
    let staging = Address::new_unique();
    let inst = Instance::random(0);
    let accounts = vec![
        authority.clone(),
        (staging, staged(&h, &authority.0, inst.key.body())),
    ];

    let mut unsigned = ix::close_staging(&h.program_id, &authority.0, &staging);
    unsigned.accounts[0].is_signer = false;
    assert_program_error(
        &h.mollusk.process_instruction(&unsigned, &accounts),
        ProgramError::MissingRequiredSignature,
    );

    // Trailing payload byte.
    let noisy = raw(
        &h,
        &[ix::Tag::CloseStaging as u8, 0],
        vec![
            AccountMeta::new(authority.0, true),
            AccountMeta::new(staging, false),
        ],
    );
    assert_program_error(
        &h.mollusk.process_instruction(&noisy, &accounts),
        ProgramError::InvalidInstructionData,
    );
}

#[test]
fn publish_rejects_wrong_signer_uninitialized_staging_and_payload() {
    let Some(h) = harness() else { return };
    let authority = h.wallet(10_000_000_000);
    let stranger = h.wallet(10_000_000_000);
    let staging = Address::new_unique();
    let inst = Instance::random(1);
    let (key_pda, _) = ix::find_key_address(&h.program_id, &inst.key.hash());

    let mut accounts = vec![
        authority.clone(),
        stranger.clone(),
        (staging, staged(&h, &authority.0, inst.key.body())),
        (key_pda, Account::default()),
        keyed_account_for_system_program(),
    ];

    // Signed by someone other than the recorded authority (who also pays).
    assert_program_error(
        &h.mollusk.process_instruction(
            &ix::publish(&h.program_id, &stranger.0, &stranger.0, &staging, &key_pda),
            &accounts,
        ),
        ProgramError::IncorrectAuthority,
    );

    // Authority present but not a signer.
    let mut unsigned = ix::publish(
        &h.program_id,
        &authority.0,
        &authority.0,
        &staging,
        &key_pda,
    );
    unsigned.accounts[0].is_signer = false;
    unsigned.accounts[1].is_signer = false;
    assert_program_error(
        &h.mollusk.process_instruction(&unsigned, &accounts),
        ProgramError::MissingRequiredSignature,
    );

    // Trailing payload byte.
    let mut noisy = ix::publish(
        &h.program_id,
        &authority.0,
        &authority.0,
        &staging,
        &key_pda,
    );
    noisy.data.push(0);
    assert_program_error(
        &h.mollusk.process_instruction(&noisy, &accounts),
        ProgramError::InvalidInstructionData,
    );

    // Staging never initialized.
    accounts[2].1 = blank_staging(&h, 1);
    assert_custom_error(
        &h.mollusk.process_instruction(
            &ix::publish(
                &h.program_id,
                &authority.0,
                &authority.0,
                &staging,
                &key_pda,
            ),
            &accounts,
        ),
        code::WRONG_DISCRIMINATOR,
    );

    // Staging owned by someone else.
    let mut foreign = staged(&h, &authority.0, inst.key.body());
    foreign.owner = SYSTEM_PROGRAM_ID;
    accounts[2].1 = foreign;
    assert_program_error(
        &h.mollusk.process_instruction(
            &ix::publish(
                &h.program_id,
                &authority.0,
                &authority.0,
                &staging,
                &key_pda,
            ),
            &accounts,
        ),
        ProgramError::InvalidAccountOwner,
    );
}

#[test]
fn client_vk_hash_matches_the_converter() {
    let inst = Instance::random(2);
    assert_eq!(ix::vk_hash(inst.key.body()), inst.key.hash());
}
