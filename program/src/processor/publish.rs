//! `Publish`: turns a fully written staging account into the canonical,
//! immutable key account — in one instruction, so the canonical address never
//! exists in a partial state.
//!
//! Accounts: `[authority (s,w), payer (s,w), staging (w), key (w), system]`.
//! No data.
//!
//! Steps, in order (see the README's registration section):
//! 1. staging is ours, initialized, and signed for by its authority;
//! 2. every point in the body validates — G2 via a pairing call (the only
//!    opcode that subgroup-checks G2), G1 via addition;
//! 3. `find_program_address([b"vk", sha256(body)])` equals `key`, and `key`
//!    is not already ours;
//! 4. bring `key` into existence at exactly its final size (tolerating a
//!    pre-funded address), copy the body, write the header, close staging.

use {
    crate::{
        error::{map_groth16, Groth16ProgramError},
        processor,
    },
    groth16_verify::{
        constants::{G1_SIZE, PAIRING_ELEMENT_SIZE},
        state::{
            key_account_len, read_staging_account, write_key_header, KeyHeader, KEY_HEADER_LEN,
            VK_SEED_PREFIX,
        },
        syscall::{g1_add, pairing_validate_points},
        VerifyingKey,
    },
    pinocchio::{
        cpi::{Seed, Signer},
        error::ProgramError,
        sysvars::{rent::Rent, Sysvar},
        AccountView, Address, ProgramResult,
    },
    pinocchio_system::instructions::{Allocate, Assign, Transfer},
};

const SYSTEM_PROGRAM_ID: Address = Address::new_from_array([0u8; 32]);

pub fn process(
    program_id: &Address,
    accounts: &mut [AccountView],
    payload: &[u8],
) -> ProgramResult {
    if !payload.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }
    let [authority, payer, staging, key, _system] = accounts else {
        return Err(ProgramError::InvalidArgument);
    };
    processor::expect_signer(authority)?;
    processor::expect_writable(authority)?;
    processor::expect_signer(payer)?;
    processor::expect_writable(payer)?;
    processor::expect_writable(staging)?;
    processor::expect_writable(key)?;
    processor::expect_owned_by(staging, program_id)?;

    // --- 1. staging header ------------------------------------------------------
    let staging_data = staging.try_borrow()?;
    let (header, body) = read_staging_account(&staging_data).map_err(map_groth16)?;
    if header.authority != *authority.address().as_array() {
        return Err(ProgramError::IncorrectAuthority);
    }
    let n = header.num_public_inputs;
    let vk = VerifyingKey::from_body_with_len(body, n).map_err(map_groth16)?;

    // --- 2. validate every point ------------------------------------------------
    validate_key_points(&vk)?;

    // --- 3. address -------------------------------------------------------------
    let hash = sha256(body);
    let (expected, bump) = Address::find_program_address(&[VK_SEED_PREFIX, &hash], program_id);
    if *key.address() != expected {
        return Err(Groth16ProgramError::KeyAddressMismatch.into());
    }
    if key.owned_by(program_id) {
        return Err(Groth16ProgramError::KeyAlreadyPublished.into());
    }
    // A PDA can only be allocated by this program, so anything other than a
    // blank system-owned account here is impossible; reject it anyway.
    if !key.owned_by(&SYSTEM_PROGRAM_ID) || key.data_len() != 0 {
        return Err(ProgramError::InvalidAccountData);
    }

    // --- 4. create, fill, close -------------------------------------------------
    let space = key_account_len(n);
    create_key_account(payer, key, program_id, &hash, bump, space)?;

    {
        let mut key_data = key.try_borrow_mut()?;
        write_key_header(
            &mut key_data,
            KeyHeader {
                bump,
                num_public_inputs: n,
            },
        );
        key_data[KEY_HEADER_LEN..].copy_from_slice(body);
    }
    drop(staging_data);

    processor::drain_and_close(staging, authority)
}

/// Validates every key point through a syscall that performs the full check.
///
/// One 3-pair pairing call covers `α`, `IC₀` and the three G2 points —
/// pairing is the only `alt_bn128` opcode whose G2 deserialization includes
/// the subgroup check. `IC₁..ICₙ` go through `G1_ADD`, which deserializes with
/// full validation and is the cheapest G1 opcode; BN254's G1 has cofactor 1,
/// so on-curve is in-subgroup. The pairing *result* is ignored: these pairs
/// have no reason to multiply to one.
///
/// `α`, `−β`, `−γ`, `−δ` must not be the identity — the equation degenerates —
/// while any `ICᵢ` may be.
fn validate_key_points(vk: &VerifyingKey) -> ProgramResult {
    let alpha = vk.alpha();
    let ic0 = vk.ic(0);
    if is_zero(alpha)
        || is_zero(vk.neg_beta())
        || is_zero(vk.neg_gamma())
        || is_zero(vk.neg_delta())
    {
        return Err(Groth16ProgramError::IdentityKeyElement.into());
    }

    let mut input = [0u8; 3 * PAIRING_ELEMENT_SIZE];
    input[..PAIRING_ELEMENT_SIZE].copy_from_slice(vk.alpha_neg_beta());
    input[PAIRING_ELEMENT_SIZE..PAIRING_ELEMENT_SIZE + G1_SIZE].copy_from_slice(ic0);
    input[PAIRING_ELEMENT_SIZE + G1_SIZE..2 * PAIRING_ELEMENT_SIZE].copy_from_slice(vk.neg_gamma());
    input[2 * PAIRING_ELEMENT_SIZE..2 * PAIRING_ELEMENT_SIZE + G1_SIZE].copy_from_slice(ic0);
    input[2 * PAIRING_ELEMENT_SIZE + G1_SIZE..].copy_from_slice(vk.neg_delta());
    pairing_validate_points(&input).map_err(map_groth16)?;

    for i in 1..=vk.num_public_inputs() {
        let ic = vk.ic(i);
        g1_add(ic, ic).map_err(map_groth16)?;
    }
    Ok(())
}

#[inline(always)]
fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|&b| b == 0)
}

/// Brings the PDA into existence at `space` bytes, owned by this program.
///
/// Not `create_account`: that fails on a target with a nonzero balance, and
/// anyone can transfer lamports to any address. Top up to rent-exemption if
/// needed, then `allocate` and `assign`, each signed with the PDA seeds.
fn create_key_account(
    payer: &AccountView,
    key: &AccountView,
    program_id: &Address,
    hash: &[u8; 32],
    bump: u8,
    space: usize,
) -> ProgramResult {
    let required = Rent::get()?.try_minimum_balance(space)?;
    let shortfall = required.saturating_sub(key.lamports());
    if shortfall > 0 {
        Transfer {
            from: payer,
            to: key,
            lamports: shortfall,
        }
        .invoke()?;
    }

    let bump_seed = [bump];
    let seeds = [
        Seed::from(VK_SEED_PREFIX),
        Seed::from(hash),
        Seed::from(&bump_seed),
    ];
    let signer = Signer::from(&seeds[..]);

    let signers = core::slice::from_ref(&signer);

    Allocate {
        account: key,
        space: space as u64,
    }
    .invoke_signed(signers)?;
    Assign {
        account: key,
        owner: program_id,
    }
    .invoke_signed(signers)
}

#[inline(always)]
fn sha256(data: &[u8]) -> [u8; 32] {
    solana_sha256_hasher::hashv(&[data]).to_bytes()
}
