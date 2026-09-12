//! `Write`.
//!
//! Accounts: `[authority (s), staging (w)]`. Data: `offset: u32 LE ‖ bytes`.
//!
//! `offset` is relative to the staging *body*. The header is unreachable: the
//! write is bounds-checked against the body slice, with checked arithmetic on
//! `offset + len`.

use {
    crate::{
        error::{map_groth16, Groth16ProgramError},
        processor,
    },
    pinocchio::{error::ProgramError, AccountView, Address, ProgramResult},
    solana_groth16_verify::state::{read_staging_account, staging_body_mut},
};

pub fn process(
    program_id: &Address,
    accounts: &mut [AccountView],
    payload: &[u8],
) -> ProgramResult {
    let [authority, staging] = accounts else {
        return Err(ProgramError::InvalidArgument);
    };
    processor::expect_signer(authority)?;
    processor::expect_writable(staging)?;
    processor::expect_owned_by(staging, program_id)?;

    let (offset, bytes) = payload
        .split_at_checked(4)
        .ok_or(ProgramError::InvalidInstructionData)?;
    let offset = u32::from_le_bytes(offset.try_into().unwrap()) as usize;

    let mut data = staging.try_borrow_mut()?;
    let (header, _) = read_staging_account(&data).map_err(map_groth16)?;
    if header.authority != *authority.address().as_array() {
        return Err(ProgramError::IncorrectAuthority);
    }

    let body = staging_body_mut(&mut data).map_err(map_groth16)?;
    let end = offset
        .checked_add(bytes.len())
        .filter(|&end| end <= body.len())
        .ok_or(Groth16ProgramError::WriteOutOfBounds)?;
    body[offset..end].copy_from_slice(bytes);
    Ok(())
}
