//! `CloseStaging`.
//!
//! Accounts: `[authority (s,w), staging (w)]`. No data.
//!
//! Refunds the staging account's lamports to its recorded authority. Canonical
//! key accounts have no close path at all.

use {
    crate::{error::map_groth16, processor},
    groth16_verify::state::read_staging_account,
    pinocchio::{error::ProgramError, AccountView, Address, ProgramResult},
};

pub fn process(
    program_id: &Address,
    accounts: &mut [AccountView],
    payload: &[u8],
) -> ProgramResult {
    if !payload.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }
    let [authority, staging] = accounts else {
        return Err(ProgramError::InvalidArgument);
    };
    processor::expect_signer(authority)?;
    processor::expect_writable(authority)?;
    processor::expect_writable(staging)?;
    processor::expect_owned_by(staging, program_id)?;

    {
        let data = staging.try_borrow()?;
        let (header, _) = read_staging_account(&data).map_err(map_groth16)?;
        if header.authority != *authority.address().as_array() {
            return Err(ProgramError::IncorrectAuthority);
        }
    }

    processor::drain_and_close(staging, authority)
}
