//! One module per instruction, plus the account checks they share.
//!
//! Each processor destructures its account slice with an exact-length
//! pattern, so both missing and surplus accounts are rejected.

use pinocchio::{error::ProgramError, AccountView, Address};

pub mod close_staging;
pub mod initialize_staging;
pub mod publish;
pub mod verify;
pub mod write;

#[inline(always)]
pub(crate) fn expect_signer(account: &AccountView) -> Result<(), ProgramError> {
    if !account.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    Ok(())
}

#[inline(always)]
pub(crate) fn expect_writable(account: &AccountView) -> Result<(), ProgramError> {
    if !account.is_writable() {
        return Err(ProgramError::InvalidArgument);
    }
    Ok(())
}

/// Owner check by 32-byte value.
#[inline(always)]
pub(crate) fn expect_owned_by(account: &AccountView, owner: &Address) -> Result<(), ProgramError> {
    if !account.owned_by(owner) {
        return Err(ProgramError::InvalidAccountOwner);
    }
    Ok(())
}

/// Moves every lamport out of `from` into `to` and closes `from`.
#[inline(always)]
pub(crate) fn drain_and_close(
    from: &mut AccountView,
    to: &mut AccountView,
) -> Result<(), ProgramError> {
    let lamports = from.lamports();
    to.set_lamports(
        to.lamports()
            .checked_add(lamports)
            .ok_or(ProgramError::ArithmeticOverflow)?,
    );
    from.set_lamports(0);
    from.close()
}

/// Parses an initialized staging account and checks its recorded authority.
/// Processors check ownership before borrowing and retain control of the borrow.
pub(crate) fn authorized_staging<'a>(
    data: &'a [u8],
    authority: &AccountView,
) -> Result<(solana_groth16_verify::state::StagingHeader, &'a [u8]), ProgramError> {
    let (header, body) = solana_groth16_verify::state::read_staging_account(data)
        .map_err(crate::error::map_groth16)?;
    if header.authority != *authority.address().as_array() {
        return Err(ProgramError::IncorrectAuthority);
    }
    Ok((header, body))
}
