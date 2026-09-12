//! `Verify`: the hot path.
//!
//! Accounts: `[key (r)]`. Data: `proof (256) ‖ public_inputs (32·n)`.
//!
//! The account check is ownership plus the key discriminator and length,
//! nothing more — see `docs/design.md §2` for why the PDA is not re-derived.

use {
    crate::{error::map_groth16, processor},
    groth16_verify::{state::read_key_account, Proof},
    pinocchio::{error::ProgramError, AccountView, Address, ProgramResult},
};

#[inline(always)]
pub fn process(
    program_id: &Address,
    accounts: &mut [AccountView],
    payload: &[u8],
) -> ProgramResult {
    let [key] = accounts else {
        return Err(ProgramError::InvalidArgument);
    };
    processor::expect_owned_by(key, program_id)?;

    let data = key.try_borrow()?;
    let (_, vk) = read_key_account(&data).map_err(map_groth16)?;
    let (proof, public_inputs) = Proof::split_from(payload).map_err(map_groth16)?;
    groth16_verify::verify(&vk, &proof, public_inputs).map_err(map_groth16)
}
