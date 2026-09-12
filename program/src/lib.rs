#![no_std]

//! Pinocchio SBF program: a content-addressed verifying-key registry and
//! Groth16 verification over BN254.
//!
//! Instruction data is `tag ‖ payload`; see [`groth16_verify::Tag`] and the
//! README's instruction table. All verification logic lives in
//! [`groth16_verify`]; this crate only parses accounts and instruction data,
//! enforces the registry's invariants, and maps errors onto `ProgramError`.
//!
//! The eager entrypoint is used because the tag — which decides how many
//! accounts an instruction takes — lives in the instruction data, and the
//! lazy entrypoint only exposes the data after every account has been read.
//! No instruction takes more than [`MAX_ACCOUNTS`] accounts.

use {
    groth16_verify::Tag,
    pinocchio::{error::ProgramError, program_entrypoint, AccountView, Address, ProgramResult},
};

pub mod error;
mod processor;

/// `Publish` takes five accounts; nothing takes more.
pub const MAX_ACCOUNTS: usize = 5;

#[cfg(any(target_os = "solana", target_arch = "bpf"))]
pinocchio::no_allocator!();
#[cfg(any(target_os = "solana", target_arch = "bpf"))]
pinocchio::nostd_panic_handler!();

program_entrypoint!(process_instruction, MAX_ACCOUNTS);

pub fn process_instruction(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let (&tag, payload) = data
        .split_first()
        .ok_or(ProgramError::InvalidInstructionData)?;
    match Tag::from_u8(tag).ok_or(ProgramError::InvalidInstructionData)? {
        Tag::Verify => processor::verify::process(program_id, accounts, payload),
        Tag::InitializeStaging => {
            processor::initialize_staging::process(program_id, accounts, payload)
        }
        Tag::Write => processor::write::process(program_id, accounts, payload),
        Tag::Publish => processor::publish::process(program_id, accounts, payload),
        Tag::CloseStaging => processor::close_staging::process(program_id, accounts, payload),
    }
}
