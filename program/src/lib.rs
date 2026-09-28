#![no_std]

//! Pinocchio SBF program: a content-addressed verifying-key registry and
//! Groth16 verification over BN254.
//!
//! Instruction data is `tag ‖ payload`; see [`solana_groth16_verify::Tag`] and the
//! README's instruction table. All verification logic lives in
//! [`solana_groth16_verify`]; this crate only parses accounts and instruction data,
//! enforces the registry's invariants, and maps errors onto `ProgramError`.
//!
//! The eager entrypoint is used because the tag — which decides how many
//! accounts an instruction takes — lives in the instruction data, and the
//! lazy entrypoint only exposes the data after every account has been read.
//! No instruction takes more than [`MAX_ACCOUNTS`] accounts.

use pinocchio::program_entrypoint;

pub mod error;
mod processor;

pub use processor::process_instruction;

/// `Publish` takes five accounts; nothing takes more.
///
/// The entrypoint deserializes at most this many accounts and skips any the
/// transaction supplies beyond them, so a processor's account-count check can
/// never observe more than five. See `processor` for what that means for each
/// instruction's surplus-account handling.
pub const MAX_ACCOUNTS: usize = 5;

#[cfg(any(target_os = "solana", target_arch = "bpf"))]
pinocchio::no_allocator!();
#[cfg(any(target_os = "solana", target_arch = "bpf"))]
pinocchio::nostd_panic_handler!();

program_entrypoint!(processor::process_instruction, MAX_ACCOUNTS);
