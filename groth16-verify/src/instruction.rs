//! Client-side instruction builders and the program's canonical address.
//!
//! Instruction data is `tag ‖ payload`. Account orders match the README's
//! instruction table exactly.

extern crate alloc;

use {
    crate::constants::{FR_SIZE, PROOF_SIZE, VK_SEED_PREFIX},
    alloc::{vec, vec::Vec},
    sha2::{Digest, Sha256},
    solana_address::{declare_id, Address},
    solana_instruction::{AccountMeta, Instruction},
};

declare_id!("GrPeAM83MtRfR8NvbW3tMMSBzQ9BsmQrgLjLCQNwZW4P");

/// System program address, spelled out to avoid a dependency for one constant.
pub const SYSTEM_PROGRAM_ID: Address = Address::new_from_array([0u8; 32]);

pub use crate::tag::Tag;

/// `sha256(body)`, the second PDA seed of a canonical key account.
pub fn vk_hash(body: &[u8]) -> [u8; 32] {
    Sha256::digest(body).into()
}

/// Derives the canonical key account for a key body, with the canonical bump.
/// Matches what `Publish` computes on-chain with `find_program_address`.
pub fn find_key_address(program_id: &Address, vk_hash: &[u8; 32]) -> (Address, u8) {
    Address::find_program_address(&[VK_SEED_PREFIX, vk_hash], program_id)
}

/// Data `[0, n as u16 LE]`. Accounts: authority (s), staging (w).
///
/// Must be placed in the same transaction as the system-program
/// `create_account` that allocates `staging`; see the README's registration
/// section for why.
pub fn initialize_staging(
    program_id: &Address,
    authority: &Address,
    staging: &Address,
    num_public_inputs: u16,
) -> Instruction {
    let mut data = Vec::with_capacity(3);
    data.push(Tag::InitializeStaging as u8);
    data.extend_from_slice(&num_public_inputs.to_le_bytes());
    Instruction::new_with_bytes(
        *program_id,
        &data,
        vec![
            AccountMeta::new_readonly(*authority, true),
            AccountMeta::new(*staging, false),
        ],
    )
}

/// Data `[1, offset as u32 LE, bytes...]`, `offset` relative to the body.
/// Accounts: authority (s), staging (w).
pub fn write(
    program_id: &Address,
    authority: &Address,
    staging: &Address,
    offset: u32,
    bytes: &[u8],
) -> Instruction {
    let mut data = Vec::with_capacity(5 + bytes.len());
    data.push(Tag::Write as u8);
    data.extend_from_slice(&offset.to_le_bytes());
    data.extend_from_slice(bytes);
    Instruction::new_with_bytes(
        *program_id,
        &data,
        vec![
            AccountMeta::new_readonly(*authority, true),
            AccountMeta::new(*staging, false),
        ],
    )
}

/// Data `[2]`. Accounts: authority (s,w), payer (s,w), staging (w),
/// key PDA (w), system program.
///
/// `key` must be `find_key_address(program_id, &vk_hash(body)).0`; the program
/// recomputes it and rejects anything else.
pub fn publish(
    program_id: &Address,
    authority: &Address,
    payer: &Address,
    staging: &Address,
    key: &Address,
) -> Instruction {
    Instruction::new_with_bytes(
        *program_id,
        &[Tag::Publish as u8],
        vec![
            AccountMeta::new(*authority, true),
            AccountMeta::new(*payer, true),
            AccountMeta::new(*staging, false),
            AccountMeta::new(*key, false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
        ],
    )
}

/// Data `[3, proof (256), public_inputs (32·n)]`. Accounts: key PDA (r).
pub fn verify(
    program_id: &Address,
    key: &Address,
    proof: &[u8; PROOF_SIZE],
    public_inputs: &[[u8; FR_SIZE]],
) -> Instruction {
    let mut data = Vec::with_capacity(1 + PROOF_SIZE + FR_SIZE * public_inputs.len());
    data.push(Tag::Verify as u8);
    data.extend_from_slice(proof);
    for input in public_inputs {
        data.extend_from_slice(input);
    }
    Instruction::new_with_bytes(
        *program_id,
        &data,
        vec![AccountMeta::new_readonly(*key, false)],
    )
}

/// Data `[4]`. Accounts: authority (s,w), staging (w).
pub fn close_staging(program_id: &Address, authority: &Address, staging: &Address) -> Instruction {
    Instruction::new_with_bytes(
        *program_id,
        &[Tag::CloseStaging as u8],
        vec![
            AccountMeta::new(*authority, true),
            AccountMeta::new(*staging, false),
        ],
    )
}
