#![no_std]

//! Stateless, allocation-free Groth16 (BN254) verification for Solana programs.
//!
//! This crate is the verifier used by `groth16-program`. A program that wants
//! to verify inline — without a CPI — depends on it directly:
//!
//! ```ignore
//! use groth16_verify::{Proof, VerifyingKey, verify};
//!
//! let vk = VerifyingKey::from_body(key_body)?;
//! let (proof, public_inputs) = Proof::split_from(instruction_data)?;
//! verify(&vk, &proof, public_inputs)?;
//! ```
//!
//! All byte formats are the on-chain wire format — uncompressed, big-endian,
//! G2 negations pre-applied in the key — documented in the repository README.
//! Use `groth16-convert` to produce them from gnark or arkworks artifacts.
//!
//! # Features
//!
//! - `verify` (default): the verifier, [`Proof`], [`VerifyingKey`], account
//!   layouts. On-chain it calls `sol_alt_bn128_group_op`; off-chain it runs
//!   the host implementation from `solana-bn254`.
//! - `instruction` (default): client-side instruction builders and the
//!   program's canonical address.

#[cfg(test)]
extern crate std;

pub mod constants;
mod error;
mod tag;

#[cfg(feature = "instruction")]
pub mod instruction;

pub use tag::Tag;

#[cfg(feature = "verify")]
mod proof;
#[cfg(feature = "verify")]
pub mod scalar;
#[cfg(feature = "verify")]
pub mod state;
#[cfg(feature = "verify")]
pub mod syscall;
#[cfg(feature = "verify")]
pub mod verifier;
#[cfg(feature = "verify")]
mod vk;

pub use error::Groth16Error;
#[cfg(feature = "verify")]
pub use {proof::Proof, verifier::verify, vk::VerifyingKey};
