//! Host-side bridge from gnark and arkworks Groth16 artifacts to the on-chain
//! wire format expected by `solana-groth16-verify`.
//!
//! Both sources funnel through arkworks types: gnark bytes are parsed (and
//! decompressed) into `ark_bn254` points, and a single writer in [`wire`]
//! turns arkworks points into the on-chain bytes. That gives one place where
//! the format is defined and lets the parser lean on arkworks for the curve
//! and subgroup checks.
//!
//! ```text
//! gnark bytes ──parse──▶ ark types ──wire──▶ on-chain bytes
//! ark_groth16 types ────────────────▶ on-chain bytes
//! ```

pub mod arkworks;
pub mod wire;

pub use wire::{OnChainKey, OnChainProof};

/// Conversion failures. All indicate bad or unsupported input; none should be
/// reachable from a key or proof that gnark or arkworks itself accepts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConvertError {
    /// Input ended before the element being read was complete.
    UnexpectedEof,
    /// Bytes remained after the last expected element.
    TrailingBytes(usize),
    /// A field element is `≥ p` (or `≥ r` for scalars).
    NonCanonicalField,
    /// A point is not on the curve, not in the prime-order subgroup, or a
    /// compressed `x` has no square root.
    InvalidPoint,
    /// The gnark artifact uses a feature the on-chain verifier does not
    /// support (commitments), or its counts disagree with each other.
    Unsupported(&'static str),
    /// More public inputs than the on-chain format admits.
    TooManyPublicInputs(usize),
}

impl core::fmt::Display for ConvertError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnexpectedEof => write!(f, "unexpected end of input"),
            Self::TrailingBytes(n) => write!(f, "{n} trailing bytes after last element"),
            Self::NonCanonicalField => write!(f, "field element is not canonical"),
            Self::InvalidPoint => write!(f, "point is not on the curve or not in the subgroup"),
            Self::Unsupported(what) => write!(f, "unsupported: {what}"),
            Self::TooManyPublicInputs(n) => {
                write!(f, "{n} public inputs exceeds the on-chain maximum")
            }
        }
    }
}

impl std::error::Error for ConvertError {}
