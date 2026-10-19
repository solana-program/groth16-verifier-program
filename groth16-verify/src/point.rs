//! Coordinate-range checks for G1 and G2 points in the wire format.
//!
//! The syscall takes all-zero bytes as the identity and hands anything else to
//! arkworks' uncompressed decoding, which reads two serialization-flag bits
//! from the most significant byte of `y` — byte 32 of a G1 point, byte 64 of
//! a G2 point (the top byte of `y.c1`) — before it looks at the coordinates:
//! with the infinity flag (`0x40`) set it returns the identity whatever `x`
//! holds, and the negative flag (`0x80`) it strips and decodes the point
//! normally, giving every point a second encoding. Neither bit is part of the
//! syscall's documented format, and an all-zero test for the identity sees
//! neither.
//!
//! Both bits put the coordinate at or above `2^254`, and `p < 2^254`, so
//! requiring every coordinate to be `< p` rejects both — and leaves each
//! point exactly one encoding, the one `groth16-convert` produces. Each check
//! is a fixed-size big-endian compare: two for a G1 point, four for G2.

use crate::constants::{FQ_MODULUS, FQ_SIZE, G1_SIZE, G2_SIZE};

/// `x < p`. Equal-length big-endian byte strings compare lexicographically in
/// the same order as the integers they encode.
#[inline]
pub fn fq_is_canonical(x: &[u8; FQ_SIZE]) -> bool {
    x.as_slice() < FQ_MODULUS.as_slice()
}

/// Both coordinates of `x ‖ y` are `< p`. Says nothing about the curve.
#[inline]
pub fn g1_is_canonical(p: &[u8; G1_SIZE]) -> bool {
    coordinates_are_canonical(p)
}

/// All four `Fq` components of `x ‖ y` are `< p`. Says nothing about the curve.
#[inline]
pub fn g2_is_canonical(p: &[u8; G2_SIZE]) -> bool {
    coordinates_are_canonical(p)
}

/// Every 32-byte chunk of `bytes` is `< p`. A proof and a key body are both
/// nothing but concatenated coordinates, so one pass covers every point.
#[inline]
pub(crate) fn coordinates_are_canonical(bytes: &[u8]) -> bool {
    debug_assert!(bytes.len().is_multiple_of(FQ_SIZE));
    bytes
        .chunks_exact(FQ_SIZE)
        .all(|c| fq_is_canonical(c.try_into().unwrap()))
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        ark_bn254::{G1Affine, G2Affine},
        ark_ec::AffineRepr,
        groth16_convert::wire::{g1_to_bytes, g2_to_bytes},
    };

    #[test]
    fn modulus_boundary() {
        assert!(!fq_is_canonical(&FQ_MODULUS));
        let mut below = FQ_MODULUS;
        below[FQ_SIZE - 1] -= 1;
        assert!(fq_is_canonical(&below));
        assert!(fq_is_canonical(&[0u8; FQ_SIZE]));
        assert!(!fq_is_canonical(&[0xff; FQ_SIZE]));
        // Both flag bits alone exceed p.
        for bit in [0x40, 0x80, 0xc0] {
            let mut flagged = [0u8; FQ_SIZE];
            flagged[0] = bit;
            assert!(!fq_is_canonical(&flagged));
        }
    }

    #[test]
    fn identity_and_generators_are_canonical_but_flagged_copies_are_not() {
        assert!(g1_is_canonical(&[0u8; G1_SIZE]));
        assert!(g2_is_canonical(&[0u8; G2_SIZE]));
        let g = g1_to_bytes(&G1Affine::generator());
        let h = g2_to_bytes(&G2Affine::generator());
        assert!(g1_is_canonical(&g));
        assert!(g2_is_canonical(&h));
        for bit in [0x40, 0x80] {
            // The byte arkworks reads flags from: the top byte of `y`.
            let mut g = g;
            g[FQ_SIZE] |= bit;
            assert!(!g1_is_canonical(&g));
            let mut h = h;
            h[2 * FQ_SIZE] |= bit;
            assert!(!g2_is_canonical(&h));
        }
        // The same bits on any other component are out of range too.
        let mut h = h;
        h[3 * FQ_SIZE] |= 0x40;
        assert!(!g2_is_canonical(&h));
    }
}
