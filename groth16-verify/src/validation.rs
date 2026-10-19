//! Explicit key validation, shared by registration and host clients.

use crate::{
    constants::{G1_SIZE, PAIRING_ELEMENT_SIZE},
    point,
    scalar::is_zero,
    syscall::{g1_add, pairing_validate_points},
    Groth16Error, VerifyingKey,
};

/// Validates every key point through a syscall that performs the full check.
///
/// First, without a syscall, every coordinate in the body must be `< p`. The
/// syscalls do not enforce this — they honor arkworks' serialization flags in
/// the top bits of `y`, under which a non-zero encoding decodes as the
/// identity — so the identity tests below are only meaningful once it holds,
/// and it also leaves each key exactly one body, hence one address.
///
/// One 3-pair pairing call covers `α`, `IC₀` and the three G2 points —
/// pairing is the only `alt_bn128` opcode whose G2 deserialization includes
/// the subgroup check. `IC₁..ICₙ` go through `G1_ADD`, which deserializes
/// *both* operands with full validation and is the cheapest G1 opcode; BN254's
/// G1 has cofactor 1, so on-curve is in-subgroup. Adjacent points are added in
/// pairs, so `n` points take `⌈n/2⌉` calls; an odd final point is added to
/// itself. Every result is ignored: the pairs have no reason to multiply to
/// one, and the sums mean nothing.
///
/// `α`, `−β`, `−γ`, `−δ` must not be the identity — the equation degenerates —
/// while any `ICᵢ` may be.
pub fn validate_for_publish(vk: &VerifyingKey) -> Result<(), Groth16Error> {
    if !point::coordinates_are_canonical(vk.body()) {
        return Err(Groth16Error::NonCanonicalCoordinate);
    }
    let alpha = vk.alpha();
    let ic0 = vk.ic(0);
    if is_zero(alpha)
        || is_zero(vk.neg_beta())
        || is_zero(vk.neg_gamma())
        || is_zero(vk.neg_delta())
    {
        return Err(Groth16Error::IdentityKeyElement);
    }

    let mut input = [0u8; 3 * PAIRING_ELEMENT_SIZE];
    input[..PAIRING_ELEMENT_SIZE].copy_from_slice(vk.alpha_neg_beta());
    input[PAIRING_ELEMENT_SIZE..PAIRING_ELEMENT_SIZE + G1_SIZE].copy_from_slice(ic0);
    input[PAIRING_ELEMENT_SIZE + G1_SIZE..2 * PAIRING_ELEMENT_SIZE].copy_from_slice(vk.neg_gamma());
    input[2 * PAIRING_ELEMENT_SIZE..2 * PAIRING_ELEMENT_SIZE + G1_SIZE].copy_from_slice(ic0);
    input[2 * PAIRING_ELEMENT_SIZE + G1_SIZE..].copy_from_slice(vk.neg_delta());
    pairing_validate_points(&input)?;

    let n = vk.num_public_inputs();
    for i in (1..=n).step_by(2) {
        let a = vk.ic(i);
        let b = if i < n { vk.ic(i + 1) } else { a };
        g1_add(a, b)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::constants::{FQ_MODULUS, FQ_SIZE, VK_ALPHA_OFFSET},
        ark_bn254::{G1Affine, G2Affine},
        ark_ec::AffineRepr,
        groth16_convert::OnChainKey,
    };

    fn validate(body: &[u8]) -> Result<(), Groth16Error> {
        VerifyingKey::from_body(body)
            .unwrap()
            .validate_for_publish()
    }

    /// The encodings the syscall would accept but the wire format does not:
    /// each fails the coordinate check before the identity test or any
    /// syscall, so an identity hidden behind a flag bit cannot be published.
    #[test]
    fn out_of_range_coordinates_are_rejected_before_the_identity_test() {
        let g1 = G1Affine::generator();
        let g2 = G2Affine::generator();
        let key = OnChainKey::new(&g1, &g2, &g2, &g2, &[g1, g1]).unwrap();
        validate(key.body()).unwrap();

        for offset in (0..key.body().len()).step_by(FQ_SIZE) {
            for bit in [0x40, 0x80, 0xc0] {
                let mut body = key.body().to_vec();
                body[offset] |= bit;
                assert_eq!(
                    validate(&body),
                    Err(Groth16Error::NonCanonicalCoordinate),
                    "coordinate at {offset}, flag {bit:#x}"
                );
            }
            let mut body = key.body().to_vec();
            body[offset..offset + FQ_SIZE].copy_from_slice(&FQ_MODULUS);
            assert_eq!(
                validate(&body),
                Err(Groth16Error::NonCanonicalCoordinate),
                "coordinate at {offset} equal to p"
            );
            body[offset + FQ_SIZE - 1] -= 1;
            // p − 1 passes the range check but can fail curve validation.
            assert_eq!(validate(&body), Err(Groth16Error::InvalidPoint));
        }

        // The plain all-zero identity still reaches the identity test.
        let mut body = key.body().to_vec();
        body[VK_ALPHA_OFFSET..VK_ALPHA_OFFSET + G1_SIZE].fill(0);
        assert_eq!(validate(&body), Err(Groth16Error::IdentityKeyElement));
    }
}
