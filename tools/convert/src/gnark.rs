//! Parsers for gnark's native BN254 Groth16 encodings.
//!
//! gnark-crypto serializes big-endian with a flag in the two most significant
//! bits of the first byte of each point:
//!
//! ```text
//! 0b00  uncompressed        x ‖ y           (64 / 128 bytes)
//! 0b10  compressed, y is the lexicographically smaller root   (32 / 64 bytes)
//! 0b11  compressed, y is the lexicographically larger root
//! 0b01  compressed identity (remaining bytes zero)
//! ```
//!
//! `Fq2` is written `c1 ‖ c0`, and "lexicographically larger" for `Fq2` means
//! `c1 > −c1`, falling back to `c0` when `c1 = 0` — which is exactly the
//! ordering arkworks' `get_point_from_x_unchecked(x, greatest)` uses, so
//! decompression delegates to it.
//!
//! Layouts (`WriteTo` compressed, `WriteRawTo` uncompressed — the parser
//! accepts either, per point):
//!
//! ```text
//! VerifyingKey  [α]₁ [β]₁ [β]₂ [γ]₂ [δ]₁ [δ]₂  u32 len ‖ [K]₁…  PublicAndCommitmentCommitted  u32 nCommitmentKeys ‖ keys…
//! Proof         Ar Bs Krs  u32 len ‖ Commitments…  CommitmentPok
//! Witness       u32 nbPublic  u32 nbSecret  u32 len ‖ Fr…
//! ```
//!
//! Keys and proofs that use gnark's commitment extension are rejected — the
//! on-chain verifier implements plain Groth16.

use {
    crate::{
        wire::{
            checked_affine, fq2_from_bytes, fq_from_bytes, fr_from_bytes, g1_from_bytes,
            g2_from_bytes, OnChainKey, OnChainProof,
        },
        ConvertError,
    },
    ark_bn254::{Fr, G1Affine, G2Affine},
    ark_ec::{
        short_weierstrass::{Affine, SWCurveConfig},
        AffineRepr,
    },
    solana_groth16_verify::constants::{FQ_SIZE, FR_SIZE, G1_SIZE, G2_SIZE, MAX_PUBLIC_INPUTS},
};

const FLAG_MASK: u8 = 0b11 << 6;
const FLAG_UNCOMPRESSED: u8 = 0b00 << 6;
const FLAG_COMPRESSED_SMALLEST: u8 = 0b10 << 6;
const FLAG_COMPRESSED_LARGEST: u8 = 0b11 << 6;
const FLAG_COMPRESSED_INFINITY: u8 = 0b01 << 6;

/// Parses a `VerifyingKey` written by `WriteTo` or `WriteRawTo`.
pub fn parse_verifying_key(bytes: &[u8]) -> Result<OnChainKey, ConvertError> {
    let mut r = Reader::new(bytes);
    let alpha = r.g1()?;
    let _beta_g1 = r.g1()?;
    let beta = r.g2()?;
    let gamma = r.g2()?;
    let _delta_g1 = r.g1()?;
    let delta = r.g2()?;

    let k_len = r.u32()? as usize;
    // Bound the allocation by what the input can actually hold: every G1
    // encoding is at least 32 bytes, and a key cannot have more IC points
    // than the on-chain format admits.
    r.ensure_remaining(k_len, FQ_SIZE)?;
    if k_len > MAX_PUBLIC_INPUTS + 1 {
        return Err(ConvertError::TooManyPublicInputs(k_len - 1));
    }
    let mut ic = Vec::with_capacity(k_len);
    for _ in 0..k_len {
        ic.push(r.g1()?);
    }

    // PublicAndCommitmentCommitted: [][]uint64 as u32 outer len, then per
    // inner slice u32 len ‖ u64 elements. Only the empty shape is supported.
    let outer = r.u32()?;
    for _ in 0..outer {
        let inner = r.u32()?;
        if inner != 0 {
            return Err(ConvertError::Unsupported(
                "verifying key uses commitments (PublicAndCommitmentCommitted is non-empty)",
            ));
        }
    }
    let n_commitment_keys = r.u32()?;
    if n_commitment_keys != 0 {
        return Err(ConvertError::Unsupported(
            "verifying key uses commitments (CommitmentKeys is non-empty)",
        ));
    }
    r.finish()?;

    OnChainKey::new(&alpha, &beta, &gamma, &delta, &ic)
}

/// Parses a `Proof` written by `WriteTo` or `WriteRawTo`.
pub fn parse_proof(bytes: &[u8]) -> Result<OnChainProof, ConvertError> {
    let mut r = Reader::new(bytes);
    let ar = r.g1()?;
    let bs = r.g2()?;
    let krs = r.g1()?;
    let n_commitments = r.u32()?;
    if n_commitments != 0 {
        return Err(ConvertError::Unsupported("proof carries commitments"));
    }
    let _commitment_pok = r.g1()?;
    r.finish()?;
    Ok(OnChainProof::new(&ar, &bs, &krs))
}

/// Parses a public `Witness` written by `MarshalBinary` / `WriteTo` into the
/// `n` scalars the on-chain verifier expects, in circuit order.
pub fn parse_public_witness(bytes: &[u8]) -> Result<Vec<Fr>, ConvertError> {
    let mut r = Reader::new(bytes);
    let nb_public = r.u32()? as usize;
    let nb_secret = r.u32()?;
    if nb_secret != 0 {
        return Err(ConvertError::Unsupported(
            "witness contains secret inputs; pass the public witness",
        ));
    }
    let len = r.u32()? as usize;
    if len != nb_public {
        return Err(ConvertError::Unsupported(
            "witness vector length disagrees with nbPublic",
        ));
    }
    r.ensure_remaining(len, FR_SIZE)?;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        out.push(r.fr()?);
    }
    r.finish()?;
    Ok(out)
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], ConvertError> {
        let end = self.pos.checked_add(n).ok_or(ConvertError::UnexpectedEof)?;
        let s = self
            .bytes
            .get(self.pos..end)
            .ok_or(ConvertError::UnexpectedEof)?;
        self.pos = end;
        Ok(s)
    }

    /// Fails unless at least `count × min_size` bytes remain. Called before
    /// sizing a `Vec` from a length prefix, so a corrupt prefix produces an
    /// error rather than a huge allocation.
    fn ensure_remaining(&self, count: usize, min_size: usize) -> Result<(), ConvertError> {
        let needed = count
            .checked_mul(min_size)
            .ok_or(ConvertError::UnexpectedEof)?;
        if self.bytes.len() - self.pos < needed {
            return Err(ConvertError::UnexpectedEof);
        }
        Ok(())
    }

    fn peek(&self) -> Result<u8, ConvertError> {
        self.bytes
            .get(self.pos)
            .copied()
            .ok_or(ConvertError::UnexpectedEof)
    }

    fn finish(self) -> Result<(), ConvertError> {
        match self.bytes.len() - self.pos {
            0 => Ok(()),
            n => Err(ConvertError::TrailingBytes(n)),
        }
    }

    fn u32(&mut self) -> Result<u32, ConvertError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn fr(&mut self) -> Result<Fr, ConvertError> {
        fr_from_bytes(self.take(FR_SIZE)?.try_into().unwrap())
    }

    fn g1(&mut self) -> Result<G1Affine, ConvertError> {
        let flag = self.peek()? & FLAG_MASK;
        match flag {
            // Same layout as the on-chain format, including all-zero for the
            // identity (gnark's `RawBytes` of the point at infinity).
            FLAG_UNCOMPRESSED => g1_from_bytes(self.take(G1_SIZE)?.try_into().unwrap()),
            FLAG_COMPRESSED_INFINITY => {
                let raw = self.take(FQ_SIZE)?;
                expect_zero_after_flag(raw)?;
                Ok(G1Affine::identity())
            }
            FLAG_COMPRESSED_SMALLEST | FLAG_COMPRESSED_LARGEST => {
                let mut raw: [u8; FQ_SIZE] = self.take(FQ_SIZE)?.try_into().unwrap();
                raw[0] &= !FLAG_MASK;
                let x = fq_from_bytes(&raw)?;
                decompress(x, flag == FLAG_COMPRESSED_LARGEST)
            }
            _ => unreachable!("two-bit flag has exactly four values, all handled"),
        }
    }

    fn g2(&mut self) -> Result<G2Affine, ConvertError> {
        let flag = self.peek()? & FLAG_MASK;
        match flag {
            FLAG_UNCOMPRESSED => g2_from_bytes(self.take(G2_SIZE)?.try_into().unwrap()),
            FLAG_COMPRESSED_INFINITY => {
                let raw = self.take(2 * FQ_SIZE)?;
                expect_zero_after_flag(raw)?;
                Ok(G2Affine::identity())
            }
            FLAG_COMPRESSED_SMALLEST | FLAG_COMPRESSED_LARGEST => {
                let mut raw: [u8; 2 * FQ_SIZE] = self.take(2 * FQ_SIZE)?.try_into().unwrap();
                raw[0] &= !FLAG_MASK;
                let x = fq2_from_bytes(&raw)?;
                decompress(x, flag == FLAG_COMPRESSED_LARGEST)
            }
            _ => unreachable!("two-bit flag has exactly four values, all handled"),
        }
    }
}

fn expect_zero_after_flag(raw: &[u8]) -> Result<(), ConvertError> {
    if raw[0] & !FLAG_MASK != 0 || raw[1..].iter().any(|&b| b != 0) {
        return Err(ConvertError::InvalidPoint);
    }
    Ok(())
}

/// Recovers `y` from `x` for the given root choice and validates the point.
/// A compressed identity never reaches here (it has its own flag), so an
/// identity result — impossible for a valid `x` anyway — is rejected.
fn decompress<C: SWCurveConfig>(x: C::BaseField, largest: bool) -> Result<Affine<C>, ConvertError> {
    let p =
        Affine::<C>::get_point_from_x_unchecked(x, largest).ok_or(ConvertError::InvalidPoint)?;
    if p.is_zero() {
        return Err(ConvertError::InvalidPoint);
    }
    checked_affine(p)
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::wire::{g1_to_bytes, g2_to_bytes},
        ark_bn254::Fq,
        ark_bn254::{G1Projective, G2Projective},
        ark_ec::CurveGroup,
        ark_ff::{BigInteger, PrimeField, UniformRand, Zero},
        ark_std::test_rng,
    };

    /// Mirrors gnark-crypto's `Bytes()`: compressed with the root-choice flag.
    fn gnark_compress_g1(p: &G1Affine) -> [u8; FQ_SIZE] {
        let mut out = [0u8; FQ_SIZE];
        match p.xy() {
            None => out[0] = FLAG_COMPRESSED_INFINITY,
            Some((x, y)) => {
                out.copy_from_slice(&x.into_bigint().to_bytes_be());
                out[0] |= if y.into_bigint() > Fq::MODULUS_MINUS_ONE_DIV_TWO {
                    FLAG_COMPRESSED_LARGEST
                } else {
                    FLAG_COMPRESSED_SMALLEST
                };
            }
        }
        out
    }

    fn gnark_compress_g2(p: &G2Affine) -> [u8; 2 * FQ_SIZE] {
        let mut out = [0u8; 2 * FQ_SIZE];
        match p.xy() {
            None => out[0] = FLAG_COMPRESSED_INFINITY,
            Some((x, y)) => {
                out[..FQ_SIZE].copy_from_slice(&x.c1.into_bigint().to_bytes_be());
                out[FQ_SIZE..].copy_from_slice(&x.c0.into_bigint().to_bytes_be());
                let largest = if y.c1.is_zero() {
                    y.c0.into_bigint() > Fq::MODULUS_MINUS_ONE_DIV_TWO
                } else {
                    y.c1.into_bigint() > Fq::MODULUS_MINUS_ONE_DIV_TWO
                };
                out[0] |= if largest {
                    FLAG_COMPRESSED_LARGEST
                } else {
                    FLAG_COMPRESSED_SMALLEST
                };
            }
        }
        out
    }

    #[test]
    fn decompresses_both_roots_g1_and_g2() {
        let mut rng = test_rng();
        for _ in 0..32 {
            let p = G1Projective::rand(&mut rng).into_affine();
            let q = G2Projective::rand(&mut rng).into_affine();
            assert_eq!(Reader::new(&gnark_compress_g1(&p)).g1().unwrap(), p);
            assert_eq!(Reader::new(&gnark_compress_g2(&q)).g2().unwrap(), q);
            assert_eq!(Reader::new(&g1_to_bytes(&p)).g1().unwrap(), p);
            assert_eq!(Reader::new(&g2_to_bytes(&q)).g2().unwrap(), q);
        }
    }

    #[test]
    fn compressed_infinity() {
        assert_eq!(
            Reader::new(&gnark_compress_g1(&G1Affine::identity()))
                .g1()
                .unwrap(),
            G1Affine::identity()
        );
        assert_eq!(
            Reader::new(&gnark_compress_g2(&G2Affine::identity()))
                .g2()
                .unwrap(),
            G2Affine::identity()
        );
        let mut bad = gnark_compress_g1(&G1Affine::identity());
        bad[5] = 1;
        assert_eq!(Reader::new(&bad).g1(), Err(ConvertError::InvalidPoint));
    }

    #[test]
    fn oversized_length_prefixes_fail_before_allocating() {
        // A witness header claiming u32::MAX public inputs with no data.
        let mut witness = Vec::new();
        witness.extend_from_slice(&u32::MAX.to_be_bytes());
        witness.extend_from_slice(&0u32.to_be_bytes());
        witness.extend_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(
            crate::gnark::parse_public_witness(&witness),
            Err(ConvertError::UnexpectedEof)
        );

        // A key whose K length is huge, right after six valid points.
        let mut rng = test_rng();
        let mut key: Vec<u8> = Vec::new();
        let g1 = g1_to_bytes(&G1Projective::rand(&mut rng).into_affine());
        let g2 = g2_to_bytes(&G2Projective::rand(&mut rng).into_affine());
        for bytes in [&g1[..], &g1[..], &g2[..], &g2[..], &g1[..], &g2[..]] {
            key.extend_from_slice(bytes);
        }
        key.extend_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(
            crate::gnark::parse_verifying_key(&key),
            Err(ConvertError::UnexpectedEof)
        );

        // A plausible-looking but over-limit K length with enough bytes behind
        // it is refused on the on-chain maximum, not parsed point by point.
        key.truncate(key.len() - 4);
        let k = (MAX_PUBLIC_INPUTS + 2) as u32;
        key.extend_from_slice(&k.to_be_bytes());
        key.extend(std::iter::repeat_n(0u8, k as usize * FQ_SIZE));
        assert_eq!(
            crate::gnark::parse_verifying_key(&key),
            Err(ConvertError::TooManyPublicInputs(MAX_PUBLIC_INPUTS + 1))
        );
    }

    /// Six valid uncompressed points in the verifying-key prefix order
    /// `[α]₁ [β]₁ [β]₂ [γ]₂ [δ]₁ [δ]₂`.
    fn vk_prefix(rng: &mut impl ark_std::rand::Rng) -> Vec<u8> {
        let g1 = |rng: &mut _| g1_to_bytes(&G1Projective::rand(rng).into_affine()).to_vec();
        let g2 = |rng: &mut _| g2_to_bytes(&G2Projective::rand(rng).into_affine()).to_vec();
        [g1(rng), g1(rng), g2(rng), g2(rng), g1(rng), g2(rng)].concat()
    }

    #[test]
    fn commitment_extension_is_rejected() {
        let mut rng = test_rng();
        let ic0 = g1_to_bytes(&G1Projective::rand(&mut rng).into_affine());

        // PublicAndCommitmentCommitted with one non-empty inner slice.
        let mut key = vk_prefix(&mut rng);
        key.extend_from_slice(&1u32.to_be_bytes());
        key.extend_from_slice(&ic0);
        key.extend_from_slice(&1u32.to_be_bytes()); // outer len
        key.extend_from_slice(&1u32.to_be_bytes()); // inner len
        key.extend_from_slice(&0u64.to_be_bytes());
        key.extend_from_slice(&0u32.to_be_bytes());
        assert!(matches!(
            crate::gnark::parse_verifying_key(&key),
            Err(ConvertError::Unsupported(msg)) if msg.contains("PublicAndCommitmentCommitted")
        ));

        // CommitmentKeys present.
        let mut key = vk_prefix(&mut rng);
        key.extend_from_slice(&1u32.to_be_bytes());
        key.extend_from_slice(&ic0);
        key.extend_from_slice(&0u32.to_be_bytes());
        key.extend_from_slice(&1u32.to_be_bytes());
        assert!(matches!(
            crate::gnark::parse_verifying_key(&key),
            Err(ConvertError::Unsupported(msg)) if msg.contains("CommitmentKeys")
        ));

        // A proof carrying one commitment.
        let a = g1_to_bytes(&G1Projective::rand(&mut rng).into_affine());
        let b = g2_to_bytes(&G2Projective::rand(&mut rng).into_affine());
        let mut proof = [&a[..], &b[..], &a[..]].concat();
        proof.extend_from_slice(&1u32.to_be_bytes());
        proof.extend_from_slice(&a);
        proof.extend_from_slice(&a);
        assert!(matches!(
            crate::gnark::parse_proof(&proof),
            Err(ConvertError::Unsupported(msg)) if msg.contains("commitments")
        ));
    }

    #[test]
    fn witness_shape_is_checked() {
        let one = crate::wire::fr_to_bytes(&Fr::from(1u64));

        // A secret input in what should be the public witness.
        let mut w = Vec::new();
        w.extend_from_slice(&1u32.to_be_bytes());
        w.extend_from_slice(&1u32.to_be_bytes());
        w.extend_from_slice(&2u32.to_be_bytes());
        w.extend_from_slice(&one);
        w.extend_from_slice(&one);
        assert!(matches!(
            crate::gnark::parse_public_witness(&w),
            Err(ConvertError::Unsupported(msg)) if msg.contains("secret")
        ));

        // Vector length disagreeing with nbPublic.
        let mut w = Vec::new();
        w.extend_from_slice(&1u32.to_be_bytes());
        w.extend_from_slice(&0u32.to_be_bytes());
        w.extend_from_slice(&2u32.to_be_bytes());
        w.extend_from_slice(&one);
        w.extend_from_slice(&one);
        assert!(matches!(
            crate::gnark::parse_public_witness(&w),
            Err(ConvertError::Unsupported(msg)) if msg.contains("nbPublic")
        ));

        // Well-formed.
        let mut w = Vec::new();
        w.extend_from_slice(&1u32.to_be_bytes());
        w.extend_from_slice(&0u32.to_be_bytes());
        w.extend_from_slice(&1u32.to_be_bytes());
        w.extend_from_slice(&one);
        assert_eq!(
            crate::gnark::parse_public_witness(&w).unwrap(),
            vec![Fr::from(1u64)]
        );
    }

    #[test]
    fn errors_display() {
        for e in [
            ConvertError::UnexpectedEof,
            ConvertError::TrailingBytes(3),
            ConvertError::NonCanonicalField,
            ConvertError::InvalidPoint,
            ConvertError::Unsupported("x"),
            ConvertError::TooManyPublicInputs(9),
        ] {
            assert!(!e.to_string().is_empty());
        }
    }

    #[test]
    fn truncated_and_trailing() {
        let p = G1Projective::rand(&mut test_rng()).into_affine();
        let bytes = g1_to_bytes(&p);
        assert_eq!(
            Reader::new(&bytes[..63]).g1(),
            Err(ConvertError::UnexpectedEof)
        );
        let mut r = Reader::new(&bytes);
        assert_eq!(r.g1().unwrap(), p);
        r.finish().unwrap();
        let mut longer = bytes.to_vec();
        longer.push(0);
        let mut r = Reader::new(&longer);
        assert_eq!(r.g1().unwrap(), p);
        assert_eq!(r.finish(), Err(ConvertError::TrailingBytes(1)));
    }
}
