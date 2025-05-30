//! Range proofs applied to structure messages.

use core::{convert::Infallible, marker::PhantomData, ops::Shl};

use bulletproofs::BulletproofGens;
use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    traits::Identity,
    Scalar as RistrettoScalar,
};
use ff::Field;
use hybrid_array::{Array, ArraySize};
use itertools::zip_eq;
use typenum::{Double, Unsigned};

use crate::{
    attributes::{AttributeArray, AttributeCount, Attributes, Encoder, EncoderOutput},
    pedersen::{PedersenCommitment, PedersenGenerators},
    zkp::{
        AllocPointVar, AllocScalarVar, CompactProof as SchnorrProof, Constraint, ProofError,
        Prover, SchnorrCS, Transcript, Verifier,
    },
};

pub struct RangeProofEncoder<F: Field>(PhantomData<F>);

impl<F: Field> Default for RangeProofEncoder<F> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<F: Field> EncoderOutput for RangeProofEncoder<F> {
    /// Attribute value encoded as a field elem and an optional bit-width constraint. If the
    /// attribute type is the native field, no range check is required and the bit-width will be
    /// None.
    type Output = (F, Option<u32>);

    /// Optional bit-width constraint. If the attribute type is the native field, no range check is
    /// required and the bit-width will be None.
    type TypeOutput = Option<u32>;
}

macro_rules! impl_encoder_range_proof_encoder {
    ($($t:ty),*) => {
        $(
            impl<F> Encoder<$t> for RangeProofEncoder<F>
            where
                F: Field,
                $t: Into<F>,
            {
                #[inline]
                fn encode_value(&mut self, value: $t) -> Self::Output {
                    (value.into(), Some(<$t>::BITS))
                }

                #[inline]
                fn encode_type(&mut self) -> Self::TypeOutput {
                    Some(<$t>::BITS)
                }
            }
        )*
    };
}

impl_encoder_range_proof_encoder!(u8, u16, u32, u64);

impl<F: Field> Encoder<bool> for RangeProofEncoder<F> {
    /// Encode true to 1 in the field, and false to 0.
    #[inline]
    fn encode_value(&mut self, value: bool) -> Self::Output {
        let scalar = match value {
            true => F::ONE,
            false => F::ZERO,
        };
        (scalar, Some(1))
    }

    #[inline]
    fn encode_type(&mut self) -> Self::TypeOutput {
        Some(1)
    }
}

impl<F: Field> Encoder<&F> for RangeProofEncoder<F> {
    fn encode_value(&mut self, value: &F) -> Self::Output {
        (*value, None)
    }

    fn encode_type(&mut self) -> Self::TypeOutput {
        None
    }
}

#[derive(Clone, Debug)]
pub struct Bulletproof<Msg: AttributeCount> {
    /// A Bulletproof ensuring that each attribute in the message is in its expected range.
    pub bulletproof: Option<bulletproofs::RangeProof>,
    /// Commitments to range-constrained scalars in the message attributes, each using the same
    /// pair of Pedersen commitment generators such that they can be constrained by a single
    /// bulletproof.
    ///
    /// Attributes of the native field type do not need a range check commitment, and so the
    /// respective index in this array will be populated with `None`.
    pub bulletproof_commits:
        AttributeArray<Option<PedersenCommitment<CompressedRistretto, RistrettoScalar>>, Msg>,
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ProveError {
    #[error("bulletproofs proving error: {0:?}")]
    BulletproofError(bulletproofs::ProofError),
}

impl From<Infallible> for ProveError {
    fn from(value: Infallible) -> Self {
        match value {}
    }
}

impl From<bulletproofs::ProofError> for ProveError {
    fn from(value: bulletproofs::ProofError) -> Self {
        ProveError::BulletproofError(value)
    }
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum VerifyError {
    #[error("malformed proof")]
    MalformedProof,

    #[error("bulletproofs verification error: {0:?}")]
    BulletproofError(bulletproofs::ProofError),

    #[error("schnorr proof verification error: {0:?}")]
    ZkpError(crate::zkp::ProofError),
}

impl From<Infallible> for VerifyError {
    fn from(value: Infallible) -> Self {
        match value {}
    }
}

impl From<bulletproofs::ProofError> for VerifyError {
    fn from(value: bulletproofs::ProofError) -> Self {
        VerifyError::BulletproofError(value)
    }
}

impl From<crate::zkp::ProofError> for VerifyError {
    fn from(value: crate::zkp::ProofError) -> Self {
        VerifyError::ZkpError(value)
    }
}

impl<Msg: AttributeCount> Bulletproof<Msg> {
    pub fn prove(
        commit: &PedersenCommitment<RistrettoPoint, Msg>,
        msg: &Msg,
        blind: RistrettoScalar,
    ) -> Result<(Bulletproof<Msg>, SchnorrProof), ProveError>
    where
        Msg: Attributes<RangeProofEncoder<RistrettoScalar>>,
        Msg::N: Shl<typenum::B1>,
        Double<Msg::N>: ArraySize,
    {
        let mut transcript = Transcript::new(b"rkvc::range::PoK::transcript");
        let mut prover = Prover::new(b"rkvc::range::PoK::constraints", &mut transcript);

        // Build out the constraints for proof of knowledge for the commit opening.
        // NOTE: Order of variable allocation effects the transcript.
        // Encode the message as scalars, ignoring the number of bits for the purpose of opening
        // the commitment (it is proven with a range proof below).
        let attribute_vars: Array<_, Msg::N> = prover
            .alloc_scalars(
                msg.encode_attributes_labeled()
                    .map(|(label, (m, _))| (label, m)),
            )
            .unwrap();
        commit.prove_opening_constraints(&mut prover, &attribute_vars, blind);
        let bulletproof_openings =
            Self::prove_range_commit_constaints(&mut prover, &attribute_vars, msg)?;

        // NOTE: Uses rand::thread_rng internally, in conmbination with witness data.
        let schnorr_proof = prover.prove_compact();
        let bulletproof = Self::prove_bulletproof(&mut transcript, &bulletproof_openings)?;

        Ok((bulletproof, schnorr_proof))
    }

    pub fn prove_range_commit_constaints<X>(
        prover: &mut Prover,
        attribute_vars: &Array<X, Msg::N>,
        msg: &Msg,
    ) -> Result<AttributeArray<Option<(RistrettoScalar, RistrettoScalar)>, Msg>, ProveError>
    where
        Msg: Attributes<RangeProofEncoder<RistrettoScalar>>,
        // NOTE: The second and later bounds on Prover as AllocScalarVar is required, but it's
        // unclear as to why. Prover is a concrete type which does indeed have this trait
        // implemented.
        for<'a> Prover<'a>: AllocScalarVar<X, Error = Infallible>
            + AllocScalarVar<(&'static str, RistrettoScalar), Error = Infallible>
            + AllocPointVar<(&'static str, RistrettoPoint), Error = Infallible>
            + AllocPointVar<<Prover<'a> as SchnorrCS>::PointVar, Error = Infallible>,
        X: Copy,
    {
        // Seperate generators are used to commit to the individual range-check values because all
        // values in a batched range check must be committed to using the same generators.
        let bulletproof_commit_gens =
            PedersenGenerators::<RistrettoPoint, RistrettoScalar>::default();

        // Allocate variables for the linking of the commitment opening to the range proof.
        let bulletproof_commit_gen_var = prover
            .alloc_point((
                "rkvc::range::PoK::bulletproof_commit_gen",
                bulletproof_commit_gens.1[0],
            ))
            .unwrap();
        let bulletproof_commit_gen_blind_var = prover
            .alloc_point((
                "rkvc::range::PoK::bulletproof_commit_gen_blind",
                bulletproof_commit_gens.0,
            ))
            .unwrap();

        // Determine the largest attribute type we need to range check. We will use that for our
        // batched range check and further constrain any smaller items into a subrange.
        // NOTE: We assume here that log_2 of the scalar field characteristic is > bits_max + 1.
        let _bits_max: Option<u32> = Msg::encode_attribute_types().fold(None, |a, b| match a {
            Some(a) => Some(u32::max(a, b.unwrap_or(u32::MIN))),
            None => b,
        });

        // Commit to each value that we will be proving the range check over.
        // TODO: Use bits here to prove the subrange constraint.
        let openings: AttributeArray<Option<(RistrettoScalar, RistrettoScalar)>, Msg> = msg
            .encode_attributes()
            .map(|(x, bits)| {
                bits.map(|_bits| {
                    let blind = RistrettoScalar::random(&mut rand::thread_rng());
                    (x, blind)
                })
            })
            .collect();
        let commits: AttributeArray<Option<PedersenCommitment<_, _>>, Msg> = openings
            .iter()
            .map(|opening| {
                opening.map(|(x, blind)| bulletproof_commit_gens.commit_with_blind(&x, blind))
            })
            .collect();

        // Populate the constraints proving knowledge of an opening for the bulletproof value
        // commitments, and their linkage to the main commitment.
        let iter = zip_eq(
            attribute_vars,
            zip_eq(Msg::label_iter(), zip_eq(commits.iter(), openings.iter())),
        );
        for (x_var, (label, (x_commit, opening))) in iter {
            if let Some(x_commit) = x_commit {
                // unwrap used here because opening being None is an implementation error.
                let (_, blind) = opening.unwrap();
                // Link the scalar used for the opening proof, to an opening proof for the Pedersen
                // commitment used by the range proof.
                // TODO: Use a distinct label here for the allocate_scalar call.
                let mut constraint = Constraint::<Prover>::new();
                constraint.add(prover, *x_var, bulletproof_commit_gen_var)?;
                constraint.add(prover, (label, blind), bulletproof_commit_gen_blind_var)?;
                constraint.eq(prover, (label, x_commit.elem))?;
            };
        }
        Ok(openings)
    }

    pub fn prove_bulletproof(
        transcript: &mut Transcript,
        openings: &Array<Option<(RistrettoScalar, RistrettoScalar)>, Msg::N>,
    ) -> Result<Self, ProveError>
    where
        Msg: Attributes<RangeProofEncoder<RistrettoScalar>>,
        Msg::N: Shl<typenum::B1>,
        Double<Msg::N>: ArraySize,
    {
        // Recompute the commits from the openings.
        // NOTE: This could be more efficient by passing the commitments calculated earlier, but
        // recomputing results in a cleaner interface. There is likely some way to improve this.
        let bulletproof_commit_gens =
            PedersenGenerators::<RistrettoPoint, RistrettoScalar>::default();
        let commits: AttributeArray<Option<PedersenCommitment<_, _>>, Msg> = openings
            .iter()
            .map(|opening| {
                opening.map(|(x, blind)| {
                    bulletproof_commit_gens
                        .commit_with_blind(&x, blind)
                        .compress()
                })
            })
            .collect();

        // Count the number of checks that we expect to apply. This is used to determine how much
        // padding is needed to get to the next power of two for Bulletproof batching.
        let check_count: usize = Msg::encode_attribute_types()
            .fold(0, |count, b| count + if b.is_some() { 1 } else { 0 });

        // If not attributes need a range check, return early.
        if check_count == 0 {
            return Ok(Bulletproof {
                bulletproof: None,
                bulletproof_commits: commits,
            });
        }

        // Determine the largest attribute type we need to range check. We will use that for our
        // batched range check and further constrain any smaller items into a subrange.
        // NOTE: We assume here that log_2 of the scalar field characteristic is > bits_max + 1.
        let bits_max: u32 = Msg::encode_attribute_types()
            .fold(None, |a, b| match a {
                Some(a) => Some(u32::max(a, b.unwrap_or(u32::MIN))),
                None => b,
            })
            .unwrap();

        // Coerce the attribute scalars into u64s. This should always succeed unless there is
        // an implementation error, and pad up to the nearest power of two.
        let x_values_u64: Array<u64, Double<Msg::N>> = openings
            .iter()
            .filter_map(|opening| *opening)
            .map(|(x, _)| {
                let x_bytes = x.as_bytes();
                assert_eq!(x_bytes[8..], [0u8; 24]);
                u64::from_le_bytes(x_bytes[..8].try_into().unwrap())
            })
            .chain((0..).map(|_| 0u64))
            .take(Double::<Msg::N>::USIZE)
            .collect();

        // Collect the blinds, with padding, as we did for commits and values.
        let bulletproof_blinds: Array<RistrettoScalar, Double<Msg::N>> = openings
            .iter()
            .filter_map(|opening| opening.map(|(_, blind)| blind))
            .chain((0..).map(|_| RistrettoScalar::ZERO))
            .take(Double::<Msg::N>::USIZE)
            .collect();

        // Run the bulletproofs prover to establish that all the committed values are
        // within the specified range.
        // TODO: Constrain futher values such as u32.
        let (bulletproof, _) = bulletproofs::RangeProof::prove_multiple_with_rng(
            &BulletproofGens::new(bits_max as usize, x_values_u64.len()),
            &bulletproof_commit_gens.into(),
            transcript,
            &x_values_u64.as_slice()[..check_count.next_power_of_two()],
            &bulletproof_blinds.as_slice()[..check_count.next_power_of_two()],
            bits_max as usize,
            &mut rand::thread_rng(),
        )?;

        Ok(Self {
            bulletproof: Some(bulletproof),
            bulletproof_commits: commits,
        })
    }

    pub fn verify(
        &self,
        schnorr_proof: &SchnorrProof,
        commit: &PedersenCommitment<CompressedRistretto, Msg>,
    ) -> Result<(), VerifyError>
    where
        Msg: Attributes<RangeProofEncoder<RistrettoScalar>>,
        Msg::N: Shl<typenum::B1>,
        Double<Msg::N>: ArraySize,
    {
        let mut transcript = Transcript::new(b"rkvc::range::PoK::transcript");
        let mut verifier = Verifier::new(b"rkvc::range::PoK::constraints", &mut transcript);

        // Build out the constraints for proof of knowledge for the commit opening.
        // NOTE: Order of variable allocation effects the transcript.
        // Encode the message, ignoring the number of bits for the purpose of opening the
        // commitment (it is verified with a range proof check in constrain_attribute_ranges).
        let attribute_vars: Array<_, Msg::N> = verifier.alloc_scalars(Msg::label_iter())?;
        commit.constrain_opening(&mut verifier, &attribute_vars)?;
        self.constrain_range_commit_opening(&mut verifier, &attribute_vars)?;

        // NOTE: Uses rand::thread_rng internally, in combination with witness data.
        verifier.verify_compact(schnorr_proof)?;
        self.verify_range_proof(&mut transcript)?;

        Ok(())
    }

    // TODO: Once I've had a chance to do some work on the zkp API, I should be able to verify the
    // bulletproof inside this function, which will make use less error-prone (nee note below).
    /// Add constraints to the [Verifier] to ensure that the range proof commitments can be opened
    /// with the given `attribute_vars`.
    ///
    /// NOTE: Does not verify the given bulletproof or otherwise check the range of the scalars.
    /// [Bulletproof::verify_range_proof] needs to be called to complete the verification.
    pub fn constrain_range_commit_opening<X>(
        &self,
        verifier: &mut Verifier,
        attribute_vars: &Array<X, Msg::N>,
    ) -> Result<(), VerifyError>
    where
        // TODO: Consider loosening this bound. Other "constrain" functions do not require a
        // specific encoder.
        Msg: Attributes<RangeProofEncoder<RistrettoScalar>>,
        // NOTE: The second and later bounds on Verifier as AllocScalarVar is required, but it's
        // unclear as to why. Verifier is a concrete type which does indeed have this trait
        // implemented.
        for<'a> Verifier<'a>: AllocScalarVar<X, Error = ProofError>
            + AllocScalarVar<&'static str, Error = ProofError>
            + AllocPointVar<(&'static str, RistrettoPoint), Error = ProofError>
            + AllocPointVar<<Verifier<'a> as SchnorrCS>::PointVar, Error = ProofError>,
        X: Copy,
    {
        // Seperate generators are used to commit to the individual range-check values because all
        // values in a batched range check must be committed to using the same generators.
        let bulletproof_commit_gens =
            PedersenGenerators::<RistrettoPoint, RistrettoScalar>::default();

        // Allocate variables for the linking of the commitment opening to the range proof.
        let bulletproof_commit_gen_var = verifier.alloc_point((
            "rkvc::range::PoK::bulletproof_commit_gen",
            bulletproof_commit_gens.1[0],
        ))?;
        let bulletproof_commit_gen_blind_var = verifier.alloc_point((
            "rkvc::range::PoK::bulletproof_commit_gen_blind",
            bulletproof_commit_gens.0,
        ))?;

        // Determine the largest attribute type we need to range check. We will use that for our
        // batched range check and further constrain any smaller items into a subrange.
        // NOTE: We assume here that log_2 of the scalar field characteristic is > bits_max + 1.
        let _bits_max: Option<u32> = Msg::encode_attribute_types().fold(None, |a, b| match a {
            Some(a) => Some(u32::max(a, b.unwrap_or(u32::MIN))),
            None => b,
        });

        // Populate the constraints proving knowledge of an opening for the bulletproof value
        // commitments, and their linkage to the main commitment.
        let iter = zip_eq(
            self.bulletproof_commits.iter(),
            zip_eq(
                attribute_vars.iter().copied(),
                Msg::encode_attributes_types_labeled(),
            ),
        );
        for (x_commit, (x_var, (label, bits))) in iter {
            // Attributes with no bit constraints do not need to be checked.
            // TODO: Enforce sub-range membership.
            if let Some(_bits) = bits {
                // Link the scalar used for the opening proof, to an opening proof for the Pedersen
                // commitment used by the range proof.
                let mut constraint = Constraint::<Verifier>::new();
                constraint.add(verifier, x_var, bulletproof_commit_gen_var)?;
                constraint.add(verifier, label, bulletproof_commit_gen_blind_var)?;
                constraint.eq(
                    verifier,
                    (
                        label,
                        x_commit.clone().ok_or(VerifyError::MalformedProof)?.elem,
                    ),
                )?;
            }
        }

        Ok(())
    }

    pub fn verify_range_proof(&self, transcript: &mut Transcript) -> Result<(), VerifyError>
    where
        Msg: Attributes<RangeProofEncoder<RistrettoScalar>>,
        Msg::N: Shl<typenum::B1>,
        Double<Msg::N>: ArraySize,
    {
        // Determine the largest attribute type we need to range check. We will use that for our
        // batched range check and further constrain any smaller items into a subrange.
        // NOTE: We assume here that log_2 of the scalar field characteristic is > bits_max + 1.
        let bits_max: Option<u32> = Msg::encode_attribute_types().fold(None, |max, b| match max {
            Some(max) => Some(u32::max(max, b.unwrap_or(u32::MIN))),
            None => b,
        });

        // Count the number of checks that we expect to apply. This is used to determine how much
        // padding is needed to get to the next power of two for Bulletproof batching.
        let check_count: usize = Msg::encode_attribute_types()
            .fold(0, |count, b| count + if b.is_some() { 1 } else { 0 });

        // Collect the commitment into a slice of type [CompressedRistretto] for use with the
        // bulletproofs. We also need to pad up to the nearest power of two.
        let bulletproof_commits: Array<CompressedRistretto, Double<Msg::N>> = zip_eq(
            Msg::encode_attribute_types(),
            self.bulletproof_commits.as_slice(),
        )
        .filter_map(|(bits, commit)| {
            bits.map(|_| match commit {
                Some(commit) => Ok(commit.elem),
                None => Err(VerifyError::MalformedProof),
            })
        })
        .chain((0..).map(|_| Ok(CompressedRistretto::identity())))
        .take(Double::<Msg::N>::USIZE)
        .collect::<Result<_, _>>()?;

        // Verify the bulletproof, ensuring the range checks are enforced.
        if let Some(bits_max) = bits_max {
            let bulletproof = self
                .bulletproof
                .as_ref()
                .ok_or(VerifyError::MalformedProof)?;
            bulletproof.verify_multiple_with_rng(
                &BulletproofGens::new(bits_max as usize, self.bulletproof_commits.len()),
                &PedersenGenerators::default().into(),
                transcript,
                &bulletproof_commits[..check_count.next_power_of_two()],
                bits_max as usize,
                &mut rand::thread_rng(),
            )?;
        }
        Ok(())
    }
}

impl From<PedersenGenerators<RistrettoPoint, RistrettoScalar>> for bulletproofs::PedersenGens {
    fn from(value: PedersenGenerators<RistrettoPoint, RistrettoScalar>) -> Self {
        Self {
            B: value.1[0],
            B_blinding: value.0,
        }
    }
}

#[cfg(test)]
mod test {
    use curve25519_dalek::{RistrettoPoint, Scalar};
    use rkvc_derive::Attributes;

    use super::{Bulletproof, VerifyError};
    use crate::pedersen::PedersenCommitment;

    #[derive(Attributes)]
    struct Example {
        a: Scalar,
        b: u32,
        c: u64,
        d: u8,
    }

    #[test]
    fn basic_success() {
        let example = Example {
            a: Scalar::from(42u64),
            b: 5,
            c: 6,
            d: 7,
        };
        let (commit, blind) = PedersenCommitment::<RistrettoPoint, Example>::commit(
            &example,
            &mut rand::thread_rng(),
        );
        let (bulletproof, schnorr_proof) = Bulletproof::prove(&commit, &example, blind).unwrap();
        bulletproof
            .verify(&schnorr_proof, &commit.compress())
            .unwrap();
    }

    // TODO: Create a test that will violate the range check.
    #[test]
    fn basic_fail() {
        let example = Example {
            a: Scalar::from(42u64),
            b: 5,
            c: 6,
            d: 7,
        };
        let (commit, blind) = PedersenCommitment::<RistrettoPoint, Example>::commit(
            &example,
            &mut rand::thread_rng(),
        );
        let (bulletproof, schnorr_proof) = Bulletproof::prove(&commit, &example, blind).unwrap();

        let bad_example = Example {
            a: Scalar::from(42u64),
            b: 5,
            c: 7,
            d: 8,
        };
        let bad_commit =
            PedersenCommitment::<RistrettoPoint, Example>::commit_with_blind(&bad_example, blind);
        let Err(VerifyError::ZkpError(crate::zkp::ProofError::VerificationFailure)) =
            bulletproof.verify(&schnorr_proof, &bad_commit.compress())
        else {
            panic!("verify did not fail with verification failure");
        };
    }
}
