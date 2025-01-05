//! Proof of knowledge for a Pederson commitment opening, with range checks.
//! NOTE: WIP module to be broken up.

use core::{convert::Infallible, marker::PhantomData, ops::Shl};

use bulletproofs::BulletproofGens;
use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    traits::Identity,
    Scalar as RistrettoScalar,
};
use ff::Field;
use generic_array::{ArrayLength, GenericArray};
use itertools::zip_eq;
use typenum::{Double, Unsigned};

use crate::{
    attributes::{AttributeCount, Attributes, Visitor, VisitorOutput},
    pederson::PedersonCommitment,
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

impl<F: Field> VisitorOutput for RangeProofEncoder<F> {
    /// Attribute value encoded as a field elem and an optional bit-width constraint. If the
    /// attribute type is the native field, no range check is required and the bit-width will be
    /// None.
    type Output = (F, Option<u32>);

    /// Optional bit-width constraint. If the attribute type is the native field, no range check is
    /// required and the bit-width will be None.
    type TypeOutput = Option<u32>;
}

macro_rules! impl_visitor_range_proof_encoder {
    ($($t:ty),*) => {
        $(
            impl<F> Visitor<$t> for RangeProofEncoder<F>
            where
                F: Field,
                $t: Into<F>,
            {
                #[inline]
                fn visit(&mut self, value: $t) -> Self::Output {
                    (value.into(), Some(<$t>::BITS))
                }

                #[inline]
                fn visit_static(&mut self) -> Self::TypeOutput {
                    Some(<$t>::BITS)
                }
            }
        )*
    };
}

impl_visitor_range_proof_encoder!(u8, u16, u32, u64);

impl<F: Field> Visitor<&F> for RangeProofEncoder<F> {
    fn visit(&mut self, value: &F) -> Self::Output {
        (*value, None)
    }

    fn visit_static(&mut self) -> Self::TypeOutput {
        None
    }
}

pub struct PoK<G, Msg>(PhantomData<G>, PhantomData<Msg>);

pub struct Bulletproof<Msg: AttributeCount> {
    /// A Bulletproof ensuring that each attribute in the message is in its expected range.
    bulletproof: Option<bulletproofs::RangeProof>,
    /// Commitments to range-constrained scalars in the message attributes, each using the same
    /// pair of Pederson commitment generators such that they can be constrained by a single
    /// bulletproof.
    ///
    /// Attributes of the native field type do not need a range check commitment, and so the
    /// respective index in this array will be populated with `None`.
    bulletproof_commits: GenericArray<Option<CompressedRistretto>, Msg::N>,
    _phantom_msg: PhantomData<Msg>,
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

impl<Msg> PoK<RistrettoPoint, Msg> {
    pub fn prove(
        commit: &PedersonCommitment<RistrettoPoint, Msg>,
        msg: &Msg,
        blind: RistrettoScalar,
    ) -> Result<(Bulletproof<Msg>, SchnorrProof), ProveError>
    where
        Msg: Attributes<RangeProofEncoder<RistrettoScalar>>,
        Msg::N: Shl<typenum::B1>,
        Double<Msg::N>: ArrayLength,
    {
        let mut transcript = Transcript::new(b"rkvc::range::PoK::transcript");
        let mut prover = Prover::new(b"rkvc::range::PoK::constraints", &mut transcript);

        // Build out the constraints for proof of knowledge for the commit opening.
        // NOTE: Order of variable allocation effects the transcript.
        // Encode the message as scalars, ignoring the number of bits for the purpose of opening
        // the commitment (it is proven with a range proof below).
        let attribute_vars: GenericArray<_, Msg::N> = prover
            .alloc_scalars(
                msg.encode_attributes_labeled()
                    .map(|(label, (m, _))| (label, m)),
            )
            .unwrap();
        commit.prove_opening_constraints(&mut prover, &attribute_vars, blind);
        let (bulletproof_commits, bulletproof_openings) =
            Self::prove_range_commit_constaints(&mut prover, &attribute_vars, msg)?;

        // NOTE: Uses rand::thread_rng internally, in conmbination with witness data.
        let schnorr_proof = prover.prove_compact();
        let bulletproof =
            Self::prove_bulletproof(&mut transcript, bulletproof_commits, bulletproof_openings)?;

        Ok((bulletproof, schnorr_proof))
    }

    #[allow(clippy::type_complexity)] // TODO: address this warning
    pub fn prove_range_commit_constaints<X>(
        prover: &mut Prover,
        attribute_vars: &GenericArray<X, Msg::N>,
        msg: &Msg,
    ) -> Result<
        (
            GenericArray<Option<RistrettoPoint>, Msg::N>,
            GenericArray<Option<(RistrettoScalar, RistrettoScalar)>, Msg::N>,
        ),
        ProveError,
    >
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
        let bulletproof_commit_gens = bulletproofs::PedersenGens::default();

        // Allocate variables for the linking of the commitment opening to the range proof.
        let bulletproof_commit_b_var = prover
            .alloc_point((
                "rkvc::range::PoK::bulletproof_commit_b",
                bulletproof_commit_gens.B,
            ))
            .unwrap();
        let bulletproof_commit_b_blind_var = prover
            .alloc_point((
                "rkvc::range::PoK::bulletproof_commit_b",
                bulletproof_commit_gens.B_blinding,
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
        let openings: GenericArray<Option<(RistrettoScalar, RistrettoScalar)>, Msg::N> = msg
            .encode_attributes()
            .map(|(x, bits)| {
                bits.map(|_bits| {
                    let blind = RistrettoScalar::random(&mut rand::thread_rng());
                    (x, blind)
                })
            })
            .collect();
        let commits: GenericArray<Option<RistrettoPoint>, Msg::N> = openings
            .iter()
            .map(|opening| opening.map(|(x, blind)| bulletproof_commit_gens.commit(x, blind)))
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
                // Link the scalar used for the opening proof, to an opening proof for the Pederson
                // commitment used by the range proof.
                // TODO: Use a distinct label here for the allocate_scalar call.
                let mut constraint = Constraint::<Prover>::new();
                constraint.add(prover, *x_var, bulletproof_commit_b_var)?;
                constraint.add(prover, (label, blind), bulletproof_commit_b_blind_var)?;
                constraint.eq(prover, (label, *x_commit))?;
            };
        }
        Ok((commits, openings))
    }

    pub fn prove_bulletproof(
        transcript: &mut Transcript,
        commits: GenericArray<Option<RistrettoPoint>, Msg::N>,
        openings: GenericArray<Option<(RistrettoScalar, RistrettoScalar)>, Msg::N>,
    ) -> Result<Bulletproof<Msg>, ProveError>
    where
        Msg: Attributes<RangeProofEncoder<RistrettoScalar>>,
        Msg::N: Shl<typenum::B1>,
        Double<Msg::N>: ArrayLength,
    {
        let commits_compressed: GenericArray<Option<CompressedRistretto>, Msg::N> =
            commits.iter().map(|c| c.map(|c| c.compress())).collect();

        // Count the number of checks that we expect to apply. This is used to determine how much
        // padding is needed to get to the next power of two for Bulletproof batching.
        let check_count: usize = Msg::encode_attribute_types()
            .fold(0, |count, b| count + if b.is_some() { 1 } else { 0 });

        // If not attributes need a range check, return early.
        if check_count == 0 {
            return Ok(Bulletproof {
                bulletproof: None,
                bulletproof_commits: commits_compressed,
                _phantom_msg: PhantomData,
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
        let x_values_u64: GenericArray<u64, Double<Msg::N>> = openings
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
        let bulletproof_blinds: GenericArray<RistrettoScalar, Double<Msg::N>> = openings
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
            &Default::default(),
            transcript,
            &x_values_u64.as_slice()[..check_count.next_power_of_two()],
            &bulletproof_blinds.as_slice()[..check_count.next_power_of_two()],
            bits_max as usize,
            &mut rand::thread_rng(),
        )?;

        Ok(Bulletproof {
            bulletproof: Some(bulletproof),
            bulletproof_commits: commits_compressed,
            _phantom_msg: PhantomData,
        })
    }

    pub fn verify(
        proof: &Bulletproof<Msg>,
        schnorr_proof: &SchnorrProof,
        commit: &PedersonCommitment<CompressedRistretto, Msg>,
    ) -> Result<(), VerifyError>
    where
        Msg: Attributes<RangeProofEncoder<RistrettoScalar>>,
        Msg::N: Shl<typenum::B1>,
        Double<Msg::N>: ArrayLength,
    {
        let mut transcript = Transcript::new(b"rkvc::range::PoK::transcript");
        let mut verifier = Verifier::new(b"rkvc::range::PoK::constraints", &mut transcript);

        // Build out the constraints for proof of knowledge for the commit opening.
        // NOTE: Order of variable allocation effects the transcript.
        // Encode the message, ignoring the number of bits for the purpose of opening the
        // commitment (it is verified with a range proof check in constrain_attribute_ranges).
        let attribute_vars: GenericArray<_, Msg::N> = verifier.alloc_scalars(Msg::label_iter())?;
        commit.constrain_opening(&mut verifier, &attribute_vars)?;
        Self::constrain_range_commit_opening(&mut verifier, proof, &attribute_vars)?;

        // NOTE: Uses rand::thread_rng internally, in combination with witness data.
        verifier.verify_compact(schnorr_proof)?;
        Self::verify_bulletproof(&mut transcript, proof)?;

        Ok(())
    }

    // TODO: Once I've had a chance to do some work on the zkp API, I should be able to verify the
    // bulletproof inside this function, which will make use less error-prone (nee note below).
    /// Add constraints to the [Verifier] to ensure that the range proof commitments can be opened
    /// with the given `attribute_vars`.
    ///
    /// NOTE: Does not verify the given bulletproof or otherwise check the range of the scalars.
    /// [Self::verify_bulletproof] needs to be called to complete the verification.
    pub fn constrain_range_commit_opening<X>(
        verifier: &mut Verifier,
        proof: &Bulletproof<Msg>,
        attribute_vars: &GenericArray<X, Msg::N>,
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
        let bulletproof_commit_gens = bulletproofs::PedersenGens::default();

        // Allocate variables for the linking of the commitment opening to the range proof.
        let bulletproof_commit_b_var = verifier.alloc_point((
            "rkvc::range::PoK::bulletproof_commit_b",
            bulletproof_commit_gens.B,
        ))?;
        let bulletproof_commit_b_blind_var = verifier.alloc_point((
            "rkvc::range::PoK::bulletproof_commit_b",
            bulletproof_commit_gens.B_blinding,
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
            proof.bulletproof_commits.iter(),
            zip_eq(
                attribute_vars.iter().copied(),
                Msg::encode_attributes_types_labeled(),
            ),
        );
        for (x_commit, (x_var, (label, bits))) in iter {
            // Attributes with no bit constraints do not need to be checked.
            // TODO: Enforce sub-range membership.
            if let Some(_bits) = bits {
                // Link the scalar used for the opening proof, to an opening proof for the Pederson
                // commitment used by the range proof.
                let mut constraint = Constraint::<Verifier>::new();
                constraint.add(verifier, x_var, bulletproof_commit_b_var)?;
                constraint.add(verifier, label, bulletproof_commit_b_blind_var)?;
                constraint.eq(
                    verifier,
                    (label, x_commit.ok_or(VerifyError::MalformedProof)?),
                )?;
            }
        }

        Ok(())
    }

    pub fn verify_bulletproof(
        transcript: &mut Transcript,
        proof: &Bulletproof<Msg>,
    ) -> Result<(), VerifyError>
    where
        Msg: Attributes<RangeProofEncoder<RistrettoScalar>>,
        Msg::N: Shl<typenum::B1>,
        Double<Msg::N>: ArrayLength,
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
        let bulletproof_commits: GenericArray<CompressedRistretto, Double<Msg::N>> = zip_eq(
            Msg::encode_attribute_types(),
            proof.bulletproof_commits.as_slice(),
        )
        .filter_map(|(bits, commit)| {
            bits.map(|_| match commit {
                Some(commit) => Ok(*commit),
                None => Err(VerifyError::MalformedProof),
            })
        })
        // TODO: Identity is likely to be rejected by bulletproofs, figure out what padding to use
        // here.
        .chain((0..).map(|_| Ok(CompressedRistretto::identity())))
        .take(Double::<Msg::N>::USIZE)
        .collect::<Result<_, _>>()?;

        // Verify the bulletproof, ensuring the range checks are enforced.
        if let Some(bits_max) = bits_max {
            let bulletproof = proof
                .bulletproof
                .as_ref()
                .ok_or(VerifyError::MalformedProof)?;
            bulletproof.verify_multiple_with_rng(
                &BulletproofGens::new(bits_max as usize, proof.bulletproof_commits.len()),
                &Default::default(),
                transcript,
                &bulletproof_commits[..check_count.next_power_of_two()],
                bits_max as usize,
                &mut rand::thread_rng(),
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use curve25519_dalek::{RistrettoPoint, Scalar};
    use rkvc_derive::Attributes;

    use super::{PoK, VerifyError};
    use crate::pederson::PedersonCommitment;

    #[derive(Attributes)]
    struct Example {
        a: Scalar,
        b: u32,
        c: u64,
        //d: u8,
    }

    #[test]
    fn basic_success() {
        let example = Example {
            a: Scalar::from(42u64),
            b: 5,
            c: 6,
            //d: 7,
        };
        let (commit, blind) = PedersonCommitment::<RistrettoPoint, Example>::commit(
            &example,
            &mut rand::thread_rng(),
        );
        let proof = PoK::<RistrettoPoint, Example>::prove(&commit, &example, blind).unwrap();

        PoK::<RistrettoPoint, Example>::verify(&proof.0, &proof.1, &commit.compress()).unwrap();
    }

    // TODO: Create a test that will violate the range check.
    #[test]
    fn basic_fail() {
        let example = Example {
            a: Scalar::from(42u64),
            b: 5,
            c: 6,
            //d: 7,
        };
        let (commit, blind) = PedersonCommitment::<RistrettoPoint, Example>::commit(
            &example,
            &mut rand::thread_rng(),
        );
        let proof = PoK::<RistrettoPoint, Example>::prove(&commit, &example, blind).unwrap();

        let bad_example = Example {
            a: Scalar::from(42u64),
            b: 5,
            c: 7,
            //d: 8,
        };
        let bad_commit =
            PedersonCommitment::<RistrettoPoint, Example>::commit_with_blind(&bad_example, blind);
        let Err(VerifyError::ZkpError(crate::zkp::ProofError::VerificationFailure)) =
            PoK::<RistrettoPoint, Example>::verify(&proof.0, &proof.1, &bad_commit.compress())
        else {
            panic!("verify did not fail with verification failure");
        };
    }
}
