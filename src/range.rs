//! Proof of knowledge for a Pederson commitment opening, with range checks.
//! NOTE: WIP module to be broken up.

use alloc::vec::Vec;
use core::{convert::Infallible, marker::PhantomData};

use bulletproofs::BulletproofGens;
use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    Scalar as RistrettoScalar,
};
use ff::Field;
use lox_zkp::{
    toolbox::{prover::Prover, verifier::Verifier, SchnorrCS},
    CompactProof as SchnorrProof, Transcript,
};

use crate::{
    attributes::{Attributes, Visitor, VisitorOutput},
    pederson::PedersonCommitment,
    zkp::Constraint,
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
    type StaticOutput = Option<u32>;
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
                fn visit_static(&mut self) -> Self::StaticOutput {
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

    fn visit_static(&mut self) -> Self::StaticOutput {
        None
    }
}

pub struct PoK<G, Msg>(PhantomData<G>, PhantomData<Msg>);

// TODO: What a bad name...
pub struct BulletPoK<Msg> {
    bulletproof: Option<bulletproofs::RangeProof>,
    // TODO: Can you do without a Vec here?
    /// Commitments to range-constrained scalars in the message attributes, each using the same
    /// pair of Pederson commitment generators such that they can be constrained by a single
    /// bulletproof.
    ///
    /// Attributes of the native field type do not do not have commitments in this list.
    bulletproof_commits: Vec<CompressedRistretto>,
    schnorr: SchnorrProof,
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
    ZkpError(lox_zkp::ProofError),
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

impl From<lox_zkp::ProofError> for VerifyError {
    fn from(value: lox_zkp::ProofError) -> Self {
        VerifyError::ZkpError(value)
    }
}

impl<Msg> PoK<RistrettoPoint, Msg>
where
    Msg: Attributes<RangeProofEncoder<RistrettoScalar>>,
{
    pub fn prove(
        commit: &PedersonCommitment<RistrettoPoint, Msg>,
        msg: &Msg,
        blind: RistrettoScalar,
    ) -> Result<BulletPoK<Msg>, ProveError> {
        // TODO: Make these labels configurable / move transcript to arguments.
        let mut transcript = Transcript::new(b"PoKTranscript");
        let mut prover = Prover::new(b"PoKConstraints", &mut transcript);

        // Seperate generators are used to commit to the individual range-check values.
        let bulletproof_commit_gens = bulletproofs::PedersenGens::default();

        // Build out the constraints for proof of knowledge for the commit opening.
        // NOTE: Order of variable allocation effects the transcript.
        let mut opening_constraint = Constraint::<Prover>::new();
        let mut attribute_vars: Vec<<Prover<'_> as SchnorrCS>::ScalarVar> = Vec::new();
        let iter = itertools::zip_eq(
            itertools::zip_eq(
                Msg::label_iter(),
                msg.attribute_walk(RangeProofEncoder::default()),
            ),
            PedersonCommitment::<RistrettoPoint, Msg>::attribute_generators(),
        );
        for ((label, (x, _)), g) in iter {
            // Add scalars to the opening proof and save the variables to link to the range proof.
            // TODO: differentiate these labels. Cannot be runtime strings due to API constraints.
            let x_var = prover.allocate_scalar(label.as_bytes(), x);
            attribute_vars.push(x_var);
            opening_constraint.add(&mut prover, x_var, (label, g))?;
        }
        opening_constraint.add(
            &mut prover,
            ("PoK::blind", blind),
            (
                "PoK::blind_gen",
                PedersonCommitment::<RistrettoPoint, Msg>::blind_generator(),
            ),
        )?;
        opening_constraint.eq(&mut prover, ("PoK::commit", commit.elem))?;

        // Allocate variables for the linking of the commitment opening to the range proof.
        let (bulletproof_commit_b_var, _) =
            prover.allocate_point(b"PoK::bulletproof_commit_b", bulletproof_commit_gens.B);
        let (bulletproof_commit_b_blind_var, _) = prover.allocate_point(
            b"PoK::bulletproof_commit_b_blind",
            bulletproof_commit_gens.B_blinding,
        );

        // Populate the constraints proving knowledge of an opening for the bulletproof value
        // commitments, and their linkage to the main commitment.
        let mut bulletproof_values = Vec::new();
        let mut bulletproof_blinds = Vec::new();
        let mut bits_max: Option<u32> = None;
        let iter = itertools::zip_eq(
            attribute_vars,
            itertools::zip_eq(
                Msg::label_iter(),
                msg.attribute_walk(RangeProofEncoder::default()),
            ),
        );
        for (x_var, (label, (x, bits))) in iter {
            if let Some(bits) = bits {
                // TODO: Enforce sub-range membership.
                bits_max = Some(bits_max.map(|x| u32::max(x, bits)).unwrap_or(bits));

                // Produce the commitment for the range-checked value that will go with the proof.
                // TODO: Try again to use the transcript RNG here? It is challenging due to the
                // fact that the transcript is immutably borrowed by the prover.
                // TODO: Use a distinct label here for the allocate_scalar call.
                let blind = RistrettoScalar::random(&mut rand::thread_rng());
                let x_commit = bulletproof_commit_gens.commit(x, blind);

                // Save the x and blind values to be used for the range proof.
                bulletproof_values.push((x, bits));
                bulletproof_blinds.push(blind);

                // Link the scalar used for the opening proof, to an opening proof for the Pederson
                // commitment used by the range proof.
                let mut constraint = Constraint::<Prover>::new();
                constraint.add(&mut prover, x_var, bulletproof_commit_b_var)?;
                constraint.add(&mut prover, (label, blind), bulletproof_commit_b_blind_var)?;
                constraint.eq(&mut prover, (label, x_commit))?;
            }
        }

        // NOTE: Uses rand::thread_rng internally, in conmbination with witness data.
        let schnorr_proof = prover.prove_compact();

        let bulletproof_output = bits_max
            .map(|bits_max| {
                // Coerce the attribute scalars into u64s. This should always succeed unless there is
                // an implementation error.
                let x_values_u64 = bulletproof_values
                    .into_iter()
                    .map(|(x, _)| {
                        let x_bytes = x.as_bytes();
                        assert_eq!(x_bytes[8..], [0u8; 24]);
                        u64::from_le_bytes(x_bytes[..8].try_into().unwrap())
                    })
                    .collect::<Vec<_>>();

                // Run the bulletproofs prover to establish that all the committed values are
                // within the specified range.
                // TODO: Constrain futher values such as u32.
                bulletproofs::RangeProof::prove_multiple_with_rng(
                    &BulletproofGens::new(bits_max as usize, x_values_u64.len()),
                    &bulletproof_commit_gens,
                    &mut transcript,
                    &x_values_u64,
                    &bulletproof_blinds,
                    bits_max as usize,
                    &mut rand::thread_rng(),
                )
            })
            .transpose()?;

        match bulletproof_output {
            Some((bulletproof, bulletproof_commits)) => Ok(BulletPoK {
                bulletproof: Some(bulletproof),
                bulletproof_commits,
                schnorr: schnorr_proof,
                _phantom_msg: PhantomData,
            }),
            None => Ok(BulletPoK {
                bulletproof: None,
                bulletproof_commits: vec![],
                schnorr: schnorr_proof,
                _phantom_msg: PhantomData,
            }),
        }
    }

    pub fn verify(
        proof: &BulletPoK<Msg>,
        commit: &PedersonCommitment<CompressedRistretto, Msg>,
    ) -> Result<(), VerifyError> {
        // TODO: Make these labels configurable / move transcript to arguments.
        let mut transcript = Transcript::new(b"PoKTranscript");
        let mut verifier = Verifier::new(b"PoKConstraints", &mut transcript);

        // Seperate generators are used to commit to the individual range-check values.
        let bulletproof_commit_gens = bulletproofs::PedersenGens::default();

        // Build out the constraints for proof of knowledge for the commit opening.
        // NOTE: Order of variable allocation effects the transcript.
        let mut constraint = Constraint::<Verifier>::new();
        let mut x_vars = Vec::new();
        let iter = itertools::zip_eq(
            itertools::zip_eq(
                Msg::label_iter(),
                Msg::attribute_type_walk(RangeProofEncoder::default()),
            ),
            PedersonCommitment::<RistrettoPoint, Msg>::attribute_generators(),
        );
        for ((label, _), g) in iter {
            // TODO: differentiate these labels. Cannot be runtime strings due to API constraints.
            let x_var = verifier.allocate_scalar(label.as_bytes());
            x_vars.push(x_var);
            constraint.add(&mut verifier, x_var, (label, g))?;
        }
        constraint.add(
            &mut verifier,
            "PoK::blind",
            (
                "PoK::blind_gen",
                PedersonCommitment::<RistrettoPoint, Msg>::blind_generator().compress(),
            ),
        )?;
        constraint.eq(&mut verifier, ("PoK::commit", commit.elem))?;

        let bulletproof_commit_b_var = verifier.allocate_point(
            b"PoK::bulletproof_commit_b",
            bulletproof_commit_gens.B.compress(),
        )?;
        let bulletproof_commit_b_blind_var = verifier.allocate_point(
            b"PoK::bulletproof_commit_b_blind",
            bulletproof_commit_gens.B_blinding.compress(),
        )?;

        // Populate the constraints proving knowledge of an opening for the bulletproof value
        // commitments, and their linkage to the main commitment.
        // TODO: Aggregation requires a power of two, so padding will need to be added.
        let mut bits_max: Option<u32> = None;
        let iter = itertools::zip_eq(
            proof.bulletproof_commits.iter(),
            itertools::zip_eq(
                x_vars,
                itertools::zip_eq(
                    Msg::label_iter(),
                    Msg::attribute_type_walk(RangeProofEncoder::default()),
                ),
            )
            .filter(|(_, (_, bits))| bits.is_some()),
        );
        for (x_commit, (x_var, (label, bits))) in iter {
            // Attributes with no bit constraints are filtered out in the iterator.
            let bits = bits.unwrap();

            // TODO: Enforce sub-range membership.
            bits_max = Some(bits_max.map(|x| u32::max(x, bits)).unwrap_or(bits));

            // Link the scalar used for the opening proof, to an opening proof for the Pederson
            // commitment used by the range proof.
            let mut constraint = Constraint::<Verifier>::new();
            constraint.add(&mut verifier, x_var, bulletproof_commit_b_var)?;
            constraint.add(&mut verifier, label, bulletproof_commit_b_blind_var)?;
            constraint.eq(&mut verifier, (label, *x_commit))?;
        }

        // NOTE: Uses rand::thread_rng internally, in conmbination with witness data.
        verifier.verify_compact(&proof.schnorr)?;
        if let Some(bits_max) = bits_max {
            let bulletproof = proof
                .bulletproof
                .as_ref()
                .ok_or(VerifyError::MalformedProof)?;
            bulletproof.verify_multiple_with_rng(
                &BulletproofGens::new(bits_max as usize, proof.bulletproof_commits.len()),
                &bulletproof_commit_gens,
                &mut transcript,
                &proof.bulletproof_commits,
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

        PoK::<RistrettoPoint, Example>::verify(&proof, &commit.compress()).unwrap();
    }

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
        let Err(VerifyError::ZkpError(lox_zkp::ProofError::VerificationFailure)) =
            PoK::<RistrettoPoint, Example>::verify(&proof, &bad_commit.compress())
        else {
            panic!("verify did not fail with verification failure");
        };
    }
}
