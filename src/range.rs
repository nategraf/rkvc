//! Proof of knowledge for a Pederson commitment opening, with range checks.
//! NOTE: WIP module to be broken up.

use alloc::vec::Vec;
use core::marker::PhantomData;

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

impl<Msg> PoK<RistrettoPoint, Msg> {
    // Constraint definition shared by prover and verifier. Ensures the prover knows some slice of
    // scalars that can be used to open the commitment.
    //
    // Variables are allocated to the Prover and to the Verifier respectively and then passed into
    // this function. Note that the slices should include the blinding factor and associated
    // generator.
    fn constrain_commit<CS: SchnorrCS>(
        cs: &mut CS,
        commit: CS::PointVar,
        msg_vars: impl IntoIterator<Item = CS::ScalarVar>,
        gen_vars: impl IntoIterator<Item = CS::PointVar>,
    ) {
        cs.constrain(
            commit,
            itertools::zip_eq(msg_vars, gen_vars).collect::<Vec<_>>(),
        );
    }
}

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
    #[error("bulletproofs priving error: {0:?}")]
    BulletproofError(bulletproofs::ProofError),
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

        let iter = itertools::zip_eq(
            itertools::zip_eq(
                Msg::label_iter(),
                msg.attribute_walk(RangeProofEncoder::default()),
            ),
            PedersonCommitment::<RistrettoPoint, Msg>::attribute_generators(),
        );

        // Seperate generators are used to commit to the individual range-check values.
        let bulletproof_commit_gens = bulletproofs::PedersenGens::default();

        // Allocate variables for the commit opening and linking of the range proof and commit,
        // note that this is repeated with respect to the verifier.
        // NOTE: Order of variable allocation effects the transcript.
        let (commit_var, _) = prover.allocate_point(b"PoK::commit", commit.elem);
        let (bulletproof_commit_b_var, _) =
            prover.allocate_point(b"PoK::bulletproof_commit_b", bulletproof_commit_gens.B);
        let (bulletproof_commit_b_blind_var, _) = prover.allocate_point(
            b"PoK::bulletproof_commit_b_blind",
            bulletproof_commit_gens.B_blinding,
        );

        let mut opening_scalar_vars = Vec::new();
        let mut opening_point_vars = Vec::new();
        let mut linking_scalar_vars = Vec::new();
        let mut linking_commit_vars = Vec::new();
        let mut bulletproof_x_values = Vec::new();
        let mut bulletproof_x_blinds = Vec::new();
        let mut bits_max: Option<u32> = None;
        for ((label, (x, bits)), g) in iter {
            // Add scalars to the Schnorr proof ensuring knowledge of an opening to the given commit.
            // TODO: differentiate these labels. Cannot be runtime strings due to API constraints.
            let x_var = prover.allocate_scalar(label.as_bytes(), x);
            opening_scalar_vars.push(x_var);
            opening_point_vars.push(prover.allocate_point(label.as_bytes(), g).0);

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
                bulletproof_x_values.push(x);
                bulletproof_x_blinds.push(blind);

                // Link the scalar used for the opening proof, to an opening proof for the Pederson
                // commitment used by the range proof.
                let blind_var = prover.allocate_scalar(label.as_bytes(), blind);
                linking_scalar_vars.push((x_var, blind_var));
                linking_commit_vars.push(prover.allocate_point(label.as_bytes(), x_commit).0);
            }
        }
        opening_scalar_vars.push(prover.allocate_scalar(b"PoK::blind", blind));
        opening_point_vars.push(
            prover
                .allocate_point(
                    b"PoK::blind_gen",
                    PedersonCommitment::<RistrettoPoint, Msg>::blind_generator(),
                )
                .0,
        );

        // Populate constraints proving knowledge of an opening for the message commit.
        Self::constrain_commit(
            &mut prover,
            commit_var,
            opening_scalar_vars,
            opening_point_vars,
        );
        // Populate constraints proving knowledge of an opening for the individual attribute commits.
        for ((x_var, blind_var), x_commit_var) in
            itertools::zip_eq(linking_scalar_vars, linking_commit_vars)
        {
            Self::constrain_commit(
                &mut prover,
                x_commit_var,
                [x_var, blind_var],
                [bulletproof_commit_b_var, bulletproof_commit_b_blind_var],
            );
        }

        // NOTE: Uses rand::thread_rng internally, in conmbination with witness data.
        let schnorr_proof = prover.prove_compact();

        let bulletproof_output = bits_max
            .map(|bits_max| {
                // Coerce the attribute scalars into u64s. This should always succeed unless there is
                // an implementation error.
                let x_values_u64 = bulletproof_x_values
                    .into_iter()
                    .map(|x| {
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
                    &bulletproof_x_blinds,
                    bits_max as usize,
                    &mut rand::thread_rng(),
                )
            })
            .transpose()
            .map_err(ProveError::BulletproofError)?;

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
        proof: &SchnorrProof,
        commit: &PedersonCommitment<RistrettoPoint, Msg>,
    ) -> Result<(), lox_zkp::ProofError> {
        // TODO: Make these labels configurable / move transcript to arguments.
        let mut transcript = Transcript::new(b"PoKTranscript");
        let mut verifier = Verifier::new(b"PoKConstraints", &mut transcript);

        let iter = itertools::zip_eq(
            Msg::label_iter(),
            PedersonCommitment::<RistrettoPoint, Msg>::attribute_generators(),
        );

        // Allocate all the variables, note that this is repeated with respect to the verifier.
        // NOTE: Order of variable allocation effects the transcript.
        let commit_var = verifier.allocate_point(b"PoK::commit", commit.elem.compress())?;
        let mut msg_vars = Vec::new();
        let mut gen_vars = Vec::new();
        for (label, g) in iter {
            // TODO: differentiate these labels. Cannot be runtime strings due to API constraints.
            msg_vars.push(verifier.allocate_scalar(label.as_bytes()));
            gen_vars.push(verifier.allocate_point(label.as_bytes(), g.compress())?);
        }
        msg_vars.push(verifier.allocate_scalar(b"PoK::blind"));
        gen_vars.push(verifier.allocate_point(
            b"PoK::blind_gen",
            PedersonCommitment::<RistrettoPoint, Msg>::blind_generator().compress(),
        )?);

        Self::constrain_commit(&mut verifier, commit_var, msg_vars, gen_vars);
        verifier.verify_compact(proof)
    }
}

#[cfg(test)]
mod test {
    use curve25519_dalek::{RistrettoPoint, Scalar};
    use rkvc_derive::Attributes;

    use super::PoK;
    use crate::pederson::PedersonCommitment;

    #[derive(Attributes)]
    struct Example {
        a: Scalar,
        b: Scalar,
    }

    #[test]
    fn basic_success() {
        let example = Example {
            a: Scalar::from(42u64),
            b: Scalar::from(5u64),
        };
        let (commit, blind) = PedersonCommitment::<RistrettoPoint, Example>::commit(
            &example,
            &mut rand::thread_rng(),
        );
        let proof = PoK::<RistrettoPoint, Example>::prove(&commit, &example, blind);

        PoK::<RistrettoPoint, Example>::verify(&proof, &commit).unwrap();
    }

    #[test]
    fn basic_fail() {
        let example = Example {
            a: Scalar::from(42u64),
            b: Scalar::from(5u64),
        };
        let (commit, blind) = PedersonCommitment::<RistrettoPoint, Example>::commit(
            &example,
            &mut rand::thread_rng(),
        );
        let proof = PoK::<RistrettoPoint, Example>::prove(&commit, &example, blind);

        let bad_example = Example {
            a: Scalar::from(42u64),
            b: Scalar::from(6u64),
        };
        let bad_commit =
            PedersonCommitment::<RistrettoPoint, Example>::commit_with_blind(&bad_example, blind);
        let Err(lox_zkp::ProofError::VerificationFailure) =
            PoK::<RistrettoPoint, Example>::verify(&proof, &bad_commit)
        else {
            panic!("verify did not fail with verification failure");
        };
    }
}
