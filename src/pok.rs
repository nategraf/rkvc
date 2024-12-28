//! Proof of knowledge for a Pederson commitment opening.
//! NOTE: WIP module to be broken up.

use core::marker::PhantomData;

use curve25519_dalek::{RistrettoPoint, Scalar as RistrettoScalar};
use group::Group;
use lox_zkp::{
    toolbox::{prover::Prover, verifier::Verifier, SchnorrCS},
    CompactProof, Transcript,
};

use crate::{
    attributes::{AttributeElems, AttributeLabels, Attributes},
    pederson::PedersonCommitment,
};

pub struct PoK<G: Group, Msg>(PhantomData<G>, PhantomData<Msg>);

impl<G: Group, Msg> PoK<G, Msg> {
    // Constraint definition shared by prover and verifier. Ensures the prover knows some slice of
    // scalars that can be used to open the commitment.
    //
    // Variables are allocated to the Prover and to the Verifier respectively and then passed into
    // this function. Note that the slices should include the blinding factor and associated
    // generator.
    fn constrain<CS: SchnorrCS>(
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

impl<Msg: Attributes<RistrettoScalar>> PoK<RistrettoPoint, Msg> {
    pub fn prove(
        commit: &PedersonCommitment<RistrettoPoint, Msg>,
        msg: &Msg,
        blind: RistrettoScalar,
    ) -> CompactProof {
        // TODO: Make these labels configurable.
        let mut transcript = Transcript::new(b"PoKTranscript");
        let mut prover = Prover::new(b"PoKConstraints", &mut transcript);

        // TODO: Does not ensure that the attribute elements are in the right range. Need to figure
        // out a way to flag this as unsafe automatically.
        let iter = itertools::zip_eq(
            itertools::zip_eq(
                Msg::attribute_labels().into_iter(),
                msg.attribute_elems().into_iter(),
            ),
            PedersonCommitment::<RistrettoPoint, Msg>::attribute_generators(),
        );

        // Allocate all the variables, note that this is repeated with respect to the verifier.
        // NOTE: Order of variable allocation effects the transcript.
        let (commit_var, _) = prover.allocate_point(b"PoK::commit", commit.elem);
        let mut msg_vars = Vec::new();
        let mut gen_vars = Vec::new();
        for ((label, x), g) in iter {
            // TODO: differentiate these labels
            msg_vars.push(prover.allocate_scalar(label.as_bytes(), x));
            gen_vars.push(prover.allocate_point(label.as_bytes(), g).0);
        }
        msg_vars.push(prover.allocate_scalar(b"PoK::blind", blind));
        gen_vars.push(
            prover
                .allocate_point(
                    b"PoK::blind_gen",
                    PedersonCommitment::<RistrettoPoint, Msg>::blind_generator(),
                )
                .0,
        );

        Self::constrain(&mut prover, commit_var, msg_vars, gen_vars);
        prover.prove_compact()
    }

    pub fn verify(
        proof: &CompactProof,
        commit: &PedersonCommitment<RistrettoPoint, Msg>,
    ) -> Result<(), lox_zkp::ProofError> {
        // TODO: Make these labels configurable.
        let mut transcript = Transcript::new(b"PoKTranscript");
        let mut verifier = Verifier::new(b"PoKConstraints", &mut transcript);

        // TODO: Does not ensure that the attribute elements are in the right range. Need to figure
        // out a way to flag this as unsafe automatically.
        let iter = itertools::zip_eq(
            Msg::attribute_labels().into_iter(),
            PedersonCommitment::<RistrettoPoint, Msg>::attribute_generators(),
        );

        // Allocate all the variables, note that this is repeated with respect to the verifier.
        // NOTE: Order of variable allocation effects the transcript.
        let commit_var = verifier.allocate_point(b"PoK::commit", commit.elem.compress())?;
        let mut msg_vars = Vec::new();
        let mut gen_vars = Vec::new();
        for (label, g) in iter {
            // TODO: differentiate these labels
            msg_vars.push(verifier.allocate_scalar(label.as_bytes()));
            gen_vars.push(verifier.allocate_point(label.as_bytes(), g.compress())?);
        }
        msg_vars.push(verifier.allocate_scalar(b"PoK::blind"));
        gen_vars.push(verifier.allocate_point(
            b"PoK::blind_gen",
            PedersonCommitment::<RistrettoPoint, Msg>::blind_generator().compress(),
        )?);

        Self::constrain(&mut verifier, commit_var, msg_vars, gen_vars);
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
    #[rkvc(field = curve25519_dalek::Scalar)]
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
