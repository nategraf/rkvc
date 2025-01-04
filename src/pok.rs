//! Proof of knowledge for a Pederson commitment opening.
//! NOTE: WIP module to be broken up.

use core::marker::PhantomData;

use curve25519_dalek::{RistrettoPoint, Scalar as RistrettoScalar};
use group::Group;
use itertools::zip_eq;

use crate::{
    attributes::{Attributes, Identity},
    pederson::{PedersonCommitment, PedersonGenerators},
    zkp::{CompactProof, Constraint, ProofError, Prover, Transcript, Verifier},
};

pub struct PoK<G: Group, Msg>(PhantomData<G>, PhantomData<Msg>);

impl<Msg> PoK<RistrettoPoint, Msg>
where
    Msg: Attributes<Identity<RistrettoScalar>>,
{
    pub fn prove(
        commit: &PedersonCommitment<RistrettoPoint, Msg>,
        msg: &Msg,
        blind: RistrettoScalar,
    ) -> CompactProof {
        // TODO: Make these labels configurable / move transcript to arguments.
        let mut transcript = Transcript::new(b"rkvc::pok::PoK::transcript");
        let mut prover = Prover::new(b"rkvc::pok::PoK::constraints", &mut transcript);

        let pederson_generators = PedersonGenerators::attributes_default::<Msg>();

        // Constrain C = \Sigma_i m_i * G_i + s * G_blind
        // TODO: differentiate the labels for the scalar and the point.
        let mut constraint = Constraint::new();
        constraint
            .sum(
                &mut prover,
                zip_eq(Msg::label_iter(), Identity::elem_iter(msg)),
                zip_eq(Msg::label_iter(), pederson_generators.1),
            )
            .unwrap();
        constraint
            .add(
                &mut prover,
                ("rkvc::pok::PoK::blind", blind),
                ("rkvc::pok::PoK::blind_gen", pederson_generators.0),
            )
            .unwrap();
        constraint
            .eq(&mut prover, ("rkvc::pok::PoK::commit", commit.elem))
            .unwrap();

        prover.prove_compact()
    }

    pub fn verify(
        proof: &CompactProof,
        commit: &PedersonCommitment<RistrettoPoint, Msg>,
    ) -> Result<(), ProofError> {
        // TODO: Make these labels configurable / move transcript to arguments.
        let mut transcript = Transcript::new(b"rkvc::pok::PoK::transcript");
        let mut verifier = Verifier::new(b"rkvc::pok::PoK::constraints", &mut transcript);

        let pederson_generators = PedersonGenerators::attributes_default::<Msg>().compress();

        // Constrain C = \Sigma_i m_i * G_i + s * G_blind
        // TODO: differentiate the labels for the scalar and the point.
        let mut constraint = Constraint::new();
        constraint.sum(
            &mut verifier,
            Msg::label_iter(),
            zip_eq(Msg::label_iter(), pederson_generators.1),
        )?;
        constraint.add(
            &mut verifier,
            "rkvc::pok::PoK::blind",
            ("rkvc::pok::PoK::blind_gen", pederson_generators.0),
        )?;
        constraint.eq(&mut verifier, ("rkvc::pok::PoK::commit", commit.elem))?;

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
