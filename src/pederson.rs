//! Pederson commitments applied to structured messages.

use core::{convert::Infallible, iter::Sum, marker::PhantomData};

use blake2::Blake2b512;

use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar as RistrettoScalar,
};
use hybrid_array::{Array, ArraySize};
use group::Group;
use itertools::zip_eq;
use rand::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;
use typenum::U64;

use crate::{
    attributes::{AttributeCount, AttributeLabels, Attributes, IdentityEncoder, UintEncoder},
    hash::FromHash,
    zkp::{AllocScalarVar, CompactProof, Constraint, ProofError, Prover, Transcript, Verifier},
};

#[derive(Clone, Debug)]
pub struct PedersonCommitment<G, Msg> {
    pub elem: G,
    _phantom_msg: PhantomData<Msg>,
}

#[derive(Clone, Debug)]
pub struct PedersonGenerators<G, N: ArraySize>(pub G, pub Array<G, N>);

#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum PedersonError {
    #[error("verification failed")]
    VerificationError,
}

impl<G: Group + FromHash<OutputSize = U64>, N: ArraySize> PedersonGenerators<G, N> {
    /// Manually construct a set of Pederson commitment generators.
    ///
    /// Discrete log relationship between the generators must be unknown to the part producing a
    /// commitment using these generators. If the discreet log is know to the committer, they may
    /// be able to break the binding property of the commitment and produce two messages than can
    /// be opened from the same commitment.
    pub fn new(blind_gen: G, attributes_gen: Array<G, N>) -> Self {
        Self(blind_gen, attributes_gen)
    }

    /// Generate a default set of generators from the given message type.
    pub fn attributes_default<Msg>() -> PedersonGenerators<G, Msg::N>
    where
        Msg: AttributeLabels + AttributeCount<N = N>,
    {
        PedersonGenerators(
            G::hash_from_bytes::<Blake2b512>(
                b"rkvc::pederson::PedersonCommitment::blind_generator",
            ),
            Msg::label_iter()
                .map(|label| G::hash_from_bytes::<Blake2b512>(label.as_bytes()))
                .collect(),
        )
    }
}

impl<N: ArraySize> PedersonGenerators<RistrettoPoint, N> {
    pub fn commit_with_blind<Msg>(
        &self,
        msg: &Msg,
        blind: RistrettoScalar,
    ) -> PedersonCommitment<RistrettoPoint, Msg>
    where
        Msg: Attributes<UintEncoder<RistrettoScalar>> + AttributeCount<N = N>,
    {
        // NOTE: It would be more performant to use curve25519_dalek::MultiscalarMul here, but that
        // requires the iterators to have an exact size. Panics at runtime otherwise. This could be
        // addressed by improvements to attributes.
        let elem = RistrettoPoint::sum(
            itertools::zip_eq(
                msg.encode_attributes().chain([blind]),
                self.1.iter().copied().chain([self.0]),
            )
            .map(|(x, g)| x * g),
        );
        PedersonCommitment {
            elem,
            _phantom_msg: PhantomData,
        }
    }

    pub fn commit<Msg>(
        &self,
        msg: &Msg,
        mut rng: impl RngCore + CryptoRng,
    ) -> (PedersonCommitment<RistrettoPoint, Msg>, RistrettoScalar)
    where
        Msg: Attributes<UintEncoder<RistrettoScalar>> + AttributeCount<N = N>,
    {
        let blind = RistrettoScalar::random(&mut rng);
        (self.commit_with_blind(msg, blind), blind)
    }

    pub fn open<Msg>(
        &self,
        commit: &PedersonCommitment<RistrettoPoint, Msg>,
        msg: &Msg,
        blind: RistrettoScalar,
    ) -> Result<(), PedersonError>
    where
        Msg: Attributes<UintEncoder<RistrettoScalar>> + AttributeCount<N = N>,
    {
        let eq = commit.elem.ct_eq(&self.commit_with_blind(msg, blind).elem);
        match eq.into() {
            true => Ok(()),
            false => Err(PedersonError::VerificationError),
        }
    }

    /// Prove knowledge of an opening for the given commitment.
    ///
    /// This function is paired with [PedersonGenerators::verify_opening].
    pub fn prove_opening<Msg>(
        &self,
        commit: &PedersonCommitment<RistrettoPoint, Msg>,
        msg: &Msg,
        blind: RistrettoScalar,
    ) -> CompactProof
    where
        Msg: Attributes<IdentityEncoder<RistrettoScalar>>,
    {
        macro_rules! label {
            ($s:literal) => {
                concat!("rkvc::pederson::PedersonGenerators::opening::", $s)
            };
        }

        let mut transcript = Transcript::new(label!("transcript").as_bytes());
        let mut prover = Prover::new(label!("constraints").as_bytes(), &mut transcript);
        self.prove_opening_constraints(
            &mut prover,
            commit,
            &msg.encode_attributes_labeled().collect(),
            blind,
        );

        prover.prove_compact()
    }

    /// Verify knowledge of an opening for the given commitment.
    ///
    /// Note that the message type must consist entirely of field elements (i.e. it is "identity
    /// encodable"; it does not contain e.g. u64 fields). Under this constraint, it can be
    /// guaranteed that the prover has knowledge of a valid message, as all field elements  are
    /// valid.
    ///
    /// This function is paired with [PedersonGenerators::prove_opening].
    pub fn verify_opening<Msg>(
        &self,
        commit: &PedersonCommitment<RistrettoPoint, Msg>,
        proof: &CompactProof,
    ) -> Result<(), ProofError>
    where
        Msg: Attributes<IdentityEncoder<RistrettoScalar>>,
    {
        macro_rules! label {
            ($s:literal) => {
                concat!("rkvc::pederson::PedersonGenerators::opening::", $s)
            };
        }

        let mut transcript = Transcript::new(label!("transcript").as_bytes());
        let mut verifier = Verifier::new(label!("constraints").as_bytes(), &mut transcript);
        self.constrain_opening(&mut verifier, commit, &Msg::label_iter().collect())?;

        verifier.verify_compact(proof)
    }

    /// Adds the constraints for the commitment opening to a [Prover], in order to compose with
    /// other statements being proven.
    ///
    /// This function is paired with [PedersonGenerators::constrain_opening].
    pub fn prove_opening_constraints<X, Msg>(
        &self,
        prover: &mut Prover,
        commit: &PedersonCommitment<RistrettoPoint, Msg>,
        msg_vars: &Array<X, Msg::N>,
        blind: RistrettoScalar,
    ) where
        Msg: AttributeLabels,
        // NOTE: The second bound on Prover as AllocScalarVar is required, but it's unclear as to
        // why. Prover is a concrete type which does indeed have this trait implemented.
        for<'a> Prover<'a>: AllocScalarVar<X, Error = Infallible>
            + AllocScalarVar<(&'static str, RistrettoScalar), Error = Infallible>,
        X: Copy,
    {
        macro_rules! label {
            ($s:literal) => {
                concat!("rkvc::pederson::PedersonGenerators::opening::", $s)
            };
        }

        // Constrain C = \Sigma_i m_i * G_i + s * G_blind
        // TODO: differentiate the labels for the scalar and the point.
        let mut constraint = Constraint::<Prover>::new();
        constraint
            .sum(
                prover,
                msg_vars.iter().copied(),
                zip_eq(Msg::label_iter(), self.1.iter().copied()),
            )
            .unwrap();
        constraint
            .add(
                prover,
                (label!("blind"), blind),
                (label!("blind_gen"), self.0),
            )
            .unwrap();
        constraint
            .eq(prover, (label!("commit"), commit.elem))
            .unwrap();
    }

    /// Add constraints for knowledge of an opening for the given commitment to a [Verifier].
    ///
    /// Note that if the message contains fields that are not in the constraint system's native
    /// field, these constraints alone will not ensure the prover knows a valid opening (e.g. if a
    /// field should be a u64, these constraints do not ensure it is in range withing the field)
    ///
    /// This function is paired with [PedersonGenerators::prove_opening_constraints].
    pub fn constrain_opening<X, Msg>(
        &self,
        verifier: &mut Verifier,
        commit: &PedersonCommitment<RistrettoPoint, Msg>,
        msg_vars: &Array<X, Msg::N>,
    ) -> Result<(), ProofError>
    where
        Msg: AttributeLabels,
        // NOTE: The second bound on Verifier as AllocScalarVar is required, but it's unclear as to
        // why. Verifier is a concrete type which does indeed have this trait implemented.
        for<'a> Verifier<'a>: AllocScalarVar<X, Error = ProofError>
            + AllocScalarVar<&'static str, Error = ProofError>,
        X: Copy,
    {
        // NOTE: Schnorr constraint system expects points to be compressed, and so compression will
        // happen at some point. This implementation choses to compress it here.
        self.compress()
            .constrain_opening(verifier, &commit.compress(), msg_vars)
    }

    pub fn compress(&self) -> PedersonGenerators<CompressedRistretto, N> {
        PedersonGenerators(
            self.0.compress(),
            self.1.iter().map(|g| g.compress()).collect(),
        )
    }
}

impl<N: ArraySize> PedersonGenerators<CompressedRistretto, N> {
    /// Add constraints for knowledge of an opening for the given commitment to a [Verifier].
    ///
    /// Note that if the message contains fields that are not in the constraint system's native
    /// field, these constraints alone will not ensure the prover knows a valid opening (e.g. if a
    /// field should be a u64, these constraints do not ensure it is in range withing the field)
    ///
    /// This function is paired with [PedersonGenerators::prove_opening_constraints].
    pub fn constrain_opening<X, Msg>(
        &self,
        verifier: &mut Verifier,
        commit: &PedersonCommitment<CompressedRistretto, Msg>,
        msg_vars: &Array<X, Msg::N>,
    ) -> Result<(), ProofError>
    where
        Msg: AttributeLabels,
        // NOTE: The second bound on Verifier as AllocScalarVar is required, but it's unclear as to
        // why. Verifier is a concrete type which does indeed have this trait implemented.
        for<'a> Verifier<'a>: AllocScalarVar<X, Error = ProofError>
            + AllocScalarVar<&'static str, Error = ProofError>,
        X: Copy,
    {
        macro_rules! label {
            ($s:literal) => {
                concat!("rkvc::pederson::PedersonGenerators::opening::", $s)
            };
        }

        // Constrain C = \Sigma_i m_i * G_i + s * G_blind
        // TODO: differentiate the labels for the scalar and the point.
        let mut constraint = Constraint::new();
        constraint.sum(
            verifier,
            msg_vars.iter().copied(),
            zip_eq(Msg::label_iter(), self.1.iter().copied()),
        )?;
        constraint.add(verifier, label!("blind"), (label!("blind_gen"), self.0))?;
        constraint.eq(verifier, (label!("commit"), commit.elem))?;

        Ok(())
    }

    pub fn decompress(&self) -> Option<PedersonGenerators<RistrettoPoint, N>> {
        Some(PedersonGenerators(
            self.0.decompress()?,
            self.1
                .iter()
                .map(|g| g.decompress())
                .collect::<Option<Array<_, _>>>()?,
        ))
    }
}

impl<Msg> PedersonCommitment<RistrettoPoint, Msg> {
    pub fn commit_with_blind(msg: &Msg, blind: RistrettoScalar) -> Self
    where
        Msg: Attributes<UintEncoder<RistrettoScalar>>,
    {
        PedersonGenerators::attributes_default::<Msg>().commit_with_blind(msg, blind)
    }

    pub fn commit<R>(msg: &Msg, rng: &mut R) -> (Self, RistrettoScalar)
    where
        R: RngCore + CryptoRng + ?Sized,
        Msg: Attributes<UintEncoder<RistrettoScalar>>,
    {
        PedersonGenerators::attributes_default::<Msg>().commit(msg, rng)
    }

    // TODO: The following methods, with &self receivers, have a sharp edge in that if the commit
    // is generated with non-default parameters then calling `commit.open(_)` and similar will
    // fail. Consider how this API could be improved.
    pub fn open(&self, msg: &Msg, blind: RistrettoScalar) -> Result<(), PedersonError>
    where
        Msg: Attributes<UintEncoder<RistrettoScalar>>,
    {
        PedersonGenerators::attributes_default::<Msg>().open(self, msg, blind)
    }

    /// Prove knowledge of an opening for this commitment, using the default [PedersonGenerators]
    /// for the specified message type.
    ///
    /// This function is paired with [PedersonCommitment::verify_opening].
    pub fn prove_opening(&self, msg: &Msg, blind: RistrettoScalar) -> CompactProof
    where
        Msg: Attributes<IdentityEncoder<RistrettoScalar>>,
    {
        PedersonGenerators::attributes_default::<Msg>().prove_opening(self, msg, blind)
    }

    /// Verify knowledge of an opening for this commitment, using the default [PedersonGenerators]
    /// for the specified message type.
    ///
    /// Note that the message type must consist entirely of field elements (i.e. it is "identity
    /// encodable"; it does not contain e.g. u64 fields). Under this constraint, it can be
    /// guaranteed that the prover has knowledge of a valid message, as all field elements  are
    /// valid.
    ///
    /// This function is paired with [PedersonCommitment::prove_opening].
    pub fn verify_opening(&self, proof: &CompactProof) -> Result<(), ProofError>
    where
        Msg: Attributes<IdentityEncoder<RistrettoScalar>>,
    {
        PedersonGenerators::attributes_default::<Msg>().verify_opening(self, proof)
    }

    /// Adds the constraints for the commitment opening to a [Prover], using the default
    /// [PedersonGenerators] for the specified message type, in order to compose with other
    /// statements being proven.
    ///
    /// This function is paired with [PedersonGenerators::constrain_opening].
    pub fn prove_opening_constraints<X>(
        &self,
        prover: &mut Prover,
        msg_vars: &Array<X, Msg::N>,
        blind: RistrettoScalar,
    ) where
        Msg: AttributeLabels,
        for<'a> Prover<'a>: AllocScalarVar<X, Error = Infallible>,
        X: Copy,
    {
        PedersonGenerators::attributes_default::<Msg>()
            .prove_opening_constraints(prover, self, msg_vars, blind)
    }

    /// Add constraints for knowledge of an opening for the given commitment to a [Verifier], using
    /// the default [PedersonGenerators] for the specified message type.
    ///
    /// Note that if the message contains fields that are not in the constraint system's native
    /// field, these constraints alone will not ensure the prover knows a valid opening (e.g. if a
    /// field should be a u64, these constraints do not ensure it is in range withing the field)
    ///
    /// This function is paired with [PedersonGenerators::prove_opening_constraints].
    pub fn constrain_opening<X>(
        &self,
        verifier: &mut Verifier,
        msg_vars: &Array<X, Msg::N>,
    ) -> Result<(), ProofError>
    where
        Msg: AttributeLabels,
        for<'a> Verifier<'a>: AllocScalarVar<X, Error = ProofError>,
        X: Copy,
    {
        PedersonGenerators::<RistrettoPoint, _>::attributes_default::<Msg>()
            .constrain_opening(verifier, self, msg_vars)
    }

    pub fn compress(&self) -> PedersonCommitment<CompressedRistretto, Msg> {
        PedersonCommitment {
            elem: self.elem.compress(),
            _phantom_msg: PhantomData,
        }
    }
}

impl<Msg> PedersonCommitment<CompressedRistretto, Msg> {
    /// Add constraints for knowledge of an opening for the given commitment to a [Verifier], using
    /// the default [PedersonGenerators] for the specified message type.
    ///
    /// Note that if the message contains fields that are not in the constraint system's native
    /// field, these constraints alone will not ensure the prover knows a valid opening (e.g. if a
    /// field should be a u64, these constraints do not ensure it is in range withing the field)
    ///
    /// This function is paired with [PedersonGenerators::prove_opening_constraints].
    pub fn constrain_opening<X>(
        &self,
        verifier: &mut Verifier,
        msg_vars: &Array<X, Msg::N>,
    ) -> Result<(), ProofError>
    where
        Msg: AttributeLabels,
        for<'a> Verifier<'a>: AllocScalarVar<X, Error = ProofError>,
        X: Copy,
    {
        PedersonGenerators::<RistrettoPoint, _>::attributes_default::<Msg>()
            .compress()
            .constrain_opening(verifier, self, msg_vars)
    }

    pub fn decompress(&self) -> Option<PedersonCommitment<RistrettoPoint, Msg>> {
        Some(PedersonCommitment {
            elem: self.elem.decompress()?,
            _phantom_msg: PhantomData,
        })
    }
}

#[cfg(test)]
mod test {
    use curve25519_dalek::{RistrettoPoint, Scalar};
    use rkvc_derive::Attributes;

    use super::{PedersonCommitment, PedersonError};

    #[derive(Attributes)]
    struct ExampleA {
        a: u64,
        b: Scalar,
    }

    #[derive(Attributes)]
    struct ExampleB {
        a: Scalar,
        b: Scalar,
    }

    #[test]
    fn basic_success() {
        let example = ExampleA {
            a: 42,
            b: Scalar::from(5u64),
        };
        let (commit, blind) = PedersonCommitment::<RistrettoPoint, ExampleA>::commit(
            &example,
            &mut rand::thread_rng(),
        );
        commit.open(&example, blind).unwrap();
    }

    #[test]
    fn basic_fail() {
        let example = ExampleA {
            a: 42,
            b: Scalar::from(5u64),
        };
        let (commit, blind) = PedersonCommitment::<RistrettoPoint, ExampleA>::commit(
            &example,
            &mut rand::thread_rng(),
        );
        commit.open(&example, blind).unwrap();

        let mangled_example = ExampleA {
            a: 42,
            b: Scalar::from(6u64),
        };
        let Err(PedersonError::VerificationError) = commit.open(&mangled_example, blind) else {
            panic!("open did not fail with verification error");
        };
    }

    #[test]
    fn basic_zkp_success() {
        let example = ExampleB {
            a: Scalar::from(42u64),
            b: Scalar::from(5u64),
        };
        let (commit, blind) = PedersonCommitment::<RistrettoPoint, ExampleB>::commit(
            &example,
            &mut rand::thread_rng(),
        );
        let proof = commit.prove_opening(&example, blind);
        commit.verify_opening(&proof).unwrap();
    }

    #[test]
    fn basic_zkp_fail() {
        let example = ExampleB {
            a: Scalar::from(42u64),
            b: Scalar::from(5u64),
        };
        let (commit, blind) = PedersonCommitment::<RistrettoPoint, ExampleB>::commit(
            &example,
            &mut rand::thread_rng(),
        );
        let proof = commit.prove_opening(&example, blind);

        let bad_example = ExampleB {
            a: Scalar::from(42u64),
            b: Scalar::from(6u64),
        };
        let bad_commit =
            PedersonCommitment::<RistrettoPoint, ExampleB>::commit_with_blind(&bad_example, blind);
        let Err(lox_zkp::ProofError::VerificationFailure) = bad_commit.verify_opening(&proof)
        else {
            panic!("verify did not fail with verification failure");
        };
    }
}
