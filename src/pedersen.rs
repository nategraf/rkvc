//! Pedersen commitments applied to structured messages.

use core::{
    convert::Infallible,
    iter::Sum,
    marker::PhantomData,
    ops::{Add, Sub},
};

use blake2::Blake2b512;

use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar as RistrettoScalar,
};
use group::Group;
use hybrid_array::Array;
use itertools::zip_eq;
use rand::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;
use typenum::U64;

use crate::{
    attributes::{
        AttributeArray, AttributeCount, AttributeLabels, Attributes, IdentityEncoder, UintEncoder,
    },
    hash::FromHash,
    zkp::{AllocScalarVar, CompactProof, Constraint, ProofError, Prover, Transcript, Verifier},
};

#[derive(Clone, Debug)]
pub struct PedersenCommitment<G, Msg> {
    pub elem: G,
    _phantom_msg: PhantomData<Msg>,
}

#[derive(Clone, Debug)]
pub struct PedersenGenerators<G, Msg: AttributeCount>(pub G, pub AttributeArray<G, Msg>);

#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum PedersenError {
    #[error("verification failed")]
    VerificationError,
}

impl<G: Group + FromHash<OutputSize = U64>, Msg: AttributeCount> PedersenGenerators<G, Msg> {
    /// Manually construct a set of Pedersen commitment generators.
    ///
    /// Discrete log relationship between the generators must be unknown to the party producing a
    /// commitment using these generators. If the discrete log is known to the committer, they may
    /// be able to break the binding property of the commitment and produce two messages than can
    /// be opened from the same commitment.
    pub fn new(blind_gen: G, attributes_gen: impl Into<Array<G, Msg::N>>) -> Self {
        Self(blind_gen, AttributeArray(attributes_gen.into()))
    }

    /// Default generator point used for blinding commitments.
    pub fn blind_gen_default() -> G {
        G::hash_from_bytes::<Blake2b512>(b"rkvc::pedersen::PedersenCommitment::blind_generator")
    }
}

impl<G: Group + FromHash<OutputSize = U64>, Msg: AttributeLabels> Default
    for PedersenGenerators<G, Msg>
{
    /// Generate a default set of generators from the given message type.
    ///
    /// Each attribute has a generator that is derived from the hash-to-group of its label.
    fn default() -> Self {
        PedersenGenerators(
            Self::blind_gen_default(),
            Msg::label_iter()
                .map(|label| G::hash_from_bytes::<Blake2b512>(label.as_bytes()))
                .collect(),
        )
    }
}

impl<Msg: AttributeCount> PedersenGenerators<RistrettoPoint, Msg> {
    pub fn commit_with_blind(
        &self,
        msg: &Msg,
        blind: RistrettoScalar,
    ) -> PedersenCommitment<RistrettoPoint, Msg>
    where
        Msg: Attributes<UintEncoder<RistrettoScalar>>,
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
        PedersenCommitment {
            elem,
            _phantom_msg: PhantomData,
        }
    }

    pub fn commit(
        &self,
        msg: &Msg,
        mut rng: impl RngCore + CryptoRng,
    ) -> (PedersenCommitment<RistrettoPoint, Msg>, RistrettoScalar)
    where
        Msg: Attributes<UintEncoder<RistrettoScalar>>,
    {
        let blind = RistrettoScalar::random(&mut rng);
        (self.commit_with_blind(msg, blind), blind)
    }

    pub fn open(
        &self,
        commit: &PedersenCommitment<RistrettoPoint, Msg>,
        msg: &Msg,
        blind: RistrettoScalar,
    ) -> Result<(), PedersenError>
    where
        Msg: Attributes<UintEncoder<RistrettoScalar>>,
    {
        let eq = commit.elem.ct_eq(&self.commit_with_blind(msg, blind).elem);
        match eq.into() {
            true => Ok(()),
            false => Err(PedersenError::VerificationError),
        }
    }

    /// Prove knowledge of an opening for the given commitment.
    ///
    /// This function is paired with [PedersenGenerators::verify_opening].
    pub fn prove_opening(
        &self,
        commit: &PedersenCommitment<RistrettoPoint, Msg>,
        msg: &Msg,
        blind: RistrettoScalar,
    ) -> CompactProof
    where
        Msg: Attributes<IdentityEncoder<RistrettoScalar>>,
    {
        macro_rules! label {
            ($s:literal) => {
                concat!("rkvc::pedersen::PedersenGenerators::opening::", $s)
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
    /// This function is paired with [PedersenGenerators::prove_opening].
    pub fn verify_opening(
        &self,
        commit: &PedersenCommitment<RistrettoPoint, Msg>,
        proof: &CompactProof,
    ) -> Result<(), ProofError>
    where
        Msg: Attributes<IdentityEncoder<RistrettoScalar>>,
    {
        macro_rules! label {
            ($s:literal) => {
                concat!("rkvc::pedersen::PedersenGenerators::opening::", $s)
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
    /// This function is paired with [PedersenGenerators::constrain_opening].
    pub fn prove_opening_constraints<X>(
        &self,
        prover: &mut Prover,
        commit: &PedersenCommitment<RistrettoPoint, Msg>,
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
                concat!("rkvc::pedersen::PedersenGenerators::opening::", $s)
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
    /// This function is paired with [PedersenGenerators::prove_opening_constraints].
    pub fn constrain_opening<X>(
        &self,
        verifier: &mut Verifier,
        commit: &PedersenCommitment<RistrettoPoint, Msg>,
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

    pub fn compress(&self) -> PedersenGenerators<CompressedRistretto, Msg> {
        PedersenGenerators(
            self.0.compress(),
            self.1.iter().map(|g| g.compress()).collect(),
        )
    }
}

impl<Msg: AttributeCount> PedersenGenerators<CompressedRistretto, Msg> {
    /// Add constraints for knowledge of an opening for the given commitment to a [Verifier].
    ///
    /// Note that if the message contains fields that are not in the constraint system's native
    /// field, these constraints alone will not ensure the prover knows a valid opening (e.g. if a
    /// field should be a u64, these constraints do not ensure it is in range withing the field)
    ///
    /// This function is paired with [PedersenGenerators::prove_opening_constraints].
    pub fn constrain_opening<X>(
        &self,
        verifier: &mut Verifier,
        commit: &PedersenCommitment<CompressedRistretto, Msg>,
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
                concat!("rkvc::pedersen::PedersenGenerators::opening::", $s)
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

    pub fn decompress(&self) -> Option<PedersenGenerators<RistrettoPoint, Msg>> {
        Some(PedersenGenerators(
            self.0.decompress()?,
            self.1
                .iter()
                .map(|g| g.decompress())
                .collect::<Option<AttributeArray<_, _>>>()?,
        ))
    }
}

impl<G, Msg> PedersenCommitment<G, Msg> {
    /// Construct a [PedersenCommitment] directly from an group element.
    pub fn from_elem(elem: G) -> Self {
        Self {
            elem,
            _phantom_msg: PhantomData,
        }
    }
}

impl<Msg> PedersenCommitment<RistrettoPoint, Msg> {
    pub fn commit_with_blind(msg: &Msg, blind: RistrettoScalar) -> Self
    where
        Msg: Attributes<UintEncoder<RistrettoScalar>>,
    {
        PedersenGenerators::default().commit_with_blind(msg, blind)
    }

    pub fn commit<R>(msg: &Msg, rng: &mut R) -> (Self, RistrettoScalar)
    where
        R: RngCore + CryptoRng + ?Sized,
        Msg: Attributes<UintEncoder<RistrettoScalar>>,
    {
        PedersenGenerators::default().commit(msg, rng)
    }

    // TODO: The following methods, with &self receivers, have a sharp edge in that if the commit
    // is generated with non-default parameters then calling `commit.open(_)` and similar will
    // fail. Consider how this API could be improved.
    pub fn open(&self, msg: &Msg, blind: RistrettoScalar) -> Result<(), PedersenError>
    where
        Msg: Attributes<UintEncoder<RistrettoScalar>>,
    {
        PedersenGenerators::default().open(self, msg, blind)
    }

    /// Prove knowledge of an opening for this commitment, using the default [PedersenGenerators]
    /// for the specified message type.
    ///
    /// This function is paired with [PedersenCommitment::verify_opening].
    pub fn prove_opening(&self, msg: &Msg, blind: RistrettoScalar) -> CompactProof
    where
        Msg: Attributes<IdentityEncoder<RistrettoScalar>>,
    {
        PedersenGenerators::default().prove_opening(self, msg, blind)
    }

    /// Verify knowledge of an opening for this commitment, using the default [PedersenGenerators]
    /// for the specified message type.
    ///
    /// Note that the message type must consist entirely of field elements (i.e. it is "identity
    /// encodable"; it does not contain e.g. u64 fields). Under this constraint, it can be
    /// guaranteed that the prover has knowledge of a valid message, as all field elements  are
    /// valid.
    ///
    /// This function is paired with [PedersenCommitment::prove_opening].
    pub fn verify_opening(&self, proof: &CompactProof) -> Result<(), ProofError>
    where
        Msg: Attributes<IdentityEncoder<RistrettoScalar>>,
    {
        PedersenGenerators::default().verify_opening(self, proof)
    }

    /// Adds the constraints for the commitment opening to a [Prover], using the default
    /// [PedersenGenerators] for the specified message type, in order to compose with other
    /// statements being proven.
    ///
    /// This function is paired with [PedersenGenerators::constrain_opening].
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
        PedersenGenerators::default().prove_opening_constraints(prover, self, msg_vars, blind)
    }

    /// Add constraints for knowledge of an opening for the given commitment to a [Verifier], using
    /// the default [PedersenGenerators] for the specified message type.
    ///
    /// Note that if the message contains fields that are not in the constraint system's native
    /// field, these constraints alone will not ensure the prover knows a valid opening (e.g. if a
    /// field should be a u64, these constraints do not ensure it is in range withing the field)
    ///
    /// This function is paired with [PedersenGenerators::prove_opening_constraints].
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
        PedersenGenerators::<RistrettoPoint, Msg>::default()
            .constrain_opening(verifier, self, msg_vars)
    }

    pub fn compress(&self) -> PedersenCommitment<CompressedRistretto, Msg> {
        PedersenCommitment {
            elem: self.elem.compress(),
            _phantom_msg: PhantomData,
        }
    }
}

impl<Msg> PedersenCommitment<CompressedRistretto, Msg> {
    /// Add constraints for knowledge of an opening for the given commitment to a [Verifier], using
    /// the default [PedersenGenerators] for the specified message type.
    ///
    /// Note that if the message contains fields that are not in the constraint system's native
    /// field, these constraints alone will not ensure the prover knows a valid opening (e.g. if a
    /// field should be a u64, these constraints do not ensure it is in range withing the field)
    ///
    /// This function is paired with [PedersenGenerators::prove_opening_constraints].
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
        PedersenGenerators::<RistrettoPoint, Msg>::default()
            .compress()
            .constrain_opening(verifier, self, msg_vars)
    }

    pub fn decompress(&self) -> Option<PedersenCommitment<RistrettoPoint, Msg>> {
        Some(PedersenCommitment {
            elem: self.elem.decompress()?,
            _phantom_msg: PhantomData,
        })
    }
}

impl<G, MsgLhs, MsgRhs> Add<PedersenCommitment<G, MsgRhs>> for PedersenCommitment<G, MsgLhs>
where
    G: Group,
    MsgLhs: AttributeCount + Add<MsgRhs>,
    MsgRhs: AttributeCount,
{
    type Output = PedersenCommitment<G, <MsgLhs as Add<MsgRhs>>::Output>;

    /// Add two [PedersenCommitment] values, which homomorphically adds the committed messages.
    ///
    /// The result will be a commitment to the addition of the committed messages. It is not
    /// guaranteed that there exists an opening for the added message unless every (set of) scalar
    /// field element(s) is a valid message.
    fn add(self, rhs: PedersenCommitment<G, MsgRhs>) -> Self::Output {
        PedersenCommitment {
            elem: self.elem + rhs.elem,
            _phantom_msg: PhantomData,
        }
    }
}

impl<MsgLhs, MsgRhs> Add<MsgRhs> for PedersenCommitment<RistrettoPoint, MsgLhs>
where
    MsgLhs: AttributeCount + Add<MsgRhs>,
    MsgRhs: Attributes<UintEncoder<RistrettoScalar>>,
    PedersenGenerators<RistrettoPoint, MsgRhs>: Default,
{
    type Output = PedersenCommitment<RistrettoPoint, <MsgLhs as Add<MsgRhs>>::Output>;

    /// Adds a message to a [PedersenCommitment], homomorphically in the commitment space.
    ///
    /// This uses the default [PedersenGenerators] for the RHS message.
    fn add(self, rhs: MsgRhs) -> Self::Output {
        self + PedersenGenerators::default().commit_with_blind(&rhs, RistrettoScalar::ZERO)
    }
}

impl<G, MsgLhs, MsgRhs> Sub<PedersenCommitment<G, MsgRhs>> for PedersenCommitment<G, MsgLhs>
where
    G: Group,
    MsgLhs: AttributeCount + Sub<MsgRhs>,
    MsgRhs: AttributeCount,
{
    type Output = PedersenCommitment<G, <MsgLhs as Sub<MsgRhs>>::Output>;

    /// Subtract two [PedersenCommitment] values, which homomorphically subtracts the committed messages.
    ///
    /// The result will be a commitment to the subtraction of the committed messages. It is not
    /// guaranteed that there exists an opening for the result unless every (set of) scalar field
    /// element(s) is a valid message.
    fn sub(self, rhs: PedersenCommitment<G, MsgRhs>) -> Self::Output {
        PedersenCommitment {
            elem: self.elem - rhs.elem,
            _phantom_msg: PhantomData,
        }
    }
}

impl<MsgLhs, MsgRhs> Sub<MsgRhs> for PedersenCommitment<RistrettoPoint, MsgLhs>
where
    MsgLhs: AttributeCount + Sub<MsgRhs>,
    MsgRhs: Attributes<UintEncoder<RistrettoScalar>>,
    PedersenGenerators<RistrettoPoint, MsgRhs>: Default,
{
    type Output = PedersenCommitment<RistrettoPoint, <MsgLhs as Sub<MsgRhs>>::Output>;

    /// Subtracts a message from a [PedersenCommitment], homomorphically in the commitment space.
    ///
    /// This uses the default [PedersenGenerators] for the RHS message.
    fn sub(self, rhs: MsgRhs) -> Self::Output {
        self - PedersenGenerators::default().commit_with_blind(&rhs, RistrettoScalar::ZERO)
    }
}

#[cfg(test)]
mod test {
    use curve25519_dalek::{RistrettoPoint, Scalar};
    use rkvc_derive::Attributes;

    use super::{PedersenCommitment, PedersenError};

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
        let (commit, blind) = PedersenCommitment::<RistrettoPoint, ExampleA>::commit(
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
        let (commit, blind) = PedersenCommitment::<RistrettoPoint, ExampleA>::commit(
            &example,
            &mut rand::thread_rng(),
        );
        commit.open(&example, blind).unwrap();

        let mangled_example = ExampleA {
            a: 42,
            b: Scalar::from(6u64),
        };
        let Err(PedersenError::VerificationError) = commit.open(&mangled_example, blind) else {
            panic!("open did not fail with verification error");
        };
    }

    #[test]
    fn basic_zkp_success() {
        let example = ExampleB {
            a: Scalar::from(42u64),
            b: Scalar::from(5u64),
        };
        let (commit, blind) = PedersenCommitment::<RistrettoPoint, ExampleB>::commit(
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
        let (commit, blind) = PedersenCommitment::<RistrettoPoint, ExampleB>::commit(
            &example,
            &mut rand::thread_rng(),
        );
        let proof = commit.prove_opening(&example, blind);

        let bad_example = ExampleB {
            a: Scalar::from(42u64),
            b: Scalar::from(6u64),
        };
        let bad_commit =
            PedersenCommitment::<RistrettoPoint, ExampleB>::commit_with_blind(&bad_example, blind);
        let Err(lox_zkp::ProofError::VerificationFailure) = bad_commit.verify_opening(&proof)
        else {
            panic!("verify did not fail with verification failure");
        };
    }
}
