use core::{iter::Sum, marker::PhantomData};

use blake2::Blake2b512;

use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar as RistrettoScalar,
};
use generic_array::{ArrayLength, GenericArray};
use group::Group;
use rand_core::CryptoRngCore;
use subtle::ConstantTimeEq;
use typenum::U64;

use crate::{
    attributes::{AttributeCount, AttributeLabels, Attributes, UintEncoder},
    hash::FromHash,
};

#[derive(Clone, Debug)]
pub struct PedersonCommitment<G, Msg> {
    pub elem: G,
    _phantom_msg: PhantomData<Msg>,
}

#[derive(Clone, Debug)]
pub struct PedersonGenerators<G, N: ArrayLength>(pub G, pub GenericArray<G, N>);

#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum PedersonError {
    #[error("verification failed")]
    VerificationError,
}

impl<G: Group + FromHash<OutputSize = U64>, N: ArrayLength> PedersonGenerators<G, N> {
    /// Manually construct a set of Pederson commitment generators.
    ///
    /// Discrete log relationship between the generators must be unknown to the part producing a
    /// commitment using these generators. If the discreet log is know to the committer, they may
    /// be able to break the binding property of the commitment and produce two messages than can
    /// be opened from the same commitment.
    pub fn new(blind_gen: G, attributes_gen: GenericArray<G, N>) -> Self {
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

impl<N: ArrayLength> PedersonGenerators<RistrettoPoint, N> {
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
                UintEncoder::encode(msg).chain([blind]),
                self.1.iter().copied().chain([self.0]),
            )
            .map(|(x, g)| x * g),
        );
        PedersonCommitment {
            elem,
            _phantom_msg: PhantomData,
        }
    }

    pub fn commit<Msg, R>(
        &self,
        msg: &Msg,
        rng: &mut R,
    ) -> (PedersonCommitment<RistrettoPoint, Msg>, RistrettoScalar)
    where
        R: CryptoRngCore + ?Sized,
        Msg: Attributes<UintEncoder<RistrettoScalar>> + AttributeCount<N = N>,
    {
        let blind = RistrettoScalar::random(rng);
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
}

impl<N: ArrayLength> PedersonGenerators<RistrettoPoint, N> {
    pub fn compress(&self) -> PedersonGenerators<CompressedRistretto, N> {
        PedersonGenerators(
            self.0.compress(),
            self.1.iter().map(|g| g.compress()).collect(),
        )
    }
}

impl<N: ArrayLength> PedersonGenerators<CompressedRistretto, N> {
    pub fn decompress(&self) -> Option<PedersonGenerators<RistrettoPoint, N>> {
        Some(PedersonGenerators(
            self.0.decompress()?,
            self.1
                .iter()
                .map(|g| g.decompress())
                .collect::<Option<GenericArray<_, _>>>()?,
        ))
    }
}

impl<Msg> PedersonCommitment<RistrettoPoint, Msg>
where
    Msg: Attributes<UintEncoder<RistrettoScalar>>,
{
    pub fn commit_with_blind(msg: &Msg, blind: RistrettoScalar) -> Self {
        PedersonGenerators::attributes_default::<Msg>().commit_with_blind(msg, blind)
    }

    pub fn commit<R>(msg: &Msg, rng: &mut R) -> (Self, RistrettoScalar)
    where
        R: CryptoRngCore + ?Sized,
    {
        PedersonGenerators::attributes_default::<Msg>().commit(msg, rng)
    }

    pub fn open(&self, msg: &Msg, blind: RistrettoScalar) -> Result<(), PedersonError> {
        PedersonGenerators::attributes_default::<Msg>().open(self, msg, blind)
    }
}

impl<Msg> PedersonCommitment<RistrettoPoint, Msg> {
    pub fn compress(&self) -> PedersonCommitment<CompressedRistretto, Msg> {
        PedersonCommitment {
            elem: self.elem.compress(),
            _phantom_msg: PhantomData,
        }
    }
}

impl<Msg> PedersonCommitment<CompressedRistretto, Msg> {
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
    struct Example {
        a: u64,
        b: Scalar,
    }

    #[test]
    fn basic_success() {
        let example = Example {
            a: 42,
            b: Scalar::from(5u64),
        };
        let (commit, blind) = PedersonCommitment::<RistrettoPoint, Example>::commit(
            &example,
            &mut rand::thread_rng(),
        );
        commit.open(&example, blind).unwrap();
    }

    #[test]
    fn basic_fail() {
        let example = Example {
            a: 42,
            b: Scalar::from(5u64),
        };
        let (commit, blind) = PedersonCommitment::<RistrettoPoint, Example>::commit(
            &example,
            &mut rand::thread_rng(),
        );
        commit.open(&example, blind).unwrap();

        let mangled_example = Example {
            a: 42,
            b: Scalar::from(6u64),
        };
        let Err(PedersonError::VerificationError) = commit.open(&mangled_example, blind) else {
            panic!("open did not fail with verification error");
        };
    }
}
