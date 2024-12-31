use core::{iter::Sum, marker::PhantomData};

use blake2::Blake2b512;

use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar as RistrettoScalar,
};
use group::Group;
use rand_core::CryptoRngCore;
use subtle::ConstantTimeEq;
use typenum::U64;

use crate::{
    attributes::{AttributeLabels, Attributes, UintEncoder},
    hash::FromHash,
};

#[derive(Clone, Debug)]
pub struct PedersonCommitment<G, Msg> {
    pub elem: G,
    _phantom_msg: PhantomData<Msg>,
}

#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum PedersonCommitmentError {
    #[error("verification failed")]
    VerificationError,
}

// TODO: Make a way to precalculate the generators, including compressed versions.
impl<G: Group + FromHash<OutputSize = U64>, Msg: AttributeLabels> PedersonCommitment<G, Msg> {
    pub fn blind_generator() -> G {
        // TODO: Make this configurable?
        G::hash_from_bytes::<Blake2b512>(b"PEDERSON_COMMIT_BLIND")
    }

    pub fn attribute_generators() -> impl Iterator<Item = G> {
        Msg::label_iter().map(|label| G::hash_from_bytes::<Blake2b512>(label.as_bytes()))
    }
}

impl<Msg> PedersonCommitment<RistrettoPoint, Msg>
where
    Msg: Attributes<UintEncoder<RistrettoScalar>>,
{
    pub fn commit_with_blind(msg: &Msg, blind: RistrettoScalar) -> Self {
        // NOTE: It would be more performant to use curve25519_dalek::MultiscalarMul here, but that
        // requires the iterators to have an exact size. Panics at runtime otherwise. This could be
        // addressed by improvements to attributes.
        let elem = RistrettoPoint::sum(
            itertools::zip_eq(
                UintEncoder::encode(msg).chain([blind]),
                Self::attribute_generators().chain([Self::blind_generator()]),
            )
            .map(|(x, g)| x * g),
        );
        Self {
            elem,
            _phantom_msg: PhantomData,
        }
    }

    pub fn commit<R>(msg: &Msg, rng: &mut R) -> (Self, RistrettoScalar)
    where
        R: CryptoRngCore + ?Sized,
    {
        let blind = RistrettoScalar::random(rng);
        (Self::commit_with_blind(msg, blind), blind)
    }

    pub fn open(&self, msg: &Msg, blind: RistrettoScalar) -> Result<(), PedersonCommitmentError> {
        let eq = self.elem.ct_eq(&Self::commit_with_blind(msg, blind).elem);
        match eq.into() {
            true => Ok(()),
            false => Err(PedersonCommitmentError::VerificationError),
        }
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

    use super::{PedersonCommitment, PedersonCommitmentError};

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
        let Err(PedersonCommitmentError::VerificationError) = commit.open(&mangled_example, blind)
        else {
            panic!("open did not fail with verification error");
        };
    }
}
