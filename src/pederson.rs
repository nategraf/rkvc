use core::{iter::Sum, marker::PhantomData};

use blake2::Blake2b512;

use curve25519_dalek::{scalar::Scalar as RistrettoScalar, RistrettoPoint};
use digest::Digest;
use group::Group;
use rand_core::CryptoRngCore;
use subtle::ConstantTimeEq;
use typenum::U64;

use crate::attributes::{AttributeElems, AttributeLabels, Attributes};

#[derive(Clone, Debug)]
pub struct PedersonCommitment<G: Group, Msg> {
    elem: G,
    _phantom_msg: PhantomData<Msg>,
}

pub trait FromHash: Sized {
    type OutputSize;

    // NOTE: Default type bound on D is required only because its required on
    // RistrettoPoint::from_hash.
    fn from_hash<D>(hash: D) -> Self
    where
        D: Digest<OutputSize = Self::OutputSize> + Default;

    fn hash_from_bytes<D>(input: &[u8]) -> Self
    where
        D: Digest<OutputSize = Self::OutputSize> + Default,
    {
        let mut hash = D::default();
        hash.update(input);
        Self::from_hash(hash)
    }
}

impl FromHash for RistrettoPoint {
    type OutputSize = U64;

    fn from_hash<D>(hash: D) -> Self
    where
        D: Digest<OutputSize = Self::OutputSize> + Default,
    {
        Self::from_hash(hash)
    }
}

impl<G: Group + FromHash<OutputSize = U64>, Msg: Attributes<G::Scalar>> PedersonCommitment<G, Msg> {
    pub fn blind_generator() -> G {
        // TODO: Make this configurable?
        G::hash_from_bytes::<Blake2b512>(b"PEDERSON_COMMIT_BLIND")
    }

    pub fn attribute_generators() -> impl Iterator<Item = G> {
        Msg::attribute_labels()
            .into_iter()
            .map(|label| G::hash_from_bytes::<Blake2b512>(label.as_bytes()))
    }
}

#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum PedersonCommitmentError {
    #[error("verification failed")]
    VerificationError,
}

impl<Msg: Attributes<RistrettoScalar>> PedersonCommitment<RistrettoPoint, Msg> {
    pub fn commit_with_blind(msg: &Msg, blind: RistrettoScalar) -> Self {
        // NOTE: It would be more performant to use curve25519_dalek::MultiscalarMul here, but that
        // requires the iterators to have an exact size. Panics at runtime otherwise. This could be
        // addressed by improvements to attributes.
        let elem = RistrettoPoint::sum(
            itertools::zip_eq(
                msg.attribute_elems().into_iter().chain([blind]),
                Self::attribute_generators().chain([Self::blind_generator()]),
            )
            .map(|(x, g)| x * g),
        );
        Self {
            elem,
            _phantom_msg: PhantomData,
        }
    }

    pub fn commit<R>(rng: &mut R, msg: &Msg) -> (Self, RistrettoScalar)
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

#[cfg(test)]
mod test {
    use curve25519_dalek::{RistrettoPoint, Scalar};
    use rkvc_derive::Attributes;

    use super::{PedersonCommitment, PedersonCommitmentError};

    #[derive(Attributes)]
    #[rkvc(field = curve25519_dalek::Scalar)]
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
            &mut rand::thread_rng(),
            &example,
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
            &mut rand::thread_rng(),
            &example,
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
