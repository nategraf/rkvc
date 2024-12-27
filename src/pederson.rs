use core::{iter::ExactSizeIterator, marker::PhantomData};

use blake2::Blake2b512;
use curve25519_dalek::{scalar::Scalar, RistrettoPoint};
use digest::Digest;
use group::Group;
use typenum::U64;

use crate::attributes::{AttributeLabels, Attributes};

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

impl<G: Group + FromHash<OutputSize = U64>, Msg: Attributes<Scalar>> PedersonCommitment<G, Msg> {
    pub fn generators() -> impl Iterator<Item = G> {
        Msg::attribute_labels()
            .into_iter()
            .map(|label| G::hash_from_bytes::<Blake2b512>(label.as_bytes()))
    }
}

impl<Msg: Attributes<Scalar>> PedersonCommitment<RistrettoPoint, Msg> {
    pub fn commit(msg: &Msg) -> Self {
        todo!()
    }
}
