use core::{iter::ExactSizeIterator, marker::PhantomData};

use blake2::Blake2b512;
use curve25519_dalek::{scalar::Scalar, RistrettoPoint};
use digest::Digest;
use group::Group;

use crate::attributes::Attributes;

#[derive(Clone, Debug)]
pub struct PedersonCommitment<G: Group, Msg> {
    elem: G,
    _phantom_msg: PhantomData<Msg>,
}

pub trait FromHash: Sized {
    type OutputSize;

    fn from_hash<D>(hash: D) -> Self
    where
        D: Digest<OutputSize = Self::OutputSize>;

    fn hash_from_bytes<D>(input: &[u8]) -> Self
    where
        D: Digest<OutputSize = Self::OutputSize> + Default,
    {
        let mut hash = D::default();
        hash.update(input);
        Self::from_hash(hash)
    }
}

impl<G: Group + FromHash, Msg: Attributes<Scalar>> PedersonCommitment<G, Msg> {
    pub fn generators() -> impl ExactSizeIterator<Item = G> {
        todo!();
        [].into_iter()
    }
}

impl<Msg: Attributes<Scalar>> PedersonCommitment<RistrettoPoint, Msg> {
    pub fn commit(msg: &Msg) -> Self {
        todo!()
    }
}
