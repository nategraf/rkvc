//! Hash-to-curve traits used in this crate.

use curve25519_dalek::RistrettoPoint;
use digest::Digest;
use typenum::U64;

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
