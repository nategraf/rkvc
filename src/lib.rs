pub mod attributes;
pub mod pederson;

use rand_core::CryptoRng;

pub trait Commitment {
    type Attributes;
}

/// Message authentication code system.
pub trait Mac {
    /// Attributes type associated with this instantiation of the MAC system.
    type Attributes;
    /// TODO: Should this be bound to the MAC system, or can it be generic?
    type Commitment: Commitment<Attributes = Self::Attributes>;
    /// Key
    type Key;
    type PublicParameters;
    type Mac;
    type Error;

    fn generate_key(rng: &mut impl CryptoRng) -> Self::Key;

    fn public_paramters(key: &Self::Key) -> Self::PublicParameters;

    fn mac(key: &Self::Key, attr: &Self::Attributes) -> Self::Mac;

    fn blind_mac(key: &Self::Key, attr: &Self::Commitment) -> Self::Mac;

    fn verify(key: &Self::Key, mac: &Self::Mac) -> Result<(), Self::Error>;
}

/// A predicate, with respect to a Mac
/// TODO
pub trait Predicate {}

#[cfg(test)]
mod tests {}
