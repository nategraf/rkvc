#![cfg_attr(not(feature = "std"), no_std)]

// TODO: This is required because the zkp crate uses alloc::Vec in it's SchnorrCS contraints API.
// Otherwise, we avoid allocation and do so to ease integration with WASM targets.
extern crate alloc;

pub mod attributes;
pub use attributes::{AttributeLabels, Attributes, UintEncoder};

pub mod hash;
pub mod pederson;

// TODO: Remove these
pub mod pok;
pub mod range;

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
