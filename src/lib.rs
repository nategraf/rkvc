#![cfg_attr(not(feature = "std"), no_std)]

// TODO: Add proptests throughout for better coverage.
// TODO: Pepper in Debug, Clone, (De)Serialize, Eq, etc derives as appropriate.

// TODO: We would like to avoid allocation, to ease integration with WASM targets.
extern crate alloc;

pub mod attributes;
pub use attributes::{AttributeCount, AttributeLabels, Attributes, UintEncoder};

#[cfg(feature = "derive")]
pub use rkvc_derive::Attributes;

pub mod cmz;
pub mod hash;
pub mod pederson;
pub mod range;
pub mod zkp;

/* TODO: None of these traits are used (yet)
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
*/
