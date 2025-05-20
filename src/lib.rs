//! `rvkc` is a library for building anonymous credentials from algerbraic MACs, based on the
//! techniques described in [Revisiting Keyed-Verification Anonymous Credentials](https://eprint.iacr.org/2024/1552), and in prior works.

#![cfg_attr(not(feature = "std"), no_std)]

// TODO: Add proptests throughout for better coverage.
// TODO: Pepper in Debug, Clone, (De)Serialize, Eq, etc derives as appropriate.

// TODO: We would like to avoid allocation, to ease integration with WASM targets.
extern crate alloc;

pub mod attributes;
pub use attributes::{
    AttributeArray, AttributeCount, AttributeLabels, Attributes, Encoder, EncoderOutput,
    IdentityEncoder, UintEncoder,
};

pub mod cmz;
pub mod hash;
pub mod pedersen;
pub mod range;
pub mod zkp;

/// rand module used by this crate, provided to ease version mismatch issues.
pub use rand;

/* TODO: None of these traits are used (yet)
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
