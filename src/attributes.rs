//! Types for encoding structured messages for use in cryptographic protocols.
//!
//! This module contains the [Attributes] trait, and associated [Encoder] types. Implementing
//! [Attributes] on a `struct` allows it to be encoded for use as a message input for algebraic
//! MACs, commitments, range checks and other cryptographic procedures defined in this crate.
//!
//! When the `derive` feature is enabled,
//!
//! ```
//! use rkvc::{Attributes, UintEncoder, EncoderOutput};
//! use curve25519_dalek::Scalar;
//!
//! // You can override the crate path used in the derived impls with the rkvc attribute
//! #[derive(Attributes)]
//! # #[rkvc(crate_path = "rkvc")]
//! struct Example {
//!     a: u32,
//!     b: u64,
//!     c: Scalar,
//! }
//!
//! let example = Example {
//!     a: 10u32,
//!     b: 11u64,
//!     c: Scalar::from(12u32),
//! };
//!
//! let attributes: Vec<Scalar> = UintEncoder::encode_attributes(&example).collect();
//! assert_eq!(
//!     attributes,
//!     vec![Scalar::from(10u32), Scalar::from(11u64), Scalar::from(12u32)]
//! );
//! ```
use core::{
    borrow::BorrowMut,
    convert::Infallible,
    fmt::Debug,
    marker::PhantomData,
    ops::{Deref, DerefMut},
};

use curve25519_dalek::Scalar as RistrettoScalar;
use hybrid_array::{sizes::U1, Array, ArraySize};
use typenum::Unsigned;

#[cfg(feature = "derive")]
pub use rkvc_derive::Attributes;

// Re-export typenum so that the derive macro has a stable path to it.
pub use typenum;

/// Count of the fields in the implementing type's [Attributes] encoding.
pub trait AttributeCount {
    type N: ArraySize + Debug + Eq;
}

/// Implementation of [AttributeCount] directly for [RistrettoScalar].
// NOTE: This is not implemented for arbitrary Field types because a blanket implementation of a
// foreign trait can conflict with any implementations in downstream crates.
impl AttributeCount for RistrettoScalar {
    type N = U1;
}

/// Implementation of [AttributeLabels] directly for [RistrettoScalar].
// NOTE: This is not implemented for arbitrary Field types because a blanket implementation of a
// TODO: Consider whether it wise to give this common label to a value.
impl AttributeLabels for RistrettoScalar {
    fn label_at(i: usize) -> Option<&'static str> {
        // NOTE: Label is chosen to represent the "one-tuple" of an unknown message. If I end up
        // implementating Attributes over more tuples, they will have labels based on position.
        (i == 0).then_some("rkvc::attributes::_::0")
    }
}

/// Implementation of [Attributes] directly for [RistrettoScalar].
///
/// A [RistrettoScalar] is considered to be a single attribute with a common label.
impl<E> Attributes<E> for RistrettoScalar
where
    E: for<'a> Encoder<&'a Self>,
{
    fn attribute_at(&self, i: usize, encoder: &mut E) -> Option<<E as EncoderOutput>::Output> {
        (i == 0).then_some(encoder.encode_value(self))
    }

    fn attribute_type_at(i: usize, encoder: &mut E) -> Option<<E as EncoderOutput>::TypeOutput> {
        (i == 0).then_some(encoder.encode_type())
    }
}

/// Labels for each field in the implementing type's [Attributes] encoding.
///
/// Labels are used in cryptographic protocols as unique identifiers for the fields. As examples,
/// the [PedersonCommitment][crate::pederson::PedersonCommitment] implementation uses the labels as
/// hash-to-curve input to create commitment generators, and the [zkp][crate::zkp] module uses them
/// as domain separators in the Fiat-Shamir transcript.
pub trait AttributeLabels: AttributeCount {
    fn label_at(i: usize) -> Option<&'static str>;

    fn label_iter() -> impl ExactSizeIterator<Item = &'static str> {
        (0..Self::N::USIZE).map(move |i| Self::label_at(i).unwrap())
    }
}

/// Implementing [Attributes] on a `struct` allows it to be encoded for use as a message input for algebraic
/// MACs, commitments, range checks and other cryptographic procedures defined in this crate.
///
/// Note that the [Attributes] trait is generic with respect to `E`, which is an encoder. When used
/// in trait bounds (e.g. `Msg: Attributes<UintEncoder>`) this indicates that `Msg` can be any type
/// that is encodable by the [UintEncoder].
pub trait Attributes<E>: AttributeLabels
where
    E: EncoderOutput,
{
    fn attribute_at(&self, i: usize, encoder: &mut E) -> Option<E::Output>;

    fn attribute_walk(
        &self,
        mut encoder: impl BorrowMut<E>,
    ) -> impl ExactSizeIterator<Item = E::Output> {
        (0..Self::N::USIZE).map(move |i| self.attribute_at(i, encoder.borrow_mut()).unwrap())
    }

    fn attribute_type_at(i: usize, encoder: &mut E) -> Option<E::TypeOutput>;

    fn attribute_type_walk(
        mut encoder: impl BorrowMut<E>,
    ) -> impl ExactSizeIterator<Item = E::TypeOutput> {
        (0..Self::N::USIZE).map(move |i| Self::attribute_type_at(i, encoder.borrow_mut()).unwrap())
    }

    fn encode_attributes(&self) -> impl ExactSizeIterator<Item = E::Output>
    where
        E: Default,
    {
        self.attribute_walk(E::default())
    }

    fn encode_attributes_labeled(&self) -> impl ExactSizeIterator<Item = (&'static str, E::Output)>
    where
        E: Default,
    {
        itertools::zip_eq(Self::label_iter(), self.attribute_walk(E::default()))
    }

    fn encode_attribute_types() -> impl ExactSizeIterator<Item = E::TypeOutput>
    where
        E: Default,
    {
        Self::attribute_type_walk(E::default())
    }

    fn encode_attributes_types_labeled(
    ) -> impl ExactSizeIterator<Item = (&'static str, E::TypeOutput)>
    where
        E: Default,
    {
        itertools::zip_eq(Self::label_iter(), Self::attribute_type_walk(E::default()))
    }
}

/// Output of the [Encoder] when encoding a field's value, and when encoding metadata about a field
/// based on it's type (e.g. how many bits are in the value).
///
/// Note that a type implementing [Encoder] will provide one implementation per supported field
/// type, but will only implement [EncoderOutput] once, as all field values should be encoded to
/// the same output types.
pub trait EncoderOutput {
    type Output;

    // TODO: Split this off into an EncoderTypeOutput trait.
    type TypeOutput;

    /// Encode the attribute values of the given message using a [Default] instance of this type.
    fn encode_attributes<Msg>(msg: &Msg) -> impl ExactSizeIterator<Item = Self::Output>
    where
        Self: Default,
        Msg: Attributes<Self>,
    {
        msg.encode_attributes()
    }

    /// Encode the attribute types of the given message using a [Default] instance of this type.
    fn encode_attribute_types<Msg>() -> impl ExactSizeIterator<Item = Self::TypeOutput>
    where
        Self: Default,
        Msg: Attributes<Self>,
    {
        Msg::encode_attribute_types()
    }
}

// TODO: Split into a Encoder and a EncoderMut trait? This might help resolve some of the
// awkwardness of e.g. the AttributeElems::attribute_at method. So far no implementation uses the
// mutability, and this may be the better practice.
/// An [Encoder] defines a procedure for encoding fields of a message's [Attributes] for input in a
/// cryptographic operation. Each concrete encoder (e.g. [UintEncoder]) implement this trait
/// multiple times, with `T` for each supported field type (e.g. u64, &Scalar, bool).
pub trait Encoder<T>: EncoderOutput {
    fn encode_value(&mut self, value: T) -> Self::Output;

    fn encode_type(&mut self) -> Self::TypeOutput {
        unimplemented!("encoder does not implement encode_type")
    }
}

/// An [Encoder] that can can can accept any primitive unsigned integer and `T`, and outputs `T`. In
/// general, `T` will be a finite field. This encoder is injective into from the set of unsigned
/// integers to the chosen type `T`, so long as the implementation of [`Into<T>`] for each unsigned
/// integer is injective (generally this is the case).
pub struct UintEncoder<T>(PhantomData<T>);

impl<T> Default for UintEncoder<T> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<T> EncoderOutput for UintEncoder<T> {
    type Output = T;

    /// UintEncoder does not implement encode_static.
    type TypeOutput = Infallible;
}

macro_rules! impl_encoder_uint_encoder {
    ($($t:ty),*) => {
        $(
            impl<T> Encoder<$t> for UintEncoder<T>
            where
                $t: Into<T>,
            {
                #[inline]
                fn encode_value(&mut self, value: $t) -> Self::Output {
                    value.into()
                }
            }
        )*
    };
}

impl_encoder_uint_encoder!(u8, u16, u32, u64, u128);

impl<T> Encoder<bool> for UintEncoder<T>
where
    T: ff::Field,
{
    /// Encode true to 1 in the field, and false to 0.
    #[inline]
    fn encode_value(&mut self, value: bool) -> Self::Output {
        match value {
            true => T::ONE,
            false => T::ZERO,
        }
    }
}

impl<T: Clone> Encoder<&T> for UintEncoder<T> {
    fn encode_value(&mut self, value: &T) -> Self::Output {
        value.clone()
    }
}

/// A trivial encoder which can accept fields of type `T` and "encodes" them to type `T` trivially.
///
/// [IdentityEncoder] is bijective, and so is useful in context, such as a proof of knowledge,
/// where every encoding must have an unambiguous decoding to a valid message.
pub struct IdentityEncoder<T>(PhantomData<T>);

impl<T> Default for IdentityEncoder<T> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<T> EncoderOutput for IdentityEncoder<T> {
    type Output = T;

    /// UintEncoder does not implement encode_type.
    type TypeOutput = Infallible;
}

impl<T: Copy> Encoder<T> for IdentityEncoder<T> {
    #[inline]
    fn encode_value(&mut self, value: T) -> Self::Output {
        value
    }
}

impl<T: Clone> Encoder<&T> for IdentityEncoder<T> {
    #[inline]
    fn encode_value(&mut self, value: &T) -> Self::Output {
        value.clone()
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct AttributeArray<T, A: AttributeCount + ?Sized>(pub Array<T, A::N>);

impl<T, A: AttributeCount + ?Sized> Deref for AttributeArray<T, A> {
    type Target = Array<T, A::N>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T, A: AttributeCount + ?Sized> DerefMut for AttributeArray<T, A> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T, A: AttributeCount + ?Sized> FromIterator<T> for AttributeArray<T, A> {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        Self(iter.into_iter().collect())
    }
}

impl<T, A: AttributeCount + ?Sized> From<Array<T, A::N>> for AttributeArray<T, A> {
    fn from(value: Array<T, A::N>) -> Self {
        Self(value)
    }
}

impl<T, A: AttributeCount + ?Sized, const N: usize> From<[T; N]> for AttributeArray<T, A>
where
    A::N: ArraySize<ArrayType<T> = [T; N]>,
{
    fn from(value: [T; N]) -> Self {
        Self(value.into())
    }
}

#[cfg(test)]
mod test {
    use core::ops::Deref;
    use curve25519_dalek::Scalar;

    use super::{AttributeArray, AttributeLabels, Attributes, UintEncoder};

    #[derive(Debug, Attributes)]
    struct Example {
        foo: u64,
        bar: u32,
        baz: Scalar,
    }

    #[test]
    fn zip_example() {
        let example = Example {
            foo: 5,
            bar: 7,
            baz: Scalar::from(8u64),
        };
        let attrs: AttributeArray<(&str, Scalar), Example> = itertools::zip_eq(
            Example::label_iter(),
            example.attribute_walk(UintEncoder::default()),
        )
        .collect();

        assert_eq!(
            attrs.deref(),
            &[
                ("Example::foo", Scalar::from(5u32)),
                ("Example::bar", Scalar::from(7u32)),
                ("Example::baz", Scalar::from(8u32)),
            ]
        );
    }
}
