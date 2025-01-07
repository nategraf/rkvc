use core::{borrow::BorrowMut, convert::Infallible, marker::PhantomData};

use generic_array::ArrayLength;
use typenum::Unsigned;

// Re-export typenum so that the derive macro has a stable path to it.
pub use typenum;

pub trait EncoderOutput {
    type Output;

    type TypeOutput;
}

// TODO: Split into a Encoder and a EncoderMut trait? This might help resolve some of the
// awkwardness of e.g. the AttributeElems::attribute_at method. So far no implementation uses the
// mutability, and this may be the better practice.
pub trait Encoder<T>: EncoderOutput {
    fn encode_value(&mut self, value: T) -> Self::Output;

    fn encode_type(&mut self) -> Self::TypeOutput {
        unimplemented!("encoder does not implement encode_type")
    }
}

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

impl<T: Clone> Encoder<&T> for UintEncoder<T> {
    fn encode_value(&mut self, value: &T) -> Self::Output {
        value.clone()
    }
}

pub struct Identity<T>(PhantomData<T>);

impl<T> Default for Identity<T> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<T> EncoderOutput for Identity<T> {
    type Output = T;

    /// UintEncoder does not implement encode_type.
    type TypeOutput = Infallible;
}

impl<T: Copy> Encoder<T> for Identity<T> {
    #[inline]
    fn encode_value(&mut self, value: T) -> Self::Output {
        value
    }
}

impl<T: Clone> Encoder<&T> for Identity<T> {
    #[inline]
    fn encode_value(&mut self, value: &T) -> Self::Output {
        value.clone()
    }
}

pub trait AttributeCount {
    type N: ArrayLength;
}

pub trait AttributeLabels: AttributeCount {
    fn label_at(i: usize) -> Option<&'static str>;

    fn label_iter() -> impl ExactSizeIterator<Item = &'static str> {
        (0..Self::N::USIZE).map(move |i| Self::label_at(i).unwrap())
    }
}

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

#[cfg(test)]
mod test {
    use curve25519_dalek::Scalar;
    use rkvc_derive::Attributes;

    use super::{AttributeLabels, Attributes, UintEncoder};

    #[derive(Attributes)]
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
        for (label, x) in itertools::zip_eq(
            Example::label_iter(),
            example.attribute_walk(UintEncoder::default()),
        ) {
            println!("{label}: {x:?}");
        }
    }
}
