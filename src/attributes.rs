use core::{borrow::BorrowMut, convert::Infallible, marker::PhantomData};

use generic_array::ArrayLength;
use typenum::Unsigned;

// Re-export typenum so that the derive macro has a stable path to it.
pub use typenum;

pub trait VisitorOutput {
    type Output;

    type TypeOutput;
}

// TODO: Split into a Visitor and a VisitorMut trait? This might help resolve some of the
// awkwardness of e.g. the AttributeElems::attribute_at method.
// TODO: Rename this to Encoder and remove the &mut on self? Revisit this after implementing proof
// of knowledge with range tours.
pub trait Visitor<T>: VisitorOutput {
    fn visit(&mut self, value: T) -> Self::Output;

    // TODO: Find a better name for this after having some examples of using it.
    fn visit_static(&mut self) -> Self::TypeOutput {
        unimplemented!("visitor does not implement visit_static")
    }
}

pub struct UintEncoder<T>(PhantomData<T>);

impl<T> Default for UintEncoder<T> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<T> VisitorOutput for UintEncoder<T> {
    type Output = T;

    /// UintEncoder does not implement visit_static.
    type TypeOutput = Infallible;
}

macro_rules! impl_visitor_uint_encoder {
    ($($t:ty),*) => {
        $(
            impl<T> Visitor<$t> for UintEncoder<T>
            where
                $t: Into<T>,
            {
                #[inline]
                fn visit(&mut self, value: $t) -> Self::Output {
                    value.into()
                }
            }
        )*
    };
}

impl_visitor_uint_encoder!(u8, u16, u32, u64, u128);

impl<T: Clone> Visitor<&T> for UintEncoder<T> {
    fn visit(&mut self, value: &T) -> Self::Output {
        value.clone()
    }
}

pub struct Identity<T>(PhantomData<T>);

impl<T> Default for Identity<T> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<T> VisitorOutput for Identity<T> {
    type Output = T;

    /// UintEncoder does not implement visit_static.
    type TypeOutput = Infallible;
}

impl<T: Copy> Visitor<T> for Identity<T> {
    #[inline]
    fn visit(&mut self, value: T) -> Self::Output {
        value
    }
}

impl<T: Clone> Visitor<&T> for Identity<T> {
    #[inline]
    fn visit(&mut self, value: &T) -> Self::Output {
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

pub trait Attributes<V>: AttributeLabels
where
    V: VisitorOutput,
{
    fn attribute_at(&self, i: usize, visitor: &mut V) -> Option<V::Output>;

    fn attribute_walk(
        &self,
        mut visitor: impl BorrowMut<V>,
    ) -> impl ExactSizeIterator<Item = V::Output> {
        (0..Self::N::USIZE).map(move |i| self.attribute_at(i, visitor.borrow_mut()).unwrap())
    }

    fn attribute_type_at(i: usize, visitor: &mut V) -> Option<V::TypeOutput>;

    fn attribute_type_walk(
        mut visitor: impl BorrowMut<V>,
    ) -> impl ExactSizeIterator<Item = V::TypeOutput> {
        (0..Self::N::USIZE).map(move |i| Self::attribute_type_at(i, visitor.borrow_mut()).unwrap())
    }

    fn encode_attributes(&self) -> impl ExactSizeIterator<Item = V::Output>
    where
        V: Default,
    {
        self.attribute_walk(V::default())
    }

    fn encode_attributes_labeled(&self) -> impl ExactSizeIterator<Item = (&'static str, V::Output)>
    where
        V: Default,
    {
        itertools::zip_eq(Self::label_iter(), self.attribute_walk(V::default()))
    }

    fn encode_attribute_types() -> impl ExactSizeIterator<Item = V::TypeOutput>
    where
        V: Default,
    {
        Self::attribute_type_walk(V::default())
    }

    fn encode_attributes_types_labeled(
    ) -> impl ExactSizeIterator<Item = (&'static str, V::TypeOutput)>
    where
        V: Default,
    {
        itertools::zip_eq(Self::label_iter(), Self::attribute_type_walk(V::default()))
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
