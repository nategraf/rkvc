use core::{borrow::BorrowMut, convert::Infallible, marker::PhantomData};

pub trait VisitorOutput {
    type Output;

    type StaticOutput;
}

// TODO: Split into a Visitor and a VisitorMut trait? This might help resolve some of the
// awkwardness of e.g. the AttributeElems::elem_at method.
// TODO: Rename this to Encoder and remove the &mut on self? Revisit this after implementing proof
// of knowledge with range tours.
pub trait Visitor<T>: VisitorOutput {
    fn visit(&mut self, value: T) -> Self::Output;

    // TODO: Find a better name for this after having some examples of using it.
    fn visit_static(&mut self) -> Self::StaticOutput {
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
    type StaticOutput = Infallible;
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

impl<T> UintEncoder<T> {
    // TODO: Understand wtf use does here.
    pub fn encode<A>(attributes: &A) -> impl Iterator<Item = T> + use<'_, A, T>
    where
        A: Attributes<Self>,
    {
        attributes.elem_walk(Self::default())
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
    type StaticOutput = Infallible;
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

impl<T> Identity<T> {
    // TODO: Understand wtf use does here.
    pub fn elem_iter<A>(attributes: &A) -> impl Iterator<Item = T> + use<'_, A, T>
    where
        A: Attributes<Self>,
    {
        attributes.elem_walk(Self::default())
    }
}

// TODO: Combine these into one traits that returns (label, f) at each index?
pub trait AttributeLabels: Sized {
    fn label_at(i: usize) -> Option<&'static str>;

    fn label_iter() -> impl Iterator<Item = &'static str> {
        (0..).map_while(move |i| Self::label_at(i))
    }
}

pub trait Attributes<V>: AttributeLabels
where
    V: VisitorOutput,
{
    fn elem_at(&self, i: usize, visitor: &mut V) -> Option<V::Output>;

    fn elem_walk(&self, mut visitor: impl BorrowMut<V>) -> impl Iterator<Item = V::Output> {
        (0..).map_while(move |i| self.elem_at(i, visitor.borrow_mut()))
    }
}

#[cfg(test)]
mod test {
    use curve25519_dalek::Scalar;
    use rkvc_derive::Attributes;

    use super::{AttributeLabels, UintEncoder};

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
            UintEncoder::<Scalar>::encode(&example),
        ) {
            println!("{label}: {x:?}");
        }
    }
}
