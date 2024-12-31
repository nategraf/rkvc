use core::{borrow::BorrowMut, marker::PhantomData};

pub trait VisitorOutput {
    type Output;
}

// TODO: Split into a Visitor and a VisitorMut trait? This might help resolve some of the
// awkwardness of e.g. the AttributeElems::elem_at method.
// TODO: Rename this to Encoder and remove the &mut on self? Revisit this after implementing proof
// of knowledge with range tours.
pub trait Visitor<T>: VisitorOutput {
    fn visit(&mut self, value: &T) -> Self::Output;
}

pub struct UintEncoder<T>(PhantomData<T>);

impl<T> Default for UintEncoder<T> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<T> VisitorOutput for UintEncoder<T> {
    type Output = T;
}

/// Private marker trait used to reduce boiler-plate;
trait PrimitiveUint: Copy {}
impl PrimitiveUint for u8 {}
impl PrimitiveUint for u16 {}
impl PrimitiveUint for u32 {}
impl PrimitiveUint for u64 {}
impl PrimitiveUint for u128 {}

impl<Uint: PrimitiveUint + Into<T>, T> Visitor<Uint> for UintEncoder<T> {
    #[inline]
    fn visit(&mut self, value: &Uint) -> Self::Output {
        (*value).into()
    }
}

// NOTE: Implemented on the concrete type rather than over all T because T could include e.g. u64.
// With specialization, it would be possible achieve this. Attempted to use autoref specialization
// without success. See the article below for more information about autoref specialization.
// http://lukaskalbertodt.github.io/2019/12/05/generalized-autoref-based-specialization.html
//
// A concrete consiquence of this is that UintEncoder cannot work for field types that this crate
// does not explicitly add here. One solution to this would be provide a macro to quickly and
// easily implement a uint encoder for the provided (field) type. Unclear on the value of this.
impl Visitor<curve25519_dalek::Scalar> for UintEncoder<curve25519_dalek::Scalar> {
    fn visit(&mut self, value: &curve25519_dalek::Scalar) -> Self::Output {
        *value
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
}

impl<T: Clone> Visitor<T> for Identity<T> {
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
    use rkvc_derive::Attributes;

    use super::{AttributeLabels, UintEncoder};

    #[derive(Attributes)]
    struct Example {
        foo: u64,
        bar: u32,
    }

    #[test]
    fn zip_example() {
        let example = Example { foo: 5, bar: 7 };
        for (label, x) in
            itertools::zip_eq(Example::label_iter(), UintEncoder::<u64>::encode(&example))
        {
            println!("{label}: {x:?}");
        }
    }
}
