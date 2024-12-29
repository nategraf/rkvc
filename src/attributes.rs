use core::{borrow::BorrowMut, marker::PhantomData};

// TODO: Split into a Visitor and a VisitorMut trait? This might help resolve some of the
// awkwardness of e.g. the AttributeElems::elem_at method.
pub trait Visitor<T> {
    type Output;

    fn visit(&mut self, field: &T) -> Self::Output;
}

// TODO: Should this exist? It's essentially one simple codec, and it's useful if it has the right
// semantics for where it can be applied. It's unclear whether or not that is true.
pub struct Encoder<Output>(PhantomData<Output>);

impl<T> Default for Encoder<T> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<T: Into<Output> + Clone, Output> Visitor<T> for Encoder<Output> {
    type Output = Output;

    #[inline]
    fn visit(&mut self, field: &T) -> Self::Output {
        field.clone().into()
    }
}

impl<Output> Encoder<Output> {
    // TODO: Understand wtf use does here.
    pub fn encode<A>(attributes: &A) -> impl Iterator<Item = Output> + use<'_, A, Output>
    where
        A: AttributeElems<Self, Output>,
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

impl<T: Clone> Visitor<T> for Identity<T> {
    type Output = T;

    #[inline]
    fn visit(&mut self, field: &T) -> Self::Output {
        field.clone()
    }
}

impl<T> Identity<T> {
    // TODO: Understand wtf use does here.
    pub fn elem_iter<A>(attributes: &A) -> impl Iterator<Item = T> + use<'_, A, T>
    where
        A: AttributeElems<Self, T>,
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

pub trait AttributeElems<V, O>: Sized {
    fn elem_at(&self, i: usize, visitor: &mut V) -> Option<O>;

    fn elem_walk(&self, mut visitor: impl BorrowMut<V>) -> impl Iterator<Item = O> {
        (0..).map_while(move |i| self.elem_at(i, visitor.borrow_mut()))
    }
}

/// NOTE: This is a simple combination of AttributeLabels and AttributeElems. These are implemented
/// as seperate traits such that callsites such as Example::label_iter() is unambigous, and does
/// not require the <V, O> generics to be specified.
pub trait Attributes<V, O>: AttributeElems<V, O> + AttributeLabels {}

impl<T, V, O> Attributes<V, O> for T where T: AttributeElems<V, O> + AttributeLabels {}

#[cfg(test)]
mod test {
    use rkvc_derive::Attributes;

    use super::{AttributeLabels, Encoder};

    #[derive(Attributes)]
    struct Example {
        foo: u64,
        bar: u32,
    }

    #[test]
    fn zip_example() {
        let example = Example { foo: 5, bar: 7 };
        for (label, x) in itertools::zip_eq(Example::label_iter(), Encoder::<u64>::encode(&example))
        {
            println!("{label}: {x:?}");
        }
    }
}
