use ff::Field;

// TODO: Combine these into one traits that returns (label, f) at each index?
pub trait AttributeLabels: Sized {
    fn at(&self, i: usize) -> Option<&'static str>;

    fn into_iter(self) -> impl Iterator<Item = &'static str> {
        (0..).map_while(move |i| self.at(i))
    }
}

pub trait AttributeElems<F: Field>: Sized {
    fn at(&self, i: usize) -> Option<F>;

    fn into_iter(self) -> impl Iterator<Item = F> {
        (0..).map_while(move |i| self.at(i)).fuse()
    }
}

pub trait Attributes<F: Field> {
    // TODO: Decide what to do here. The associated type for elems is currently removed because it
    // is intended to be implemented as a view over the attributes, but its unclear how best to
    // factor the lifetime parameters.
    type Labels: AttributeLabels;
    //type Elems: AttributeElems<F>;

    fn attribute_labels() -> Self::Labels;
    fn attribute_elems(&self) -> impl AttributeElems<F>;
}

#[cfg(test)]
mod test {
    use rkvc_derive::Attributes;

    use super::{AttributeElems, AttributeLabels, Attributes};

    #[derive(Attributes)]
    #[rkvc(field = curve25519_dalek::Scalar)]
    struct Example {
        foo: u64,
        bar: u64,
    }

    #[test]
    fn zip_example() {
        let example = Example { foo: 5, bar: 7 };
        for (label, x) in itertools::zip_eq(
            Example::attribute_labels().into_iter(),
            example.attribute_elems().into_iter(),
        ) {
            println!("{label}: {x:?}");
        }
    }
}
