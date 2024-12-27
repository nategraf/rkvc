use ff::Field;

// TODO: Combine these into one traits that returns (label, f) at each index?
pub trait AttributeLabels {
    fn at(&self, i: usize) -> Option<&'static str>;

    fn iter(&self) -> impl Iterator<Item = &'static str> {
        (0..).map_while(|i| self.at(i))
    }
}

pub trait AttributeElems<F: Field> {
    fn at(&self, i: usize) -> Option<F>;

    fn iter(&self) -> impl Iterator<Item = F> {
        (0..).map_while(|i| self.at(i)).fuse()
    }
}

pub trait Attributes<F: Field> {
    // TODO: Decide what to do here. The associated type for elems is currently removed because it
    // is intended to be implemented as a view over the attributes, but its unclear how best to
    // factor the lifetime parameters.
    type Labels: AttributeLabels;
    //type Elems: AttributeElems<F>;

    fn attribute_labels(&self) -> Self::Labels;
    fn attribute_elems(&self) -> impl AttributeElems<F>;
}

#[cfg(test)]
mod test {
    use curve25519_dalek::Scalar;

    use super::{AttributeElems, AttributeLabels, Attributes};

    struct Example {
        foo: u64,
        bar: u64,
    }

    struct ExampleLabels;

    impl AttributeLabels for ExampleLabels {
        fn at(&self, i: usize) -> Option<&'static str> {
            match i {
                0 => Some("foo"),
                1 => Some("bar"),
                _ => None,
            }
        }
    }

    struct ExampleElems<'a>(&'a Example);

    impl AttributeElems<Scalar> for ExampleElems<'_> {
        fn at(&self, i: usize) -> Option<Scalar> {
            match i {
                0 => Some(Scalar::from(self.0.foo)),
                1 => Some(Scalar::from(self.0.bar)),
                _ => None,
            }
        }
    }

    impl Attributes<Scalar> for Example {
        type Labels = ExampleLabels;

        fn attribute_labels(&self) -> Self::Labels {
            ExampleLabels
        }

        fn attribute_elems(&self) -> impl AttributeElems<Scalar> {
            ExampleElems(self)
        }
    }

    #[test]
    fn zip_example() {
        let example = Example { foo: 5, bar: 7 };
        for (label, x) in itertools::zip_eq(
            example.attribute_labels().iter(),
            example.attribute_elems().iter(),
        ) {
            println!("{label}: {x:?}");
        }
    }
}
