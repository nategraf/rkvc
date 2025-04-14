use rkvc_derive::Attributes;
use std::collections::HashMap;
struct CustomType {
    field: u32,
}
struct ComplexTypes {
    a: Vec<u32>,
    b: HashMap<String, u64>,
    c: Option<u32>,
    d: CustomType,
}
trait ComplexTypesIndex {
    type Value;
    ///Index into the container to access the element associated with [ComplexTypes::a]
    fn a(&self) -> &Self::Value;
    ///Index into the container to access the element associated with [ComplexTypes::b]
    fn b(&self) -> &Self::Value;
    ///Index into the container to access the element associated with [ComplexTypes::c]
    fn c(&self) -> &Self::Value;
    ///Index into the container to access the element associated with [ComplexTypes::d]
    fn d(&self) -> &Self::Value;
}
impl<T> ComplexTypesIndex for rkvc::AttributeArray<T, ComplexTypes> {
    type Value = T;
    fn a(&self) -> &Self::Value {
        &self.0[0usize]
    }
    fn b(&self) -> &Self::Value {
        &self.0[1usize]
    }
    fn c(&self) -> &Self::Value {
        &self.0[2usize]
    }
    fn d(&self) -> &Self::Value {
        &self.0[3usize]
    }
}
impl rkvc::AttributeCount for ComplexTypes {
    type N = rkvc::attributes::typenum::U<4usize>;
}
impl rkvc::AttributeLabels for ComplexTypes {
    fn label_at(i: usize) -> Option<&'static str> {
        match i {
            0usize => Some("ComplexTypes::a"),
            1usize => Some("ComplexTypes::b"),
            2usize => Some("ComplexTypes::c"),
            3usize => Some("ComplexTypes::d"),
            _ => None,
        }
    }
}
impl<E> rkvc::Attributes<E> for ComplexTypes
where
    E: rkvc::attributes::EncoderOutput,
    E: for<'a> rkvc::attributes::Encoder<&'a CustomType>,
    E: for<'a> rkvc::attributes::Encoder<&'a HashMap<String, u64>>,
    E: for<'a> rkvc::attributes::Encoder<&'a Option<u32>>,
    E: for<'a> rkvc::attributes::Encoder<&'a Vec<u32>>,
{
    fn attribute_at(&self, i: usize, encoder: &mut E) -> Option<E::Output> {
        match i {
            0usize => Some(encoder.encode_value(&self.a)),
            1usize => Some(encoder.encode_value(&self.b)),
            2usize => Some(encoder.encode_value(&self.c)),
            3usize => Some(encoder.encode_value(&self.d)),
            _ => None,
        }
    }
    fn attribute_type_at(i: usize, encoder: &mut E) -> Option<E::TypeOutput> {
        match i {
            0usize => {
                Some(<E as rkvc::attributes::Encoder<&Vec<u32>>>::encode_type(encoder))
            }
            1usize => {
                Some(
                    <E as rkvc::attributes::Encoder<
                        &HashMap<String, u64>,
                    >>::encode_type(encoder),
                )
            }
            2usize => {
                Some(
                    <E as rkvc::attributes::Encoder<&Option<u32>>>::encode_type(encoder),
                )
            }
            3usize => {
                Some(<E as rkvc::attributes::Encoder<&CustomType>>::encode_type(encoder))
            }
            _ => None,
        }
    }
}
fn main() {}
