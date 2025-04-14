use rkvc_derive::Attributes;
#[rkvc(crate_path = "rkvc")]
struct BasicStruct {
    a: u64,
}
impl rkvc::AttributeCount for BasicStruct {
    type N = rkvc::attributes::typenum::U<1usize>;
}
impl rkvc::AttributeLabels for BasicStruct {
    fn label_at(i: usize) -> Option<&'static str> {
        match i {
            0usize => Some("BasicStruct::a"),
            _ => None,
        }
    }
}
impl<E> rkvc::Attributes<E> for BasicStruct
where
    E: rkvc::attributes::EncoderOutput,
    E: rkvc::attributes::Encoder<u64>,
{
    fn attribute_at(&self, i: usize, encoder: &mut E) -> Option<E::Output> {
        match i {
            0usize => Some(encoder.encode_value(self.a)),
            _ => None,
        }
    }
    fn attribute_type_at(i: usize, encoder: &mut E) -> Option<E::TypeOutput> {
        match i {
            0usize => Some(<E as rkvc::attributes::Encoder<u64>>::encode_type(encoder)),
            _ => None,
        }
    }
}
fn main() {}
