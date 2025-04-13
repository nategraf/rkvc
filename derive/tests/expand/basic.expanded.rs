use rkvc_derive::Attributes;
struct BasicStruct {
    value1: u64,
    value2: u32,
    value3: String,
}
impl rkvc::AttributeCount for BasicStruct {
    type N = rkvc::attributes::typenum::U<3usize>;
}
impl rkvc::AttributeLabels for BasicStruct {
    fn label_at(i: usize) -> Option<&'static str> {
        match i {
            0usize => Some("BasicStruct::value1"),
            1usize => Some("BasicStruct::value2"),
            2usize => Some("BasicStruct::value3"),
            _ => None,
        }
    }
}
impl<E> rkvc::Attributes<E> for BasicStruct
where
    E: rkvc::attributes::EncoderOutput,
    E: for<'a> rkvc::attributes::Encoder<&'a String>,
    E: rkvc::attributes::Encoder<u32>,
    E: rkvc::attributes::Encoder<u64>,
{
    fn attribute_at(&self, i: usize, encoder: &mut E) -> Option<E::Output> {
        match i {
            0usize => Some(encoder.encode_value(self.value1)),
            1usize => Some(encoder.encode_value(self.value2)),
            2usize => Some(encoder.encode_value(&self.value3)),
            _ => None,
        }
    }
    fn attribute_type_at(i: usize, encoder: &mut E) -> Option<E::TypeOutput> {
        match i {
            0usize => Some(<E as rkvc::attributes::Encoder<u64>>::encode_type(encoder)),
            1usize => Some(<E as rkvc::attributes::Encoder<u32>>::encode_type(encoder)),
            2usize => {
                Some(<E as rkvc::attributes::Encoder<&String>>::encode_type(encoder))
            }
            _ => None,
        }
    }
}
fn main() {}
