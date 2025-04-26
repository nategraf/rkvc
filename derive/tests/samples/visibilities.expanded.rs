use rkvc_derive::Attributes;
struct BasicStruct {
    pub pub_value: u64,
    pub(crate) pub_crate_value: u32,
    private_value: String,
    pub pub_value2: u32,
}
trait BasicStructIndex {
    type Value;
    ///Index into the container to access the element associated with [BasicStruct::pub_value]
    fn pub_value(&self) -> &Self::Value;
    ///Index into the container to access the element associated with [BasicStruct::pub_value2]
    fn pub_value2(&self) -> &Self::Value;
    ///Mutably index into the container to modify the element associated with [BasicStruct::pub_value]
    fn pub_value_mut(&mut self) -> &mut Self::Value;
    ///Mutably index into the container to modify the element associated with [BasicStruct::pub_value2]
    fn pub_value2_mut(&mut self) -> &mut Self::Value;
}
impl<T> BasicStructIndex for rkvc::AttributeArray<T, BasicStruct> {
    type Value = T;
    fn pub_value(&self) -> &Self::Value {
        &self.0[0usize]
    }
    fn pub_value2(&self) -> &Self::Value {
        &self.0[3usize]
    }
    fn pub_value_mut(&mut self) -> &mut Self::Value {
        &mut self.0[0usize]
    }
    fn pub_value2_mut(&mut self) -> &mut Self::Value {
        &mut self.0[3usize]
    }
}
impl rkvc::AttributeCount for BasicStruct {
    type N = rkvc::attributes::typenum::U<4usize>;
}
impl rkvc::AttributeLabels for BasicStruct {
    fn label_at(i: usize) -> Option<&'static str> {
        match i {
            0usize => Some("BasicStruct::pub_value"),
            1usize => Some("BasicStruct::pub_crate_value"),
            2usize => Some("BasicStruct::private_value"),
            3usize => Some("BasicStruct::pub_value2"),
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
            0usize => Some(encoder.encode_value(self.pub_value)),
            1usize => Some(encoder.encode_value(self.pub_crate_value)),
            2usize => Some(encoder.encode_value(&self.private_value)),
            3usize => Some(encoder.encode_value(self.pub_value2)),
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
            3usize => Some(<E as rkvc::attributes::Encoder<u32>>::encode_type(encoder)),
            _ => None,
        }
    }
}
fn main() {}
