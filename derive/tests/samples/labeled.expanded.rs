use rkvc_derive::Attributes;
struct LabeledStruct {
    #[rkvc(label = "specified_label")]
    pub labeled: u64,
    pub default_label: u32,
}
trait LabeledStructIndex {
    type Value;
    ///Index into the container to access the element associated with [LabeledStruct::labeled]
    fn labeled(&self) -> &Self::Value;
    ///Index into the container to access the element associated with [LabeledStruct::default_label]
    fn default_label(&self) -> &Self::Value;
    ///Mutably index into the container to modify the element associated with [LabeledStruct::labeled]
    fn labeled_mut(&mut self) -> &mut Self::Value;
    ///Mutably index into the container to modify the element associated with [LabeledStruct::default_label]
    fn default_label_mut(&mut self) -> &mut Self::Value;
}
impl<T> LabeledStructIndex for rkvc::AttributeArray<T, LabeledStruct> {
    type Value = T;
    fn labeled(&self) -> &Self::Value {
        &self.0[0usize]
    }
    fn default_label(&self) -> &Self::Value {
        &self.0[1usize]
    }
    fn labeled_mut(&mut self) -> &mut Self::Value {
        &mut self.0[0usize]
    }
    fn default_label_mut(&mut self) -> &mut Self::Value {
        &mut self.0[1usize]
    }
}
impl rkvc::AttributeCount for LabeledStruct {
    type N = rkvc::attributes::typenum::U<2usize>;
}
impl rkvc::AttributeLabels for LabeledStruct {
    fn label_at(i: usize) -> Option<&'static str> {
        match i {
            0usize => Some("specified_label"),
            1usize => Some("LabeledStruct::default_label"),
            _ => None,
        }
    }
}
impl<E> rkvc::Attributes<E> for LabeledStruct
where
    E: rkvc::attributes::EncoderOutput,
    E: rkvc::attributes::Encoder<u32>,
    E: rkvc::attributes::Encoder<u64>,
{
    fn attribute_at(&self, i: usize, encoder: &mut E) -> Option<E::Output> {
        match i {
            0usize => Some(encoder.encode_value(self.labeled)),
            1usize => Some(encoder.encode_value(self.default_label)),
            _ => None,
        }
    }
    fn attribute_type_at(i: usize, encoder: &mut E) -> Option<E::TypeOutput> {
        match i {
            0usize => Some(<E as rkvc::attributes::Encoder<u64>>::encode_type(encoder)),
            1usize => Some(<E as rkvc::attributes::Encoder<u32>>::encode_type(encoder)),
            _ => None,
        }
    }
}
fn main() {}
