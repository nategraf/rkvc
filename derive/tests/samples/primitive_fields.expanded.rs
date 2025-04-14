use rkvc_derive::Attributes;
struct Primitives {
    a: u8,
    b: u16,
    c: u32,
    d: u64,
    e: u128,
    f: usize,
    g: i8,
    h: i16,
    i: i32,
    j: i64,
    k: i128,
    l: isize,
    m: bool,
    n: char,
}
trait PrimitivesIndex {
    type Value;
    ///Index into the container to access the element associated with [Primitives::a]
    fn a(&self) -> &Self::Value;
    ///Index into the container to access the element associated with [Primitives::b]
    fn b(&self) -> &Self::Value;
    ///Index into the container to access the element associated with [Primitives::c]
    fn c(&self) -> &Self::Value;
    ///Index into the container to access the element associated with [Primitives::d]
    fn d(&self) -> &Self::Value;
    ///Index into the container to access the element associated with [Primitives::e]
    fn e(&self) -> &Self::Value;
    ///Index into the container to access the element associated with [Primitives::f]
    fn f(&self) -> &Self::Value;
    ///Index into the container to access the element associated with [Primitives::g]
    fn g(&self) -> &Self::Value;
    ///Index into the container to access the element associated with [Primitives::h]
    fn h(&self) -> &Self::Value;
    ///Index into the container to access the element associated with [Primitives::i]
    fn i(&self) -> &Self::Value;
    ///Index into the container to access the element associated with [Primitives::j]
    fn j(&self) -> &Self::Value;
    ///Index into the container to access the element associated with [Primitives::k]
    fn k(&self) -> &Self::Value;
    ///Index into the container to access the element associated with [Primitives::l]
    fn l(&self) -> &Self::Value;
    ///Index into the container to access the element associated with [Primitives::m]
    fn m(&self) -> &Self::Value;
    ///Index into the container to access the element associated with [Primitives::n]
    fn n(&self) -> &Self::Value;
}
impl<T> PrimitivesIndex for rkvc::AttributeArray<T, Primitives> {
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
    fn e(&self) -> &Self::Value {
        &self.0[4usize]
    }
    fn f(&self) -> &Self::Value {
        &self.0[5usize]
    }
    fn g(&self) -> &Self::Value {
        &self.0[6usize]
    }
    fn h(&self) -> &Self::Value {
        &self.0[7usize]
    }
    fn i(&self) -> &Self::Value {
        &self.0[8usize]
    }
    fn j(&self) -> &Self::Value {
        &self.0[9usize]
    }
    fn k(&self) -> &Self::Value {
        &self.0[10usize]
    }
    fn l(&self) -> &Self::Value {
        &self.0[11usize]
    }
    fn m(&self) -> &Self::Value {
        &self.0[12usize]
    }
    fn n(&self) -> &Self::Value {
        &self.0[13usize]
    }
}
impl rkvc::AttributeCount for Primitives {
    type N = rkvc::attributes::typenum::U<14usize>;
}
impl rkvc::AttributeLabels for Primitives {
    fn label_at(i: usize) -> Option<&'static str> {
        match i {
            0usize => Some("Primitives::a"),
            1usize => Some("Primitives::b"),
            2usize => Some("Primitives::c"),
            3usize => Some("Primitives::d"),
            4usize => Some("Primitives::e"),
            5usize => Some("Primitives::f"),
            6usize => Some("Primitives::g"),
            7usize => Some("Primitives::h"),
            8usize => Some("Primitives::i"),
            9usize => Some("Primitives::j"),
            10usize => Some("Primitives::k"),
            11usize => Some("Primitives::l"),
            12usize => Some("Primitives::m"),
            13usize => Some("Primitives::n"),
            _ => None,
        }
    }
}
impl<E> rkvc::Attributes<E> for Primitives
where
    E: rkvc::attributes::EncoderOutput,
    E: rkvc::attributes::Encoder<bool>,
    E: rkvc::attributes::Encoder<char>,
    E: rkvc::attributes::Encoder<i128>,
    E: rkvc::attributes::Encoder<i16>,
    E: rkvc::attributes::Encoder<i32>,
    E: rkvc::attributes::Encoder<i64>,
    E: rkvc::attributes::Encoder<i8>,
    E: rkvc::attributes::Encoder<isize>,
    E: rkvc::attributes::Encoder<u128>,
    E: rkvc::attributes::Encoder<u16>,
    E: rkvc::attributes::Encoder<u32>,
    E: rkvc::attributes::Encoder<u64>,
    E: rkvc::attributes::Encoder<u8>,
    E: rkvc::attributes::Encoder<usize>,
{
    fn attribute_at(&self, i: usize, encoder: &mut E) -> Option<E::Output> {
        match i {
            0usize => Some(encoder.encode_value(self.a)),
            1usize => Some(encoder.encode_value(self.b)),
            2usize => Some(encoder.encode_value(self.c)),
            3usize => Some(encoder.encode_value(self.d)),
            4usize => Some(encoder.encode_value(self.e)),
            5usize => Some(encoder.encode_value(self.f)),
            6usize => Some(encoder.encode_value(self.g)),
            7usize => Some(encoder.encode_value(self.h)),
            8usize => Some(encoder.encode_value(self.i)),
            9usize => Some(encoder.encode_value(self.j)),
            10usize => Some(encoder.encode_value(self.k)),
            11usize => Some(encoder.encode_value(self.l)),
            12usize => Some(encoder.encode_value(self.m)),
            13usize => Some(encoder.encode_value(self.n)),
            _ => None,
        }
    }
    fn attribute_type_at(i: usize, encoder: &mut E) -> Option<E::TypeOutput> {
        match i {
            0usize => Some(<E as rkvc::attributes::Encoder<u8>>::encode_type(encoder)),
            1usize => Some(<E as rkvc::attributes::Encoder<u16>>::encode_type(encoder)),
            2usize => Some(<E as rkvc::attributes::Encoder<u32>>::encode_type(encoder)),
            3usize => Some(<E as rkvc::attributes::Encoder<u64>>::encode_type(encoder)),
            4usize => Some(<E as rkvc::attributes::Encoder<u128>>::encode_type(encoder)),
            5usize => Some(<E as rkvc::attributes::Encoder<usize>>::encode_type(encoder)),
            6usize => Some(<E as rkvc::attributes::Encoder<i8>>::encode_type(encoder)),
            7usize => Some(<E as rkvc::attributes::Encoder<i16>>::encode_type(encoder)),
            8usize => Some(<E as rkvc::attributes::Encoder<i32>>::encode_type(encoder)),
            9usize => Some(<E as rkvc::attributes::Encoder<i64>>::encode_type(encoder)),
            10usize => Some(<E as rkvc::attributes::Encoder<i128>>::encode_type(encoder)),
            11usize => {
                Some(<E as rkvc::attributes::Encoder<isize>>::encode_type(encoder))
            }
            12usize => Some(<E as rkvc::attributes::Encoder<bool>>::encode_type(encoder)),
            13usize => Some(<E as rkvc::attributes::Encoder<char>>::encode_type(encoder)),
            _ => None,
        }
    }
}
fn main() {}
