use rkvc_derive::Attributes;
use std::collections::HashMap;

struct CustomType {
    field: u32,
}

#[derive(Attributes)]
struct ComplexTypes {
    pub a: Vec<u32>,
    pub b: HashMap<String, u64>,
    pub c: Option<u32>,
    pub d: CustomType,
}

fn main() {}
