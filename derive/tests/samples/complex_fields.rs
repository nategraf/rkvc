use rkvc_derive::Attributes;
use std::collections::HashMap;

struct CustomType {
    field: u32,
}

#[derive(Attributes)]
struct ComplexTypes {
    a: Vec<u32>,
    b: HashMap<String, u64>,
    c: Option<u32>,
    d: CustomType,
}

fn main() {}
