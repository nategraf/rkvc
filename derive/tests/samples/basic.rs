use rkvc_derive::Attributes;

#[derive(Attributes)]
struct BasicStruct {
    pub value1: u64,
    pub value2: u32,
    pub value3: String,
}

fn main() {}
