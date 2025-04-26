use rkvc_derive::Attributes;

#[derive(Attributes)]
struct BasicStruct {
    pub pub_value: u64,
    pub(crate) pub_crate_value: u32,
    private_value: String,
}

fn main() {}
