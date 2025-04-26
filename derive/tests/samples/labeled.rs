use rkvc_derive::Attributes;

#[derive(Attributes)]
struct LabeledStruct {
    #[rkvc(label = "specified_label")]
    pub labeled: u64,
    pub default_label: u32,
}

fn main() {}
