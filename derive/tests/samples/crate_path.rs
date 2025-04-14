use rkvc_derive::Attributes;

// Add the crate_path attribute to test that this is parsed. This test does not ensure it works as
// intended, because setting the crate_path to "rkvc" is the same as not setting it.
#[derive(Attributes)]
#[rkvc(crate_path = "rkvc")]
struct BasicStruct {
    a: u64,
}

fn main() {}
