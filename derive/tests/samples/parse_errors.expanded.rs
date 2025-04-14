use rkvc_derive::Attributes;
#[rkvc]
struct A {
    a: u64,
}
#[rkvc(foo = "bar")]
struct B {
    b: u64,
}
#[rkvc(crate_path = rkvc)]
struct C {
    c: u64,
}
fn main() {}
