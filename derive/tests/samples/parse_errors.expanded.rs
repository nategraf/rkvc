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
struct D {
    #[rkvc(foo = "bar")]
    d: u64,
}
struct E {
    #[rkvc]
    e: u64,
}
struct F {
    #[rkvc(label = foo)]
    f: u64,
}
fn main() {}
