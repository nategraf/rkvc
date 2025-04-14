use rkvc_derive::Attributes;

#[derive(Attributes)]
#[rkvc]
struct A {
    a: u64,
}

#[derive(Attributes)]
#[rkvc(foo = "bar")]
struct B {
    b: u64,
}

#[derive(Attributes)]
#[rkvc(crate_path = rkvc)]
struct C {
    c: u64,
}

fn main() {}
