use rkvc_derive::Attributes;

#[derive(Attributes)]
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

fn main() {}
