use rkvc_derive::Attributes;

#[derive(Attributes)]
struct Primitives {
    pub a: u8,
    pub b: u16,
    pub c: u32,
    pub d: u64,
    pub e: u128,
    pub f: usize,
    pub g: i8,
    pub h: i16,
    pub i: i32,
    pub j: i64,
    pub k: i128,
    pub l: isize,
    pub m: bool,
    pub n: char,
}

fn main() {}
