//! Experiment

#![allow(dead_code)]

use alloc::vec::Vec;
use core::{
    cell::{Cell, RefCell},
    ops::Neg,
};

use curve25519_dalek::{RistrettoPoint, Scalar};

#[derive(Clone, Debug, Default)]
struct Allocator {
    scalar_count: Cell<usize>,
    points: RefCell<Vec<Option<RistrettoPoint>>>,
}

#[derive(Clone, Copy, Debug)]
struct ScalarVar<'a> {
    alloc: &'a Allocator,
    index: usize,
}

#[derive(Clone, Copy, Debug)]
struct PointVar<'a> {
    alloc: &'a Allocator,
    index: usize,
    weight: Scalar,
}

impl Allocator {
    pub fn alloc_scalar(&self) -> ScalarVar {
        let index = {
            let scalar_count = self.scalar_count.get();
            self.scalar_count.set(scalar_count + 1);
            scalar_count
        };
        ScalarVar { alloc: self, index }
    }
}

impl Neg for PointVar<'_> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example() {
        let alloc = Allocator::default();
        let _var = alloc.alloc_scalar();
    }
}
