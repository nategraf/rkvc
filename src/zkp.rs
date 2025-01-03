use alloc::vec::Vec;
use core::convert::Infallible;

use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    Scalar as RistrettoScalar,
};

// Re-export the core types for use in other modules.
pub use lox_zkp::{
    toolbox::{prover::Prover, verifier::Verifier, SchnorrCS},
    CompactProof, ProofError, Transcript,
};

pub trait AllocScalarVar<T>: SchnorrCS {
    type Error;

    fn alloc_scalar(&mut self, value: T) -> Result<Self::ScalarVar, Self::Error>;
}

impl AllocScalarVar<(&'static str, RistrettoScalar)> for Prover<'_> {
    type Error = Infallible;

    fn alloc_scalar(
        &mut self,
        value: (&'static str, RistrettoScalar),
    ) -> Result<Self::ScalarVar, Self::Error> {
        Ok(self.allocate_scalar(value.0.as_bytes(), value.1))
    }
}

impl AllocScalarVar<lox_zkp::toolbox::prover::ScalarVar> for Prover<'_> {
    type Error = Infallible;

    fn alloc_scalar(
        &mut self,
        value: lox_zkp::toolbox::prover::ScalarVar,
    ) -> Result<Self::ScalarVar, Self::Error> {
        Ok(value)
    }
}

impl AllocScalarVar<&'static str> for Verifier<'_> {
    type Error = lox_zkp::ProofError;

    fn alloc_scalar(&mut self, value: &'static str) -> Result<Self::ScalarVar, Self::Error> {
        Ok(self.allocate_scalar(value.as_bytes()))
    }
}

impl AllocScalarVar<lox_zkp::toolbox::verifier::ScalarVar> for Verifier<'_> {
    type Error = lox_zkp::ProofError;

    fn alloc_scalar(
        &mut self,
        value: lox_zkp::toolbox::verifier::ScalarVar,
    ) -> Result<Self::ScalarVar, Self::Error> {
        Ok(value)
    }
}

pub trait AllocPointVar<T>: SchnorrCS {
    type Error;

    fn alloc_point(&mut self, value: T) -> Result<Self::PointVar, Self::Error>;
}

impl AllocPointVar<(&'static str, RistrettoPoint)> for Prover<'_> {
    type Error = Infallible;

    fn alloc_point(
        &mut self,
        value: (&'static str, RistrettoPoint),
    ) -> Result<Self::PointVar, Self::Error> {
        Ok(self.allocate_point(value.0.as_bytes(), value.1).0)
    }
}

impl AllocPointVar<lox_zkp::toolbox::prover::PointVar> for Prover<'_> {
    type Error = Infallible;

    fn alloc_point(
        &mut self,
        value: lox_zkp::toolbox::prover::PointVar,
    ) -> Result<Self::PointVar, Self::Error> {
        Ok(value)
    }
}

impl AllocPointVar<(&'static str, RistrettoPoint)> for Verifier<'_> {
    type Error = lox_zkp::ProofError;

    fn alloc_point(
        &mut self,
        value: (&'static str, RistrettoPoint),
    ) -> Result<Self::PointVar, Self::Error> {
        self.allocate_point(value.0.as_bytes(), value.1.compress())
    }
}

impl AllocPointVar<(&'static str, CompressedRistretto)> for Verifier<'_> {
    type Error = lox_zkp::ProofError;

    fn alloc_point(
        &mut self,
        value: (&'static str, CompressedRistretto),
    ) -> Result<Self::PointVar, Self::Error> {
        self.allocate_point(value.0.as_bytes(), value.1)
    }
}

impl AllocPointVar<lox_zkp::toolbox::verifier::PointVar> for Verifier<'_> {
    type Error = lox_zkp::ProofError;

    fn alloc_point(
        &mut self,
        value: lox_zkp::toolbox::verifier::PointVar,
    ) -> Result<Self::PointVar, Self::Error> {
        Ok(value)
    }
}

pub struct Constraint<CS: SchnorrCS> {
    pub linear_combination: Vec<(CS::ScalarVar, CS::PointVar)>,
}

impl<CS: SchnorrCS> Constraint<CS> {
    pub fn new() -> Self {
        Self {
            linear_combination: Vec::new(),
        }
    }

    pub fn add<X, G, E>(&mut self, cs: &mut CS, x: X, g: G) -> Result<(), E>
    where
        CS: AllocScalarVar<X, Error = E> + AllocPointVar<G, Error = E>,
    {
        let x_var = cs.alloc_scalar(x)?;
        let g_var = cs.alloc_point(g)?;
        self.linear_combination.push((x_var, g_var));
        Ok(())
    }

    pub fn eq<G>(self, cs: &mut CS, g: G) -> Result<(), CS::Error>
    where
        CS: AllocPointVar<G>,
    {
        let g_var = cs.alloc_point(g)?;
        cs.constrain(g_var, self.linear_combination);
        Ok(())
    }
}
