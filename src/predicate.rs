// A predicate is a collection of linear combinations of g_0 = s_1 * g_1 + s_2 * g_2 + ...
// When building a predicate, the points are all available as are any public scalars.
// Private scalars make up the witness. The witness is not known when building the predicate, and
// is never known to the prover.
//
// OONI
//
// #[derive(Attributes, Clone, Debug)]
// struct OoniAttributes {
//     /// A secret key held by the client for the purpose of deriving context-specific pseudonyms.
//     /// This value is private during issuance, and used during presentation to derive pseudonyms.
//     #[rkvc(label = "OoniAttributes::pseudonym_key")]
//     pub pseudonym_key: Scalar,
//     /// An creation time for the credential. Public and chosen by the server during issuance, and
//     /// private thereafter. The client must prove during presentation that there credential is at
//     /// least a certain age.
//     pub created_at: u64,
//     /// A count of the number of measurements uploaded by this client. Intialized to zero during
//     /// issuance and incremented by one for each provided measurement.
//     pub measurement_count: u64,
//     /// A bit set to true if the client is a trusted party. Set by the server during presentation,
//     /// and can be optionally revealed to bypass other predicate checks if true.
//     pub is_trusted: bool,
// }
//
// Auth predicate (min_age: F, min_measurement_count: F, now: F, pseudonym_ctx: G, pseudonym: G)
//
// * Allocate A = AttributeArray<ScalarVar, OoniAttributes>
// * mac_presentation is valid over A.
// * A.measurement_count - min_measurement_count >= 0
// * A.created_at <= now - min_age
// * pseudonym == A.pseudonym_key * pseudonym_ctx

// In the prover,
// * the witness values are given during allocation of scalar vars.
// * points are computed in the course of the predicate and become part of the proof. A point is
//   allocated when it is contrained to be equal to a linear combinations of previously allocated
//   point and scalar variables. Any G that is used in a linear combination results in the allocation
//   of a point.
//
// In the verifier,
// * the witness values are not supplied, so the scalar vars are simply labels.
// * all point vars have values up-front rather than only at the end.

#![allow(dead_code)]
#![allow(unused_imports)]

use alloc::{borrow::Cow, vec, vec::Vec};
use core::{
    convert::Infallible,
    ops::{Add, Div, Mul, Neg, Sub},
};

use ff::Field;

// Alias type for a string that can either be static, or allocated at runtime and owned.
type Label = Cow<'static, str>;

use curve25519_dalek::{RistrettoPoint, Scalar};

// NOTE: A var can be created with one constraint system struct and then passed to another, which
// could have strange results. It may be possible to use the trick from GhostCell to bind a var to
// a particular constraint system.
// https://docs.rs/ghost-cell/latest/src/ghost_cell/ghost_cell.rs.html#533

#[derive(Copy, Clone, Debug, Hash)]
struct ScalarVar(usize);

#[derive(Copy, Clone, Debug, Hash)]
struct PointVar(usize, Scalar);

/// A linear combination of scalar variables (private the prover) and point variables (known to
/// both parties). If the scalar variable is `None`, it is equivalent to the known constant 1.
struct LinearCombination(Vec<(Option<ScalarVar>, PointVar)>);

impl From<PointVar> for LinearCombination {
    fn from(value: PointVar) -> Self {
        Self(vec![(None, value)])
    }
}

impl Add<LinearCombination> for LinearCombination {
    type Output = Self;

    fn add(mut self, mut rhs: LinearCombination) -> Self {
        self.0.append(&mut rhs.0);
        self
    }
}

impl Sub<LinearCombination> for LinearCombination {
    type Output = Self;

    fn sub(mut self, mut rhs: LinearCombination) -> Self {
        // Negate the coefficient for each of the point vars on the RHS.
        for (_, point_var) in rhs.0.iter_mut() {
            point_var.1 = -point_var.1;
        }
        self.0.append(&mut rhs.0);
        self
    }
}

impl Mul<Scalar> for LinearCombination {
    type Output = Self;

    fn mul(mut self, rhs: Scalar) -> Self {
        for (_, point_var) in self.0.iter_mut() {
            point_var.1 *= rhs;
        }
        self
    }
}

impl Mul<LinearCombination> for Scalar {
    type Output = LinearCombination;

    fn mul(self, mut rhs: LinearCombination) -> LinearCombination {
        for (_, point_var) in rhs.0.iter_mut() {
            point_var.1 *= self;
        }
        rhs
    }
}

impl Mul<ScalarVar> for PointVar {
    type Output = LinearCombination;

    fn mul(self, rhs: ScalarVar) -> LinearCombination {
        LinearCombination(vec![(Some(rhs), self)])
    }
}

impl Mul<PointVar> for ScalarVar {
    type Output = LinearCombination;

    fn mul(self, rhs: PointVar) -> LinearCombination {
        LinearCombination(vec![(Some(self), rhs)])
    }
}

#[derive(Default)]
struct Prover {
    scalars: Vec<Scalar>,
    /// A points may be `None` if it is an unknown to be resolved in the linear constraint system.
    points: Vec<Option<RistrettoPoint>>,
    constraints: Vec<LinearCombination>,
}

impl Prover {
    pub fn alloc_scalar(&mut self, witness: Scalar) -> ScalarVar {
        self.scalars.push(witness);
        ScalarVar(self.scalars.len() - 1)
    }

    pub fn alloc_point(&mut self, point: impl Into<Option<RistrettoPoint>>) -> PointVar {
        self.points.push(point.into());
        PointVar(self.points.len() - 1, Scalar::ONE)
    }

    fn scalars_val(&self, var: impl Into<Option<ScalarVar>>) -> Scalar {
        var.into().map_or(Scalar::ONE, |var| self.scalars[var.0])
    }

    /// Assign a point that is unassigned, but determined by a linear combination.
    // TODO: This is a pretty clunky way to address this.
    fn assign_constrained_point(
        &mut self,
        linear_combination: &LinearCombination,
    ) -> Result<(), &'static str> {
        let unassigned = linear_combination
            .0
            .iter()
            .filter(|(_, point_var)| self.points[point_var.0].is_none())
            .collect::<Vec<_>>();

        if unassigned.is_empty() {
            return Ok(());
        }
        if unassigned.len() > 1 {
            return Err("too many unassigned points");
        }
        let (scalar_var, unassigned_point_var) = unassigned[0];

        // Calculate the linear combination of the assigned points.
        let point: RistrettoPoint = linear_combination
            .0
            .iter()
            .filter_map(|(scalar_var, point_var)| {
                self.points[point_var.0].map(|p| (scalar_var, point_var.1, p))
            })
            .map(|(scalar_var, point_multiplier, point_val)| {
                self.scalars_val(*scalar_var) * point_multiplier * point_val
            })
            .sum();

        // FIXME: Invert here is dangerous / potentiall incorrect without zero check.
        self.points[unassigned_point_var.0] =
            Some(point * (self.scalars_val(*scalar_var) * unassigned_point_var.1).invert());

        Ok(())
    }

    fn prove(mut self) -> Result<(), &'static str> {
        // TODO: At least sort from least to most unassigned.
        for linear_combination in core::mem::take(&mut self.constraints).iter() {
            self.assign_constrained_point(linear_combination)?;
        }
        Ok(())
    }
}

#[derive(Default)]
struct Verifier {
    scalars_count: usize,
    points: Vec<RistrettoPoint>,
    constraints: Vec<LinearCombination>,
}

impl Verifier {
    fn alloc_scalar(&mut self) -> ScalarVar {
        self.scalars_count += 1;
        ScalarVar(self.scalars_count - 1)
    }

    fn alloc_point(&mut self, point: RistrettoPoint) -> PointVar {
        self.points.push(point);
        PointVar(self.points.len() - 1, Scalar::ONE)
    }

    fn verify(self, proof: ()) -> Result<(), Infallible> {
        let () = proof;
        Ok(())
    }
}

trait ConstraintSystem {
    fn constrain_zero(&mut self, linear_combination: LinearCombination);

    fn constrain_eq(
        &mut self,
        lhs: impl Into<LinearCombination>,
        rhs: impl Into<LinearCombination>,
    ) {
        self.constrain_zero(lhs.into() - rhs.into());
    }
}

impl ConstraintSystem for Prover {
    fn constrain_zero(&mut self, linear_combination: LinearCombination) {
        self.constraints.push(linear_combination);
    }
}

impl ConstraintSystem for Verifier {
    fn constrain_zero(&mut self, linear_combination: LinearCombination) {
        self.constraints.push(linear_combination);
    }
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::{RistrettoPoint, Scalar};

    use super::{ConstraintSystem, PointVar, Prover, ScalarVar, Verifier};

    /// Example statement constraining two pairs of points to have the same discrete log.
    fn example_statement(
        cs: &mut impl ConstraintSystem,
        x: ScalarVar,
        dl_pairs: [(PointVar, PointVar); 2],
    ) {
        for (a, b) in dl_pairs {
            cs.constrain_eq(a, x * b);
        }
    }

    fn example() {
        let g = RistrettoPoint::random(&mut rand::thread_rng());
        let h = RistrettoPoint::random(&mut rand::thread_rng());

        let proof = {
            let scalar = Scalar::random(&mut rand::thread_rng());

            let mut prover = Prover::default();
            let scalar_var = prover.alloc_scalar(scalar);
            let dl_pair_vars = [
                (prover.alloc_point(None), prover.alloc_point(g)),
                (prover.alloc_point(None), prover.alloc_point(g)),
            ];
            example_statement(&mut prover, scalar_var, dl_pair_vars);
            prover.prove().unwrap()
        };

        let mut verifier = Verifier::default();
        let scalar_var = verifier.alloc_scalar();
        let dl_pair_vars = [
            (verifier.alloc_point(a), verifier.alloc_point(g)),
            (verifier.alloc_point(b), verifier.alloc_point(g)),
        ];
        example_statement(&mut verifier, scalar_var, dl_pair_vars);
        verifier.verify(proof).unwrap();
    }
}
