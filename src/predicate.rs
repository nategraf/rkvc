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

/// Implementations of core ops for the predicate types.
mod ops;

// NOTE: A var can be created with one constraint system struct and then passed to another, which
// could have strange results. It may be possible to use the trick from GhostCell to bind a var to
// a particular constraint system.
// https://docs.rs/ghost-cell/latest/src/ghost_cell/ghost_cell.rs.html#533

#[derive(Copy, Clone, Debug)]
struct ScalarVar(usize);

#[derive(Copy, Clone, Debug)]
struct PointVar(usize);

#[derive(Copy, Clone, Debug)]
struct Term {
    /// A scalar in the linear combination that is part of the witness (i.e. it is secret to the
    /// prover). If `None`, this indicates that the term does not have an associated secret and
    /// this term only a public point.
    scalar: Option<ScalarVar>,
    /// A point in the linear combination that is part of the instance.
    point: PointVar,
    /// A constant multiplicative factor applied to the term.
    ///
    /// In a relation, this is a public constant that is part of the relation's definition. When
    /// constructing a witness of the relation, it is folded into the point value which is known at
    /// that time.
    weight: Scalar,
}

/// A linear combination of scalar variables (private the prover) and point variables (known to
/// both parties). If the scalar variable is `None`, it is equivalent to the known constant 1.
#[derive(Clone, Debug, Default)]
struct LinearCombination(Vec<Term>);

impl From<PointVar> for Term {
    fn from(var: PointVar) -> Self {
        Self {
            scalar: None,
            point: var,
            weight: Scalar::ONE,
        }
    }
}

impl From<Term> for LinearCombination {
    fn from(term: Term) -> Self {
        Self(vec![term])
    }
}

impl From<PointVar> for LinearCombination {
    fn from(var: PointVar) -> Self {
        Self(vec![var.into()])
    }
}

#[derive(Clone, Debug, Default)]
struct Relation {
    scalar_count: usize,
    points: Vec<Option<RistrettoPoint>>,
    constraints: Vec<LinearCombination>,
}

// NOTE: By providing two methods for allocating a point variable, one which must be assigned, and
// the other than must be equal to a linear combination of point variables, we can ensure by
// construction that all unassigned point variables can be computed given the witness.
impl Relation {
    pub fn alloc_scalar(&mut self) -> ScalarVar {
        self.scalar_count += 1;
        ScalarVar(self.scalar_count - 1)
    }

    pub fn alloc_point(&mut self, point: RistrettoPoint) -> PointVar {
        self.points.push(Some(point));
        PointVar(self.points.len() - 1)
    }

    pub fn constrain_zero(&mut self, linear_combination: impl Into<LinearCombination>) {
        // NOTE: It would be possible here for the caller to pass a linear_combination that has no
        // scalar variables, and is known to be non-zero. It might be good to panic if that
        // happens.
        self.constraints.push(linear_combination.into());
    }

    pub fn constrain_eq(
        &mut self,
        lhs: impl Into<LinearCombination>,
        rhs: impl Into<LinearCombination>,
    ) {
        self.constrain_zero(lhs.into() - rhs.into());
    }

    pub fn alloc_eq(&mut self, linear_combination: impl Into<LinearCombination>) -> PointVar {
        // Allocate an unassigned point
        // NOTE: It would be possible here for the caller to pass a linear_combination that has no
        // scalar vars and has all points assigned. In which case, we can simply assign this point.
        self.points.push(None);
        let point_var = PointVar(self.points.len() - 1);

        // Constraint the newly allocated point to be equal to the linear combination.
        self.constrain_eq(point_var, linear_combination);
        point_var
    }

    pub fn assign_point(&mut self, var: PointVar, value: RistrettoPoint) {
        match self.points[var.0] {
            Some(assignment) => {
                assert_eq!(
                    assignment, value,
                    "attempted to assign a point variable twice with distinct values"
                )
            }
            None => self.points[var.0] = Some(value),
        }
    }
}

struct Instance {
    scalar_count: usize,
    points: Vec<RistrettoPoint>,
    constraints: Vec<LinearCombination>,
}

struct Witness(Vec<Scalar>);

// Relation - contains public points and constants, along with variable points.
//  - Has functions to allocate scalars.
//  - Has functions to allocate points
//    - What is the point of allocating points? Because we need some way to bridge the gap that
//      verifiers must assign all points, and provers may assign only those that are not fully
//      determine by other points.
//  - Constant points are just provided as instance of G.
// Instance - A relation with all variable points resolved.
// Witness - Assignments to all scalar variables.

#[cfg(test)]
mod tests {
    /*
    use curve25519_dalek::{RistrettoPoint, Scalar};

    use super::{ConstraintSystem, PointVar, Prover, ScalarVar, Verifier};

    /// Example statement constraining two pairs of points to have the same discrete log.
    fn example_statement(
        cs: &mut impl ConstraintSystem,
        x: ScalarVar,
        dl_pairs: [(PointVar, PointVar); 2],
    ) {
        let [(a, g), (b, h)] = dl_pairs;
        cs.constrain_eq(a, x * g);
        cs.constrain_eq(b, x * h);
    }

    fn example() {
        let g = RistrettoPoint::random(&mut rand::thread_rng());
        let h = RistrettoPoint::random(&mut rand::thread_rng());

        let (proof, a, b) = {
            let scalar = Scalar::random(&mut rand::thread_rng());

            let mut prover = Prover::default();
            let scalar_var = prover.alloc_scalar(scalar);
            let dl_pair_vars = [
                (prover.alloc_point(None), prover.alloc_point(g)),
                (prover.alloc_point(None), prover.alloc_point(h)),
            ];

            example_statement(&mut prover, scalar_var, dl_pair_vars);

            let proof = prover.prove().unwrap();

            // Get the values assigned for a and b during proving.
            let a = prover.point_val(dl_pair_vars[0].0).unwrap();
            let b = prover.point_val(dl_pair_vars[1].0).unwrap();

            (proof, a, b)
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
    */
}
