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
use group::Group;

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

impl From<Vec<Term>> for LinearCombination {
    fn from(terms: Vec<Term>) -> Self {
        Self(terms)
    }
}

impl FromIterator<Term> for LinearCombination {
    fn from_iter<T: IntoIterator<Item = Term>>(iter: T) -> Self {
        Self(iter.into_iter().collect())
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

#[non_exhaustive]
#[derive(Clone, Debug)]
struct Proof {}

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

    // TODO: Does it make sense to have this here versus making this some kind of intermediate step
    // towards making an Instance? The idea with this function is that only the verifier would call
    // it, as the prover instead provides a Witness, and the unassigned points get calculated from
    // that.
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

    /// Convert the [Relation] into an [Instance], checking that all point variables are assigned.
    pub fn into_instance(self) -> Result<Instance, Error> {
        let points = self
            .points
            .into_iter()
            .enumerate()
            .map(|(index, point)| point.ok_or(Error::UnassignedPoint { index }))
            .collect::<Result<_, _>>()?;

        Ok(Instance {
            points,
            scalar_count: self.scalar_count,
            constraints: self.constraints,
        })
    }

    pub fn assign_witness(mut self, witness: &Witness) -> Result<Instance, Error> {
        // TODO: Its possible that we could enforce this at compile-time instead.
        if witness.0.len() != self.scalar_count {
            return Err(Error::InvalidWitnessLength {
                expected: self.scalar_count,
                received: witness.0.len(),
            });
        }

        // Solve for the unassigned point variables.
        // NOTE: In the current implementation, we make utilize an invariant created by the
        // construction of `alloc_point` and `alloc_eq`, such that all points are "determined".
        // *) Assigned points are determined. Any point that is constrained to be equal to a linear
        // combination of determined points is determined.
        // A) In a new relation, there are no point variables. As a result, all point variables are
        // trivially determined.
        // B) When calling `alloc_point`, the point is assigned and therefore determined. If all
        // points in the relation are determined before the call to `alloc_point`, all points
        // including the new point variable are determined after.
        // C) When calling `alloc_point`, a single new unassigned point is created. It is set equal
        // to a linear combination of previously created points in the relation. Therefore if all
        // points were determined before the call to `alloc_eq`, they will be after.
        //
        // Additionally, we are able to resolve the point variables by looping through the
        // constraints in the order that they are listed. Each constraint can introduce at most one
        // unassigned point variable, which must be determined by the previously allocated point
        // variables.
        for constraint in self.constraints.iter() {
            // Split the constraints into those with assigned and unassigned points.
            let unassigned_points = constraint
                .0
                .iter()
                .filter(|term| self.points[term.point.0].is_none())
                .map(|term| {
                    // alloc_eq should only create terms with weight of one and no scalar var.
                    assert_eq!(
                        term.weight,
                        Scalar::ONE,
                        "invariant check failed: non-unit weight"
                    );
                    assert!(
                        term.scalar.is_none(),
                        "invariant check failed: scalar var is not none"
                    );
                    term.point
                })
                .collect::<Vec<_>>();

            // Extract the one unassigned point from the vector.
            if unassigned_points.is_empty() {
                continue;
            }
            if unassigned_points.len() > 1 {
                unreachable!("oh no");
            }
            let unassigned_point = unassigned_points[0];

            // Evaluate the terms with assigned points to determine the unassigned point.
            // NOTE: Could be optimized by using a proper MSM.
            self.points[unassigned_point.0] = constraint
                .0
                .iter()
                .filter_map(|term| {
                    self.points[term.point.0].map(|point| (term.scalar, term.weight, point))
                })
                .fold(
                    RistrettoPoint::identity(),
                    |value, (scalar_var, weight, point)| {
                        value + (witness.scalar_val(scalar_var) * weight) * point
                    },
                )
                .neg()
                .into();
        }

        Ok(self.into_instance().expect("all points should be assigned"))
    }
}

struct Instance {
    scalar_count: usize,
    points: Vec<RistrettoPoint>,
    // NOTE: Instead of a LinearCombination, which allows for a weight to be applied to each term,
    // this could simply be Vec<Vec<(ScalarVar, G)>> which would allow dropping the points vec.
    constraints: Vec<LinearCombination>,
}

impl Instance {
    pub fn prove(&self, witness: &Witness) -> Result<Proof, Error> {
        // TODO: Its possible that we could enforce this at compile-time instead.
        if witness.0.len() != self.scalar_count {
            return Err(Error::InvalidWitnessLength {
                expected: self.scalar_count,
                received: witness.0.len(),
            });
        }

        // Check the constraints, to make sure everything actually works.
        for (index, constraint) in self.constraints.iter().enumerate() {
            // Evaluate the terms with assigned points to determine the unassigned point.
            // NOTE: When proving, this computation duplicates what is done to assign points variables.
            let eval = constraint
                .0
                .iter()
                .fold(RistrettoPoint::identity(), |value, term| {
                    value
                        + (witness.scalar_val(term.scalar) * term.weight)
                            * self.points[term.point.0]
                });

            if eval != RistrettoPoint::identity() {
                return Err(Error::ConstraintEvalNotZero { index });
            }
        }

        // Obviously not a real proof.
        Ok(Proof {})
    }

    pub fn verify(&self, proof: &Proof) -> Result<(), Error> {
        // LGTM 👌
        let Proof {} = proof;
        Ok(())
    }

    pub fn point_val(&self, var: PointVar) -> RistrettoPoint {
        self.points[var.0]
    }
}

#[derive(Default, Clone, Debug)]
struct Witness(Vec<Scalar>);

impl Witness {
    pub fn assign_scalar(&mut self, var: ScalarVar, scalar: impl Into<Scalar>) {
        if self.0.len() <= var.0 {
            self.0.resize(var.0 + 1, Scalar::ZERO);
        }
        self.0[var.0] = scalar.into();
    }

    fn scalar_val(&self, var: impl Into<Option<ScalarVar>>) -> Scalar {
        var.into().map(|var| self.0[var.0]).unwrap_or(Scalar::ONE)
    }
}

impl FromIterator<(ScalarVar, Scalar)> for Witness {
    fn from_iter<T: IntoIterator<Item = (ScalarVar, Scalar)>>(iter: T) -> Self {
        iter.into_iter()
            .fold(Witness::default(), |mut witness, (var, val)| {
                witness.assign_scalar(var, val);
                witness
            })
    }
}

#[derive(Clone, Debug, thiserror::Error)]
enum Error {
    #[error("point variable with index {index} is unassigned")]
    UnassignedPoint { index: usize },
    #[error("witness length of {received} does not match the expected length for the relation, {expected}")]
    InvalidWitnessLength { expected: usize, received: usize },
    #[error("constraint does not evaluates to non-zero value: {index}")]
    ConstraintEvalNotZero { index: usize },
}

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
    use curve25519_dalek::{RistrettoPoint, Scalar};

    use super::{PointVar, Relation, ScalarVar, Witness};

    /// Example statement constraining two pairs of points to have the same discrete log.
    /// A = x * G && B = x * H
    fn example_statement(
        g: RistrettoPoint,
        h: RistrettoPoint,
    ) -> (Relation, ScalarVar, (PointVar, PointVar)) {
        let mut rel = Relation::default();
        let x = rel.alloc_scalar();
        let (g_var, h_var) = (rel.alloc_point(g), rel.alloc_point(h));

        let a = rel.alloc_eq(x * g_var);
        let b = rel.alloc_eq(x * h_var);

        (rel, x, (a, b))
    }

    fn example() {
        let g = RistrettoPoint::random(&mut rand::thread_rng());
        let h = RistrettoPoint::random(&mut rand::thread_rng());

        let (proof, a, b) = {
            let (relation, x_var, (a_var, b_var)) = example_statement(g, h);

            let x = Scalar::random(&mut rand::thread_rng());
            let witness = Witness::from_iter([(x_var, x)]);

            let instance = relation.assign_witness(&witness).unwrap();
            let proof = instance.prove(&witness).unwrap();
            let a = instance.point_val(a_var);
            let b = instance.point_val(b_var);

            (proof, a, b)
        };

        let (mut relation, _, (a_var, b_var)) = example_statement(g, h);
        relation.assign_point(a_var, a);
        relation.assign_point(b_var, b);
        relation.into_instance().unwrap().verify(&proof).unwrap();
    }
}
