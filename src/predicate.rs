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

/// A group element part of a [Term], which can either be a constant in the relation (e.g. a
/// basepoint for a commitment) or a variable that is part of the instance definition (e.g. a
/// public key for a signature).
#[derive(Copy, Clone, Debug)]
enum GroupTerm {
    /// An instance variable, as an identifier and a constant scalar weight.
    Var(PointVar, Scalar),
    /// A constant point in the relation.
    Const(RistrettoPoint),
}

impl From<RistrettoPoint> for GroupTerm {
    fn from(value: RistrettoPoint) -> Self {
        Self::Const(value)
    }
}

impl From<PointVar> for GroupTerm {
    fn from(var: PointVar) -> Self {
        Self::Var(var, Scalar::ONE)
    }
}

#[derive(Copy, Clone, Debug)]
struct Term {
    /// A scalar in the linear combination that is part of the witness (i.e. it is secret to the
    /// prover). If `None`, this indicates that the term does not have an associated secret and
    /// this term only a public point.
    scalar: Option<ScalarVar>,
    /// The group element part of a term in a [LinearCombination].
    point: GroupTerm,
}

/// A linear combination of scalar variables (private the prover) and point variables (known to
/// both parties). If the scalar variable is `None`, it is equivalent to the known constant 1.
#[derive(Clone, Debug, Default)]
struct LinearCombination(Vec<Term>);

impl From<RistrettoPoint> for Term {
    fn from(value: RistrettoPoint) -> Self {
        Self {
            scalar: None,
            point: value.into(),
        }
    }
}

impl From<PointVar> for Term {
    fn from(var: PointVar) -> Self {
        Self {
            scalar: None,
            point: var.into(),
        }
    }
}

impl From<GroupTerm> for Term {
    fn from(value: GroupTerm) -> Self {
        Self {
            scalar: None,
            point: value,
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

    pub fn alloc_scalars(
        &mut self,
        count: usize,
    ) -> impl ExactSizeIterator<Item = ScalarVar> + use<'_> {
        (0..count).map(|_| self.alloc_scalar())
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

    pub fn prove(mut self, witness: &Witness) -> Result<(Instance, Proof), Error> {
        // TODO: Its possible that we could enforce this at compile-time instead.
        if witness.0.len() != self.scalar_count {
            return Err(Error::InvalidWitnessLength {
                expected: self.scalar_count,
                received: witness.0.len(),
            });
        }

        for constraint in self.constraints.iter() {
            // Split the constraints into those with assigned and unassigned points.
            let unassigned_points = constraint
                .0
                .iter()
                .filter(|term| !self.is_term_assigned(term))
                .map(|term| {
                    let Term {
                        scalar,
                        point: GroupTerm::Var(var, weight),
                    } = term
                    else {
                        panic!("invariant check failed: constant is not assigned")
                    };
                    // alloc_eq should only create terms with weight of one and no scalar var.
                    assert_eq!(
                        *weight,
                        Scalar::ONE,
                        "invariant check failed: non-unit weight"
                    );
                    assert!(
                        scalar.is_none(),
                        "invariant check failed: scalar var is not none"
                    );
                    var
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
                .filter(|term| self.is_term_assigned(term))
                .fold(RistrettoPoint::identity(), |value, term| {
                    value + self.eval_term(term, witness).unwrap()
                })
                .neg()
                .into();
        }

        let instance = self.into_instance().expect("all points should be assigned");
        let proof = instance.prove(witness)?;
        Ok((instance, proof))
    }

    fn is_term_assigned(&self, term: &Term) -> bool {
        match term.point {
            GroupTerm::Const(_) => true,
            GroupTerm::Var(var, _) => self.points[var.0].is_some(),
        }
    }

    fn eval_term(&self, term: &Term, witness: &Witness) -> Result<RistrettoPoint, Error> {
        let scalar = witness.scalar_val(term.scalar);
        Ok(match term.point {
            GroupTerm::Const(point) => point * scalar,
            GroupTerm::Var(var, weight) => {
                self.points[var.0].ok_or(Error::UnassignedPoint { index: var.0 })?
                    * (scalar * weight)
            }
        })
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
                    value + self.eval_term(term, witness)
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

    fn eval_term(&self, term: &Term, witness: &Witness) -> RistrettoPoint {
        let scalar = witness.scalar_val(term.scalar);
        match term.point {
            GroupTerm::Const(point) => point * scalar,
            GroupTerm::Var(var, weight) => self.points[var.0] * (scalar * weight),
        }
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

    use super::{Error, PointVar, Proof, Relation, ScalarVar, Witness};

    /// Example statement constraining two pairs of points to have the same discrete log.
    /// A = x * G && B = x * H
    struct DlEqRelation {
        rel: Relation,
        pub x: ScalarVar,
        pub a: PointVar,
        pub b: PointVar,
    }

    struct DlEqInstance {
        pub a: RistrettoPoint,
        pub b: RistrettoPoint,
    }

    impl DlEqRelation {
        pub fn new(g: RistrettoPoint, h: RistrettoPoint) -> Self {
            let mut rel = Relation::default();
            let x = rel.alloc_scalar();

            let a = rel.alloc_eq(x * g);
            let b = rel.alloc_eq(x * h);

            Self { rel, x, a, b }
        }

        pub fn prove(self, x: Scalar) -> Result<(DlEqInstance, Proof), Error> {
            let mut witness = Witness::default();
            witness.assign_scalar(self.x, x);

            let (instance, proof) = self.rel.prove(&witness)?;
            let a = instance.point_val(self.a);
            let b = instance.point_val(self.b);

            Ok((DlEqInstance { a, b }, proof))
        }

        pub fn verify(mut self, instance: &DlEqInstance, proof: &Proof) -> Result<(), Error> {
            self.rel.assign_point(self.a, instance.a);
            self.rel.assign_point(self.b, instance.b);
            self.rel.into_instance()?.verify(proof)
        }
    }

    #[test]
    fn example() {
        let g = RistrettoPoint::random(&mut rand::thread_rng());
        let h = RistrettoPoint::random(&mut rand::thread_rng());

        let (instance, proof) = {
            let relation = DlEqRelation::new(g, h);

            let x = Scalar::random(&mut rand::thread_rng());
            let (instance, proof) = relation.prove(x).unwrap();

            (instance, proof)
        };

        let relation = DlEqRelation::new(g, h);
        relation.verify(&instance, &proof).unwrap();

        // This is where the verifier might use (a, b) from the instance/message.
    }
}
