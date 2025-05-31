#![allow(dead_code)]

use alloc::{borrow::Cow, vec, vec::Vec};
use core::ops::Neg;

use group::Group;

use crate::zkp::{
    AllocPointVar, CompactProof, ProofError, Prover, SchnorrCS, Transcript, Verifier,
};

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
pub struct ScalarVar(usize);

#[derive(Copy, Clone, Debug)]
pub struct PointVar(usize);

/// A group element part of a [Term], which can either be a constant in the relation (e.g. a
/// basepoint for a commitment) or a variable that is part of the instance definition (e.g. a
/// public key for a signature).
#[derive(Copy, Clone, Debug)]
pub enum PointTerm {
    /// An instance variable, as an identifier and a constant scalar weight.
    Var(PointVar, Scalar),
    /// A constant point in the relation.
    Const(RistrettoPoint),
}

impl From<RistrettoPoint> for PointTerm {
    fn from(value: RistrettoPoint) -> Self {
        Self::Const(value)
    }
}

impl From<PointVar> for PointTerm {
    fn from(var: PointVar) -> Self {
        Self::Var(var, Scalar::ONE)
    }
}

#[derive(Copy, Clone, Debug)]
pub struct Term {
    /// A scalar in the linear combination that is part of the witness (i.e. it is secret to the
    /// prover). If `None`, this indicates that the term does not have an associated secret and
    /// this term only a public point.
    scalar: Option<ScalarVar>,
    /// The group element part of a term in a [LinearCombination].
    point: PointTerm,
}

/// A linear combination of scalar variables (private the prover) and point variables (known to
/// both parties). If the scalar variable is `None`, it is equivalent to the known constant 1.
#[derive(Clone, Debug, Default)]
pub struct LinearCombination(Vec<Term>);

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

impl From<PointTerm> for Term {
    fn from(value: PointTerm) -> Self {
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
pub struct Relation {
    scalar_var_count: usize,
    point_var_count: usize,
    constraints: Vec<LinearCombination>,
}

// NOTE: By providing two methods for allocating a point variable, one which must be assigned, and
// the other than must be equal to a linear combination of point variables, we can ensure by
// construction that all unassigned point variables can be computed given the witness.
impl Relation {
    pub fn alloc_scalar(&mut self) -> ScalarVar {
        self.scalar_var_count += 1;
        ScalarVar(self.scalar_var_count - 1)
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

    // NOTE: Intentionally private for now.
    fn alloc_point(&mut self) -> PointVar {
        self.point_var_count += 1;
        PointVar(self.point_var_count - 1)
    }

    pub fn alloc_eq(&mut self, linear_combination: impl Into<LinearCombination>) -> PointVar {
        // Allocate an unassigned point
        // NOTE: It would be possible here for the caller to pass a linear_combination that has no
        // scalar vars and has all points assigned. In which case, we can simply assign this point.
        let point_var = self.alloc_point();

        // Constraint the newly allocated point to be equal to the linear combination.
        self.constrain_eq(point_var, linear_combination);
        point_var
    }

    pub fn alloc<S: Statement<SchnorrConstaintSystem> + ?Sized>(
        &mut self,
        statement: &S,
    ) -> S::Vars {
        statement.constrain(self)
    }

    pub fn compute_instance(&self, witness: &Witness) -> Result<Instance, Error> {
        // TODO: Its possible that we could enforce this at compile-time instead.
        if witness.0.len() != self.scalar_var_count {
            return Err(Error::InvalidWitnessLength {
                expected: self.scalar_var_count,
                received: witness.0.len(),
            });
        }

        let mut instance = Instance::default();
        for constraint in self.constraints.iter() {
            // Split the constraints into those with assigned and unassigned points.
            let unassigned_points = constraint
                .0
                .iter()
                .filter(|term| !self.is_term_assigned(&instance, term))
                .map(|term| {
                    let Term {
                        scalar,
                        point: PointTerm::Var(var, weight),
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
            instance.assign_point(
                *unassigned_point,
                constraint
                    .0
                    .iter()
                    .filter(|term| self.is_term_assigned(&instance, term))
                    .fold(RistrettoPoint::identity(), |value, term| {
                        value + instance.eval_term(term, witness)
                    })
                    .neg(),
            );
        }
        Ok(instance)
    }

    pub fn prove(&self, witness: &Witness) -> Result<(Instance, CompactProof), Error> {
        // TODO: Its possible that we could enforce this at compile-time instead.
        if witness.0.len() != self.scalar_var_count {
            return Err(Error::InvalidWitnessLength {
                expected: self.scalar_var_count,
                received: witness.0.len(),
            });
        }

        let instance = self.compute_instance(witness)?;

        // HACK: Translate the constraints into the zkp crate.
        let mut transcript = Transcript::new(b"rkvc::predicate::transcript");
        let mut prover = Prover::new(b"rkvc::predicate::constraints", &mut transcript);

        let zkp_scalar_vars = witness
            .0
            .iter()
            .map(|scalar| prover.allocate_scalar(b"", scalar.expect("unassigned scalar")))
            .collect::<Vec<_>>();
        for constraint in self.constraints.iter() {
            let mut rhs = Vec::<(
                <Prover as SchnorrCS>::ScalarVar,
                <Prover as SchnorrCS>::PointVar,
            )>::new();
            let mut lhs = RistrettoPoint::identity();
            for term in constraint.0.iter() {
                let point = match term.point {
                    PointTerm::Var(var, weight) => instance.point_val(var) * weight,
                    PointTerm::Const(point) => point,
                };
                match term.scalar {
                    Some(scalar_var) => {
                        let zkp_point_var = prover.alloc_point(("", point)).unwrap();
                        rhs.push((zkp_scalar_vars[scalar_var.0], zkp_point_var));
                    }
                    None => lhs -= point,
                }
            }

            let zkp_lhs_point_var = prover.alloc_point(("lhs", lhs)).unwrap();
            prover.constrain(zkp_lhs_point_var, rhs);
        }

        Ok((instance, prover.prove_compact()))
    }

    pub fn verify(&self, instance: &Instance, proof: &CompactProof) -> Result<(), Error> {
        // HACK: Translate the constraints into the zkp crate.
        let mut transcript = Transcript::new(b"rkvc::predicate::transcript");
        let mut verifier = Verifier::new(b"rkvc::predicate::constraints", &mut transcript);

        let zkp_scalar_vars = (0..self.scalar_var_count)
            .map(|_| verifier.allocate_scalar(b""))
            .collect::<Vec<_>>();
        for constraint in self.constraints.iter() {
            let mut rhs = Vec::<(
                <Verifier as SchnorrCS>::ScalarVar,
                <Verifier as SchnorrCS>::PointVar,
            )>::new();
            let mut lhs = RistrettoPoint::identity();
            for term in constraint.0.iter() {
                let point = match term.point {
                    PointTerm::Var(var, weight) => instance.point_val(var) * weight,
                    PointTerm::Const(point) => point,
                };
                match term.scalar {
                    Some(scalar_var) => {
                        let zkp_point_var = verifier.alloc_point(("", point)).unwrap();
                        rhs.push((zkp_scalar_vars[scalar_var.0], zkp_point_var));
                    }
                    None => lhs -= point,
                }
            }

            let zkp_lhs_point_var = verifier.alloc_point(("lhs", lhs)).unwrap();
            verifier.constrain(zkp_lhs_point_var, rhs);
        }
        verifier.verify_compact(proof).map_err(Error::Verification)
    }

    fn is_term_assigned(&self, instance: &Instance, term: &Term) -> bool {
        match term.point {
            PointTerm::Const(_) => true,
            PointTerm::Var(var, _) => instance.0[var.0].is_some(),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Instance(Vec<Option<RistrettoPoint>>);

impl Instance {
    pub fn assign<S: Statement<SchnorrConstaintSystem> + ?Sized>(
        &mut self,
        vars: &S::Vars,
        inst: &S::Instance,
    ) {
        S::assign_instance(self, vars, inst)
    }

    pub fn assign_point(&mut self, var: PointVar, point: RistrettoPoint) {
        if self.0.len() <= var.0 {
            self.0.resize(var.0 + 1, None);
        } else if let Some(assignment) = self.0[var.0] {
            assert_eq!(assignment, point, "conflicting assignments for var {var:?}")
        }
        self.0[var.0] = Some(point);
    }

    pub fn assign_points(
        &mut self,
        assignments: impl IntoIterator<Item = (PointVar, RistrettoPoint)>,
    ) {
        for (var, value) in assignments.into_iter() {
            self.assign_point(var, value);
        }
    }

    pub fn point_val(&self, var: PointVar) -> RistrettoPoint {
        self.0[var.0].unwrap_or_else(|| panic!("unassigned point var {var:?}"))
    }

    pub fn point_vals<I: IntoIterator<Item = PointVar>>(
        &self,
        vars: I,
    ) -> impl Iterator<Item = RistrettoPoint> + use<'_, I> {
        vars.into_iter().map(|var| self.point_val(var))
    }

    pub fn extract<S: Statement<SchnorrConstaintSystem> + ?Sized>(
        &self,
        vars: &S::Vars,
    ) -> Result<S::Instance, Error> {
        S::extract_instance(vars, self)
    }

    fn eval_term(&self, term: &Term, witness: &Witness) -> RistrettoPoint {
        let scalar = witness.scalar_val(term.scalar);
        match term.point {
            PointTerm::Const(point) => point * scalar,
            PointTerm::Var(var, weight) => self.point_val(var) * (scalar * weight),
        }
    }

    // NOTE: Not implemented as `IntoIterator` for now because doing so requires explicitly
    // defining an iterator type, See https://github.com/rust-lang/rust/issues/63063
    fn into_iter(self) -> impl Iterator<Item = (PointVar, RistrettoPoint)> {
        self.0
            .into_iter()
            .enumerate()
            .filter_map(|(i, x)| x.map(|x| (PointVar(i), x)))
    }
}

pub trait ConstraintSystem {
    type Relation;
    type Instance;
    type Witness;
    type Proof;
    type Error;
}

pub struct SchnorrConstaintSystem;

impl ConstraintSystem for SchnorrConstaintSystem {
    type Relation = Relation;
    type Instance = Instance;
    type Witness = Witness;
    type Proof = CompactProof;
    type Error = Error;
}

pub trait Statement<CS: ConstraintSystem> {
    type Vars;
    type Instance;
    type Witness;

    fn constrain(&self, cs: &mut CS::Relation) -> Self::Vars;

    fn assign_witness(cs: &mut CS::Witness, vars: &Self::Vars, witness: &Self::Witness);

    fn assign_instance(
        cs_instance: &mut CS::Instance,
        vars: &Self::Vars,
        instance: &Self::Instance,
    );

    fn extract_instance(
        vars: &Self::Vars,
        instance: &CS::Instance,
    ) -> Result<Self::Instance, CS::Error>;
}

pub trait Prove: Statement<SchnorrConstaintSystem> {
    fn prove(&self, witness: &Self::Witness) -> Result<(Self::Instance, CompactProof), Error> {
        let mut relation = Relation::default();
        let vars = relation.alloc(self);

        let mut relation_witness = Witness::default();
        // TODO: Figure out how to enable type inference here.
        relation_witness.assign::<Self>(&vars, witness);

        let (relation_instance, proof) = relation.prove(&relation_witness)?;

        let instance = relation_instance.extract::<Self>(&vars)?;
        Ok((instance, proof))
    }
}

pub trait Verify: Statement<SchnorrConstaintSystem> {
    fn verify(&self, instance: &Self::Instance, proof: &CompactProof) -> Result<(), Error> {
        let mut relation = Relation::default();
        let vars = relation.alloc(self);

        let mut relation_instance = Instance::default();
        // TODO: Figure out how to enable type inference here.
        relation_instance.assign::<Self>(&vars, instance);
        relation.verify(&relation_instance, proof)
    }
}

#[derive(Default, Clone, Debug)]
pub struct Witness(Vec<Option<Scalar>>);

impl Witness {
    pub fn assign<S: Statement<SchnorrConstaintSystem> + ?Sized>(
        &mut self,
        vars: &S::Vars,
        wit: &S::Witness,
    ) {
        S::assign_witness(self, vars, wit)
    }

    pub fn assign_scalar(&mut self, var: ScalarVar, scalar: impl Into<Scalar>) {
        let scalar = scalar.into();
        if self.0.len() <= var.0 {
            self.0.resize(var.0 + 1, None);
        } else if let Some(assignment) = self.0[var.0] {
            assert_eq!(
                assignment, scalar,
                "conflicting assignments for var {var:?}"
            )
        }
        self.0[var.0] = Some(scalar);
    }

    pub fn assign_scalars(&mut self, assignments: impl IntoIterator<Item = (ScalarVar, Scalar)>) {
        for (var, value) in assignments.into_iter() {
            self.assign_scalar(var, value);
        }
    }

    fn scalar_val(&self, var: impl Into<Option<ScalarVar>>) -> Scalar {
        // TODO: Should this be a panic, or an error?
        var.into()
            .map(|var| self.0[var.0].unwrap_or_else(|| panic!("unassigned scalar var {var:?}")))
            .unwrap_or(Scalar::ONE)
    }

    // NOTE: Not implemented as `IntoIterator` for now because doing so requires explicitly
    // defining an iterator type, See https://github.com/rust-lang/rust/issues/63063
    fn into_iter(self) -> impl Iterator<Item = (ScalarVar, Scalar)> {
        self.0
            .into_iter()
            .enumerate()
            .filter_map(|(i, x)| x.map(|x| (ScalarVar(i), x)))
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

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("point variable with index {index} is unassigned")]
    UnassignedPoint { index: usize },
    #[error("witness length of {received} does not match the expected length for the relation, {expected}")]
    InvalidWitnessLength { expected: usize, received: usize },
    #[error("constraint does not evaluates to non-zero value: {index}")]
    ConstraintEvalNotZero { index: usize },
    #[error("proof fails to verify: {0}")]
    Verification(#[source] ProofError),
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::{RistrettoPoint, Scalar};

    use super::{CompactProof, Error, Instance, PointVar, Relation, ScalarVar, Witness};

    /// Example statement constraining two pairs of points to have the same discrete log.
    /// A = x * G && B = x * H
    struct DlEqRelation {
        rel: Relation,
        pub x: ScalarVar,
        pub a: PointVar,
        pub b: PointVar,
    }

    impl DlEqRelation {
        pub fn new(g: RistrettoPoint, h: RistrettoPoint) -> Self {
            let mut rel = Relation::default();
            let x = rel.alloc_scalar();

            let a = rel.alloc_eq(x * g);
            let b = rel.alloc_eq(x * h);

            Self { rel, x, a, b }
        }

        pub fn prove(
            &self,
            x: Scalar,
        ) -> Result<(RistrettoPoint, RistrettoPoint, CompactProof), Error> {
            let mut witness = Witness::default();
            witness.assign_scalar(self.x, x);

            let (instance, proof) = self.rel.prove(&witness)?;
            let a = instance.point_val(self.a);
            let b = instance.point_val(self.b);

            Ok((a, b, proof))
        }

        pub fn verify(
            &self,
            a: RistrettoPoint,
            b: RistrettoPoint,
            proof: &CompactProof,
        ) -> Result<(), Error> {
            let mut instance = Instance::default();
            instance.assign_point(self.a, a);
            instance.assign_point(self.b, b);

            self.rel.verify(&instance, proof)
        }
    }

    #[test]
    fn example() {
        let g = RistrettoPoint::random(&mut rand::thread_rng());
        let h = RistrettoPoint::random(&mut rand::thread_rng());

        let (a, b, proof) = {
            let relation = DlEqRelation::new(g, h);

            let x = Scalar::random(&mut rand::thread_rng());
            let (a, b, proof) = relation.prove(x).unwrap();

            (a, b, proof)
        };

        let relation = DlEqRelation::new(g, h);
        relation.verify(a, b, &proof).unwrap();

        // This is where the verifier might use (a, b) from the instance/message.
    }
}
