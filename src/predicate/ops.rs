use alloc::{vec, vec::Vec};
use core::ops::{Add, Div, Mul, Neg, Sub};

use super::{LinearCombination, PointVar, Scalar, ScalarVar, Term};

impl Neg for Term {
    type Output = Self;

    fn neg(self) -> Self {
        Self {
            weight: -self.weight,
            ..self
        }
    }
}

impl Neg for PointVar {
    type Output = Term;

    fn neg(self) -> Term {
        Term {
            weight: -Scalar::ONE,
            point: self,
            scalar: None,
        }
    }
}

impl Neg for LinearCombination {
    type Output = LinearCombination;

    fn neg(mut self) -> Self::Output {
        for term in self.0.iter_mut() {
            *term = -*term
        }
        self
    }
}

impl Add<LinearCombination> for LinearCombination {
    type Output = Self;

    fn add(mut self, mut rhs: LinearCombination) -> Self {
        self.0.append(&mut rhs.0);
        self
    }
}

impl Add<Term> for LinearCombination {
    type Output = LinearCombination;

    fn add(mut self, rhs: Term) -> LinearCombination {
        self.0.push(rhs);
        self
    }
}

impl Add<LinearCombination> for Term {
    type Output = LinearCombination;

    fn add(self, rhs: LinearCombination) -> LinearCombination {
        rhs + self
    }
}

impl Add<PointVar> for LinearCombination {
    type Output = LinearCombination;

    fn add(mut self, rhs: PointVar) -> LinearCombination {
        self.0.push(rhs.into());
        self
    }
}

impl Add<LinearCombination> for PointVar {
    type Output = LinearCombination;

    fn add(self, rhs: LinearCombination) -> LinearCombination {
        rhs + self
    }
}

impl Add<Term> for Term {
    type Output = LinearCombination;

    fn add(self, rhs: Term) -> LinearCombination {
        LinearCombination::from(self) + rhs
    }
}

impl Add<PointVar> for Term {
    type Output = LinearCombination;

    fn add(self, rhs: PointVar) -> LinearCombination {
        LinearCombination::from(self) + rhs
    }
}

impl Add<Term> for PointVar {
    type Output = LinearCombination;

    fn add(self, rhs: Term) -> LinearCombination {
        rhs + self
    }
}

impl Add<PointVar> for PointVar {
    type Output = LinearCombination;

    fn add(self, rhs: PointVar) -> LinearCombination {
        Term::from(self) + rhs
    }
}

impl Sub<LinearCombination> for LinearCombination {
    type Output = Self;

    fn sub(self, rhs: LinearCombination) -> Self {
        self + (-rhs)
    }
}

impl Sub<Term> for Term {
    type Output = LinearCombination;

    fn sub(self, rhs: Term) -> LinearCombination {
        self + (-rhs)
    }
}

impl Sub<PointVar> for PointVar {
    type Output = LinearCombination;

    fn sub(self, rhs: PointVar) -> LinearCombination {
        self + (-rhs)
    }
}

impl Sub<Term> for LinearCombination {
    type Output = LinearCombination;

    fn sub(self, rhs: Term) -> LinearCombination {
        self + (-rhs)
    }
}

impl Sub<LinearCombination> for Term {
    type Output = LinearCombination;

    fn sub(self, rhs: LinearCombination) -> LinearCombination {
        self + (-rhs)
    }
}

impl Sub<PointVar> for LinearCombination {
    type Output = LinearCombination;

    fn sub(self, rhs: PointVar) -> LinearCombination {
        self + (-rhs)
    }
}

impl Sub<LinearCombination> for PointVar {
    type Output = LinearCombination;

    fn sub(self, rhs: LinearCombination) -> LinearCombination {
        self + (-rhs)
    }
}

impl Mul<Scalar> for Term {
    type Output = Self;

    fn mul(self, rhs: Scalar) -> Self {
        Self {
            weight: self.weight * rhs,
            ..self
        }
    }
}

impl Mul<Term> for Scalar {
    type Output = Term;

    fn mul(self, rhs: Term) -> Term {
        rhs * self
    }
}

impl Mul<Scalar> for PointVar {
    type Output = Term;

    fn mul(self, rhs: Scalar) -> Term {
        Term {
            point: self,
            weight: rhs,
            scalar: None,
        }
    }
}

impl Mul<PointVar> for Scalar {
    type Output = Term;

    fn mul(self, rhs: PointVar) -> Term {
        rhs * self
    }
}

impl Mul<Scalar> for LinearCombination {
    type Output = Self;

    fn mul(mut self, rhs: Scalar) -> Self {
        for term in self.0.iter_mut() {
            *term = *term * rhs;
        }
        self
    }
}

impl Mul<LinearCombination> for Scalar {
    type Output = LinearCombination;

    fn mul(self, rhs: LinearCombination) -> LinearCombination {
        rhs * self
    }
}

impl Mul<ScalarVar> for PointVar {
    type Output = Term;

    fn mul(self, rhs: ScalarVar) -> Term {
        Term {
            scalar: Some(rhs),
            point: self,
            weight: Scalar::ONE,
        }
    }
}

impl Mul<PointVar> for ScalarVar {
    type Output = Term;

    fn mul(self, rhs: PointVar) -> Term {
        rhs * self
    }
}
