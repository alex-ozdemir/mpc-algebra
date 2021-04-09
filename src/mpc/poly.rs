use ark_poly::{univariate, Polynomial, UVPolynomial};

use super::*;

pub mod pc;

macro_rules! impl_poly {
    ($field:ty, $poly:ty) => {
        impl<'a> std::ops::AddAssign<(MpcVal<$field>, &'a MpcVal<$poly>)> for MpcVal<$poly> {
            fn add_assign(&mut self, (scalar, f): (MpcVal<$field>, &'a MpcVal<$poly>)) {
                match (self.shared, scalar.shared, f.shared) {
                    (false, false, false) => {
                        self.val += (scalar.val, &f.val);
                    }
                    _ => unimplemented!("Shared poly scaled sum"),
                }
            }
        }

        impl Polynomial<MpcVal<$field>> for MpcVal<$poly> {
            type Point = MpcVal<<$poly as Polynomial<$field>>::Point>;
            fn degree(&self) -> usize {
                self.val.degree()
            }
            fn evaluate(&self, p: &Self::Point) -> MpcVal<$field> {
                assert!(!p.shared, "unimplemented: evaluation at shared points");
                MpcVal::new(self.val.evaluate(&p.val), self.shared)
            }
        }
    };
}

macro_rules! impl_uv_poly {
    ($field:ty, $poly:ty) => {
        impl UVPolynomial<MpcVal<$field>> for MpcVal<$poly> {
            fn from_coefficients_slice(s: &[MpcVal<$field>]) -> Self {
                assert!(s.len() > 0);
                let first_shared = s[0].shared;
                assert!(s.iter().all(|x| x.shared == first_shared));
                MpcVal::new(
                    <$poly>::from_coefficients_vec(s.iter().map(|x| x.val).collect()),
                    first_shared,
                )
            }
            fn from_coefficients_vec(s: Vec<MpcVal<$field>>) -> Self {
                assert!(s.len() > 0);
                let first_shared = s[0].shared;
                assert!(s.iter().all(|x| x.shared == first_shared));
                MpcVal::new(
                    <$poly>::from_coefficients_vec(s.iter().map(|x| x.val).collect()),
                    first_shared,
                )
            }
            fn coeffs(&self) -> &[MpcVal<$field>] {
                // hard because we don't have that in memory. Leak? New wrapper?
                unimplemented!("{} UVPolynomial::coeffs", std::stringify!($field))
            }
            fn rand<R>(d: usize, r: &mut R) -> Self
            where
                R: rand::Rng,
            {
                MpcVal::from_shared(<$poly>::rand(d, r))
            }
        }
        impl<'a, 'b> std::ops::Div<&'b MpcVal<$poly>> for &'a MpcVal<$poly> {
            type Output = MpcVal<$poly>;
            fn div(self, other: &MpcVal<$poly>) -> MpcVal<$poly> {
                assert!(!other.shared);
                let self_p = <$poly>::from_coefficients_slice(self.val.coeffs());
                let other_p = <$poly>::from_coefficients_slice(other.val.coeffs());
                MpcVal::new(&self_p / &other_p, self.shared)
            }
        }
    };
}

impl_poly!(
    ark_bls12_377::Fr,
    univariate::DensePolynomial<ark_bls12_377::Fr>
);

impl_uv_poly!(
    ark_bls12_377::Fr,
    univariate::DensePolynomial<ark_bls12_377::Fr>
);
