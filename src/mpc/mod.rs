use ark_bls12_377::Bls12_377;
//use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ec::PairingEngine;
use ark_ff::{FftField, Field, LegendreSymbol, One, PrimeField, SquareRootField, Zero};
use ark_serialize::*;
use ark_std::UniformRand;
use log::debug;
use rand::prelude::*;
use sha2::Digest;
use std::borrow::Cow;
use std::ops::*;

pub mod channel;

// const N_PARTIES: u32 = 2;

#[derive(Clone, Copy, Default, Hash, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct MpcVal<T> {
    val: T,
    shared: bool,
}

impl<F: std::fmt::Display> std::fmt::Display for MpcVal<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.val)?;
        if self.shared {
            write!(f, " (shared)")
        } else {
            write!(f, " (public)")
        }
    }
}

impl<T> MpcVal<T> {
    pub fn new(val: T, shared: bool) -> Self {
        Self { val, shared }
    }
    pub fn from_public(val: T) -> Self {
        Self::new(val, false)
    }
    pub fn from_shared(val: T) -> Self {
        Self::new(val, true)
    }
}

impl<F: zeroize::Zeroize> zeroize::Zeroize for MpcVal<F> {
    fn zeroize(&mut self) {
        self.val.zeroize();
    }
}

impl<F: ark_ff::ToBytes> ark_ff::ToBytes for MpcVal<F> {
    #[inline]
    fn write<W: ark_std::io::Write>(&self, writer: W) -> ark_std::io::Result<()> {
        assert!(!self.shared);
        self.val.write(writer)
    }
}

// macro_rules! add_op {
//    ($T:ty,$L:ty,$R:ty,$O:ty,$f:ident) => {
//        impl<F: Field> $T<$R<F>> for $L<F> {
//            type Output = $O;
//
//            fn add(self, other: $R<R>) -> Self::Output {
//                Self {
//                    shared: self.shared || other.shared,
//                    val: match (self.shared, other.shared) {
//                        (true, true) => self.val.$f(other.val),
//                        (true, false) => self.val.$f(other.val /
// F::from(N_PARTIES)),                        (false, true) => (self.val /
// F::from(N_PARTIES)).$f(other.val),                        (false, false) =>
// self.val.$f(other.val),                    },
//                }
//            }
//        }
//    }
//}
// add_op!(Sub,MpcVal,MpcVal,MpcVal,sub);

impl<F: AddAssign<F>> AddAssign<MpcVal<F>> for MpcVal<F> {
    fn add_assign(&mut self, other: MpcVal<F>) {
        match (self.shared, other.shared) {
            (true, false) => {
                if channel::am_first() {
                    self.val.add_assign(other.val);
                } else {
                }
            }
            (false, true) => {
                if channel::am_first() {
                    self.val.add_assign(other.val);
                } else {
                    self.val = other.val;
                }
            }
            _ => {
                self.val.add_assign(other.val);
            }
        }
        self.shared = self.shared || other.shared;
    }
}

impl<F: Add<F, Output = F>> Add<MpcVal<F>> for MpcVal<F> {
    type Output = MpcVal<F>;
    fn add(self, other: MpcVal<F>) -> Self::Output {
        Self::new(
            if self.shared == other.shared || channel::am_first() {
                self.val.add(other.val)
            } else if other.shared {
                other.val
            } else {
                self.val
            },
            self.shared || other.shared,
        )
    }
}

impl<'a, F: AddAssign<&'a F> + Clone> AddAssign<&'a MpcVal<F>> for MpcVal<F> {
    fn add_assign(&mut self, other: &'a MpcVal<F>) {
        match (self.shared, other.shared) {
            (true, false) => {
                if channel::am_first() {
                    self.val.add_assign(&other.val);
                } else {
                }
            }
            (false, true) => {
                if channel::am_first() {
                    self.val.add_assign(&other.val);
                } else {
                    self.val = other.val.clone();
                }
            }
            _ => {
                self.val.add_assign(&other.val);
            }
        }
        self.shared = self.shared || other.shared;
    }
}

impl<'a, F: Add<&'a F, Output = F> + Clone> Add<&'a MpcVal<F>> for MpcVal<F> {
    type Output = MpcVal<F>;
    fn add(self, other: &'a MpcVal<F>) -> Self::Output {
        Self::new(
            if self.shared == other.shared || channel::am_first() {
                self.val.add(&other.val)
            } else if other.shared {
                other.val.clone()
            } else {
                self.val
            },
            self.shared || other.shared,
        )
    }
}

impl<F: SubAssign<F> + Neg<Output = F>> SubAssign<MpcVal<F>> for MpcVal<F> {
    fn sub_assign(&mut self, other: MpcVal<F>) {
        match (self.shared, other.shared) {
            (true, false) => {
                if channel::am_first() {
                    self.val.sub_assign(other.val);
                } else {
                }
            }
            (false, true) => {
                if channel::am_first() {
                    self.val.sub_assign(other.val);
                } else {
                    self.val = -other.val;
                }
            }
            _ => {
                self.val.sub_assign(other.val);
            }
        }
        self.shared = self.shared || other.shared;
    }
}

impl<F: Sub<F, Output = F> + Neg<Output = F>> Sub<MpcVal<F>> for MpcVal<F> {
    type Output = MpcVal<F>;
    fn sub(self, other: MpcVal<F>) -> Self::Output {
        Self::new(
            if self.shared == other.shared || channel::am_first() {
                self.val.sub(other.val)
            } else if other.shared {
                -other.val
            } else {
                self.val
            },
            self.shared || other.shared,
        )
    }
}

impl<'a, F: SubAssign<&'a F> + Clone + Neg<Output = F>> SubAssign<&'a MpcVal<F>> for MpcVal<F> {
    fn sub_assign(&mut self, other: &'a MpcVal<F>) {
        match (self.shared, other.shared) {
            (true, false) => {
                if channel::am_first() {
                    self.val.sub_assign(&other.val);
                } else {
                }
            }
            (false, true) => {
                if channel::am_first() {
                    self.val.sub_assign(&other.val);
                } else {
                    self.val = -other.val.clone();
                }
            }
            _ => {
                self.val.sub_assign(&other.val);
            }
        }
        self.shared = self.shared || other.shared;
    }
}

impl<'a, F: Sub<&'a F, Output = F> + Clone + Neg<Output = F>> Sub<&'a MpcVal<F>> for MpcVal<F> {
    type Output = MpcVal<F>;
    fn sub(self, other: &'a MpcVal<F>) -> Self::Output {
        Self::new(
            if self.shared == other.shared || channel::am_first() {
                self.val.sub(&other.val)
            } else if other.shared {
                -other.val.clone()
            } else {
                self.val
            },
            self.shared || other.shared,
        )
    }
}

impl<F: Field> MulAssign<MpcVal<F>> for MpcVal<F> {
    fn mul_assign(&mut self, other: MpcVal<F>) {
        match (self.shared, other.shared) {
            (true, true) => {
                *self = channel::field_mul(*self, other);
            }
            _ => self.val.mul_assign(other.val),
        };
        self.shared = self.shared || other.shared;
    }
}

impl<F: Field> Mul<MpcVal<F>> for MpcVal<F> {
    type Output = MpcVal<F>;
    fn mul(self, other: MpcVal<F>) -> Self::Output {
        Self::Output::new(
            match (self.shared, other.shared) {
                (true, true) => channel::field_mul(self, other).val,
                _ => self.val.mul(other.val),
            },
            self.shared || other.shared,
        )
    }
}

impl<'a, F: Field> MulAssign<&'a MpcVal<F>> for MpcVal<F> {
    fn mul_assign(&mut self, other: &'a MpcVal<F>) {
        match (self.shared, other.shared) {
            (true, true) => {
                *self = channel::field_mul(*self, *other);
            }
            _ => self.val.mul_assign(&other.val),
        };
        self.shared = self.shared || other.shared;
    }
}
impl<'a, F: Field> Mul<&'a MpcVal<F>> for MpcVal<F> {
    type Output = MpcVal<F>;
    fn mul(self, other: &'a MpcVal<F>) -> Self::Output {
        Self::Output::new(
            match (self.shared, other.shared) {
                (true, true) => channel::field_mul(self, *other).val,
                _ => self.val.mul(&other.val),
            },
            self.shared || other.shared,
        )
    }
}
impl<G, F: DivAssign<G>> DivAssign<MpcVal<G>> for MpcVal<F> {
    fn div_assign(&mut self, other: MpcVal<G>) {
        match (self.shared, other.shared) {
            (true, true) => unimplemented!("ss div"),
            _ => self.val.div_assign(other.val),
        };
        self.shared = self.shared || other.shared;
    }
}
impl<F: DivAssign<F>> Div<MpcVal<F>> for MpcVal<F> {
    type Output = MpcVal<F>;
    fn div(mut self, other: MpcVal<F>) -> Self::Output {
        self.div_assign(other);
        self
    }
}
impl<'a, G, F: DivAssign<&'a G>> DivAssign<&'a MpcVal<G>> for MpcVal<F> {
    fn div_assign(&mut self, other: &'a MpcVal<G>) {
        match (self.shared, other.shared) {
            (true, true) => unimplemented!("ss div"),
            _ => self.val.div_assign(&other.val),
        };
        self.shared = self.shared || other.shared;
    }
}
impl<'a, F: DivAssign<&'a F>> Div<&'a MpcVal<F>> for MpcVal<F> {
    type Output = MpcVal<F>;
    fn div(mut self, other: &'a MpcVal<F>) -> Self::Output {
        self.div_assign(other);
        self
    }
}
impl<F: Neg<Output = F>> Neg for MpcVal<F> {
    type Output = MpcVal<F>;
    fn neg(mut self) -> Self::Output {
        self.val = self.val.neg();
        self
    }
}

impl<F: Field> ark_ff::One for MpcVal<F> {
    fn one() -> Self {
        Self::from_public(F::one())
    }
}

impl<F: ark_ff::Zero> ark_ff::Zero for MpcVal<F> {
    fn zero() -> Self {
        Self::from_public(F::zero())
    }
    fn is_zero(&self) -> bool {
        assert!(!self.shared);
        self.val.is_zero()
    }
}

impl<F: ark_ff::Zero + Add> ark_std::iter::Sum<MpcVal<F>> for MpcVal<F> {
    fn sum<I>(i: I) -> Self
    where
        I: Iterator<Item = MpcVal<F>>,
    {
        i.fold(MpcVal::zero(), Add::add)
    }
}
impl<'a, F: 'a + ark_ff::Zero + Add<&'a F, Output = F> + Clone> ark_std::iter::Sum<&'a MpcVal<F>>
    for MpcVal<F>
{
    fn sum<I>(i: I) -> Self
    where
        I: Iterator<Item = &'a MpcVal<F>>,
    {
        i.fold(MpcVal::zero(), Add::add)
    }
}
impl<F: Field> ark_std::iter::Product<MpcVal<F>> for MpcVal<F> {
    fn product<I>(i: I) -> Self
    where
        I: Iterator<Item = MpcVal<F>>,
    {
        i.fold(MpcVal::one(), Mul::mul)
    }
}
impl<'a, F: 'a + Field> ark_std::iter::Product<&'a MpcVal<F>> for MpcVal<F> {
    fn product<I>(i: I) -> Self
    where
        I: Iterator<Item = &'a MpcVal<F>>,
    {
        i.fold(MpcVal::one(), Mul::mul)
    }
}
impl<
        F: AddAssign<F>
            + ark_serialize::CanonicalSerialize
            + ark_serialize::CanonicalDeserialize
            + Clone,
    > ark_serialize::CanonicalSerialize for MpcVal<F>
{
    fn serialize<W>(&self, w: W) -> std::result::Result<(), ark_serialize::SerializationError>
    where
        W: ark_serialize::Write,
    {
        self.publicize_cow().val.serialize(w)
    }
    fn serialized_size(&self) -> usize {
        self.val.serialized_size()
    }
}
impl<
        F: AddAssign<F>
            + ark_serialize::CanonicalSerialize
            + ark_serialize::CanonicalDeserialize
            + Clone,
    > ark_serialize::CanonicalDeserialize for MpcVal<F>
{
    fn deserialize<R>(r: R) -> std::result::Result<Self, ark_serialize::SerializationError>
    where
        R: ark_serialize::Read,
    {
        F::deserialize(r).map(MpcVal::from_public)
    }
}
impl<
        F: AddAssign<F>
            + ark_serialize::CanonicalSerialize
            + ark_serialize::CanonicalDeserializeWithFlags
            + Clone,
    > ark_serialize::CanonicalDeserializeWithFlags for MpcVal<F>
{
    fn deserialize_with_flags<R, Fl>(
        r: R,
    ) -> std::result::Result<(Self, Fl), ark_serialize::SerializationError>
    where
        R: ark_serialize::Read,
        Fl: Flags,
    {
        F::deserialize_with_flags(r).map(|(s, f)| (MpcVal::from_public(s), f))
    }
}

impl<
        F: AddAssign<F>
            + ark_serialize::CanonicalSerializeWithFlags
            + ark_serialize::CanonicalDeserialize
            + Clone,
    > ark_serialize::CanonicalSerializeWithFlags for MpcVal<F>
{
    fn serialize_with_flags<W, Fl>(
        &self,
        w: W,
        f: Fl,
    ) -> std::result::Result<(), ark_serialize::SerializationError>
    where
        W: ark_serialize::Write,
        Fl: Flags,
    {
        self.publicize_cow().val.serialize_with_flags(w, f)
    }
    fn serialized_size_with_flags<Fl>(&self) -> usize
    where
        Fl: ark_serialize::Flags,
    {
        self.val.serialized_size_with_flags::<Fl>()
    }
}
//impl<F: ark_serialize::ConstantSerializedSize> ark_serialize::ConstantSerializedSize for MpcVal<F> {
//    const SERIALIZED_SIZE: usize = F::SERIALIZED_SIZE;
//    const UNCOMPRESSED_SIZE: usize = F::UNCOMPRESSED_SIZE;
//}

macro_rules! from_prim {
    ($t:ty) => {
        impl<F: std::convert::From<$t>> std::convert::From<$t> for MpcVal<F> {
            fn from(t: $t) -> Self {
                Self::from_public(F::from(t))
            }
        }
    };
}

from_prim!(bool);
from_prim!(u8);
from_prim!(u16);
from_prim!(u32);
from_prim!(u64);
from_prim!(u128);

impl<F: ark_ff::FromBytes> ark_ff::FromBytes for MpcVal<F> {
    #[inline]
    fn read<R: ark_std::io::Read>(reader: R) -> ark_std::io::Result<Self> {
        F::read(reader).map(Self::from_public)
    }
}

impl<F: UniformRand> Distribution<MpcVal<F>> for rand::distributions::Standard {
    fn sample<R: ?Sized>(&self, r: &mut R) -> MpcVal<F>
    where
        R: Rng,
    {
        MpcVal {
            val: F::rand(r),
            // TODO: Good for FRI, bad in general?
            shared: false,
        }
    }
}

impl<F: AsMut<[u64]>> AsMut<[u64]> for MpcVal<F> {
    fn as_mut(&mut self) -> &mut [u64] {
        self.val.as_mut()
    }
}

impl<F: AsRef<[u64]>> AsRef<[u64]> for MpcVal<F> {
    fn as_ref(&self) -> &[u64] {
        self.val.as_ref()
    }
}

impl<F: std::str::FromStr> std::str::FromStr for MpcVal<F> {
    type Err = F::Err;
    fn from_str(s: &str) -> Result<Self, F::Err> {
        F::from_str(s).map(Self::from_public)
    }
}

macro_rules! shared_field {
    ($Pf:ty) => {
        impl Field for MpcVal<$Pf> {
            type BasePrimeField = MpcVal<$Pf>;
            fn extension_degree() -> u64 {
                todo!()
            }
            fn from_base_prime_field_elems(b: &[<Self as Field>::BasePrimeField]) -> Option<Self> {
                assert!(b.len() > 0);
                let shared = b[0].shared;
                assert!(b.iter().all(|e| e.shared == shared));
                let base_values = b.iter().map(|e| e.val.clone()).collect::<Vec<_>>();
                <$Pf as Field>::from_base_prime_field_elems(&base_values)
                    .map(|val| Self { val, shared })
            }
            fn double(&self) -> Self {
                Self {
                    val: self.val.double(),
                    shared: self.shared,
                }
            }
            fn double_in_place(&mut self) -> &mut Self {
                self.val.double_in_place();
                self
            }
            fn from_random_bytes_with_flags<F: Flags>(b: &[u8]) -> Option<(Self, F)> {
                <$Pf>::from_random_bytes_with_flags(b).map(|(val, f)| (Self::from_shared(val), f))
            }
            fn square(&self) -> Self {
                if self.shared {
                    unimplemented!()
                } else {
                    Self::new(self.val.square(), self.shared)
                }
            }
            fn square_in_place(&mut self) -> &mut Self {
                if self.shared {
                    unimplemented!()
                } else {
                    self.val.square_in_place();
                    self
                }
            }
            fn inverse(&self) -> Option<Self> {
                if self.shared {
                    unimplemented!()
                } else {
                    self.val.inverse().map(Self::from_public)
                }
            }
            fn inverse_in_place(&mut self) -> Option<&mut Self> {
                if self.shared {
                    unimplemented!()
                } else {
                    if self.val.inverse_in_place().is_some() {
                        Some(self)
                    } else {
                        None
                    }
                }
            }
            fn frobenius_map(&mut self, _: usize) {
                todo!()
            }
        }
    };
}
macro_rules! shared_prime_field {
    ($Pf:ty, $Repr:ty) => {
        impl FftField for MpcVal<$Pf> {
            type FftParams = <$Pf as FftField>::FftParams;
            fn two_adic_root_of_unity() -> Self {
                Self::from_public(<$Pf as FftField>::two_adic_root_of_unity())
            }
            fn large_subgroup_root_of_unity() -> Option<Self> {
                <$Pf as FftField>::large_subgroup_root_of_unity().map(Self::from_public)
            }
            fn multiplicative_generator() -> Self {
                Self::from_public(<$Pf as FftField>::multiplicative_generator())
            }
        }

        impl PrimeField for MpcVal<$Pf> {
            type Params = <$Pf as PrimeField>::Params;
            // type BigInt = MpcVal<F::BigInt>;
            type BigInt = <$Pf as PrimeField>::BigInt;
            fn from_repr(r: <Self as PrimeField>::BigInt) -> Option<Self> {
                // F::from_repr(r.val).map(|v| MpcVal::new(v, r.shared))
                <$Pf>::from_repr(r).map(|v| MpcVal::from_public(v))
            }
            fn into_repr(&self) -> <Self as PrimeField>::BigInt {
                // MpcVal::new(self.val.into_repr(), self.shared)
                self.val.into_repr()
            }
        }

        impl From<$Repr> for MpcVal<$Pf> {
            /// Converts `Self::BigInteger` into `Self`
            ///
            /// # Panics
            /// This method panics if `int` is larger than `P::MODULUS`.
            fn from(int: $Repr) -> Self {
                Self::from_repr(int).unwrap()
            }
        }

        impl From<MpcVal<$Pf>> for $Repr {
            /// Converts `Self::BigInteger` into `Self`
            ///
            /// # Panics
            /// This method panics if `int` is larger than `P::MODULUS`.
            fn from(int: MpcVal<$Pf>) -> Self {
                int.into_repr()
            }
        }
    };
}
macro_rules! shared_sqrt_field {
    ($Pf:ty) => {
        impl SquareRootField for MpcVal<$Pf> {
            fn legendre(&self) -> LegendreSymbol {
                todo!()
            }
            fn sqrt(&self) -> Option<Self> {
                todo!()
            }
            fn sqrt_in_place(&mut self) -> Option<&mut Self> {
                todo!()
            }
        }
    };
}

shared_field!(ark_bls12_377::Fr);
shared_prime_field!(ark_bls12_377::Fr, ark_ff::BigInteger256);
shared_sqrt_field!(ark_bls12_377::Fr);

shared_field!(ark_bls12_377::Fq);
shared_prime_field!(ark_bls12_377::Fq, ark_ff::BigInteger384);
shared_sqrt_field!(ark_bls12_377::Fq);

// shared_field!(ark_bls12_377::Fq2);
// shared_sqrt_field!(ark_bls12_377::Fq2);

//impl AffineCurve for MpcVal<ark_bls12_377::G1Affine> {
//    type ScalarField = MpcVal<ark_bls12_377::Fr>;
//    const COFACTOR: &'static [u64] = ark_bls12_377::G1Affine::COFACTOR;
//    type BaseField = MpcVal<ark_bls12_377::Fq>;
//    type Projective = MpcVal<ark_bls12_377::G1Projective>;
//    fn prime_subgroup_generator() -> Self {
//        todo!()
//    }
//    fn from_random_bytes(_: &[u8]) -> Option<Self> {
//        todo!()
//    }
//    fn mul<S: Into<<Self::ScalarField as PrimeField>::BigInt>>(
//        &self,
//        _: S,
//    ) -> <Self as AffineCurve>::Projective {
//        todo!()
//    }
//    fn mul_by_cofactor_to_projective(&self) -> <Self as AffineCurve>::Projective {
//        todo!()
//    }
//    fn mul_by_cofactor_inv(&self) -> Self {
//        todo!()
//    }
//}
//impl From<MpcVal<ark_bls12_377::G1Projective>> for MpcVal<ark_bls12_377::G1Affine> {
//    fn from(p: MpcVal<ark_bls12_377::G1Projective>) -> Self {
//        Self::new(p.val.into(), p.shared)
//    }
//}
//impl From<MpcVal<ark_bls12_377::G1Affine>> for MpcVal<ark_bls12_377::G1Projective> {
//    fn from(p: MpcVal<ark_bls12_377::G1Affine>) -> Self {
//        Self::new(p.val.into(), p.shared)
//    }
//}
//impl ProjectiveCurve for MpcVal<ark_bls12_377::G1Projective> {
//    const COFACTOR: &'static [u64] = ark_bls12_377::G1Projective::COFACTOR;
//    type ScalarField = MpcVal<ark_bls12_377::Fr>;
//    type BaseField = MpcVal<ark_bls12_377::Fq>;
//    type Affine = MpcVal<ark_bls12_377::G1Affine>;
//    fn prime_subgroup_generator() -> Self {
//        todo!()
//    }
//    fn batch_normalization(_: &mut [Self]) {
//        todo!()
//    }
//    fn is_normalized(&self) -> bool {
//        todo!()
//    }
//    fn double_in_place(&mut self) -> &mut Self {
//        todo!()
//    }
//    fn add_assign_mixed(&mut self, _: &<Self as ProjectiveCurve>::Affine) {
//        todo!()
//    }
//}
//    type ScalarField: PrimeField + SquareRootField + Into<<Self::ScalarField
// as PrimeField>::BigInt>;    type BaseField: Field;
//    type Projective: ProjectiveCurve<Affine = Self, ScalarField =
// Self::ScalarField, BaseField = Self::BaseField> + From<Self> + Into<Self> +
// MulAssign<Self::ScalarField>;
//
//    pub const COFACTOR: &'static [u64];
//
//    fn prime_subgroup_generator() -> Self;
//    fn from_random_bytes(bytes: &[u8]) -> Option<Self>;
//    fn mul<S: Into<<Self::ScalarField as PrimeField>::BigInt>>(
//        &self,
//        other: S
//    ) -> Self::Projective;
//    fn mul_by_cofactor_to_projective(&self) -> Self::Projective;
//    fn mul_by_cofactor_inv(&self) -> Self;
//
//    fn into_projective(&self) -> Self::Projective { ... }
//    fn mul_by_cofactor(&self) -> Self { ... }
//}

/// A wrapper for a pairing engine
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MpcPairingEngine<E: PairingEngine> {
    inner: E,
}

impl PairingEngine for MpcPairingEngine<Bls12_377> {
    type Fr = <Bls12_377 as PairingEngine>::Fr;
    type G1Projective = <Bls12_377 as PairingEngine>::G1Projective;
    type G1Affine = <Bls12_377 as PairingEngine>::G1Affine;
    type G1Prepared = <Bls12_377 as PairingEngine>::G1Prepared;
    type G2Projective = <Bls12_377 as PairingEngine>::G2Projective;
    type G2Affine = <Bls12_377 as PairingEngine>::G2Affine;
    type G2Prepared = <Bls12_377 as PairingEngine>::G2Prepared;
    type Fq = <Bls12_377 as PairingEngine>::Fq;
    type Fqe = <Bls12_377 as PairingEngine>::Fqe;
    type Fqk = <Bls12_377 as PairingEngine>::Fqk;

    fn miller_loop<'a, I>(_i: I) -> Self::Fqk
    where
        I: IntoIterator<Item = &'a (Self::G1Prepared, Self::G2Prepared)>,
    {
        unimplemented!()
        // <Bls12_377 as PairingEngine>::miller_loop(i)
    }

    fn final_exponentiation(_f: &Self::Fqk) -> Option<Self::Fqk> {
        unimplemented!()
        // <Bls12_377 as PairingEngine>::final_exponentiation(f)
    }

    /// Computes a product of pairings.
    #[must_use]
    fn product_of_pairings<'a, I>(_i: I) -> Self::Fqk
    where
        I: IntoIterator<Item = &'a (Self::G1Prepared, Self::G2Prepared)>,
    {
        // TODO: MPC!
        // <Bls12_377 as PairingEngine>::product_of_pairings(i)
        unimplemented!()
    }

    /// Performs multiple pairing operations
    #[must_use]
    fn pairing<G1, G2>(p: G1, q: G2) -> Self::Fqk
    where
        G1: Into<Self::G1Affine>,
        G2: Into<Self::G2Affine>,
    {
        // TODO: MPC!
        <Bls12_377 as PairingEngine>::pairing(p, q)
    }
}

impl<
        F: AddAssign<F>
            + ark_serialize::CanonicalSerialize
            + ark_serialize::CanonicalDeserialize
            + Clone,
    > MpcVal<F>
{
    pub fn publicize(self) -> Self {
        if self.shared {
            let mut other_val = channel::exchange(self.val.clone());
            other_val += self.val;
            Self::from_public(other_val)
        } else {
            self
        }
    }
}

impl<
        F: AddAssign<F>
            + ark_serialize::CanonicalSerialize
            + ark_serialize::CanonicalDeserialize
            + Clone,
    > MpcVal<F>
{
    pub fn publicize_cow<'a>(&'a self) -> Cow<'a, Self> {
        if self.shared {
            let mut other_val = channel::exchange(self.val.clone());
            other_val += self.val.clone();
            Cow::Owned(Self::from_public(other_val))
        } else {
            Cow::Borrowed(self)
        }
    }
}


/// Vector-Commitable Field
pub trait ComField: FftField {
    type Commitment: ark_serialize::CanonicalSerialize;
    type Key;
    type OpeningProof: ark_serialize::CanonicalSerialize;
    fn publicize(self) -> Self;
    fn commit(vs: &[Self]) -> (Self::Key, Self::Commitment);
    fn open_at(vs: &[Self], key: &Self::Key, i: usize) -> (Self, Self::OpeningProof);
    fn check_opening(c: &Self::Commitment, p: Self::OpeningProof, i: usize, v: Self) -> bool;
}

impl ComField for MpcVal<<Bls12_377 as PairingEngine>::Fr> {
    type Commitment = (Vec<u8>, Vec<u8>);
    type Key = Vec<Vec<Vec<u8>>>;
    type OpeningProof = (
        <Bls12_377 as PairingEngine>::Fr,
        <Bls12_377 as PairingEngine>::Fr,
        Vec<(Vec<u8>, Vec<u8>)>,
    );
    fn publicize(self) -> Self {
        self.publicize()
    }
    fn commit(vs: &[Self]) -> (Self::Key, Self::Commitment) {
        let mut tree = Vec::new();
        let mut hashes: Vec<Vec<u8>> = vs
            .into_iter()
            .enumerate()
            .map(|(i, v)| {
                let mut bytes_out = Vec::new();
                v.val.serialize(&mut bytes_out).unwrap();
                let o = sha2::Sha256::digest(&bytes_out[..]).as_slice().to_owned();
                debug!("Hash {} {}: {:?}", vs.len(), i, o);
                o
            })
            .collect();
        assert!(hashes.len().is_power_of_two());
        while hashes.len() > 1 {
            let n = hashes.len() / 2;
            let mut new = Vec::new();
            for i in 0..n {
                let mut h = sha2::Sha256::default();
                h.update(&hashes[2 * i]);
                h.update(&hashes[2 * i + 1]);
                new.push(h.finalize().as_slice().to_owned());
                debug!("Hash {} {}: {:?}", hashes.len() / 2, i, new[new.len() - 1]);
            }
            tree.push(std::mem::replace(&mut hashes, new));
        }
        let slf = hashes.pop().unwrap();
        let other = channel::exchange_bytes(slf.clone());
        if channel::am_first() {
            (tree, (other, slf))
        } else {
            (tree, (slf, other))
        }
    }
    fn open_at(inputs: &[Self], tree: &Self::Key, mut i: usize) -> (Self, Self::OpeningProof) {
        let self_f = inputs[i].val.clone();
        let other_f = channel::exchange(self_f.clone());
        let mut siblings = Vec::new();
        for level in 0..tree.len() {
            debug!("sib {}: {:?}", level, tree[level][i^1]);
            siblings.push(tree[level][i ^ 1].clone());
            i /= 2;
        }
        assert_eq!(i / 2, 0);
        let other = siblings
            .clone()
            .into_iter()
            .map(|s| channel::exchange_bytes(s));
        let p = if channel::am_first() {
            siblings.into_iter().zip(other.into_iter()).collect()
        } else {
            other.into_iter().zip(siblings.into_iter()).collect()
        };
        (
            MpcVal::from_public(self_f + other_f),
            if channel::am_first() {
                (self_f, other_f, p)
            } else {
                (other_f, self_f, p)
            },
        )
    }
    fn check_opening(c: &Self::Commitment, p: Self::OpeningProof, i: usize, v: Self) -> bool {
        if p.0 + p.1 != v.val {
            return false;
        }
        let mut hash0 = Vec::new();
        p.0.serialize(&mut hash0).unwrap();
        hash0 = sha2::Sha256::digest(&hash0).as_slice().to_owned();
        let mut hash1 = Vec::new();
        p.1.serialize(&mut hash1).unwrap();
        hash1 = sha2::Sha256::digest(&hash1).as_slice().to_owned();
        debug!("Hash init0: {:?}", hash0);
        debug!("Hash init1: {:?}", hash1);
        for (j, (sib0, sib1)) in p.2.into_iter().enumerate() {
            let mut h0 = sha2::Sha256::default();
            let mut h1 = sha2::Sha256::default();
            if (i >> j) & 1 == 0 {
                h0.update(&hash0);
                h0.update(&sib0);
                h1.update(&hash1);
                h1.update(&sib1);
            } else {
                h0.update(&sib0);
                h0.update(&hash0);
                h1.update(&sib1);
                h1.update(&hash1);
            }
            hash0 = h0.finalize().as_slice().to_owned();
            hash1 = h1.finalize().as_slice().to_owned();
            debug!("Hash0: {:?}", hash0);
            debug!("Hash1: {:?}", hash1);
        }
        &(hash1, hash0) == c
    }
}
