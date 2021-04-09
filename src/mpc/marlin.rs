use super::silly::MySillyCircuit;
use ark_bls12_377::Bls12_377;
use ark_ec::PairingEngine;
use ark_marlin::Marlin;
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::marlin_pc::MarlinKZG10;
use ark_poly_commit::{Polynomial, LabeledPolynomial, LabeledCommitment, PolynomialCommitment};
use ark_std::{test_rng, UniformRand};
use blake2::Blake2s;
use std::marker::PhantomData;

use super::*;

type MultiPC<E, Fr> = MarlinKZG10<E, DensePolynomial<Fr>>;
type MarlinPair<E, Fr> = Marlin<Fr, MultiPC<E, Fr>, Blake2s>;

pub fn local_test_prove_and_verify<E: PairingEngine>(n_iters: usize) {
    let rng = &mut test_rng();

    let srs = &MarlinPair::<E, E::Fr>::universal_setup(100, 50, 100, rng).unwrap();

    for _ in 0..n_iters {
        let a = E::Fr::rand(rng);
        let b = E::Fr::rand(rng);
        let circ = MySillyCircuit {
            a: Some(a),
            b: Some(b),
        };
        let mut c = a;
        c *= &b;
        let inputs = vec![c];
        let (index_pk, index_vk) = MarlinPair::<E, E::Fr>::index(srs, circ.clone()).unwrap();
        let proof = MarlinPair::<E, E::Fr>::prove(&index_pk, circ, rng).unwrap();
        let is_valid = MarlinPair::<E, E::Fr>::verify(&index_vk, &inputs, &proof, rng).unwrap();
        assert!(is_valid);
        let is_valid = MarlinPair::<E, E::Fr>::verify(&index_vk, &[a], &proof, rng).unwrap();
        assert!(!is_valid);
    }
}

//struct MpcPolyCommit<F: Field, P: Polynomial<F>, PC: PolynomialCommitment<F, P>>(PC, PhantomData<F>, PhantomData<P>);
//
//type Fr = ark_bls12_377::Fr;
//type P = DensePolynomial<Fr>;
//impl<P: Polynomial<Fr>, PC: PolynomialCommitment<Fr, P>>
//    PolynomialCommitment<MpcVal<Fr>, DensePolynomial<MpcVal<Fr>>> for MpcPolyCommit<Fr, PC>
//{
//    type UniversalParams = PC::UniversalParams;
//    type CommitterKey = Type;
//    type VerifierKey = Type;
//    type PreparedVerifierKey = Type;
//    type Commitment = Type;
//    type PreparedCommitment = Type;
//    type Randomness = Type;
//    type Proof = Type;
//    type BatchProof = Type;
//    type Error = Type;
//    fn setup<R: RngCore>(
//        max_degree: usize,
//        num_vars: Option<usize>,
//        rng: &mut R,
//    ) -> Result<Self::UniversalParams, Self::Error> {
//        todo!()
//    }
//
//    /// Specializes the public parameters for polynomials up to the given `supported_degree`
//    /// and for enforcing degree bounds in the range `1..=supported_degree`.
//    fn trim(
//        pp: &Self::UniversalParams,
//        supported_degree: usize,
//        supported_hiding_bound: usize,
//        enforced_degree_bounds: Option<&[usize]>,
//    ) -> Result<(Self::CommitterKey, Self::VerifierKey), Self::Error> {
//        todo!()
//    }
//
//    /// Outputs a commitments to `polynomials`. If `polynomials[i].is_hiding()`,
//    /// then the `i`-th commitment is hiding up to `polynomials.hiding_bound()` queries.
//    /// `rng` should not be `None` if `polynomials[i].is_hiding() == true` for any `i`.
//    ///
//    /// If for some `i`, `polynomials[i].is_hiding() == false`, then the
//    /// corresponding randomness is `Self::Randomness::empty()`.
//    ///
//    /// If for some `i`, `polynomials[i].degree_bound().is_some()`, then that
//    /// polynomial will have the corresponding degree bound enforced.
//    fn commit<'a>(
//        ck: &Self::CommitterKey,
//        polynomials: impl IntoIterator<Item = &'a LabeledPolynomial<F, P>>,
//        rng: Option<&mut dyn RngCore>,
//    ) -> Result<
//        (
//            Vec<LabeledCommitment<Self::Commitment>>,
//            Vec<Self::Randomness>,
//        ),
//        Self::Error,
//    >
//    where
//        P: 'a,
//    {
//        todo!()
//    }
//    /// open but with individual challenges
//    fn open_individual_opening_challenges<'a>(
//        ck: &Self::CommitterKey,
//        labeled_polynomials: impl IntoIterator<Item = &'a LabeledPolynomial<F, P>>,
//        commitments: impl IntoIterator<Item = &'a LabeledCommitment<Self::Commitment>>,
//        point: &'a P::Point,
//        opening_challenges: &dyn Fn(u64) -> F,
//        rands: impl IntoIterator<Item = &'a Self::Randomness>,
//        rng: Option<&mut dyn RngCore>,
//    ) -> Result<Self::Proof, Self::Error>
//    where
//        P: 'a,
//        Self::Randomness: 'a,
//        Self::Commitment: 'a,
//    {
//        todo!()
//    }
//
//    /// check but with individual challenges
//    fn check_individual_opening_challenges<'a>(
//        vk: &Self::VerifierKey,
//        commitments: impl IntoIterator<Item = &'a LabeledCommitment<Self::Commitment>>,
//        point: &'a P::Point,
//        values: impl IntoIterator<Item = F>,
//        proof: &Self::Proof,
//        opening_challenges: &dyn Fn(u64) -> F,
//        rng: Option<&mut dyn RngCore>,
//    ) -> Result<bool, Self::Error>
//    where
//        Self::Commitment: 'a,
//    {
//        todo!()
//    }
//}

pub fn mpc_test_prove_and_verify<E: PairingEngine>(n_iters: usize) {
    let rng = &mut test_rng();

    let srs = &MarlinPair::<E, E::Fr>::universal_setup(100, 50, 100, rng).unwrap();

    for _ in 0..n_iters {
        let a = E::Fr::rand(rng);
        let b = E::Fr::rand(rng);
        let circ = MySillyCircuit {
            a: Some(a),
            b: Some(b),
        };
        let mut c = a;
        c *= &b;
        let inputs = vec![c];
        let (index_pk, index_vk) = MarlinPair::<E, E::Fr>::index(srs, circ.clone()).unwrap();
        let proof = MarlinPair::<E, E::Fr>::prove(&index_pk, circ, rng).unwrap();
        let is_valid = MarlinPair::<E, E::Fr>::verify(&index_vk, &inputs, &proof, rng).unwrap();
        assert!(is_valid);
    }
}
