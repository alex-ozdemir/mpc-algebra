use super::*;
use super::super::*;

use ark_poly_commit::marlin_pc::MarlinKZG10;
use ark_poly_commit::{Evaluations, BatchLCProof, PolynomialCommitment, QuerySet, LabeledPolynomial, LabeledCommitment, LinearCombination, PCRandomness};
use ark_poly::UVPolynomial;

use std::marker::PhantomData;


pub struct MpcPolyCommit<F: Field, P: Polynomial<F>, PC: PolynomialCommitment<F, P>>(PC, PhantomData<F>, PhantomData<P>);


type F = ark_bls12_377::Fr;
type P = ark_poly::univariate::DensePolynomial<F>;
type E = ark_bls12_377::Bls12_377;
type PC = MarlinKZG10<E, P>;
type PCR = <PC as PolynomialCommitment<F, P>>::Randomness;
type MPC = MarlinKZG10<crate::mpc::MpcPairingEngine<E>, MpcVal<P>>;

impl PCRandomness for MpcVal<PCR> {
    fn empty() -> Self {
        MpcVal::from_public(PCR::empty())
    }
    fn rand<R: rand::RngCore>(
        num_queries: usize,
        has_degree_bound: bool,
        num_vars: Option<usize>,
        rng: &mut R
    ) -> Self {
        MpcVal::from_shared(PCR::rand(num_queries, has_degree_bound, num_vars, rng))
    }
}

impl PolynomialCommitment<MpcVal<F>, MpcVal<P>> for MpcPolyCommit<F, P, PC>
where
    for<'a, 'b> &'a P: Div<&'b P, Output = P>,
{
    type UniversalParams = <PC as PolynomialCommitment<F, P>>::UniversalParams;
    type CommitterKey = <PC as PolynomialCommitment<F, P>>::CommitterKey;
    type VerifierKey = <PC as PolynomialCommitment<F, P>>::VerifierKey;
    type PreparedVerifierKey = <PC as PolynomialCommitment<F, P>>::PreparedVerifierKey;
    type Commitment = <PC as PolynomialCommitment<F, P>>::Commitment;
    type PreparedCommitment = <PC as PolynomialCommitment<F, P>>::PreparedCommitment;
    type Randomness = MpcVal<PCR>;
    type Proof = <PC as PolynomialCommitment<F, P>>::Proof;
    type BatchProof = Vec<Self::Proof>;
    type Error = <PC as PolynomialCommitment<F, P>>::Error;

    /// Constructs public parameters when given as input the maximum degree `max_degree`
    /// for the polynomial commitment scheme.
    fn setup<R: RngCore>(
        max_degree: usize,
        num_vars: Option<usize>,
        rng: &mut R,
    ) -> Result<Self::UniversalParams, Self::Error> {
        PC::setup(max_degree, num_vars, rng)
    }

    fn trim(
        pp: &Self::UniversalParams,
        supported_degree: usize,
        supported_hiding_bound: usize,
        enforced_degree_bounds: Option<&[usize]>,
    ) -> Result<(Self::CommitterKey, Self::VerifierKey), Self::Error> {
        PC::trim(pp, supported_degree, supported_hiding_bound, enforced_degree_bounds)
    }

    /// Outputs a commitment to `polynomial`.
    fn commit<'a>(
        ck: &Self::CommitterKey,
        polynomials: impl IntoIterator<Item = &'a LabeledPolynomial<MpcVal<F>, MpcVal<P>>>,
        rng: Option<&mut dyn RngCore>,
    ) -> Result<
        (
            Vec<LabeledCommitment<Self::Commitment>>,
            Vec<Self::Randomness>,
        ),
        Self::Error,
    >
    where
        P: 'a,
    {
        let polynomial_shares: Vec<LabeledPolynomial<F, P>> = polynomials.into_iter().map(|p| {
            assert!(p.shared, "Can only commit to shared polynomials");
            LabeledPolynomial::new(p.label().clone(), p.polynomial().val.clone(), p.degree_bound(), p.hiding_bound())
        }).collect();
        let (c_share_comms, c_share_rands) = PC::commit(ck, &polynomial_shares, rng)?;
        c_share_comms.into_iter().map(|c_share| {
            let g_elem = c_share.commitment().comm.0;
            let shifted_g_elem = c_share.commitment().shifted_comm.map(|s| s.0);
        });
        unimplemented!()
    }

    /// On input a polynomial `p` and a point `point`, outputs a proof for the same.
    fn open_individual_opening_challenges<'a>(
        ck: &Self::CommitterKey,
        labeled_polynomials: impl IntoIterator<Item = &'a LabeledPolynomial<MpcVal<F>, MpcVal<P>>>,
        _commitments: impl IntoIterator<Item = &'a LabeledCommitment<Self::Commitment>>,
        point: &'a MpcVal<F>,
        opening_challenges: &dyn Fn(u64) -> MpcVal<F>,
        rands: impl IntoIterator<Item = &'a Self::Randomness>,
        _rng: Option<&mut dyn RngCore>,
    ) -> Result<Self::Proof, Self::Error>
    where
        P: 'a,
        Self::Randomness: 'a,
        Self::Commitment: 'a,
    {
        unimplemented!()
    }

    /// Verifies that `value` is the evaluation at `x` of the polynomial
    /// committed inside `comm`.
    fn check_individual_opening_challenges<'a>(
        vk: &Self::VerifierKey,
        commitments: impl IntoIterator<Item = &'a LabeledCommitment<Self::Commitment>>,
        point: &'a MpcVal<F>,
        values: impl IntoIterator<Item = MpcVal<F>>,
        proof: &Self::Proof,
        opening_challenges: &dyn Fn(u64) -> MpcVal<F>,
        _rng: Option<&mut dyn RngCore>,
    ) -> Result<bool, Self::Error>
    where
        Self::Commitment: 'a,
    {
        unimplemented!()
    }

    fn batch_check_individual_opening_challenges<'a, R: RngCore>(
        vk: &Self::VerifierKey,
        commitments: impl IntoIterator<Item = &'a LabeledCommitment<Self::Commitment>>,
        query_set: &QuerySet<MpcVal<F>>,
        values: &Evaluations<MpcVal<F>, MpcVal<F>>,
        proof: &Self::BatchProof,
        opening_challenges: &dyn Fn(u64) -> MpcVal<F>,
        rng: &mut R,
    ) -> Result<bool, Self::Error>
    where
        Self::Commitment: 'a,
    {
        unimplemented!()
    }

    fn open_combinations_individual_opening_challenges<'a>(
        ck: &Self::CommitterKey,
        lc_s: impl IntoIterator<Item = &'a LinearCombination<MpcVal<F>>>,
        polynomials: impl IntoIterator<Item = &'a LabeledPolynomial<MpcVal<F>, MpcVal<P>>>,
        commitments: impl IntoIterator<Item = &'a LabeledCommitment<Self::Commitment>>,
        query_set: &QuerySet<MpcVal<F>>,
        opening_challenges: &dyn Fn(u64) -> MpcVal<F>,
        rands: impl IntoIterator<Item = &'a Self::Randomness>,
        rng: Option<&mut dyn RngCore>,
    ) -> Result<BatchLCProof<MpcVal<F>, MpcVal<P>, Self>, Self::Error>
    where
        P: 'a,
        Self::Randomness: 'a,
        Self::Commitment: 'a,
    {
        unimplemented!()
    }

    /// Checks that `values` are the true evaluations at `query_set` of the polynomials
    /// committed in `labeled_commitments`.
    fn check_combinations_individual_opening_challenges<'a, R: RngCore>(
        vk: &Self::VerifierKey,
        lc_s: impl IntoIterator<Item = &'a LinearCombination<MpcVal<F>>>,
        commitments: impl IntoIterator<Item = &'a LabeledCommitment<Self::Commitment>>,
        query_set: &QuerySet<MpcVal<F>>,
        evaluations: &Evaluations<MpcVal<F>, MpcVal<F>>,
        proof: &BatchLCProof<MpcVal<F>, MpcVal<P>, Self>,
        opening_challenges: &dyn Fn(u64) -> MpcVal<F>,
        rng: &mut R,
    ) -> Result<bool, Self::Error>
    where
        Self::Commitment: 'a,
    {
        unimplemented!()
    }

    /// On input a list of labeled polynomials and a query set, `open` outputs a proof of evaluation
    /// of the polynomials at the points in the query set.
    fn batch_open_individual_opening_challenges<'a>(
        ck: &Self::CommitterKey,
        labeled_polynomials: impl IntoIterator<Item = &'a LabeledPolynomial<MpcVal<F>, MpcVal<P>>>,
        commitments: impl IntoIterator<Item = &'a LabeledCommitment<Self::Commitment>>,
        query_set: &QuerySet<MpcVal<F>>,
        opening_challenges: &dyn Fn(u64) -> MpcVal<F>,
        rands: impl IntoIterator<Item = &'a Self::Randomness>,
        rng: Option<&mut dyn RngCore>,
    ) -> Result<Vec<Self::Proof>, Self::Error>
    where
        P: 'a,
        Self::Randomness: 'a,
        Self::Commitment: 'a,
    {
        unimplemented!()
    }
}

/// Marlin PC run over MPC types
pub type MpcMarlinKZG10 = MarlinKZG10<MpcPairingEngine<Bls12_377>, MpcVal<univariate::DensePolynomial<ark_bls12_377::Fr>>>;


