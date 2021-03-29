use log::debug;

mod mpc;

use ark_bls12_377::Fr;
use ark_ec::group::Group;
use ark_ec::ProjectiveCurve;
use ark_ec::PairingEngine;
use ark_poly::domain::radix2::Radix2EvaluationDomain;
use ark_poly::EvaluationDomain;
use ark_serialize::CanonicalSerialize;
use ark_std::rand::SeedableRng;
use std::net::{SocketAddr, ToSocketAddrs};

use mpc::channel;
use mpc::ComField;
use mpc::MpcCurve;
use mpc::MpcCurve2;
use mpc::MpcVal;
use mpc::MpcWire;

use clap::arg_enum;
use merlin::Transcript;
use structopt::StructOpt;

arg_enum! {
    #[derive(PartialEq, Debug)]
    pub enum Computation {
        Fft,
        Sum,
        Product,
        Commit,
        Merkle,
        Fri,
        Dh,
        PairingDh,
    }
}

enum ComputationDomain {
    G1,
    G2,
    Field,
    Pairing,
}

#[derive(Debug, StructOpt)]
#[structopt(name = "client", about = "An example MPC")]
struct Opt {
    /// Activate debug mode
    // short and long flags (-d, --debug) will be deduced from the field's name
    #[structopt(short, long)]
    debug: bool,

    /// Your host
    #[structopt(long, default_value = "localhost")]
    host: String,

    /// Your port
    #[structopt(long, default_value = "8000")]
    port: u16,

    /// Peer host
    #[structopt(long)]
    peer_host: String,

    /// Peer port
    #[structopt(long, default_value = "8000")]
    peer_port: u16,

    /// Which party are you? 0 or 1?
    #[structopt(long, default_value = "0")]
    party: u8,

    /// Computation to perform
    #[structopt()]
    computation: Computation,

    /// Computation to perform
    #[structopt(long)]
    use_g2: bool,

    /// Input a
    #[structopt()]
    args: Vec<u64>,
}

impl Opt {
    fn domain(&self) -> ComputationDomain {
        match &self.computation {
            Computation::Dh => if self.use_g2 { ComputationDomain::G2 }  else {
                ComputationDomain::G1},

            Computation::PairingDh => ComputationDomain::Pairing,
            _ => ComputationDomain::Field,
        }
    }
}

impl Computation {
    fn run_pairing<P: PairingEngine>(
        &self,
        inputs: Vec<<P as PairingEngine>::Fr>,
    ) -> Vec<<P as PairingEngine>::Fr>
        where <P as PairingEngine>::Fr: mpc::MpcWire
            , <P as PairingEngine>::Fqk: mpc::MpcWire
    {
        let outputs = match self {
            Computation::PairingDh => {
                assert_eq!(3, inputs.len());
                let a = inputs[0];
                let b = inputs[1];
                let c = inputs[2];
                let g1 = <P as PairingEngine>::G1Projective::prime_subgroup_generator();
                let g2 = <P as PairingEngine>::G2Projective::prime_subgroup_generator();
                let g1a = <<P as PairingEngine>::G1Projective as Group>::mul(&g1, &a);
                let g2b = <<P as PairingEngine>::G2Projective as Group>::mul(&g2, &b);
                let g1c = <<P as PairingEngine>::G1Projective as Group>::mul(&g1, &c);
                let gc = P::pairing(g1c, g2).publicize();
                let gcc = P::pairing(g1a, g2b).publicize();
                assert_eq!(gc, gcc);
                vec![]
            }
            c => unimplemented!("Cannot run_pairing {:?}", c),
        };
        println!("Outputs:");
        for (i, v) in outputs.iter().enumerate() {
            println!("  {}: {}", i, v);
        }
        outputs
    }
    fn run_gp<G: ProjectiveCurve + mpc::MpcWire>(
        &self,
        inputs: Vec<<G as Group>::ScalarField>,
    ) -> Vec<G> {
        let outputs = match self {
            Computation::Dh => {
                assert_eq!(3, inputs.len());
                let a = inputs[0];
                let b = inputs[1];
                let c = inputs[2];
                let g = G::prime_subgroup_generator();
                let ga = <G as Group>::mul(&g, &a);
                let gb = <G as Group>::mul(&g, &b);
                let gc = <G as Group>::mul(&g, &c);
                let gcc = ga + gb;
                let gc = gc.publicize();
                let gcc = gcc.publicize();
                assert_eq!(gc, gcc);
                vec![]
            }
            c => unimplemented!("Cannot run_dh {:?}", c),
        };
        println!("Outputs:");
        for (i, v) in outputs.iter().enumerate() {
            println!("  {}: {}", i, v);
        }
        outputs
    }
    fn run_field<F: ComField>(&self, mut inputs: Vec<F>) -> Vec<F> {
        let outputs = match self {
            Computation::Fft => {
                let d = Radix2EvaluationDomain::<F>::new(inputs.len()).unwrap();
                d.ifft_in_place(&mut inputs);
                inputs
            }
            Computation::Sum => {
                vec![inputs.into_iter().fold(F::from(0u32), std::ops::Add::add)]
            }
            Computation::Product => {
                assert_eq!(inputs.len(), 2);
                vec![inputs[0] * inputs[1]]
            }
            Computation::Commit => {
                let mut t = Transcript::new(b"commit");
                for i in &inputs {
                    let mut bytes = Vec::new();
                    i.serialize(&mut bytes).unwrap();
                    t.append_message(b"input", &bytes);
                }
                let mut challenge_bytes = vec![0u8; 64];
                t.challenge_bytes(b"challenge", &mut challenge_bytes);
                let c = F::from_random_bytes(&challenge_bytes).expect("Couldn't sample");
                vec![c]
            }
            Computation::Merkle => {
                let mut t = Transcript::new(b"merkle");
                let (k, c) = F::commit(&inputs[..]);
                let mut bytes = Vec::new();
                c.serialize(&mut bytes).unwrap();
                t.append_message(b"commitment", &bytes);
                let mut challenge_bytes: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 0];
                t.challenge_bytes(b"challenge", &mut challenge_bytes[..]);
                let n = u64::from_be_bytes(challenge_bytes) as usize;
                let i = n % inputs.len();
                println!("Query at: {}", i);
                let (value, pf) = F::open_at(&inputs[..], &k, i);
                let v = F::check_opening(&c, pf, i, value);
                assert!(v);
                println!("Valid proof: {}", v);
                vec![]
            }
            Computation::Fri => {
                let mut t = Transcript::new(b"fri");
                let n = inputs.len();
                assert!(n.is_power_of_two());
                let k = n.trailing_zeros() as usize;
                let l = k + 1;
                let mut fs = vec![inputs];
                let mut commitments = Vec::new();
                let mut alphas = Vec::new();
                println!("k: {}", k);
                for i in 0..k {
                    let f_last = fs.last().unwrap();
                    let mut evals = f_last.clone();
                    evals.extend(std::iter::repeat(F::zero()).take((1 << (l - i)) - evals.len()));
                    let d = Radix2EvaluationDomain::<F>::new(evals.len()).unwrap();
                    d.fft_in_place(&mut evals);
                    let (tree, root) = F::commit(&evals);
                    commitments.push((evals, tree, root));
                    let mut bytes = Vec::new();
                    commitments.last().unwrap().2.serialize(&mut bytes).unwrap();
                    t.append_message(b"commitment", &bytes);
                    //TODO: entropy problem for large fields...
                    // need to wrestle with ff's random sampling implementation properly
                    let mut challenge_bytes = [0u8; 32];
                    t.challenge_bytes(b"challenge", &mut challenge_bytes);
                    let mut rng = rand::rngs::StdRng::from_seed(challenge_bytes);
                    let alpha = F::rand(&mut rng);
                    println!("Fri commit round {}, challenge: {}", i, alpha);
                    let mut f_next = Vec::new();
                    for i in 0..f_last.len() / 2 {
                        f_next.push(f_last[2 * i] + f_last[2 * i + 1] * alpha);
                    }
                    fs.push(f_next);
                    alphas.push(alpha);
                }
                assert_eq!(fs.last().unwrap().len(), 1);
                let constant = fs.last().unwrap().last().unwrap().clone().publicize();
                let mut bytes = Vec::new();
                constant.serialize(&mut bytes).unwrap();
                t.append_message(b"constant", &bytes);
                println!("Constant: {}", constant);

                let iter = 1;
                for j in 0..iter {
                    println!("FRI chain check {}/{}", j + 1, iter);
                    let mut challenge_bytes: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 0];
                    t.challenge_bytes(b"challenge", &mut challenge_bytes[..]);
                    let mut x_i = u64::from_be_bytes(challenge_bytes) % (1 << l);
                    // index of x in seq.
                    for i in 0..k {
                        let n: u64 = 1 << (l - i);
                        let omega = F::get_root_of_unity(n as usize).unwrap();
                        let x = omega.pow(&[x_i]);
                        let neg_x_i = (n / 2 + x_i) % n;
                        assert_eq!(-x, omega.pow(&[neg_x_i]));
                        let x2_i = 2 * x_i % n / 2;
                        let (val, pf) =
                            F::open_at(&commitments[i].0[..], &commitments[i].1, x_i as usize);
                        let mut bytes = Vec::new();
                        pf.serialize(&mut bytes).unwrap();
                        t.append_message(b"path", &bytes);
                        assert!(F::check_opening(&commitments[i].2, pf, x_i as usize, val));
                        let (neg_val, neg_pf) =
                            F::open_at(&commitments[i].0[..], &commitments[i].1, neg_x_i as usize);
                        let mut bytes = Vec::new();
                        neg_pf.serialize(&mut bytes).unwrap();
                        t.append_message(b"path1", &bytes);
                        assert!(F::check_opening(
                            &commitments[i].2,
                            neg_pf,
                            neg_x_i as usize,
                            neg_val
                        ));
                        let next_val = if i + 1 < k {
                            let (next_val, next_pf) = F::open_at(
                                &commitments[i + 1].0[..],
                                &commitments[i + 1].1,
                                x2_i as usize,
                            );
                            let mut bytes = Vec::new();
                            next_pf.serialize(&mut bytes).unwrap();
                            t.append_message(b"path2", &bytes);
                            assert!(F::check_opening(
                                &commitments[i + 1].2,
                                next_pf,
                                x2_i as usize,
                                next_val
                            ));
                            next_val
                        } else {
                            constant
                        };
                        assert!(
                            next_val
                                == (val + neg_val) / F::from(2u8)
                                    + alphas[i] * (val - neg_val) / (F::from(2u8) * x)
                        );
                        // TODO: add to transcript
                        x_i = x2_i;
                    }
                }
                vec![]
            }
            c => unimplemented!("Cannot run_field {:?}", c),
        };
        println!("Outputs:");
        for (i, v) in outputs.iter().enumerate() {
            println!("  {}: {}", i, v);
        }
        outputs
    }
}

type MFr = MpcVal<Fr>;
type G1 = ark_bls12_377::G1Projective;
type MG1 = MpcCurve<G1>;
type G2 = ark_bls12_377::G2Projective;
type MG2 = MpcCurve2<G2>;

fn main() -> () {
    let opt = Opt::from_args();
    if opt.debug {
        env_logger::builder()
            .filter_level(log::LevelFilter::Debug)
            .init();
    } else {
        env_logger::init();
    }
    let domain = opt.domain();
    let self_addr = (opt.host, opt.port)
        .to_socket_addrs()
        .unwrap()
        .filter(SocketAddr::is_ipv4)
        .next()
        .unwrap();
    let peer_addr = (opt.peer_host, opt.peer_port)
        .to_socket_addrs()
        .unwrap()
        .filter(SocketAddr::is_ipv4)
        .next()
        .unwrap();
    channel::init(self_addr, peer_addr, opt.party == 0);
    debug!("Start");
        let inputs = opt
            .args
            .iter()
            .map(|i| MFr::from_shared(Fr::from(*i)))
            .collect::<Vec<MFr>>();
        println!("Inputs:");
        for (i, v) in inputs.iter().enumerate() {
            println!("  {}: {}", i, v);
        }
    match domain {
        ComputationDomain::Field => {
            let outputs = opt.computation.run_field(inputs);
            let public_outputs = outputs
                .into_iter()
                .map(|c| c.publicize())
                .collect::<Vec<_>>();
            println!("Public Outputs:");
            for (i, v) in public_outputs.iter().enumerate() {
                println!("  {}: {}", i, v);
            }
        }
        ComputationDomain::G1 => {
            let outputs = opt
                .computation
                .run_gp::<MG1>(inputs);
            let public_outputs = outputs
                .into_iter()
                .map(|c: MG1| c.publicize())
                .collect::<Vec<_>>();
            println!("Public Outputs:");
            for (i, v) in public_outputs.iter().enumerate() {
                println!("  {}: {}", i, v);
            }
        }
        ComputationDomain::G2 => {
            let outputs = opt
                .computation
                .run_gp::<MG2>(inputs);
            let public_outputs = outputs
                .into_iter()
                .map(|c: MG2| c.publicize())
                .collect::<Vec<_>>();
            println!("Public Outputs:");
            for (i, v) in public_outputs.iter().enumerate() {
                println!("  {}: {}", i, v);
            }
        }
        ComputationDomain::Pairing => {
            let outputs = opt
                .computation
                .run_pairing::<mpc::MpcPairingEngine<ark_bls12_377::Bls12_377>>(inputs);
            let public_outputs = outputs
                .into_iter()
                .map(|c: MFr| c.publicize())
                .collect::<Vec<_>>();
            println!("Public Outputs:");
            for (i, v) in public_outputs.iter().enumerate() {
                println!("  {}: {}", i, v);
            }
        }
    }
    debug!("Stats: {:#?}", channel::stats());
    channel::deinit();
    debug!("Done");
}
