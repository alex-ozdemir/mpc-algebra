use log::debug;

mod mpc;

use ark_bls12_377::Fr;
use ark_ff::{FftField, Field};
use ark_serialize::CanonicalSerialize;
use ark_poly::domain::radix2::Radix2EvaluationDomain;
use ark_poly::EvaluationDomain;
use std::net::{SocketAddr, ToSocketAddrs};

use mpc::channel;
use mpc::MpcVal;
use mpc::ComField;

use clap::arg_enum;
use structopt::StructOpt;
use merlin::Transcript;

arg_enum! {
    #[derive(PartialEq, Debug)]
    pub enum Computation {
        Fft,
        Sum,
        Product,
        Commit,
        Merkle,
    }
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

    /// Input a
    #[structopt()]
    args: Vec<u64>,
}

impl Computation {
    fn run<F: ComField>(&self, mut inputs: Vec<F>) -> Vec<F> {
        println!("Inputs:");
        for (i, v) in inputs.iter().enumerate() {
            println!("  {}: {}", i, v);
        }
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
                let mut challenge_bytes: [u8; 8] = [0,0,0,0,0,0,0,0];
                t.challenge_bytes(b"challenge", &mut challenge_bytes[..]);
                let n = u64::from_be_bytes(challenge_bytes) as usize;
                let i = n % inputs.len();
                println!("Query at: {}", i);
                let (value, pf) = F::open_at(&inputs[..], &k, i);
                let v = F::check_opening(&c, pf, i, value);
                println!("Valid proof: {}", v);
                vec![]
            }
        };
        println!("Outputs:");
        for (i, v) in outputs.iter().enumerate() {
            println!("  {}: {}", i, v);
        }
        outputs
    }
}


type MFr = MpcVal<Fr>;

fn main() -> () {
    let opt = Opt::from_args();
    if opt.debug {
        env_logger::builder()
            .filter_level(log::LevelFilter::Debug)
            .init();
    } else {
        env_logger::init();
    }
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
    let inputs = opt.args.iter().map(|i| MFr::from_shared(Fr::from(*i))).collect::<Vec<MFr>>();
    let outputs = opt.computation.run(inputs);
    let public_outputs = outputs.into_iter().map(|c| c.publicize()).collect::<Vec<_>>();
    println!("Public Outputs:");
    for (i, v) in public_outputs.iter().enumerate() {
        println!("  {}: {}", i, v);
    }
    debug!("Stats: {:#?}", channel::stats());
    channel::deinit();
    debug!("Done");
}
