use log::debug;

mod mpc;

use ark_bls12_377::Fr;
use ark_ff::{FftField, Field};
use ark_poly::domain::radix2::Radix2EvaluationDomain;
use ark_poly::EvaluationDomain;
use std::net::{ToSocketAddrs, SocketAddr};
use std::str::FromStr;

use mpc::channel;
use mpc::MpcVal;

use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "client", about = "An example MPC")]
struct Opt {
    /// Activate debug mode
    // short and long flags (-d, --debug) will be deduced from the field's name
    #[structopt(short, long)]
    debug: bool,

    /// Your host
    #[structopt(long,default_value = "localhost")]
    host: String,

    /// Your port
    #[structopt(long,default_value = "8000")]
    port: u16,

    /// Peer host
    #[structopt(long)]
    peer_host: String,

    /// Peer port
    #[structopt(long,default_value = "8000")]
    peer_port: u16,

    /// Which party are you? 0 or 1?
    #[structopt(long,default_value = "0")]
    party: u8,

    /// Input a
    #[structopt()]
    a: u64,

    /// Input b
    #[structopt()]
    b: u64,
}

fn computation<F: Field>(mut a: F, b: F) -> F {
    a *= &b;
    a
}

fn fft_computation<F: FftField>(mut vs: Vec<F>) -> Vec<F> {
    let d = Radix2EvaluationDomain::<F>::new(4).unwrap();
    for (i, v) in vs.iter().enumerate() {
        println!("  {}: {}", i, v);
    }
    d.ifft_in_place(&mut vs);
    vs
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
    let self_addr = (opt.host, opt.port).to_socket_addrs().unwrap().filter(SocketAddr::is_ipv4).next().unwrap();
    let peer_addr = (opt.peer_host, opt.peer_port).to_socket_addrs().unwrap().filter(SocketAddr::is_ipv4).next().unwrap();
    channel::init(self_addr, peer_addr, opt.party == 0);
    debug!("Start");
    let a = MFr::from_shared(Fr::from(opt.a));
    let b = MFr::from_shared(Fr::from(opt.b));
    let c = computation(a, b);
    println!("c: {}", c);
    let cc = c.publicize();
    println!("cc: {}", cc);
    let mut vs = fft_computation(vec![a, a, a, a]);
    for v in &mut vs {
        *v = v.publicize();
    }
    for (i, v) in vs.iter().enumerate() {
        println!("  {}: {}", i, v);
    }
    //let stdin = std::io::stdin();
    //for l in stdin.lock().lines().map(|l| l.unwrap()) {
    //    let token = l.trim();
    //    debug!("Line: {}", token);
    //    let field_elem = Fr::from_str(&token).unwrap();
    //    debug!("F: {:?}", field_elem);
    //    let field_elem2 = channel::exchange(field_elem);
    //    debug!("F: {:?}", field_elem2);
    //}
    channel::deinit();
    debug!("Done");

    //    let coord = "localhost".to_owned();
    //    let (mut client, mut incoming) = {
    //        let mut client_cfg = ClientConfig::new(id.clone(), coord);
    //        let mut cert_path = std::env::temp_dir();
    //        cert_path.push("cert.der");
    //        client_cfg.set_ca(
    //            Certificate::from_der(&std::fs::read(cert_path).unwrap())
    //                .expect("could not find cert file at /tmp/cert.der"),
    //        );
    //        conec::Client::new(client_cfg).await.unwrap()
    //    };
    //    let (send, recv) = if &id < &other_id {
    //        eprintln!("Initiating");
    //        client.new_stream(other_id).await.unwrap()
    //    } else {
    //        eprintln!("Waiting");
    //        let (_, _, send, recv) = incoming.next().await.unwrap();
    //        (send, recv)
    //    };
    //    eprintln!("Go ahead and type.");
    //    let rfut =
    //        SymmetricallyFramed::new(recv, SymmetricalBincode::<Vec<u8>>::default()).for_each(|s| {
    //            let bytes = s.unwrap();
    //            let field_elem = Fr::deserialize(&bytes[..]).unwrap();
    //            println!("---> {:?}", field_elem);
    //            future::ready(())
    //        });
    //
    //    let stdin = tokio::io::BufReader::new(tokio::io::stdin());
    //    let sfut = stdin
    //        .lines()
    //        .map(|s| {
    //            let field_elem = Fr::from_str(&s.unwrap().trim()).unwrap();
    //            let mut bytes = Vec::new();
    //            field_elem.serialize(&mut bytes).unwrap();
    //            println!("---> {:?}", field_elem);
    //            Ok(bytes)
    //        })
    //        .forward(SymmetricallyFramed::new(
    //            send,
    //            SymmetricalBincode::<Vec<u8>>::default(),
    //        ))
    //        .then(|sf| async {
    //            sf.ok();
    //            eprintln!("*** STDIN closed.");
    //        });
    //
    //    futures::future::join(sfut, rfut).await;
}
