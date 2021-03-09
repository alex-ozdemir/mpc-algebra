use conec::quinn::Certificate;
use conec::{client::IncomingStreams, InStream, OutStream};
use conec::{Client, ClientConfig};
use std::io::BufRead;
use lazy_static::lazy_static;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
//use futures_util::stream::stream::StreamExt;
use futures::{executor::block_on, future, prelude::*};
use tokio::io::AsyncBufReadExt;
use tokio_serde::{formats::SymmetricalBincode, SymmetricallyFramed};

mod mpc;

use ark_bls12_377::Fr;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use std::str::FromStr;

type VecU8Out = SymmetricallyFramed<OutStream, Vec<u8>, SymmetricalBincode<Vec<u8>>>;
type VecU8In = SymmetricallyFramed<InStream, Vec<u8>, SymmetricalBincode<Vec<u8>>>;

lazy_static! {
    static ref CH: Mutex<Option<FieldChannel>> = Mutex::new(None);
}

struct FieldChannel {
    conec_client: Client,
    incoming: IncomingStreams,
    send: VecU8Out,
    recv: VecU8In,
    id: String,
    other_id: String,
}

impl FieldChannel {
    async fn new(id: String, other_id: String) -> Self {
        let coord = "localhost".to_owned();
        let (mut client, mut incoming) = {
            let mut client_cfg = ClientConfig::new(id.clone(), coord);
            let mut cert_path = std::env::temp_dir();
            cert_path.push("cert.der");
            client_cfg.set_ca(
                Certificate::from_der(&std::fs::read(cert_path).unwrap())
                    .expect("could not find cert file at /tmp/cert.der"),
            );
            eprintln!("Fut4");
            conec::Client::new(client_cfg).await.unwrap()
        };
        let (send, recv) = if &id < &other_id {
            eprintln!("Initiating");
            loop {
                if let Ok((send, recv)) = client.new_stream(other_id.clone()).await {
                    break (send, recv);
                }
                eprintln!("Retry");
                tokio::time::delay_for(std::time::Duration::from_millis(1000)).await;
            }
        } else {
            eprintln!("Waiting");
            let (_, i, send, recv) = incoming.next().await.unwrap();
            eprintln!("Id: {:?}", i);
            (send, recv)
        };
        let s = SymmetricallyFramed::new(send, SymmetricalBincode::<Vec<u8>>::default());
        let r = SymmetricallyFramed::new(recv, SymmetricalBincode::<Vec<u8>>::default());
        FieldChannel {
            conec_client: client,
            incoming,
            send: s,
            recv: r,
            id,
            other_id,
        }
    }
    async fn exchange<F: ark_ff::Field>(&mut self, f: F) -> F {
        let mut bytes_out = Vec::new();
        f.serialize(&mut bytes_out).unwrap();
        self.send.send(bytes_out).await.unwrap();
        let bytes_in = self.recv.try_next().await.expect("closed").expect("EOF");
        F::deserialize(&bytes_in[..]).unwrap()
    }
}

//pub fn init_mpc(id: String, other_id: String) {
//    block_on(
//}


#[tokio::main]
async fn main() -> () {
    let id = std::env::args().nth(1).unwrap();
    let other_id = std::env::args().nth(2).unwrap();
    eprintln!("b4 create");
    let mut channel = block_on(FieldChannel::new(id, other_id));
    eprintln!("after create");
    let stdin = std::io::stdin();
    eprintln!("Start");
    for l in stdin.lock().lines().map(|l| l.unwrap()) {
        let token = l.trim();
        eprintln!("Line: {}", token);
        let field_elem = Fr::from_str(&token).unwrap();
        eprintln!("F: {:?}", field_elem);
        let field_elem2 = block_on(channel.exchange(field_elem));
        eprintln!("F: {:?}", field_elem2);
    }
    eprintln!("Done");

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
