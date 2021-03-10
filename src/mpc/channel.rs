use lazy_static::lazy_static;
use log::debug;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::Mutex;

use super::MpcVal;
//use ark_ec::AffineCurve;
use ark_ff::Field;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

lazy_static! {
    static ref CH: Mutex<FieldChannel> = Mutex::new(FieldChannel {
        stream: None,
        id: "127.0.0.1:8000".parse().unwrap(),
        other_id: "127.0.0.1:8000".parse().unwrap(),
    });
}

fn tcp_send_slice(s: &mut TcpStream, v: &[u8]) {
    let bytes = (v.len() as u64).to_ne_bytes();
    s.write_all(&bytes[..]).unwrap();
    s.write_all(v).unwrap();
}

fn tcp_recv_vec(s: &mut TcpStream) -> Vec<u8> {
    let mut len = [0u8; 8];
    s.read_exact(&mut len[..]).unwrap();
    let mut bytes = vec![0u8; u64::from_ne_bytes(len) as usize];
    s.read_exact(&mut bytes[..]).unwrap();
    bytes
}

struct FieldChannel {
    /// Empty if unitialized
    stream: Option<TcpStream>,
    id: SocketAddr,
    other_id: SocketAddr,
}

const HOST: &str = "localhost";

impl FieldChannel {
    pub fn new<A1: ToSocketAddrs, A2: ToSocketAddrs>(self_: A1, peer: A2) -> Self {
        let id = self_.to_socket_addrs().unwrap().next().unwrap();
        let other_id = peer.to_socket_addrs().unwrap().next().unwrap();
        debug!("{} vs {}", id, other_id);
        let stream = if id < other_id {
            debug!("Attempting to contact peer");
            loop {
                let mut ms_waited = 0;
                match TcpStream::connect(other_id) {
                    Ok(s) => break s,
                    Err(e) => {
                        if e.kind() == std::io::ErrorKind::ConnectionRefused {
                            ms_waited += 100;
                            std::thread::sleep(std::time::Duration::from_millis(100));
                            if ms_waited % 3_000 == 0 {
                                debug!("Still waiting");
                            } else if ms_waited > 30_000 {
                                panic!("Could not find peer in 30s");
                            }
                        } else {
                            panic!("Error during FieldChannel::new: {}", e);
                        }
                    }
                }
            }
        } else {
            let listener = TcpListener::bind(id).unwrap();
            debug!("Waiting for peer to contact us");
            let (stream, _addr) = listener.accept().unwrap();
            stream
        };
        debug!("Connected");
        FieldChannel {
            stream: Some(stream),
            id,
            other_id,
        }
    }
    fn stream(&mut self) -> &mut TcpStream {
        self.stream
            .as_mut()
            .expect("Unitialized FieldChannel. Did you forget mpc_init(..)?")
    }
    fn exchange<F: CanonicalSerialize + CanonicalDeserialize>(&mut self, f: F) -> F {
        let mut bytes_out = Vec::new();
        f.serialize(&mut bytes_out).unwrap();
        let bytes_in = if &self.id < &self.other_id {
            tcp_send_slice(self.stream(), &bytes_out[..]);
            tcp_recv_vec(self.stream())
        } else {
            let bytes_in = tcp_recv_vec(&mut self.stream());
            tcp_send_slice(&mut self.stream(), &bytes_out[..]);
            bytes_in
        };
        F::deserialize(&bytes_in[..]).unwrap()
    }
}

/// Initialize the MPC
pub fn init<A1: ToSocketAddrs, A2: ToSocketAddrs>(self_: A1, peer: A2) {
    let mut ch = CH.lock().unwrap();
    assert!(
        ch.stream.is_none(),
        "FieldChannel should no be re-intialized. Did you call mpc_init(..) twice?"
    );
    *ch = FieldChannel::new(self_, peer);
}

/// Exchange serializable element with the other party.
pub fn exchange<F: CanonicalSerialize + CanonicalDeserialize>(f: F) -> F {
    CH.lock().expect("Poisoned FieldChannel").exchange(f)
}

/// Are you the first party in the MPC?
pub fn am_first() -> bool {
    let c = CH.lock().expect("Poisoned FieldChannel");
    c.id < c.other_id
}

pub type Triple<F, G, H> = (MpcVal<F>, MpcVal<G>, MpcVal<H>);

/// Get a field triple
pub fn field_triple<F: Field>() -> Triple<F, F, F> {
    //TODO: fix
    (
        MpcVal::from_shared(F::from(0u8)),
        MpcVal::from_shared(F::from(0u8)),
        MpcVal::from_shared(F::from(0u8)),
    )
}

//impl<F: Field, C: AffineCurve<ScalarField=F>> Triple<F, C> for C {
//    fn triple() -> (MpcVal<Self>, MpcVal<F>, MpcVal<F>) {
//        //TODO: fix
//        (
//            MpcVal::from_shared(F::from(0u8)),
//            C::zero(),
//            MpcVal::from_shared(F::from(0u8)),
//        )
//    }
//}

pub fn deinit() {
    CH.lock().expect("Poisoned FieldChannel").stream = None;
}
