use lazy_static::lazy_static;
use log::debug;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Mutex;

use super::MpcVal;
//use ark_ec::AffineCurve;
use ark_ff::Field;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

lazy_static! {
    static ref CH: Mutex<FieldChannel> = Mutex::new(FieldChannel {
        stream: None,
        id: 0,
        other_id: 0,
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
    id: u16,
    other_id: u16,
}

const HOST: &str = "localhost";

impl FieldChannel {
    fn new(id: u16, other_id: u16) -> Self {
        let stream = if id < other_id {
            debug!("Waiting for peer");
            loop {
                if let Ok(s) = TcpStream::connect((HOST, other_id)) {
                    break s;
                } else {
                    std::thread::sleep(std::time::Duration::from_secs(1))
                }
            }
        } else {
            let listener = TcpListener::bind((HOST, id)).unwrap();
            debug!("Waiting for peer");
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

pub fn init(id: u16, other_id: u16) {
    let mut ch = CH.lock().unwrap();
    assert!(
        ch.stream.is_none(),
        "FieldChannel should no be re-intialized. Did you call mpc_init(..) twice?"
    );
    *ch = FieldChannel::new(id, other_id);
}

pub fn exchange<F: CanonicalSerialize + CanonicalDeserialize>(f: F) -> F {
    CH.lock().expect("Poisoned FieldChannel").exchange(f)
}

pub fn am_first() -> bool {
    let c = CH.lock().expect("Poisoned FieldChannel");
    c.id < c.other_id
}

pub trait Triple<G, H>: Sized {
    fn triple() -> (MpcVal<Self>, MpcVal<G>, MpcVal<H>);
}

impl<F: Field> Triple<F, F> for F {
    fn triple() -> (MpcVal<Self>, MpcVal<F>, MpcVal<F>) {
        //TODO: fix
        (
            MpcVal::from_shared(F::from(0u8)),
            MpcVal::from_shared(F::from(0u8)),
            MpcVal::from_shared(F::from(0u8)),
        )
    }
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
