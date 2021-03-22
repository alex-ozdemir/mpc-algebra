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
    static ref CH: Mutex<FieldChannel> = Mutex::new(FieldChannel::default());
}

/// Macro for locking the FieldChannel singleton in the current scope.
#[macro_use]
macro_rules! get_ch {
    () => {
        CH.lock().expect("Poisoned FieldChannel")
    };
}

struct FieldChannel {
    /// Empty if unitialized
    stream: Option<TcpStream>,
    self_addr: SocketAddr,
    other_addr: SocketAddr,
    bytes_sent: usize,
    bytes_recv: usize,
    exchanges: usize,
    talk_first: bool,
}

impl std::default::Default for FieldChannel {
    fn default() -> Self {
        Self {
            stream: None,
            self_addr: "127.0.0.1:8000".parse().unwrap(),
            other_addr: "127.0.0.1:8000".parse().unwrap(),
            bytes_sent: 0,
            bytes_recv: 0,
            exchanges: 0,
            talk_first: false,
        }
    }
}

impl FieldChannel {
    fn connect<A1: ToSocketAddrs, A2: ToSocketAddrs>(
        &mut self,
        self_addr: A1,
        other_addr: A2,
        talk_first: bool,
    ) {
        self.self_addr = self_addr.to_socket_addrs().unwrap().next().unwrap();
        self.other_addr = other_addr.to_socket_addrs().unwrap().next().unwrap();
        self.talk_first = talk_first;
        debug!("I am {}, connecting to {}", self.self_addr, self.other_addr);
        self.stream = Some(if talk_first {
            debug!("Attempting to contact peer");
            loop {
                let mut ms_waited = 0;
                match TcpStream::connect(self.other_addr) {
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
            let listener = TcpListener::bind(self.self_addr).unwrap();
            debug!("Waiting for peer to contact us");
            let (stream, _addr) = listener.accept().unwrap();
            stream
        });
    }
    fn stream(&mut self) -> &mut TcpStream {
        self.stream
            .as_mut()
            .expect("Unitialized FieldChannel. Did you forget init(..)?")
    }

    fn send_slice(&mut self, v: &[u8]) {
        let s = self.stream();
        let bytes = (v.len() as u64).to_ne_bytes();
        s.write_all(&bytes[..]).unwrap();
        s.write_all(v).unwrap();
        self.bytes_sent += bytes.len() + v.len();
    }

    fn recv_vec(&mut self) -> Vec<u8> {
        let s = self.stream();
        let mut len = [0u8; 8];
        s.read_exact(&mut len[..]).unwrap();
        let mut bytes = vec![0u8; u64::from_ne_bytes(len) as usize];
        s.read_exact(&mut bytes[..]).unwrap();
        self.bytes_recv += bytes.len() + len.len();
        bytes
    }

    fn exchange<F: CanonicalSerialize + CanonicalDeserialize>(&mut self, f: F) -> F {
        let mut bytes_out = Vec::new();
        f.serialize(&mut bytes_out).unwrap();
        let bytes_in = if self.talk_first {
            self.send_slice(&bytes_out[..]);
            self.recv_vec()
        } else {
            let bytes_in = self.recv_vec();
            self.send_slice(&bytes_out[..]);
            bytes_in
        };
        self.exchanges += 1;
        F::deserialize(&bytes_in[..]).unwrap()
    }

    fn exchange_bytes(&mut self, f: Vec<u8>) -> Vec<u8> {
        self.exchanges += 1;
        if self.talk_first {
            self.send_slice(&f[..]);
            self.recv_vec()
        } else {
            let bytes_in = self.recv_vec();
            self.send_slice(&f[..]);
            bytes_in
        }
    }

    fn field_triple<F: Field>(&self) -> Triple<F, F, F> {
        //TODO
        if self.talk_first {
            (
                MpcVal::from_shared(F::from(1u8)),
                MpcVal::from_shared(F::from(1u8)),
                MpcVal::from_shared(F::from(1u8)),
            )
        } else {
            (
                MpcVal::from_shared(F::from(0u8)),
                MpcVal::from_shared(F::from(0u8)),
                MpcVal::from_shared(F::from(0u8)),
            )
        }
    }

    fn field_mul<F: Field>(&mut self, mut a: MpcVal<F>, b: MpcVal<F>) -> MpcVal<F> {
        if a.shared && b.shared {
            // x * y = z
            let (x, y, mut z) = self.field_triple();
            // x + aA
            let xa = self.field_add(a, &x);
            let xa = self.field_publicize(xa);
            // y + b
            let yb = self.field_add(b, &y);
            let yb = self.field_publicize(yb);
            z.val -= y.val * &xa.val;
            z.val -= x.val * &yb.val;
            if self.talk_first {
                z.val += xa.val * &yb.val;
            }
            z
        } else {
            a.val *= b.val;
            a.shared = a.shared || b.shared;
            a
        }
    }

    fn field_add<F: Field>(&mut self, mut a: MpcVal<F>, b: &MpcVal<F>) -> MpcVal<F> {
        match (a.shared, b.shared) {
            (true, true) | (false, false) => {
                a.val += &b.val;
                a
            }
            (true, false) => {
                if self.talk_first {
                    a.val += &b.val;
                }
                a
            }
            (false, true) => {
                a.shared = true;
                if self.talk_first {
                    a.val += &b.val;
                }
                a
            }
        }
    }

    fn field_sub<F: Field>(&mut self, mut a: MpcVal<F>, b: &MpcVal<F>) -> MpcVal<F> {
        match (a.shared, b.shared) {
            (true, true) | (false, false) => {
                a.val -= &b.val;
                a
            }
            (true, false) => {
                if self.talk_first {
                    a.val -= &b.val;
                }
                a
            }
            (false, true) => {
                a.shared = true;
                if self.talk_first {
                    a.val -= &b.val;
                }
                a
            }
        }
    }

    fn field_publicize<F: Field>(&mut self, a: MpcVal<F>) -> MpcVal<F> {
        assert!(a.shared);
        let mut other_val = self.exchange(a.val.clone());
        other_val += a.val;
        MpcVal::from_public(other_val)
    }

    fn stats(&self) -> ChannelStats {
        ChannelStats {
            bytes_recv: self.bytes_recv,
            bytes_sent: self.bytes_sent,
            exchanges: self.exchanges,
        }
    }
}

/// Initialize the MPC
pub fn init<A1: ToSocketAddrs, A2: ToSocketAddrs>(self_: A1, peer: A2, talk_first: bool) {
    let mut ch = get_ch!();
    assert!(
        ch.stream.is_none(),
        "FieldChannel should no be re-intialized. Did you call init(..) twice?"
    );
    ch.connect(self_, peer, talk_first);
}

/// Exchange serializable element with the other party.
pub fn exchange<F: CanonicalSerialize + CanonicalDeserialize>(f: F) -> F {
    get_ch!().exchange(f)
}

/// Exchange serializable element with the other party.
pub fn exchange_bytes(f: Vec<u8>) -> Vec<u8> {
    get_ch!().exchange_bytes(f)
}

/// Are you the first party in the MPC?
pub fn am_first() -> bool {
    get_ch!().talk_first
}

pub type Triple<F, G, H> = (MpcVal<F>, MpcVal<G>, MpcVal<H>);

/// Get a field triple
pub fn field_triple<F: Field>() -> Triple<F, F, F> {
    get_ch!().field_triple()
}

/// Copute a field product over SS data
pub fn field_mul<F: Field>(a: MpcVal<F>, b: MpcVal<F>) -> MpcVal<F> {
    get_ch!().field_mul(a, b)
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

#[derive(Debug)]
pub struct ChannelStats {
    pub bytes_sent: usize,
    pub bytes_recv: usize,
    pub exchanges: usize,
}

pub fn stats() -> ChannelStats {
    CH.lock().expect("Poisoned FieldChannel").stats()
}
