extern crate bytes;
#[macro_use]
extern crate futures;
extern crate rand;
extern crate ring;
extern crate rustls;
extern crate tokio;
extern crate tokio_io;
extern crate webpki;
extern crate webpki_roots;

use futures::{Async, Future, Poll};

use rand::{thread_rng, Rng};

use self::frame::{Frame, StreamFrame};
use self::packet::{DRAFT_10, Header, LongType, Packet};

use std::io;
use std::net::ToSocketAddrs;

use tokio::net::{RecvDgram, SendDgram, UdpSocket};

pub use server::Server;

mod codec;
mod crypto;
mod frame;
mod packet;
mod server;
pub mod tls;
mod types;


pub struct QuicStream {}

impl QuicStream {
    pub fn connect(server: &str, port: u16) -> ConnectFuture {
        let mut rng = thread_rng();
        let mut tls = tls::Client::new();
        let handshake = tls.get_handshake(server).unwrap();
        let packet = Packet {
            header: Header::Long {
                ptype: LongType::Initial,
                conn_id: rng.gen(),
                version: DRAFT_10,
                number: rng.gen(),
            },
            payload: vec![
                Frame::Stream(StreamFrame {
                    id: 0,
                    fin: false,
                    offset: 0,
                    len: Some(handshake.len() as u64),
                    data: handshake,
                }),
            ],
        };

        let handshake_key = crypto::PacketKey::for_client_handshake(packet.conn_id().unwrap());
        let mut buf = Vec::with_capacity(65536);
        packet.encode(&handshake_key, &mut buf);

        let addr = (server, port).to_socket_addrs().unwrap().next().unwrap();
        let sock = UdpSocket::bind(&"0.0.0.0:0".parse().unwrap()).unwrap();
        ConnectFuture {
            state: ConnectFutureState::InitialSent(sock.send_dgram(buf, &addr)),
        }
    }
}

#[must_use = "futures do nothing unless polled"]
pub struct ConnectFuture {
    state: ConnectFutureState,
}

impl Future for ConnectFuture {
    type Item = ();
    type Error = io::Error;
    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let mut new = None;
        if let ConnectFutureState::InitialSent(ref mut future) = self.state {
            let (sock, mut buf) = try_ready!(future.poll());
            let size = buf.capacity();
            buf.resize(size, 0);
            new = Some(ConnectFutureState::WaitingForResponse(sock.recv_dgram(buf)));
        };
        if let Some(state) = new.take() {
            self.state = state;
        }

        if let ConnectFutureState::WaitingForResponse(ref mut future) = self.state {
            let (sock, mut buf, len, addr) = try_ready!(future.poll());
            buf.truncate(len);
            new = Some(ConnectFutureState::InitialSent(sock.send_dgram(buf, &addr)));
        };
        if let Some(state) = new.take() {
            self.state = state;
        }

        Ok(Async::NotReady)
    }
}

enum ConnectFutureState {
    InitialSent(SendDgram<Vec<u8>>),
    WaitingForResponse(RecvDgram<Vec<u8>>),
}
