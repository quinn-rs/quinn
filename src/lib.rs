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

use futures::Future;

use rand::{ThreadRng, thread_rng, Rng};

use self::frame::{Frame, StreamFrame};
use self::packet::{DRAFT_10, Header, LongType, Packet};

use std::net::ToSocketAddrs;

use tokio::net::UdpSocket;

pub use server::Server;

mod codec;
mod crypto;
mod frame;
mod packet;
mod server;
pub mod tls;
mod types;


pub struct Client {
    socket: Option<UdpSocket>,
    tls: tls::Client,
    buf: Option<Vec<u8>>,
    rng: ThreadRng,
}

impl Client {
    pub fn new() -> Self {
        let local = "0.0.0.0:0".parse().unwrap();
        Client {
            socket: Some(UdpSocket::bind(&local).unwrap()),
            tls: tls::Client::new(),
            buf: Some(vec![0u8; 65536]),
            rng: thread_rng(),
        }
    }

    pub fn connect(&mut self, server: &str, port: u16) {
        let remote = (server, port).to_socket_addrs().unwrap().next().unwrap();
        let handshake = self.tls.get_handshake(server).unwrap();
        let packet = Packet {
            header: Header::Long {
                ptype: LongType::Initial,
                conn_id: self.rng.gen(),
                version: DRAFT_10,
                number: self.rng.gen(),
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
        let mut buf = self.buf.take().unwrap();
        packet.encode(&handshake_key, &mut buf);
        let (_, mut buf, len, _) = self.socket.take()
            .unwrap()
            .send_dgram(buf, &remote)
            .and_then(|(sock, buf)| sock.recv_dgram(buf))
            .wait()
            .unwrap();
        buf.truncate(len);
    }
}
