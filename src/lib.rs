extern crate bytes;
extern crate futures;
extern crate rand;
extern crate rustls;
extern crate tokio;
extern crate tokio_io;
extern crate webpki;
extern crate webpki_roots;

use rand::{Rng, thread_rng};

use self::proto::{Frame, Header, LongType, Packet, QuicCodec, StreamFrame};

use std::net::ToSocketAddrs;

use tokio::net::{UdpFramed, UdpSocket};

mod proto;
mod tls;
mod types;

pub fn connect(server: &str, port: u16) {
    let mut client = tls::Client::new(server);
    let mut rng = thread_rng();
    let conn_id: u64 = rng.gen();
    let number: u32 = rng.gen();

    let handshake = client.get_handshake();
    let packet = Packet {
        header: Header::Long {
            ptype: LongType::Initial,
            conn_id,
            version: 1,
        },
        number,
        payload: vec![
            Frame::Stream(StreamFrame {
                id: 0,
                fin: false,
                offset: None,
                len: Some(handshake.len() as u64),
                data: handshake,
            }),
        ],
    };

    let local = "0.0.0.0:0".parse().unwrap();
    let sock = UdpSocket::bind(&local).unwrap();
    let remote = (server, port).to_socket_addrs().unwrap().next().unwrap();
    println!("{:?} -> {:?}", local, remote);
    sock.connect(&remote).unwrap();
    let framed = UdpFramed::new(sock, QuicCodec {});
}
