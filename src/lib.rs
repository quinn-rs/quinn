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

use rand::{thread_rng, Rng};

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

pub fn connect(server: &str, port: u16) {
    let mut client = tls::Client::new();
    let mut rng = thread_rng();
    let conn_id: u64 = rng.gen();
    let number: u32 = rng.gen();

    let handshake = client.get_handshake(server).unwrap();
    let packet = Packet {
        header: Header::Long {
            ptype: LongType::Initial,
            conn_id,
            version: DRAFT_10,
            number,
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
    println!("PACKET {:?}", packet);

    let local = "0.0.0.0:0".parse().unwrap();
    let sock = UdpSocket::bind(&local).unwrap();
    let remote = (server, port).to_socket_addrs().unwrap().next().unwrap();
    println!("{:?} -> {:?}", local, remote);

    let handshake_key = crypto::PacketKey::for_client_handshake(conn_id);
    let mut buf = Vec::new();
    packet.encode(&handshake_key, &mut buf);
    let (sock, mut buf, len, remote) = sock.send_dgram(buf, &remote)
        .and_then(|(sock, buf)| sock.recv_dgram(buf))
        .wait()
        .unwrap();
    buf.truncate(len);
    println!("{:?} {:?} {:?} {:?}", sock, len, remote, buf);
}
