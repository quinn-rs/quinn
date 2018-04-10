extern crate bytes;
extern crate futures;
extern crate rand;
extern crate rustls;
extern crate tokio;
extern crate tokio_io;
extern crate webpki;
extern crate webpki_roots;

use futures::Future;

use rand::{Rng, thread_rng};

use self::codec::{BufLen, Codec};
use self::frame::{Frame, PaddingFrame, StreamFrame};
use self::proto::{DRAFT_10, Header, LongType, Packet};

use std::net::{SocketAddr, ToSocketAddrs};

use tokio::net::UdpSocket;

mod codec;
mod frame;
mod proto;
mod tls;
mod types;

pub fn connect(server: &str, port: u16) {
    let mut client = tls::Client::new(server);
    let mut rng = thread_rng();
    let conn_id: u64 = rng.gen();
    let number: u32 = rng.gen();

    let handshake = client.get_handshake();
    let mut packet = Packet {
        header: Header::Long {
            ptype: LongType::Initial,
            conn_id,
            version: DRAFT_10,
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

    let len = packet.buf_len();
    if len < 1200 {
        packet.payload.push(Frame::Padding(PaddingFrame(1200 - len)));
    }

    let local = "0.0.0.0:0".parse().unwrap();
    let sock = UdpSocket::bind(&local).unwrap();
    let remote = (server, port).to_socket_addrs().unwrap().next().unwrap();
    println!("{:?} -> {:?}", local, remote);

    let mut buf = Vec::with_capacity(1200);
    packet.encode(&mut buf);
    let (mut sock, mut buf, len, remote) = sock.send_dgram(buf, &remote)
        .and_then(|(sock, buf)| sock.recv_dgram(buf))
        .wait()
        .unwrap();
    println!("{:?} {:?} {:?} {:?}", sock, len, remote, buf);
}
