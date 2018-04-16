extern crate bytes;
#[macro_use]
extern crate futures;
extern crate rand;
extern crate rustls;
extern crate tokio;
extern crate tokio_io;
extern crate webpki;
extern crate webpki_roots;

use futures::{Future, Poll};

use rand::{Rng, thread_rng};

use self::codec::{BufLen, Codec};
use self::frame::{Frame, PaddingFrame, StreamFrame};
use self::proto::{DRAFT_10, Header, LongType, Packet};

use std::io;
use std::net::{ToSocketAddrs};

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
            number,
        },
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
    let (sock, mut buf, len, remote) = sock.send_dgram(buf, &remote)
        .and_then(|(sock, buf)| sock.recv_dgram(buf))
        .wait()
        .unwrap();
    buf.truncate(len);
    println!("{:?} {:?} {:?} {:?}", sock, len, remote, buf);
}

pub struct Server {
    socket: UdpSocket,
    in_buf: Vec<u8>,
    out_buf: Vec<u8>,
}

impl Server {
    pub fn new(ip: &str, port: u16) -> Self {
        let addr = (ip, port).to_socket_addrs().unwrap().next().unwrap();
        Server {
            socket: UdpSocket::bind(&addr).unwrap(),
            in_buf: vec![0u8; 1600],
            out_buf: vec![20u8, 2, 19, 83, 2, 1, 20, 16, 13, 6, 19, 81],
        }
    }

    pub fn run(&mut self) {
        self.wait().unwrap();
    }
}

impl Future for Server {
    type Item = ();
    type Error = io::Error;

    fn poll(&mut self) -> Poll<(), io::Error> {
        loop {
            let (size, addr) = try_ready!(self.socket.poll_recv_from(&mut self.in_buf));
            println!("remote {:?} ({}): {:?}", addr, size, &self.in_buf[..size]);
            let msg = &self.out_buf[..self.out_buf.len()];
            let sent = try_ready!(self.socket.poll_send_to(msg, &addr));
            println!("responded with {} bytes", sent);
        }
    }
}
