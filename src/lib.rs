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

use futures::{Future, Poll};

use rand::{thread_rng, Rng, ThreadRng};

use tls::{ServerConfig, ServerSession, Session};

use self::frame::{Frame, StreamFrame};
use self::proto::{DRAFT_10, Header, LongType, Packet};

use std::collections::{HashMap, hash_map::Entry};
use std::io::{self, Cursor};
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;

use tokio::net::UdpSocket;

mod codec;
mod crypto;
mod frame;
mod proto;
pub mod tls;
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

pub struct Server {
    socket: UdpSocket,
    tls_config: Arc<rustls::ServerConfig>,
    in_buf: Vec<u8>,
    out_buf: Vec<u8>,
    rng: ThreadRng,
    connections: HashMap<u64, Connection>,
}

impl Server {
    pub fn new(ip: &str, port: u16, tls_config: ServerConfig) -> Self {
        let addr = (ip, port).to_socket_addrs().unwrap().next().unwrap();
        Server {
            socket: UdpSocket::bind(&addr).unwrap(),
            tls_config: Arc::new(tls_config),
            in_buf: vec![0u8; 1600],
            out_buf: vec![0u8; 1600],
            rng: thread_rng(),
            connections: HashMap::new(),
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
            self.in_buf.truncate(size);
            let packet = Packet::decode(&mut self.in_buf);
            let conn_id = packet.header.conn_id().unwrap();
            match self.connections.entry(conn_id) {
                Entry::Occupied(_) => {
                    println!("connection found for {}", conn_id);
                }
                Entry::Vacant(entry) => {
                    let conn = entry.insert(Connection {
                        local_id: self.rng.gen(),
                        local_pn: self.rng.gen(),
                        addr: addr.clone(),
                        tls: ServerSession::new(&self.tls_config),
                    });

                    if let Some(rsp) = conn.received(&packet) {
                        self.out_buf.truncate(0);
                        let key = crypto::PacketKey::for_server_handshake(conn_id);
                        rsp.encode(&key, &mut self.out_buf);
                        try_ready!(self.socket.poll_send_to(&self.out_buf, &conn.addr));
                    }
                }
            };
        }
    }
}

struct Connection {
    local_id: u64,
    local_pn: u32,
    addr: SocketAddr,
    tls: ServerSession,
}

impl Connection {
    fn received(&mut self, p: &Packet) -> Option<Packet> {
        match p.header {
            Header::Long {
                ptype: LongType::Initial,
                ..
            } => self.handle_initial(p),
            _ => panic!("unhandled packet {:?}", p),
        }
    }

    fn handle_initial(&mut self, p: &Packet) -> Option<Packet> {
        let frame = match p.payload[0] {
            Frame::Stream(ref f) => f,
            _ => panic!("expected stream frame as first in payload"),
        };

        let conn_id = self.local_id;
        self.local_id += 1;
        let number = self.local_pn;
        self.local_pn += 1;
        let mut read = Cursor::new(&frame.data);
        let did_read = self.tls.read_tls(&mut read).expect("should read data");
        debug_assert_eq!(did_read, frame.data.len());
        self.tls.process_new_packets().expect("TLS errors found");
        let mut handshake = Vec::new();
        let wrote = self.tls
            .write_tls(&mut handshake)
            .expect("TLS errors found");
        println!("wrote handshake of {} bytes", wrote);

        Some(Packet {
            header: Header::Long {
                ptype: LongType::Handshake,
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
        })
    }
}
