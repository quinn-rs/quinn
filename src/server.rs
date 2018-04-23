use futures::{Future, Poll};

use rand::{thread_rng, Rng, ThreadRng};

use crypto::PacketKey;
use frame::{Frame, StreamFrame};
use packet::{DRAFT_10, Header, LongType, Packet};
use tls::{ServerConfig, ServerSession, Session};

use std::collections::{HashMap, hash_map::Entry};
use std::io::{self, Cursor};
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;

use tokio::net::UdpSocket;

pub struct Server {
    socket: UdpSocket,
    tls_config: Arc<ServerConfig>,
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
            self.in_buf.resize(1600, 0);

            let conn_id = packet.conn_id().unwrap();
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
                        let key = PacketKey::for_server_handshake(conn_id);
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
        match p.ptype() {
            Some(LongType::Initial) => self.handle_initial(p),
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
