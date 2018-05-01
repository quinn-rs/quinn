use futures::{Future, Poll};

use crypto::Secret;
use packet::{LongType, Packet};
use types::{Endpoint, Side};
use tls::{self, ServerTls};

use std::collections::{HashMap, hash_map::Entry};
use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;

use tokio::net::UdpSocket;

pub struct Server {
    socket: UdpSocket,
    tls_config: Arc<tls::ServerConfig>,
    in_buf: Vec<u8>,
    out_buf: Vec<u8>,
    connections: HashMap<u64, (SocketAddr, Endpoint<ServerTls>)>,
}

impl Server {
    pub fn new(ip: &str, port: u16, tls_config: tls::ServerConfig) -> Self {
        let addr = (ip, port).to_socket_addrs().unwrap().next().unwrap();
        Server {
            socket: UdpSocket::bind(&addr).unwrap(),
            tls_config: Arc::new(tls_config),
            in_buf: vec![0u8; 65536],
            out_buf: vec![0u8; 65536],
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
            let (len, addr) = try_ready!(self.socket.poll_recv_from(&mut self.in_buf));
            let partial = Packet::start_decode(&mut self.in_buf[..len]);
            let conn_id = partial.conn_id().unwrap();
            match self.connections.entry(conn_id) {
                Entry::Occupied(_) => {
                    println!("connection found for {}", conn_id);
                }
                Entry::Vacant(entry) => {
                    let endpoint = Endpoint::new(
                        ServerTls::with_config(&self.tls_config),
                        Side::Server,
                        Some(Secret::Handshake(conn_id))
                    );
                    let &mut (addr, ref mut endpoint) = entry.insert((addr, endpoint));
                    let key = endpoint.decode_key(&partial.header);
                    let packet = partial.finish(&key);

                    let rsp = match packet.ptype() {
                        Some(LongType::Initial) => endpoint.handle_handshake(&packet),
                        _ => panic!("unhandled packet {:?}", packet),
                    };

                    if let Some(rsp) = rsp {
                        self.out_buf.truncate(0);
                        rsp.encode(&endpoint.encode_key(&rsp.header), &mut self.out_buf);
                        try_ready!(self.socket.poll_send_to(&self.out_buf, &addr));
                    }
                }
            };
        }
    }
}

