use futures::{Future, Poll};

use crypto::Secret;
use endpoint::Endpoint;
use packet::{LongType, Packet};
use types::{ConnectionId, Side};
use tls;

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
    connections: HashMap<ConnectionId, (SocketAddr, Endpoint<tls::QuicServerTls>)>,
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
            let dst_cid = partial.dst_cid();

            let cid = if partial.header.ptype() == Some(LongType::Initial) {
                let mut endpoint = Endpoint::new(
                    tls::server_session(&self.tls_config),
                    Side::Server,
                    Some(Secret::Handshake(dst_cid)),
                );

                while self.connections.contains_key(&endpoint.src_cid) {
                    endpoint.update_src_cid();
                }

                let cid = endpoint.src_cid;
                self.connections.insert(endpoint.src_cid, (addr, endpoint));
                cid
            } else {
                dst_cid
            };

            match self.connections.entry(cid) {
                Entry::Occupied(mut inner) => {
                    let &mut (addr, ref mut endpoint) = inner.get_mut();
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
                Entry::Vacant(_) => panic!("connection ID {:?} unknown", dst_cid),
            }
        }
    }
}
