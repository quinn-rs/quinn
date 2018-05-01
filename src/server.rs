use futures::{Future, Poll};

use frame::{Ack, AckFrame, Frame, StreamFrame};
use packet::{LongType, Packet};
use types::Endpoint;
use tls::{self, Secret, ServerTls};

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
    connections: HashMap<u64, ServerStreamState>,
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
                    let state =
                        entry.insert(ServerStreamState::new(&addr, &self.tls_config, conn_id));
                    let key = state.tls.decode_key(&partial.header);
                    let packet = partial.finish(&key);

                    if let Some(rsp) = state.handle(&packet) {
                        self.out_buf.truncate(0);
                        rsp.encode(&state.tls.encode_key(&rsp.header), &mut self.out_buf);
                        try_ready!(self.socket.poll_send_to(&self.out_buf, &state.addr));
                    }
                }
            };
        }
    }
}

pub(crate) struct ServerStreamState {
    endpoint: Endpoint,
    addr: SocketAddr,
    tls: ServerTls,
}

impl ServerStreamState {
    pub(crate) fn new(addr: &SocketAddr, tls_config: &Arc<tls::ServerConfig>, hs_cid: u64) -> Self {
        Self {
            endpoint: Endpoint::new(),
            addr: addr.clone(),
            tls: ServerTls::with_config(tls_config, Secret::Handshake(hs_cid)),
        }
    }

    pub(crate) fn handle(&mut self, p: &Packet) -> Option<Packet> {
        match p.ptype() {
            Some(LongType::Initial) => self.handle_initial(p),
            _ => panic!("unhandled packet {:?}", p),
        }
    }

    fn handle_initial(&mut self, p: &Packet) -> Option<Packet> {
        let conn_id = p.conn_id().unwrap();
        self.endpoint.dst_cid = conn_id;

        let frame = match p.payload[0] {
            Frame::Stream(ref f) => f,
            _ => panic!("expected stream frame as first in payload"),
        };
        let handshake = self.tls.get_handshake(&frame.data).unwrap();

        Some(self.endpoint.build_handshake_packet(vec![
            Frame::Ack(AckFrame {
                largest: p.number(),
                ack_delay: 0,
                blocks: vec![Ack::Ack(0)],
            }),
            Frame::Stream(StreamFrame {
                id: 0,
                fin: false,
                offset: 0,
                len: Some(handshake.len() as u64),
                data: handshake,
            }),
        ]))
    }
}
