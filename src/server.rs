use futures::{Future, Poll};

use crypto::PacketKey;
use frame::{Ack, AckFrame, Frame, StreamFrame};
use packet::{DRAFT_10, Header, LongType, Packet};
use types::{Endpoint, TransportParameter};
use tls::{self, ServerConfig, ServerSession, ServerTransportParameters};

use std::collections::{HashMap, hash_map::Entry};
use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;

use tokio::net::UdpSocket;

pub struct Server {
    socket: UdpSocket,
    tls_config: Arc<ServerConfig>,
    in_buf: Vec<u8>,
    out_buf: Vec<u8>,
    connections: HashMap<u64, ServerStreamState>,
}

impl Server {
    pub fn new(ip: &str, port: u16, tls_config: ServerConfig) -> Self {
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
            let partial = Packet::start_decode(&self.in_buf[..len]);
            let conn_id = partial.conn_id().unwrap();
            match self.connections.entry(conn_id) {
                Entry::Occupied(_) => {
                    println!("connection found for {}", conn_id);
                }
                Entry::Vacant(entry) => {
                    let state = entry.insert(ServerStreamState::new(&addr, &self.tls_config));
                    let key = PacketKey::for_client_handshake(conn_id);
                    let packet = partial.finish(&key, &mut self.in_buf[..len]);

                    if let Some(rsp) = state.handle(&packet) {
                        self.out_buf.truncate(0);
                        let key = PacketKey::for_server_handshake(conn_id);
                        rsp.encode(&key, &mut self.out_buf);
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
    tls: ServerSession,
}

impl ServerStreamState {
    pub(crate) fn new(addr: &SocketAddr, tls_config: &Arc<tls::ServerConfig>) -> Self {
        Self {
            endpoint: Endpoint::new(),
            addr: addr.clone(),
            tls: ServerSession::new(
                tls_config,
                ServerTransportParameters {
                    negotiated_version: DRAFT_10,
                    supported_versions: vec![DRAFT_10],
                    parameters: tls::encode_transport_parameters(&vec![
                        TransportParameter::InitialMaxStreamData(131072),
                        TransportParameter::InitialMaxData(1048576),
                        TransportParameter::IdleTimeout(300),
                    ]),
                },
            ),
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
        self.endpoint.hs_cid = conn_id;

        let frame = match p.payload[0] {
            Frame::Stream(ref f) => f,
            _ => panic!("expected stream frame as first in payload"),
        };
        let handshake = self.tls.get_handshake(&frame.data).unwrap();

        let number = self.endpoint.src_pn;
        self.endpoint.src_pn += 1;
        Some(Packet {
            header: Header::Long {
                ptype: LongType::Handshake,
                conn_id: self.endpoint.dst_cid,
                version: DRAFT_10,
                number,
            },
            payload: vec![
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
            ],
        })
    }
}
