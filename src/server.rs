use futures::{Future, Poll};

use super::{QuicError, QuicResult};
use crypto::Secret;
use endpoint::Endpoint;
use packet::{LongType, Packet};
use parameters::ServerTransportParameters;
use tls;
use types::{ConnectionId, Side};

use std::collections::{HashMap, hash_map::Entry};
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;

use tokio::net::UdpSocket;

pub struct Server {
    socket: UdpSocket,
    tls_config: Arc<tls::ServerConfig>,
    in_buf: Vec<u8>,
    connections: HashMap<ConnectionId, (SocketAddr, Endpoint<tls::ServerSession>)>,
}

impl Server {
    pub fn new(ip: &str, port: u16, tls_config: tls::ServerConfig) -> QuicResult<Self> {
        let addr = (ip, port)
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| QuicError::General("no address found for host".into()))?;
        Ok(Server {
            socket: UdpSocket::bind(&addr)?,
            tls_config: Arc::new(tls_config),
            in_buf: vec![0u8; 65536],
            connections: HashMap::new(),
        })
    }

    pub fn run(&mut self) -> QuicResult<()> {
        self.wait()
    }
}

impl Future for Server {
    type Item = ();
    type Error = QuicError;

    fn poll(&mut self) -> Poll<(), QuicError> {
        loop {
            let connections = &mut self.connections;
            let (len, addr) = try_ready!(self.socket.poll_recv_from(&mut self.in_buf));
            let partial = Packet::start_decode(&mut self.in_buf[..len]);
            let dst_cid = partial.dst_cid();

            let cid = if partial.header.ptype() == Some(LongType::Initial) {
                let mut endpoint = Endpoint::new(
                    tls::server_session(&self.tls_config, &ServerTransportParameters::default()),
                    Side::Server,
                    Some(Secret::Handshake(dst_cid)),
                );

                let cid = endpoint.pick_unused_cid(|cid| connections.contains_key(&cid));
                connections.insert(cid, (addr, endpoint));
                cid
            } else {
                dst_cid
            };

            match connections.entry(cid) {
                Entry::Occupied(mut inner) => {
                    let &mut (addr, ref mut endpoint) = inner.get_mut();
                    endpoint.handle_partial(partial)?;

                    let mut sent = false;
                    if let Some(rsp) = endpoint.queued() {
                        let buf = endpoint.encode_packet(rsp)?;
                        try_ready!(self.socket.poll_send_to(&buf, &addr));
                        sent = true;
                    }

                    if sent {
                        endpoint.pop_queue();
                    }
                }
                Entry::Vacant(_) => panic!("connection ID {:?} unknown", dst_cid),
            }
        }
    }
}
