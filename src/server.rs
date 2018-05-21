use futures::{Future, Poll};

use super::{QuicError, QuicResult};
use conn_state::ConnectionState;
use crypto::Secret;
use packet::{LongType, Packet};
use parameters::ServerTransportParameters;
use tls;
use types::ConnectionId;

use std::collections::{HashMap, hash_map::Entry};
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;

use tokio_udp::UdpSocket;

pub struct Server {
    socket: UdpSocket,
    tls_config: Arc<tls::ServerConfig>,
    in_buf: Vec<u8>,
    connections: HashMap<ConnectionId, (SocketAddr, ConnectionState<tls::ServerSession>)>,
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
            debug!("incoming packet: {:?} {:?}", addr, partial.header);
            let dst_cid = partial.dst_cid();

            let cid = if partial.header.ptype() == Some(LongType::Initial) {
                let mut conn_state = ConnectionState::new(
                    tls::server_session(&self.tls_config, &ServerTransportParameters::default()),
                    Some(Secret::Handshake(dst_cid)),
                );

                let cid = conn_state.pick_unused_cid(|cid| connections.contains_key(&cid));
                connections.insert(cid, (addr, conn_state));
                cid
            } else {
                dst_cid
            };

            match connections.entry(cid) {
                Entry::Occupied(mut inner) => {
                    let &mut (addr, ref mut conn_state) = inner.get_mut();
                    if let Err(e) = conn_state.handle_partial(partial) {
                        error!("error from handle_partial: {:?}", e);
                        continue;
                    }

                    let mut sent = false;
                    match conn_state.queued() {
                        Ok(Some(buf)) => {
                            debug!("send response to {:?} ({})", addr, buf.len());
                            try_ready!(self.socket.poll_send_to(&buf, &addr));
                            debug!("response to {:?} sent", addr);
                            sent = true;
                        }
                        Err(e) => {
                            error!("error from queued: {:?}", e);
                            continue;
                        }
                        _ => {}
                    }

                    if sent {
                        conn_state.pop_queue();
                    }
                }
                Entry::Vacant(_) => debug!("connection ID {:?} unknown", dst_cid),
            }
        }
    }
}
