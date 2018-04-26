use futures::{Async, Future, Poll};

use rand::thread_rng;

use crypto::{self, PacketKey};
use frame::{Ack, AckFrame, Frame, StreamFrame};
use packet::{DRAFT_10, Header, LongType, Packet};
use tls;
use types::Endpoint;

use std::io;
use std::net::ToSocketAddrs;

use tokio::net::{RecvDgram, SendDgram, UdpSocket};

pub use server::Server;

pub struct QuicStream {}

impl QuicStream {
    pub fn connect(server: &str, port: u16) -> ConnectFuture {
        let mut endpoint = Endpoint::new(&mut thread_rng());
        endpoint.hs_cid = endpoint.dst_cid;
        let mut state = ClientStreamState {
            endpoint,
            tls: tls::Client::new(),
        };

        let packet = state.initial(server);
        let handshake_key = crypto::PacketKey::for_client_handshake(packet.conn_id().unwrap());
        let mut buf = Vec::with_capacity(65536);
        packet.encode(&handshake_key, &mut buf);

        let addr = (server, port).to_socket_addrs().unwrap().next().unwrap();
        let sock = UdpSocket::bind(&"0.0.0.0:0".parse().unwrap()).unwrap();
        ConnectFuture {
            state,
            future: ConnectFutureState::InitialSent(sock.send_dgram(buf, &addr)),
        }
    }
}

#[must_use = "futures do nothing unless polled"]
pub struct ConnectFuture {
    state: ClientStreamState,
    future: ConnectFutureState,
}

impl Future for ConnectFuture {
    type Item = ();
    type Error = io::Error;
    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let mut waiting;
        let mut new = None;
        loop {
            waiting = true;
            if let ConnectFutureState::InitialSent(ref mut future) = self.future {
                let (sock, mut buf) = try_ready!(future.poll());
                let size = buf.capacity();
                buf.resize(size, 0);
                new = Some(ConnectFutureState::WaitingForResponse(sock.recv_dgram(buf)));
            };
            if let Some(future) = new.take() {
                waiting = false;
                self.future = future;
            }

            if let ConnectFutureState::WaitingForResponse(ref mut future) = self.future {
                let (sock, mut buf, len, addr) = try_ready!(future.poll());
                buf.truncate(len);

                let key = PacketKey::for_server_handshake(self.state.endpoint.hs_cid);
                let packet = Packet::start_decode(&mut buf).finish(&key, &mut buf);

                let req = match self.state.handle(&packet) {
                    Some(p) => p,
                    None => {
                        return Err(io::Error::new(
                            io::ErrorKind::Other,
                            "no response to packet",
                        ));
                    }
                };

                let key = PacketKey::for_client_handshake(self.state.endpoint.hs_cid);
                req.encode(&key, &mut buf);
                new = Some(ConnectFutureState::InitialSent(sock.send_dgram(buf, &addr)));
            };
            if let Some(future) = new.take() {
                waiting = false;
                self.future = future;
            }

            if waiting {
                break;
            }
        }

        Ok(Async::NotReady)
    }
}

pub(crate) struct ClientStreamState {
    pub(crate) endpoint: Endpoint,
    pub(crate) tls: tls::Client,
}

impl ClientStreamState {
    pub(crate) fn initial(&mut self, server: &str) -> Packet {
        let number = self.endpoint.src_pn;
        self.endpoint.src_pn += 1;
        let handshake = self.tls.get_handshake(server).unwrap();

        Packet {
            header: Header::Long {
                ptype: LongType::Initial,
                conn_id: self.endpoint.dst_cid,
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
        }
    }

    pub(crate) fn handle(&mut self, rsp: &Packet) -> Option<Packet> {
        self.endpoint.dst_cid = rsp.conn_id().unwrap();
        let tls_frame = rsp.payload
            .iter()
            .filter_map(|f| match *f {
                Frame::Stream(ref f) => Some(f),
                _ => None,
            })
            .next()
            .unwrap();
        let tls = self.tls
            .process_handshake_messages(&tls_frame.data)
            .unwrap();

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
                    largest: rsp.number(),
                    ack_delay: 0,
                    blocks: vec![Ack::Ack(0)],
                }),
                Frame::Stream(StreamFrame {
                    id: 0,
                    fin: false,
                    offset: 0,
                    len: Some(tls.len() as u64),
                    data: tls,
                }),
            ],
        })
    }
}

enum ConnectFutureState {
    InitialSent(SendDgram<Vec<u8>>),
    WaitingForResponse(RecvDgram<Vec<u8>>),
}
