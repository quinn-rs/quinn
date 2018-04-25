use futures::{Async, Future, Poll};

use rand::thread_rng;

use crypto::{self, PacketKey};
use frame::{Ack, AckFrame, Frame, StreamFrame};
use packet::{DRAFT_10, Header, KeyType, LongType, Packet};
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
        let mut tls = tls::Client::new();
        let handshake = tls.get_handshake(server).unwrap();

        let packet = Packet {
            header: Header::Long {
                ptype: LongType::Initial,
                conn_id: endpoint.dst_cid,
                version: DRAFT_10,
                number: endpoint.src_pn,
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

        endpoint.src_pn += 1;
        let handshake_key = crypto::PacketKey::for_client_handshake(packet.conn_id().unwrap());
        let mut buf = Vec::with_capacity(65536);
        packet.encode(&handshake_key, &mut buf);

        let addr = (server, port).to_socket_addrs().unwrap().next().unwrap();
        let sock = UdpSocket::bind(&"0.0.0.0:0".parse().unwrap()).unwrap();
        ConnectFuture {
            endpoint,
            tls,
            state: ConnectFutureState::InitialSent(sock.send_dgram(buf, &addr)),
        }
    }
}

#[must_use = "futures do nothing unless polled"]
pub struct ConnectFuture {
    endpoint: Endpoint,
    tls: tls::Client,
    state: ConnectFutureState,
}

impl Future for ConnectFuture {
    type Item = ();
    type Error = io::Error;
    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let mut waiting;
        let mut new = None;
        loop {
            waiting = true;
            if let ConnectFutureState::InitialSent(ref mut future) = self.state {
                let (sock, mut buf) = try_ready!(future.poll());
                let size = buf.capacity();
                buf.resize(size, 0);
                new = Some(ConnectFutureState::WaitingForResponse(sock.recv_dgram(buf)));
            };
            if let Some(state) = new.take() {
                waiting = false;
                self.state = state;
            }

            if let ConnectFutureState::WaitingForResponse(ref mut future) = self.state {
                let (sock, mut buf, len, addr) = try_ready!(future.poll());
                buf.truncate(len);

                let key_type = KeyType::ServerHandshake(self.endpoint.hs_cid);
                let packet = Packet::decode(key_type, &mut buf);
                self.endpoint.dst_cid = packet.conn_id().unwrap();
                let tls_frame = packet.payload.iter().filter_map(|f| {
                    match *f {
                        Frame::Stream(ref f) => Some(f),
                        _ => None,
                    }
                }).next().unwrap();
                let tls = self.tls.process_handshake_messages(&tls_frame.data).unwrap();

                let rsp = Packet {
                    header: Header::Long {
                        ptype: LongType::Handshake,
                        conn_id: packet.conn_id().unwrap(),
                        version: DRAFT_10,
                        number: self.endpoint.src_pn,
                    },
                    payload: vec![
                        Frame::Ack(AckFrame {
                            largest: packet.number(),
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
                };

                self.endpoint.src_pn += 1;
                let key = PacketKey::for_client_handshake(self.endpoint.hs_cid);
                rsp.encode(&key, &mut buf);
                new = Some(ConnectFutureState::InitialSent(sock.send_dgram(buf, &addr)));
            };
            if let Some(state) = new.take() {
                waiting = false;
                self.state = state;
            }

            if waiting {
                break;
            }
        }

        Ok(Async::NotReady)
    }
}

enum ConnectFutureState {
    InitialSent(SendDgram<Vec<u8>>),
    WaitingForResponse(RecvDgram<Vec<u8>>),
}
