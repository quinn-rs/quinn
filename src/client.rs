use futures::{Async, Future, Poll};

use crypto::Secret;
use frame::{Ack, AckFrame, Frame, StreamFrame};
use packet::Packet;
use tls::ClientTls;
use types::Endpoint;

use std::io;
use std::net::ToSocketAddrs;

use tokio::net::{RecvDgram, SendDgram, UdpSocket};

pub use server::Server;

pub struct QuicStream {}

impl QuicStream {
    pub fn connect(server: &str, port: u16) -> ConnectFuture {
        let mut state = ClientStreamState::new();
        let packet = state.initial(server);
        let mut buf = Vec::with_capacity(65536);
        packet.encode(&state.tls.encode_key(&packet.header), &mut buf);

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
                let packet = {
                    let mut pbuf = &mut buf[..len];
                    let decode = Packet::start_decode(pbuf);
                    let key = self.state.tls.decode_key(&decode.header);
                    decode.finish(&key)
                };

                let req = match self.state.handle(&packet) {
                    Some(p) => p,
                    None => {
                        return Err(io::Error::new(
                            io::ErrorKind::Other,
                            "no response to packet",
                        ));
                    }
                };

                req.encode(&self.state.tls.encode_key(&req.header), &mut buf);
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
    pub(crate) tls: ClientTls,
}

impl ClientStreamState {
    pub fn new() -> Self {
        let endpoint = Endpoint::new();
        let secret = Secret::Handshake(endpoint.dst_cid);

        Self {
            endpoint,
            tls: ClientTls::new(secret),
        }
    }

    pub(crate) fn initial(&mut self, server: &str) -> Packet {
        let handshake = self.tls.get_handshake(server).unwrap();
        self.endpoint.build_initial_packet(vec![
            Frame::Stream(StreamFrame {
                id: 0,
                fin: false,
                offset: 0,
                len: Some(handshake.len() as u64),
                data: handshake,
            }),
        ])
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

        let handshake = self.tls
            .process_handshake_messages(&tls_frame.data)
            .unwrap();

        Some(self.endpoint.build_handshake_packet(vec![
            Frame::Ack(AckFrame {
                largest: rsp.number(),
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

enum ConnectFutureState {
    InitialSent(SendDgram<Vec<u8>>),
    WaitingForResponse(RecvDgram<Vec<u8>>),
}
