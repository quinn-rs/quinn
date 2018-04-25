use futures::{Async, Future, Poll};

use rand::thread_rng;

use crypto;
use frame::{Frame, StreamFrame};
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

        let handshake_key = crypto::PacketKey::for_client_handshake(packet.conn_id().unwrap());
        let mut buf = Vec::with_capacity(65536);
        packet.encode(&handshake_key, &mut buf);

        let addr = (server, port).to_socket_addrs().unwrap().next().unwrap();
        let sock = UdpSocket::bind(&"0.0.0.0:0".parse().unwrap()).unwrap();
        ConnectFuture {
            endpoint,
            state: ConnectFutureState::InitialSent(sock.send_dgram(buf, &addr)),
        }
    }
}

#[must_use = "futures do nothing unless polled"]
pub struct ConnectFuture {
    endpoint: Endpoint,
    state: ConnectFutureState,
}

impl Future for ConnectFuture {
    type Item = ();
    type Error = io::Error;
    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let mut new = None;
        if let ConnectFutureState::InitialSent(ref mut future) = self.state {
            let (sock, mut buf) = try_ready!(future.poll());
            let size = buf.capacity();
            buf.resize(size, 0);
            new = Some(ConnectFutureState::WaitingForResponse(sock.recv_dgram(buf)));
        };
        if let Some(state) = new.take() {
            self.state = state;
        }

        if let ConnectFutureState::WaitingForResponse(ref mut future) = self.state {
            let (sock, mut buf, len, addr) = try_ready!(future.poll());
            buf.truncate(len);

            let key_type = KeyType::ServerHandshake(self.endpoint.hs_cid);
            let packet = Packet::decode(key_type, &mut buf);
            println!("PACKET: {:?}", packet);

            new = Some(ConnectFutureState::InitialSent(sock.send_dgram(buf, &addr)));
        };
        if let Some(state) = new.take() {
            self.state = state;
        }

        Ok(Async::NotReady)
    }
}

enum ConnectFutureState {
    InitialSent(SendDgram<Vec<u8>>),
    WaitingForResponse(RecvDgram<Vec<u8>>),
}
