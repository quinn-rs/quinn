use futures::{Async, Future, Poll};

use packet::Packet;
use tls::ClientTls;
use types::{Endpoint, Side};

use std::io;
use std::net::ToSocketAddrs;

use tokio::net::{RecvDgram, SendDgram, UdpSocket};

pub use server::Server;

pub struct QuicStream {}

impl QuicStream {
    pub fn connect(server: &str, port: u16) -> ConnectFuture {
        let mut endpoint = Endpoint::new(ClientTls::new(), Side::Client, None);
        let packet = endpoint.initial(server);
        let mut buf = Vec::with_capacity(65536);
        packet.encode(&endpoint.encode_key(&packet.header), &mut buf);

        let addr = (server, port).to_socket_addrs().unwrap().next().unwrap();
        let sock = UdpSocket::bind(&"0.0.0.0:0".parse().unwrap()).unwrap();
        ConnectFuture {
            endpoint,
            future: ConnectFutureState::InitialSent(sock.send_dgram(buf, &addr)),
        }
    }
}

#[must_use = "futures do nothing unless polled"]
pub struct ConnectFuture {
    endpoint: Endpoint<ClientTls>,
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
                    let key = self.endpoint.decode_key(&decode.header);
                    decode.finish(&key)
                };

                let req = match self.endpoint.handle_handshake(&packet) {
                    Some(p) => p,
                    None => {
                        return Err(io::Error::new(
                            io::ErrorKind::Other,
                            "no response to packet",
                        ));
                    }
                };

                req.encode(&self.endpoint.encode_key(&req.header), &mut buf);
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

enum ConnectFutureState {
    InitialSent(SendDgram<Vec<u8>>),
    WaitingForResponse(RecvDgram<Vec<u8>>),
}
