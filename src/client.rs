use futures::{Async, Future, Poll};

use endpoint::Endpoint;
use packet::Packet;
use tls::ClientTls;
use types::Side;

use std::io;
use std::net::ToSocketAddrs;

use tokio::net::UdpSocket;

pub struct QuicStream {}

impl QuicStream {
    pub fn connect(server: &str, port: u16) -> ConnectFuture {
        let mut endpoint = Endpoint::new(ClientTls::new(), Side::Client, None);
        let packet = endpoint.initial(server);
        let mut buf = Vec::with_capacity(65536);
        packet.encode(&endpoint.encode_key(&packet.header), &mut buf);

        let addr = (server, port).to_socket_addrs().unwrap().next().unwrap();
        let socket = UdpSocket::bind(&"0.0.0.0:0".parse().unwrap()).unwrap();
        socket.connect(&addr).unwrap();
        ConnectFuture {
            endpoint,
            socket,
            buf,
            state: ConnectionState::Sending,
        }
    }
}

#[must_use = "futures do nothing unless polled"]
pub struct ConnectFuture {
    endpoint: Endpoint<ClientTls>,
    socket: UdpSocket,
    buf: Vec<u8>,
    state: ConnectionState,
}

impl Future for ConnectFuture {
    type Item = ();
    type Error = io::Error;
    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let mut waiting;
        loop {
            waiting = true;
            if self.state == ConnectionState::Sending {
                let len = try_ready!(self.socket.poll_send(&self.buf));
                debug_assert_eq!(len, self.buf.len());
                let size = self.buf.capacity();
                self.buf.resize(size, 0);
                self.state = ConnectionState::Receiving;
                waiting = false;
            }

            if self.state == ConnectionState::Receiving {
                let len = try_ready!(self.socket.poll_recv(&mut self.buf));
                let packet = {
                    let partial = Packet::start_decode(&mut self.buf[..len]);
                    let key = self.endpoint.decode_key(&partial.header);
                    partial.finish(&key)
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

                req.encode(&self.endpoint.encode_key(&req.header), &mut self.buf);
                self.state = ConnectionState::Sending;
                waiting = false;
            }

            if waiting {
                break;
            }
        }

        Ok(Async::NotReady)
    }
}

#[derive(PartialEq)]
enum ConnectionState {
    Sending,
    Receiving,
}
