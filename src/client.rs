use futures::{Async, Future, Poll};

use endpoint::Endpoint;
use packet::Packet;
use tls;
use types::Side;

use std::io;
use std::net::ToSocketAddrs;

use tokio::net::UdpSocket;

pub struct Client {
    endpoint: Endpoint<tls::QuicClientTls>,
    socket: UdpSocket,
    buf: Vec<u8>,
}

impl Client {
    pub fn connect(server: &str, port: u16) -> ConnectFuture {
        let mut endpoint = Endpoint::new(tls::client_session(None), Side::Client, None);
        let packet = endpoint.initial(server);
        let mut buf = Vec::with_capacity(65536);
        packet.encode(&endpoint.encode_key(&packet.header), &mut buf);

        let addr = (server, port).to_socket_addrs().unwrap().next().unwrap();
        let socket = UdpSocket::bind(&"0.0.0.0:0".parse().unwrap()).unwrap();
        socket.connect(&addr).unwrap();
        ConnectFuture {
            client: Client {
                endpoint,
                socket,
                buf,
            },
            state: ConnectionState::Sending,
        }
    }
}

#[must_use = "futures do nothing unless polled"]
pub struct ConnectFuture {
    client: Client,
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
                let len = try_ready!(self.client.socket.poll_send(&self.client.buf));
                debug_assert_eq!(len, self.client.buf.len());
                let size = self.client.buf.capacity();
                self.client.buf.resize(size, 0);
                self.state = ConnectionState::Receiving;
                waiting = false;
            }

            if self.state == ConnectionState::Receiving {
                let len = try_ready!(self.client.socket.poll_recv(&mut self.client.buf));
                let packet = {
                    let partial = Packet::start_decode(&mut self.client.buf[..len]);
                    let key = self.client.endpoint.decode_key(&partial.header);
                    partial.finish(&key)
                };

                let req = match self.client.endpoint.handle_handshake(&packet) {
                    Some(p) => p,
                    None => {
                        return Err(io::Error::new(
                            io::ErrorKind::Other,
                            "no response to packet",
                        ));
                    }
                };

                req.encode(&self.client.endpoint.encode_key(&req.header), &mut self.client.buf);
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
