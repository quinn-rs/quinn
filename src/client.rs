use futures::{Async, Future, Poll};

use endpoint::Endpoint;
use packet::Packet;
use tls;
use types::Side;

use std::io;
use std::mem;
use std::net::{SocketAddr, ToSocketAddrs};

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

        let mut addr = None;
        for a in (server, port).to_socket_addrs().unwrap() {
            if let SocketAddr::V4(_) = a {
                addr = Some(a);
                break;
            }
        }

        let socket = UdpSocket::bind(&"0.0.0.0:0".parse().unwrap()).unwrap();
        socket.connect(&addr.unwrap()).unwrap();
        ConnectFuture::Waiting(
            Client {
                endpoint,
                socket,
                buf,
            },
            ConnectionState::Sending,
        )
    }
}

#[must_use = "futures do nothing unless polled"]
pub enum ConnectFuture {
    Waiting(Client, ConnectionState),
    Empty,
}

impl Future for ConnectFuture {
    type Item = Client;
    type Error = io::Error;
    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let mut waiting;
        let mut done = false;
        loop {
            waiting = true;
            if let ConnectFuture::Waiting(ref mut client, ref mut state) = *self {
                if let ConnectionState::Sending = *state {
                    let len = try_ready!(client.socket.poll_send(&client.buf));
                    debug_assert_eq!(len, client.buf.len());
                    let size = client.buf.capacity();
                    client.buf.resize(size, 0);

                    if !client.endpoint.is_handshaking() {
                        done = true;
                        break;
                    }

                    *state = ConnectionState::Receiving;
                    waiting = false;
                }

                if let ConnectionState::Receiving = *state {
                    let len = try_ready!(client.socket.poll_recv(&mut client.buf));
                    let packet = {
                        let partial = Packet::start_decode(&mut client.buf[..len]);
                        let key = client.endpoint.decode_key(&partial.header);
                        partial.finish(&key)
                    };

                    let req = match client.endpoint.handle_handshake(&packet) {
                        Some(p) => p,
                        None => {
                            return Err(io::Error::new(
                                io::ErrorKind::Other,
                                "no response to packet",
                            ));
                        }
                    };

                    req.encode(&client.endpoint.encode_key(&req.header), &mut client.buf);
                    *state = ConnectionState::Sending;
                    waiting = false;
                }
            }

            if waiting {
                break;
            }
        }

        if done {
            match mem::replace(self, ConnectFuture::Empty) {
                ConnectFuture::Waiting(client, _) => Ok(Async::Ready(client)),
                _ => panic!("invalid future state"),
            }
        } else {
            Ok(Async::NotReady)
        }
    }
}

pub enum ConnectionState {
    Sending,
    Receiving,
}
