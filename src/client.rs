use futures::{Async, Future, Poll};

use super::{QuicError, QuicResult};
use endpoint::Endpoint;
use packet::Packet;
use tls;
use types::Side;

use std::mem;
use std::net::{SocketAddr, ToSocketAddrs};

use tokio::net::UdpSocket;

pub struct Client {
    endpoint: Endpoint<tls::QuicClientTls>,
    socket: UdpSocket,
    buf: Vec<u8>,
}

impl Client {
    pub fn connect(server: &str, port: u16) -> QuicResult<ConnectFuture> {
        let endpoint = Endpoint::new(tls::client_session(None), Side::Client, None);
        ConnectFuture::new(endpoint, server, port)
    }
}

#[must_use = "futures do nothing unless polled"]
pub enum ConnectFuture {
    Waiting(Client, ConnectionState),
    Empty,
}

impl ConnectFuture {
    pub(crate) fn new(
        mut endpoint: Endpoint<tls::QuicClientTls>,
        server: &str,
        port: u16,
    ) -> QuicResult<Self> {
        let packet = endpoint.initial(server)?;
        let mut buf = Vec::with_capacity(65536);
        packet.encode(&endpoint.encode_key(&packet.header), &mut buf)?;

        let mut addr = None;
        for a in (server, port).to_socket_addrs()? {
            if let SocketAddr::V4(_) = a {
                addr = Some(a);
                break;
            }
        }

        let socket = UdpSocket::bind(&"0.0.0.0:0".parse()?)?;
        socket.connect(&addr.ok_or_else(|| {
            QuicError::General("no IPv4 address found for host".into())
        })?)?;
        Ok(ConnectFuture::Waiting(
            Client {
                endpoint,
                socket,
                buf,
            },
            ConnectionState::Sending,
        ))
    }
}

impl Future for ConnectFuture {
    type Item = Client;
    type Error = QuicError;
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
                        partial.finish(&key)?
                    };

                    let req = match client.endpoint.handle_handshake(&packet)? {
                        Some(p) => p,
                        None => {
                            return Err(QuicError::General("no response to packet".into()));
                        }
                    };

                    req.encode(&client.endpoint.encode_key(&req.header), &mut client.buf)?;
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
