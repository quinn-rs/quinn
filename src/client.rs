use futures::{Async, Future, Poll};

use super::{QuicError, QuicResult};
use endpoint::Endpoint;
use packet::Packet;
use tls;
use types::Side;

use std::net::{SocketAddr, ToSocketAddrs};

use tokio::net::UdpSocket;

pub struct Client {
    endpoint: Endpoint<tls::QuicClientTls>,
    socket: UdpSocket,
    buf: Vec<u8>,
    msg_len: Option<usize>,
}

impl Client {
    pub fn connect(server: &str, port: u16) -> QuicResult<ClientFuture> {
        let endpoint = Endpoint::new(tls::client_session(None), Side::Client, None);
        connect(endpoint, server, port)
    }
}

pub(crate) fn connect(
    mut endpoint: Endpoint<tls::QuicClientTls>,
    server: &str,
    port: u16,
) -> QuicResult<ClientFuture> {
    endpoint.initial(server)?;
    let packet = endpoint.queued().unwrap();
    let mut buf = vec![0u8; 65536];
    let msg_len = Some(packet.encode(&endpoint.encode_key(&packet.header), &mut buf)?);

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
    Ok(ClientFuture {
        client: Some(Client {
            endpoint,
            socket,
            buf,
            msg_len,
        }),
        check: Box::new(|c: Client| !c.endpoint.is_handshaking()),
    })
}

#[must_use = "futures do nothing unless polled"]
pub struct ClientFuture {
    client: Option<Client>,
    check: Box<Fn(Client) -> bool>,
}

impl Future for ClientFuture {
    type Item = Client;
    type Error = QuicError;
    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let mut waiting;
        let mut done = false;
        loop {
            waiting = true;
            if let Some(ref mut client) = self.client {
                if let Some(ref msg_len) = client.msg_len {
                    let len = try_ready!(client.socket.poll_send(&client.buf[..*msg_len]));
                    debug_assert_eq!(len, *msg_len);
                    if !client.endpoint.is_handshaking() {
                        done = true;
                        break;
                    }
                    waiting = false;
                }
                if !waiting {
                    client.msg_len.take();
                }

                if let None = client.msg_len {
                    let len = try_ready!(client.socket.poll_recv(&mut client.buf));
                    let packet = {
                        let partial = Packet::start_decode(&mut client.buf[..len]);
                        let key = client.endpoint.decode_key(&partial.header);
                        partial.finish(&key)?
                    };
                    client.endpoint.handle(&packet)?;
                    waiting = false;
                }

                if let None = client.msg_len {
                    if let Some(p) = client.endpoint.queued() {
                        client.msg_len = Some(p.encode(
                            &client.endpoint.encode_key(&p.header),
                            &mut client.buf,
                        )?);
                        waiting = false;
                    }
                }
            }

            if waiting {
                break;
            }
        }

        if done {
            match self.client.take() {
                Some(client) => Ok(Async::Ready(client)),
                _ => panic!("invalid future state"),
            }
        } else {
            Ok(Async::NotReady)
        }
    }
}
