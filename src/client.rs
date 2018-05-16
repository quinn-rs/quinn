use futures::{Async, Future, Poll};

use super::{QuicError, QuicResult};
use endpoint::Endpoint;
use parameters::ClientTransportParameters;
use streams::Streams;
use tls;
use types::Side;

use std::net::{SocketAddr, ToSocketAddrs};

use tokio::net::UdpSocket;

pub struct Client {
    endpoint: Endpoint<tls::ClientSession>,
    socket: UdpSocket,
    buf: Vec<u8>,
}

impl Client {
    pub fn connect(server: &str, port: u16) -> QuicResult<ConnectFuture> {
        let tls = tls::client_session(None, server, &ClientTransportParameters::default())?;
        let endpoint = Endpoint::new(tls, Side::Client, None);
        ConnectFuture::new(endpoint, server, port)
    }
}

impl Future for Client {
    type Item = ();
    type Error = QuicError;
    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let mut waiting;
        loop {
            waiting = true;
            if let Some(buf) = self.endpoint.queued() {
                let len = try_ready!(self.socket.poll_send(&buf));
                debug_assert_eq!(len, buf.len());
                waiting = false;
            }
            if !waiting {
                self.endpoint.pop_queue();
            }

            let len = try_ready!(self.socket.poll_recv(&mut self.buf));
            self.endpoint.handle(&mut self.buf[..len])?;
            waiting = false;

            if waiting {
                break;
            }
        }
        Ok(Async::NotReady)
    }
}

#[must_use = "futures do nothing unless polled"]
pub struct ConnectFuture {
    client: Option<Client>,
}

impl ConnectFuture {
    pub(crate) fn new(
        mut endpoint: Endpoint<tls::ClientSession>,
        server: &str,
        port: u16,
    ) -> QuicResult<ConnectFuture> {
        endpoint.initial()?;

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
        Ok(ConnectFuture {
            client: Some(Client {
                endpoint,
                socket,
                buf: vec![0u8; 65536],
            }),
        })
    }
}

impl Future for ConnectFuture {
    type Item = (Client, Streams);
    type Error = QuicError;
    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let done = if let Some(ref mut client) = self.client {
            match client.poll() {
                Err(e) => {
                    return Err(e);
                }
                _ => !client.endpoint.is_handshaking(),
            }
        } else {
            panic!("invalid state for ConnectFuture");
        };

        if done {
            match self.client.take() {
                Some(client) => {
                    let streams = client.endpoint.streams.clone();
                    Ok(Async::Ready((client, streams)))
                }
                _ => panic!("invalid future state"),
            }
        } else {
            Ok(Async::NotReady)
        }
    }
}
