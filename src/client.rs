use futures::{task, Async, Future, Poll};

use super::{QuicError, QuicResult};
use endpoint::Endpoint;
use parameters::ClientTransportParameters;
use streams::Streams;
use tls;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};

use tokio_udp::UdpSocket;

pub struct Client {
    endpoint: Endpoint<tls::ClientSession>,
    socket: UdpSocket,
    buf: Vec<u8>,
}

impl Client {
    pub fn connect(server: &str, port: u16) -> QuicResult<ConnectFuture> {
        let tls = tls::client_session(None, server, &ClientTransportParameters::default())?;
        let endpoint = Endpoint::new(tls, None);
        ConnectFuture::new(endpoint, server, port)
    }
}

impl Future for Client {
    type Item = ();
    type Error = QuicError;
    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        self.endpoint.streams.set_task(task::current());
        let mut waiting;
        loop {
            waiting = true;
            if let Some(buf) = self.endpoint.queued()? {
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
        let remote = (server, port).to_socket_addrs()?.next().ok_or_else(|| {
            QuicError::General(format!("no address found for '{}:{}'", server, port))
        })?;
        let local = match remote {
            SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0),
            SocketAddr::V6(_) => {
                SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), 0)
            }
        };

        endpoint.initial()?;
        let socket = UdpSocket::bind(&local)?;
        socket.connect(&remote)?;
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

#[cfg(test)]
mod tests {
    extern crate tokio;
    use self::tokio::executor::current_thread::CurrentThread;
    use endpoint::tests::client_endpoint;
    use futures::Future;
    use server::Server;
    use tls::tests::server_config;

    #[test]
    fn test_client_connect_resolves() {
        let server = Server::new("::1", 4433, server_config()).unwrap();
        let connector = super::ConnectFuture::new(client_endpoint(), "localhost", 4433).unwrap();
        let mut exec = CurrentThread::new();
        exec.spawn(server.map_err(|_| ()));
        exec.block_on(connector).unwrap();
    }
}
