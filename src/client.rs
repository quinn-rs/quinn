use futures::{task, Async, Future, Poll};

use super::{QuicError, QuicResult};
use conn_state::ConnectionState;
use parameters::ClientTransportParameters;
use streams::Streams;
use tls;

use std::net::{SocketAddr, ToSocketAddrs};

use tokio::net::UdpSocket;

pub struct Client {
    conn_state: ConnectionState<tls::ClientSession>,
    socket: UdpSocket,
    buf: Vec<u8>,
}

impl Client {
    pub(crate) fn new(server: &str, port: u16) -> QuicResult<Client> {
        let tls = tls::client_session(None, server, &ClientTransportParameters::default())?;
        Self::with_state(server, port, ConnectionState::new(tls, None))
    }

    pub fn with_state(
        server: &str,
        port: u16,
        mut conn_state: ConnectionState<tls::ClientSession>,
    ) -> QuicResult<Client> {
        let addr = (server, port).to_socket_addrs()?.next().ok_or_else(|| {
            QuicError::General(format!("no address found for '{}:{}'", server, port))
        })?;

        let local = match addr {
            SocketAddr::V4(_) => SocketAddr::from(([127, 0, 0, 1], 0)),
            SocketAddr::V6(_) => SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], 0)),
        };

        conn_state.initial()?;
        let socket = UdpSocket::bind(&local)?;
        socket.connect(&addr)?;
        Ok(Self {
            conn_state,
            socket,
            buf: vec![0u8; 65536],
        })
    }

    pub fn connect(server: &str, port: u16) -> QuicResult<ConnectFuture> {
        Ok(ConnectFuture::new(Self::new(server, port)?))
    }

    fn poll_send(&mut self) -> Poll<(), QuicError> {
        if let Some(buf) = self.conn_state.queued()? {
            let len = try_ready!(self.socket.poll_send(&buf));
            debug_assert_eq!(len, buf.len());
        }
        self.conn_state.pop_queue();
        Ok(Async::Ready(()))
    }
}

impl Future for Client {
    type Item = ();
    type Error = QuicError;
    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        self.conn_state.streams.set_task(task::current());
        loop {
            match self.poll_send() {
                Ok(Async::Ready(())) | Ok(Async::NotReady) => {}
                e @ Err(_) => try_ready!(e),
            }
            let len = try_ready!(self.socket.poll_recv(&mut self.buf));
            self.conn_state.handle(&mut self.buf[..len])?;
        }
    }
}

#[must_use = "futures do nothing unless polled"]
pub struct ConnectFuture {
    client: Option<Client>,
}

impl ConnectFuture {
    fn new(client: Client) -> ConnectFuture {
        ConnectFuture {
            client: Some(client),
        }
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
                _ => !client.conn_state.is_handshaking(),
            }
        } else {
            panic!("invalid state for ConnectFuture");
        };

        if done {
            match self.client.take() {
                Some(client) => {
                    let streams = client.conn_state.streams.clone();
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
    use conn_state::tests::client_conn_state;
    use futures::Future;
    use server::Server;
    use tls::tests::server_config;
    use tokio::executor::current_thread::CurrentThread;

    #[test]
    fn test_client_connect_resolves() {
        let server = Server::new("127.0.0.1", 4433, server_config()).unwrap();
        let client = super::Client::with_state("127.0.0.1", 4433, client_conn_state()).unwrap();
        let connector = super::ConnectFuture::new(client);
        let mut exec = CurrentThread::new();
        exec.spawn(server.map_err(|_| ()));
        exec.block_on(connector).unwrap();
    }
}
