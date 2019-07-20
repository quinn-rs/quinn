use std::{io, net::SocketAddr};

use mio::net::UdpSocket;

use proto::EcnCodepoint;

impl super::UdpExt for UdpSocket {
    fn init_ext(&self) -> io::Result<()> {
        Ok(())
    }

    fn send_ext(
        &self,
        remote: &SocketAddr,
        _: Option<EcnCodepoint>,
        msg: &[u8],
    ) -> io::Result<usize> {
        self.send_to(msg, remote)
    }

    fn recv_ext(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr, Option<EcnCodepoint>)> {
        self.recv_from(buf).map(|(x, y)| (x, y, None))
    }
}
