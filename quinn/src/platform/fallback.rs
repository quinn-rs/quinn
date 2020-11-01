use std::{io, io::IoSliceMut};

use mio::net::UdpSocket;

use proto::Transmit;

use crate::udp::RecvMeta;

impl super::UdpExt for UdpSocket {
    fn init_ext(&self) -> io::Result<()> {
        Ok(())
    }

    fn send_ext(&self, transmits: &[Transmit]) -> io::Result<usize> {
        let mut sent = 0;
        for transmit in transmits {
            match self.send_to(&transmit.contents, &transmit.destination) {
                Ok(_) => {
                    sent += 1;
                }
                Err(_) if sent != 0 => {
                    // We need to report that some packets were sent in this case, so we rely on
                    // errors being either harmlessly transient (in the case of WouldBlock) or
                    // recurring on the next call.
                    return Ok(sent);
                }
                Err(e) => {
                    return Err(e);
                }
            }
        }
        Ok(sent)
    }

    fn recv_ext(&self, bufs: &mut [IoSliceMut<'_>], meta: &mut [RecvMeta]) -> io::Result<usize> {
        let (len, addr) = self.recv_from(&mut bufs[0])?;
        meta[0] = RecvMeta {
            len,
            addr,
            ecn: None,
        };
        Ok(1)
    }
}
