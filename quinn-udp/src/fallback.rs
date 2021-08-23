use crate::{RecvMeta, SocketType};
use proto::Transmit;

use std::io::{IoSliceMut, Result};

pub fn init(socket: &std::net::UdpSocket) -> Result<SocketType> {
    Ok(if socket.local_addr()?.is_ipv4() {
        SocketType::Ipv4
    } else {
        SocketType::Ipv6Only
    })
}

pub fn send(socket: &std::net::UdpSocket, transmits: &[Transmit]) -> Result<usize> {
    let mut sent = 0;
    for transmit in transmits {
        match socket.send_to(&transmit.contents, &transmit.destination) {
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

pub fn recv(
    socket: &std::net::UdpSocket,
    buffers: &mut [IoSliceMut<'_>],
    meta: &mut [RecvMeta],
) -> Result<usize> {
    let (len, addr) = socket.recv_from(&mut buffers[0])?;
    meta[0] = RecvMeta {
        addr,
        len,
        ecn: None,
        dst_ip: None,
    };
    Ok(1)
}

/// Returns the platforms UDP socket capabilities
pub fn max_gso_segments() -> Result<usize> {
    Ok(1)
}

pub const BATCH_SIZE: usize = 1;
