use std::{
    io::IoSliceMut,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket},
    slice,
};

use bytes::Bytes;
use quinn_udp::{EcnCodepoint, RecvMeta, Transmit, UdpSocketState};
use socket2::Socket;

#[test]
fn basic() {
    let send = UdpSocket::bind("[::1]:0").unwrap();
    let recv = UdpSocket::bind("[::1]:0").unwrap();
    let dst_addr = recv.local_addr().unwrap();
    test_send_recv(
        &send.into(),
        &recv.into(),
        Transmit {
            destination: dst_addr,
            ecn: None,
            contents: Bytes::from_static(b"hello"),
            segment_size: None,
            src_ip: None,
        },
    );
}

#[test]
fn ecn_v6() {
    let recv = socket2::Socket::new(
        socket2::Domain::IPV6,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )
    .unwrap();
    recv.set_only_v6(false).unwrap();
    // We must use the unspecified address here, rather than a local address, to support dual-stack
    // mode
    recv.bind(&socket2::SockAddr::from(
        "[::]:0".parse::<SocketAddr>().unwrap(),
    ))
    .unwrap();
    let recv_v6 = SocketAddr::V6(SocketAddrV6::new(
        Ipv6Addr::LOCALHOST,
        recv.local_addr().unwrap().as_socket().unwrap().port(),
        0,
        0,
    ));
    let recv_v4 = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, recv_v6.port()));
    for (src, dst) in [("[::1]:0", recv_v6), ("127.0.0.1:0", recv_v4)] {
        dbg!(src, dst);
        let send = UdpSocket::bind(src).unwrap();
        let send = Socket::from(send);
        for codepoint in [EcnCodepoint::Ect0, EcnCodepoint::Ect1, EcnCodepoint::Ce] {
            test_send_recv(
                &send,
                &recv,
                Transmit {
                    destination: dst,
                    ecn: Some(codepoint),
                    contents: Bytes::from_static(b"hello"),
                    segment_size: None,
                    src_ip: None,
                },
            );
        }
    }
}

#[test]
fn ecn_v4() {
    let send = Socket::from(UdpSocket::bind("127.0.0.1:0").unwrap());
    let recv = Socket::from(UdpSocket::bind("127.0.0.1:0").unwrap());
    for codepoint in [EcnCodepoint::Ect0, EcnCodepoint::Ect1, EcnCodepoint::Ce] {
        test_send_recv(
            &send,
            &recv,
            Transmit {
                destination: recv.local_addr().unwrap().as_socket().unwrap(),
                ecn: Some(codepoint),
                contents: Bytes::from_static(b"hello"),
                segment_size: None,
                src_ip: None,
            },
        );
    }
}

fn test_send_recv(send: &Socket, recv: &Socket, transmit: Transmit) {
    let send_state = UdpSocketState::new(send.into()).unwrap();
    let recv_state = UdpSocketState::new(recv.into()).unwrap();

    // Reverse non-blocking flag set by `UdpSocketState` to make the test non-racy
    recv.set_nonblocking(false).unwrap();

    send_state
        .send((&send).into(), slice::from_ref(&transmit))
        .unwrap();

    let mut buf = [0; 1024];
    let mut meta = RecvMeta::default();
    let n = recv_state
        .recv(
            recv.into(),
            &mut [IoSliceMut::new(&mut buf)],
            slice::from_mut(&mut meta),
        )
        .unwrap();

    let send_v6 = send.local_addr().unwrap().as_socket().unwrap().is_ipv6();
    let recv_v6 = recv.local_addr().unwrap().as_socket().unwrap().is_ipv6();

    assert_eq!(n, 1);
    match send_v6 == recv_v6 {
        true => assert_eq!(meta.addr, send.local_addr().unwrap().as_socket().unwrap()),
        false => assert_eq!(
            meta.addr,
            to_v6_mapped(send.local_addr().unwrap().as_socket().unwrap())
        ),
    }
    assert_eq!(&buf[..meta.len], transmit.contents);
    assert_eq!(meta.stride, meta.len);
    assert_eq!(meta.ecn, transmit.ecn);
    let dst = meta.dst_ip.unwrap();
    match (send_v6, recv_v6) {
        (_, false) => assert_eq!(dst, Ipv4Addr::LOCALHOST),
        (false, true) => assert_eq!(dst, Ipv4Addr::LOCALHOST.to_ipv6_mapped()),
        (true, true) => assert_eq!(dst, Ipv6Addr::LOCALHOST),
    }
}

fn to_v6_mapped(x: SocketAddr) -> SocketAddr {
    match x {
        SocketAddr::V4(x) => SocketAddrV6::new(x.ip().to_ipv6_mapped(), x.port(), 0, 0).into(),
        SocketAddr::V6(_) => x,
    }
}
