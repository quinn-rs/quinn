use criterion::{criterion_group, criterion_main, Criterion};
use quinn_udp::{RecvMeta, Transmit, UdpSocketState};
use std::cmp::min;
use std::{io::IoSliceMut, net::UdpSocket, slice};

pub fn criterion_benchmark(c: &mut Criterion) {
    const TOTAL_BYTES: usize = 10 * 1024 * 1024;
    // Maximum GSO buffer size is 64k.
    const MAX_BUFFER_SIZE: usize = u16::MAX as usize;
    const SEGMENT_SIZE: usize = 1280;

    let send = UdpSocket::bind("[::1]:0")
        .or_else(|_| UdpSocket::bind("127.0.0.1:0"))
        .unwrap();
    let recv = UdpSocket::bind("[::1]:0")
        .or_else(|_| UdpSocket::bind("127.0.0.1:0"))
        .unwrap();
    let max_segments = min(
        UdpSocketState::new((&send).into())
            .unwrap()
            .max_gso_segments(),
        MAX_BUFFER_SIZE / SEGMENT_SIZE,
    );
    let dst_addr = recv.local_addr().unwrap();
    let send_state = UdpSocketState::new((&send).into()).unwrap();
    let recv_state = UdpSocketState::new((&recv).into()).unwrap();
    // Reverse non-blocking flag set by `UdpSocketState` to make the test non-racy
    recv.set_nonblocking(false).unwrap();

    let mut receive_buffer = vec![0; MAX_BUFFER_SIZE];
    let mut meta = RecvMeta::default();

    for gso_enabled in [false, true] {
        let mut group = c.benchmark_group(format!("gso_{}", gso_enabled));
        group.throughput(criterion::Throughput::Bytes(TOTAL_BYTES as u64));

        let segments = if gso_enabled { max_segments } else { 1 };
        let msg = vec![0xAB; SEGMENT_SIZE * segments];

        let transmit = Transmit {
            destination: dst_addr,
            ecn: None,
            contents: &msg,
            segment_size: gso_enabled.then_some(SEGMENT_SIZE),
            src_ip: None,
        };

        group.bench_function("throughput", |b| {
            b.iter(|| {
                let mut sent: usize = 0;
                while sent < TOTAL_BYTES {
                    send_state.send((&send).into(), &transmit).unwrap();
                    sent += transmit.contents.len();

                    let mut received_segments = 0;
                    while received_segments < segments {
                        let n = recv_state
                            .recv(
                                (&recv).into(),
                                &mut [IoSliceMut::new(&mut receive_buffer)],
                                slice::from_mut(&mut meta),
                            )
                            .unwrap();
                        assert_eq!(n, 1);
                        received_segments += meta.len / meta.stride;
                    }
                    assert_eq!(received_segments, segments);
                }
            })
        });
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
