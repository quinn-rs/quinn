use anyhow::Result;
use std::io::IoSliceMut;
use std::net::Ipv4Addr;
use std::time::Instant;
use proto::{EcnCodepoint, Transmit};
use quinn_udp::{RecvMeta, UdpSocket, BATCH_SIZE};

fn main() -> Result<()> {
    env_logger::init();
    let mut socket1 = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0).into())?;
    let socket2 = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0).into())?;
    let addr2 = socket2.local_addr()?;

    let mut transmits = Vec::with_capacity(BATCH_SIZE);
    for i in 0..BATCH_SIZE {
        let contents = (i as u64).to_be_bytes().to_vec();
        transmits.push(Transmit {
            destination: addr2,
            ecn: Some(EcnCodepoint::Ce),
            segment_size: Some(1200),
            contents,
            src_ip: Some(Ipv4Addr::LOCALHOST.into()),
        });
    }

    let task1 = async_global_executor::spawn(async move {
        log::debug!("before send");
        socket1.send(&transmits).await.unwrap();
        log::debug!("after send");
    });

    let task2 = async_global_executor::spawn(async move {
        let mut storage = [[0u8; 1200]; BATCH_SIZE];
        let mut buffers = Vec::with_capacity(BATCH_SIZE);
        let mut rest = &mut storage[..];
        for _ in 0..BATCH_SIZE {
            let (b, r) = rest.split_at_mut(1);
            rest = r;
            buffers.push(IoSliceMut::new(&mut b[0]));
        }

        let mut meta = [RecvMeta::default(); BATCH_SIZE];
        let n = socket2.recv(&mut buffers, &mut meta).await.unwrap();
        for i in 0..n {
            log::debug!(
                "received {} {:?} {:?}",
                i,
                &buffers[i][..meta[i].len],
                &meta[i]
            );
        }
    });

    async_global_executor::block_on(async move {
        let start = Instant::now();
        task1.await;
        task2.await;
        println!(
            "sent {} packets in {}ms",
            BATCH_SIZE,
            start.elapsed().as_millis()
        );
    });

    Ok(())
}
