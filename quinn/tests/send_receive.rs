#![cfg(any(feature = "rustls-aws-lc-rs", feature = "rustls-ring"))]
use std::{
    convert::TryInto,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use quinn::{ConnectionError, StoppedError, TransportConfig};
use rand::{self, RngCore};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use tokio::runtime::Builder;

const BUFFER_SIZE: usize = 1000;
const MESSAGE_COUNT: u32 = 100;

// This test is failing on a specific Samsung Android device:
//   Product name:    Galaxy A32 5G
//   Model name:      SM-A326B/DS
//   Android version: 13
//   Kernel version:  4.14.186-27095505
//   Android security patch level: 1. August 2024
#[test]
fn send_receive() {
    tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .finish(),
    )
    .unwrap();

    let runtime = Builder::new_current_thread().enable_all().build().unwrap();
    let _guard = runtime.enter();

    let (cfg, listener_cert) = configure_listener();
    let endpoint =
        quinn::Endpoint::server(cfg, SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).unwrap();
    let listener_addr = endpoint.local_addr().unwrap();

    let recv_join = runtime.spawn({
        let endpoint = endpoint.clone();
        async move {
            let conn = endpoint.accept().await.unwrap().await.unwrap();

            let mut stream = conn.accept_uni().await.unwrap();
            for i in 0..MESSAGE_COUNT {
                println!("receiving buffer #{i}");
                read_from_peer(&mut stream).await;
            }
            conn.close(0u32.into(), &[]);
        }
    });

    let client_cfg = configure_connector(listener_cert);

    let connecting = endpoint
        .connect_with(client_cfg.clone(), listener_addr, "localhost")
        .unwrap();

    let send_join = runtime.spawn(async move {
        let conn = connecting.await.unwrap();
        let mut s = conn.open_uni().await.unwrap();
        for i in 0..MESSAGE_COUNT {
            println!("sending buffer #{i}");
            write_to_peer(&mut s).await;
            // Uncommenting the below line will make the test pass.
            //tokio::task::yield_now().await;
        }
        s.finish().unwrap();
        // Wait for the stream to be fully received
        //s.stopped().await.unwrap();
        match s.stopped().await {
            Ok(_) => Ok(()),
            Err(StoppedError::ConnectionLost(ConnectionError::ApplicationClosed { .. })) => Ok(()),
            Err(e) => Err(e),
        }
        .unwrap();
    });

    runtime.block_on(async move {
        endpoint.wait_idle().await;
        assert!(send_join.await.is_ok());
        assert!(recv_join.await.is_ok());
    });
}

async fn read_from_peer(stream: &mut quinn::RecvStream) {
    let mut buf: Vec<u8> = vec![0; BUFFER_SIZE];
    stream.read_exact(buf.as_mut()).await.unwrap();
    assert!(hash_correct(&buf));
}

async fn write_to_peer(s: &mut quinn::SendStream) {
    let data = random_data_with_hash(BUFFER_SIZE);
    s.write_all(&data).await.unwrap();
}

/// Builds client configuration. Trusts given node certificate.
fn configure_connector(node_cert: CertificateDer<'static>) -> quinn::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(node_cert).unwrap();

    let mut transport_config = TransportConfig::default();
    transport_config.max_idle_timeout(Some(Duration::from_secs(20).try_into().unwrap()));

    let mut peer_cfg = quinn::ClientConfig::with_root_certificates(Arc::new(roots)).unwrap();
    peer_cfg.transport_config(Arc::new(transport_config));
    peer_cfg
}

/// Builds listener configuration along with its certificate.
fn configure_listener() -> (quinn::ServerConfig, CertificateDer<'static>) {
    let (our_cert, our_priv_key) = gen_cert();
    let mut our_cfg =
        quinn::ServerConfig::with_single_cert(vec![our_cert.clone()], our_priv_key.into()).unwrap();

    let transport_config = Arc::get_mut(&mut our_cfg.transport).unwrap();
    transport_config.max_idle_timeout(Some(Duration::from_secs(20).try_into().unwrap()));

    (our_cfg, our_cert)
}

fn gen_cert() -> (CertificateDer<'static>, PrivatePkcs8KeyDer<'static>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    (
        cert.cert.into(),
        PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()),
    )
}

/// Constructs a buffer with random bytes of given size prefixed with a hash of this data.
fn random_data_with_hash(size: usize) -> Vec<u8> {
    let crc = crc::Crc::<u32>::new(&crc::CRC_32_ISO_HDLC);
    assert!(size >= 4, "Need space for CRC");
    let mut data = random_vec(size);
    let hash = crc.checksum(&data[4..]);
    // write hash in big endian
    data[0] = (hash >> 24) as u8;
    data[1] = ((hash >> 16) & 0xff) as u8;
    data[2] = ((hash >> 8) & 0xff) as u8;
    data[3] = (hash & 0xff) as u8;
    data
}

/// Checks if given data buffer hash is correct. Hash itself is a 4 byte prefix in the data.
fn hash_correct(data: &[u8]) -> bool {
    let crc = crc::Crc::<u32>::new(&crc::CRC_32_ISO_HDLC);
    let encoded_hash = ((data[0] as u32) << 24)
        | ((data[1] as u32) << 16)
        | ((data[2] as u32) << 8)
        | data[3] as u32;
    let actual_hash = crc.checksum(&data[4..]);
    encoded_hash == actual_hash
}

fn random_vec(size: usize) -> Vec<u8> {
    let mut ret = vec![0; size];
    rand::rng().fill_bytes(&mut ret[..]);
    ret
}
