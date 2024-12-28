#![cfg(feature = "rustls-aws-lc-rs")]

use std::{
    error::Error,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
};

use rustls::{
    pki_types::{CertificateDer, PrivatePkcs8KeyDer},
    NamedGroup,
};
use tracing::info;

use quinn::{
    crypto::rustls::{HandshakeData, QuicClientConfig, QuicServerConfig},
    Endpoint,
};

#[tokio::test]
async fn post_quantum_key_worst_case_header() {
    check_post_quantum_key_exchange(1274, 8081).await;
}

#[tokio::test]
async fn post_quantum_key_exchange_large_mtu() {
    check_post_quantum_key_exchange(1433, 8082).await;
}

async fn check_post_quantum_key_exchange(min_mtu: u16, server_port: u16) {
    let _ = tracing_subscriber::FmtSubscriber::builder()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();

    let server_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, server_port));

    let (endpoint, server_cert) = make_server_endpoint(server_addr, min_mtu).unwrap();
    // accept a single connection
    tokio::spawn(async move {
        let incoming_conn = endpoint.accept().await.unwrap();
        let conn = incoming_conn.await.unwrap();
        info!(
            "[server] connection accepted: addr={}",
            conn.remote_address()
        );
        assert_eq!(
            conn.handshake_data()
                .unwrap()
                .downcast::<HandshakeData>()
                .unwrap()
                .negotiated_key_exchange_group,
            X25519_KYBER768_DRAFT00
        )
        // Dropping all handles associated with a connection implicitly closes it
    });

    let endpoint =
        make_client_endpoint(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)), server_cert).unwrap();
    // connect to server
    let connection = endpoint
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    info!("[client] connected: addr={}", connection.remote_address());

    // Waiting for a stream will complete with an error when the server closes the connection
    let _ = connection.accept_uni().await;

    // Make sure the server has a chance to clean up
    endpoint.wait_idle().await;
}

fn make_client_endpoint(
    bind_addr: SocketAddr,
    server_cert: CertificateDer<'static>,
) -> Result<Endpoint, Box<dyn Error + Send + Sync + 'static>> {
    let mut certs = rustls::RootCertStore::empty();
    certs.add(server_cert)?;
    let rustls_config =
        rustls::ClientConfig::builder_with_provider(Arc::new(rustls_post_quantum::provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(certs)
            .with_no_client_auth();

    let client_cfg =
        quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(rustls_config).unwrap()));
    let mut endpoint = Endpoint::client(bind_addr)?;
    endpoint.set_default_client_config(client_cfg);
    Ok(endpoint)
}

fn make_server_endpoint(
    bind_addr: SocketAddr,
    min_mtu: u16,
) -> Result<(Endpoint, CertificateDer<'static>), Box<dyn Error + Send + Sync + 'static>> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let server_cert = CertificateDer::from(cert.cert);
    let priv_key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(
            rustls::ServerConfig::builder_with_provider(Arc::new(rustls_post_quantum::provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(vec![server_cert.clone()], priv_key.into())
                .unwrap(),
        )
        .unwrap(),
    ));

    let transport_config = Arc::get_mut(&mut server_config.transport).unwrap();
    transport_config.max_concurrent_uni_streams(0_u8.into());
    transport_config.min_mtu(min_mtu);

    let endpoint = Endpoint::server(server_config, bind_addr)?;
    Ok((endpoint, server_cert))
}

/// <https://datatracker.ietf.org/doc/html/draft-tls-westerbaan-xyber768d00-02#name-iana-considerations-23>
const X25519_KYBER768_DRAFT00: NamedGroup = NamedGroup::Unknown(0x06399);
