//! Debug QUIC connection test

use ant_quic::{
    config::{ClientConfig, ServerConfig},
    high_level::Endpoint,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::time::{Duration, timeout, interval};

fn gen_self_signed_cert() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("failed to generate self-signed certificate");
    let cert_der = CertificateDer::from(cert.cert);
    let key_der = PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
    (vec![cert_der], key_der)
}

#[tokio::main]
async fn main() {
    // Set up tracing for debugging
    tracing_subscriber::fmt()
        .with_env_filter("ant_quic=trace")
        .init();
    
    eprintln!("Starting debug test with tracing...");
    
    // Install crypto provider
    eprintln!("Installing crypto provider...");
    let installed = rustls::crypto::aws_lc_rs::default_provider().install_default();
    eprintln!("Crypto provider installed: {:?}", installed);
    
    // Server config
    eprintln!("Generating certs...");
    let (chain, key) = gen_self_signed_cert();
    eprintln!("Building server config...");
    let server_cfg = ServerConfig::with_single_cert(chain.clone(), key).expect("failed to build ServerConfig");
    
    // Bind server
    eprintln!("Creating server endpoint...");
    let server_addr: SocketAddr = ([127, 0, 0, 1], 0).into();
    let server_ep = Endpoint::server(server_cfg, server_addr).expect("server endpoint");
    let listen_addr = server_ep.local_addr().expect("obtain server local addr");
    eprintln!("Server listening on: {}", listen_addr);
    
    // Track progress
    static SERVER_PROGRESS: AtomicU64 = AtomicU64::new(0);
    static CLIENT_PROGRESS: AtomicU64 = AtomicU64::new(0);
    
    // Spawn server accept
    let accept_task = tokio::spawn(async move {
        eprintln!("[SERVER] Waiting for incoming connection...");
        SERVER_PROGRESS.store(1, Ordering::SeqCst);
        let inc = timeout(Duration::from_secs(10), server_ep.accept())
            .await
            .expect("server accept timeout")
            .expect("server incoming");
        eprintln!("[SERVER] Got incoming, starting handshake...");
        SERVER_PROGRESS.store(2, Ordering::SeqCst);
        let conn = timeout(Duration::from_secs(10), inc)
            .await
            .expect("server handshake timeout")
            .expect("server handshake");
        eprintln!("[SERVER] Handshake complete!");
        SERVER_PROGRESS.store(3, Ordering::SeqCst);
        conn.remote_address()
    });
    
    // Progress monitor task
    let _monitor = tokio::spawn(async move {
        let mut tick = interval(Duration::from_secs(1));
        loop {
            tick.tick().await;
            let s = SERVER_PROGRESS.load(Ordering::SeqCst);
            let c = CLIENT_PROGRESS.load(Ordering::SeqCst);
            eprintln!("[MONITOR] Server progress: {}, Client progress: {}", s, c);
        }
    });
    
    // Client config
    eprintln!("Building client config...");
    let mut roots = rustls::RootCertStore::empty();
    for c in chain {
        roots.add(c).expect("add server cert to roots");
    }
    let client_cfg = ClientConfig::with_root_certificates(Arc::new(roots)).expect("client config");
    
    // Client endpoint
    eprintln!("Creating client endpoint...");
    let client_addr: SocketAddr = ([127, 0, 0, 1], 0).into();
    let mut client_ep = Endpoint::client(client_addr).expect("client endpoint");
    client_ep.set_default_client_config(client_cfg);
    let client_local = client_ep.local_addr().expect("client addr");
    eprintln!("Client on: {}", client_local);
    
    // Connect
    eprintln!("[CLIENT] Starting connect to {}...", listen_addr);
    CLIENT_PROGRESS.store(1, Ordering::SeqCst);
    let connecting = client_ep
        .connect(listen_addr, "localhost")
        .expect("start connect");
    eprintln!("[CLIENT] connect() returned, awaiting handshake...");
    CLIENT_PROGRESS.store(2, Ordering::SeqCst);
    
    let result = timeout(Duration::from_secs(10), connecting).await;
    CLIENT_PROGRESS.store(3, Ordering::SeqCst);
    match result {
        Ok(Ok(conn)) => eprintln!("[CLIENT] Connected! Remote: {}", conn.remote_address()),
        Ok(Err(e)) => eprintln!("[CLIENT] Connection error: {:?}", e),
        Err(_) => eprintln!("[CLIENT] TIMEOUT waiting for connection"),
    }
    
    // Wait for server
    eprintln!("Waiting for server task...");
    match accept_task.await {
        Ok(addr) => eprintln!("[SERVER] Task complete, remote: {}", addr),
        Err(e) => eprintln!("[SERVER] Task error: {:?}", e),
    }
    
    eprintln!("Test complete");
}
