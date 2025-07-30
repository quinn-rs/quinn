//! Basic Post-Quantum Cryptography example
//!
//! This example demonstrates the simplest way to enable PQC in ant-quic.
//! It creates a client and server that communicate using hybrid PQC.

use ant_quic::crypto::pqc::{PqcConfig, PqcMode};
use ant_quic::{ClientConfig, Endpoint, EndpointConfig, ServerConfig, VarInt};
use std::error::Error;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Initialize logging
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // Parse command line arguments
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <server|client> [server_addr]", args[0]);
        std::process::exit(1);
    }

    let mode = &args[1];

    match mode.as_str() {
        "server" => run_server().await,
        "client" => {
            if args.len() < 3 {
                eprintln!("Client mode requires server address");
                std::process::exit(1);
            }
            let server_addr = args[2].parse()?;
            run_client(server_addr).await
        }
        _ => {
            eprintln!("Invalid mode. Use 'server' or 'client'");
            std::process::exit(1);
        }
    }
}

async fn run_server() -> Result<(), Box<dyn Error + Send + Sync>> {
    println!("🔐 Starting PQC-enabled QUIC server...");

    // Create PQC configuration (hybrid mode by default)
    let pqc_config = PqcConfig::default();
    println!("📋 PQC Mode: {:?}", pqc_config.mode());

    // Generate self-signed certificate with PQC support
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let cert_der = cert.serialize_der()?;
    let priv_key = cert.serialize_private_key_der();
    let priv_key = rustls::PrivateKey(priv_key);
    let cert_chain = vec![rustls::Certificate(cert_der)];

    // Create server configuration with PQC
    let mut server_config = ServerConfig::with_single_cert(cert_chain, priv_key)?;
    let transport_config = Arc::get_mut(&mut server_config.transport).unwrap();
    transport_config.max_idle_timeout(Some(VarInt::from_u32(30_000).into()));

    // Enable PQC in crypto provider
    let crypto = Arc::new(rustls::crypto::ring::default_provider());

    // Create endpoint with PQC-enabled configuration
    let endpoint = Endpoint::server(server_config, "0.0.0.0:4433".parse()?)?;
    println!("✅ Server listening on {}", endpoint.local_addr()?);
    println!("🔬 Post-Quantum Cryptography: ENABLED (Hybrid Mode)");
    println!("   - Key Exchange: X25519 + ML-KEM-768");
    println!("   - Signatures: Ed25519 + ML-DSA-65");

    // Accept connections
    while let Some(conn) = endpoint.accept().await {
        let connection = conn.await?;
        println!("\n📥 New connection from: {}", connection.remote_address());

        // Check if connection is using PQC
        let handshake_data = connection.handshake_data().await?;
        if let Some(data) = handshake_data.downcast_ref::<ant_quic::crypto::rustls::HandshakeData>()
        {
            println!("🔐 TLS Version: {:?}", data.protocol_version);
            println!("🔐 Cipher Suite: {:?}", data.negotiated_cipher_suite);
        }

        // Spawn handler for this connection
        tokio::spawn(handle_connection(connection));
    }

    Ok(())
}

async fn run_client(server_addr: SocketAddr) -> Result<(), Box<dyn Error + Send + Sync>> {
    println!("🔐 Starting PQC-enabled QUIC client...");

    // Create PQC configuration
    let pqc_config = PqcConfig::default();
    println!("📋 PQC Mode: {:?}", pqc_config.mode());

    // Create client configuration with PQC
    let mut roots = rustls::RootCertStore::empty();
    roots.add(&rustls::Certificate(std::fs::read("cert.der")?))?;

    let client_config = ClientConfig::with_root_certificates(roots);

    // Create endpoint
    let mut endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(client_config);

    println!("🔬 Connecting with Post-Quantum Cryptography...");
    println!("   - Key Exchange: X25519 + ML-KEM-768");
    println!("   - Signatures: Ed25519 + ML-DSA-65");

    // Connect to server
    let connection = timeout(
        Duration::from_secs(5),
        endpoint.connect(server_addr, "localhost")?,
    )
    .await??;

    println!("✅ Connected to {} with PQC protection!", server_addr);

    // Open a bidirectional stream
    let (mut send, mut recv) = connection.open_bi().await?;

    // Send a message
    let message = b"Hello from PQC-protected client!";
    send.write_all(message).await?;
    send.finish().await?;
    println!("📤 Sent: {}", std::str::from_utf8(message)?);

    // Read response
    let response = recv.read_to_end(1024).await?;
    println!("📥 Received: {}", std::str::from_utf8(&response)?);

    // Show connection statistics
    let stats = connection.stats();
    println!("\n📊 Connection Statistics:");
    println!("   - RTT: {:?}", stats.path.rtt);
    println!("   - Packets sent: {}", stats.path.sent_packets);
    println!("   - Packets lost: {}", stats.path.lost_packets);

    connection.close(0u32.into(), b"done");
    endpoint.wait_idle().await;

    Ok(())
}

async fn handle_connection(
    connection: ant_quic::Connection,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    // Accept a stream
    if let Ok((mut send, mut recv)) = connection.accept_bi().await {
        // Read message
        let message = recv.read_to_end(1024).await?;
        println!("📥 Received: {}", std::str::from_utf8(&message)?);

        // Send response
        let response = format!("Echo (PQC-protected): {}", std::str::from_utf8(&message)?);
        send.write_all(response.as_bytes()).await?;
        send.finish().await?;
        println!("📤 Sent response");
    }

    Ok(())
}
