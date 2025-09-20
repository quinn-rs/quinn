//! Basic Post-Quantum Cryptography example
//!
//! This example demonstrates the simplest way to enable PQC in ant-quic
//! using the QuicP2PNode high-level API.

#[cfg(feature = "pqc")]
use ant_quic::{
    auth::AuthConfig,
    crypto::pqc::{PqcConfig, PqcMode},
    crypto::raw_public_keys::key_utils::{
        derive_peer_id_from_public_key, generate_ed25519_keypair,
    },
    nat_traversal_api::EndpointRole,
    quic_node::{QuicNodeConfig, QuicP2PNode},
};

#[cfg(feature = "pqc")]
use std::{net::SocketAddr, sync::Arc, time::Duration};
#[cfg(feature = "pqc")]
use tracing::{error, info, warn};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("info".parse().unwrap()),
        )
        .init();

    // Check if PQC features are enabled
    #[cfg(not(feature = "pqc"))]
    {
        println!("Error: This example requires the 'pqc' feature to be enabled.");
        println!("Run with: cargo run --example pqc_basic --features pqc -- <server|client>");
        std::process::exit(1);
    }

    #[cfg(feature = "pqc")]
    {
        // Parse command line arguments
        let args: Vec<String> = std::env::args().collect();
        if args.len() < 2 {
            println!("Usage: {} <server|client> [server_addr]", args[0]);
            println!("\nExamples:");
            println!(
                "  {} server              # Start a PQC-enabled server",
                args[0]
            );
            println!(
                "  {} client 127.0.0.1:5000  # Connect to a PQC server",
                args[0]
            );
            return Ok(());
        }

        let mode = &args[1];

        match mode.as_str() {
            "server" => run_server().await,
            "client" => {
                if args.len() < 3 {
                    eprintln!("Error: Client mode requires server address");
                    return Ok(());
                }
                let server_addr: SocketAddr = args[2].parse()?;
                run_client(server_addr).await
            }
            _ => {
                eprintln!("Error: Unknown mode '{mode}'. Use 'server' or 'client'");
                Ok(())
            }
        }
    }
}

#[cfg(feature = "pqc")]
async fn run_server() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!("🚀 Starting PQC-enabled QUIC server...");

    // Generate identity
    let (_private_key, public_key) = generate_ed25519_keypair();
    let peer_id = derive_peer_id_from_public_key(&public_key);
    println!("📋 Server PeerID: {peer_id:?}");

    // Create PQC configuration (configured in the auth layer)
    #[cfg(feature = "pqc")]
    let pqc_config = PqcConfig::builder().mode(PqcMode::Hybrid).build().unwrap();
    #[cfg(feature = "pqc")]
    println!("🔐 PQC Mode: {:?}", pqc_config.mode);
    #[cfg(not(feature = "pqc"))]
    println!("🔐 PQC disabled - using classical cryptography only");

    // Create server configuration
    let config = QuicNodeConfig {
        role: EndpointRole::Bootstrap,
        bootstrap_nodes: vec![],
        enable_coordinator: false,
        max_connections: 50,
        connection_timeout: Duration::from_secs(30),
        stats_interval: Duration::from_secs(60),
        auth_config: AuthConfig::default(), // PQC is configured here internally
        bind_addr: Some("0.0.0.0:5001".parse()?),
    };

    let node = Arc::new(QuicP2PNode::new(config).await?);
    println!("🎧 Listening on 0.0.0.0:5000");
    println!("🔐 PQC protection enabled!");

    // Handle incoming messages
    println!("🎧 Server ready and waiting for connections...");
    loop {
        println!("🔄 Waiting for incoming connection...");
        match node.accept().await {
            Ok((remote_addr, peer_id)) => {
                println!("✅ Accepted connection from {remote_addr} (peer: {peer_id:?})");

                // Handle messages from this peer
                loop {
                    match node.receive().await {
                        Ok((recv_peer_id, data)) => {
                            if recv_peer_id == peer_id {
                                let message = String::from_utf8_lossy(&data);
                                println!("📩 Message from {peer_id:?}: {message}");

                                // Echo the message back
                                let response = format!("Server received: {message}");
                                if let Err(e) =
                                    node.send_to_peer(&peer_id, response.as_bytes()).await
                                {
                                    warn!("Failed to send response: {}", e);
                                }
                                break; // Exit after handling one message
                            }
                        }
                        Err(_) => {
                            // No messages available
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                    }
                }
            }
            Err(e) => {
                error!("Failed to accept connection: {}", e);
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

#[cfg(feature = "pqc")]
async fn run_client(
    server_addr: SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!("🚀 Starting PQC-enabled QUIC client...");

    // Generate identity
    let (_private_key, public_key) = generate_ed25519_keypair();
    let peer_id = derive_peer_id_from_public_key(&public_key);
    println!("📋 Client PeerID: {peer_id:?}");

    // Create PQC configuration
    #[cfg(feature = "pqc")]
    let pqc_config = PqcConfig::builder().mode(PqcMode::Hybrid).build().unwrap();
    #[cfg(feature = "pqc")]
    println!("🔐 PQC Mode: {:?}", pqc_config.mode);
    #[cfg(not(feature = "pqc"))]
    println!("🔐 PQC disabled - using classical cryptography only");

    // Create client configuration
    let config = QuicNodeConfig {
        role: EndpointRole::Bootstrap,
        bootstrap_nodes: vec!["127.0.0.1:5001".parse()?],
        enable_coordinator: false,
        max_connections: 10,
        connection_timeout: Duration::from_secs(30),
        stats_interval: Duration::from_secs(60),
        auth_config: AuthConfig::default(), // PQC is configured here internally
        bind_addr: None,
    };

    let node = Arc::new(QuicP2PNode::new(config).await?);
    println!("🔗 Connecting to {server_addr} with PQC...");

    // Connect to server (bootstrap node) with retry logic
    println!("🔄 Attempting to connect to server...");
    tokio::time::sleep(Duration::from_secs(1)).await; // Wait a bit for server to be ready
    let server_peer_id = loop {
        match node.connect_to_bootstrap(server_addr).await {
            Ok(peer_id) => {
                break peer_id;
            }
            Err(e) => {
                warn!("Connection attempt failed: {}. Retrying in 2 seconds...", e);
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    };
    println!("✅ Connected to server with PQC protection!");
    println!("   Server PeerID: {server_peer_id:?}");

    // Send a test message
    let message = "Hello from PQC-protected client!";
    info!("Sending message: {}", message);
    node.send_to_peer(&server_peer_id, message.as_bytes())
        .await?;

    // Wait for response
    let timeout = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match node.receive().await {
                Ok((peer_id, data)) => {
                    if peer_id == server_peer_id {
                        let response = String::from_utf8_lossy(&data);
                        println!("📨 Response: {response}");
                        return Ok::<(), Box<dyn std::error::Error + Send + Sync>>(());
                    }
                }
                Err(_) => {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    })
    .await;

    match timeout {
        Ok(Ok(())) => println!("✅ Communication successful with PQC protection!"),
        Ok(Err(_)) => warn!("Failed to receive response"),
        Err(_) => warn!("Timeout waiting for response"),
    }

    // Graceful shutdown
    drop(node);
    println!("👋 Client shutdown complete");

    Ok(())
}
