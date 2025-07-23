//! Example demonstrating QUIC Address Discovery extension usage
//! 
//! This example shows how to use the address discovery feature to:
//! - Automatically discover reflexive addresses behind NAT
//! - Improve NAT traversal success rates
//! - Monitor address changes

use ant_quic::{
    ClientConfig, Endpoint, EndpointConfig, ServerConfig, TransportConfig,
    AddressDiscoveryStats,
};
use std::error::Error;
use std::net::{SocketAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;
use tokio;
use tracing::{info, debug, warn};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter("ant_quic=debug,address_discovery_demo=info")
        .init();

    // Parse command line arguments
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(|s| s.as_str()).unwrap_or("server");
    let bootstrap = args.get(2);

    match mode {
        "server" => run_server().await,
        "client" => run_client(bootstrap).await,
        "bootstrap" => run_bootstrap().await,
        _ => {
            eprintln!("Usage: {} [server|client|bootstrap] [bootstrap_addr]", args[0]);
            std::process::exit(1);
        }
    }
}

/// Run as a bootstrap node with aggressive address observation
async fn run_bootstrap() -> Result<(), Box<dyn Error>> {
    info!("Starting bootstrap node with aggressive address discovery");

    // Create endpoint config with address discovery enabled
    let mut config = EndpointConfig::default();
    config.set_address_discovery_enabled(true);
    config.set_max_observation_rate(30); // Higher rate for bootstrap
    config.set_observe_all_paths(true); // Observe all paths

    // Create server config
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    let cert_der = cert.cert.der().clone();
    let priv_key = cert.key_pair.serialize_der();
    
    let mut server_config = ServerConfig::with_single_cert(
        vec![cert_der.clone()],
        priv_key.into(),
    )?;
    
    // Configure transport for optimal NAT traversal
    let transport_config = Arc::get_mut(&mut server_config.transport).unwrap();
    transport_config.keep_alive_interval(Some(Duration::from_secs(5)));
    transport_config.max_idle_timeout(Some(Duration::from_secs(60).try_into()?));

    // Bind to port
    let addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 5000));
    let endpoint = Endpoint::server(server_config, addr)?;
    let local_addr = endpoint.local_addr()?;
    
    info!("Bootstrap node listening on {}", local_addr);
    info!("Address discovery is ENABLED with rate limit: {} obs/sec", 
          config.max_observation_rate());

    // Accept connections and observe addresses
    loop {
        let incoming = endpoint.accept().await.ok_or("endpoint closed")?;
        let connection = incoming.await?;
        
        let remote = connection.remote_address();
        info!("New connection from {}", remote);
        
        // The bootstrap node will automatically send OBSERVED_ADDRESS frames
        // to inform the client of its reflexive address
        
        tokio::spawn(handle_connection(connection));
    }
}

/// Run as a regular server
async fn run_server() -> Result<(), Box<dyn Error>> {
    info!("Starting server with address discovery enabled");

    // Use default config (address discovery enabled by default)
    let config = EndpointConfig::default();
    info!("Address discovery enabled: {}", config.address_discovery_enabled());

    // Create server config
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    let cert_der = cert.cert.der().clone();
    let priv_key = cert.key_pair.serialize_der();
    
    let server_config = ServerConfig::with_single_cert(
        vec![cert_der.clone()],
        priv_key.into(),
    )?;

    // Bind to port
    let addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 5001));
    let endpoint = Endpoint::server(server_config, addr)?;
    let local_addr = endpoint.local_addr()?;
    
    info!("Server listening on {}", local_addr);
    
    // Monitor address discovery statistics
    tokio::spawn(monitor_stats(endpoint.clone()));

    // Accept connections
    loop {
        let incoming = endpoint.accept().await.ok_or("endpoint closed")?;
        let connection = incoming.await?;
        
        let remote = connection.remote_address();
        info!("New connection from {}", remote);
        
        // Check if the client has a different observed address
        if let Some(observed) = connection.observed_address() {
            if observed != remote {
                info!("Client's real address is {} (behind NAT)", observed);
            }
        }
        
        tokio::spawn(handle_connection(connection));
    }
}

/// Run as a client
async fn run_client(bootstrap: Option<&String>) -> Result<(), Box<dyn Error>> {
    info!("Starting client with address discovery");

    // Create endpoint
    let mut endpoint = Endpoint::client(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))?;
    
    // Enable address discovery (enabled by default, but we can control it)
    endpoint.enable_address_discovery(true);
    
    // Set up address change callback
    endpoint.set_address_change_callback(|old_addr, new_addr| {
        info!("Address changed from {:?} to {}", old_addr, new_addr);
    });

    // Connect to bootstrap node first if provided
    if let Some(bootstrap_addr) = bootstrap {
        info!("Connecting to bootstrap node at {}", bootstrap_addr);
        
        let bootstrap_addr: SocketAddr = bootstrap_addr.parse()?;
        let connection = endpoint.connect(bootstrap_addr, "bootstrap")?.await?;
        
        info!("Connected to bootstrap node");
        
        // Wait a bit to receive OBSERVED_ADDRESS frames
        tokio::time::sleep(Duration::from_millis(500)).await;
        
        if let Some(observed) = connection.observed_address() {
            info!("Bootstrap node observed our address as: {}", observed);
        }
        
        // Check all discovered addresses
        let addresses = endpoint.discovered_addresses();
        if !addresses.is_empty() {
            info!("All discovered addresses: {:?}", addresses);
        }
    }

    // Connect to the main server
    let server_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 5001));
    info!("Connecting to server at {}", server_addr);
    
    let connection = endpoint.connect(server_addr, "localhost")?.await?;
    info!("Connected to server");
    
    // Send some data
    let mut send = connection.open_uni().await?;
    send.write_all(b"Hello from client with address discovery!").await?;
    send.finish()?;
    
    // Keep connection alive and monitor statistics
    let stats_endpoint = endpoint.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            let stats = stats_endpoint.address_discovery_stats();
            debug!("Address discovery stats: {:?}", stats);
        }
    });
    
    // Keep the connection open
    loop {
        tokio::time::sleep(Duration::from_secs(10)).await;
        
        if let Some(observed) = connection.observed_address() {
            debug!("Current observed address: {}", observed);
        }
    }
}

/// Handle a connection
async fn handle_connection(connection: ant_quic::Connection) {
    let remote = connection.remote_address();
    
    // Read data from the client
    match connection.accept_uni().await {
        Ok(Some(mut stream)) => {
            let mut buf = vec![0; 1024];
            match stream.read(&mut buf).await {
                Ok(Some(n)) => {
                    let msg = String::from_utf8_lossy(&buf[..n]);
                    info!("Received from {}: {}", remote, msg);
                }
                Ok(None) => info!("Stream from {} closed", remote),
                Err(e) => warn!("Error reading from {}: {}", remote, e),
            }
        }
        Ok(None) => info!("Connection from {} closed", remote),
        Err(e) => warn!("Error accepting stream from {}: {}", remote, e),
    }
}

/// Monitor address discovery statistics
async fn monitor_stats(endpoint: Endpoint) {
    let mut last_stats = AddressDiscoveryStats::default();
    
    loop {
        tokio::time::sleep(Duration::from_secs(10)).await;
        
        let stats = endpoint.address_discovery_stats();
        
        if stats.frames_sent != last_stats.frames_sent || 
           stats.frames_received != last_stats.frames_received {
            info!("Address Discovery Stats:");
            info!("  Frames sent: {}", stats.frames_sent);
            info!("  Frames received: {}", stats.frames_received);
            info!("  Addresses discovered: {}", stats.addresses_discovered);
            info!("  Address changes: {}", stats.address_changes_detected);
        }
        
        last_stats = stats;
    }
}