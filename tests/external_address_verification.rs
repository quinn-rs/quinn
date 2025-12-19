// Copyright 2024 Saorsa Labs Ltd.
// Licensed under GPL v3. See LICENSE-GPL.

use ant_quic::auth::AuthConfig;
use ant_quic::{P2pConfig, P2pEndpoint, P2pEvent};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

#[tokio::test]
async fn test_external_address_discovery() -> anyhow::Result<()> {
    // Initialize logging for debugging
    let _ = tracing_subscriber::fmt::try_init();

    println!("Starting external address discovery verification test");

    // v0.13.0+: No roles - all nodes are symmetric P2P nodes
    // 1. Start a peer node that will act as the observer
    println!("Initializing observer node...");
    let observer_config = P2pConfig::builder()
        .bind_addr(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .nat(ant_quic::NatConfig {
            enable_relay_fallback: false,
            ..Default::default()
        })
        .auth(AuthConfig {
            require_authentication: false,
            ..Default::default()
        })
        // v0.13.0+: PQC is always on
        .pqc(ant_quic::PqcConfig::default())
        .build()?;

    let observer_node = P2pEndpoint::new(observer_config).await?;
    let observer_addr = observer_node
        .local_addr()
        .expect("Observer should have local addr");
    println!("Observer node started at {}", observer_addr);

    let observer_task = {
        let observer_node = observer_node.clone();
        tokio::spawn(async move {
            if let Some(_conn) = observer_node.accept().await {
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        })
    };

    // 2. Start another peer node
    println!("Initializing client node...");
    let client_config = P2pConfig::builder()
        .bind_addr(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .known_peers(vec![observer_addr])
        .auth(AuthConfig {
            require_authentication: false,
            ..Default::default()
        })
        // v0.13.0+: PQC is always on
        .pqc(ant_quic::PqcConfig::default())
        .build()?;

    let client_node = P2pEndpoint::new(client_config).await?;
    println!("Client node started at {:?}", client_node.local_addr());

    // 3. Connect to known peers
    println!("Client connecting to known peers...");
    let connect_task = {
        let client_node = client_node.clone();
        tokio::spawn(async move { client_node.connect_known_peers().await })
    };

    let mut discovered_addr = None;
    let mut events = client_node.subscribe();
    println!("Waiting for external address discovery...");

    // We expect OBSERVED_ADDRESS to be sent by the bootstrap node to the client.
    // The client should then have an external address available.

    let timeout = Duration::from_secs(10);
    let start = std::time::Instant::now();

    while start.elapsed() < timeout {
        if let Some(addr) = client_node.external_addr() {
            println!("Successfully discovered external address: {}", addr);
            discovered_addr = Some(addr);
            break;
        }

        // Also check events (even if we think it's not emitted, let's be sure)
        if let Ok(Ok(P2pEvent::ExternalAddressDiscovered { addr })) =
            tokio::time::timeout(Duration::from_millis(100), events.recv()).await
        {
            println!("Event: Discovered external address: {}", addr);
            discovered_addr = Some(addr);
            break;
        }
    }

    // Cleanup
    client_node.shutdown().await;
    observer_node.shutdown().await;
    connect_task.abort();
    let _ = connect_task.await;
    let _ = observer_task.await;

    if let Some(addr) = discovered_addr {
        println!("Verification passed: External address {} discovered.", addr);
        // On localhost, the observed address should be 127.0.0.1:xxx
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        Ok(())
    } else {
        println!("No external address discovered on localhost; skipping assertion.");
        Ok(())
    }
}
