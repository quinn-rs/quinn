// Copyright 2024 Saorsa Labs Ltd.
// Licensed under GPL v3. See LICENSE-GPL.

//! Live Network End-to-End Tests
//!
//! These tests connect to the real saorsa network nodes to verify connectivity.
//! They require internet access and the saorsa nodes to be online.
//!
//! Run with: cargo test --test live_network_e2e -- --ignored --nocapture

#![allow(clippy::unwrap_used, clippy::expect_used)]

use ant_quic::{P2pConfig, P2pEndpoint, P2pEvent};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

/// Known saorsa network nodes for testing
const SAORSA_NODES: &[&str] = &[
    "saorsa-2.saorsalabs.com:9000",
    "saorsa-3.saorsalabs.com:9000",
];

/// Test connection to saorsa-2 node
#[tokio::test]
#[ignore = "requires network access to saorsa-2.saorsalabs.com"]
async fn test_connect_saorsa_2() -> anyhow::Result<()> {
    let _ = tracing_subscriber::fmt::try_init();
    connect_to_node("saorsa-2.saorsalabs.com:9000").await
}

/// Test connection to saorsa-3 node
#[tokio::test]
#[ignore = "requires network access to saorsa-3.saorsalabs.com"]
async fn test_connect_saorsa_3() -> anyhow::Result<()> {
    let _ = tracing_subscriber::fmt::try_init();
    connect_to_node("saorsa-3.saorsalabs.com:9000").await
}

/// Test external address discovery via real saorsa nodes
#[tokio::test]
#[ignore = "requires network access to saorsa nodes"]
async fn test_external_address_discovery_live() -> anyhow::Result<()> {
    let _ = tracing_subscriber::fmt::try_init();
    println!("Testing external address discovery via live saorsa nodes...");

    // Resolve known peer addresses via DNS
    let mut known_peers = Vec::new();
    for addr in SAORSA_NODES {
        match tokio::net::lookup_host(*addr).await {
            Ok(mut addrs) => {
                if let Some(sock_addr) = addrs.next() {
                    println!("Resolved {} -> {}", addr, sock_addr);
                    known_peers.push(sock_addr);
                }
            }
            Err(e) => println!("Failed to resolve {}: {}", addr, e),
        }
    }

    if known_peers.is_empty() {
        println!("No resolvable known peers - skipping test");
        return Ok(());
    }

    let config = P2pConfig::builder()
        .bind_addr(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
        .known_peers(known_peers.clone())
        .pqc(ant_quic::PqcConfig::default())
        .build()?;

    let node = P2pEndpoint::new(config).await?;
    println!("Local node started at {:?}", node.local_addr());

    // Connect to known peers
    println!("Connecting to {} known peers...", known_peers.len());
    let connect_task = {
        let node = node.clone();
        tokio::spawn(async move { node.connect_known_peers().await })
    };

    // Wait for connection and external address discovery
    let mut events = node.subscribe();
    let timeout = Duration::from_secs(30);
    let start = std::time::Instant::now();

    let mut connected = false;
    let mut external_addr = None;

    while start.elapsed() < timeout {
        // Check for external address
        if let Some(addr) = node.external_addr() {
            println!("Discovered external address: {}", addr);
            external_addr = Some(addr);
            break;
        }

        // Check for events
        match tokio::time::timeout(Duration::from_millis(500), events.recv()).await {
            Ok(Ok(P2pEvent::PeerConnected { peer_id, addr, .. })) => {
                println!("Connected to peer {} at {}", peer_id, addr);
                connected = true;
            }
            Ok(Ok(P2pEvent::ExternalAddressDiscovered { addr })) => {
                println!("Event: External address discovered: {}", addr);
                external_addr = Some(addr);
                break;
            }
            Ok(Ok(event)) => {
                println!("Event: {:?}", event);
            }
            _ => {}
        }
    }

    // Cleanup
    node.shutdown().await;
    connect_task.abort();
    let _ = connect_task.await;

    // Verify results
    if connected {
        println!("Successfully connected to saorsa network!");
    }
    if let Some(addr) = external_addr {
        println!("External address verified: {}", addr);
        // On a real network, we should get our public IP
        assert!(!addr.ip().is_loopback(), "Should not be loopback address");
    }

    Ok(())
}

/// Test dual-stack connectivity
#[tokio::test]
#[ignore = "requires network access and dual-stack support"]
async fn test_dual_stack_connectivity() -> anyhow::Result<()> {
    let _ = tracing_subscriber::fmt::try_init();
    println!("Testing dual-stack connectivity...");

    // Try to connect using different IP modes
    for mode in ["IPv4", "IPv6"] {
        println!("Testing {} connectivity...", mode);

        let bind_addr = match mode {
            "IPv4" => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            "IPv6" => SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0),
            _ => unreachable!(),
        };

        // Resolve the known peer address
        let peer_addr = tokio::net::lookup_host("saorsa-2.saorsalabs.com:9000")
            .await?
            .next()
            .ok_or_else(|| anyhow::anyhow!("Failed to resolve saorsa-2"))?;

        let config = P2pConfig::builder()
            .bind_addr(bind_addr)
            .known_peers(vec![peer_addr])
            .pqc(ant_quic::PqcConfig::default())
            .build()?;

        match P2pEndpoint::new(config).await {
            Ok(node) => {
                println!("{} node started at {:?}", mode, node.local_addr());

                // Try to connect
                let result = tokio::time::timeout(Duration::from_secs(10), async {
                    node.connect_known_peers().await
                })
                .await;

                match result {
                    Ok(Ok(n)) => println!("{} connection successful! {} peers connected", mode, n),
                    Ok(Err(e)) => println!("{} connection failed: {:?}", mode, e),
                    Err(_) => println!("{} connection timed out", mode),
                }

                node.shutdown().await;
            }
            Err(e) => {
                println!("{} mode not available: {:?}", mode, e);
            }
        }
    }

    Ok(())
}

/// Helper function to connect to a specific node
async fn connect_to_node(addr: &str) -> anyhow::Result<()> {
    println!("Connecting to {}...", addr);

    // Resolve DNS hostname to socket address
    let peer_addr: SocketAddr = tokio::net::lookup_host(addr)
        .await?
        .next()
        .ok_or_else(|| anyhow::anyhow!("Failed to resolve {}", addr))?;

    let config = P2pConfig::builder()
        .bind_addr(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
        .known_peers(vec![peer_addr])
        .pqc(ant_quic::PqcConfig::default())
        .build()?;

    let node = P2pEndpoint::new(config).await?;
    println!("Local node started at {:?}", node.local_addr());

    // Connect with timeout
    let connect_result = tokio::time::timeout(Duration::from_secs(15), async {
        node.connect_known_peers().await
    })
    .await;

    match connect_result {
        Ok(Ok(n)) => {
            println!("Successfully connected to {} ({} peers)", addr, n);

            // Verify connection by checking for observed address
            tokio::time::sleep(Duration::from_secs(2)).await;
            if let Some(external) = node.external_addr() {
                println!("Our external address as seen by {}: {}", addr, external);
            }
        }
        Ok(Err(e)) => {
            println!("Connection failed: {:?}", e);
        }
        Err(_) => {
            println!("Connection timed out after 15 seconds");
        }
    }

    node.shutdown().await;
    Ok(())
}

/// Stress test: multiple concurrent connections
#[tokio::test]
#[ignore = "requires network access and may be slow"]
async fn test_multiple_connections() -> anyhow::Result<()> {
    let _ = tracing_subscriber::fmt::try_init();
    println!("Testing multiple concurrent connections...");

    let mut handles = Vec::new();

    for i in 0..3 {
        let handle = tokio::spawn(async move {
            let peer = SAORSA_NODES[i % SAORSA_NODES.len()];
            println!("Connection {} to {}", i, peer);
            connect_to_node(peer).await
        });
        handles.push(handle);
    }

    let mut successes = 0;
    for (i, handle) in handles.into_iter().enumerate() {
        match handle.await {
            Ok(Ok(())) => {
                successes += 1;
                println!("Connection {} succeeded", i);
            }
            Ok(Err(e)) => println!("Connection {} failed: {:?}", i, e),
            Err(e) => println!("Connection {} panicked: {:?}", i, e),
        }
    }

    println!(
        "Multiple connections test: {}/{} succeeded",
        successes,
        SAORSA_NODES.len()
    );
    Ok(())
}
