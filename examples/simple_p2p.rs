// Copyright 2024 Saorsa Labs Ltd.
// Licensed under GPL v3. See LICENSE-GPL.

//! Simple P2P Example - Demonstrates the ant-quic API
//!
//! v0.13.0+: All nodes are symmetric P2P nodes - no roles needed.
//! This example shows how to use `P2pEndpoint` to create a P2P node
//! that connects to other peers and listens for events.
//!
//! Run with: `cargo run --example simple_p2p`

use ant_quic::{P2pConfig, P2pEndpoint, P2pEvent};
use std::time::Duration;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    // v0.13.0+: No role needed - all nodes are symmetric P2P nodes
    let config = P2pConfig::builder()
        .fast_timeouts() // Use fast timeouts for demo
        .build()?;

    // Create the P2P endpoint
    let endpoint = P2pEndpoint::new(config).await?;
    println!("Peer ID: {:?}", endpoint.peer_id());

    if let Some(addr) = endpoint.local_addr() {
        println!("Local address: {}", addr);
    }

    // Subscribe to events
    let mut events = endpoint.subscribe();
    tokio::spawn(async move {
        while let Ok(event) = events.recv().await {
            match event {
                P2pEvent::PeerConnected { peer_id, addr } => {
                    println!("Connected to peer {:?} at {}", peer_id, addr);
                }
                P2pEvent::ExternalAddressDiscovered { addr } => {
                    println!("Discovered external address: {}", addr);
                }
                _ => println!("Event: {:?}", event),
            }
        }
    });

    // Show statistics
    let stats = endpoint.stats().await;
    println!("Stats: {} active connections", stats.active_connections);

    // Keep running briefly to show the endpoint works
    tokio::time::sleep(Duration::from_secs(2)).await;
    endpoint.shutdown().await;
    println!("Endpoint shut down cleanly");

    Ok(())
}
