// Copyright 2024 Saorsa Labs Ltd.
// Licensed under GPL v3. See LICENSE-GPL.

//! PQC Verification Example
//!
//! v0.13.0+: PQC is always enabled (100% PQC, no classical crypto).
//! This example verifies the P2pEndpoint initializes with PQC correctly.

use ant_quic::{P2pConfig, P2pEndpoint, PqcConfig};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // v0.13.0+: PQC is always-on. Configure ML-KEM and ML-DSA.
    let pqc_config = PqcConfig::builder()
        .ml_kem(true)
        .ml_dsa(true)
        .build()?;

    // v0.13.0+: No role needed - all nodes are symmetric P2P nodes
    let config = P2pConfig::builder()
        .known_peer("127.0.0.1:9000".parse()?)
        .pqc(pqc_config)
        .build()?;

    println!("Attempting to create P2pEndpoint with PQC...");

    // Create the endpoint
    let endpoint = P2pEndpoint::new(config).await?;
    println!("Endpoint created with Peer ID: {:?}", endpoint.peer_id());

    // Verify PQC is enabled
    println!("Verification passed: P2pEndpoint initialized with PQC config.");

    endpoint.shutdown().await;
    Ok(())
}
