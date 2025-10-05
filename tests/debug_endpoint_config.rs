//! Debug test to verify endpoint configuration

use ant_quic::{EndpointRole, QuicNodeConfig, QuicP2PNode, auth::AuthConfig};
use std::time::Duration;

#[tokio::test]
async fn test_endpoint_has_server_config() -> anyhow::Result<()> {
    let config = QuicNodeConfig {
        role: EndpointRole::Bootstrap,  // Should create server_config
        bootstrap_nodes: vec![],
        enable_coordinator: false,
        max_connections: 100,
        connection_timeout: Duration::from_secs(30),
        stats_interval: Duration::from_secs(60),
        auth_config: AuthConfig {
            require_authentication: false,
            ..AuthConfig::default()
        },
        bind_addr: Some("127.0.0.1:0".parse()?),
    };

    println!("\n=== Creating node with EndpointRole::Bootstrap ===");
    let node = QuicP2PNode::new(config).await.map_err(|e| anyhow::anyhow!("{}", e))?;

    let nat_endpoint = node.get_nat_endpoint().map_err(|e| anyhow::anyhow!("{}", e))?;
    let quinn_endpoint = nat_endpoint.get_quinn_endpoint()
        .ok_or_else(|| anyhow::anyhow!("No Quinn endpoint"))?;
    let addr = quinn_endpoint.local_addr()?;

    println!("✅ Node created successfully, listening on: {}", addr);
    println!("Check logs above for 'Creating server config' message");

    Ok(())
}
