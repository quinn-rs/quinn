//! Comprehensive Example: RFC 7250 Certificate Type Negotiation
//!
//! This example demonstrates the complete Phase 2 implementation of RFC 7250
//! Raw Public Keys certificate type negotiation, including:
//! 
//! - TLS extension handling
//! - Certificate type negotiation
//! - Quinn QUIC integration
//! - Bootstrap node support
//! - Performance monitoring
//! - Production hardening features

use std::{
    net::{SocketAddr, IpAddr, Ipv4Addr},
    sync::Arc,
    time::Duration,
};

use tokio::time::timeout;
use tracing::{info, warn, error, Level};
use tracing_subscriber;

use ant_quic::{
    crypto::{
        tls_extensions::{
            CertificateType, CertificateTypeList, CertificateTypePreferences,
        },
        certificate_negotiation::{NegotiationConfig, CertificateNegotiationManager},
        bootstrap_support::{
            CertTypeBootstrapRegistry, BootstrapRegistryConfig,
            CertificateTypeCapabilities,
        },
        performance_monitoring::{
            CertTypePerformanceMonitor, PerformanceThresholds,
            ProductionCertTypeSystem, ProductionHardeningConfig,
        },
        raw_public_keys::{RawPublicKeyConfigBuilder, utils},
        quinn_integration::{CertTypeQuicEndpointBuilder, CertTypeAwareQuicEndpoint},
    },
    nat_traversal_api::{EndpointRole, PeerId},
};

/// Example configuration for different deployment scenarios
#[derive(Debug, Clone)]
enum DeploymentScenario {
    /// Raw Public Keys only (ideal P2P scenario)
    RpkOnly,
    /// Mixed deployment (some RPK, some X.509)
    Mixed,
    /// Legacy X.509 with RPK migration
    LegacyMigration,
    /// Bootstrap node configuration
    Bootstrap,
}

impl DeploymentScenario {
    /// Get certificate type preferences for this scenario
    fn preferences(&self) -> CertificateTypePreferences {
        match self {
            DeploymentScenario::RpkOnly => {
                CertificateTypePreferences::raw_public_key_only()
            }
            DeploymentScenario::Mixed => {
                CertificateTypePreferences::prefer_raw_public_key()
            }
            DeploymentScenario::LegacyMigration => {
                // Prefer X.509 but allow RPK for gradual migration
                CertificateTypePreferences {
                    client_types: CertificateTypeList::new(vec![
                        CertificateType::X509,
                        CertificateType::RawPublicKey,
                    ]).unwrap(),
                    server_types: CertificateTypeList::new(vec![
                        CertificateType::X509,
                        CertificateType::RawPublicKey,
                    ]).unwrap(),
                    require_extensions: false,
                    fallback_client: CertificateType::X509,
                    fallback_server: CertificateType::X509,
                }
            }
            DeploymentScenario::Bootstrap => {
                // Bootstrap nodes support all certificate types
                CertificateTypePreferences::prefer_raw_public_key()
            }
        }
    }

    /// Get role for this scenario
    fn role(&self) -> EndpointRole {
        match self {
            DeploymentScenario::Bootstrap => EndpointRole::Bootstrap,
            _ => EndpointRole::Client,
        }
    }
}

/// Example P2P node with certificate type negotiation
struct CertTypeP2PNode {
    /// Node configuration
    scenario: DeploymentScenario,
    /// QUIC endpoint with certificate type awareness
    endpoint: CertTypeAwareQuicEndpoint,
    /// Bootstrap registry for peer discovery
    bootstrap_registry: Option<Arc<CertTypeBootstrapRegistry>>,
    /// Performance monitoring
    performance_monitor: Arc<CertTypePerformanceMonitor>,
    /// Production system for health monitoring
    production_system: Arc<ProductionCertTypeSystem>,
    /// Local keypair for Raw Public Keys
    local_keypair: (ed25519_dalek::SigningKey, ed25519_dalek::VerifyingKey),
    /// Peer ID derived from public key
    peer_id: PeerId,
}

impl CertTypeP2PNode {
    /// Create a new P2P node with certificate type negotiation
    async fn new(
        scenario: DeploymentScenario,
        bind_addr: SocketAddr,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        info!("Creating P2P node with scenario: {:?}", scenario);

        // Generate keypair for Raw Public Keys
        let (private_key, public_key) = utils::generate_ed25519_keypair();
        let key_bytes = utils::public_key_to_bytes(&public_key);
        let peer_id = PeerId(key_bytes);

        // Create certificate type preferences
        let preferences = scenario.preferences();
        let role = scenario.role();

        // Create production hardening configuration
        let production_config = ProductionHardeningConfig {
            enable_monitoring: true,
            enable_detailed_tracing: matches!(scenario, DeploymentScenario::Bootstrap),
            max_negotiation_timeout: Duration::from_secs(30),
            max_cache_size: if matches!(scenario, DeploymentScenario::Bootstrap) { 10000 } else { 1000 },
            enable_cache_cleanup: true,
            cache_cleanup_interval: Duration::from_secs(300),
            enable_rate_limiting: true,
            max_negotiations_per_second: if matches!(scenario, DeploymentScenario::Bootstrap) { 1000 } else { 100 },
        };

        // Create production system
        let production_system = Arc::new(ProductionCertTypeSystem::new(production_config));
        let performance_monitor = production_system.monitor().clone();

        // Create Raw Public Key configuration
        let rpk_config = RawPublicKeyConfigBuilder::new()
            .with_server_key(private_key.clone())
            .with_certificate_type_extensions(preferences.clone())
            .allow_any_key(); // For demo purposes

        // Create negotiation configuration
        let negotiation_config = NegotiationConfig {
            timeout: Duration::from_secs(10),
            enable_caching: true,
            max_cache_size: 1000,
            allow_fallback: !matches!(scenario, DeploymentScenario::RpkOnly),
            default_preferences: preferences.clone(),
        };

        // Create QUIC endpoint
        let endpoint = if matches!(scenario, DeploymentScenario::Bootstrap) {
            CertTypeQuicEndpointBuilder::new()
                .with_preferences(preferences.clone())
                .with_negotiation_config(negotiation_config.clone())
                .with_rpk_config(rpk_config)
                .enable_0rtt_rpk()
                .build_server_endpoint(bind_addr)?
        } else {
            CertTypeQuicEndpointBuilder::new()
                .with_preferences(preferences.clone())
                .with_negotiation_config(negotiation_config.clone())
                .with_rpk_config(rpk_config)
                .enable_0rtt_rpk()
                .build_client_endpoint(bind_addr)?
        };

        // Create bootstrap registry if this is a bootstrap node or client
        let bootstrap_registry = if matches!(scenario, DeploymentScenario::Bootstrap) || 
                                   matches!(scenario, DeploymentScenario::Mixed) {
            let capabilities = CertificateTypeCapabilities::from_preferences(&preferences, role);
            let registry_config = BootstrapRegistryConfig::default();
            let registry = Arc::new(CertTypeBootstrapRegistry::new(
                capabilities,
                negotiation_config,
                registry_config,
            ));
            Some(registry)
        } else {
            None
        };

        info!("Created P2P node: peer_id={:?}, scenario={:?}, supports_rpk={}, supports_x509={}",
              peer_id, scenario, preferences.client_types.supports_raw_public_key(),
              preferences.client_types.supports_x509());

        Ok(Self {
            scenario,
            endpoint,
            bootstrap_registry,
            performance_monitor,
            production_system,
            local_keypair: (private_key, public_key),
            peer_id,
        })
    }

    /// Connect to another peer with certificate type negotiation
    async fn connect_to_peer(
        &self,
        peer_addr: SocketAddr,
        server_name: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        info!("Connecting to peer at {} with certificate type negotiation", peer_addr);

        // Check rate limiting
        if !self.production_system.check_negotiation_allowed() {
            warn!("Connection rate limited");
            return Err("Rate limited".into());
        }

        // Attempt connection with timeout
        let connect_start = std::time::Instant::now();
        let connection_result = timeout(
            Duration::from_secs(30),
            self.endpoint.connect_with_cert_negotiation(peer_addr, server_name),
        ).await?;

        match connection_result {
            Ok((connection, context)) => {
                let duration = connect_start.elapsed();
                info!("Successfully connected to peer: client_cert={}, server_cert={}, 0rtt={}, duration={:?}",
                      context.result.client_cert_type, context.result.server_cert_type,
                      context.used_0rtt, duration);

                // Record performance metrics
                self.performance_monitor.record_negotiation(
                    duration,
                    true,
                    Some(context.result.clone()),
                    false, // Simplified - would check actual cache hit
                );

                // If we have a bootstrap registry, record successful connection
                if let Some(registry) = &self.bootstrap_registry {
                    // Would extract peer ID from connection in real implementation
                    let dummy_peer_id = PeerId([0; 32]);
                    registry.record_connection_attempt(dummy_peer_id, true);
                }

                // Demonstrate connection usage
                self.demonstrate_connection_usage(&connection, &context).await?;

                Ok(())
            }
            Err(e) => {
                let duration = connect_start.elapsed();
                error!("Failed to connect to peer: {}", e);

                // Record performance metrics
                self.performance_monitor.record_negotiation(
                    duration,
                    false,
                    None,
                    false,
                );

                Err(e.into())
            }
        }
    }

    /// Accept incoming connections (for server/bootstrap nodes)
    async fn accept_connections(&self) -> Result<(), Box<dyn std::error::Error>> {
        info!("Starting to accept incoming connections");

        let endpoint = self.endpoint.endpoint();
        
        while let Some(incoming) = endpoint.accept().await {
            let performance_monitor = self.performance_monitor.clone();
            let bootstrap_registry = self.bootstrap_registry.clone();
            let production_system = self.production_system.clone();
            
            tokio::spawn(async move {
                let accept_start = std::time::Instant::now();
                
                // Check rate limiting
                if !production_system.check_negotiation_allowed() {
                    warn!("Incoming connection rate limited");
                    return;
                }

                match endpoint.accept_with_cert_negotiation(incoming).await {
                    Ok((connection, context)) => {
                        let duration = accept_start.elapsed();
                        info!("Accepted connection: client_cert={}, server_cert={}, 0rtt={}, duration={:?}",
                              context.result.client_cert_type, context.result.server_cert_type,
                              context.used_0rtt, duration);

                        // Record performance metrics
                        performance_monitor.record_negotiation(
                            duration,
                            true,
                            Some(context.result.clone()),
                            false,
                        );

                        // Register peer in bootstrap registry if available
                        if let Some(registry) = bootstrap_registry {
                            // In real implementation, would extract actual capabilities from connection
                            let dummy_capabilities = CertificateTypeCapabilities::from_preferences(
                                &CertificateTypePreferences::prefer_raw_public_key(),
                                EndpointRole::Client,
                            );
                            let dummy_peer_id = PeerId([1; 32]);
                            
                            if let Err(e) = registry.register_peer(dummy_peer_id, context.peer_addr, dummy_capabilities) {
                                warn!("Failed to register peer: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        let duration = accept_start.elapsed();
                        error!("Failed to accept connection: {}", e);

                        performance_monitor.record_negotiation(
                            duration,
                            false,
                            None,
                            false,
                        );
                    }
                }
            });
        }

        Ok(())
    }

    /// Demonstrate connection usage after successful establishment
    async fn demonstrate_connection_usage(
        &self,
        connection: &quinn::Connection,
        context: &ant_quic::crypto::quinn_integration::QuicNegotiationContext,
    ) -> Result<(), Box<dyn std::error::Error>> {
        info!("Demonstrating connection usage with cert type: {:?}", context.result);

        // Open a bidirectional stream
        let (mut send, mut recv) = connection.open_bi().await?;

        // Send a message based on certificate type
        let message = if context.result.is_raw_public_key_only() {
            "Hello from Raw Public Key peer!"
        } else if context.result.is_x509_only() {
            "Hello from X.509 peer!"
        } else {
            "Hello from mixed certificate type peer!"
        };

        send.write_all(message.as_bytes()).await?;
        send.finish()?;

        // Read response (with timeout)
        match timeout(Duration::from_secs(5), recv.read_to_end(64 * 1024)).await {
            Ok(Ok(response)) => {
                info!("Received response: {}", String::from_utf8_lossy(&response));
            }
            Ok(Err(e)) => {
                warn!("Failed to read response: {}", e);
            }
            Err(_) => {
                warn!("Timeout reading response");
            }
        }

        Ok(())
    }

    /// Get performance summary
    fn get_performance_summary(&self) -> String {
        let summary = self.performance_monitor.get_summary();
        let health = self.production_system.health_report();

        format!(
            "Performance Summary:\n\
             - Total negotiations: {}\n\
             - Success rate: {:.2}%\n\
             - Average negotiation time: {:?}\n\
             - Cache hit rate: {:.2}%\n\
             - RPK usage: {:.2}%\n\
             - Health status: {:?}\n\
             - Active alerts: {}",
            summary.total_negotiations,
            summary.success_rate * 100.0,
            summary.avg_negotiation_time,
            summary.cache_hit_rate * 100.0,
            summary.rpk_usage_percentage,
            health.status,
            summary.active_alerts
        )
    }

    /// Get bootstrap registry statistics (if available)
    fn get_bootstrap_stats(&self) -> Option<String> {
        self.bootstrap_registry.as_ref().map(|registry| {
            let stats = registry.get_stats();
            format!(
                "Bootstrap Registry Stats:\n\
                 - Total peers: {}\n\
                 - RPK peers: {}\n\
                 - X.509 peers: {}\n\
                 - Mixed peers: {}\n\
                 - Average quality: {:.2}\n\
                 - Average success rate: {:.2}%",
                stats.total_peers,
                stats.rpk_peers,
                stats.x509_peers,
                stats.mixed_peers,
                stats.avg_quality_score,
                stats.avg_success_rate * 100.0
            )
        })
    }
}

/// Demonstration scenarios
async fn run_demonstration_scenarios() -> Result<(), Box<dyn std::error::Error>> {
    info!("Starting RFC 7250 Certificate Type Negotiation demonstration");

    // Scenario 1: Bootstrap node
    let bootstrap_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8000);
    let bootstrap_node = CertTypeP2PNode::new(
        DeploymentScenario::Bootstrap,
        bootstrap_addr,
    ).await?;

    info!("Created bootstrap node at {}", bootstrap_addr);

    // Start accepting connections on bootstrap node
    let bootstrap_node = Arc::new(bootstrap_node);
    let bootstrap_task = {
        let node_clone = bootstrap_node.clone();
        tokio::spawn(async move {
            if let Err(e) = node_clone.accept_connections().await {
                error!("Bootstrap node error: {}", e);
            }
        })
    };

    // Give bootstrap node time to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Scenario 2: RPK-only client
    let rpk_client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8001);
    let rpk_client = CertTypeP2PNode::new(
        DeploymentScenario::RpkOnly,
        rpk_client_addr,
    ).await?;

    info!("Created RPK-only client at {}", rpk_client_addr);

    // Scenario 3: Mixed deployment client
    let mixed_client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8002);
    let mixed_client = CertTypeP2PNode::new(
        DeploymentScenario::Mixed,
        mixed_client_addr,
    ).await?;

    info!("Created mixed deployment client at {}", mixed_client_addr);

    // Demonstrate connections
    info!("Demonstrating certificate type negotiation...");

    // RPK client connects to bootstrap
    if let Err(e) = rpk_client.connect_to_peer(bootstrap_addr, "localhost").await {
        warn!("RPK client connection failed: {}", e);
    }

    // Mixed client connects to bootstrap
    if let Err(e) = mixed_client.connect_to_peer(bootstrap_addr, "localhost").await {
        warn!("Mixed client connection failed: {}", e);
    }

    // Give some time for connections to complete
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Print performance summaries
    info!("\n{}", rpk_client.get_performance_summary());
    info!("\n{}", mixed_client.get_performance_summary());

    if let Some(bootstrap_stats) = bootstrap_node.get_bootstrap_stats() {
        info!("\n{}", bootstrap_stats);
    }

    // Clean shutdown
    bootstrap_task.abort();
    
    info!("Demonstration completed successfully");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .init();

    info!("RFC 7250 Certificate Type Negotiation Example");
    info!("This example demonstrates the complete Phase 2 implementation");

    // Run the demonstration
    if let Err(e) = run_demonstration_scenarios().await {
        error!("Demonstration failed: {}", e);
        std::process::exit(1);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_deployment_scenarios() {
        // Test that all deployment scenarios can be created
        let scenarios = vec![
            DeploymentScenario::RpkOnly,
            DeploymentScenario::Mixed,
            DeploymentScenario::LegacyMigration,
            DeploymentScenario::Bootstrap,
        ];

        for scenario in scenarios {
            let preferences = scenario.preferences();
            assert!(!preferences.client_types.types.is_empty());
            assert!(!preferences.server_types.types.is_empty());
        }
    }

    #[test]
    fn test_certificate_type_preferences() {
        let rpk_prefs = CertificateTypePreferences::raw_public_key_only();
        assert!(rpk_prefs.client_types.supports_raw_public_key());
        assert!(!rpk_prefs.client_types.supports_x509());

        let mixed_prefs = CertificateTypePreferences::prefer_raw_public_key();
        assert!(mixed_prefs.client_types.supports_raw_public_key());
        assert!(mixed_prefs.client_types.supports_x509());
        assert_eq!(mixed_prefs.client_types.most_preferred(), CertificateType::RawPublicKey);
    }
}