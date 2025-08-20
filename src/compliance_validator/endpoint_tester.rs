// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

/// Endpoint Testing Module
///
/// Tests QUIC implementation against real-world endpoints
use super::{EndpointResult, EndpointValidationReport, ValidationError};
use crate::{
    ClientConfig, EndpointConfig, VarInt,
    high_level::{Connection, Endpoint},
    transport_parameters::TransportParameters,
};
use std::collections::HashMap;
use std::net::ToSocketAddrs;
use std::time::Duration;
use tokio::time::timeout;
use tracing::{error, info, warn};

/// Known public QUIC endpoints for testing
/// Last verified: 2025-07-25
pub const PUBLIC_QUIC_ENDPOINTS: &[&str] = &[
    // Major providers (production)
    "quic.nginx.org:443", // NGINX official QUIC endpoint
    "cloudflare.com:443", // Cloudflare production
    "www.google.com:443", // Google production
    "facebook.com:443",   // Meta/Facebook production
    // Dedicated test servers
    "cloudflare-quic.com:443",           // Cloudflare QUIC test site
    "quic.rocks:4433",                   // Google QUIC test endpoint
    "http3-test.litespeedtech.com:4433", // LiteSpeed standard test
    "http3-test.litespeedtech.com:4434", // LiteSpeed with stateless retry
    "test.privateoctopus.com:4433",      // Picoquic test server
    "test.privateoctopus.com:4434",      // Picoquic retry test
    "test.pquic.org:443",                // PQUIC research server
    "www.litespeedtech.com:443",         // LiteSpeed production
    // Additional endpoints from previous list
    "quic.tech:4433",
    "quic.westus.cloudapp.azure.com:4433",
    "h3.vortex.data.msn.com:443",
];

/// Endpoint tester for validating against real QUIC servers
pub struct EndpointTester {
    /// Local endpoint for testing
    endpoint: Option<Endpoint>,
    /// Test timeout
    timeout_duration: Duration,
    /// Custom test endpoints
    custom_endpoints: Vec<String>,
}

impl Default for EndpointTester {
    fn default() -> Self {
        Self::new()
    }
}

impl EndpointTester {
    /// Create a new endpoint tester
    pub fn new() -> Self {
        Self {
            endpoint: None,
            timeout_duration: Duration::from_secs(10),
            custom_endpoints: Vec::new(),
        }
    }

    /// Set custom timeout duration
    pub fn with_timeout(mut self, duration: Duration) -> Self {
        self.timeout_duration = duration;
        self
    }

    /// Add custom endpoint for testing
    pub fn add_endpoint(&mut self, endpoint: String) {
        self.custom_endpoints.push(endpoint);
    }

    /// Initialize the local endpoint
    async fn init_endpoint(&mut self) -> Result<(), ValidationError> {
        if self.endpoint.is_none() {
            let socket = std::net::UdpSocket::bind("0.0.0.0:0").map_err(|e| {
                ValidationError::ValidationError(format!("Failed to bind socket: {e}"))
            })?;
            let runtime = crate::high_level::default_runtime().ok_or_else(|| {
                ValidationError::ValidationError("No compatible async runtime found".to_string())
            })?;
            let endpoint = Endpoint::new(
                EndpointConfig::default(),
                None, // No server config for client
                socket,
                runtime,
            )
            .map_err(|e| {
                ValidationError::ValidationError(format!("Failed to create endpoint: {e}"))
            })?;

            self.endpoint = Some(endpoint);
        }
        Ok(())
    }

    /// Test all endpoints
    pub async fn test_all_endpoints(&mut self) -> EndpointValidationReport {
        self.init_endpoint().await.unwrap_or_else(|e| {
            error!("Failed to initialize endpoint: {}", e);
        });

        let mut all_endpoints = PUBLIC_QUIC_ENDPOINTS
            .iter()
            .map(|&s| s.to_string())
            .collect::<Vec<_>>();
        all_endpoints.extend(self.custom_endpoints.clone());

        let mut endpoint_results = HashMap::new();
        let mut successful = 0;
        let mut common_issues = HashMap::new();

        for endpoint_str in &all_endpoints {
            info!("Testing endpoint: {}", endpoint_str);

            match self.test_endpoint(endpoint_str).await {
                Ok(result) => {
                    if result.connected {
                        successful += 1;
                    }

                    // Track common issues
                    for issue in &result.issues {
                        *common_issues.entry(issue.clone()).or_insert(0) += 1;
                    }

                    endpoint_results.insert(endpoint_str.clone(), result);
                }
                Err(e) => {
                    warn!("Failed to test endpoint {}: {}", endpoint_str, e);
                    endpoint_results.insert(
                        endpoint_str.clone(),
                        EndpointResult {
                            endpoint: endpoint_str.clone(),
                            connected: false,
                            quic_versions: vec![],
                            extensions: vec![],
                            issues: vec![format!("Test failed: {}", e)],
                        },
                    );
                }
            }
        }

        let success_rate = if all_endpoints.is_empty() {
            0.0
        } else {
            successful as f64 / all_endpoints.len() as f64
        };

        // Extract most common issues
        let mut common_issues_vec: Vec<_> = common_issues.into_iter().collect();
        common_issues_vec.sort_by(|a, b| b.1.cmp(&a.1));
        let common_issues = common_issues_vec
            .into_iter()
            .take(5)
            .map(|(issue, _)| issue)
            .collect();

        EndpointValidationReport {
            endpoint_results,
            success_rate,
            common_issues,
        }
    }

    /// Test a single endpoint
    async fn test_endpoint(&self, endpoint_str: &str) -> Result<EndpointResult, ValidationError> {
        let addr = endpoint_str
            .to_socket_addrs()
            .map_err(|e| ValidationError::ValidationError(format!("Invalid address: {e}")))?
            .next()
            .ok_or_else(|| ValidationError::ValidationError("No address resolved".to_string()))?;

        let endpoint = self.endpoint.as_ref().ok_or_else(|| {
            ValidationError::ValidationError("Endpoint not initialized".to_string())
        })?;

        // Extract server name from endpoint string
        let server_name = endpoint_str.split(':').next().unwrap_or(endpoint_str);

        // Create client config
        let client_config = create_test_client_config(server_name)?;

        // Attempt connection
        let connecting = match endpoint.connect_with(client_config, addr, server_name) {
            Ok(connecting) => connecting,
            Err(e) => {
                return Ok(EndpointResult {
                    endpoint: endpoint_str.to_string(),
                    connected: false,
                    quic_versions: vec![],
                    extensions: vec![],
                    issues: vec![format!("Failed to start connection: {}", e)],
                });
            }
        };

        let connect_result = timeout(self.timeout_duration, connecting).await;

        match connect_result {
            Ok(Ok(connection)) => {
                // Connection successful - analyze capabilities
                let result = self.analyze_connection(endpoint_str, connection).await?;
                Ok(result)
            }
            Ok(Err(e)) => {
                // Connection failed
                Ok(EndpointResult {
                    endpoint: endpoint_str.to_string(),
                    connected: false,
                    quic_versions: vec![],
                    extensions: vec![],
                    issues: vec![format!("Connection failed: {}", e)],
                })
            }
            Err(_) => {
                // Timeout
                Ok(EndpointResult {
                    endpoint: endpoint_str.to_string(),
                    connected: false,
                    quic_versions: vec![],
                    extensions: vec![],
                    issues: vec!["Connection timeout".to_string()],
                })
            }
        }
    }

    /// Analyze a successful connection
    async fn analyze_connection(
        &self,
        endpoint_str: &str,
        connection: Connection,
    ) -> Result<EndpointResult, ValidationError> {
        let mut issues = Vec::new();

        // TODO: Get actual transport parameters from connection
        // For now, use placeholder values
        let quic_versions = vec![0x00000001]; // QUIC v1

        // Check for extensions
        let extensions = Vec::new();

        // TODO: Check for address discovery and NAT traversal support
        // when we have access to transport parameters

        // Test basic data exchange
        match self.test_data_exchange(&connection).await {
            Ok(()) => {
                info!("Data exchange successful with {}", endpoint_str);
            }
            Err(e) => {
                issues.push(format!("Data exchange failed: {e}"));
            }
        }

        // TODO: Check compliance issues when we have transport parameters

        // Close connection gracefully
        connection.close(VarInt::from_u32(0), b"test complete");

        Ok(EndpointResult {
            endpoint: endpoint_str.to_string(),
            connected: true,
            quic_versions,
            extensions,
            issues,
        })
    }

    /// Test basic data exchange
    async fn test_data_exchange(&self, connection: &Connection) -> Result<(), ValidationError> {
        // Open a bidirectional stream
        let (mut send, mut recv) = connection
            .open_bi()
            .await
            .map_err(|e| ValidationError::ValidationError(format!("Failed to open stream: {e}")))?;

        // Send test data
        let test_data = b"QUIC compliance test";
        send.write_all(&test_data[..])
            .await
            .map_err(|e| ValidationError::ValidationError(format!("Failed to send data: {e}")))?;

        send.finish().map_err(|e| {
            ValidationError::ValidationError(format!("Failed to finish stream: {e}"))
        })?;

        // Read response (if any)
        let mut buf = vec![0u8; 1024];
        let _ = timeout(Duration::from_secs(2), recv.read(&mut buf)).await;

        Ok(())
    }

    /// Check compliance issues in transport parameters
    fn check_compliance(&self, params: &TransportParameters) -> Option<Vec<String>> {
        let mut issues = Vec::new();

        // Check max_udp_payload_size
        if params.max_udp_payload_size.0 < 1200 {
            issues.push("max_udp_payload_size < 1200 (RFC 9000 violation)".to_string());
        }

        // Check ack_delay_exponent
        if params.ack_delay_exponent.0 > 20 {
            issues.push("ack_delay_exponent > 20 (RFC 9000 violation)".to_string());
        }

        // Check max_ack_delay
        if params.max_ack_delay.0 >= (1 << 14) {
            issues.push("max_ack_delay >= 2^14 (RFC 9000 violation)".to_string());
        }

        // Check active_connection_id_limit
        if params.active_connection_id_limit.0 < 2 {
            issues.push("active_connection_id_limit < 2 (RFC 9000 violation)".to_string());
        }

        if issues.is_empty() {
            None
        } else {
            Some(issues)
        }
    }
}

/// Create a test client configuration
fn create_test_client_config(_server_name: &str) -> Result<ClientConfig, ValidationError> {
    // Use the platform verifier if available
    #[cfg(feature = "platform-verifier")]
    {
        ClientConfig::try_with_platform_verifier().map_err(|e| {
            ValidationError::ValidationError(format!("Failed to create client config: {e}"))
        })
    }

    #[cfg(not(feature = "platform-verifier"))]
    {
        // Fall back to accepting any certificate for testing
        use crate::crypto::rustls::QuicClientConfig;
        use std::sync::Arc;

        let mut roots = rustls::RootCertStore::empty();

        // Add system roots
        let cert_result = rustls_native_certs::load_native_certs();
        for cert in cert_result.certs {
            roots.add(cert.into()).ok();
        }
        if !cert_result.errors.is_empty() {
            warn!("Failed to load some native certs: {:?}", cert_result.errors);
        }

        // Create rustls config
        let crypto = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();

        // Convert to QUIC client config
        let quic_crypto = QuicClientConfig::try_from(Arc::new(crypto)).map_err(|e| {
            ValidationError::ValidationError(format!(
                "Failed to create QUIC crypto config: {:?}",
                e
            ))
        })?;

        Ok(ClientConfig::new(Arc::new(quic_crypto)))
    }
}

/// Get recommended test endpoints based on requirements
pub fn get_recommended_endpoints(requirements: &[&str]) -> Vec<String> {
    let mut endpoints = Vec::new();

    for req in requirements {
        match *req {
            "address_discovery" => {
                // Endpoints known to support address discovery
                endpoints.push("quic.tech:4433".to_string());
            }
            "nat_traversal" => {
                // Endpoints that might support NAT traversal
                endpoints.push("test.privateoctopus.com:4433".to_string());
            }
            "h3" => {
                // HTTP/3 endpoints
                endpoints.push("cloudflare.com:443".to_string());
                endpoints.push("www.google.com:443".to_string());
            }
            _ => {}
        }
    }

    // Remove duplicates
    endpoints.sort();
    endpoints.dedup();

    endpoints
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_endpoint_tester_creation() {
        let tester = EndpointTester::new();
        assert_eq!(tester.timeout_duration, Duration::from_secs(10));
        assert!(tester.custom_endpoints.is_empty());
    }

    #[test]
    fn test_add_endpoint() {
        let mut tester = EndpointTester::new();
        tester.add_endpoint("example.com:443".to_string());
        assert_eq!(tester.custom_endpoints.len(), 1);
        assert_eq!(tester.custom_endpoints[0], "example.com:443");
    }

    #[test]
    fn test_with_timeout() {
        let tester = EndpointTester::new().with_timeout(Duration::from_secs(30));
        assert_eq!(tester.timeout_duration, Duration::from_secs(30));
    }

    #[test]
    fn test_recommended_endpoints() {
        let endpoints = get_recommended_endpoints(&["h3"]);
        assert!(!endpoints.is_empty());
        assert!(endpoints.contains(&"cloudflare.com:443".to_string()));

        let endpoints = get_recommended_endpoints(&["address_discovery"]);
        assert!(endpoints.contains(&"quic.tech:4433".to_string()));
    }

    #[test]
    fn test_compliance_check() {
        let tester = EndpointTester::new();

        // Valid parameters
        let mut params = TransportParameters::default();
        params.max_udp_payload_size = VarInt::from_u32(1500);
        params.ack_delay_exponent = VarInt::from_u32(3);
        params.max_ack_delay = VarInt::from_u32(25);
        params.active_connection_id_limit = VarInt::from_u32(4);

        assert!(tester.check_compliance(&params).is_none());

        // Invalid parameters
        params.max_udp_payload_size = VarInt::from_u32(1000);
        params.ack_delay_exponent = VarInt::from_u32(21);

        let issues = tester.check_compliance(&params).unwrap();
        assert_eq!(issues.len(), 2);
    }
}
