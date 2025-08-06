#\![edition = "2024"]
/// Integration test for QUIC interoperability framework
///
/// This test validates the interoperability test infrastructure
use std::path::Path;

#[test]
fn test_matrix_yaml_parsing() {
    // Test that the YAML format is valid
    let yaml_content = include_str!("interop/interop-matrix.yaml");

    // Basic validation - just check it's not empty
    assert!(!yaml_content.is_empty());
    assert!(yaml_content.contains("version:"));
    assert!(yaml_content.contains("implementations:"));
    assert!(yaml_content.contains("test_categories:"));
}

#[tokio::test]
async fn test_endpoint_creation() {
    use ant_quic::high_level::Endpoint;

    // Test that we can create a client endpoint
    let endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap());
    assert!(endpoint.is_ok());
}

#[test]
fn test_docker_config_exists() {
    // Verify Docker configuration files exist
    let docker_compose = Path::new("docker/docker-compose.yml");
    let nat_script = Path::new("docker/scripts/nat-gateway-entrypoint.sh");
    let network_config = Path::new("docker/configs/network-conditions.yaml");

    assert!(docker_compose.exists(), "docker-compose.yml not found");
    assert!(nat_script.exists(), "NAT gateway script not found");
    assert!(
        network_config.exists(),
        "Network conditions config not found"
    );
}

#[test]
fn test_public_endpoints_doc() {
    // Verify public endpoints documentation exists
    let endpoints_doc = Path::new("docs/public-quic-endpoints.md");
    assert!(
        endpoints_doc.exists(),
        "Public endpoints documentation not found"
    );

    // Verify it contains expected content
    let content = std::fs::read_to_string(endpoints_doc).unwrap();
    assert!(content.contains("Google"));
    assert!(content.contains("Cloudflare"));
    assert!(content.contains("Picoquic"));
}
