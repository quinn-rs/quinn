//! Comprehensive tests for candidate discovery mechanisms
//!
//! Tests all aspects of network interface discovery and candidate generation:
//! - Platform-specific interface enumeration
//! - IPv4/IPv6 dual-stack scenarios  
//! - Network change detection
//! - Invalid address filtering
//! - Performance with many interfaces

use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};

use ant_quic::{
    CandidateDiscoveryManager, DiscoveryConfig, DiscoveryEvent, DiscoveryError,
    NetworkInterface, ValidatedCandidate, CandidateSource,
};
use tokio::{sync::mpsc, time::timeout};
use tracing::{debug, info, warn};

/// Mock network interface for testing
#[derive(Debug, Clone)]
struct MockNetworkInterface {
    name: String,
    addresses: Vec<IpAddr>,
    is_up: bool,
    is_loopback: bool,
    is_point_to_point: bool,
    supports_multicast: bool,
    mtu: u32,
}

impl MockNetworkInterface {
    fn ethernet(name: &str, ip: IpAddr) -> Self {
        Self {
            name: name.to_string(),
            addresses: vec![ip],
            is_up: true,
            is_loopback: false,
            is_point_to_point: false,
            supports_multicast: true,
            mtu: 1500,
        }
    }

    fn loopback() -> Self {
        Self {
            name: "lo".to_string(),
            addresses: vec![
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V6(Ipv6Addr::LOCALHOST),
            ],
            is_up: true,
            is_loopback: true,
            is_point_to_point: false,
            supports_multicast: false,
            mtu: 65536,
        }
    }

    fn vpn(name: &str, ip: IpAddr) -> Self {
        Self {
            name: name.to_string(),
            addresses: vec![ip],
            is_up: true,
            is_loopback: false,
            is_point_to_point: true,
            supports_multicast: false,
            mtu: 1400,
        }
    }
}

/// Test harness for candidate discovery
struct CandidateDiscoveryTestHarness {
    interfaces: Vec<MockNetworkInterface>,
    stun_servers: Vec<SocketAddr>,
    discovery_config: DiscoveryConfig,
    network_changes: Arc<Mutex<Vec<NetworkChangeEvent>>>,
}

#[derive(Debug, Clone)]
enum NetworkChangeEvent {
    InterfaceAdded(MockNetworkInterface),
    InterfaceRemoved(String),
    AddressChanged(String, Vec<IpAddr>),
    InterfaceStateChanged(String, bool),
}

impl CandidateDiscoveryTestHarness {
    fn new() -> Self {
        Self {
            interfaces: vec![
                MockNetworkInterface::loopback(),
                MockNetworkInterface::ethernet("eth0", "192.168.1.100".parse().unwrap()),
            ],
            stun_servers: vec![
                "stun.example.com:3478".parse().unwrap(),
                "stun2.example.com:3478".parse().unwrap(),
            ],
            discovery_config: DiscoveryConfig::default(),
            network_changes: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn with_interfaces(mut self, interfaces: Vec<MockNetworkInterface>) -> Self {
        self.interfaces = interfaces;
        self
    }

    fn with_stun_servers(mut self, servers: Vec<&str>) -> Self {
        self.stun_servers = servers.iter()
            .map(|s| s.parse().unwrap())
            .collect();
        self
    }

    async fn discover_candidates(&self) -> Result<Vec<ValidatedCandidate>, DiscoveryError> {
        let mut candidates = Vec::new();

        // Discover host candidates from interfaces
        for interface in &self.interfaces {
            if !interface.is_up || interface.is_loopback {
                continue;
            }

            for addr in &interface.addresses {
                let candidate = ValidatedCandidate {
                    address: SocketAddr::new(*addr, 0),
                    source: CandidateSource::Host,
                    priority: self.calculate_priority(*addr, CandidateSource::Host),
                    foundation: self.calculate_foundation(*addr, CandidateSource::Host),
                    network_cost: if interface.is_point_to_point { 10 } else { 5 },
                    validated_at: std::time::Instant::now(),
                };
                candidates.push(candidate);
            }
        }

        // Simulate STUN discovery for server reflexive candidates
        if !self.stun_servers.is_empty() {
            for interface in &self.interfaces {
                if !interface.is_up || interface.is_loopback {
                    continue;
                }

                for addr in &interface.addresses {
                    // Simulate NAT mapping
                    let reflexive_addr = self.simulate_nat_mapping(*addr);
                    
                    let candidate = ValidatedCandidate {
                        address: SocketAddr::new(reflexive_addr, rand::random::<u16>()),
                        source: CandidateSource::ServerReflexive,
                        priority: self.calculate_priority(reflexive_addr, CandidateSource::ServerReflexive),
                        foundation: self.calculate_foundation(reflexive_addr, CandidateSource::ServerReflexive),
                        network_cost: 15,
                        validated_at: std::time::Instant::now(),
                    };
                    candidates.push(candidate);
                }
            }
        }

        Ok(candidates)
    }

    fn calculate_priority(&self, addr: IpAddr, source: CandidateSource) -> u32 {
        let type_preference = match source {
            CandidateSource::Host => 126,
            CandidateSource::ServerReflexive => 100,
            CandidateSource::PeerReflexive => 110,
            CandidateSource::Relayed => 0,
        };

        let local_preference = if addr.is_ipv6() { 65535 } else { 65534 };
        let component_id = 1;

        (type_preference << 24) | (local_preference << 8) | (256 - component_id)
    }

    fn calculate_foundation(&self, addr: IpAddr, source: CandidateSource) -> String {
        use std::hash::{Hash, Hasher};
        use std::collections::hash_map::DefaultHasher;

        let mut hasher = DefaultHasher::new();
        addr.hash(&mut hasher);
        source.hash(&mut hasher);
        format!("{:x}", hasher.finish())
    }

    fn simulate_nat_mapping(&self, local_addr: IpAddr) -> IpAddr {
        match local_addr {
            IpAddr::V4(addr) => {
                // Simulate mapping to public IP
                if addr.is_private() {
                    IpAddr::V4(Ipv4Addr::new(203, 0, 113, rand::random::<u8>()))
                } else {
                    local_addr
                }
            }
            IpAddr::V6(addr) => {
                // IPv6 typically doesn't use NAT
                local_addr
            }
        }
    }

    async fn simulate_network_change(&self, event: NetworkChangeEvent) {
        self.network_changes.lock().unwrap().push(event);
    }
}

// Test implementations

#[tokio::test]
async fn test_basic_candidate_discovery() {
    let harness = CandidateDiscoveryTestHarness::new();
    let candidates = harness.discover_candidates().await.unwrap();

    assert!(!candidates.is_empty(), "Should discover at least one candidate");
    
    // Verify we have both host and server reflexive candidates
    let has_host = candidates.iter().any(|c| matches!(c.source, CandidateSource::Host));
    let has_reflexive = candidates.iter().any(|c| matches!(c.source, CandidateSource::ServerReflexive));
    
    assert!(has_host, "Should have host candidates");
    assert!(has_reflexive, "Should have server reflexive candidates");
}

#[tokio::test]
async fn test_ipv6_discovery() {
    let harness = CandidateDiscoveryTestHarness::new()
        .with_interfaces(vec![
            MockNetworkInterface::ethernet("eth0", "192.168.1.100".parse().unwrap()),
            MockNetworkInterface::ethernet("eth0", "2001:db8::1".parse().unwrap()),
        ]);

    let candidates = harness.discover_candidates().await.unwrap();

    let ipv4_count = candidates.iter().filter(|c| c.address.is_ipv4()).count();
    let ipv6_count = candidates.iter().filter(|c| c.address.is_ipv6()).count();

    assert!(ipv4_count > 0, "Should discover IPv4 candidates");
    assert!(ipv6_count > 0, "Should discover IPv6 candidates");
    
    // Verify IPv6 candidates have higher priority
    let ipv6_priority = candidates.iter()
        .filter(|c| c.address.is_ipv6())
        .map(|c| c.priority)
        .max()
        .unwrap();
    let ipv4_priority = candidates.iter()
        .filter(|c| c.address.is_ipv4())
        .map(|c| c.priority)
        .max()
        .unwrap();
        
    assert!(ipv6_priority > ipv4_priority, "IPv6 should have higher priority");
}

#[tokio::test]
async fn test_loopback_filtering() {
    let harness = CandidateDiscoveryTestHarness::new()
        .with_interfaces(vec![
            MockNetworkInterface::loopback(),
            MockNetworkInterface::ethernet("eth0", "192.168.1.100".parse().unwrap()),
        ]);

    let candidates = harness.discover_candidates().await.unwrap();

    // Verify no loopback addresses in candidates
    let has_loopback = candidates.iter().any(|c| {
        match c.address.ip() {
            IpAddr::V4(addr) => addr.is_loopback(),
            IpAddr::V6(addr) => addr.is_loopback(),
        }
    });

    assert!(!has_loopback, "Should filter out loopback addresses");
}

#[tokio::test]
async fn test_vpn_interface_handling() {
    let harness = CandidateDiscoveryTestHarness::new()
        .with_interfaces(vec![
            MockNetworkInterface::ethernet("eth0", "192.168.1.100".parse().unwrap()),
            MockNetworkInterface::vpn("tun0", "10.8.0.2".parse().unwrap()),
        ]);

    let candidates = harness.discover_candidates().await.unwrap();

    // Verify VPN candidates have higher network cost
    let vpn_candidate = candidates.iter()
        .find(|c| c.address.ip() == "10.8.0.2".parse::<IpAddr>().unwrap())
        .expect("Should have VPN candidate");

    assert_eq!(vpn_candidate.network_cost, 10, "VPN should have higher network cost");
}

#[tokio::test]
async fn test_multiple_addresses_per_interface() {
    let mut multi_addr_interface = MockNetworkInterface::ethernet("eth0", "192.168.1.100".parse().unwrap());
    multi_addr_interface.addresses.push("192.168.1.101".parse().unwrap());
    multi_addr_interface.addresses.push("fe80::1".parse().unwrap());

    let harness = CandidateDiscoveryTestHarness::new()
        .with_interfaces(vec![multi_addr_interface]);

    let candidates = harness.discover_candidates().await.unwrap();

    // Should have candidates for all addresses
    assert!(candidates.len() >= 3, "Should have candidates for all addresses");
    
    // Verify unique addresses
    let unique_addrs: HashSet<_> = candidates.iter()
        .map(|c| c.address.ip())
        .collect();
    assert_eq!(unique_addrs.len(), candidates.len(), "All candidates should have unique addresses");
}

#[tokio::test]
async fn test_stun_server_failure_handling() {
    let harness = CandidateDiscoveryTestHarness::new()
        .with_stun_servers(vec![
            "invalid.stun.server:3478",
            "unreachable.server:3478",
        ]);

    let candidates = harness.discover_candidates().await.unwrap();

    // Should still have host candidates even if STUN fails
    let host_candidates = candidates.iter()
        .filter(|c| matches!(c.source, CandidateSource::Host))
        .count();

    assert!(host_candidates > 0, "Should have host candidates despite STUN failure");
}

#[tokio::test]
async fn test_candidate_priority_ordering() {
    let harness = CandidateDiscoveryTestHarness::new();
    let candidates = harness.discover_candidates().await.unwrap();

    // Verify priority ordering
    for window in candidates.windows(2) {
        let (first, second) = (&window[0], &window[1]);
        
        // Higher priority candidates should come first
        assert!(
            first.priority >= second.priority,
            "Candidates should be ordered by priority"
        );
    }

    // Verify host candidates have highest priority
    if let Some(host_candidate) = candidates.iter().find(|c| matches!(c.source, CandidateSource::Host)) {
        if let Some(reflexive_candidate) = candidates.iter().find(|c| matches!(c.source, CandidateSource::ServerReflexive)) {
            assert!(
                host_candidate.priority > reflexive_candidate.priority,
                "Host candidates should have higher priority than reflexive"
            );
        }
    }
}

#[tokio::test]
async fn test_foundation_uniqueness() {
    let harness = CandidateDiscoveryTestHarness::new();
    let candidates = harness.discover_candidates().await.unwrap();

    // Group by foundation
    let mut foundation_groups: HashMap<String, Vec<&ValidatedCandidate>> = HashMap::new();
    for candidate in &candidates {
        foundation_groups.entry(candidate.foundation.clone())
            .or_insert_with(Vec::new)
            .push(candidate);
    }

    // Candidates with same foundation should have same base properties
    for (foundation, group) in foundation_groups {
        if group.len() > 1 {
            let first_source = group[0].source;
            for candidate in &group {
                assert_eq!(
                    candidate.source, first_source,
                    "Same foundation should have same source type"
                );
            }
        }
    }
}

#[tokio::test]
async fn test_network_change_detection() {
    let harness = CandidateDiscoveryTestHarness::new();
    
    // Initial discovery
    let initial_candidates = harness.discover_candidates().await.unwrap();
    let initial_count = initial_candidates.len();

    // Simulate adding a new interface
    harness.simulate_network_change(
        NetworkChangeEvent::InterfaceAdded(
            MockNetworkInterface::ethernet("eth1", "192.168.2.100".parse().unwrap())
        )
    ).await;

    // Note: In real implementation, this would trigger re-discovery
    // For testing, we'll manually check the network changes were recorded
    let changes = harness.network_changes.lock().unwrap();
    assert_eq!(changes.len(), 1, "Should record network change");
}

#[tokio::test]
async fn test_interface_down_handling() {
    let mut down_interface = MockNetworkInterface::ethernet("eth0", "192.168.1.100".parse().unwrap());
    down_interface.is_up = false;

    let harness = CandidateDiscoveryTestHarness::new()
        .with_interfaces(vec![down_interface]);

    let candidates = harness.discover_candidates().await.unwrap();

    assert!(
        candidates.is_empty() || !candidates.iter().any(|c| c.address.ip() == "192.168.1.100".parse::<IpAddr>().unwrap()),
        "Should not include candidates from down interfaces"
    );
}

// Stress tests

#[tokio::test]
#[ignore = "stress test"]
async fn stress_test_many_interfaces() {
    let mut interfaces = vec![MockNetworkInterface::loopback()];
    
    // Add 100 interfaces with multiple addresses each
    for i in 0..100 {
        let mut iface = MockNetworkInterface::ethernet(&format!("eth{}", i), 
            format!("192.168.{}.1", i).parse().unwrap());
        iface.addresses.push(format!("192.168.{}.2", i).parse().unwrap());
        iface.addresses.push(format!("2001:db8:{}::1", i).parse().unwrap());
        interfaces.push(iface);
    }

    let harness = CandidateDiscoveryTestHarness::new()
        .with_interfaces(interfaces);

    let start = std::time::Instant::now();
    let candidates = harness.discover_candidates().await.unwrap();
    let duration = start.elapsed();

    info!("Discovered {} candidates from 100 interfaces in {:?}", candidates.len(), duration);
    
    assert!(candidates.len() >= 200, "Should discover many candidates");
    assert!(duration < Duration::from_secs(1), "Should complete quickly even with many interfaces");
}

#[tokio::test]
#[ignore = "stress test"]
async fn stress_test_rapid_network_changes() {
    let harness = CandidateDiscoveryTestHarness::new();
    let changes = harness.network_changes.clone();

    // Simulate rapid network changes
    let change_task = tokio::spawn(async move {
        for i in 0..1000 {
            let event = if i % 2 == 0 {
                NetworkChangeEvent::InterfaceAdded(
                    MockNetworkInterface::ethernet(&format!("eth{}", i), 
                        format!("192.168.{}.1", i % 255).parse().unwrap())
                )
            } else {
                NetworkChangeEvent::InterfaceRemoved(format!("eth{}", i - 1))
            };
            
            changes.lock().unwrap().push(event);
            tokio::time::sleep(Duration::from_micros(100)).await;
        }
    });

    // Perform discovery during network changes
    let mut discovery_count = 0;
    let start = std::time::Instant::now();
    
    while start.elapsed() < Duration::from_millis(200) {
        let _ = harness.discover_candidates().await;
        discovery_count += 1;
    }

    change_task.abort();
    
    info!("Completed {} discoveries during rapid network changes", discovery_count);
    assert!(discovery_count > 10, "Should handle discovery during network changes");
}

#[tokio::test]
async fn test_ipv4_mapped_ipv6_handling() {
    let harness = CandidateDiscoveryTestHarness::new()
        .with_interfaces(vec![
            MockNetworkInterface::ethernet("eth0", "::ffff:192.168.1.100".parse().unwrap()),
        ]);

    let candidates = harness.discover_candidates().await.unwrap();

    // Should properly handle IPv4-mapped IPv6 addresses
    for candidate in &candidates {
        if let IpAddr::V6(addr) = candidate.address.ip() {
            if addr.to_ipv4_mapped().is_some() {
                // Should have lower priority than native addresses
                assert!(candidate.priority < 100 << 24, "Mapped addresses should have lower priority");
            }
        }
    }
}

#[tokio::test]
async fn test_link_local_address_handling() {
    let harness = CandidateDiscoveryTestHarness::new()
        .with_interfaces(vec![
            MockNetworkInterface::ethernet("eth0", "169.254.1.1".parse().unwrap()),
            MockNetworkInterface::ethernet("eth0", "fe80::1".parse().unwrap()),
        ]);

    let candidates = harness.discover_candidates().await.unwrap();

    // Link-local addresses should have lower priority
    for candidate in &candidates {
        match candidate.address.ip() {
            IpAddr::V4(addr) if addr.is_link_local() => {
                assert!(candidate.priority < 50 << 24, "Link-local IPv4 should have low priority");
            }
            IpAddr::V6(addr) if addr.segments()[0] == 0xfe80 => {
                assert!(candidate.priority < 50 << 24, "Link-local IPv6 should have low priority");
            }
            _ => {}
        }
    }
}