//! IPv6 and Dual-Stack Support Tests
//!
//! This test suite validates IPv6 address handling, dual-stack socket binding,
//! and candidate discovery with both IPv4 and IPv6 addresses.

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    collections::HashMap,
    time::Duration,
};

use ant_quic::{
    NetworkInterface,
    test_utils::{calculate_address_priority, is_valid_address},
    CandidateSource, CandidateState,
    nat_traversal_api::CandidateAddress,
};

use tokio::net::UdpSocket;
use tracing::{info, debug};

/// Test IPv6 address priority calculation
#[test]
fn test_ipv6_address_priority() {
    let _ = tracing_subscriber::fmt::try_init();
    
    // Test global unicast IPv6 (2000::/3)
    let global_ipv6 = IpAddr::V6("2001:db8::1".parse().unwrap());
    let global_priority = calculate_address_priority(&global_ipv6);
    info!("Global IPv6 priority: {}", global_priority);
    
    // Test link-local IPv6 (fe80::/10)
    let link_local_ipv6 = IpAddr::V6("fe80::1".parse().unwrap());
    let link_local_priority = calculate_address_priority(&link_local_ipv6);
    info!("Link-local IPv6 priority: {}", link_local_priority);
    
    // Test unique local IPv6 (fc00::/7)
    let unique_local_ipv6 = IpAddr::V6("fc00::1".parse().unwrap());
    let unique_local_priority = calculate_address_priority(&unique_local_ipv6);
    info!("Unique local IPv6 priority: {}", unique_local_priority);
    
    // Test IPv4 for comparison
    let ipv4_addr = IpAddr::V4("192.168.1.1".parse().unwrap());
    let ipv4_priority = calculate_address_priority(&ipv4_addr);
    info!("IPv4 priority: {}", ipv4_priority);
    
    // Assertions based on our priority system
    assert!(global_priority > link_local_priority, "Global IPv6 should have higher priority than link-local");
    assert!(global_priority > unique_local_priority, "Global IPv6 should have higher priority than unique local");
    assert!(unique_local_priority > link_local_priority, "Unique local should have higher priority than link-local");
    assert!(global_priority > ipv4_priority, "Global IPv6 should have higher priority than IPv4");
}

/// Test IPv6 address validation
#[test]
fn test_ipv6_address_validation() {
    let _ = tracing_subscriber::fmt::try_init();
    
    // Valid IPv6 addresses
    let valid_addresses = vec![
        "2001:db8::1",        // Global unicast
        "fe80::1",            // Link-local
        "fc00::1",            // Unique local
        "::1",                // Loopback
        "2001:db8:85a3::8a2e:370:7334", // Full format
    ];
    
    for addr_str in valid_addresses {
        let addr = IpAddr::V6(addr_str.parse().unwrap());
        let is_valid = is_valid_address(&addr);
        debug!("Address {} is valid: {}", addr_str, is_valid);
        
        // All should be valid except loopback
        if addr_str != "::1" {
            assert!(is_valid, "Address {} should be valid", addr_str);
        }
    }
    
    // Loopback should not be valid for NAT traversal
    let loopback = IpAddr::V6("::1".parse().unwrap());
    assert!(!is_valid_address(&loopback), "Loopback should not be valid for NAT traversal");
}

/// Test dual-stack socket binding
#[tokio::test]
async fn test_dual_stack_socket_binding() {
    let _ = tracing_subscriber::fmt::try_init();
    
    // Test IPv4 primary with IPv6 fallback
    let ipv4_result = bind_dual_stack_socket(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)).await;
    assert!(ipv4_result.is_ok(), "IPv4 dual-stack binding should succeed");
    
    if let Ok((ipv4_socket, ipv6_socket, addrs)) = ipv4_result {
        assert!(ipv4_socket.is_some(), "IPv4 socket should be bound");
        info!("IPv4 socket bound successfully");
        
        // IPv6 might fail on some systems, so we don't assert it
        if ipv6_socket.is_some() {
            info!("IPv6 socket also bound successfully");
        } else {
            info!("IPv6 socket binding failed (expected on some systems)");
        }
        
        assert!(!addrs.is_empty(), "At least one address should be bound");
        info!("Bound addresses: {:?}", addrs);
    }
    
    // Test IPv6 primary with IPv4 fallback
    let ipv6_result = bind_dual_stack_socket(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)).await;
    
    // IPv6 might not be available on all systems
    if let Ok((ipv4_socket, ipv6_socket, addrs)) = ipv6_result {
        assert!(ipv6_socket.is_some(), "IPv6 socket should be bound");
        info!("IPv6 socket bound successfully");
        
        if ipv4_socket.is_some() {
            info!("IPv4 socket also bound successfully");
        } else {
            info!("IPv4 socket binding failed");
        }
        
        assert!(!addrs.is_empty(), "At least one address should be bound");
        info!("Bound addresses: {:?}", addrs);
    } else {
        info!("IPv6 dual-stack binding failed (expected on some systems)");
    }
}

/// Test IPv6 candidate address creation
#[test]
fn test_ipv6_candidate_creation() {
    let _ = tracing_subscriber::fmt::try_init();
    
    // Create IPv6 candidate addresses
    let candidates = vec![
        create_ipv6_candidate("2001:db8::1", 8080, CandidateSource::Local),
        create_ipv6_candidate("fe80::1", 8080, CandidateSource::Local),
        create_ipv6_candidate("fc00::1", 8080, CandidateSource::Local),
    ];
    
    for candidate in candidates {
        assert!(candidate.address.is_ipv6(), "Candidate should be IPv6");
        assert!(candidate.priority > 0, "Candidate should have positive priority");
        assert_eq!(candidate.state, CandidateState::New);
        info!("Created candidate: {:?}", candidate);
    }
}

/// Test mixed IPv4 and IPv6 candidate sorting
#[test]
fn test_mixed_candidate_sorting() {
    let _ = tracing_subscriber::fmt::try_init();
    
    let mut candidates = vec![
        create_ipv4_candidate("192.168.1.1", 8080, CandidateSource::Local),
        create_ipv6_candidate("2001:db8::1", 8080, CandidateSource::Local),
        create_ipv4_candidate("10.0.0.1", 8080, CandidateSource::Local),
        create_ipv6_candidate("fe80::1", 8080, CandidateSource::Local),
        create_ipv6_candidate("fc00::1", 8080, CandidateSource::Local),
    ];
    
    // Sort by priority (descending)
    candidates.sort_by(|a, b| b.priority.cmp(&a.priority));
    
    info!("Sorted candidates:");
    for (i, candidate) in candidates.iter().enumerate() {
        info!("  {}: {} (priority: {})", i, candidate.address, candidate.priority);
    }
    
    // The first candidate should be the global IPv6 with highest priority
    assert!(candidates[0].address.is_ipv6(), "Highest priority should be IPv6");
    assert!(candidates[0].address.to_string().starts_with("[2001:db8"), "Should be global unicast IPv6");
}

/// Test IPv6 network interface discovery
#[test]
fn test_ipv6_interface_discovery() {
    let _ = tracing_subscriber::fmt::try_init();
    
    // Create mock network interfaces with IPv6 addresses
    let interfaces = vec![
        NetworkInterface {
            name: "eth0".to_string(),
            addresses: vec![
                "192.168.1.100:0".parse().unwrap(),
                "[2001:db8::100]:0".parse().unwrap(),
            ],
            is_up: true,
            is_wireless: false,
            mtu: Some(1500),
        },
        NetworkInterface {
            name: "wlan0".to_string(),
            addresses: vec![
                "10.0.0.50:0".parse().unwrap(),
                "[fe80::1]:0".parse().unwrap(),
            ],
            is_up: true,
            is_wireless: true,
            mtu: Some(1500),
        },
    ];
    
    let mut ipv4_count = 0;
    let mut ipv6_count = 0;
    
    for interface in &interfaces {
        for addr in &interface.addresses {
            if addr.is_ipv4() {
                ipv4_count += 1;
            } else if addr.is_ipv6() {
                ipv6_count += 1;
            }
        }
    }
    
    assert_eq!(ipv4_count, 2, "Should have 2 IPv4 addresses");
    assert_eq!(ipv6_count, 2, "Should have 2 IPv6 addresses");
    
    info!("Interface discovery test passed with {} IPv4 and {} IPv6 addresses", ipv4_count, ipv6_count);
}

/// Test IPv6 NAT traversal candidate pairing
#[test]
fn test_ipv6_candidate_pairing() {
    let _ = tracing_subscriber::fmt::try_init();
    
    // Create local and remote candidates
    let local_candidates = vec![
        create_ipv6_candidate("2001:db8::1", 8080, CandidateSource::Local),
        create_ipv4_candidate("192.168.1.1", 8080, CandidateSource::Local),
    ];
    
    let remote_candidates = vec![
        create_ipv6_candidate("2001:db8::2", 9090, CandidateSource::Local),
        create_ipv4_candidate("10.0.0.2", 9090, CandidateSource::Local),
    ];
    
    // Test pairing logic
    let mut pairs = Vec::new();
    for local in &local_candidates {
        for remote in &remote_candidates {
            // Only pair same IP version
            if local.address.is_ipv4() == remote.address.is_ipv4() {
                let pair_priority = calculate_pair_priority(local.priority, remote.priority);
                pairs.push((local.clone(), remote.clone(), pair_priority));
            }
        }
    }
    
    // Sort pairs by priority
    pairs.sort_by(|a, b| b.2.cmp(&a.2));
    
    assert_eq!(pairs.len(), 2, "Should have 2 valid pairs");
    
    // IPv6 pair should have higher priority
    assert!(pairs[0].0.address.is_ipv6(), "Highest priority pair should be IPv6");
    assert!(pairs[0].1.address.is_ipv6(), "Highest priority pair should be IPv6");
    
    info!("Candidate pairing test passed with {} pairs", pairs.len());
}

// Helper functions

/// Helper function to bind dual-stack socket
async fn bind_dual_stack_socket(addr: SocketAddr) -> Result<(Option<UdpSocket>, Option<UdpSocket>, Vec<SocketAddr>), Box<dyn std::error::Error>> {
    let mut ipv4_socket = None;
    let mut ipv6_socket = None;
    let mut bound_addresses = Vec::new();
    
    match addr {
        SocketAddr::V4(_) => {
            // Bind IPv4 first
            if let Ok(socket) = UdpSocket::bind(addr).await {
                let bound_addr = socket.local_addr()?;
                bound_addresses.push(bound_addr);
                ipv4_socket = Some(socket);
                
                // Try to bind IPv6 on same port
                let ipv6_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), bound_addr.port());
                if let Ok(socket) = UdpSocket::bind(ipv6_addr).await {
                    let ipv6_bound_addr = socket.local_addr()?;
                    bound_addresses.push(ipv6_bound_addr);
                    ipv6_socket = Some(socket);
                }
            }
        }
        SocketAddr::V6(_) => {
            // Bind IPv6 first
            if let Ok(socket) = UdpSocket::bind(addr).await {
                let bound_addr = socket.local_addr()?;
                bound_addresses.push(bound_addr);
                ipv6_socket = Some(socket);
                
                // Try to bind IPv4 on same port
                let ipv4_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), bound_addr.port());
                if let Ok(socket) = UdpSocket::bind(ipv4_addr).await {
                    let ipv4_bound_addr = socket.local_addr()?;
                    bound_addresses.push(ipv4_bound_addr);
                    ipv4_socket = Some(socket);
                }
            }
        }
    }
    
    if bound_addresses.is_empty() {
        return Err("Failed to bind any socket".into());
    }
    
    Ok((ipv4_socket, ipv6_socket, bound_addresses))
}

/// Helper function to create IPv6 candidate
fn create_ipv6_candidate(ip: &str, port: u16, source: CandidateSource) -> CandidateAddress {
    let addr = SocketAddr::new(IpAddr::V6(ip.parse().unwrap()), port);
    let priority = calculate_address_priority(&addr.ip());
    
    CandidateAddress {
        address: addr,
        priority,
        source,
        state: CandidateState::New,
    }
}

/// Helper function to create IPv4 candidate
fn create_ipv4_candidate(ip: &str, port: u16, source: CandidateSource) -> CandidateAddress {
    let addr = SocketAddr::new(IpAddr::V4(ip.parse().unwrap()), port);
    let priority = calculate_address_priority(&addr.ip());
    
    CandidateAddress {
        address: addr,
        priority,
        source,
        state: CandidateState::New,
    }
}

/// Helper function to calculate candidate pair priority
fn calculate_pair_priority(local_priority: u32, remote_priority: u32) -> u64 {
    // ICE-like pair priority calculation
    let (controlling_priority, controlled_priority) = if local_priority > remote_priority {
        (local_priority as u64, remote_priority as u64)
    } else {
        (remote_priority as u64, local_priority as u64)
    };
    
    (controlling_priority << 32) | controlled_priority
}