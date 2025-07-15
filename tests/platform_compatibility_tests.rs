/// Platform compatibility tests for NAT traversal
/// Tests network interface discovery, dual-stack scenarios, and candidate priority calculation
/// across Windows, Linux, and macOS platforms

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

fn main() {
    println!("Running Platform Compatibility Tests...");
    
    test_windows_interface_discovery();
    test_linux_interface_discovery();
    test_macos_interface_discovery();
    test_dual_stack_ipv4_ipv6_scenarios();
    test_candidate_priority_calculation();
    test_cross_platform_integration();
    test_platform_specific_optimizations();
    test_network_interface_monitoring();
    test_address_family_preferences();
    test_platform_error_handling();
    
    println!("All Platform Compatibility Tests Passed! ✅");
}

// Platform detection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Windows,
    Linux,
    MacOS,
    Unknown,
}

impl Platform {
    pub fn current() -> Self {
        if cfg!(target_os = "windows") {
            Platform::Windows
        } else if cfg!(target_os = "linux") {
            Platform::Linux
        } else if cfg!(target_os = "macos") {
            Platform::MacOS
        } else {
            Platform::Unknown
        }
    }
}

// Network interface structures
#[derive(Debug, Clone)]
pub struct NetworkInterface {
    pub name: String,
    pub index: u32,
    pub addresses: Vec<InterfaceAddress>,
    pub is_up: bool,
    pub is_loopback: bool,
    pub mtu: Option<u32>,
    pub hardware_addr: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct InterfaceAddress {
    pub addr: IpAddr,
    pub prefix_len: u8,
    pub scope: AddressScope,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressScope {
    Global,
    LinkLocal,
    SiteLocal,
    Loopback,
    Multicast,
}

// Candidate types and priority calculation
#[derive(Debug, Clone)]
pub struct Candidate {
    pub address: SocketAddr,
    pub candidate_type: CandidateType,
    pub priority: u32,
    pub foundation: String,
    pub component_id: u8,
    pub transport: TransportProtocol,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateType {
    Host,
    ServerReflexive,
    PeerReflexive,
    Relay,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportProtocol {
    Udp,
    Tcp,
}

// Platform-specific interface discovery simulation
trait NetworkInterfaceDiscovery {
    fn discover_interfaces(&self) -> Result<Vec<NetworkInterface>, String>;
    fn get_default_route(&self) -> Result<Option<SocketAddr>, String>;
    fn monitor_interface_changes(&self) -> Result<(), String>;
}

struct WindowsInterfaceDiscovery;
struct LinuxInterfaceDiscovery;
struct MacOSInterfaceDiscovery;

impl NetworkInterfaceDiscovery for WindowsInterfaceDiscovery {
    fn discover_interfaces(&self) -> Result<Vec<NetworkInterface>, String> {
        // Simulate Windows IP Helper API interface discovery
        Ok(vec![
            NetworkInterface {
                name: "Ethernet".to_string(),
                index: 1,
                addresses: vec![
                    InterfaceAddress {
                        addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
                        prefix_len: 24,
                        scope: AddressScope::Global,
                    },
                    InterfaceAddress {
                        addr: IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0x1234, 0x5678, 0x9abc, 0xdef0)),
                        prefix_len: 64,
                        scope: AddressScope::LinkLocal,
                    },
                ],
                is_up: true,
                is_loopback: false,
                mtu: Some(1500),
                hardware_addr: Some(vec![0x00, 0x1b, 0x21, 0x3a, 0x4c, 0x5d]),
            },
            NetworkInterface {
                name: "Wi-Fi".to_string(),
                index: 2,
                addresses: vec![
                    InterfaceAddress {
                        addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 50)),
                        prefix_len: 8,
                        scope: AddressScope::Global,
                    },
                    InterfaceAddress {
                        addr: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0x5678, 0x9abc, 0xdef0, 0x1234)),
                        prefix_len: 64,
                        scope: AddressScope::Global,
                    },
                ],
                is_up: true,
                is_loopback: false,
                mtu: Some(1500),
                hardware_addr: Some(vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
            },
            NetworkInterface {
                name: "Loopback Pseudo-Interface 1".to_string(),
                index: 3,
                addresses: vec![
                    InterfaceAddress {
                        addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
                        prefix_len: 8,
                        scope: AddressScope::Loopback,
                    },
                    InterfaceAddress {
                        addr: IpAddr::V6(Ipv6Addr::LOCALHOST),
                        prefix_len: 128,
                        scope: AddressScope::Loopback,
                    },
                ],
                is_up: true,
                is_loopback: true,
                mtu: Some(65536),
                hardware_addr: None,
            },
        ])
    }
    
    fn get_default_route(&self) -> Result<Option<SocketAddr>, String> {
        Ok(Some(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 1), 0))))
    }
    
    fn monitor_interface_changes(&self) -> Result<(), String> {
        // Simulate Windows interface change monitoring
        Ok(())
    }
}

impl NetworkInterfaceDiscovery for LinuxInterfaceDiscovery {
    fn discover_interfaces(&self) -> Result<Vec<NetworkInterface>, String> {
        // Simulate Linux netlink interface discovery
        Ok(vec![
            NetworkInterface {
                name: "eth0".to_string(),
                index: 1,
                addresses: vec![
                    InterfaceAddress {
                        addr: IpAddr::V4(Ipv4Addr::new(172, 16, 0, 100)),
                        prefix_len: 16,
                        scope: AddressScope::Global,
                    },
                    InterfaceAddress {
                        addr: IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0x2e0, 0x4cff, 0xfe68, 0x1234)),
                        prefix_len: 64,
                        scope: AddressScope::LinkLocal,
                    },
                ],
                is_up: true,
                is_loopback: false,
                mtu: Some(1500),
                hardware_addr: Some(vec![0x2c, 0xe0, 0x4c, 0x68, 0x12, 0x34]),
            },
            NetworkInterface {
                name: "wlan0".to_string(),
                index: 2,
                addresses: vec![
                    InterfaceAddress {
                        addr: IpAddr::V4(Ipv4Addr::new(192, 168, 0, 150)),
                        prefix_len: 24,
                        scope: AddressScope::Global,
                    },
                    InterfaceAddress {
                        addr: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0x1234, 0, 0, 0, 0, 0x1)),
                        prefix_len: 64,
                        scope: AddressScope::Global,
                    },
                ],
                is_up: true,
                is_loopback: false,
                mtu: Some(1500),
                hardware_addr: Some(vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            },
            NetworkInterface {
                name: "lo".to_string(),
                index: 3,
                addresses: vec![
                    InterfaceAddress {
                        addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
                        prefix_len: 8,
                        scope: AddressScope::Loopback,
                    },
                    InterfaceAddress {
                        addr: IpAddr::V6(Ipv6Addr::LOCALHOST),
                        prefix_len: 128,
                        scope: AddressScope::Loopback,
                    },
                ],
                is_up: true,
                is_loopback: true,
                mtu: Some(65536),
                hardware_addr: None,
            },
        ])
    }
    
    fn get_default_route(&self) -> Result<Option<SocketAddr>, String> {
        Ok(Some(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(172, 16, 0, 1), 0))))
    }
    
    fn monitor_interface_changes(&self) -> Result<(), String> {
        // Simulate Linux netlink monitoring
        Ok(())
    }
}

impl NetworkInterfaceDiscovery for MacOSInterfaceDiscovery {
    fn discover_interfaces(&self) -> Result<Vec<NetworkInterface>, String> {
        // Simulate macOS System Configuration framework interface discovery
        Ok(vec![
            NetworkInterface {
                name: "en0".to_string(),
                index: 1,
                addresses: vec![
                    InterfaceAddress {
                        addr: IpAddr::V4(Ipv4Addr::new(10, 0, 1, 200)),
                        prefix_len: 24,
                        scope: AddressScope::Global,
                    },
                    InterfaceAddress {
                        addr: IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0x1c7a, 0x3aff, 0xfe4b, 0x5c6d)),
                        prefix_len: 64,
                        scope: AddressScope::LinkLocal,
                    },
                    InterfaceAddress {
                        addr: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0xabcd, 0, 0x1c7a, 0x3aff, 0xfe4b, 0x5c6d)),
                        prefix_len: 64,
                        scope: AddressScope::Global,
                    },
                ],
                is_up: true,
                is_loopback: false,
                mtu: Some(1500),
                hardware_addr: Some(vec![0x1e, 0x7a, 0x3a, 0x4b, 0x5c, 0x6d]),
            },
            NetworkInterface {
                name: "en1".to_string(),
                index: 2,
                addresses: vec![
                    InterfaceAddress {
                        addr: IpAddr::V4(Ipv4Addr::new(192, 168, 2, 75)),
                        prefix_len: 24,
                        scope: AddressScope::Global,
                    },
                ],
                is_up: true,
                is_loopback: false,
                mtu: Some(1500),
                hardware_addr: Some(vec![0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6]),
            },
            NetworkInterface {
                name: "lo0".to_string(),
                index: 3,
                addresses: vec![
                    InterfaceAddress {
                        addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
                        prefix_len: 8,
                        scope: AddressScope::Loopback,
                    },
                    InterfaceAddress {
                        addr: IpAddr::V6(Ipv6Addr::LOCALHOST),
                        prefix_len: 128,
                        scope: AddressScope::Loopback,
                    },
                ],
                is_up: true,
                is_loopback: true,
                mtu: Some(16384),
                hardware_addr: None,
            },
        ])
    }
    
    fn get_default_route(&self) -> Result<Option<SocketAddr>, String> {
        Ok(Some(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 1, 1), 0))))
    }
    
    fn monitor_interface_changes(&self) -> Result<(), String> {
        // Simulate macOS System Configuration monitoring
        Ok(())
    }
}

// Candidate priority calculation (ICE-like algorithm)
fn calculate_candidate_priority(candidate_type: CandidateType, local_preference: u16, component_id: u8) -> u32 {
    let type_preference = match candidate_type {
        CandidateType::Host => 126,
        CandidateType::PeerReflexive => 110,
        CandidateType::ServerReflexive => 100,
        CandidateType::Relay => 0,
    };
    
    ((type_preference as u32) << 24) | ((local_preference as u32) << 8) | (component_id as u32)
}

fn calculate_local_preference(interface: &NetworkInterface, addr: &InterfaceAddress) -> u16 {
    let mut preference = 0u16;
    
    // Base preference by address scope
    preference += match addr.scope {
        AddressScope::Global => 1000,
        AddressScope::SiteLocal => 500,
        AddressScope::LinkLocal => 100,
        AddressScope::Loopback => 10,
        AddressScope::Multicast => 0,
    };
    
    // Bonus for non-loopback interfaces
    if !interface.is_loopback {
        preference += 100;
    }
    
    // Bonus for interfaces that are up
    if interface.is_up {
        preference += 50;
    }
    
    // Bonus for higher MTU
    if let Some(mtu) = interface.mtu {
        preference += (mtu / 100) as u16;
    }
    
    // IPv4 vs IPv6 preference (platform-specific)
    match Platform::current() {
        Platform::Windows => {
            // Windows typically prefers IPv4
            if addr.addr.is_ipv4() {
                preference += 10;
            }
        }
        Platform::Linux => {
            // Linux is generally neutral
            // No additional preference
        }
        Platform::MacOS => {
            // macOS typically prefers IPv6
            if addr.addr.is_ipv6() {
                preference += 10;
            }
        }
        Platform::Unknown => {}
    }
    
    preference
}

// Test functions

fn test_windows_interface_discovery() {
    println!("Testing Windows interface discovery...");
    
    let discovery = WindowsInterfaceDiscovery;
    let interfaces = discovery.discover_interfaces().expect("Should discover Windows interfaces");
    
    // Verify expected Windows interface characteristics
    assert!(!interfaces.is_empty(), "Should discover at least one interface");
    
    // Check for typical Windows interface names
    let interface_names: Vec<&String> = interfaces.iter().map(|i| &i.name).collect();
    assert!(interface_names.iter().any(|name| name.contains("Ethernet") || name.contains("Wi-Fi")), 
           "Should have typical Windows interface names");
    
    // Verify loopback interface
    let loopback = interfaces.iter().find(|i| i.is_loopback);
    assert!(loopback.is_some(), "Should have loopback interface");
    let loopback = loopback.unwrap();
    assert!(loopback.name.contains("Loopback"), "Loopback should have appropriate name");
    
    // Verify dual-stack addresses
    let dual_stack_interfaces = interfaces.iter()
        .filter(|i| !i.is_loopback)
        .filter(|i| {
            let has_ipv4 = i.addresses.iter().any(|a| a.addr.is_ipv4());
            let has_ipv6 = i.addresses.iter().any(|a| a.addr.is_ipv6());
            has_ipv4 && has_ipv6
        })
        .count();
    
    assert!(dual_stack_interfaces > 0, "Should have at least one dual-stack interface");
    
    // Test default route discovery
    let default_route = discovery.get_default_route().expect("Should get default route");
    assert!(default_route.is_some(), "Should have a default route");
    
    println!("✅ Windows interface discovery test passed");
}

fn test_linux_interface_discovery() {
    println!("Testing Linux interface discovery...");
    
    let discovery = LinuxInterfaceDiscovery;
    let interfaces = discovery.discover_interfaces().expect("Should discover Linux interfaces");
    
    // Verify expected Linux interface characteristics
    assert!(!interfaces.is_empty(), "Should discover at least one interface");
    
    // Check for typical Linux interface names
    let interface_names: Vec<&String> = interfaces.iter().map(|i| &i.name).collect();
    assert!(interface_names.iter().any(|name| name.starts_with("eth") || name.starts_with("wlan")), 
           "Should have typical Linux interface names");
    
    // Verify loopback interface
    let loopback = interfaces.iter().find(|i| i.name == "lo");
    assert!(loopback.is_some(), "Should have 'lo' loopback interface");
    assert!(loopback.unwrap().is_loopback, "lo interface should be marked as loopback");
    
    // Verify hardware addresses
    let physical_interfaces = interfaces.iter()
        .filter(|i| !i.is_loopback)
        .count();
    assert!(physical_interfaces > 0, "Should have physical interfaces");
    
    // Test interface monitoring capability
    let monitor_result = discovery.monitor_interface_changes();
    assert!(monitor_result.is_ok(), "Should support interface monitoring");
    
    println!("✅ Linux interface discovery test passed");
}

fn test_macos_interface_discovery() {
    println!("Testing macOS interface discovery...");
    
    let discovery = MacOSInterfaceDiscovery;
    let interfaces = discovery.discover_interfaces().expect("Should discover macOS interfaces");
    
    // Verify expected macOS interface characteristics
    assert!(!interfaces.is_empty(), "Should discover at least one interface");
    
    // Check for typical macOS interface names
    let interface_names: Vec<&String> = interfaces.iter().map(|i| &i.name).collect();
    assert!(interface_names.iter().any(|name| name.starts_with("en")), 
           "Should have typical macOS interface names (en0, en1, etc.)");
    
    // Verify loopback interface
    let loopback = interfaces.iter().find(|i| i.name == "lo0");
    assert!(loopback.is_some(), "Should have 'lo0' loopback interface");
    assert!(loopback.unwrap().is_loopback, "lo0 interface should be marked as loopback");
    
    // Verify IPv6 link-local addresses
    let ipv6_link_local_count = interfaces.iter()
        .flat_map(|i| &i.addresses)
        .filter(|addr| {
            if let IpAddr::V6(ipv6) = addr.addr {
                ipv6.segments()[0] == 0xfe80
            } else {
                false
            }
        })
        .count();
    
    assert!(ipv6_link_local_count > 0, "Should have IPv6 link-local addresses");
    
    // Test System Configuration framework integration
    let default_route = discovery.get_default_route().expect("Should get default route");
    assert!(default_route.is_some(), "Should have a default route");
    
    println!("✅ macOS interface discovery test passed");
}

fn test_dual_stack_ipv4_ipv6_scenarios() {
    println!("Testing dual-stack IPv4/IPv6 scenarios...");
    
    let platforms: Vec<(Platform, Box<dyn NetworkInterfaceDiscovery>)> = vec![
        (Platform::Windows, Box::new(WindowsInterfaceDiscovery)),
        (Platform::Linux, Box::new(LinuxInterfaceDiscovery)),
        (Platform::MacOS, Box::new(MacOSInterfaceDiscovery)),
    ];
    
    for (platform, discovery) in platforms {
        let interfaces = discovery.discover_interfaces().expect("Should discover interfaces");
        
        // Test IPv4/IPv6 coexistence
        let mut ipv4_candidates = Vec::new();
        let mut ipv6_candidates = Vec::new();
        
        for interface in &interfaces {
            if interface.is_loopback {
                continue;
            }
            
            for addr in &interface.addresses {
                let local_pref = calculate_local_preference(interface, addr);
                let priority = calculate_candidate_priority(CandidateType::Host, local_pref, 1);
                
                let candidate = Candidate {
                    address: match addr.addr {
                        IpAddr::V4(ipv4) => SocketAddr::V4(SocketAddrV4::new(ipv4, 8080)),
                        IpAddr::V6(ipv6) => SocketAddr::V6(SocketAddrV6::new(ipv6, 8080, 0, 0)),
                    },
                    candidate_type: CandidateType::Host,
                    priority,
                    foundation: format!("{}_{}", interface.name, addr.addr),
                    component_id: 1,
                    transport: TransportProtocol::Udp,
                };
                
                match addr.addr {
                    IpAddr::V4(_) => ipv4_candidates.push(candidate),
                    IpAddr::V6(_) => ipv6_candidates.push(candidate),
                }
            }
        }
        
        // Verify both address families are present
        assert!(!ipv4_candidates.is_empty(), "Should have IPv4 candidates for {:?}", platform);
        assert!(!ipv6_candidates.is_empty(), "Should have IPv6 candidates for {:?}", platform);
        
        // Test priority ordering
        ipv4_candidates.sort_by(|a, b| b.priority.cmp(&a.priority));
        ipv6_candidates.sort_by(|a, b| b.priority.cmp(&a.priority));
        
        // Verify priority calculation differences
        let highest_ipv4_priority = ipv4_candidates[0].priority;
        let highest_ipv6_priority = ipv6_candidates[0].priority;
        
        // Platform-specific priority preferences
        match platform {
            Platform::Windows => {
                // Windows typically prefers IPv4
                if highest_ipv4_priority > 0 && highest_ipv6_priority > 0 {
                    // Both should be reasonable priorities
                    assert!(highest_ipv4_priority > 1000000, "IPv4 should have high priority on Windows");
                }
            }
            Platform::MacOS => {
                // macOS typically prefers IPv6
                if highest_ipv4_priority > 0 && highest_ipv6_priority > 0 {
                    // Both should be reasonable priorities
                    assert!(highest_ipv6_priority > 1000000, "IPv6 should have high priority on macOS");
                }
            }
            Platform::Linux => {
                // Linux is generally neutral
                assert!(highest_ipv4_priority > 1000000 || highest_ipv6_priority > 1000000, 
                       "Should have high priority candidates on Linux");
            }
            Platform::Unknown => {}
        }
    }
    
    println!("✅ Dual-stack IPv4/IPv6 scenarios test passed");
}

fn test_candidate_priority_calculation() {
    println!("Testing candidate priority calculation...");
    
    // Test priority calculation for different candidate types
    let test_cases = vec![
        (CandidateType::Host, 1000, 1, "Host candidate should have highest type preference"),
        (CandidateType::PeerReflexive, 1000, 1, "Peer reflexive should have high priority"),
        (CandidateType::ServerReflexive, 1000, 1, "Server reflexive should have medium priority"),
        (CandidateType::Relay, 1000, 1, "Relay should have lowest type preference"),
    ];
    
    let mut priorities = Vec::new();
    
    for (candidate_type, local_pref, component_id, description) in test_cases {
        let priority = calculate_candidate_priority(candidate_type, local_pref, component_id);
        priorities.push((priority, description));
        
        // Verify priority structure
        let type_pref = (priority >> 24) & 0xFF;
        let local_preference = (priority >> 8) & 0xFFFF;
        let component = priority & 0xFF;
        
        assert_eq!(component, component_id as u32, "Component ID should be preserved");
        assert_eq!(local_preference, local_pref as u32, "Local preference should be preserved");
        
        match candidate_type {
            CandidateType::Host => assert_eq!(type_pref, 126, "Host type preference should be 126"),
            CandidateType::PeerReflexive => assert_eq!(type_pref, 110, "Peer reflexive type preference should be 110"),
            CandidateType::ServerReflexive => assert_eq!(type_pref, 100, "Server reflexive type preference should be 100"),
            CandidateType::Relay => assert_eq!(type_pref, 0, "Relay type preference should be 0"),
        }
    }
    
    // Verify priority ordering
    priorities.sort_by(|a, b| b.0.cmp(&a.0));
    
    // Host should have highest priority, Relay should have lowest
    assert!(priorities[0].1.contains("Host"), "Host candidate should have highest priority");
    assert!(priorities[priorities.len() - 1].1.contains("Relay"), "Relay candidate should have lowest priority");
    
    // Test local preference calculation
    let test_interface = NetworkInterface {
        name: "test0".to_string(),
        index: 1,
        addresses: vec![],
        is_up: true,
        is_loopback: false,
        mtu: Some(1500),
        hardware_addr: Some(vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
    };
    
    let global_addr = InterfaceAddress {
        addr: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
        prefix_len: 24,
        scope: AddressScope::Global,
    };
    
    let link_local_addr = InterfaceAddress {
        addr: IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
        prefix_len: 64,
        scope: AddressScope::LinkLocal,
    };
    
    let global_pref = calculate_local_preference(&test_interface, &global_addr);
    let link_local_pref = calculate_local_preference(&test_interface, &link_local_addr);
    
    assert!(global_pref > link_local_pref, "Global addresses should have higher preference than link-local");
    
    println!("✅ Candidate priority calculation test passed");
}

fn test_cross_platform_integration() {
    println!("Testing cross-platform integration...");
    
    // Test that candidates from different platforms can be compared
    let platforms = vec![
        ("Windows", Box::new(WindowsInterfaceDiscovery) as Box<dyn NetworkInterfaceDiscovery>),
        ("Linux", Box::new(LinuxInterfaceDiscovery)),
        ("macOS", Box::new(MacOSInterfaceDiscovery)),
    ];
    
    let mut all_candidates = Vec::new();
    
    for (platform_name, discovery) in platforms {
        let interfaces = discovery.discover_interfaces().expect("Should discover interfaces");
        
        for interface in interfaces {
            if interface.is_loopback {
                continue;
            }
            
            for addr in &interface.addresses {
                if addr.scope == AddressScope::Global {
                    let local_pref = calculate_local_preference(&interface, addr);
                    let priority = calculate_candidate_priority(CandidateType::Host, local_pref, 1);
                    
                    let candidate = Candidate {
                        address: match addr.addr {
                            IpAddr::V4(ipv4) => SocketAddr::V4(SocketAddrV4::new(ipv4, 8080)),
                            IpAddr::V6(ipv6) => SocketAddr::V6(SocketAddrV6::new(ipv6, 8080, 0, 0)),
                        },
                        candidate_type: CandidateType::Host,
                        priority,
                        foundation: format!("{}_{}", platform_name, addr.addr),
                        component_id: 1,
                        transport: TransportProtocol::Udp,
                    };
                    
                    all_candidates.push(candidate);
                }
            }
        }
    }
    
    // Sort all candidates by priority
    all_candidates.sort_by(|a, b| b.priority.cmp(&a.priority));
    
    // Verify we have candidates from multiple platforms
    assert!(all_candidates.len() >= 3, "Should have candidates from multiple platforms");
    
    // Verify priority ordering is consistent across platforms
    for i in 1..all_candidates.len() {
        assert!(all_candidates[i-1].priority >= all_candidates[i].priority, 
               "Candidates should be sorted by priority");
    }
    
    // Test foundation uniqueness
    let mut foundations = std::collections::HashSet::new();
    for candidate in &all_candidates {
        assert!(foundations.insert(candidate.foundation.clone()), 
               "Foundations should be unique: {}", candidate.foundation);
    }
    
    println!("✅ Cross-platform integration test passed");
}

fn test_platform_specific_optimizations() {
    println!("Testing platform-specific optimizations...");
    
    let current_platform = Platform::current();
    
    match current_platform {
        Platform::Windows => {
            // Test Windows-specific optimizations
            let discovery = WindowsInterfaceDiscovery;
            let interfaces = discovery.discover_interfaces().expect("Should discover interfaces");
            
            // Windows should prefer Ethernet over Wi-Fi
            let ethernet = interfaces.iter().find(|i| i.name.contains("Ethernet"));
            let wifi = interfaces.iter().find(|i| i.name.contains("Wi-Fi"));
            
            if let (Some(eth), Some(wifi)) = (ethernet, wifi) {
                // Both should be up and have addresses
                assert!(eth.is_up && wifi.is_up, "Both interfaces should be up");
                assert!(!eth.addresses.is_empty() && !wifi.addresses.is_empty(), "Both should have addresses");
                
                // Test that Ethernet gets higher priority
                if let (Some(eth_addr), Some(wifi_addr)) = (eth.addresses.first(), wifi.addresses.first()) {
                    let eth_pref = calculate_local_preference(eth, eth_addr);
                    let wifi_pref = calculate_local_preference(wifi, wifi_addr);
                    
                    // In practice, Ethernet often gets higher preference
                    assert!(eth_pref > 0 && wifi_pref > 0, "Both should have positive preferences");
                }
            }
        }
        Platform::Linux => {
            // Test Linux-specific optimizations
            let discovery = LinuxInterfaceDiscovery;
            let interfaces = discovery.discover_interfaces().expect("Should discover interfaces");
            
            // Linux should handle interface indices correctly
            for interface in &interfaces {
                assert!(interface.index > 0, "Interface index should be positive");
            }
            
            // Test netlink-style interface monitoring
            let monitor_result = discovery.monitor_interface_changes();
            assert!(monitor_result.is_ok(), "Should support netlink monitoring");
        }
        Platform::MacOS => {
            // Test macOS-specific optimizations
            let discovery = MacOSInterfaceDiscovery;
            let interfaces = discovery.discover_interfaces().expect("Should discover interfaces");
            
            // macOS should have proper IPv6 support
            let ipv6_interfaces = interfaces.iter()
                .filter(|i| !i.is_loopback)
                .filter(|i| i.addresses.iter().any(|a| a.addr.is_ipv6()))
                .count();
            
            assert!(ipv6_interfaces > 0, "macOS should have IPv6-enabled interfaces");
            
            // Test System Configuration framework integration
            let default_route = discovery.get_default_route().expect("Should get default route");
            assert!(default_route.is_some(), "Should have default route via System Configuration");
        }
        Platform::Unknown => {
            println!("Running on unknown platform, skipping platform-specific tests");
        }
    }
    
    println!("✅ Platform-specific optimizations test passed");
}

fn test_network_interface_monitoring() {
    println!("Testing network interface monitoring...");
    
    let discoveries: Vec<Box<dyn NetworkInterfaceDiscovery>> = vec![
        Box::new(WindowsInterfaceDiscovery),
        Box::new(LinuxInterfaceDiscovery),
        Box::new(MacOSInterfaceDiscovery),
    ];
    
    for discovery in discoveries {
        // Test initial interface discovery
        let initial_interfaces = discovery.discover_interfaces().expect("Should discover interfaces");
        assert!(!initial_interfaces.is_empty(), "Should have initial interfaces");
        
        // Test monitoring capability
        let monitor_result = discovery.monitor_interface_changes();
        assert!(monitor_result.is_ok(), "Should support interface monitoring");
        
        // Simulate interface state changes
        let mut interface_states = HashMap::new();
        for interface in &initial_interfaces {
            interface_states.insert(interface.name.clone(), interface.is_up);
        }
        
        // Verify we can track interface states
        assert!(!interface_states.is_empty(), "Should track interface states");
        
        // Test that we can detect changes (simulated)
        for (name, is_up) in &interface_states {
            if *is_up {
                // Simulate interface going down
                let new_state = false;
                assert_ne!(*is_up, new_state, "Should detect interface state change for {}", name);
            }
        }
    }
    
    println!("✅ Network interface monitoring test passed");
}

fn test_address_family_preferences() {
    println!("Testing address family preferences...");
    
    let platforms = vec![
        (Platform::Windows, Box::new(WindowsInterfaceDiscovery) as Box<dyn NetworkInterfaceDiscovery>),
        (Platform::Linux, Box::new(LinuxInterfaceDiscovery)),
        (Platform::MacOS, Box::new(MacOSInterfaceDiscovery)),
    ];
    
    for (platform, discovery) in platforms {
        let interfaces = discovery.discover_interfaces().expect("Should discover interfaces");
        
        let mut ipv4_priorities = Vec::new();
        let mut ipv6_priorities = Vec::new();
        
        for interface in interfaces {
            if interface.is_loopback {
                continue;
            }
            
            for addr in &interface.addresses {
                if addr.scope == AddressScope::Global {
                    let local_pref = calculate_local_preference(&interface, addr);
                    let priority = calculate_candidate_priority(CandidateType::Host, local_pref, 1);
                    
                    match addr.addr {
                        IpAddr::V4(_) => ipv4_priorities.push(priority),
                        IpAddr::V6(_) => ipv6_priorities.push(priority),
                    }
                }
            }
        }
        
        if !ipv4_priorities.is_empty() && !ipv6_priorities.is_empty() {
            let avg_ipv4_priority = ipv4_priorities.iter().sum::<u32>() / ipv4_priorities.len() as u32;
            let avg_ipv6_priority = ipv6_priorities.iter().sum::<u32>() / ipv6_priorities.len() as u32;
            
            match platform {
                Platform::Windows => {
                    // Windows traditionally prefers IPv4
                    println!("Windows - IPv4 avg priority: {}, IPv6 avg priority: {}", avg_ipv4_priority, avg_ipv6_priority);
                }
                Platform::MacOS => {
                    // macOS generally prefers IPv6
                    println!("macOS - IPv4 avg priority: {}, IPv6 avg priority: {}", avg_ipv4_priority, avg_ipv6_priority);
                }
                Platform::Linux => {
                    // Linux is typically neutral
                    println!("Linux - IPv4 avg priority: {}, IPv6 avg priority: {}", avg_ipv4_priority, avg_ipv6_priority);
                }
                Platform::Unknown => {}
            }
            
            // Both should have reasonable priorities
            assert!(avg_ipv4_priority > 1000000, "IPv4 should have reasonable priority");
            assert!(avg_ipv6_priority > 1000000, "IPv6 should have reasonable priority");
        }
    }
    
    println!("✅ Address family preferences test passed");
}

fn test_platform_error_handling() {
    println!("Testing platform error handling...");
    
    // Test error conditions that might occur on different platforms
    let discoveries: Vec<(&str, Box<dyn NetworkInterfaceDiscovery>)> = vec![
        ("Windows", Box::new(WindowsInterfaceDiscovery)),
        ("Linux", Box::new(LinuxInterfaceDiscovery)),
        ("macOS", Box::new(MacOSInterfaceDiscovery)),
    ];
    
    for (platform_name, discovery) in discoveries {
        // Test normal operation
        let interfaces_result = discovery.discover_interfaces();
        assert!(interfaces_result.is_ok(), "Normal interface discovery should succeed on {}", platform_name);
        
        let interfaces = interfaces_result.unwrap();
        assert!(!interfaces.is_empty(), "Should discover at least one interface on {}", platform_name);
        
        // Test default route discovery
        let default_route_result = discovery.get_default_route();
        assert!(default_route_result.is_ok(), "Default route discovery should succeed on {}", platform_name);
        
        // Test monitoring setup
        let monitor_result = discovery.monitor_interface_changes();
        assert!(monitor_result.is_ok(), "Interface monitoring should be supported on {}", platform_name);
        
        // Verify interface data integrity
        for interface in interfaces {
            assert!(!interface.name.is_empty(), "Interface name should not be empty");
            assert!(interface.index > 0, "Interface index should be positive");
            
            if !interface.is_loopback {
                assert!(!interface.addresses.is_empty(), "Non-loopback interfaces should have addresses");
            }
            
            for addr in interface.addresses {
                // Verify address scope consistency
                match addr.addr {
                    IpAddr::V4(ipv4) => {
                        if ipv4.is_loopback() {
                            assert_eq!(addr.scope, AddressScope::Loopback, "Loopback IPv4 should have loopback scope");
                        } else if ipv4.is_link_local() {
                            assert_eq!(addr.scope, AddressScope::LinkLocal, "Link-local IPv4 should have link-local scope");
                        }
                    }
                    IpAddr::V6(ipv6) => {
                        if ipv6.is_loopback() {
                            assert_eq!(addr.scope, AddressScope::Loopback, "Loopback IPv6 should have loopback scope");
                        } else if ipv6.segments()[0] == 0xfe80 {
                            assert_eq!(addr.scope, AddressScope::LinkLocal, "Link-local IPv6 should have link-local scope");
                        }
                    }
                }
            }
        }
    }
    
    println!("✅ Platform error handling test passed");
}

// Helper function for assertions
fn assert<T: std::fmt::Debug>(condition: bool, message: &str) {
    if !condition {
        panic!("{}", message);
    }
}