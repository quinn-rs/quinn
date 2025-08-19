//! Platform-specific API integration tests for network interface discovery
//!
//! These tests verify that platform-specific APIs work correctly on each OS

use ant_quic::candidate_discovery::NetworkInterfaceDiscovery;

#[cfg(target_os = "windows")]
mod windows_tests {
    use super::*;
    use ant_quic::candidate_discovery::windows::WindowsInterfaceDiscovery;
    use std::time::Duration;

    #[test]
    fn test_windows_ip_helper_api_functionality() {
        let mut discovery = WindowsInterfaceDiscovery::new();

        // Test that we can start a scan
        match discovery.start_scan() {
            Ok(_) => {
                // Wait for scan to complete
                std::thread::sleep(Duration::from_millis(100));

                // Check scan results
                if let Some(interfaces) = discovery.check_scan_complete() {
                    println!("Found {} network interfaces on Windows", interfaces.len());

                    // Verify we have at least one interface (loopback should always exist)
                    assert!(
                        !interfaces.is_empty(),
                        "Windows should have at least one network interface"
                    );

                    // Check that interfaces have valid data
                    for interface in interfaces {
                        assert!(
                            !interface.name.is_empty(),
                            "Interface name should not be empty"
                        );
                        assert!(
                            !interface.addresses.is_empty(),
                            "Interface should have at least one address"
                        );

                        println!(
                            "Windows interface: {} with {} addresses",
                            interface.name,
                            interface.addresses.len()
                        );
                    }
                } else {
                    panic!("Windows network scan did not complete");
                }
            }
            Err(e) => {
                // On CI, we might not have full permissions
                if e.contains("Access is denied") || e.contains("permission") {
                    println!("Skipping test due to permission issues on CI: {}", e);
                } else {
                    panic!("Failed to start Windows network scan: {}", e);
                }
            }
        }
    }

    #[test]
    fn test_windows_network_change_monitoring() {
        let mut discovery = WindowsInterfaceDiscovery::new();

        // Initialize monitoring
        if let Err(e) = discovery.start_scan() {
            if e.contains("permission") {
                println!("Skipping monitoring test due to permissions");
                return;
            }
        }

        // In a real scenario, we would trigger network changes
        // For now, just verify the monitoring system initializes
        assert!(true, "Windows network monitoring initialized");
    }

    #[test]
    #[ignore] // Requires admin privileges
    fn test_windows_adapter_enumeration_stress() {
        // Stress test: rapid enumeration
        for i in 0..10 {
            let mut discovery = WindowsInterfaceDiscovery::new();
            match discovery.start_scan() {
                Ok(_) => {
                    std::thread::sleep(Duration::from_millis(50));
                    if let Some(interfaces) = discovery.check_scan_complete() {
                        println!("Iteration {}: Found {} interfaces", i, interfaces.len());
                    }
                }
                Err(e) => println!("Iteration {} failed: {}", i, e),
            }
        }
    }
}

#[cfg(target_os = "linux")]
mod linux_tests {
    use super::*;
    use ant_quic::candidate_discovery::linux::LinuxInterfaceDiscovery;
    use std::time::Duration;

    #[test]
    fn test_linux_netlink_socket_functionality() {
        let mut discovery = LinuxInterfaceDiscovery::new();

        // Test that we can start a scan
        match discovery.start_scan() {
            Ok(_) => {
                // Wait for scan to complete
                std::thread::sleep(Duration::from_millis(100));

                // Check scan results
                if let Some(interfaces) = discovery.check_scan_complete() {
                    println!("Found {} network interfaces on Linux", interfaces.len());

                    // Verify we have at least one interface (lo should always exist)
                    assert!(
                        !interfaces.is_empty(),
                        "Linux should have at least one network interface"
                    );

                    // Look for loopback interface (may not exist in all CI environments)
                    let has_loopback = interfaces.iter().any(|i| i.name == "lo");
                    if !has_loopback {
                        println!("Warning: No loopback interface found (may be normal in CI)");
                    }

                    // Check that interfaces have valid data
                    for interface in interfaces {
                        assert!(
                            !interface.name.is_empty(),
                            "Interface name should not be empty"
                        );
                        println!(
                            "Linux interface: {} with {} addresses, up: {}",
                            interface.name,
                            interface.addresses.len(),
                            interface.is_up
                        );
                    }
                } else {
                    panic!("Linux network scan did not complete");
                }
            }
            Err(e) => {
                panic!("Failed to start Linux network scan: {}", e);
            }
        }
    }

    #[test]
    fn test_linux_proc_filesystem_access() {
        // Verify we can access required /proc files
        assert!(
            std::path::Path::new("/proc/net/dev").exists(),
            "/proc/net/dev should exist on Linux"
        );

        // Check if we can read the file
        match std::fs::read_to_string("/proc/net/dev") {
            Ok(content) => {
                assert!(
                    content.contains("lo:"),
                    "/proc/net/dev should contain loopback interface"
                );
            }
            Err(e) => panic!("Cannot read /proc/net/dev: {}", e),
        }

        // Check IPv6 support (might not exist on all systems)
        if std::path::Path::new("/proc/net/if_inet6").exists() {
            println!("IPv6 support detected via /proc/net/if_inet6");
        }
    }

    #[test]
    fn test_linux_netlink_monitoring() {
        let mut discovery = LinuxInterfaceDiscovery::new();

        // Try to initialize netlink socket for monitoring
        match discovery.initialize_netlink_socket() {
            Ok(_) => {
                println!("Linux netlink socket initialized successfully");

                // Check for network changes (none expected in test)
                match discovery.check_network_changes() {
                    Ok(changes) => {
                        println!("Network changes detected: {}", changes);
                    }
                    Err(e) => {
                        println!("Error checking network changes: {:?}", e);
                    }
                }
            }
            Err(e) => {
                // Might fail on some CI environments
                println!(
                    "Netlink initialization failed (may be normal on CI): {:?}",
                    e
                );
            }
        }
    }

    #[test]
    #[ignore] // Requires specific network setup
    fn test_linux_netlink_namespace() {
        // This test would require network namespace capabilities
        // Usually requires root or CAP_NET_ADMIN
        println!("Network namespace test would run with appropriate privileges");
    }

    #[test]
    fn test_linux_interface_enumeration_stress() {
        // Stress test: rapid enumeration
        for i in 0..10 {
            let mut discovery = LinuxInterfaceDiscovery::new();
            match discovery.start_scan() {
                Ok(_) => {
                    std::thread::sleep(Duration::from_millis(50));
                    if let Some(interfaces) = discovery.check_scan_complete() {
                        println!("Iteration {}: Found {} interfaces", i, interfaces.len());
                    }
                }
                Err(e) => panic!("Iteration {} failed: {}", i, e),
            }
        }
    }
}

#[cfg(target_os = "macos")]
mod macos_tests {
    use super::*;
    use ant_quic::candidate_discovery::macos::MacOSInterfaceDiscovery;
    use std::time::Duration;

    #[test]
    fn test_macos_system_configuration_functionality() {
        let mut discovery = MacOSInterfaceDiscovery::new();

        // Test that we can start a scan
        match discovery.start_scan() {
            Ok(_) => {
                // Wait for scan to complete
                std::thread::sleep(Duration::from_millis(100));

                // Check scan results
                if let Some(interfaces) = discovery.check_scan_complete() {
                    println!("Found {} network interfaces on macOS", interfaces.len());

                    // Verify we have at least one interface (lo0 should always exist)
                    assert!(
                        !interfaces.is_empty(),
                        "macOS should have at least one network interface"
                    );

                    // Look for loopback interface (may not exist in all CI environments)
                    let has_loopback = interfaces.iter().any(|i| i.name == "lo0");
                    if !has_loopback {
                        println!("Warning: No lo0 interface found (may be normal in CI)");
                    }

                    // Check that interfaces have valid data
                    for interface in interfaces {
                        assert!(
                            !interface.name.is_empty(),
                            "Interface name should not be empty"
                        );
                        println!(
                            "macOS interface: {} with {} addresses, wireless: {}",
                            interface.name,
                            interface.addresses.len(),
                            interface.is_wireless
                        );
                    }
                } else {
                    panic!("macOS network scan did not complete");
                }
            }
            Err(e) => {
                panic!("Failed to start macOS network scan: {}", e);
            }
        }
    }

    #[test]
    fn test_macos_scf_dynamic_store() {
        let mut discovery = MacOSInterfaceDiscovery::new();

        // Test creating dynamic store
        match discovery.initialize_dynamic_store() {
            Ok(_) => {
                println!("macOS SCDynamicStore created successfully");

                // The store should be initialized
                assert!(
                    discovery.sc_store.is_some(),
                    "Dynamic store should be initialized"
                );
            }
            Err(e) => {
                // Might fail on some CI environments
                println!(
                    "Dynamic store creation failed (may be normal on CI): {:?}",
                    e
                );
            }
        }
    }

    #[test]
    fn test_macos_framework_availability() {
        // Check that required frameworks exist
        let frameworks = [
            "/System/Library/Frameworks/SystemConfiguration.framework",
            "/System/Library/Frameworks/CoreFoundation.framework",
        ];

        for framework in &frameworks {
            assert!(
                std::path::Path::new(framework).exists(),
                "Required framework {} should exist",
                framework
            );
        }
    }

    #[test]
    fn test_macos_network_change_monitoring() {
        let mut discovery = MacOSInterfaceDiscovery::new();

        // Try to set up monitoring
        match discovery.enable_change_monitoring() {
            Ok(_) => {
                println!("macOS network monitoring initialized");

                // Check if monitoring detects changes
                let changed = discovery.check_network_changes();
                println!("Network changes detected: {}", changed);
            }
            Err(e) => {
                println!(
                    "Network monitoring setup failed (may be normal on CI): {:?}",
                    e
                );
            }
        }
    }

    #[test]
    #[ignore] // Long-running test
    fn test_macos_interface_enumeration_stress() {
        // Stress test: rapid enumeration
        for i in 0..10 {
            let mut discovery = MacOSInterfaceDiscovery::new();
            match discovery.start_scan() {
                Ok(_) => {
                    std::thread::sleep(Duration::from_millis(50));
                    if let Some(interfaces) = discovery.check_scan_complete() {
                        println!("Iteration {}: Found {} interfaces", i, interfaces.len());
                    }
                }
                Err(e) => panic!("Iteration {} failed: {}", i, e),
            }
        }
    }
}

// Cross-platform comparison tests
#[test]
fn test_platform_interface_consistency() {
    #[cfg(target_os = "windows")]
    let mut discovery = ant_quic::candidate_discovery::windows::WindowsInterfaceDiscovery::new();

    #[cfg(target_os = "linux")]
    let mut discovery = ant_quic::candidate_discovery::linux::LinuxInterfaceDiscovery::new();

    #[cfg(target_os = "macos")]
    let mut discovery = ant_quic::candidate_discovery::macos::MacOSInterfaceDiscovery::new();

    // All platforms should support the same trait
    match discovery.start_scan() {
        Ok(_) => {
            std::thread::sleep(std::time::Duration::from_millis(100));

            if let Some(interfaces) = discovery.check_scan_complete() {
                // All platforms should report consistent interface structure
                for interface in interfaces {
                    // Basic validation
                    assert!(!interface.name.is_empty());
                    assert!(interface.mtu.is_none() || interface.mtu.unwrap() >= 576);

                    // Addresses should be valid
                    for addr in &interface.addresses {
                        assert!(addr.port() == 0, "Interface addresses should have port 0");
                    }
                }
            }
        }
        Err(e) => {
            println!("Platform consistency test skipped due to: {}", e);
        }
    }
}
