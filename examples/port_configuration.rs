// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Port configuration examples for ant-quic
//!
//! This example demonstrates various port binding strategies including:
//! - OS-assigned ports (recommended default)
//! - Explicit port binding
//! - Port ranges
//! - IPv4/IPv6 configuration
//! - Retry behaviors

use ant_quic::config::{EndpointPortConfig, IpMode, PortBinding, PortRetryBehavior, bind_endpoint};

fn main() {
    println!("=== ant-quic Port Configuration Examples ===\n");

    // Example 1: OS-assigned port (recommended default)
    println!("Example 1: OS-assigned port");
    let config = EndpointPortConfig::default();
    match bind_endpoint(&config) {
        Ok(bound) => {
            println!("✓ Successfully bound to: {:?}", bound.primary_addr());
            println!("  All addresses: {:?}\n", bound.all_addrs());
        }
        Err(e) => println!("✗ Failed: {}\n", e),
    }

    // Example 2: Explicit port binding
    println!("Example 2: Explicit port (12345)");
    let config = EndpointPortConfig {
        port: PortBinding::Explicit(12345),
        ..Default::default()
    };
    match bind_endpoint(&config) {
        Ok(bound) => {
            println!("✓ Successfully bound to: {:?}", bound.primary_addr());
            println!("  All addresses: {:?}\n", bound.all_addrs());
        }
        Err(e) => println!("✗ Failed: {}\n", e),
    }

    // Example 3: Port range
    println!("Example 3: Port range (15000-15010)");
    let config = EndpointPortConfig {
        port: PortBinding::Range(15000, 15010),
        ..Default::default()
    };
    match bind_endpoint(&config) {
        Ok(bound) => {
            println!("✓ Successfully bound to: {:?}", bound.primary_addr());
            println!("  Port selected from range\n");
        }
        Err(e) => println!("✗ Failed: {}\n", e),
    }

    // Example 4: Fallback to OS-assigned on conflict
    println!("Example 4: Fallback behavior");
    // First, bind to a port
    let config1 = EndpointPortConfig {
        port: PortBinding::Explicit(16000),
        ..Default::default()
    };
    let _bound1 = match bind_endpoint(&config1) {
        Ok(bound) => bound,
        Err(e) => {
            println!("✗ Could not bind first endpoint: {}\n", e);
            return;
        }
    };
    println!("✓ First endpoint bound to port 16000");

    // Try to bind to same port with fallback
    let config2 = EndpointPortConfig {
        port: PortBinding::Explicit(16000),
        retry_behavior: PortRetryBehavior::FallbackToOsAssigned,
        ..Default::default()
    };
    match bind_endpoint(&config2) {
        Ok(bound) => {
            println!("✓ Second endpoint fell back to: {:?}", bound.primary_addr());
            println!("  Avoided port conflict\n");
        }
        Err(e) => println!("✗ Failed: {}\n", e),
    }

    // Example 5: IPv4-only mode (default)
    println!("Example 5: IPv4-only binding");
    let config = EndpointPortConfig {
        ip_mode: IpMode::IPv4Only,
        ..Default::default()
    };
    match bind_endpoint(&config) {
        Ok(bound) => {
            println!("✓ Successfully bound to IPv4: {:?}", bound.primary_addr());
            for addr in bound.all_addrs() {
                println!("  - {} (IPv4: {})", addr, addr.is_ipv4());
            }
            println!();
        }
        Err(e) => println!("✗ Failed: {}\n", e),
    }

    // Example 6: IPv6-only mode (if available)
    println!("Example 6: IPv6-only binding (may fail if IPv6 not available)");
    let config = EndpointPortConfig {
        ip_mode: IpMode::IPv6Only,
        ..Default::default()
    };
    match bind_endpoint(&config) {
        Ok(bound) => {
            println!("✓ Successfully bound to IPv6: {:?}", bound.primary_addr());
            for addr in bound.all_addrs() {
                println!("  - {} (IPv6: {})", addr, addr.is_ipv6());
            }
            println!();
        }
        Err(e) => println!("✗ Failed (expected on IPv6-disabled systems): {}\n", e),
    }

    // Example 7: Dual-stack with separate ports (safest dual-stack option)
    println!("Example 7: Dual-stack with separate ports");
    let config = EndpointPortConfig {
        ip_mode: IpMode::DualStackSeparate {
            ipv4_port: PortBinding::OsAssigned,
            ipv6_port: PortBinding::OsAssigned,
        },
        ..Default::default()
    };
    match bind_endpoint(&config) {
        Ok(bound) => {
            println!("✓ Successfully bound to dual-stack:");
            for addr in bound.all_addrs() {
                println!(
                    "  - {} (IPv4: {}, IPv6: {})",
                    addr,
                    addr.is_ipv4(),
                    addr.is_ipv6()
                );
            }
            println!();
        }
        Err(e) => println!("✗ Failed: {}\n", e),
    }

    // Example 8: Demonstrating privileged port rejection
    println!("Example 8: Privileged port rejection");
    let config = EndpointPortConfig {
        port: PortBinding::Explicit(80), // Privileged port
        ..Default::default()
    };
    match bind_endpoint(&config) {
        Ok(_) => println!("✗ Unexpected success (running as root?)\n"),
        Err(e) => println!("✓ Correctly rejected: {}\n", e),
    }

    println!("=== Examples Complete ===");
}
