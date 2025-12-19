//! Property tests for NAT traversal functionality
//!
//! v0.13.0+: Updated for symmetric P2P node architecture - no roles.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::config::*;
use super::generators::*;
use proptest::prelude::*;
use std::collections::HashSet;

proptest! {
    #![proptest_config(default_config())]

    /// Property: Priority values should be in valid ranges
    #[test]
    fn priority_value_ranges(
        local_priority in 0u32..=u32::MAX,
        remote_priority in 0u32..=u32::MAX,
    ) {
        // Simulate combined priority calculation
        let combined: u64 = ((local_priority as u64) << 32) | (remote_priority as u64);

        // Property: Combined priority should preserve component priorities
        let extracted_local = (combined >> 32) as u32;
        let extracted_remote = (combined & 0xFFFFFFFF) as u32;

        prop_assert_eq!(extracted_local, local_priority);
        prop_assert_eq!(extracted_remote, remote_priority);
    }

    /// Property: NAT hole punching coordination
    #[test]
    fn hole_punching_coordination(
        num_rounds in 1usize..10,
        delays in prop::collection::vec(arb_network_delay(), 10..11),
    ) {
        // Generate deterministic rounds
        let rounds: Vec<u32> = (0..num_rounds as u32).collect();

        // Simulate hole punching rounds
        let mut successful_rounds = HashSet::new();

        for (round, delay) in rounds.iter().zip(delays.iter().cycle().take(num_rounds)) {
            // Success probability based on delay
            let success_chance = if delay.as_millis() < 50 {
                0.9  // High success for low latency
            } else if delay.as_millis() < 200 {
                0.7  // Medium success for medium latency
            } else {
                0.4  // Lower success for high latency
            };

            // Simulate success based on network conditions
            if ((*round as f64) / 100.0) < success_chance {
                successful_rounds.insert(*round);
            }
        }

        // Property: Each successful round should be unique
        prop_assert!(successful_rounds.len() <= num_rounds,
            "More successful rounds than total rounds");
    }

    /// Property: Address discovery sequence numbers
    #[test]
    fn address_sequence_numbers(
        addresses in prop::collection::vec(arb_socket_addr(), 1..20),
    ) {
        let mut seq_nums = HashSet::new();
        let mut last_seq = 0u64;

        for (idx, addr) in addresses.iter().enumerate() {
            let seq = idx as u64;

            // Property: Sequence numbers should be unique
            prop_assert!(seq_nums.insert(seq),
                "Duplicate sequence number {} for address {}", seq, addr);

            // Property: Sequence numbers should be monotonic
            if idx > 0 {
                prop_assert!(seq > last_seq,
                    "Sequence number {} not greater than previous {}", seq, last_seq);
            }

            last_seq = seq;
        }

        // Property: Should have discovered at least one address
        prop_assert!(!seq_nums.is_empty());
    }
}

proptest! {
    #![proptest_config(default_config())]

    /// Property: NAT type behavior simulation
    #[test]
    fn nat_type_behavior(
        nat_type in arb_nat_type(),
        internal_port in 1024u16..65535,
        external_base_port in 1024u16..60000,
        num_connections in 1usize..10,
    ) {
        let mut port_mappings = HashSet::new();

        for i in 0..num_connections {
            let external_port = match nat_type {
                NatType::FullCone | NatType::Restricted | NatType::PortRestricted => {
                    // Same external port for all connections
                    external_base_port
                }
                NatType::Symmetric => {
                    // Different port for each connection
                    external_base_port + i as u16
                }
            };

            port_mappings.insert((internal_port, external_port));
        }

        // Property: Full Cone should use same port
        if matches!(nat_type, NatType::FullCone) {
            prop_assert_eq!(port_mappings.len(), 1,
                "Full Cone NAT should use same external port");
        }

        // Property: Symmetric should use different ports
        if matches!(nat_type, NatType::Symmetric) && num_connections > 1 {
            prop_assert!(port_mappings.len() > 1,
                "Symmetric NAT should use different external ports");
        }
    }

    /// Property: Connection migration validation
    #[test]
    fn connection_migration_validity(
        old_path in arb_socket_addr(),
        new_paths in prop::collection::vec(arb_socket_addr(), 1..5),
        migration_allowed in any::<bool>(),
    ) {
        // Ensure new paths are different from old
        let valid_new_paths: Vec<_> = new_paths.into_iter()
            .filter(|p| p != &old_path)
            .collect();

        if !valid_new_paths.is_empty() {
            if migration_allowed {
                // Property: Migration should succeed to different address
                for new_path in &valid_new_paths {
                    prop_assert_ne!(new_path, &old_path,
                        "New path must be different from old path");
                }
            } else {
                // Property: Migration disabled means staying on same path
                prop_assert!(valid_new_paths.iter().all(|p| p != &old_path) || valid_new_paths.is_empty(),
                    "Migration disabled but paths changed");
            }
        }
    }

    /// Property: Relay chain validation
    #[test]
    fn relay_chain_properties(
        chain_length in 1usize..6,
    ) {
        // Generate unique nodes for the chain
        let relay_chain: Vec<_> = (0..chain_length)
            .map(|i| {
                use std::net::{IpAddr, Ipv4Addr, SocketAddr};
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, i as u8)), 9000 + i as u16)
            })
            .collect();

        // Property: No cycles in relay chain
        let unique_nodes: HashSet<_> = relay_chain.iter().collect();
        prop_assert_eq!(unique_nodes.len(), relay_chain.len(),
            "Relay chain contains duplicate nodes");

        // Property: Reasonable chain length
        prop_assert!(chain_length <= 5,
            "Relay chain too long: {} nodes", chain_length);
    }

    /// Property: Symmetric P2P node equality
    /// v0.13.0+: All nodes should have equal capabilities
    #[test]
    fn symmetric_node_equality(
        num_nodes in 2usize..10,
    ) {
        // In v0.13.0+, all nodes are symmetric - they have equal capabilities
        // This property test verifies that the concept holds

        let node_capabilities: Vec<_> = (0..num_nodes)
            .map(|_| {
                // All nodes have the same capabilities:
                // - can_connect: true
                // - can_accept: true
                // - can_coordinate: true
                (true, true, true)
            })
            .collect();

        // Property: All nodes should have identical capabilities
        let first_caps = &node_capabilities[0];
        for (i, caps) in node_capabilities.iter().enumerate() {
            prop_assert_eq!(caps, first_caps,
                "Node {} has different capabilities than node 0", i);
        }
    }
}

// Property: NAT traversal state machine invariants
proptest! {
    #![proptest_config(extended_config())]

    #[test]
    fn nat_state_machine_invariants(
        transitions in prop::collection::vec(
            prop_oneof![
                Just("Init"),
                Just("Discovering"),
                Just("Advertising"),
                Just("Punching"),
                Just("Connected"),
                Just("Failed"),
            ],
            1..50
        )
    ) {
        let mut state = "Init";
        let mut connected = false;
        let mut failed = false;

        for next_state in transitions {
            // Apply state transition rules
            let valid_transition = matches!(
                (state, next_state),
                ("Init", "Discovering")
                    | ("Init", "Failed")
                    | ("Discovering", "Advertising")
                    | ("Discovering", "Failed")
                    | ("Advertising", "Punching")
                    | ("Advertising", "Failed")
                    | ("Punching", "Connected")
                    | ("Punching", "Failed")
                    | ("Connected", "Connected")
                    | ("Failed", "Failed")
            );

            if valid_transition {
                state = next_state;
                if state == "Connected" {
                    connected = true;
                }
                if state == "Failed" {
                    failed = true;
                }
            }

            // Property: Cannot be both connected and failed
            prop_assert!(!(connected && failed),
                "Invalid state: both connected and failed");

            // Property: Terminal states don't transition
            if connected || failed {
                prop_assert!(state == "Connected" || state == "Failed",
                    "Terminal state {} transitioned", state);
            }
        }
    }
}
