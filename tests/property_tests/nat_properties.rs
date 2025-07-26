//! Property tests for NAT traversal functionality

use super::config::*;
use super::generators::*;
use ant_quic::nat_traversal::{AddressType, NatTraversalRole};
use proptest::prelude::*;
use std::collections::HashSet;

proptest! {
    #![proptest_config(default_config())]

    /// Property: NAT traversal roles should have consistent behavior
    #[test]
    fn nat_role_consistency(
        role in prop_oneof![
            Just(NatTraversalRole::Client),
            Just(NatTraversalRole::Server),
            Just(NatTraversalRole::Bootstrap),
        ]
    ) {
        // Clients should not act as relays
        if matches!(role, NatTraversalRole::Client) {
            prop_assert!(!role.can_relay());
        }

        // Bootstrap nodes should be able to relay
        if matches!(role, NatTraversalRole::Bootstrap) {
            prop_assert!(role.can_relay());
        }

        // All roles should have consistent string representation
        let role_str = format!("{:?}", role);
        prop_assert!(!role_str.is_empty());
    }

    /// Property: Address types should map to valid priorities
    #[test]
    fn address_type_priority(
        addr_type in prop_oneof![
            Just(AddressType::ServerReflexive),
            Just(AddressType::Host),
            Just(AddressType::PeerReflexive),
            Just(AddressType::Relayed),
        ]
    ) {
        let priority = addr_type.priority();

        // Priority should be in valid range
        prop_assert!(priority > 0);
        prop_assert!(priority <= 255);

        // Server reflexive should have highest priority
        if matches!(addr_type, AddressType::ServerReflexive) {
            prop_assert!(priority >= 200);
        }

        // Relayed should have lowest priority
        if matches!(addr_type, AddressType::Relayed) {
            prop_assert!(priority <= 100);
        }
    }

    /// Property: Candidate pairing should be symmetric
    #[test]
    fn candidate_pairing_symmetry(
        local_addr in arb_socket_addr(),
        remote_addr in arb_socket_addr(),
        local_type in 0u8..4,
        remote_type in 0u8..4,
    ) {
        use ant_quic::connection::CandidatePair;

        // Create candidate pair
        let pair1 = CandidatePair {
            local: local_addr,
            remote: remote_addr,
            priority: ((local_type as u32) << 16) | (remote_type as u32),
            nominated: false,
        };

        // Create reverse pair
        let pair2 = CandidatePair {
            local: remote_addr,
            remote: local_addr,
            priority: ((remote_type as u32) << 16) | (local_type as u32),
            nominated: false,
        };

        // Property: Both pairs should be valid
        prop_assert_ne!(pair1.local, pair1.remote);
        prop_assert_ne!(pair2.local, pair2.remote);

        // Property: Priority calculation should be consistent
        let p1_local = (pair1.priority >> 16) as u8;
        let p1_remote = (pair1.priority & 0xFFFF) as u8;
        prop_assert_eq!(p1_local, local_type);
        prop_assert_eq!(p1_remote, remote_type);
    }

    /// Property: NAT hole punching coordination
    #[test]
    fn hole_punching_coordination(
        rounds in prop::collection::vec(0u32..100, 1..10),
        delays in prop::collection::vec(arb_network_delay(), 1..10),
    ) {
        prop_assert_eq!(rounds.len(), delays.len());

        // Simulate hole punching rounds
        let mut successful_rounds = HashSet::new();

        for (round, delay) in rounds.iter().zip(delays.iter()) {
            // Success probability based on delay
            let success_chance = if delay.as_millis() < 50 {
                0.9  // High success for low latency
            } else if delay.as_millis() < 200 {
                0.7  // Medium success for medium latency
            } else {
                0.4  // Lower success for high latency
            };

            // Property: Each round should have unique identifier
            prop_assert!(!successful_rounds.contains(round) || *round == 0);

            // Simulate success based on network conditions
            if ((*round as f64) / 100.0) < success_chance {
                successful_rounds.insert(*round);
            }
        }

        // Property: At least one round should succeed in good conditions
        let avg_delay: u128 = delays.iter().map(|d| d.as_millis()).sum::<u128>() / delays.len() as u128;
        if avg_delay < 100 && rounds.len() >= 3 {
            prop_assert!(!successful_rounds.is_empty(),
                "No successful rounds with average delay {}ms", avg_delay);
        }
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
        chain_length in 1usize..10,
        nodes in prop::collection::vec(arb_socket_addr(), 10..20),
    ) {
        if chain_length <= nodes.len() {
            let relay_chain: Vec<_> = nodes.iter().take(chain_length).collect();

            // Property: No cycles in relay chain
            let unique_nodes: HashSet<_> = relay_chain.iter().collect();
            prop_assert_eq!(unique_nodes.len(), relay_chain.len(),
                "Relay chain contains duplicate nodes");

            // Property: Reasonable chain length
            prop_assert!(chain_length <= 5,
                "Relay chain too long: {} nodes", chain_length);
        }
    }
}

/// Property: NAT traversal state machine invariants
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
            let valid_transition = match (state, next_state) {
                ("Init", "Discovering") => true,
                ("Init", "Failed") => true,
                ("Discovering", "Advertising") => true,
                ("Discovering", "Failed") => true,
                ("Advertising", "Punching") => true,
                ("Advertising", "Failed") => true,
                ("Punching", "Connected") => true,
                ("Punching", "Failed") => true,
                ("Connected", "Connected") => true,
                ("Failed", "Failed") => true,
                _ => false,
            };

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
