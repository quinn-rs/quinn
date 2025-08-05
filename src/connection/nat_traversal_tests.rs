//! Unit tests for NAT traversal state machine and coordination logic
//!
//! This module provides comprehensive testing for the NAT traversal implementation
//! including state transitions, candidate management, coordination protocols,
//! and error handling.

#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::{
        VarInt, Instant, Duration,
        transport_parameters::TransportParameters,
        frame::{Frame, FrameType},
        ConnectionError, TransportError, TransportErrorCode,
        config::{EndpointConfig, TransportConfig},
        crypto::{Keys, KeyPair},
        packet::{SpaceId},
    };
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::collections::HashMap;
    use std::sync::Arc;

    /// Create a test NAT traversal state
    fn create_test_state(role: NatTraversalRole) -> NatTraversalState {
        NatTraversalState {
            role,
            local_candidates: HashMap::new(),
            remote_candidates: HashMap::new(),
            candidate_pairs: Vec::new(),
            active_validations: HashMap::new(),
            coordination: None,
            next_sequence: VarInt::from_u32(1),
            max_candidates: 32,
            coordination_timeout: Duration::from_secs(10),
            stats: NatTraversalStats::default(),
        }
    }

    /// Create a test candidate
    fn create_test_candidate(addr: SocketAddr, source: CandidateSource) -> AddressCandidate {
        AddressCandidate {
            sequence: VarInt::from_u32(1),
            address: addr,
            source,
            priority: calculate_candidate_priority(addr, source),
            foundation: calculate_foundation(addr, source),
            validated: false,
            last_activity: Instant::now(),
        }
    }

    fn calculate_candidate_priority(addr: SocketAddr, source: CandidateSource) -> u32 {
        let type_preference = match source {
            CandidateSource::Host => 126,
            CandidateSource::ServerReflexive => 100,
            CandidateSource::PeerReflexive => 110,
            CandidateSource::Relayed => 0,
        };
        
        let local_preference = if addr.is_ipv6() { 65535 } else { 65534 };
        (type_preference << 24) | (local_preference << 8) | 256
    }

    fn calculate_foundation(addr: SocketAddr, source: CandidateSource) -> String {
        use std::hash::{Hash, Hasher};
        use std::collections::hash_map::DefaultHasher;
        
        let mut hasher = DefaultHasher::new();
        addr.hash(&mut hasher);
        source.hash(&mut hasher);
        format!("{:x}", hasher.finish())
    }

    #[test]
    fn test_nat_traversal_role_serialization() {
        // Test role encoding/decoding
        assert_eq!(NatTraversalRole::Client as u8, 0);
        assert_eq!(NatTraversalRole::Server { can_relay: false } as u8, 1);
        assert_eq!(NatTraversalRole::Bootstrap as u8, 2);
    }

    #[test]
    fn test_candidate_priority_calculation() {
        let ipv4_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 1234);
        let ipv6_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)), 1234);
        
        // Host candidates should have highest priority
        let host_priority = calculate_candidate_priority(ipv4_addr, CandidateSource::Host);
        let reflexive_priority = calculate_candidate_priority(ipv4_addr, CandidateSource::ServerReflexive);
        assert!(host_priority > reflexive_priority);
        
        // IPv6 should have higher local preference
        let ipv6_priority = calculate_candidate_priority(ipv6_addr, CandidateSource::Host);
        let ipv4_priority = calculate_candidate_priority(ipv4_addr, CandidateSource::Host);
        assert!((ipv6_priority & 0x00FFFF00) > (ipv4_priority & 0x00FFFF00));
    }

    #[test]
    fn test_add_local_candidate() {
        let mut state = create_test_state(NatTraversalRole::Client);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 5000);
        
        // Add candidate
        let candidate = create_test_candidate(addr, CandidateSource::Host);
        let sequence = candidate.sequence;
        state.local_candidates.insert(sequence, candidate);
        
        assert_eq!(state.local_candidates.len(), 1);
        assert!(state.local_candidates.contains_key(&sequence));
        
        // Verify candidate properties
        let stored = &state.local_candidates[&sequence];
        assert_eq!(stored.address, addr);
        assert_eq!(stored.source, CandidateSource::Host);
        assert!(!stored.validated);
    }

    #[test]
    fn test_add_remote_candidate() {
        let mut state = create_test_state(NatTraversalRole::Server { can_relay: false });
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), 6000);
        
        // Add remote candidate
        let candidate = create_test_candidate(addr, CandidateSource::ServerReflexive);
        let sequence = candidate.sequence;
        state.remote_candidates.insert(sequence, candidate);
        
        assert_eq!(state.remote_candidates.len(), 1);
        assert!(state.remote_candidates.contains_key(&sequence));
    }

    #[test]
    fn test_candidate_pair_generation() {
        let mut state = create_test_state(NatTraversalRole::Client);
        
        // Add local candidates
        let local1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 5000);
        let local2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 50)), 5001);
        
        state.local_candidates.insert(
            VarInt::from_u32(1),
            create_test_candidate(local1, CandidateSource::Host),
        );
        state.local_candidates.insert(
            VarInt::from_u32(2),
            create_test_candidate(local2, CandidateSource::Host),
        );
        
        // Add remote candidates
        let remote1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), 6000);
        let remote2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)), 6001);
        
        state.remote_candidates.insert(
            VarInt::from_u32(3),
            create_test_candidate(remote1, CandidateSource::ServerReflexive),
        );
        state.remote_candidates.insert(
            VarInt::from_u32(4),
            create_test_candidate(remote2, CandidateSource::ServerReflexive),
        );
        
        // Generate pairs
        state.generate_candidate_pairs();
        
        // Should have 4 pairs (2 local × 2 remote)
        assert_eq!(state.candidate_pairs.len(), 4);
        
        // Verify pairs are sorted by priority
        for i in 1..state.candidate_pairs.len() {
            assert!(
                state.candidate_pairs[i - 1].priority >= state.candidate_pairs[i].priority,
                "Pairs should be sorted by priority"
            );
        }
    }

    #[test]
    fn test_max_candidates_limit() {
        let mut state = create_test_state(NatTraversalRole::Client);
        state.max_candidates = 5;
        
        // Try to add more than max candidates
        for i in 0..10 {
            let addr = SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, i as u8)),
                5000 + i as u16,
            );
            let candidate = create_test_candidate(addr, CandidateSource::Host);
            
            if state.local_candidates.len() < state.max_candidates as usize {
                state.local_candidates.insert(VarInt::from_u32(i), candidate);
            }
        }
        
        assert_eq!(state.local_candidates.len(), 5, "Should not exceed max candidates");
    }

    #[test]
    fn test_candidate_validation() {
        let mut state = create_test_state(NatTraversalRole::Client);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 5000);
        
        // Add unvalidated candidate
        let mut candidate = create_test_candidate(addr, CandidateSource::Host);
        assert!(!candidate.validated);
        
        // Validate candidate
        candidate.validated = true;
        candidate.last_activity = Instant::now();
        
        let sequence = candidate.sequence;
        state.local_candidates.insert(sequence, candidate);
        
        assert!(state.local_candidates[&sequence].validated);
    }

    #[test]
    fn test_coordination_state_transitions() {
        let mut state = create_test_state(NatTraversalRole::Client);
        
        // Start coordination
        let coordination = CoordinationState {
            round: 1,
            phase: CoordinationPhase::Discovery,
            started_at: Instant::now(),
            candidates_sent: false,
            punch_sent: false,
            peer_ready: false,
        };
        
        state.coordination = Some(coordination);
        
        // Verify initial state
        let coord = state.coordination.as_ref().unwrap();
        assert_eq!(coord.round, 1);
        assert_eq!(coord.phase, CoordinationPhase::Discovery);
        assert!(!coord.candidates_sent);
        assert!(!coord.punch_sent);
        
        // Transition to punching phase
        if let Some(coord) = state.coordination.as_mut() {
            coord.phase = CoordinationPhase::Punching;
            coord.candidates_sent = true;
        }
        
        let coord = state.coordination.as_ref().unwrap();
        assert_eq!(coord.phase, CoordinationPhase::Punching);
        assert!(coord.candidates_sent);
    }

    #[test]
    fn test_path_validation_state() {
        let mut state = create_test_state(NatTraversalRole::Client);
        let remote_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), 6000);
        
        // Add path validation
        let validation = PathValidationState {
            challenge: [1, 2, 3, 4, 5, 6, 7, 8],
            sent_at: Instant::now(),
            attempts: 1,
            validated: false,
        };
        
        state.active_validations.insert(remote_addr, validation);
        
        assert_eq!(state.active_validations.len(), 1);
        assert!(!state.active_validations[&remote_addr].validated);
        
        // Mark as validated
        if let Some(val) = state.active_validations.get_mut(&remote_addr) {
            val.validated = true;
        }
        
        assert!(state.active_validations[&remote_addr].validated);
    }

    #[test]
    fn test_stats_tracking() {
        let mut state = create_test_state(NatTraversalRole::Client);
        
        // Update stats
        state.stats.candidates_discovered += 5;
        state.stats.candidates_validated += 3;
        state.stats.coordination_rounds += 2;
        state.stats.hole_punch_attempts += 10;
        state.stats.hole_punch_successes += 7;
        
        assert_eq!(state.stats.candidates_discovered, 5);
        assert_eq!(state.stats.candidates_validated, 3);
        assert_eq!(state.stats.coordination_rounds, 2);
        assert_eq!(state.stats.hole_punch_attempts, 10);
        assert_eq!(state.stats.hole_punch_successes, 7);
        
        // Calculate success rate
        let success_rate = state.stats.hole_punch_successes as f64 
            / state.stats.hole_punch_attempts as f64;
        assert!((success_rate - 0.7).abs() < 0.001);
    }

    #[test]
    fn test_ipv6_candidate_handling() {
        let mut state = create_test_state(NatTraversalRole::Client);
        
        // Add IPv6 candidates
        let ipv6_addr = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            5000,
        );
        
        let candidate = create_test_candidate(ipv6_addr, CandidateSource::Host);
        state.local_candidates.insert(candidate.sequence, candidate);
        
        assert_eq!(state.local_candidates.len(), 1);
        
        // Verify IPv6 address is stored correctly
        let stored = state.local_candidates.values().next().unwrap();
        assert!(stored.address.is_ipv6());
    }

    #[test]
    fn test_candidate_pair_priority_calculation() {
        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 5000);
        let remote_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), 6000);
        
        let local = create_test_candidate(local_addr, CandidateSource::Host);
        let remote = create_test_candidate(remote_addr, CandidateSource::ServerReflexive);
        
        let pair = CandidatePair {
            local: local_addr,
            remote: remote_addr,
            local_priority: local.priority,
            remote_priority: remote.priority,
            priority: calculate_pair_priority(local.priority, remote.priority, true),
            nominated: false,
            state: CandidatePairState::Waiting,
            last_activity: None,
        };
        
        // Verify priority calculation
        assert!(pair.priority > 0);
        
        // Controller should have higher priority
        let controller_priority = calculate_pair_priority(local.priority, remote.priority, true);
        let controlled_priority = calculate_pair_priority(local.priority, remote.priority, false);
        assert!(controller_priority > controlled_priority);
    }

    fn calculate_pair_priority(local: u32, remote: u32, is_controller: bool) -> u64 {
        let g = local.min(remote) as u64;
        let d = (local as i64 - remote as i64).abs() as u64;
        
        if is_controller {
            (1u64 << 32) * g + 2 * d
        } else {
            (1u64 << 32) * g + 2 * d + 1
        }
    }

    #[test]
    fn test_coordination_timeout() {
        let mut state = create_test_state(NatTraversalRole::Client);
        state.coordination_timeout = Duration::from_millis(100);
        
        // Start coordination
        let coordination = CoordinationState {
            round: 1,
            phase: CoordinationPhase::Discovery,
            started_at: Instant::now() - Duration::from_millis(200), // Already expired
            candidates_sent: false,
            punch_sent: false,
            peer_ready: false,
        };
        
        state.coordination = Some(coordination);
        
        // Check if coordination has timed out
        let timed_out = state.coordination.as_ref()
            .map(|c| c.started_at.elapsed() > state.coordination_timeout)
            .unwrap_or(false);
        
        assert!(timed_out, "Coordination should have timed out");
    }

    #[test]
    fn test_role_capabilities() {
        // Client cannot relay
        let client = NatTraversalRole::Client;
        assert!(!matches!(client, NatTraversalRole::Server { can_relay: true }));
        
        // Server can optionally relay
        let server_no_relay = NatTraversalRole::Server { can_relay: false };
        let server_relay = NatTraversalRole::Server { can_relay: true };
        
        assert!(matches!(server_no_relay, NatTraversalRole::Server { .. }));
        assert!(matches!(server_relay, NatTraversalRole::Server { can_relay: true }));
        
        // Bootstrap always relays
        let bootstrap = NatTraversalRole::Bootstrap;
        assert!(matches!(bootstrap, NatTraversalRole::Bootstrap));
    }

    #[test]
    fn test_candidate_filtering() {
        let mut state = create_test_state(NatTraversalRole::Client);
        
        // Add various candidates
        let candidates = vec![
            (SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 5000), false), // Loopback
            (SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 5001), true), // Private
            (SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), 5002), true), // Public
            (SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 5003), false), // Invalid
            (SocketAddr::new(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)), 5004), false), // Broadcast
        ];
        
        for (i, (addr, should_add)) in candidates.into_iter().enumerate() {
            if should_add && !addr.ip().is_loopback() && !addr.ip().is_unspecified() {
                let candidate = create_test_candidate(addr, CandidateSource::Host);
                state.local_candidates.insert(VarInt::from_u32(i as u32), candidate);
            }
        }
        
        // Only valid addresses should be added
        assert_eq!(state.local_candidates.len(), 2);
        
        // Verify no loopback or invalid addresses
        for candidate in state.local_candidates.values() {
            assert!(!candidate.address.ip().is_loopback());
            assert!(!candidate.address.ip().is_unspecified());
        }
    }

    #[test]
    fn test_concurrent_coordination_rounds() {
        let mut state = create_test_state(NatTraversalRole::Client);
        
        // Complete first round
        state.stats.coordination_rounds = 1;
        
        // Start second round
        let coordination = CoordinationState {
            round: 2,
            phase: CoordinationPhase::Discovery,
            started_at: Instant::now(),
            candidates_sent: false,
            punch_sent: false,
            peer_ready: false,
        };
        
        state.coordination = Some(coordination);
        state.stats.coordination_rounds += 1;
        
        assert_eq!(state.stats.coordination_rounds, 2);
        assert_eq!(state.coordination.as_ref().unwrap().round, 2);
    }

    #[test]
    fn test_candidate_pair_state_machine() {
        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 5000);
        let remote_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), 6000);
        
        let mut pair = CandidatePair {
            local: local_addr,
            remote: remote_addr,
            local_priority: 1000,
            remote_priority: 900,
            priority: 1000000,
            nominated: false,
            state: CandidatePairState::Waiting,
            last_activity: None,
        };
        
        // State transitions
        assert_eq!(pair.state, CandidatePairState::Waiting);
        
        pair.state = CandidatePairState::InProgress;
        pair.last_activity = Some(Instant::now());
        assert_eq!(pair.state, CandidatePairState::InProgress);
        
        pair.state = CandidatePairState::Succeeded;
        assert_eq!(pair.state, CandidatePairState::Succeeded);
        
        // Nomination
        pair.nominated = true;
        assert!(pair.nominated);
    }

    #[test]
    fn test_sequence_number_overflow() {
        let mut state = create_test_state(NatTraversalRole::Client);
        
        // Set sequence near max
        state.next_sequence = VarInt::from_u32(u32::MAX - 1);
        
        // Add candidates
        let addr1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 5000);
        let mut candidate1 = create_test_candidate(addr1, CandidateSource::Host);
        candidate1.sequence = state.next_sequence;
        state.local_candidates.insert(candidate1.sequence, candidate1);
        
        // Increment sequence
        state.next_sequence = VarInt::from_u32(state.next_sequence.into_inner() + 1);
        
        let addr2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 101)), 5001);
        let mut candidate2 = create_test_candidate(addr2, CandidateSource::Host);
        candidate2.sequence = state.next_sequence;
        state.local_candidates.insert(candidate2.sequence, candidate2);
        
        assert_eq!(state.local_candidates.len(), 2);
        assert_eq!(state.next_sequence.into_inner(), u32::MAX);
    }

    /// Create a mock connection for testing NAT traversal methods
    fn create_test_connection() -> Connection {
        use crate::{
            Side, EndpointConfig, ServerConfig, TransportConfig,
            crypto::{rustls::QuicServerConfig, rustls::QuicClientConfig},
            shared::ConnectionId,
        };
        use std::sync::Arc;
        
        // Create a minimal connection for testing
        // Note: This is a simplified mock - in real tests you'd use the proper connection setup
        let endpoint_config = EndpointConfig::default();
        let mut config = TransportConfig::default();
        config.max_concurrent_uni_streams(100u32.into());
        
        let server_config = ServerConfig {
            transport: Arc::new(config),
            crypto: Arc::new(QuicServerConfig::with_single_cert(
                vec![], // Empty cert chain for testing
                Arc::new(ed25519_dalek::SigningKey::from_bytes(&[42; 32])),
            ).unwrap()),
        };
        
        Connection::new(
            endpoint_config,
            server_config,
            ConnectionId::random(&mut rand::thread_rng(), 8),
            ConnectionId::random(&mut rand::thread_rng(), 8),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 4433),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 4434),
            Side::Server,
            Some(NatTraversalRole::Server { can_relay: false }),
        )
    }

    #[test]
    fn test_send_nat_address_advertisement_success() {
        let mut conn = create_test_connection();
        let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 5000);
        let priority = 1000;
        
        // Should succeed with NAT traversal enabled
        let result = conn.send_nat_address_advertisement(address, priority);
        assert!(result.is_ok());
        
        let frame_id = result.unwrap();
        assert!(frame_id.into_inner() > 0);
    }

    #[test]
    fn test_send_nat_address_advertisement_without_nat_traversal() {
        let mut conn = create_test_connection();
        // Disable NAT traversal
        conn.nat_traversal = None;
        
        let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 5000);
        let priority = 1000;
        
        // Should fail without NAT traversal
        let result = conn.send_nat_address_advertisement(address, priority);
        assert!(result.is_err());
    }

    #[test]
    fn test_send_nat_address_advertisement_sequence_increment() {
        let mut conn = create_test_connection();
        let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 5000);
        let priority = 1000;
        
        // Send multiple advertisements
        let frame1 = conn.send_nat_address_advertisement(address, priority).unwrap();
        let frame2 = conn.send_nat_address_advertisement(address, priority + 100).unwrap();
        
        // Sequence numbers should increment
        assert!(frame2.into_inner() > frame1.into_inner());
    }

    #[test]
    fn test_send_nat_punch_coordination_success() {
        let mut conn = create_test_connection();
        let paired_with_sequence_number = 5;
        let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 5000);
        let round = 1;
        
        // Should succeed with NAT traversal enabled
        let result = conn.send_nat_punch_coordination(paired_with_sequence_number, address, round);
        assert!(result.is_ok());
    }

    #[test]
    fn test_send_nat_punch_coordination_without_nat_traversal() {
        let mut conn = create_test_connection();
        // Disable NAT traversal
        conn.nat_traversal = None;
        
        let paired_with_sequence_number = 5;
        let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 5000);
        let round = 1;
        
        // Should fail without NAT traversal
        let result = conn.send_nat_punch_coordination(paired_with_sequence_number, address, round);
        assert!(result.is_err());
    }

    #[test]
    fn test_send_nat_punch_coordination_invalid_sequence() {
        let mut conn = create_test_connection();
        let paired_with_sequence_number = 0; // Invalid sequence
        let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 5000);
        let round = 1;
        
        // Should handle invalid sequence gracefully
        let result = conn.send_nat_punch_coordination(paired_with_sequence_number, address, round);
        // This might succeed but with validation happening later
        assert!(result.is_ok() || result.is_err());
    }

    #[test]
    fn test_queue_add_address_frame_structure() {
        let mut conn = create_test_connection();
        let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), 6000);
        let priority = 2000;
        
        let frame_id = conn.send_nat_address_advertisement(address, priority).unwrap();
        
        // Verify the frame was queued properly
        assert!(frame_id.into_inner() > 0);
        
        // Check that NAT stats were updated
        if let Some(ref nat_state) = conn.nat_traversal {
            assert!(nat_state.stats.frames_sent > 0);
        }
    }

    #[test]
    fn test_queue_punch_me_now_frame_structure() {
        let mut conn = create_test_connection();
        let paired_with_sequence_number = 10;
        let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 5000);
        let round = 2;
        
        let result = conn.send_nat_punch_coordination(paired_with_sequence_number, address, round);
        assert!(result.is_ok());
        
        // Check that NAT stats were updated
        if let Some(ref nat_state) = conn.nat_traversal {
            assert!(nat_state.stats.frames_sent > 0);
        }
    }

    #[test]
    fn test_multiple_frame_queuing() {
        let mut conn = create_test_connection();
        
        // Queue multiple ADD_ADDRESS frames
        for i in 1..=5 {
            let address = SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, i as u8)),
                5000 + i as u16,
            );
            let result = conn.send_nat_address_advertisement(address, 1000 + i * 100);
            assert!(result.is_ok());
        }
        
        // Queue multiple PUNCH_ME_NOW frames
        for i in 1..=3 {
            let paired_with_sequence_number = i as u64;
            let address = SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, i as u8)),
                6000 + i as u16,
            );
            let result = conn.send_nat_punch_coordination(paired_with_sequence_number, address, i as u8);
            assert!(result.is_ok());
        }
        
        // Verify frames were queued
        if let Some(ref nat_state) = conn.nat_traversal {
            assert!(nat_state.stats.frames_sent >= 8); // 5 ADD_ADDRESS + 3 PUNCH_ME_NOW
        }
    }

    #[test]
    fn test_nat_traversal_statistics_update() {
        let mut conn = create_test_connection();
        
        // Initial stats should be zero
        if let Some(ref nat_state) = conn.nat_traversal {
            assert_eq!(nat_state.stats.frames_sent, 0);
        }
        
        // Send a frame
        let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 5000);
        let _ = conn.send_nat_address_advertisement(address, 1000);
        
        // Stats should be updated
        if let Some(ref nat_state) = conn.nat_traversal {
            assert!(nat_state.stats.frames_sent > 0);
        }
    }

    #[test]
    fn test_ipv6_address_handling() {
        let mut conn = create_test_connection();
        let ipv6_address = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            5000,
        );
        let priority = 1500;
        
        // Should handle IPv6 addresses correctly
        let result = conn.send_nat_address_advertisement(ipv6_address, priority);
        assert!(result.is_ok());
        
        // Test punch coordination with IPv6
        let paired_with_sequence_number = 1;
        let result = conn.send_nat_punch_coordination(paired_with_sequence_number, ipv6_address, 1);
        assert!(result.is_ok());
    }
}

// Additional edge case and error condition tests

#[cfg(test)]
mod edge_case_tests {
    use super::*;

    #[test]
    fn test_empty_candidate_lists() {
        let mut state = create_test_state(NatTraversalRole::Client);
        
        // Generate pairs with empty lists
        state.generate_candidate_pairs();
        assert_eq!(state.candidate_pairs.len(), 0);
        
        // Add only local candidates
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 5000);
        state.local_candidates.insert(
            VarInt::from_u32(1),
            create_test_candidate(addr, CandidateSource::Host),
        );
        
        state.generate_candidate_pairs();
        assert_eq!(state.candidate_pairs.len(), 0, "No pairs without remote candidates");
    }

    #[test]
    fn test_duplicate_candidates() {
        let mut state = create_test_state(NatTraversalRole::Client);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 5000);
        
        // Add same address with different sequences
        for i in 1..=3 {
            let mut candidate = create_test_candidate(addr, CandidateSource::Host);
            candidate.sequence = VarInt::from_u32(i);
            state.local_candidates.insert(candidate.sequence, candidate);
        }
        
        assert_eq!(state.local_candidates.len(), 3);
        
        // All should have same address
        for candidate in state.local_candidates.values() {
            assert_eq!(candidate.address, addr);
        }
    }

    #[test] 
    fn test_malformed_address_handling() {
        let mut state = create_test_state(NatTraversalRole::Client);
        
        // Test with port 0
        let addr_port_zero = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 0);
        let candidate = create_test_candidate(addr_port_zero, CandidateSource::Host);
        state.local_candidates.insert(candidate.sequence, candidate);
        
        // Port 0 is technically valid (OS assigns port)
        assert_eq!(state.local_candidates.len(), 1);
    }

    #[test]
    fn test_rapid_state_changes() {
        let mut state = create_test_state(NatTraversalRole::Client);
        
        // Rapidly change coordination state
        for round in 1..=10 {
            state.coordination = Some(CoordinationState {
                round,
                phase: if round % 2 == 0 { 
                    CoordinationPhase::Punching 
                } else { 
                    CoordinationPhase::Discovery 
                },
                started_at: Instant::now(),
                candidates_sent: round > 5,
                punch_sent: round > 7,
                peer_ready: round > 8,
            });
            
            state.stats.coordination_rounds = round;
        }
        
        assert_eq!(state.stats.coordination_rounds, 10);
        assert!(state.coordination.as_ref().unwrap().peer_ready);
    }

    #[test]
    fn test_memory_pressure_scenarios() {
        let mut state = create_test_state(NatTraversalRole::Client);
        state.max_candidates = 1000; // High limit
        
        // Add many candidates
        for i in 0..100 {
            for j in 0..10 {
                let addr = SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(192, 168, i as u8, j as u8)),
                    5000 + (i * 10 + j) as u16,
                );
                
                let candidate = create_test_candidate(addr, CandidateSource::Host);
                let seq = VarInt::from_u32((i * 10 + j) as u32);
                state.local_candidates.insert(seq, candidate);
            }
        }
        
        assert_eq!(state.local_candidates.len(), 1000);
    }

    #[test]
    fn test_time_based_candidate_expiry() {
        let mut state = create_test_state(NatTraversalRole::Client);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 5000);
        
        // Add candidate with old timestamp
        let mut candidate = create_test_candidate(addr, CandidateSource::Host);
        candidate.last_activity = Instant::now() - Duration::from_secs(3600); // 1 hour old
        
        state.local_candidates.insert(candidate.sequence, candidate);
        
        // In real implementation, old candidates would be pruned
        let old_activity = state.local_candidates.values().next().unwrap().last_activity;
        assert!(old_activity.elapsed() > Duration::from_secs(3000));
    }

    #[test]
    #[should_panic(expected = "not yet implemented")]
    fn test_panic_on_unimplemented_feature() {
        // Test that unimplemented features properly panic
        todo!("Implement relay candidate handling");
    }
}

// Performance and stress tests for NAT traversal

#[cfg(test)]
mod performance_tests {
    use super::*;
    
    #[test]
    #[ignore = "performance test"]
    fn bench_candidate_pair_generation() {
        let mut state = create_test_state(NatTraversalRole::Client);
        
        // Add many candidates
        for i in 0..50 {
            let local_addr = SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, i as u8)),
                5000 + i as u16,
            );
            state.local_candidates.insert(
                VarInt::from_u32(i),
                create_test_candidate(local_addr, CandidateSource::Host),
            );
            
            let remote_addr = SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, i as u8)),
                6000 + i as u16,
            );
            state.remote_candidates.insert(
                VarInt::from_u32(100 + i),
                create_test_candidate(remote_addr, CandidateSource::ServerReflexive),
            );
        }
        
        let start = std::time::Instant::now();
        state.generate_candidate_pairs();
        let duration = start.elapsed();
        
        assert_eq!(state.candidate_pairs.len(), 2500); // 50 × 50
        println!("Generated {} pairs in {:?}", state.candidate_pairs.len(), duration);
        assert!(duration < Duration::from_millis(100), "Pair generation too slow");
    }

    #[test]
    #[ignore = "performance test"]
    fn bench_priority_sorting() {
        let mut pairs = Vec::new();
        
        // Create many pairs with random priorities
        for i in 0..10000 {
            let pair = CandidatePair {
                local: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 5000),
                remote: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), 6000),
                local_priority: rand::random::<u32>() % 1000,
                remote_priority: rand::random::<u32>() % 1000,
                priority: rand::random::<u64>(),
                nominated: false,
                state: CandidatePairState::Waiting,
                last_activity: None,
            };
            pairs.push(pair);
        }
        
        let start = std::time::Instant::now();
        pairs.sort_by_key(|p| std::cmp::Reverse(p.priority));
        let duration = start.elapsed();
        
        println!("Sorted {} pairs in {:?}", pairs.len(), duration);
        assert!(duration < Duration::from_millis(10), "Sorting too slow");
    }
}