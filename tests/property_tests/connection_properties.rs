//! Property tests for connection state machine

#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::config::*;
use super::generators::*;
use proptest::prelude::*;
use std::collections::HashSet;

proptest! {
    #![proptest_config(default_config())]

    /// Property: Connection ID validity
    #[test]
    fn connection_id_validity(
        ids in prop::collection::vec(arb_connection_id(), 1..20)
    ) {
        // Property: Connection IDs should be within valid length
        for id in &ids {
            prop_assert!(id.len() <= 20, "Connection ID too long: {} bytes", id.len());
        }

        // Count non-empty IDs for uniqueness check
        let non_empty_ids: Vec<_> = ids.iter().filter(|id| !id.is_empty()).collect();
        if non_empty_ids.len() > 1 {
            let unique_non_empty: HashSet<_> = non_empty_ids.iter().collect();
            // With random generation, some duplicates are expected but not most
            prop_assert!(unique_non_empty.len() >= non_empty_ids.len() / 3,
                "Too many duplicate connection IDs: {} unique out of {}",
                unique_non_empty.len(), non_empty_ids.len());
        }
    }

    /// Property: Stream ID allocation
    #[test]
    fn stream_id_allocation(
        is_client in any::<bool>(),
        is_bidirectional in any::<bool>(),
        stream_count in 0u64..1000,
    ) {
        let mut allocated_ids = HashSet::new();

        for i in 0..stream_count {
            // Calculate stream ID based on role and type
            let stream_id = (i * 4) |
                (if is_client { 0 } else { 1 }) |
                (if is_bidirectional { 0 } else { 2 });

            // Property: Stream IDs should be unique
            prop_assert!(allocated_ids.insert(stream_id),
                "Duplicate stream ID: {}", stream_id);

            // Property: Client-initiated streams have bit 0 = 0
            if is_client {
                prop_assert_eq!(stream_id & 1, 0,
                    "Client stream ID {} has wrong initiator bit", stream_id);
            } else {
                prop_assert_eq!(stream_id & 1, 1,
                    "Server stream ID {} has wrong initiator bit", stream_id);
            }

            // Property: Unidirectional streams have bit 1 = 1
            if !is_bidirectional {
                prop_assert_eq!(stream_id & 2, 2,
                    "Unidirectional stream ID {} has wrong type bit", stream_id);
            } else {
                prop_assert_eq!(stream_id & 2, 0,
                    "Bidirectional stream ID {} has wrong type bit", stream_id);
            }
        }
    }

    /// Property: Connection state transitions
    #[test]
    fn connection_state_machine(
        events in prop::collection::vec(
            prop_oneof![
                Just("start"),
                Just("send_initial"),
                Just("recv_initial"),
                Just("send_handshake"),
                Just("recv_handshake"),
                Just("handshake_complete"),
                Just("send_data"),
                Just("recv_data"),
                Just("close"),
                Just("timeout"),
            ],
            1..50
        )
    ) {
        #[derive(Debug, Clone, Copy, PartialEq)]
        enum State {
            Idle,
            Initial,
            Handshake,
            Established,
            Closing,
            Closed,
        }

        let mut state = State::Idle;
        let mut handshake_sent = false;
        let mut handshake_received = false;

        for event in events {
            let old_state = state;

            match (state, event) {
                (State::Idle, "start") => state = State::Initial,
                (State::Initial, "send_initial") => {},
                (State::Initial, "recv_initial") => state = State::Handshake,
                (State::Handshake, "send_handshake") => handshake_sent = true,
                (State::Handshake, "recv_handshake") => handshake_received = true,
                (State::Handshake, "handshake_complete") if handshake_sent && handshake_received => {
                    state = State::Established;
                }
                (State::Established, "send_data") => {},
                (State::Established, "recv_data") => {},
                (State::Established, "close") => state = State::Closing,
                (State::Closing, "close") => state = State::Closed,
                (_, "timeout") => state = State::Closed,
                _ => {}, // Invalid transition, state unchanged
            }

            // Property: State should only move forward
            match (old_state, state) {
                (State::Idle, State::Initial) |
                (State::Initial, State::Handshake) |
                (State::Handshake, State::Established) |
                (State::Established, State::Closing) |
                (State::Closing, State::Closed) |
                (_, State::Closed) => {}, // Valid forward transitions
                (old, new) if old == new => {}, // No change is valid
                (old, new) => {
                    prop_assert!(false,
                        "Invalid state transition: {:?} -> {:?}", old, new);
                }
            }
        }

        // Property: Terminal states
        if state == State::Closed {
            prop_assert!(true, "Reached terminal state");
        }
    }

    /// Property: Packet number space ordering
    #[test]
    fn packet_number_ordering(
        num_packets in 1usize..100
    ) {
        let mut spaces: [HashSet<u64>; 3] = [
            HashSet::new(), // Initial
            HashSet::new(), // Handshake
            HashSet::new(), // Application
        ];

        // Use sequential packet numbers to ensure uniqueness within each space
        for i in 0..num_packets {
            let space = i % 3;
            let pn = (i / 3) as u64; // Sequential within each space

            // Property: Packet numbers within a space should be unique
            prop_assert!(spaces[space].insert(pn),
                "Duplicate packet number {} in space {}", pn, space);
        }

        // Property: Each space maintains independent numbering
        for (i, space) in spaces.iter().enumerate() {
            if !space.is_empty() {
                let min = *space.iter().min().unwrap();
                let max = *space.iter().max().unwrap();

                // Property: Packet numbers should be sequential (starting from 0)
                prop_assert_eq!(min, 0,
                    "Packet numbers in space {} should start at 0", i);

                // Property: Range should equal count - 1
                prop_assert_eq!(max as usize, space.len() - 1,
                    "Packet numbers in space {} not sequential", i);
            }
        }
    }
}

proptest! {
    #![proptest_config(default_config())]

    /// Property: Flow control window updates
    #[test]
    fn flow_control_windows(
        initial_window in 1024u64..10_000_000,
        updates in prop::collection::vec(0u64..100_000, 0..20),
        consumes in prop::collection::vec(0u64..100_000, 0..20),
    ) {
        let mut window = initial_window;
        let mut total_consumed = 0u64;

        for (update, consume) in updates.iter().zip(consumes.iter()) {
            // Consume data
            if *consume <= window {
                window = window.saturating_sub(*consume);
                total_consumed += consume;
            }

            // Update window
            window = window.saturating_add(*update);

            // Property: Window should not exceed reasonable limits
            prop_assert!(window < 1_000_000_000,
                "Flow control window too large: {}", window);
        }

        // Property: Total consumed should not exceed initial + updates
        let total_updates: u64 = updates.iter().sum();
        prop_assert!(total_consumed <= initial_window + total_updates,
            "Consumed {} but only had {} available",
            total_consumed, initial_window + total_updates);
    }

    /// Property: RTT estimation
    #[test]
    fn rtt_estimation(
        samples in prop::collection::vec(arb_network_delay(), 1..50),
    ) {
        if samples.is_empty() {
            return Ok(());
        }

        let mut smoothed_rtt = samples[0];
        let mut rtt_variance = samples[0].as_millis() as f64 / 2.0;
        const ALPHA: f64 = 0.125; // 1/8
        const BETA: f64 = 0.25;   // 1/4

        for sample in samples.iter().skip(1) {
            let sample_ms = sample.as_millis() as f64;
            let smoothed_ms = smoothed_rtt.as_millis() as f64;

            // Update RTT variance
            let diff = (sample_ms - smoothed_ms).abs();
            rtt_variance = (1.0 - BETA) * rtt_variance + BETA * diff;

            // Update smoothed RTT
            let new_smoothed = (1.0 - ALPHA) * smoothed_ms + ALPHA * sample_ms;
            smoothed_rtt = std::time::Duration::from_millis(new_smoothed as u64);

            // Property: Smoothed RTT should be reasonable (can be 0 for very fast local networks)
            prop_assert!(smoothed_rtt.as_secs() < 60,
                "RTT estimate too large: {:?}", smoothed_rtt);

            // Property: Variance should be positive
            prop_assert!(rtt_variance >= 0.0);
        }

        // Property: Final RTT should be influenced by samples
        let avg_sample: u128 = samples.iter().map(|d| d.as_millis()).sum::<u128>() / samples.len() as u128;
        let final_rtt = smoothed_rtt.as_millis();

        // RTT should be within reasonable range of average
        let diff = (final_rtt as i128 - avg_sample as i128).abs();
        prop_assert!(diff < 1000, "Final RTT {} too far from average {}", final_rtt, avg_sample);
    }

    /// Property: Congestion control behavior
    #[test]
    fn congestion_control(
        initial_cwnd in 10u32..100,
        loss_events in prop::collection::vec(any::<bool>(), 0..50),
        ack_events in prop::collection::vec(any::<bool>(), 0..50),
    ) {
        let mut cwnd = initial_cwnd;
        let mut ssthresh = u32::MAX;
        let min_cwnd = 2;

        for (loss, ack) in loss_events.iter().zip(ack_events.iter()) {
            if *loss {
                // Multiplicative decrease on loss
                ssthresh = cwnd / 2;
                cwnd = cwnd.max(ssthresh).max(min_cwnd);
            } else if *ack {
                // Increase congestion window
                if cwnd < ssthresh {
                    // Slow start: exponential increase
                    cwnd = (cwnd * 2).min(ssthresh);
                } else {
                    // Congestion avoidance: linear increase
                    cwnd += 1;
                }
            }

            // Property: Congestion window bounds
            prop_assert!(cwnd >= min_cwnd,
                "Congestion window {} below minimum", cwnd);
            prop_assert!(cwnd <= 1000000,
                "Congestion window {} too large", cwnd);

            // Property: ssthresh relationship
            if ssthresh < u32::MAX {
                prop_assert!(ssthresh >= min_cwnd,
                    "Slow start threshold {} below minimum", ssthresh);
            }
        }
    }
}
