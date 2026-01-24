// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! ARQ (Automatic Repeat Request) reliability layer
//!
//! Provides reliable delivery over unreliable transports using:
//! - Sliding window for flow control
//! - Cumulative acknowledgments
//! - Retransmission timeout (RTO) with exponential backoff
//! - Sequence number wrap-around handling

use super::types::SequenceNumber;
use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Default window size (number of unacknowledged packets allowed)
pub const DEFAULT_WINDOW_SIZE: u8 = 8;

/// Default retransmission timeout
pub const DEFAULT_RTO: Duration = Duration::from_secs(2);

/// Maximum retransmission timeout (after backoff)
pub const MAX_RTO: Duration = Duration::from_secs(30);

/// Maximum retransmission attempts before giving up
pub const DEFAULT_MAX_RETRIES: u32 = 5;

/// Configuration for the ARQ layer
#[derive(Debug, Clone)]
pub struct ArqConfig {
    /// Window size (number of unacknowledged packets)
    pub window_size: u8,
    /// Initial retransmission timeout
    pub initial_rto: Duration,
    /// Maximum retransmission timeout
    pub max_rto: Duration,
    /// Maximum retransmission attempts
    pub max_retries: u32,
}

impl Default for ArqConfig {
    fn default() -> Self {
        Self {
            window_size: DEFAULT_WINDOW_SIZE,
            initial_rto: DEFAULT_RTO,
            max_rto: MAX_RTO,
            max_retries: DEFAULT_MAX_RETRIES,
        }
    }
}

impl ArqConfig {
    /// Create config optimized for BLE transport
    pub fn for_ble() -> Self {
        Self {
            window_size: 4, // Smaller window for slower transport
            initial_rto: Duration::from_millis(1500),
            max_rto: Duration::from_secs(15),
            max_retries: 5,
        }
    }

    /// Create config optimized for LoRa transport
    pub fn for_lora() -> Self {
        Self {
            window_size: 2, // Very small window for very slow transport
            initial_rto: Duration::from_secs(10),
            max_rto: Duration::from_secs(60),
            max_retries: 3,
        }
    }
}

/// Entry in the send window tracking an unacknowledged packet
#[derive(Debug, Clone)]
pub struct SendEntry {
    /// Sequence number of this packet
    pub seq: SequenceNumber,
    /// Packet data (for retransmission)
    pub data: Vec<u8>,
    /// When the packet was first sent (used for RTT estimation)
    #[allow(dead_code)]
    first_sent: Instant,
    /// When the packet was last sent (for retransmission)
    last_sent: Instant,
    /// Number of transmissions (1 = first time, 2+ = retransmissions)
    pub transmissions: u32,
}

impl SendEntry {
    /// Create a new send entry
    pub fn new(seq: SequenceNumber, data: Vec<u8>) -> Self {
        let now = Instant::now();
        Self {
            seq,
            data,
            first_sent: now,
            last_sent: now,
            transmissions: 1,
        }
    }

    /// Time since last transmission
    pub fn time_since_sent(&self) -> Duration {
        self.last_sent.elapsed()
    }

    /// Total time since first transmission
    #[allow(dead_code)]
    pub fn total_time(&self) -> Duration {
        self.first_sent.elapsed()
    }

    /// Mark as retransmitted
    pub fn mark_retransmitted(&mut self) {
        self.last_sent = Instant::now();
        self.transmissions += 1;
    }
}

/// Sliding window for send-side reliability
#[derive(Debug)]
pub struct SendWindow {
    /// Configuration
    config: ArqConfig,
    /// Next sequence number to use for new packets
    next_seq: SequenceNumber,
    /// Oldest unacknowledged sequence number
    base_seq: SequenceNumber,
    /// Queue of unacknowledged packets
    unacked: VecDeque<SendEntry>,
    /// Current RTO (adaptive)
    current_rto: Duration,
    /// Smoothed RTT estimate
    srtt: Option<Duration>,
}

impl SendWindow {
    /// Create a new send window
    pub fn new(config: ArqConfig) -> Self {
        Self {
            current_rto: config.initial_rto,
            config,
            next_seq: SequenceNumber::new(0),
            base_seq: SequenceNumber::new(0),
            unacked: VecDeque::new(),
            srtt: None,
        }
    }

    /// Create with default config
    pub fn with_defaults() -> Self {
        Self::new(ArqConfig::default())
    }

    /// Get next sequence number to use
    pub fn next_seq(&self) -> SequenceNumber {
        self.next_seq
    }

    /// Check if window has room for more packets
    pub fn can_send(&self) -> bool {
        self.unacked.len() < self.config.window_size as usize
    }

    /// Check if window is full
    pub fn is_full(&self) -> bool {
        !self.can_send()
    }

    /// Number of packets currently in flight
    pub fn in_flight(&self) -> usize {
        self.unacked.len()
    }

    /// Alias for in_flight() - number of unacked packets
    pub fn len(&self) -> usize {
        self.in_flight()
    }

    /// Check if no packets are in flight
    pub fn is_empty(&self) -> bool {
        self.unacked.is_empty()
    }

    /// Add a packet to the send window
    ///
    /// Returns the sequence number assigned to the packet, or None if window is full.
    pub fn send(&mut self, data: Vec<u8>) -> Option<SequenceNumber> {
        if !self.can_send() {
            return None;
        }

        let seq = self.next_seq;
        self.next_seq = self.next_seq.next();
        self.unacked.push_back(SendEntry::new(seq, data));

        Some(seq)
    }

    /// Add a packet with a specific sequence number
    ///
    /// Used when the caller manages sequence numbers.
    /// Returns error if window is full.
    pub fn add(
        &mut self,
        seq: SequenceNumber,
        data: Vec<u8>,
    ) -> Result<(), super::types::ConstrainedError> {
        if self.is_full() {
            return Err(super::types::ConstrainedError::SendBufferFull);
        }

        self.unacked.push_back(SendEntry::new(seq, data));
        Ok(())
    }

    /// Process a cumulative ACK
    ///
    /// Acknowledges all packets up to and including the given sequence number.
    /// Returns the number of packets acknowledged.
    pub fn acknowledge(&mut self, ack: SequenceNumber) -> usize {
        let mut count = 0;

        // Remove all packets with seq <= ack
        while let Some(entry) = self.unacked.front() {
            let dist = self.base_seq.distance_to(entry.seq);
            let ack_dist = self.base_seq.distance_to(ack);

            if dist <= ack_dist {
                // This packet is acknowledged
                if let Some(entry) = self.unacked.pop_front() {
                    // Update RTT estimate
                    if entry.transmissions == 1 {
                        // Only use samples from non-retransmitted packets
                        self.update_rtt(entry.time_since_sent());
                    }
                    count += 1;
                }
            } else {
                break;
            }
        }

        // Update base sequence
        if count > 0 {
            self.base_seq = ack.next();
        }

        count
    }

    /// Update RTT estimate using simplified Jacobson algorithm
    ///
    /// Uses exponential moving average for SRTT without RTTVAR tracking.
    fn update_rtt(&mut self, sample: Duration) {
        const ALPHA: f64 = 0.125; // 1/8 smoothing factor

        if let Some(srtt) = self.srtt {
            let srtt_secs = srtt.as_secs_f64();
            let sample_secs = sample.as_secs_f64();

            // SRTT = (1 - alpha) * SRTT + alpha * R
            let new_srtt = (1.0 - ALPHA) * srtt_secs + ALPHA * sample_secs;

            // RTTVAR not tracked for simplicity, use simpler RTO = 2 * SRTT
            let new_rto = (2.0 * new_srtt).clamp(
                self.config.initial_rto.as_secs_f64(),
                self.config.max_rto.as_secs_f64(),
            );

            self.srtt = Some(Duration::from_secs_f64(new_srtt));
            self.current_rto = Duration::from_secs_f64(new_rto);
        } else {
            // First sample
            self.srtt = Some(sample);
            self.current_rto = sample * 2;
        }
    }

    /// Get current RTO
    pub fn rto(&self) -> Duration {
        self.current_rto
    }

    /// Get packets that need retransmission
    ///
    /// Returns a list of packets that have exceeded RTO and haven't exceeded max retries.
    /// Returns None if any packet has exceeded max retries (connection should fail).
    pub fn get_retransmissions(&mut self) -> Option<Vec<(SequenceNumber, Vec<u8>)>> {
        let rto = self.current_rto;
        let max_retries = self.config.max_retries;
        let mut retransmits = Vec::new();

        for entry in &mut self.unacked {
            if entry.time_since_sent() > rto {
                if entry.transmissions > max_retries {
                    // Max retries exceeded
                    return None;
                }
                retransmits.push((entry.seq, entry.data.clone()));
                entry.mark_retransmitted();
            }
        }

        // Apply exponential backoff after retransmissions
        if !retransmits.is_empty() {
            self.current_rto = (self.current_rto * 2).min(self.config.max_rto);
        }

        Some(retransmits)
    }

    /// Reset the window (for connection close/reset)
    pub fn reset(&mut self) {
        self.next_seq = SequenceNumber::new(0);
        self.base_seq = SequenceNumber::new(0);
        self.unacked.clear();
        self.current_rto = self.config.initial_rto;
        self.srtt = None;
    }
}

/// Sliding window for receive-side reliability
#[derive(Debug)]
pub struct ReceiveWindow {
    /// Window size
    window_size: u8,
    /// Next expected sequence number
    next_expected: SequenceNumber,
    /// Highest cumulative ACK we can send
    cumulative_ack: SequenceNumber,
    /// Out-of-order received packets (seq -> data)
    out_of_order: VecDeque<(SequenceNumber, Vec<u8>)>,
}

impl ReceiveWindow {
    /// Create a new receive window
    pub fn new(window_size: u8) -> Self {
        Self {
            window_size,
            next_expected: SequenceNumber::new(0),
            cumulative_ack: SequenceNumber::new(0),
            out_of_order: VecDeque::new(),
        }
    }

    /// Create with default window size
    pub fn with_defaults() -> Self {
        Self::new(DEFAULT_WINDOW_SIZE)
    }

    /// Get the cumulative ACK to send
    pub fn cumulative_ack(&self) -> SequenceNumber {
        self.cumulative_ack
    }

    /// Check if a sequence number is within the receive window
    pub fn is_in_window(&self, seq: SequenceNumber) -> bool {
        self.next_expected.is_in_window(seq, self.window_size)
    }

    /// Receive a packet
    ///
    /// Returns the data if packet is in-order, or None if out-of-order (buffered).
    /// Also returns any subsequently buffered packets that are now in-order.
    pub fn receive(
        &mut self,
        seq: SequenceNumber,
        data: Vec<u8>,
    ) -> Option<Vec<(SequenceNumber, Vec<u8>)>> {
        // Check if in window
        if !self.is_in_window(seq) {
            // Duplicate or out of window, ignore but update ACK
            return None;
        }

        if seq == self.next_expected {
            // In-order packet
            let mut deliverable = vec![(seq, data)];
            self.next_expected = self.next_expected.next();
            self.cumulative_ack = seq;

            // Check for buffered packets that are now in-order
            while let Some(entry_idx) = self
                .out_of_order
                .iter()
                .position(|(s, _)| *s == self.next_expected)
            {
                if let Some((s, d)) = self.out_of_order.remove(entry_idx) {
                    deliverable.push((s, d));
                    self.next_expected = self.next_expected.next();
                    self.cumulative_ack = s;
                }
            }

            Some(deliverable)
        } else {
            // Out-of-order, buffer it if not duplicate
            if !self.out_of_order.iter().any(|(s, _)| *s == seq) {
                // Keep buffer sorted
                let pos = self
                    .out_of_order
                    .iter()
                    .position(|(s, _)| self.next_expected.distance_to(*s) > self.next_expected.distance_to(seq))
                    .unwrap_or(self.out_of_order.len());
                self.out_of_order.insert(pos, (seq, data));
            }
            None
        }
    }

    /// Reset the window
    pub fn reset(&mut self) {
        self.next_expected = SequenceNumber::new(0);
        self.cumulative_ack = SequenceNumber::new(0);
        self.out_of_order.clear();
    }

    /// Reset the window with a starting sequence number
    pub fn reset_with_seq(&mut self, start_seq: SequenceNumber) {
        self.next_expected = start_seq;
        self.cumulative_ack = start_seq;
        self.out_of_order.clear();
    }

    /// Get count of buffered out-of-order packets
    pub fn buffered_count(&self) -> usize {
        self.out_of_order.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arq_config_defaults() {
        let config = ArqConfig::default();
        assert_eq!(config.window_size, DEFAULT_WINDOW_SIZE);
        assert_eq!(config.initial_rto, DEFAULT_RTO);
    }

    #[test]
    fn test_arq_config_ble() {
        let config = ArqConfig::for_ble();
        assert!(config.window_size < DEFAULT_WINDOW_SIZE);
        assert!(config.initial_rto < DEFAULT_RTO);
    }

    #[test]
    fn test_send_entry() {
        let entry = SendEntry::new(SequenceNumber::new(5), b"test".to_vec());
        assert_eq!(entry.seq, SequenceNumber::new(5));
        assert_eq!(entry.transmissions, 1);
        assert!(entry.time_since_sent() < Duration::from_secs(1));
    }

    #[test]
    fn test_send_window_basic() {
        let mut window = SendWindow::with_defaults();
        assert!(window.can_send());
        assert_eq!(window.in_flight(), 0);

        // Send a packet
        let seq = window.send(b"hello".to_vec()).unwrap();
        assert_eq!(seq, SequenceNumber::new(0));
        assert_eq!(window.in_flight(), 1);

        // Acknowledge it
        let acked = window.acknowledge(SequenceNumber::new(0));
        assert_eq!(acked, 1);
        assert_eq!(window.in_flight(), 0);
    }

    #[test]
    fn test_send_window_full() {
        let config = ArqConfig {
            window_size: 2,
            ..Default::default()
        };
        let mut window = SendWindow::new(config);

        // Fill the window
        assert!(window.send(b"1".to_vec()).is_some());
        assert!(window.send(b"2".to_vec()).is_some());
        assert!(!window.can_send());
        assert!(window.send(b"3".to_vec()).is_none());
    }

    #[test]
    fn test_send_window_cumulative_ack() {
        let mut window = SendWindow::with_defaults();

        // Send 3 packets
        window.send(b"1".to_vec());
        window.send(b"2".to_vec());
        window.send(b"3".to_vec());
        assert_eq!(window.in_flight(), 3);

        // ACK up to seq 1 acknowledges seq 0 and 1
        let acked = window.acknowledge(SequenceNumber::new(1));
        assert_eq!(acked, 2);
        assert_eq!(window.in_flight(), 1);
    }

    #[test]
    fn test_receive_window_in_order() {
        let mut window = ReceiveWindow::with_defaults();

        // Receive in order
        let result = window.receive(SequenceNumber::new(0), b"first".to_vec());
        assert!(result.is_some());
        let packets = result.unwrap();
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].1, b"first");

        assert_eq!(window.cumulative_ack(), SequenceNumber::new(0));
    }

    #[test]
    fn test_receive_window_out_of_order() {
        let mut window = ReceiveWindow::with_defaults();

        // Receive seq 1 first (out of order)
        let result = window.receive(SequenceNumber::new(1), b"second".to_vec());
        assert!(result.is_none());
        assert_eq!(window.buffered_count(), 1);

        // Now receive seq 0
        let result = window.receive(SequenceNumber::new(0), b"first".to_vec());
        assert!(result.is_some());
        let packets = result.unwrap();
        assert_eq!(packets.len(), 2);
        assert_eq!(packets[0].1, b"first");
        assert_eq!(packets[1].1, b"second");

        assert_eq!(window.cumulative_ack(), SequenceNumber::new(1));
        assert_eq!(window.buffered_count(), 0);
    }

    #[test]
    fn test_receive_window_duplicate() {
        let mut window = ReceiveWindow::with_defaults();

        // Receive seq 0
        window.receive(SequenceNumber::new(0), b"first".to_vec());

        // Receive seq 0 again (duplicate)
        let result = window.receive(SequenceNumber::new(0), b"first".to_vec());
        assert!(result.is_none());
    }

    #[test]
    fn test_receive_window_out_of_window() {
        let config = ArqConfig {
            window_size: 4,
            ..Default::default()
        };
        let mut window = ReceiveWindow::new(config.window_size);

        // Try to receive seq 10 when expecting 0 (out of window)
        let result = window.receive(SequenceNumber::new(10), b"data".to_vec());
        assert!(result.is_none());
        assert_eq!(window.buffered_count(), 0);
    }

    #[test]
    fn test_send_window_reset() {
        let mut window = SendWindow::with_defaults();
        window.send(b"data".to_vec());
        assert_eq!(window.in_flight(), 1);

        window.reset();
        assert_eq!(window.in_flight(), 0);
        assert_eq!(window.next_seq(), SequenceNumber::new(0));
    }

    #[test]
    fn test_receive_window_reset() {
        let mut window = ReceiveWindow::with_defaults();
        window.receive(SequenceNumber::new(1), b"data".to_vec());
        assert_eq!(window.buffered_count(), 1);

        window.reset();
        assert_eq!(window.buffered_count(), 0);
    }
}
