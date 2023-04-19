use crate::AckFrequencyConfig;
use std::time::Duration;

pub(super) struct AckFrequencyState {
    in_flight_ack_frequency_frame: Option<(u64, Duration)>,
    next_sequence_number: u64,
    pub(super) peer_max_ack_delay: Duration,
}

impl AckFrequencyState {
    pub(super) fn new(peer_max_ack_delay: Duration) -> Self {
        Self {
            in_flight_ack_frequency_frame: None,
            next_sequence_number: 0,
            peer_max_ack_delay,
        }
    }

    /// Returns the `max_ack_delay` that should be requested of the peer when sending an
    /// ACK_FREQUENCY frame
    pub(super) fn candidate_max_ack_delay(&self, config: &AckFrequencyConfig) -> Duration {
        // Use the peer's max_ack_delay if no custom max_ack_delay was provided in the config
        config.max_ack_delay.unwrap_or(self.peer_max_ack_delay)
    }

    /// Returns the `max_ack_delay` for the purposes of calculating the PTO, defined as the maximum
    /// of the peer's current `max_ack_delay` and all in-flight max ack delays.
    pub(super) fn max_ack_delay_for_pto(&self) -> Duration {
        if let Some((_, max_ack_delay)) = self.in_flight_ack_frequency_frame {
            self.peer_max_ack_delay.max(max_ack_delay)
        } else {
            self.peer_max_ack_delay
        }
    }

    /// Returns the next sequence number for an ACK_FREQUENCY frame
    pub(super) fn next_sequence_number(&mut self) -> u64 {
        let seq = self.next_sequence_number;
        self.next_sequence_number += 1;
        seq
    }

    /// Returns true if we should send an ACK_FREQUENCY frame
    pub(super) fn should_send_ack_frequency(&self) -> bool {
        // Currently, we only allow sending a single ACK_FREQUENCY frame. There is no need to send
        // more, because none of the sent values needs to be updated in the course of the connection
        self.next_sequence_number == 0
    }

    /// Notifies the [`AckFrequencyState`] that a packet containing an ACK_FREQUENCY frame was sent
    pub(super) fn ack_frequency_sent(&mut self, pn: u64, requested_max_ack_delay: Duration) {
        self.in_flight_ack_frequency_frame = Some((pn, requested_max_ack_delay));
    }

    /// Notifies the [`AckFrequencyState`] that a packet has been ACKed
    pub(super) fn on_acked(&mut self, pn: u64) {
        match self.in_flight_ack_frequency_frame {
            Some((number, requested_max_ack_delay)) if number == pn => {
                self.in_flight_ack_frequency_frame = None;
                self.peer_max_ack_delay = requested_max_ack_delay;
            }
            _ => {}
        }
    }
}
