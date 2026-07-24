//! Logic for controlling the rate at which data is sent

use crate::connection::RttEstimator;
use crate::{Instant, frame::EcnCounts};
use std::any::Any;
use std::sync::Arc;

mod bbr;
mod cubic;
mod new_reno;
mod prague;

pub use bbr::{Bbr, BbrConfig};
pub use cubic::{Cubic, CubicConfig};
pub use new_reno::{NewReno, NewRenoConfig};
pub use prague::{Prague, PragueConfig};

/// Common interface for different congestion controllers
pub trait Controller: Send + Sync {
    /// One or more packets were just sent
    #[allow(unused_variables)]
    fn on_sent(&mut self, now: Instant, bytes: u64, last_packet_number: u64) {}

    /// Packet deliveries were confirmed
    ///
    /// `app_limited` indicates whether the connection was blocked on outgoing
    /// application data prior to receiving these acknowledgements.
    #[allow(unused_variables)]
    fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        app_limited: bool,
        rtt: &RttEstimator,
    ) {
    }

    /// Packets are acked in batches, all with the same `now` argument. This indicates one of those batches has completed.
    #[allow(unused_variables)]
    fn on_end_acks(
        &mut self,
        now: Instant,
        in_flight: u64,
        app_limited: bool,
        largest_packet_num_acked: Option<u64>,
    ) {
    }

    /// Packets were deemed lost or marked congested
    ///
    /// `in_persistent_congestion` indicates whether all packets sent within the persistent
    /// congestion threshold period ending when the most recent packet in this batch was sent were
    /// lost.
    /// `lost_bytes` indicates how many bytes were lost. This value will be 0 for ECN triggers.
    fn on_congestion_event(
        &mut self,
        now: Instant,
        sent: Instant,
        is_persistent_congestion: bool,
        is_ecn: bool,
        lost_bytes: u64,
        increment: EcnCounts,
    );

    /// ECN counter increments were observed
    ///
    /// `increment` the increment of ECN counters compared to its value prior to the most recent ACK.
    /// It is assumed that `increment` has at least one non-zero value (for ECT(0), ECT(1) or CE).
    #[allow(unused_variables)]
    fn on_ecn_delivery(&mut self, now: Instant, increment: EcnCounts) {}

    /// Packets were incorrectly deemed lost
    ///
    /// This function is called when all packets that were deemed lost (for instance because
    /// of packet reordering) are acknowledged after the congestion event was raised.
    fn on_spurious_congestion_event(&mut self) {}

    /// Exit recovery/loss state
    ///
    /// This allows a controller to resume normal congestion window growth immediately.
    #[allow(unused_variables)]
    fn exit_recovery(&mut self, now: Instant) {}

    /// The known MTU for the current network path has been updated
    fn on_mtu_update(&mut self, new_mtu: u16);

    /// Externally set the CWND size
    fn set_window(&mut self, size: u64);

    /// Externally set the slow start threshold size
    #[allow(unused_variables)]
    fn set_ssthresh(&mut self, size: u64) {}

    /// Number of ack-eliciting bytes that may be in flight
    fn window(&self) -> u64;

    /// Retrieve implementation-specific metrics used to populate `qlog` traces when they are enabled
    fn metrics(&self) -> ControllerMetrics {
        ControllerMetrics {
            congestion_window: self.window(),
            ssthresh: None,
            pacing_rate: None,
        }
    }

    /// Duplicate the controller's state
    fn clone_box(&self) -> Box<dyn Controller>;

    /// Initial congestion window
    fn initial_window(&self) -> u64;

    /// Pacing gain required by the controller
    ///
    /// Defaults to the recommended value in RFC 9002 <https://datatracker.ietf.org/doc/html/rfc9002#name-pacing>
    fn pacing_gain(&self) -> f64 {
        1.25
    }

    /// Assures the controller that using ECT(0) is supported and enabled by the endpoint.
    /// Returns whether the controller supports and agrees to handle ECT(0) packets accordingly.
    fn enable_ect0(&mut self) -> bool {
        true
    }

    /// Assures the controller that using ECT(1) is supported and enabled by the endpoint.
    /// Returns whether the controller supports and agrees to handle ECT(1) packets accordingly.
    fn enable_ect1(&mut self) -> bool {
        false
    }

    /// Returns Self for use in down-casting to extract implementation details
    fn into_any(self: Box<Self>) -> Box<dyn Any>;
}

/// Common congestion controller metrics
#[derive(Default)]
#[non_exhaustive]
pub struct ControllerMetrics {
    /// Congestion window (bytes)
    pub congestion_window: u64,
    /// Slow start threshold (bytes)
    pub ssthresh: Option<u64>,
    /// Pacing rate (bits/s)
    pub pacing_rate: Option<u64>,
}

/// Constructs controllers on demand
pub trait ControllerFactory {
    /// Construct a fresh `Controller`
    fn build(
        self: Arc<Self>,
        now: Instant,
        current_mtu: u16,
        config: &crate::TransportConfig,
    ) -> Box<dyn Controller>;
}

const BASE_DATAGRAM_SIZE: u64 = 1200;
