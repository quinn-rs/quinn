//! Logic for controlling the rate at which data is sent

use std::time::Instant;

mod new_reno;
pub use new_reno::{NewReno, NewRenoConfig};

/// Common interface for different congestion controllers
pub trait Controller: Send {
    /// Packet deliveries were confirmed
    ///
    /// `congestion_blocked` indicates whether the connection was blocked on congestion prior to
    /// receiving these acknowledgements.
    fn on_ack(&mut self, now: Instant, sent: Instant, bytes: u64, congestion_blocked: bool);

    /// Packets were deemed lost or marked congested
    ///
    /// `in_persistent_congestion` indicates whether all packets sent within the persistent
    /// congestion threshold period ending when the most recent packet in this batch was sent were
    /// lost.
    fn on_congestion_event(&mut self, now: Instant, sent: Instant, is_persistent_congestion: bool);

    /// Number of ack-eliciting bytes that may be in flight
    fn window(&self) -> u64;

    /// Duplicate the controller's state
    fn clone_box(&self) -> Box<dyn Controller>;
}

/// Constructs controllers on demand
pub trait ControllerFactory {
    /// Construct a fresh `Controller`
    fn build(&self, now: Instant) -> Box<dyn Controller>;
}
