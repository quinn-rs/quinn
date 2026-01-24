// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Connection state machine for the constrained protocol
//!
//! The state machine follows a simplified TCP-like model:
//!
//! ```text
//!            SYN_SENT
//!               ↓
//! CLOSED → SYN_RCVD → ESTABLISHED → FIN_WAIT → CLOSING → TIME_WAIT → CLOSED
//!               ↑                      ↓
//!               └─────── RST ─────────┘
//! ```

use super::types::ConstrainedError;
use std::fmt;
use std::time::{Duration, Instant};

/// Connection state for the constrained protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum ConnectionState {
    /// Connection is closed (initial or final state)
    #[default]
    Closed,
    /// SYN sent, waiting for SYN-ACK
    SynSent,
    /// SYN received, SYN-ACK sent, waiting for ACK
    SynReceived,
    /// Connection established, data can flow
    Established,
    /// FIN sent, waiting for ACK
    FinWait,
    /// Received FIN, sent ACK, waiting to close
    Closing,
    /// Waiting for enough time to pass before reusing connection ID
    TimeWait,
}

impl ConnectionState {
    /// Check if this state allows sending data
    pub const fn can_send_data(&self) -> bool {
        matches!(self, Self::Established | Self::FinWait)
    }

    /// Check if this state allows receiving data
    pub const fn can_receive_data(&self) -> bool {
        matches!(self, Self::Established | Self::FinWait | Self::Closing)
    }

    /// Check if connection is considered open
    pub const fn is_open(&self) -> bool {
        matches!(
            self,
            Self::SynSent
                | Self::SynReceived
                | Self::Established
                | Self::FinWait
                | Self::Closing
        )
    }

    /// Check if connection is closed or closing
    pub const fn is_closed(&self) -> bool {
        matches!(self, Self::Closed | Self::TimeWait)
    }

    /// Check if connection is fully established
    pub const fn is_established(&self) -> bool {
        matches!(self, Self::Established)
    }

    /// Get timeout duration for this state
    ///
    /// Returns how long to wait in this state before timing out.
    pub fn timeout(&self) -> Duration {
        match self {
            Self::Closed => Duration::MAX, // No timeout for closed
            Self::SynSent => Duration::from_secs(5), // Connection setup timeout
            Self::SynReceived => Duration::from_secs(5),
            Self::Established => Duration::from_secs(300), // 5 minute idle timeout
            Self::FinWait => Duration::from_secs(30), // Wait for FIN-ACK
            Self::Closing => Duration::from_secs(30),
            Self::TimeWait => Duration::from_secs(4), // 2*MSL equivalent for constrained
        }
    }
}

impl fmt::Display for ConnectionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Closed => "CLOSED",
            Self::SynSent => "SYN_SENT",
            Self::SynReceived => "SYN_RCVD",
            Self::Established => "ESTABLISHED",
            Self::FinWait => "FIN_WAIT",
            Self::Closing => "CLOSING",
            Self::TimeWait => "TIME_WAIT",
        };
        write!(f, "{}", name)
    }
}

/// Events that can trigger state transitions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateEvent {
    /// Application requested connection open
    Open,
    /// Received SYN from peer
    RecvSyn,
    /// Received SYN-ACK from peer
    RecvSynAck,
    /// Received ACK
    RecvAck,
    /// Received FIN from peer
    RecvFin,
    /// Received RST from peer
    RecvRst,
    /// Application requested close
    Close,
    /// Timeout expired
    Timeout,
}

impl fmt::Display for StateEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Open => "OPEN",
            Self::RecvSyn => "RECV_SYN",
            Self::RecvSynAck => "RECV_SYN_ACK",
            Self::RecvAck => "RECV_ACK",
            Self::RecvFin => "RECV_FIN",
            Self::RecvRst => "RECV_RST",
            Self::Close => "CLOSE",
            Self::Timeout => "TIMEOUT",
        };
        write!(f, "{}", name)
    }
}

/// Connection state machine with transition validation
#[derive(Debug)]
pub struct StateMachine {
    /// Current state
    state: ConnectionState,
    /// When we entered the current state
    state_entered: Instant,
    /// Transition history for debugging (last 8 transitions)
    history: Vec<(ConnectionState, StateEvent, ConnectionState)>,
}

impl StateMachine {
    /// Create a new state machine in Closed state
    pub fn new() -> Self {
        Self {
            state: ConnectionState::Closed,
            state_entered: Instant::now(),
            history: Vec::with_capacity(8),
        }
    }

    /// Get current state
    pub fn state(&self) -> ConnectionState {
        self.state
    }

    /// Get time spent in current state
    pub fn time_in_state(&self) -> Duration {
        self.state_entered.elapsed()
    }

    /// Check if current state has timed out
    pub fn is_timed_out(&self) -> bool {
        self.time_in_state() > self.state.timeout()
    }

    /// Check if data can be sent
    pub fn can_send_data(&self) -> bool {
        self.state.can_send_data()
    }

    /// Check if data can be received
    pub fn can_receive_data(&self) -> bool {
        self.state.can_receive_data()
    }

    /// Process an event and transition to new state
    ///
    /// Returns the new state if transition is valid, or an error if invalid.
    pub fn transition(&mut self, event: StateEvent) -> Result<ConnectionState, ConstrainedError> {
        let old_state = self.state;
        let new_state = self.next_state(event)?;

        // Record transition in history
        if self.history.len() >= 8 {
            self.history.remove(0);
        }
        self.history.push((old_state, event, new_state));

        // Update state
        self.state = new_state;
        self.state_entered = Instant::now();

        tracing::trace!(
            from = %old_state,
            event = %event,
            to = %new_state,
            "State transition"
        );

        Ok(new_state)
    }

    /// Calculate next state for an event without actually transitioning
    fn next_state(&self, event: StateEvent) -> Result<ConnectionState, ConstrainedError> {
        use ConnectionState::*;
        use StateEvent::*;

        let new_state = match (self.state, event) {
            // From Closed
            (Closed, Open) => SynSent,
            (Closed, RecvSyn) => SynReceived,

            // From SynSent
            (SynSent, RecvSynAck) => Established,
            (SynSent, RecvRst) => Closed,
            (SynSent, Timeout) => Closed,
            (SynSent, Close) => Closed,

            // From SynReceived
            (SynReceived, RecvAck) => Established,
            (SynReceived, RecvRst) => Closed,
            (SynReceived, Timeout) => Closed,
            (SynReceived, Close) => Closed,

            // From Established
            (Established, RecvFin) => Closing,
            (Established, Close) => FinWait,
            (Established, RecvRst) => Closed,
            (Established, Timeout) => Closed,

            // From FinWait
            (FinWait, RecvAck) => Closing,
            (FinWait, RecvFin) => TimeWait,
            (FinWait, RecvRst) => Closed,
            (FinWait, Timeout) => Closed,

            // From Closing
            (Closing, RecvAck) => TimeWait,
            (Closing, RecvFin) => TimeWait,
            (Closing, RecvRst) => Closed,
            (Closing, Timeout) => Closed,

            // From TimeWait
            (TimeWait, Timeout) => Closed,
            (TimeWait, RecvRst) => Closed,

            // Invalid transitions
            _ => {
                return Err(ConstrainedError::InvalidStateTransition {
                    from: self.state.to_string(),
                    to: format!("{} -> ?", event),
                });
            }
        };

        Ok(new_state)
    }

    /// Force transition to a specific state (for testing or recovery)
    #[cfg(test)]
    pub fn force_state(&mut self, state: ConnectionState) {
        self.state = state;
        self.state_entered = Instant::now();
    }

    /// Get transition history
    pub fn history(&self) -> &[(ConnectionState, StateEvent, ConnectionState)] {
        &self.history
    }
}

impl Default for StateMachine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_display() {
        assert_eq!(format!("{}", ConnectionState::Closed), "CLOSED");
        assert_eq!(format!("{}", ConnectionState::Established), "ESTABLISHED");
        assert_eq!(format!("{}", ConnectionState::SynSent), "SYN_SENT");
    }

    #[test]
    fn test_state_properties() {
        assert!(!ConnectionState::Closed.can_send_data());
        assert!(ConnectionState::Established.can_send_data());
        assert!(ConnectionState::FinWait.can_send_data());

        assert!(ConnectionState::Closed.is_closed());
        assert!(ConnectionState::TimeWait.is_closed());
        assert!(!ConnectionState::Established.is_closed());

        assert!(ConnectionState::Established.is_established());
        assert!(!ConnectionState::SynSent.is_established());
    }

    #[test]
    fn test_state_machine_new() {
        let sm = StateMachine::new();
        assert_eq!(sm.state(), ConnectionState::Closed);
    }

    #[test]
    fn test_normal_connection_flow() {
        let mut sm = StateMachine::new();

        // Initiator side: CLOSED -> SYN_SENT -> ESTABLISHED
        assert_eq!(sm.transition(StateEvent::Open).unwrap(), ConnectionState::SynSent);
        assert_eq!(
            sm.transition(StateEvent::RecvSynAck).unwrap(),
            ConnectionState::Established
        );

        // Close: ESTABLISHED -> FIN_WAIT -> TIME_WAIT -> CLOSED
        assert_eq!(
            sm.transition(StateEvent::Close).unwrap(),
            ConnectionState::FinWait
        );
        assert_eq!(
            sm.transition(StateEvent::RecvFin).unwrap(),
            ConnectionState::TimeWait
        );
        assert_eq!(
            sm.transition(StateEvent::Timeout).unwrap(),
            ConnectionState::Closed
        );
    }

    #[test]
    fn test_responder_flow() {
        let mut sm = StateMachine::new();

        // Responder side: CLOSED -> SYN_RCVD -> ESTABLISHED
        assert_eq!(
            sm.transition(StateEvent::RecvSyn).unwrap(),
            ConnectionState::SynReceived
        );
        assert_eq!(
            sm.transition(StateEvent::RecvAck).unwrap(),
            ConnectionState::Established
        );
    }

    #[test]
    fn test_reset_from_any_state() {
        let mut sm = StateMachine::new();

        sm.transition(StateEvent::Open).unwrap();
        assert_eq!(sm.state(), ConnectionState::SynSent);

        assert_eq!(
            sm.transition(StateEvent::RecvRst).unwrap(),
            ConnectionState::Closed
        );
    }

    #[test]
    fn test_invalid_transition() {
        let mut sm = StateMachine::new();

        // Can't receive SYN-ACK from Closed state
        let result = sm.transition(StateEvent::RecvSynAck);
        assert!(result.is_err());
        match result {
            Err(ConstrainedError::InvalidStateTransition { from, .. }) => {
                assert_eq!(from, "CLOSED");
            }
            _ => panic!("Expected InvalidStateTransition error"),
        }
    }

    #[test]
    fn test_timeout_detection() {
        let sm = StateMachine::new();
        // Closed state has Duration::MAX timeout, so should never timeout
        assert!(!sm.is_timed_out());
    }

    #[test]
    fn test_history_tracking() {
        let mut sm = StateMachine::new();

        sm.transition(StateEvent::Open).unwrap();
        sm.transition(StateEvent::RecvSynAck).unwrap();

        let history = sm.history();
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].0, ConnectionState::Closed);
        assert_eq!(history[0].1, StateEvent::Open);
        assert_eq!(history[0].2, ConnectionState::SynSent);
    }

    #[test]
    fn test_event_display() {
        assert_eq!(format!("{}", StateEvent::Open), "OPEN");
        assert_eq!(format!("{}", StateEvent::RecvSyn), "RECV_SYN");
        assert_eq!(format!("{}", StateEvent::Close), "CLOSE");
    }

    #[test]
    fn test_state_timeout_durations() {
        // Verify timeout durations are reasonable
        assert!(ConnectionState::SynSent.timeout() < Duration::from_secs(60));
        assert!(ConnectionState::Established.timeout() >= Duration::from_secs(60));
        assert!(ConnectionState::TimeWait.timeout() < Duration::from_secs(60));
    }
}
