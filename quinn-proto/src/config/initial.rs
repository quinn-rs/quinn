use std::net::{IpAddr, SocketAddr};

use crate::Instant;

/// Policy for new Initial packets, i.e. those not routed to an existing connection
///
/// Callbacks run synchronously in the endpoint's receive path, possibly under its lock. They must
/// be cheap, must not block and must not re-enter the endpoint. They may see the same Initial more
/// than once.
pub trait InitialFilter: Send + Sync {
    /// Admit a new Initial before its token is checked or Initial keys are derived
    ///
    /// Returning false drops the packet silently, whatever its token. The metadata is
    /// unauthenticated, so per-source limits alone don't bound spoofed traffic: use a global
    /// budget. The default admits everything.
    ///
    /// Initials with a malformed header or an invalid Retry token (e.g. expired, or issued for
    /// another address) skip [`Self::after_token_check`] and are refused with an encrypted
    /// CONNECTION_CLOSE, which costs Initial keys and a response. Only this hook bounds them.
    fn before_token_check(&self, _initial: &InitialMetadata) -> bool {
        true
    }

    /// Decide what to do with an admitted Initial, given the result of its token check
    ///
    /// Runs before Initial keys are derived or incoming state is created. A missing or unusable
    /// token leaves the address unvalidated (see [`TokenCheck::remote_address_validated`]); only
    /// invalid Retry tokens skip this hook.
    ///
    /// A valid NEW_TOKEN is already recorded in the replay log, so after
    /// [`InitialDecision::Ignore`], retransmissions carrying it may no longer validate.
    ///
    /// A Retry token can be reused on any number of Initials within its lifetime, so keep a budget
    /// on [`InitialDecision::Proceed`] for validated peers too.
    fn after_token_check(&self, initial: &InitialMetadata, token: &TokenCheck) -> InitialDecision;
}

/// What to do with an admitted Initial
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum InitialDecision {
    /// Continue as without a filter
    Proceed,
    /// Drop silently, before Initial keys are derived or incoming state is created
    Ignore,
}

/// Unauthenticated metadata of a new Initial
#[derive(Debug, Copy, Clone)]
pub struct InitialMetadata {
    pub(crate) remote: SocketAddr,
    pub(crate) local_ip: Option<IpAddr>,
    pub(crate) received_at: Instant,
    pub(crate) datagram_len: usize,
}

impl InitialMetadata {
    /// Source address, possibly spoofed
    pub fn remote_address(&self) -> SocketAddr {
        self.remote
    }
    /// Destination IP, if reported by the platform
    pub fn local_ip(&self) -> Option<IpAddr> {
        self.local_ip
    }
    /// Time the datagram was received
    pub fn received_at(&self) -> Instant {
        self.received_at
    }
    /// Size of the UDP datagram carrying the Initial
    pub fn datagram_len(&self) -> usize {
        self.datagram_len
    }
}

/// Result of checking the token of an admitted Initial
#[derive(Debug, Copy, Clone)]
pub struct TokenCheck {
    pub(crate) validated: bool,
    pub(crate) may_retry: bool,
}

impl TokenCheck {
    /// Whether a token validated the source address
    ///
    /// A NEW_TOKEN validates the IP only; a Retry token, the IP and port.
    pub fn remote_address_validated(&self) -> bool {
        self.validated
    }
    /// Whether a Retry may be sent, i.e. the Initial carries no valid Retry token
    pub fn may_retry(&self) -> bool {
        self.may_retry
    }
}
