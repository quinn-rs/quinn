// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

use std::{
    collections::{HashMap, VecDeque},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

use crate::shared::ConnectionId;
use tracing::{debug, info, trace, warn};

use crate::{Instant, VarInt};

/// NAT traversal state for a QUIC connection
///
/// This manages address candidate discovery, validation, and coordination
/// for establishing direct P2P connections through NATs.
#[derive(Debug)]
pub(super) struct NatTraversalState {
    /// Our role in NAT traversal (from transport parameters)
    pub(super) role: NatTraversalRole,
    /// Candidate addresses we've advertised to the peer
    pub(super) local_candidates: HashMap<VarInt, AddressCandidate>,
    /// Candidate addresses received from the peer
    pub(super) remote_candidates: HashMap<VarInt, AddressCandidate>,
    /// Generated candidate pairs for connectivity testing
    pub(super) candidate_pairs: Vec<CandidatePair>,
    /// Index for fast pair lookup by remote address (maintained during generation)
    pub(super) pair_index: HashMap<SocketAddr, usize>,
    /// Currently active path validation attempts
    pub(super) active_validations: HashMap<SocketAddr, PathValidationState>,
    /// Coordination state for simultaneous hole punching
    pub(super) coordination: Option<CoordinationState>,
    /// Sequence number for address advertisements
    pub(super) next_sequence: VarInt,
    /// Maximum candidates we're willing to handle
    pub(super) max_candidates: u32,
    /// Timeout for coordination rounds
    pub(super) coordination_timeout: Duration,
    /// Statistics for this NAT traversal session
    pub(super) stats: NatTraversalStats,
    /// Security validation state
    pub(super) security_state: SecurityValidationState,
    /// Network condition monitoring for adaptive timeouts
    pub(super) network_monitor: NetworkConditionMonitor,
    /// Resource management and cleanup coordinator
    pub(super) resource_manager: ResourceCleanupCoordinator,
    /// Bootstrap coordinator (only for Bootstrap role)
    pub(super) bootstrap_coordinator: Option<BootstrapCoordinator>,
}
/// Role in NAT traversal coordination
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatTraversalRole {
    /// Client endpoint (initiates connections, on-demand)
    Client,
    /// Server endpoint (accepts connections, always reachable)
    Server {
        /// Whether this server can relay traffic for other peers
        can_relay: bool,
    },
    /// Bootstrap/relay endpoint (publicly reachable, coordinates traversal)
    Bootstrap,
}
/// Address candidate with metadata
#[derive(Debug, Clone)]
pub(super) struct AddressCandidate {
    /// The socket address
    pub(super) address: SocketAddr,
    /// Priority for ICE-like selection (higher = better)
    pub(super) priority: u32,
    /// How this candidate was discovered
    pub(super) source: CandidateSource,
    /// When this candidate was first learned
    pub(super) discovered_at: Instant,
    /// Current state of this candidate
    pub(super) state: CandidateState,
    /// Number of validation attempts for this candidate
    pub(super) attempt_count: u32,
    /// Last validation attempt time
    pub(super) last_attempt: Option<Instant>,
}
/// How an address candidate was discovered
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateSource {
    /// Local network interface
    Local,
    /// Observed by a bootstrap node
    ///
    /// When present, `by_node` identifies the coordinator that reported the
    /// observation using its node identifier.
    Observed {
        /// Identifier of the coordinator that observed our address
        by_node: Option<VarInt>,
    },
    /// Received from peer via AddAddress frame
    Peer,
    /// Generated prediction for symmetric NAT
    Predicted,
}
/// Current state of a candidate address
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateState {
    /// Newly discovered, not yet tested
    New,
    /// Currently being validated
    Validating,
    /// Successfully validated and usable
    Valid,
    /// Validation failed
    Failed,
    /// Removed by peer or expired
    Removed,
}
/// State of an individual path validation attempt
#[derive(Debug)]
#[allow(dead_code)]
pub(super) struct PathValidationState {
    /// Challenge value sent
    pub(super) challenge: u64,
    /// When the challenge was sent
    pub(super) sent_at: Instant,
    /// Number of retransmissions
    pub(super) retry_count: u32,
    /// Maximum retries allowed
    pub(super) max_retries: u32,
    /// Associated with a coordination round (if any)
    pub(super) coordination_round: Option<VarInt>,
    /// Adaptive timeout state
    pub(super) timeout_state: AdaptiveTimeoutState,
    /// Last retry attempt time
    pub(super) last_retry_at: Option<Instant>,
}
/// Coordination state for simultaneous hole punching
#[derive(Debug)]
#[allow(dead_code)]
pub(super) struct CoordinationState {
    /// Current coordination round number
    pub(super) round: VarInt,
    /// Addresses we're punching to in this round
    pub(super) punch_targets: Vec<PunchTarget>,
    /// When this round started (coordination phase)
    pub(super) round_start: Instant,
    /// When hole punching should begin (synchronized time)
    pub(super) punch_start: Instant,
    /// Duration of this coordination round
    pub(super) round_duration: Duration,
    /// Current state of this coordination round
    pub(super) state: CoordinationPhase,
    /// Whether we've sent our PUNCH_ME_NOW to coordinator
    pub(super) punch_request_sent: bool,
    /// Whether we've received peer's PUNCH_ME_NOW via coordinator
    pub(super) peer_punch_received: bool,
    /// Retry count for this round
    pub(super) retry_count: u32,
    /// Maximum retries before giving up
    pub(super) max_retries: u32,
    /// Adaptive timeout state for coordination
    pub(super) timeout_state: AdaptiveTimeoutState,
    /// Last retry attempt time
    pub(super) last_retry_at: Option<Instant>,
}
/// Phases of the coordination protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum CoordinationPhase {
    /// Waiting to start coordination
    Idle,
    /// Sending PUNCH_ME_NOW to coordinator
    Requesting,
    /// Waiting for peer's PUNCH_ME_NOW via coordinator
    Coordinating,
    /// Grace period before synchronized hole punching
    Preparing,
    /// Actively sending PATH_CHALLENGE packets
    Punching,
    /// Waiting for PATH_RESPONSE validation
    Validating,
    /// This round completed successfully
    Succeeded,
    /// This round failed, may retry
    Failed,
}
/// Target for hole punching in a coordination round
#[derive(Debug, Clone)]
pub(super) struct PunchTarget {
    /// Remote address to punch to
    pub(super) remote_addr: SocketAddr,
    /// Sequence number of the remote candidate
    pub(super) remote_sequence: VarInt,
    /// Challenge value for validation
    pub(super) challenge: u64,
}
/// Actions to take when handling NAT traversal timeouts
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum TimeoutAction {
    /// Retry candidate discovery
    RetryDiscovery,
    /// Retry coordination with bootstrap node
    RetryCoordination,
    /// Start path validation for discovered candidates
    StartValidation,
    /// NAT traversal completed successfully
    Complete,
    /// NAT traversal failed
    Failed,
}

/// Candidate pair for ICE-like connectivity testing
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub(super) struct CandidatePair {
    /// Sequence of remote candidate
    pub(super) remote_sequence: VarInt,
    /// Our local address for this pair
    pub(super) local_addr: SocketAddr,
    /// Remote address we're testing connectivity to
    pub(super) remote_addr: SocketAddr,
    /// Combined priority for pair ordering (higher = better)
    pub(super) priority: u64,
    /// Current state of this pair
    pub(super) state: PairState,
    /// Type classification for this pair
    pub(super) pair_type: PairType,
    /// When this pair was created
    pub(super) created_at: Instant,
    /// When validation was last attempted
    pub(super) last_check: Option<Instant>,
}
/// State of a candidate pair during validation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub(super) enum PairState {
    /// Waiting to be tested
    Waiting,
    /// Validation succeeded - this pair works
    Succeeded,
    /// Validation failed
    Failed,
    /// Temporarily frozen (waiting for other pairs)
    Frozen,
}
/// Type classification for candidate pairs (based on ICE)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum PairType {
    /// Both candidates are on local network
    HostToHost,
    /// Local is host, remote is server reflexive (through NAT)
    HostToServerReflexive,
    /// Local is server reflexive, remote is host
    ServerReflexiveToHost,
    /// Both are server reflexive (both behind NAT)
    ServerReflexiveToServerReflexive,
    /// One side is peer reflexive (learned from peer)
    PeerReflexive,
}
/// Type of address candidate (following ICE terminology)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CandidateType {
    /// Host candidate - directly reachable local interface
    Host,
    /// Server reflexive - public address observed by bootstrap node
    ServerReflexive,
    /// Peer reflexive - address learned from incoming packets
    PeerReflexive,
}

/// Calculate ICE-like priority for an address candidate
/// Based on RFC 8445 Section 5.1.2.1
#[allow(dead_code)]
fn calculate_candidate_priority(
    candidate_type: CandidateType,
    local_preference: u16,
    component_id: u8,
) -> u32 {
    let type_preference = match candidate_type {
        CandidateType::Host => 126,
        CandidateType::PeerReflexive => 110,
        CandidateType::ServerReflexive => 100,
    };
    // ICE priority formula: (2^24 * type_pref) + (2^8 * local_pref) + component_id
    (1u32 << 24) * type_preference + (1u32 << 8) * local_preference as u32 + component_id as u32
}

/// Calculate combined priority for a candidate pair
/// Based on RFC 8445 Section 6.1.2.3
fn calculate_pair_priority(local_priority: u32, remote_priority: u32) -> u64 {
    let g = local_priority as u64;
    let d = remote_priority as u64;
    // ICE pair priority formula: 2^32 * MIN(G,D) + 2 * MAX(G,D) + (G>D ? 1 : 0)
    (1u64 << 32) * g.min(d) + 2 * g.max(d) + if g > d { 1 } else { 0 }
}

/// Determine candidate type from source information
fn classify_candidate_type(source: CandidateSource) -> CandidateType {
    match source {
        CandidateSource::Local => CandidateType::Host,
        CandidateSource::Observed { .. } => CandidateType::ServerReflexive,
        CandidateSource::Peer => CandidateType::PeerReflexive,
        CandidateSource::Predicted => CandidateType::ServerReflexive, // Symmetric NAT prediction
    }
}
/// Determine pair type from individual candidate types
fn classify_pair_type(local_type: CandidateType, remote_type: CandidateType) -> PairType {
    match (local_type, remote_type) {
        (CandidateType::Host, CandidateType::Host) => PairType::HostToHost,
        (CandidateType::Host, CandidateType::ServerReflexive) => PairType::HostToServerReflexive,
        (CandidateType::ServerReflexive, CandidateType::Host) => PairType::ServerReflexiveToHost,
        (CandidateType::ServerReflexive, CandidateType::ServerReflexive) => {
            PairType::ServerReflexiveToServerReflexive
        }
        (CandidateType::PeerReflexive, _) | (_, CandidateType::PeerReflexive) => {
            PairType::PeerReflexive
        }
    }
}
/// Check if two candidates are compatible for pairing
fn are_candidates_compatible(local: &AddressCandidate, remote: &AddressCandidate) -> bool {
    // Must be same address family (IPv4 with IPv4, IPv6 with IPv6)
    match (local.address, remote.address) {
        (SocketAddr::V4(_), SocketAddr::V4(_)) => true,
        (SocketAddr::V6(_), SocketAddr::V6(_)) => true,
        _ => false, // No IPv4/IPv6 mixing for now
    }
}
/// Statistics for NAT traversal attempts
#[derive(Debug, Default, Clone)]
#[allow(dead_code)]
pub(crate) struct NatTraversalStats {
    /// Total candidates received from peer
    pub(super) remote_candidates_received: u32,
    /// Total candidates we've advertised
    pub(super) local_candidates_sent: u32,
    /// Successful validations
    pub(super) validations_succeeded: u32,
    /// Failed validations
    pub(super) validations_failed: u32,
    /// Coordination rounds attempted
    pub(super) coordination_rounds: u32,
    /// Successful coordinations
    pub(super) successful_coordinations: u32,
    /// Failed coordinations
    pub(super) failed_coordinations: u32,
    /// Timed out coordinations
    pub(super) timed_out_coordinations: u32,
    /// Coordination failures due to poor network conditions
    pub(super) coordination_failures: u32,
    /// Successful direct connections established
    pub(super) direct_connections: u32,
    /// Security validation rejections
    pub(super) security_rejections: u32,
    /// Rate limiting violations
    pub(super) rate_limit_violations: u32,
    /// Invalid address rejections
    pub(super) invalid_address_rejections: u32,
    /// Suspicious coordination attempts
    pub(super) suspicious_coordination_attempts: u32,
}
/// Security validation state for rate limiting and attack detection
#[derive(Debug)]
#[allow(dead_code)]
pub(super) struct SecurityValidationState {
    /// Rate limiting: track candidate additions per time window
    candidate_rate_tracker: VecDeque<Instant>,
    /// Maximum candidates per time window
    max_candidates_per_window: u32,
    /// Rate limiting time window
    rate_window: Duration,
    /// Coordination request tracking for suspicious patterns
    coordination_requests: VecDeque<CoordinationRequest>,
    /// Maximum coordination requests per time window
    max_coordination_per_window: u32,
    /// Address validation cache to avoid repeated validation
    address_validation_cache: HashMap<SocketAddr, AddressValidationResult>,
    /// Cache timeout for address validation
    validation_cache_timeout: Duration,
}
/// Coordination request tracking for security analysis
#[derive(Debug, Clone)]
struct CoordinationRequest {
    /// When the request was made
    timestamp: Instant,
}
/// Result of address validation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AddressValidationResult {
    /// Address is valid and safe
    Valid,
    /// Address is invalid (malformed, reserved, etc.)
    Invalid,
    /// Address is suspicious (potential attack)
    Suspicious,
}
/// Adaptive timeout state for network condition awareness
#[derive(Debug, Clone)]
pub(super) struct AdaptiveTimeoutState {
    /// Current timeout value
    current_timeout: Duration,
    /// Minimum allowed timeout
    min_timeout: Duration,
    /// Maximum allowed timeout
    max_timeout: Duration,
    /// Base timeout for exponential backoff
    base_timeout: Duration,
    /// Current backoff multiplier
    backoff_multiplier: f64,
    /// Maximum backoff multiplier
    max_backoff_multiplier: f64,
    /// Jitter factor for randomization
    jitter_factor: f64,
    /// Smoothed round-trip time estimation
    srtt: Option<Duration>,
    /// Round-trip time variance
    rttvar: Option<Duration>,
    /// Last successful round-trip time
    last_rtt: Option<Duration>,
    /// Number of consecutive timeouts
    consecutive_timeouts: u32,
    /// Number of successful responses
    successful_responses: u32,
}
/// Network condition monitoring for adaptive behavior
#[derive(Debug)]
#[allow(dead_code)]
pub(super) struct NetworkConditionMonitor {
    /// Recent round-trip time measurements
    rtt_samples: VecDeque<Duration>,
    /// Maximum samples to keep
    max_samples: usize,
    /// Packet loss rate estimation
    packet_loss_rate: f64,
    /// Congestion window estimate
    congestion_window: u32,
    /// Network quality score (0.0 = poor, 1.0 = excellent)
    quality_score: f64,
    /// Last quality update time
    last_quality_update: Instant,
    /// Quality measurement interval
    quality_update_interval: Duration,
    /// Timeout statistics
    timeout_stats: TimeoutStatistics,
}
/// Statistics for timeout behavior
#[derive(Debug, Default)]
struct TimeoutStatistics {
    /// Total timeout events
    total_timeouts: u64,
    /// Total successful responses
    total_responses: u64,
    /// Average response time
    avg_response_time: Duration,
    /// Timeout rate (0.0 = no timeouts, 1.0 = all timeouts)
    timeout_rate: f64,
    /// Last update time
    last_update: Option<Instant>,
}
#[allow(dead_code)]
impl SecurityValidationState {
    /// Create new security validation state with default settings
    fn new() -> Self {
        Self {
            candidate_rate_tracker: VecDeque::new(),
            max_candidates_per_window: 20, // Max 20 candidates per 60 seconds
            rate_window: Duration::from_secs(60),
            coordination_requests: VecDeque::new(),
            max_coordination_per_window: 5, // Max 5 coordination requests per 60 seconds
            address_validation_cache: HashMap::new(),
            validation_cache_timeout: Duration::from_secs(300), // 5 minute cache
        }
    }
    /// Create new security validation state with custom rate limits
    fn new_with_limits(
        max_candidates_per_window: u32,
        max_coordination_per_window: u32,
        rate_window: Duration,
    ) -> Self {
        Self {
            candidate_rate_tracker: VecDeque::new(),
            max_candidates_per_window,
            rate_window,
            coordination_requests: VecDeque::new(),
            max_coordination_per_window,
            address_validation_cache: HashMap::new(),
            validation_cache_timeout: Duration::from_secs(300),
        }
    }
    /// Enhanced rate limiting with adaptive thresholds
    ///
    /// This implements adaptive rate limiting that adjusts based on network conditions
    /// and detected attack patterns to prevent flooding while maintaining usability.
    fn is_adaptive_rate_limited(&mut self, peer_id: [u8; 32], now: Instant) -> bool {
        // Clean up old entries first
        self.cleanup_rate_tracker(now);
        self.cleanup_coordination_tracker(now);
        // Calculate current request rate
        let _current_candidate_rate =
            self.candidate_rate_tracker.len() as f64 / self.rate_window.as_secs_f64();
        let _current_coordination_rate =
            self.coordination_requests.len() as f64 / self.rate_window.as_secs_f64();

        // Adaptive threshold based on peer behavior
        let peer_reputation = self.calculate_peer_reputation(peer_id);
        let adaptive_candidate_limit =
            (self.max_candidates_per_window as f64 * peer_reputation) as u32;
        let adaptive_coordination_limit =
            (self.max_coordination_per_window as f64 * peer_reputation) as u32;

        // Check if either limit is exceeded
        if self.candidate_rate_tracker.len() >= adaptive_candidate_limit as usize {
            debug!(
                "Adaptive candidate rate limit exceeded for peer {:?}: {} >= {}",
                hex::encode(&peer_id[..8]),
                self.candidate_rate_tracker.len(),
                adaptive_candidate_limit
            );
            return true;
        }

        if self.coordination_requests.len() >= adaptive_coordination_limit as usize {
            debug!(
                "Adaptive coordination rate limit exceeded for peer {:?}: {} >= {}",
                hex::encode(&peer_id[..8]),
                self.coordination_requests.len(),
                adaptive_coordination_limit
            );
            return true;
        }

        false
    }

    /// Calculate peer reputation score (0.0 = bad, 1.0 = good)
    ///
    /// This implements a simple reputation system to adjust rate limits
    /// based on peer behavior patterns.
    fn calculate_peer_reputation(&self, _peer_id: [u8; 32]) -> f64 {
        // Simplified reputation calculation
        // In production, this would track:
        // - Historical success rates
        // - Suspicious behavior patterns
        // - Coordination completion rates
        // - Address validation failures
        // For now, return a default good reputation
        // This can be enhanced with persistent peer reputation storage
        1.0
    }

    /// Implement amplification attack mitigation
    ///
    /// This prevents the bootstrap node from being used as an amplifier
    /// in DDoS attacks by limiting server-initiated validation packets.
    fn validate_amplification_limits(
        &mut self,
        source_addr: SocketAddr,
        target_addr: SocketAddr,
        now: Instant,
    ) -> Result<(), NatTraversalError> {
        // Check if we're being asked to send too many packets to the same target
        let amplification_key = (source_addr, target_addr);
        // Simple amplification protection: limit packets per source-target pair
        // In production, this would be more sophisticated with:
        // - Bandwidth tracking
        // - Packet size ratios
        // - Geographic analysis
        // - Temporal pattern analysis

        // For now, implement basic per-pair rate limiting
        if self.is_amplification_suspicious(amplification_key, now) {
            warn!(
                "Potential amplification attack detected: {} -> {}",
                source_addr, target_addr
            );
            return Err(NatTraversalError::SuspiciousCoordination);
        }

        Ok(())
    }

    /// Check for suspicious amplification patterns
    fn is_amplification_suspicious(
        &self,
        _amplification_key: (SocketAddr, SocketAddr),
        _now: Instant,
    ) -> bool {
        // Simplified amplification detection
        // In production, this would track:
        // - Request/response ratios
        // - Bandwidth amplification factors
        // - Temporal clustering of requests
        // - Geographic distribution analysis
        // For now, return false (no amplification detected)
        // This can be enhanced with persistent amplification tracking
        false
    }

    /// Generate cryptographically secure random values for coordination rounds
    ///
    /// This ensures that coordination rounds use secure random values to prevent
    /// prediction attacks and ensure proper synchronization security.
    fn generate_secure_coordination_round(&self) -> VarInt {
        // Use cryptographically secure random number generation
        let secure_random: u64 = rand::random();
        // Ensure the value is within reasonable bounds for VarInt
        let bounded_random = secure_random % 1000000; // Limit to reasonable range

        VarInt::from_u64(bounded_random).unwrap_or(VarInt::from_u32(1))
    }

    /// Enhanced address validation with security checks
    ///
    /// This performs comprehensive address validation including:
    /// - Basic format validation
    /// - Security threat detection
    /// - Amplification attack prevention
    /// - Suspicious pattern recognition
    fn enhanced_address_validation(
        &mut self,
        addr: SocketAddr,
        source_addr: SocketAddr,
        now: Instant,
    ) -> Result<AddressValidationResult, NatTraversalError> {
        // First, perform basic address validation
        let basic_result = self.validate_address(addr, now);
        match basic_result {
            AddressValidationResult::Invalid => {
                return Err(NatTraversalError::InvalidAddress);
            }
            AddressValidationResult::Suspicious => {
                return Err(NatTraversalError::SuspiciousCoordination);
            }
            AddressValidationResult::Valid => {
                // Continue with enhanced validation
            }
        }

        // Check for amplification attack patterns
        self.validate_amplification_limits(source_addr, addr, now)?;

        // Additional security checks
        if self.is_address_in_suspicious_range(addr) {
            warn!("Address in suspicious range detected: {}", addr);
            return Err(NatTraversalError::SuspiciousCoordination);
        }

        if self.is_coordination_pattern_suspicious(source_addr, addr, now) {
            warn!(
                "Suspicious coordination pattern detected: {} -> {}",
                source_addr, addr
            );
            return Err(NatTraversalError::SuspiciousCoordination);
        }

        Ok(AddressValidationResult::Valid)
    }

    /// Check if address is in a suspicious range
    fn is_address_in_suspicious_range(&self, addr: SocketAddr) -> bool {
        match addr.ip() {
            IpAddr::V4(ipv4) => {
                // Check for addresses commonly used in attacks
                let octets = ipv4.octets();
                // Reject certain reserved ranges that shouldn't be used for P2P
                if octets[0] == 0 || octets[0] == 127 {
                    return true;
                }

                // Check for test networks (RFC 5737)
                if octets[0] == 192 && octets[1] == 0 && octets[2] == 2 {
                    return true;
                }
                if octets[0] == 198 && octets[1] == 51 && octets[2] == 100 {
                    return true;
                }
                if octets[0] == 203 && octets[1] == 0 && octets[2] == 113 {
                    return true;
                }

                false
            }
            IpAddr::V6(ipv6) => {
                // Check for suspicious IPv6 ranges
                if ipv6.is_loopback() || ipv6.is_unspecified() {
                    return true;
                }

                // Check for documentation ranges (RFC 3849)
                let segments = ipv6.segments();
                if segments[0] == 0x2001 && segments[1] == 0x0db8 {
                    return true;
                }

                false
            }
        }
    }

    /// Check for suspicious coordination patterns
    fn is_coordination_pattern_suspicious(
        &self,
        _source_addr: SocketAddr,
        _target_addr: SocketAddr,
        _now: Instant,
    ) -> bool {
        // Simplified pattern detection
        // In production, this would analyze:
        // - Temporal patterns (too frequent requests)
        // - Geographic patterns (unusual source/target combinations)
        // - Behavioral patterns (consistent with known attack signatures)
        // - Network topology patterns (suspicious routing)
        // For now, return false (no suspicious patterns detected)
        // This can be enhanced with machine learning-based pattern detection
        false
    }

    /// Check if candidate rate limit is exceeded
    fn is_candidate_rate_limited(&mut self, now: Instant) -> bool {
        // Clean up old entries
        self.cleanup_rate_tracker(now);
        // Check if we've exceeded the rate limit
        if self.candidate_rate_tracker.len() >= self.max_candidates_per_window as usize {
            return true;
        }

        // Record this attempt
        self.candidate_rate_tracker.push_back(now);
        false
    }

    /// Check if coordination rate limit is exceeded
    fn is_coordination_rate_limited(&mut self, now: Instant) -> bool {
        // Clean up old entries
        self.cleanup_coordination_tracker(now);
        // Check if we've exceeded the rate limit
        if self.coordination_requests.len() >= self.max_coordination_per_window as usize {
            return true;
        }

        // Record this attempt
        let request = CoordinationRequest { timestamp: now };
        self.coordination_requests.push_back(request);
        false
    }

    /// Clean up old rate tracking entries
    fn cleanup_rate_tracker(&mut self, now: Instant) {
        let cutoff = now - self.rate_window;
        while let Some(&front_time) = self.candidate_rate_tracker.front() {
            if front_time < cutoff {
                self.candidate_rate_tracker.pop_front();
            } else {
                break;
            }
        }
    }
    /// Clean up old coordination tracking entries
    fn cleanup_coordination_tracker(&mut self, now: Instant) {
        let cutoff = now - self.rate_window;
        while let Some(front_request) = self.coordination_requests.front() {
            if front_request.timestamp < cutoff {
                self.coordination_requests.pop_front();
            } else {
                break;
            }
        }
    }
    /// Validate an address for security concerns
    fn validate_address(&mut self, addr: SocketAddr, now: Instant) -> AddressValidationResult {
        // Check cache first
        if let Some(&cached_result) = self.address_validation_cache.get(&addr) {
            return cached_result;
        }
        let result = self.perform_address_validation(addr);

        // Cache the result
        self.address_validation_cache.insert(addr, result);

        // Clean up old cache entries periodically
        if self.address_validation_cache.len() > 1000 {
            self.cleanup_address_cache(now);
        }

        result
    }

    /// Perform actual address validation
    fn perform_address_validation(&self, addr: SocketAddr) -> AddressValidationResult {
        match addr.ip() {
            IpAddr::V4(ipv4) => {
                // Check for invalid IPv4 addresses
                if ipv4.is_unspecified() || ipv4.is_broadcast() {
                    return AddressValidationResult::Invalid;
                }
                // Check for suspicious addresses
                if ipv4.is_multicast() || ipv4.is_documentation() {
                    return AddressValidationResult::Suspicious;
                }

                // Check for reserved ranges that shouldn't be used for P2P
                if ipv4.octets()[0] == 0 || ipv4.octets()[0] == 127 {
                    return AddressValidationResult::Invalid;
                }

                // Check for common attack patterns
                if self.is_suspicious_ipv4(ipv4) {
                    return AddressValidationResult::Suspicious;
                }
            }
            IpAddr::V6(ipv6) => {
                // Check for invalid IPv6 addresses
                if ipv6.is_unspecified() || ipv6.is_multicast() {
                    return AddressValidationResult::Invalid;
                }

                // Check for suspicious IPv6 addresses
                if self.is_suspicious_ipv6(ipv6) {
                    return AddressValidationResult::Suspicious;
                }
            }
        }

        // Check port range
        if addr.port() == 0 || addr.port() < 1024 {
            return AddressValidationResult::Suspicious;
        }

        AddressValidationResult::Valid
    }

    /// Check for suspicious IPv4 patterns
    fn is_suspicious_ipv4(&self, ipv4: Ipv4Addr) -> bool {
        let octets = ipv4.octets();
        // Check for patterns that might indicate scanning or attacks
        // Sequential or patterned addresses
        if octets[0] == octets[1] && octets[1] == octets[2] && octets[2] == octets[3] {
            return true;
        }

        // Check for addresses in ranges commonly used for attacks
        // This is a simplified check - production would have more sophisticated patterns
        false
    }

    /// Check for suspicious IPv6 patterns
    fn is_suspicious_ipv6(&self, ipv6: Ipv6Addr) -> bool {
        let segments = ipv6.segments();
        // Check for obvious patterns
        if segments.iter().all(|&s| s == segments[0]) {
            return true;
        }

        false
    }

    /// Clean up old address validation cache entries
    fn cleanup_address_cache(&mut self, _now: Instant) {
        // Simple cleanup - remove random entries to keep size bounded
        // In production, this would use LRU or timestamp-based cleanup
        if self.address_validation_cache.len() > 500 {
            let keys_to_remove: Vec<_> = self
                .address_validation_cache
                .keys()
                .take(self.address_validation_cache.len() / 2)
                .copied()
                .collect();
            for key in keys_to_remove {
                self.address_validation_cache.remove(&key);
            }
        }
    }

    /// Comprehensive path validation for PUNCH_ME_NOW frames
    ///
    /// This performs security-critical validation to prevent various attacks:
    /// - Address spoofing prevention
    /// - Reflection attack mitigation
    /// - Coordination request validation
    /// - Rate limiting enforcement
    fn validate_punch_me_now_frame(
        &mut self,
        frame: &crate::frame::PunchMeNow,
        source_addr: SocketAddr,
        peer_id: [u8; 32],
        now: Instant,
    ) -> Result<(), NatTraversalError> {
        // 1. Rate limiting validation
        if self.is_coordination_rate_limited(now) {
            debug!(
                "PUNCH_ME_NOW frame rejected: coordination rate limit exceeded for peer {:?}",
                hex::encode(&peer_id[..8])
            );
            return Err(NatTraversalError::RateLimitExceeded);
        }
        // 2. Address validation - validate the address claimed in the frame
        let addr_validation = self.validate_address(frame.address, now);
        match addr_validation {
            AddressValidationResult::Invalid => {
                debug!(
                    "PUNCH_ME_NOW frame rejected: invalid address {:?} from peer {:?}",
                    frame.address,
                    hex::encode(&peer_id[..8])
                );
                return Err(NatTraversalError::InvalidAddress);
            }
            AddressValidationResult::Suspicious => {
                debug!(
                    "PUNCH_ME_NOW frame rejected: suspicious address {:?} from peer {:?}",
                    frame.address,
                    hex::encode(&peer_id[..8])
                );
                return Err(NatTraversalError::SuspiciousCoordination);
            }
            AddressValidationResult::Valid => {
                // Continue validation
            }
        }

        // 3. Source address consistency validation
        // The frame's address should reasonably relate to the actual source
        if !self.validate_address_consistency(frame.address, source_addr) {
            debug!(
                "PUNCH_ME_NOW frame rejected: address consistency check failed. Frame claims {:?}, but received from {:?}",
                frame.address, source_addr
            );
            return Err(NatTraversalError::SuspiciousCoordination);
        }

        // 4. Coordination parameters validation
        if !self.validate_coordination_parameters(frame) {
            debug!(
                "PUNCH_ME_NOW frame rejected: invalid coordination parameters from peer {:?}",
                hex::encode(&peer_id[..8])
            );
            return Err(NatTraversalError::SuspiciousCoordination);
        }

        // 5. Target peer validation (if present)
        if let Some(target_peer_id) = frame.target_peer_id {
            if !self.validate_target_peer_request(peer_id, target_peer_id, frame) {
                debug!(
                    "PUNCH_ME_NOW frame rejected: invalid target peer request from {:?} to {:?}",
                    hex::encode(&peer_id[..8]),
                    hex::encode(&target_peer_id[..8])
                );
                return Err(NatTraversalError::SuspiciousCoordination);
            }
        }

        // 6. Resource limits validation
        if !self.validate_resource_limits(frame) {
            debug!(
                "PUNCH_ME_NOW frame rejected: resource limits exceeded from peer {:?}",
                hex::encode(&peer_id[..8])
            );
            return Err(NatTraversalError::ResourceLimitExceeded);
        }

        debug!(
            "PUNCH_ME_NOW frame validation passed for peer {:?}",
            hex::encode(&peer_id[..8])
        );
        Ok(())
    }

    /// Validate address consistency between claimed and observed addresses
    ///
    /// This prevents address spoofing by ensuring the claimed local address
    /// is reasonably consistent with the observed source address.
    fn validate_address_consistency(
        &self,
        claimed_addr: SocketAddr,
        observed_addr: SocketAddr,
    ) -> bool {
        // For P2P NAT traversal, the port will typically be different due to NAT,
        // but the IP should be consistent unless there's multi-homing or proxying
        // Check if IPs are in the same family
        match (claimed_addr.ip(), observed_addr.ip()) {
            (IpAddr::V4(claimed_ip), IpAddr::V4(observed_ip)) => {
                // For IPv4, allow same IP or addresses in same private range
                if claimed_ip == observed_ip {
                    return true;
                }

                // Allow within same private network (simplified check)
                if self.are_in_same_private_network_v4(claimed_ip, observed_ip) {
                    return true;
                }

                // Allow certain NAT scenarios where external IP differs
                // This is a simplified check - production would be more sophisticated
                !claimed_ip.is_private() && !observed_ip.is_private()
            }
            (IpAddr::V6(claimed_ip), IpAddr::V6(observed_ip)) => {
                // For IPv6, be more lenient due to complex addressing
                claimed_ip == observed_ip || self.are_in_same_prefix_v6(claimed_ip, observed_ip)
            }
            _ => {
                // Mismatched IP families - suspicious
                false
            }
        }
    }

    /// Check if two IPv4 addresses are in the same private network
    fn are_in_same_private_network_v4(&self, ip1: Ipv4Addr, ip2: Ipv4Addr) -> bool {
        // Check common private ranges
        let ip1_octets = ip1.octets();
        let ip2_octets = ip2.octets();
        // 10.0.0.0/8
        if ip1_octets[0] == 10 && ip2_octets[0] == 10 {
            return true;
        }

        // 172.16.0.0/12
        if ip1_octets[0] == 172
            && ip2_octets[0] == 172
            && (16..=31).contains(&ip1_octets[1])
            && (16..=31).contains(&ip2_octets[1])
        {
            return true;
        }

        // 192.168.0.0/16
        if ip1_octets[0] == 192
            && ip1_octets[1] == 168
            && ip2_octets[0] == 192
            && ip2_octets[1] == 168
        {
            return true;
        }

        false
    }

    /// Check if two IPv6 addresses are in the same prefix
    fn are_in_same_prefix_v6(&self, ip1: Ipv6Addr, ip2: Ipv6Addr) -> bool {
        // Simplified IPv6 prefix check - compare first 64 bits
        let segments1 = ip1.segments();
        let segments2 = ip2.segments();
        segments1[0] == segments2[0]
            && segments1[1] == segments2[1]
            && segments1[2] == segments2[2]
            && segments1[3] == segments2[3]
    }

    /// Validate coordination parameters for security
    fn validate_coordination_parameters(&self, frame: &crate::frame::PunchMeNow) -> bool {
        // Check round number is reasonable (not too large to prevent overflow attacks)
        if frame.round.into_inner() > 1000000 {
            return false;
        }
        // Check target sequence is reasonable
        if frame.paired_with_sequence_number.into_inner() > 10000 {
            return false;
        }

        // Validate address is not obviously invalid
        match frame.address.ip() {
            IpAddr::V4(ipv4) => {
                // Reject obviously invalid addresses
                !ipv4.is_unspecified() && !ipv4.is_broadcast() && !ipv4.is_multicast()
            }
            IpAddr::V6(ipv6) => {
                // Reject obviously invalid addresses
                !ipv6.is_unspecified() && !ipv6.is_multicast()
            }
        }
    }

    /// Validate target peer request for potential abuse
    fn validate_target_peer_request(
        &self,
        requesting_peer: [u8; 32],
        target_peer: [u8; 32],
        _frame: &crate::frame::PunchMeNow,
    ) -> bool {
        // Prevent self-coordination (peer requesting coordination with itself)
        if requesting_peer == target_peer {
            return false;
        }
        // Additional validation could include:
        // - Check if target peer is known/registered
        // - Validate target peer hasn't opted out of coordination
        // - Check for suspicious patterns in target peer selection

        true
    }

    /// Validate resource limits for the coordination request
    fn validate_resource_limits(&self, _frame: &crate::frame::PunchMeNow) -> bool {
        // Check current load and resource usage
        // This is a simplified check - production would monitor:
        // - Active coordination sessions
        // - Memory usage
        // - Network bandwidth
        // - CPU utilization
        // For now, just check if we have too many active coordination requests
        self.coordination_requests.len() < self.max_coordination_per_window as usize
    }
}

impl AdaptiveTimeoutState {
    /// Create new adaptive timeout state with default values
    pub(crate) fn new() -> Self {
        let base_timeout = Duration::from_millis(1000); // 1 second base
        Self {
            current_timeout: base_timeout,
            min_timeout: Duration::from_millis(100),
            max_timeout: Duration::from_secs(30),
            base_timeout,
            backoff_multiplier: 1.0,
            max_backoff_multiplier: 8.0,
            jitter_factor: 0.1, // 10% jitter
            srtt: None,
            rttvar: None,
            last_rtt: None,
            consecutive_timeouts: 0,
            successful_responses: 0,
        }
    }
    /// Update timeout based on successful response
    fn update_success(&mut self, rtt: Duration) {
        self.last_rtt = Some(rtt);
        self.successful_responses += 1;
        self.consecutive_timeouts = 0;
        // Update smoothed RTT using TCP algorithm
        match self.srtt {
            None => {
                self.srtt = Some(rtt);
                self.rttvar = Some(rtt / 2);
            }
            Some(srtt) => {
                let rttvar = self.rttvar.unwrap_or(rtt / 2);
                let abs_diff = rtt.abs_diff(srtt);

                self.rttvar = Some(rttvar * 3 / 4 + abs_diff / 4);
                self.srtt = Some(srtt * 7 / 8 + rtt / 8);
            }
        }

        // Reduce backoff multiplier on success
        self.backoff_multiplier = (self.backoff_multiplier * 0.8).max(1.0);

        // Update current timeout
        self.calculate_current_timeout();
    }

    /// Update timeout based on timeout event
    fn update_timeout(&mut self) {
        self.consecutive_timeouts += 1;
        // Exponential backoff with bounds
        self.backoff_multiplier = (self.backoff_multiplier * 2.0).min(self.max_backoff_multiplier);

        // Update current timeout
        self.calculate_current_timeout();
    }

    /// Calculate current timeout based on conditions
    fn calculate_current_timeout(&mut self) {
        let base_timeout = if let (Some(srtt), Some(rttvar)) = (self.srtt, self.rttvar) {
            // Use TCP-style RTO calculation: RTO = SRTT + 4 * RTTVAR
            srtt + rttvar * 4
        } else {
            self.base_timeout
        };
        // Apply backoff multiplier
        let timeout = base_timeout.mul_f64(self.backoff_multiplier);

        // Apply jitter to prevent thundering herd
        let jitter = 1.0 + (rand::random::<f64>() - 0.5) * 2.0 * self.jitter_factor;
        let timeout = timeout.mul_f64(jitter);

        // Bound the timeout
        self.current_timeout = timeout.clamp(self.min_timeout, self.max_timeout);
    }

    /// Get current timeout value
    fn get_timeout(&self) -> Duration {
        self.current_timeout
    }
    /// Check if retry should be attempted
    fn should_retry(&self, max_retries: u32) -> bool {
        self.consecutive_timeouts < max_retries
    }
    /// Get retry delay with exponential backoff
    fn get_retry_delay(&self) -> Duration {
        let delay = self.current_timeout.mul_f64(self.backoff_multiplier);
        delay.clamp(self.min_timeout, self.max_timeout)
    }
}
/// Resource management limits and cleanup configuration
#[derive(Debug)]
#[allow(dead_code)]
pub(super) struct ResourceManagementConfig {
    /// Maximum number of active validations
    max_active_validations: usize,
    /// Maximum number of local candidates
    max_local_candidates: usize,
    /// Maximum number of remote candidates
    max_remote_candidates: usize,
    /// Maximum number of candidate pairs
    max_candidate_pairs: usize,
    /// Maximum coordination rounds to keep in history
    max_coordination_history: usize,
    /// Cleanup interval for expired resources
    cleanup_interval: Duration,
    /// Timeout for stale candidates
    candidate_timeout: Duration,
    /// Timeout for path validations
    validation_timeout: Duration,
    /// Timeout for coordination rounds
    coordination_timeout: Duration,
    /// Memory pressure threshold (0.0 = no pressure, 1.0 = maximum pressure)
    memory_pressure_threshold: f64,
    /// Aggressive cleanup mode threshold
    aggressive_cleanup_threshold: f64,
}
/// Resource usage statistics and monitoring
#[derive(Debug, Default)]
#[allow(dead_code)]
pub(super) struct ResourceStats {
    /// Current number of active validations
    active_validations: usize,
    /// Current number of local candidates
    local_candidates: usize,
    /// Current number of remote candidates
    remote_candidates: usize,
    /// Current number of candidate pairs
    candidate_pairs: usize,
    /// Peak memory usage
    peak_memory_usage: usize,
    /// Number of cleanup operations performed
    cleanup_operations: u64,
    /// Number of resources cleaned up
    resources_cleaned: u64,
    /// Number of resource allocation failures
    allocation_failures: u64,
    /// Last cleanup time
    last_cleanup: Option<Instant>,
    /// Memory pressure level (0.0 = no pressure, 1.0 = maximum pressure)
    memory_pressure: f64,
}
/// Resource cleanup coordinator
#[derive(Debug)]
pub(super) struct ResourceCleanupCoordinator {
    /// Configuration for resource limits
    config: ResourceManagementConfig,
    /// Resource usage statistics
    stats: ResourceStats,
    /// Last cleanup time
    last_cleanup: Option<Instant>,
    /// Cleanup operation counter
    cleanup_counter: u64,
    /// Shutdown flag
    shutdown_requested: bool,
}
impl ResourceManagementConfig {
    /// Create new resource management configuration with production-ready defaults
    fn new() -> Self {
        Self {
            max_active_validations: 100,
            max_local_candidates: 50,
            max_remote_candidates: 100,
            max_candidate_pairs: 200,
            max_coordination_history: 10,
            cleanup_interval: Duration::from_secs(30),
            candidate_timeout: Duration::from_secs(300), // 5 minutes
            validation_timeout: Duration::from_secs(30),
            coordination_timeout: Duration::from_secs(60),
            memory_pressure_threshold: 0.75,
            aggressive_cleanup_threshold: 0.90,
        }
    }
    /// Create configuration optimized for low-memory environments
    #[cfg(feature = "low_memory")]
    fn low_memory() -> Self {
        Self {
            max_active_validations: 25,
            max_local_candidates: 10,
            max_remote_candidates: 25,
            max_candidate_pairs: 50,
            max_coordination_history: 3,
            cleanup_interval: Duration::from_secs(15),
            candidate_timeout: Duration::from_secs(180), // 3 minutes
            validation_timeout: Duration::from_secs(20),
            coordination_timeout: Duration::from_secs(30),
            memory_pressure_threshold: 0.60,
            aggressive_cleanup_threshold: 0.80,
        }
    }
}
#[allow(dead_code)]
impl ResourceCleanupCoordinator {
    /// Create new resource cleanup coordinator
    fn new() -> Self {
        Self {
            config: ResourceManagementConfig::new(),
            stats: ResourceStats::default(),
            last_cleanup: None,
            cleanup_counter: 0,
            shutdown_requested: false,
        }
    }
    /// Create coordinator optimized for low-memory environments
    #[cfg(feature = "low_memory")]
    fn low_memory() -> Self {
        Self {
            config: ResourceManagementConfig::low_memory(),
            stats: ResourceStats::default(),
            last_cleanup: None,
            cleanup_counter: 0,
            shutdown_requested: false,
        }
    }
    /// Check if resource limits are exceeded
    fn check_resource_limits(&self, state: &NatTraversalState) -> bool {
        state.active_validations.len() > self.config.max_active_validations
            || state.local_candidates.len() > self.config.max_local_candidates
            || state.remote_candidates.len() > self.config.max_remote_candidates
            || state.candidate_pairs.len() > self.config.max_candidate_pairs
    }
    /// Calculate current memory pressure level
    fn calculate_memory_pressure(
        &mut self,
        active_validations_len: usize,
        local_candidates_len: usize,
        remote_candidates_len: usize,
        candidate_pairs_len: usize,
    ) -> f64 {
        let total_limit = self.config.max_active_validations
            + self.config.max_local_candidates
            + self.config.max_remote_candidates
            + self.config.max_candidate_pairs;
        let current_usage = active_validations_len
            + local_candidates_len
            + remote_candidates_len
            + candidate_pairs_len;

        let pressure = current_usage as f64 / total_limit as f64;
        self.stats.memory_pressure = pressure;
        pressure
    }

    /// Determine if cleanup is needed
    fn should_cleanup(&self, now: Instant) -> bool {
        if self.shutdown_requested {
            return true;
        }
        // Check if it's time for regular cleanup
        if let Some(last_cleanup) = self.last_cleanup {
            if now.duration_since(last_cleanup) >= self.config.cleanup_interval {
                return true;
            }
        } else {
            return true; // First cleanup
        }

        // Check memory pressure
        if self.stats.memory_pressure > self.config.memory_pressure_threshold {
            return true;
        }

        false
    }

    /// Perform cleanup of expired resources
    fn cleanup_expired_resources(
        &mut self,
        active_validations: &mut HashMap<SocketAddr, PathValidationState>,
        local_candidates: &mut HashMap<VarInt, AddressCandidate>,
        remote_candidates: &mut HashMap<VarInt, AddressCandidate>,
        candidate_pairs: &mut Vec<CandidatePair>,
        coordination: &mut Option<CoordinationState>,
        now: Instant,
    ) -> u64 {
        let mut cleaned = 0;
        // Clean up expired path validations
        cleaned += self.cleanup_expired_validations(active_validations, now);

        // Clean up stale candidates
        cleaned += self.cleanup_stale_candidates(local_candidates, remote_candidates, now);

        // Clean up failed candidate pairs
        cleaned += self.cleanup_failed_pairs(candidate_pairs, now);

        // Clean up old coordination state
        cleaned += self.cleanup_old_coordination(coordination, now);

        // Update statistics
        self.stats.cleanup_operations += 1;
        self.stats.resources_cleaned += cleaned;
        self.last_cleanup = Some(now);
        self.cleanup_counter += 1;

        debug!("Cleaned up {} expired resources", cleaned);
        cleaned
    }

    /// Clean up expired path validations
    fn cleanup_expired_validations(
        &mut self,
        active_validations: &mut HashMap<SocketAddr, PathValidationState>,
        now: Instant,
    ) -> u64 {
        let mut cleaned = 0;
        let validation_timeout = self.config.validation_timeout;
        active_validations.retain(|_addr, validation| {
            let is_expired = now.duration_since(validation.sent_at) > validation_timeout;
            if is_expired {
                cleaned += 1;
                trace!("Cleaned up expired validation for {:?}", _addr);
            }
            !is_expired
        });

        cleaned
    }

    /// Clean up stale candidates
    fn cleanup_stale_candidates(
        &mut self,
        local_candidates: &mut HashMap<VarInt, AddressCandidate>,
        remote_candidates: &mut HashMap<VarInt, AddressCandidate>,
        now: Instant,
    ) -> u64 {
        let mut cleaned = 0;
        let candidate_timeout = self.config.candidate_timeout;
        // Clean up local candidates
        local_candidates.retain(|_seq, candidate| {
            let is_stale = now.duration_since(candidate.discovered_at) > candidate_timeout
                || candidate.state == CandidateState::Failed
                || candidate.state == CandidateState::Removed;
            if is_stale {
                cleaned += 1;
                trace!("Cleaned up stale local candidate {:?}", candidate.address);
            }
            !is_stale
        });

        // Clean up remote candidates
        remote_candidates.retain(|_seq, candidate| {
            let is_stale = now.duration_since(candidate.discovered_at) > candidate_timeout
                || candidate.state == CandidateState::Failed
                || candidate.state == CandidateState::Removed;
            if is_stale {
                cleaned += 1;
                trace!("Cleaned up stale remote candidate {:?}", candidate.address);
            }
            !is_stale
        });

        cleaned
    }

    /// Clean up failed candidate pairs
    fn cleanup_failed_pairs(
        &mut self,
        candidate_pairs: &mut Vec<CandidatePair>,
        now: Instant,
    ) -> u64 {
        let mut cleaned = 0;
        let pair_timeout = self.config.candidate_timeout;
        candidate_pairs.retain(|pair| {
            let is_stale = now.duration_since(pair.created_at) > pair_timeout
                || pair.state == PairState::Failed;
            if is_stale {
                cleaned += 1;
                trace!(
                    "Cleaned up failed candidate pair {:?} -> {:?}",
                    pair.local_addr, pair.remote_addr
                );
            }
            !is_stale
        });

        cleaned
    }

    /// Clean up old coordination state
    fn cleanup_old_coordination(
        &mut self,
        coordination: &mut Option<CoordinationState>,
        now: Instant,
    ) -> u64 {
        let mut cleaned = 0;
        if let Some(coord) = coordination {
            let is_expired =
                now.duration_since(coord.round_start) > self.config.coordination_timeout;
            let is_failed = coord.state == CoordinationPhase::Failed;

            if is_expired || is_failed {
                let round = coord.round;
                *coordination = None;
                cleaned += 1;
                trace!("Cleaned up old coordination state for round {}", round);
            }
        }

        cleaned
    }

    /// Perform aggressive cleanup when under memory pressure
    fn aggressive_cleanup(
        &mut self,
        active_validations: &mut HashMap<SocketAddr, PathValidationState>,
        local_candidates: &mut HashMap<VarInt, AddressCandidate>,
        remote_candidates: &mut HashMap<VarInt, AddressCandidate>,
        candidate_pairs: &mut Vec<CandidatePair>,
        now: Instant,
    ) -> u64 {
        let mut cleaned = 0;
        // More aggressive timeout for candidates
        let aggressive_timeout = self.config.candidate_timeout / 2;

        // Clean up older candidates first
        local_candidates.retain(|_seq, candidate| {
            let keep = now.duration_since(candidate.discovered_at) <= aggressive_timeout
                && candidate.state != CandidateState::Failed;
            if !keep {
                cleaned += 1;
            }
            keep
        });

        remote_candidates.retain(|_seq, candidate| {
            let keep = now.duration_since(candidate.discovered_at) <= aggressive_timeout
                && candidate.state != CandidateState::Failed;
            if !keep {
                cleaned += 1;
            }
            keep
        });

        // Clean up waiting candidate pairs
        candidate_pairs.retain(|pair| {
            let keep = pair.state != PairState::Waiting
                || now.duration_since(pair.created_at) <= aggressive_timeout;
            if !keep {
                cleaned += 1;
            }
            keep
        });

        // Clean up old validations more aggressively
        active_validations.retain(|_addr, validation| {
            let keep = now.duration_since(validation.sent_at) <= self.config.validation_timeout / 2;
            if !keep {
                cleaned += 1;
            }
            keep
        });

        warn!(
            "Aggressive cleanup removed {} resources due to memory pressure",
            cleaned
        );
        cleaned
    }

    /// Request graceful shutdown and cleanup
    fn request_shutdown(&mut self) {
        self.shutdown_requested = true;
        debug!("Resource cleanup coordinator shutdown requested");
    }
    /// Perform final cleanup during shutdown
    fn shutdown_cleanup(
        &mut self,
        active_validations: &mut HashMap<SocketAddr, PathValidationState>,
        local_candidates: &mut HashMap<VarInt, AddressCandidate>,
        remote_candidates: &mut HashMap<VarInt, AddressCandidate>,
        candidate_pairs: &mut Vec<CandidatePair>,
        coordination: &mut Option<CoordinationState>,
    ) -> u64 {
        let mut cleaned = 0;
        // Clear all resources
        cleaned += active_validations.len() as u64;
        active_validations.clear();

        cleaned += local_candidates.len() as u64;
        local_candidates.clear();

        cleaned += remote_candidates.len() as u64;
        remote_candidates.clear();

        cleaned += candidate_pairs.len() as u64;
        candidate_pairs.clear();

        if coordination.is_some() {
            *coordination = None;
            cleaned += 1;
        }

        info!("Shutdown cleanup removed {} resources", cleaned);
        cleaned
    }

    /// Get current resource usage statistics
    fn get_resource_stats(&self) -> &ResourceStats {
        &self.stats
    }
    /// Update resource usage statistics
    fn update_stats(
        &mut self,
        active_validations_len: usize,
        local_candidates_len: usize,
        remote_candidates_len: usize,
        candidate_pairs_len: usize,
    ) {
        self.stats.active_validations = active_validations_len;
        self.stats.local_candidates = local_candidates_len;
        self.stats.remote_candidates = remote_candidates_len;
        self.stats.candidate_pairs = candidate_pairs_len;
        // Update peak memory usage
        let current_usage = self.stats.active_validations
            + self.stats.local_candidates
            + self.stats.remote_candidates
            + self.stats.candidate_pairs;

        if current_usage > self.stats.peak_memory_usage {
            self.stats.peak_memory_usage = current_usage;
        }
    }

    /// Perform resource cleanup based on current state
    pub(super) fn perform_cleanup(&mut self, now: Instant) {
        self.last_cleanup = Some(now);
        self.cleanup_counter += 1;
        // Update cleanup statistics
        self.stats.cleanup_operations += 1;

        debug!("Performed resource cleanup #{}", self.cleanup_counter);
    }
}

#[allow(dead_code)]
impl NetworkConditionMonitor {
    /// Create new network condition monitor
    fn new() -> Self {
        Self {
            rtt_samples: VecDeque::new(),
            max_samples: 20,
            packet_loss_rate: 0.0,
            congestion_window: 10,
            quality_score: 0.8, // Start with good quality assumption
            last_quality_update: Instant::now(),
            quality_update_interval: Duration::from_secs(10),
            timeout_stats: TimeoutStatistics::default(),
        }
    }
    /// Record a successful response time
    fn record_success(&mut self, rtt: Duration, now: Instant) {
        // Add RTT sample
        self.rtt_samples.push_back(rtt);
        if self.rtt_samples.len() > self.max_samples {
            self.rtt_samples.pop_front();
        }
        // Update timeout statistics
        self.timeout_stats.total_responses += 1;
        self.update_timeout_stats(now);

        // Update quality score
        self.update_quality_score(now);
    }

    /// Record a timeout event
    fn record_timeout(&mut self, now: Instant) {
        self.timeout_stats.total_timeouts += 1;
        self.update_timeout_stats(now);
        // Update quality score
        self.update_quality_score(now);
    }

    /// Update timeout statistics
    fn update_timeout_stats(&mut self, now: Instant) {
        let total_attempts = self.timeout_stats.total_responses + self.timeout_stats.total_timeouts;
        if total_attempts > 0 {
            self.timeout_stats.timeout_rate =
                self.timeout_stats.total_timeouts as f64 / total_attempts as f64;
        }

        // Calculate average response time
        if !self.rtt_samples.is_empty() {
            let total_rtt: Duration = self.rtt_samples.iter().sum();
            self.timeout_stats.avg_response_time = total_rtt / self.rtt_samples.len() as u32;
        }

        self.timeout_stats.last_update = Some(now);
    }

    /// Update network quality score
    fn update_quality_score(&mut self, now: Instant) {
        if now.duration_since(self.last_quality_update) < self.quality_update_interval {
            return;
        }
        // Quality factors
        let timeout_factor = 1.0 - self.timeout_stats.timeout_rate;
        let rtt_factor = self.calculate_rtt_factor();
        let consistency_factor = self.calculate_consistency_factor();

        // Weighted quality score
        let new_quality = (timeout_factor * 0.4) + (rtt_factor * 0.3) + (consistency_factor * 0.3);

        // Smooth the quality score
        self.quality_score = self.quality_score * 0.7 + new_quality * 0.3;
        self.last_quality_update = now;
    }

    /// Calculate RTT factor for quality score
    fn calculate_rtt_factor(&self) -> f64 {
        if self.rtt_samples.is_empty() {
            return 0.5; // Neutral score
        }
        let avg_rtt = self.timeout_stats.avg_response_time;

        // Good RTT: < 50ms = 1.0, Poor RTT: > 1000ms = 0.0
        let rtt_ms = avg_rtt.as_millis() as f64;
        let factor = 1.0 - (rtt_ms - 50.0) / 950.0;
        factor.clamp(0.0, 1.0)
    }

    /// Calculate consistency factor for quality score
    fn calculate_consistency_factor(&self) -> f64 {
        if self.rtt_samples.len() < 3 {
            return 0.5; // Neutral score
        }
        // Calculate RTT variance
        let mean_rtt = self.timeout_stats.avg_response_time;
        let variance: f64 = self
            .rtt_samples
            .iter()
            .map(|rtt| {
                let diff = (*rtt).abs_diff(mean_rtt);
                diff.as_millis() as f64
            })
            .map(|diff| diff * diff)
            .sum::<f64>()
            / self.rtt_samples.len() as f64;

        let std_dev = variance.sqrt();

        // Low variance = high consistency
        let consistency = 1.0 - (std_dev / 1000.0).min(1.0);
        consistency.clamp(0.0, 1.0)
    }

    /// Get current network quality score
    fn get_quality_score(&self) -> f64 {
        self.quality_score
    }
    /// Get estimated RTT based on recent samples
    fn get_estimated_rtt(&self) -> Option<Duration> {
        if self.rtt_samples.is_empty() {
            return None;
        }
        Some(self.timeout_stats.avg_response_time)
    }

    /// Check if network conditions are suitable for coordination
    fn is_suitable_for_coordination(&self) -> bool {
        // Require reasonable quality for coordination attempts
        self.quality_score >= 0.3 && self.timeout_stats.timeout_rate < 0.5
    }
    /// Get estimated packet loss rate
    fn get_packet_loss_rate(&self) -> f64 {
        self.packet_loss_rate
    }

    /// Get recommended timeout multiplier based on conditions
    fn get_timeout_multiplier(&self) -> f64 {
        let base_multiplier = 1.0;

        // Adjust based on quality score
        let quality_multiplier = if self.quality_score < 0.3 {
            2.0 // Poor quality, increase timeouts
        } else if self.quality_score > 0.8 {
            0.8 // Good quality, reduce timeouts
        } else {
            1.0 // Neutral
        };

        // Adjust based on packet loss
        let loss_multiplier = 1.0 + (self.packet_loss_rate * 2.0);

        base_multiplier * quality_multiplier * loss_multiplier
    }

    /// Clean up old samples and statistics
    fn cleanup(&mut self, now: Instant) {
        // Remove old RTT samples (keep only recent ones)
        let _cutoff_time = now - Duration::from_secs(60);

        // Reset statistics if they're too old
        if let Some(last_update) = self.timeout_stats.last_update {
            if now.duration_since(last_update) > Duration::from_secs(300) {
                self.timeout_stats = TimeoutStatistics::default();
            }
        }
    }
}

#[allow(dead_code)]
impl NatTraversalState {
    /// Create new NAT traversal state with given role and configuration
    pub(super) fn new(
        role: NatTraversalRole,
        max_candidates: u32,
        coordination_timeout: Duration,
    ) -> Self {
        let bootstrap_coordinator = if matches!(role, NatTraversalRole::Bootstrap) {
            Some(BootstrapCoordinator::new(BootstrapConfig::default()))
        } else {
            None
        };
        Self {
            role,
            local_candidates: HashMap::new(),
            remote_candidates: HashMap::new(),
            candidate_pairs: Vec::new(),
            pair_index: HashMap::new(),
            active_validations: HashMap::new(),
            coordination: None,
            next_sequence: VarInt::from_u32(1),
            max_candidates,
            coordination_timeout,
            stats: NatTraversalStats::default(),
            security_state: SecurityValidationState::new(),
            network_monitor: NetworkConditionMonitor::new(),
            resource_manager: ResourceCleanupCoordinator::new(),
            bootstrap_coordinator,
        }
    }

    /// Add a remote candidate from AddAddress frame with security validation
    pub(super) fn add_remote_candidate(
        &mut self,
        sequence: VarInt,
        address: SocketAddr,
        priority: VarInt,
        now: Instant,
    ) -> Result<(), NatTraversalError> {
        // Resource management: Check if we should reject new resources
        if self.should_reject_new_resources(now) {
            debug!(
                "Rejecting new candidate due to resource limits: {}",
                address
            );
            return Err(NatTraversalError::ResourceLimitExceeded);
        }
        // Security validation: Check rate limiting
        if self.security_state.is_candidate_rate_limited(now) {
            self.stats.rate_limit_violations += 1;
            debug!("Rate limit exceeded for candidate addition: {}", address);
            return Err(NatTraversalError::RateLimitExceeded);
        }

        // Security validation: Validate address format and safety
        match self.security_state.validate_address(address, now) {
            AddressValidationResult::Invalid => {
                self.stats.invalid_address_rejections += 1;
                self.stats.security_rejections += 1;
                debug!("Invalid address rejected: {}", address);
                return Err(NatTraversalError::InvalidAddress);
            }
            AddressValidationResult::Suspicious => {
                self.stats.security_rejections += 1;
                debug!("Suspicious address rejected: {}", address);
                return Err(NatTraversalError::SecurityValidationFailed);
            }
            AddressValidationResult::Valid => {
                // Continue with normal processing
            }
        }

        // Check candidate count limit
        if self.remote_candidates.len() >= self.max_candidates as usize {
            return Err(NatTraversalError::TooManyCandidates);
        }

        // Check for duplicate addresses (different sequence, same address)
        if self
            .remote_candidates
            .values()
            .any(|c| c.address == address && c.state != CandidateState::Removed)
        {
            return Err(NatTraversalError::DuplicateAddress);
        }

        let candidate = AddressCandidate {
            address,
            priority: priority.into_inner() as u32,
            source: CandidateSource::Peer,
            discovered_at: now,
            state: CandidateState::New,
            attempt_count: 0,
            last_attempt: None,
        };

        self.remote_candidates.insert(sequence, candidate);
        self.stats.remote_candidates_received += 1;

        trace!(
            "Added remote candidate: {} with priority {}",
            address, priority
        );
        Ok(())
    }

    /// Remove a candidate by sequence number
    pub(super) fn remove_candidate(&mut self, sequence: VarInt) -> bool {
        if let Some(candidate) = self.remote_candidates.get_mut(&sequence) {
            candidate.state = CandidateState::Removed;
            // Cancel any active validation for this address
            self.active_validations.remove(&candidate.address);
            true
        } else {
            false
        }
    }

    /// Add a local candidate that we've discovered
    pub(super) fn add_local_candidate(
        &mut self,
        address: SocketAddr,
        source: CandidateSource,
        now: Instant,
    ) -> VarInt {
        let sequence = self.next_sequence;
        self.next_sequence = VarInt::from_u64(self.next_sequence.into_inner() + 1)
            .expect("sequence number overflow");
        // Calculate priority for this candidate
        let candidate_type = classify_candidate_type(source);
        let local_preference = self.calculate_local_preference(address);
        let priority = calculate_candidate_priority(candidate_type, local_preference, 1);

        let candidate = AddressCandidate {
            address,
            priority,
            source,
            discovered_at: now,
            state: CandidateState::New,
            attempt_count: 0,
            last_attempt: None,
        };

        self.local_candidates.insert(sequence, candidate);
        self.stats.local_candidates_sent += 1;

        // Regenerate pairs when we add a new local candidate
        self.generate_candidate_pairs(now);

        sequence
    }

    /// Calculate local preference for address prioritization
    fn calculate_local_preference(&self, addr: SocketAddr) -> u16 {
        match addr {
            SocketAddr::V4(v4) => {
                if v4.ip().is_loopback() {
                    0 // Lowest priority
                } else if v4.ip().is_private() {
                    65000 // High priority for local network
                } else {
                    32000 // Medium priority for public addresses
                }
            }
            SocketAddr::V6(v6) => {
                if v6.ip().is_loopback() {
                    0
                } else if v6.ip().segments()[0] == 0xfe80 {
                    // Link-local IPv6 check
                    30000 // Link-local gets medium-low priority
                } else {
                    50000 // IPv6 generally gets good priority
                }
            }
        }
    }
    /// Generate all possible candidate pairs from local and remote candidates
    pub(super) fn generate_candidate_pairs(&mut self, now: Instant) {
        self.candidate_pairs.clear();
        self.pair_index.clear();
        // Pre-allocate capacity to avoid reallocations
        let estimated_capacity = self.local_candidates.len() * self.remote_candidates.len();
        self.candidate_pairs.reserve(estimated_capacity);
        self.pair_index.reserve(estimated_capacity);

        // Cache compatibility checks to avoid repeated work
        let mut compatibility_cache: HashMap<(SocketAddr, SocketAddr), bool> = HashMap::new();

        for local_candidate in self.local_candidates.values() {
            // Skip removed candidates early
            if local_candidate.state == CandidateState::Removed {
                continue;
            }

            // Pre-classify local candidate type once
            let local_type = classify_candidate_type(local_candidate.source);

            for (remote_seq, remote_candidate) in &self.remote_candidates {
                // Skip removed candidates
                if remote_candidate.state == CandidateState::Removed {
                    continue;
                }

                // Check compatibility with caching
                let cache_key = (local_candidate.address, remote_candidate.address);
                let compatible = *compatibility_cache.entry(cache_key).or_insert_with(|| {
                    are_candidates_compatible(local_candidate, remote_candidate)
                });

                if !compatible {
                    continue;
                }

                // Calculate combined priority
                let pair_priority =
                    calculate_pair_priority(local_candidate.priority, remote_candidate.priority);

                // Classify pair type (local already classified)
                let remote_type = classify_candidate_type(remote_candidate.source);
                let pair_type = classify_pair_type(local_type, remote_type);

                let pair = CandidatePair {
                    remote_sequence: *remote_seq,
                    local_addr: local_candidate.address,
                    remote_addr: remote_candidate.address,
                    priority: pair_priority,
                    state: PairState::Waiting,
                    pair_type,
                    created_at: now,
                    last_check: None,
                };

                // Store index for O(1) lookup
                let index = self.candidate_pairs.len();
                self.pair_index.insert(remote_candidate.address, index);
                self.candidate_pairs.push(pair);
            }
        }

        // Sort pairs by priority (highest first) - use unstable sort for better performance
        self.candidate_pairs
            .sort_unstable_by(|a, b| b.priority.cmp(&a.priority));

        // Rebuild index after sorting since indices changed
        self.pair_index.clear();
        for (idx, pair) in self.candidate_pairs.iter().enumerate() {
            self.pair_index.insert(pair.remote_addr, idx);
        }

        trace!("Generated {} candidate pairs", self.candidate_pairs.len());
    }

    /// Get the highest priority pairs ready for validation
    pub(super) fn get_next_validation_pairs(
        &mut self,
        max_concurrent: usize,
    ) -> Vec<&mut CandidatePair> {
        // Since pairs are sorted by priority (highest first), we can stop early
        // once we find enough waiting pairs or reach lower priority pairs
        let mut result = Vec::with_capacity(max_concurrent);
        for pair in self.candidate_pairs.iter_mut() {
            if pair.state == PairState::Waiting {
                result.push(pair);
                if result.len() >= max_concurrent {
                    break;
                }
            }
        }

        result
    }

    /// Find a candidate pair by remote address
    pub(super) fn find_pair_by_remote_addr(
        &mut self,
        addr: SocketAddr,
    ) -> Option<&mut CandidatePair> {
        // Use index for O(1) lookup instead of O(n) linear search
        if let Some(&index) = self.pair_index.get(&addr) {
            self.candidate_pairs.get_mut(index)
        } else {
            None
        }
    }
    /// Mark a pair as succeeded and handle promotion
    pub(super) fn mark_pair_succeeded(&mut self, remote_addr: SocketAddr) -> bool {
        // Find the pair and get its type and priority
        let (succeeded_type, succeeded_priority) = {
            if let Some(pair) = self.find_pair_by_remote_addr(remote_addr) {
                pair.state = PairState::Succeeded;
                (pair.pair_type, pair.priority)
            } else {
                return false;
            }
        };
        // Freeze lower priority pairs of the same type to avoid unnecessary testing
        for other_pair in &mut self.candidate_pairs {
            if other_pair.pair_type == succeeded_type
                && other_pair.priority < succeeded_priority
                && other_pair.state == PairState::Waiting
            {
                other_pair.state = PairState::Frozen;
            }
        }

        true
    }

    /// Get the best succeeded pair for each address family
    pub(super) fn get_best_succeeded_pairs(&self) -> Vec<&CandidatePair> {
        let mut best_ipv4: Option<&CandidatePair> = None;
        let mut best_ipv6: Option<&CandidatePair> = None;
        for pair in &self.candidate_pairs {
            if pair.state != PairState::Succeeded {
                continue;
            }

            match pair.remote_addr {
                SocketAddr::V4(_) => {
                    if best_ipv4.is_none_or(|best| pair.priority > best.priority) {
                        best_ipv4 = Some(pair);
                    }
                }
                SocketAddr::V6(_) => {
                    if best_ipv6.is_none_or(|best| pair.priority > best.priority) {
                        best_ipv6 = Some(pair);
                    }
                }
            }
        }

        let mut result = Vec::new();
        if let Some(pair) = best_ipv4 {
            result.push(pair);
        }
        if let Some(pair) = best_ipv6 {
            result.push(pair);
        }
        result
    }

    /// Get candidates ready for validation, sorted by priority
    pub(super) fn get_validation_candidates(&self) -> Vec<(VarInt, &AddressCandidate)> {
        let mut candidates: Vec<_> = self
            .remote_candidates
            .iter()
            .filter(|(_, c)| c.state == CandidateState::New)
            .map(|(k, v)| (*k, v))
            .collect();
        // Sort by priority (higher priority first)
        candidates.sort_by(|a, b| b.1.priority.cmp(&a.1.priority));
        candidates
    }

    /// Start validation for a candidate address with security checks
    pub(super) fn start_validation(
        &mut self,
        sequence: VarInt,
        challenge: u64,
        now: Instant,
    ) -> Result<(), NatTraversalError> {
        let candidate = self
            .remote_candidates
            .get_mut(&sequence)
            .ok_or(NatTraversalError::UnknownCandidate)?;
        if candidate.state != CandidateState::New {
            return Err(NatTraversalError::InvalidCandidateState);
        }

        // Security validation: Check for validation abuse patterns
        if Self::is_validation_suspicious(candidate, now) {
            self.stats.security_rejections += 1;
            debug!(
                "Suspicious validation attempt rejected for address {}",
                candidate.address
            );
            return Err(NatTraversalError::SecurityValidationFailed);
        }

        // Security validation: Limit concurrent validations
        if self.active_validations.len() >= 10 {
            debug!(
                "Too many concurrent validations, rejecting new validation for {}",
                candidate.address
            );
            return Err(NatTraversalError::SecurityValidationFailed);
        }

        // Update candidate state
        candidate.state = CandidateState::Validating;
        candidate.attempt_count += 1;
        candidate.last_attempt = Some(now);

        // Track validation state
        let validation = PathValidationState {
            challenge,
            sent_at: now,
            retry_count: 0,
            max_retries: 3, // TODO: Make configurable
            coordination_round: self.coordination.as_ref().map(|c| c.round),
            timeout_state: AdaptiveTimeoutState::new(),
            last_retry_at: None,
        };

        self.active_validations
            .insert(candidate.address, validation);
        trace!(
            "Started validation for candidate {} with challenge {}",
            candidate.address, challenge
        );
        Ok(())
    }

    /// Check if a validation request shows suspicious patterns
    fn is_validation_suspicious(candidate: &AddressCandidate, now: Instant) -> bool {
        // Check for excessive retry attempts
        if candidate.attempt_count > 10 {
            return true;
        }
        // Check for rapid retry patterns
        if let Some(last_attempt) = candidate.last_attempt {
            let time_since_last = now.duration_since(last_attempt);
            if time_since_last < Duration::from_millis(100) {
                return true; // Too frequent attempts
            }
        }

        // Check if this candidate was recently failed
        if candidate.state == CandidateState::Failed {
            let time_since_discovery = now.duration_since(candidate.discovered_at);
            if time_since_discovery < Duration::from_secs(60) {
                return true; // Recently failed, shouldn't retry so soon
            }
        }

        false
    }

    /// Handle successful validation response
    pub(super) fn handle_validation_success(
        &mut self,
        remote_addr: SocketAddr,
        challenge: u64,
        now: Instant,
    ) -> Result<VarInt, NatTraversalError> {
        // Find the candidate with this address
        let sequence = self
            .remote_candidates
            .iter()
            .find(|(_, c)| c.address == remote_addr)
            .map(|(seq, _)| *seq)
            .ok_or(NatTraversalError::UnknownCandidate)?;
        // Verify challenge matches and update timeout state
        let validation = self
            .active_validations
            .get_mut(&remote_addr)
            .ok_or(NatTraversalError::NoActiveValidation)?;

        if validation.challenge != challenge {
            return Err(NatTraversalError::ChallengeMismatch);
        }

        // Calculate RTT and update adaptive timeout
        let rtt = now.duration_since(validation.sent_at);
        validation.timeout_state.update_success(rtt);

        // Update network monitor
        self.network_monitor.record_success(rtt, now);

        // Update candidate state
        let candidate = self
            .remote_candidates
            .get_mut(&sequence)
            .ok_or(NatTraversalError::UnknownCandidate)?;

        candidate.state = CandidateState::Valid;
        self.active_validations.remove(&remote_addr);
        self.stats.validations_succeeded += 1;

        trace!(
            "Validation successful for {} with RTT {:?}",
            remote_addr, rtt
        );
        Ok(sequence)
    }

    /// Start a new coordination round for simultaneous hole punching with security validation
    pub(super) fn start_coordination_round(
        &mut self,
        targets: Vec<PunchTarget>,
        now: Instant,
    ) -> Result<VarInt, NatTraversalError> {
        // Security validation: Check rate limiting for coordination requests
        if self.security_state.is_coordination_rate_limited(now) {
            self.stats.rate_limit_violations += 1;
            debug!(
                "Rate limit exceeded for coordination request with {} targets",
                targets.len()
            );
            return Err(NatTraversalError::RateLimitExceeded);
        }
        // Security validation: Check for suspicious coordination patterns
        if self.is_coordination_suspicious(&targets, now) {
            self.stats.suspicious_coordination_attempts += 1;
            self.stats.security_rejections += 1;
            debug!(
                "Suspicious coordination request rejected with {} targets",
                targets.len()
            );
            return Err(NatTraversalError::SuspiciousCoordination);
        }

        // Security validation: Validate all target addresses
        for target in &targets {
            match self
                .security_state
                .validate_address(target.remote_addr, now)
            {
                AddressValidationResult::Invalid => {
                    self.stats.invalid_address_rejections += 1;
                    self.stats.security_rejections += 1;
                    debug!(
                        "Invalid target address in coordination: {}",
                        target.remote_addr
                    );
                    return Err(NatTraversalError::InvalidAddress);
                }
                AddressValidationResult::Suspicious => {
                    self.stats.security_rejections += 1;
                    debug!(
                        "Suspicious target address in coordination: {}",
                        target.remote_addr
                    );
                    return Err(NatTraversalError::SecurityValidationFailed);
                }
                AddressValidationResult::Valid => {
                    // Continue with normal processing
                }
            }
        }

        let round = self.next_sequence;
        self.next_sequence = VarInt::from_u64(self.next_sequence.into_inner() + 1)
            .expect("sequence number overflow");

        // Calculate synchronized punch time (grace period for coordination)
        let coordination_grace = Duration::from_millis(500); // 500ms for coordination
        let punch_start = now + coordination_grace;

        self.coordination = Some(CoordinationState {
            round,
            punch_targets: targets,
            round_start: now,
            punch_start,
            round_duration: self.coordination_timeout,
            state: CoordinationPhase::Requesting,
            punch_request_sent: false,
            peer_punch_received: false,
            retry_count: 0,
            max_retries: 3,
            timeout_state: AdaptiveTimeoutState::new(),
            last_retry_at: None,
        });

        self.stats.coordination_rounds += 1;
        trace!(
            "Started coordination round {} with {} targets",
            round,
            self.coordination
                .as_ref()
                .map(|c| c.punch_targets.len())
                .unwrap_or(0)
        );
        Ok(round)
    }

    /// Check if a coordination request shows suspicious patterns
    fn is_coordination_suspicious(&self, targets: &[PunchTarget], _now: Instant) -> bool {
        // Check for excessive number of targets
        if targets.len() > 20 {
            return true;
        }
        // Check for duplicate targets
        let mut seen_addresses = std::collections::HashSet::new();
        for target in targets {
            if !seen_addresses.insert(target.remote_addr) {
                return true; // Duplicate target
            }
        }

        // Check for patterns that might indicate scanning
        if targets.len() > 5 {
            // Check if all targets are in sequential IP ranges (potential scan)
            let mut ipv4_addresses: Vec<_> = targets
                .iter()
                .filter_map(|t| match t.remote_addr.ip() {
                    IpAddr::V4(ipv4) => Some(u32::from(ipv4)),
                    _ => None,
                })
                .collect();

            if ipv4_addresses.len() >= 3 {
                ipv4_addresses.sort();
                let mut sequential_count = 1;
                for i in 1..ipv4_addresses.len() {
                    if ipv4_addresses[i] == ipv4_addresses[i - 1] + 1 {
                        sequential_count += 1;
                        if sequential_count >= 3 {
                            return true; // Sequential IPs detected
                        }
                    } else {
                        sequential_count = 1;
                    }
                }
            }
        }

        false
    }

    /// Get the current coordination phase
    pub(super) fn get_coordination_phase(&self) -> Option<CoordinationPhase> {
        self.coordination.as_ref().map(|c| c.state)
    }
    /// Check if we need to send PUNCH_ME_NOW frame
    pub(super) fn should_send_punch_request(&self) -> bool {
        if let Some(coord) = &self.coordination {
            coord.state == CoordinationPhase::Requesting && !coord.punch_request_sent
        } else {
            false
        }
    }
    /// Mark that we've sent our PUNCH_ME_NOW request
    pub(super) fn mark_punch_request_sent(&mut self) {
        if let Some(coord) = &mut self.coordination {
            coord.punch_request_sent = true;
            coord.state = CoordinationPhase::Coordinating;
            trace!("PUNCH_ME_NOW sent, waiting for peer coordination");
        }
    }
    /// Handle receiving peer's PUNCH_ME_NOW (via coordinator) with security validation
    pub(super) fn handle_peer_punch_request(
        &mut self,
        peer_round: VarInt,
        now: Instant,
    ) -> Result<bool, NatTraversalError> {
        // Security validation: Check if this is a valid coordination request
        if self.is_peer_coordination_suspicious(peer_round, now) {
            self.stats.suspicious_coordination_attempts += 1;
            self.stats.security_rejections += 1;
            debug!(
                "Suspicious peer coordination request rejected for round {}",
                peer_round
            );
            return Err(NatTraversalError::SuspiciousCoordination);
        }
        if let Some(coord) = &mut self.coordination {
            if coord.round == peer_round {
                match coord.state {
                    CoordinationPhase::Coordinating | CoordinationPhase::Requesting => {
                        coord.peer_punch_received = true;
                        coord.state = CoordinationPhase::Preparing;

                        // Calculate adaptive grace period based on network conditions
                        let network_rtt = self
                            .network_monitor
                            .get_estimated_rtt()
                            .unwrap_or(Duration::from_millis(100));
                        let quality_score = self.network_monitor.get_quality_score();

                        // Scale grace period: good networks get shorter delays
                        let base_grace = Duration::from_millis(150);
                        let rtt_factor = (network_rtt.as_millis() as f64 / 100.0).clamp(0.5, 3.0);
                        let quality_factor = (2.0 - quality_score).clamp(1.0, 2.0);

                        let adaptive_grace = Duration::from_millis(
                            (base_grace.as_millis() as f64 * rtt_factor * quality_factor) as u64,
                        );

                        coord.punch_start = now + adaptive_grace;

                        trace!(
                            "Peer coordination received, punch starts in {:?} (RTT: {:?}, quality: {:.2})",
                            adaptive_grace, network_rtt, quality_score
                        );
                        Ok(true)
                    }
                    CoordinationPhase::Preparing => {
                        // Already in preparation phase, just acknowledge
                        trace!("Peer coordination confirmed during preparation");
                        Ok(true)
                    }
                    _ => {
                        debug!(
                            "Received coordination in unexpected phase: {:?}",
                            coord.state
                        );
                        Ok(false)
                    }
                }
            } else {
                debug!(
                    "Received coordination for wrong round: {} vs {}",
                    peer_round, coord.round
                );
                Ok(false)
            }
        } else {
            debug!("Received peer coordination but no active round");
            Ok(false)
        }
    }

    /// Check if a peer coordination request is suspicious
    fn is_peer_coordination_suspicious(&self, peer_round: VarInt, _now: Instant) -> bool {
        // Check for round number anomalies
        if peer_round.into_inner() == 0 {
            return true; // Invalid round number
        }
        // Check if round is too far in the future or past
        if let Some(coord) = &self.coordination {
            let our_round = coord.round.into_inner();
            let peer_round_num = peer_round.into_inner();

            // Allow some variance but reject extreme differences
            if peer_round_num > our_round + 100 || peer_round_num + 100 < our_round {
                return true;
            }
        }

        false
    }

    /// Check if it's time to start hole punching
    pub(super) fn should_start_punching(&self, now: Instant) -> bool {
        if let Some(coord) = &self.coordination {
            match coord.state {
                CoordinationPhase::Preparing => now >= coord.punch_start,
                CoordinationPhase::Coordinating => {
                    // Check if we have peer confirmation and grace period elapsed
                    coord.peer_punch_received && now >= coord.punch_start
                }
                _ => false,
            }
        } else {
            false
        }
    }
    /// Start the synchronized hole punching phase
    pub(super) fn start_punching_phase(&mut self, now: Instant) {
        if let Some(coord) = &mut self.coordination {
            coord.state = CoordinationPhase::Punching;
            // Calculate precise timing for coordinated transmission
            let network_rtt = self
                .network_monitor
                .get_estimated_rtt()
                .unwrap_or(Duration::from_millis(100));

            // Add small random jitter to avoid thundering herd
            let jitter_ms: u64 = rand::random::<u64>() % 11;
            let jitter = Duration::from_millis(jitter_ms);
            let transmission_time = coord.punch_start + network_rtt / 2 + jitter;

            // Update punch start time with precise calculation
            coord.punch_start = transmission_time.max(now);

            trace!(
                "Starting synchronized hole punching at {:?} (RTT: {:?}, jitter: {:?})",
                coord.punch_start, network_rtt, jitter
            );
        }
    }

    /// Get punch targets for the current round
    pub(super) fn get_punch_targets_from_coordination(&self) -> Option<&[PunchTarget]> {
        self.coordination
            .as_ref()
            .map(|c| c.punch_targets.as_slice())
    }
    /// Mark coordination as validating (PATH_CHALLENGE sent)
    pub(super) fn mark_coordination_validating(&mut self) {
        if let Some(coord) = &mut self.coordination {
            if coord.state == CoordinationPhase::Punching {
                coord.state = CoordinationPhase::Validating;
                trace!("Coordination moved to validation phase");
            }
        }
    }
    /// Handle successful path validation during coordination
    pub(super) fn handle_coordination_success(
        &mut self,
        remote_addr: SocketAddr,
        now: Instant,
    ) -> bool {
        if let Some(coord) = &mut self.coordination {
            // Check if this address was one of our punch targets
            let was_target = coord
                .punch_targets
                .iter()
                .any(|target| target.remote_addr == remote_addr);
            if was_target && coord.state == CoordinationPhase::Validating {
                // Calculate RTT and update adaptive timeout
                let rtt = now.duration_since(coord.round_start);
                coord.timeout_state.update_success(rtt);
                self.network_monitor.record_success(rtt, now);

                coord.state = CoordinationPhase::Succeeded;
                self.stats.direct_connections += 1;
                trace!(
                    "Coordination succeeded via {} with RTT {:?}",
                    remote_addr, rtt
                );
                true
            } else {
                false
            }
        } else {
            false
        }
    }

    /// Handle coordination failure and determine if we should retry
    pub(super) fn handle_coordination_failure(&mut self, now: Instant) -> bool {
        if let Some(coord) = &mut self.coordination {
            coord.retry_count += 1;
            coord.timeout_state.update_timeout();
            self.network_monitor.record_timeout(now);
            // Check network conditions before retrying
            if coord.timeout_state.should_retry(coord.max_retries)
                && self.network_monitor.is_suitable_for_coordination()
            {
                // Retry with adaptive timeout
                coord.state = CoordinationPhase::Requesting;
                coord.punch_request_sent = false;
                coord.peer_punch_received = false;
                coord.round_start = now;
                coord.last_retry_at = Some(now);

                // Use adaptive timeout for retry delay
                let retry_delay = coord.timeout_state.get_retry_delay();

                // Factor in network quality for retry timing
                let quality_multiplier = 2.0 - self.network_monitor.get_quality_score();
                let adjusted_delay = Duration::from_millis(
                    (retry_delay.as_millis() as f64 * quality_multiplier) as u64,
                );

                coord.punch_start = now + adjusted_delay;

                trace!(
                    "Coordination failed, retrying round {} (attempt {}) with delay {:?} (quality: {:.2})",
                    coord.round,
                    coord.retry_count + 1,
                    adjusted_delay,
                    self.network_monitor.get_quality_score()
                );
                true
            } else {
                coord.state = CoordinationPhase::Failed;
                self.stats.coordination_failures += 1;

                if !self.network_monitor.is_suitable_for_coordination() {
                    trace!(
                        "Coordination failed due to poor network conditions (quality: {:.2})",
                        self.network_monitor.get_quality_score()
                    );
                } else {
                    trace!("Coordination failed after {} attempts", coord.retry_count);
                }
                false
            }
        } else {
            false
        }
    }

    /// Check if the current coordination round has timed out
    pub(super) fn check_coordination_timeout(&mut self, now: Instant) -> bool {
        if let Some(coord) = &mut self.coordination {
            let timeout = coord.timeout_state.get_timeout();
            let elapsed = now.duration_since(coord.round_start);
            if elapsed > timeout {
                trace!(
                    "Coordination round {} timed out after {:?} (adaptive timeout: {:?})",
                    coord.round, elapsed, timeout
                );
                self.handle_coordination_failure(now);
                true
            } else {
                false
            }
        } else {
            false
        }
    }

    /// Check for validation timeouts and handle retries
    pub(super) fn check_validation_timeouts(&mut self, now: Instant) -> Vec<SocketAddr> {
        let mut expired_validations = Vec::new();
        let mut retry_validations = Vec::new();

        for (addr, validation) in &mut self.active_validations {
            let timeout = validation.timeout_state.get_timeout();
            let elapsed = now.duration_since(validation.sent_at);

            if elapsed >= timeout {
                if validation
                    .timeout_state
                    .should_retry(validation.max_retries)
                {
                    // Schedule retry
                    retry_validations.push(*addr);
                } else {
                    // Mark as expired
                    expired_validations.push(*addr);
                }
            }
        }

        // Handle retries
        for addr in retry_validations {
            if let Some(validation) = self.active_validations.get_mut(&addr) {
                validation.retry_count += 1;
                validation.sent_at = now;
                validation.last_retry_at = Some(now);
                validation.timeout_state.update_timeout();

                trace!(
                    "Retrying validation for {} (attempt {})",
                    addr,
                    validation.retry_count + 1
                );
            }
        }

        // Remove expired validations
        for addr in &expired_validations {
            self.active_validations.remove(addr);
            self.network_monitor.record_timeout(now);
            trace!("Validation expired for {}", addr);
        }

        expired_validations
    }

    /// Schedule validation retries for active validations that need retry
    pub(super) fn schedule_validation_retries(&mut self, now: Instant) -> Vec<SocketAddr> {
        let mut retry_addresses = Vec::new();

        // Get all active validations that need retry
        for (addr, validation) in &mut self.active_validations {
            let elapsed = now.duration_since(validation.sent_at);
            let timeout = validation.timeout_state.get_timeout();

            if elapsed > timeout
                && validation
                    .timeout_state
                    .should_retry(validation.max_retries)
            {
                // Update retry state
                validation.retry_count += 1;
                validation.last_retry_at = Some(now);
                validation.sent_at = now; // Reset sent time for new attempt
                validation.timeout_state.update_timeout();

                retry_addresses.push(*addr);
                trace!(
                    "Scheduled retry {} for validation to {}",
                    validation.retry_count, addr
                );
            }
        }

        retry_addresses
    }

    /// Update network conditions and cleanup
    pub(super) fn update_network_conditions(&mut self, now: Instant) {
        self.network_monitor.cleanup(now);

        // Update timeout multiplier based on network conditions
        let multiplier = self.network_monitor.get_timeout_multiplier();

        // Apply network-aware timeout adjustments to active validations
        for validation in self.active_validations.values_mut() {
            if multiplier > 1.5 {
                // Poor network conditions - be more patient
                validation.timeout_state.backoff_multiplier =
                    (validation.timeout_state.backoff_multiplier * 1.2)
                        .min(validation.timeout_state.max_backoff_multiplier);
            } else if multiplier < 0.8 {
                // Good network conditions - be more aggressive
                validation.timeout_state.backoff_multiplier =
                    (validation.timeout_state.backoff_multiplier * 0.9).max(1.0);
            }
        }
    }

    /// Check if coordination should be retried now
    pub(super) fn should_retry_coordination(&self, now: Instant) -> bool {
        if let Some(coord) = &self.coordination {
            if coord.retry_count > 0 {
                if let Some(last_retry) = coord.last_retry_at {
                    let retry_delay = coord.timeout_state.get_retry_delay();
                    return now.duration_since(last_retry) >= retry_delay;
                }
            }
        }
        false
    }

    /// Perform resource management and cleanup
    pub(super) fn perform_resource_management(&mut self, now: Instant) -> u64 {
        // Update resource usage statistics
        self.resource_manager.update_stats(
            self.active_validations.len(),
            self.local_candidates.len(),
            self.remote_candidates.len(),
            self.candidate_pairs.len(),
        );

        // Calculate current memory pressure
        let memory_pressure = self.resource_manager.calculate_memory_pressure(
            self.active_validations.len(),
            self.local_candidates.len(),
            self.remote_candidates.len(),
            self.candidate_pairs.len(),
        );

        // Perform cleanup if needed
        let mut cleaned = 0;

        if self.resource_manager.should_cleanup(now) {
            cleaned += self.resource_manager.cleanup_expired_resources(
                &mut self.active_validations,
                &mut self.local_candidates,
                &mut self.remote_candidates,
                &mut self.candidate_pairs,
                &mut self.coordination,
                now,
            );

            // If memory pressure is high, perform aggressive cleanup
            if memory_pressure > self.resource_manager.config.aggressive_cleanup_threshold {
                cleaned += self.resource_manager.aggressive_cleanup(
                    &mut self.active_validations,
                    &mut self.local_candidates,
                    &mut self.remote_candidates,
                    &mut self.candidate_pairs,
                    now,
                );
            }
        }

        cleaned
    }

    /// Check if we should reject new resources due to limits
    pub(super) fn should_reject_new_resources(&mut self, _now: Instant) -> bool {
        // Update stats and check limits
        self.resource_manager.update_stats(
            self.active_validations.len(),
            self.local_candidates.len(),
            self.remote_candidates.len(),
            self.candidate_pairs.len(),
        );
        let memory_pressure = self.resource_manager.calculate_memory_pressure(
            self.active_validations.len(),
            self.local_candidates.len(),
            self.remote_candidates.len(),
            self.candidate_pairs.len(),
        );
        // Reject if memory pressure is too high
        if memory_pressure > self.resource_manager.config.memory_pressure_threshold {
            self.resource_manager.stats.allocation_failures += 1;
            return true;
        }

        // Reject if hard limits are exceeded
        if self.resource_manager.check_resource_limits(self) {
            self.resource_manager.stats.allocation_failures += 1;
            return true;
        }

        false
    }

    /// Get the next timeout instant for NAT traversal operations
    pub(super) fn get_next_timeout(&self, now: Instant) -> Option<Instant> {
        let mut next_timeout = None;
        // Check coordination timeout
        if let Some(coord) = &self.coordination {
            match coord.state {
                CoordinationPhase::Requesting | CoordinationPhase::Coordinating => {
                    let timeout_at = coord.round_start + self.coordination_timeout;
                    next_timeout =
                        Some(next_timeout.map_or(timeout_at, |t: Instant| t.min(timeout_at)));
                }
                CoordinationPhase::Preparing => {
                    // Punch start time is when we should start punching
                    next_timeout = Some(
                        next_timeout
                            .map_or(coord.punch_start, |t: Instant| t.min(coord.punch_start)),
                    );
                }
                CoordinationPhase::Punching | CoordinationPhase::Validating => {
                    // Check for coordination round timeout
                    let timeout_at = coord.round_start + coord.timeout_state.get_timeout();
                    next_timeout =
                        Some(next_timeout.map_or(timeout_at, |t: Instant| t.min(timeout_at)));
                }
                _ => {}
            }
        }

        // Check validation timeouts
        for validation in self.active_validations.values() {
            let timeout_at = validation.sent_at + validation.timeout_state.get_timeout();
            next_timeout = Some(next_timeout.map_or(timeout_at, |t: Instant| t.min(timeout_at)));
        }

        // Check resource cleanup interval
        if self.resource_manager.should_cleanup(now) {
            // Schedule cleanup soon
            let cleanup_at = now + Duration::from_secs(1);
            next_timeout = Some(next_timeout.map_or(cleanup_at, |t: Instant| t.min(cleanup_at)));
        }

        next_timeout
    }

    /// Handle timeout events and return actions to take
    pub(super) fn handle_timeout(
        &mut self,
        now: Instant,
    ) -> Result<Vec<TimeoutAction>, NatTraversalError> {
        let mut actions = Vec::new();
        // Handle coordination timeouts
        if let Some(coord) = &mut self.coordination {
            match coord.state {
                CoordinationPhase::Requesting | CoordinationPhase::Coordinating => {
                    let timeout_at = coord.round_start + self.coordination_timeout;
                    if now >= timeout_at {
                        coord.retry_count += 1;
                        if coord.retry_count >= coord.max_retries {
                            debug!("Coordination failed after {} retries", coord.retry_count);
                            coord.state = CoordinationPhase::Failed;
                            actions.push(TimeoutAction::Failed);
                        } else {
                            debug!(
                                "Coordination timeout, retrying ({}/{})",
                                coord.retry_count, coord.max_retries
                            );
                            coord.state = CoordinationPhase::Requesting;
                            coord.round_start = now;
                            actions.push(TimeoutAction::RetryCoordination);
                        }
                    }
                }
                CoordinationPhase::Preparing => {
                    // Check if it's time to start punching
                    if now >= coord.punch_start {
                        debug!("Starting coordinated hole punching");
                        coord.state = CoordinationPhase::Punching;
                        actions.push(TimeoutAction::StartValidation);
                    }
                }
                CoordinationPhase::Punching | CoordinationPhase::Validating => {
                    let timeout_at = coord.round_start + coord.timeout_state.get_timeout();
                    if now >= timeout_at {
                        coord.retry_count += 1;
                        if coord.retry_count >= coord.max_retries {
                            debug!("Validation failed after {} retries", coord.retry_count);
                            coord.state = CoordinationPhase::Failed;
                            actions.push(TimeoutAction::Failed);
                        } else {
                            debug!(
                                "Validation timeout, retrying ({}/{})",
                                coord.retry_count, coord.max_retries
                            );
                            coord.state = CoordinationPhase::Punching;
                            actions.push(TimeoutAction::StartValidation);
                        }
                    }
                }
                CoordinationPhase::Succeeded => {
                    actions.push(TimeoutAction::Complete);
                }
                CoordinationPhase::Failed => {
                    actions.push(TimeoutAction::Failed);
                }
                _ => {}
            }
        }

        // Handle validation timeouts
        let mut expired_validations = Vec::new();
        for (addr, validation) in &mut self.active_validations {
            let timeout_at = validation.sent_at + validation.timeout_state.get_timeout();
            if now >= timeout_at {
                validation.retry_count += 1;
                if validation.retry_count >= validation.max_retries {
                    debug!("Path validation failed for {}: max retries exceeded", addr);
                    expired_validations.push(*addr);
                } else {
                    debug!(
                        "Path validation timeout for {}, retrying ({}/{})",
                        addr, validation.retry_count, validation.max_retries
                    );
                    validation.sent_at = now;
                    validation.last_retry_at = Some(now);
                    actions.push(TimeoutAction::StartValidation);
                }
            }
        }

        // Remove expired validations
        for addr in expired_validations {
            self.active_validations.remove(&addr);
        }

        // Handle resource cleanup
        if self.resource_manager.should_cleanup(now) {
            self.resource_manager.perform_cleanup(now);
        }

        // Update network condition monitoring
        self.network_monitor.update_quality_score(now);

        // If no coordination is active and we have candidates, try to start discovery
        if self.coordination.is_none()
            && !self.local_candidates.is_empty()
            && !self.remote_candidates.is_empty()
        {
            actions.push(TimeoutAction::RetryDiscovery);
        }

        Ok(actions)
    }

    /// Handle address observation for bootstrap nodes
    ///
    /// This method is called when a peer connects to this bootstrap node,
    /// allowing the bootstrap to observe the peer's public address.
    pub(super) fn handle_address_observation(
        &mut self,
        peer_id: [u8; 32],
        observed_address: SocketAddr,
        connection_id: crate::shared::ConnectionId,
        peer_role: NatTraversalRole,
        now: Instant,
    ) -> Result<Option<crate::frame::AddAddress>, NatTraversalError> {
        if let Some(bootstrap_coordinator) = &mut self.bootstrap_coordinator {
            let connection_context = ConnectionContext {
                connection_id,
                original_destination: observed_address, // For now, use same as observed
                peer_role,
            };

            // Observe the peer's address
            bootstrap_coordinator.observe_peer_address(
                peer_id,
                observed_address,
                connection_context,
                now,
            )?;

            // Generate ADD_ADDRESS frame to inform peer of their observed address
            let sequence = self.next_sequence;
            self.next_sequence =
                VarInt::from_u32((self.next_sequence.into_inner() + 1).try_into().unwrap());

            let priority = VarInt::from_u32(100); // Server-reflexive priority
            let add_address_frame =
                bootstrap_coordinator.generate_add_address_frame(peer_id, sequence, priority);

            Ok(add_address_frame)
        } else {
            // Not a bootstrap node
            Ok(None)
        }
    }

    /// Handle PUNCH_ME_NOW frame for bootstrap coordination
    ///
    /// This processes coordination requests from peers and facilitates
    /// hole punching between them.
    pub(super) fn handle_punch_me_now_frame(
        &mut self,
        from_peer: [u8; 32],
        source_addr: SocketAddr,
        frame: &crate::frame::PunchMeNow,
        now: Instant,
    ) -> Result<Option<crate::frame::PunchMeNow>, NatTraversalError> {
        if let Some(bootstrap_coordinator) = &mut self.bootstrap_coordinator {
            bootstrap_coordinator.process_punch_me_now_frame(from_peer, source_addr, frame, now)
        } else {
            // Not a bootstrap node - this frame should not be processed here
            Ok(None)
        }
    }
    /// Perform bootstrap cleanup operations
    ///
    /// Get observed address for a peer
    pub(super) fn get_observed_address(&self, peer_id: [u8; 32]) -> Option<SocketAddr> {
        self.bootstrap_coordinator
            .as_ref()
            .and_then(|coord| coord.peer_index.get(&peer_id).map(|p| p.observed_addr))
    }

    /// Start candidate discovery process
    pub(super) fn start_candidate_discovery(&mut self) -> Result<(), NatTraversalError> {
        debug!("Starting candidate discovery for NAT traversal");
        // Initialize discovery state if needed
        if self.local_candidates.is_empty() {
            // Add local interface candidates
            // This would be populated by the candidate discovery manager
            debug!("Local candidates will be populated by discovery manager");
        }

        Ok(())
    }

    /// Queue an ADD_ADDRESS frame for transmission
    pub(super) fn queue_add_address_frame(
        &mut self,
        sequence: VarInt,
        address: SocketAddr,
        priority: u32,
    ) -> Result<(), NatTraversalError> {
        debug!(
            "Queuing ADD_ADDRESS frame: seq={}, addr={}, priority={}",
            sequence, address, priority
        );

        // Add to local candidates if not already present
        let candidate = AddressCandidate {
            address,
            priority,
            source: CandidateSource::Local,
            discovered_at: Instant::now(),
            state: CandidateState::New,
            attempt_count: 0,
            last_attempt: None,
        };

        // Check if candidate already exists
        if !self.local_candidates.values().any(|c| c.address == address) {
            self.local_candidates.insert(sequence, candidate);
        }

        Ok(())
    }
}

/// Errors that can occur during NAT traversal
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum NatTraversalError {
    /// Too many candidates received
    TooManyCandidates,
    /// Duplicate address for different sequence
    DuplicateAddress,
    /// Unknown candidate sequence
    UnknownCandidate,
    /// Candidate in wrong state for operation
    InvalidCandidateState,
    /// No active validation for address
    NoActiveValidation,
    /// Challenge value mismatch
    ChallengeMismatch,
    /// Coordination round not active
    NoActiveCoordination,
    /// Security validation failed
    SecurityValidationFailed,
    /// Rate limit exceeded
    RateLimitExceeded,
    /// Invalid address format
    InvalidAddress,
    /// Suspicious coordination request
    SuspiciousCoordination,
    /// Resource limit exceeded
    ResourceLimitExceeded,
}
impl std::fmt::Display for NatTraversalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooManyCandidates => write!(f, "too many candidates"),
            Self::DuplicateAddress => write!(f, "duplicate address"),
            Self::UnknownCandidate => write!(f, "unknown candidate"),
            Self::InvalidCandidateState => write!(f, "invalid candidate state"),
            Self::NoActiveValidation => write!(f, "no active validation"),
            Self::ChallengeMismatch => write!(f, "challenge mismatch"),
            Self::NoActiveCoordination => write!(f, "no active coordination"),
            Self::SecurityValidationFailed => write!(f, "security validation failed"),
            Self::RateLimitExceeded => write!(f, "rate limit exceeded"),
            Self::InvalidAddress => write!(f, "invalid address"),
            Self::SuspiciousCoordination => write!(f, "suspicious coordination request"),
            Self::ResourceLimitExceeded => write!(f, "resource limit exceeded"),
        }
    }
}

impl std::error::Error for NatTraversalError {}

/// Security statistics for monitoring and debugging
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub(crate) struct SecurityStats {
    /// Total security rejections
    pub total_security_rejections: u32,
    /// Rate limiting violations
    pub rate_limit_violations: u32,
    /// Invalid address rejections
    pub invalid_address_rejections: u32,
    /// Suspicious coordination attempts
    pub suspicious_coordination_attempts: u32,
    /// Number of active validations
    pub active_validations: usize,
    /// Number of cached address validations
    pub cached_address_validations: usize,
    /// Current candidate addition rate
    pub current_candidate_rate: usize,
    /// Current coordination request rate
    pub current_coordination_rate: usize,
}
/// Bootstrap coordinator state machine for NAT traversal coordination
///
/// This manages the bootstrap node's role in observing client addresses,
/// coordinating hole punching, and relaying coordination messages.
#[derive(Debug)]
pub(crate) struct BootstrapCoordinator {
    /// Address observation cache for quick lookups
    address_observations: HashMap<SocketAddr, AddressObservation>,
    /// Quick lookup by peer id for the last observed address
    peer_index: HashMap<PeerId, ObservedPeer>,
    /// Minimal coordination table keyed by round id
    coordination_table: HashMap<VarInt, CoordinationEntry>,
    /// Security validator for coordination requests
    security_validator: SecurityValidationState,
    /// Statistics for bootstrap operations
    stats: BootstrapStats,
}
// Removed legacy CoordinationSessionId type
/// Peer identifier for bootstrap coordination
type PeerId = [u8; 32];
/// Observed peer summary (minimal index)
#[derive(Debug, Clone)]
struct ObservedPeer {
    observed_addr: SocketAddr,
}

/// Minimal coordination record linking two peers for a round
#[derive(Debug, Clone)]
struct CoordinationEntry {
    peer_b: Option<PeerId>,
    address_hint: SocketAddr,
}
/// Record of observed peer information
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub(crate) struct PeerObservationRecord {
    /// The peer's unique identifier
    peer_id: PeerId,
    /// Last observed public address
    observed_address: SocketAddr,
    /// When this observation was made
    observed_at: Instant,
    /// Connection context for this observation
    connection_context: ConnectionContext,
    /// Whether this peer can participate in coordination
    can_coordinate: bool,
    /// Number of successful coordinations
    coordination_count: u32,
    /// Average coordination success rate
    success_rate: f64,
}

/// Connection context for address observations
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub(crate) struct ConnectionContext {
    /// Connection ID for this observation
    connection_id: ConnectionId,
    /// Original destination address (what peer thought it was connecting to)
    original_destination: SocketAddr,
    /// NAT traversal role of the connecting peer
    peer_role: NatTraversalRole,
    // Transport parameters were unused; removed
}

// Transport parameters for NAT traversal removed (legacy)

/// Address observation with validation
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct AddressObservation {
    /// The observed address
    address: SocketAddr,
    /// When this address was first observed
    first_observed: Instant,
    /// How many times this address has been observed
    observation_count: u32,
    /// Validation state for this address
    validation_state: AddressValidationResult,
    /// Associated peer IDs for this address
    associated_peers: Vec<PeerId>,
}

// Removed coordination session scaffolding
/// Pending coordination request awaiting peer participation (stub implementation)
/// Configuration for bootstrap coordinator behavior (stub implementation)
#[derive(Debug, Clone, Default)]
pub(crate) struct BootstrapConfig {
    _unused: (),
}
/// Statistics for bootstrap operations
#[derive(Debug, Clone, Default)]
pub(crate) struct BootstrapStats {
    /// Total address observations made
    total_observations: u64,
    /// Total coordination sessions facilitated
    total_coordinations: u64,
    /// Successful coordinations
    successful_coordinations: u64,
    /// Security rejections
    security_rejections: u64,
}
// Removed session state machine enums and recovery actions
impl BootstrapCoordinator {
    /// Create a new bootstrap coordinator
    pub(crate) fn new(_config: BootstrapConfig) -> Self {
        Self {
            address_observations: HashMap::new(),
            peer_index: HashMap::new(),
            coordination_table: HashMap::new(),
            security_validator: SecurityValidationState::new(),
            stats: BootstrapStats::default(),
        }
    }
    /// Observe a peer's address from an incoming connection
    ///
    /// This is called when a peer connects to this bootstrap node,
    /// allowing us to observe their public address.
    pub(crate) fn observe_peer_address(
        &mut self,
        peer_id: PeerId,
        observed_address: SocketAddr,
        _connection_context: ConnectionContext,
        now: Instant,
    ) -> Result<(), NatTraversalError> {
        // Security validation
        match self
            .security_validator
            .validate_address(observed_address, now)
        {
            AddressValidationResult::Valid => {}
            AddressValidationResult::Invalid => {
                self.stats.security_rejections += 1;
                return Err(NatTraversalError::InvalidAddress);
            }
            AddressValidationResult::Suspicious => {
                self.stats.security_rejections += 1;
                return Err(NatTraversalError::SecurityValidationFailed);
            }
        }

        // Rate limiting check
        if self.security_validator.is_candidate_rate_limited(now) {
            self.stats.security_rejections += 1;
            return Err(NatTraversalError::RateLimitExceeded);
        }

        // Update address observation
        let observation = self
            .address_observations
            .entry(observed_address)
            .or_insert_with(|| AddressObservation {
                address: observed_address,
                first_observed: now,
                observation_count: 0,
                validation_state: AddressValidationResult::Valid,
                associated_peers: Vec::new(),
            });

        observation.observation_count += 1;
        if !observation.associated_peers.contains(&peer_id) {
            observation.associated_peers.push(peer_id);
        }

        // Update minimal peer index for quick lookups
        self.peer_index.insert(
            peer_id,
            ObservedPeer {
                observed_addr: observed_address,
            },
        );

        // Note: Full peer registry and session scaffolding removed; we keep only minimal caches
        self.stats.total_observations += 1;
        // active_peers removed from stats

        debug!(
            "Observed peer {:?} at address {} (total observations: {})",
            peer_id, observed_address, self.stats.total_observations
        );

        Ok(())
    }

    /// Generate ADD_ADDRESS frame for a peer based on observation
    ///
    /// This creates an ADD_ADDRESS frame to inform a peer of their
    /// observed public address.
    pub(crate) fn generate_add_address_frame(
        &self,
        peer_id: PeerId,
        sequence: VarInt,
        priority: VarInt,
    ) -> Option<crate::frame::AddAddress> {
        let addr = self.peer_index.get(&peer_id)?.observed_addr;
        Some(crate::frame::AddAddress {
            sequence,
            address: addr,
            priority,
        })
    }

    /// Process a PUNCH_ME_NOW frame from a peer
    ///
    /// This handles coordination requests from peers wanting to establish
    /// direct connections through NAT traversal.
    pub(crate) fn process_punch_me_now_frame(
        &mut self,
        from_peer: PeerId,
        source_addr: SocketAddr,
        frame: &crate::frame::PunchMeNow,
        now: Instant,
    ) -> Result<Option<crate::frame::PunchMeNow>, NatTraversalError> {
        // Enhanced security validation with adaptive rate limiting
        if self
            .security_validator
            .is_adaptive_rate_limited(from_peer, now)
        {
            self.stats.security_rejections += 1;
            debug!(
                "PUNCH_ME_NOW frame rejected: adaptive rate limit exceeded for peer {:?}",
                hex::encode(&from_peer[..8])
            );
            return Err(NatTraversalError::RateLimitExceeded);
        }
        // Enhanced address validation with amplification protection
        self.security_validator
            .enhanced_address_validation(frame.address, source_addr, now)
            .inspect_err(|&e| {
                self.stats.security_rejections += 1;
                debug!(
                    "PUNCH_ME_NOW frame address validation failed from peer {:?}: {:?}",
                    hex::encode(&from_peer[..8]),
                    e
                );
            })?;

        // Comprehensive security validation
        self.security_validator
            .validate_punch_me_now_frame(frame, source_addr, from_peer, now)
            .inspect_err(|&e| {
                self.stats.security_rejections += 1;
                debug!(
                    "PUNCH_ME_NOW frame validation failed from peer {:?}: {:?}",
                    hex::encode(&from_peer[..8]),
                    e
                );
            })?;

        // Track coordination entry minimally
        let _entry = self
            .coordination_table
            .entry(frame.round)
            .or_insert(CoordinationEntry {
                peer_b: frame.target_peer_id,
                address_hint: frame.address,
            });
        // Update target if provided later
        if let Some(peer_b) = frame.target_peer_id {
            if _entry.peer_b.is_none() {
                _entry.peer_b = Some(peer_b);
            }
            _entry.address_hint = frame.address;
        }

        // If we have a target, echo back with swapped target to coordinate
        if let Some(_target_peer_id) = frame.target_peer_id {
            let coordination_frame = crate::frame::PunchMeNow {
                round: frame.round,
                paired_with_sequence_number: frame.paired_with_sequence_number,
                address: frame.address,
                target_peer_id: Some(from_peer),
            };
            self.stats.total_coordinations += 1;
            Ok(Some(coordination_frame))
        } else {
            // Response path: increment success metric
            self.stats.successful_coordinations += 1;
            Ok(None)
        }
    }

    // Removed legacy session tracking helpers
    // Generate secure coordination round using cryptographically secure random values (legacy removed)

    // Perform comprehensive security validation for coordination requests (legacy removed)

    #[allow(dead_code)]
    pub(crate) fn cleanup_expired_sessions(&mut self, _now: Instant) {}

    // Get bootstrap statistics (legacy removed)

    // Removed peer coordination success-rate tracking and full registry

    #[allow(dead_code)]
    pub(crate) fn poll_session_state_machine(&mut self, _now: Instant) -> Vec<()> {
        // Legacy session state machine removed
        Vec::new()
    }

    // Check if a session should advance its state (legacy removed)
    // Advance session state based on event (legacy removed)

    #[allow(dead_code)]
    fn cleanup_completed_sessions(&mut self, _now: Instant) {}

    // Legacy retry mechanism removed

    // Handle coordination errors with appropriate recovery strategies (legacy removed)

    #[allow(dead_code)]
    fn estimate_peer_rtt(&self, peer_id: &PeerId) -> Option<Duration> {
        // Simple estimation based on peer record
        // In a real implementation, this would use historical RTT data
        let _ = peer_id;
        None
    }
    // Coordinate hole punching between two peers (legacy removed)
    // This method implemented the core coordination logic for establishing
    // direct P2P connections through NAT traversal.

    // Relay coordination frame between peers (legacy removed)
    // This method handled the relay of coordination messages between peers
    // to facilitate synchronized hole punching.

    // Implement round-based synchronization protocol (legacy removed)
    // This managed the timing and synchronization of hole punching rounds
    // to maximize the chances of successful NAT traversal.

    // Get coordination session by ID (legacy removed)

    // Get mutable coordination session by ID (legacy removed)

    // Mark coordination session as successful (legacy removed)

    // Mark coordination session as failed (legacy removed)

    #[allow(dead_code)]
    pub(crate) fn get_peer_record(&self, _peer_id: PeerId) -> Option<&PeerObservationRecord> {
        // Legacy API kept for callers; we no longer maintain full records
        None
    }
}

// Multi-destination packet transmission manager for NAT traversal
//
// This component handles simultaneous packet transmission to multiple candidate
// addresses during hole punching attempts, maximizing the chances of successful
// NAT traversal by sending packets to all viable destinations concurrently.
// TODO: Implement multi-path transmission infrastructure when needed
// This would include MultiDestinationTransmitter for sending packets to multiple
// destinations simultaneously for improved NAT traversal success rates.
// TODO: Fix nat_traversal_tests module imports
// #[cfg(test)]
// #[path = "nat_traversal_tests.rs"]
// mod tests;

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_state(role: NatTraversalRole) -> NatTraversalState {
        NatTraversalState::new(
            role,
            10,                      // max_candidates
            Duration::from_secs(30), // coordination_timeout
        )
    }

    #[test]
    fn test_add_quic_discovered_address() {
        // Test that QUIC-discovered addresses are properly added as local candidates
        let mut state = create_test_state(NatTraversalRole::Client);
        let now = Instant::now();

        // Add a QUIC-discovered address (using add_local_candidate with Observed source)
        let discovered_addr = SocketAddr::from(([1, 2, 3, 4], 5678));
        let seq = state.add_local_candidate(
            discovered_addr,
            CandidateSource::Observed { by_node: None },
            now,
        );

        // Verify it was added correctly
        assert_eq!(state.local_candidates.len(), 1);
        let candidate = state.local_candidates.get(&seq).unwrap();
        assert_eq!(candidate.address, discovered_addr);
        assert!(matches!(candidate.source, CandidateSource::Observed { .. }));
        assert_eq!(candidate.state, CandidateState::New);

        // Verify priority is set appropriately for server-reflexive
        assert!(candidate.priority > 0);
    }

    #[test]
    fn test_add_multiple_quic_discovered_addresses() {
        // Test adding multiple QUIC-discovered addresses
        let mut state = create_test_state(NatTraversalRole::Client);
        let now = Instant::now();

        let addrs = vec![
            SocketAddr::from(([1, 2, 3, 4], 5678)),
            SocketAddr::from(([5, 6, 7, 8], 9012)),
            SocketAddr::from(([2001, 0xdb8, 0, 0, 0, 0, 0, 1], 443)),
        ];

        let mut sequences = Vec::new();
        for addr in &addrs {
            let seq =
                state.add_local_candidate(*addr, CandidateSource::Observed { by_node: None }, now);
            sequences.push(seq);
        }

        // Verify all were added
        assert_eq!(state.local_candidates.len(), 3);

        // Verify each address
        for (seq, addr) in sequences.iter().zip(&addrs) {
            let candidate = state.local_candidates.get(seq).unwrap();
            assert_eq!(candidate.address, *addr);
            assert!(matches!(candidate.source, CandidateSource::Observed { .. }));
        }
    }

    #[test]
    fn test_quic_discovered_addresses_in_local_candidates() {
        // Test that QUIC-discovered addresses are included in local candidates
        let mut state = create_test_state(NatTraversalRole::Client);
        let now = Instant::now();

        // Add a discovered address
        let addr = SocketAddr::from(([192, 168, 1, 100], 5000));
        let seq = state.add_local_candidate(addr, CandidateSource::Observed { by_node: None }, now);

        // Verify it's in local candidates for advertisement
        assert!(state.local_candidates.contains_key(&seq));
        let candidate = state.local_candidates.get(&seq).unwrap();
        assert_eq!(candidate.address, addr);

        // Verify it has appropriate priority for server-reflexive
        assert!(matches!(candidate.source, CandidateSource::Observed { .. }));
    }

    #[test]
    fn test_quic_discovered_addresses_included_in_hole_punching() {
        // Test that QUIC-discovered addresses are used in hole punching
        let mut state = create_test_state(NatTraversalRole::Client);
        let now = Instant::now();

        // Add a local discovered address
        let local_addr = SocketAddr::from(([192, 168, 1, 100], 5000));
        state.add_local_candidate(local_addr, CandidateSource::Observed { by_node: None }, now);

        // Add a remote candidate (using valid public IP, not documentation range)
        let remote_addr = SocketAddr::from(([1, 2, 3, 4], 6000));
        let priority = VarInt::from_u32(100);
        state
            .add_remote_candidate(VarInt::from_u32(1), remote_addr, priority, now)
            .expect("add remote candidate should succeed");

        // Generate candidate pairs
        state.generate_candidate_pairs(now);

        // Should have one pair
        assert_eq!(state.candidate_pairs.len(), 1);
        let pair = &state.candidate_pairs[0];
        assert_eq!(pair.local_addr, local_addr);
        assert_eq!(pair.remote_addr, remote_addr);
    }

    #[test]
    fn test_prioritize_quic_discovered_over_predicted() {
        // Test that QUIC-discovered addresses have higher priority than predicted
        let mut state = create_test_state(NatTraversalRole::Client);
        let now = Instant::now();

        // Add a predicted address
        let predicted_addr = SocketAddr::from(([1, 2, 3, 4], 5000));
        let predicted_seq =
            state.add_local_candidate(predicted_addr, CandidateSource::Predicted, now);

        // Add a QUIC-discovered address
        let discovered_addr = SocketAddr::from(([1, 2, 3, 4], 5001));
        let discovered_seq = state.add_local_candidate(
            discovered_addr,
            CandidateSource::Observed { by_node: None },
            now,
        );

        // Compare priorities
        let predicted_priority = state.local_candidates.get(&predicted_seq).unwrap().priority;
        let discovered_priority = state
            .local_candidates
            .get(&discovered_seq)
            .unwrap()
            .priority;

        // QUIC-discovered (server-reflexive) should have higher priority than predicted
        // Both are server-reflexive type, but observed addresses should get higher local preference
        assert!(discovered_priority >= predicted_priority);
    }

    #[test]
    fn test_integration_with_nat_traversal_flow() {
        // Test full integration with NAT traversal flow
        let mut state = create_test_state(NatTraversalRole::Client);
        let now = Instant::now();

        // Add both local interface and QUIC-discovered addresses
        let local_addr = SocketAddr::from(([192, 168, 1, 2], 5000));
        state.add_local_candidate(local_addr, CandidateSource::Local, now);

        let discovered_addr = SocketAddr::from(([44, 55, 66, 77], 5000));
        state.add_local_candidate(
            discovered_addr,
            CandidateSource::Observed { by_node: None },
            now,
        );

        // Add remote candidates (using valid public IPs)
        let remote1 = SocketAddr::from(([93, 184, 215, 123], 6000));
        let remote2 = SocketAddr::from(([172, 217, 16, 34], 7000));
        let priority = VarInt::from_u32(100);
        state
            .add_remote_candidate(VarInt::from_u32(1), remote1, priority, now)
            .expect("add remote candidate should succeed");
        state
            .add_remote_candidate(VarInt::from_u32(2), remote2, priority, now)
            .expect("add remote candidate should succeed");

        // Generate candidate pairs
        state.generate_candidate_pairs(now);

        // Should have 4 pairs (2 local × 2 remote)
        assert_eq!(state.candidate_pairs.len(), 4);

        // Verify QUIC-discovered addresses are included
        let discovered_pairs: Vec<_> = state
            .candidate_pairs
            .iter()
            .filter(|p| p.local_addr == discovered_addr)
            .collect();
        assert_eq!(discovered_pairs.len(), 2);
    }
}
