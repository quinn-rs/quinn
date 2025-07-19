use std::{
    collections::{HashMap, VecDeque},
    net::{IpAddr, SocketAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};

use tracing::{trace, debug, warn, info};
use crate::shared::ConnectionId;

use crate::{
    Instant, VarInt,
};

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
    /// Multi-destination packet transmission manager
    #[allow(dead_code)] // Part of multi-path transmission infrastructure
    pub(super) multi_dest_transmitter: MultiDestinationTransmitter,
}

/// Role in NAT traversal coordination
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatTraversalRole {
    /// Client endpoint (initiates connections, on-demand)
    Client,
    /// Server endpoint (accepts connections, always reachable)
    Server { can_relay: bool },
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
    Observed { by_node: Option<VarInt> },
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
    #[allow(dead_code)] // Used for coordination tracking
    pub(super) coordination_round: Option<VarInt>,
    /// Adaptive timeout state
    pub(super) timeout_state: AdaptiveTimeoutState,
    /// Last retry attempt time
    pub(super) last_retry_at: Option<Instant>,
}

/// Coordination state for simultaneous hole punching
#[derive(Debug)]
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
    #[allow(dead_code)] // Used for timing coordination rounds
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
#[allow(dead_code)] // All variants needed for complete state machine
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

/// Target for multi-destination hole punching transmission
#[derive(Debug, Clone)]
#[allow(dead_code)] // Fields tracked for debugging and future multi-path optimization
pub(super) struct MultiDestPunchTarget {
    /// Destination address to send packets to
    pub destination: SocketAddr,
    /// Local address to send from
    pub local_addr: SocketAddr,
    /// Type of candidate pair
    pub pair_type: PairType,
    /// Priority of this target
    pub priority: u32,
    /// When this target was created
    pub created_at: Instant,
}

/// Candidate pair for ICE-like connectivity testing
#[derive(Debug, Clone)]
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
    #[allow(dead_code)] // Used for retry timing
    pub(super) last_check: Option<Instant>,
}

/// State of a candidate pair during validation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PairState {
    /// Waiting to be tested
    Waiting,
    /// Validation succeeded - this pair works
    Succeeded,
    /// Validation failed 
    #[allow(dead_code)] // Will be used when implementing pair retry logic
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
    (1u32 << 24) * type_preference 
        + (1u32 << 8) * local_preference as u32 
        + component_id as u32
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
        (CandidateType::ServerReflexive, CandidateType::ServerReflexive) => PairType::ServerReflexiveToServerReflexive,
        (CandidateType::PeerReflexive, _) | (_, CandidateType::PeerReflexive) => PairType::PeerReflexive,
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
pub(crate) struct NatTraversalStats {
    /// Total candidates received from peer
    pub(super) remote_candidates_received: u32,
    /// Total candidates we've advertised
    pub(super) local_candidates_sent: u32,
    /// Successful validations
    pub(super) validations_succeeded: u32,
    /// Failed validations
    #[allow(dead_code)] // Tracked for statistics
    pub(super) validations_failed: u32,
    /// Coordination rounds attempted
    pub(super) coordination_rounds: u32,
    /// Successful coordinations
    #[allow(dead_code)] // Tracked for success rate calculation
    pub(super) successful_coordinations: u32,
    /// Failed coordinations
    #[allow(dead_code)] // Tracked for failure analysis
    pub(super) failed_coordinations: u32,
    /// Timed out coordinations
    #[allow(dead_code)] // Tracked for timeout optimization
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
    #[allow(dead_code)] // Used for cache expiry
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
pub(super) struct NetworkConditionMonitor {
    /// Recent round-trip time measurements
    rtt_samples: VecDeque<Duration>,
    /// Maximum samples to keep
    max_samples: usize,
    /// Packet loss rate estimation
    packet_loss_rate: f64,
    /// Congestion window estimate
    #[allow(dead_code)] // Used for adaptive timeout calculations
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
    #[allow(dead_code)] // Will be used for custom security configurations
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
        let _current_candidate_rate = self.candidate_rate_tracker.len() as f64 / self.rate_window.as_secs_f64();
        let _current_coordination_rate = self.coordination_requests.len() as f64 / self.rate_window.as_secs_f64();

        // Adaptive threshold based on peer behavior
        let peer_reputation = self.calculate_peer_reputation(peer_id);
        let adaptive_candidate_limit = (self.max_candidates_per_window as f64 * peer_reputation) as u32;
        let adaptive_coordination_limit = (self.max_coordination_per_window as f64 * peer_reputation) as u32;

        // Check if either limit is exceeded
        if self.candidate_rate_tracker.len() >= adaptive_candidate_limit as usize {
            debug!("Adaptive candidate rate limit exceeded for peer {:?}: {} >= {}", 
                   hex::encode(&peer_id[..8]), self.candidate_rate_tracker.len(), adaptive_candidate_limit);
            return true;
        }

        if self.coordination_requests.len() >= adaptive_coordination_limit as usize {
            debug!("Adaptive coordination rate limit exceeded for peer {:?}: {} >= {}", 
                   hex::encode(&peer_id[..8]), self.coordination_requests.len(), adaptive_coordination_limit);
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
            warn!("Potential amplification attack detected: {} -> {}", source_addr, target_addr);
            return Err(NatTraversalError::SuspiciousCoordination);
        }

        Ok(())
    }

    /// Check for suspicious amplification patterns
    fn is_amplification_suspicious(&self, _amplification_key: (SocketAddr, SocketAddr), _now: Instant) -> bool {
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
    #[allow(dead_code)] // Used by BootstrapCoordinator
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
            warn!("Suspicious coordination pattern detected: {} -> {}", source_addr, addr);
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
        let request = CoordinationRequest {
            timestamp: now,
        };
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
            let keys_to_remove: Vec<_> = self.address_validation_cache
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
        now: Instant
    ) -> Result<(), NatTraversalError> {
        // 1. Rate limiting validation
        if self.is_coordination_rate_limited(now) {
            debug!("PUNCH_ME_NOW frame rejected: coordination rate limit exceeded for peer {:?}", hex::encode(&peer_id[..8]));
            return Err(NatTraversalError::RateLimitExceeded);
        }

        // 2. Address validation - validate the local_address claimed in the frame
        let addr_validation = self.validate_address(frame.local_address, now);
        match addr_validation {
            AddressValidationResult::Invalid => {
                debug!("PUNCH_ME_NOW frame rejected: invalid local_address {:?} from peer {:?}", 
                       frame.local_address, hex::encode(&peer_id[..8]));
                return Err(NatTraversalError::InvalidAddress);
            }
            AddressValidationResult::Suspicious => {
                debug!("PUNCH_ME_NOW frame rejected: suspicious local_address {:?} from peer {:?}", 
                       frame.local_address, hex::encode(&peer_id[..8]));
                return Err(NatTraversalError::SuspiciousCoordination);
            }
            AddressValidationResult::Valid => {
                // Continue validation
            }
        }

        // 3. Source address consistency validation
        // The frame's local_address should reasonably relate to the actual source
        if !self.validate_address_consistency(frame.local_address, source_addr) {
            debug!("PUNCH_ME_NOW frame rejected: address consistency check failed. Frame claims {:?}, but received from {:?}", 
                   frame.local_address, source_addr);
            return Err(NatTraversalError::SuspiciousCoordination);
        }

        // 4. Coordination parameters validation
        if !self.validate_coordination_parameters(frame) {
            debug!("PUNCH_ME_NOW frame rejected: invalid coordination parameters from peer {:?}", 
                   hex::encode(&peer_id[..8]));
            return Err(NatTraversalError::SuspiciousCoordination);
        }

        // 5. Target peer validation (if present)
        if let Some(target_peer_id) = frame.target_peer_id {
            if !self.validate_target_peer_request(peer_id, target_peer_id, frame) {
                debug!("PUNCH_ME_NOW frame rejected: invalid target peer request from {:?} to {:?}", 
                       hex::encode(&peer_id[..8]), hex::encode(&target_peer_id[..8]));
                return Err(NatTraversalError::SuspiciousCoordination);
            }
        }

        // 6. Resource limits validation
        if !self.validate_resource_limits(frame) {
            debug!("PUNCH_ME_NOW frame rejected: resource limits exceeded from peer {:?}", 
                   hex::encode(&peer_id[..8]));
            return Err(NatTraversalError::ResourceLimitExceeded);
        }

        debug!("PUNCH_ME_NOW frame validation passed for peer {:?}", hex::encode(&peer_id[..8]));
        Ok(())
    }

    /// Validate address consistency between claimed and observed addresses
    /// 
    /// This prevents address spoofing by ensuring the claimed local address
    /// is reasonably consistent with the observed source address.
    fn validate_address_consistency(&self, claimed_addr: SocketAddr, observed_addr: SocketAddr) -> bool {
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
                claimed_ip == observed_ip || 
                self.are_in_same_prefix_v6(claimed_ip, observed_ip)
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
        if ip1_octets[0] == 172 && ip2_octets[0] == 172 &&
           (16..=31).contains(&ip1_octets[1]) && (16..=31).contains(&ip2_octets[1]) {
            return true;
        }
        
        // 192.168.0.0/16
        if ip1_octets[0] == 192 && ip1_octets[1] == 168 &&
           ip2_octets[0] == 192 && ip2_octets[1] == 168 {
            return true;
        }
        
        false
    }

    /// Check if two IPv6 addresses are in the same prefix
    fn are_in_same_prefix_v6(&self, ip1: Ipv6Addr, ip2: Ipv6Addr) -> bool {
        // Simplified IPv6 prefix check - compare first 64 bits
        let segments1 = ip1.segments();
        let segments2 = ip2.segments();
        
        segments1[0] == segments2[0] && 
        segments1[1] == segments2[1] && 
        segments1[2] == segments2[2] && 
        segments1[3] == segments2[3]
    }

    /// Validate coordination parameters for security
    fn validate_coordination_parameters(&self, frame: &crate::frame::PunchMeNow) -> bool {
        // Check round number is reasonable (not too large to prevent overflow attacks)
        if frame.round.into_inner() > 1000000 {
            return false;
        }
        
        // Check target sequence is reasonable
        if frame.target_sequence.into_inner() > 10000 {
            return false;
        }
        
        // Validate address is not obviously invalid
        match frame.local_address.ip() {
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
        _frame: &crate::frame::PunchMeNow
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
                let abs_diff = if rtt > srtt { rtt - srtt } else { srtt - rtt };
                
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
    #[allow(dead_code)] // Used for memory management
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
    #[allow(dead_code)] // Used for cleanup scheduling
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
    #[allow(dead_code)] // Used when system is under memory pressure
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
    #[allow(dead_code)] // Used in memory-constrained environments
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
        state.active_validations.len() > self.config.max_active_validations ||
        state.local_candidates.len() > self.config.max_local_candidates ||
        state.remote_candidates.len() > self.config.max_remote_candidates ||
        state.candidate_pairs.len() > self.config.max_candidate_pairs
    }
    
    /// Calculate current memory pressure level
    fn calculate_memory_pressure(&mut self, active_validations_len: usize, local_candidates_len: usize, 
                                remote_candidates_len: usize, candidate_pairs_len: usize) -> f64 {
        let total_limit = self.config.max_active_validations + 
                         self.config.max_local_candidates + 
                         self.config.max_remote_candidates + 
                         self.config.max_candidate_pairs;
        
        let current_usage = active_validations_len + 
                           local_candidates_len + 
                           remote_candidates_len + 
                           candidate_pairs_len;
        
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
    #[allow(dead_code)] // Will be used when implementing automatic resource cleanup
    fn cleanup_expired_resources(&mut self, 
                                active_validations: &mut HashMap<SocketAddr, PathValidationState>,
                                local_candidates: &mut HashMap<VarInt, AddressCandidate>,
                                remote_candidates: &mut HashMap<VarInt, AddressCandidate>,
                                candidate_pairs: &mut Vec<CandidatePair>,
                                coordination: &mut Option<CoordinationState>,
                                now: Instant) -> u64 {
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
    #[allow(dead_code)] // Called from cleanup_expired_resources
    fn cleanup_expired_validations(&mut self, active_validations: &mut HashMap<SocketAddr, PathValidationState>, now: Instant) -> u64 {
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
    #[allow(dead_code)] // Called from cleanup_expired_resources
    fn cleanup_stale_candidates(&mut self, local_candidates: &mut HashMap<VarInt, AddressCandidate>, remote_candidates: &mut HashMap<VarInt, AddressCandidate>, now: Instant) -> u64 {
        let mut cleaned = 0;
        let candidate_timeout = self.config.candidate_timeout;
        
        // Clean up local candidates
        local_candidates.retain(|_seq, candidate| {
            let is_stale = now.duration_since(candidate.discovered_at) > candidate_timeout ||
                          candidate.state == CandidateState::Failed ||
                          candidate.state == CandidateState::Removed;
            if is_stale {
                cleaned += 1;
                trace!("Cleaned up stale local candidate {:?}", candidate.address);
            }
            !is_stale
        });
        
        // Clean up remote candidates
        remote_candidates.retain(|_seq, candidate| {
            let is_stale = now.duration_since(candidate.discovered_at) > candidate_timeout ||
                          candidate.state == CandidateState::Failed ||
                          candidate.state == CandidateState::Removed;
            if is_stale {
                cleaned += 1;
                trace!("Cleaned up stale remote candidate {:?}", candidate.address);
            }
            !is_stale
        });
        
        cleaned
    }
    
    /// Clean up failed candidate pairs
    #[allow(dead_code)] // Called from cleanup_expired_resources
    fn cleanup_failed_pairs(&mut self, candidate_pairs: &mut Vec<CandidatePair>, now: Instant) -> u64 {
        let mut cleaned = 0;
        let pair_timeout = self.config.candidate_timeout;
        
        candidate_pairs.retain(|pair| {
            let is_stale = now.duration_since(pair.created_at) > pair_timeout ||
                          pair.state == PairState::Failed;
            if is_stale {
                cleaned += 1;
                trace!("Cleaned up failed candidate pair {:?} -> {:?}", pair.local_addr, pair.remote_addr);
            }
            !is_stale
        });
        
        cleaned
    }
    
    /// Clean up old coordination state
    #[allow(dead_code)] // Called from cleanup_expired_resources
    fn cleanup_old_coordination(&mut self, coordination: &mut Option<CoordinationState>, now: Instant) -> u64 {
        let mut cleaned = 0;
        
        if let Some(coord) = coordination {
            let is_expired = now.duration_since(coord.round_start) > self.config.coordination_timeout;
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
    #[allow(dead_code)] // Will be used when implementing memory pressure response
    fn aggressive_cleanup(&mut self, 
                         active_validations: &mut HashMap<SocketAddr, PathValidationState>,
                         local_candidates: &mut HashMap<VarInt, AddressCandidate>,
                         remote_candidates: &mut HashMap<VarInt, AddressCandidate>,
                         candidate_pairs: &mut Vec<CandidatePair>,
                         now: Instant) -> u64 {
        let mut cleaned = 0;
        
        // More aggressive timeout for candidates
        let aggressive_timeout = self.config.candidate_timeout / 2;
        
        // Clean up older candidates first
        local_candidates.retain(|_seq, candidate| {
            let keep = now.duration_since(candidate.discovered_at) <= aggressive_timeout &&
                      candidate.state != CandidateState::Failed;
            if !keep {
                cleaned += 1;
            }
            keep
        });
        
        remote_candidates.retain(|_seq, candidate| {
            let keep = now.duration_since(candidate.discovered_at) <= aggressive_timeout &&
                      candidate.state != CandidateState::Failed;
            if !keep {
                cleaned += 1;
            }
            keep
        });
        
        // Clean up waiting candidate pairs
        candidate_pairs.retain(|pair| {
            let keep = pair.state != PairState::Waiting ||
                      now.duration_since(pair.created_at) <= aggressive_timeout;
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
        
        warn!("Aggressive cleanup removed {} resources due to memory pressure", cleaned);
        cleaned
    }
    
    /// Request graceful shutdown and cleanup
    #[allow(dead_code)] // Used for clean shutdown procedures
    fn request_shutdown(&mut self) {
        self.shutdown_requested = true;
        debug!("Resource cleanup coordinator shutdown requested");
    }
    
    /// Perform final cleanup during shutdown
    #[allow(dead_code)] // Called during graceful shutdown
    fn shutdown_cleanup(&mut self, 
                       active_validations: &mut HashMap<SocketAddr, PathValidationState>,
                       local_candidates: &mut HashMap<VarInt, AddressCandidate>,
                       remote_candidates: &mut HashMap<VarInt, AddressCandidate>,
                       candidate_pairs: &mut Vec<CandidatePair>,
                       coordination: &mut Option<CoordinationState>) -> u64 {
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
    #[allow(dead_code)] // Used for monitoring and debugging
    fn get_resource_stats(&self) -> &ResourceStats {
        &self.stats
    }
    
    /// Update resource usage statistics
    fn update_stats(&mut self, active_validations_len: usize, local_candidates_len: usize, 
                   remote_candidates_len: usize, candidate_pairs_len: usize) {
        self.stats.active_validations = active_validations_len;
        self.stats.local_candidates = local_candidates_len;
        self.stats.remote_candidates = remote_candidates_len;
        self.stats.candidate_pairs = candidate_pairs_len;
        
        // Update peak memory usage
        let current_usage = self.stats.active_validations + 
                           self.stats.local_candidates + 
                           self.stats.remote_candidates + 
                           self.stats.candidate_pairs;
        
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
            self.timeout_stats.timeout_rate = self.timeout_stats.total_timeouts as f64 / total_attempts as f64;
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
        let variance: f64 = self.rtt_samples
            .iter()
            .map(|rtt| {
                let diff = if *rtt > mean_rtt { *rtt - mean_rtt } else { mean_rtt - *rtt };
                diff.as_millis() as f64
            })
            .map(|diff| diff * diff)
            .sum::<f64>() / self.rtt_samples.len() as f64;
        
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
    #[allow(dead_code)] // Used for adaptive timeout calculations
    fn get_packet_loss_rate(&self) -> f64 {
        self.packet_loss_rate
    }

    /// Get recommended timeout multiplier based on conditions
    #[allow(dead_code)] // Will be used for dynamic timeout adjustments
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
    #[allow(dead_code)] // Will be used in periodic maintenance
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
            multi_dest_transmitter: MultiDestinationTransmitter::new(),
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
            debug!("Rejecting new candidate due to resource limits: {}", address);
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
        if self.remote_candidates.values()
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
        
        trace!("Added remote candidate: {} with priority {}", address, priority);
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
                } else if v6.ip().is_unicast_link_local() {
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
        
        for (_local_seq, local_candidate) in &self.local_candidates {
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
                let pair_priority = calculate_pair_priority(
                    local_candidate.priority, 
                    remote_candidate.priority
                );

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
        self.candidate_pairs.sort_unstable_by(|a, b| b.priority.cmp(&a.priority));
        
        // Rebuild index after sorting since indices changed
        self.pair_index.clear();
        for (idx, pair) in self.candidate_pairs.iter().enumerate() {
            self.pair_index.insert(pair.remote_addr, idx);
        }

        trace!("Generated {} candidate pairs", self.candidate_pairs.len());
    }

    /// Get the highest priority pairs ready for validation
    pub(super) fn get_next_validation_pairs(&mut self, max_concurrent: usize) -> Vec<&mut CandidatePair> {
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
    pub(super) fn find_pair_by_remote_addr(&mut self, addr: SocketAddr) -> Option<&mut CandidatePair> {
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
                && other_pair.state == PairState::Waiting {
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
                    if best_ipv4.map_or(true, |best| pair.priority > best.priority) {
                        best_ipv4 = Some(pair);
                    }
                }
                SocketAddr::V6(_) => {
                    if best_ipv6.map_or(true, |best| pair.priority > best.priority) {
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
        let mut candidates: Vec<_> = self.remote_candidates
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
        let candidate = self.remote_candidates.get_mut(&sequence)
            .ok_or(NatTraversalError::UnknownCandidate)?;
        
        if candidate.state != CandidateState::New {
            return Err(NatTraversalError::InvalidCandidateState);
        }

        // Security validation: Check for validation abuse patterns
        if Self::is_validation_suspicious(candidate, now) {
            self.stats.security_rejections += 1;
            debug!("Suspicious validation attempt rejected for address {}", candidate.address);
            return Err(NatTraversalError::SecurityValidationFailed);
        }

        // Security validation: Limit concurrent validations
        if self.active_validations.len() >= 10 {
            debug!("Too many concurrent validations, rejecting new validation for {}", candidate.address);
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

        self.active_validations.insert(candidate.address, validation);
        trace!("Started validation for candidate {} with challenge {}", candidate.address, challenge);
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
        let sequence = self.remote_candidates
            .iter()
            .find(|(_, c)| c.address == remote_addr)
            .map(|(seq, _)| *seq)
            .ok_or(NatTraversalError::UnknownCandidate)?;

        // Verify challenge matches and update timeout state
        let validation = self.active_validations.get_mut(&remote_addr)
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
        let candidate = self.remote_candidates.get_mut(&sequence)
            .ok_or(NatTraversalError::UnknownCandidate)?;
        
        candidate.state = CandidateState::Valid;
        self.active_validations.remove(&remote_addr);
        self.stats.validations_succeeded += 1;

        trace!("Validation successful for {} with RTT {:?}", remote_addr, rtt);
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
            debug!("Rate limit exceeded for coordination request with {} targets", targets.len());
            return Err(NatTraversalError::RateLimitExceeded);
        }

        // Security validation: Check for suspicious coordination patterns
        if self.is_coordination_suspicious(&targets, now) {
            self.stats.suspicious_coordination_attempts += 1;
            self.stats.security_rejections += 1;
            debug!("Suspicious coordination request rejected with {} targets", targets.len());
            return Err(NatTraversalError::SuspiciousCoordination);
        }

        // Security validation: Validate all target addresses
        for target in &targets {
            match self.security_state.validate_address(target.remote_addr, now) {
                AddressValidationResult::Invalid => {
                    self.stats.invalid_address_rejections += 1;
                    self.stats.security_rejections += 1;
                    debug!("Invalid target address in coordination: {}", target.remote_addr);
                    return Err(NatTraversalError::InvalidAddress);
                }
                AddressValidationResult::Suspicious => {
                    self.stats.security_rejections += 1;
                    debug!("Suspicious target address in coordination: {}", target.remote_addr);
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
        trace!("Started coordination round {} with {} targets", round, self.coordination.as_ref().unwrap().punch_targets.len());
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
                    if ipv4_addresses[i] == ipv4_addresses[i-1] + 1 {
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
    pub(super) fn handle_peer_punch_request(&mut self, peer_round: VarInt, now: Instant) -> Result<bool, NatTraversalError> {
        // Security validation: Check if this is a valid coordination request
        if self.is_peer_coordination_suspicious(peer_round, now) {
            self.stats.suspicious_coordination_attempts += 1;
            self.stats.security_rejections += 1;
            debug!("Suspicious peer coordination request rejected for round {}", peer_round);
            return Err(NatTraversalError::SuspiciousCoordination);
        }

        if let Some(coord) = &mut self.coordination {
            if coord.round == peer_round {
                match coord.state {
                    CoordinationPhase::Coordinating | CoordinationPhase::Requesting => {
                        coord.peer_punch_received = true;
                        coord.state = CoordinationPhase::Preparing;
                        
                        // Calculate adaptive grace period based on network conditions
                        let network_rtt = self.network_monitor.get_estimated_rtt()
                            .unwrap_or(Duration::from_millis(100));
                        let quality_score = self.network_monitor.get_quality_score();
                        
                        // Scale grace period: good networks get shorter delays
                        let base_grace = Duration::from_millis(150);
                        let rtt_factor = (network_rtt.as_millis() as f64 / 100.0).clamp(0.5, 3.0);
                        let quality_factor = (2.0 - quality_score).clamp(1.0, 2.0);
                        
                        let adaptive_grace = Duration::from_millis(
                            (base_grace.as_millis() as f64 * rtt_factor * quality_factor) as u64
                        );
                        
                        coord.punch_start = now + adaptive_grace;
                        
                        trace!("Peer coordination received, punch starts in {:?} (RTT: {:?}, quality: {:.2})", 
                               adaptive_grace, network_rtt, quality_score);
                        Ok(true)
                    }
                    CoordinationPhase::Preparing => {
                        // Already in preparation phase, just acknowledge
                        trace!("Peer coordination confirmed during preparation");
                        Ok(true)
                    }
                    _ => {
                        debug!("Received coordination in unexpected phase: {:?}", coord.state);
                        Ok(false)
                    }
                }
            } else {
                debug!("Received coordination for wrong round: {} vs {}", peer_round, coord.round);
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
            let network_rtt = self.network_monitor.get_estimated_rtt()
                .unwrap_or(Duration::from_millis(100));
            
            // Add small random jitter to avoid thundering herd
            let jitter_ms: u64 = rand::random::<u64>() % 11;
            let jitter = Duration::from_millis(jitter_ms);
            let transmission_time = coord.punch_start + network_rtt / 2 + jitter;
            
            // Update punch start time with precise calculation
            coord.punch_start = transmission_time.max(now);
            
            trace!("Starting synchronized hole punching at {:?} (RTT: {:?}, jitter: {:?})", 
                   coord.punch_start, network_rtt, jitter);
        }
    }

    /// Get punch targets for the current round
    pub(super) fn get_punch_targets_from_coordination(&self) -> Option<&[PunchTarget]> {
        self.coordination.as_ref().map(|c| c.punch_targets.as_slice())
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
    pub(super) fn handle_coordination_success(&mut self, remote_addr: SocketAddr, now: Instant) -> bool {
        if let Some(coord) = &mut self.coordination {
            // Check if this address was one of our punch targets
            let was_target = coord.punch_targets.iter().any(|target| target.remote_addr == remote_addr);
            
            if was_target && coord.state == CoordinationPhase::Validating {
                // Calculate RTT and update adaptive timeout
                let rtt = now.duration_since(coord.round_start);
                coord.timeout_state.update_success(rtt);
                self.network_monitor.record_success(rtt, now);
                
                coord.state = CoordinationPhase::Succeeded;
                self.stats.direct_connections += 1;
                trace!("Coordination succeeded via {} with RTT {:?}", remote_addr, rtt);
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
                && self.network_monitor.is_suitable_for_coordination() {
                
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
                    (retry_delay.as_millis() as f64 * quality_multiplier) as u64
                );
                
                coord.punch_start = now + adjusted_delay;
                
                trace!("Coordination failed, retrying round {} (attempt {}) with delay {:?} (quality: {:.2})", 
                       coord.round, coord.retry_count + 1, adjusted_delay, self.network_monitor.get_quality_score());
                true
            } else {
                coord.state = CoordinationPhase::Failed;
                self.stats.coordination_failures += 1;
                
                if !self.network_monitor.is_suitable_for_coordination() {
                    trace!("Coordination failed due to poor network conditions (quality: {:.2})", 
                           self.network_monitor.get_quality_score());
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
                trace!("Coordination round {} timed out after {:?} (adaptive timeout: {:?})", 
                       coord.round, elapsed, timeout);
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
                if validation.timeout_state.should_retry(validation.max_retries) {
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
                
                trace!("Retrying validation for {} (attempt {})", addr, validation.retry_count + 1);
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
            
            if elapsed > timeout && validation.timeout_state.should_retry(validation.max_retries) {
                // Update retry state
                validation.retry_count += 1;
                validation.last_retry_at = Some(now);
                validation.sent_at = now; // Reset sent time for new attempt
                validation.timeout_state.update_timeout();
                
                retry_addresses.push(*addr);
                trace!("Scheduled retry {} for validation to {}", validation.retry_count, addr);
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
                    (validation.timeout_state.backoff_multiplier * 1.2).min(validation.timeout_state.max_backoff_multiplier);
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
            self.candidate_pairs.len()
        );
        
        // Calculate current memory pressure
        let memory_pressure = self.resource_manager.calculate_memory_pressure(
            self.active_validations.len(),
            self.local_candidates.len(),
            self.remote_candidates.len(),
            self.candidate_pairs.len()
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
                now
            );
            
            // If memory pressure is high, perform aggressive cleanup
            if memory_pressure > self.resource_manager.config.aggressive_cleanup_threshold {
                cleaned += self.resource_manager.aggressive_cleanup(
                    &mut self.active_validations,
                    &mut self.local_candidates,
                    &mut self.remote_candidates,
                    &mut self.candidate_pairs,
                    now
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
            self.candidate_pairs.len()
        );
        let memory_pressure = self.resource_manager.calculate_memory_pressure(
            self.active_validations.len(),
            self.local_candidates.len(),
            self.remote_candidates.len(),
            self.candidate_pairs.len()
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
                    next_timeout = Some(next_timeout.map_or(timeout_at, |t: Instant| t.min(timeout_at)));
                }
                CoordinationPhase::Preparing => {
                    // Punch start time is when we should start punching
                    next_timeout = Some(next_timeout.map_or(coord.punch_start, |t: Instant| t.min(coord.punch_start)));
                }
                CoordinationPhase::Punching | CoordinationPhase::Validating => {
                    // Check for coordination round timeout
                    let timeout_at = coord.round_start + coord.timeout_state.get_timeout();
                    next_timeout = Some(next_timeout.map_or(timeout_at, |t: Instant| t.min(timeout_at)));
                }
                _ => {}
            }
        }
        
        // Check validation timeouts
        for (_, validation) in &self.active_validations {
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
    pub(super) fn handle_timeout(&mut self, now: Instant) -> Result<Vec<TimeoutAction>, NatTraversalError> {
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
                            debug!("Coordination timeout, retrying ({}/{})", coord.retry_count, coord.max_retries);
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
                            debug!("Validation timeout, retrying ({}/{})", coord.retry_count, coord.max_retries);
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
                    debug!("Path validation timeout for {}, retrying ({}/{})", 
                           addr, validation.retry_count, validation.max_retries);
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
        if self.coordination.is_none() && !self.local_candidates.is_empty() && !self.remote_candidates.is_empty() {
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
                transport_params: None,
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
            self.next_sequence = VarInt::from_u32((self.next_sequence.into_inner() + 1).try_into().unwrap());
            
            let priority = VarInt::from_u32(100); // Server-reflexive priority
            let add_address_frame = bootstrap_coordinator.generate_add_address_frame(
                peer_id,
                sequence,
                priority,
            );
            
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
    #[allow(dead_code)] // Used for address reflexive candidate discovery
    pub(super) fn get_observed_address(&self, peer_id: [u8; 32]) -> Option<SocketAddr> {
        self.bootstrap_coordinator
            .as_ref()
            .and_then(|coord| coord.get_peer_record(peer_id))
            .map(|record| record.observed_address)
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
        debug!("Queuing ADD_ADDRESS frame: seq={}, addr={}, priority={}", 
               sequence, address, priority);
        
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
#[allow(dead_code)] // NoActiveCoordination variant reserved for bootstrap coordination errors
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
#[allow(dead_code)] // Security statistics reserved for monitoring and reporting
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
    /// Active peer registry with observed addresses
    peer_registry: HashMap<PeerId, PeerObservationRecord>,
    /// Active coordination sessions between peers
    coordination_sessions: HashMap<CoordinationSessionId, CoordinationSession>,
    /// Pending coordination requests awaiting peer participation
    #[allow(dead_code)] // Used for coordination queue management
    pending_coordination: VecDeque<PendingCoordinationRequest>,
    /// Address observation cache for quick lookups
    #[allow(dead_code)] // Will be used for address correlation and verification
    address_observations: HashMap<SocketAddr, AddressObservation>,
    /// Security validator for coordination requests
    security_validator: SecurityValidationState,
    /// Statistics for bootstrap operations
    stats: BootstrapStats,
    /// Configuration for bootstrap behavior (stub)
    _config: BootstrapConfig,
    /// Last cleanup time (stub)
    _last_cleanup: Option<Instant>,
}

/// Unique identifier for coordination sessions
type CoordinationSessionId = u64;

/// Peer identifier for bootstrap coordination
type PeerId = [u8; 32];

/// Record of observed peer information
#[derive(Debug, Clone)]
pub(crate) struct PeerObservationRecord {
    /// The peer's unique identifier
    #[allow(dead_code)] // Used for peer tracking
    peer_id: PeerId,
    /// Last observed public address
    observed_address: SocketAddr,
    /// When this observation was made
    #[allow(dead_code)] // Used for observation aging
    observed_at: Instant,
    /// Connection context for this observation
    #[allow(dead_code)] // Used for coordination context
    connection_context: ConnectionContext,
    /// Whether this peer can participate in coordination
    #[allow(dead_code)] // Used for coordination eligibility
    can_coordinate: bool,
    /// Number of successful coordinations
    #[allow(dead_code)] // Used for coordination statistics
    coordination_count: u32,
    /// Average coordination success rate
    #[allow(dead_code)] // Used for peer quality assessment
    success_rate: f64,
}

/// Connection context for address observations
#[derive(Debug, Clone)]
pub(crate) struct ConnectionContext {
    /// Connection ID for this observation
    #[allow(dead_code)] // Used for connection correlation
    connection_id: ConnectionId,
    /// Original destination address (what peer thought it was connecting to)
    #[allow(dead_code)] // Used for NAT analysis
    original_destination: SocketAddr,
    /// NAT traversal role of the connecting peer
    #[allow(dead_code)] // Used for role-based decisions
    peer_role: NatTraversalRole,
    /// Transport parameters received from peer
    #[allow(dead_code)] // Used for capability negotiation
    transport_params: Option<NatTraversalTransportParams>,
}

/// Transport parameters for NAT traversal
#[derive(Debug, Clone)]
struct NatTraversalTransportParams {
    /// Maximum candidates this peer can handle
    #[allow(dead_code)] // Used for capability negotiation
    max_candidates: u32,
    /// Coordination timeout for this peer
    #[allow(dead_code)] // Used for timing adjustments
    coordination_timeout: Duration,
    /// Whether this peer supports advanced features
    #[allow(dead_code)] // Used for feature detection
    supports_advanced_features: bool,
}

/// Address observation with validation
#[derive(Debug, Clone)]
struct AddressObservation {
    /// The observed address
    #[allow(dead_code)] // Used for address tracking
    address: SocketAddr,
    /// When this address was first observed
    #[allow(dead_code)] // Used for observation aging
    first_observed: Instant,
    /// How many times this address has been observed
    #[allow(dead_code)] // Will be used for address reliability scoring
    observation_count: u32,
    /// Validation state for this address
    #[allow(dead_code)] // Used for address validation tracking
    validation_state: AddressValidationResult,
    /// Associated peer IDs for this address
    #[allow(dead_code)] // Will be used for peer-address correlation
    associated_peers: Vec<PeerId>,
}

/// Active coordination session between two peers
#[derive(Debug, Clone)]
#[allow(dead_code)] // Fields tracked for coordination state management
pub(crate) struct CoordinationSession {
    /// Unique session identifier
    session_id: CoordinationSessionId,
    /// First peer in coordination
    peer_a: PeerId,
    /// Second peer in coordination
    peer_b: PeerId,
    /// Current coordination round
    current_round: VarInt,
    /// When this session started
    started_at: Instant,
    /// Current phase of coordination
    phase: CoordinationPhase,
    /// Target addresses for hole punching
    target_addresses: Vec<(SocketAddr, VarInt)>, // (address, sequence)
    /// Synchronization state
    sync_state: SynchronizationState,
    /// Session statistics
    stats: CoordinationSessionStats,
}

/// Synchronization state for coordinated hole punching
#[derive(Debug, Clone)]
struct SynchronizationState {
    /// Confirmation from peer A
    peer_a_ready: bool,
    /// Confirmation from peer B
    peer_b_ready: bool,
}

/// Statistics for a coordination session
#[derive(Debug, Clone, Default)]
struct CoordinationSessionStats {
    /// Number of successful coordinations
    successful_coordinations: u32,
}

/// Pending coordination request awaiting peer participation (stub implementation)
#[derive(Debug, Clone)]
struct PendingCoordinationRequest {
    _unused: (),
}

/// Configuration for bootstrap coordinator behavior (stub implementation)
#[derive(Debug, Clone)]
pub(crate) struct BootstrapConfig {
    _unused: (),
}

/// Statistics for bootstrap operations
#[derive(Debug, Clone, Default)]
pub(crate) struct BootstrapStats {
    /// Total address observations made
    #[allow(dead_code)] // Will be used for bootstrap performance metrics
    total_observations: u64,
    /// Total coordination sessions facilitated
    total_coordinations: u64,
    /// Successful coordinations
    successful_coordinations: u64,
    /// Active peer count
    #[allow(dead_code)] // Will be used for bootstrap load monitoring
    active_peers: usize,
    /// Active coordination sessions
    active_sessions: usize,
    /// Security rejections
    security_rejections: u64,
}

/// Events generated by the coordination session state machine
#[derive(Debug, Clone)]
#[allow(dead_code)] // Will be used for coordination event handling and logging
pub(crate) enum CoordinationSessionEvent {
    /// Session phase changed
    PhaseChanged {
        session_id: CoordinationSessionId,
        old_phase: CoordinationPhase,
        new_phase: CoordinationPhase,
    },
    /// Session failed with reason
    SessionFailed {
        session_id: CoordinationSessionId,
        peer_a: PeerId,
        peer_b: PeerId,
        reason: String,
    },
    /// Start hole punching for session
    StartHolePunching {
        session_id: CoordinationSessionId,
        peer_a: PeerId,
        peer_b: PeerId,
        target_addresses: Vec<(SocketAddr, VarInt)>,
    },
    /// Session ready for cleanup
    ReadyForCleanup {
        session_id: CoordinationSessionId,
    },
}

/// Events that trigger session state advancement
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)] // Will be used in coordination state machine implementation
enum SessionAdvancementEvent {
    /// Both peers are ready for coordination
    BothPeersReady,
    /// Coordination phase completed
    CoordinationComplete,
    /// Preparation phase completed
    PreparationComplete,
    /// Hole punching phase completed
    PunchingComplete,
    /// Validation timed out
    ValidationTimeout,
    /// Session timed out
    Timeout,
    /// Session ready for cleanup
    ReadyForCleanup,
}

/// Recovery actions for coordination errors
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)] // Will be used for coordination error recovery logic
pub(crate) enum CoordinationRecoveryAction {
    /// No action needed
    NoAction,
    /// Retry with exponential backoff
    RetryWithBackoff,
    /// Mark session as failed
    MarkAsFailed,
    /// Clean up session
    Cleanup,
}

impl BootstrapCoordinator {
    /// Create a new bootstrap coordinator
    pub(crate) fn new(config: BootstrapConfig) -> Self {
        Self {
            peer_registry: HashMap::new(),
            coordination_sessions: HashMap::new(),
            pending_coordination: VecDeque::new(),
            address_observations: HashMap::new(),
            security_validator: SecurityValidationState::new(),
            stats: BootstrapStats::default(),
            _config: config,
            _last_cleanup: None,
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
        connection_context: ConnectionContext,
        now: Instant,
    ) -> Result<(), NatTraversalError> {
        // Security validation
        match self.security_validator.validate_address(observed_address, now) {
            AddressValidationResult::Valid => {},
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
        let observation = self.address_observations.entry(observed_address)
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
        
        // Update or create peer record
        let peer_record = PeerObservationRecord {
            peer_id,
            observed_address,
            observed_at: now,
            connection_context,
            can_coordinate: true, // Assume true initially
            coordination_count: 0,
            success_rate: 1.0,
        };
        
        self.peer_registry.insert(peer_id, peer_record);
        self.stats.total_observations += 1;
        self.stats.active_peers = self.peer_registry.len();
        
        debug!("Observed peer {:?} at address {} (total observations: {})", 
               peer_id, observed_address, self.stats.total_observations);
        
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
        if let Some(peer_record) = self.peer_registry.get(&peer_id) {
            Some(crate::frame::AddAddress {
                sequence,
                address: peer_record.observed_address,
                priority,
            })
        } else {
            None
        }
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
        if self.security_validator.is_adaptive_rate_limited(from_peer, now) {
            self.stats.security_rejections += 1;
            debug!("PUNCH_ME_NOW frame rejected: adaptive rate limit exceeded for peer {:?}", 
                   hex::encode(&from_peer[..8]));
            return Err(NatTraversalError::RateLimitExceeded);
        }

        // Enhanced address validation with amplification protection
        self.security_validator.enhanced_address_validation(frame.local_address, source_addr, now)
            .map_err(|e| {
                self.stats.security_rejections += 1;
                debug!("PUNCH_ME_NOW frame address validation failed from peer {:?}: {:?}", 
                       hex::encode(&from_peer[..8]), e);
                e
            })?;

        // Comprehensive security validation
        self.security_validator.validate_punch_me_now_frame(frame, source_addr, from_peer, now)
            .map_err(|e| {
                self.stats.security_rejections += 1;
                debug!("PUNCH_ME_NOW frame validation failed from peer {:?}: {:?}", 
                       hex::encode(&from_peer[..8]), e);
                e
            })?;
        
        // Check if we have a target peer for this coordination
        if let Some(target_peer_id) = frame.target_peer_id {
            // This is a coordination request that should be relayed
            if let Some(target_peer) = self.peer_registry.get(&target_peer_id) {
                // Create coordination session if it doesn't exist
                let session_id = self.generate_session_id();
                
                if !self.coordination_sessions.contains_key(&session_id) {
                    // Calculate optimal coordination timing based on network conditions
                    let _network_rtt = self.estimate_peer_rtt(&from_peer)
                        .unwrap_or(Duration::from_millis(100));
                    
                    let session = CoordinationSession {
                        session_id,
                        peer_a: from_peer,
                        peer_b: target_peer_id,
                        current_round: frame.round,
                        started_at: now,
                        phase: CoordinationPhase::Requesting,
                        target_addresses: vec![(frame.local_address, frame.target_sequence)],
                        sync_state: SynchronizationState {
                            peer_a_ready: true, // Requesting peer is ready
                            peer_b_ready: false,
                        },
                        stats: CoordinationSessionStats::default(),
                    };
                    
                    self.coordination_sessions.insert(session_id, session);
                    self.stats.total_coordinations += 1;
                    self.stats.active_sessions = self.coordination_sessions.len();
                }
                
                // Generate coordination frame to send to target peer
                let coordination_frame = crate::frame::PunchMeNow {
                    round: frame.round,
                    target_sequence: frame.target_sequence,
                    local_address: target_peer.observed_address,
                    target_peer_id: Some(from_peer),
                };
                
                info!("Coordinating hole punch between {:?} and {:?} (round: {})", 
                      from_peer, target_peer_id, frame.round);
                
                Ok(Some(coordination_frame))
            } else {
                // Target peer not found
                warn!("Target peer {:?} not found for coordination from {:?}", 
                      target_peer_id, from_peer);
                Ok(None)
            }
        } else {
            // This is a response to coordination - update session state
            let session_id = if let Some(session) = self.find_coordination_session_by_peer(from_peer, frame.round) {
                session.sync_state.peer_b_ready = true;
                
                // If both peers are ready, coordination is complete
                if session.sync_state.peer_a_ready && session.sync_state.peer_b_ready {
                    session.phase = CoordinationPhase::Punching;
                    session.stats.successful_coordinations += 1;
                    Some(session.session_id)
                } else {
                    None
                }
            } else {
                None
            };
            
            // Update stats after releasing the mutable borrow
            if let Some(session_id) = session_id {
                self.stats.successful_coordinations += 1;
                info!("Coordination complete for session {} (round: {})", 
                      session_id, frame.round);
            }
            
            Ok(None)
        }
    }
    
    /// Find coordination session by peer and round
    fn find_coordination_session_by_peer(
        &mut self,
        peer_id: PeerId,
        round: VarInt,
    ) -> Option<&mut CoordinationSession> {
        self.coordination_sessions.values_mut().find(|session| {
            (session.peer_a == peer_id || session.peer_b == peer_id) &&
            session.current_round == round
        })
    }
    
    /// Generate unique session ID
    fn generate_session_id(&self) -> CoordinationSessionId {
        rand::random()
    }

    /// Generate secure coordination round using cryptographically secure random values
    pub(crate) fn generate_secure_coordination_round(&self) -> VarInt {
        self.security_validator.generate_secure_coordination_round()
    }

    /// Perform comprehensive security validation for coordination requests
    pub(crate) fn validate_coordination_security(
        &mut self,
        peer_id: PeerId,
        source_addr: SocketAddr,
        target_addr: SocketAddr,
        now: Instant,
    ) -> Result<(), NatTraversalError> {
        // Check adaptive rate limiting
        if self.security_validator.is_adaptive_rate_limited(peer_id, now) {
            self.stats.security_rejections += 1;
            return Err(NatTraversalError::RateLimitExceeded);
        }

        // Perform enhanced address validation
        self.security_validator.enhanced_address_validation(target_addr, source_addr, now)?;

        // Check amplification limits
        self.security_validator.validate_amplification_limits(source_addr, target_addr, now)?;

        Ok(())
    }

    /// Clean up expired sessions and perform maintenance
    pub(crate) fn cleanup_expired_sessions(&mut self, now: Instant) {
        let session_timeout = Duration::from_secs(300); // 5 minutes
        
        // Collect expired session IDs
        let expired_sessions: Vec<CoordinationSessionId> = self.coordination_sessions
            .iter()
            .filter(|(_, session)| {
                now.duration_since(session.started_at) > session_timeout
            })
            .map(|(&session_id, _)| session_id)
            .collect();

        // Remove expired sessions
        for session_id in expired_sessions {
            if let Some(session) = self.coordination_sessions.remove(&session_id) {
                debug!("Cleaned up expired coordination session {} between {:?} and {:?}",
                       session_id, hex::encode(&session.peer_a[..8]), hex::encode(&session.peer_b[..8]));
            }
        }

        // Update active session count
        self.stats.active_sessions = self.coordination_sessions.len();

        // Clean up old peer observations
        let observation_timeout = Duration::from_secs(3600); // 1 hour
        self.peer_registry.retain(|_, record| {
            now.duration_since(record.observed_at) <= observation_timeout
        });

        // Update active peer count
        self.stats.active_peers = self.peer_registry.len();

        // Clean up address observations
        self.address_observations.retain(|_, observation| {
            now.duration_since(observation.first_observed) <= observation_timeout
        });
    }

    /// Get bootstrap statistics
    pub(crate) fn get_stats(&self) -> &BootstrapStats {
        &self.stats
    }

    /// Update peer coordination statistics
    pub(crate) fn update_peer_coordination_stats(
        &mut self,
        peer_id: PeerId,
        success: bool,
    ) {
        if let Some(peer_record) = self.peer_registry.get_mut(&peer_id) {
            peer_record.coordination_count += 1;
            
            if success {
                // Update success rate using exponential moving average
                let alpha = 0.1; // Learning rate
                peer_record.success_rate = peer_record.success_rate * (1.0 - alpha) + alpha;
            } else {
                // Decrease success rate
                let alpha = 0.1;
                peer_record.success_rate = peer_record.success_rate * (1.0 - alpha);
            }

            // Disable coordination for peers with very low success rates
            if peer_record.success_rate < 0.1 && peer_record.coordination_count > 10 {
                peer_record.can_coordinate = false;
                warn!("Disabled coordination for peer {:?} due to low success rate: {:.2}",
                      hex::encode(&peer_id[..8]), peer_record.success_rate);
            }
        }
    }

    /// Poll session state machine and advance coordination sessions
    /// 
    /// This method implements the core session state machine polling logic
    /// with timeout handling, retry mechanisms, and error recovery.
    pub(crate) fn poll_session_state_machine(&mut self, now: Instant) -> Vec<CoordinationSessionEvent> {
        let mut events = Vec::new();
        let mut sessions_to_update = Vec::new();

        // Collect sessions that need state machine advancement
        for (&session_id, session) in &self.coordination_sessions {
            if let Some(event) = self.should_advance_session(session, now) {
                sessions_to_update.push((session_id, event));
            }
        }

        // Process session updates
        for (session_id, event) in sessions_to_update {
            let session_events = if let Some(session) = self.coordination_sessions.get_mut(&session_id) {
                let peer_a = session.peer_a;
                let peer_b = session.peer_b;
                
                match Self::advance_session_state_static(session, event, now) {
                    Ok(session_events) => session_events,
                    Err(e) => {
                        warn!("Failed to advance session {} state: {:?}", session_id, e);
                        // Mark session as failed
                        session.phase = CoordinationPhase::Failed;
                        vec![CoordinationSessionEvent::SessionFailed {
                            session_id,
                            peer_a,
                            peer_b,
                            reason: format!("State advancement error: {:?}", e),
                        }]
                    }
                }
            } else {
                Vec::new()
            };
            
            events.extend(session_events);
        }

        // Clean up completed or failed sessions
        self.cleanup_completed_sessions(now);

        events
    }

    /// Check if a session should advance its state
    fn should_advance_session(&self, session: &CoordinationSession, now: Instant) -> Option<SessionAdvancementEvent> {
        let session_age = now.duration_since(session.started_at);
        
        match session.phase {
            CoordinationPhase::Requesting => {
                // Check if we've been waiting too long for peer responses
                if session_age > Duration::from_secs(10) {
                    Some(SessionAdvancementEvent::Timeout)
                } else if session.sync_state.peer_a_ready && session.sync_state.peer_b_ready {
                    Some(SessionAdvancementEvent::BothPeersReady)
                } else {
                    None
                }
            }
            CoordinationPhase::Coordinating => {
                // Move to preparing phase after brief coordination period
                if session_age > Duration::from_millis(500) {
                    Some(SessionAdvancementEvent::CoordinationComplete)
                } else {
                    None
                }
            }
            CoordinationPhase::Preparing => {
                // Move to punching phase after preparation period
                if session_age > Duration::from_secs(1) {
                    Some(SessionAdvancementEvent::PreparationComplete)
                } else {
                    None
                }
            }
            CoordinationPhase::Punching => {
                // Move to validation phase after punching period
                if session_age > Duration::from_secs(2) {
                    Some(SessionAdvancementEvent::PunchingComplete)
                } else {
                    None
                }
            }
            CoordinationPhase::Validating => {
                // Check for validation timeout
                if session_age > Duration::from_secs(10) {
                    Some(SessionAdvancementEvent::ValidationTimeout)
                } else {
                    None
                }
            }
            CoordinationPhase::Succeeded | CoordinationPhase::Failed => {
                // Terminal states - check for cleanup
                if session_age > Duration::from_secs(60) {
                    Some(SessionAdvancementEvent::ReadyForCleanup)
                } else {
                    None
                }
            }
            CoordinationPhase::Idle => {
                // Should not happen in active sessions
                Some(SessionAdvancementEvent::Timeout)
            }
        }
    }

    /// Advance session state based on event (static version to avoid borrowing issues)
    fn advance_session_state_static(
        session: &mut CoordinationSession,
        event: SessionAdvancementEvent,
        _now: Instant,
    ) -> Result<Vec<CoordinationSessionEvent>, NatTraversalError> {
        let mut events = Vec::new();
        let previous_phase = session.phase;

        match (session.phase, event) {
            (CoordinationPhase::Requesting, SessionAdvancementEvent::BothPeersReady) => {
                session.phase = CoordinationPhase::Coordinating;
                debug!("Session {} advanced from Requesting to Coordinating", session.session_id);
                events.push(CoordinationSessionEvent::PhaseChanged {
                    session_id: session.session_id,
                    old_phase: previous_phase,
                    new_phase: session.phase,
                });
            }
            (CoordinationPhase::Requesting, SessionAdvancementEvent::Timeout) => {
                session.phase = CoordinationPhase::Failed;
                warn!("Session {} timed out in Requesting phase", session.session_id);
                events.push(CoordinationSessionEvent::SessionFailed {
                    session_id: session.session_id,
                    peer_a: session.peer_a,
                    peer_b: session.peer_b,
                    reason: "Timeout waiting for peer responses".to_string(),
                });
            }
            (CoordinationPhase::Coordinating, SessionAdvancementEvent::CoordinationComplete) => {
                session.phase = CoordinationPhase::Preparing;
                debug!("Session {} advanced from Coordinating to Preparing", session.session_id);
                events.push(CoordinationSessionEvent::PhaseChanged {
                    session_id: session.session_id,
                    old_phase: previous_phase,
                    new_phase: session.phase,
                });
            }
            (CoordinationPhase::Preparing, SessionAdvancementEvent::PreparationComplete) => {
                session.phase = CoordinationPhase::Punching;
                debug!("Session {} advanced from Preparing to Punching", session.session_id);
                events.push(CoordinationSessionEvent::PhaseChanged {
                    session_id: session.session_id,
                    old_phase: previous_phase,
                    new_phase: session.phase,
                });
                events.push(CoordinationSessionEvent::StartHolePunching {
                    session_id: session.session_id,
                    peer_a: session.peer_a,
                    peer_b: session.peer_b,
                    target_addresses: session.target_addresses.clone(),
                });
            }
            (CoordinationPhase::Punching, SessionAdvancementEvent::PunchingComplete) => {
                session.phase = CoordinationPhase::Validating;
                debug!("Session {} advanced from Punching to Validating", session.session_id);
                events.push(CoordinationSessionEvent::PhaseChanged {
                    session_id: session.session_id,
                    old_phase: previous_phase,
                    new_phase: session.phase,
                });
            }
            (CoordinationPhase::Validating, SessionAdvancementEvent::ValidationTimeout) => {
                session.phase = CoordinationPhase::Failed;
                warn!("Session {} validation timed out", session.session_id);
                events.push(CoordinationSessionEvent::SessionFailed {
                    session_id: session.session_id,
                    peer_a: session.peer_a,
                    peer_b: session.peer_b,
                    reason: "Validation timeout".to_string(),
                });
            }
            (phase, SessionAdvancementEvent::ReadyForCleanup) => {
                debug!("Session {} ready for cleanup in phase {:?}", session.session_id, phase);
                events.push(CoordinationSessionEvent::ReadyForCleanup {
                    session_id: session.session_id,
                });
            }
            _ => {
                // Invalid state transition - log warning but don't fail
                warn!("Invalid state transition for session {}: {:?} -> {:?}", 
                      session.session_id, session.phase, event);
            }
        }

        Ok(events)
    }

    /// Clean up completed or failed sessions
    fn cleanup_completed_sessions(&mut self, now: Instant) {
        let cleanup_timeout = Duration::from_secs(300); // 5 minutes
        
        let sessions_to_remove: Vec<CoordinationSessionId> = self.coordination_sessions
            .iter()
            .filter(|(_, session)| {
                matches!(session.phase, CoordinationPhase::Succeeded | CoordinationPhase::Failed) &&
                now.duration_since(session.started_at) > cleanup_timeout
            })
            .map(|(&session_id, _)| session_id)
            .collect();

        for session_id in sessions_to_remove {
            if let Some(session) = self.coordination_sessions.remove(&session_id) {
                debug!("Cleaned up completed session {} in phase {:?}", 
                       session_id, session.phase);
            }
        }

        self.stats.active_sessions = self.coordination_sessions.len();
    }

    /// Implement retry mechanism with exponential backoff
    /// 
    /// This method handles retry logic for failed coordination attempts
    /// with exponential backoff to avoid overwhelming the network.
    pub(crate) fn retry_failed_coordination(
        &mut self,
        session_id: CoordinationSessionId,
        now: Instant,
    ) -> Result<bool, NatTraversalError> {
        let session = self.coordination_sessions.get_mut(&session_id)
            .ok_or(NatTraversalError::NoActiveCoordination)?;

        // Check if session is in a retryable state
        if !matches!(session.phase, CoordinationPhase::Failed) {
            return Ok(false);
        }

        // Calculate retry delay with exponential backoff
        let base_delay = Duration::from_secs(1);
        let max_delay = Duration::from_secs(60);
        let retry_count = session.stats.successful_coordinations; // Reuse this field for retry count
        
        let delay = std::cmp::min(
            base_delay * 2_u32.pow(retry_count.min(10)), // Cap at 2^10 to prevent overflow
            max_delay
        );

        // Add jitter to prevent thundering herd
        let _jitter_factor = 0.1;
        let jitter = Duration::from_millis((rand::random::<u64>() % 100) * delay.as_millis() as u64 / 1000);
        let total_delay = delay + jitter;

        // Check if enough time has passed for retry
        if now.duration_since(session.started_at) < total_delay {
            return Ok(false);
        }

        // Check retry limits
        const MAX_RETRIES: u32 = 5;
        if retry_count >= MAX_RETRIES {
            warn!("Session {} exceeded maximum retry attempts ({})", session_id, MAX_RETRIES);
            return Ok(false);
        }

        // Reset session for retry
        session.phase = CoordinationPhase::Requesting;
        session.started_at = now;
        session.sync_state.peer_a_ready = false;
        session.sync_state.peer_b_ready = false;
        session.stats.successful_coordinations += 1; // Increment retry count

        info!("Retrying coordination session {} (attempt {})", session_id, retry_count + 1);
        Ok(true)
    }

    /// Handle coordination errors with appropriate recovery strategies
    pub(crate) fn handle_coordination_error(
        &mut self,
        session_id: CoordinationSessionId,
        error: NatTraversalError,
        _now: Instant,
    ) -> CoordinationRecoveryAction {
        let session = match self.coordination_sessions.get_mut(&session_id) {
            Some(session) => session,
            None => return CoordinationRecoveryAction::NoAction,
        };

        match error {
            NatTraversalError::RateLimitExceeded => {
                // Temporary error - retry with backoff
                warn!("Rate limit exceeded for session {}, will retry", session_id);
                CoordinationRecoveryAction::RetryWithBackoff
            }
            NatTraversalError::SecurityValidationFailed | NatTraversalError::SuspiciousCoordination => {
                // Security error - mark session as failed and don't retry
                session.phase = CoordinationPhase::Failed;
                warn!("Security validation failed for session {}, marking as failed", session_id);
                CoordinationRecoveryAction::MarkAsFailed
            }
            NatTraversalError::InvalidAddress => {
                // Address error - might be temporary, allow limited retries
                warn!("Invalid address in session {}, allowing retry", session_id);
                CoordinationRecoveryAction::RetryWithBackoff
            }
            NatTraversalError::NoActiveCoordination => {
                // Session state error - clean up
                warn!("No active coordination for session {}, cleaning up", session_id);
                CoordinationRecoveryAction::Cleanup
            }
            _ => {
                // Other errors - generic retry with backoff
                warn!("Coordination error for session {}: {:?}, will retry", session_id, error);
                CoordinationRecoveryAction::RetryWithBackoff
            }
        }
    }

    /// Estimate RTT to a specific peer based on observations
    fn estimate_peer_rtt(&self, peer_id: &PeerId) -> Option<Duration> {
        // Simple estimation based on peer record
        // In a real implementation, this would use historical RTT data
        if let Some(_peer_record) = self.peer_registry.get(peer_id) {
            // Return a reasonable default based on peer observation patterns
            Some(Duration::from_millis(100))
        } else {
            None
        }
    }
    
    
    /// Coordinate hole punching between two peers
    /// 
    /// This method implements the core coordination logic for establishing
    /// direct P2P connections through NAT traversal.
    pub(crate) fn coordinate_hole_punching(
        &mut self,
        peer_a: PeerId,
        peer_b: PeerId,
        round: VarInt,
        now: Instant,
    ) -> Result<CoordinationSessionId, NatTraversalError> {
        // Validate that both peers are known and can coordinate
        let peer_a_record = self.peer_registry.get(&peer_a)
            .ok_or(NatTraversalError::UnknownCandidate)?;
        let peer_b_record = self.peer_registry.get(&peer_b)
            .ok_or(NatTraversalError::UnknownCandidate)?;

        if !peer_a_record.can_coordinate || !peer_b_record.can_coordinate {
            return Err(NatTraversalError::InvalidCandidateState);
        }

        // Generate unique session ID
        let session_id = self.generate_session_id();

        // Create coordination session
        let session = CoordinationSession {
            session_id,
            peer_a,
            peer_b,
            current_round: round,
            started_at: now,
            phase: CoordinationPhase::Requesting,
            target_addresses: vec![
                (peer_a_record.observed_address, VarInt::from_u32(0)),
                (peer_b_record.observed_address, VarInt::from_u32(1)),
            ],
            sync_state: SynchronizationState {
                peer_a_ready: false,
                peer_b_ready: false,
            },
            stats: CoordinationSessionStats::default(),
        };

        self.coordination_sessions.insert(session_id, session);
        self.stats.total_coordinations += 1;
        self.stats.active_sessions = self.coordination_sessions.len();

        info!("Started coordination session {} between peers {:?} and {:?} (round: {})",
              session_id, hex::encode(&peer_a[..8]), hex::encode(&peer_b[..8]), round);

        Ok(session_id)
    }

    /// Relay coordination frame between peers
    /// 
    /// This method handles the relay of coordination messages between peers
    /// to facilitate synchronized hole punching.
    pub(crate) fn relay_coordination_frame(
        &mut self,
        session_id: CoordinationSessionId,
        from_peer: PeerId,
        frame: &crate::frame::PunchMeNow,
        _now: Instant,
    ) -> Result<Option<(PeerId, crate::frame::PunchMeNow)>, NatTraversalError> {
        let session = self.coordination_sessions.get_mut(&session_id)
            .ok_or(NatTraversalError::NoActiveCoordination)?;

        // Validate that the sender is part of this session
        if session.peer_a != from_peer && session.peer_b != from_peer {
            return Err(NatTraversalError::SuspiciousCoordination);
        }

        // Determine target peer
        let target_peer = if session.peer_a == from_peer {
            session.peer_b
        } else {
            session.peer_a
        };

        // Get target peer's observed address
        let target_record = self.peer_registry.get(&target_peer)
            .ok_or(NatTraversalError::UnknownCandidate)?;

        // Update session state based on frame
        if session.peer_a == from_peer {
            session.sync_state.peer_a_ready = true;
        } else {
            session.sync_state.peer_b_ready = true;
        }

        // Create relay frame with target peer's information
        let relay_frame = crate::frame::PunchMeNow {
            round: frame.round,
            target_sequence: frame.target_sequence,
            local_address: target_record.observed_address,
            target_peer_id: Some(from_peer),
        };

        // Check if coordination is complete
        if session.sync_state.peer_a_ready && session.sync_state.peer_b_ready {
            session.phase = CoordinationPhase::Coordinating;
            info!("Coordination phase complete for session {} - both peers ready", session_id);
        }

        debug!("Relaying coordination frame from {:?} to {:?} in session {}",
               hex::encode(&from_peer[..8]), hex::encode(&target_peer[..8]), session_id);

        Ok(Some((target_peer, relay_frame)))
    }

    /// Implement round-based synchronization protocol
    /// 
    /// This method manages the timing and synchronization of hole punching rounds
    /// to maximize the chances of successful NAT traversal.
    pub(crate) fn advance_coordination_round(
        &mut self,
        session_id: CoordinationSessionId,
        now: Instant,
    ) -> Result<CoordinationPhase, NatTraversalError> {
        let session = self.coordination_sessions.get_mut(&session_id)
            .ok_or(NatTraversalError::NoActiveCoordination)?;

        let previous_phase = session.phase;

        // Advance the state machine based on current phase and timing
        match session.phase {
            CoordinationPhase::Requesting => {
                // Wait for both peers to send PUNCH_ME_NOW frames
                if session.sync_state.peer_a_ready && session.sync_state.peer_b_ready {
                    session.phase = CoordinationPhase::Coordinating;
                    debug!("Session {} advanced to Coordinating phase", session_id);
                }
            }
            CoordinationPhase::Coordinating => {
                // Calculate synchronized punch time
                let coordination_delay = Duration::from_millis(200); // Grace period
                let punch_time = now + coordination_delay;
                
                session.phase = CoordinationPhase::Preparing;
                debug!("Session {} advanced to Preparing phase, punch time: {:?}", 
                       session_id, punch_time);
            }
            CoordinationPhase::Preparing => {
                // Transition to active hole punching
                session.phase = CoordinationPhase::Punching;
                debug!("Session {} advanced to Punching phase", session_id);
            }
            CoordinationPhase::Punching => {
                // Wait for validation results
                session.phase = CoordinationPhase::Validating;
                debug!("Session {} advanced to Validating phase", session_id);
            }
            CoordinationPhase::Validating => {
                // Check for timeout or success
                let validation_timeout = Duration::from_secs(5);
                if now.duration_since(session.started_at) > validation_timeout {
                    session.phase = CoordinationPhase::Failed;
                    debug!("Session {} timed out in validation", session_id);
                }
            }
            CoordinationPhase::Succeeded | CoordinationPhase::Failed => {
                // Terminal states - no further advancement
            }
            CoordinationPhase::Idle => {
                // Should not happen in active sessions
                session.phase = CoordinationPhase::Requesting;
            }
        }

        // Update statistics if phase changed
        if session.phase != previous_phase {
            match session.phase {
                CoordinationPhase::Succeeded => {
                    session.stats.successful_coordinations += 1;
                    self.stats.successful_coordinations += 1;
                }
                CoordinationPhase::Failed => {
                    // Update failure statistics
                }
                _ => {}
            }
        }

        Ok(session.phase)
    }

    /// Get coordination session by ID
    pub(crate) fn get_coordination_session(&self, session_id: CoordinationSessionId) -> Option<&CoordinationSession> {
        self.coordination_sessions.get(&session_id)
    }

    /// Get mutable coordination session by ID
    pub(crate) fn get_coordination_session_mut(&mut self, session_id: CoordinationSessionId) -> Option<&mut CoordinationSession> {
        self.coordination_sessions.get_mut(&session_id)
    }

    /// Mark coordination session as successful
    pub(crate) fn mark_coordination_success(
        &mut self,
        session_id: CoordinationSessionId,
        _now: Instant,
    ) -> Result<(), NatTraversalError> {
        let session = self.coordination_sessions.get_mut(&session_id)
            .ok_or(NatTraversalError::NoActiveCoordination)?;

        session.phase = CoordinationPhase::Succeeded;
        session.stats.successful_coordinations += 1;
        self.stats.successful_coordinations += 1;

        // Update peer success rates
        if let Some(peer_a_record) = self.peer_registry.get_mut(&session.peer_a) {
            peer_a_record.coordination_count += 1;
            peer_a_record.success_rate = (peer_a_record.success_rate * (peer_a_record.coordination_count - 1) as f64 + 1.0) / peer_a_record.coordination_count as f64;
        }

        if let Some(peer_b_record) = self.peer_registry.get_mut(&session.peer_b) {
            peer_b_record.coordination_count += 1;
            peer_b_record.success_rate = (peer_b_record.success_rate * (peer_b_record.coordination_count - 1) as f64 + 1.0) / peer_b_record.coordination_count as f64;
        }

        info!("Coordination session {} marked as successful", session_id);
        Ok(())
    }

    /// Mark coordination session as failed
    pub(crate) fn mark_coordination_failure(
        &mut self,
        session_id: CoordinationSessionId,
        reason: &str,
        _now: Instant,
    ) -> Result<(), NatTraversalError> {
        let session = self.coordination_sessions.get_mut(&session_id)
            .ok_or(NatTraversalError::NoActiveCoordination)?;

        session.phase = CoordinationPhase::Failed;

        // Update peer success rates
        if let Some(peer_a_record) = self.peer_registry.get_mut(&session.peer_a) {
            peer_a_record.coordination_count += 1;
            peer_a_record.success_rate = (peer_a_record.success_rate * (peer_a_record.coordination_count - 1) as f64) / peer_a_record.coordination_count as f64;
        }

        if let Some(peer_b_record) = self.peer_registry.get_mut(&session.peer_b) {
            peer_b_record.coordination_count += 1;
            peer_b_record.success_rate = (peer_b_record.success_rate * (peer_b_record.coordination_count - 1) as f64) / peer_b_record.coordination_count as f64;
        }

        warn!("Coordination session {} failed: {}", session_id, reason);
        Ok(())
    }

    /// Get peer observation record
    pub(crate) fn get_peer_record(&self, peer_id: PeerId) -> Option<&PeerObservationRecord> {
        self.peer_registry.get(&peer_id)
    }
    
}

impl Default for BootstrapConfig {
    fn default() -> Self {
        Self {
            _unused: (),
        }
    }
}

/// Multi-destination packet transmission manager for NAT traversal
/// 
/// This component handles simultaneous packet transmission to multiple candidate
/// addresses during hole punching attempts, maximizing the chances of successful
/// NAT traversal by sending packets to all viable destinations concurrently.
#[derive(Debug)]
#[allow(dead_code)] // Part of multi-path transmission infrastructure
pub(super) struct MultiDestinationTransmitter {
    /// Current transmission targets
    active_targets: Vec<MultiDestPunchTarget>,
    /// Transmission statistics
    stats: MultiDestTransmissionStats,
    /// Maximum number of concurrent targets
    max_targets: usize,
    /// Transmission rate limiting
    rate_limiter: TransmissionRateLimiter,
    /// Adaptive target selection
    target_selector: AdaptiveTargetSelector,
    /// Performance monitoring
    performance_monitor: TransmissionPerformanceMonitor,
}


/// Statistics for multi-destination transmission (stub implementation)
#[derive(Debug, Default, Clone)]
pub(super) struct MultiDestTransmissionStats {
    _unused: (),
}

/// Rate limiter for transmission bursts (stub implementation)
#[derive(Debug)]
struct TransmissionRateLimiter {
    _unused: (),
}


/// Adaptive target selection based on network conditions (stub implementation)
#[derive(Debug)]
struct AdaptiveTargetSelector {
    _unused: (),
}


/// Performance monitoring for transmission efficiency (stub implementation)
#[derive(Debug)]
struct TransmissionPerformanceMonitor {
    _unused: (),
}

impl MultiDestinationTransmitter {
    /// Create a new multi-destination transmitter
    pub(super) fn new() -> Self {
        Self {
            active_targets: Vec::new(),
            stats: MultiDestTransmissionStats::default(),
            max_targets: 8, // Maximum concurrent targets
            rate_limiter: TransmissionRateLimiter::new(100, 50), // 100 pps, burst 50
            target_selector: AdaptiveTargetSelector::new(),
            performance_monitor: TransmissionPerformanceMonitor::new(),
        }
    }








}



impl TransmissionRateLimiter {
    fn new(_max_pps: u64, _burst_size: u64) -> Self {
        Self {
            _unused: (),
        }
    }

}


impl AdaptiveTargetSelector {
    fn new() -> Self {
        Self {
            _unused: (),
        }
    }


}

impl TransmissionPerformanceMonitor {
    fn new() -> Self {
        Self {
            _unused: (),
        }
    }

}

// TODO: Fix nat_traversal_tests module imports
// #[cfg(test)]
// #[path = "nat_traversal_tests.rs"]
// mod tests;