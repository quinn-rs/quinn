use std::{
    collections::HashMap,
    net::SocketAddr,
    time::Duration,
};

use tracing::{trace, debug};

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
    pub(super) coordination_round: Option<VarInt>,
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
}

/// Phases of the coordination protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoordinationPhase {
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
    /// Our local address for this punch
    pub(super) local_addr: SocketAddr,
    /// Sequence number of the remote candidate
    pub(super) remote_sequence: VarInt,
    /// Challenge value for validation
    pub(super) challenge: u64,
}

/// Candidate pair for ICE-like connectivity testing
#[derive(Debug, Clone)]
pub(super) struct CandidatePair {
    /// Sequence of our local candidate
    pub(super) local_sequence: VarInt,
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
pub(super) enum PairState {
    /// Waiting to be tested
    Waiting,
    /// Currently being validated
    InProgress,
    /// Validation succeeded - this pair works
    Succeeded,
    /// Validation failed 
    Failed,
    /// Temporarily frozen (waiting for other pairs)
    Frozen,
}

/// Type classification for candidate pairs (based on ICE)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    /// Using relay servers
    Relayed,
}

/// Type of address candidate (following ICE terminology)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CandidateType {
    /// Host candidate - directly reachable local interface
    Host,
    /// Server reflexive - public address observed by STUN-like server
    ServerReflexive,
    /// Peer reflexive - address learned from incoming packets
    PeerReflexive,
    /// Relayed - address of relay server
    Relayed,
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
        CandidateType::Relayed => 0,
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
        (CandidateType::Relayed, _) | (_, CandidateType::Relayed) => PairType::Relayed,
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
#[derive(Debug, Default)]
pub(super) struct NatTraversalStats {
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
    /// Successful direct connections established
    pub(super) direct_connections: u32,
}

impl NatTraversalState {
    /// Create new NAT traversal state with given role and configuration
    pub(super) fn new(
        role: NatTraversalRole,
        max_candidates: u32,
        coordination_timeout: Duration,
    ) -> Self {
        Self {
            role,
            local_candidates: HashMap::new(),
            remote_candidates: HashMap::new(),
            candidate_pairs: Vec::new(),
            active_validations: HashMap::new(),
            coordination: None,
            next_sequence: VarInt::from_u32(1),
            max_candidates,
            coordination_timeout,
            stats: NatTraversalStats::default(),
        }
    }

    /// Add a remote candidate from AddAddress frame
    pub(super) fn add_remote_candidate(
        &mut self,
        sequence: VarInt,
        address: SocketAddr,
        priority: VarInt,
        now: Instant,
    ) -> Result<(), NatTraversalError> {
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
        
        for (local_seq, local_candidate) in &self.local_candidates {
            for (remote_seq, remote_candidate) in &self.remote_candidates {
                // Skip removed candidates
                if local_candidate.state == CandidateState::Removed 
                    || remote_candidate.state == CandidateState::Removed {
                    continue;
                }

                // Check compatibility
                if !are_candidates_compatible(local_candidate, remote_candidate) {
                    continue;
                }

                // Calculate combined priority
                let pair_priority = calculate_pair_priority(
                    local_candidate.priority, 
                    remote_candidate.priority
                );

                // Classify pair type
                let local_type = classify_candidate_type(local_candidate.source);
                let remote_type = classify_candidate_type(remote_candidate.source);
                let pair_type = classify_pair_type(local_type, remote_type);

                let pair = CandidatePair {
                    local_sequence: *local_seq,
                    remote_sequence: *remote_seq,
                    local_addr: local_candidate.address,
                    remote_addr: remote_candidate.address,
                    priority: pair_priority,
                    state: PairState::Waiting,
                    pair_type,
                    created_at: now,
                    last_check: None,
                };

                self.candidate_pairs.push(pair);
            }
        }

        // Sort pairs by priority (highest first)
        self.candidate_pairs.sort_by(|a, b| b.priority.cmp(&a.priority));

        trace!("Generated {} candidate pairs", self.candidate_pairs.len());
    }

    /// Get the highest priority pairs ready for validation
    pub(super) fn get_next_validation_pairs(&mut self, max_concurrent: usize) -> Vec<&mut CandidatePair> {
        self.candidate_pairs
            .iter_mut()
            .filter(|pair| pair.state == PairState::Waiting)
            .take(max_concurrent)
            .collect()
    }

    /// Find a candidate pair by remote address
    pub(super) fn find_pair_by_remote_addr(&mut self, addr: SocketAddr) -> Option<&mut CandidatePair> {
        self.candidate_pairs
            .iter_mut()
            .find(|pair| pair.remote_addr == addr)
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

    /// Start validation for a candidate address
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
        };

        self.active_validations.insert(candidate.address, validation);
        Ok(())
    }

    /// Handle successful validation response
    pub(super) fn handle_validation_success(
        &mut self,
        remote_addr: SocketAddr,
        challenge: u64,
    ) -> Result<VarInt, NatTraversalError> {
        // Find the candidate with this address
        let sequence = self.remote_candidates
            .iter()
            .find(|(_, c)| c.address == remote_addr)
            .map(|(seq, _)| *seq)
            .ok_or(NatTraversalError::UnknownCandidate)?;

        // Verify challenge matches
        let validation = self.active_validations.get(&remote_addr)
            .ok_or(NatTraversalError::NoActiveValidation)?;
        
        if validation.challenge != challenge {
            return Err(NatTraversalError::ChallengeMismatch);
        }

        // Update candidate state
        let candidate = self.remote_candidates.get_mut(&sequence)
            .ok_or(NatTraversalError::UnknownCandidate)?;
        
        candidate.state = CandidateState::Valid;
        self.active_validations.remove(&remote_addr);
        self.stats.validations_succeeded += 1;

        Ok(sequence)
    }

    /// Handle failed validation (timeout or error)
    pub(super) fn handle_validation_failure(
        &mut self,
        remote_addr: SocketAddr,
    ) -> Option<VarInt> {
        self.active_validations.remove(&remote_addr);
        
        // Find and mark candidate as failed
        let sequence = self.remote_candidates
            .iter_mut()
            .find(|(_, c)| c.address == remote_addr)
            .map(|(seq, candidate)| {
                candidate.state = CandidateState::Failed;
                *seq
            });

        if sequence.is_some() {
            self.stats.validations_failed += 1;
        }

        sequence
    }

    /// Get the highest priority valid candidate
    pub(super) fn get_best_candidate(&self) -> Option<(VarInt, &AddressCandidate)> {
        self.remote_candidates
            .iter()
            .filter(|(_, c)| c.state == CandidateState::Valid)
            .max_by_key(|(_, c)| c.priority)
            .map(|(k, v)| (*k, v))
    }

    /// Start a new coordination round for simultaneous hole punching
    pub(super) fn start_coordination_round(
        &mut self,
        targets: Vec<PunchTarget>,
        now: Instant,
    ) -> VarInt {
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
        });

        self.stats.coordination_rounds += 1;
        trace!("Started coordination round {} with {} targets", round, self.coordination.as_ref().unwrap().punch_targets.len());
        round
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

    /// Handle receiving peer's PUNCH_ME_NOW (via coordinator)
    pub(super) fn handle_peer_punch_request(&mut self, peer_round: VarInt, now: Instant) -> bool {
        if let Some(coord) = &mut self.coordination {
            if coord.round == peer_round && coord.state == CoordinationPhase::Coordinating {
                coord.peer_punch_received = true;
                coord.state = CoordinationPhase::Preparing;
                
                // Recalculate punch time based on when we received coordination
                let remaining_grace = Duration::from_millis(200); // 200ms remaining grace
                coord.punch_start = now + remaining_grace;
                
                trace!("Peer coordination received, punch starts in {:?}", remaining_grace);
                true
            } else {
                debug!("Received coordination for wrong round or phase: {} vs {}, {:?}", 
                       peer_round, coord.round, coord.state);
                false
            }
        } else {
            debug!("Received peer coordination but no active round");
            false
        }
    }

    /// Check if it's time to start hole punching
    pub(super) fn should_start_punching(&self, now: Instant) -> bool {
        if let Some(coord) = &self.coordination {
            coord.state == CoordinationPhase::Preparing && now >= coord.punch_start
        } else {
            false
        }
    }

    /// Start the synchronized hole punching phase
    pub(super) fn start_punching_phase(&mut self, _now: Instant) {
        if let Some(coord) = &mut self.coordination {
            coord.state = CoordinationPhase::Punching;
            trace!("Starting synchronized hole punching with {} targets", coord.punch_targets.len());
        }
    }

    /// Get punch targets for the current round
    pub(super) fn get_punch_targets(&self) -> Option<&[PunchTarget]> {
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
    pub(super) fn handle_coordination_success(&mut self, remote_addr: SocketAddr) -> bool {
        if let Some(coord) = &mut self.coordination {
            // Check if this address was one of our punch targets
            let was_target = coord.punch_targets.iter().any(|target| target.remote_addr == remote_addr);
            
            if was_target && coord.state == CoordinationPhase::Validating {
                coord.state = CoordinationPhase::Succeeded;
                self.stats.direct_connections += 1;
                trace!("Coordination succeeded via {}", remote_addr);
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
            
            if coord.retry_count < coord.max_retries {
                // Retry with next best candidates
                coord.state = CoordinationPhase::Requesting;
                coord.punch_request_sent = false;
                coord.peer_punch_received = false;
                coord.round_start = now;
                coord.punch_start = now + Duration::from_millis(500);
                
                trace!("Coordination failed, retrying round {} (attempt {})", 
                       coord.round, coord.retry_count + 1);
                true
            } else {
                coord.state = CoordinationPhase::Failed;
                trace!("Coordination failed after {} attempts", coord.retry_count);
                false
            }
        } else {
            false
        }
    }

    /// Check if the current coordination round has timed out
    pub(super) fn check_coordination_timeout(&mut self, now: Instant) -> bool {
        if let Some(coord) = &mut self.coordination {
            let elapsed = now.duration_since(coord.round_start);
            
            if elapsed > coord.round_duration {
                trace!("Coordination round {} timed out after {:?}", coord.round, elapsed);
                self.handle_coordination_failure(now);
                true
            } else {
                false
            }
        } else {
            false
        }
    }

    /// Check if coordination round has timed out
    pub(super) fn is_coordination_expired(&self, now: Instant) -> bool {
        self.coordination.as_ref()
            .map_or(false, |c| now.duration_since(c.round_start) > c.round_duration)
    }

    /// Complete coordination round
    pub(super) fn complete_coordination(&mut self) {
        self.coordination = None;
    }
}

/// Errors that can occur during NAT traversal
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatTraversalError {
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
        }
    }
}

impl std::error::Error for NatTraversalError {}