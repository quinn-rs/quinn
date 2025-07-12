//! Candidate Discovery System for QUIC NAT Traversal
//!
//! This module implements sophisticated address candidate discovery including:
//! - Local network interface enumeration (platform-specific)
//! - Server reflexive address discovery via bootstrap nodes
//! - Symmetric NAT port prediction algorithms
//! - Bootstrap node health management and consensus

use std::{
    collections::{HashMap, VecDeque},
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};

use tracing::{debug, info, warn};

use crate::{
    connection::nat_traversal::{CandidateSource, CandidateState, NatTraversalRole},
    nat_traversal_api::{BootstrapNode, CandidateAddress, PeerId},
};

// Platform-specific implementations
#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(target_os = "windows")]
pub use windows::WindowsInterfaceDiscovery;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "linux")]
pub use linux::LinuxInterfaceDiscovery;

#[cfg(target_os = "macos")]
pub(crate) mod macos;

#[cfg(target_os = "macos")]
pub(crate) use macos::MacOSInterfaceDiscovery;

/// Convert discovery source type to NAT traversal source type
fn convert_to_nat_source(discovery_source: DiscoverySourceType) -> CandidateSource {
    match discovery_source {
        DiscoverySourceType::Local => CandidateSource::Local,
        DiscoverySourceType::ServerReflexive => CandidateSource::Observed { by_node: None },
        DiscoverySourceType::Predicted => CandidateSource::Predicted,
    }
}

/// Source type used during discovery process
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoverySourceType {
    Local,
    ServerReflexive,
    Predicted,
}

/// Internal candidate type used during discovery
#[derive(Debug, Clone)]
pub(crate) struct DiscoveryCandidate {
    pub address: SocketAddr,
    pub priority: u32,
    pub source: DiscoverySourceType,
    pub state: CandidateState,
}

impl DiscoveryCandidate {
    /// Convert to external CandidateAddress
    pub(crate) fn to_candidate_address(&self) -> CandidateAddress {
        CandidateAddress {
            address: self.address,
            priority: self.priority,
            source: convert_to_nat_source(self.source),
            state: self.state,
        }
    }
}

/// Main candidate discovery manager coordinating all discovery phases
pub struct CandidateDiscoveryManager {
    /// Current discovery phase
    current_phase: DiscoveryPhase,
    /// Configuration for discovery behavior
    config: DiscoveryConfig,
    /// Platform-specific interface discovery
    interface_discovery: Box<dyn NetworkInterfaceDiscovery + Send>,
    /// Server reflexive discovery coordinator
    server_reflexive_discovery: ServerReflexiveDiscovery,
    /// Symmetric NAT prediction engine
    symmetric_predictor: SymmetricNatPredictor,
    /// Bootstrap node health manager
    bootstrap_manager: BootstrapNodeManager,
    /// Discovery result cache
    cache: DiscoveryCache,
    /// Discovery session state
    session_state: DiscoverySessionState,
}

/// Configuration for candidate discovery behavior
#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    /// Maximum time for entire discovery process
    pub total_timeout: Duration,
    /// Maximum time for local interface scanning
    pub local_scan_timeout: Duration,
    /// Timeout for individual bootstrap queries
    pub bootstrap_query_timeout: Duration,
    /// Maximum number of candidates to discover
    pub max_candidates: usize,
    /// Enable symmetric NAT prediction
    pub enable_symmetric_prediction: bool,
    /// Minimum bootstrap nodes required for consensus
    pub min_bootstrap_consensus: usize,
    /// Cache TTL for local interfaces
    pub interface_cache_ttl: Duration,
    /// Cache TTL for server reflexive addresses
    pub server_reflexive_cache_ttl: Duration,
}

/// Current phase of the discovery process
#[derive(Debug, Clone, PartialEq)]
pub enum DiscoveryPhase {
    /// Initial state, ready to begin discovery
    Idle,
    /// Scanning local network interfaces
    LocalInterfaceScanning {
        started_at: Instant,
    },
    /// Querying bootstrap nodes for server reflexive addresses
    ServerReflexiveQuerying {
        started_at: Instant,
        active_queries: HashMap<BootstrapNodeId, QueryState>,
        responses_received: Vec<ServerReflexiveResponse>,
    },
    /// Analyzing NAT behavior and predicting symmetric ports
    SymmetricNatPrediction {
        started_at: Instant,
        prediction_attempts: u32,
        pattern_analysis: PatternAnalysisState,
    },
    /// Validating discovered candidates
    CandidateValidation {
        started_at: Instant,
        validation_results: HashMap<CandidateId, ValidationResult>,
    },
    /// Discovery completed successfully
    Completed {
        final_candidates: Vec<ValidatedCandidate>,
        completion_time: Instant,
    },
    /// Discovery failed with error details
    Failed {
        error: DiscoveryError,
        failed_at: Instant,
        fallback_options: Vec<FallbackStrategy>,
    },
}

/// Events generated during candidate discovery
#[derive(Debug, Clone)]
pub enum DiscoveryEvent {
    /// Discovery process started
    DiscoveryStarted {
        peer_id: PeerId,
        bootstrap_count: usize,
    },
    /// Local interface scanning started
    LocalScanningStarted,
    /// Local candidate discovered
    LocalCandidateDiscovered {
        candidate: CandidateAddress,
    },
    /// Local interface scanning completed
    LocalScanningCompleted {
        candidate_count: usize,
        duration: Duration,
    },
    /// Server reflexive discovery started
    ServerReflexiveDiscoveryStarted {
        bootstrap_count: usize,
    },
    /// Server reflexive address discovered
    ServerReflexiveCandidateDiscovered {
        candidate: CandidateAddress,
        bootstrap_node: SocketAddr,
    },
    /// Bootstrap node query failed
    BootstrapQueryFailed {
        bootstrap_node: SocketAddr,
        error: String,
    },
    /// Symmetric NAT prediction started
    SymmetricPredictionStarted {
        base_address: SocketAddr,
    },
    /// Predicted candidate generated
    PredictedCandidateGenerated {
        candidate: CandidateAddress,
        confidence: f64,
    },
    /// Discovery completed successfully
    DiscoveryCompleted {
        candidate_count: usize,
        total_duration: Duration,
        success_rate: f64,
    },
    /// Discovery failed
    DiscoveryFailed {
        error: DiscoveryError,
        partial_results: Vec<CandidateAddress>,
    },
}

/// Unique identifier for bootstrap nodes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BootstrapNodeId(pub u64);

/// State of a bootstrap node query
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryState {
    pub started_at: Instant,
    pub timeout: Duration,
    pub retry_count: u32,
    pub last_error: Option<String>,
}

/// Response from server reflexive discovery
#[derive(Debug, Clone, PartialEq)]
pub struct ServerReflexiveResponse {
    pub bootstrap_node: BootstrapNodeId,
    pub observed_address: SocketAddr,
    pub server_address: SocketAddr,
    pub response_time: Duration,
    pub reliability_score: f64,
}

/// State for symmetric NAT pattern analysis
#[derive(Debug, Clone, PartialEq)]
pub struct PatternAnalysisState {
    pub allocation_history: VecDeque<PortAllocationEvent>,
    pub detected_pattern: Option<PortAllocationPattern>,
    pub confidence_level: f64,
    pub prediction_accuracy: f64,
}

/// Port allocation event for pattern analysis
#[derive(Debug, Clone, PartialEq)]
pub struct PortAllocationEvent {
    pub port: u16,
    pub timestamp: Instant,
    pub source_address: SocketAddr,
}

/// Detected port allocation pattern
#[derive(Debug, Clone, PartialEq)]
pub struct PortAllocationPattern {
    pub pattern_type: AllocationPatternType,
    pub base_port: u16,
    pub stride: u16,
    pub pool_boundaries: Option<(u16, u16)>,
    pub confidence: f64,
}

/// Types of port allocation patterns
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AllocationPatternType {
    /// Sequential allocation (port + 1, port + 2, ...)
    Sequential,
    /// Fixed stride allocation (port + N, port + 2N, ...)
    FixedStride,
    /// Random allocation within range
    Random,
    /// Pool-based allocation
    PoolBased,
    /// Time-based allocation
    TimeBased,
    /// Unknown/unpredictable pattern
    Unknown,
}

/// Unique identifier for candidates
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CandidateId(pub u64);

/// Result of candidate validation
#[derive(Debug, Clone, PartialEq)]
pub enum ValidationResult {
    Valid { rtt: Duration },
    Invalid { reason: String },
    Timeout,
    Pending,
}

/// Validated candidate with metadata
#[derive(Debug, Clone, PartialEq)]
pub struct ValidatedCandidate {
    pub id: CandidateId,
    pub address: SocketAddr,
    pub source: DiscoverySourceType,
    pub priority: u32,
    pub rtt: Option<Duration>,
    pub reliability_score: f64,
}

impl ValidatedCandidate {
    /// Convert to CandidateAddress with proper NAT traversal source type
    pub fn to_candidate_address(&self) -> CandidateAddress {
        CandidateAddress {
            address: self.address,
            priority: self.priority,
            source: convert_to_nat_source(self.source),
            state: CandidateState::Valid,
        }
    }
}

/// Discovery session state tracking
#[derive(Debug)]
pub(crate) struct DiscoverySessionState {
    pub peer_id: PeerId,
    pub session_id: u64,
    pub started_at: Instant,
    pub discovered_candidates: Vec<DiscoveryCandidate>,
    pub statistics: DiscoveryStatistics,
}

/// Discovery performance statistics
#[derive(Debug, Default, Clone)]
pub struct DiscoveryStatistics {
    pub local_candidates_found: u32,
    pub server_reflexive_candidates_found: u32,
    pub predicted_candidates_generated: u32,
    pub bootstrap_queries_sent: u32,
    pub bootstrap_queries_successful: u32,
    pub total_discovery_time: Option<Duration>,
    pub average_bootstrap_rtt: Option<Duration>,
}

/// Errors that can occur during discovery
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoveryError {
    /// No local interfaces found
    NoLocalInterfaces,
    /// All bootstrap node queries failed
    AllBootstrapsFailed,
    /// Discovery timeout exceeded
    DiscoveryTimeout,
    /// Insufficient candidates discovered
    InsufficientCandidates { found: usize, required: usize },
    /// Platform-specific network error
    NetworkError(String),
    /// Configuration error
    ConfigurationError(String),
    /// Internal system error
    InternalError(String),
}

/// Fallback strategies when discovery fails
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FallbackStrategy {
    /// Use cached results from previous discovery
    UseCachedResults,
    /// Retry with relaxed parameters
    RetryWithRelaxedParams,
    /// Use minimal candidate set
    UseMinimalCandidates,
    /// Enable relay-based fallback
    EnableRelayFallback,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            total_timeout: Duration::from_secs(30),
            local_scan_timeout: Duration::from_secs(2),
            bootstrap_query_timeout: Duration::from_secs(5),
            max_candidates: 8,
            enable_symmetric_prediction: true,
            min_bootstrap_consensus: 2,
            interface_cache_ttl: Duration::from_secs(60),
            server_reflexive_cache_ttl: Duration::from_secs(300),
        }
    }
}

impl CandidateDiscoveryManager {
    /// Create a new candidate discovery manager
    pub fn new(config: DiscoveryConfig, _role: NatTraversalRole) -> Self {
        let interface_discovery = create_platform_interface_discovery();
        let server_reflexive_discovery = ServerReflexiveDiscovery::new(&config);
        let symmetric_predictor = SymmetricNatPredictor::new(&config);
        let bootstrap_manager = BootstrapNodeManager::new(&config);
        let cache = DiscoveryCache::new(&config);

        Self {
            current_phase: DiscoveryPhase::Idle,
            config,
            interface_discovery,
            server_reflexive_discovery,
            symmetric_predictor,
            bootstrap_manager,
            cache,
            session_state: DiscoverySessionState {
                peer_id: PeerId([0; 32]), // Will be set when discovery starts
                session_id: 0,
                started_at: Instant::now(),
                discovered_candidates: Vec::new(),
                statistics: DiscoveryStatistics::default(),
            },
        }
    }

    /// Start candidate discovery for a specific peer
    pub fn start_discovery(&mut self, peer_id: PeerId, bootstrap_nodes: Vec<BootstrapNode>) -> Result<(), DiscoveryError> {
        if !matches!(self.current_phase, DiscoveryPhase::Idle | DiscoveryPhase::Failed { .. } | DiscoveryPhase::Completed { .. }) {
            return Err(DiscoveryError::InternalError("Discovery already in progress".to_string()));
        }

        info!("Starting candidate discovery for peer {:?}", peer_id);

        // Initialize session state
        self.session_state.peer_id = peer_id;
        self.session_state.session_id = rand::random();
        self.session_state.started_at = Instant::now();
        self.session_state.discovered_candidates.clear();
        self.session_state.statistics = DiscoveryStatistics::default();

        // Update bootstrap node manager
        self.bootstrap_manager.update_bootstrap_nodes(bootstrap_nodes);

        // Start with local interface scanning
        self.current_phase = DiscoveryPhase::LocalInterfaceScanning {
            started_at: Instant::now(),
        };

        Ok(())
    }

    /// Poll for discovery progress and state updates
    pub fn poll(&mut self, now: Instant) -> Vec<DiscoveryEvent> {
        let mut events = Vec::new();

        // Check for overall timeout
        if self.session_state.started_at.elapsed() > self.config.total_timeout {
            self.handle_discovery_timeout(&mut events, now);
            return events;
        }

        match &self.current_phase.clone() {
            DiscoveryPhase::Idle => {
                // Nothing to do in idle state
            },

            DiscoveryPhase::LocalInterfaceScanning { started_at } => {
                self.poll_local_interface_scanning(*started_at, now, &mut events);
            },

            DiscoveryPhase::ServerReflexiveQuerying { started_at, active_queries, responses_received } => {
                self.poll_server_reflexive_discovery(*started_at, active_queries, responses_received, now, &mut events);
            },

            DiscoveryPhase::SymmetricNatPrediction { started_at, prediction_attempts, pattern_analysis } => {
                self.poll_symmetric_prediction(*started_at, *prediction_attempts, pattern_analysis, now, &mut events);
            },

            DiscoveryPhase::CandidateValidation { started_at, validation_results } => {
                self.poll_candidate_validation(*started_at, validation_results, now, &mut events);
            },

            DiscoveryPhase::Completed { .. } | DiscoveryPhase::Failed { .. } => {
                // Discovery is finished, no further polling needed
            },
        }

        events
    }

    /// Get current discovery status
    pub fn get_status(&self) -> DiscoveryStatus {
        DiscoveryStatus {
            phase: self.current_phase.clone(),
            discovered_candidates: self.session_state.discovered_candidates.iter()
                .map(|c| c.to_candidate_address())
                .collect(),
            statistics: self.session_state.statistics.clone(),
            elapsed_time: self.session_state.started_at.elapsed(),
        }
    }

    /// Check if discovery is complete
    pub fn is_complete(&self) -> bool {
        matches!(self.current_phase, DiscoveryPhase::Completed { .. } | DiscoveryPhase::Failed { .. })
    }

    /// Get final discovery results
    pub fn get_results(&self) -> Option<DiscoveryResults> {
        match &self.current_phase {
            DiscoveryPhase::Completed { final_candidates, completion_time } => {
                Some(DiscoveryResults {
                    candidates: final_candidates.clone(),
                    completion_time: *completion_time,
                    statistics: self.session_state.statistics.clone(),
                })
            },
            DiscoveryPhase::Failed { .. } => {
                Some(DiscoveryResults {
                    candidates: Vec::new(),
                    completion_time: Instant::now(),
                    statistics: self.session_state.statistics.clone(),
                })
            },
            _ => None,
        }
    }

    // Private implementation methods

    fn poll_local_interface_scanning(&mut self, started_at: Instant, now: Instant, events: &mut Vec<DiscoveryEvent>) {
        // Check for timeout
        if started_at.elapsed() > self.config.local_scan_timeout {
            warn!("Local interface scanning timeout");
            self.handle_local_scan_timeout(events, now);
            return;
        }

        // Check if scanning is complete
        if let Some(interfaces) = self.interface_discovery.check_scan_complete() {
            self.process_local_interfaces(interfaces, events, now);
        }
    }

    fn process_local_interfaces(&mut self, interfaces: Vec<NetworkInterface>, events: &mut Vec<DiscoveryEvent>, now: Instant) {
        debug!("Processing {} network interfaces", interfaces.len());

        for interface in interfaces {
            for address in &interface.addresses {
                if self.is_valid_local_address(&address) {
                    let candidate = DiscoveryCandidate {
                        address: *address,
                        priority: self.calculate_local_priority(address, &interface),
                        source: DiscoverySourceType::Local,
                        state: CandidateState::New,
                    };

                    self.session_state.discovered_candidates.push(candidate.clone());
                    self.session_state.statistics.local_candidates_found += 1;

                    events.push(DiscoveryEvent::LocalCandidateDiscovered { 
                        candidate: candidate.to_candidate_address() 
                    });
                }
            }
        }

        events.push(DiscoveryEvent::LocalScanningCompleted {
            candidate_count: self.session_state.statistics.local_candidates_found as usize,
            duration: now.duration_since(self.session_state.started_at),
        });

        // Transition to server reflexive discovery
        self.start_server_reflexive_discovery(events, now);
    }

    fn start_server_reflexive_discovery(&mut self, events: &mut Vec<DiscoveryEvent>, now: Instant) {
        let bootstrap_nodes = self.bootstrap_manager.get_active_bootstrap_nodes();
        
        if bootstrap_nodes.is_empty() {
            warn!("No bootstrap nodes available for server reflexive discovery");
            self.handle_no_bootstrap_nodes(events, now);
            return;
        }

        let active_queries = self.server_reflexive_discovery.start_queries(&bootstrap_nodes, now);

        events.push(DiscoveryEvent::ServerReflexiveDiscoveryStarted {
            bootstrap_count: bootstrap_nodes.len(),
        });

        self.current_phase = DiscoveryPhase::ServerReflexiveQuerying {
            started_at: now,
            active_queries,
            responses_received: Vec::new(),
        };
    }

    fn poll_server_reflexive_discovery(
        &mut self,
        started_at: Instant,
        active_queries: &HashMap<BootstrapNodeId, QueryState>,
        responses_received: &Vec<ServerReflexiveResponse>,
        now: Instant,
        events: &mut Vec<DiscoveryEvent>
    ) {
        // Check for new responses
        let new_responses = self.server_reflexive_discovery.poll_queries(active_queries, now);
        
        let mut updated_responses = responses_received.clone();
        for response in new_responses {
            self.process_server_reflexive_response(&response, events);
            updated_responses.push(response);
        }

        // Check if we should transition to next phase
        if self.should_transition_to_prediction(&updated_responses, now) {
            self.start_symmetric_prediction(&updated_responses, events, now);
        } else if started_at.elapsed() > self.config.bootstrap_query_timeout * 2 {
            // Timeout for server reflexive discovery
            if updated_responses.len() >= self.config.min_bootstrap_consensus {
                self.start_symmetric_prediction(&updated_responses, events, now);
            } else {
                self.handle_insufficient_bootstrap_responses(events, now);
            }
        } else {
            // Update the phase with new responses
            self.current_phase = DiscoveryPhase::ServerReflexiveQuerying {
                started_at,
                active_queries: active_queries.clone(),
                responses_received: updated_responses,
            };
        }
    }

    fn process_server_reflexive_response(&mut self, response: &ServerReflexiveResponse, events: &mut Vec<DiscoveryEvent>) {
        debug!("Received server reflexive response: {:?}", response);

        let candidate = DiscoveryCandidate {
            address: response.observed_address,
            priority: self.calculate_server_reflexive_priority(response),
            source: DiscoverySourceType::ServerReflexive,
            state: CandidateState::New,
        };

        self.session_state.discovered_candidates.push(candidate.clone());
        self.session_state.statistics.server_reflexive_candidates_found += 1;

        events.push(DiscoveryEvent::ServerReflexiveCandidateDiscovered {
            candidate: candidate.to_candidate_address(),
            bootstrap_node: self.bootstrap_manager.get_bootstrap_address(response.bootstrap_node).unwrap_or_else(|| "unknown".parse().unwrap()),
        });
    }

    fn start_symmetric_prediction(&mut self, responses: &[ServerReflexiveResponse], events: &mut Vec<DiscoveryEvent>, now: Instant) {
        if !self.config.enable_symmetric_prediction || responses.is_empty() {
            self.start_candidate_validation(events, now);
            return;
        }

        // Use consensus address as base for prediction
        let base_address = self.calculate_consensus_address(responses);
        
        events.push(DiscoveryEvent::SymmetricPredictionStarted { base_address });

        self.current_phase = DiscoveryPhase::SymmetricNatPrediction {
            started_at: now,
            prediction_attempts: 0,
            pattern_analysis: PatternAnalysisState {
                allocation_history: VecDeque::new(),
                detected_pattern: None,
                confidence_level: 0.0,
                prediction_accuracy: 0.0,
            },
        };
    }

    fn poll_symmetric_prediction(
        &mut self,
        _started_at: Instant,
        _prediction_attempts: u32,
        pattern_analysis: &PatternAnalysisState,
        now: Instant,
        events: &mut Vec<DiscoveryEvent>
    ) {
        // Generate predicted candidates
        let predicted_candidates = self.symmetric_predictor.generate_predictions(pattern_analysis, self.config.max_candidates - self.session_state.discovered_candidates.len());

        for candidate in predicted_candidates {
            self.session_state.discovered_candidates.push(candidate.clone());
            self.session_state.statistics.predicted_candidates_generated += 1;

            events.push(DiscoveryEvent::PredictedCandidateGenerated {
                candidate: candidate.to_candidate_address(),
                confidence: pattern_analysis.confidence_level,
            });
        }

        // Transition to validation phase
        self.start_candidate_validation(events, now);
    }

    fn start_candidate_validation(&mut self, _events: &mut Vec<DiscoveryEvent>, now: Instant) {
        debug!("Starting candidate validation for {} candidates", self.session_state.discovered_candidates.len());

        self.current_phase = DiscoveryPhase::CandidateValidation {
            started_at: now,
            validation_results: HashMap::new(),
        };
    }

    fn poll_candidate_validation(
        &mut self,
        _started_at: Instant,
        _validation_results: &HashMap<CandidateId, ValidationResult>,
        now: Instant,
        events: &mut Vec<DiscoveryEvent>
    ) {
        // For now, mark all candidates as valid (actual validation would involve PATH_CHALLENGE/RESPONSE)
        let validated_candidates: Vec<ValidatedCandidate> = self.session_state.discovered_candidates
            .iter()
            .enumerate()
            .map(|(i, candidate)| ValidatedCandidate {
                id: CandidateId(i as u64),
                address: candidate.address,
                source: candidate.source,
                priority: candidate.priority,
                rtt: Some(Duration::from_millis(50)), // Placeholder
                reliability_score: 0.8, // Placeholder
            })
            .collect();

        self.complete_discovery(validated_candidates, events, now);
    }

    fn complete_discovery(&mut self, candidates: Vec<ValidatedCandidate>, events: &mut Vec<DiscoveryEvent>, now: Instant) {
        let total_duration = now.duration_since(self.session_state.started_at);
        self.session_state.statistics.total_discovery_time = Some(total_duration);

        let success_rate = if self.session_state.statistics.bootstrap_queries_sent > 0 {
            self.session_state.statistics.bootstrap_queries_successful as f64 / self.session_state.statistics.bootstrap_queries_sent as f64
        } else {
            1.0
        };

        events.push(DiscoveryEvent::DiscoveryCompleted {
            candidate_count: candidates.len(),
            total_duration,
            success_rate,
        });

        self.current_phase = DiscoveryPhase::Completed {
            final_candidates: candidates,
            completion_time: now,
        };

        info!("Candidate discovery completed successfully in {:?}", total_duration);
    }

    // Helper methods

    fn handle_discovery_timeout(&mut self, events: &mut Vec<DiscoveryEvent>, now: Instant) {
        let error = DiscoveryError::DiscoveryTimeout;
        events.push(DiscoveryEvent::DiscoveryFailed {
            error: error.clone(),
            partial_results: self.session_state.discovered_candidates.iter()
                .map(|c| c.to_candidate_address())
                .collect(),
        });

        self.current_phase = DiscoveryPhase::Failed {
            error,
            failed_at: now,
            fallback_options: vec![FallbackStrategy::UseCachedResults, FallbackStrategy::UseMinimalCandidates],
        };
    }

    fn handle_local_scan_timeout(&mut self, events: &mut Vec<DiscoveryEvent>, now: Instant) {
        warn!("Local interface scan timeout, proceeding with available candidates");
        
        events.push(DiscoveryEvent::LocalScanningCompleted {
            candidate_count: self.session_state.statistics.local_candidates_found as usize,
            duration: now.duration_since(self.session_state.started_at),
        });

        self.start_server_reflexive_discovery(events, now);
    }

    fn handle_no_bootstrap_nodes(&mut self, events: &mut Vec<DiscoveryEvent>, now: Instant) {
        let error = DiscoveryError::AllBootstrapsFailed;
        events.push(DiscoveryEvent::DiscoveryFailed {
            error: error.clone(),
            partial_results: self.session_state.discovered_candidates.iter()
                .map(|c| c.to_candidate_address())
                .collect(),
        });

        self.current_phase = DiscoveryPhase::Failed {
            error,
            failed_at: now,
            fallback_options: vec![FallbackStrategy::UseMinimalCandidates],
        };
    }

    fn handle_insufficient_bootstrap_responses(&mut self, events: &mut Vec<DiscoveryEvent>, now: Instant) {
        warn!("Insufficient bootstrap responses, proceeding with available data");
        self.start_candidate_validation(events, now);
    }

    fn is_valid_local_address(&self, address: &SocketAddr) -> bool {
        match address.ip() {
            IpAddr::V4(ipv4) => !ipv4.is_loopback() && !ipv4.is_unspecified(),
            IpAddr::V6(ipv6) => !ipv6.is_loopback() && !ipv6.is_unspecified(),
        }
    }

    fn calculate_local_priority(&self, address: &SocketAddr, interface: &NetworkInterface) -> u32 {
        let mut priority = 100; // Base priority

        match address.ip() {
            IpAddr::V4(ipv4) => {
                if ipv4.is_private() {
                    priority += 50; // Prefer private addresses for local networks
                }
            },
            IpAddr::V6(_) => {
                priority += 30; // IPv6 gets moderate priority
            },
        }

        if interface.is_wireless {
            priority -= 10; // Slight penalty for wireless
        }

        priority
    }

    fn calculate_server_reflexive_priority(&self, response: &ServerReflexiveResponse) -> u32 {
        let mut priority = 200; // Base priority for server reflexive

        // Adjust based on response time
        if response.response_time < Duration::from_millis(50) {
            priority += 20;
        } else if response.response_time > Duration::from_millis(200) {
            priority -= 10;
        }

        // Adjust based on reliability score
        priority += (response.reliability_score * 50.0) as u32;

        priority
    }

    fn should_transition_to_prediction(&self, responses: &[ServerReflexiveResponse], _now: Instant) -> bool {
        responses.len() >= self.config.min_bootstrap_consensus.max(1)
    }

    fn calculate_consensus_address(&self, responses: &[ServerReflexiveResponse]) -> SocketAddr {
        // Simple majority consensus - in practice, would use more sophisticated algorithm
        let mut address_counts: HashMap<SocketAddr, usize> = HashMap::new();
        
        for response in responses {
            *address_counts.entry(response.observed_address).or_insert(0) += 1;
        }

        address_counts
            .into_iter()
            .max_by_key(|(_, count)| *count)
            .map(|(addr, _)| addr)
            .unwrap_or_else(|| "0.0.0.0:0".parse().unwrap())
    }
}

/// Current status of candidate discovery
#[derive(Debug, Clone)]
pub struct DiscoveryStatus {
    pub phase: DiscoveryPhase,
    pub discovered_candidates: Vec<CandidateAddress>,
    pub statistics: DiscoveryStatistics,
    pub elapsed_time: Duration,
}

/// Final results of candidate discovery
#[derive(Debug, Clone)]
pub struct DiscoveryResults {
    pub candidates: Vec<ValidatedCandidate>,
    pub completion_time: Instant,
    pub statistics: DiscoveryStatistics,
}

// Placeholder implementations for components to be implemented

/// Platform-specific network interface discovery
pub(crate) trait NetworkInterfaceDiscovery {
    fn start_scan(&mut self) -> Result<(), String>;
    fn check_scan_complete(&mut self) -> Option<Vec<NetworkInterface>>;
}

/// Network interface information
#[derive(Debug, Clone, PartialEq)]
pub struct NetworkInterface {
    pub name: String,
    pub addresses: Vec<SocketAddr>,
    pub is_up: bool,
    pub is_wireless: bool,
    pub mtu: Option<u16>,
}

/// Server reflexive address discovery coordinator
#[derive(Debug)]
pub(crate) struct ServerReflexiveDiscovery {
    config: DiscoveryConfig,
}

impl ServerReflexiveDiscovery {
    pub(crate) fn new(config: &DiscoveryConfig) -> Self {
        Self {
            config: config.clone(),
        }
    }

    pub(crate) fn start_queries(&mut self, _bootstrap_nodes: &[BootstrapNodeId], _now: Instant) -> HashMap<BootstrapNodeId, QueryState> {
        // Placeholder implementation
        HashMap::new()
    }

    pub(crate) fn poll_queries(&mut self, _active_queries: &HashMap<BootstrapNodeId, QueryState>, _now: Instant) -> Vec<ServerReflexiveResponse> {
        // Placeholder implementation
        Vec::new()
    }
}

/// Symmetric NAT port prediction engine
#[derive(Debug)]
pub(crate) struct SymmetricNatPredictor {
    config: DiscoveryConfig,
}

impl SymmetricNatPredictor {
    pub(crate) fn new(config: &DiscoveryConfig) -> Self {
        Self {
            config: config.clone(),
        }
    }

    pub(crate) fn generate_predictions(&mut self, _pattern_analysis: &PatternAnalysisState, _max_count: usize) -> Vec<DiscoveryCandidate> {
        // Placeholder implementation
        Vec::new()
    }
}

/// Bootstrap node health manager
#[derive(Debug)]
pub(crate) struct BootstrapNodeManager {
    config: DiscoveryConfig,
    bootstrap_nodes: HashMap<BootstrapNodeId, BootstrapNode>,
}

impl BootstrapNodeManager {
    pub(crate) fn new(config: &DiscoveryConfig) -> Self {
        Self {
            config: config.clone(),
            bootstrap_nodes: HashMap::new(),
        }
    }

    pub(crate) fn update_bootstrap_nodes(&mut self, nodes: Vec<BootstrapNode>) {
        // Placeholder implementation
        self.bootstrap_nodes.clear();
        for (i, node) in nodes.into_iter().enumerate() {
            self.bootstrap_nodes.insert(BootstrapNodeId(i as u64), node);
        }
    }

    pub(crate) fn get_active_bootstrap_nodes(&self) -> Vec<BootstrapNodeId> {
        self.bootstrap_nodes.keys().copied().collect()
    }

    pub(crate) fn get_bootstrap_address(&self, id: BootstrapNodeId) -> Option<SocketAddr> {
        self.bootstrap_nodes.get(&id).map(|node| node.address)
    }
}

/// Discovery result cache
#[derive(Debug)]
pub(crate) struct DiscoveryCache {
    config: DiscoveryConfig,
}

impl DiscoveryCache {
    pub(crate) fn new(config: &DiscoveryConfig) -> Self {
        Self {
            config: config.clone(),
        }
    }
}

/// Create platform-specific network interface discovery
pub(crate) fn create_platform_interface_discovery() -> Box<dyn NetworkInterfaceDiscovery + Send> {
    #[cfg(target_os = "windows")]
    return Box::new(WindowsInterfaceDiscovery::new());
    
    #[cfg(target_os = "linux")]
    return Box::new(LinuxInterfaceDiscovery::new());
    
    #[cfg(target_os = "macos")]
    return Box::new(MacOSInterfaceDiscovery::new());
    
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    return Box::new(GenericInterfaceDiscovery::new());
}

// Platform-specific implementations

// Windows implementation is in windows.rs module

// Linux implementation is in linux.rs module

// macOS implementation is in macos.rs module

// Generic fallback implementation
pub(crate) struct GenericInterfaceDiscovery {
    scan_complete: bool,
}

impl GenericInterfaceDiscovery {
    pub(crate) fn new() -> Self {
        Self { scan_complete: false }
    }
}

impl NetworkInterfaceDiscovery for GenericInterfaceDiscovery {
    fn start_scan(&mut self) -> Result<(), String> {
        // Generic implementation using standard library
        self.scan_complete = true;
        Ok(())
    }

    fn check_scan_complete(&mut self) -> Option<Vec<NetworkInterface>> {
        if self.scan_complete {
            self.scan_complete = false;
            Some(vec![
                NetworkInterface {
                    name: "generic".to_string(),
                    addresses: vec!["127.0.0.1:0".parse().unwrap()],
                    is_up: true,
                    is_wireless: false,
                    mtu: Some(1500),
                }
            ])
        } else {
            None
        }
    }
}

impl std::fmt::Display for DiscoveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoLocalInterfaces => write!(f, "no local network interfaces found"),
            Self::AllBootstrapsFailed => write!(f, "all bootstrap node queries failed"),
            Self::DiscoveryTimeout => write!(f, "discovery process timed out"),
            Self::InsufficientCandidates { found, required } => write!(f, "insufficient candidates found: {} < {}", found, required),
            Self::NetworkError(msg) => write!(f, "network error: {}", msg),
            Self::ConfigurationError(msg) => write!(f, "configuration error: {}", msg),
            Self::InternalError(msg) => write!(f, "internal error: {}", msg),
        }
    }
}

impl std::error::Error for DiscoveryError {}