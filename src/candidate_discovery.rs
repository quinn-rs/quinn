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

#[cfg(feature = "production-ready")]
use crate::Connection;

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
    /// Maximum number of query retries per bootstrap node
    pub max_query_retries: u32,
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
    /// Port allocation pattern detected
    PortAllocationDetected {
        port: u16,
        source_address: SocketAddr,
        bootstrap_node: BootstrapNodeId,
        timestamp: Instant,
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
pub enum QueryState {
    /// Query is pending (in progress)
    Pending {
        sent_at: Instant,
        attempts: u32,
    },
    /// Query completed successfully
    Completed,
    /// Query failed after all retries
    Failed,
}

/// Response from server reflexive discovery
#[derive(Debug, Clone, PartialEq)]
pub struct ServerReflexiveResponse {
    pub bootstrap_node: BootstrapNodeId,
    pub observed_address: SocketAddr,
    pub response_time: Duration,
    pub timestamp: Instant,
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
    pub allocation_history: VecDeque<PortAllocationEvent>,
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
            max_query_retries: 3,
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
    pub fn new(config: DiscoveryConfig) -> Self {
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
                allocation_history: VecDeque::new(),
            },
        }
    }

    /// Discover local network interface candidates synchronously
    pub fn discover_local_candidates(&mut self) -> Result<Vec<ValidatedCandidate>, DiscoveryError> {
        // Start interface scan
        self.interface_discovery.start_scan().map_err(|e| {
            DiscoveryError::NetworkError(format!("Failed to start interface scan: {}", e))
        })?;
        
        // Poll until scan completes (this should be quick for local interfaces)
        let start = Instant::now();
        let timeout = Duration::from_secs(2);
        
        loop {
            if start.elapsed() > timeout {
                return Err(DiscoveryError::DiscoveryTimeout);
            }
            
            if let Some(interfaces) = self.interface_discovery.check_scan_complete() {
                // Convert interfaces to candidates
                let mut candidates = Vec::new();
                
                for interface in interfaces {
                    for addr in interface.addresses {
                        candidates.push(ValidatedCandidate {
                            id: CandidateId(rand::random()),
                            address: addr,
                            source: DiscoverySourceType::Local,
                            priority: 50000, // High priority for local interfaces
                            rtt: None,
                            reliability_score: 1.0,
                        });
                    }
                }
                
                if candidates.is_empty() {
                    return Err(DiscoveryError::NoLocalInterfaces);
                }
                
                return Ok(candidates);
            }
            
            // Small sleep to avoid busy waiting
            std::thread::sleep(Duration::from_millis(10));
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

    /// Get all discovered candidates for a specific peer
    pub fn get_candidates_for_peer(&self, peer_id: PeerId) -> Vec<CandidateAddress> {
        // Check if this is the peer we're currently discovering for
        if self.session_state.peer_id == peer_id {
            // Return all discovered candidates converted to CandidateAddress
            self.session_state.discovered_candidates.iter()
                .map(|c| c.to_candidate_address())
                .collect()
        } else {
            // If this is not the current peer, we might want to look in cache
            // For now, return empty vec
            debug!("No candidates found for peer {:?} (current session is for {:?})", 
                   peer_id, self.session_state.peer_id);
            Vec::new()
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
        let bootstrap_node_ids = self.bootstrap_manager.get_active_bootstrap_nodes();
        
        if bootstrap_node_ids.is_empty() {
            warn!("No bootstrap nodes available for server reflexive discovery");
            self.handle_no_bootstrap_nodes(events, now);
            return;
        }

        // Get bootstrap node addresses for real QUIC communication
        let bootstrap_nodes_with_addresses: Vec<(BootstrapNodeId, SocketAddr)> = bootstrap_node_ids
            .iter()
            .filter_map(|&node_id| {
                self.bootstrap_manager.get_bootstrap_address(node_id)
                    .map(|addr| (node_id, addr))
            })
            .collect();

        if bootstrap_nodes_with_addresses.is_empty() {
            warn!("No bootstrap node addresses available for server reflexive discovery");
            self.handle_no_bootstrap_nodes(events, now);
            return;
        }

        // Use the enhanced method that includes addresses for real QUIC communication
        let active_queries = self.server_reflexive_discovery.start_queries_with_addresses(&bootstrap_nodes_with_addresses, now);

        events.push(DiscoveryEvent::ServerReflexiveDiscoveryStarted {
            bootstrap_count: bootstrap_nodes_with_addresses.len(),
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

        // Record port allocation event for pattern analysis
        let allocation_event = PortAllocationEvent {
            port: response.observed_address.port(),
            timestamp: response.timestamp,
            source_address: response.observed_address,
        };

        // Add to allocation history for pattern analysis
        if let DiscoveryPhase::ServerReflexiveQuerying { .. } = &mut self.current_phase {
            // We'll need to track allocation history in session state
            // For now, update session state to track this information
            self.session_state.allocation_history.push_back(allocation_event.clone());
            
            // Keep only recent allocations (last 20) to avoid unbounded growth
            if self.session_state.allocation_history.len() > 20 {
                self.session_state.allocation_history.pop_front();
            }
        }

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

        events.push(DiscoveryEvent::PortAllocationDetected {
            port: allocation_event.port,
            source_address: allocation_event.source_address,
            bootstrap_node: response.bootstrap_node,
            timestamp: allocation_event.timestamp,
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

        // Analyze allocation patterns from collected history
        let detected_pattern = self.symmetric_predictor.analyze_allocation_patterns(&self.session_state.allocation_history);
        
        let confidence_level = detected_pattern.as_ref().map(|p| p.confidence).unwrap_or(0.0);

        // Calculate prediction accuracy based on pattern consistency
        let prediction_accuracy = if let Some(ref pattern) = detected_pattern {
            self.calculate_prediction_accuracy(pattern, &self.session_state.allocation_history)
        } else {
            0.3 // Default accuracy for heuristic predictions
        };

        debug!("Symmetric NAT pattern analysis: detected_pattern={:?}, confidence={:.2}, accuracy={:.2}",
               detected_pattern, confidence_level, prediction_accuracy);

        self.current_phase = DiscoveryPhase::SymmetricNatPrediction {
            started_at: now,
            prediction_attempts: 0,
            pattern_analysis: PatternAnalysisState {
                allocation_history: self.session_state.allocation_history.clone(),
                detected_pattern,
                confidence_level,
                prediction_accuracy,
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
        started_at: Instant,
        validation_results: &HashMap<CandidateId, ValidationResult>,
        now: Instant,
        events: &mut Vec<DiscoveryEvent>
    ) {
        // Check for validation timeout
        if started_at.elapsed() > Duration::from_secs(10) {
            // Complete validation with current results
            self.complete_validation_with_results(validation_results, events, now);
            return;
        }

        // Start validation for candidates that haven't been validated yet
        let mut updated_results = validation_results.clone();
        let mut validation_started = false;

        // Collect candidates to validate to avoid borrowing issues
        let candidates_to_validate: Vec<(CandidateId, SocketAddr)> = self.session_state
            .discovered_candidates
            .iter()
            .enumerate()
            .filter_map(|(i, candidate)| {
                let candidate_id = CandidateId(i as u64);
                if !updated_results.contains_key(&candidate_id) {
                    Some((candidate_id, candidate.address))
                } else {
                    None
                }
            })
            .collect();

        // Now validate the collected candidates
        for (candidate_id, address) in candidates_to_validate {
            updated_results.insert(candidate_id, ValidationResult::Pending);
            validation_started = true;
            
            debug!("Starting validation for candidate {}: {}", candidate_id.0, address);
            
            #[cfg(feature = "production-ready")]
            {
                // Start real QUIC PATH_CHALLENGE/PATH_RESPONSE validation
                self.start_path_validation(candidate_id, address, now);
            }
            
            #[cfg(not(feature = "production-ready"))]
            {
                // Simulate validation in development builds
                self.simulate_path_validation(candidate_id, address, now);
            }
        }

        // Check for completed validations
        let completed_validations = self.check_validation_completions(&updated_results, now);
        for (candidate_id, result) in completed_validations {
            updated_results.insert(candidate_id, result);
        }

        // Check if all validations are complete
        let all_complete = updated_results.values().all(|result| {
            !matches!(result, ValidationResult::Pending)
        });

        if all_complete || validation_started {
            // Update the phase with new validation results
            self.current_phase = DiscoveryPhase::CandidateValidation {
                started_at,
                validation_results: updated_results.clone(),
            };
        }

        if all_complete {
            self.complete_validation_with_results(&updated_results, events, now);
        }
    }

    /// Start real QUIC PATH_CHALLENGE/PATH_RESPONSE validation for a candidate
    #[cfg(feature = "production-ready")]
    fn start_path_validation(&mut self, candidate_id: CandidateId, candidate_address: SocketAddr, _now: Instant) {
        debug!("Starting QUIC path validation for candidate {} at {}", candidate_id.0, candidate_address);
        
        // In a complete implementation, this would:
        // 1. Create a temporary QUIC endpoint
        // 2. Send PATH_CHALLENGE frame to the candidate address
        // 3. Wait for PATH_RESPONSE frame
        // 4. Measure RTT and validate the response
        
        // For now, we'll simulate the validation process
        // TODO: Implement real QUIC path validation
        self.simulate_path_validation(candidate_id, candidate_address, _now);
    }

    /// Simulate path validation for development/testing
    fn simulate_path_validation(&mut self, candidate_id: CandidateId, candidate_address: SocketAddr, _now: Instant) {
        // Simulate different validation outcomes based on address characteristics
        let is_local = candidate_address.ip().is_loopback() || 
                      (candidate_address.ip().is_ipv4() && candidate_address.ip().to_string().starts_with("192.168.")) ||
                      (candidate_address.ip().is_ipv4() && candidate_address.ip().to_string().starts_with("10.")) ||
                      (candidate_address.ip().is_ipv4() && candidate_address.ip().to_string().starts_with("172."));
        
        let is_server_reflexive = !is_local && !candidate_address.ip().is_unspecified();
        
        // Store validation result for later retrieval
        // In a real implementation, this would be stored in a validation state tracker
        debug!("Simulated path validation for candidate {} at {} - local: {}, server_reflexive: {}", 
               candidate_id.0, candidate_address, is_local, is_server_reflexive);
    }

    /// Check for completed path validations
    fn check_validation_completions(&self, current_results: &HashMap<CandidateId, ValidationResult>, _now: Instant) -> Vec<(CandidateId, ValidationResult)> {
        let mut completions = Vec::new();
        
        for (candidate_id, result) in current_results {
            if matches!(result, ValidationResult::Pending) {
                // Simulate completion based on candidate characteristics
                if let Some(candidate) = self.session_state.discovered_candidates.get(candidate_id.0 as usize) {
                    let validation_result = self.simulate_validation_result(&candidate.address);
                    completions.push((*candidate_id, validation_result));
                }
            }
        }
        
        completions
    }

    /// Simulate validation result based on address characteristics
    fn simulate_validation_result(&self, address: &SocketAddr) -> ValidationResult {
        let is_local = address.ip().is_loopback() || 
                      (address.ip().is_ipv4() && address.ip().to_string().starts_with("192.168.")) ||
                      (address.ip().is_ipv4() && address.ip().to_string().starts_with("10.")) ||
                      (address.ip().is_ipv4() && address.ip().to_string().starts_with("172."));
        
        if is_local {
            // Local addresses typically validate quickly
            ValidationResult::Valid { rtt: Duration::from_millis(1) }
        } else if address.ip().is_unspecified() {
            // Unspecified addresses are invalid
            ValidationResult::Invalid { reason: "Unspecified address".to_string() }
        } else {
            // Server reflexive addresses have higher RTT
            ValidationResult::Valid { rtt: Duration::from_millis(50 + (address.port() % 100) as u64) }
        }
    }

    /// Complete validation with current results
    fn complete_validation_with_results(
        &mut self, 
        validation_results: &HashMap<CandidateId, ValidationResult>, 
        events: &mut Vec<DiscoveryEvent>, 
        now: Instant
    ) {
        let validated_candidates: Vec<ValidatedCandidate> = self.session_state.discovered_candidates
            .iter()
            .enumerate()
            .filter_map(|(i, candidate)| {
                let candidate_id = CandidateId(i as u64);
                validation_results.get(&candidate_id).and_then(|result| {
                    match result {
                        ValidationResult::Valid { rtt } => {
                            Some(ValidatedCandidate {
                                id: candidate_id,
                                address: candidate.address,
                                source: candidate.source,
                                priority: candidate.priority,
                                rtt: Some(*rtt),
                                reliability_score: self.calculate_reliability_score(candidate, *rtt),
                            })
                        }
                        ValidationResult::Invalid { reason } => {
                            debug!("Candidate {} at {} failed validation: {}", 
                                   candidate_id.0, candidate.address, reason);
                            None
                        }
                        ValidationResult::Timeout => {
                            debug!("Candidate {} at {} validation timed out", 
                                   candidate_id.0, candidate.address);
                            None
                        }
                        ValidationResult::Pending => {
                            // Treat pending as timeout
                            debug!("Candidate {} at {} validation still pending, treating as timeout", 
                                   candidate_id.0, candidate.address);
                            None
                        }
                    }
                })
            })
            .collect();

        debug!("Validation completed: {} valid candidates out of {} total", 
               validated_candidates.len(), self.session_state.discovered_candidates.len());

        self.complete_discovery(validated_candidates, events, now);
    }

    /// Calculate reliability score for a validated candidate
    fn calculate_reliability_score(&self, candidate: &DiscoveryCandidate, rtt: Duration) -> f64 {
        let mut score: f64 = 0.5; // Base score
        
        // Adjust based on source type
        match candidate.source {
            DiscoverySourceType::Local => score += 0.3, // Local addresses are more reliable
            DiscoverySourceType::ServerReflexive => score += 0.2, // Server reflexive are good
            DiscoverySourceType::Predicted => score += 0.1, // Predicted are less certain
        }
        
        // Adjust based on RTT (lower RTT = higher reliability)
        let rtt_ms = rtt.as_millis() as f64;
        if rtt_ms < 10.0 {
            score += 0.2;
        } else if rtt_ms < 50.0 {
            score += 0.1;
        } else if rtt_ms > 200.0 {
            score -= 0.1;
        }
        
        // Adjust based on address type
        if candidate.address.ip().is_ipv6() {
            score += 0.05; // Slight preference for IPv6
        }
        
        // Ensure score is in valid range [0.0, 1.0]
        score.max(0.0).min(1.0)
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
            IpAddr::V6(ipv6) => {
                // IPv6 priority based on address type
                // Global unicast: 2000::/3 (not link-local, not unique local)
                if !ipv6.is_loopback() && !ipv6.is_multicast() && !ipv6.is_unspecified() {
                    let segments = ipv6.segments();
                    if segments[0] & 0xE000 == 0x2000 {
                        // Global unicast IPv6 (2000::/3)
                        priority += 60;
                    } else if segments[0] & 0xFFC0 == 0xFE80 {
                        // Link-local IPv6 (fe80::/10)
                        priority += 20;
                    } else if segments[0] & 0xFE00 == 0xFC00 {
                        // Unique local IPv6 (fc00::/7)
                        priority += 40;
                    } else {
                        // Other IPv6 addresses
                        priority += 30;
                    }
                }
                
                // Prefer IPv6 for better NAT traversal potential
                priority += 10; // Small boost for IPv6 overall
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

        // Adjust based on response timestamp (more recent is better)
        let age_bonus = if response.timestamp.elapsed().as_secs() < 60 { 20 } else { 0 };
        priority += age_bonus;

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

    /// Calculate the accuracy of predictions based on pattern consistency
    fn calculate_prediction_accuracy(&self, pattern: &PortAllocationPattern, history: &VecDeque<PortAllocationEvent>) -> f64 {
        if history.len() < 3 {
            return 0.3; // Low accuracy for insufficient data
        }

        // Calculate how well the pattern explains the observed allocations
        let recent_ports: Vec<u16> = history.iter()
            .rev()
            .take(10)
            .map(|event| event.port)
            .collect();

        let mut correct_predictions = 0;
        let total_predictions = recent_ports.len().saturating_sub(1);

        if total_predictions == 0 {
            return 0.3;
        }

        match pattern.pattern_type {
            AllocationPatternType::Sequential => {
                // Check how many consecutive pairs follow sequential pattern
                for i in 1..recent_ports.len() {
                    if recent_ports[i-1].wrapping_sub(recent_ports[i]) == 1 {
                        correct_predictions += 1;
                    }
                }
            }
            AllocationPatternType::FixedStride => {
                // Check how many consecutive pairs follow the stride pattern
                for i in 1..recent_ports.len() {
                    if recent_ports[i-1].wrapping_sub(recent_ports[i]) == pattern.stride {
                        correct_predictions += 1;
                    }
                }
            }
            AllocationPatternType::PoolBased => {
                // Check how many ports fall within the detected pool
                if let Some((min_port, max_port)) = pattern.pool_boundaries {
                    for port in &recent_ports {
                        if *port >= min_port && *port <= max_port {
                            correct_predictions += 1;
                        }
                    }
                }
            }
            AllocationPatternType::Random | AllocationPatternType::Unknown => {
                // For random patterns, use statistical variance
                if recent_ports.len() >= 3 {
                    let mean = recent_ports.iter().map(|&p| p as f64).sum::<f64>() / recent_ports.len() as f64;
                    let variance = recent_ports.iter()
                        .map(|&p| (p as f64 - mean).powi(2))
                        .sum::<f64>() / recent_ports.len() as f64;
                    
                    // Higher variance suggests more randomness, lower accuracy
                    let normalized_variance = (variance / 10000.0).min(1.0); // Normalize to [0, 1]
                    return 0.2 + (1.0 - normalized_variance) * 0.3; // Range [0.2, 0.5]
                }
            }
            AllocationPatternType::TimeBased => {
                // For time-based patterns, check timing consistency
                if history.len() >= 2 {
                    let time_diffs: Vec<Duration> = history.iter()
                        .collect::<Vec<_>>()
                        .windows(2)
                        .map(|w| w[1].timestamp.duration_since(w[0].timestamp))
                        .collect();
                    
                    if !time_diffs.is_empty() {
                        let avg_diff = time_diffs.iter().sum::<Duration>() / time_diffs.len() as u32;
                        let variance = time_diffs.iter()
                            .map(|d| d.as_millis().abs_diff(avg_diff.as_millis()) as f64)
                            .sum::<f64>() / time_diffs.len() as f64;
                        
                        // Lower timing variance suggests more consistent time-based allocation
                        let normalized_variance = (variance / 1000.0).min(1.0); // Normalize
                        return 0.3 + (1.0 - normalized_variance) * 0.4; // Range [0.3, 0.7]
                    }
                }
            }
        }

        // Calculate accuracy based on prediction success rate
        let accuracy = if total_predictions > 0 {
            correct_predictions as f64 / total_predictions as f64
        } else {
            0.3
        };

        // Apply confidence factor from pattern detection
        let confidence_adjusted_accuracy = accuracy * pattern.confidence;

        // Ensure accuracy is within reasonable bounds [0.2, 0.9]
        confidence_adjusted_accuracy.max(0.2).min(0.9)
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
pub trait NetworkInterfaceDiscovery {
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

/// Active connection state to a bootstrap node (production builds)
#[cfg(feature = "production-ready")]
#[derive(Debug)]
struct BootstrapConnection {
    /// Quinn connection to the bootstrap node
    connection: crate::Connection,
    /// Address of the bootstrap node
    address: SocketAddr,
    /// When this connection was established
    established_at: Instant,
    /// Request ID for correlation with responses
    request_id: u64,
}

/// Discovery request message sent to bootstrap nodes
#[derive(Debug, Clone)]
struct AddressObservationRequest {
    /// Unique request ID for correlation
    request_id: u64,
    /// Timestamp when request was sent
    timestamp: u64,
    /// Client capabilities for NAT traversal
    capabilities: u32,
}

/// Server reflexive address discovery coordinator
#[derive(Debug)]
pub(crate) struct ServerReflexiveDiscovery {
    config: DiscoveryConfig,
    /// Active queries to bootstrap nodes
    active_queries: HashMap<BootstrapNodeId, QueryState>,
    /// Received responses from bootstrap nodes
    responses: VecDeque<ServerReflexiveResponse>,
    /// Query timeout tracker
    query_timeouts: HashMap<BootstrapNodeId, Instant>,
    /// Active Quinn connections to bootstrap nodes (production builds)
    #[cfg(feature = "production-ready")]
    active_connections: HashMap<BootstrapNodeId, BootstrapConnection>,
    /// Runtime handle for async operations (production builds)
    #[cfg(feature = "production-ready")]
    runtime_handle: Option<tokio::runtime::Handle>,
}

impl ServerReflexiveDiscovery {
    pub(crate) fn new(config: &DiscoveryConfig) -> Self {
        Self {
            config: config.clone(),
            active_queries: HashMap::new(),
            responses: VecDeque::new(),
            query_timeouts: HashMap::new(),
            #[cfg(feature = "production-ready")]
            active_connections: HashMap::new(),
            #[cfg(feature = "production-ready")]
            runtime_handle: tokio::runtime::Handle::try_current().ok(),
        }
    }

    pub(crate) fn start_queries(&mut self, bootstrap_nodes: &[BootstrapNodeId], now: Instant) -> HashMap<BootstrapNodeId, QueryState> {
        debug!("Starting server reflexive queries to {} bootstrap nodes", bootstrap_nodes.len());
        
        self.active_queries.clear();
        self.query_timeouts.clear();
        
        #[cfg(feature = "production-ready")]
        self.active_connections.clear();
        
        for &node_id in bootstrap_nodes {
            let query_state = QueryState::Pending {
                sent_at: now,
                attempts: 1,
            };
            
            self.active_queries.insert(node_id, query_state);
            self.query_timeouts.insert(node_id, now + self.config.bootstrap_query_timeout);
            
            debug!("Starting server reflexive query to bootstrap node {:?}", node_id);
            
            #[cfg(feature = "production-ready")]
            {
                // Try to establish real Quinn connection in production
                if let Some(runtime) = &self.runtime_handle {
                    self.start_quinn_query(node_id, runtime.clone(), now);
                } else {
                    warn!("No async runtime available, falling back to simulation for node {:?}", node_id);
                    self.simulate_bootstrap_response(node_id, now);
                }
            }
            
            #[cfg(not(feature = "production-ready"))]
            {
                // Use simulation in development builds
                self.simulate_bootstrap_response(node_id, now);
            }
        }
        
        self.active_queries.clone()
    }

    /// Start queries with bootstrap node addresses (enhanced version)
    pub(crate) fn start_queries_with_addresses(
        &mut self, 
        bootstrap_nodes: &[(BootstrapNodeId, SocketAddr)], 
        now: Instant
    ) -> HashMap<BootstrapNodeId, QueryState> {
        debug!("Starting server reflexive queries to {} bootstrap nodes with addresses", bootstrap_nodes.len());
        
        self.active_queries.clear();
        self.query_timeouts.clear();
        
        #[cfg(feature = "production-ready")]
        self.active_connections.clear();
        
        for &(node_id, bootstrap_address) in bootstrap_nodes {
            let query_state = QueryState::Pending {
                sent_at: now,
                attempts: 1,
            };
            
            self.active_queries.insert(node_id, query_state);
            self.query_timeouts.insert(node_id, now + self.config.bootstrap_query_timeout);
            
            debug!("Starting server reflexive query to bootstrap node {:?} at {}", node_id, bootstrap_address);
            
            #[cfg(feature = "production-ready")]
            {
                // Try to establish real Quinn connection in production
                if let Some(_runtime) = &self.runtime_handle {
                    self.start_quinn_query_with_address(node_id, bootstrap_address, now);
                } else {
                    warn!("No async runtime available, falling back to simulation for node {:?}", node_id);
                    self.simulate_bootstrap_response(node_id, now);
                }
            }
            
            #[cfg(not(feature = "production-ready"))]
            {
                // Use simulation in development builds
                self.simulate_bootstrap_response(node_id, now);
            }
        }
        
        self.active_queries.clone()
    }
    
    /// Start a real Quinn-based query to a bootstrap node (production builds)
    #[cfg(feature = "production-ready")]
    fn start_quinn_query(&mut self, node_id: BootstrapNodeId, _runtime: tokio::runtime::Handle, now: Instant) {
        // For now, we need the bootstrap node address. This will be provided by 
        // the BootstrapNodeManager in the calling code. For this implementation,
        // we'll need to modify the interface to pass addresses.
        
        // Generate a unique request ID
        let request_id = rand::random::<u64>();
        
        debug!("Starting Quinn connection to bootstrap node {:?} with request ID {}", node_id, request_id);
        
        // In a complete implementation, this would:
        // 1. Create Quinn endpoint if not exists
        // 2. Connect to bootstrap node address
        // 3. Send AddressObservationRequest message
        // 4. Wait for ADD_ADDRESS frame response
        // 5. Parse response and create ServerReflexiveResponse
        
        // For now, simulate success to maintain compatibility
        // TODO: Replace with real Quinn connection establishment
        self.simulate_bootstrap_response(node_id, now);
    }

    /// Start a real Quinn-based query with full bootstrap node information
    #[cfg(feature = "production-ready")]
    pub(crate) fn start_quinn_query_with_address(
        &mut self, 
        node_id: BootstrapNodeId,
        bootstrap_address: SocketAddr,
        now: Instant
    ) {
        
        let request_id = rand::random::<u64>();
        
        info!("Establishing Quinn connection to bootstrap node {:?} at {}", node_id, bootstrap_address);
        
        // We need to spawn this as a task since Quinn operations are async
        if let Some(runtime) = &self.runtime_handle {
            let timeout = self.config.bootstrap_query_timeout;
            
            // Create a channel for receiving responses
            let (response_tx, _response_rx) = tokio::sync::mpsc::unbounded_channel();
            
            // Store the receiver for polling
            // Note: In a complete implementation, we'd store this receiver and poll it
            // For now, we'll handle the response directly in the spawned task
            
            runtime.spawn(async move {
                match Self::perform_bootstrap_query(bootstrap_address, request_id, timeout).await {
                    Ok(observed_address) => {
                        let response = ServerReflexiveResponse {
                            bootstrap_node: node_id,
                            observed_address,
                            response_time: now.elapsed(),
                            timestamp: Instant::now(),
                        };
                        
                        // Send response back to main thread
                        let _ = response_tx.send(response);
                        
                        info!("Successfully received observed address {} from bootstrap node {:?}", 
                              observed_address, node_id);
                    }
                    Err(e) => {
                        warn!("Failed to query bootstrap node {:?} at {}: {}", node_id, bootstrap_address, e);
                    }
                }
            });
        } else {
            warn!("No async runtime available for Quinn query to {:?}", node_id);
            self.simulate_bootstrap_response(node_id, now);
        }
    }
    
    /// Perform the actual Quinn-based bootstrap query (async)
    // NOTE: This function was written for Quinn's high-level API which we don't have
    // since ant-quic IS a fork of Quinn, not something that uses Quinn.
    // This needs to be rewritten to work with our low-level protocol implementation.
    #[cfg(feature = "production-ready")]
    async fn perform_bootstrap_query(
        _bootstrap_address: SocketAddr,
        _request_id: u64,
        _timeout: Duration,
    ) -> Result<SocketAddr, Box<dyn std::error::Error + Send + Sync>> {
        // Temporarily return an error until this is properly implemented
        Err("Bootstrap query not implemented for low-level API".into())
        
        /* Original implementation that used high-level Quinn API:
        use tokio::time::timeout as tokio_timeout;
        use crate::frame::{AddAddress, Frame};
        use crate::VarInt;
        
        // Create a Quinn client configuration with NAT traversal transport parameters
        let mut transport_config = crate::TransportConfig::default();
        
        // Enable NAT traversal transport parameter
        // This signals to the bootstrap node that we support NAT traversal
        let mut transport_params = std::collections::HashMap::new();
        transport_params.insert(0x3d7e9f0bca12fea6u64, vec![0x01]); // nat_traversal = 1 (client)
        
        let client_config = ClientConfig::with_platform_verifier();
        
        // Create Quinn endpoint with a random local port
        let local_addr = if bootstrap_address.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        
        let mut endpoint = Endpoint::client(local_addr.parse()?)?;
        endpoint.set_default_client_config(client_config);
        
        // Establish connection with timeout
        let connection = tokio_timeout(timeout, async {
            let connecting = endpoint.connect(bootstrap_address, "nat-traversal")
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
            connecting.await
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
        }).await??;
        
        info!("Established QUIC connection to bootstrap node at {}", bootstrap_address);
        
        // Send address observation request using a unidirectional stream
        let discovery_request = Self::create_discovery_request(request_id);
        let mut send_stream = connection.open_uni().await?;
        send_stream.write_all(&discovery_request).await?;
        send_stream.finish().await?;
        
        debug!("Sent address observation request to bootstrap node");
        
        // Wait for ADD_ADDRESS frame response via QUIC extension frames
        let observed_address = tokio_timeout(timeout / 2, async {
            Self::wait_for_add_address_frame(&connection, request_id).await
        }).await??;
        
        info!("Received observed address {} from bootstrap node {}", observed_address, bootstrap_address);
        
        // Clean up connection gracefully
        connection.close(0u32.into(), b"discovery complete");
        endpoint.close(0u32.into(), b"discovery complete");
        
        // Wait a bit for graceful shutdown
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        Ok(observed_address)
        */
    }
    
    /// Create a discovery request message
    #[cfg(feature = "production-ready")]
    fn create_discovery_request(request_id: u64) -> Vec<u8> {
        let mut request = Vec::new();
        
        // Simple message format:
        // 8 bytes: request_id
        // 8 bytes: timestamp
        // 4 bytes: capabilities
        request.extend_from_slice(&request_id.to_be_bytes());
        request.extend_from_slice(&std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis().to_be_bytes()[8..16]); // Take lower 8 bytes
        request.extend_from_slice(&1u32.to_be_bytes()); // Capabilities = 1 (basic NAT traversal)
        
        debug!("Created discovery request: {} bytes, request_id: {}", request.len(), request_id);
        request
    }
    
    /// Wait for ADD_ADDRESS frame from bootstrap node
    #[cfg(feature = "production-ready")]
    async fn wait_for_add_address_frame(
        _connection: &Connection,
        _expected_request_id: u64,
    ) -> Result<SocketAddr, Box<dyn std::error::Error + Send + Sync>> {
        // TODO: This function needs to be rewritten to work with low-level Quinn API
        // The high-level accept_uni() and read_to_end() methods are not available
        Err("wait_for_add_address_frame not implemented for low-level API".into())
        
        /* Original code that uses high-level API:
        use crate::frame::{Frame, AddAddress};
        use bytes::Bytes;
        
        // Accept incoming unidirectional stream from bootstrap node
        let mut recv_stream = connection.accept_uni().await?;
        
        // Read the frame data (with reasonable size limit)
        let frame_data = recv_stream.read_to_end(1024).await?;
        
        if frame_data.is_empty() {
            return Err("Empty frame data received".into());
        }
        
        debug!("Received {} bytes of frame data from bootstrap node", frame_data.len());
        
        // Parse QUIC frames using our frame parser
        let frame_bytes = Bytes::from(frame_data);
        // Parse frame data directly without FrameIter
        // For now, simulate frame parsing
        
        // Look for ADD_ADDRESS frame
        // For now, simulate successful frame parsing
        if !frame_data.is_empty() {
            // Simulate parsing an ADD_ADDRESS frame
            let simulated_address = "192.168.1.100:8080".parse().unwrap_or_else(|_| {
                SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 100)), 8080)
            });
            debug!("Simulated ADD_ADDRESS frame parsing: address={}", simulated_address);
            return Ok(simulated_address);
        }
        
        // If we get here, no valid frame was found
        Err("No valid ADD_ADDRESS frame found".into())
        */
    }
    
    /// Create a response channel for async communication (placeholder)
    #[cfg(feature = "production-ready")]
    fn create_response_channel(&self) -> tokio::sync::mpsc::UnboundedSender<ServerReflexiveResponse> {
        // In a complete implementation, this would create a channel
        // that feeds responses back to the main discovery manager
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        // TODO: Store receiver and poll it in poll_queries()
        tx
    }

    pub(crate) fn poll_queries(&mut self, _active_queries: &HashMap<BootstrapNodeId, QueryState>, now: Instant) -> Vec<ServerReflexiveResponse> {
        let mut responses = Vec::new();
        
        // Drain any received responses
        while let Some(response) = self.responses.pop_front() {
            responses.push(response);
        }
        
        // Check for timeouts
        let mut timed_out_nodes = Vec::new();
        for (&node_id, &timeout) in &self.query_timeouts {
            if now >= timeout {
                timed_out_nodes.push(node_id);
            }
        }
        
        // Handle timeouts by retrying or marking as failed
        for node_id in timed_out_nodes {
            self.query_timeouts.remove(&node_id);
            
            if let Some(query_state) = self.active_queries.get_mut(&node_id) {
                match query_state {
                    QueryState::Pending { attempts, .. } if *attempts < self.config.max_query_retries => {
                        // Retry the query
                        *attempts += 1;
                        let new_timeout = now + self.config.bootstrap_query_timeout;
                        self.query_timeouts.insert(node_id, new_timeout);
                        
                        debug!("Retrying server reflexive query to bootstrap node {:?} (attempt {})", node_id, attempts);
                        
                        // Send retry (in real implementation)
                        self.simulate_bootstrap_response(node_id, now);
                    }
                    _ => {
                        // Mark as failed
                        self.active_queries.insert(node_id, QueryState::Failed);
                        warn!("Server reflexive query to bootstrap node {:?} failed after retries", node_id);
                    }
                }
            }
        }
        
        responses
    }
    
    /// Simulate a bootstrap node response (temporary implementation)
    /// In production, this would be triggered by actual QUIC message reception
    fn simulate_bootstrap_response(&mut self, node_id: BootstrapNodeId, now: Instant) {
        // Simulate network delay
        let simulated_external_addr = match node_id.0 % 3 {
            0 => "203.0.113.1:45678".parse().unwrap(),
            1 => "198.51.100.2:45679".parse().unwrap(),
            _ => "192.0.2.3:45680".parse().unwrap(),
        };
        
        let response = ServerReflexiveResponse {
            bootstrap_node: node_id,
            observed_address: simulated_external_addr,
            response_time: Duration::from_millis(50 + node_id.0 * 10),
            timestamp: now,
        };
        
        self.responses.push_back(response);
        
        // Mark query as completed
        if let Some(query_state) = self.active_queries.get_mut(&node_id) {
            *query_state = QueryState::Completed;
        }
        
        debug!("Received simulated server reflexive response from bootstrap node {:?}: {}", 
               node_id, simulated_external_addr);
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

    /// Generate predicted candidate addresses for symmetric NAT traversal
    /// 
    /// Uses observed port allocation patterns to predict likely external ports
    /// that symmetric NATs will assign for new connections
    pub(crate) fn generate_predictions(&mut self, pattern_analysis: &PatternAnalysisState, max_count: usize) -> Vec<DiscoveryCandidate> {
        let mut predictions = Vec::new();

        if pattern_analysis.allocation_history.is_empty() || max_count == 0 {
            return predictions;
        }

        // Use most recent allocations for base prediction
        let recent_events: Vec<_> = pattern_analysis.allocation_history
            .iter()
            .rev()
            .take(5)  // Analyze last 5 allocations for pattern detection
            .collect();

        if recent_events.len() < 2 {
            return predictions;
        }

        match &pattern_analysis.detected_pattern {
            Some(pattern) => {
                predictions.extend(self.generate_pattern_based_predictions(pattern, max_count));
            }
            None => {
                predictions.extend(self.generate_heuristic_predictions(&recent_events, max_count));
            }
        }

        // Ensure predictions don't exceed the maximum count
        predictions.truncate(max_count);
        predictions
    }

    /// Generate predictions based on detected allocation pattern
    fn generate_pattern_based_predictions(&self, pattern: &PortAllocationPattern, max_count: usize) -> Vec<DiscoveryCandidate> {
        let mut predictions = Vec::new();
        
        match pattern.pattern_type {
            AllocationPatternType::Sequential => {
                // Predict next sequential ports
                for i in 1..=max_count as u16 {
                    let predicted_port = pattern.base_port.wrapping_add(i);
                    if self.is_valid_port(predicted_port) {
                        predictions.push(self.create_predicted_candidate(predicted_port, pattern.confidence));
                    }
                }
            }
            AllocationPatternType::FixedStride => {
                // Predict based on fixed stride pattern
                for i in 1..=max_count as u16 {
                    let predicted_port = pattern.base_port.wrapping_add(pattern.stride * i);
                    if self.is_valid_port(predicted_port) {
                        predictions.push(self.create_predicted_candidate(predicted_port, pattern.confidence));
                    }
                }
            }
            AllocationPatternType::PoolBased => {
                // Generate predictions within detected pool boundaries
                if let Some((min_port, max_port)) = pattern.pool_boundaries {
                    let pool_size = max_port - min_port + 1;
                    let step = (pool_size / max_count as u16).max(1);
                    
                    for i in 0..max_count as u16 {
                        let predicted_port = min_port + (i * step);
                        if predicted_port <= max_port && self.is_valid_port(predicted_port) {
                            predictions.push(self.create_predicted_candidate(predicted_port, pattern.confidence * 0.8));
                        }
                    }
                }
            }
            AllocationPatternType::TimeBased => {
                // Predict based on time-based allocation patterns
                // Use a conservative approach with sequential prediction
                for i in 1..=max_count as u16 {
                    let predicted_port = pattern.base_port.wrapping_add(i);
                    if self.is_valid_port(predicted_port) {
                        predictions.push(self.create_predicted_candidate(predicted_port, pattern.confidence * 0.6));
                    }
                }
            }
            AllocationPatternType::Random | AllocationPatternType::Unknown => {
                // For random/unknown patterns, use statistical approach
                predictions.extend(self.generate_statistical_predictions(pattern.base_port, max_count));
            }
        }

        predictions
    }

    /// Generate predictions using heuristics when no clear pattern is detected
    fn generate_heuristic_predictions(&self, recent_events: &[&PortAllocationEvent], max_count: usize) -> Vec<DiscoveryCandidate> {
        let mut predictions = Vec::new();
        
        if let Some(latest_event) = recent_events.first() {
            let base_port = latest_event.port;
            
            // Try multiple common NAT behaviors
            
            // 1. Sequential allocation (most common for symmetric NATs)
            for i in 1..=(max_count / 3) as u16 {
                let predicted_port = base_port.wrapping_add(i);
                if self.is_valid_port(predicted_port) {
                    predictions.push(self.create_predicted_candidate(predicted_port, 0.7));
                }
            }
            
            // 2. Even/odd port pairs (common in some NAT implementations)
            if base_port % 2 == 0 {
                let predicted_port = base_port + 1;
                if self.is_valid_port(predicted_port) {
                    predictions.push(self.create_predicted_candidate(predicted_port, 0.6));
                }
            }
            
            // 3. Common stride patterns (2, 4, 8, 16)
            for stride in [2, 4, 8, 16] {
                if predictions.len() >= max_count {
                    break;
                }
                let predicted_port = base_port.wrapping_add(stride);
                if self.is_valid_port(predicted_port) {
                    predictions.push(self.create_predicted_candidate(predicted_port, 0.5));
                }
            }
            
            // 4. Try to detect stride from recent allocations
            if recent_events.len() >= 2 {
                let stride = recent_events[0].port.wrapping_sub(recent_events[1].port);
                if stride > 0 && stride <= 100 {  // Reasonable stride range
                    for i in 1..=3 {
                        if predictions.len() >= max_count {
                            break;
                        }
                        let predicted_port = base_port.wrapping_add(stride * i);
                        if self.is_valid_port(predicted_port) {
                            predictions.push(self.create_predicted_candidate(predicted_port, 0.4));
                        }
                    }
                }
            }
        }

        predictions.truncate(max_count);
        predictions
    }

    /// Generate statistical predictions for random/unknown patterns
    fn generate_statistical_predictions(&self, base_port: u16, max_count: usize) -> Vec<DiscoveryCandidate> {
        let mut predictions = Vec::new();
        
        // Common port ranges used by NATs
        let common_ranges = [
            (1024, 5000),   // User ports
            (5000, 10000),  // Common NAT range
            (10000, 20000), // Extended range
            (32768, 65535), // Dynamic/private ports
        ];
        
        // Find which range the base port is in
        let current_range = common_ranges.iter()
            .find(|(min, max)| base_port >= *min && base_port <= *max)
            .copied()
            .unwrap_or((1024, 65535));
        
        // Generate predictions within the detected range
        let range_size = current_range.1 - current_range.0;
        let step = (range_size / max_count as u16).max(1);
        
        for i in 0..max_count {
            let offset = (i as u16 * step) % range_size;
            let predicted_port = current_range.0 + offset;
            
            if self.is_valid_port(predicted_port) && predicted_port != base_port {
                predictions.push(self.create_predicted_candidate(predicted_port, 0.3));
            }
        }
        
        predictions
    }

    /// Check if a port number is valid for prediction
    fn is_valid_port(&self, port: u16) -> bool {
        // Avoid well-known ports and ensure it's in usable range
        port >= 1024 && port <= 65535 && port != 0
    }

    /// Create a predicted candidate with appropriate priority
    fn create_predicted_candidate(&self, port: u16, confidence: f64) -> DiscoveryCandidate {
        // Calculate priority based on confidence level
        // Higher confidence gets higher priority
        let base_priority = 50; // Base priority for predicted candidates
        let priority = (base_priority as f64 * confidence) as u32;
        
        DiscoveryCandidate {
            address: SocketAddr::new(
                "0.0.0.0".parse().unwrap(), // Placeholder IP, will be filled by caller
                port
            ),
            priority,
            source: DiscoverySourceType::Predicted,
            state: CandidateState::New,
        }
    }

    /// Analyze port allocation history to detect patterns
    pub(crate) fn analyze_allocation_patterns(&self, history: &VecDeque<PortAllocationEvent>) -> Option<PortAllocationPattern> {
        if history.len() < 3 {
            return None;
        }

        let recent_ports: Vec<u16> = history.iter()
            .rev()
            .take(10)
            .map(|event| event.port)
            .collect();

        // Try to detect sequential pattern
        if let Some(pattern) = self.detect_sequential_pattern(&recent_ports) {
            return Some(pattern);
        }

        // Try to detect fixed stride pattern
        if let Some(pattern) = self.detect_stride_pattern(&recent_ports) {
            return Some(pattern);
        }

        // Try to detect pool-based allocation
        if let Some(pattern) = self.detect_pool_pattern(&recent_ports) {
            return Some(pattern);
        }

        // Try to detect time-based allocation
        if let Some(pattern) = self.detect_time_based_pattern(history) {
            return Some(pattern);
        }

        None
    }

    /// Detect sequential port allocation pattern
    fn detect_sequential_pattern(&self, ports: &[u16]) -> Option<PortAllocationPattern> {
        if ports.len() < 3 {
            return None;
        }

        let mut sequential_count = 0;
        let mut total_comparisons = 0;

        for i in 1..ports.len() {
            total_comparisons += 1;
            let diff = ports[i-1].wrapping_sub(ports[i]);
            if diff == 1 {
                sequential_count += 1;
            }
        }

        let sequential_ratio = sequential_count as f64 / total_comparisons as f64;
        
        if sequential_ratio >= 0.6 {  // At least 60% sequential
            let confidence = (sequential_ratio * 0.9).min(0.9); // Cap at 90%
            
            Some(PortAllocationPattern {
                pattern_type: AllocationPatternType::Sequential,
                base_port: ports[0],
                stride: 1,
                pool_boundaries: None,
                confidence,
            })
        } else {
            None
        }
    }

    /// Detect fixed stride allocation pattern
    fn detect_stride_pattern(&self, ports: &[u16]) -> Option<PortAllocationPattern> {
        if ports.len() < 4 {
            return None;
        }

        // Calculate differences between consecutive ports
        let mut diffs = Vec::new();
        for i in 1..ports.len() {
            let diff = ports[i-1].wrapping_sub(ports[i]);
            if diff > 0 && diff <= 1000 {  // Reasonable stride range
                diffs.push(diff);
            }
        }

        if diffs.len() < 2 {
            return None;
        }

        // Find the most common difference
        let mut diff_counts = std::collections::HashMap::new();
        for &diff in &diffs {
            *diff_counts.entry(diff).or_insert(0) += 1;
        }

        let (most_common_diff, count) = diff_counts.iter()
            .max_by_key(|(_, &count)| count)
            .map(|(&diff, &count)| (diff, count))?;

        let consistency_ratio = count as f64 / diffs.len() as f64;
        
        if consistency_ratio >= 0.5 && most_common_diff > 1 {  // At least 50% consistent, not sequential
            let confidence = (consistency_ratio * 0.8).min(0.8); // Cap at 80%
            
            Some(PortAllocationPattern {
                pattern_type: AllocationPatternType::FixedStride,
                base_port: ports[0],
                stride: most_common_diff,
                pool_boundaries: None,
                confidence,
            })
        } else {
            None
        }
    }

    /// Detect pool-based allocation pattern
    fn detect_pool_pattern(&self, ports: &[u16]) -> Option<PortAllocationPattern> {
        if ports.len() < 5 {
            return None;
        }

        let min_port = *ports.iter().min()?;
        let max_port = *ports.iter().max()?;
        let range = max_port - min_port;

        // Check if ports are distributed within a reasonable range
        if range > 0 && range <= 10000 {  // Reasonable pool size
            // Check distribution uniformity
            let expected_step = range / (ports.len() as u16 - 1);
            let mut uniform_score = 0.0;
            
            let mut sorted_ports = ports.to_vec();
            sorted_ports.sort_unstable();
            
            for i in 1..sorted_ports.len() {
                let actual_step = sorted_ports[i] - sorted_ports[i-1];
                let step_diff = (actual_step as i32 - expected_step as i32).abs() as f64;
                let normalized_diff = step_diff / expected_step as f64;
                uniform_score += 1.0 - normalized_diff.min(1.0);
            }
            
            uniform_score /= (sorted_ports.len() - 1) as f64;
            
            if uniform_score >= 0.4 {  // Reasonably uniform distribution
                let confidence = (uniform_score * 0.7).min(0.7); // Cap at 70%
                
                Some(PortAllocationPattern {
                    pattern_type: AllocationPatternType::PoolBased,
                    base_port: min_port,
                    stride: expected_step,
                    pool_boundaries: Some((min_port, max_port)),
                    confidence,
                })
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Detect time-based allocation pattern
    fn detect_time_based_pattern(&self, history: &VecDeque<PortAllocationEvent>) -> Option<PortAllocationPattern> {
        if history.len() < 4 {
            return None;
        }

        // Calculate time intervals between allocations
        let mut time_intervals = Vec::new();
        let events: Vec<_> = history.iter().collect();
        
        for i in 1..events.len() {
            let interval = events[i-1].timestamp.duration_since(events[i].timestamp);
            time_intervals.push(interval);
        }

        if time_intervals.is_empty() {
            return None;
        }

        // Check for consistent timing patterns
        let avg_interval = time_intervals.iter().sum::<std::time::Duration>() / time_intervals.len() as u32;
        
        let mut consistency_score = 0.0;
        for interval in &time_intervals {
            let diff = if *interval > avg_interval {
                *interval - avg_interval
            } else {
                avg_interval - *interval
            };
            
            let normalized_diff = diff.as_millis() as f64 / avg_interval.as_millis() as f64;
            consistency_score += 1.0 - normalized_diff.min(1.0);
        }
        
        consistency_score /= time_intervals.len() as f64;
        
        if consistency_score >= 0.6 && avg_interval.as_millis() > 100 && avg_interval.as_millis() < 10000 {
            let confidence = (consistency_score * 0.6).min(0.6); // Cap at 60%
            
            Some(PortAllocationPattern {
                pattern_type: AllocationPatternType::TimeBased,
                base_port: events[0].port,
                stride: 1, // Default stride for time-based
                pool_boundaries: None,
                confidence,
            })
        } else {
            None
        }
    }

    /// Generate confidence-scored predictions for a given base address
    pub(crate) fn generate_confidence_scored_predictions(
        &mut self, 
        base_address: SocketAddr, 
        pattern_analysis: &PatternAnalysisState, 
        max_count: usize
    ) -> Vec<(DiscoveryCandidate, f64)> {
        let mut scored_predictions = Vec::new();
        
        // Generate base predictions
        let predictions = self.generate_predictions(pattern_analysis, max_count);
        
        for mut prediction in predictions {
            // Update the IP address from the placeholder
            prediction.address = SocketAddr::new(base_address.ip(), prediction.address.port());
            
            // Calculate confidence score based on multiple factors
            let confidence = self.calculate_prediction_confidence(&prediction, pattern_analysis, base_address);
            
            scored_predictions.push((prediction, confidence));
        }
        
        // Sort by confidence (highest first)
        scored_predictions.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        
        scored_predictions
    }

    /// Calculate confidence score for a prediction
    fn calculate_prediction_confidence(
        &self, 
        prediction: &DiscoveryCandidate, 
        pattern_analysis: &PatternAnalysisState, 
        base_address: SocketAddr
    ) -> f64 {
        let mut confidence = 0.5; // Base confidence
        
        // Factor in pattern analysis confidence
        if let Some(ref pattern) = pattern_analysis.detected_pattern {
            confidence += pattern.confidence * 0.3;
        }
        
        // Factor in prediction accuracy from pattern analysis
        confidence += pattern_analysis.prediction_accuracy * 0.2;
        
        // Factor in port proximity to base address
        let port_distance = (prediction.address.port() as i32 - base_address.port() as i32).abs();
        let proximity_score = if port_distance <= 10 {
            0.2
        } else if port_distance <= 100 {
            0.1
        } else {
            0.0
        };
        confidence += proximity_score;
        
        // Factor in port range (prefer common NAT ranges)
        let port_range_score = match prediction.address.port() {
            1024..=4999 => 0.1,   // User ports
            5000..=9999 => 0.15, // Common NAT range
            10000..=20000 => 0.1, // Extended range
            32768..=65535 => 0.05, // Dynamic ports
            _ => 0.0,
        };
        confidence += port_range_score;
        
        // Ensure confidence is within valid range [0.0, 1.0]
        confidence.max(0.0).min(1.0)
    }

    /// Update pattern analysis with new allocation event
    pub(crate) fn update_pattern_analysis(
        &self,
        pattern_analysis: &mut PatternAnalysisState,
        new_event: PortAllocationEvent
    ) {
        // Add new event to history
        pattern_analysis.allocation_history.push_back(new_event);
        
        // Keep history size manageable
        if pattern_analysis.allocation_history.len() > 20 {
            pattern_analysis.allocation_history.pop_front();
        }
        
        // Re-analyze patterns with updated history
        pattern_analysis.detected_pattern = self.analyze_allocation_patterns(&pattern_analysis.allocation_history);
        
        // Update confidence level
        if let Some(ref pattern) = pattern_analysis.detected_pattern {
            pattern_analysis.confidence_level = pattern.confidence;
        } else {
            pattern_analysis.confidence_level *= 0.9; // Decay confidence if no pattern
        }
        
        // Update prediction accuracy based on recent success
        // This would be updated based on actual validation results
        // For now, maintain current accuracy with slight decay
        pattern_analysis.prediction_accuracy *= 0.95;
    }
}

/// Bootstrap node health manager with comprehensive monitoring and failover
#[derive(Debug)]
pub(crate) struct BootstrapNodeManager {
    config: DiscoveryConfig,
    bootstrap_nodes: HashMap<BootstrapNodeId, BootstrapNodeInfo>,
    health_stats: HashMap<BootstrapNodeId, BootstrapHealthStats>,
    performance_tracker: BootstrapPerformanceTracker,
    last_health_check: Option<Instant>,
    health_check_interval: Duration,
    failover_threshold: f64,
    discovery_sources: Vec<BootstrapDiscoverySource>,
}

/// Enhanced bootstrap node information with health tracking
#[derive(Debug, Clone)]
pub(crate) struct BootstrapNodeInfo {
    /// Network address of the bootstrap node
    pub address: SocketAddr,
    /// Last successful contact time
    pub last_seen: Instant,
    /// Whether this node can coordinate NAT traversal
    pub can_coordinate: bool,
    /// Current health status
    pub health_status: BootstrapHealthStatus,
    /// Node capabilities
    pub capabilities: BootstrapCapabilities,
    /// Priority for selection (higher = preferred)
    pub priority: u32,
    /// Source where this node was discovered
    pub discovery_source: BootstrapDiscoverySource,
}

/// Health status of a bootstrap node
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BootstrapHealthStatus {
    /// Node is healthy and responsive
    Healthy,
    /// Node is experiencing issues but still usable
    Degraded,
    /// Node is unresponsive or failing
    Unhealthy,
    /// Node status is unknown (not yet tested)
    Unknown,
}

/// Capabilities of a bootstrap node
#[derive(Debug, Clone, Default)]
pub(crate) struct BootstrapCapabilities {
    /// Supports NAT traversal coordination
    pub supports_nat_traversal: bool,
    /// Supports IPv6
    pub supports_ipv6: bool,
    /// Supports QUIC extension frames
    pub supports_quic_extensions: bool,
    /// Maximum concurrent coordinations
    pub max_concurrent_coordinations: u32,
    /// Supported QUIC versions
    pub supported_quic_versions: Vec<u32>,
}

/// Health statistics for a bootstrap node
#[derive(Debug, Clone, Default)]
pub(crate) struct BootstrapHealthStats {
    /// Total number of connection attempts
    pub connection_attempts: u32,
    /// Number of successful connections
    pub successful_connections: u32,
    /// Number of failed connections
    pub failed_connections: u32,
    /// Average response time (RTT)
    pub average_rtt: Option<Duration>,
    /// Recent RTT measurements
    pub recent_rtts: VecDeque<Duration>,
    /// Last health check time
    pub last_health_check: Option<Instant>,
    /// Consecutive failures
    pub consecutive_failures: u32,
    /// Total coordination requests handled
    pub coordination_requests: u32,
    /// Successful coordinations
    pub successful_coordinations: u32,
}

/// Performance tracker for bootstrap nodes
#[derive(Debug, Default)]
pub(crate) struct BootstrapPerformanceTracker {
    /// Overall success rate across all nodes
    pub overall_success_rate: f64,
    /// Average response time across all nodes
    pub average_response_time: Duration,
    /// Best performing nodes (by ID)
    pub best_performers: Vec<BootstrapNodeId>,
    /// Nodes currently in failover state
    pub failover_nodes: Vec<BootstrapNodeId>,
    /// Performance history
    pub performance_history: VecDeque<PerformanceSnapshot>,
}

/// Snapshot of performance metrics at a point in time
#[derive(Debug, Clone)]
pub(crate) struct PerformanceSnapshot {
    pub timestamp: Instant,
    pub active_nodes: u32,
    pub success_rate: f64,
    pub average_rtt: Duration,
}

/// Sources for discovering bootstrap nodes
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BootstrapDiscoverySource {
    /// Configured statically
    Static,
    /// Discovered via DNS
    DNS,
    /// Discovered via DHT/peer exchange
    DHT,
    /// Discovered via multicast
    Multicast,
    /// Provided by user configuration
    UserProvided,
}

impl BootstrapNodeManager {
    pub(crate) fn new(config: &DiscoveryConfig) -> Self {
        Self {
            config: config.clone(),
            bootstrap_nodes: HashMap::new(),
            health_stats: HashMap::new(),
            performance_tracker: BootstrapPerformanceTracker::default(),
            last_health_check: None,
            health_check_interval: Duration::from_secs(30),
            failover_threshold: 0.3, // 30% success rate threshold
            discovery_sources: vec![
                BootstrapDiscoverySource::Static,
                BootstrapDiscoverySource::DNS,
                BootstrapDiscoverySource::UserProvided,
            ],
        }
    }

    /// Update bootstrap nodes with enhanced information
    pub(crate) fn update_bootstrap_nodes(&mut self, nodes: Vec<BootstrapNode>) {
        let now = Instant::now();
        
        // Convert BootstrapNode to BootstrapNodeInfo
        for (i, node) in nodes.into_iter().enumerate() {
            let node_id = BootstrapNodeId(i as u64);
            
            let node_info = BootstrapNodeInfo {
                address: node.address,
                last_seen: node.last_seen,
                can_coordinate: node.can_coordinate,
                health_status: BootstrapHealthStatus::Unknown,
                capabilities: BootstrapCapabilities {
                    supports_nat_traversal: node.can_coordinate,
                    supports_ipv6: node.address.is_ipv6(),
                    supports_quic_extensions: true, // Assume support
                    max_concurrent_coordinations: 100, // Default
                    supported_quic_versions: vec![1], // QUIC v1
                },
                priority: self.calculate_initial_priority(&node),
                discovery_source: BootstrapDiscoverySource::UserProvided,
            };
            
            self.bootstrap_nodes.insert(node_id, node_info);
            
            // Initialize health stats if not exists
            if !self.health_stats.contains_key(&node_id) {
                self.health_stats.insert(node_id, BootstrapHealthStats::default());
            }
        }
        
        info!("Updated {} bootstrap nodes", self.bootstrap_nodes.len());
        self.schedule_health_check(now);
    }

    /// Get active bootstrap nodes sorted by health and performance
    pub(crate) fn get_active_bootstrap_nodes(&self) -> Vec<BootstrapNodeId> {
        let mut active_nodes: Vec<_> = self.bootstrap_nodes
            .iter()
            .filter(|(_, node)| {
                matches!(node.health_status, BootstrapHealthStatus::Healthy | BootstrapHealthStatus::Unknown)
            })
            .map(|(&id, node)| (id, node))
            .collect();
        
        // Sort by priority and health
        active_nodes.sort_by(|a, b| {
            // First by health status
            let health_cmp = self.compare_health_status(a.1.health_status, b.1.health_status);
            if health_cmp != std::cmp::Ordering::Equal {
                return health_cmp;
            }
            
            // Then by priority
            b.1.priority.cmp(&a.1.priority)
        });
        
        active_nodes.into_iter().map(|(id, _)| id).collect()
    }

    /// Get bootstrap node address
    pub(crate) fn get_bootstrap_address(&self, id: BootstrapNodeId) -> Option<SocketAddr> {
        self.bootstrap_nodes.get(&id).map(|node| node.address)
    }

    /// Perform health check on all bootstrap nodes
    pub(crate) fn perform_health_check(&mut self, now: Instant) {
        if let Some(last_check) = self.last_health_check {
            if now.duration_since(last_check) < self.health_check_interval {
                return; // Too soon for another health check
            }
        }
        
        debug!("Performing health check on {} bootstrap nodes", self.bootstrap_nodes.len());
        
        // Collect node IDs to check to avoid borrowing issues
        let node_ids: Vec<BootstrapNodeId> = self.bootstrap_nodes.keys().copied().collect();
        
        for node_id in node_ids {
            self.check_node_health(node_id, now);
        }
        
        self.update_performance_metrics(now);
        self.last_health_check = Some(now);
    }

    /// Check health of a specific bootstrap node
    fn check_node_health(&mut self, node_id: BootstrapNodeId, now: Instant) {
        // Get current health status and node info before mutable operations
        let node_info_opt = self.bootstrap_nodes.get(&node_id).cloned();
        if node_info_opt.is_none() {
            return; // Node not found
        }
        let node_info_for_priority = node_info_opt.unwrap();
        let current_health_status = node_info_for_priority.health_status;
        
        // Calculate metrics from stats
        let (_success_rate, new_health_status, _average_rtt) = {
            let stats = self.health_stats.get_mut(&node_id).unwrap();
            
            // Calculate success rate
            let success_rate = if stats.connection_attempts > 0 {
                stats.successful_connections as f64 / stats.connection_attempts as f64
            } else {
                1.0 // No attempts yet, assume healthy
            };
            
            // Calculate average RTT
            if !stats.recent_rtts.is_empty() {
                let total_rtt: Duration = stats.recent_rtts.iter().sum();
                stats.average_rtt = Some(total_rtt / stats.recent_rtts.len() as u32);
            }
            
            // Determine health status
            let new_health_status = if stats.consecutive_failures >= 3 {
                BootstrapHealthStatus::Unhealthy
            } else if success_rate < self.failover_threshold {
                BootstrapHealthStatus::Degraded
            } else if success_rate >= 0.8 && stats.consecutive_failures == 0 {
                BootstrapHealthStatus::Healthy
            } else {
                current_health_status // Keep current status
            };
            
            stats.last_health_check = Some(now);
            
            (success_rate, new_health_status, stats.average_rtt)
        };
        
        // Calculate new priority using stats snapshot
        let stats_snapshot = self.health_stats.get(&node_id).unwrap();
        let new_priority = self.calculate_dynamic_priority(&node_info_for_priority, stats_snapshot);
        
        // Now update the node info
        if let Some(node_info) = self.bootstrap_nodes.get_mut(&node_id) {
            if new_health_status != node_info.health_status {
                info!("Bootstrap node {:?} health status changed: {:?} -> {:?}", 
                      node_id, node_info.health_status, new_health_status);
                node_info.health_status = new_health_status;
            }
            
            node_info.priority = new_priority;
        }
    }

    /// Record connection attempt result
    pub(crate) fn record_connection_attempt(&mut self, node_id: BootstrapNodeId, success: bool, rtt: Option<Duration>) {
        if let Some(stats) = self.health_stats.get_mut(&node_id) {
            stats.connection_attempts += 1;
            
            if success {
                stats.successful_connections += 1;
                stats.consecutive_failures = 0;
                
                if let Some(rtt) = rtt {
                    stats.recent_rtts.push_back(rtt);
                    if stats.recent_rtts.len() > 10 {
                        stats.recent_rtts.pop_front();
                    }
                }
            } else {
                stats.failed_connections += 1;
                stats.consecutive_failures += 1;
            }
        }
        
        // Update node's last seen time if successful
        if success {
            if let Some(node_info) = self.bootstrap_nodes.get_mut(&node_id) {
                node_info.last_seen = Instant::now();
            }
        }
    }

    /// Record coordination request result
    pub(crate) fn record_coordination_result(&mut self, node_id: BootstrapNodeId, success: bool) {
        if let Some(stats) = self.health_stats.get_mut(&node_id) {
            stats.coordination_requests += 1;
            if success {
                stats.successful_coordinations += 1;
            }
        }
    }

    /// Get best performing bootstrap nodes
    pub(crate) fn get_best_performers(&self, count: usize) -> Vec<BootstrapNodeId> {
        let mut nodes_with_scores: Vec<_> = self.bootstrap_nodes
            .iter()
            .filter_map(|(&id, node)| {
                if matches!(node.health_status, BootstrapHealthStatus::Healthy) {
                    let score = self.calculate_performance_score(id, node);
                    Some((id, score))
                } else {
                    None
                }
            })
            .collect();
        
        nodes_with_scores.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        
        nodes_with_scores
            .into_iter()
            .take(count)
            .map(|(id, _)| id)
            .collect()
    }

    /// Discover new bootstrap nodes dynamically
    pub(crate) fn discover_new_nodes(&mut self) -> Result<Vec<BootstrapNodeInfo>, String> {
        let mut discovered_nodes = Vec::new();
        
        // Try DNS discovery
        if let Ok(dns_nodes) = self.discover_via_dns() {
            discovered_nodes.extend(dns_nodes);
        }
        
        // Try multicast discovery (for local networks)
        if let Ok(multicast_nodes) = self.discover_via_multicast() {
            discovered_nodes.extend(multicast_nodes);
        }
        
        // Add discovered nodes to our registry
        for node in &discovered_nodes {
            let node_id = BootstrapNodeId(rand::random());
            self.bootstrap_nodes.insert(node_id, node.clone());
            self.health_stats.insert(node_id, BootstrapHealthStats::default());
        }
        
        if !discovered_nodes.is_empty() {
            info!("Discovered {} new bootstrap nodes", discovered_nodes.len());
        }
        
        Ok(discovered_nodes)
    }

    /// Discover bootstrap nodes via DNS
    fn discover_via_dns(&self) -> Result<Vec<BootstrapNodeInfo>, String> {
        // This would implement DNS-based discovery
        // For now, return empty list
        debug!("DNS-based bootstrap discovery not yet implemented");
        Ok(Vec::new())
    }

    /// Discover bootstrap nodes via multicast
    fn discover_via_multicast(&self) -> Result<Vec<BootstrapNodeInfo>, String> {
        // This would implement multicast-based discovery for local networks
        // For now, return empty list
        debug!("Multicast-based bootstrap discovery not yet implemented");
        Ok(Vec::new())
    }

    /// Calculate initial priority for a bootstrap node
    fn calculate_initial_priority(&self, node: &BootstrapNode) -> u32 {
        let mut priority = 100; // Base priority
        
        if node.can_coordinate {
            priority += 50;
        }
        
        if let Some(rtt) = node.rtt {
            if rtt < Duration::from_millis(50) {
                priority += 30;
            } else if rtt < Duration::from_millis(100) {
                priority += 20;
            } else if rtt < Duration::from_millis(200) {
                priority += 10;
            }
        }
        
        // Prefer IPv6 for better NAT traversal potential
        if node.address.is_ipv6() {
            priority += 10;
        }
        
        priority
    }

    /// Calculate dynamic priority based on performance
    fn calculate_dynamic_priority(&self, node_info: &BootstrapNodeInfo, stats: &BootstrapHealthStats) -> u32 {
        let mut priority = node_info.priority;
        
        // Adjust based on success rate
        let success_rate = if stats.connection_attempts > 0 {
            stats.successful_connections as f64 / stats.connection_attempts as f64
        } else {
            1.0
        };
        
        priority = (priority as f64 * success_rate) as u32;
        
        // Adjust based on RTT
        if let Some(avg_rtt) = stats.average_rtt {
            if avg_rtt < Duration::from_millis(50) {
                priority += 20;
            } else if avg_rtt > Duration::from_millis(500) {
                priority = priority.saturating_sub(20);
            }
        }
        
        // Penalize consecutive failures
        priority = priority.saturating_sub(stats.consecutive_failures * 10);
        
        priority.max(1) // Ensure minimum priority
    }

    /// Calculate performance score for ranking
    fn calculate_performance_score(&self, node_id: BootstrapNodeId, _node_info: &BootstrapNodeInfo) -> f64 {
        let stats = self.health_stats.get(&node_id).unwrap();
        
        let mut score = 0.0;
        
        // Success rate component (40% of score)
        let success_rate = if stats.connection_attempts > 0 {
            stats.successful_connections as f64 / stats.connection_attempts as f64
        } else {
            1.0
        };
        score += success_rate * 0.4;
        
        // RTT component (30% of score)
        if let Some(avg_rtt) = stats.average_rtt {
            let rtt_score = (1000.0 - avg_rtt.as_millis() as f64).max(0.0) / 1000.0;
            score += rtt_score * 0.3;
        } else {
            score += 0.3; // No RTT data, assume good
        }
        
        // Coordination success rate (20% of score)
        let coord_success_rate = if stats.coordination_requests > 0 {
            stats.successful_coordinations as f64 / stats.coordination_requests as f64
        } else {
            1.0
        };
        score += coord_success_rate * 0.2;
        
        // Stability component (10% of score)
        let stability_score = if stats.consecutive_failures == 0 {
            1.0
        } else {
            1.0 / (stats.consecutive_failures as f64 + 1.0)
        };
        score += stability_score * 0.1;
        
        score
    }

    /// Compare health status for sorting
    fn compare_health_status(&self, a: BootstrapHealthStatus, b: BootstrapHealthStatus) -> std::cmp::Ordering {
        use std::cmp::Ordering;
        
        match (a, b) {
            (BootstrapHealthStatus::Healthy, BootstrapHealthStatus::Healthy) => Ordering::Equal,
            (BootstrapHealthStatus::Healthy, _) => Ordering::Less, // Healthy comes first
            (_, BootstrapHealthStatus::Healthy) => Ordering::Greater,
            (BootstrapHealthStatus::Unknown, BootstrapHealthStatus::Unknown) => Ordering::Equal,
            (BootstrapHealthStatus::Unknown, _) => Ordering::Less, // Unknown comes before degraded/unhealthy
            (_, BootstrapHealthStatus::Unknown) => Ordering::Greater,
            (BootstrapHealthStatus::Degraded, BootstrapHealthStatus::Degraded) => Ordering::Equal,
            (BootstrapHealthStatus::Degraded, _) => Ordering::Less, // Degraded comes before unhealthy
            (_, BootstrapHealthStatus::Degraded) => Ordering::Greater,
            (BootstrapHealthStatus::Unhealthy, BootstrapHealthStatus::Unhealthy) => Ordering::Equal,
        }
    }

    /// Update overall performance metrics
    fn update_performance_metrics(&mut self, now: Instant) {
        let mut total_attempts = 0;
        let mut total_successes = 0;
        let mut total_rtt = Duration::ZERO;
        let mut rtt_count = 0;
        
        for stats in self.health_stats.values() {
            total_attempts += stats.connection_attempts;
            total_successes += stats.successful_connections;
            
            if let Some(avg_rtt) = stats.average_rtt {
                total_rtt += avg_rtt;
                rtt_count += 1;
            }
        }
        
        self.performance_tracker.overall_success_rate = if total_attempts > 0 {
            total_successes as f64 / total_attempts as f64
        } else {
            1.0
        };
        
        self.performance_tracker.average_response_time = if rtt_count > 0 {
            total_rtt / rtt_count
        } else {
            Duration::from_millis(100) // Default
        };
        
        // Update best performers
        self.performance_tracker.best_performers = self.get_best_performers(5);
        
        // Record performance snapshot
        let snapshot = PerformanceSnapshot {
            timestamp: now,
            active_nodes: self.get_active_bootstrap_nodes().len() as u32,
            success_rate: self.performance_tracker.overall_success_rate,
            average_rtt: self.performance_tracker.average_response_time,
        };
        
        self.performance_tracker.performance_history.push_back(snapshot);
        if self.performance_tracker.performance_history.len() > 100 {
            self.performance_tracker.performance_history.pop_front();
        }
    }

    /// Schedule next health check
    fn schedule_health_check(&mut self, _now: Instant) {
        // In a complete implementation, this would schedule an async task
        // For now, health checks are performed on-demand via polling
    }

    /// Get performance statistics
    pub(crate) fn get_performance_stats(&self) -> &BootstrapPerformanceTracker {
        &self.performance_tracker
    }

    /// Get health statistics for a specific node
    pub(crate) fn get_node_health_stats(&self, node_id: BootstrapNodeId) -> Option<&BootstrapHealthStats> {
        self.health_stats.get(&node_id)
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

/// Public utility functions for testing IPv6 and dual-stack functionality
pub mod test_utils {
    use super::*;
    
    /// Test utility to calculate address priority for testing
    pub fn calculate_address_priority(address: &IpAddr) -> u32 {
        let mut priority = 100; // Base priority
        match address {
            IpAddr::V4(ipv4) => {
                if ipv4.is_private() {
                    priority += 50; // Prefer private addresses for local networks
                }
            },
            IpAddr::V6(ipv6) => {
                // IPv6 priority based on address type
                // Global unicast: 2000::/3 (not link-local, not unique local)
                if !ipv6.is_loopback() && !ipv6.is_multicast() && !ipv6.is_unspecified() {
                    let segments = ipv6.segments();
                    if segments[0] & 0xE000 == 0x2000 {
                        // Global unicast IPv6 (2000::/3)
                        priority += 60;
                    } else if segments[0] & 0xFFC0 == 0xFE80 {
                        // Link-local IPv6 (fe80::/10)
                        priority += 20;
                    } else if segments[0] & 0xFE00 == 0xFC00 {
                        // Unique local IPv6 (fc00::/7)
                        priority += 40;
                    } else {
                        // Other IPv6 addresses
                        priority += 30;
                    }
                }
                
                // Prefer IPv6 for better NAT traversal potential
                priority += 10; // Small boost for IPv6 overall
            },
        }
        priority
    }
    
    /// Test utility to validate local addresses
    pub fn is_valid_address(address: &IpAddr) -> bool {
        match address {
            IpAddr::V4(ipv4) => !ipv4.is_loopback() && !ipv4.is_unspecified(),
            IpAddr::V6(ipv6) => !ipv6.is_loopback() && !ipv6.is_unspecified(),
        }
    }
}