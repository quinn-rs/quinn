// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses
#![allow(missing_docs)]

//! Candidate Discovery System for QUIC NAT Traversal
//!
//! This module implements sophisticated address candidate discovery including:
//! - Local network interface enumeration (platform-specific)
//! - Server reflexive address discovery via bootstrap nodes
//! - Symmetric NAT port prediction algorithms
//! - Bootstrap node health management and consensus

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use tracing::{debug, error, info, warn};

use crate::{
    connection::nat_traversal::{CandidateSource, CandidateState},
    nat_traversal_api::{BootstrapNode, CandidateAddress, PeerId},
};

// Platform-specific implementations
#[cfg(all(target_os = "windows", feature = "network-discovery"))]
pub mod windows;

#[cfg(all(target_os = "windows", feature = "network-discovery"))]
pub use windows::WindowsInterfaceDiscovery;

#[cfg(all(target_os = "linux", feature = "network-discovery"))]
pub mod linux;

#[cfg(all(target_os = "linux", feature = "network-discovery"))]
pub use linux::LinuxInterfaceDiscovery;

#[cfg(all(target_os = "macos", feature = "network-discovery"))]
pub mod macos;

#[cfg(all(target_os = "macos", feature = "network-discovery"))]
pub use macos::MacOSInterfaceDiscovery;

/// Convert discovery source type to NAT traversal source type
fn convert_to_nat_source(discovery_source: DiscoverySourceType) -> CandidateSource {
    match discovery_source {
        DiscoverySourceType::Local => CandidateSource::Local,
        DiscoverySourceType::ServerReflexive => CandidateSource::Observed { by_node: None },
        DiscoverySourceType::Predicted => CandidateSource::Predicted,
    }
}

/// Source type used during the NAT traversal discovery process
///
/// This enum identifies how a network address candidate was discovered,
/// which affects its priority and reliability in the connection establishment process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoverySourceType {
    /// Locally discovered network interface addresses
    ///
    /// These are addresses assigned to the local machine's network interfaces
    /// and are typically the most reliable for direct connections.
    Local,

    /// Server reflexive addresses discovered via STUN/TURN-like servers
    ///
    /// These are the public addresses that peers see when communicating with
    /// the local endpoint, as observed by bootstrap/coordinator nodes.
    ServerReflexive,

    /// Predicted addresses based on NAT behavior patterns
    ///
    /// These are algorithmically predicted addresses that might work based on
    /// observed NAT traversal patterns and port prediction algorithms.
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

/// Per-peer discovery session containing all state for a single peer's discovery
#[derive(Debug)]
pub struct DiscoverySession {
    /// Current discovery phase
    current_phase: DiscoveryPhase,
    /// Session start time
    started_at: Instant,
    /// Discovered candidates for this peer
    discovered_candidates: Vec<DiscoveryCandidate>,
    /// Discovery statistics
    statistics: DiscoveryStatistics,
}

/// Main candidate discovery manager coordinating all discovery phases
pub struct CandidateDiscoveryManager {
    /// Configuration for discovery behavior
    config: DiscoveryConfig,
    /// Platform-specific interface discovery (shared)
    ///
    /// Uses `parking_lot::Mutex` instead of `std::sync::Mutex` to prevent
    /// tokio runtime deadlocks. parking_lot locks are faster, don't poison,
    /// and have fair locking semantics.
    interface_discovery: Arc<parking_lot::Mutex<Box<dyn NetworkInterfaceDiscovery + Send>>>,
    /// Active discovery sessions per peer
    active_sessions: HashMap<PeerId, DiscoverySession>,
    /// Cached local interface results (shared across all sessions)
    cached_local_candidates: Option<(Instant, Vec<ValidatedCandidate>)>,
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
    /// Actual bound address of the local endpoint (if known)
    pub bound_address: Option<SocketAddr>,
    /// Minimum time to wait before completing discovery (allows time for OBSERVED_ADDRESS)
    pub min_discovery_time: Duration,
}

/// Current phase of the discovery process
#[derive(Debug, Clone, PartialEq)]
#[allow(missing_docs)]
pub enum DiscoveryPhase {
    /// Initial state, ready to begin discovery
    Idle,
    /// Scanning local network interfaces
    LocalInterfaceScanning { started_at: Instant },
    /// Querying bootstrap nodes for server reflexive addresses
    ServerReflexiveQuerying {
        started_at: Instant,
        active_queries: HashMap<BootstrapNodeId, QueryState>,
        responses_received: Vec<ServerReflexiveResponse>,
    },
    // Symmetric NAT prediction phase removed
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
        /// The discovery error that occurred
        error: DiscoveryError,
        /// When the failure occurred
        failed_at: Instant,
        /// Available fallback strategies
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
    LocalCandidateDiscovered { candidate: CandidateAddress },
    /// Local interface scanning completed
    LocalScanningCompleted {
        candidate_count: usize,
        duration: Duration,
    },
    /// Server reflexive discovery started
    ServerReflexiveDiscoveryStarted { bootstrap_count: usize },
    /// Server reflexive address discovered
    ServerReflexiveCandidateDiscovered {
        candidate: CandidateAddress,
        bootstrap_node: SocketAddr,
    },
    /// Bootstrap node query failed
    BootstrapQueryFailed {
        /// The bootstrap node that failed
        bootstrap_node: SocketAddr,
        /// The error message
        error: String,
    },
    // Prediction events removed
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
        /// The discovery error that occurred
        error: DiscoveryError,
        /// Any partial results before failure
        partial_results: Vec<CandidateAddress>,
    },
    /// Path validation requested for a candidate
    PathValidationRequested {
        candidate_id: CandidateId,
        candidate_address: SocketAddr,
        challenge_token: u64,
    },
    /// Path validation response received
    PathValidationResponse {
        candidate_id: CandidateId,
        candidate_address: SocketAddr,
        challenge_token: u64,
        rtt: Duration,
    },
}

/// Unique identifier for bootstrap nodes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BootstrapNodeId(pub u64);

/// State of a bootstrap node query
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryState {
    /// Query is pending (in progress)
    Pending { sent_at: Instant, attempts: u32 },
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
    /// Create a ValidatedCandidate from a DiscoveryCandidate
    ///
    /// # Parameters
    /// - `candidate`: The discovery candidate to convert
    /// - `reliability_score`: Score between 0.0 and 1.0 (1.0 = fully reliable)
    #[inline]
    pub(crate) fn from_discovery(candidate: &DiscoveryCandidate, reliability_score: f64) -> Self {
        Self {
            id: CandidateId(rand::random()),
            address: candidate.address,
            source: candidate.source,
            priority: candidate.priority,
            rtt: None,
            reliability_score,
        }
    }

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
    pub invalid_addresses_rejected: u32,
}

/// Errors that can occur during the NAT traversal discovery process
///
/// These errors represent various failure modes that can occur while
/// discovering network address candidates for NAT traversal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoveryError {
    /// No local network interfaces could be discovered
    ///
    /// This typically indicates a network configuration issue or
    /// insufficient permissions to enumerate network interfaces.
    NoLocalInterfaces,

    /// All bootstrap node queries failed
    ///
    /// This means the endpoint could not reach any bootstrap nodes
    /// to discover its public address or coordinate with other peers.
    AllBootstrapsFailed,

    /// Discovery process exceeded the configured timeout
    ///
    /// The discovery process took longer than the configured
    /// `total_timeout` duration and was terminated.
    DiscoveryTimeout,

    /// Insufficient candidates were discovered for reliable connectivity
    ///
    /// The discovery process found fewer candidates than required
    /// for establishing reliable peer-to-peer connections.
    InsufficientCandidates {
        /// Number of candidates actually found
        found: usize,
        /// Minimum number of candidates required
        required: usize,
    },

    /// Platform-specific network error occurred
    ///
    /// This wraps lower-level network errors that are specific to
    /// the operating system or platform being used.
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
            bound_address: None,
            // Wait at least 10 seconds for external address discovery (OBSERVED_ADDRESS)
            // before completing discovery. This ensures we don't complete before
            // connecting to peers who can tell us our external address.
            min_discovery_time: Duration::from_secs(10),
        }
    }
}

impl DiscoverySession {
    /// Create a new discovery session for a peer
    fn new(_config: &DiscoveryConfig) -> Self {
        Self {
            current_phase: DiscoveryPhase::Idle,
            started_at: Instant::now(),
            discovered_candidates: Vec::new(),
            statistics: DiscoveryStatistics::default(),
        }
    }
}

impl CandidateDiscoveryManager {
    /// Create a new candidate discovery manager
    pub fn new(config: DiscoveryConfig) -> Self {
        let interface_discovery = Arc::new(parking_lot::Mutex::new(
            create_platform_interface_discovery(),
        ));

        Self {
            config,
            interface_discovery,
            active_sessions: HashMap::new(),
            cached_local_candidates: None,
        }
    }

    /// Set the actual bound address of the local endpoint
    pub fn set_bound_address(&mut self, address: SocketAddr) {
        self.config.bound_address = Some(address);
        // Clear cached local candidates to force refresh with new bound address
        self.cached_local_candidates = None;
    }

    /// Discover local network interface candidates synchronously
    pub fn discover_local_candidates(&mut self) -> Result<Vec<ValidatedCandidate>, DiscoveryError> {
        // Start interface scan
        self.interface_discovery.lock().start_scan().map_err(|e| {
            DiscoveryError::NetworkError(format!("Failed to start interface scan: {e}"))
        })?;

        // Poll until scan completes (this should be quick for local interfaces)
        let start = Instant::now();
        let timeout = Duration::from_secs(2);

        loop {
            if start.elapsed() > timeout {
                return Err(DiscoveryError::DiscoveryTimeout);
            }

            let scan_complete = self.interface_discovery.lock().check_scan_complete();

            if let Some(interfaces) = scan_complete {
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
    pub fn start_discovery(
        &mut self,
        peer_id: PeerId,
        _bootstrap_nodes: Vec<BootstrapNode>,
    ) -> Result<(), DiscoveryError> {
        // Check if session already exists for this peer
        if let Some(existing) = self.active_sessions.get(&peer_id) {
            match &existing.current_phase {
                DiscoveryPhase::Completed { .. } | DiscoveryPhase::Failed { .. } => {
                    // Old session is done - remove it and allow new discovery
                    debug!(
                        "Removing old completed/failed session for peer {:?} to start new discovery",
                        peer_id
                    );
                    self.active_sessions.remove(&peer_id);
                }
                DiscoveryPhase::LocalInterfaceScanning { .. } => {
                    // Discovery is actively in progress
                    return Err(DiscoveryError::InternalError(format!(
                        "Discovery already in progress for peer {peer_id:?}"
                    )));
                }
                DiscoveryPhase::Idle => {
                    // Session exists but is idle - remove and restart
                    self.active_sessions.remove(&peer_id);
                }
                _ => {
                    // Other phases - discovery is in progress
                    return Err(DiscoveryError::InternalError(format!(
                        "Discovery already in progress for peer {peer_id:?}"
                    )));
                }
            }
        }

        info!("Starting candidate discovery for peer {:?}", peer_id);

        // Create new session
        let mut session = DiscoverySession::new(&self.config);

        // Start with local interface scanning
        session.current_phase = DiscoveryPhase::LocalInterfaceScanning {
            started_at: Instant::now(),
        };

        // Add session to active sessions
        self.active_sessions.insert(peer_id, session);

        Ok(())
    }

    /// Poll for discovery progress and state updates across all active sessions
    pub fn poll(&mut self, now: Instant) -> Vec<DiscoveryEvent> {
        let mut all_events = Vec::new();

        // Collect peer IDs to process (avoid borrowing issues)
        let peer_ids: Vec<PeerId> = self.active_sessions.keys().copied().collect();

        for peer_id in peer_ids {
            // Get the current phase by cloning the needed data
            let phase_info = self
                .active_sessions
                .get(&peer_id)
                .map(|s| (s.current_phase.clone(), s.started_at));

            if let Some((DiscoveryPhase::LocalInterfaceScanning { started_at }, session_start)) =
                phase_info
            {
                // Step 1: Start interface scan if just entering phase (within first 50ms)
                if started_at.elapsed().as_millis() < 50 {
                    let scan_result = self.interface_discovery.lock().start_scan();
                    if let Err(e) = scan_result {
                        error!("Failed to start interface scan for {:?}: {}", peer_id, e);
                    } else {
                        debug!("Started local interface scan for peer {:?}", peer_id);
                        all_events.push(DiscoveryEvent::LocalScanningStarted);
                    }
                }

                // Step 2: Check if scanning is complete
                let scan_complete_result = self.interface_discovery.lock().check_scan_complete();

                if let Some(interfaces) = scan_complete_result {
                    // Step 3: Process interfaces and add candidates
                    debug!(
                        "Processing {} network interfaces for peer {:?}",
                        interfaces.len(),
                        peer_id
                    );

                    let mut candidates_added = 0;

                    // Add the bound address if available
                    if let Some(bound_addr) = self.config.bound_address {
                        if self.is_valid_local_address(&bound_addr) || bound_addr.ip().is_loopback()
                        {
                            let candidate = DiscoveryCandidate {
                                address: bound_addr,
                                priority: 60000, // High priority for the actual bound address
                                source: DiscoverySourceType::Local,
                                state: CandidateState::New,
                            };

                            if let Some(session) = self.active_sessions.get_mut(&peer_id) {
                                session.discovered_candidates.push(candidate.clone());
                                session.statistics.local_candidates_found += 1;
                                candidates_added += 1;

                                all_events.push(DiscoveryEvent::LocalCandidateDiscovered {
                                    candidate: candidate.to_candidate_address(),
                                });

                                debug!(
                                    "Added bound address {} as local candidate for peer {:?}",
                                    bound_addr, peer_id
                                );
                            }
                        }
                    }

                    // Process discovered interfaces
                    // Get the bound port to use for interface addresses (they come with port 0)
                    let bound_port = self.config.bound_address.map(|a| a.port()).unwrap_or(9000);

                    for interface in &interfaces {
                        for address in &interface.addresses {
                            // Interface addresses come with port 0, use our bound port instead
                            let candidate_addr = if address.port() == 0 {
                                SocketAddr::new(address.ip(), bound_port)
                            } else {
                                *address
                            };

                            // Skip if this is the same as the bound address
                            if Some(candidate_addr) == self.config.bound_address {
                                continue;
                            }

                            // Skip unspecified addresses (0.0.0.0 or ::)
                            if candidate_addr.ip().is_unspecified() {
                                continue;
                            }

                            if self.is_valid_local_address(&candidate_addr) {
                                // Calculate priority before borrowing session mutably
                                let priority =
                                    self.calculate_local_priority(&candidate_addr, interface);
                                if let Some(session) = self.active_sessions.get_mut(&peer_id) {
                                    let candidate = DiscoveryCandidate {
                                        address: candidate_addr,
                                        priority,
                                        source: DiscoverySourceType::Local,
                                        state: CandidateState::New,
                                    };

                                    session.discovered_candidates.push(candidate.clone());
                                    session.statistics.local_candidates_found += 1;
                                    candidates_added += 1;

                                    debug!(
                                        "Added local candidate {} for peer {:?}",
                                        candidate_addr, peer_id
                                    );

                                    all_events.push(DiscoveryEvent::LocalCandidateDiscovered {
                                        candidate: candidate.to_candidate_address(),
                                    });
                                }
                            }
                        }
                    }

                    all_events.push(DiscoveryEvent::LocalScanningCompleted {
                        candidate_count: candidates_added,
                        duration: started_at.elapsed(),
                    });

                    // Step 4: Check if we should complete discovery
                    // Wait for min_discovery_time to allow OBSERVED_ADDRESS frames
                    let elapsed = now.duration_since(session_start);
                    let has_external = self
                        .active_sessions
                        .get(&peer_id)
                        .is_some_and(|s| s.statistics.server_reflexive_candidates_found > 0);

                    if elapsed >= self.config.min_discovery_time || has_external {
                        // Complete discovery
                        if let Some(session) = self.active_sessions.get_mut(&peer_id) {
                            let final_candidates: Vec<ValidatedCandidate> = session
                                .discovered_candidates
                                .iter()
                                .map(|dc| ValidatedCandidate::from_discovery(dc, 1.0))
                                .collect();

                            let candidate_count = final_candidates.len();
                            session.current_phase = DiscoveryPhase::Completed {
                                final_candidates,
                                completion_time: now,
                            };

                            info!(
                                "Discovery completed for peer {:?}: {} candidates found",
                                peer_id, candidate_count
                            );

                            all_events.push(DiscoveryEvent::DiscoveryCompleted {
                                candidate_count,
                                total_duration: elapsed,
                                success_rate: if candidate_count > 0 { 1.0 } else { 0.0 },
                            });
                        }
                    } else {
                        debug!(
                            "Delaying discovery completion for peer {:?}: elapsed {:?} < min {:?}",
                            peer_id, elapsed, self.config.min_discovery_time
                        );
                    }
                } else if started_at.elapsed() > self.config.local_scan_timeout {
                    // Timeout - complete with whatever we have
                    warn!(
                        "Local interface scan timeout for peer {:?}, proceeding with available candidates",
                        peer_id
                    );

                    if let Some(session) = self.active_sessions.get_mut(&peer_id) {
                        let final_candidates: Vec<ValidatedCandidate> = session
                            .discovered_candidates
                            .iter()
                            .map(|dc| ValidatedCandidate::from_discovery(dc, 1.0))
                            .collect();

                        let candidate_count = final_candidates.len();

                        all_events.push(DiscoveryEvent::LocalScanningCompleted {
                            candidate_count,
                            duration: started_at.elapsed(),
                        });

                        session.current_phase = DiscoveryPhase::Completed {
                            final_candidates,
                            completion_time: now,
                        };

                        all_events.push(DiscoveryEvent::DiscoveryCompleted {
                            candidate_count,
                            total_duration: now.duration_since(session.started_at),
                            success_rate: if candidate_count > 0 { 1.0 } else { 0.0 },
                        });

                        info!(
                            "Discovery completed (timeout) for peer {:?}: {} candidates",
                            peer_id, candidate_count
                        );
                    }
                }
            }
        }

        // Note: We intentionally do NOT remove completed sessions here.
        // Sessions remain in active_sessions so get_candidates_for_peer() can access them.
        // They will be cleaned up when a new discovery is started for the same peer,
        // or via cleanup_stale_sessions() if needed.

        all_events
    }

    /// Clean up sessions that have been completed for longer than the specified duration
    pub fn cleanup_stale_sessions(&mut self, max_age: Duration) {
        let now = Instant::now();
        let stale: Vec<PeerId> = self
            .active_sessions
            .iter()
            .filter_map(|(peer_id, session)| {
                if let DiscoveryPhase::Completed {
                    completion_time, ..
                } = &session.current_phase
                {
                    if now.duration_since(*completion_time) > max_age {
                        return Some(*peer_id);
                    }
                }
                None
            })
            .collect();

        for peer_id in stale {
            self.active_sessions.remove(&peer_id);
            debug!("Cleaned up stale discovery session for peer {:?}", peer_id);
        }
    }

    /// Get current discovery status
    pub fn get_status(&self) -> DiscoveryStatus {
        // Return a default status since we now manage multiple sessions
        DiscoveryStatus {
            phase: DiscoveryPhase::Idle,
            discovered_candidates: Vec::new(),
            statistics: DiscoveryStatistics::default(),
            elapsed_time: Duration::from_secs(0),
        }
    }

    /// Check if discovery is complete
    pub fn is_complete(&self) -> bool {
        // All sessions must be complete
        self.active_sessions.values().all(|session| {
            matches!(
                session.current_phase,
                DiscoveryPhase::Completed { .. } | DiscoveryPhase::Failed { .. }
            )
        })
    }

    /// Get final discovery results
    pub fn get_results(&self) -> Option<DiscoveryResults> {
        // Return results from all completed sessions
        if self.active_sessions.is_empty() {
            return None;
        }

        // Aggregate results from all sessions
        let mut all_candidates = Vec::new();
        let mut latest_completion = Instant::now();
        let mut combined_stats = DiscoveryStatistics::default();

        for session in self.active_sessions.values() {
            match &session.current_phase {
                DiscoveryPhase::Completed {
                    final_candidates,
                    completion_time,
                } => {
                    // Add candidates from this session
                    all_candidates.extend(final_candidates.clone());
                    latest_completion = *completion_time;
                    // Combine statistics
                    combined_stats.local_candidates_found +=
                        session.statistics.local_candidates_found;
                    combined_stats.server_reflexive_candidates_found +=
                        session.statistics.server_reflexive_candidates_found;
                    combined_stats.predicted_candidates_generated +=
                        session.statistics.predicted_candidates_generated;
                    combined_stats.bootstrap_queries_sent +=
                        session.statistics.bootstrap_queries_sent;
                    combined_stats.bootstrap_queries_successful +=
                        session.statistics.bootstrap_queries_successful;
                }
                DiscoveryPhase::Failed { .. } => {
                    // Include any partial results from failed sessions
                    let validated: Vec<ValidatedCandidate> = session
                        .discovered_candidates
                        .iter()
                        .map(|dc| ValidatedCandidate::from_discovery(dc, 0.5))
                        .collect();
                    all_candidates.extend(validated);
                }
                _ => {}
            }
        }

        if all_candidates.is_empty() {
            None
        } else {
            Some(DiscoveryResults {
                candidates: all_candidates,
                completion_time: latest_completion,
                statistics: combined_stats,
            })
        }
    }

    /// Get all discovered candidates for a specific peer
    pub fn get_candidates_for_peer(&self, peer_id: PeerId) -> Vec<CandidateAddress> {
        // Look up the specific session for this peer
        if let Some(session) = self.active_sessions.get(&peer_id) {
            // Return all discovered candidates converted to CandidateAddress
            session
                .discovered_candidates
                .iter()
                .map(|c| c.to_candidate_address())
                .collect()
        } else {
            // No active session for this peer
            debug!("No active discovery session found for peer {:?}", peer_id);
            Vec::new()
        }
    }

    /// Add an external address discovered from an OBSERVED_ADDRESS frame
    ///
    /// This is called when a connected peer reports our external address via the
    /// OBSERVED_ADDRESS frame (draft-ietf-quic-address-discovery). These addresses
    /// are server-reflexive and represent how we appear to external peers.
    pub fn add_external_address(&mut self, peer_id: PeerId, external_addr: SocketAddr) {
        if let Some(session) = self.active_sessions.get_mut(&peer_id) {
            // Check if we already have this address
            if session
                .discovered_candidates
                .iter()
                .any(|c| c.address == external_addr)
            {
                debug!(
                    "External address {} already known for peer {:?}",
                    external_addr, peer_id
                );
                return;
            }

            let candidate = DiscoveryCandidate {
                address: external_addr,
                priority: 55000, // High priority - external addresses are valuable
                source: DiscoverySourceType::ServerReflexive,
                state: CandidateState::New,
            };

            session.discovered_candidates.push(candidate);
            session.statistics.server_reflexive_candidates_found += 1;

            info!(
                "Added external address {} for peer {:?} (from OBSERVED_ADDRESS)",
                external_addr, peer_id
            );
        } else {
            debug!(
                "No active session for peer {:?}, cannot add external address {}",
                peer_id, external_addr
            );
        }
    }

    /// Add an external address for all active sessions
    ///
    /// This is useful when we discover our external address from any connected peer -
    /// it can be used for NAT traversal to other peers as well.
    pub fn add_external_address_to_all(&mut self, external_addr: SocketAddr) {
        let peer_ids: Vec<PeerId> = self.active_sessions.keys().copied().collect();
        let mut added_count = 0;

        for peer_id in peer_ids {
            if let Some(session) = self.active_sessions.get_mut(&peer_id) {
                // Check if we already have this address
                if session
                    .discovered_candidates
                    .iter()
                    .any(|c| c.address == external_addr)
                {
                    continue;
                }

                let candidate = DiscoveryCandidate {
                    address: external_addr,
                    priority: 55000,
                    source: DiscoverySourceType::ServerReflexive,
                    state: CandidateState::New,
                };

                session.discovered_candidates.push(candidate);
                session.statistics.server_reflexive_candidates_found += 1;
                added_count += 1;
            }
        }

        if added_count > 0 {
            info!(
                "Added external address {} to {} active discovery sessions",
                external_addr, added_count
            );
        }
    }

    fn is_valid_local_address(&self, address: &SocketAddr) -> bool {
        // Use the enhanced validation from CandidateAddress
        use crate::nat_traversal_api::CandidateAddress;

        if let Err(e) = CandidateAddress::validate_address(address) {
            debug!("Address {} failed validation: {}", address, e);
            return false;
        }

        match address.ip() {
            IpAddr::V4(ipv4) => {
                // For testing, allow loopback addresses
                #[cfg(test)]
                if ipv4.is_loopback() {
                    return true;
                }
                // For local addresses, we want actual interface addresses
                // Allow private addresses (RFC1918)
                !ipv4.is_loopback()
                    && !ipv4.is_unspecified()
                    && !ipv4.is_broadcast()
                    && !ipv4.is_multicast()
                    && !ipv4.is_documentation()
            }
            IpAddr::V6(ipv6) => {
                // For testing, allow loopback addresses
                #[cfg(test)]
                if ipv6.is_loopback() {
                    return true;
                }
                // For IPv6, accept most addresses except special ones
                let segments = ipv6.segments();
                let is_documentation = segments[0] == 0x2001 && segments[1] == 0x0db8;

                !ipv6.is_loopback()
                    && !ipv6.is_unspecified()
                    && !ipv6.is_multicast()
                    && !is_documentation
            }
        }
    }

    // Removed server reflexive address validation helper

    fn calculate_local_priority(&self, address: &SocketAddr, interface: &NetworkInterface) -> u32 {
        let mut priority = 100; // Base priority

        match address.ip() {
            IpAddr::V4(ipv4) => {
                if ipv4.is_private() {
                    priority += 50; // Prefer private addresses for local networks
                }
            }
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
            }
        }

        if interface.is_wireless {
            priority -= 10; // Slight penalty for wireless
        }

        priority
    }
    /// Accept a QUIC-discovered address (from OBSERVED_ADDRESS frames)
    /// This replaces the need for STUN-based server reflexive discovery
    pub fn accept_quic_discovered_address(
        &mut self,
        peer_id: PeerId,
        discovered_address: SocketAddr,
    ) -> Result<bool, DiscoveryError> {
        // Calculate priority for the discovered address first to avoid borrow issues
        let priority = self.calculate_quic_discovered_priority(&discovered_address);

        // Get the active session for this peer
        let session = self.active_sessions.get_mut(&peer_id).ok_or_else(|| {
            DiscoveryError::InternalError(format!(
                "No active discovery session for peer {peer_id:?}"
            ))
        })?;

        // Check if address already exists
        let already_exists = session
            .discovered_candidates
            .iter()
            .any(|c| c.address == discovered_address);

        if already_exists {
            debug!(
                "QUIC-discovered address {} already in candidates",
                discovered_address
            );
            return Ok(false);
        }

        info!("Accepting QUIC-discovered address: {}", discovered_address);

        // Create candidate from QUIC-discovered address
        let candidate = DiscoveryCandidate {
            address: discovered_address,
            priority,
            source: DiscoverySourceType::ServerReflexive,
            state: CandidateState::New,
        };

        // Add to discovered candidates
        session.discovered_candidates.push(candidate);
        session.statistics.server_reflexive_candidates_found += 1;

        Ok(true)
    }

    /// Calculate priority for QUIC-discovered addresses
    fn calculate_quic_discovered_priority(&self, address: &SocketAddr) -> u32 {
        // QUIC-discovered addresses get higher priority than STUN-discovered ones
        // because they come from actual QUIC connections and are more reliable
        let mut priority = 255; // Base priority for QUIC-discovered addresses

        match address.ip() {
            IpAddr::V4(ipv4) => {
                if ipv4.is_private() {
                    priority -= 10; // Slight penalty for private addresses
                } else if ipv4.is_loopback() {
                    priority -= 20; // More penalty for loopback
                }
                // Public IPv4 keeps base priority of 255
            }
            IpAddr::V6(ipv6) => {
                // Prefer IPv6 for better NAT traversal potential
                priority += 10; // Boost for IPv6 (265 base)

                if ipv6.is_loopback() {
                    priority -= 30; // Significant penalty for loopback
                } else if ipv6.is_multicast() {
                    priority -= 40; // Even more penalty for multicast
                } else if ipv6.is_unspecified() {
                    priority -= 50; // Unspecified should not be used
                } else {
                    // Check for specific IPv6 types
                    let segments = ipv6.segments();
                    if segments[0] & 0xFFC0 == 0xFE80 {
                        // Link-local IPv6 (fe80::/10)
                        priority -= 30; // Significant penalty
                    } else if segments[0] & 0xFE00 == 0xFC00 {
                        // Unique local IPv6 (fc00::/7)
                        priority -= 10; // Slight penalty, similar to private IPv4
                    }
                    // Global unicast IPv6 (2000::/3) keeps the boost
                }
            }
        }

        priority
    }

    /// Poll discovery progress and get pending events
    pub fn poll_discovery_progress(&mut self, peer_id: PeerId) -> Vec<DiscoveryEvent> {
        let mut events = Vec::new();

        if let Some(session) = self.active_sessions.get_mut(&peer_id) {
            // Check if we have new candidates to report
            for candidate in &session.discovered_candidates {
                if matches!(candidate.state, CandidateState::New) {
                    events.push(DiscoveryEvent::ServerReflexiveCandidateDiscovered {
                        candidate: candidate.to_candidate_address(),
                        bootstrap_node: SocketAddr::from(([0, 0, 0, 0], 0)),
                    });
                }
            }

            // Mark all new candidates as reported
            for candidate in &mut session.discovered_candidates {
                if matches!(candidate.state, CandidateState::New) {
                    candidate.state = CandidateState::Validating;
                }
            }
        }

        events
    }

    /// Get the current discovery status for a peer
    pub fn get_discovery_status(&self, peer_id: PeerId) -> Option<DiscoveryStatus> {
        self.active_sessions.get(&peer_id).map(|session| {
            let discovered_candidates = session
                .discovered_candidates
                .iter()
                .map(|c| c.to_candidate_address())
                .collect();

            DiscoveryStatus {
                phase: session.current_phase.clone(),
                discovered_candidates,
                statistics: session.statistics.clone(),
                elapsed_time: session.started_at.elapsed(),
            }
        })
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

/// Create platform-specific network interface discovery
pub(crate) fn create_platform_interface_discovery() -> Box<dyn NetworkInterfaceDiscovery + Send> {
    #[cfg(all(target_os = "windows", feature = "network-discovery"))]
    return Box::new(WindowsInterfaceDiscovery::new());

    #[cfg(all(target_os = "linux", feature = "network-discovery"))]
    return Box::new(LinuxInterfaceDiscovery::new());

    #[cfg(all(target_os = "macos", feature = "network-discovery"))]
    return Box::new(MacOSInterfaceDiscovery::new());

    // Fallback to generic implementation when:
    // - Platform doesn't have a specific implementation
    // - network-discovery feature is disabled
    #[cfg(any(
        all(target_os = "windows", not(feature = "network-discovery")),
        all(target_os = "linux", not(feature = "network-discovery")),
        all(target_os = "macos", not(feature = "network-discovery")),
        not(any(target_os = "windows", target_os = "linux", target_os = "macos"))
    ))]
    return Box::new(GenericInterfaceDiscovery::new());
}

// Platform-specific implementations

// Windows implementation is in windows.rs module

// Linux implementation is in linux.rs module

// macOS implementation is in macos.rs module

// Generic fallback implementation
#[allow(dead_code)]
pub(crate) struct GenericInterfaceDiscovery {
    scan_complete: bool,
}

impl GenericInterfaceDiscovery {
    #[allow(dead_code)]
    pub(crate) fn new() -> Self {
        Self {
            scan_complete: false,
        }
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
            Some(vec![NetworkInterface {
                name: "generic".to_string(),
                addresses: vec![SocketAddr::from(([127, 0, 0, 1], 0))],
                is_up: true,
                is_wireless: false,
                mtu: Some(1500),
            }])
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
            Self::InsufficientCandidates { found, required } => {
                write!(f, "insufficient candidates found: {found} < {required}")
            }
            Self::NetworkError(msg) => write!(f, "network error: {msg}"),
            Self::ConfigurationError(msg) => write!(f, "configuration error: {msg}"),
            Self::InternalError(msg) => write!(f, "internal error: {msg}"),
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
            }
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
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_manager() -> CandidateDiscoveryManager {
        let config = DiscoveryConfig {
            total_timeout: Duration::from_secs(30),
            local_scan_timeout: Duration::from_secs(5),
            bootstrap_query_timeout: Duration::from_secs(10),
            max_query_retries: 3,
            max_candidates: 50,
            enable_symmetric_prediction: true,
            min_bootstrap_consensus: 2,
            interface_cache_ttl: Duration::from_secs(300),
            server_reflexive_cache_ttl: Duration::from_secs(600),
            bound_address: None,
            // For tests, allow immediate completion (no waiting for OBSERVED_ADDRESS)
            min_discovery_time: Duration::ZERO,
        };
        CandidateDiscoveryManager::new(config)
    }

    #[test]
    fn test_accept_quic_discovered_addresses() {
        let mut manager = create_test_manager();
        let peer_id = PeerId([1; 32]);

        // Create a discovery session
        manager
            .start_discovery(peer_id, vec![])
            .expect("Failed to start discovery in test");

        // Test accepting QUIC-discovered addresses
        let discovered_addr = "192.168.1.100:5000"
            .parse()
            .expect("Failed to parse test address");
        let result = manager.accept_quic_discovered_address(peer_id, discovered_addr);

        assert!(result.is_ok());

        // Verify the address was added to the session
        if let Some(session) = manager.active_sessions.get(&peer_id) {
            let found = session.discovered_candidates.iter().any(|c| {
                c.address == discovered_addr
                    && matches!(c.source, DiscoverySourceType::ServerReflexive)
            });
            assert!(found, "QUIC-discovered address should be in candidates");
        }
    }

    #[test]
    fn test_accept_quic_discovered_addresses_no_session() {
        let mut manager = create_test_manager();
        let peer_id = PeerId([1; 32]);
        let discovered_addr = "192.168.1.100:5000"
            .parse()
            .expect("Failed to parse test address");

        // Try to add address without an active session
        let result = manager.accept_quic_discovered_address(peer_id, discovered_addr);

        assert!(result.is_err());
        match result {
            Err(DiscoveryError::InternalError(msg)) => {
                assert!(msg.contains("No active discovery session"));
            }
            _ => panic!("Expected InternalError for missing session"),
        }
    }

    #[test]
    fn test_accept_quic_discovered_addresses_deduplication() {
        let mut manager = create_test_manager();
        let peer_id = PeerId([1; 32]);

        // Create a discovery session
        manager
            .start_discovery(peer_id, vec![])
            .expect("Failed to start discovery in test");

        // Add the same address twice
        let discovered_addr = "192.168.1.100:5000"
            .parse()
            .expect("Failed to parse test address");
        let result1 = manager.accept_quic_discovered_address(peer_id, discovered_addr);
        let result2 = manager.accept_quic_discovered_address(peer_id, discovered_addr);

        assert!(result1.is_ok());
        assert!(result2.is_ok()); // Should succeed but not duplicate

        // Verify no duplicates
        if let Some(session) = manager.active_sessions.get(&peer_id) {
            let count = session
                .discovered_candidates
                .iter()
                .filter(|c| c.address == discovered_addr)
                .count();
            assert_eq!(count, 1, "Should not have duplicate addresses");
        }
    }

    #[test]
    fn test_accept_quic_discovered_addresses_priority() {
        let mut manager = create_test_manager();
        let peer_id = PeerId([1; 32]);

        // Create a discovery session
        manager
            .start_discovery(peer_id, vec![])
            .expect("Failed to start discovery in test");

        // Add different types of addresses
        let public_addr = "8.8.8.8:5000"
            .parse()
            .expect("Failed to parse test address");
        let private_addr = "192.168.1.100:5000"
            .parse()
            .expect("Failed to parse test address");
        let ipv6_addr = "[2001:db8::1]:5000"
            .parse()
            .expect("Failed to parse test address");

        manager
            .accept_quic_discovered_address(peer_id, public_addr)
            .expect("Failed to accept public address in test");
        manager
            .accept_quic_discovered_address(peer_id, private_addr)
            .expect("Failed to accept private address in test");
        manager
            .accept_quic_discovered_address(peer_id, ipv6_addr)
            .unwrap();

        // Verify priorities are assigned correctly
        if let Some(session) = manager.active_sessions.get(&peer_id) {
            for candidate in &session.discovered_candidates {
                assert!(
                    candidate.priority > 0,
                    "All candidates should have non-zero priority"
                );

                // Verify IPv6 gets a boost
                if candidate.address == ipv6_addr {
                    let ipv4_priority = session
                        .discovered_candidates
                        .iter()
                        .find(|c| c.address == public_addr)
                        .map(|c| c.priority)
                        .expect("Public address should be found in candidates");

                    // IPv6 should have higher or equal priority (due to boost)
                    assert!(candidate.priority >= ipv4_priority);
                }
            }
        }
    }

    #[test]
    fn test_accept_quic_discovered_addresses_event_generation() {
        let mut manager = create_test_manager();
        let peer_id = PeerId([1; 32]);

        // Create a discovery session
        manager
            .start_discovery(peer_id, vec![])
            .expect("Failed to start discovery in test");

        // Add address and check for events
        let discovered_addr = "192.168.1.100:5000"
            .parse()
            .expect("Failed to parse test address");
        manager
            .accept_quic_discovered_address(peer_id, discovered_addr)
            .expect("Failed to accept address in test");

        // Poll for events
        let events = manager.poll_discovery_progress(peer_id);

        // Should have a ServerReflexiveCandidateDiscovered event
        let has_event = events.iter().any(|e| {
            matches!(e,
                DiscoveryEvent::ServerReflexiveCandidateDiscovered { candidate, .. }
                if candidate.address == discovered_addr
            )
        });

        assert!(
            has_event,
            "Should generate discovery event for QUIC-discovered address"
        );
    }

    #[test]
    fn test_discovery_completes_without_server_reflexive_phase() {
        let mut manager = create_test_manager();
        let peer_id = PeerId([1; 32]);

        // Start discovery
        manager
            .start_discovery(peer_id, vec![])
            .expect("Failed to start discovery in test");

        // Add a QUIC-discovered address
        let discovered_addr = "192.168.1.100:5000"
            .parse()
            .expect("Failed to parse test address");
        manager
            .accept_quic_discovered_address(peer_id, discovered_addr)
            .expect("Failed to accept address in test");

        // Poll discovery to advance state
        let status = manager
            .get_discovery_status(peer_id)
            .expect("Failed to get discovery status in test");

        // Should not be in ServerReflexiveQuerying phase
        match &status.phase {
            DiscoveryPhase::ServerReflexiveQuerying { .. } => {
                panic!("Should not be in ServerReflexiveQuerying phase when using QUIC discovery");
            }
            _ => {} // Any other phase is fine
        }
    }

    #[test]
    fn test_no_bootstrap_queries_when_using_quic_discovery() {
        let mut manager = create_test_manager();
        let peer_id = PeerId([1; 32]);

        // Start discovery
        manager
            .start_discovery(peer_id, vec![])
            .expect("Failed to start discovery in test");

        // Immediately add QUIC-discovered addresses
        let addr1 = "192.168.1.100:5000"
            .parse()
            .expect("Failed to parse test address");
        let addr2 = "8.8.8.8:5000"
            .parse()
            .expect("Failed to parse test address");
        manager
            .accept_quic_discovered_address(peer_id, addr1)
            .expect("Failed to accept address in test");
        manager
            .accept_quic_discovered_address(peer_id, addr2)
            .expect("Failed to accept address in test");

        // Get status to check phase
        let status = manager
            .get_discovery_status(peer_id)
            .expect("Failed to get discovery status in test");

        // Verify we have candidates from QUIC discovery
        assert!(status.discovered_candidates.len() >= 2);

        // Verify no bootstrap queries were made
        if let Some(session) = manager.active_sessions.get(&peer_id) {
            // Check that we didn't record any bootstrap query statistics
            assert_eq!(
                session.statistics.bootstrap_queries_sent, 0,
                "Should not query bootstrap nodes when using QUIC discovery"
            );
        }
    }

    #[test]
    fn test_priority_differences_quic_vs_placeholder() {
        let mut manager = create_test_manager();
        let peer_id = PeerId([1; 32]);

        // Start discovery
        manager
            .start_discovery(peer_id, vec![])
            .expect("Failed to start discovery in test");

        // Add QUIC-discovered address
        let discovered_addr = "8.8.8.8:5000"
            .parse()
            .expect("Failed to parse test address");
        manager
            .accept_quic_discovered_address(peer_id, discovered_addr)
            .expect("Failed to accept address in test");

        // Check the priority assigned
        if let Some(session) = manager.active_sessions.get(&peer_id) {
            let candidate = session
                .discovered_candidates
                .iter()
                .find(|c| c.address == discovered_addr)
                .expect("Should find the discovered address");

            // QUIC-discovered addresses should have reasonable priority
            assert!(
                candidate.priority > 100,
                "QUIC-discovered address should have good priority"
            );
            assert!(candidate.priority < 300, "Priority should be reasonable");

            // Verify it's marked as ServerReflexive type (for compatibility)
            assert!(matches!(
                candidate.source,
                DiscoverySourceType::ServerReflexive
            ));
        }
    }

    #[test]
    fn test_quic_discovered_address_priority_calculation() {
        // Test that QUIC-discovered addresses get appropriate priorities based on characteristics
        let mut manager = create_test_manager();
        let peer_id = PeerId([1; 32]);

        // Start discovery
        manager
            .start_discovery(peer_id, vec![])
            .expect("Failed to start discovery in test");

        // Test different types of addresses
        let test_cases = vec![
            // (address, expected_priority_range, description)
            ("1.2.3.4:5678", (250, 260), "Public IPv4"),
            ("192.168.1.100:9000", (240, 250), "Private IPv4"),
            ("[2001:db8::1]:5678", (260, 280), "Global IPv6"),
            ("[fe80::1]:5678", (220, 240), "Link-local IPv6"),
            ("[fc00::1]:5678", (240, 260), "Unique local IPv6"),
            ("10.0.0.1:9000", (240, 250), "Private IPv4 (10.x)"),
            ("172.16.0.1:9000", (240, 250), "Private IPv4 (172.16.x)"),
        ];

        for (addr_str, (min_priority, max_priority), description) in test_cases {
            let addr: SocketAddr = addr_str.parse().expect("Failed to parse test address");
            manager
                .accept_quic_discovered_address(peer_id, addr)
                .expect("Failed to accept address in test");

            let session = manager
                .active_sessions
                .get(&peer_id)
                .expect("Session should exist in test");
            let candidate = session
                .discovered_candidates
                .iter()
                .find(|c| c.address == addr)
                .unwrap_or_else(|| panic!("No candidate found for {}", description));

            assert!(
                candidate.priority >= min_priority && candidate.priority <= max_priority,
                "{} priority {} not in range [{}, {}]",
                description,
                candidate.priority,
                min_priority,
                max_priority
            );
        }
    }

    #[test]
    fn test_quic_discovered_priority_factors() {
        // Test that various factors affect priority calculation
        let manager = create_test_manager();

        // Test base priority calculation
        let base_priority = manager.calculate_quic_discovered_priority(
            &"1.2.3.4:5678"
                .parse()
                .expect("Failed to parse test address"),
        );
        assert_eq!(
            base_priority, 255,
            "Base priority should be 255 for public IPv4"
        );

        // Test IPv6 gets higher priority
        let ipv6_priority = manager.calculate_quic_discovered_priority(
            &"[2001:db8::1]:5678"
                .parse()
                .expect("Failed to parse test address"),
        );
        assert!(
            ipv6_priority > base_priority,
            "IPv6 should have higher priority than IPv4"
        );

        // Test private addresses get lower priority
        let private_priority = manager.calculate_quic_discovered_priority(
            &"192.168.1.1:5678"
                .parse()
                .expect("Failed to parse test address"),
        );
        assert!(
            private_priority < base_priority,
            "Private addresses should have lower priority"
        );

        // Test link-local gets even lower priority
        let link_local_priority = manager.calculate_quic_discovered_priority(
            &"[fe80::1]:5678"
                .parse()
                .expect("Failed to parse test address"),
        );
        assert!(
            link_local_priority < private_priority,
            "Link-local should have lower priority than private"
        );
    }

    #[test]
    fn test_quic_discovered_addresses_override_stale_server_reflexive() {
        // Test that QUIC-discovered addresses can replace stale server reflexive candidates
        let mut manager = create_test_manager();
        let peer_id = PeerId([1; 32]);

        // Start discovery
        manager
            .start_discovery(peer_id, vec![])
            .expect("Failed to start discovery in test");

        // Simulate adding an old server reflexive candidate (from placeholder STUN)
        let session = manager
            .active_sessions
            .get_mut(&peer_id)
            .expect("Session should exist in test");
        let old_candidate = DiscoveryCandidate {
            address: "1.2.3.4:1234"
                .parse()
                .expect("Failed to parse test address"),
            priority: 200,
            source: DiscoverySourceType::ServerReflexive,
            state: CandidateState::Validating,
        };
        session.discovered_candidates.push(old_candidate);

        // Add a QUIC-discovered address for the same IP but different port
        let new_addr = "1.2.3.4:5678"
            .parse()
            .expect("Failed to parse test address");
        manager
            .accept_quic_discovered_address(peer_id, new_addr)
            .expect("Failed to accept address in test");

        // Check that we have both candidates
        let session = manager
            .active_sessions
            .get(&peer_id)
            .expect("Session should exist in test");
        let candidates: Vec<_> = session
            .discovered_candidates
            .iter()
            .filter(|c| c.source == DiscoverySourceType::ServerReflexive)
            .collect();

        assert_eq!(
            candidates.len(),
            2,
            "Should have both old and new candidates"
        );

        // The new candidate should have a different priority
        let new_candidate = candidates
            .iter()
            .find(|c| c.address == new_addr)
            .expect("New candidate should be found");
        assert_ne!(
            new_candidate.priority, 200,
            "New candidate should have recalculated priority"
        );
    }

    #[test]
    fn test_quic_discovered_address_generates_events() {
        // Test that adding a QUIC-discovered address generates appropriate events
        let mut manager = create_test_manager();
        let peer_id = PeerId([1; 32]);

        // Start discovery
        manager
            .start_discovery(peer_id, vec![])
            .expect("Failed to start discovery in test");

        // Clear any startup events
        manager.poll_discovery_progress(peer_id);

        // Add a QUIC-discovered address
        let discovered_addr = "8.8.8.8:5000"
            .parse()
            .expect("Failed to parse test address");
        manager
            .accept_quic_discovered_address(peer_id, discovered_addr)
            .expect("Failed to accept address in test");

        // Poll for events
        let events = manager.poll_discovery_progress(peer_id);

        // Should have at least one event about the new candidate
        assert!(
            !events.is_empty(),
            "Should generate events for new QUIC-discovered address"
        );

        // Check for ServerReflexiveCandidateDiscovered event
        let has_new_candidate = events.iter().any(|e| {
            matches!(e,
                DiscoveryEvent::ServerReflexiveCandidateDiscovered { candidate, .. }
                if candidate.address == discovered_addr
            )
        });
        assert!(
            has_new_candidate,
            "Should generate ServerReflexiveCandidateDiscovered event for the discovered address"
        );
    }

    #[test]
    fn test_multiple_quic_discovered_addresses_generate_events() {
        // Test that multiple QUIC-discovered addresses each generate events
        let mut manager = create_test_manager();
        let peer_id = PeerId([1; 32]);

        // Start discovery
        manager
            .start_discovery(peer_id, vec![])
            .expect("Failed to start discovery in test");

        // Clear startup events
        manager.poll_discovery_progress(peer_id);

        // Add multiple QUIC-discovered addresses
        let addresses = vec![
            "8.8.8.8:5000"
                .parse()
                .expect("Failed to parse test address"),
            "1.1.1.1:6000"
                .parse()
                .expect("Failed to parse test address"),
            "[2001:db8::1]:7000"
                .parse()
                .expect("Failed to parse test address"),
        ];

        for addr in &addresses {
            manager
                .accept_quic_discovered_address(peer_id, *addr)
                .expect("Failed to accept address in test");
        }

        // Poll for events
        let events = manager.poll_discovery_progress(peer_id);

        // Should have events for all addresses
        for addr in &addresses {
            let has_event = events.iter().any(|e| {
                matches!(e,
                    DiscoveryEvent::ServerReflexiveCandidateDiscovered { candidate, .. }
                    if candidate.address == *addr
                )
            });
            assert!(has_event, "Should have event for address {addr}");
        }
    }

    #[test]
    fn test_duplicate_quic_discovered_address_no_event() {
        // Test that duplicate addresses don't generate duplicate events
        let mut manager = create_test_manager();
        let peer_id = PeerId([1; 32]);

        // Start discovery
        manager
            .start_discovery(peer_id, vec![])
            .expect("Failed to start discovery in test");

        // Add a QUIC-discovered address
        let discovered_addr = "8.8.8.8:5000"
            .parse()
            .expect("Failed to parse test address");
        manager
            .accept_quic_discovered_address(peer_id, discovered_addr)
            .expect("Failed to accept address in test");

        // Poll and clear events
        manager.poll_discovery_progress(peer_id);

        // Try to add the same address again
        manager
            .accept_quic_discovered_address(peer_id, discovered_addr)
            .expect("Failed to accept address in test");

        // Poll for events
        let events = manager.poll_discovery_progress(peer_id);

        // Should not generate any new events for duplicate
        let has_duplicate_event = events.iter().any(|e| {
            matches!(e,
                DiscoveryEvent::ServerReflexiveCandidateDiscovered { candidate, .. }
                if candidate.address == discovered_addr
            )
        });

        assert!(
            !has_duplicate_event,
            "Should not generate event for duplicate address"
        );
    }

    #[test]
    fn test_quic_discovered_address_event_timing() {
        // Test that events are queued and delivered on poll
        let mut manager = create_test_manager();
        let peer_id = PeerId([1; 32]);

        // Start discovery
        manager
            .start_discovery(peer_id, vec![])
            .expect("Failed to start discovery in test");

        // Clear startup events
        manager.poll_discovery_progress(peer_id);

        // Add addresses without polling
        let addr1 = "8.8.8.8:5000"
            .parse()
            .expect("Failed to parse test address");
        let addr2 = "1.1.1.1:6000"
            .parse()
            .expect("Failed to parse test address");

        manager
            .accept_quic_discovered_address(peer_id, addr1)
            .expect("Failed to accept address in test");
        manager
            .accept_quic_discovered_address(peer_id, addr2)
            .expect("Failed to accept address in test");

        // Events should be queued
        // Now poll for events
        let events = manager.poll_discovery_progress(peer_id);

        // Should get all queued events
        let server_reflexive_count = events
            .iter()
            .filter(|e| matches!(e, DiscoveryEvent::ServerReflexiveCandidateDiscovered { .. }))
            .count();

        assert!(
            server_reflexive_count >= 2,
            "Should deliver all queued events on poll, got {server_reflexive_count} events"
        );

        // Subsequent poll should return no new server reflexive events
        let events2 = manager.poll_discovery_progress(peer_id);
        let server_reflexive_count2 = events2
            .iter()
            .filter(|e| matches!(e, DiscoveryEvent::ServerReflexiveCandidateDiscovered { .. }))
            .count();
        assert_eq!(
            server_reflexive_count2, 0,
            "Server reflexive events should not be duplicated on subsequent polls"
        );
    }

    #[test]
    fn test_is_valid_local_address() {
        let manager = create_test_manager();

        // Valid IPv4 addresses
        assert!(
            manager.is_valid_local_address(
                &"192.168.1.1:8080"
                    .parse()
                    .expect("Failed to parse test address")
            )
        );
        assert!(
            manager.is_valid_local_address(
                &"10.0.0.1:8080"
                    .parse()
                    .expect("Failed to parse test address")
            )
        );
        assert!(
            manager.is_valid_local_address(
                &"172.16.0.1:8080"
                    .parse()
                    .expect("Failed to parse test address")
            )
        );

        // Valid IPv6 addresses
        assert!(
            manager.is_valid_local_address(
                &"[2001:4860:4860::8888]:8080"
                    .parse()
                    .expect("Failed to parse test address")
            )
        );
        assert!(
            manager.is_valid_local_address(
                &"[fe80::1]:8080"
                    .parse()
                    .expect("Failed to parse test address")
            )
        ); // Link-local is valid for local
        assert!(
            manager.is_valid_local_address(
                &"[fc00::1]:8080"
                    .parse()
                    .expect("Failed to parse test address")
            )
        ); // Unique local is valid for local

        // Invalid addresses
        assert!(
            !manager.is_valid_local_address(
                &"0.0.0.0:8080"
                    .parse()
                    .expect("Failed to parse test address")
            )
        );
        assert!(
            !manager.is_valid_local_address(
                &"255.255.255.255:8080"
                    .parse()
                    .expect("Failed to parse test address")
            )
        );
        assert!(
            !manager.is_valid_local_address(
                &"224.0.0.1:8080"
                    .parse()
                    .expect("Failed to parse test address")
            )
        ); // Multicast
        assert!(
            !manager.is_valid_local_address(
                &"0.0.0.1:8080"
                    .parse()
                    .expect("Failed to parse test address")
            )
        ); // Reserved
        assert!(
            !manager.is_valid_local_address(
                &"240.0.0.1:8080"
                    .parse()
                    .expect("Failed to parse test address")
            )
        ); // Reserved
        assert!(
            !manager.is_valid_local_address(
                &"[::]:8080".parse().expect("Failed to parse test address")
            )
        ); // Unspecified
        assert!(
            !manager.is_valid_local_address(
                &"[ff02::1]:8080"
                    .parse()
                    .expect("Failed to parse test address")
            )
        ); // Multicast
        assert!(
            !manager.is_valid_local_address(
                &"[2001:db8::1]:8080"
                    .parse()
                    .expect("Failed to parse test address")
            )
        ); // Documentation

        // Port 0 should fail
        assert!(
            !manager.is_valid_local_address(
                &"192.168.1.1:0"
                    .parse()
                    .expect("Failed to parse test address")
            )
        );

        // Test mode allows loopback
        #[cfg(test)]
        {
            assert!(
                manager.is_valid_local_address(
                    &"127.0.0.1:8080"
                        .parse()
                        .expect("Failed to parse test address")
                )
            );
            assert!(manager.is_valid_local_address(
                &"[::1]:8080".parse().expect("Failed to parse test address")
            ));
        }
    }

    #[test]
    fn test_validation_rejects_invalid_addresses() {}

    #[test]
    fn test_candidate_validation_error_types() {
        use crate::nat_traversal_api::{CandidateAddress, CandidateValidationError};

        // Test specific error types
        assert!(matches!(
            CandidateAddress::validate_address(&"192.168.1.1:0".parse().unwrap()),
            Err(CandidateValidationError::InvalidPort(0))
        ));

        assert!(matches!(
            CandidateAddress::validate_address(&"0.0.0.0:8080".parse().unwrap()),
            Err(CandidateValidationError::UnspecifiedAddress)
        ));

        assert!(matches!(
            CandidateAddress::validate_address(&"255.255.255.255:8080".parse().unwrap()),
            Err(CandidateValidationError::BroadcastAddress)
        ));

        assert!(matches!(
            CandidateAddress::validate_address(&"224.0.0.1:8080".parse().unwrap()),
            Err(CandidateValidationError::MulticastAddress)
        ));

        assert!(matches!(
            CandidateAddress::validate_address(&"240.0.0.1:8080".parse().unwrap()),
            Err(CandidateValidationError::ReservedAddress)
        ));

        assert!(matches!(
            CandidateAddress::validate_address(&"[2001:db8::1]:8080".parse().unwrap()),
            Err(CandidateValidationError::DocumentationAddress)
        ));

        assert!(matches!(
            CandidateAddress::validate_address(&"[::ffff:192.168.1.1]:8080".parse().unwrap()),
            Err(CandidateValidationError::IPv4MappedAddress)
        ));
    }
}
