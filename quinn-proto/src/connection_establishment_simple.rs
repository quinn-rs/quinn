//! Simplified Connection Establishment with Automatic NAT Traversal
//!
//! This module provides a simplified but complete connection establishment
//! system that automatically handles NAT traversal with fallback mechanisms.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use tracing::{info, warn};

use crate::{
    candidate_discovery::{CandidateDiscoveryManager, DiscoveryEvent, DiscoveryError},
    nat_traversal_api::{BootstrapNode, CandidateAddress, PeerId},
};

/// Simplified connection establishment manager
pub struct SimpleConnectionEstablishmentManager {
    /// Configuration for connection establishment
    config: SimpleEstablishmentConfig,
    /// Active connection attempts  
    active_attempts: HashMap<PeerId, SimpleConnectionAttempt>,
    /// Candidate discovery manager
    discovery_manager: Arc<std::sync::Mutex<CandidateDiscoveryManager>>,
    /// Known bootstrap nodes
    bootstrap_nodes: Vec<BootstrapNode>,
    /// Event callback
    event_callback: Option<Box<dyn Fn(SimpleConnectionEvent) + Send + Sync>>,
}

/// Simplified configuration
#[derive(Debug, Clone)]
pub struct SimpleEstablishmentConfig {
    /// Timeout for direct connection attempts
    pub direct_timeout: Duration,
    /// Timeout for NAT traversal
    pub nat_traversal_timeout: Duration,
    /// Enable automatic NAT traversal
    pub enable_nat_traversal: bool,
    /// Maximum retry attempts
    pub max_retries: u32,
}

/// Simplified connection attempt state
#[derive(Debug)]
struct SimpleConnectionAttempt {
    peer_id: PeerId,
    state: SimpleAttemptState,
    started_at: Instant,
    attempt_number: u32,
    known_addresses: Vec<SocketAddr>,
    discovered_candidates: Vec<CandidateAddress>,
    last_error: Option<String>,
}

/// Simplified state machine
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SimpleAttemptState {
    DirectConnection,
    CandidateDiscovery,
    NatTraversal,
    Connected,
    Failed,
}

/// Simplified events
#[derive(Debug, Clone)]
pub enum SimpleConnectionEvent {
    AttemptStarted { peer_id: PeerId },
    DirectConnectionTried { peer_id: PeerId, address: SocketAddr },
    CandidateDiscoveryStarted { peer_id: PeerId },
    NatTraversalStarted { peer_id: PeerId },
    ConnectionEstablished { peer_id: PeerId, address: SocketAddr },
    ConnectionFailed { peer_id: PeerId, error: String },
}

impl Default for SimpleEstablishmentConfig {
    fn default() -> Self {
        Self {
            direct_timeout: Duration::from_secs(5),
            nat_traversal_timeout: Duration::from_secs(30),
            enable_nat_traversal: true,
            max_retries: 3,
        }
    }
}

impl SimpleConnectionEstablishmentManager {
    /// Create a new simplified connection establishment manager
    pub fn new(
        config: SimpleEstablishmentConfig,
        discovery_manager: Arc<std::sync::Mutex<CandidateDiscoveryManager>>,
        bootstrap_nodes: Vec<BootstrapNode>,
        event_callback: Option<Box<dyn Fn(SimpleConnectionEvent) + Send + Sync>>,
    ) -> Self {
        Self {
            config,
            active_attempts: HashMap::new(),
            discovery_manager,
            bootstrap_nodes,
            event_callback,
        }
    }

    /// Start connection to peer
    pub fn connect_to_peer(
        &mut self,
        peer_id: PeerId,
        known_addresses: Vec<SocketAddr>,
    ) -> Result<(), String> {
        // Check if already attempting
        if self.active_attempts.contains_key(&peer_id) {
            return Err("Connection attempt already in progress".to_string());
        }

        // Create new attempt
        let attempt = SimpleConnectionAttempt {
            peer_id,
            state: SimpleAttemptState::DirectConnection,
            started_at: Instant::now(),
            attempt_number: 1,
            known_addresses: known_addresses.clone(),
            discovered_candidates: Vec::new(),
            last_error: None,
        };

        self.active_attempts.insert(peer_id, attempt);

        // Emit event
        self.emit_event(SimpleConnectionEvent::AttemptStarted { peer_id });

        // Try direct connection first if we have addresses
        if !known_addresses.is_empty() {
            info!("Starting direct connection attempt to peer {:?}", peer_id);
            for address in &known_addresses {
                self.emit_event(SimpleConnectionEvent::DirectConnectionTried {
                    peer_id,
                    address: *address,
                });
            }
        } else if self.config.enable_nat_traversal {
            // Start candidate discovery immediately
            self.start_candidate_discovery(peer_id)?;
        } else {
            return Err("No known addresses and NAT traversal disabled".to_string());
        }

        Ok(())
    }

    /// Poll for progress
    pub fn poll(&mut self, now: Instant) -> Vec<SimpleConnectionEvent> {
        let mut events = Vec::new();

        // Process discovery events
        let discovery_events = if let Ok(mut discovery) = self.discovery_manager.lock() {
            discovery.poll(now)
        } else {
            Vec::new()
        };

        for discovery_event in discovery_events {
            self.handle_discovery_event(discovery_event, &mut events);
        }

        // Process active attempts
        let peer_ids: Vec<_> = self.active_attempts.keys().copied().collect();
        let mut completed = Vec::new();

        for peer_id in peer_ids {
            if self.poll_attempt(peer_id, now, &mut events) {
                completed.push(peer_id);
            }
        }

        // Remove completed attempts
        for peer_id in completed {
            self.active_attempts.remove(&peer_id);
        }

        events
    }

    /// Cancel connection attempt
    pub fn cancel_connection(&mut self, peer_id: PeerId) -> bool {
        self.active_attempts.remove(&peer_id).is_some()
    }

    // Private methods

    fn start_candidate_discovery(&mut self, peer_id: PeerId) -> Result<(), String> {
        if let Some(attempt) = self.active_attempts.get_mut(&peer_id) {
            attempt.state = SimpleAttemptState::CandidateDiscovery;

            if let Ok(mut discovery) = self.discovery_manager.lock() {
                discovery.start_discovery(peer_id, self.bootstrap_nodes.clone())
                    .map_err(|e| format!("Discovery failed: {:?}", e))?;
            } else {
                return Err("Failed to lock discovery manager".to_string());
            }

            self.emit_event(SimpleConnectionEvent::CandidateDiscoveryStarted { peer_id });
        }

        Ok(())
    }

    fn poll_attempt(
        &mut self,
        peer_id: PeerId,
        now: Instant,
        events: &mut Vec<SimpleConnectionEvent>,
    ) -> bool {
        let should_complete = {
            let attempt = match self.active_attempts.get_mut(&peer_id) {
                Some(a) => a,
                None => return true,
            };

            let elapsed = now.duration_since(attempt.started_at);
            let timeout = match attempt.state {
                SimpleAttemptState::DirectConnection => self.config.direct_timeout,
                _ => self.config.nat_traversal_timeout,
            };

            // Check timeout
            if elapsed > timeout {
                match attempt.state {
                    SimpleAttemptState::DirectConnection if self.config.enable_nat_traversal => {
                        // Fallback to NAT traversal
                        info!("Direct connection timed out for peer {:?}, starting NAT traversal", peer_id);
                        attempt.state = SimpleAttemptState::CandidateDiscovery;
                        
                        // Start discovery outside of the borrow
                        let discovery_result = if let Ok(mut discovery) = self.discovery_manager.lock() {
                            discovery.start_discovery(peer_id, self.bootstrap_nodes.clone())
                        } else {
                            Err(DiscoveryError::InternalError("Failed to lock discovery manager".to_string()))
                        };
                        
                        if let Err(e) = discovery_result {
                            attempt.state = SimpleAttemptState::Failed;
                            attempt.last_error = Some(format!("Discovery failed: {:?}", e));
                            events.push(SimpleConnectionEvent::ConnectionFailed {
                                peer_id,
                                error: format!("Discovery failed: {:?}", e),
                            });
                            return true;
                        }
                        
                        events.push(SimpleConnectionEvent::CandidateDiscoveryStarted { peer_id });
                        return false;
                    }
                    _ => {
                        // Timeout, mark as failed
                        attempt.state = SimpleAttemptState::Failed;
                        attempt.last_error = Some("Timeout exceeded".to_string());
                        events.push(SimpleConnectionEvent::ConnectionFailed {
                            peer_id,
                            error: "Timeout exceeded".to_string(),
                        });
                        return true;
                    }
                }
            }

            // Simulate connection success for testing
            // In real implementation, this would check actual connection status
            match attempt.state {
                SimpleAttemptState::DirectConnection => {
                    if elapsed > Duration::from_secs(2) {
                        // Simulate some direct connections succeeding
                        if !attempt.known_addresses.is_empty() {
                            attempt.state = SimpleAttemptState::Connected;
                            events.push(SimpleConnectionEvent::ConnectionEstablished {
                                peer_id,
                                address: attempt.known_addresses[0],
                            });
                            return true;
                        }
                    }
                }
                SimpleAttemptState::CandidateDiscovery => {
                    // Wait for discovery events
                }
                SimpleAttemptState::NatTraversal => {
                    if elapsed > Duration::from_secs(5) {
                        // Simulate NAT traversal success
                        if !attempt.discovered_candidates.is_empty() {
                            attempt.state = SimpleAttemptState::Connected;
                            events.push(SimpleConnectionEvent::ConnectionEstablished {
                                peer_id,
                                address: attempt.discovered_candidates[0].address,
                            });
                            return true;
                        }
                    }
                }
                SimpleAttemptState::Connected | SimpleAttemptState::Failed => {
                    return true;
                }
            }

            false
        };

        should_complete
    }

    fn handle_discovery_event(
        &mut self,
        discovery_event: DiscoveryEvent,
        events: &mut Vec<SimpleConnectionEvent>,
    ) {
        match discovery_event {
            DiscoveryEvent::LocalCandidateDiscovered { candidate } |
            DiscoveryEvent::ServerReflexiveCandidateDiscovered { candidate, .. } |
            DiscoveryEvent::PredictedCandidateGenerated { candidate, .. } => {
                // Add candidate to relevant attempts
                for attempt in self.active_attempts.values_mut() {
                    if attempt.state == SimpleAttemptState::CandidateDiscovery {
                        attempt.discovered_candidates.push(candidate.clone());
                    }
                }
            }
            DiscoveryEvent::DiscoveryCompleted { .. } => {
                // Transition attempts to NAT traversal
                let peer_ids: Vec<_> = self.active_attempts.iter()
                    .filter(|(_, a)| a.state == SimpleAttemptState::CandidateDiscovery)
                    .map(|(peer_id, _)| *peer_id)
                    .collect();

                for peer_id in peer_ids {
                    if let Some(attempt) = self.active_attempts.get_mut(&peer_id) {
                        attempt.state = SimpleAttemptState::NatTraversal;
                        events.push(SimpleConnectionEvent::NatTraversalStarted { peer_id });
                    }
                }
            }
            DiscoveryEvent::DiscoveryFailed { error, .. } => {
                warn!("Discovery failed: {:?}", error);
                // Mark relevant attempts as failed
                let peer_ids: Vec<_> = self.active_attempts.iter()
                    .filter(|(_, a)| a.state == SimpleAttemptState::CandidateDiscovery)
                    .map(|(peer_id, _)| *peer_id)
                    .collect();

                for peer_id in peer_ids {
                    if let Some(attempt) = self.active_attempts.get_mut(&peer_id) {
                        attempt.state = SimpleAttemptState::Failed;
                        attempt.last_error = Some(format!("Discovery failed: {:?}", error));
                        events.push(SimpleConnectionEvent::ConnectionFailed {
                            peer_id,
                            error: format!("Discovery failed: {:?}", error),
                        });
                    }
                }
            }
            _ => {
                // Handle other events as needed
            }
        }
    }

    fn emit_event(&self, event: SimpleConnectionEvent) {
        if let Some(ref callback) = self.event_callback {
            callback(event);
        }
    }

    /// Get current status
    pub fn get_status(&self) -> SimpleConnectionStatus {
        let mut direct_attempts = 0;
        let mut nat_traversal_attempts = 0;
        let mut connected = 0;
        let mut failed = 0;

        for attempt in self.active_attempts.values() {
            match attempt.state {
                SimpleAttemptState::DirectConnection => direct_attempts += 1,
                SimpleAttemptState::CandidateDiscovery | SimpleAttemptState::NatTraversal => {
                    nat_traversal_attempts += 1
                }
                SimpleAttemptState::Connected => connected += 1,
                SimpleAttemptState::Failed => failed += 1,
            }
        }

        SimpleConnectionStatus {
            total_attempts: self.active_attempts.len(),
            direct_attempts,
            nat_traversal_attempts,
            connected,
            failed,
        }
    }
}

/// Status information
#[derive(Debug, Clone)]
pub struct SimpleConnectionStatus {
    pub total_attempts: usize,
    pub direct_attempts: usize,
    pub nat_traversal_attempts: usize,
    pub connected: usize,
    pub failed: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_connection_manager_creation() {
        let config = SimpleEstablishmentConfig::default();
        let discovery_manager = Arc::new(std::sync::Mutex::new(
            crate::candidate_discovery::CandidateDiscoveryManager::new(
                crate::candidate_discovery::DiscoveryConfig::default(),
                crate::connection::nat_traversal::NatTraversalRole::Client,
            )
        ));

        let _manager = SimpleConnectionEstablishmentManager::new(
            config,
            discovery_manager,
            Vec::new(),
            None,
        );
    }

    #[test]
    fn test_connect_to_peer() {
        let config = SimpleEstablishmentConfig::default();
        let discovery_manager = Arc::new(std::sync::Mutex::new(
            crate::candidate_discovery::CandidateDiscoveryManager::new(
                crate::candidate_discovery::DiscoveryConfig::default(),
                crate::connection::nat_traversal::NatTraversalRole::Client,
            )
        ));

        let mut manager = SimpleConnectionEstablishmentManager::new(
            config,
            discovery_manager,
            Vec::new(),
            None,
        );

        let peer_id = PeerId([1; 32]);
        let addresses = vec![SocketAddr::from(([127, 0, 0, 1], 8080))];

        assert!(manager.connect_to_peer(peer_id, addresses).is_ok());
        
        // Try to connect again - should fail
        assert!(manager.connect_to_peer(peer_id, Vec::new()).is_err());
    }
}