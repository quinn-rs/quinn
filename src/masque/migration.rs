// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Connection Migration for MASQUE Relay
//!
//! Provides relay-to-direct path upgrade functionality. When a connection
//! is established through a relay, this module coordinates attempts to
//! establish a direct path and migrate the connection.
//!
//! # Migration Flow
//!
//! 1. Data flows via relay (RelayOnly state)
//! 2. Exchange ADD_ADDRESS frames through relay
//! 3. Coordinate PUNCH_ME_NOW timing
//! 4. Both peers send PATH_CHALLENGE to candidates
//! 5. On PATH_RESPONSE, QUIC migrates to direct path
//! 6. Relay kept as fallback
//!
//! # Example
//!
//! ```rust,ignore
//! use ant_quic::masque::migration::{MigrationCoordinator, MigrationConfig};
//!
//! let config = MigrationConfig::default();
//! let coordinator = MigrationCoordinator::new(config);
//!
//! // Start migration attempt
//! coordinator.start_migration(peer_addr).await;
//!
//! // Check migration state
//! match coordinator.state() {
//!     MigrationState::DirectEstablished => println!("Direct path active!"),
//!     MigrationState::RelayOnly => println!("Still using relay"),
//!     _ => {}
//! }
//! ```

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Configuration for connection migration
#[derive(Debug, Clone)]
pub struct MigrationConfig {
    /// Time to wait between migration attempts
    pub probe_interval: Duration,
    /// Maximum time to wait for path validation
    pub validation_timeout: Duration,
    /// Maximum concurrent path probes
    pub max_concurrent_probes: usize,
    /// Delay before attempting migration after relay established
    pub initial_delay: Duration,
    /// Maximum migration attempts before giving up
    pub max_attempts: u32,
    /// Whether to automatically attempt migration
    pub auto_migrate: bool,
}

impl Default for MigrationConfig {
    fn default() -> Self {
        Self {
            probe_interval: Duration::from_secs(5),
            validation_timeout: Duration::from_secs(3),
            max_concurrent_probes: 4,
            initial_delay: Duration::from_secs(2),
            max_attempts: 5,
            auto_migrate: true,
        }
    }
}

/// State of a connection migration attempt
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigrationState {
    /// Connection is relay-only, no migration attempted
    RelayOnly,
    /// Waiting for initial delay before probing
    WaitingToProbe {
        /// When we'll start probing
        probe_at: Instant,
    },
    /// Actively probing candidate addresses
    ProbeInProgress {
        /// Candidate addresses being probed
        candidates: Vec<SocketAddr>,
        /// When probing started
        started_at: Instant,
    },
    /// A direct path has been validated, migration pending
    MigrationPending {
        /// The validated direct path
        verified_path: SocketAddr,
        /// RTT measured on the direct path
        measured_rtt: Duration,
    },
    /// Successfully migrated to direct path
    DirectEstablished {
        /// The direct path address
        direct_path: SocketAddr,
        /// When migration completed
        migrated_at: Instant,
    },
    /// Migration failed, falling back to relay
    FallbackToRelay {
        /// Reason for fallback
        reason: String,
        /// Number of attempts made
        attempts: u32,
    },
}

impl MigrationState {
    /// Check if currently using relay
    pub fn is_relayed(&self) -> bool {
        !matches!(self, Self::DirectEstablished { .. })
    }

    /// Check if migration is in progress
    pub fn is_migrating(&self) -> bool {
        matches!(
            self,
            Self::WaitingToProbe { .. }
                | Self::ProbeInProgress { .. }
                | Self::MigrationPending { .. }
        )
    }

    /// Check if direct path is established
    pub fn is_direct(&self) -> bool {
        matches!(self, Self::DirectEstablished { .. })
    }
}

/// Statistics for migration operations
#[derive(Debug, Default)]
pub struct MigrationStats {
    /// Total migration attempts
    pub attempts: AtomicU64,
    /// Successful migrations
    pub successful: AtomicU64,
    /// Failed migrations
    pub failed: AtomicU64,
    /// Paths probed
    pub paths_probed: AtomicU64,
    /// Average migration time (ms)
    pub avg_migration_time_ms: AtomicU64,
}

impl MigrationStats {
    /// Create new statistics
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a migration attempt result
    pub fn record_attempt(&self, success: bool, duration: Duration) {
        self.attempts.fetch_add(1, Ordering::Relaxed);
        if success {
            self.successful.fetch_add(1, Ordering::Relaxed);
            // Update average migration time
            let ms = duration.as_millis() as u64;
            let prev_avg = self.avg_migration_time_ms.load(Ordering::Relaxed);
            let successful = self.successful.load(Ordering::Relaxed);
            if successful > 0 {
                let new_avg = ((prev_avg * (successful - 1)) + ms) / successful;
                self.avg_migration_time_ms.store(new_avg, Ordering::Relaxed);
            }
        } else {
            self.failed.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Record a path probe
    pub fn record_probe(&self) {
        self.paths_probed.fetch_add(1, Ordering::Relaxed);
    }

    /// Get success rate as percentage
    pub fn success_rate(&self) -> f64 {
        let attempts = self.attempts.load(Ordering::Relaxed);
        if attempts == 0 {
            return 0.0;
        }
        let successful = self.successful.load(Ordering::Relaxed);
        (successful as f64 / attempts as f64) * 100.0
    }
}

/// Information about a candidate path
#[derive(Debug, Clone)]
#[allow(dead_code)] // Fields reserved for future path management
struct CandidatePath {
    /// Address of the candidate
    address: SocketAddr,
    /// When we started probing this candidate
    probe_started: Option<Instant>,
    /// Measured RTT if validated
    rtt: Option<Duration>,
    /// Whether this path is validated
    validated: bool,
    /// Number of probe attempts
    probe_count: u32,
}

impl CandidatePath {
    fn new(address: SocketAddr) -> Self {
        Self {
            address,
            probe_started: None,
            rtt: None,
            validated: false,
            probe_count: 0,
        }
    }
}

/// Coordinates connection migration from relay to direct path
#[derive(Debug)]
pub struct MigrationCoordinator {
    /// Configuration
    config: MigrationConfig,
    /// Current migration state per peer
    states: RwLock<HashMap<SocketAddr, MigrationState>>,
    /// Candidate paths per peer
    candidates: RwLock<HashMap<SocketAddr, Vec<CandidatePath>>>,
    /// Statistics
    stats: Arc<MigrationStats>,
    /// Relay address (for fallback)
    relay_address: RwLock<Option<SocketAddr>>,
}

impl MigrationCoordinator {
    /// Create a new migration coordinator
    pub fn new(config: MigrationConfig) -> Self {
        Self {
            config,
            states: RwLock::new(HashMap::new()),
            candidates: RwLock::new(HashMap::new()),
            stats: Arc::new(MigrationStats::new()),
            relay_address: RwLock::new(None),
        }
    }

    /// Get statistics
    pub fn stats(&self) -> Arc<MigrationStats> {
        Arc::clone(&self.stats)
    }

    /// Set the relay address for this coordinator
    pub async fn set_relay(&self, relay: SocketAddr) {
        let mut relay_addr = self.relay_address.write().await;
        *relay_addr = Some(relay);
    }

    /// Get current migration state for a peer
    pub async fn state(&self, peer: SocketAddr) -> MigrationState {
        let states = self.states.read().await;
        states
            .get(&peer)
            .cloned()
            .unwrap_or(MigrationState::RelayOnly)
    }

    /// Register candidate addresses for a peer
    pub async fn add_candidates(&self, peer: SocketAddr, addrs: Vec<SocketAddr>) {
        let mut candidates = self.candidates.write().await;
        let peer_candidates = candidates.entry(peer).or_default();

        for addr in addrs {
            if !peer_candidates.iter().any(|c| c.address == addr) {
                peer_candidates.push(CandidatePath::new(addr));
            }
        }
    }

    /// Get candidates for a peer, filtered by IP version
    ///
    /// # Arguments
    /// * `peer` - The peer to get candidates for
    /// * `ipv4_only` - If Some(true), return only IPv4 candidates; if Some(false), only IPv6.
    ///   If None, return all candidates
    pub async fn get_candidates_filtered(
        &self,
        peer: SocketAddr,
        ipv4_only: Option<bool>,
    ) -> Vec<SocketAddr> {
        let candidates = self.candidates.read().await;
        candidates
            .get(&peer)
            .map(|c| {
                c.iter()
                    .filter(|p| match ipv4_only {
                        Some(true) => p.address.is_ipv4(),
                        Some(false) => p.address.is_ipv6(),
                        None => true,
                    })
                    .map(|p| p.address)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get all candidate addresses for a peer
    pub async fn get_all_candidates(&self, peer: SocketAddr) -> Vec<SocketAddr> {
        self.get_candidates_filtered(peer, None).await
    }

    /// Get IPv4 candidates for a peer
    pub async fn get_ipv4_candidates(&self, peer: SocketAddr) -> Vec<SocketAddr> {
        self.get_candidates_filtered(peer, Some(true)).await
    }

    /// Get IPv6 candidates for a peer
    pub async fn get_ipv6_candidates(&self, peer: SocketAddr) -> Vec<SocketAddr> {
        self.get_candidates_filtered(peer, Some(false)).await
    }

    /// Check if peer has candidates in both IP versions (dual-stack)
    pub async fn has_dual_stack_candidates(&self, peer: SocketAddr) -> bool {
        let candidates = self.candidates.read().await;
        if let Some(c) = candidates.get(&peer) {
            let has_ipv4 = c.iter().any(|p| p.address.is_ipv4());
            let has_ipv6 = c.iter().any(|p| p.address.is_ipv6());
            has_ipv4 && has_ipv6
        } else {
            false
        }
    }

    /// Start migration attempt for a peer
    pub async fn start_migration(&self, peer: SocketAddr) {
        if !self.config.auto_migrate {
            return;
        }

        let mut states = self.states.write().await;

        // Only start if in relay-only state
        if let Some(state) = states.get(&peer) {
            if !matches!(state, MigrationState::RelayOnly) {
                return;
            }
        }

        // Set waiting state with initial delay
        states.insert(
            peer,
            MigrationState::WaitingToProbe {
                probe_at: Instant::now() + self.config.initial_delay,
            },
        );

        tracing::debug!(peer = %peer, "Scheduled migration probe");
    }

    /// Poll migration progress - should be called periodically
    pub async fn poll(&self, peer: SocketAddr) -> MigrationState {
        let state = self.state(peer).await;

        match &state {
            MigrationState::WaitingToProbe { probe_at } => {
                if Instant::now() >= *probe_at {
                    // Time to start probing
                    self.begin_probing(peer).await;
                }
            }
            MigrationState::ProbeInProgress {
                candidates: _,
                started_at,
            } => {
                if started_at.elapsed() > self.config.validation_timeout {
                    // Probing timed out
                    self.handle_probe_timeout(peer).await;
                }
            }
            _ => {}
        }

        self.state(peer).await
    }

    /// Begin probing candidates
    async fn begin_probing(&self, peer: SocketAddr) {
        let candidates = {
            let candidates = self.candidates.read().await;
            candidates
                .get(&peer)
                .map(|c| c.iter().map(|p| p.address).collect::<Vec<_>>())
                .unwrap_or_default()
        };

        if candidates.is_empty() {
            // No candidates to probe
            let mut states = self.states.write().await;
            states.insert(
                peer,
                MigrationState::FallbackToRelay {
                    reason: "No candidate addresses available".to_string(),
                    attempts: 0,
                },
            );
            return;
        }

        // Limit concurrent probes
        let probe_candidates: Vec<_> = candidates
            .into_iter()
            .take(self.config.max_concurrent_probes)
            .collect();

        let mut states = self.states.write().await;
        states.insert(
            peer,
            MigrationState::ProbeInProgress {
                candidates: probe_candidates.clone(),
                started_at: Instant::now(),
            },
        );

        // Record probe stats
        for _ in &probe_candidates {
            self.stats.record_probe();
        }

        tracing::info!(
            peer = %peer,
            candidates = probe_candidates.len(),
            "Started probing candidate paths"
        );
    }

    /// Handle probe timeout
    async fn handle_probe_timeout(&self, peer: SocketAddr) {
        let mut states = self.states.write().await;

        let attempts =
            if let Some(MigrationState::FallbackToRelay { attempts, .. }) = states.get(&peer) {
                *attempts + 1
            } else {
                1
            };

        if attempts >= self.config.max_attempts {
            states.insert(
                peer,
                MigrationState::FallbackToRelay {
                    reason: "Maximum migration attempts exceeded".to_string(),
                    attempts,
                },
            );
            self.stats
                .record_attempt(false, self.config.validation_timeout);
            tracing::warn!(peer = %peer, "Migration failed after {} attempts", attempts);
        } else {
            // Schedule another attempt
            states.insert(
                peer,
                MigrationState::WaitingToProbe {
                    probe_at: Instant::now() + self.config.probe_interval,
                },
            );
            tracing::debug!(peer = %peer, "Scheduling retry after probe timeout");
        }
    }

    /// Report a validated path (called when PATH_RESPONSE received)
    pub async fn report_validated_path(&self, peer: SocketAddr, path: SocketAddr, rtt: Duration) {
        let mut states = self.states.write().await;

        // Update candidate
        {
            let mut candidates = self.candidates.write().await;
            if let Some(peer_candidates) = candidates.get_mut(&peer) {
                if let Some(candidate) = peer_candidates.iter_mut().find(|c| c.address == path) {
                    candidate.validated = true;
                    candidate.rtt = Some(rtt);
                }
            }
        }

        // Only transition from ProbeInProgress
        if let Some(MigrationState::ProbeInProgress { started_at, .. }) = states.get(&peer) {
            let duration = started_at.elapsed();

            states.insert(
                peer,
                MigrationState::MigrationPending {
                    verified_path: path,
                    measured_rtt: rtt,
                },
            );

            tracing::info!(
                peer = %peer,
                path = %path,
                rtt_ms = rtt.as_millis(),
                "Direct path validated, migration pending"
            );

            self.stats.record_attempt(true, duration);
        }
    }

    /// Complete migration to direct path
    pub async fn complete_migration(&self, peer: SocketAddr) {
        let mut states = self.states.write().await;

        if let Some(MigrationState::MigrationPending { verified_path, .. }) = states.get(&peer) {
            let path = *verified_path;
            states.insert(
                peer,
                MigrationState::DirectEstablished {
                    direct_path: path,
                    migrated_at: Instant::now(),
                },
            );

            tracing::info!(peer = %peer, path = %path, "Migration completed - direct path active");
        }
    }

    /// Force fallback to relay
    pub async fn fallback_to_relay(&self, peer: SocketAddr, reason: &str) {
        let mut states = self.states.write().await;

        let attempts =
            if let Some(MigrationState::FallbackToRelay { attempts, .. }) = states.get(&peer) {
                *attempts
            } else {
                0
            };

        states.insert(
            peer,
            MigrationState::FallbackToRelay {
                reason: reason.to_string(),
                attempts,
            },
        );

        tracing::warn!(peer = %peer, reason = reason, "Forced fallback to relay");
    }

    /// Reset migration state for a peer
    pub async fn reset(&self, peer: SocketAddr) {
        let mut states = self.states.write().await;
        let mut candidates = self.candidates.write().await;

        states.remove(&peer);
        candidates.remove(&peer);
    }

    /// Get all peers currently migrating
    pub async fn migrating_peers(&self) -> Vec<SocketAddr> {
        let states = self.states.read().await;
        states
            .iter()
            .filter(|(_, state)| state.is_migrating())
            .map(|(peer, _)| *peer)
            .collect()
    }

    /// Get all peers with direct paths
    pub async fn direct_peers(&self) -> Vec<SocketAddr> {
        let states = self.states.read().await;
        states
            .iter()
            .filter(|(_, state)| state.is_direct())
            .map(|(peer, _)| *peer)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn peer_addr(id: u8) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, id)), 9000)
    }

    fn candidate_addr(id: u8) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, id)), 9001)
    }

    #[tokio::test]
    async fn test_coordinator_creation() {
        let config = MigrationConfig::default();
        let coordinator = MigrationCoordinator::new(config);

        let state = coordinator.state(peer_addr(1)).await;
        assert!(matches!(state, MigrationState::RelayOnly));
    }

    #[tokio::test]
    async fn test_add_candidates() {
        let config = MigrationConfig::default();
        let coordinator = MigrationCoordinator::new(config);

        let peer = peer_addr(1);
        let candidates = vec![candidate_addr(1), candidate_addr(2)];

        coordinator.add_candidates(peer, candidates.clone()).await;

        let stored = coordinator.candidates.read().await;
        let peer_candidates = stored.get(&peer).unwrap();
        assert_eq!(peer_candidates.len(), 2);
    }

    #[tokio::test]
    async fn test_start_migration() {
        let config = MigrationConfig {
            initial_delay: Duration::from_millis(1),
            ..Default::default()
        };
        let coordinator = MigrationCoordinator::new(config);

        let peer = peer_addr(1);
        coordinator.start_migration(peer).await;

        let state = coordinator.state(peer).await;
        assert!(matches!(state, MigrationState::WaitingToProbe { .. }));
    }

    #[tokio::test]
    async fn test_begin_probing_no_candidates() {
        let config = MigrationConfig {
            initial_delay: Duration::from_millis(1),
            ..Default::default()
        };
        let coordinator = MigrationCoordinator::new(config);

        let peer = peer_addr(1);
        coordinator.start_migration(peer).await;

        // Wait for delay
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Poll should transition to FallbackToRelay due to no candidates
        let state = coordinator.poll(peer).await;
        assert!(matches!(state, MigrationState::FallbackToRelay { .. }));
    }

    #[tokio::test]
    async fn test_begin_probing_with_candidates() {
        let config = MigrationConfig {
            initial_delay: Duration::from_millis(1),
            validation_timeout: Duration::from_secs(10),
            ..Default::default()
        };
        let coordinator = MigrationCoordinator::new(config);

        let peer = peer_addr(1);
        let candidates = vec![candidate_addr(1), candidate_addr(2)];
        coordinator.add_candidates(peer, candidates).await;
        coordinator.start_migration(peer).await;

        // Wait for delay
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Poll should transition to ProbeInProgress
        let state = coordinator.poll(peer).await;
        assert!(matches!(state, MigrationState::ProbeInProgress { .. }));
    }

    #[tokio::test]
    async fn test_report_validated_path() {
        let config = MigrationConfig {
            initial_delay: Duration::from_millis(1),
            validation_timeout: Duration::from_secs(10),
            ..Default::default()
        };
        let coordinator = MigrationCoordinator::new(config);

        let peer = peer_addr(1);
        let candidate = candidate_addr(1);
        coordinator.add_candidates(peer, vec![candidate]).await;
        coordinator.start_migration(peer).await;

        tokio::time::sleep(Duration::from_millis(10)).await;
        coordinator.poll(peer).await;

        // Report validated path
        coordinator
            .report_validated_path(peer, candidate, Duration::from_millis(50))
            .await;

        let state = coordinator.state(peer).await;
        assert!(matches!(state, MigrationState::MigrationPending { .. }));
    }

    #[tokio::test]
    async fn test_complete_migration() {
        let config = MigrationConfig {
            initial_delay: Duration::from_millis(1),
            validation_timeout: Duration::from_secs(10),
            ..Default::default()
        };
        let coordinator = MigrationCoordinator::new(config);

        let peer = peer_addr(1);
        let candidate = candidate_addr(1);
        coordinator.add_candidates(peer, vec![candidate]).await;
        coordinator.start_migration(peer).await;

        tokio::time::sleep(Duration::from_millis(10)).await;
        coordinator.poll(peer).await;

        coordinator
            .report_validated_path(peer, candidate, Duration::from_millis(50))
            .await;
        coordinator.complete_migration(peer).await;

        let state = coordinator.state(peer).await;
        assert!(matches!(state, MigrationState::DirectEstablished { .. }));
        assert!(state.is_direct());
        assert!(!state.is_relayed());
    }

    #[tokio::test]
    async fn test_fallback_to_relay() {
        let config = MigrationConfig::default();
        let coordinator = MigrationCoordinator::new(config);

        let peer = peer_addr(1);
        coordinator.fallback_to_relay(peer, "Test fallback").await;

        let state = coordinator.state(peer).await;
        assert!(matches!(state, MigrationState::FallbackToRelay { .. }));
    }

    #[tokio::test]
    async fn test_reset() {
        let config = MigrationConfig::default();
        let coordinator = MigrationCoordinator::new(config);

        let peer = peer_addr(1);
        coordinator
            .add_candidates(peer, vec![candidate_addr(1)])
            .await;
        coordinator.start_migration(peer).await;
        coordinator.reset(peer).await;

        let state = coordinator.state(peer).await;
        assert!(matches!(state, MigrationState::RelayOnly));

        let candidates = coordinator.candidates.read().await;
        assert!(candidates.get(&peer).is_none());
    }

    #[tokio::test]
    async fn test_stats() {
        let config = MigrationConfig::default();
        let coordinator = MigrationCoordinator::new(config);

        let stats = coordinator.stats();
        stats.record_attempt(true, Duration::from_millis(100));
        stats.record_attempt(true, Duration::from_millis(200));
        stats.record_attempt(false, Duration::from_millis(150));

        assert_eq!(stats.attempts.load(Ordering::Relaxed), 3);
        assert_eq!(stats.successful.load(Ordering::Relaxed), 2);
        assert_eq!(stats.failed.load(Ordering::Relaxed), 1);
        assert!((stats.success_rate() - 66.67).abs() < 1.0);
    }

    #[tokio::test]
    async fn test_migrating_and_direct_peers() {
        let config = MigrationConfig {
            initial_delay: Duration::from_millis(1),
            validation_timeout: Duration::from_secs(10),
            ..Default::default()
        };
        let coordinator = MigrationCoordinator::new(config);

        let peer1 = peer_addr(1);
        let peer2 = peer_addr(2);
        let candidate = candidate_addr(1);

        // Start migration for peer1
        coordinator.add_candidates(peer1, vec![candidate]).await;
        coordinator.start_migration(peer1).await;

        // Complete migration for peer2
        coordinator.add_candidates(peer2, vec![candidate]).await;
        coordinator.start_migration(peer2).await;
        tokio::time::sleep(Duration::from_millis(10)).await;
        coordinator.poll(peer2).await;
        coordinator
            .report_validated_path(peer2, candidate, Duration::from_millis(50))
            .await;
        coordinator.complete_migration(peer2).await;

        let migrating = coordinator.migrating_peers().await;
        let direct = coordinator.direct_peers().await;

        assert!(migrating.contains(&peer1));
        assert!(!migrating.contains(&peer2));
        assert!(direct.contains(&peer2));
        assert!(!direct.contains(&peer1));
    }

    // ========== IP Version Filtering Tests ==========

    fn ipv6_addr(id: u16) -> SocketAddr {
        use std::net::Ipv6Addr;
        SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, id)),
            9000,
        )
    }

    #[tokio::test]
    async fn test_get_candidates_filtered_all() {
        let config = MigrationConfig::default();
        let coordinator = MigrationCoordinator::new(config);

        let peer = peer_addr(1);
        let ipv4_candidate = candidate_addr(1);
        let ipv6_candidate = ipv6_addr(1);

        coordinator
            .add_candidates(peer, vec![ipv4_candidate, ipv6_candidate])
            .await;

        let all = coordinator.get_all_candidates(peer).await;
        assert_eq!(all.len(), 2);
        assert!(all.contains(&ipv4_candidate));
        assert!(all.contains(&ipv6_candidate));
    }

    #[tokio::test]
    async fn test_get_ipv4_candidates() {
        let config = MigrationConfig::default();
        let coordinator = MigrationCoordinator::new(config);

        let peer = peer_addr(1);
        let ipv4_candidate1 = candidate_addr(1);
        let ipv4_candidate2 = candidate_addr(2);
        let ipv6_candidate = ipv6_addr(1);

        coordinator
            .add_candidates(peer, vec![ipv4_candidate1, ipv4_candidate2, ipv6_candidate])
            .await;

        let ipv4_only = coordinator.get_ipv4_candidates(peer).await;
        assert_eq!(ipv4_only.len(), 2);
        assert!(ipv4_only.contains(&ipv4_candidate1));
        assert!(ipv4_only.contains(&ipv4_candidate2));
        assert!(!ipv4_only.contains(&ipv6_candidate));
    }

    #[tokio::test]
    async fn test_get_ipv6_candidates() {
        let config = MigrationConfig::default();
        let coordinator = MigrationCoordinator::new(config);

        let peer = peer_addr(1);
        let ipv4_candidate = candidate_addr(1);
        let ipv6_candidate1 = ipv6_addr(1);
        let ipv6_candidate2 = ipv6_addr(2);

        coordinator
            .add_candidates(peer, vec![ipv4_candidate, ipv6_candidate1, ipv6_candidate2])
            .await;

        let ipv6_only = coordinator.get_ipv6_candidates(peer).await;
        assert_eq!(ipv6_only.len(), 2);
        assert!(!ipv6_only.contains(&ipv4_candidate));
        assert!(ipv6_only.contains(&ipv6_candidate1));
        assert!(ipv6_only.contains(&ipv6_candidate2));
    }

    #[tokio::test]
    async fn test_has_dual_stack_candidates() {
        let config = MigrationConfig::default();
        let coordinator = MigrationCoordinator::new(config);

        let peer1 = peer_addr(1);
        let peer2 = peer_addr(2);
        let peer3 = peer_addr(3);

        // peer1: only IPv4 candidates
        coordinator
            .add_candidates(peer1, vec![candidate_addr(1), candidate_addr(2)])
            .await;

        // peer2: only IPv6 candidates
        coordinator
            .add_candidates(peer2, vec![ipv6_addr(1), ipv6_addr(2)])
            .await;

        // peer3: both IPv4 and IPv6 candidates (dual-stack)
        coordinator
            .add_candidates(peer3, vec![candidate_addr(3), ipv6_addr(3)])
            .await;

        assert!(!coordinator.has_dual_stack_candidates(peer1).await);
        assert!(!coordinator.has_dual_stack_candidates(peer2).await);
        assert!(coordinator.has_dual_stack_candidates(peer3).await);
    }

    #[tokio::test]
    async fn test_no_candidates_returns_empty() {
        let config = MigrationConfig::default();
        let coordinator = MigrationCoordinator::new(config);

        let peer = peer_addr(1);
        // Don't add any candidates

        assert!(coordinator.get_all_candidates(peer).await.is_empty());
        assert!(coordinator.get_ipv4_candidates(peer).await.is_empty());
        assert!(coordinator.get_ipv6_candidates(peer).await.is_empty());
        assert!(!coordinator.has_dual_stack_candidates(peer).await);
    }
}
