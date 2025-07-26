//! Network efficiency optimization components for ant-quic
//!
//! This module provides network-aware optimizations including:
//! - Parallel candidate discovery across interfaces
//! - Adaptive timeout adjustment based on network conditions
//! - Bandwidth-aware QUIC path validation strategies
//! - Congestion control integration during QUIC connection migration

use std::{
    collections::{HashMap, VecDeque},
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex, RwLock},
    time::{Duration, Instant},
};

use tokio::time::timeout;

use tracing::{debug, info, warn};

use tokio::time::sleep;

use crate::{
    candidate_discovery::NetworkInterface,
    connection::nat_traversal::{CandidateSource, CandidateState},
    nat_traversal_api::{CandidateAddress, PeerId},
};

/// Parallel candidate discovery coordinator
#[derive(Debug)]
pub struct ParallelDiscoveryCoordinator {
    /// Active discovery tasks by interface
    active_discoveries: Arc<RwLock<HashMap<String, DiscoveryTask>>>,
    /// Discovery configuration
    config: ParallelDiscoveryConfig,
    /// Discovery statistics
    stats: Arc<Mutex<ParallelDiscoveryStats>>,
    /// Task coordination handle
    coordination_handle: Option<tokio::task::JoinHandle<()>>,
}

/// Configuration for parallel discovery
#[derive(Debug, Clone)]
pub struct ParallelDiscoveryConfig {
    /// Maximum concurrent discovery tasks
    pub max_concurrent_tasks: usize,
    /// Timeout for individual interface discovery
    pub interface_timeout: Duration,
    /// Enable interface prioritization
    pub enable_prioritization: bool,
    /// Preferred interface types
    pub preferred_interface_types: Vec<InterfaceType>,
    /// Enable adaptive parallelism based on system resources
    pub enable_adaptive_parallelism: bool,
}

/// Network interface type for prioritization
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterfaceType {
    Ethernet,
    WiFi,
    Cellular,
    Loopback,
    VPN,
    Unknown,
}

/// Individual discovery task state
#[derive(Debug)]
struct DiscoveryTask {
    interface_name: String,
    interface_type: InterfaceType,
    started_at: Instant,
    status: TaskStatus,
    discovered_candidates: Vec<CandidateAddress>,
    priority: u32,
}

/// Status of a discovery task
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TaskStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Timeout,
}

/// Statistics for parallel discovery
#[derive(Debug, Default, Clone)]
pub struct ParallelDiscoveryStats {
    /// Total discovery tasks started
    pub tasks_started: u64,
    /// Total discovery tasks completed
    pub tasks_completed: u64,
    /// Total discovery tasks failed
    pub tasks_failed: u64,
    /// Average discovery time per interface
    pub avg_discovery_time: Duration,
    /// Total candidates discovered
    pub total_candidates: u64,
    /// Parallelism efficiency (0.0 - 1.0)
    pub parallelism_efficiency: f64,
}

/// Adaptive timeout manager for network condition awareness
#[derive(Debug)]
pub struct AdaptiveTimeoutManager {
    /// Network condition measurements
    network_conditions: Arc<RwLock<NetworkConditions>>,
    /// Timeout configurations by operation type
    timeout_configs: HashMap<OperationType, AdaptiveTimeoutConfig>,
    /// Timeout statistics
    stats: Arc<Mutex<AdaptiveTimeoutStats>>,
    /// Monitoring task handle
    monitoring_handle: Option<tokio::task::JoinHandle<()>>,
}

/// Network conditions measurement
#[derive(Debug, Clone)]
pub struct NetworkConditions {
    /// Recent RTT measurements
    rtt_samples: VecDeque<Duration>,
    /// Packet loss rate (0.0 - 1.0)
    packet_loss_rate: f64,
    /// Bandwidth estimate (bytes/sec)
    bandwidth_estimate: u64,
    /// Network quality score (0.0 - 1.0)
    quality_score: f64,
    /// Congestion level (0.0 - 1.0)
    congestion_level: f64,
    /// Last measurement time
    last_measurement: Instant,
}

/// Operation types for adaptive timeouts
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OperationType {
    CandidateDiscovery,
    PathValidation,
    CoordinationRequest,
    HolePunching,
    ConnectionEstablishment,
}

/// Adaptive timeout configuration
#[derive(Debug, Clone)]
struct AdaptiveTimeoutConfig {
    /// Base timeout value
    base_timeout: Duration,
    /// Minimum timeout
    min_timeout: Duration,
    /// Maximum timeout
    max_timeout: Duration,
    /// RTT multiplier for timeout calculation
    rtt_multiplier: f64,
    /// Quality adjustment factor
    quality_factor: f64,
    /// Congestion adjustment factor
    congestion_factor: f64,
}

/// Statistics for adaptive timeouts
#[derive(Debug, Default, Clone)]
pub struct AdaptiveTimeoutStats {
    /// Total timeout adjustments made
    pub adjustments_made: u64,
    /// Average timeout value by operation
    pub avg_timeouts: HashMap<OperationType, Duration>,
    /// Timeout effectiveness (success rate)
    pub timeout_effectiveness: f64,
    /// Network condition accuracy
    pub condition_accuracy: f64,
}

/// Bandwidth-aware path validation coordinator
#[derive(Debug)]
pub struct BandwidthAwareValidator {
    /// Active validation sessions
    active_validations: Arc<RwLock<HashMap<SocketAddr, ValidationSession>>>,
    /// Bandwidth monitoring
    bandwidth_monitor: Arc<Mutex<BandwidthMonitor>>,
    /// Validation configuration
    config: BandwidthValidationConfig,
    /// Validation statistics
    stats: Arc<Mutex<BandwidthValidationStats>>,
}

/// Configuration for bandwidth-aware validation
#[derive(Debug, Clone)]
pub struct BandwidthValidationConfig {
    /// Maximum concurrent validations
    pub max_concurrent_validations: usize,
    /// Bandwidth threshold for validation throttling (bytes/sec)
    pub bandwidth_threshold: u64,
    /// Enable adaptive validation based on bandwidth
    pub enable_adaptive_validation: bool,
    /// Validation packet size
    pub validation_packet_size: usize,
    /// Maximum validation rate (packets/sec)
    pub max_validation_rate: f64,
}

/// Bandwidth monitoring state
#[derive(Debug)]
struct BandwidthMonitor {
    /// Recent bandwidth measurements
    bandwidth_samples: VecDeque<BandwidthSample>,
    /// Current bandwidth estimate
    current_bandwidth: u64,
    /// Bandwidth utilization (0.0 - 1.0)
    utilization: f64,
    /// Last measurement time
    last_measurement: Instant,
}

/// Individual bandwidth measurement
#[derive(Debug, Clone)]
struct BandwidthSample {
    timestamp: Instant,
    bytes_transferred: u64,
    duration: Duration,
    bandwidth: u64,
}

/// Path validation session
#[derive(Debug)]
struct ValidationSession {
    target_address: SocketAddr,
    started_at: Instant,
    packets_sent: u32,
    packets_received: u32,
    total_bytes: u64,
    rtt_samples: Vec<Duration>,
    bandwidth_usage: u64,
    priority: ValidationPriority,
}

/// Priority for path validation
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ValidationPriority {
    Low,
    Normal,
    High,
    Critical,
}

/// Statistics for bandwidth-aware validation
#[derive(Debug, Default, Clone)]
pub struct BandwidthValidationStats {
    /// Total validations started
    pub validations_started: u64,
    /// Total validations completed
    pub validations_completed: u64,
    /// Total bandwidth used for validation
    pub total_bandwidth_used: u64,
    /// Average validation time
    pub avg_validation_time: Duration,
    /// Bandwidth efficiency (successful validations / bandwidth used)
    pub bandwidth_efficiency: f64,
}

/// Congestion control integration for connection migration
#[derive(Debug)]
pub struct CongestionControlIntegrator {
    /// Active connection migrations
    active_migrations: Arc<RwLock<HashMap<PeerId, MigrationSession>>>,
    /// Congestion control state
    congestion_state: Arc<Mutex<CongestionState>>,
    /// Integration configuration
    config: CongestionIntegrationConfig,
    /// Integration statistics
    stats: Arc<Mutex<CongestionIntegrationStats>>,
}

/// Configuration for congestion control integration
#[derive(Debug, Clone)]
pub struct CongestionIntegrationConfig {
    /// Enable congestion-aware migration
    pub enable_congestion_awareness: bool,
    /// Congestion threshold for migration decisions
    pub congestion_threshold: f64,
    /// Migration rate limiting
    pub max_migrations_per_second: f64,
    /// Enable bandwidth estimation during migration
    pub enable_bandwidth_estimation: bool,
    /// Congestion window scaling factor
    pub cwnd_scaling_factor: f64,
}

/// Connection migration session
#[derive(Debug)]
struct MigrationSession {
    peer_id: PeerId,
    old_path: SocketAddr,
    new_path: SocketAddr,
    started_at: Instant,
    migration_state: MigrationState,
    congestion_window: u32,
    rtt_estimate: Duration,
    bandwidth_estimate: u64,
}

/// State of connection migration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationState {
    Initiated,
    PathValidating,
    CongestionProbing,
    Migrating,
    Completed,
    Failed,
}

/// Congestion control state
#[derive(Debug)]
struct CongestionState {
    /// Current congestion window
    congestion_window: u32,
    /// Slow start threshold
    ssthresh: u32,
    /// RTT measurements
    rtt_measurements: VecDeque<Duration>,
    /// Congestion events
    congestion_events: VecDeque<CongestionEvent>,
    /// Current congestion level
    congestion_level: f64,
}

/// Congestion event for tracking
#[derive(Debug, Clone)]
struct CongestionEvent {
    timestamp: Instant,
    event_type: CongestionEventType,
    severity: f64,
}

/// Types of congestion events
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CongestionEventType {
    PacketLoss,
    Timeout,
    ECNMark,
    RTTIncrease,
}

/// Statistics for congestion control integration
#[derive(Debug, Default, Clone)]
pub struct CongestionIntegrationStats {
    /// Total migrations attempted
    pub migrations_attempted: u64,
    /// Total migrations successful
    pub migrations_successful: u64,
    /// Average migration time
    pub avg_migration_time: Duration,
    /// Congestion-avoided migrations
    pub congestion_avoided_migrations: u64,
    /// Bandwidth utilization efficiency
    pub bandwidth_utilization_efficiency: f64,
}

impl Default for ParallelDiscoveryConfig {
    fn default() -> Self {
        Self {
            max_concurrent_tasks: 8,
            interface_timeout: Duration::from_secs(5),
            enable_prioritization: true,
            preferred_interface_types: vec![
                InterfaceType::Ethernet,
                InterfaceType::WiFi,
                InterfaceType::Cellular,
            ],
            enable_adaptive_parallelism: true,
        }
    }
}

impl Default for BandwidthValidationConfig {
    fn default() -> Self {
        Self {
            max_concurrent_validations: 16,
            bandwidth_threshold: 1_000_000, // 1 MB/s
            enable_adaptive_validation: true,
            validation_packet_size: 64,
            max_validation_rate: 100.0, // 100 packets/sec
        }
    }
}

impl Default for CongestionIntegrationConfig {
    fn default() -> Self {
        Self {
            enable_congestion_awareness: true,
            congestion_threshold: 0.7, // 70% congestion level
            max_migrations_per_second: 10.0,
            enable_bandwidth_estimation: true,
            cwnd_scaling_factor: 0.8,
        }
    }
}

impl ParallelDiscoveryCoordinator {
    /// Create a new parallel discovery coordinator
    pub fn new(config: ParallelDiscoveryConfig) -> Self {
        Self {
            active_discoveries: Arc::new(RwLock::new(HashMap::new())),
            config,
            stats: Arc::new(Mutex::new(ParallelDiscoveryStats::default())),
            coordination_handle: None,
        }
    }

    /// Start parallel discovery across multiple interfaces
    pub async fn start_parallel_discovery(
        &mut self,
        interfaces: Vec<NetworkInterface>,
        peer_id: PeerId,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!(
            "Starting parallel discovery across {} interfaces for peer {:?}",
            interfaces.len(),
            peer_id
        );

        // Prioritize interfaces if enabled
        let prioritized_interfaces = if self.config.enable_prioritization {
            self.prioritize_interfaces(interfaces)
        } else {
            interfaces
        };

        // Limit concurrent tasks based on configuration and system resources
        let max_tasks = if self.config.enable_adaptive_parallelism {
            self.calculate_adaptive_parallelism().await
        } else {
            self.config.max_concurrent_tasks
        };

        let tasks_to_start = prioritized_interfaces
            .into_iter()
            .take(max_tasks)
            .collect::<Vec<_>>();

        // Start discovery tasks
        for interface in tasks_to_start {
            self.start_interface_discovery(interface, peer_id).await?;
        }

        // Start coordination task
        self.start_coordination_task().await?;

        Ok(())
    }

    /// Prioritize interfaces based on type and characteristics
    fn prioritize_interfaces(
        &self,
        mut interfaces: Vec<NetworkInterface>,
    ) -> Vec<NetworkInterface> {
        interfaces.sort_by_key(|interface| {
            let interface_type = self.classify_interface_type(&interface.name);
            let type_priority = self
                .config
                .preferred_interface_types
                .iter()
                .position(|&t| t == interface_type)
                .unwrap_or(999);

            // Lower number = higher priority
            (type_priority, interface.addresses.len())
        });

        interfaces
    }

    /// Classify interface type from name
    fn classify_interface_type(&self, name: &str) -> InterfaceType {
        let name_lower = name.to_lowercase();

        if name_lower.contains("eth") || name_lower.contains("en") {
            InterfaceType::Ethernet
        } else if name_lower.contains("wlan")
            || name_lower.contains("wifi")
            || name_lower.contains("wl")
        {
            InterfaceType::WiFi
        } else if name_lower.contains("cell")
            || name_lower.contains("wwan")
            || name_lower.contains("ppp")
        {
            InterfaceType::Cellular
        } else if name_lower.contains("lo") || name_lower.contains("loopback") {
            InterfaceType::Loopback
        } else if name_lower.contains("vpn")
            || name_lower.contains("tun")
            || name_lower.contains("tap")
        {
            InterfaceType::VPN
        } else {
            InterfaceType::Unknown
        }
    }

    /// Calculate adaptive parallelism based on system resources
    async fn calculate_adaptive_parallelism(&self) -> usize {
        // Simplified adaptive calculation
        // In production, this would consider:
        // - CPU cores
        // - Memory availability
        // - Network bandwidth
        // - Current system load

        let base_parallelism = self.config.max_concurrent_tasks;
        let system_load_factor = 0.8; // Assume 80% system capacity

        ((base_parallelism as f64) * system_load_factor) as usize
    }

    /// Start discovery for a specific interface
    async fn start_interface_discovery(
        &self,
        interface: NetworkInterface,
        _peer_id: PeerId,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let interface_type = self.classify_interface_type(&interface.name);
        let priority = self.calculate_interface_priority(interface_type);

        let task = DiscoveryTask {
            interface_name: interface.name.clone(),
            interface_type,
            started_at: Instant::now(),
            status: TaskStatus::Pending,
            discovered_candidates: Vec::new(),
            priority,
        };

        // Add to active discoveries
        {
            let mut discoveries = self.active_discoveries.write().unwrap();
            discoveries.insert(interface.name.clone(), task);
        }

        // Update stats
        {
            let mut stats = self.stats.lock().unwrap();
            stats.tasks_started += 1;
        }

        // Start actual discovery (simplified)
        self.perform_interface_discovery(interface).await?;

        Ok(())
    }

    /// Calculate priority for interface type
    fn calculate_interface_priority(&self, interface_type: InterfaceType) -> u32 {
        match interface_type {
            InterfaceType::Ethernet => 100,
            InterfaceType::WiFi => 80,
            InterfaceType::Cellular => 60,
            InterfaceType::VPN => 40,
            InterfaceType::Loopback => 20,
            InterfaceType::Unknown => 10,
        }
    }

    /// Perform discovery for a specific interface
    async fn perform_interface_discovery(
        &self,
        interface: NetworkInterface,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let interface_name = interface.name.clone();

        // Update task status to running
        {
            let mut discoveries = self.active_discoveries.write().unwrap();
            if let Some(task) = discoveries.get_mut(&interface_name) {
                task.status = TaskStatus::Running;
            }
        }

        // Perform discovery with timeout
        let discovery_result = timeout(
            self.config.interface_timeout,
            self.discover_candidates_for_interface(interface),
        )
        .await;

        match discovery_result {
            Ok(Ok(candidates)) => {
                // Discovery successful
                {
                    let mut discoveries = self.active_discoveries.write().unwrap();
                    if let Some(task) = discoveries.get_mut(&interface_name) {
                        task.status = TaskStatus::Completed;
                        task.discovered_candidates = candidates;
                    }
                }

                // Update stats
                {
                    let mut stats = self.stats.lock().unwrap();
                    stats.tasks_completed += 1;
                }

                debug!("Interface discovery completed for {}", interface_name);
            }
            Ok(Err(_)) => {
                // Discovery failed
                {
                    let mut discoveries = self.active_discoveries.write().unwrap();
                    if let Some(task) = discoveries.get_mut(&interface_name) {
                        task.status = TaskStatus::Failed;
                    }
                }

                // Update stats
                {
                    let mut stats = self.stats.lock().unwrap();
                    stats.tasks_failed += 1;
                }

                warn!("Interface discovery failed for {}", interface_name);
            }
            Err(_) => {
                // Discovery timeout
                {
                    let mut discoveries = self.active_discoveries.write().unwrap();
                    if let Some(task) = discoveries.get_mut(&interface_name) {
                        task.status = TaskStatus::Timeout;
                    }
                }

                // Update stats
                {
                    let mut stats = self.stats.lock().unwrap();
                    stats.tasks_failed += 1;
                }

                warn!("Interface discovery timeout for {}", interface_name);
            }
        }

        Ok(())
    }

    /// Discover candidates for a specific interface
    async fn discover_candidates_for_interface(
        &self,
        interface: NetworkInterface,
    ) -> Result<Vec<CandidateAddress>, Box<dyn std::error::Error + Send + Sync>> {
        let mut candidates = Vec::new();

        for address in &interface.addresses {
            // Skip loopback and link-local addresses for P2P
            if self.is_valid_candidate_address(address) {
                let candidate = CandidateAddress {
                    address: *address,
                    priority: self.calculate_candidate_priority(address, &interface),
                    source: CandidateSource::Local,
                    state: CandidateState::New,
                };

                candidates.push(candidate);
            }
        }

        // Simulate some discovery time
        sleep(Duration::from_millis(100)).await;

        Ok(candidates)
    }

    /// Check if address is valid for P2P candidate
    fn is_valid_candidate_address(&self, address: &SocketAddr) -> bool {
        match address.ip() {
            IpAddr::V4(ipv4) => {
                !ipv4.is_loopback() && !ipv4.is_link_local() && !ipv4.is_broadcast()
            }
            IpAddr::V6(ipv6) => !ipv6.is_loopback() && !ipv6.is_unspecified(),
        }
    }

    /// Calculate priority for a candidate address
    fn calculate_candidate_priority(
        &self,
        address: &SocketAddr,
        interface: &NetworkInterface,
    ) -> u32 {
        let mut priority = 1000u32;

        // Prefer IPv4 over IPv6 for simplicity
        if address.is_ipv4() {
            priority += 100;
        }

        // Prefer non-private addresses
        if !self.is_private_address(address) {
            priority += 200;
        }

        // Add interface-specific priority
        let interface_type = self.classify_interface_type(&interface.name);
        priority += self.calculate_interface_priority(interface_type);

        priority
    }

    /// Check if address is in private range
    fn is_private_address(&self, address: &SocketAddr) -> bool {
        match address.ip() {
            IpAddr::V4(ipv4) => ipv4.is_private(),
            IpAddr::V6(ipv6) => {
                // Check for unique local addresses (fc00::/7)
                let segments = ipv6.segments();
                (segments[0] & 0xfe00) == 0xfc00
            }
        }
    }

    /// Start coordination task for managing parallel discoveries
    async fn start_coordination_task(
        &mut self,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let discoveries = Arc::clone(&self.active_discoveries);
        let stats = Arc::clone(&self.stats);
        let config = self.config.clone();

        let coordination_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(500));

            loop {
                interval.tick().await;
                Self::coordinate_discoveries(&discoveries, &stats, &config).await;

                // Check if all discoveries are complete
                let all_complete = {
                    let discoveries_read = discoveries.read().unwrap();
                    discoveries_read.values().all(|task| {
                        matches!(
                            task.status,
                            TaskStatus::Completed | TaskStatus::Failed | TaskStatus::Timeout
                        )
                    })
                };

                if all_complete {
                    break;
                }
            }
        });

        self.coordination_handle = Some(coordination_handle);
        Ok(())
    }

    /// Coordinate parallel discoveries
    async fn coordinate_discoveries(
        discoveries: &Arc<RwLock<HashMap<String, DiscoveryTask>>>,
        stats: &Arc<Mutex<ParallelDiscoveryStats>>,
        _config: &ParallelDiscoveryConfig,
    ) {
        let mut total_candidates = 0u64;
        let mut completed_tasks = 0u64;
        let mut total_discovery_time = Duration::ZERO;

        {
            let discoveries_read = discoveries.read().unwrap();
            for task in discoveries_read.values() {
                if task.status == TaskStatus::Completed {
                    total_candidates += task.discovered_candidates.len() as u64;
                    completed_tasks += 1;
                    total_discovery_time += task.started_at.elapsed();
                }
            }
        }

        // Update stats
        {
            let mut stats_guard = stats.lock().unwrap();
            stats_guard.total_candidates = total_candidates;
            stats_guard.tasks_completed = completed_tasks;

            if completed_tasks > 0 {
                stats_guard.avg_discovery_time = total_discovery_time / completed_tasks as u32;
                stats_guard.parallelism_efficiency =
                    completed_tasks as f64 / stats_guard.tasks_started as f64;
            }
        }
    }

    /// Get all discovered candidates from parallel discovery
    pub async fn get_all_candidates(&self) -> Vec<CandidateAddress> {
        let mut all_candidates = Vec::new();

        let discoveries = self.active_discoveries.read().unwrap();
        for task in discoveries.values() {
            if task.status == TaskStatus::Completed {
                all_candidates.extend(task.discovered_candidates.clone());
            }
        }

        // Sort by priority (highest first)
        all_candidates.sort_by(|a, b| b.priority.cmp(&a.priority));

        all_candidates
    }

    /// Get parallel discovery statistics
    pub async fn get_stats(&self) -> ParallelDiscoveryStats {
        self.stats.lock().unwrap().clone()
    }

    /// Shutdown parallel discovery coordinator
    pub async fn shutdown(&mut self) {
        if let Some(handle) = self.coordination_handle.take() {
            handle.abort();
        }

        // Clear active discoveries
        {
            let mut discoveries = self.active_discoveries.write().unwrap();
            discoveries.clear();
        }

        info!("Parallel discovery coordinator shutdown complete");
    }
}

impl Default for AdaptiveTimeoutManager {
    fn default() -> Self {
        Self::new()
    }
}

impl AdaptiveTimeoutManager {
    /// Create a new adaptive timeout manager
    pub fn new() -> Self {
        let mut timeout_configs = HashMap::new();

        // Initialize default timeout configurations for each operation type
        timeout_configs.insert(
            OperationType::CandidateDiscovery,
            AdaptiveTimeoutConfig {
                base_timeout: Duration::from_secs(5),
                min_timeout: Duration::from_millis(500),
                max_timeout: Duration::from_secs(30),
                rtt_multiplier: 4.0,
                quality_factor: 0.5,
                congestion_factor: 0.3,
            },
        );

        timeout_configs.insert(
            OperationType::PathValidation,
            AdaptiveTimeoutConfig {
                base_timeout: Duration::from_secs(3),
                min_timeout: Duration::from_millis(200),
                max_timeout: Duration::from_secs(15),
                rtt_multiplier: 3.0,
                quality_factor: 0.4,
                congestion_factor: 0.4,
            },
        );

        timeout_configs.insert(
            OperationType::CoordinationRequest,
            AdaptiveTimeoutConfig {
                base_timeout: Duration::from_secs(10),
                min_timeout: Duration::from_secs(1),
                max_timeout: Duration::from_secs(60),
                rtt_multiplier: 5.0,
                quality_factor: 0.6,
                congestion_factor: 0.2,
            },
        );

        timeout_configs.insert(
            OperationType::HolePunching,
            AdaptiveTimeoutConfig {
                base_timeout: Duration::from_secs(2),
                min_timeout: Duration::from_millis(100),
                max_timeout: Duration::from_secs(10),
                rtt_multiplier: 2.0,
                quality_factor: 0.3,
                congestion_factor: 0.5,
            },
        );

        timeout_configs.insert(
            OperationType::ConnectionEstablishment,
            AdaptiveTimeoutConfig {
                base_timeout: Duration::from_secs(15),
                min_timeout: Duration::from_secs(2),
                max_timeout: Duration::from_secs(120),
                rtt_multiplier: 6.0,
                quality_factor: 0.7,
                congestion_factor: 0.1,
            },
        );

        Self {
            network_conditions: Arc::new(RwLock::new(NetworkConditions {
                rtt_samples: VecDeque::new(),
                packet_loss_rate: 0.0,
                bandwidth_estimate: 1_000_000, // 1 MB/s default
                quality_score: 0.8,            // Good quality default
                congestion_level: 0.2,         // Low congestion default
                last_measurement: Instant::now(),
            })),
            timeout_configs,
            stats: Arc::new(Mutex::new(AdaptiveTimeoutStats::default())),
            monitoring_handle: None,
        }
    }

    /// Start the adaptive timeout manager with network monitoring
    pub async fn start(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let network_conditions = Arc::clone(&self.network_conditions);
        let stats = Arc::clone(&self.stats);

        let monitoring_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));

            loop {
                interval.tick().await;
                Self::update_network_conditions(&network_conditions, &stats).await;
            }
        });

        self.monitoring_handle = Some(monitoring_handle);
        info!("Adaptive timeout manager started");
        Ok(())
    }

    /// Calculate adaptive timeout for an operation
    pub async fn calculate_timeout(&self, operation: OperationType) -> Duration {
        let config = self
            .timeout_configs
            .get(&operation)
            .cloned()
            .unwrap_or_else(|| AdaptiveTimeoutConfig {
                base_timeout: Duration::from_secs(5),
                min_timeout: Duration::from_millis(500),
                max_timeout: Duration::from_secs(30),
                rtt_multiplier: 4.0,
                quality_factor: 0.5,
                congestion_factor: 0.3,
            });

        let conditions = self.network_conditions.read().unwrap();

        // Calculate base timeout from RTT if available
        let rtt_based_timeout =
            if let Some(avg_rtt) = self.calculate_average_rtt(&conditions.rtt_samples) {
                Duration::from_millis((avg_rtt.as_millis() as f64 * config.rtt_multiplier) as u64)
            } else {
                config.base_timeout
            };

        // Adjust for network quality
        let quality_adjustment = 1.0 + (1.0 - conditions.quality_score) * config.quality_factor;

        // Adjust for congestion
        let congestion_adjustment = 1.0 + conditions.congestion_level * config.congestion_factor;

        // Calculate final timeout
        let adjusted_timeout = Duration::from_millis(
            (rtt_based_timeout.as_millis() as f64 * quality_adjustment * congestion_adjustment)
                as u64,
        );

        // Clamp to min/max bounds
        let final_timeout = adjusted_timeout
            .max(config.min_timeout)
            .min(config.max_timeout);

        // Update stats
        {
            let mut stats = self.stats.lock().unwrap();
            stats.adjustments_made += 1;
            stats.avg_timeouts.insert(operation, final_timeout);
        }

        debug!(
            "Calculated adaptive timeout for {:?}: {:?} (quality: {:.2}, congestion: {:.2})",
            operation, final_timeout, conditions.quality_score, conditions.congestion_level
        );

        final_timeout
    }

    /// Record network measurement for adaptive timeout calculation
    pub async fn record_measurement(
        &self,
        rtt: Duration,
        packet_loss: bool,
        bandwidth: Option<u64>,
    ) {
        let mut conditions = self.network_conditions.write().unwrap();

        // Add RTT sample
        conditions.rtt_samples.push_back(rtt);
        if conditions.rtt_samples.len() > 50 {
            conditions.rtt_samples.pop_front();
        }

        // Update packet loss rate (exponential moving average)
        let loss_sample = if packet_loss { 1.0 } else { 0.0 };
        conditions.packet_loss_rate = conditions.packet_loss_rate * 0.9 + loss_sample * 0.1;

        // Update bandwidth estimate if provided
        if let Some(bw) = bandwidth {
            conditions.bandwidth_estimate =
                (conditions.bandwidth_estimate as f64 * 0.8 + bw as f64 * 0.2) as u64;
        }

        // Update quality score based on RTT and packet loss
        let rtt_quality = 1.0 - (rtt.as_millis() as f64 / 1000.0).min(1.0);
        let loss_quality = 1.0 - conditions.packet_loss_rate;
        conditions.quality_score = (rtt_quality + loss_quality) / 2.0;

        // Update congestion level based on RTT variance and packet loss
        let rtt_variance = self.calculate_rtt_variance(&conditions.rtt_samples);
        conditions.congestion_level = (conditions.packet_loss_rate + rtt_variance).min(1.0);

        conditions.last_measurement = Instant::now();
    }

    /// Calculate average RTT from samples
    fn calculate_average_rtt(&self, samples: &VecDeque<Duration>) -> Option<Duration> {
        if samples.is_empty() {
            return None;
        }

        let total_ms: u64 = samples.iter().map(|d| d.as_millis() as u64).sum();
        Some(Duration::from_millis(total_ms / samples.len() as u64))
    }

    /// Calculate RTT variance for congestion detection
    fn calculate_rtt_variance(&self, samples: &VecDeque<Duration>) -> f64 {
        if samples.len() < 2 {
            return 0.0;
        }

        let avg = self.calculate_average_rtt(samples).unwrap().as_millis() as f64;
        let variance: f64 = samples
            .iter()
            .map(|d| {
                let diff = d.as_millis() as f64 - avg;
                diff * diff
            })
            .sum::<f64>()
            / samples.len() as f64;

        (variance.sqrt() / avg).min(1.0)
    }

    /// Update network conditions periodically
    async fn update_network_conditions(
        network_conditions: &Arc<RwLock<NetworkConditions>>,
        _stats: &Arc<Mutex<AdaptiveTimeoutStats>>,
    ) {
        // Periodic network condition updates
        // In production, this would:
        // - Probe network conditions
        // - Update bandwidth estimates
        // - Detect congestion patterns
        // - Adjust quality scores

        let mut conditions = network_conditions.write().unwrap();

        // Age out old RTT samples (keep last 100 samples)
        while conditions.rtt_samples.len() > 100 {
            conditions.rtt_samples.pop_front();
        }

        // Decay packet loss rate over time
        conditions.packet_loss_rate *= 0.99;

        // Update quality score based on recent measurements
        if conditions.last_measurement.elapsed() > Duration::from_secs(10) {
            // No recent measurements, assume degraded quality
            conditions.quality_score *= 0.95;
        }
    }

    /// Get current network conditions
    pub async fn get_network_conditions(&self) -> NetworkConditions {
        self.network_conditions.read().unwrap().clone()
    }

    /// Get adaptive timeout statistics
    pub async fn get_stats(&self) -> AdaptiveTimeoutStats {
        self.stats.lock().unwrap().clone()
    }

    /// Shutdown the adaptive timeout manager
    pub async fn shutdown(&mut self) {
        if let Some(handle) = self.monitoring_handle.take() {
            handle.abort();
        }

        info!("Adaptive timeout manager shutdown complete");
    }
}

impl BandwidthAwareValidator {
    /// Create a new bandwidth-aware validator
    pub fn new(config: BandwidthValidationConfig) -> Self {
        Self {
            active_validations: Arc::new(RwLock::new(HashMap::new())),
            bandwidth_monitor: Arc::new(Mutex::new(BandwidthMonitor {
                bandwidth_samples: VecDeque::new(),
                current_bandwidth: 1_000_000, // 1 MB/s default
                utilization: 0.0,
                last_measurement: Instant::now(),
            })),
            config,
            stats: Arc::new(Mutex::new(BandwidthValidationStats::default())),
        }
    }

    /// Start path validation with bandwidth awareness
    pub async fn start_validation(
        &self,
        target_address: SocketAddr,
        priority: ValidationPriority,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Check if we can start new validation based on bandwidth constraints
        if !self.can_start_validation().await {
            return Err("Bandwidth limit reached, cannot start validation".into());
        }

        let session = ValidationSession {
            target_address,
            started_at: Instant::now(),
            packets_sent: 0,
            packets_received: 0,
            total_bytes: 0,
            rtt_samples: Vec::new(),
            bandwidth_usage: 0,
            priority,
        };

        // Add to active validations
        {
            let mut validations = self.active_validations.write().unwrap();
            validations.insert(target_address, session);
        }

        // Update stats
        {
            let mut stats = self.stats.lock().unwrap();
            stats.validations_started += 1;
        }

        debug!("Started bandwidth-aware validation for {}", target_address);
        Ok(())
    }

    /// Check if new validation can be started based on bandwidth constraints
    async fn can_start_validation(&self) -> bool {
        let validations = self.active_validations.read().unwrap();
        let bandwidth_monitor = self.bandwidth_monitor.lock().unwrap();

        // Check concurrent validation limit
        if validations.len() >= self.config.max_concurrent_validations {
            return false;
        }

        // Check bandwidth utilization if adaptive validation is enabled
        if self.config.enable_adaptive_validation {
            let current_usage: u64 = validations
                .values()
                .map(|session| session.bandwidth_usage)
                .sum();

            let available_bandwidth = bandwidth_monitor.current_bandwidth;
            let utilization = current_usage as f64 / available_bandwidth as f64;

            if utilization > 0.8 {
                // 80% utilization threshold
                return false;
            }
        }

        true
    }

    /// Record validation packet transmission
    pub async fn record_packet_sent(
        &self,
        target_address: SocketAddr,
        packet_size: usize,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut validations = self.active_validations.write().unwrap();

        if let Some(session) = validations.get_mut(&target_address) {
            session.packets_sent += 1;
            session.total_bytes += packet_size as u64;
            session.bandwidth_usage += packet_size as u64;
        }

        // Update bandwidth monitoring
        self.update_bandwidth_usage(packet_size as u64).await;

        Ok(())
    }

    /// Record validation packet reception
    pub async fn record_packet_received(
        &self,
        target_address: SocketAddr,
        rtt: Duration,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut validations = self.active_validations.write().unwrap();

        if let Some(session) = validations.get_mut(&target_address) {
            session.packets_received += 1;
            session.rtt_samples.push(rtt);
        }

        Ok(())
    }

    /// Update bandwidth usage monitoring
    async fn update_bandwidth_usage(&self, bytes_used: u64) {
        let mut monitor = self.bandwidth_monitor.lock().unwrap();

        let now = Instant::now();
        let sample = BandwidthSample {
            timestamp: now,
            bytes_transferred: bytes_used,
            duration: now.duration_since(monitor.last_measurement),
            bandwidth: if monitor.last_measurement.elapsed().as_secs() > 0 {
                bytes_used / monitor.last_measurement.elapsed().as_secs()
            } else {
                0
            },
        };

        monitor.bandwidth_samples.push_back(sample);
        if monitor.bandwidth_samples.len() > 100 {
            monitor.bandwidth_samples.pop_front();
        }

        // Update current bandwidth estimate
        if !monitor.bandwidth_samples.is_empty() {
            let total_bytes: u64 = monitor
                .bandwidth_samples
                .iter()
                .map(|s| s.bytes_transferred)
                .sum();
            let total_time: Duration = monitor.bandwidth_samples.iter().map(|s| s.duration).sum();

            if total_time.as_secs() > 0 {
                monitor.current_bandwidth = total_bytes / total_time.as_secs();
            }
        }

        monitor.last_measurement = now;
    }

    /// Complete validation session
    pub async fn complete_validation(
        &self,
        target_address: SocketAddr,
        success: bool,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let session = {
            let mut validations = self.active_validations.write().unwrap();
            validations.remove(&target_address)
        };

        if let Some(session) = session {
            let duration = session.started_at.elapsed();

            // Update stats
            {
                let mut stats = self.stats.lock().unwrap();
                if success {
                    stats.validations_completed += 1;
                }
                stats.total_bandwidth_used += session.bandwidth_usage;
                stats.avg_validation_time = if stats.validations_completed > 0 {
                    Duration::from_millis(
                        (stats.avg_validation_time.as_millis() as u64
                            * (stats.validations_completed - 1)
                            + duration.as_millis() as u64)
                            / stats.validations_completed,
                    )
                } else {
                    duration
                };

                if stats.total_bandwidth_used > 0 {
                    stats.bandwidth_efficiency = stats.validations_completed as f64
                        / stats.total_bandwidth_used as f64
                        * 1000.0; // per KB
                }
            }

            debug!(
                "Completed validation for {} in {:?} (success: {})",
                target_address, duration, success
            );
        }

        Ok(())
    }

    /// Get bandwidth validation statistics
    pub async fn get_stats(&self) -> BandwidthValidationStats {
        self.stats.lock().unwrap().clone()
    }
}

impl CongestionControlIntegrator {
    /// Create a new congestion control integrator
    pub fn new(config: CongestionIntegrationConfig) -> Self {
        Self {
            active_migrations: Arc::new(RwLock::new(HashMap::new())),
            congestion_state: Arc::new(Mutex::new(CongestionState {
                congestion_window: 10, // Initial cwnd
                ssthresh: 65535,
                rtt_measurements: VecDeque::new(),
                congestion_events: VecDeque::new(),
                congestion_level: 0.0,
            })),
            config,
            stats: Arc::new(Mutex::new(CongestionIntegrationStats::default())),
        }
    }

    /// Start connection migration with congestion awareness
    pub async fn start_migration(
        &self,
        peer_id: PeerId,
        old_path: SocketAddr,
        new_path: SocketAddr,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Check if migration should be delayed due to congestion
        if self.config.enable_congestion_awareness {
            let congestion_state = self.congestion_state.lock().unwrap();
            if congestion_state.congestion_level > self.config.congestion_threshold {
                return Err("Migration delayed due to high congestion".into());
            }
        }

        let session = MigrationSession {
            peer_id,
            old_path,
            new_path,
            started_at: Instant::now(),
            migration_state: MigrationState::Initiated,
            congestion_window: {
                let state = self.congestion_state.lock().unwrap();
                (state.congestion_window as f64 * self.config.cwnd_scaling_factor) as u32
            },
            rtt_estimate: Duration::from_millis(100), // Default RTT
            bandwidth_estimate: 1_000_000,            // 1 MB/s default
        };

        // Add to active migrations
        {
            let mut migrations = self.active_migrations.write().unwrap();
            migrations.insert(peer_id, session);
        }

        // Update stats
        {
            let mut stats = self.stats.lock().unwrap();
            stats.migrations_attempted += 1;
        }

        info!(
            "Started congestion-aware migration for peer {:?}: {} -> {}",
            peer_id, old_path, new_path
        );
        Ok(())
    }

    /// Update migration state based on congestion feedback
    pub async fn update_migration_state(
        &self,
        peer_id: PeerId,
        new_state: MigrationState,
        rtt: Option<Duration>,
        bandwidth: Option<u64>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut migrations = self.active_migrations.write().unwrap();

        if let Some(session) = migrations.get_mut(&peer_id) {
            session.migration_state = new_state;

            if let Some(rtt) = rtt {
                session.rtt_estimate = rtt;

                // Update global congestion state
                let mut congestion_state = self.congestion_state.lock().unwrap();
                congestion_state.rtt_measurements.push_back(rtt);
                if congestion_state.rtt_measurements.len() > 50 {
                    congestion_state.rtt_measurements.pop_front();
                }
            }

            if let Some(bw) = bandwidth {
                session.bandwidth_estimate = bw;
            }

            // Check if migration completed
            if matches!(new_state, MigrationState::Completed) {
                let duration = session.started_at.elapsed();

                // Update stats
                let mut stats = self.stats.lock().unwrap();
                stats.migrations_successful += 1;
                stats.avg_migration_time = if stats.migrations_successful > 0 {
                    Duration::from_millis(
                        (stats.avg_migration_time.as_millis() as u64
                            * (stats.migrations_successful - 1)
                            + duration.as_millis() as u64)
                            / stats.migrations_successful,
                    )
                } else {
                    duration
                };

                debug!(
                    "Migration completed for peer {:?} in {:?}",
                    peer_id, duration
                );
            }
        }

        Ok(())
    }

    /// Record congestion event
    pub async fn record_congestion_event(&self, event_type: CongestionEventType, severity: f64) {
        let event = CongestionEvent {
            timestamp: Instant::now(),
            event_type,
            severity,
        };

        let mut congestion_state = self.congestion_state.lock().unwrap();
        congestion_state.congestion_events.push_back(event);

        // Keep only recent events
        if congestion_state.congestion_events.len() > 100 {
            congestion_state.congestion_events.pop_front();
        }

        // Update congestion level based on recent events
        let recent_events: Vec<_> = congestion_state
            .congestion_events
            .iter()
            .filter(|e| e.timestamp.elapsed() < Duration::from_secs(10))
            .collect();

        if !recent_events.is_empty() {
            let avg_severity: f64 =
                recent_events.iter().map(|e| e.severity).sum::<f64>() / recent_events.len() as f64;

            congestion_state.congestion_level = avg_severity;
        }

        // Adjust congestion window based on event
        match event_type {
            CongestionEventType::PacketLoss | CongestionEventType::Timeout => {
                congestion_state.ssthresh = congestion_state.congestion_window / 2;
                congestion_state.congestion_window = congestion_state.ssthresh;
            }
            CongestionEventType::ECNMark => {
                congestion_state.congestion_window =
                    (congestion_state.congestion_window as f64 * 0.8) as u32;
            }
            CongestionEventType::RTTIncrease => {
                // Gradual reduction for RTT increase
                congestion_state.congestion_window =
                    (congestion_state.congestion_window as f64 * 0.95) as u32;
            }
        }

        debug!(
            "Recorded congestion event: {:?} (severity: {:.2}, new cwnd: {})",
            event_type, severity, congestion_state.congestion_window
        );
    }

    /// Get congestion control integration statistics
    pub async fn get_stats(&self) -> CongestionIntegrationStats {
        self.stats.lock().unwrap().clone()
    }
}

/// Network efficiency optimization manager that coordinates all network optimization components
#[derive(Debug)]
pub struct NetworkEfficiencyManager {
    parallel_discovery: ParallelDiscoveryCoordinator,
    adaptive_timeout: AdaptiveTimeoutManager,
    bandwidth_validator: BandwidthAwareValidator,
    congestion_integrator: CongestionControlIntegrator,
    is_running: bool,
}

impl NetworkEfficiencyManager {
    /// Create a new network efficiency manager with default configurations
    pub fn new() -> Self {
        Self {
            parallel_discovery: ParallelDiscoveryCoordinator::new(
                ParallelDiscoveryConfig::default(),
            ),
            adaptive_timeout: AdaptiveTimeoutManager::new(),
            bandwidth_validator: BandwidthAwareValidator::new(BandwidthValidationConfig::default()),
            congestion_integrator: CongestionControlIntegrator::new(
                CongestionIntegrationConfig::default(),
            ),
            is_running: false,
        }
    }

    /// Create a new network efficiency manager with custom configurations
    pub fn with_configs(
        discovery_config: ParallelDiscoveryConfig,
        validation_config: BandwidthValidationConfig,
        congestion_config: CongestionIntegrationConfig,
    ) -> Self {
        Self {
            parallel_discovery: ParallelDiscoveryCoordinator::new(discovery_config),
            adaptive_timeout: AdaptiveTimeoutManager::new(),
            bandwidth_validator: BandwidthAwareValidator::new(validation_config),
            congestion_integrator: CongestionControlIntegrator::new(congestion_config),
            is_running: false,
        }
    }

    /// Start all network efficiency components
    pub async fn start(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if self.is_running {
            return Ok(());
        }

        self.adaptive_timeout.start().await?;

        self.is_running = true;
        info!("Network efficiency manager started");
        Ok(())
    }

    /// Get parallel discovery coordinator reference
    pub fn parallel_discovery(&mut self) -> &mut ParallelDiscoveryCoordinator {
        &mut self.parallel_discovery
    }

    /// Get adaptive timeout manager reference
    pub fn adaptive_timeout(&self) -> &AdaptiveTimeoutManager {
        &self.adaptive_timeout
    }

    /// Get bandwidth validator reference
    pub fn bandwidth_validator(&self) -> &BandwidthAwareValidator {
        &self.bandwidth_validator
    }

    /// Get congestion integrator reference
    pub fn congestion_integrator(&self) -> &CongestionControlIntegrator {
        &self.congestion_integrator
    }

    /// Get comprehensive network efficiency statistics
    pub async fn get_comprehensive_stats(&self) -> NetworkEfficiencyStats {
        NetworkEfficiencyStats {
            parallel_discovery: self.parallel_discovery.get_stats().await,
            adaptive_timeout: self.adaptive_timeout.get_stats().await,
            bandwidth_validation: self.bandwidth_validator.get_stats().await,
            congestion_integration: self.congestion_integrator.get_stats().await,
        }
    }

    /// Shutdown all network efficiency components
    pub async fn shutdown(&mut self) {
        if !self.is_running {
            return;
        }

        self.parallel_discovery.shutdown().await;
        self.adaptive_timeout.shutdown().await;

        self.is_running = false;
        info!("Network efficiency manager shutdown complete");
    }
}

/// Comprehensive network efficiency statistics
#[derive(Debug, Clone)]
pub struct NetworkEfficiencyStats {
    pub parallel_discovery: ParallelDiscoveryStats,
    pub adaptive_timeout: AdaptiveTimeoutStats,
    pub bandwidth_validation: BandwidthValidationStats,
    pub congestion_integration: CongestionIntegrationStats,
}

impl Default for NetworkEfficiencyManager {
    fn default() -> Self {
        Self::new()
    }
}
