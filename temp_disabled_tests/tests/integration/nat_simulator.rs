//! NAT Simulator for Integration Testing
//!
//! This module provides comprehensive NAT behavior simulation for testing
//! NAT traversal functionality across different network configurations.

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use rand::Rng;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::{
    connection::nat_traversal::{
        NatTraversalRole, CandidateSource, CandidateState,
    },
    nat_traversal_api::{
        NatTraversalConfig, NatTraversalEndpoint, EndpointRole, PeerId,
        CandidateAddress, NatTraversalStatistics,
    },
};

use super::{
    mock_network::{MockNetworkEnvironment, NatType, NatDeviceId, NetworkSimulationResult},
    NetworkSimulationConfig, NatScenario, PerformanceMetrics,
};

/// Network simulator for NAT traversal testing
pub struct NetworkSimulator {
    /// Configuration for network simulation
    config: NetworkSimulationConfig,
    /// Mock network environment
    network_env: MockNetworkEnvironment,
    /// Active NAT scenarios
    active_scenarios: HashMap<String, NatScenario>,
    /// Performance metrics
    metrics: Arc<Mutex<PerformanceMetrics>>,
    /// Simulation state
    state: SimulatorState,
}

/// Simulator state
#[derive(Debug, Clone)]
enum SimulatorState {
    Uninitialized,
    Ready,
    Running,
    Paused,
    Stopped,
}

/// NAT simulation configuration
#[derive(Debug, Clone)]
pub struct NatSimulationConfig {
    /// NAT types for each device
    pub nat_types: Vec<NatType>,
    /// Connection success rates by NAT combination
    pub success_rates: HashMap<(NatType, NatType), f32>,
    /// Packet processing delays
    pub processing_delays: HashMap<NatType, Duration>,
    /// Port allocation behavior
    pub port_allocation: PortAllocationBehavior,
    /// Symmetric NAT port prediction accuracy
    pub port_prediction_accuracy: f32,
}

/// Port allocation behavior for NAT simulation
#[derive(Debug, Clone)]
pub enum PortAllocationBehavior {
    /// Sequential port allocation
    Sequential,
    /// Random port allocation
    Random,
    /// Predictable pattern for testing
    Predictable { increment: u16 },
}

impl Default for NatSimulationConfig {
    fn default() -> Self {
        let mut success_rates = HashMap::new();
        
        // Configure realistic success rates based on NAT combinations
        success_rates.insert((NatType::FullCone, NatType::FullCone), 0.95);
        success_rates.insert((NatType::FullCone, NatType::RestrictedCone), 0.90);
        success_rates.insert((NatType::FullCone, NatType::PortRestrictedCone), 0.85);
        success_rates.insert((NatType::FullCone, NatType::Symmetric), 0.70);
        success_rates.insert((NatType::RestrictedCone, NatType::RestrictedCone), 0.85);
        success_rates.insert((NatType::RestrictedCone, NatType::PortRestrictedCone), 0.80);
        success_rates.insert((NatType::RestrictedCone, NatType::Symmetric), 0.60);
        success_rates.insert((NatType::PortRestrictedCone, NatType::PortRestrictedCone), 0.75);
        success_rates.insert((NatType::PortRestrictedCone, NatType::Symmetric), 0.50);
        success_rates.insert((NatType::Symmetric, NatType::Symmetric), 0.30);
        success_rates.insert((NatType::CarrierGrade, NatType::CarrierGrade), 0.20);
        
        let mut processing_delays = HashMap::new();
        processing_delays.insert(NatType::FullCone, Duration::from_millis(1));
        processing_delays.insert(NatType::RestrictedCone, Duration::from_millis(2));
        processing_delays.insert(NatType::PortRestrictedCone, Duration::from_millis(3));
        processing_delays.insert(NatType::Symmetric, Duration::from_millis(5));
        processing_delays.insert(NatType::CarrierGrade, Duration::from_millis(10));
        
        Self {
            nat_types: vec![NatType::FullCone, NatType::Symmetric],
            success_rates,
            processing_delays,
            port_allocation: PortAllocationBehavior::Sequential,
            port_prediction_accuracy: 0.8,
        }
    }
}

impl NetworkSimulator {
    /// Create a new network simulator
    pub fn new(config: NetworkSimulationConfig) -> Self {
        let network_env = MockNetworkEnvironment::new(config.clone());
        
        Self {
            config,
            network_env,
            active_scenarios: HashMap::new(),
            metrics: Arc::new(Mutex::new(PerformanceMetrics::default())),
            state: SimulatorState::Uninitialized,
        }
    }

    /// Initialize the simulator
    pub fn initialize(&mut self) {
        info!("Initializing network simulator");
        self.state = SimulatorState::Ready;
    }

    /// Configure a specific NAT scenario
    pub fn configure_nat_scenario(&mut self, scenario: NatScenario) {
        info!("Configuring NAT scenario: {:?}", scenario);
        
        match scenario {
            NatScenario::FullConeToFullCone => {
                self.setup_full_cone_scenario();
            }
            NatScenario::FullConeToRestricted => {
                self.setup_mixed_scenario(NatType::FullCone, NatType::RestrictedCone);
            }
            NatScenario::RestrictedToPortRestricted => {
                self.setup_mixed_scenario(NatType::RestrictedCone, NatType::PortRestrictedCone);
            }
            NatScenario::PortRestrictedToSymmetric => {
                self.setup_mixed_scenario(NatType::PortRestrictedCone, NatType::Symmetric);
            }
            NatScenario::SymmetricToSymmetric => {
                self.setup_symmetric_scenario();
            }
            NatScenario::CgnatScenario => {
                self.setup_cgnat_scenario();
            }
            NatScenario::DoubleNatScenario => {
                self.setup_double_nat_scenario();
            }
        }
        
        self.active_scenarios.insert(format!("{:?}", scenario), scenario);
    }

    /// Setup full cone NAT scenario
    fn setup_full_cone_scenario(&mut self) {
        let (device1, device2) = self.network_env.create_home_network_scenario();
        debug!("Created full cone scenario with devices {:?} and {:?}", device1, device2);
    }

    /// Setup mixed NAT scenario
    fn setup_mixed_scenario(&mut self, nat1: NatType, nat2: NatType) {
        let device1 = NatDeviceId(100);
        let device2 = NatDeviceId(101);
        
        self.network_env.add_nat_device(
            device1,
            nat1,
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 100)),
            (IpAddr::V4(Ipv4Addr::new(192, 168, 100, 0)), 24),
        );
        
        self.network_env.add_nat_device(
            device2,
            nat2,
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 101)),
            (IpAddr::V4(Ipv4Addr::new(192, 168, 101, 0)), 24),
        );
        
        self.network_env.add_network_link(device1, device2, Duration::from_millis(50), 1_000_000);
        self.network_env.add_network_link(device2, device1, Duration::from_millis(50), 1_000_000);
        
        debug!("Created mixed NAT scenario: {:?} <-> {:?}", nat1, nat2);
    }

    /// Setup symmetric NAT scenario
    fn setup_symmetric_scenario(&mut self) {
        self.setup_mixed_scenario(NatType::Symmetric, NatType::Symmetric);
    }

    /// Setup carrier grade NAT scenario
    fn setup_cgnat_scenario(&mut self) {
        let (device1, device2) = self.network_env.create_mobile_network_scenario();
        debug!("Created CGNAT scenario with devices {:?} and {:?}", device1, device2);
    }

    /// Setup double NAT scenario
    fn setup_double_nat_scenario(&mut self) {
        // Create a more complex topology with multiple NAT layers
        let device1 = NatDeviceId(200);
        let device2 = NatDeviceId(201);
        let intermediate = NatDeviceId(202);
        
        // First layer NAT
        self.network_env.add_nat_device(
            device1,
            NatType::FullCone,
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 200)),
            (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 16),
        );
        
        // Second layer NAT (intermediate)
        self.network_env.add_nat_device(
            intermediate,
            NatType::PortRestrictedCone,
            IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
            (IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)), 24),
        );
        
        // Target NAT
        self.network_env.add_nat_device(
            device2,
            NatType::Symmetric,
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 201)),
            (IpAddr::V4(Ipv4Addr::new(172, 16, 0, 0)), 16),
        );
        
        // Create network links
        self.network_env.add_network_link(device1, intermediate, Duration::from_millis(25), 10_000_000);
        self.network_env.add_network_link(intermediate, device2, Duration::from_millis(75), 5_000_000);
        self.network_env.add_network_link(device2, intermediate, Duration::from_millis(75), 5_000_000);
        self.network_env.add_network_link(intermediate, device1, Duration::from_millis(25), 10_000_000);
        
        debug!("Created double NAT scenario with intermediate device");
    }

    /// Simulate NAT traversal attempt
    pub async fn simulate_nat_traversal(
        &mut self,
        client_config: NatTraversalConfig,
        server_config: NatTraversalConfig,
    ) -> Result<NatTraversalSimulationResult, Box<dyn std::error::Error>> {
        info!("Starting NAT traversal simulation");
        self.state = SimulatorState::Running;
        
        let start_time = Instant::now();
        
        // Update metrics
        {
            let mut metrics = self.metrics.lock().unwrap();
            metrics.connection_attempts += 1;
        }
        
        // Simulate the NAT traversal process
        let result = self.execute_traversal_simulation(client_config, server_config).await?;
        
        let duration = start_time.elapsed();
        
        // Update metrics based on result
        {
            let mut metrics = self.metrics.lock().unwrap();
            if result.success {
                metrics.successful_connections += 1;
                metrics.avg_connection_time = if metrics.successful_connections == 1 {
                    duration
                } else {
                    Duration::from_millis(
                        (metrics.avg_connection_time.as_millis() as u64 + duration.as_millis() as u64) / 2
                    )
                };
            } else {
                metrics.failed_connections += 1;
            }
        }
        
        Ok(result)
    }

    /// Execute the actual traversal simulation
    async fn execute_traversal_simulation(
        &mut self,
        client_config: NatTraversalConfig,
        server_config: NatTraversalConfig,
    ) -> Result<NatTraversalSimulationResult, Box<dyn std::error::Error>> {
        
        // Simulate candidate discovery phase
        let client_candidates = self.simulate_candidate_discovery(&client_config).await?;
        let server_candidates = self.simulate_candidate_discovery(&server_config).await?;
        
        debug!("Client discovered {} candidates", client_candidates.len());
        debug!("Server discovered {} candidates", server_candidates.len());
        
        // Simulate candidate pairing and connectivity checks
        let connectivity_results = self.simulate_connectivity_checks(
            &client_candidates,
            &server_candidates,
        ).await?;
        
        // Determine overall success based on connectivity results
        let success = connectivity_results.iter().any(|result| result.success);
        let connection_time = connectivity_results.iter()
            .filter(|r| r.success)
            .map(|r| r.round_trip_time)
            .min()
            .unwrap_or(Duration::from_secs(0));
        
        let selected_pair = if success {
            connectivity_results.iter()
                .find(|r| r.success)
                .map(|r| (r.local_candidate.clone(), r.remote_candidate.clone()))
        } else {
            None
        };
        
        Ok(NatTraversalSimulationResult {
            success,
            connection_time,
            total_candidates: client_candidates.len() + server_candidates.len(),
            successful_pairs: connectivity_results.iter().filter(|r| r.success).count(),
            selected_pair,
            connectivity_results,
            failure_reason: if success { None } else { Some("No successful candidate pairs".to_string()) },
        })
    }

    /// Simulate candidate discovery
    async fn simulate_candidate_discovery(
        &self,
        config: &NatTraversalConfig,
    ) -> Result<Vec<SimulatedCandidate>, Box<dyn std::error::Error>> {
        let mut candidates = Vec::new();
        
        // Add host candidates
        candidates.push(SimulatedCandidate {
            address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 5000),
            candidate_type: CandidateType::Host,
            priority: 126,
            foundation: "host".to_string(),
        });
        
        // Add server reflexive candidates
        candidates.push(SimulatedCandidate {
            address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), 12345),
            candidate_type: CandidateType::ServerReflexive,
            priority: 100,
            foundation: "srflx".to_string(),
        });
        
        // Add relay candidates if enabled
        if config.enable_relay_fallback {
            candidates.push(SimulatedCandidate {
                address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)), 3478),
                candidate_type: CandidateType::Relay,
                priority: 2,
                foundation: "relay".to_string(),
            });
        }
        
        // Limit candidates based on configuration
        candidates.truncate(config.max_candidates as usize);
        
        Ok(candidates)
    }

    /// Simulate connectivity checks between candidate pairs
    async fn simulate_connectivity_checks(
        &self,
        client_candidates: &[SimulatedCandidate],
        server_candidates: &[SimulatedCandidate],
    ) -> Result<Vec<ConnectivityCheckResult>, Box<dyn std::error::Error>> {
        let mut results = Vec::new();
        
        for client_candidate in client_candidates {
            for server_candidate in server_candidates {
                let result = self.simulate_single_connectivity_check(
                    client_candidate,
                    server_candidate,
                ).await?;
                
                results.push(result);
            }
        }
        
        // Sort by success and then by RTT
        results.sort_by(|a, b| {
            match (a.success, b.success) {
                (true, false) => std::cmp::Ordering::Less,
                (false, true) => std::cmp::Ordering::Greater,
                (true, true) => a.round_trip_time.cmp(&b.round_trip_time),
                (false, false) => std::cmp::Ordering::Equal,
            }
        });
        
        Ok(results)
    }

    /// Simulate a single connectivity check
    async fn simulate_single_connectivity_check(
        &self,
        local_candidate: &SimulatedCandidate,
        remote_candidate: &SimulatedCandidate,
    ) -> Result<ConnectivityCheckResult, Box<dyn std::error::Error>> {
        
        // Determine success based on candidate types and NAT configuration
        let success_probability = self.calculate_success_probability(
            &local_candidate.candidate_type,
            &remote_candidate.candidate_type,
        );
        
        let mut rng = rand::thread_rng();
        let success = rng.gen::<f32>() < success_probability;
        
        let round_trip_time = if success {
            Duration::from_millis(rng.gen_range(20..200))
        } else {
            Duration::from_secs(0)
        };
        
        Ok(ConnectivityCheckResult {
            local_candidate: local_candidate.clone(),
            remote_candidate: remote_candidate.clone(),
            success,
            round_trip_time,
            error_message: if success { 
                None 
            } else { 
                Some("Connectivity check failed".to_string()) 
            },
        })
    }

    /// Calculate success probability based on candidate types
    fn calculate_success_probability(
        &self,
        local_type: &CandidateType,
        remote_type: &CandidateType,
    ) -> f32 {
        match (local_type, remote_type) {
            (CandidateType::Host, CandidateType::Host) => 0.95,
            (CandidateType::Host, CandidateType::ServerReflexive) => 0.85,
            (CandidateType::ServerReflexive, CandidateType::Host) => 0.85,
            (CandidateType::ServerReflexive, CandidateType::ServerReflexive) => 0.70,
            (CandidateType::Relay, _) | (_, CandidateType::Relay) => 0.98,
            _ => 0.50,
        }
    }

    /// Get current simulation metrics
    pub fn get_metrics(&self) -> PerformanceMetrics {
        self.metrics.lock().unwrap().clone()
    }

    /// Reset simulation state
    pub fn reset(&mut self) {
        self.state = SimulatorState::Ready;
        self.active_scenarios.clear();
        *self.metrics.lock().unwrap() = PerformanceMetrics::default();
        self.network_env.reset_statistics();
    }
}

/// Simulated candidate for testing
#[derive(Debug, Clone)]
pub struct SimulatedCandidate {
    /// Candidate address
    pub address: SocketAddr,
    /// Type of candidate
    pub candidate_type: CandidateType,
    /// ICE priority
    pub priority: u32,
    /// ICE foundation
    pub foundation: String,
}

/// Types of ICE candidates
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CandidateType {
    /// Host candidate (local interface)
    Host,
    /// Server reflexive candidate (observed by STUN)
    ServerReflexive,
    /// Peer reflexive candidate (learned from peer)
    PeerReflexive,
    /// Relay candidate (TURN server)
    Relay,
}

/// Result of a connectivity check between two candidates
#[derive(Debug, Clone)]
pub struct ConnectivityCheckResult {
    /// Local candidate
    pub local_candidate: SimulatedCandidate,
    /// Remote candidate
    pub remote_candidate: SimulatedCandidate,
    /// Whether the check succeeded
    pub success: bool,
    /// Round trip time for successful checks
    pub round_trip_time: Duration,
    /// Error message for failed checks
    pub error_message: Option<String>,
}

/// Result of a complete NAT traversal simulation
#[derive(Debug, Clone)]
pub struct NatTraversalSimulationResult {
    /// Overall success of the traversal
    pub success: bool,
    /// Time to establish connection
    pub connection_time: Duration,
    /// Total number of candidates discovered
    pub total_candidates: usize,
    /// Number of successful candidate pairs
    pub successful_pairs: usize,
    /// The selected candidate pair (if successful)
    pub selected_pair: Option<(SimulatedCandidate, SimulatedCandidate)>,
    /// Results of all connectivity checks
    pub connectivity_results: Vec<ConnectivityCheckResult>,
    /// Reason for failure (if applicable)
    pub failure_reason: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_simulator_creation() {
        let config = NetworkSimulationConfig::default();
        let mut simulator = NetworkSimulator::new(config);
        
        simulator.initialize();
        assert!(matches!(simulator.state, SimulatorState::Ready));
    }

    #[test]
    fn test_nat_scenario_configuration() {
        let config = NetworkSimulationConfig::default();
        let mut simulator = NetworkSimulator::new(config);
        
        simulator.initialize();
        simulator.configure_nat_scenario(NatScenario::FullConeToFullCone);
        
        assert!(simulator.active_scenarios.contains_key("FullConeToFullCone"));
    }

    #[test]
    fn test_success_probability_calculation() {
        let config = NetworkSimulationConfig::default();
        let simulator = NetworkSimulator::new(config);
        
        let host_to_host = simulator.calculate_success_probability(
            &CandidateType::Host,
            &CandidateType::Host,
        );
        assert!(host_to_host > 0.9);
        
        let relay_probability = simulator.calculate_success_probability(
            &CandidateType::Relay,
            &CandidateType::Host,
        );
        assert!(relay_probability > 0.95);
    }

    #[tokio::test]
    async fn test_candidate_discovery_simulation() {
        let config = NetworkSimulationConfig::default();
        let simulator = NetworkSimulator::new(config);
        
        let nat_config = NatTraversalConfig::default();
        let candidates = simulator.simulate_candidate_discovery(&nat_config).await;
        
        assert!(candidates.is_ok());
        let candidates = candidates.unwrap();
        assert!(!candidates.is_empty());
        assert!(candidates.len() <= nat_config.max_candidates as usize);
    }
}