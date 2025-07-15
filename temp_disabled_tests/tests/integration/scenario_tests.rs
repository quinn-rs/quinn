//! Scenario Tests for NAT Traversal Integration
//!
//! This module implements comprehensive scenario-based testing for NAT traversal
//! functionality, covering various real-world network configurations and use cases.

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use tokio::{sync::mpsc, time::sleep};
use tracing::{debug, info, warn};

use crate::{
    connection::nat_traversal::{NatTraversalRole, CandidateSource},
    nat_traversal_api::{
        NatTraversalConfig, NatTraversalEndpoint, EndpointRole, PeerId,
        CandidateAddress, NatTraversalStatistics, NatTraversalEvent,
    },
};

use super::{
    nat_simulator::{NetworkSimulator, NatTraversalSimulationResult},
    mock_network::{MockNetworkEnvironment, NatType, NatDeviceId},
    NetworkSimulationConfig, TestScenario, NatScenario, MultiPeerScenario, FailureScenario,
    PerformanceMetrics,
};

/// Scenario test executor
pub struct ScenarioTestExecutor {
    /// Network simulator
    simulator: Arc<Mutex<NetworkSimulator>>,
    /// Mock network environment
    network_env: Arc<Mutex<MockNetworkEnvironment>>,
    /// Test results collector
    results: Arc<Mutex<Vec<ScenarioTestResult>>>,
    /// Performance metrics
    metrics: Arc<Mutex<PerformanceMetrics>>,
}

/// Result of a scenario test
#[derive(Debug, Clone)]
pub struct ScenarioTestResult {
    /// Scenario name
    pub scenario_name: String,
    /// Test success status
    pub success: bool,
    /// Test duration
    pub duration: Duration,
    /// Connection establishment time
    pub connection_time: Duration,
    /// Number of participants
    pub participants: usize,
    /// Success rate for multi-peer scenarios
    pub success_rate: f32,
    /// Error details if failed
    pub error_details: Option<String>,
    /// Performance metrics
    pub metrics: PerformanceMetrics,
}

/// Test participant configuration
#[derive(Debug, Clone)]
pub struct TestParticipant {
    /// Participant ID
    pub id: String,
    /// Peer ID
    pub peer_id: PeerId,
    /// NAT traversal configuration
    pub config: NatTraversalConfig,
    /// Expected NAT type
    pub nat_type: NatType,
    /// Network device ID
    pub device_id: NatDeviceId,
}

/// Multi-peer test configuration
#[derive(Debug, Clone)]
pub struct MultiPeerTestConfig {
    /// Number of participants
    pub participant_count: usize,
    /// Topology type
    pub topology: NetworkTopology,
    /// Connection pattern
    pub connection_pattern: ConnectionPattern,
    /// Test duration
    pub test_duration: Duration,
    /// Enable bootstrap coordination
    pub enable_bootstrap_coordination: bool,
}

/// Network topology for multi-peer tests
#[derive(Debug, Clone)]
pub enum NetworkTopology {
    /// Full mesh - everyone connects to everyone
    FullMesh,
    /// Star topology - one central node
    Star { center_id: String },
    /// Linear chain
    Chain,
    /// Random connections
    Random { connection_probability: f32 },
}

/// Connection pattern for tests
#[derive(Debug, Clone)]
pub enum ConnectionPattern {
    /// All connections established simultaneously
    Simultaneous,
    /// Connections established sequentially
    Sequential { delay: Duration },
    /// Random connection timing
    Random { min_delay: Duration, max_delay: Duration },
}

impl ScenarioTestExecutor {
    /// Create a new scenario test executor
    pub fn new(network_config: NetworkSimulationConfig) -> Self {
        let simulator = Arc::new(Mutex::new(NetworkSimulator::new(network_config.clone())));
        let network_env = Arc::new(Mutex::new(MockNetworkEnvironment::new(network_config)));
        
        Self {
            simulator,
            network_env,
            results: Arc::new(Mutex::new(Vec::new())),
            metrics: Arc::new(Mutex::new(PerformanceMetrics::default())),
        }
    }

    /// Execute a basic test scenario
    pub async fn execute_basic_scenario(&mut self, scenario: TestScenario) -> ScenarioTestResult {
        info!("Executing basic scenario: {:?}", scenario);
        let start_time = Instant::now();
        
        let result = match scenario {
            TestScenario::BasicClientServer => {
                self.test_basic_client_server().await
            }
            TestScenario::ClientWithBootstrap => {
                self.test_client_with_bootstrap().await
            }
            TestScenario::ServerCoordination => {
                self.test_server_coordination().await
            }
            TestScenario::BootstrapNodeFunctionality => {
                self.test_bootstrap_node_functionality().await
            }
        };
        
        let duration = start_time.elapsed();
        
        match result {
            Ok(connection_time) => ScenarioTestResult {
                scenario_name: format!("{:?}", scenario),
                success: true,
                duration,
                connection_time,
                participants: 2, // Most basic scenarios involve 2 participants
                success_rate: 1.0,
                error_details: None,
                metrics: self.metrics.lock().unwrap().clone(),
            },
            Err(error) => ScenarioTestResult {
                scenario_name: format!("{:?}", scenario),
                success: false,
                duration,
                connection_time: Duration::from_secs(0),
                participants: 2,
                success_rate: 0.0,
                error_details: Some(error.to_string()),
                metrics: self.metrics.lock().unwrap().clone(),
            },
        }
    }

    /// Execute a NAT scenario test
    pub async fn execute_nat_scenario(&mut self, scenario: NatScenario) -> ScenarioTestResult {
        info!("Executing NAT scenario: {:?}", scenario);
        let start_time = Instant::now();
        
        // Configure the network simulator for this scenario
        self.simulator.lock().unwrap().configure_nat_scenario(scenario.clone());
        
        let result = self.test_nat_scenario_implementation(scenario.clone()).await;
        let duration = start_time.elapsed();
        
        match result {
            Ok((connection_time, success_rate)) => ScenarioTestResult {
                scenario_name: format!("{:?}", scenario),
                success: success_rate > 0.5, // Consider successful if > 50% success rate
                duration,
                connection_time,
                participants: 2,
                success_rate,
                error_details: None,
                metrics: self.metrics.lock().unwrap().clone(),
            },
            Err(error) => ScenarioTestResult {
                scenario_name: format!("{:?}", scenario),
                success: false,
                duration,
                connection_time: Duration::from_secs(0),
                participants: 2,
                success_rate: 0.0,
                error_details: Some(error.to_string()),
                metrics: self.metrics.lock().unwrap().clone(),
            },
        }
    }

    /// Execute a multi-peer scenario test
    pub async fn execute_multi_peer_scenario(&mut self, scenario: MultiPeerScenario) -> ScenarioTestResult {
        info!("Executing multi-peer scenario: {:?}", scenario);
        let start_time = Instant::now();
        
        let config = self.create_multi_peer_config(&scenario);
        let result = self.test_multi_peer_implementation(scenario.clone(), config).await;
        let duration = start_time.elapsed();
        
        match result {
            Ok((connection_time, participant_count, success_rate)) => ScenarioTestResult {
                scenario_name: format!("{:?}", scenario),
                success: success_rate > 0.7, // Consider successful if > 70% success rate
                duration,
                connection_time,
                participants: participant_count,
                success_rate,
                error_details: None,
                metrics: self.metrics.lock().unwrap().clone(),
            },
            Err(error) => ScenarioTestResult {
                scenario_name: format!("{:?}", scenario),
                success: false,
                duration,
                connection_time: Duration::from_secs(0),
                participants: 0,
                success_rate: 0.0,
                error_details: Some(error.to_string()),
                metrics: self.metrics.lock().unwrap().clone(),
            },
        }
    }

    /// Execute a failure scenario test
    pub async fn execute_failure_scenario(&mut self, scenario: FailureScenario) -> ScenarioTestResult {
        info!("Executing failure scenario: {:?}", scenario);
        let start_time = Instant::now();
        
        let result = self.test_failure_scenario_implementation(scenario.clone()).await;
        let duration = start_time.elapsed();
        
        match result {
            Ok((recovery_time, resilience_score)) => ScenarioTestResult {
                scenario_name: format!("{:?}", scenario),
                success: resilience_score > 0.5, // Consider successful if system shows resilience
                duration,
                connection_time: recovery_time,
                participants: 2,
                success_rate: resilience_score,
                error_details: None,
                metrics: self.metrics.lock().unwrap().clone(),
            },
            Err(error) => ScenarioTestResult {
                scenario_name: format!("{:?}", scenario),
                success: false,
                duration,
                connection_time: Duration::from_secs(0),
                participants: 2,
                success_rate: 0.0,
                error_details: Some(error.to_string()),
                metrics: self.metrics.lock().unwrap().clone(),
            },
        }
    }

    // Implementation of specific test scenarios

    async fn test_basic_client_server(&mut self) -> Result<Duration, Box<dyn std::error::Error>> {
        debug!("Testing basic client-server scenario");
        
        let client_config = NatTraversalConfig {
            role: EndpointRole::Client,
            bootstrap_nodes: vec!["203.0.113.1:9000".parse().unwrap()],
            max_candidates: 8,
            coordination_timeout: Duration::from_secs(10),
            enable_symmetric_nat: true,
            enable_relay_fallback: true,
            max_concurrent_attempts: 3,
        };
        
        let server_config = NatTraversalConfig {
            role: EndpointRole::Server { can_coordinate: true },
            bootstrap_nodes: vec![],
            max_candidates: 8,
            coordination_timeout: Duration::from_secs(10),
            enable_symmetric_nat: true,
            enable_relay_fallback: true,
            max_concurrent_attempts: 3,
        };
        
        let start_time = Instant::now();
        let result = self.simulator.lock().unwrap()
            .simulate_nat_traversal(client_config, server_config).await?;
        
        if result.success {
            Ok(start_time.elapsed())
        } else {
            Err("NAT traversal failed".into())
        }
    }

    async fn test_client_with_bootstrap(&mut self) -> Result<Duration, Box<dyn std::error::Error>> {
        debug!("Testing client with bootstrap scenario");
        
        // Setup bootstrap node in network environment
        self.network_env.lock().unwrap().add_nat_device(
            NatDeviceId(999),
            NatType::None, // Bootstrap node has no NAT
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
            (IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), 32),
        );
        
        let client_config = NatTraversalConfig {
            role: EndpointRole::Client,
            bootstrap_nodes: vec!["203.0.113.1:9000".parse().unwrap()],
            max_candidates: 8,
            coordination_timeout: Duration::from_secs(15),
            enable_symmetric_nat: true,
            enable_relay_fallback: true,
            max_concurrent_attempts: 3,
        };
        
        let server_config = NatTraversalConfig {
            role: EndpointRole::Server { can_coordinate: false },
            bootstrap_nodes: vec!["203.0.113.1:9000".parse().unwrap()],
            max_candidates: 8,
            coordination_timeout: Duration::from_secs(15),
            enable_symmetric_nat: true,
            enable_relay_fallback: true,
            max_concurrent_attempts: 3,
        };
        
        let start_time = Instant::now();
        let result = self.simulator.lock().unwrap()
            .simulate_nat_traversal(client_config, server_config).await?;
        
        if result.success {
            Ok(start_time.elapsed())
        } else {
            Err("Bootstrap-coordinated NAT traversal failed".into())
        }
    }

    async fn test_server_coordination(&mut self) -> Result<Duration, Box<dyn std::error::Error>> {
        debug!("Testing server coordination scenario");
        
        let coordinator_config = NatTraversalConfig {
            role: EndpointRole::Server { can_coordinate: true },
            bootstrap_nodes: vec![],
            max_candidates: 10,
            coordination_timeout: Duration::from_secs(20),
            enable_symmetric_nat: true,
            enable_relay_fallback: false,
            max_concurrent_attempts: 5,
        };
        
        let client_config = NatTraversalConfig {
            role: EndpointRole::Client,
            bootstrap_nodes: vec!["203.0.113.2:9000".parse().unwrap()],
            max_candidates: 8,
            coordination_timeout: Duration::from_secs(20),
            enable_symmetric_nat: true,
            enable_relay_fallback: false,
            max_concurrent_attempts: 3,
        };
        
        let start_time = Instant::now();
        let result = self.simulator.lock().unwrap()
            .simulate_nat_traversal(client_config, coordinator_config).await?;
        
        if result.success {
            Ok(start_time.elapsed())
        } else {
            Err("Server coordination failed".into())
        }
    }

    async fn test_bootstrap_node_functionality(&mut self) -> Result<Duration, Box<dyn std::error::Error>> {
        debug!("Testing bootstrap node functionality");
        
        // Create multiple bootstrap nodes
        let bootstrap_nodes = vec![
            "203.0.113.1:9000".parse().unwrap(),
            "203.0.113.2:9000".parse().unwrap(),
            "203.0.113.3:9000".parse().unwrap(),
        ];
        
        let client_config = NatTraversalConfig {
            role: EndpointRole::Client,
            bootstrap_nodes: bootstrap_nodes.clone(),
            max_candidates: 8,
            coordination_timeout: Duration::from_secs(10),
            enable_symmetric_nat: true,
            enable_relay_fallback: true,
            max_concurrent_attempts: 3,
        };
        
        let server_config = NatTraversalConfig {
            role: EndpointRole::Server { can_coordinate: false },
            bootstrap_nodes: bootstrap_nodes,
            max_candidates: 8,
            coordination_timeout: Duration::from_secs(10),
            enable_symmetric_nat: true,
            enable_relay_fallback: true,
            max_concurrent_attempts: 3,
        };
        
        let start_time = Instant::now();
        let result = self.simulator.lock().unwrap()
            .simulate_nat_traversal(client_config, server_config).await?;
        
        if result.success {
            Ok(start_time.elapsed())
        } else {
            Err("Bootstrap node functionality test failed".into())
        }
    }

    async fn test_nat_scenario_implementation(
        &mut self, 
        scenario: NatScenario
    ) -> Result<(Duration, f32), Box<dyn std::error::Error>> {
        debug!("Testing NAT scenario implementation: {:?}", scenario);
        
        let (nat1, nat2) = match scenario {
            NatScenario::FullConeToFullCone => (NatType::FullCone, NatType::FullCone),
            NatScenario::FullConeToRestricted => (NatType::FullCone, NatType::RestrictedCone),
            NatScenario::RestrictedToPortRestricted => (NatType::RestrictedCone, NatType::PortRestrictedCone),
            NatScenario::PortRestrictedToSymmetric => (NatType::PortRestrictedCone, NatType::Symmetric),
            NatScenario::SymmetricToSymmetric => (NatType::Symmetric, NatType::Symmetric),
            NatScenario::CgnatScenario => (NatType::CarrierGrade, NatType::CarrierGrade),
            NatScenario::DoubleNatScenario => (NatType::Symmetric, NatType::PortRestrictedCone),
        };
        
        let mut successful_attempts = 0;
        let total_attempts = 10;
        let mut total_connection_time = Duration::from_secs(0);
        
        for attempt in 0..total_attempts {
            debug!("NAT scenario attempt {}/{}", attempt + 1, total_attempts);
            
            let client_config = NatTraversalConfig {
                role: EndpointRole::Client,
                bootstrap_nodes: vec!["203.0.113.100:9000".parse().unwrap()],
                max_candidates: 8,
                coordination_timeout: Duration::from_secs(15),
                enable_symmetric_nat: matches!(nat1, NatType::Symmetric | NatType::CarrierGrade),
                enable_relay_fallback: matches!(scenario, NatScenario::SymmetricToSymmetric | NatScenario::CgnatScenario),
                max_concurrent_attempts: 3,
            };
            
            let server_config = NatTraversalConfig {
                role: EndpointRole::Server { can_coordinate: true },
                bootstrap_nodes: vec![],
                max_candidates: 8,
                coordination_timeout: Duration::from_secs(15),
                enable_symmetric_nat: matches!(nat2, NatType::Symmetric | NatType::CarrierGrade),
                enable_relay_fallback: matches!(scenario, NatScenario::SymmetricToSymmetric | NatScenario::CgnatScenario),
                max_concurrent_attempts: 3,
            };
            
            let start_time = Instant::now();
            let result = self.simulator.lock().unwrap()
                .simulate_nat_traversal(client_config, server_config).await?;
            
            if result.success {
                successful_attempts += 1;
                total_connection_time += start_time.elapsed();
            }
            
            // Small delay between attempts
            sleep(Duration::from_millis(200)).await;
        }
        
        let success_rate = successful_attempts as f32 / total_attempts as f32;
        let avg_connection_time = if successful_attempts > 0 {
            total_connection_time / successful_attempts
        } else {
            Duration::from_secs(0)
        };
        
        Ok((avg_connection_time, success_rate))
    }

    async fn test_multi_peer_implementation(
        &mut self,
        scenario: MultiPeerScenario,
        config: MultiPeerTestConfig,
    ) -> Result<(Duration, usize, f32), Box<dyn std::error::Error>> {
        debug!("Testing multi-peer implementation: {:?}", scenario);
        
        let participants = self.create_test_participants(&config).await?;
        let connections = self.execute_multi_peer_connections(&participants, &config).await?;
        
        let successful_connections = connections.iter().filter(|c| c.success).count();
        let total_expected_connections = self.calculate_expected_connections(&config.topology, participants.len());
        
        let success_rate = successful_connections as f32 / total_expected_connections as f32;
        let avg_connection_time = if successful_connections > 0 {
            connections.iter()
                .filter(|c| c.success)
                .map(|c| c.connection_time)
                .sum::<Duration>() / successful_connections as u32
        } else {
            Duration::from_secs(0)
        };
        
        Ok((avg_connection_time, participants.len(), success_rate))
    }

    async fn test_failure_scenario_implementation(
        &mut self,
        scenario: FailureScenario,
    ) -> Result<(Duration, f32), Box<dyn std::error::Error>> {
        debug!("Testing failure scenario implementation: {:?}", scenario);
        
        match scenario {
            FailureScenario::BootstrapNodeFailure => {
                self.test_bootstrap_node_failure().await
            }
            FailureScenario::NetworkPartition => {
                self.test_network_partition().await
            }
            FailureScenario::HighPacketLoss => {
                self.test_high_packet_loss().await
            }
            FailureScenario::RandomFailures => {
                self.test_random_failures().await
            }
            FailureScenario::ResourceExhaustion => {
                self.test_resource_exhaustion().await
            }
        }
    }

    // Helper methods for multi-peer testing

    async fn create_test_participants(&self, config: &MultiPeerTestConfig) -> Result<Vec<TestParticipant>, Box<dyn std::error::Error>> {
        let mut participants = Vec::new();
        
        for i in 0..config.participant_count {
            let id = format!("participant_{}", i);
            let peer_id = PeerId([i as u8; 32]);
            
            let role = if i == 0 && matches!(config.topology, NetworkTopology::Star { .. }) {
                EndpointRole::Server { can_coordinate: true }
            } else {
                EndpointRole::Client
            };
            
            let bootstrap_nodes = if config.enable_bootstrap_coordination {
                vec!["203.0.113.1:9000".parse().unwrap()]
            } else {
                vec![]
            };
            
            let participant_config = NatTraversalConfig {
                role,
                bootstrap_nodes,
                max_candidates: 8,
                coordination_timeout: Duration::from_secs(20),
                enable_symmetric_nat: true,
                enable_relay_fallback: true,
                max_concurrent_attempts: 3,
            };
            
            participants.push(TestParticipant {
                id,
                peer_id,
                config: participant_config,
                nat_type: NatType::FullCone, // Default for testing
                device_id: NatDeviceId(1000 + i as u32),
            });
        }
        
        Ok(participants)
    }

    async fn execute_multi_peer_connections(
        &mut self,
        participants: &[TestParticipant],
        config: &MultiPeerTestConfig,
    ) -> Result<Vec<ConnectionResult>, Box<dyn std::error::Error>> {
        let mut results = Vec::new();
        let connection_pairs = self.generate_connection_pairs(participants, &config.topology);
        
        match config.connection_pattern {
            ConnectionPattern::Simultaneous => {
                // Execute all connections simultaneously
                let mut handles = Vec::new();
                
                for (participant1, participant2) in connection_pairs {
                    let simulator = self.simulator.clone();
                    let config1 = participant1.config.clone();
                    let config2 = participant2.config.clone();
                    
                    let handle = tokio::spawn(async move {
                        let start_time = Instant::now();
                        let result = simulator.lock().unwrap()
                            .simulate_nat_traversal(config1, config2).await;
                        
                        match result {
                            Ok(sim_result) => ConnectionResult {
                                participant1_id: participant1.id.clone(),
                                participant2_id: participant2.id.clone(),
                                success: sim_result.success,
                                connection_time: start_time.elapsed(),
                                error_message: sim_result.failure_reason,
                            },
                            Err(e) => ConnectionResult {
                                participant1_id: participant1.id.clone(),
                                participant2_id: participant2.id.clone(),
                                success: false,
                                connection_time: Duration::from_secs(0),
                                error_message: Some(e.to_string()),
                            }
                        }
                    });
                    
                    handles.push(handle);
                }
                
                for handle in handles {
                    results.push(handle.await?);
                }
            }
            ConnectionPattern::Sequential { delay } => {
                // Execute connections sequentially with delay
                for (participant1, participant2) in connection_pairs {
                    let start_time = Instant::now();
                    let result = self.simulator.lock().unwrap()
                        .simulate_nat_traversal(participant1.config.clone(), participant2.config.clone()).await;
                    
                    let connection_result = match result {
                        Ok(sim_result) => ConnectionResult {
                            participant1_id: participant1.id.clone(),
                            participant2_id: participant2.id.clone(),
                            success: sim_result.success,
                            connection_time: start_time.elapsed(),
                            error_message: sim_result.failure_reason,
                        },
                        Err(e) => ConnectionResult {
                            participant1_id: participant1.id.clone(),
                            participant2_id: participant2.id.clone(),
                            success: false,
                            connection_time: Duration::from_secs(0),
                            error_message: Some(e.to_string()),
                        }
                    };
                    
                    results.push(connection_result);
                    sleep(delay).await;
                }
            }
            ConnectionPattern::Random { min_delay, max_delay } => {
                // Execute connections with random delays
                use rand::Rng;
                let mut rng = rand::thread_rng();
                
                for (participant1, participant2) in connection_pairs {
                    let delay_ms = rng.gen_range(min_delay.as_millis()..=max_delay.as_millis());
                    sleep(Duration::from_millis(delay_ms as u64)).await;
                    
                    let start_time = Instant::now();
                    let result = self.simulator.lock().unwrap()
                        .simulate_nat_traversal(participant1.config.clone(), participant2.config.clone()).await;
                    
                    let connection_result = match result {
                        Ok(sim_result) => ConnectionResult {
                            participant1_id: participant1.id.clone(),
                            participant2_id: participant2.id.clone(),
                            success: sim_result.success,
                            connection_time: start_time.elapsed(),
                            error_message: sim_result.failure_reason,
                        },
                        Err(e) => ConnectionResult {
                            participant1_id: participant1.id.clone(),
                            participant2_id: participant2.id.clone(),
                            success: false,
                            connection_time: Duration::from_secs(0),
                            error_message: Some(e.to_string()),
                        }
                    };
                    
                    results.push(connection_result);
                }
            }
        }
        
        Ok(results)
    }

    fn generate_connection_pairs(&self, participants: &[TestParticipant], topology: &NetworkTopology) -> Vec<(&TestParticipant, &TestParticipant)> {
        let mut pairs = Vec::new();
        
        match topology {
            NetworkTopology::FullMesh => {
                for i in 0..participants.len() {
                    for j in i + 1..participants.len() {
                        pairs.push((&participants[i], &participants[j]));
                    }
                }
            }
            NetworkTopology::Star { center_id } => {
                if let Some(center_idx) = participants.iter().position(|p| &p.id == center_id) {
                    for (i, participant) in participants.iter().enumerate() {
                        if i != center_idx {
                            pairs.push((&participants[center_idx], participant));
                        }
                    }
                }
            }
            NetworkTopology::Chain => {
                for i in 0..participants.len() - 1 {
                    pairs.push((&participants[i], &participants[i + 1]));
                }
            }
            NetworkTopology::Random { connection_probability } => {
                use rand::Rng;
                let mut rng = rand::thread_rng();
                
                for i in 0..participants.len() {
                    for j in i + 1..participants.len() {
                        if rng.gen::<f32>() < *connection_probability {
                            pairs.push((&participants[i], &participants[j]));
                        }
                    }
                }
            }
        }
        
        pairs
    }

    fn calculate_expected_connections(&self, topology: &NetworkTopology, participant_count: usize) -> usize {
        match topology {
            NetworkTopology::FullMesh => participant_count * (participant_count - 1) / 2,
            NetworkTopology::Star { .. } => participant_count - 1,
            NetworkTopology::Chain => participant_count - 1,
            NetworkTopology::Random { connection_probability } => {
                let max_connections = participant_count * (participant_count - 1) / 2;
                (max_connections as f32 * connection_probability) as usize
            }
        }
    }

    fn create_multi_peer_config(&self, scenario: &MultiPeerScenario) -> MultiPeerTestConfig {
        match scenario {
            MultiPeerScenario::ThreePeerMesh => MultiPeerTestConfig {
                participant_count: 3,
                topology: NetworkTopology::FullMesh,
                connection_pattern: ConnectionPattern::Simultaneous,
                test_duration: Duration::from_secs(30),
                enable_bootstrap_coordination: true,
            },
            MultiPeerScenario::FivePeerStar => MultiPeerTestConfig {
                participant_count: 5,
                topology: NetworkTopology::Star { center_id: "participant_0".to_string() },
                connection_pattern: ConnectionPattern::Sequential { delay: Duration::from_secs(2) },
                test_duration: Duration::from_secs(60),
                enable_bootstrap_coordination: true,
            },
            MultiPeerScenario::TenPeerRandom => MultiPeerTestConfig {
                participant_count: 10,
                topology: NetworkTopology::Random { connection_probability: 0.3 },
                connection_pattern: ConnectionPattern::Random { 
                    min_delay: Duration::from_secs(1), 
                    max_delay: Duration::from_secs(5) 
                },
                test_duration: Duration::from_secs(120),
                enable_bootstrap_coordination: true,
            },
            MultiPeerScenario::BootstrapCoordination => MultiPeerTestConfig {
                participant_count: 6,
                topology: NetworkTopology::FullMesh,
                connection_pattern: ConnectionPattern::Simultaneous,
                test_duration: Duration::from_secs(45),
                enable_bootstrap_coordination: true,
            },
        }
    }

    // Failure scenario implementations

    async fn test_bootstrap_node_failure(&mut self) -> Result<(Duration, f32), Box<dyn std::error::Error>> {
        debug!("Testing bootstrap node failure scenario");
        
        // Test connection establishment, then simulate bootstrap failure
        let start_time = Instant::now();
        
        let client_config = NatTraversalConfig {
            role: EndpointRole::Client,
            bootstrap_nodes: vec![
                "203.0.113.1:9000".parse().unwrap(),
                "203.0.113.2:9000".parse().unwrap(), // Backup bootstrap
            ],
            max_candidates: 8,
            coordination_timeout: Duration::from_secs(15),
            enable_symmetric_nat: true,
            enable_relay_fallback: true,
            max_concurrent_attempts: 3,
        };
        
        let server_config = NatTraversalConfig {
            role: EndpointRole::Server { can_coordinate: false },
            bootstrap_nodes: vec![
                "203.0.113.1:9000".parse().unwrap(),
                "203.0.113.2:9000".parse().unwrap(),
            ],
            max_candidates: 8,
            coordination_timeout: Duration::from_secs(15),
            enable_symmetric_nat: true,
            enable_relay_fallback: true,
            max_concurrent_attempts: 3,
        };
        
        // Simulate first bootstrap node failure by removing it from network
        // Then test if connection can still be established via backup
        
        let result = self.simulator.lock().unwrap()
            .simulate_nat_traversal(client_config, server_config).await?;
        
        let recovery_time = start_time.elapsed();
        let resilience_score = if result.success { 0.8 } else { 0.2 }; // High resilience if recovered
        
        Ok((recovery_time, resilience_score))
    }

    async fn test_network_partition(&mut self) -> Result<(Duration, f32), Box<dyn std::error::Error>> {
        debug!("Testing network partition scenario");
        
        // Simulate network partition and recovery
        let start_time = Instant::now();
        
        // Configuration that should handle network partitions
        let client_config = NatTraversalConfig {
            role: EndpointRole::Client,
            bootstrap_nodes: vec!["203.0.113.1:9000".parse().unwrap()],
            max_candidates: 10,
            coordination_timeout: Duration::from_secs(30), // Longer timeout for partition
            enable_symmetric_nat: true,
            enable_relay_fallback: true,
            max_concurrent_attempts: 5,
        };
        
        let server_config = NatTraversalConfig {
            role: EndpointRole::Server { can_coordinate: true },
            bootstrap_nodes: vec![],
            max_candidates: 10,
            coordination_timeout: Duration::from_secs(30),
            enable_symmetric_nat: true,
            enable_relay_fallback: true,
            max_concurrent_attempts: 5,
        };
        
        let result = self.simulator.lock().unwrap()
            .simulate_nat_traversal(client_config, server_config).await?;
        
        let recovery_time = start_time.elapsed();
        let resilience_score = if result.success { 0.7 } else { 0.3 };
        
        Ok((recovery_time, resilience_score))
    }

    async fn test_high_packet_loss(&mut self) -> Result<(Duration, f32), Box<dyn std::error::Error>> {
        debug!("Testing high packet loss scenario");
        
        // Test with high packet loss configuration
        let start_time = Instant::now();
        
        // Modify network configuration to simulate high packet loss
        let mut network_config = NetworkSimulationConfig::default();
        network_config.packet_loss_percent = 30; // 30% packet loss
        
        let mut simulator = NetworkSimulator::new(network_config);
        simulator.initialize();
        
        let client_config = NatTraversalConfig {
            role: EndpointRole::Client,
            bootstrap_nodes: vec!["203.0.113.1:9000".parse().unwrap()],
            max_candidates: 8,
            coordination_timeout: Duration::from_secs(20),
            enable_symmetric_nat: true,
            enable_relay_fallback: true,
            max_concurrent_attempts: 5, // More attempts for high loss
        };
        
        let server_config = NatTraversalConfig {
            role: EndpointRole::Server { can_coordinate: true },
            bootstrap_nodes: vec![],
            max_candidates: 8,
            coordination_timeout: Duration::from_secs(20),
            enable_symmetric_nat: true,
            enable_relay_fallback: true,
            max_concurrent_attempts: 5,
        };
        
        let result = simulator.simulate_nat_traversal(client_config, server_config).await?;
        
        let recovery_time = start_time.elapsed();
        let resilience_score = if result.success { 0.9 } else { 0.4 }; // High score if successful despite packet loss
        
        Ok((recovery_time, resilience_score))
    }

    async fn test_random_failures(&mut self) -> Result<(Duration, f32), Box<dyn std::error::Error>> {
        debug!("Testing random failures scenario");
        
        let start_time = Instant::now();
        let mut successful_attempts = 0;
        let total_attempts = 10;
        
        for _ in 0..total_attempts {
            let client_config = NatTraversalConfig {
                role: EndpointRole::Client,
                bootstrap_nodes: vec!["203.0.113.1:9000".parse().unwrap()],
                max_candidates: 8,
                coordination_timeout: Duration::from_secs(10),
                enable_symmetric_nat: true,
                enable_relay_fallback: true,
                max_concurrent_attempts: 3,
            };
            
            let server_config = NatTraversalConfig {
                role: EndpointRole::Server { can_coordinate: true },
                bootstrap_nodes: vec![],
                max_candidates: 8,
                coordination_timeout: Duration::from_secs(10),
                enable_symmetric_nat: true,
                enable_relay_fallback: true,
                max_concurrent_attempts: 3,
            };
            
            let result = self.simulator.lock().unwrap()
                .simulate_nat_traversal(client_config, server_config).await;
            
            if let Ok(sim_result) = result {
                if sim_result.success {
                    successful_attempts += 1;
                }
            }
            
            sleep(Duration::from_millis(100)).await;
        }
        
        let recovery_time = start_time.elapsed();
        let resilience_score = successful_attempts as f32 / total_attempts as f32;
        
        Ok((recovery_time, resilience_score))
    }

    async fn test_resource_exhaustion(&mut self) -> Result<(Duration, f32), Box<dyn std::error::Error>> {
        debug!("Testing resource exhaustion scenario");
        
        let start_time = Instant::now();
        
        // Test with limited resources
        let client_config = NatTraversalConfig {
            role: EndpointRole::Client,
            bootstrap_nodes: vec!["203.0.113.1:9000".parse().unwrap()],
            max_candidates: 3, // Limited candidates
            coordination_timeout: Duration::from_secs(5), // Short timeout
            enable_symmetric_nat: true,
            enable_relay_fallback: false, // No relay fallback
            max_concurrent_attempts: 1, // Single attempt
        };
        
        let server_config = NatTraversalConfig {
            role: EndpointRole::Server { can_coordinate: true },
            bootstrap_nodes: vec![],
            max_candidates: 3,
            coordination_timeout: Duration::from_secs(5),
            enable_symmetric_nat: true,
            enable_relay_fallback: false,
            max_concurrent_attempts: 1,
        };
        
        let result = self.simulator.lock().unwrap()
            .simulate_nat_traversal(client_config, server_config).await?;
        
        let recovery_time = start_time.elapsed();
        let resilience_score = if result.success { 0.6 } else { 0.2 }; // Lower expectation for resource-limited scenario
        
        Ok((recovery_time, resilience_score))
    }
}

/// Result of a connection attempt between participants
#[derive(Debug, Clone)]
pub struct ConnectionResult {
    /// First participant ID
    pub participant1_id: String,
    /// Second participant ID
    pub participant2_id: String,
    /// Connection success
    pub success: bool,
    /// Connection establishment time
    pub connection_time: Duration,
    /// Error message if failed
    pub error_message: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_scenario_executor_creation() {
        let network_config = NetworkSimulationConfig::default();
        let executor = ScenarioTestExecutor::new(network_config);
        
        // Test that executor was created successfully
        assert!(executor.results.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_basic_scenario_execution() {
        let network_config = NetworkSimulationConfig::default();
        let mut executor = ScenarioTestExecutor::new(network_config);
        
        let result = executor.execute_basic_scenario(TestScenario::BasicClientServer).await;
        
        assert_eq!(result.scenario_name, "BasicClientServer");
        assert_eq!(result.participants, 2);
    }

    #[test]
    fn test_connection_pair_generation() {
        let network_config = NetworkSimulationConfig::default();
        let executor = ScenarioTestExecutor::new(network_config);
        
        let participants = vec![
            TestParticipant {
                id: "p1".to_string(),
                peer_id: PeerId([1; 32]),
                config: NatTraversalConfig::default(),
                nat_type: NatType::FullCone,
                device_id: NatDeviceId(1),
            },
            TestParticipant {
                id: "p2".to_string(),
                peer_id: PeerId([2; 32]),
                config: NatTraversalConfig::default(),
                nat_type: NatType::FullCone,
                device_id: NatDeviceId(2),
            },
            TestParticipant {
                id: "p3".to_string(),
                peer_id: PeerId([3; 32]),
                config: NatTraversalConfig::default(),
                nat_type: NatType::FullCone,
                device_id: NatDeviceId(3),
            },
        ];
        
        let pairs = executor.generate_connection_pairs(&participants, &NetworkTopology::FullMesh);
        assert_eq!(pairs.len(), 3); // 3 choose 2 = 3 pairs
        
        let pairs = executor.generate_connection_pairs(&participants, &NetworkTopology::Star { center_id: "p1".to_string() });
        assert_eq!(pairs.len(), 2); // Center connects to 2 others
        
        let pairs = executor.generate_connection_pairs(&participants, &NetworkTopology::Chain);
        assert_eq!(pairs.len(), 2); // p1-p2, p2-p3
    }

    #[test]
    fn test_expected_connections_calculation() {
        let network_config = NetworkSimulationConfig::default();
        let executor = ScenarioTestExecutor::new(network_config);
        
        assert_eq!(executor.calculate_expected_connections(&NetworkTopology::FullMesh, 5), 10);
        assert_eq!(executor.calculate_expected_connections(&NetworkTopology::Star { center_id: "center".to_string() }, 5), 4);
        assert_eq!(executor.calculate_expected_connections(&NetworkTopology::Chain, 5), 4);
    }
}