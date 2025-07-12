//! Network Condition Simulation
//!
//! This module simulates various network conditions for testing NAT traversal
//! under realistic and challenging network scenarios.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use tokio::sync::{RwLock, Mutex};
use tracing::{debug, info, warn};

use crate::validation::{ValidationError, NetworkCondition};

/// Network condition simulator
pub struct NetworkConditionSimulator {
    /// Active conditions
    conditions: Arc<RwLock<HashMap<String, ActiveCondition>>>,
    /// Simulation state
    state: Arc<Mutex<SimulatorState>>,
    /// Condition profiles
    profiles: ConditionProfiles,
}

impl NetworkConditionSimulator {
    /// Create new network condition simulator
    pub fn new() -> Self {
        Self {
            conditions: Arc::new(RwLock::new(HashMap::new())),
            state: Arc::new(Mutex::new(SimulatorState::default())),
            profiles: ConditionProfiles::new(),
        }
    }
    
    /// Apply network condition
    pub async fn apply_condition(&self, condition: NetworkCondition) -> Result<String, ValidationError> {
        let condition_id = format!("condition_{}", condition.id);
        
        info!("Applying network condition: {} ({})", condition.id, condition_id);
        
        let active_condition = ActiveCondition {
            id: condition_id.clone(),
            condition: condition.clone(),
            applied_at: Instant::now(),
            packets_affected: 0,
            bytes_affected: 0,
        };
        
        // Store active condition
        let mut conditions = self.conditions.write().await;
        conditions.insert(condition_id.clone(), active_condition);
        
        // Update simulator state
        let mut state = self.state.lock().await;
        state.active_conditions += 1;
        
        Ok(condition_id)
    }
    
    /// Remove network condition
    pub async fn remove_condition(&self, condition_id: &str) -> Result<(), ValidationError> {
        info!("Removing network condition: {}", condition_id);
        
        let mut conditions = self.conditions.write().await;
        if conditions.remove(condition_id).is_some() {
            let mut state = self.state.lock().await;
            state.active_conditions -= 1;
            Ok(())
        } else {
            Err(ValidationError::EnvironmentError(
                format!("Condition {} not found", condition_id)
            ))
        }
    }
    
    /// Simulate packet processing through conditions
    pub async fn process_packet(&self, packet: &mut NetworkPacket) -> PacketDecision {
        let conditions = self.conditions.read().await;
        
        for condition in conditions.values() {
            match self.apply_condition_to_packet(&condition.condition, packet).await {
                PacketDecision::Drop => return PacketDecision::Drop,
                PacketDecision::Delay(delay) => {
                    packet.additional_delay += delay;
                }
                PacketDecision::Forward => continue,
            }
        }
        
        PacketDecision::Forward
    }
    
    /// Apply specific condition to packet
    async fn apply_condition_to_packet(
        &self,
        condition: &NetworkCondition,
        packet: &NetworkPacket,
    ) -> PacketDecision {
        // Parse condition parameters
        if let Some(&packet_loss) = condition.parameters.get("packet_loss") {
            if rand::random::<f64>() < packet_loss {
                debug!("Dropping packet due to packet loss condition");
                return PacketDecision::Drop;
            }
        }
        
        if let Some(&latency) = condition.parameters.get("latency_ms") {
            let delay = Duration::from_millis(latency as u64);
            debug!("Adding {}ms latency to packet", latency);
            return PacketDecision::Delay(delay);
        }
        
        if let Some(&jitter) = condition.parameters.get("jitter_ms") {
            let jitter_delay = Duration::from_millis(
                (rand::random::<f64>() * jitter) as u64
            );
            debug!("Adding {}ms jitter to packet", jitter_delay.as_millis());
            return PacketDecision::Delay(jitter_delay);
        }
        
        if let Some(&bandwidth_limit) = condition.parameters.get("bandwidth_kbps") {
            // Simplified bandwidth limiting
            let packet_time = (packet.size as f64 * 8.0) / (bandwidth_limit * 1000.0);
            let delay = Duration::from_secs_f64(packet_time);
            debug!("Adding bandwidth delay of {}ms", delay.as_millis());
            return PacketDecision::Delay(delay);
        }
        
        PacketDecision::Forward
    }
    
    /// Get predefined network profiles
    pub fn get_network_profiles(&self) -> &ConditionProfiles {
        &self.profiles
    }
    
    /// Apply network profile
    pub async fn apply_profile(&self, profile_name: &str) -> Result<Vec<String>, ValidationError> {
        let profile = self.profiles.get_profile(profile_name)
            .ok_or_else(|| ValidationError::EnvironmentError(
                format!("Network profile '{}' not found", profile_name)
            ))?;
        
        info!("Applying network profile: {}", profile_name);
        
        let mut condition_ids = Vec::new();
        for condition in &profile.conditions {
            let id = self.apply_condition(condition.clone()).await?;
            condition_ids.push(id);
        }
        
        Ok(condition_ids)
    }
    
    /// Clear all conditions
    pub async fn clear_all_conditions(&self) -> Result<(), ValidationError> {
        info!("Clearing all network conditions");
        
        let mut conditions = self.conditions.write().await;
        conditions.clear();
        
        let mut state = self.state.lock().await;
        state.active_conditions = 0;
        
        Ok(())
    }
    
    /// Get current statistics
    pub async fn get_statistics(&self) -> NetworkSimulatorStats {
        let conditions = self.conditions.read().await;
        let state = self.state.lock().await;
        
        let mut total_packets_affected = 0;
        let mut total_bytes_affected = 0;
        
        for condition in conditions.values() {
            total_packets_affected += condition.packets_affected;
            total_bytes_affected += condition.bytes_affected;
        }
        
        NetworkSimulatorStats {
            active_conditions: state.active_conditions,
            total_packets_affected,
            total_bytes_affected,
            uptime: state.start_time.elapsed(),
            conditions_applied: state.conditions_applied,
        }
    }
}

/// Active network condition
#[derive(Debug, Clone)]
struct ActiveCondition {
    /// Condition ID
    id: String,
    /// Condition configuration
    condition: NetworkCondition,
    /// When condition was applied
    applied_at: Instant,
    /// Number of packets affected
    packets_affected: u64,
    /// Number of bytes affected
    bytes_affected: u64,
}

/// Simulator state
#[derive(Debug, Default)]
struct SimulatorState {
    /// Number of active conditions
    active_conditions: usize,
    /// Total conditions applied
    conditions_applied: u64,
    /// Simulator start time
    start_time: Instant,
}

impl Default for Instant {
    fn default() -> Self {
        Instant::now()
    }
}

/// Network packet for simulation
#[derive(Debug, Clone)]
pub struct NetworkPacket {
    /// Source address
    pub source: SocketAddr,
    /// Destination address
    pub destination: SocketAddr,
    /// Packet size in bytes
    pub size: usize,
    /// Protocol type
    pub protocol: String,
    /// Additional delay accumulated
    pub additional_delay: Duration,
    /// Original timestamp
    pub timestamp: Instant,
}

/// Packet processing decision
#[derive(Debug, Clone)]
pub enum PacketDecision {
    /// Forward packet normally
    Forward,
    /// Drop packet
    Drop,
    /// Delay packet by duration
    Delay(Duration),
}

/// Network condition profiles
pub struct ConditionProfiles {
    /// Predefined profiles
    profiles: HashMap<String, NetworkProfile>,
}

impl ConditionProfiles {
    /// Create new condition profiles
    pub fn new() -> Self {
        let mut profiles = HashMap::new();
        
        // Mobile network profile
        profiles.insert("mobile_3g".to_string(), NetworkProfile {
            name: "Mobile 3G".to_string(),
            description: "Simulates 3G mobile network conditions".to_string(),
            conditions: vec![
                NetworkCondition {
                    id: "3g_latency".to_string(),
                    parameters: HashMap::from([
                        ("latency_ms".to_string(), 200.0),
                        ("jitter_ms".to_string(), 50.0),
                    ]),
                },
                NetworkCondition {
                    id: "3g_bandwidth".to_string(),
                    parameters: HashMap::from([
                        ("bandwidth_kbps".to_string(), 1000.0),
                    ]),
                },
                NetworkCondition {
                    id: "3g_packet_loss".to_string(),
                    parameters: HashMap::from([
                        ("packet_loss".to_string(), 0.02),
                    ]),
                },
            ],
        });
        
        // Poor WiFi profile
        profiles.insert("poor_wifi".to_string(), NetworkProfile {
            name: "Poor WiFi".to_string(),
            description: "Simulates poor WiFi conditions".to_string(),
            conditions: vec![
                NetworkCondition {
                    id: "wifi_latency".to_string(),
                    parameters: HashMap::from([
                        ("latency_ms".to_string(), 100.0),
                        ("jitter_ms".to_string(), 30.0),
                    ]),
                },
                NetworkCondition {
                    id: "wifi_packet_loss".to_string(),
                    parameters: HashMap::from([
                        ("packet_loss".to_string(), 0.05),
                    ]),
                },
            ],
        });
        
        // Congested network profile
        profiles.insert("congested".to_string(), NetworkProfile {
            name: "Congested Network".to_string(),
            description: "Simulates network congestion".to_string(),
            conditions: vec![
                NetworkCondition {
                    id: "congestion_latency".to_string(),
                    parameters: HashMap::from([
                        ("latency_ms".to_string(), 300.0),
                        ("jitter_ms".to_string(), 100.0),
                    ]),
                },
                NetworkCondition {
                    id: "congestion_bandwidth".to_string(),
                    parameters: HashMap::from([
                        ("bandwidth_kbps".to_string(), 500.0),
                    ]),
                },
                NetworkCondition {
                    id: "congestion_packet_loss".to_string(),
                    parameters: HashMap::from([
                        ("packet_loss".to_string(), 0.08),
                    ]),
                },
            ],
        });
        
        // Satellite network profile
        profiles.insert("satellite".to_string(), NetworkProfile {
            name: "Satellite".to_string(),
            description: "Simulates satellite network conditions".to_string(),
            conditions: vec![
                NetworkCondition {
                    id: "satellite_latency".to_string(),
                    parameters: HashMap::from([
                        ("latency_ms".to_string(), 600.0),
                        ("jitter_ms".to_string(), 20.0),
                    ]),
                },
                NetworkCondition {
                    id: "satellite_packet_loss".to_string(),
                    parameters: HashMap::from([
                        ("packet_loss".to_string(), 0.01),
                    ]),
                },
            ],
        });
        
        // Asymmetric connection profile
        profiles.insert("asymmetric".to_string(), NetworkProfile {
            name: "Asymmetric Connection".to_string(),
            description: "Simulates asymmetric upload/download speeds".to_string(),
            conditions: vec![
                NetworkCondition {
                    id: "asymmetric_upload".to_string(),
                    parameters: HashMap::from([
                        ("bandwidth_kbps".to_string(), 256.0),
                        ("direction".to_string(), 1.0), // 1 = upload
                    ]),
                },
                NetworkCondition {
                    id: "asymmetric_download".to_string(),
                    parameters: HashMap::from([
                        ("bandwidth_kbps".to_string(), 2048.0),
                        ("direction".to_string(), 0.0), // 0 = download
                    ]),
                },
            ],
        });
        
        Self { profiles }
    }
    
    /// Get profile by name
    pub fn get_profile(&self, name: &str) -> Option<&NetworkProfile> {
        self.profiles.get(name)
    }
    
    /// List all available profiles
    pub fn list_profiles(&self) -> Vec<&str> {
        self.profiles.keys().map(|k| k.as_str()).collect()
    }
    
    /// Get profile descriptions
    pub fn get_profile_descriptions(&self) -> HashMap<String, String> {
        self.profiles.iter()
            .map(|(name, profile)| (name.clone(), profile.description.clone()))
            .collect()
    }
}

/// Network profile definition
#[derive(Debug, Clone)]
pub struct NetworkProfile {
    /// Profile name
    pub name: String,
    /// Profile description
    pub description: String,
    /// List of conditions to apply
    pub conditions: Vec<NetworkCondition>,
}

/// Network simulator statistics
#[derive(Debug)]
pub struct NetworkSimulatorStats {
    /// Number of active conditions
    pub active_conditions: usize,
    /// Total packets affected
    pub total_packets_affected: u64,
    /// Total bytes affected
    pub total_bytes_affected: u64,
    /// Simulator uptime
    pub uptime: Duration,
    /// Total conditions applied
    pub conditions_applied: u64,
}

/// Advanced network condition types
pub struct AdvancedConditions;

impl AdvancedConditions {
    /// Create packet burst condition
    pub fn packet_burst(burst_size: u32, burst_interval: Duration) -> NetworkCondition {
        NetworkCondition {
            id: "packet_burst".to_string(),
            parameters: HashMap::from([
                ("burst_size".to_string(), burst_size as f64),
                ("burst_interval_ms".to_string(), burst_interval.as_millis() as f64),
            ]),
        }
    }
    
    /// Create intermittent connectivity condition
    pub fn intermittent_connectivity(
        disconnect_duration: Duration,
        connect_duration: Duration,
    ) -> NetworkCondition {
        NetworkCondition {
            id: "intermittent".to_string(),
            parameters: HashMap::from([
                ("disconnect_ms".to_string(), disconnect_duration.as_millis() as f64),
                ("connect_ms".to_string(), connect_duration.as_millis() as f64),
            ]),
        }
    }
    
    /// Create path MTU discovery issues
    pub fn mtu_issues(mtu_limit: u16) -> NetworkCondition {
        NetworkCondition {
            id: "mtu_limit".to_string(),
            parameters: HashMap::from([
                ("mtu_bytes".to_string(), mtu_limit as f64),
            ]),
        }
    }
    
    /// Create reordering condition
    pub fn packet_reordering(reorder_probability: f64, max_reorder_distance: u32) -> NetworkCondition {
        NetworkCondition {
            id: "packet_reorder".to_string(),
            parameters: HashMap::from([
                ("reorder_probability".to_string(), reorder_probability),
                ("max_distance".to_string(), max_reorder_distance as f64),
            ]),
        }
    }
    
    /// Create duplication condition
    pub fn packet_duplication(duplication_probability: f64) -> NetworkCondition {
        NetworkCondition {
            id: "packet_duplicate".to_string(),
            parameters: HashMap::from([
                ("duplicate_probability".to_string(), duplication_probability),
            ]),
        }
    }
    
    /// Create corruption condition
    pub fn packet_corruption(corruption_probability: f64) -> NetworkCondition {
        NetworkCondition {
            id: "packet_corrupt".to_string(),
            parameters: HashMap::from([
                ("corrupt_probability".to_string(), corruption_probability),
            ]),
        }
    }
}

/// Real-world scenario builder
pub struct ScenarioBuilder {
    conditions: Vec<NetworkCondition>,
}

impl ScenarioBuilder {
    /// Create new scenario builder
    pub fn new() -> Self {
        Self {
            conditions: Vec::new(),
        }
    }
    
    /// Add condition to scenario
    pub fn add_condition(mut self, condition: NetworkCondition) -> Self {
        self.conditions.push(condition);
        self
    }
    
    /// Add latency condition
    pub fn with_latency(self, latency_ms: u32, jitter_ms: u32) -> Self {
        self.add_condition(NetworkCondition {
            id: "scenario_latency".to_string(),
            parameters: HashMap::from([
                ("latency_ms".to_string(), latency_ms as f64),
                ("jitter_ms".to_string(), jitter_ms as f64),
            ]),
        })
    }
    
    /// Add packet loss condition
    pub fn with_packet_loss(self, loss_rate: f64) -> Self {
        self.add_condition(NetworkCondition {
            id: "scenario_packet_loss".to_string(),
            parameters: HashMap::from([
                ("packet_loss".to_string(), loss_rate),
            ]),
        })
    }
    
    /// Add bandwidth limit condition
    pub fn with_bandwidth_limit(self, bandwidth_kbps: u32) -> Self {
        self.add_condition(NetworkCondition {
            id: "scenario_bandwidth".to_string(),
            parameters: HashMap::from([
                ("bandwidth_kbps".to_string(), bandwidth_kbps as f64),
            ]),
        })
    }
    
    /// Build the scenario
    pub fn build(self, name: String, description: String) -> NetworkProfile {
        NetworkProfile {
            name,
            description,
            conditions: self.conditions,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn test_network_condition_application() {
        let simulator = NetworkConditionSimulator::new();
        
        let condition = NetworkCondition {
            id: "test_latency".to_string(),
            parameters: HashMap::from([
                ("latency_ms".to_string(), 100.0),
            ]),
        };
        
        let condition_id = simulator.apply_condition(condition).await.unwrap();
        
        let stats = simulator.get_statistics().await;
        assert_eq!(stats.active_conditions, 1);
        
        simulator.remove_condition(&condition_id).await.unwrap();
        
        let stats = simulator.get_statistics().await;
        assert_eq!(stats.active_conditions, 0);
    }
    
    #[tokio::test]
    async fn test_packet_processing() {
        let simulator = NetworkConditionSimulator::new();
        
        // Apply packet loss condition
        let condition = NetworkCondition {
            id: "test_packet_loss".to_string(),
            parameters: HashMap::from([
                ("packet_loss".to_string(), 1.0), // 100% packet loss for testing
            ]),
        };
        
        simulator.apply_condition(condition).await.unwrap();
        
        let mut packet = NetworkPacket {
            source: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080),
            destination: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)), 8081),
            size: 1024,
            protocol: "UDP".to_string(),
            additional_delay: Duration::ZERO,
            timestamp: Instant::now(),
        };
        
        let decision = simulator.process_packet(&mut packet).await;
        assert!(matches!(decision, PacketDecision::Drop));
    }
    
    #[test]
    fn test_condition_profiles() {
        let profiles = ConditionProfiles::new();
        
        assert!(profiles.get_profile("mobile_3g").is_some());
        assert!(profiles.get_profile("poor_wifi").is_some());
        assert!(profiles.get_profile("congested").is_some());
        assert!(profiles.get_profile("satellite").is_some());
        
        let profile_list = profiles.list_profiles();
        assert!(profile_list.contains(&"mobile_3g"));
        assert!(profile_list.contains(&"poor_wifi"));
    }
    
    #[test]
    fn test_scenario_builder() {
        let scenario = ScenarioBuilder::new()
            .with_latency(50, 10)
            .with_packet_loss(0.01)
            .with_bandwidth_limit(1000)
            .build(
                "Test Scenario".to_string(),
                "Test scenario description".to_string(),
            );
        
        assert_eq!(scenario.name, "Test Scenario");
        assert_eq!(scenario.conditions.len(), 3);
    }
}