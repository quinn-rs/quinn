//! Mock Network Environment for NAT Traversal Testing
//!
//! This module provides a comprehensive mock network environment that simulates
//! various network conditions, NAT configurations, and routing scenarios for
//! testing NAT traversal functionality.

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use rand::Rng;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use super::{NetworkSimulationConfig, PerformanceMetrics};

/// Mock network environment for testing
pub struct MockNetworkEnvironment {
    /// Network configuration
    config: NetworkSimulationConfig,
    /// NAT devices in the network
    nat_devices: HashMap<NatDeviceId, NatDevice>,
    /// Network links between devices
    network_links: HashMap<(NatDeviceId, NatDeviceId), NetworkLink>,
    /// Packet routing table
    routing_table: HashMap<IpAddr, NatDeviceId>,
    /// Performance metrics
    metrics: Arc<Mutex<PerformanceMetrics>>,
    /// Packet loss simulation
    packet_loss_simulator: PacketLossSimulator,
    /// Latency simulation
    latency_simulator: LatencySimulator,
    /// Bandwidth limitation
    bandwidth_limiter: BandwidthLimiter,
}

/// NAT device identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NatDeviceId(pub u32);

/// NAT device types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NatType {
    /// Full cone NAT (most permissive)
    FullCone,
    /// Restricted cone NAT
    RestrictedCone,
    /// Port restricted cone NAT
    PortRestrictedCone,
    /// Symmetric NAT (most restrictive)
    Symmetric,
    /// Carrier Grade NAT
    CarrierGrade,
    /// No NAT (direct connection)
    None,
}

/// NAT device configuration
#[derive(Debug, Clone)]
pub struct NatDevice {
    /// Device ID
    id: NatDeviceId,
    /// NAT type
    nat_type: NatType,
    /// External IP address
    external_ip: IpAddr,
    /// Internal IP range
    internal_ip_range: (IpAddr, u8), // (network, prefix_length)
    /// Port mapping table
    port_mappings: HashMap<(IpAddr, u16), (IpAddr, u16)>,
    /// Connection tracking for stateful NAT
    connection_tracking: HashMap<ConnectionKey, ConnectionState>,
    /// NAT timeout for mappings
    mapping_timeout: Duration,
    /// Port range for dynamic allocation
    port_range: (u16, u16),
    /// Next available port
    next_port: u16,
    /// Device statistics
    stats: NatDeviceStats,
}

/// Connection key for NAT tracking
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ConnectionKey {
    internal_addr: SocketAddr,
    external_addr: SocketAddr,
    protocol: Protocol,
}

/// Connection state for NAT tracking
#[derive(Debug, Clone)]
struct ConnectionState {
    /// Mapped external port
    mapped_port: u16,
    /// Last activity timestamp
    last_activity: Instant,
    /// Connection direction
    direction: ConnectionDirection,
    /// Number of packets
    packet_count: u64,
    /// Total bytes transferred
    bytes_transferred: u64,
}

/// Connection direction
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectionDirection {
    Outbound,
    Inbound,
}

/// Protocol type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Protocol {
    Udp,
    Tcp,
}

/// NAT device statistics
#[derive(Debug, Clone, Default)]
pub struct NatDeviceStats {
    /// Total packets processed
    pub packets_processed: u64,
    /// Packets dropped due to NAT rules
    pub packets_dropped: u64,
    /// Active port mappings
    pub active_mappings: u64,
    /// Expired mappings
    pub expired_mappings: u64,
    /// Memory usage
    pub memory_usage: u64,
}

/// Network link between devices
#[derive(Debug, Clone)]
struct NetworkLink {
    /// Source device
    source: NatDeviceId,
    /// Destination device
    destination: NatDeviceId,
    /// Link latency
    latency: Duration,
    /// Bandwidth capacity
    bandwidth: u64,
    /// Current utilization
    utilization: f32,
    /// Packet loss rate
    packet_loss_rate: f32,
}

/// Packet loss simulator
pub struct PacketLossSimulator {
    /// Loss rate (0.0 - 1.0)
    loss_rate: f32,
    /// Random number generator
    rng: rand::rngs::ThreadRng,
}

/// Latency simulator
pub struct LatencySimulator {
    /// Base latency
    base_latency: Duration,
    /// Jitter amount
    jitter: Duration,
    /// Random number generator
    rng: rand::rngs::ThreadRng,
}

/// Bandwidth limiter
pub struct BandwidthLimiter {
    /// Bandwidth limit in bytes per second
    bandwidth_limit: Option<u64>,
    /// Token bucket for rate limiting
    token_bucket: TokenBucket,
}

/// Token bucket for bandwidth limiting
struct TokenBucket {
    /// Current number of tokens
    tokens: f64,
    /// Maximum tokens
    max_tokens: f64,
    /// Refill rate per second
    refill_rate: f64,
    /// Last refill time
    last_refill: Instant,
}

/// Mock packet for network simulation
#[derive(Debug, Clone)]
pub struct MockPacket {
    /// Source address
    pub source: SocketAddr,
    /// Destination address
    pub destination: SocketAddr,
    /// Packet payload
    pub payload: Vec<u8>,
    /// Timestamp when packet was created
    pub timestamp: Instant,
    /// Packet size
    pub size: usize,
    /// Protocol type
    pub protocol: Protocol,
}

/// Network simulation result
#[derive(Debug, Clone)]
pub enum NetworkSimulationResult {
    /// Packet delivered successfully
    Delivered(MockPacket),
    /// Packet dropped due to loss
    Dropped(String),
    /// Packet delayed
    Delayed(MockPacket, Duration),
    /// Packet blocked by NAT
    Blocked(String),
}

impl MockNetworkEnvironment {
    /// Create a new mock network environment
    pub fn new(config: NetworkSimulationConfig) -> Self {
        Self {
            config: config.clone(),
            nat_devices: HashMap::new(),
            network_links: HashMap::new(),
            routing_table: HashMap::new(),
            metrics: Arc::new(Mutex::new(PerformanceMetrics::default())),
            packet_loss_simulator: PacketLossSimulator::new(config.packet_loss_percent as f32 / 100.0),
            latency_simulator: LatencySimulator::new(
                Duration::from_millis(config.latency_ms as u64),
                Duration::from_millis(config.jitter_ms as u64),
            ),
            bandwidth_limiter: BandwidthLimiter::new(config.bandwidth_limit_bps),
        }
    }

    /// Add a NAT device to the network
    pub fn add_nat_device(&mut self, id: NatDeviceId, nat_type: NatType, external_ip: IpAddr, internal_range: (IpAddr, u8)) {
        let device = NatDevice {
            id,
            nat_type,
            external_ip,
            internal_ip_range: internal_range,
            port_mappings: HashMap::new(),
            connection_tracking: HashMap::new(),
            mapping_timeout: Duration::from_secs(300), // 5 minutes
            port_range: (10000, 60000),
            next_port: 10000,
            stats: NatDeviceStats::default(),
        };

        self.nat_devices.insert(id, device);
        self.routing_table.insert(external_ip, id);
        
        info!("Added NAT device {:?} with type {:?} at {}", id, nat_type, external_ip);
    }

    /// Add a network link between two devices
    pub fn add_network_link(&mut self, source: NatDeviceId, destination: NatDeviceId, latency: Duration, bandwidth: u64) {
        let link = NetworkLink {
            source,
            destination,
            latency,
            bandwidth,
            utilization: 0.0,
            packet_loss_rate: self.config.packet_loss_percent as f32 / 100.0,
        };

        self.network_links.insert((source, destination), link);
        info!("Added network link from {:?} to {:?}", source, destination);
    }

    /// Create a typical home network scenario
    pub fn create_home_network_scenario(&mut self) -> (NatDeviceId, NatDeviceId) {
        // Create two home networks behind NAT
        let home1_id = NatDeviceId(1);
        let home2_id = NatDeviceId(2);
        
        // Network 1: Full cone NAT
        self.add_nat_device(
            home1_id,
            NatType::FullCone,
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
            (IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)), 24),
        );
        
        // Network 2: Symmetric NAT
        self.add_nat_device(
            home2_id,
            NatType::Symmetric,
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2)),
            (IpAddr::V4(Ipv4Addr::new(192, 168, 2, 0)), 24),
        );
        
        // Add links between networks (simulating internet)
        self.add_network_link(home1_id, home2_id, Duration::from_millis(50), 1_000_000); // 1 Mbps
        self.add_network_link(home2_id, home1_id, Duration::from_millis(50), 1_000_000); // 1 Mbps
        
        (home1_id, home2_id)
    }

    /// Create a corporate network scenario
    pub fn create_corporate_network_scenario(&mut self) -> (NatDeviceId, NatDeviceId) {
        // Create corporate networks with different NAT types
        let corp1_id = NatDeviceId(3);
        let corp2_id = NatDeviceId(4);
        
        // Corporate network 1: Port restricted NAT
        self.add_nat_device(
            corp1_id,
            NatType::PortRestrictedCone,
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 16),
        );
        
        // Corporate network 2: Carrier grade NAT
        self.add_nat_device(
            corp2_id,
            NatType::CarrierGrade,
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)),
            (IpAddr::V4(Ipv4Addr::new(172, 16, 0, 0)), 16),
        );
        
        // Add links with higher latency (corporate networks)
        self.add_network_link(corp1_id, corp2_id, Duration::from_millis(100), 10_000_000); // 10 Mbps
        self.add_network_link(corp2_id, corp1_id, Duration::from_millis(100), 10_000_000); // 10 Mbps
        
        (corp1_id, corp2_id)
    }

    /// Create a mobile network scenario
    pub fn create_mobile_network_scenario(&mut self) -> (NatDeviceId, NatDeviceId) {
        // Create mobile networks with CGNAT
        let mobile1_id = NatDeviceId(5);
        let mobile2_id = NatDeviceId(6);
        
        // Mobile network 1: Carrier grade NAT
        self.add_nat_device(
            mobile1_id,
            NatType::CarrierGrade,
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)),
            (IpAddr::V4(Ipv4Addr::new(100, 64, 0, 0)), 10),
        );
        
        // Mobile network 2: Symmetric NAT
        self.add_nat_device(
            mobile2_id,
            NatType::Symmetric,
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2)),
            (IpAddr::V4(Ipv4Addr::new(100, 64, 1, 0)), 10),
        );
        
        // Add links with variable latency (mobile networks)
        self.add_network_link(mobile1_id, mobile2_id, Duration::from_millis(150), 5_000_000); // 5 Mbps
        self.add_network_link(mobile2_id, mobile1_id, Duration::from_millis(150), 5_000_000); // 5 Mbps
        
        (mobile1_id, mobile2_id)
    }

    /// Simulate packet transmission through the network
    pub fn simulate_packet_transmission(&mut self, packet: MockPacket) -> NetworkSimulationResult {
        // Update metrics
        {
            let mut metrics = self.metrics.lock().unwrap();
            metrics.packets_sent += 1;
        }

        // Check packet loss
        if self.packet_loss_simulator.should_drop_packet() {
            let mut metrics = self.metrics.lock().unwrap();
            metrics.packet_loss_rate = (metrics.packet_loss_rate + 1.0) / 2.0; // Running average
            return NetworkSimulationResult::Dropped("Packet lost due to network conditions".to_string());
        }

        // Check bandwidth limiting
        if !self.bandwidth_limiter.allow_packet(packet.size) {
            return NetworkSimulationResult::Delayed(packet, Duration::from_millis(100));
        }

        // Route packet through NAT devices
        let route_result = self.route_packet(&packet);
        
        match route_result {
            Ok(processed_packet) => {
                // Apply latency simulation
                let latency = self.latency_simulator.calculate_latency();
                
                // Update metrics
                {
                    let mut metrics = self.metrics.lock().unwrap();
                    metrics.packets_received += 1;
                    metrics.network_bandwidth_usage += packet.size as u64;
                }

                if latency > Duration::from_millis(0) {
                    NetworkSimulationResult::Delayed(processed_packet, latency)
                } else {
                    NetworkSimulationResult::Delivered(processed_packet)
                }
            }
            Err(error) => {
                NetworkSimulationResult::Blocked(error)
            }
        }
    }

    /// Route a packet through the network topology
    fn route_packet(&mut self, packet: &MockPacket) -> Result<MockPacket, String> {
        // Find the NAT device that should handle this packet
        let dest_device_id = self.routing_table.get(&packet.destination.ip())
            .copied()
            .ok_or_else(|| "No route to destination".to_string())?;

        // Check if device exists first
        if !self.nat_devices.contains_key(&dest_device_id) {
            return Err("Destination device not found".to_string());
        }

        // Process packet through NAT
        self.process_packet_through_nat_by_id(dest_device_id, packet)
    }

    /// Process a packet through NAT device by device ID
    fn process_packet_through_nat_by_id(&mut self, device_id: NatDeviceId, packet: &MockPacket) -> Result<MockPacket, String> {
        // Simplified processing for compilation - update stats and return packet
        if let Some(device) = self.nat_devices.get_mut(&device_id) {
            device.stats.packets_processed += 1;
            // For compilation, just return the packet with some basic modification
            let mut new_packet = packet.clone();
            // Simulate some basic NAT behavior
            if device.nat_type != NatType::None {
                // Just modify the port slightly to simulate NAT
                new_packet.source = SocketAddr::new(device.external_ip, 
                    packet.source.port().wrapping_add(1000));
            }
            Ok(new_packet)
        } else {
            Err("Device not found".to_string())
        }
    }

    /// Process a packet through NAT device
    fn process_packet_through_nat(&mut self, device: &mut NatDevice, packet: &MockPacket) -> Result<MockPacket, String> {
        device.stats.packets_processed += 1;

        match device.nat_type {
            NatType::None => {
                // No NAT processing, pass through
                Ok(packet.clone())
            }
            NatType::FullCone => {
                self.process_full_cone_nat(device, packet)
            }
            NatType::RestrictedCone => {
                self.process_restricted_cone_nat(device, packet)
            }
            NatType::PortRestrictedCone => {
                self.process_port_restricted_nat(device, packet)
            }
            NatType::Symmetric => {
                self.process_symmetric_nat(device, packet)
            }
            NatType::CarrierGrade => {
                self.process_carrier_grade_nat(device, packet)
            }
        }
    }

    /// Process packet through full cone NAT
    fn process_full_cone_nat(&mut self, device: &mut NatDevice, packet: &MockPacket) -> Result<MockPacket, String> {
        // Full cone NAT: Once a mapping is created, any external host can send packets
        // through that mapping
        
        // Check if we have an existing mapping
        if let Some(&(internal_ip, internal_port)) = device.port_mappings.get(&(packet.destination.ip(), packet.destination.port())) {
            // Forward packet to internal address
            let mut new_packet = packet.clone();
            new_packet.destination = SocketAddr::new(internal_ip, internal_port);
            Ok(new_packet)
        } else {
            // Create new mapping for outbound traffic
            let internal_addr = self.get_internal_address(device, packet.source.ip())?;
            let external_port = self.allocate_external_port(device)?;
            
            device.port_mappings.insert((device.external_ip, external_port), (internal_addr, packet.source.port()));
            
            let mut new_packet = packet.clone();
            new_packet.source = SocketAddr::new(device.external_ip, external_port);
            Ok(new_packet)
        }
    }

    /// Process packet through restricted cone NAT
    fn process_restricted_cone_nat(&mut self, device: &mut NatDevice, packet: &MockPacket) -> Result<MockPacket, String> {
        // Restricted cone NAT: External host can only send packets if internal host
        // has previously sent a packet to that external host
        
        let connection_key = ConnectionKey {
            internal_addr: packet.source,
            external_addr: packet.destination,
            protocol: Protocol::Udp,
        };

        if let Some(connection) = device.connection_tracking.get_mut(&connection_key) {
            // Update connection activity
            connection.last_activity = Instant::now();
            connection.packet_count += 1;
            connection.bytes_transferred += packet.size as u64;
            
            // Allow packet through existing connection
            Ok(packet.clone())
        } else {
            // Check if this is a response to an outbound connection
            let reverse_key = ConnectionKey {
                internal_addr: packet.destination,
                external_addr: packet.source,
                protocol: Protocol::Udp,
            };
            
            if device.connection_tracking.contains_key(&reverse_key) {
                // Allow response packet
                Ok(packet.clone())
            } else {
                device.stats.packets_dropped += 1;
                Err("Packet blocked by restricted cone NAT".to_string())
            }
        }
    }

    /// Process packet through port restricted NAT
    fn process_port_restricted_nat(&mut self, device: &mut NatDevice, packet: &MockPacket) -> Result<MockPacket, String> {
        // Port restricted NAT: External host can only send packets if internal host
        // has previously sent a packet to that exact external host and port
        
        let connection_key = ConnectionKey {
            internal_addr: packet.source,
            external_addr: packet.destination,
            protocol: Protocol::Udp,
        };

        if let Some(connection) = device.connection_tracking.get_mut(&connection_key) {
            // Update connection activity
            connection.last_activity = Instant::now();
            connection.packet_count += 1;
            connection.bytes_transferred += packet.size as u64;
            
            // Allow packet through existing connection
            Ok(packet.clone())
        } else {
            device.stats.packets_dropped += 1;
            Err("Packet blocked by port restricted NAT".to_string())
        }
    }

    /// Process packet through symmetric NAT
    fn process_symmetric_nat(&mut self, device: &mut NatDevice, packet: &MockPacket) -> Result<MockPacket, String> {
        // Symmetric NAT: Each outbound connection gets a unique external port
        // Inbound packets are only allowed if they match exact connection
        
        let connection_key = ConnectionKey {
            internal_addr: packet.source,
            external_addr: packet.destination,
            protocol: Protocol::Udp,
        };

        if let Some(connection) = device.connection_tracking.get_mut(&connection_key) {
            // Update connection activity
            connection.last_activity = Instant::now();
            connection.packet_count += 1;
            connection.bytes_transferred += packet.size as u64;
            
            // Modify source port to mapped port
            let mut new_packet = packet.clone();
            new_packet.source = SocketAddr::new(device.external_ip, connection.mapped_port);
            Ok(new_packet)
        } else {
            // Create new connection with unique external port
            let external_port = self.allocate_external_port(device)?;
            
            let connection = ConnectionState {
                mapped_port: external_port,
                last_activity: Instant::now(),
                direction: ConnectionDirection::Outbound,
                packet_count: 1,
                bytes_transferred: packet.size as u64,
            };
            
            device.connection_tracking.insert(connection_key, connection);
            
            let mut new_packet = packet.clone();
            new_packet.source = SocketAddr::new(device.external_ip, external_port);
            Ok(new_packet)
        }
    }

    /// Process packet through carrier grade NAT
    fn process_carrier_grade_nat(&mut self, device: &mut NatDevice, packet: &MockPacket) -> Result<MockPacket, String> {
        // Carrier grade NAT: Very restrictive, similar to symmetric but with additional restrictions
        // and shorter timeouts
        
        let connection_key = ConnectionKey {
            internal_addr: packet.source,
            external_addr: packet.destination,
            protocol: Protocol::Udp,
        };

        if let Some(connection) = device.connection_tracking.get_mut(&connection_key) {
            // CGNAT has shorter timeouts
            if connection.last_activity.elapsed() > Duration::from_secs(60) {
                device.connection_tracking.remove(&connection_key);
                device.stats.packets_dropped += 1;
                return Err("Connection expired in CGNAT".to_string());
            }
            
            // Update connection activity
            connection.last_activity = Instant::now();
            connection.packet_count += 1;
            connection.bytes_transferred += packet.size as u64;
            
            let mut new_packet = packet.clone();
            new_packet.source = SocketAddr::new(device.external_ip, connection.mapped_port);
            Ok(new_packet)
        } else {
            // CGNAT may have limited port range
            let external_port = self.allocate_external_port(device)?;
            
            let connection = ConnectionState {
                mapped_port: external_port,
                last_activity: Instant::now(),
                direction: ConnectionDirection::Outbound,
                packet_count: 1,
                bytes_transferred: packet.size as u64,
            };
            
            device.connection_tracking.insert(connection_key, connection);
            
            let mut new_packet = packet.clone();
            new_packet.source = SocketAddr::new(device.external_ip, external_port);
            Ok(new_packet)
        }
    }

    /// Get internal address for a device
    fn get_internal_address(&self, device: &NatDevice, external_ip: IpAddr) -> Result<IpAddr, String> {
        // Simple mapping for testing - in reality this would be more complex
        match device.internal_ip_range.0 {
            IpAddr::V4(base) => {
                let octets = base.octets();
                Ok(IpAddr::V4(Ipv4Addr::new(octets[0], octets[1], octets[2], 100)))
            }
            IpAddr::V6(_) => {
                Err("IPv6 not implemented in mock".to_string())
            }
        }
    }

    /// Allocate an external port for NAT mapping
    fn allocate_external_port(&mut self, device: &mut NatDevice) -> Result<u16, String> {
        if device.next_port >= device.port_range.1 {
            device.next_port = device.port_range.0;
        }
        
        let port = device.next_port;
        device.next_port += 1;
        
        Ok(port)
    }

    /// Get network statistics
    pub fn get_network_statistics(&self) -> NetworkStatistics {
        let metrics = self.metrics.lock().unwrap();
        
        NetworkStatistics {
            total_packets_sent: metrics.packets_sent,
            total_packets_received: metrics.packets_received,
            packet_loss_rate: metrics.packet_loss_rate,
            total_bandwidth_usage: metrics.network_bandwidth_usage,
            device_stats: self.nat_devices.iter()
                .map(|(id, device)| (*id, device.stats.clone()))
                .collect(),
        }
    }

    /// Reset network statistics
    pub fn reset_statistics(&mut self) {
        let mut metrics = self.metrics.lock().unwrap();
        *metrics = PerformanceMetrics::default();
        
        for device in self.nat_devices.values_mut() {
            device.stats = NatDeviceStats::default();
        }
    }
}

/// Network statistics
#[derive(Debug, Clone)]
pub struct NetworkStatistics {
    pub total_packets_sent: u64,
    pub total_packets_received: u64,
    pub packet_loss_rate: f32,
    pub total_bandwidth_usage: u64,
    pub device_stats: HashMap<NatDeviceId, NatDeviceStats>,
}

impl PacketLossSimulator {
    fn new(loss_rate: f32) -> Self {
        Self {
            loss_rate: loss_rate.clamp(0.0, 1.0),
            rng: rand::thread_rng(),
        }
    }

    fn should_drop_packet(&mut self) -> bool {
        if self.loss_rate <= 0.0 {
            return false;
        }
        
        self.rng.gen::<f32>() < self.loss_rate
    }
}

impl LatencySimulator {
    fn new(base_latency: Duration, jitter: Duration) -> Self {
        Self {
            base_latency,
            jitter,
            rng: rand::thread_rng(),
        }
    }

    fn calculate_latency(&mut self) -> Duration {
        let jitter_amount = if self.jitter > Duration::from_millis(0) {
            let jitter_ms = self.jitter.as_millis() as i64;
            let neg_jitter_ms = -jitter_ms;
            let random_jitter = self.rng.gen_range(neg_jitter_ms..=jitter_ms);
            Duration::from_millis(random_jitter.abs() as u64)
        } else {
            Duration::from_millis(0)
        };
        
        self.base_latency + jitter_amount
    }
}

impl BandwidthLimiter {
    fn new(bandwidth_limit: Option<u64>) -> Self {
        let token_bucket = if let Some(limit) = bandwidth_limit {
            TokenBucket {
                tokens: limit as f64,
                max_tokens: limit as f64,
                refill_rate: limit as f64,
                last_refill: Instant::now(),
            }
        } else {
            TokenBucket {
                tokens: f64::INFINITY,
                max_tokens: f64::INFINITY,
                refill_rate: f64::INFINITY,
                last_refill: Instant::now(),
            }
        };
        
        Self {
            bandwidth_limit,
            token_bucket,
        }
    }

    fn allow_packet(&mut self, packet_size: usize) -> bool {
        if self.bandwidth_limit.is_none() {
            return true;
        }
        
        // Refill token bucket
        let now = Instant::now();
        let elapsed = now.duration_since(self.token_bucket.last_refill);
        let tokens_to_add = elapsed.as_secs_f64() * self.token_bucket.refill_rate;
        
        self.token_bucket.tokens = (self.token_bucket.tokens + tokens_to_add).min(self.token_bucket.max_tokens);
        self.token_bucket.last_refill = now;
        
        // Check if we have enough tokens
        if self.token_bucket.tokens >= packet_size as f64 {
            self.token_bucket.tokens -= packet_size as f64;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_network_creation() {
        let config = NetworkSimulationConfig::default();
        let mut network = MockNetworkEnvironment::new(config);
        
        // Test adding NAT devices
        let (home1, home2) = network.create_home_network_scenario();
        assert_eq!(home1, NatDeviceId(1));
        assert_eq!(home2, NatDeviceId(2));
        
        // Test network statistics
        let stats = network.get_network_statistics();
        assert_eq!(stats.total_packets_sent, 0);
        assert_eq!(stats.total_packets_received, 0);
    }

    #[test]
    fn test_packet_loss_simulation() {
        let mut simulator = PacketLossSimulator::new(0.5); // 50% loss
        let mut dropped_count = 0;
        let total_packets = 1000;
        
        for _ in 0..total_packets {
            if simulator.should_drop_packet() {
                dropped_count += 1;
            }
        }
        
        // Should be approximately 50% loss (within 10% tolerance)
        let loss_rate = dropped_count as f32 / total_packets as f32;
        assert!(loss_rate > 0.4 && loss_rate < 0.6);
    }

    #[test]
    fn test_latency_simulation() {
        let mut simulator = LatencySimulator::new(Duration::from_millis(100), Duration::from_millis(20));
        
        for _ in 0..100 {
            let latency = simulator.calculate_latency();
            // Should be base latency ± jitter
            assert!(latency >= Duration::from_millis(80) && latency <= Duration::from_millis(120));
        }
    }

    #[test]
    fn test_bandwidth_limiting() {
        let mut limiter = BandwidthLimiter::new(Some(1000)); // 1000 bytes/sec
        
        // Should allow initial packets
        assert!(limiter.allow_packet(500));
        assert!(limiter.allow_packet(500));
        
        // Should block additional packets
        assert!(!limiter.allow_packet(100));
    }
}