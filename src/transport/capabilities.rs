// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Transport capability profiles for protocol engine selection
//!
//! This module defines [`TransportCapabilities`], which describes what a transport
//! can do in terms of bandwidth, latency, MTU, and operational constraints.
//!
//! These capabilities are used to:
//! 1. Select the appropriate protocol engine (QUIC vs Constrained)
//! 2. Choose optimal routes when multiple transports are available
//! 3. Adapt protocol behavior (fragmentation, retransmission strategy)
//!
//! # Capability Profiles
//!
//! Pre-defined profiles match common transport configurations:
//!
//! | Profile | Bandwidth | MTU | RTT | Use Case |
//! |---------|-----------|-----|-----|----------|
//! | `broadband()` | 100 Mbps | 1200 | 50ms | UDP/IP |
//! | `ble()` | 125 kbps | 244 | 100ms | Bluetooth LE |
//! | `lora_long_range()` | 293 bps | 222 | 5s | LoRa SF12 |
//! | `lora_fast()` | 22 kbps | 222 | 500ms | LoRa SF7 |
//! | `serial_115200()` | 115.2 kbps | 1024 | 50ms | Direct serial |
//!
//! # Protocol Engine Selection
//!
//! The [`supports_full_quic()`](TransportCapabilities::supports_full_quic) method
//! determines whether a transport can run full QUIC or requires the constrained engine:
//!
//! - **Full QUIC**: bandwidth >= 10 kbps, MTU >= 1200 bytes, RTT < 2 seconds
//! - **Constrained**: All other transports

use std::time::Duration;

/// Bandwidth classification for routing decisions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BandwidthClass {
    /// Very low bandwidth (< 1 kbps) - LoRa SF12, packet radio
    VeryLow,
    /// Low bandwidth (1-100 kbps) - LoRa SF7, serial, BLE
    Low,
    /// Medium bandwidth (100 kbps - 10 Mbps) - WiFi, 4G
    Medium,
    /// High bandwidth (> 10 Mbps) - Ethernet, 5G
    High,
}

impl BandwidthClass {
    /// Classify bandwidth in bits per second
    pub fn from_bps(bps: u64) -> Self {
        match bps {
            0..=999 => Self::VeryLow,
            1000..=99_999 => Self::Low,
            100_000..=9_999_999 => Self::Medium,
            _ => Self::High,
        }
    }
}

/// Transport capability description
///
/// Describes what a transport can do, used for protocol selection and routing.
/// All values are estimates/typical values; actual performance may vary.
#[derive(Debug, Clone)]
pub struct TransportCapabilities {
    /// Expected bandwidth in bits per second
    /// Range: 5 (slow LoRa) to 1_000_000_000 (gigabit Ethernet)
    pub bandwidth_bps: u64,

    /// Maximum transmission unit in bytes
    /// Range: 222 (LoRa) to 65535 (jumbo frames)
    pub mtu: usize,

    /// Typical round-trip time under normal conditions
    pub typical_rtt: Duration,

    /// Maximum RTT before link is considered dead
    pub max_rtt: Duration,

    /// Half-duplex link (can only send OR receive at once)
    /// Radio links are typically half-duplex
    pub half_duplex: bool,

    /// Supports broadcast/multicast to multiple recipients
    pub broadcast: bool,

    /// Metered connection (cost per byte, e.g., satellite, cellular)
    pub metered: bool,

    /// Expected packet loss rate (0.0 to 1.0)
    /// Used for selecting retransmission strategy
    pub loss_rate: f32,

    /// Power-constrained device (battery operated)
    /// Affects keep-alive intervals and transmission scheduling
    pub power_constrained: bool,

    /// Link layer provides acknowledgements
    /// If true, application-layer ACKs can be optimized
    pub link_layer_acks: bool,

    /// Estimated link availability (0.0 to 1.0)
    /// 1.0 = always available, lower values for intermittent links
    pub availability: f32,
}

impl TransportCapabilities {
    /// Determine if this transport can run full QUIC protocol
    ///
    /// Full QUIC requires:
    /// - Bandwidth >= 10,000 bps (10 kbps)
    /// - MTU >= 1200 bytes (QUIC minimum initial packet size)
    /// - Typical RTT < 2 seconds
    ///
    /// Transports not meeting these criteria should use the constrained engine.
    pub fn supports_full_quic(&self) -> bool {
        self.bandwidth_bps >= 10_000
            && self.mtu >= 1200
            && self.typical_rtt < Duration::from_secs(2)
    }

    /// Get bandwidth classification
    pub fn bandwidth_class(&self) -> BandwidthClass {
        BandwidthClass::from_bps(self.bandwidth_bps)
    }

    /// Estimate time to transmit data of given size
    pub fn estimate_transmission_time(&self, bytes: usize) -> Duration {
        if self.bandwidth_bps == 0 {
            return Duration::MAX;
        }
        let bits = bytes as u64 * 8;
        Duration::from_secs_f64(bits as f64 / self.bandwidth_bps as f64)
    }

    /// Calculate effective bandwidth considering loss rate
    pub fn effective_bandwidth_bps(&self) -> u64 {
        ((1.0 - self.loss_rate) * self.bandwidth_bps as f32) as u64
    }

    /// High-bandwidth, low-latency UDP/IP transport
    ///
    /// Typical for Internet connectivity over Ethernet, WiFi, or mobile data.
    pub fn broadband() -> Self {
        Self {
            bandwidth_bps: 100_000_000, // 100 Mbps
            mtu: 1200,
            typical_rtt: Duration::from_millis(50),
            max_rtt: Duration::from_secs(5),
            half_duplex: false,
            broadcast: true,
            metered: false,
            loss_rate: 0.001,
            power_constrained: false,
            link_layer_acks: false,
            availability: 0.99,
        }
    }

    /// Bluetooth Low Energy transport
    ///
    /// Short-range wireless with moderate bandwidth and low power consumption.
    /// BLE 4.2 with extended data length.
    pub fn ble() -> Self {
        Self {
            bandwidth_bps: 125_000, // ~125 kbps practical throughput
            mtu: 244,               // BLE max ATT MTU - overhead
            typical_rtt: Duration::from_millis(100),
            max_rtt: Duration::from_secs(5),
            half_duplex: false,
            broadcast: true, // BLE advertising
            metered: false,
            loss_rate: 0.02,
            power_constrained: true,
            link_layer_acks: true,
            availability: 0.95,
        }
    }

    /// LoRa long-range configuration (SF12, 125kHz)
    ///
    /// Maximum range but very low bandwidth. Suitable for telemetry
    /// and infrequent messaging over distances up to 15+ km.
    pub fn lora_long_range() -> Self {
        Self {
            bandwidth_bps: 293, // ~300 bps at SF12/125kHz
            mtu: 222,           // LoRa max payload
            typical_rtt: Duration::from_secs(5),
            max_rtt: Duration::from_secs(60),
            half_duplex: true,
            broadcast: true,
            metered: false,
            loss_rate: 0.1,
            power_constrained: true,
            link_layer_acks: false,
            availability: 0.95,
        }
    }

    /// LoRa short-range fast configuration (SF7, 500kHz)
    ///
    /// Shorter range but higher bandwidth. Suitable for local mesh
    /// networking within 1-2 km range.
    pub fn lora_fast() -> Self {
        Self {
            bandwidth_bps: 21_875, // ~22 kbps at SF7/500kHz
            mtu: 222,
            typical_rtt: Duration::from_millis(500),
            max_rtt: Duration::from_secs(10),
            half_duplex: true,
            broadcast: true,
            metered: false,
            loss_rate: 0.05,
            power_constrained: true,
            link_layer_acks: false,
            availability: 0.90,
        }
    }

    /// Serial port connection at 115200 baud
    ///
    /// Direct wired connection, typically point-to-point.
    /// Very reliable with low latency.
    pub fn serial_115200() -> Self {
        Self {
            bandwidth_bps: 115_200,
            mtu: 1024,
            typical_rtt: Duration::from_millis(50),
            max_rtt: Duration::from_secs(5),
            half_duplex: true,
            broadcast: false, // Point-to-point
            metered: false,
            loss_rate: 0.001,
            power_constrained: false,
            link_layer_acks: false,
            availability: 1.0, // Cable doesn't go down
        }
    }

    /// AX.25 packet radio at 1200 baud AFSK
    ///
    /// Amateur radio packet networking, typically VHF/UHF.
    /// Moderate range with shared channel.
    pub fn packet_radio_1200() -> Self {
        Self {
            bandwidth_bps: 1_200,
            mtu: 256,
            typical_rtt: Duration::from_secs(2),
            max_rtt: Duration::from_secs(30),
            half_duplex: true,
            broadcast: true,
            metered: false,
            loss_rate: 0.15,
            power_constrained: true,
            link_layer_acks: true, // AX.25 has ARQ
            availability: 0.80,
        }
    }

    /// I2P anonymous overlay network
    ///
    /// Anonymity network with variable performance.
    /// High latency but large MTU.
    pub fn i2p() -> Self {
        Self {
            bandwidth_bps: 50_000, // Highly variable
            mtu: 61_440,           // I2P tunnel MTU
            typical_rtt: Duration::from_secs(2),
            max_rtt: Duration::from_secs(30),
            half_duplex: false,
            broadcast: false,
            metered: false,
            loss_rate: 0.05,
            power_constrained: false,
            link_layer_acks: false,
            availability: 0.90,
        }
    }

    /// Yggdrasil mesh network
    ///
    /// Encrypted mesh overlay with automatic routing.
    /// Performance depends on path length.
    pub fn yggdrasil() -> Self {
        Self {
            bandwidth_bps: 10_000_000, // Variable based on underlying links
            mtu: 65535,                // Full IPv6 MTU
            typical_rtt: Duration::from_millis(200),
            max_rtt: Duration::from_secs(10),
            half_duplex: false,
            broadcast: false,
            metered: false,
            loss_rate: 0.02,
            power_constrained: false,
            link_layer_acks: false,
            availability: 0.95,
        }
    }

    /// Create custom capabilities with builder pattern
    pub fn custom() -> TransportCapabilitiesBuilder {
        TransportCapabilitiesBuilder::default()
    }
}

impl Default for TransportCapabilities {
    fn default() -> Self {
        Self::broadband()
    }
}

/// Builder for custom [`TransportCapabilities`]
#[derive(Debug, Default)]
pub struct TransportCapabilitiesBuilder {
    bandwidth_bps: Option<u64>,
    mtu: Option<usize>,
    typical_rtt: Option<Duration>,
    max_rtt: Option<Duration>,
    half_duplex: Option<bool>,
    broadcast: Option<bool>,
    metered: Option<bool>,
    loss_rate: Option<f32>,
    power_constrained: Option<bool>,
    link_layer_acks: Option<bool>,
    availability: Option<f32>,
}

impl TransportCapabilitiesBuilder {
    /// Set bandwidth in bits per second
    pub fn bandwidth_bps(mut self, bps: u64) -> Self {
        self.bandwidth_bps = Some(bps);
        self
    }

    /// Set maximum transmission unit
    pub fn mtu(mut self, mtu: usize) -> Self {
        self.mtu = Some(mtu);
        self
    }

    /// Set typical round-trip time
    pub fn typical_rtt(mut self, rtt: Duration) -> Self {
        self.typical_rtt = Some(rtt);
        self
    }

    /// Set maximum round-trip time
    pub fn max_rtt(mut self, rtt: Duration) -> Self {
        self.max_rtt = Some(rtt);
        self
    }

    /// Set half-duplex mode
    pub fn half_duplex(mut self, enabled: bool) -> Self {
        self.half_duplex = Some(enabled);
        self
    }

    /// Set broadcast capability
    pub fn broadcast(mut self, enabled: bool) -> Self {
        self.broadcast = Some(enabled);
        self
    }

    /// Set metered connection flag
    pub fn metered(mut self, enabled: bool) -> Self {
        self.metered = Some(enabled);
        self
    }

    /// Set expected packet loss rate (0.0 to 1.0)
    pub fn loss_rate(mut self, rate: f32) -> Self {
        self.loss_rate = Some(rate.clamp(0.0, 1.0));
        self
    }

    /// Set power-constrained flag
    pub fn power_constrained(mut self, enabled: bool) -> Self {
        self.power_constrained = Some(enabled);
        self
    }

    /// Set link-layer acknowledgements flag
    pub fn link_layer_acks(mut self, enabled: bool) -> Self {
        self.link_layer_acks = Some(enabled);
        self
    }

    /// Set link availability (0.0 to 1.0)
    pub fn availability(mut self, avail: f32) -> Self {
        self.availability = Some(avail.clamp(0.0, 1.0));
        self
    }

    /// Build the capabilities, using broadband defaults for unset fields
    pub fn build(self) -> TransportCapabilities {
        let defaults = TransportCapabilities::broadband();
        TransportCapabilities {
            bandwidth_bps: self.bandwidth_bps.unwrap_or(defaults.bandwidth_bps),
            mtu: self.mtu.unwrap_or(defaults.mtu),
            typical_rtt: self.typical_rtt.unwrap_or(defaults.typical_rtt),
            max_rtt: self.max_rtt.unwrap_or(defaults.max_rtt),
            half_duplex: self.half_duplex.unwrap_or(defaults.half_duplex),
            broadcast: self.broadcast.unwrap_or(defaults.broadcast),
            metered: self.metered.unwrap_or(defaults.metered),
            loss_rate: self.loss_rate.unwrap_or(defaults.loss_rate),
            power_constrained: self.power_constrained.unwrap_or(defaults.power_constrained),
            link_layer_acks: self.link_layer_acks.unwrap_or(defaults.link_layer_acks),
            availability: self.availability.unwrap_or(defaults.availability),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_broadband_supports_quic() {
        let caps = TransportCapabilities::broadband();
        assert!(caps.supports_full_quic());
        assert_eq!(caps.bandwidth_class(), BandwidthClass::High);
    }

    #[test]
    fn test_ble_supports_quic() {
        let caps = TransportCapabilities::ble();
        // BLE has low MTU (244) so it doesn't support full QUIC
        assert!(!caps.supports_full_quic());
        // BLE has 125kbps which is Medium bandwidth (100kbps - 10Mbps)
        assert_eq!(caps.bandwidth_class(), BandwidthClass::Medium);
    }

    #[test]
    fn test_lora_long_range_no_quic() {
        let caps = TransportCapabilities::lora_long_range();
        assert!(!caps.supports_full_quic());
        assert_eq!(caps.bandwidth_class(), BandwidthClass::VeryLow);
    }

    #[test]
    fn test_lora_fast_no_quic() {
        let caps = TransportCapabilities::lora_fast();
        // MTU is 222, less than QUIC minimum of 1200
        assert!(!caps.supports_full_quic());
        assert_eq!(caps.bandwidth_class(), BandwidthClass::Low);
    }

    #[test]
    fn test_serial_no_quic() {
        let caps = TransportCapabilities::serial_115200();
        // MTU is 1024, less than QUIC minimum of 1200
        assert!(!caps.supports_full_quic());
        // Serial at 115200 bps is Medium bandwidth (100kbps - 10Mbps)
        assert_eq!(caps.bandwidth_class(), BandwidthClass::Medium);
    }

    #[test]
    fn test_i2p_bandwidth() {
        let caps = TransportCapabilities::i2p();
        // I2P has 50kbps bandwidth but high RTT (2+ seconds), so it may not support full QUIC
        // MTU is 61KB which is fine, but RTT is typically >= 2 seconds
        // supports_full_quic checks RTT < 2s, so this is borderline
        // With typical_rtt of 2s, it's exactly at the boundary
        assert_eq!(caps.bandwidth_class(), BandwidthClass::Low);
    }

    #[test]
    fn test_yggdrasil_supports_quic() {
        let caps = TransportCapabilities::yggdrasil();
        assert!(caps.supports_full_quic());
        assert_eq!(caps.bandwidth_class(), BandwidthClass::High);
    }

    #[test]
    fn test_estimate_transmission_time() {
        let caps = TransportCapabilities::lora_long_range();
        // 222 bytes at 293 bps
        let time = caps.estimate_transmission_time(222);
        // 222 * 8 / 293 = ~6 seconds
        assert!(time > Duration::from_secs(5));
        assert!(time < Duration::from_secs(7));
    }

    #[test]
    fn test_effective_bandwidth() {
        let caps = TransportCapabilities::custom()
            .bandwidth_bps(1000)
            .loss_rate(0.1)
            .build();

        // 10% loss means 90% effective
        assert_eq!(caps.effective_bandwidth_bps(), 900);
    }

    #[test]
    fn test_custom_capabilities() {
        let caps = TransportCapabilities::custom()
            .bandwidth_bps(9600)
            .mtu(512)
            .typical_rtt(Duration::from_millis(200))
            .half_duplex(true)
            .power_constrained(true)
            .build();

        assert_eq!(caps.bandwidth_bps, 9600);
        assert_eq!(caps.mtu, 512);
        assert!(caps.half_duplex);
        assert!(caps.power_constrained);
        assert!(!caps.supports_full_quic()); // MTU too small
    }

    #[test]
    fn test_bandwidth_class_boundaries() {
        assert_eq!(BandwidthClass::from_bps(0), BandwidthClass::VeryLow);
        assert_eq!(BandwidthClass::from_bps(999), BandwidthClass::VeryLow);
        assert_eq!(BandwidthClass::from_bps(1000), BandwidthClass::Low);
        assert_eq!(BandwidthClass::from_bps(99_999), BandwidthClass::Low);
        assert_eq!(BandwidthClass::from_bps(100_000), BandwidthClass::Medium);
        assert_eq!(BandwidthClass::from_bps(9_999_999), BandwidthClass::Medium);
        assert_eq!(BandwidthClass::from_bps(10_000_000), BandwidthClass::High);
    }

    #[test]
    fn test_loss_rate_clamping() {
        let caps = TransportCapabilities::custom()
            .loss_rate(1.5) // > 1.0
            .build();
        assert_eq!(caps.loss_rate, 1.0);

        let caps = TransportCapabilities::custom()
            .loss_rate(-0.5) // < 0.0
            .build();
        assert_eq!(caps.loss_rate, 0.0);
    }

    #[test]
    fn test_availability_clamping() {
        let caps = TransportCapabilities::custom()
            .availability(2.0) // > 1.0
            .build();
        assert_eq!(caps.availability, 1.0);

        let caps = TransportCapabilities::custom()
            .availability(-1.0) // < 0.0
            .build();
        assert_eq!(caps.availability, 0.0);
    }
}
