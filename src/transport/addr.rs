// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Transport-specific addressing for multi-transport P2P networking
//!
//! This module defines [`TransportAddr`], a unified addressing type that supports
//! multiple physical transports including UDP/IP, Bluetooth Low Energy, LoRa radio,
//! serial connections, and overlay networks.
//!
//! # Design
//!
//! Each transport has its own addressing scheme:
//! - **UDP**: Standard IP socket addresses (IPv4/IPv6)
//! - **BLE**: Bluetooth device address + GATT service UUID
//! - **LoRa**: Device address + radio parameters (SF, bandwidth)
//! - **Serial**: Port name (e.g., `/dev/ttyUSB0`, `COM3`)
//! - **Overlay**: I2P destinations, Yggdrasil addresses
//!
//! The [`TransportType`] enum identifies transport categories for routing decisions.

use std::fmt;
use std::net::SocketAddr;

/// Transport type identifier for routing and capability matching
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportType {
    /// UDP/IP transport - standard Internet connectivity
    Udp,
    /// Bluetooth Low Energy - short-range, low-power wireless
    Ble,
    /// LoRa radio - long-range, low-bandwidth wireless
    LoRa,
    /// Serial port - direct wired connection
    Serial,
    /// AX.25 packet radio - amateur radio networks
    Ax25,
    /// I2P anonymous overlay network
    I2p,
    /// Yggdrasil mesh network
    Yggdrasil,
}

impl fmt::Display for TransportType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Udp => write!(f, "UDP"),
            Self::Ble => write!(f, "BLE"),
            Self::LoRa => write!(f, "LoRa"),
            Self::Serial => write!(f, "Serial"),
            Self::Ax25 => write!(f, "AX.25"),
            Self::I2p => write!(f, "I2P"),
            Self::Yggdrasil => write!(f, "Yggdrasil"),
        }
    }
}

/// LoRa radio configuration parameters
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LoRaParams {
    /// Spreading factor (7-12)
    pub spreading_factor: u8,
    /// Bandwidth in kHz (125, 250, or 500)
    pub bandwidth_khz: u16,
    /// Coding rate numerator (5-8 for 4/5 to 4/8)
    pub coding_rate: u8,
}

impl Default for LoRaParams {
    fn default() -> Self {
        Self {
            spreading_factor: 12, // Maximum range
            bandwidth_khz: 125,   // Standard narrow bandwidth
            coding_rate: 5,       // 4/5 coding (most efficient)
        }
    }
}

/// Transport-specific addressing
///
/// A unified address type that can represent destinations on any supported transport.
/// This enables transport-agnostic routing at higher layers.
///
/// # Example
///
/// ```rust
/// use ant_quic::transport::{TransportAddr, TransportType};
/// use std::net::SocketAddr;
///
/// // UDP address
/// let udp_addr = TransportAddr::Udp("192.168.1.1:9000".parse().unwrap());
/// assert_eq!(udp_addr.transport_type(), TransportType::Udp);
///
/// // BLE address
/// let ble_addr = TransportAddr::ble([0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC], None);
/// assert_eq!(ble_addr.transport_type(), TransportType::Ble);
/// ```
#[derive(Clone, PartialEq, Eq, Hash)]
pub enum TransportAddr {
    /// UDP/IP socket address (IPv4 or IPv6)
    Udp(SocketAddr),

    /// Bluetooth Low Energy device
    Ble {
        /// 48-bit Bluetooth device address (MAC address)
        device_id: [u8; 6],
        /// Optional GATT service UUID for connection
        /// If None, uses the default ant-quic service UUID
        service_uuid: Option<[u8; 16]>,
    },

    /// LoRa radio device
    LoRa {
        /// 32-bit device address
        device_addr: [u8; 4],
        /// Radio parameters (spreading factor, bandwidth, coding rate)
        params: LoRaParams,
    },

    /// Serial port connection
    Serial {
        /// Port name (e.g., "/dev/ttyUSB0", "COM3")
        port: String,
    },

    /// AX.25 packet radio (amateur radio)
    Ax25 {
        /// Amateur radio callsign
        callsign: String,
        /// Secondary Station Identifier (0-15)
        ssid: u8,
    },

    /// I2P anonymous overlay network
    I2p {
        /// I2P destination (387 bytes base64-decoded)
        destination: Box<[u8; 387]>,
    },

    /// Yggdrasil mesh network
    Yggdrasil {
        /// 128-bit Yggdrasil address
        address: [u8; 16],
    },

    /// Broadcast on a specific transport
    Broadcast {
        /// Transport type to broadcast on
        transport_type: TransportType,
    },
}

impl TransportAddr {
    /// Get the transport type for this address
    pub fn transport_type(&self) -> TransportType {
        match self {
            Self::Udp(_) => TransportType::Udp,
            Self::Ble { .. } => TransportType::Ble,
            Self::LoRa { .. } => TransportType::LoRa,
            Self::Serial { .. } => TransportType::Serial,
            Self::Ax25 { .. } => TransportType::Ax25,
            Self::I2p { .. } => TransportType::I2p,
            Self::Yggdrasil { .. } => TransportType::Yggdrasil,
            Self::Broadcast { transport_type } => *transport_type,
        }
    }

    /// Create a BLE address with optional service UUID
    pub fn ble(device_id: [u8; 6], service_uuid: Option<[u8; 16]>) -> Self {
        Self::Ble {
            device_id,
            service_uuid,
        }
    }

    /// Create a LoRa address with default parameters
    pub fn lora(device_addr: [u8; 4]) -> Self {
        Self::LoRa {
            device_addr,
            params: LoRaParams::default(),
        }
    }

    /// Create a LoRa address with custom parameters
    pub fn lora_with_params(device_addr: [u8; 4], params: LoRaParams) -> Self {
        Self::LoRa {
            device_addr,
            params,
        }
    }

    /// Create a serial port address
    pub fn serial(port: impl Into<String>) -> Self {
        Self::Serial { port: port.into() }
    }

    /// Create an AX.25 address
    pub fn ax25(callsign: impl Into<String>, ssid: u8) -> Self {
        Self::Ax25 {
            callsign: callsign.into(),
            ssid: ssid.min(15), // SSID is 0-15
        }
    }

    /// Create a Yggdrasil address
    pub fn yggdrasil(address: [u8; 16]) -> Self {
        Self::Yggdrasil { address }
    }

    /// Create a broadcast address for a specific transport
    pub fn broadcast(transport_type: TransportType) -> Self {
        Self::Broadcast { transport_type }
    }

    /// Check if this is a broadcast address
    pub fn is_broadcast(&self) -> bool {
        matches!(self, Self::Broadcast { .. })
    }

    /// Get the UDP socket address if this is a UDP address
    ///
    /// # Returns
    ///
    /// - `Some(SocketAddr)` if this is a `TransportAddr::Udp`
    /// - `None` for all other transport types
    ///
    /// # Example
    ///
    /// ```rust
    /// use ant_quic::transport::TransportAddr;
    /// use std::net::SocketAddr;
    ///
    /// let socket_addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
    /// let transport_addr = TransportAddr::from(socket_addr);
    ///
    /// assert_eq!(transport_addr.as_socket_addr(), Some(socket_addr));
    ///
    /// let ble_addr = TransportAddr::ble([0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC], None);
    /// assert_eq!(ble_addr.as_socket_addr(), None);
    /// ```
    pub fn as_socket_addr(&self) -> Option<SocketAddr> {
        match self {
            Self::Udp(addr) => Some(*addr),
            _ => None,
        }
    }

    /// Convert this transport address to a synthetic SocketAddr for internal tracking
    ///
    /// For UDP addresses, returns the actual socket address.
    /// For non-UDP addresses (BLE, LoRa, Serial, etc.), creates a synthetic IPv6 address
    /// in the documentation range (2001:db8::/32) that uniquely identifies the transport
    /// endpoint for use with the constrained protocol engine.
    ///
    /// The synthetic address encodes:
    /// - Transport type in the first octet
    /// - Transport-specific identifier in the remaining bytes
    /// - Port 0 (since non-UDP transports don't use ports)
    ///
    /// # Example
    ///
    /// ```rust
    /// use ant_quic::transport::TransportAddr;
    ///
    /// let ble_addr = TransportAddr::ble([0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC], None);
    /// let synthetic = ble_addr.to_synthetic_socket_addr();
    /// // Returns a unique IPv6 address encoding the BLE device ID
    /// ```
    pub fn to_synthetic_socket_addr(&self) -> SocketAddr {
        use std::net::{IpAddr, Ipv6Addr};

        match self {
            Self::Udp(addr) => *addr,
            Self::Ble { device_id, .. } => {
                // Create synthetic IPv6 in documentation range: 2001:db8:ble:XXXX:XXXX:XXXX::
                // Encodes 6-byte MAC address in last 6 bytes of IPv6
                let addr = Ipv6Addr::new(
                    0x2001,
                    0x0db8,
                    0x0001, // Transport type 1 = BLE
                    ((device_id[0] as u16) << 8) | (device_id[1] as u16),
                    ((device_id[2] as u16) << 8) | (device_id[3] as u16),
                    ((device_id[4] as u16) << 8) | (device_id[5] as u16),
                    0,
                    0,
                );
                SocketAddr::new(IpAddr::V6(addr), 0)
            }
            Self::LoRa { device_addr, .. } => {
                // Create synthetic IPv6: 2001:db8:lora:XXXX::
                let addr = Ipv6Addr::new(
                    0x2001,
                    0x0db8,
                    0x0002, // Transport type 2 = LoRa
                    ((device_addr[0] as u16) << 8) | (device_addr[1] as u16),
                    ((device_addr[2] as u16) << 8) | (device_addr[3] as u16),
                    0,
                    0,
                    0,
                );
                SocketAddr::new(IpAddr::V6(addr), 0)
            }
            Self::Serial { port } => {
                // Hash the port name to create a unique address
                use std::hash::{Hash, Hasher};
                let mut hasher = std::collections::hash_map::DefaultHasher::new();
                port.hash(&mut hasher);
                let hash = hasher.finish();
                let addr = Ipv6Addr::new(
                    0x2001,
                    0x0db8,
                    0x0003, // Transport type 3 = Serial
                    (hash >> 48) as u16,
                    (hash >> 32) as u16,
                    (hash >> 16) as u16,
                    hash as u16,
                    0,
                );
                SocketAddr::new(IpAddr::V6(addr), 0)
            }
            Self::Ax25 { callsign, ssid } => {
                // Hash callsign+ssid
                use std::hash::{Hash, Hasher};
                let mut hasher = std::collections::hash_map::DefaultHasher::new();
                callsign.hash(&mut hasher);
                ssid.hash(&mut hasher);
                let hash = hasher.finish();
                let addr = Ipv6Addr::new(
                    0x2001,
                    0x0db8,
                    0x0004, // Transport type 4 = AX.25
                    (hash >> 48) as u16,
                    (hash >> 32) as u16,
                    (hash >> 16) as u16,
                    hash as u16,
                    0,
                );
                SocketAddr::new(IpAddr::V6(addr), 0)
            }
            Self::I2p { destination } => {
                // Use first 8 bytes of destination as identifier
                let addr = Ipv6Addr::new(
                    0x2001,
                    0x0db8,
                    0x0005, // Transport type 5 = I2P
                    ((destination[0] as u16) << 8) | (destination[1] as u16),
                    ((destination[2] as u16) << 8) | (destination[3] as u16),
                    ((destination[4] as u16) << 8) | (destination[5] as u16),
                    ((destination[6] as u16) << 8) | (destination[7] as u16),
                    0,
                );
                SocketAddr::new(IpAddr::V6(addr), 0)
            }
            Self::Yggdrasil { address } => {
                // Yggdrasil already has 128-bit address, use directly with marker
                let addr = Ipv6Addr::new(
                    0x2001,
                    0x0db8,
                    0x0006, // Transport type 6 = Yggdrasil
                    ((address[0] as u16) << 8) | (address[1] as u16),
                    ((address[2] as u16) << 8) | (address[3] as u16),
                    ((address[4] as u16) << 8) | (address[5] as u16),
                    ((address[6] as u16) << 8) | (address[7] as u16),
                    0,
                );
                SocketAddr::new(IpAddr::V6(addr), 0)
            }
            Self::Broadcast { transport_type } => {
                // Use all-ones for broadcast
                let type_code = match transport_type {
                    TransportType::Udp => 0,
                    TransportType::Ble => 1,
                    TransportType::LoRa => 2,
                    TransportType::Serial => 3,
                    TransportType::Ax25 => 4,
                    TransportType::I2p => 5,
                    TransportType::Yggdrasil => 6,
                };
                let addr = Ipv6Addr::new(
                    0x2001, 0x0db8, type_code, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
                );
                SocketAddr::new(IpAddr::V6(addr), 0)
            }
        }
    }
}

impl fmt::Debug for TransportAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Udp(addr) => write!(f, "Udp({addr})"),
            Self::Ble {
                device_id,
                service_uuid,
            } => {
                write!(
                    f,
                    "Ble({:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                    device_id[0],
                    device_id[1],
                    device_id[2],
                    device_id[3],
                    device_id[4],
                    device_id[5]
                )?;
                if service_uuid.is_some() {
                    write!(f, ", custom_service")?;
                }
                write!(f, ")")
            }
            Self::LoRa {
                device_addr,
                params,
            } => {
                write!(
                    f,
                    "LoRa(0x{:02X}{:02X}{:02X}{:02X}, SF{}, {}kHz)",
                    device_addr[0],
                    device_addr[1],
                    device_addr[2],
                    device_addr[3],
                    params.spreading_factor,
                    params.bandwidth_khz
                )
            }
            Self::Serial { port } => write!(f, "Serial({port})"),
            Self::Ax25 { callsign, ssid } => write!(f, "Ax25({callsign}-{ssid})"),
            Self::I2p { .. } => write!(f, "I2p([destination])"),
            Self::Yggdrasil { address } => {
                write!(f, "Yggdrasil({:02x}{:02x}:...)", address[0], address[1])
            }
            Self::Broadcast { transport_type } => write!(f, "Broadcast({transport_type})"),
        }
    }
}

impl fmt::Display for TransportAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Udp(addr) => write!(f, "udp://{addr}"),
            Self::Ble { device_id, .. } => {
                write!(
                    f,
                    "ble://{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                    device_id[0],
                    device_id[1],
                    device_id[2],
                    device_id[3],
                    device_id[4],
                    device_id[5]
                )
            }
            Self::LoRa { device_addr, .. } => {
                write!(
                    f,
                    "lora://0x{:02X}{:02X}{:02X}{:02X}",
                    device_addr[0], device_addr[1], device_addr[2], device_addr[3]
                )
            }
            Self::Serial { port } => write!(f, "serial://{port}"),
            Self::Ax25 { callsign, ssid } => write!(f, "ax25://{callsign}-{ssid}"),
            Self::I2p { .. } => write!(f, "i2p://[destination]"),
            Self::Yggdrasil { address } => {
                // Display as IPv6-style address
                write!(
                    f,
                    "yggdrasil://{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
                    address[0],
                    address[1],
                    address[2],
                    address[3],
                    address[4],
                    address[5],
                    address[6],
                    address[7],
                    address[8],
                    address[9],
                    address[10],
                    address[11],
                    address[12],
                    address[13],
                    address[14],
                    address[15]
                )
            }
            Self::Broadcast { transport_type } => write!(f, "broadcast://{transport_type}"),
        }
    }
}

/// Convert a `SocketAddr` into a `TransportAddr::Udp`
///
/// This enables seamless migration from `SocketAddr` to `TransportAddr` in existing code.
///
/// # Example
///
/// ```rust
/// use ant_quic::transport::TransportAddr;
/// use std::net::SocketAddr;
///
/// // Direct conversion
/// let socket_addr: SocketAddr = "192.168.1.1:9000".parse().unwrap();
/// let transport_addr = TransportAddr::from(socket_addr);
/// assert_eq!(transport_addr.as_socket_addr(), Some(socket_addr));
///
/// // Using Into trait
/// let transport_addr: TransportAddr = "127.0.0.1:8080".parse::<SocketAddr>().unwrap().into();
/// assert!(transport_addr.as_socket_addr().is_some());
/// ```
impl From<SocketAddr> for TransportAddr {
    fn from(addr: SocketAddr) -> Self {
        Self::Udp(addr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_udp_addr() {
        let addr: SocketAddr = "192.168.1.1:9000".parse().unwrap();
        let transport_addr = TransportAddr::Udp(addr);

        assert_eq!(transport_addr.transport_type(), TransportType::Udp);
        assert_eq!(transport_addr.as_socket_addr(), Some(addr));
        assert!(!transport_addr.is_broadcast());
    }

    #[test]
    fn test_ble_addr() {
        let device_id = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC];
        let addr = TransportAddr::ble(device_id, None);

        assert_eq!(addr.transport_type(), TransportType::Ble);
        assert!(addr.as_socket_addr().is_none());

        let debug_str = format!("{addr:?}");
        assert!(debug_str.contains("12:34:56:78:9A:BC"));
    }

    #[test]
    fn test_lora_addr() {
        let device_addr = [0xDE, 0xAD, 0xBE, 0xEF];
        let addr = TransportAddr::lora(device_addr);

        assert_eq!(addr.transport_type(), TransportType::LoRa);

        if let TransportAddr::LoRa { params, .. } = &addr {
            assert_eq!(params.spreading_factor, 12);
            assert_eq!(params.bandwidth_khz, 125);
        }
    }

    #[test]
    fn test_lora_custom_params() {
        let device_addr = [0xDE, 0xAD, 0xBE, 0xEF];
        let params = LoRaParams {
            spreading_factor: 7,
            bandwidth_khz: 500,
            coding_rate: 8,
        };
        let addr = TransportAddr::lora_with_params(device_addr, params.clone());

        if let TransportAddr::LoRa { params: p, .. } = &addr {
            assert_eq!(p.spreading_factor, 7);
            assert_eq!(p.bandwidth_khz, 500);
            assert_eq!(p.coding_rate, 8);
        }
    }

    #[test]
    fn test_serial_addr() {
        let addr = TransportAddr::serial("/dev/ttyUSB0");
        assert_eq!(addr.transport_type(), TransportType::Serial);

        let display = format!("{addr}");
        assert_eq!(display, "serial:///dev/ttyUSB0");
    }

    #[test]
    fn test_ax25_addr() {
        let addr = TransportAddr::ax25("N0CALL", 5);
        assert_eq!(addr.transport_type(), TransportType::Ax25);

        if let TransportAddr::Ax25 { callsign, ssid } = &addr {
            assert_eq!(callsign, "N0CALL");
            assert_eq!(*ssid, 5);
        }
    }

    #[test]
    fn test_ax25_ssid_clamp() {
        let addr = TransportAddr::ax25("N0CALL", 20); // SSID > 15

        if let TransportAddr::Ax25 { ssid, .. } = &addr {
            assert_eq!(*ssid, 15); // Should be clamped
        }
    }

    #[test]
    fn test_broadcast_addr() {
        let addr = TransportAddr::broadcast(TransportType::Ble);

        assert!(addr.is_broadcast());
        assert_eq!(addr.transport_type(), TransportType::Ble);
    }

    #[test]
    fn test_from_socket_addr() {
        let socket_addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let transport_addr: TransportAddr = socket_addr.into();

        assert_eq!(transport_addr, TransportAddr::Udp(socket_addr));
    }

    #[test]
    fn test_from_socket_addr_ipv6() {
        // Test IPv6 socket address conversion
        let socket_addr: SocketAddr = "[::1]:9000".parse().unwrap();
        let transport_addr = TransportAddr::from(socket_addr);

        // Verify it's a UDP variant
        assert_eq!(transport_addr.transport_type(), TransportType::Udp);

        // Verify roundtrip conversion preserves IPv6 address
        assert_eq!(transport_addr.as_socket_addr(), Some(socket_addr));

        // Verify it's actually an IPv6 address
        match transport_addr.as_socket_addr().unwrap() {
            SocketAddr::V6(_) => {} // Expected
            SocketAddr::V4(_) => panic!("Expected IPv6 address, got IPv4"),
        }
    }

    #[test]
    fn test_socket_addr_conversion_pattern() {
        // Test the conversion pattern for seamless migration
        let socket_addr: SocketAddr = "192.168.1.100:5000".parse().unwrap();

        // From conversion
        let transport_addr = TransportAddr::from(socket_addr);
        assert_eq!(transport_addr.transport_type(), TransportType::Udp);

        // Round-trip conversion
        assert_eq!(transport_addr.as_socket_addr(), Some(socket_addr));

        // Into conversion
        let transport_addr2: TransportAddr = socket_addr.into();
        assert_eq!(transport_addr, transport_addr2);

        // Non-UDP addresses return None
        let ble = TransportAddr::ble([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF], None);
        assert_eq!(ble.as_socket_addr(), None);

        let serial = TransportAddr::serial("/dev/ttyUSB0");
        assert_eq!(serial.as_socket_addr(), None);
    }

    #[test]
    fn test_display_formats() {
        let udp_addr = TransportAddr::Udp("192.168.1.1:9000".parse().unwrap());
        assert_eq!(format!("{udp_addr}"), "udp://192.168.1.1:9000");

        let ble_addr = TransportAddr::ble([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF], None);
        assert_eq!(format!("{ble_addr}"), "ble://AA:BB:CC:DD:EE:FF");

        let serial_addr = TransportAddr::serial("COM3");
        assert_eq!(format!("{serial_addr}"), "serial://COM3");
    }

    #[test]
    fn test_transport_type_display() {
        assert_eq!(format!("{}", TransportType::Udp), "UDP");
        assert_eq!(format!("{}", TransportType::Ble), "BLE");
        assert_eq!(format!("{}", TransportType::LoRa), "LoRa");
        assert_eq!(format!("{}", TransportType::Serial), "Serial");
        assert_eq!(format!("{}", TransportType::Ax25), "AX.25");
        assert_eq!(format!("{}", TransportType::I2p), "I2P");
        assert_eq!(format!("{}", TransportType::Yggdrasil), "Yggdrasil");
    }
}
