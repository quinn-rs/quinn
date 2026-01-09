# Constrained Transport Support for ant-quic

## Research Document: LoRa, Serial, and Multi-Transport Architecture

**Status**: Research / Proposal  
**Author**: David Irvine, Saorsa Labs  
**Date**: January 2026  
**Version**: 0.1

---

## Executive Summary

This document explores extending ant-quic beyond UDP/IP to support constrained transports including LoRa, serial links, packet radio, Bluetooth Low Energy, and overlay networks. The goal is to create a truly universal P2P networking layer that maintains quantum-resistant security across all mediums while adapting protocol behaviour to match transport capabilities.

The approach draws heavily from the architectural lessons of the Reticulum Network Stack while preserving ant-quic's core differentiators: pure post-quantum cryptography (ML-KEM-768 + ML-DSA-65) and high-performance QUIC transport where bandwidth allows.

---

## Table of Contents

1. [Motivation](#1-motivation)
2. [Prior Art: Reticulum Network Stack](#2-prior-art-reticulum-network-stack)
3. [Architectural Vision](#3-architectural-vision)
4. [Transport Abstraction Design](#4-transport-abstraction-design)
5. [Protocol Engine Strategy](#5-protocol-engine-strategy)
6. [The PQC Challenge on Constrained Links](#6-the-pqc-challenge-on-constrained-links)
7. [Network Layer and Routing](#7-network-layer-and-routing)
8. [Gateway Architecture](#8-gateway-architecture)
9. [Message Protocol Design](#9-message-protocol-design)
10. [Drawbacks and Risks](#10-drawbacks-and-risks)
11. [Alternative Approaches Considered](#11-alternative-approaches-considered)
12. [Implementation Roadmap](#12-implementation-roadmap)
13. [Open Questions](#13-open-questions)
14. [References](#14-references)

---

## 1. Motivation

### 1.1 The Vision

ant-quic currently provides excellent P2P connectivity over UDP/IP networks with pure post-quantum cryptography. However, limiting ourselves to UDP excludes important use cases:

- **Off-grid communication**: Disaster response, remote areas, wilderness operations
- **Mesh networking**: Local community networks without Internet dependency
- **IoT and embedded**: Low-power devices with constrained connectivity
- **Censorship resistance**: Networks that don't depend on Internet infrastructure
- **Tactical applications**: Military, emergency services, field operations
- **Robotics**: Saorsa Labs' robotics work requires communication across diverse mediums

The goal is for any ant-quic peer to communicate with any other peer, regardless of whether they're connected via:

- Gigabit Ethernet
- Mobile data
- WiFi
- LoRa radio (sub-1 kbps)
- Serial cable
- Packet radio / AX.25
- Bluetooth Low Energy
- I2P or Tor overlay
- Yggdrasil mesh
- Any future transport

### 1.2 Design Principles

1. **Transport Agnosticism**: Higher layers should be unaware of underlying transport
2. **Single Identity**: One cryptographic identity (ML-DSA-65 keypair) works everywhere
3. **Adaptive Protocol**: Use full QUIC where capable, minimal protocol where constrained
4. **No Degradation**: Adding constrained transport support must not harm high-bandwidth performance
5. **PQC Non-Negotiable**: Quantum resistance is preserved even on constrained links
6. **Practical Deployment**: Must work with real hardware (RNode, TNC, serial cables)

### 1.3 Use Cases

| Use Case | Transports | Requirements |
|----------|------------|--------------|
| Urban mesh network | LoRa + WiFi + Internet | Gateway nodes, delay tolerance |
| Disaster response | LoRa + Packet radio | Store-and-forward, low power |
| Remote monitoring | LoRa + Satellite backhaul | Telemetry, infrequent updates |
| Secure messaging | Any available | E2E encryption, delivery confirmation |
| Robotics swarm | BLE + WiFi + LoRa | Low latency where possible, fallback |
| Censorship circumvention | I2P + Yggdrasil + Direct | Overlay routing, anonymity |

---

## 2. Prior Art: Reticulum Network Stack

### 2.1 Overview

[Reticulum](https://github.com/markqvist/Reticulum) is a cryptography-based networking stack designed for building resilient networks over any available medium. It successfully operates from 5 bps to 500 Mbps, making it an invaluable reference for this work.

The Reticulum ecosystem includes:

- **Reticulum**: Core networking stack (transport + routing)
- **LXMF**: Delay-tolerant messaging protocol
- **LXST**: Real-time voice/signals transport
- **Sideband**: Full-featured mobile/desktop client
- **Nomad Network**: Terminal-based client with BBS features
- **MeshChat**: Web-based client

### 2.2 What Reticulum Gets Right

#### 2.2.1 Interface Abstraction

Reticulum's `Interface` abstraction is elegant and proven. Every physical medium presents identical semantics to higher layers:

```python
# Reticulum interface pattern (simplified)
class Interface:
    def __init__(self, name, mtu, bandwidth):
        self.name = name
        self.mtu = mtu
        self.bandwidth = bandwidth
    
    def send(self, data, destination):
        # Transport-specific implementation
        pass
    
    def receive(self):
        # Transport-specific implementation
        pass
```

Interfaces implemented include: UDP, TCP, Serial, LoRa (RNode), AX.25 (TNC), I2P, Pipe, and custom.

#### 2.2.2 Cryptographic Addressing

Reticulum uses cryptographic addresses derived from public keys, eliminating dependency on DNS, IP allocation, or any external naming system:

- Address = SHA-256(Ed25519 public key)[..16] = 128 bits
- Works identically across all transports
- No configuration required for addressing

This mirrors ant-quic's PeerId model (SHA-256 of ML-DSA-65 public key).

#### 2.2.3 Delay-Tolerant Design

LXMF (Lightweight Extensible Message Format) handles:

- Store-and-forward via propagation nodes
- Multi-day message latency
- Delivery confirmations
- Paper messages (encrypted QR codes)

This is essential for constrained links where peers may not be simultaneously online.

#### 2.2.4 Voice Over Constrained Links

LXST achieves voice calls over LoRa using Codec2 at 700-3200 bps. This proves that real-time communication is possible even on severely constrained links.

#### 2.2.5 Practical Deployment

Reticulum has real-world users:

- Off-grid communities
- Amateur radio operators
- Privacy-conscious messaging
- Disaster preparedness

This validates that the multi-transport approach works in practice.

### 2.3 Where ant-quic Differs

| Aspect | Reticulum | ant-quic |
|--------|-----------|----------|
| Cryptography | Classical (X25519/Ed25519/AES-256) | Pure PQC (ML-KEM-768/ML-DSA-65) |
| Quantum resistance | None | NIST Level 3 |
| High-bandwidth protocol | Custom lightweight | Full QUIC (RFC 9000) |
| Stream multiplexing | Manual | Native QUIC streams |
| Congestion control | Basic | Full QUIC CC |
| NAT traversal | Via relays | Native QUIC extension |
| Implementation | Python | Rust |
| Performance focus | Constrained links | High bandwidth, with constrained support |

### 2.4 Why Not Just Use Reticulum?

Several factors make building on ant-quic preferable to adopting Reticulum:

1. **Post-Quantum Security**: Autonomi is a long-term project. Quantum computers will exist within its operational lifetime. Retrofitting PQC onto classical crypto is complex and error-prone.

2. **Performance Requirements**: Autonomi needs to move large amounts of data efficiently. QUIC's stream multiplexing, congestion control, and 0-RTT resumption are essential for high-throughput scenarios.

3. **Rust Ecosystem**: ant-quic integrates with the Rust-based Autonomi stack. A Python dependency would complicate deployment.

4. **Clean PQC Design**: Starting with PQC allows cleaner protocol design without hybrid complexity.

5. **QUIC Compatibility**: ant-quic can interoperate with standard QUIC implementations for specific use cases.

However, Reticulum's architectural patterns are excellent and should be adopted where applicable.

---

## 3. Architectural Vision

### 3.1 Layered Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                            APPLICATION                                   │
│                    (Autonomi, Communitas, Robotics)                     │
├─────────────────────────────────────────────────────────────────────────┤
│                          ant-quic API                                    │
│         P2pEndpoint, Streams, Datagrams, Connection Events              │
│                                                                          │
│   • Connect by PeerId (transport-agnostic)                              │
│   • Open bidirectional/unidirectional streams                           │
│   • Send/receive datagrams                                              │
│   • Subscribe to events                                                  │
├─────────────────────────────────────────────────────────────────────────┤
│                         NETWORK LAYER                                    │
│              Routing, Multi-path, Gateway Coordination                   │
│                                                                          │
│   • PeerId → TransportAddr resolution                                   │
│   • Multi-path bonding (use WiFi AND LoRa simultaneously)               │
│   • Gateway discovery and relay                                         │
│   • Reachability announcements                                          │
├─────────────────────────────────────────────────────────────────────────┤
│                        PROTOCOL ENGINES                                  │
│                                                                          │
│   ┌─────────────────────┐     ┌─────────────────────────────────────┐   │
│   │    QUIC Engine      │     │      Constrained Engine             │   │
│   │                     │     │                                     │   │
│   │  • Full RFC 9000    │     │  • Minimal headers (4-8 bytes)      │   │
│   │  • Quinn-based      │     │  • No congestion control            │   │
│   │  • Congestion ctrl  │     │  • ARQ for reliability              │   │
│   │  • Flow control     │     │  • Optimised for <1KB MTU           │   │
│   │  • 0-RTT resumption │     │  • Session key caching              │   │
│   └─────────────────────┘     └─────────────────────────────────────┘   │
│                                                                          │
├─────────────────────────────────────────────────────────────────────────┤
│                      TRANSPORT ABSTRACTION                               │
│                      (TransportProvider trait)                           │
│                                                                          │
│   ┌───────┬───────┬────────┬───────┬───────┬────────┬───────────────┐   │
│   │  UDP  │ LoRa  │ Serial │  BLE  │  I2P  │Yggdra- │  PacketRadio  │   │
│   │       │       │  HDLC  │       │       │  sil   │    AX.25      │   │
│   └───────┴───────┴────────┴───────┴───────┴────────┴───────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
```

### 3.2 Key Design Decisions

#### 3.2.1 Dual Protocol Engine

Rather than forcing one protocol to work everywhere, ant-quic will use two protocol engines:

1. **QUIC Engine**: Full RFC 9000 implementation via Quinn for capable transports
2. **Constrained Engine**: Minimal protocol for bandwidth/MTU-limited transports

The transport's capabilities determine which engine handles the connection.

#### 3.2.2 Unified Identity

A single ML-DSA-65 keypair provides identity across all transports:

```
PeerId = SHA-256(ML-DSA-65 public key) = 32 bytes
```

This PeerId is used for:
- Addressing peers on any transport
- Deriving session keys (via ML-KEM exchange)
- Signing announcements and messages
- Authenticating across transport boundaries

#### 3.2.3 Transport-Aware Routing

The network layer maintains routing information including:

- Which transports can reach which peers
- Quality metrics per route (RTT, loss, bandwidth)
- Gateway nodes that bridge transport domains

When sending to a peer reachable via multiple transports, the network layer selects the optimal route based on message requirements and transport capabilities.

---

## 4. Transport Abstraction Design

### 4.1 Core Traits

```rust
/// Transport-specific addressing
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum TransportAddr {
    /// UDP/IP - standard Internet
    Udp(std::net::SocketAddr),
    
    /// LoRa - device address + channel parameters
    LoRa {
        device_addr: [u8; 4],
        spreading_factor: u8,
        bandwidth_khz: u16,
    },
    
    /// Serial port - direct cable connection
    Serial { port: String },
    
    /// Bluetooth Low Energy
    Ble {
        device_id: [u8; 6],
        service_uuid: [u8; 16],
    },
    
    /// AX.25 Packet Radio
    Ax25 {
        callsign: String,
        ssid: u8,
    },
    
    /// I2P anonymous overlay
    I2p { destination: [u8; 387] },
    
    /// Yggdrasil mesh
    Yggdrasil { address: [u8; 16] },
    
    /// Broadcast on a transport
    Broadcast { transport_type: TransportType },
}

/// What a transport can do
#[derive(Clone, Debug)]
pub struct TransportCapabilities {
    /// Bits per second (5 for slow LoRa, 1_000_000_000 for gigabit)
    pub bandwidth_bps: u64,
    
    /// Maximum transmission unit in bytes
    pub mtu: usize,
    
    /// Expected round-trip time
    pub typical_rtt: Duration,
    
    /// Maximum RTT before link considered dead
    pub max_rtt: Duration,
    
    /// Half-duplex (can only send OR receive at once)
    pub half_duplex: bool,
    
    /// Supports broadcast/multicast
    pub broadcast: bool,
    
    /// Metered connection (cost per byte)
    pub metered: bool,
    
    /// Expected packet loss rate (0.0 - 1.0)
    pub loss_rate: f32,
    
    /// Power-constrained (battery operated)
    pub power_constrained: bool,
    
    /// Link layer provides acknowledgements
    pub link_layer_acks: bool,
    
    /// Estimated availability (0.0 - 1.0)
    pub availability: f32,
}

impl TransportCapabilities {
    /// Should we use full QUIC or constrained protocol?
    pub fn supports_full_quic(&self) -> bool {
        self.bandwidth_bps >= 10_000 
            && self.mtu >= 1200 
            && self.typical_rtt < Duration::from_secs(2)
    }
}

/// Core transport abstraction
#[async_trait]
pub trait TransportProvider: Send + Sync + 'static {
    /// Human-readable name
    fn name(&self) -> &str;
    
    /// Transport type identifier
    fn transport_type(&self) -> TransportType;
    
    /// What can this transport do?
    fn capabilities(&self) -> &TransportCapabilities;
    
    /// Our address on this transport
    fn local_addr(&self) -> Option<TransportAddr>;
    
    /// Send a datagram
    async fn send(&self, data: &[u8], dest: &TransportAddr) -> Result<(), TransportError>;
    
    /// Receive channel
    fn inbound(&self) -> mpsc::Receiver<InboundDatagram>;
    
    /// Is this transport currently online?
    fn is_online(&self) -> bool;
    
    /// Graceful shutdown
    async fn shutdown(&self) -> Result<(), TransportError>;
    
    /// Broadcast (if supported)
    async fn broadcast(&self, data: &[u8]) -> Result<(), TransportError>;
    
    /// Current link quality to peer (if measurable)
    async fn link_quality(&self, peer: &TransportAddr) -> Option<LinkQuality>;
}
```

### 4.2 Transport Capability Profiles

```rust
impl TransportCapabilities {
    /// High-bandwidth, low-latency (UDP, Ethernet)
    pub fn broadband() -> Self {
        Self {
            bandwidth_bps: 100_000_000,  // 100 Mbps
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
    
    /// LoRa long-range radio (SF12, 125kHz)
    pub fn lora_long_range() -> Self {
        Self {
            bandwidth_bps: 293,          // ~300 bps
            mtu: 222,                    // Max LoRa payload
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
    
    /// LoRa short-range, higher speed (SF7, 500kHz)
    pub fn lora_fast() -> Self {
        Self {
            bandwidth_bps: 21_875,       // ~22 kbps
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
    
    /// Serial/UART direct connection (115200 baud)
    pub fn serial_115200() -> Self {
        Self {
            bandwidth_bps: 115_200,
            mtu: 1024,
            typical_rtt: Duration::from_millis(50),
            max_rtt: Duration::from_secs(5),
            half_duplex: true,
            broadcast: false,            // Point-to-point
            metered: false,
            loss_rate: 0.001,
            power_constrained: false,
            link_layer_acks: false,
            availability: 1.0,           // Cable doesn't go down
        }
    }
    
    /// Packet radio (1200 baud AFSK)
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
            link_layer_acks: true,       // AX.25 has ARQ
            availability: 0.80,
        }
    }
    
    /// Bluetooth Low Energy
    pub fn ble() -> Self {
        Self {
            bandwidth_bps: 125_000,      // BLE 4.2 typical
            mtu: 244,                    // BLE MTU
            typical_rtt: Duration::from_millis(100),
            max_rtt: Duration::from_secs(5),
            half_duplex: false,
            broadcast: true,             // BLE advertising
            metered: false,
            loss_rate: 0.02,
            power_constrained: true,
            link_layer_acks: true,
            availability: 0.95,
        }
    }
    
    /// I2P overlay network
    pub fn i2p() -> Self {
        Self {
            bandwidth_bps: 50_000,       // Highly variable
            mtu: 61_440,                 // I2P tunnel MTU
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
}
```

### 4.3 Example Transport Implementations

#### 4.3.1 UDP Transport

```rust
pub struct UdpTransport {
    socket: UdpSocket,
    capabilities: TransportCapabilities,
    inbound_tx: mpsc::Sender<InboundDatagram>,
}

impl UdpTransport {
    pub async fn bind(addr: SocketAddr) -> Result<Self> {
        let socket = UdpSocket::bind(addr).await?;
        let (tx, _) = mpsc::channel(1024);
        
        let transport = Self {
            socket,
            capabilities: TransportCapabilities::broadband(),
            inbound_tx: tx,
        };
        
        transport.spawn_recv_loop();
        Ok(transport)
    }
}

#[async_trait]
impl TransportProvider for UdpTransport {
    fn name(&self) -> &str { "UDP" }
    fn transport_type(&self) -> TransportType { TransportType::Udp }
    fn capabilities(&self) -> &TransportCapabilities { &self.capabilities }
    
    async fn send(&self, data: &[u8], dest: &TransportAddr) -> Result<()> {
        match dest {
            TransportAddr::Udp(addr) => {
                self.socket.send_to(data, addr).await?;
                Ok(())
            }
            _ => Err(TransportError::AddressMismatch),
        }
    }
    
    // ... remaining implementation
}
```

#### 4.3.2 LoRa Transport (RNode)

```rust
pub struct LoRaTransport {
    serial: tokio_serial::SerialStream,
    device_addr: [u8; 4],
    config: LoRaConfig,
    capabilities: TransportCapabilities,
    inbound_tx: mpsc::Sender<InboundDatagram>,
}

pub struct LoRaConfig {
    pub spreading_factor: u8,   // 7-12
    pub bandwidth_khz: u16,     // 125, 250, 500
    pub coding_rate: u8,        // 5-8 (4/5 to 4/8)
    pub frequency_mhz: f32,     // e.g., 868.1
    pub tx_power_dbm: i8,       // -4 to +20
}

impl LoRaTransport {
    pub async fn new(
        serial_port: &str,
        device_addr: [u8; 4],
        config: LoRaConfig,
    ) -> Result<Self> {
        let serial = tokio_serial::new(serial_port, 115200)
            .open_native_async()?;
        
        // Calculate actual bandwidth from LoRa parameters
        let symbol_rate = config.bandwidth_khz as f32 * 1000.0 
            / (1 << config.spreading_factor) as f32;
        let bit_rate = symbol_rate * config.spreading_factor as f32 
            * (4.0 / config.coding_rate as f32);
        
        let capabilities = TransportCapabilities {
            bandwidth_bps: bit_rate as u64,
            mtu: 222,
            typical_rtt: Duration::from_millis(
                (1000.0 * 222.0 * 8.0 / bit_rate) as u64 * 2 + 100
            ),
            // ... remaining fields
        };
        
        // ... setup KISS framing, spawn receive loop
        
        Ok(transport)
    }
}

#[async_trait]
impl TransportProvider for LoRaTransport {
    fn name(&self) -> &str { "LoRa" }
    fn transport_type(&self) -> TransportType { TransportType::LoRa }
    
    async fn send(&self, data: &[u8], dest: &TransportAddr) -> Result<()> {
        if data.len() > self.capabilities.mtu {
            return Err(TransportError::MessageTooLarge {
                size: data.len(),
                mtu: self.capabilities.mtu,
            });
        }
        
        // Frame as KISS and send to RNode
        let kiss_frame = self.frame_kiss(data, dest)?;
        self.serial.write_all(&kiss_frame).await?;
        
        Ok(())
    }
    
    async fn link_quality(&self, _peer: &TransportAddr) -> Option<LinkQuality> {
        // RNode provides RSSI/SNR in received frames
        Some(LinkQuality {
            rssi: self.last_rssi,
            snr: self.last_snr,
            hop_count: None,
        })
    }
    
    // ... remaining implementation
}
```

#### 4.3.3 Serial Transport (HDLC Framing)

```rust
pub struct SerialTransport {
    serial: tokio_serial::SerialStream,
    capabilities: TransportCapabilities,
    inbound_tx: mpsc::Sender<InboundDatagram>,
}

impl SerialTransport {
    pub async fn new(port: &str, baud: u32) -> Result<Self> {
        let serial = tokio_serial::new(port, baud)
            .open_native_async()?;
        
        let capabilities = TransportCapabilities {
            bandwidth_bps: baud as u64,
            mtu: 1024,
            typical_rtt: Duration::from_millis(50),
            max_rtt: Duration::from_secs(5),
            half_duplex: true,
            broadcast: false,  // Point-to-point
            // ...
        };
        
        Ok(transport)
    }
    
    /// HDLC-like framing for reliable serial transport
    fn frame_hdlc(&self, data: &[u8]) -> Vec<u8> {
        let mut frame = vec![0x7E];  // Start flag
        
        // Escape special bytes
        for &byte in data {
            match byte {
                0x7E => frame.extend_from_slice(&[0x7D, 0x5E]),
                0x7D => frame.extend_from_slice(&[0x7D, 0x5D]),
                _ => frame.push(byte),
            }
        }
        
        // CRC-16
        let crc = crc16::checksum_x25(data);
        frame.push((crc & 0xFF) as u8);
        frame.push((crc >> 8) as u8);
        
        frame.push(0x7E);  // End flag
        frame
    }
}
```

---

## 5. Protocol Engine Strategy

### 5.1 Dual Engine Approach

```rust
/// Protocol engine selection based on transport capabilities
pub enum ProtocolEngine {
    /// Full QUIC for high-bandwidth, low-latency links
    Quic(QuicEngine),
    
    /// Minimal protocol for constrained links
    Constrained(ConstrainedEngine),
}

impl ProtocolEngine {
    pub fn for_transport(caps: &TransportCapabilities) -> Self {
        if caps.supports_full_quic() {
            Self::Quic(QuicEngine::new())
        } else {
            Self::Constrained(ConstrainedEngine::new())
        }
    }
}
```

### 5.2 QUIC Engine

The QUIC engine wraps the existing Quinn-based implementation:

- Full RFC 9000 compliance
- ML-KEM-768 key exchange
- ML-DSA-65 authentication
- Stream multiplexing
- Congestion control
- 0-RTT resumption
- NAT traversal extensions

Used when: `bandwidth >= 10 kbps && mtu >= 1200 && rtt < 2s`

### 5.3 Constrained Protocol Engine

A minimal protocol designed for low-bandwidth, high-latency links:

#### 5.3.1 Packet Header (4 bytes base)

```
┌─────────┬──────────┬─────────────┬────────────┐
│  Type   │  Flags   │  Seq/Frag   │  Session   │
│ (4 bit) │ (4 bit)  │   (8 bit)   │  (16 bit)  │
└─────────┴──────────┴─────────────┴────────────┘
```

Compare to QUIC's minimum header of ~20 bytes.

#### 5.3.2 Packet Types

```rust
#[repr(u8)]
pub enum ConstrainedPacketType {
    /// Initial handshake (fragmented ML-KEM)
    HandshakeInit = 0x01,
    
    /// Handshake response
    HandshakeResp = 0x02,
    
    /// Handshake complete
    HandshakeDone = 0x03,
    
    /// Encrypted data
    Data = 0x10,
    
    /// Acknowledgement
    Ack = 0x11,
    
    /// Session resumption
    Resume = 0x20,
    
    /// Keep-alive
    Ping = 0x30,
    
    /// Route announcement
    Announce = 0x40,
}
```

#### 5.3.3 Features

- **No congestion control**: Link layer handles flow, or we accept loss
- **Simple ARQ**: Stop-and-wait or sliding window based on link
- **Session caching**: Avoid repeated PQC handshakes
- **Fragmentation**: Split large messages across multiple packets
- **Piggyback ACKs**: Reduce overhead by combining with data

---

## 6. The PQC Challenge on Constrained Links

### 6.1 The Problem

Post-quantum cryptographic primitives have significantly larger key and signature sizes than classical alternatives:

| Algorithm | Public Key | Ciphertext/Signature |
|-----------|------------|----------------------|
| **ML-KEM-768** | 1,184 bytes | 1,088 bytes |
| **ML-DSA-65** | 1,952 bytes | 3,293 bytes |
| **X25519** (classical) | 32 bytes | 32 bytes |
| **Ed25519** (classical) | 32 bytes | 64 bytes |

A full ant-quic PQC handshake requires transmitting:
- Initiator → Responder: ML-KEM public key (1,184) + ML-DSA signature (~3,293) ≈ **4,477 bytes**
- Responder → Initiator: ML-KEM ciphertext (1,088) + ML-DSA signature (~3,293) ≈ **4,381 bytes**
- Total: **~8,858 bytes**

On LoRa at 300 bps with 222-byte MTU:
- Fragments needed: ~40 packets
- Time to transmit: **~4 minutes** for handshake alone

Compare to Reticulum (X25519/Ed25519):
- Full handshake: ~200 bytes
- Time on same link: **~5 seconds**

### 6.2 Mitigation Strategies

#### 6.2.1 Aggressive Session Caching

Cache session keys for extended periods to avoid repeated handshakes:

```rust
pub struct SessionCache {
    sessions: HashMap<PeerId, CachedSession>,
    max_age: Duration,    // 24+ hours
    max_idle: Duration,   // 1+ hours
}

pub struct CachedSession {
    peer_id: PeerId,
    session_key: [u8; 32],
    local_session_id: u16,
    remote_session_id: u16,
    created: Instant,
    last_active: Instant,
}
```

Once a session is established, subsequent communication uses the cached symmetric key.

#### 6.2.2 Session Resumption Tokens

Instead of full handshake, send a 32-byte token:

```rust
pub struct ResumeToken {
    peer_id_hash: [u8; 16],   // First 16 bytes of PeerId
    session_hash: [u8; 16],    // Hash of session key + nonce
}
// Total: 32 bytes vs 8,858 bytes
```

If the peer has the session cached, communication continues immediately.

#### 6.2.3 Opportunistic Key Pre-Distribution

When high-bandwidth connectivity is available, push public keys to propagation nodes:

```rust
pub struct KeyAnnounce {
    peer_id: PeerId,
    ml_kem_public: [u8; 1184],
    ml_dsa_public: [u8; 1952],
    signature: [u8; 3293],
    valid_until: u64,
}

// Pre-distribute via Internet when available
async fn predistribute_keys(endpoint: &P2pEndpoint, prop_nodes: &[PeerId]) {
    let announce = KeyAnnounce::new(endpoint);
    for node in prop_nodes {
        endpoint.store_at(node, announce.clone()).await;
    }
}

// Later, constrained peer fetches cached key
async fn fetch_peer_key(prop_node: &PeerId, target: &PeerId) -> Option<KeyAnnounce> {
    // Single request to propagation node
}
```

#### 6.2.4 ML-KEM-512 for Constrained-Only Links

For peers that will *only* communicate over constrained links, consider ML-KEM-512:

| Variant | Security Level | Public Key | Ciphertext |
|---------|---------------|------------|------------|
| ML-KEM-768 | NIST Level 3 (192-bit) | 1,184 bytes | 1,088 bytes |
| ML-KEM-512 | NIST Level 1 (128-bit) | 800 bytes | 768 bytes |

ML-KEM-512 saves ~600 bytes per handshake while maintaining quantum resistance.

```rust
pub enum KemVariant {
    MlKem768,  // Default, NIST Level 3
    MlKem512,  // Constrained option, NIST Level 1
}

impl TransportCapabilities {
    pub fn recommended_kem(&self) -> KemVariant {
        if self.bandwidth_bps < 1000 {
            KemVariant::MlKem512
        } else {
            KemVariant::MlKem768
        }
    }
}
```

#### 6.2.5 Fragmented Progressive Handshake

Don't block on complete key reception:

```rust
pub struct ProgressiveHandshake {
    fragments_received: BitVec,
    partial_key: Vec<u8>,
    confidence: f32,
    
    // After receiving enough fragments, can start
    // limited communication with partial security
}

impl ProgressiveHandshake {
    /// Start with partial key exchange for time-critical messages
    pub fn partial_security_available(&self) -> bool {
        self.confidence >= 0.8  // 80% of fragments received
    }
}
```

#### 6.2.6 Handshake Time Budget

| Transport | Time Budget | Strategy |
|-----------|-------------|----------|
| LoRa 300 bps | 5 minutes acceptable | Full ML-KEM-768, fragment |
| LoRa 22 kbps | 30 seconds acceptable | Full ML-KEM-768 |
| Packet radio | 2 minutes acceptable | ML-KEM-512 or cached |
| Serial 115k | 1 second acceptable | Full ML-KEM-768 |
| BLE | 2 seconds acceptable | Full ML-KEM-768 |

### 6.3 Recommended Approach

1. **Default to ML-KEM-768** for all transports (maintain NIST Level 3)
2. **Aggressive session caching** with 24+ hour validity
3. **Session resumption tokens** for subsequent connections
4. **Key pre-distribution** via propagation nodes when bandwidth available
5. **Accept longer handshakes** on constrained links as trade-off for quantum resistance
6. **Optional ML-KEM-512** for constrained-only deployments (user choice)

---

## 7. Network Layer and Routing

### 7.1 Routing Table Design

```rust
pub struct RoutingTable {
    /// Known routes to peers
    routes: HashMap<PeerId, Route>,
    
    /// Available local transports
    local_transports: Vec<Arc<dyn TransportProvider>>,
    
    /// Route announcement sequence number
    sequence: AtomicU32,
}

pub struct Route {
    pub peer_id: PeerId,
    pub direct_addrs: Vec<TransportAddr>,
    pub gateways: Vec<GatewayRoute>,
    pub last_seen: Instant,
    pub metrics: RouteMetrics,
}

pub struct GatewayRoute {
    pub via: PeerId,
    pub gateway_transport: TransportType,
    pub hops: u8,
    pub announced: Instant,
}

pub struct RouteMetrics {
    pub min_rtt: Duration,
    pub avg_rtt: Duration,
    pub loss_rate: f32,
    pub bandwidth: Option<u64>,
}
```

### 7.2 Route Selection

```rust
impl RoutingTable {
    pub fn select_route(&self, dest: &PeerId, requirements: &RouteRequirements) -> Option<SelectedRoute> {
        let route = self.routes.get(dest)?;
        
        // Try direct routes first
        for addr in &route.direct_addrs {
            let transport = self.transport_for_addr(addr)?;
            let caps = transport.capabilities();
            
            if requirements.satisfied_by(caps) {
                return Some(SelectedRoute::Direct { 
                    addr: addr.clone(),
                    transport: transport.clone(),
                });
            }
        }
        
        // Fall back to gateway routes
        for gw in &route.gateways {
            if gw.hops < requirements.max_hops {
                return Some(SelectedRoute::Gateway {
                    via: gw.via,
                    hops: gw.hops,
                });
            }
        }
        
        None
    }
}

pub struct RouteRequirements {
    pub min_bandwidth: Option<u64>,
    pub max_latency: Option<Duration>,
    pub max_hops: u8,
    pub require_low_loss: bool,
}
```

### 7.3 Route Announcements

```rust
pub struct RouteAnnouncement {
    /// Announcing peer
    pub from: PeerId,
    
    /// Peers reachable through this node
    pub reachable: Vec<ReachableEntry>,
    
    /// Sequence number (loop prevention)
    pub sequence: u32,
    
    /// TTL (decrement on forward)
    pub ttl: u8,
    
    /// Signature
    pub signature: MlDsa65Signature,
}

pub struct ReachableEntry {
    pub peer_id: PeerId,
    pub hops: u8,
    pub transport_type: TransportType,
    pub metrics: Option<RouteMetrics>,
}
```

### 7.4 Multi-Path Support

When a peer is reachable via multiple transports, ant-quic can:

1. **Select best path** based on requirements
2. **Fail over** when primary path degrades
3. **Bond paths** for increased throughput (future)
4. **Use different paths** for different traffic types

---

## 8. Gateway Architecture

### 8.1 Gateway Node Concept

Gateway nodes bridge transport domains, enabling communication between peers on different networks:

```
┌─────────────────┐                    ┌─────────────────┐
│   LoRa Mesh     │                    │   Internet      │
│                 │                    │                 │
│  Device A ───►  │    Gateway Node    │  ◄─── Device C  │
│  Device B ───►  │◄─────────────────►│  ◄─── Device D  │
│                 │                    │                 │
│  (Constrained)  │  LoRa + UDP/IP     │  (Broadband)    │
└─────────────────┘                    └─────────────────┘
```

### 8.2 Gateway Implementation

```rust
pub struct GatewayNode {
    peer_id: PeerId,
    keypair: MlDsa65KeyPair,
    
    /// All available transports
    transports: Vec<Arc<dyn TransportProvider>>,
    
    /// Protocol engines per transport class
    engines: HashMap<TransportType, Arc<dyn ProtocolEngine>>,
    
    /// Unified routing table
    routing: Arc<RwLock<RoutingTable>>,
    
    /// Message relay queue
    relay_queue: mpsc::Sender<RelayRequest>,
}

impl GatewayNode {
    pub async fn new(
        keypair: MlDsa65KeyPair,
        transports: Vec<Arc<dyn TransportProvider>>,
    ) -> Result<Self> {
        let peer_id = PeerId::from_public_key(&keypair.public);
        let mut engines = HashMap::new();
        
        for transport in &transports {
            let caps = transport.capabilities();
            let engine: Arc<dyn ProtocolEngine> = if caps.supports_full_quic() {
                Arc::new(QuicEngine::new(transport.clone(), keypair.clone()).await?)
            } else {
                Arc::new(ConstrainedEngine::new(transport.clone(), keypair.clone()).await?)
            };
            engines.insert(transport.transport_type(), engine);
        }
        
        // Start relay worker
        let (relay_tx, relay_rx) = mpsc::channel(1024);
        tokio::spawn(Self::relay_worker(relay_rx, engines.clone(), routing.clone()));
        
        Ok(Self { peer_id, keypair, transports, engines, routing, relay_queue: relay_tx })
    }
    
    /// Handle message that needs relaying
    async fn relay_message(&self, from: TransportType, to: PeerId, data: Vec<u8>) -> Result<()> {
        let route = self.routing.read().await.select_route(&to, &RouteRequirements::default())
            .ok_or(GatewayError::NoRoute)?;
        
        match route {
            SelectedRoute::Direct { addr, transport } => {
                let engine = self.engines.get(&addr.transport_type())
                    .ok_or(GatewayError::NoEngine)?;
                engine.send_datagram(to, data).await?;
            }
            SelectedRoute::Gateway { via, .. } => {
                // Forward to next gateway
                self.relay_queue.send(RelayRequest { to: via, data }).await?;
            }
        }
        
        Ok(())
    }
    
    /// Announce our routing capabilities
    async fn announce_routes(&self) {
        let reachable = self.collect_reachable_peers().await;
        
        let announcement = RouteAnnouncement {
            from: self.peer_id,
            reachable,
            sequence: self.next_sequence(),
            ttl: 8,
            signature: self.sign_announcement(),
        };
        
        // Broadcast on all transports
        for transport in &self.transports {
            if transport.capabilities().broadcast {
                let _ = transport.broadcast(&announcement.encode()).await;
            }
        }
    }
}
```

### 8.3 End-to-End Encryption Through Gateways

Gateways can operate in two modes:

#### 8.3.1 Transparent Relay (Recommended)

Gateway sees only encrypted blobs, cannot read content:

```
Device A ──► [E2E Encrypted Message] ──► Gateway ──► [E2E Encrypted Message] ──► Device C
                                            │
                                    (Cannot decrypt)
```

Requires pre-shared or pre-exchanged keys between A and C.

#### 8.3.2 Hop-by-Hop Encryption

Gateway decrypts/re-encrypts at each hop:

```
Device A ──► [Encrypted for Gateway] ──► Gateway ──► [Encrypted for Device C] ──► Device C
                                            │
                                    (Decrypts & re-encrypts)
```

Simpler key management but gateway sees plaintext.

---

## 9. Message Protocol Design

### 9.1 Requirements

Drawing from LXMF's success:

1. **Delay tolerance**: Messages may take hours/days to deliver
2. **Store-and-forward**: Propagation nodes hold messages for offline peers
3. **Delivery confirmation**: Sender knows when message arrived
4. **Encryption**: End-to-end, even through relays
5. **Offline composition**: Create messages without network
6. **Paper messaging**: QR codes for air-gapped exchange

### 9.2 Message Format

```rust
pub struct Message {
    /// Unique message ID
    pub id: [u8; 16],
    
    /// Sender's PeerId
    pub from: PeerId,
    
    /// Recipient's PeerId  
    pub to: PeerId,
    
    /// Message timestamp
    pub timestamp: u64,
    
    /// Time-to-live in seconds
    pub ttl: u32,
    
    /// Encrypted payload
    pub payload: EncryptedPayload,
    
    /// Sender's signature over (id, from, to, timestamp, ttl, payload_hash)
    pub signature: MlDsa65Signature,
}

pub struct EncryptedPayload {
    /// ML-KEM encapsulated key (for first message to recipient)
    pub encapsulation: Option<[u8; 1088]>,
    
    /// AES-256-GCM nonce
    pub nonce: [u8; 12],
    
    /// Encrypted content
    pub ciphertext: Vec<u8>,
    
    /// Authentication tag
    pub tag: [u8; 16],
}

pub struct MessageContent {
    /// Content type (text, file, voice, telemetry, etc.)
    pub content_type: ContentType,
    
    /// Actual content
    pub data: Vec<u8>,
    
    /// Optional: request delivery confirmation
    pub request_confirmation: bool,
}
```

### 9.3 Propagation Nodes

```rust
#[async_trait]
pub trait PropagationNode {
    /// Store message for later delivery
    async fn store(&self, message: Message) -> Result<()>;
    
    /// Retrieve messages for a peer
    async fn retrieve(&self, for_peer: &PeerId, limit: usize) -> Vec<Message>;
    
    /// Sync with another propagation node
    async fn sync(&self, other: &dyn PropagationNode) -> SyncResult;
    
    /// Announce stored message availability
    async fn announce_available(&self, peer: &PeerId);
}
```

### 9.4 Paper Messages (QR Codes)

For air-gapped exchange, messages can be encoded as QR codes:

```rust
impl Message {
    /// Encode as URL for QR code
    pub fn to_paper_url(&self) -> String {
        let encoded = base64_url::encode(&self.serialize());
        format!("ant://{}", encoded)
    }
    
    /// Decode from scanned QR
    pub fn from_paper_url(url: &str) -> Result<Self> {
        let encoded = url.strip_prefix("ant://")
            .ok_or(MessageError::InvalidUrl)?;
        let bytes = base64_url::decode(encoded)?;
        Self::deserialize(&bytes)
    }
}
```

---

## 10. Drawbacks and Risks

### 10.1 Technical Risks

#### 10.1.1 PQC Overhead on Constrained Links

**Risk**: ML-KEM-768/ML-DSA-65 sizes make initial handshake prohibitively slow on LoRa.

**Severity**: High

**Mitigation**: Aggressive session caching, pre-distribution, optional ML-KEM-512.

**Residual Risk**: First contact over LoRa will always be slow (~3-5 minutes).

#### 10.1.2 Protocol Complexity

**Risk**: Maintaining two protocol engines (QUIC + Constrained) doubles testing surface.

**Severity**: Medium

**Mitigation**: Shared cryptographic core, extensive integration testing.

**Residual Risk**: Edge cases at protocol boundaries.

#### 10.1.3 Gateway Security

**Risk**: Gateways become high-value targets and potential surveillance points.

**Severity**: Medium

**Mitigation**: End-to-end encryption through gateways, gateway diversity.

**Residual Risk**: Traffic analysis possible at gateways.

#### 10.1.4 Transport Implementation Quality

**Risk**: Each transport (LoRa, BLE, Serial) requires careful implementation.

**Severity**: Medium

**Mitigation**: Start with well-understood transports (Serial, then LoRa).

**Residual Risk**: Hardware-specific bugs.

### 10.2 Operational Risks

#### 10.2.1 Network Fragmentation

**Risk**: Different transport domains may become isolated.

**Severity**: Medium

**Mitigation**: Multiple gateway nodes, propagation node network.

**Residual Risk**: Extended isolation during outages.

#### 10.2.2 Key Management Complexity

**Risk**: Pre-distribution, caching, and cross-transport keys add complexity.

**Severity**: Medium

**Mitigation**: Clear key lifecycle, automatic rotation.

**Residual Risk**: User confusion about key states.

#### 10.2.3 Regulatory Compliance

**Risk**: LoRa and packet radio have regulatory requirements per jurisdiction.

**Severity**: Low (technical), Medium (legal)

**Mitigation**: Configurable TX power, frequency, duty cycle.

**Residual Risk**: User responsibility for compliance.

### 10.3 Strategic Risks

#### 10.3.1 Reticulum Competition

**Risk**: Reticulum already has mindshare in constrained networking space.

**Severity**: Low

**Mitigation**: Focus on PQC as differentiator, don't compete directly.

**Note**: Reticulum users who need PQC are our target audience.

#### 10.3.2 Scope Creep

**Risk**: Building a complete Reticulum replacement is massive scope.

**Severity**: High

**Mitigation**: Phased approach, MVP focus, clear milestones.

**Residual Risk**: Resource constraints.

#### 10.3.3 Maintenance Burden

**Risk**: Supporting many transports creates ongoing maintenance.

**Severity**: Medium

**Mitigation**: Community contributions, modular architecture.

**Residual Risk**: Long-term sustainability.

### 10.4 Risk Summary Matrix

| Risk | Likelihood | Impact | Priority |
|------|------------|--------|----------|
| PQC overhead on constrained | High | Medium | P1 |
| Protocol complexity | Medium | Medium | P2 |
| Gateway security | Low | High | P2 |
| Transport implementation | Medium | Medium | P2 |
| Network fragmentation | Low | Medium | P3 |
| Key management | Medium | Low | P3 |
| Regulatory compliance | Low | Low | P4 |
| Scope creep | High | High | P1 |

---

## 11. Alternative Approaches Considered

### 11.1 Reticulum Integration

**Approach**: Make ant-quic a Reticulum-compatible interface.

**Pros**:
- Instant ecosystem (Sideband, Nomad Network, etc.)
- Proven transport abstraction
- Active community

**Cons**:
- Classical cryptography on other links
- Python dependency
- Constrained by Reticulum protocol decisions

**Decision**: Learn from Reticulum, don't integrate directly. The PQC requirement is non-negotiable.

### 11.2 QUIC-Only with Adaptation

**Approach**: Force QUIC protocol everywhere with transport-specific tuning.

**Pros**:
- Single protocol engine
- Less complexity

**Cons**:
- QUIC assumptions don't fit constrained links
- Impossible to get reasonable performance on LoRa
- Congestion control inappropriate for half-duplex

**Decision**: Rejected. QUIC is fundamentally unsuited for <1kbps links.

### 11.3 Tunneling Over Reticulum

**Approach**: Use Reticulum as transport for ant-quic traffic.

**Pros**:
- Leverage Reticulum's transport support
- Relatively simple integration

**Cons**:
- Double encryption overhead
- Latency penalty
- Dependency on external project

**Decision**: Not pursued, but could be a future option for interop.

### 11.4 libp2p Integration

**Approach**: Use libp2p for transport abstraction.

**Pros**:
- Mature project
- Many transports available

**Cons**:
- No PQC support currently
- Heavy dependency
- Different architectural assumptions

**Decision**: Rejected. PQC requirement and architectural mismatch.

---

## 12. Implementation Roadmap

### Phase 1: Transport Abstraction Foundation (4-6 weeks)

**Goals**:
- Define `TransportProvider` trait
- Implement `UdpTransport` wrapping current behavior
- Refactor Quinn integration to use trait
- All existing tests pass unchanged

**Deliverables**:
- `ant-quic-transport` crate
- `UdpTransport` implementation
- Updated Quinn integration
- Test suite

### Phase 2: Serial Transport (3-4 weeks)

**Goals**:
- Implement HDLC framing
- Basic serial transport
- Test with two machines over null modem
- Prove abstraction works

**Deliverables**:
- `SerialTransport` implementation
- HDLC framing module
- Integration tests
- Documentation

### Phase 3: Constrained Protocol Design (4-6 weeks)

**Goals**:
- Design minimal packet format
- Implement handshake fragmentation
- Session key caching
- Simple ARQ reliability

**Deliverables**:
- Protocol specification document
- `ConstrainedEngine` implementation
- Session cache module
- Fragmentation module

### Phase 4: LoRa Transport (4-5 weeks)

**Goals**:
- RNode/KISS integration
- LoRa transport implementation
- Test constrained protocol over LoRa
- Benchmark handshake times

**Deliverables**:
- `LoRaTransport` implementation
- RNode driver
- Performance benchmarks
- Real-world testing report

### Phase 5: Network Layer (5-6 weeks)

**Goals**:
- Routing table design
- Route announcements
- Gateway logic
- Multi-transport peer discovery

**Deliverables**:
- `ant-quic-routing` crate
- Gateway node implementation
- Route announcement protocol
- Multi-path selection

### Phase 6: Message Protocol (4-5 weeks)

**Goals**:
- Delay-tolerant message format
- Propagation node design
- Delivery confirmations
- Paper messaging support

**Deliverables**:
- Message protocol specification
- Basic propagation node
- QR code encoding
- Integration tests

### Phase 7: Integration & Polish (3-4 weeks)

**Goals**:
- Unified `P2pEndpoint` API
- Documentation
- Example applications
- Performance optimization

**Deliverables**:
- Updated API
- Comprehensive documentation
- Example apps
- Release v0.3.0

### Timeline Summary

| Phase | Duration | Dependencies |
|-------|----------|--------------|
| 1. Transport Abstraction | 4-6 weeks | None |
| 2. Serial Transport | 3-4 weeks | Phase 1 |
| 3. Constrained Protocol | 4-6 weeks | Phase 1 |
| 4. LoRa Transport | 4-5 weeks | Phase 2, 3 |
| 5. Network Layer | 5-6 weeks | Phase 3 |
| 6. Message Protocol | 4-5 weeks | Phase 5 |
| 7. Integration | 3-4 weeks | All |

**Total**: ~28-36 weeks (7-9 months)

---

## 13. Open Questions

### 13.1 Identity Model

**Question**: Should there be transport-specific sub-identities, or one ML-DSA-65 keypair everywhere?

**Current Thinking**: Single identity everywhere for simplicity.

**Considerations**:
- Linkability across transports
- Key compromise impact
- Operational complexity

### 13.2 Gateway Trust Model

**Question**: Should gateways see plaintext (hop-by-hop) or only encrypted blobs (E2E)?

**Current Thinking**: E2E encryption through gateways preferred.

**Considerations**:
- Key exchange complexity for first contact
- Gateway operator trust
- Traffic analysis resistance

### 13.3 ML-KEM Variant Selection

**Question**: Should users be able to choose ML-KEM-512 for constrained links?

**Current Thinking**: Default to ML-KEM-768, allow opt-in to ML-KEM-512.

**Considerations**:
- Security margin reduction
- Interoperability
- User understanding

### 13.4 Compatibility with Reticulum

**Question**: Should ant-quic implement a Reticulum-compatible mode?

**Current Thinking**: Not initially, possibly later as a gateway mode.

**Considerations**:
- Classical crypto exposure
- Ecosystem access
- Development effort

### 13.5 Voice/Real-Time Support

**Question**: Should ant-quic support LXST-like real-time voice?

**Current Thinking**: Out of scope for initial implementation.

**Considerations**:
- Codec2 integration
- Latency requirements
- Complexity

---

## 14. References

### Projects

- [Reticulum Network Stack](https://github.com/markqvist/Reticulum)
- [LXMF Protocol](https://github.com/markqvist/lxmf)
- [LXST Protocol](https://github.com/markqvist/lxst)
- [Sideband Client](https://github.com/markqvist/Sideband)
- [Nomad Network](https://github.com/markqvist/NomadNet)
- [RNode Hardware](https://unsigned.io/rnode/)

### Standards

- [RFC 9000 - QUIC Transport](https://www.rfc-editor.org/rfc/rfc9000)
- [FIPS 203 - ML-KEM](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf)
- [FIPS 204 - ML-DSA](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf)
- [LoRa Alliance Specifications](https://lora-alliance.org/resource_hub/)
- [AX.25 Protocol](https://www.tapr.org/pdf/AX25.2.2.pdf)

### ant-quic Documentation

- [NAT Traversal Guide](../NAT_TRAVERSAL_GUIDE.md)
- [PQC Security Analysis](../guides/pqc-security.md)
- [Architecture Overview](../architecture/ARCHITECTURE.md)

---

## Appendix A: Transport Comparison Matrix

| Transport | Bandwidth | MTU | RTT | Half-Duplex | Broadcast | Use Case |
|-----------|-----------|-----|-----|-------------|-----------|----------|
| UDP/IP | 1 Gbps+ | 1200 | 50ms | No | Yes | General |
| LoRa SF12 | 300 bps | 222 | 5s | Yes | Yes | Long range |
| LoRa SF7 | 22 kbps | 222 | 500ms | Yes | Yes | Short range |
| Serial 115k | 115 kbps | 1024 | 50ms | Yes | No | Direct |
| Packet 1200 | 1.2 kbps | 256 | 2s | Yes | Yes | Ham radio |
| BLE | 125 kbps | 244 | 100ms | No | Yes | Short range |
| I2P | 50 kbps | 61K | 2s | No | No | Anonymous |

---

## Appendix B: PQC Size Comparison

| Operation | ML-KEM-768 | ML-KEM-512 | X25519 |
|-----------|------------|------------|--------|
| Public Key | 1,184 bytes | 800 bytes | 32 bytes |
| Ciphertext | 1,088 bytes | 768 bytes | 32 bytes |
| Shared Secret | 32 bytes | 32 bytes | 32 bytes |

| Operation | ML-DSA-65 | ML-DSA-44 | Ed25519 |
|-----------|-----------|-----------|---------|
| Public Key | 1,952 bytes | 1,312 bytes | 32 bytes |
| Signature | 3,293 bytes | 2,420 bytes | 64 bytes |

---

## Appendix C: Handshake Time Estimates

Assumptions:
- ML-KEM-768 + ML-DSA-65
- Handshake requires ~8.8 KB total
- 50% overhead for framing/headers

| Transport | Effective Rate | Handshake Time |
|-----------|----------------|----------------|
| LoRa SF12 | 150 bps | ~8 minutes |
| LoRa SF7 | 11 kbps | ~6 seconds |
| Packet 1200 | 600 bps | ~2 minutes |
| Serial 115k | 57.5 kbps | ~1.2 seconds |
| BLE | 62.5 kbps | ~1.1 seconds |
| UDP/IP | 50 Mbps | ~1.4 ms |

With session caching, subsequent communications avoid handshake entirely.

---

*Document Version: 0.1*  
*Last Updated: January 2026*
