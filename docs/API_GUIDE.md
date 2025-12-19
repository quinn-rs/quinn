# ant-quic API Guide

Comprehensive API reference for ant-quic v0.13.0.

## Overview

ant-quic provides a symmetric P2P networking API with:
- 100% Post-Quantum Cryptography (always on)
- Automatic NAT traversal
- Event-driven architecture
- Zero configuration defaults

## Primary API: P2pEndpoint

`P2pEndpoint` is the main entry point for all P2P operations.

```rust
use ant_quic::{P2pEndpoint, P2pConfig};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = P2pConfig::builder()
        .known_peer("peer.example.com:9000".parse()?)
        .build()?;

    let endpoint = P2pEndpoint::new(config).await?;

    // Your endpoint is now ready
    Ok(())
}
```

### Creation

```rust
impl P2pEndpoint {
    /// Create a new P2P endpoint with the given configuration.
    ///
    /// This generates a new Ed25519 keypair and initializes the NAT traversal
    /// subsystem. The endpoint immediately begins listening for connections.
    pub async fn new(config: P2pConfig) -> Result<Self, EndpointError>;
}
```

### Identity

```rust
impl P2pEndpoint {
    /// Get this endpoint's peer ID.
    ///
    /// The PeerId is derived from the Ed25519 public key:
    /// `PeerId = SHA-256(SubjectPublicKeyInfo)`
    pub fn peer_id(&self) -> PeerId;

    /// Get the local socket address this endpoint is bound to.
    ///
    /// Returns `None` if the endpoint failed to bind.
    pub fn local_addr(&self) -> Option<SocketAddr>;

    /// Get the discovered external address (if any).
    ///
    /// This is learned via OBSERVED_ADDRESS frames from connected peers.
    /// Returns `None` if no external address has been discovered yet.
    pub fn external_address(&self) -> Option<SocketAddr>;

    /// Get all discovered external addresses from all peers.
    ///
    /// Different peers may see different addresses if you're behind
    /// multiple NATs or load balancers.
    pub fn discovered_addresses(&self) -> Vec<SocketAddr>;
}
```

### Connections

```rust
impl P2pEndpoint {
    /// Connect to all configured known peers.
    ///
    /// This initiates connections to peers listed in `P2pConfig::known_peers`.
    /// Use this for initial network discovery and external address detection.
    pub async fn connect_bootstrap(&self) -> Result<(), EndpointError>;

    /// Connect to a specific peer by their PeerId.
    ///
    /// If the peer is not directly reachable, NAT traversal coordination
    /// is attempted through connected peers.
    pub async fn connect_to_peer(&self, peer: PeerId) -> Result<Connection, EndpointError>;

    /// Get a list of currently connected peer IDs.
    pub fn connected_peers(&self) -> Vec<PeerId>;

    /// Get connection info for a specific peer.
    pub fn peer_connection(&self, peer: &PeerId) -> Option<PeerConnection>;

    /// Get the connection count.
    pub fn connection_count(&self) -> usize;
}
```

### Events

```rust
impl P2pEndpoint {
    /// Subscribe to endpoint events.
    ///
    /// Returns a broadcast receiver for P2pEvent notifications.
    /// Multiple subscribers can exist simultaneously.
    pub fn subscribe(&self) -> broadcast::Receiver<P2pEvent>;
}
```

### Statistics

```rust
impl P2pEndpoint {
    /// Get endpoint statistics.
    pub fn stats(&self) -> EndpointStats;

    /// Get NAT traversal statistics.
    pub fn nat_stats(&self) -> NatTraversalStatistics;
}
```

### Lifecycle

```rust
impl P2pEndpoint {
    /// Gracefully shut down the endpoint.
    ///
    /// Closes all connections and releases resources.
    pub async fn shutdown(&self);
}
```

## Configuration: P2pConfig

### Builder Pattern

```rust
use ant_quic::{P2pConfig, NatConfig, MtuConfig};
use ant_quic::crypto::pqc::PqcConfig;

let config = P2pConfig::builder()
    // Network binding
    .bind_addr("0.0.0.0:9000".parse()?)

    // Known peers for discovery
    .known_peer("peer1.example.com:9000".parse()?)
    .known_peers(vec![
        "peer2.example.com:9000".parse()?,
        "peer3.example.com:9000".parse()?,
    ])

    // Connection limits
    .max_connections(100)

    // Sub-configurations
    .pqc(PqcConfig::default())
    .nat(NatConfig::default())
    .mtu(MtuConfig::pqc_optimized())

    // Statistics interval
    .stats_interval(Duration::from_secs(30))

    .build()?;
```

### P2pConfig Fields

```rust
pub struct P2pConfig {
    /// Local address to bind to.
    /// If `None`, an ephemeral port is auto-assigned.
    pub bind_addr: Option<SocketAddr>,

    /// Known peers for initial discovery.
    /// These can be any nodes - all nodes are symmetric.
    pub known_peers: Vec<SocketAddr>,

    /// Maximum number of concurrent connections.
    pub max_connections: usize,

    /// Authentication configuration.
    pub auth: AuthConfig,

    /// NAT traversal configuration.
    pub nat: NatConfig,

    /// Timeout configuration.
    pub timeouts: TimeoutConfig,

    /// Post-quantum cryptography configuration.
    pub pqc: PqcConfig,

    /// MTU configuration.
    pub mtu: MtuConfig,

    /// Statistics collection interval.
    pub stats_interval: Duration,
}
```

## PQC Configuration

PQC is always enabled. `PqcConfig` controls tuning parameters only.

```rust
use ant_quic::crypto::pqc::{PqcConfig, PqcConfigBuilder};

let pqc = PqcConfig::builder()
    .ml_kem(true)                        // ML-KEM-768 (key exchange)
    .ml_dsa(true)                        // ML-DSA-65 (signatures)
    .memory_pool_size(10)                // Pre-allocated crypto buffers
    .handshake_timeout_multiplier(2.0)   // Extra time for larger handshakes
    .build()?;
```

### PqcConfig Fields

```rust
pub struct PqcConfig {
    /// Enable ML-KEM-768 key encapsulation.
    /// Required - at least one algorithm must be enabled.
    pub ml_kem_enabled: bool,

    /// Enable ML-DSA-65 digital signatures.
    /// Optional - provides authentication.
    pub ml_dsa_enabled: bool,

    /// Memory pool size for crypto operations.
    /// Higher values use more memory but improve performance
    /// under high connection load.
    pub memory_pool_size: usize,

    /// Handshake timeout multiplier.
    /// PQC handshakes are larger; this extends the timeout.
    /// Range: 1.0 to 10.0
    pub handshake_timeout_multiplier: f64,
}
```

### Validation Rules

- At least one algorithm (ML-KEM or ML-DSA) must be enabled
- Memory pool size must be > 0
- Timeout multiplier must be between 1.0 and 10.0

## NAT Configuration

```rust
pub struct NatConfig {
    /// Maximum number of address candidates to track.
    pub max_candidates: usize,

    /// Enable symmetric NAT prediction algorithms.
    pub enable_symmetric_nat: bool,

    /// Enable automatic relay fallback when direct connection fails.
    pub enable_relay_fallback: bool,

    /// Maximum concurrent NAT traversal attempts.
    pub max_concurrent_attempts: usize,

    /// Prefer RFC-compliant NAT traversal frame format.
    pub prefer_rfc_nat_traversal: bool,
}
```

### Default Values

```rust
impl Default for NatConfig {
    fn default() -> Self {
        Self {
            max_candidates: 10,
            enable_symmetric_nat: true,
            enable_relay_fallback: true,
            max_concurrent_attempts: 3,
            prefer_rfc_nat_traversal: true,
        }
    }
}
```

## MTU Configuration

```rust
pub struct MtuConfig {
    /// Initial MTU before discovery (minimum: 1200).
    pub initial_mtu: u16,

    /// Minimum MTU that must always work.
    pub min_mtu: u16,

    /// Enable path MTU discovery.
    pub discovery_enabled: bool,

    /// Upper bound for MTU probing.
    pub max_mtu: u16,

    /// Auto-adjust MTU for PQC handshakes.
    pub auto_pqc_adjustment: bool,
}
```

### Presets

```rust
// Default configuration
let mtu = MtuConfig::default();

// Optimized for PQC (larger keys)
let mtu = MtuConfig::pqc_optimized();

// Constrained networks (no discovery)
let mtu = MtuConfig::constrained();

// High-bandwidth with jumbo frames
let mtu = MtuConfig::jumbo_frames();
```

## Events: P2pEvent

Subscribe to events for reactive programming:

```rust
let mut events = endpoint.subscribe();

tokio::spawn(async move {
    while let Ok(event) = events.recv().await {
        handle_event(event);
    }
});
```

### Event Types

```rust
pub enum P2pEvent {
    /// A new peer connected.
    Connected {
        peer_id: PeerId,
        addr: SocketAddr,
    },

    /// A peer disconnected.
    Disconnected {
        peer_id: PeerId,
    },

    /// Our external address was discovered.
    AddressDiscovered {
        addr: SocketAddr,
    },

    /// NAT traversal completed (success or failure).
    NatTraversalComplete {
        peer_id: PeerId,
        success: bool,
    },

    /// Peer was authenticated.
    Authenticated {
        peer_id: PeerId,
    },

    /// Authentication failed.
    AuthenticationFailed {
        peer_id: PeerId,
        reason: String,
    },

    /// Connection metrics updated.
    MetricsUpdated {
        peer_id: PeerId,
        metrics: ConnectionMetrics,
    },
}
```

## Key Management

### Key Generation

```rust
use ant_quic::crypto::raw_public_keys::key_utils::{
    generate_ed25519_keypair,
    derive_peer_id_from_public_key,
};

// Generate a new keypair
let (public_key, secret_key) = generate_ed25519_keypair();

// Derive PeerId from public key
let peer_id = derive_peer_id_from_public_key(&public_key);
```

### PeerId

```rust
/// 32-byte peer identifier derived from public key.
pub struct PeerId(pub [u8; 32]);

impl PeerId {
    /// Create from raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self;

    /// Get as byte slice.
    pub fn as_bytes(&self) -> &[u8; 32];

    /// Convert to hex string.
    pub fn to_hex(&self) -> String;

    /// Parse from hex string.
    pub fn from_hex(hex: &str) -> Result<Self, Error>;
}
```

## Error Handling

### EndpointError

```rust
pub enum EndpointError {
    /// Failed to bind to local address.
    BindError(std::io::Error),

    /// Connection failed.
    ConnectionFailed(String),

    /// Peer not found.
    PeerNotFound(PeerId),

    /// NAT traversal failed.
    NatTraversalFailed(NatTraversalError),

    /// Authentication error.
    AuthError(String),

    /// Configuration error.
    ConfigError(String),

    /// Internal error.
    Internal(String),
}
```

### NatTraversalError

```rust
pub enum NatTraversalError {
    /// No candidates available.
    NoCandidates,

    /// Coordination timeout.
    CoordinationTimeout,

    /// All punch attempts failed.
    PunchFailed,

    /// Relay unavailable.
    RelayUnavailable,

    /// Invalid address.
    InvalidAddress(String),
}
```

## Statistics

### EndpointStats

```rust
pub struct EndpointStats {
    /// Total connections since startup.
    pub total_connections: u64,

    /// Currently active connections.
    pub active_connections: usize,

    /// Total bytes sent.
    pub bytes_sent: u64,

    /// Total bytes received.
    pub bytes_received: u64,

    /// NAT traversal success count.
    pub nat_traversal_successes: u64,

    /// NAT traversal failure count.
    pub nat_traversal_failures: u64,
}
```

### NatTraversalStatistics

```rust
pub struct NatTraversalStatistics {
    /// Local candidates discovered.
    pub local_candidates: usize,

    /// Server-reflexive candidates (from OBSERVED_ADDRESS).
    pub server_reflexive_candidates: usize,

    /// Active coordination sessions.
    pub active_sessions: usize,

    /// Successful traversals.
    pub successful_traversals: u64,

    /// Failed traversals.
    pub failed_traversals: u64,
}
```

### ConnectionMetrics

```rust
pub struct ConnectionMetrics {
    /// Bytes sent to this peer.
    pub bytes_sent: u64,

    /// Bytes received from this peer.
    pub bytes_received: u64,

    /// Round-trip time.
    pub rtt: Option<Duration>,

    /// Packet loss rate (0.0 to 1.0).
    pub packet_loss: f64,

    /// Last activity timestamp.
    pub last_activity: Option<Instant>,
}
```

## Complete Example

```rust
use ant_quic::{P2pEndpoint, P2pConfig, P2pEvent, NatConfig, MtuConfig};
use ant_quic::crypto::pqc::PqcConfig;
use std::time::Duration;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Configure PQC (always on, just tuning)
    let pqc = PqcConfig::builder()
        .ml_kem(true)
        .ml_dsa(true)
        .memory_pool_size(20)
        .build()?;

    // Configure NAT traversal
    let nat = NatConfig {
        max_candidates: 10,
        enable_symmetric_nat: true,
        enable_relay_fallback: true,
        ..Default::default()
    };

    // Build endpoint configuration
    let config = P2pConfig::builder()
        .bind_addr("0.0.0.0:0".parse()?)
        .known_peer("peer1.example.com:9000".parse()?)
        .known_peer("peer2.example.com:9000".parse()?)
        .max_connections(100)
        .pqc(pqc)
        .nat(nat)
        .mtu(MtuConfig::pqc_optimized())
        .stats_interval(Duration::from_secs(30))
        .build()?;

    // Create endpoint
    let endpoint = P2pEndpoint::new(config).await?;
    println!("Peer ID: {:?}", endpoint.peer_id());
    println!("Local addr: {:?}", endpoint.local_addr());

    // Subscribe to events
    let mut events = endpoint.subscribe();
    let event_endpoint = endpoint.clone();
    tokio::spawn(async move {
        while let Ok(event) = events.recv().await {
            match event {
                P2pEvent::Connected { peer_id, addr } => {
                    println!("Connected: {} @ {}", peer_id.to_hex(), addr);
                }
                P2pEvent::AddressDiscovered { addr } => {
                    println!("External address: {}", addr);
                }
                P2pEvent::NatTraversalComplete { peer_id, success } => {
                    println!("NAT traversal {}: {}", peer_id.to_hex(), success);
                }
                _ => {}
            }
        }
    });

    // Connect to known peers for discovery
    endpoint.connect_bootstrap().await?;

    // Wait for address discovery
    tokio::time::sleep(Duration::from_secs(2)).await;

    if let Some(addr) = endpoint.external_address() {
        println!("Discovered external address: {}", addr);
    }

    // Print statistics
    let stats = endpoint.stats();
    println!("Active connections: {}", stats.active_connections);

    let nat_stats = endpoint.nat_stats();
    println!("Local candidates: {}", nat_stats.local_candidates);
    println!("Reflexive candidates: {}", nat_stats.server_reflexive_candidates);

    Ok(())
}
```

## See Also

- [Symmetric P2P Architecture](SYMMETRIC_P2P.md) - Node model explanation
- [NAT Traversal Guide](NAT_TRAVERSAL_GUIDE.md) - NAT traversal details
- [PQC Configuration](guides/pqc-configuration.md) - Post-quantum crypto tuning
- [Troubleshooting](TROUBLESHOOTING.md) - Common issues
