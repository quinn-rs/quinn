# ADR-001: LinkTransport Trait Abstraction

## Status

Accepted (2025-12-21)

## Context

Overlay networks like saorsa-core need to build on top of ant-quic's QUIC transport, but face several challenges:

1. **Version coupling**: Overlays compile directly against ant-quic's concrete types, creating tight coupling that breaks when ant-quic evolves
2. **Testing difficulty**: Testing overlay logic requires instantiating real QUIC endpoints, making unit tests slow and flaky
3. **Transport flexibility**: Future requirements may need alternative transports (WebRTC for browsers, TCP fallback for restrictive networks)

## Decision

Introduce a `LinkTransport` trait that provides a stable abstraction layer between overlays and the underlying transport:

```rust
pub trait LinkTransport: Send + Sync + 'static {
    type Conn: LinkConn;

    fn local_peer(&self) -> PeerId;
    fn external_address(&self) -> Option<SocketAddr>;
    fn peer_table(&self) -> Vec<(PeerId, Capabilities)>;
    fn dial(&self, peer: PeerId, proto: ProtocolId) -> BoxFuture<'_, LinkResult<Self::Conn>>;
    fn dial_addr(&self, addr: SocketAddr, proto: ProtocolId) -> BoxFuture<'_, LinkResult<Self::Conn>>;
    fn accept(&self, proto: ProtocolId) -> BoxStream<'_, LinkResult<Self::Conn>>;
    fn events(&self) -> BoxStream<'_, LinkEvent>;
    fn shutdown(&self) -> BoxFuture<'_, ()>;
}
```

Key design elements:
- **Protocol multiplexing**: 16-byte `ProtocolId` enables multiple overlays on one endpoint
- **Capability discovery**: `peer_table()` exposes peer metadata for intelligent routing
- **Event streaming**: Async event stream for connection/peer state changes
- **Associated type pattern**: `type Conn: LinkConn` allows different connection implementations

## Consequences

### Benefits
- **Version decoupling**: Overlays compile against trait, not implementation
- **Testability**: Mock implementations enable fast, deterministic unit tests
- **Future flexibility**: Can add WebRTC, TCP, or other transports without API changes
- **Clean separation**: Clear boundary between transport concerns and overlay logic

### Trade-offs
- **Abstraction overhead**: Additional indirection (minimal - trait objects are cheap)
- **API surface**: Another interface to maintain alongside raw QUIC
- **Boxing requirements**: Some async methods require boxing for trait objects

## Alternatives Considered

1. **Direct QUIC exposure**: Let overlays use Quinn types directly
   - Rejected: Creates tight coupling, hard to evolve

2. **Callback-based API**: Use closures instead of traits
   - Rejected: Less composable, harder to test

3. **Message-passing**: Actor model with channels
   - Rejected: More complexity, higher latency for simple operations

## References

- Commit: `0c91bcab` (feat: add LinkTransport trait abstraction layer)
- File: `src/link_transport.rs`
- Related: Three-layer architecture in `docs/architecture/ARCHITECTURE.md`
