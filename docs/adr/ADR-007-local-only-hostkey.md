# ADR-007: Local-only HostKey for Key Hierarchy and Bootstrap Cache

## Status

Accepted (2025-12-22)

## Context

ant-quic is a global, decentralised connectivity substrate: PQC-by-default QUIC transport with NAT traversal (including IPv4/IPv6 dual-stack and MASQUE relay fallback), and a greedy bootstrap cache for rapid rejoin and improved reachability.

Current constraints and observations:

- IP endpoints (IPv4/IPv6 + ports) are **volatile locators**, not identities
- A single machine may run **multiple endpoints** serving **multiple overlay networks** identified by `network_id`
- We require **mandatory** relay/coordinator duties (no opt-out), bounded by rate limits and resource budgets
- We explicitly want to avoid **regressive UX** approaches (e.g., PoW/PoS "identity cost") and do not want to introduce any central identity service

A missing piece is a clean model for local key management and state storage that:

- Supports multiple endpoints and multiple overlays on the same host
- Allows a greedy peer cache to be shared safely across endpoints
- Does not introduce a network-visible "host identity" that increases correlatability or invites incorrect assumptions about Sybil resistance

## Decision

Introduce a **single, local-only HostKey** (host root secret) that:

1. **Never appears on the wire** (not transmitted, not advertised, not referenced in any protocol frame, handshake extension, or node record)
2. Is used to deterministically derive:
   - Endpoint authentication keys (`EndpointKeys`) according to a key policy
   - Encryption keys for local state (bootstrap cache and related databases)
3. Enables a **host-scoped greedy bootstrap cache** shared across all endpoints on the host, encrypted at rest with HostKey-derived keys

### Key Derivation (HKDF-SHA256)

Using domain-separated HKDF matching existing patterns in `src/crypto/ring_like.rs`:

```
// Root derivations from HostKey (HK)
K_endpoint_seed = HKDF-Expand(HK, salt="antq:hostkey:v1", info="antq:endpoint-seed:v1")
K_cache         = HKDF-Expand(HK, salt="antq:hostkey:v1", info="antq:cache-key:v1")

// Per-network endpoint derivation (privacy boundary)
IKM = HKDF-Expand(K_endpoint_seed, salt=network_id_bytes, info="antq:endpoint-ikm:v1")

// IKM → ML-DSA-65 keypair via deterministic seed
```

### Default Key Policy

- **Per-network EndpointIds** by default (privacy boundary between overlays)
- Optional "shared identity" mode for operators who explicitly want a single public node identity across networks

### Storage Priority (Platform-Specific)

1. **macOS**: Keychain Services (`security-framework` crate)
2. **Linux**: libsecret/GNOME Keyring (`secret-service` crate), else encrypted file fallback
3. **Windows**: DPAPI (`windows` crate)
4. **Fallback**: XChaCha20-Poly1305 encrypted file with `ANTQ_HOSTKEY_PASSWORD` environment variable (fail if not set—no interactive prompt)

### Coordinator/Relay Duties

Enforcement remains **resource-based**, not keyed to HostKey:

- All endpoints participate in coordination/relaying as requested by protocol
- Subject to global resource budgets, per-peer quotas, and anti-abuse rate limits

## Consequences

### Positive

- **Clean key hierarchy**: One root secret, deterministic derivation, versioning, and rotation hooks
- **Host-scoped bootstrap cache**: Safely shared across endpoints and processes, encrypted at rest
- **Better UX**: No PoW/PoS, no sign-ups, no central service
- **Improved privacy defaults**: Per-network endpoint identities reduce cross-overlay correlation
- **Faster rejoin**: Accumulated NAT traversal observations benefit all endpoints

### Negative / Trade-offs

- **Does not provide Sybil resistance** (by design—key minting is cheap; overlays needing Sybil resistance must address it at their layer)
- **HostKey becomes a high-value local secret**: Must be protected at rest via OS keychain or encrypted storage
- **Migration complexity**: Existing deployments need careful handling to avoid surprising identity changes

## Alternatives Considered

### 1. No HostKey; store independent endpoint keys

**Pros**: Simpler to reason about; no root secret
**Cons**: Fragmented state; harder cache sharing; more operational complexity; inconsistent key rotation and backup

### 2. Network-visible HostKey / single host identity used for policy

**Pros**: Could simplify quota accounting
**Cons**: Not Sybil-resistant without scarcity; increases correlatability; invites misuse as a global identity

### 3. Sybil resistance via PoW/PoS or registration

**Pros**: Makes identities costly
**Cons**: Regressive UX; operational friction; unwanted economic coupling at transport layer

### 4. Trusted hardware attestation (TPM/TEE)

**Pros**: Can bind identity to a machine
**Cons**: Not universal; adds complexity; conflicts with "works anywhere" decentralised assumption unless optional

## Implementation

### New Module: `src/host_identity/`

```rust
// src/host_identity/mod.rs
pub mod derivation;
pub mod storage;

pub use derivation::{HostIdentity, EndpointKeyPolicy};
pub use storage::{HostKeyStorage, StorageBackend};

// src/host_identity/derivation.rs
pub struct HostIdentity {
    secret: [u8; 32],  // Never exposed
    policy: EndpointKeyPolicy,
}

pub enum EndpointKeyPolicy {
    PerNetwork,   // Default: distinct EndpointId per network_id
    Shared,       // Single EndpointId across all networks
}

impl HostIdentity {
    pub fn derive_endpoint_key(&self, network_id: &[u8]) -> (MlDsa65PublicKey, MlDsa65SecretKey);
    pub fn derive_cache_key(&self) -> [u8; 32];
}
```

### Bootstrap Cache Integration

- **Max peers**: Increased from 20,000 → 30,000
- **Encryption**: XChaCha20-Poly1305 with HostKey-derived `K_cache`
- **New field**: `RelayPathHint` for MASQUE relay path tracking

### API Surface

```rust
// Endpoint construction with HostIdentity
P2pEndpoint::builder()
    .with_host_identity(&host_id, network_id)
    .build()

// Cache construction with encryption
BootstrapCache::builder()
    .with_encryption_key(host_id.derive_cache_key())
    .build()
```

### CLI Commands

```
ant-quic identity show     # Show EndpointId(s) without exposing HostKey
ant-quic identity wipe     # Delete HostKey and cache, start fresh
ant-quic cache stats       # Show cache health metrics
ant-quic doctor            # Diagnostic mode
```

## References

- `src/crypto/raw_public_keys/pqc.rs` - Current PeerId derivation using domain separator `AUTONOMI_PEER_ID_V2:`
- `src/crypto/ring_like.rs` - Existing HKDF-SHA256 patterns
- `src/bootstrap_cache/` - Current cache implementation with file locking
- [ADR-002](ADR-002-epsilon-greedy-bootstrap-cache.md) - Epsilon-greedy bootstrap cache design
- [ADR-003](ADR-003-pure-post-quantum-cryptography.md) - Pure PQC architecture (ML-DSA-65)
