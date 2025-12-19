# Glossary

Terms and concepts used in ant-quic documentation.

## A

### ADD_ADDRESS
A QUIC extension frame (type 0x3d7e90/0x3d7e91) used to advertise candidate addresses during NAT traversal.

### Address Discovery
The process of learning your external IP address and port as seen by other peers. Implemented via OBSERVED_ADDRESS frames per draft-ietf-quic-address-discovery-00.

## C

### Candidate Address
An address that might be used to reach a peer. Candidates can be:
- **Local**: Interface addresses
- **Observed**: Discovered via OBSERVED_ADDRESS
- **Predicted**: Symmetric NAT port predictions

### CGNAT
Carrier Grade NAT. ISP-level NAT using the 100.64.0.0/10 address space. Increasingly common due to IPv4 exhaustion.

### Connection
A QUIC connection between two peers, providing encrypted bidirectional communication with stream multiplexing.

## D

### draft-ietf-quic-address-discovery-00
IETF draft specifying how QUIC peers can discover their external addresses through OBSERVED_ADDRESS frames.

### draft-seemann-quic-nat-traversal-02
IETF draft specifying QUIC-native NAT traversal using ADD_ADDRESS and PUNCH_ME_NOW frames.

## E

### Ed25519
An elliptic curve digital signature algorithm used for peer identity in ant-quic.

### Endpoint
A QUIC endpoint that can both initiate and accept connections. In ant-quic, all endpoints are symmetric.

## F

### FIPS 203
NIST standard for ML-KEM (Module-Lattice-based Key Encapsulation Mechanism).

### FIPS 204
NIST standard for ML-DSA (Module-Lattice-based Digital Signature Algorithm).

### Forward Secrecy
A property where compromise of long-term keys doesn't compromise past session keys. ant-quic achieves this through ephemeral key exchange.

### Full Cone NAT
The most permissive NAT type. Once a mapping is created, any external host can send packets to the internal host.

## H

### Hole Punching
A technique for establishing direct connections through NAT by having both peers send packets simultaneously, creating NAT mappings that allow the other's packets through.

### Hybrid Cryptography
Using both classical and post-quantum algorithms together. An attacker must break both to compromise security.

## K

### Known Peer
An address to connect to first for address discovery. Replaces the outdated term "bootstrap node" - known peers are just regular peers with known addresses.

## M

### ML-DSA-65
Module-Lattice-based Digital Signature Algorithm at NIST security level 3. Used for post-quantum authentication in ant-quic.

### ML-KEM-768
Module-Lattice-based Key Encapsulation Mechanism at NIST security level 3. Used for post-quantum key exchange in ant-quic.

### MTU
Maximum Transmission Unit. The largest packet size that can be sent. PQC increases handshake sizes, affecting MTU requirements.

## N

### NAT
Network Address Translation. A technique for mapping private IP addresses to public ones. NAT traversal is needed for P2P connectivity.

### NatConfig
Configuration struct for NAT traversal parameters in ant-quic.

## O

### OBSERVED_ADDRESS
A QUIC extension frame (type 0x9f81a6/0x9f81a7) that reports the external address observed by the peer.

## P

### P2pConfig
The main configuration struct for ant-quic P2P endpoints.

### P2pEndpoint
The primary API for ant-quic. Represents a symmetric P2P node that can connect to and accept connections from peers.

### P2pEvent
Events emitted by the endpoint, including connection events, address discovery, and NAT traversal status.

### Peer ID
A unique identifier for a peer, derived from their Ed25519 public key.

### Port Restricted NAT
A NAT type where external hosts can only send packets if the internal host previously sent to that host and port.

### PQC
Post-Quantum Cryptography. Cryptographic algorithms designed to resist attacks by quantum computers.

### PqcConfig
Configuration struct for PQC parameters. Note: PQC cannot be disabled in v0.13.0+.

### PUNCH_ME_NOW
A QUIC extension frame (type 0x3d7e92/0x3d7e93) used to coordinate simultaneous hole punching.

## Q

### QUIC
A modern transport protocol providing multiplexed, encrypted connections over UDP. ant-quic extends QUIC with NAT traversal capabilities.

## R

### Raw Public Keys
A TLS extension (RFC 7250) allowing authentication using bare public keys instead of X.509 certificates.

### RFC 7250
IETF RFC specifying Raw Public Keys for TLS authentication.

### RFC 9000
IETF RFC specifying the QUIC transport protocol.

## S

### Stream
A bidirectional or unidirectional data channel within a QUIC connection. Multiple streams can be multiplexed on one connection.

### Symmetric NAT
The most restrictive NAT type. Uses different external ports for different destinations, making direct connections difficult.

### Symmetric P2P
ant-quic's architectural model where all nodes have identical capabilities - no special roles like "client", "server", or "bootstrap".

## T

### Transport Parameters
QUIC parameters exchanged during connection establishment. ant-quic uses custom transport parameters for NAT traversal negotiation.

## X

### X25519
An elliptic curve Diffie-Hellman function used for classical key exchange in ant-quic's hybrid scheme.

---

## Removed Terms (v0.13.0)

These terms are **no longer used** in ant-quic v0.13.0+:

| Removed Term | Reason |
|--------------|--------|
| Bootstrap Node | All nodes are symmetric - use "known peer" instead |
| Client Role | No roles in symmetric P2P |
| Server Role | No roles in symmetric P2P |
| Coordinator | All nodes can coordinate |
| EndpointRole | Removed enum - all nodes symmetric |
| PqcMode | Removed - PQC always enabled |
| HybridPreference | Removed - no mode selection |
| Classical-Only | Not available - PQC always on |
