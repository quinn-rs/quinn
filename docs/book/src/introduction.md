# Introduction

Welcome to the ant-quic documentation!

ant-quic is a QUIC transport protocol implementation with advanced NAT traversal capabilities, optimized for P2P networks and the Autonomi ecosystem. It provides sophisticated hole-punching protocols to achieve near 100% connectivity through restrictive NATs, with 100% Post-Quantum Cryptography security.

## Key Features

- **Symmetric P2P Architecture**: Every node is equal - no special client/server/bootstrap roles
- **100% Post-Quantum Cryptography**: ML-KEM-768 + ML-DSA-65 on every connection (always enabled)
- **Advanced NAT Traversal**: Implementation of draft-seemann-quic-nat-traversal-02
- **Address Discovery**: Native QUIC address discovery (draft-ietf-quic-address-discovery-00)
- **Raw Public Keys**: Ed25519 identity via RFC 7250 (no certificates required)
- **High Performance**: Built on top of the battle-tested Quinn QUIC implementation
- **Cross-Platform**: Supports Windows, Linux, and macOS
- **Production Ready**: Comprehensive test suite with 580+ tests

## Symmetric P2P Model

In ant-quic v0.13.0+, **all nodes are symmetric**. Every node can:
- Initiate connections to other nodes
- Accept incoming connections
- Observe external addresses of connecting peers
- Coordinate NAT traversal for other peers
- Relay traffic when direct connection fails

There are no special "bootstrap nodes", "coordinators", or "servers" - just peers with different network positions (some have public IPs, some are behind NAT).

## Post-Quantum Security

Every connection uses hybrid cryptography:
- **Key Exchange**: X25519 + ML-KEM-768
- **Signatures**: Ed25519 + ML-DSA-65

This protects against both current classical attacks and future quantum computer threats. PQC cannot be disabled - it's always on in v0.13.0+.

## Who is this for?

- **P2P Application Developers**: Build decentralized applications with reliable connectivity
- **Network Engineers**: Deploy QUIC-based services with NAT traversal
- **Security-Conscious Developers**: Applications requiring post-quantum security
- **Researchers**: Experiment with modern transport protocols

## Getting Help

- [GitHub Issues](https://github.com/dirvine/ant-quic/issues)
- [API Documentation](https://docs.rs/ant-quic)
- [Examples](https://github.com/dirvine/ant-quic/tree/master/examples)

## Protocol Standards

ant-quic implements these standards:
- [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000) - QUIC Transport Protocol
- [RFC 7250](https://www.rfc-editor.org/rfc/rfc7250) - Raw Public Keys in TLS
- [draft-seemann-quic-nat-traversal-02](../../rfcs/draft-seemann-quic-nat-traversal-02.txt) - QUIC NAT Traversal
- [draft-ietf-quic-address-discovery-00](../../rfcs/draft-ietf-quic-address-discovery-00.txt) - Address Discovery
- [FIPS 203](../../rfcs/fips-203-ml-kem.pdf) - ML-KEM Key Encapsulation
- [FIPS 204](../../rfcs/fips-204-ml-dsa.pdf) - ML-DSA Digital Signatures

## License

ant-quic is dual-licensed under MIT and Apache 2.0.
