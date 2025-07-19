# Product Overview

ant-quic is a QUIC transport protocol implementation with advanced NAT traversal capabilities, optimized for P2P networks and the Autonomi ecosystem.

## Core Purpose
- Enable peer-to-peer connections through restrictive NATs with near 100% success rate
- Provide decentralized networking infrastructure for any p2p ecosystem
- Extend Quinn QUIC implementation with sophisticated NAT traversal
- Does not use STUN or ICE but instead uses QUIC-native NAT traversal (see below)

## Key Features
- **QUIC-native NAT Traversal**: Pure QUIC extension based on draft-seemann-quic-nat-traversal-01 (NO STUN/ICE)
- **Symmetric NAT Penetration**: Breakthrough restrictive NATs through coordinated QUIC protocols
- **Automatic Role Detection**: Nodes dynamically become coordinators when publicly reachable
- **Decentralized Bootstrap**: Self-organizing network of coordinator nodes
- **Multi-path Connectivity**: Test multiple connection paths simultaneously

## QUIC-native NAT traversal 

The QUIC-native NAT traversal approach leverages QUIC's inherent path validation mechanism and connection migration capabilities to establish direct peer-to-peer connections without requiring external protocols like ICE/STUN. The mechanism begins with peers connected via a proxied QUIC connection (potentially using CONNECT-UDP or MASQUE), where the server advertises its candidate addresses through ADD_ADDRESS frames containing sequence numbers and socket addresses. The client, upon receiving these candidates, performs ICE-like pairing logic locally and sends PUNCH_ME_NOW frames to coordinate simultaneous path validation attempts. Both peers then initiate QUIC path validation by sending PATH_CHALLENGE frames to create bidirectional NAT bindings, with the server-side path validation being a key extension since RFC 9000 only specifies client-initiated validation. The concurrency is controlled through a transport parameter negotiated during the handshake, limiting amplification attacks while allowing parallel path probing. Once path validation succeeds, the peers use QUIC's connection migration to seamlessly transition from the relayed path to the direct path, maintaining all stream state and security context. This approach is particularly elegant because it reuses QUIC's existing mechanisms - the same connection IDs that enable migration also allow the relay to forward packets without decryption, path validation provides built-in RTT measurement and packet loss detection, and the entire process maintains QUIC's security properties including forward secrecy and authenticated encryption, all while requiring minimal protocol extensions (just three new frame types and one transport parameter).

## Target Use Cases
- P2P networking applications requiring high connectivity rates
- Decentralized systems needing NAT traversal without central infrastructure
- Applications built on the Autonomi decentralized network
- Any system requiring reliable peer-to-peer QUIC connections

## Architecture Philosophy
- Built on proven Quinn QUIC foundation using its high-level API patterns
- Extends QUIC with custom transport parameters and frames for NAT traversal
- Implements ICE-like candidate pairing with priority-based selection
- Uses coordinated hole punching for symmetric NAT penetration
- Provides both low-level protocol APIs and high-level convenience interfaces
- Leverages Quinn's Endpoint and Connection abstractions for consistency