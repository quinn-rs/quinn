# Product Overview

ant-quic is a QUIC transport protocol implementation with advanced NAT traversal capabilities, optimized for P2P networks and the Autonomi ecosystem.

## Core Purpose
- Enable peer-to-peer connections through restrictive NATs with near 100% success rate
- Provide decentralized networking infrastructure for the Autonomi ecosystem
- Extend Quinn QUIC implementation with sophisticated NAT traversal

## Key Features
- **Advanced NAT Traversal**: ICE-like candidate discovery and coordinated hole punching
- **Symmetric NAT Penetration**: Breakthrough restrictive NATs through coordinated protocols
- **Automatic Role Detection**: Nodes dynamically become coordinators when publicly reachable
- **Decentralized Bootstrap**: Self-organizing network of coordinator nodes
- **Multi-path Connectivity**: Test multiple connection paths simultaneously

## Target Use Cases
- P2P networking applications requiring high connectivity rates
- Decentralized systems needing NAT traversal without central infrastructure
- Applications built on the Autonomi decentralized network
- Any system requiring reliable peer-to-peer QUIC connections

## Architecture Philosophy
- Built on proven Quinn QUIC foundation
- Extends QUIC with custom transport parameters and frames for NAT traversal
- Implements ICE-like candidate pairing with priority-based selection
- Uses coordinated hole punching for symmetric NAT penetration
- Provides both low-level protocol APIs and high-level convenience interfaces