# Architecture Decision Records

This directory contains Architecture Decision Records (ADRs) for the ant-quic project.

## What are ADRs?

ADRs document significant architectural decisions made in the project. Each record captures the context, decision, and consequences to help future maintainers understand why things are the way they are.

## Index

| ADR | Title | Status | Date |
|-----|-------|--------|------|
| [ADR-001](ADR-001-link-transport-abstraction.md) | LinkTransport Trait Abstraction | Accepted | 2025-12-21 |
| [ADR-002](ADR-002-epsilon-greedy-bootstrap-cache.md) | Epsilon-Greedy Bootstrap Cache | Accepted | 2025-12-21 |
| [ADR-003](ADR-003-pure-post-quantum-cryptography.md) | Pure Post-Quantum Cryptography | Accepted | 2025-12-21 |
| [ADR-004](ADR-004-symmetric-p2p-architecture.md) | Symmetric P2P Architecture | Accepted | 2025-12-21 |
| [ADR-005](ADR-005-native-quic-nat-traversal.md) | Native QUIC NAT Traversal | Accepted | 2025-12-21 |
| [ADR-006](ADR-006-masque-relay-fallback.md) | MASQUE CONNECT-UDP Bind Relay | Accepted | 2025-12-21 |
| [ADR-007](ADR-007-local-only-hostkey.md) | Local-only HostKey | Accepted | 2025-12-22 |
| [ADR-008](ADR-008-universal-connectivity-architecture.md) | Universal Connectivity Architecture | Accepted | 2025-12-26 |

## ADR Template

New ADRs should follow this structure:

```markdown
# ADR-N: Title

## Status
Proposed | Accepted | Deprecated | Superseded

## Context
Why this decision was necessary.

## Decision
What was chosen and why.

## Consequences
Benefits and trade-offs.

## Alternatives Considered
Other options and why rejected.

## References
Relevant commits, RFCs, code paths.
```

## Related Documentation

- [Architecture Overview](../architecture/ARCHITECTURE.md)
- [Symmetric P2P Design](../SYMMETRIC_P2P.md)
- [NAT Traversal Guide](../NAT_TRAVERSAL_GUIDE.md)
- [PQC Authentication Spec](../rfcs/ant-quic-pqc-authentication.md)
