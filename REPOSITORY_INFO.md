# Repository Information

## Status: Independent Project

ant-quic is a **standalone QUIC implementation** with advanced NAT traversal capabilities.

### NOT a Quinn Fork

While ant-quic originally started from Quinn's codebase, it has:
- Diverged significantly with custom NAT traversal protocols
- Added Post-Quantum Cryptography support
- Implemented QUIC protocol extensions (draft-seemann-quic-nat-traversal)
- Developed its own P2P networking stack

### Repository Details

- **Repository**: https://github.com/dirvine/ant-quic
- **Type**: Independent project (not a fork)
- **Upstream**: None (we don't sync with Quinn)
- **Contributions**: Direct to ant-quic only

### For Developers

When working on this codebase:
1. Never push to quinn-rs repositories
2. Never create PRs to Quinn
3. Treat this as a completely independent project
4. All contributions go to dirvine/ant-quic

### Git Configuration

To prevent accidental upstream pushes:
```bash
# Enable local Git hooks
git config core.hooksPath .githooks
```

This will activate pre-push hooks that prevent pushing to Quinn repositories.