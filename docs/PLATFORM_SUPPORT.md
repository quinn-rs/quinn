# Platform Support Matrix

This document outlines the platform support for ant-quic across different operating systems, architectures, and configurations.

## Support Tiers

### Tier 1: Guaranteed Support
These platforms are tested in CI on every commit and are guaranteed to work.

| Platform | Architecture | Rust Version | Status |
|----------|--------------|--------------|--------|
| Linux (glibc 2.17+) | x86_64 | 1.74.1+ | ✅ Full Support |
| Windows 10/11 | x86_64 | 1.74.1+ | ✅ Full Support |
| macOS 11+ | x86_64 | 1.74.1+ | ✅ Full Support |
| macOS 11+ | aarch64 (M1/M2) | 1.74.1+ | ✅ Full Support |

### Tier 2: Best Effort Support
These platforms are tested regularly and should work, but may have occasional issues.

| Platform | Architecture | Rust Version | Status |
|----------|--------------|--------------|--------|
| Linux (glibc) | aarch64 | 1.74.1+ | ✅ Tested |
| Linux (glibc) | armv7 | 1.74.1+ | ✅ Tested |
| Linux (musl) | x86_64 | 1.74.1+ | ✅ Tested |
| Linux (musl) | aarch64 | 1.74.1+ | ✅ Cross-compiled |
| Windows | i686 | 1.74.1+ | ✅ Tested |
| FreeBSD 14+ | x86_64 | 1.74.1+ | ✅ Tested |
| NetBSD 10+ | x86_64 | 1.74.1+ | ⚠️ Build only |
| illumos | x86_64 | 1.74.1+ | ⚠️ Build only |
| Android | x86_64, arm64 | 1.74.1+ | ✅ Tested |
| iOS | arm64 | 1.74.1+ | ⚠️ Build only |
| WASM | wasm32 | 1.74.1+ | ⚠️ Limited features |

### Tier 3: Experimental Support
These platforms may compile but are not regularly tested.

| Platform | Architecture | Status |
|----------|--------------|--------|
| Linux | riscv64 | 🧪 Experimental |
| Linux | s390x | 🧪 Experimental |
| Linux | powerpc64le | 🧪 Experimental |
| Embedded | thumbv7em | 🧪 No std only |
| Embedded | thumbv8m | 🧪 No std only |
| Redox OS | x86_64 | 🧪 Untested |
| Haiku | x86_64 | 🧪 Untested |

## Feature Availability by Platform

### Network Discovery
| Platform | Status | Notes |
|----------|--------|-------|
| Linux | ✅ Full | Uses netlink |
| macOS | ✅ Full | Uses system APIs |
| Windows | ✅ Full | Uses Win32 APIs |
| BSD | ⚠️ Partial | Basic support |
| WASM | ❌ Not available | No direct network access |

### Platform Certificate Verification
| Platform | Status | Notes |
|----------|--------|-------|
| Linux | ✅ | Uses system cert store |
| macOS | ✅ | Uses Keychain |
| Windows | ✅ | Uses Windows cert store |
| Android | ✅ | Uses Android cert store |
| iOS | ✅ | Uses iOS cert store |
| WASM | ❌ | Not supported |

### Async Runtime Support
| Platform | Tokio | async-std |
|----------|-------|-----------|
| Linux | ✅ | ✅ |
| macOS | ✅ | ✅ |
| Windows | ✅ | ✅ |
| BSD | ✅ | ⚠️ |
| WASM | ⚠️ | ⚠️ |

## Platform-Specific Considerations

### Linux
- Requires glibc 2.17+ or musl libc
- Full NAT traversal support
- Best performance with kernel 5.10+
- Supports io_uring on kernel 5.19+

### macOS
- Requires macOS 11.0+ for full feature support
- Universal binaries supported (x86_64 + aarch64)
- Network extension capabilities available
- Keychain integration for certificates

### Windows
- Requires Windows 10 1809+ or Windows Server 2019+
- Full Windows Firewall integration
- Uses Windows certificate store
- Supports both MSVC and GNU toolchains

### BSD Systems
- FreeBSD: Full support with minor limitations
- NetBSD/OpenBSD: Basic functionality, limited testing
- Uses kqueue for async I/O

### Mobile Platforms
- Android: Requires NDK r21+, API level 21+
- iOS: Requires iOS 12.0+, build-only support
- Limited background operation capabilities

### Embedded Systems
- No std support available
- Requires custom allocator
- Limited to core protocol functionality
- No async runtime included

### WebAssembly
- Browser environment only
- No direct UDP socket access
- Requires WebRTC datachannel transport
- Limited to client-side operations

## Building for Different Platforms

### Native Compilation
```bash
# Linux/macOS/Windows
cargo build --release

# With specific features
cargo build --release --no-default-features --features rustls-ring,runtime-tokio
```

### Cross Compilation
```bash
# Install cross
cargo install cross

# Build for Linux ARM64
cross build --target aarch64-unknown-linux-gnu --release

# Build for Android
cross build --target aarch64-linux-android --release

# Build for iOS
cargo build --target aarch64-apple-ios --release
```

### WASM Compilation
```bash
# Install wasm-pack
curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh

# Build for WASM
wasm-pack build --target web -- --no-default-features
```

## Testing on Different Platforms

### Running Platform Tests
```bash
# Run platform-specific tests
cargo test --features platform-tests

# Run with platform test script
.github/scripts/platform-test.sh
```

### CI Platform Matrix
Our CI tests the following combinations:
- OS: Ubuntu (20.04, 22.04, latest), Windows (2019, 2022), macOS (12, 13, 14)
- Rust: stable, beta, nightly, MSRV (1.74.1)
- Architectures: x86_64, aarch64, i686, armv7

## Known Platform Issues

### Linux
- Issue #XXX: Symmetric NAT detection may fail on older kernels
- Issue #XXX: io_uring support requires kernel 5.19+

### macOS
- Issue #XXX: Firewall prompts on first run
- Issue #XXX: Rosetta 2 translation overhead on Intel binaries

### Windows
- Issue #XXX: Windows Defender may flag first-time network access
- Issue #XXX: Long path support requires Windows 10 1607+

### WASM
- Issue #XXX: No UDP socket support (requires WebRTC)
- Issue #XXX: Limited to single-threaded operation

## Platform-Specific Optimizations

### Linux
- Uses epoll for efficient I/O multiplexing
- Supports SO_REUSEPORT for load balancing
- Can use io_uring for better performance

### macOS
- Uses kqueue for I/O notifications
- Optimized for Apple Silicon with native builds
- Supports Network.framework integration

### Windows
- Uses IOCP for async I/O
- Integrated with Windows Filtering Platform
- Supports Windows-specific socket options

## Contributing Platform Support

To add support for a new platform:

1. Add platform detection in `src/platform/mod.rs`
2. Implement platform-specific modules in `src/platform/<platform>/`
3. Add CI configuration in `.github/workflows/cross-platform.yml`
4. Update this documentation
5. Add platform-specific tests in `tests/platform_specific/`

## Platform Support Lifecycle

- **Tier 1**: Must pass all tests, security updates within 24h
- **Tier 2**: Should pass tests, security updates within 7 days
- **Tier 3**: Best effort, community-supported

Platforms may be promoted/demoted based on:
- User demand
- CI reliability
- Maintenance burden
- Security considerations