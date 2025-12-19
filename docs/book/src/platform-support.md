# Platform Support

ant-quic supports multiple platforms with varying levels of support.

## Support Tiers

### Tier 1: Full Support

Fully tested, CI coverage, production ready.

| Platform | Architecture | Notes |
|----------|-------------|-------|
| Linux | x86_64 | Primary development platform |
| Linux | aarch64 | ARM64 servers |
| macOS | x86_64 | Intel Macs |
| macOS | aarch64 | Apple Silicon |
| Windows | x86_64 | Windows 10+ |

### Tier 2: Best Effort

Builds and passes tests, but not in regular CI.

| Platform | Architecture | Notes |
|----------|-------------|-------|
| Linux | armv7 | Raspberry Pi, embedded |
| Android | aarch64 | Mobile devices |
| Android | x86_64 | Emulators |
| FreeBSD | x86_64 | BSD servers |

### Not Supported

| Platform | Reason |
|----------|--------|
| WASM | No raw UDP sockets |
| iOS | Restricted networking APIs |
| Browser | Sandbox restrictions |

## Platform-Specific Notes

### Linux

**Requirements**:
- glibc 2.17+ (or musl)
- Kernel 3.10+
- UDP networking

**Optimizations**:
```bash
# Increase UDP buffer sizes
sudo sysctl -w net.core.rmem_max=26214400
sudo sysctl -w net.core.wmem_max=26214400
```

**NAT Traversal**:
- Full support on all NAT types
- Best connectivity rates

### macOS

**Requirements**:
- macOS 10.13+ (High Sierra)
- Xcode Command Line Tools (for building)

**Optimizations**:
```bash
sudo sysctl -w kern.ipc.maxsockbuf=8388608
```

**Known Limitations**:
- Some corporate networks may block UDP

### Windows

**Requirements**:
- Windows 10 version 1607+
- Visual Studio Build Tools (for building)
- Windows Firewall exceptions for UDP

**Firewall Configuration**:
```powershell
# Allow UDP for your application
New-NetFirewallRule -DisplayName "ant-quic" -Direction Inbound -Protocol UDP -LocalPort 9000 -Action Allow
```

**Registry Optimization**:
```
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AFD\Parameters
  DefaultReceiveWindow = 8388608
  DefaultSendWindow = 8388608
```

### Android

**Requirements**:
- API level 21+ (Android 5.0)
- Network permission in manifest

**Manifest**:
```xml
<uses-permission android:name="android.permission.INTERNET" />
<uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
```

**Limitations**:
- Battery optimization may affect background connections
- VPN interoperability varies

### FreeBSD

**Requirements**:
- FreeBSD 12+
- clang or gcc

**Building**:
```bash
pkg install rust cmake
cargo build --release
```

## Building for Different Platforms

### Cross-Compilation

```bash
# Add target
rustup target add aarch64-unknown-linux-gnu

# Cross-compile
cargo build --target aarch64-unknown-linux-gnu --release
```

### Docker Builds

```dockerfile
# Multi-platform build
FROM rust:1.85 AS builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
COPY --from=builder /app/target/release/ant-quic /usr/local/bin/
CMD ["ant-quic"]
```

```bash
# Build for multiple architectures
docker buildx build --platform linux/amd64,linux/arm64 -t ant-quic .
```

## Feature Support by Platform

| Feature | Linux | macOS | Windows | Android |
|---------|-------|-------|---------|---------|
| NAT Traversal | Full | Full | Full | Full |
| Hole Punching | Full | Full | Full | Partial |
| PQC | Full | Full | Full | Full |
| Interface Discovery | Full | Full | Full | Limited |
| IPv6 | Full | Full | Full | Partial |

## Network Interface Discovery

ant-quic discovers local interfaces for candidate addresses.

### Linux

Uses `/proc/net/if_inet6` and `getifaddrs()`.

### macOS

Uses `getifaddrs()` and System Configuration framework.

### Windows

Uses `GetAdaptersAddresses()` Win32 API.

### Android

Limited to primary interface. Background discovery restricted.

## Crypto Provider Support

| Provider | Linux | macOS | Windows | Android |
|----------|-------|-------|---------|---------|
| ring | Full | Full | Full | Full |
| aws-lc-rs | Full | Full | Full | Partial |

### Recommendations

- **Linux/macOS/Windows**: Either provider works well
- **Android**: `ring` recommended (simpler build)
- **ARM**: `aws-lc-rs` has assembly optimizations

## Testing on Platforms

### Local Testing

```bash
# Run tests
cargo test

# Platform-specific test
cargo test --target x86_64-unknown-linux-gnu
```

### CI Matrix

```yaml
jobs:
  test:
    strategy:
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
        rust: [stable, 1.85.0]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@master
        with:
          toolchain: ${{ matrix.rust }}
      - run: cargo test
```

## Troubleshooting Platform Issues

### Linux: Permission Denied

```bash
# If bind fails on low ports
sudo setcap cap_net_bind_service=+ep ./target/release/ant-quic
```

### macOS: Network Extension

Some corporate MDM may require network extension approval.

### Windows: Firewall

```powershell
# Check if firewall is blocking
Get-NetFirewallRule -DisplayName "ant-quic"
```

### Android: Battery Optimization

```kotlin
// Request to ignore battery optimizations
val intent = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS)
intent.data = Uri.parse("package:$packageName")
startActivity(intent)
```

## See Also

- [Installation](./installation.md)
- [Troubleshooting](./troubleshooting.md)
- [Performance](./performance.md)

