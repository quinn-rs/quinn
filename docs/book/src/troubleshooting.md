# Troubleshooting

Common issues and solutions for ant-quic.

## Connection Issues

### Cannot Connect to Known Peers

**Symptom**: `connect_bootstrap()` times out or fails.

**Solutions**:

1. **Check network connectivity**:
   ```bash
   ping quic.saorsalabs.com
   nc -zvu quic.saorsalabs.com 9000
   ```

2. **Verify port is not blocked**:
   ```bash
   # Check firewall
   sudo ufw status
   sudo iptables -L -n
   ```

3. **Try multiple known peers**:
   ```rust
   let config = P2pConfig::builder()
       .known_peer("peer1.example.com:9000".parse()?)
       .known_peer("peer2.example.com:9000".parse()?)
       .known_peer("peer3.example.com:9000".parse()?)
       .build()?;
   ```

4. **Increase timeout**:
   ```rust
   let config = P2pConfig::builder()
       .connection_timeout(Duration::from_secs(60))
       .build()?;
   ```

### Connection Refused

**Symptom**: Immediate connection failure.

**Causes**:
- Target not listening on the port
- Firewall blocking UDP
- Wrong address/port

**Debug**:
```bash
RUST_LOG=ant_quic::connection=debug cargo run
```

### Handshake Timeout

**Symptom**: Connection starts but times out during handshake.

**Solutions**:

1. **Allow more time for PQC handshake**:
   ```rust
   let pqc = PqcConfig::builder()
       .handshake_timeout_multiplier(2.0)
       .build()?;
   ```

2. **Check MTU issues**:
   ```rust
   let mtu = MtuConfig {
       initial: 1200,
       min: 1200,
       max: 1280, // Conservative
   };
   ```

## NAT Traversal Issues

### No External Address Discovered

**Symptom**: `external_address()` returns `None`.

**Solutions**:

1. **Ensure connected to known peer first**:
   ```rust
   endpoint.connect_bootstrap().await?;
   let addr = endpoint.external_address();
   ```

2. **Subscribe to events to see what's happening**:
   ```rust
   let mut events = endpoint.subscribe();
   while let Ok(event) = events.recv().await {
       match event {
           P2pEvent::AddressDiscovered { addr } => {
               println!("Discovered: {}", addr);
           }
           P2pEvent::ConnectionFailed { reason, .. } => {
               println!("Failed: {}", reason);
           }
           _ => {}
       }
   }
   ```

### Hole Punch Always Fails

**Symptom**: `HolePunchFailed` events for all attempts.

**Causes**:
- Both peers behind symmetric NAT
- Firewall blocking UDP
- Network doesn't support hole punching

**Solutions**:

1. **Check NAT type**:
   ```rust
   let candidates = endpoint.get_local_candidates();
   for c in candidates {
       println!("{:?}: {}", c.source, c.addr);
   }
   ```

2. **Enable symmetric NAT support**:
   ```rust
   let nat = NatConfig {
       enable_symmetric_nat: true,
       hole_punch_retries: 10,
       ..Default::default()
   };
   ```

3. **Use relay (if available)**:
   ```rust
   // Connect via a peer with public IP
   endpoint.connect_via_peer(peer_id, relay_addr).await?;
   ```

### Candidates Not Found

**Symptom**: `get_local_candidates()` returns empty.

**Solutions**:

1. **Wait for discovery**:
   ```rust
   endpoint.connect_bootstrap().await?;
   tokio::time::sleep(Duration::from_secs(2)).await;
   let candidates = endpoint.get_local_candidates();
   ```

2. **Increase candidate limit**:
   ```rust
   let nat = NatConfig {
       max_candidates: 20,
       discovery_timeout: Duration::from_secs(10),
       ..Default::default()
   };
   ```

## Crypto Issues

### PQC Handshake Failure

**Symptom**: Handshake fails with crypto error.

**Solutions**:

1. **Check both peers support PQC** (all v0.13.0+ do)

2. **Increase handshake timeout**:
   ```rust
   let pqc = PqcConfig::builder()
       .handshake_timeout_multiplier(3.0)
       .build()?;
   ```

3. **Check MTU for large PQC keys**:
   ```rust
   let mtu = MtuConfig {
       initial: 1200,
       min: 1200,
       max: 1500,
   };
   ```

### Certificate/Key Errors

**Note**: ant-quic uses Raw Public Keys (RFC 7250), not X.509 certificates.

**Symptom**: Key validation fails.

**Solutions**:

1. **Verify key generation**:
   ```rust
   use ant_quic::key_utils::{generate_ed25519_keypair, derive_peer_id};

   let (private, public) = generate_ed25519_keypair();
   let peer_id = derive_peer_id(&public);
   println!("Generated: {}", peer_id.to_hex());
   ```

## Build Issues

### Crypto Provider Conflicts

**Symptom**: Multiple crypto backends error.

**Solution**:
```toml
# Cargo.toml - use only one
ant-quic = { version = "0.13", default-features = false, features = ["rustls-aws-lc-rs"] }
```

### AWS-LC Build Failure

**Symptom**: CMake or compiler errors.

**Solution**:
```bash
# Install dependencies
# Ubuntu/Debian
sudo apt install build-essential cmake

# macOS
xcode-select --install
brew install cmake
```

### Link Errors

**Symptom**: Undefined symbols during linking.

**Solution**:
```bash
cargo clean
cargo build
```

## Logging and Debugging

### Enable Debug Logging

```bash
# Full debug
RUST_LOG=ant_quic=debug cargo run

# Specific modules
RUST_LOG=ant_quic::nat_traversal=trace cargo run
RUST_LOG=ant_quic::connection=debug cargo run
RUST_LOG=ant_quic::crypto::pqc=debug cargo run
```

### Capture Packet Traces

```bash
# With tcpdump
sudo tcpdump -i any -w capture.pcap udp port 9000

# With Wireshark
# Filter: udp.port == 9000
```

### Network Simulation

Use Docker for controlled testing:

```bash
cd docker/nat-test
docker-compose up
```

## Common Error Messages

| Error | Cause | Solution |
|-------|-------|----------|
| `ConnectionRefused` | No listener at address | Verify target is running |
| `TimedOut` | Network/firewall issue | Check connectivity |
| `HandshakeFailed` | Crypto mismatch | Verify both peers are v0.13.0+ |
| `NoViableCandidates` | NAT too restrictive | Enable symmetric NAT support |
| `CoordinationTimeout` | Slow coordination | Increase timeout |

## Getting Help

1. **Enable verbose logging** and capture output
2. **Check platform support** for your OS
3. **File an issue** at github.com/dirvine/ant-quic/issues

Include:
- ant-quic version
- OS and version
- Rust version
- Debug log output
- Network topology (behind NAT? VPN?)

## See Also

- [Configuration](./configuration.md) - All options
- [Performance](./performance.md) - Tuning guide
- [NAT Traversal](./nat-traversal.md) - How NAT traversal works

