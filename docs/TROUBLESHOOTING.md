# Troubleshooting Guide for ant-quic

This guide helps diagnose and resolve common issues with ant-quic's v0.13.0+ NAT traversal and address discovery features.

## Table of Contents
1. [Connection Issues](#connection-issues)
2. [NAT Traversal Problems](#nat-traversal-problems)
3. [Address Discovery Issues](#address-discovery-issues)
4. [Performance Problems](#performance-problems)
5. [Authentication Failures](#authentication-failures)
6. [PQC Issues](#pqc-issues)
7. [Debugging Tools](#debugging-tools)
8. [Common Error Messages](#common-error-messages)
9. [Platform-Specific Issues](#platform-specific-issues)
10. [FAQ](#faq)

## Connection Issues

### Problem: Cannot connect to any peers

**Symptoms:**
- Connection attempts timeout
- No successful peer connections
- "Connection refused" errors

**Solutions:**

1. **Check network connectivity**
   ```bash
   # Test basic network connectivity
   ping quic.saorsalabs.com

   # Check if port is reachable
   nc -zv quic.saorsalabs.com 9000
   ```

2. **Verify known peers are running**
   ```rust
   let config = P2pConfig::builder()
       .known_peer("peer1.example.com:9000".parse()?)
       .known_peer("peer2.example.com:9000".parse()?)
       .build()?;
   ```

3. **Check firewall settings**
   ```bash
   # Linux: Check iptables
   sudo iptables -L -n | grep 9000

   # macOS: Check firewall
   sudo pfctl -sr | grep 9000

   # Windows: Check Windows Firewall
   netsh advfirewall firewall show rule name=all | findstr 9000
   ```

4. **Enable debug logging**
   ```bash
   RUST_LOG=ant_quic=debug cargo run
   ```

### Problem: Connections drop after establishment

**Symptoms:**
- Initial connection succeeds
- Connection drops after a few seconds
- "Connection reset" errors

**Solutions:**

1. **Increase connection timeout**
   ```rust
   let config = P2pConfig::builder()
       .connection_timeout(Duration::from_secs(60))
       .build()?;
   ```

2. **Monitor connection events**
   ```rust
   let mut events = endpoint.subscribe();
   while let Ok(event) = events.recv().await {
       match event {
           P2pEvent::Disconnected { peer_id, reason } => {
               eprintln!("Disconnected from {}: {}", peer_id.to_hex(), reason);
           }
           _ => {}
       }
   }
   ```

3. **Check keepalive settings**
   ```rust
   // QUIC handles keepalives automatically
   // Check that idle timeout is appropriate
   let config = P2pConfig::builder()
       .idle_timeout(Duration::from_secs(60))
       .build()?;
   ```

## NAT Traversal Problems

### Problem: NAT traversal fails with symmetric NAT

**Symptoms:**
- Works on some networks but not others
- "No viable candidates" error
- Connection works via relay but not direct

**Solutions:**

1. **Enable address discovery**
   ```rust
   // Address discovery is enabled by default in v0.13.0+
   // Verify with debug logging:
   RUST_LOG=ant_quic::address_discovery=debug cargo run
   ```

2. **Increase candidate discovery timeout**
   ```rust
   let config = P2pConfig::builder()
       .nat(NatConfig {
           discovery_timeout: Duration::from_secs(10),
           max_candidates: 15,
           enable_symmetric_nat: true,
           ..Default::default()
       })
       .build()?;
   ```

3. **Use more known peers**
   ```rust
   // More known peers = better address observation
   let config = P2pConfig::builder()
       .known_peer("us-east.example.com:9000".parse()?)
       .known_peer("eu-west.example.com:9000".parse()?)
       .known_peer("asia.example.com:9000".parse()?)
       .build()?;
   ```

4. **Check NAT type**
   ```rust
   // Log discovered addresses to understand NAT behavior
   let addresses = endpoint.discovered_addresses();
   for addr in addresses {
       println!("Discovered: {} (check if port varies)", addr);
   }
   ```

### Problem: Hole punching timeout

**Symptoms:**
- "Coordination timeout" errors
- Candidates discovered but connection fails
- Works sometimes but not consistently

**Solutions:**

1. **Increase coordination timeout**
   ```rust
   let config = P2pConfig::builder()
       .nat(NatConfig {
           coordination_timeout: Duration::from_secs(20),
           hole_punch_retries: 8,
           ..Default::default()
       })
       .build()?;
   ```

2. **Check time synchronization**
   ```bash
   # Ensure system clocks are synchronized
   # Linux/macOS
   ntpdate -q pool.ntp.org

   # Windows
   w32tm /query /status
   ```

3. **Verify peer connectivity**
   ```rust
   // Test connection to known peer
   let connection = endpoint.connect("peer.example.com:9000".parse()?).await;
   match connection {
       Ok(_) => println!("Known peer reachable"),
       Err(e) => eprintln!("Known peer unreachable: {}", e),
   }
   ```

## Address Discovery Issues

### Problem: No addresses being discovered

**Symptoms:**
- `discovered_addresses()` returns empty
- No OBSERVED_ADDRESS frames in logs
- NAT traversal using only local addresses

**Solutions:**

1. **Connect to known peers first**
   ```rust
   // Address discovery requires at least one connection
   endpoint.connect_bootstrap().await?;

   // Then check addresses
   let addresses = endpoint.discovered_addresses();
   println!("Discovered {} addresses", addresses.len());
   ```

2. **Verify transport parameter negotiation**
   ```bash
   # Enable transport parameter logging
   RUST_LOG=ant_quic::transport_parameters=trace cargo run
   ```

3. **Check if peers support address discovery**
   ```bash
   # Look for OBSERVED_ADDRESS frames in trace logs
   RUST_LOG=ant_quic::frame=trace cargo run 2>&1 | grep OBSERVED_ADDRESS
   ```

### Problem: Wrong addresses being observed

**Symptoms:**
- Discovered addresses are internal/private
- IPv6 addresses when expecting IPv4
- Addresses don't match actual external IP

**Solutions:**

1. **Validate peer connectivity**
   ```bash
   # Check your actual external IP
   curl -s https://api.ipify.org

   # Compare with discovered addresses in logs
   ```

2. **Check for proxies or tunnels**
   ```bash
   # Verify you're not behind VPN or proxy
   traceroute peer.example.com
   ```

3. **Force specific address family**
   ```rust
   // For IPv4-only
   let config = P2pConfig::builder()
       .bind_addr("0.0.0.0:9000".parse()?)
       .build()?;

   // For IPv6-only
   let config = P2pConfig::builder()
       .bind_addr("[::]:9000".parse()?)
       .build()?;
   ```

## Performance Problems

### Problem: High CPU usage

**Symptoms:**
- CPU usage above 50%
- System becomes unresponsive
- Many threads active

**Solutions:**

1. **Reduce connection limits**
   ```rust
   let config = P2pConfig::builder()
       .max_connections(50)
       .build()?;
   ```

2. **Profile the application**
   ```bash
   # Use cargo flamegraph
   cargo install flamegraph
   cargo flamegraph --bin ant-quic
   ```

### Problem: High memory usage

**Symptoms:**
- Memory usage grows over time
- Out of memory errors
- System swapping

**Solutions:**

1. **Tune PQC memory pool**
   ```rust
   let config = P2pConfig::builder()
       .pqc(PqcConfig::builder()
           .memory_pool_size(5)  // Reduce from default 10
           .build()?)
       .build()?;
   ```

2. **Monitor for leaks**
   ```bash
   # Use valgrind on Linux
   valgrind --leak-check=full ./ant-quic

   # Use heaptrack
   heaptrack ./ant-quic
   ```

## Authentication Failures

### Problem: Peer authentication fails

**Symptoms:**
- "Authentication failed" errors
- "Invalid signature" messages
- Peers reject connections

**Solutions:**

1. **Verify key generation**
   ```rust
   use ant_quic::key_utils::{generate_ed25519_keypair, derive_peer_id};

   let (private_key, public_key) = generate_ed25519_keypair();
   let peer_id = derive_peer_id(&public_key);
   println!("Generated peer ID: {:?}", peer_id);
   ```

2. **Check Raw Public Key format**
   ```rust
   // ant-quic uses RFC 7250 Raw Public Keys
   // Ensure you're using Ed25519 keys, not certificates
   ```

3. **Verify time synchronization**
   ```rust
   // Authentication includes timestamps
   let now = std::time::SystemTime::now();
   println!("System time: {:?}", now);
   ```

## PQC Issues

### Problem: PQC handshake fails

**Symptoms:**
- "PQC negotiation failed" errors
- Handshake timeouts
- Cannot connect to any peers

**Solutions:**

1. **Check peer version compatibility**
   ```bash
   # v0.13.0+ requires PQC - older peers may not support it
   # Ensure all peers are running v0.13.0+
   ```

2. **Increase handshake timeout**
   ```rust
   let config = P2pConfig::builder()
       .pqc(PqcConfig::builder()
           .handshake_timeout_multiplier(2.0)
           .build()?)
       .build()?;
   ```

3. **Check for hardware support**
   ```bash
   # Verify CPU supports required instructions
   RUST_LOG=ant_quic::crypto::pqc=debug cargo run 2>&1 | grep -i "hardware\|simd\|avx"
   ```

### Problem: High PQC overhead

**Symptoms:**
- Slow connection establishment
- High CPU during handshakes
- Memory spikes

**Solutions:**

1. **Tune PQC settings**
   ```rust
   let config = P2pConfig::builder()
       .pqc(PqcConfig::builder()
           .memory_pool_size(10)
           .build()?)
       .build()?;
   ```

2. **Use connection pooling**
   ```rust
   // Reuse connections instead of creating new ones
   // PQC handshake overhead is amortized over connection lifetime
   ```

## Debugging Tools

### Enable detailed logging

```bash
# Full debug logging
RUST_LOG=ant_quic=trace cargo run

# Specific module logging
RUST_LOG=ant_quic::nat_traversal=debug cargo run
RUST_LOG=ant_quic::address_discovery=trace cargo run
RUST_LOG=ant_quic::crypto::pqc=debug cargo run

# Log to file
RUST_LOG=debug cargo run 2>&1 | tee debug.log
```

### Network packet capture

```bash
# Capture QUIC packets (UDP port 9000)
sudo tcpdump -i any -w quic.pcap 'udp port 9000'

# Analyze with Wireshark (has QUIC dissector)
wireshark quic.pcap
```

### Performance profiling

```bash
# CPU profiling
perf record --call-graph=dwarf cargo run
perf report

# Memory profiling
heaptrack cargo run
heaptrack --analyze heaptrack.cargo.12345.gz
```

## Common Error Messages

### "No viable candidates for connection"
- **Cause**: No valid address pairs found
- **Fix**: Enable address discovery, add more known peers

### "Coordination timeout reached"
- **Cause**: Hole punching coordination failed
- **Fix**: Increase timeout, check peer connectivity

### "PQC handshake failed: peer does not support PQC"
- **Cause**: Connecting to pre-v0.13.0 peer
- **Fix**: Upgrade peer to v0.13.0+

### "Authentication challenge expired"
- **Cause**: Response took too long
- **Fix**: Check network latency, increase timeout

### "Connection migration failed"
- **Cause**: Network change during connection
- **Fix**: Normal behavior, connection will retry

## Platform-Specific Issues

### Linux

**Problem**: Can't bind to port < 1024
```bash
# Allow binding to privileged ports
sudo setcap cap_net_bind_service=+ep ./ant-quic
```

**Problem**: Too many open files
```bash
# Increase file descriptor limit
ulimit -n 65536
```

### macOS

**Problem**: Firewall blocking connections
```bash
# Add to firewall exceptions
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add $(pwd)/ant-quic
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --unblockapp $(pwd)/ant-quic
```

### Windows

**Problem**: Windows Defender blocking
```powershell
# Add exclusion
Add-MpPreference -ExclusionPath "C:\path\to\ant-quic.exe"
```

**Problem**: Network interface detection fails
```rust
// Fallback to manual configuration
let config = P2pConfig::builder()
    .bind_addr("192.168.1.100:9000".parse()?)
    .build()?;
```

## FAQ

### Q: Why is address discovery important for NAT traversal?
**A**: Address discovery provides accurate external addresses without STUN servers, improving connection success rates by ~27% and making connections faster.

### Q: How many known peers should I use?
**A**: Use at least 3 known peers in different geographic locations for redundancy and accurate address observation.

### Q: What's the overhead of PQC?
**A**: Approximately 8% compared to classical-only cryptography. Connection pooling minimizes impact.

### Q: Can I use ant-quic without any known peers?
**A**: Yes, if peers have public IPs or are on the same local network. Known peers are primarily for NAT traversal and address discovery.

### Q: How do I know what type of NAT I'm behind?
**A**: Check discovered addresses - if the port changes between connections to different peers, you're likely behind a symmetric NAT.

### Q: Why do connections fail even with address discovery?
**A**: Some network configurations (CGNAT, strict firewalls) may still block direct connections. Consider using a relay as fallback.

### Q: Can I disable PQC for debugging?
**A**: No. In v0.13.0+, PQC is always enabled. Use debug logging instead to diagnose PQC issues.

### Q: How can I improve connection reliability?
**A**: Use multiple known peers, enable address discovery, increase timeouts, and implement retry logic with exponential backoff.

## Getting Help

If you've tried the solutions above and still have issues:

1. **Enable debug logging** and collect logs
2. **Check GitHub issues** for similar problems
3. **File a bug report** with:
   - ant-quic version (`ant-quic --version`)
   - Platform and OS version
   - Network configuration
   - Debug logs
   - Steps to reproduce

Report issues at: https://github.com/dirvine/ant-quic/issues
