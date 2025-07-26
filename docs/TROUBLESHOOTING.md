# Troubleshooting Guide for ant-quic

This guide helps diagnose and resolve common issues with ant-quic's NAT traversal and address discovery features.

## Table of Contents
1. [Connection Issues](#connection-issues)
2. [NAT Traversal Problems](#nat-traversal-problems)
3. [Address Discovery Issues](#address-discovery-issues)
4. [Performance Problems](#performance-problems)
5. [Authentication Failures](#authentication-failures)
6. [Bootstrap Node Issues](#bootstrap-node-issues)
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

2. **Verify bootstrap nodes are running**
   ```rust
   // Use multiple bootstrap nodes for redundancy
   let config = NatTraversalConfig {
       bootstrap_nodes: vec![
           "quic.saorsalabs.com:9000".parse()?
       ],
       ..Default::default()
   };
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
   RUST_LOG=ant_quic=debug,quinn=debug cargo run
   ```

### Problem: Connections drop after establishment

**Symptoms:**
- Initial connection succeeds
- Connection drops after a few seconds
- "Connection reset" errors

**Solutions:**

1. **Increase connection timeout**
   ```rust
   let config = QuicNodeConfig {
       connection_timeout: Duration::from_secs(60), // Increase from 30s
       ..Default::default()
   };
   ```

2. **Check for network instability**
   ```rust
   // Monitor connection events
   endpoint.set_event_callback(|event| {
       match event {
           ConnectionEvent::ConnectionLost { reason } => {
               eprintln!("Connection lost: {:?}", reason);
           }
           _ => {}
       }
   });
   ```

3. **Verify keepalive settings**
   ```rust
   // QUIC handles keepalives automatically
   // But you can adjust transport parameters
   let mut transport_config = TransportConfig::default();
   transport_config.keep_alive_interval(Some(Duration::from_secs(15)));
   ```

## NAT Traversal Problems

### Problem: NAT traversal fails with symmetric NAT

**Symptoms:**
- Works on some networks but not others
- "No viable candidates" error
- Connection works with relay but not direct

**Solutions:**

1. **Enable address discovery (if disabled)**
   ```rust
   // Ensure address discovery is enabled
   endpoint_config.set_address_discovery_enabled(true);
   ```

2. **Increase candidate discovery timeout**
   ```rust
   let config = NatTraversalConfig {
       discovery_timeout: Duration::from_secs(10), // Increase from 5s
       max_candidates: 15, // Increase from 10
       ..Default::default()
   };
   ```

3. **Use more bootstrap nodes**
   ```rust
   // More bootstrap nodes = better NAT detection
   let bootstrap_nodes = vec![
       "us-east.bootstrap.com:9000".parse()?,
       "eu-west.bootstrap.com:9000".parse()?,
       "asia-pacific.bootstrap.com:9000".parse()?,
   ];
   ```

4. **Check NAT type**
   ```rust
   // Log discovered addresses to understand NAT behavior
   let addresses = endpoint.discovered_addresses();
   for addr in addresses {
       println!("Discovered: {} (check if port changes)", addr);
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
   let config = NatTraversalConfig {
       coordination_timeout: Duration::from_secs(20), // Increase from 10s
       ..Default::default()
   };
   ```

2. **Check time synchronization**
   ```bash
   # Ensure system clocks are synchronized
   # Linux/macOS
   ntpdate -q pool.ntp.org

   # Windows
   w32tm /query /status
   ```

3. **Verify bootstrap node connectivity**
   ```rust
   // Monitor bootstrap connection health
   for bootstrap in &config.bootstrap_nodes {
       match endpoint.ping_bootstrap(bootstrap).await {
           Ok(rtt) => println!("Bootstrap {} RTT: {:?}", bootstrap, rtt),
           Err(e) => eprintln!("Bootstrap {} unreachable: {}", bootstrap, e),
       }
   }
   ```

## Address Discovery Issues

### Problem: No addresses being discovered

**Symptoms:**
- `discovered_addresses()` returns empty
- No OBSERVED_ADDRESS frames in logs
- NAT traversal using only local addresses

**Solutions:**

1. **Check if address discovery is enabled**
   ```rust
   // Verify configuration
   if !endpoint_config.address_discovery_enabled() {
       endpoint_config.set_address_discovery_enabled(true);
   }
   ```

2. **Verify transport parameter negotiation**
   ```bash
   # Enable transport parameter logging
   RUST_LOG=ant_quic::transport_parameters=trace cargo run
   ```

3. **Check rate limiting**
   ```rust
   // Temporarily increase rate limit for testing
   endpoint_config.set_max_observation_rate(60);

   // Check statistics
   let stats = endpoint.address_discovery_stats();
   println!("Observation rate limited: {}", stats.rate_limited_count);
   ```

### Problem: Wrong addresses being observed

**Symptoms:**
- Discovered addresses are internal/private
- IPv6 addresses when expecting IPv4
- Addresses don't match actual external IP

**Solutions:**

1. **Validate bootstrap node configuration**
   ```rust
   // Ensure bootstrap nodes are on public IPs
   for bootstrap in &bootstrap_nodes {
       if is_private_ip(bootstrap.ip()) {
           eprintln!("Warning: Bootstrap {} is on private IP", bootstrap);
       }
   }
   ```

2. **Check for proxies or tunnels**
   ```bash
   # Check if behind proxy
   curl -s https://api.ipify.org

   # Compare with discovered addresses
   ```

3. **Force specific address family**
   ```rust
   // For IPv4-only networks
   let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;

   // For IPv6-only networks
   let socket = std::net::UdpSocket::bind("[::]:0")?;
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
   let config = QuicNodeConfig {
       max_connections: 50, // Reduce from 100
       ..Default::default()
   };
   ```

2. **Adjust observation rates**
   ```rust
   // Reduce address observation frequency
   endpoint_config.set_max_observation_rate(10); // Reduce from 30
   ```

3. **Profile the application**
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

1. **Limit pending operations**
   ```rust
   let auth_config = AuthConfig {
       max_pending_auths: 50, // Reduce from 100
       ..Default::default()
   };
   ```

2. **Configure buffer sizes**
   ```rust
   let mut transport_config = TransportConfig::default();
   transport_config.stream_receive_window(256 * 1024); // Reduce window
   transport_config.receive_window(512 * 1024);
   ```

3. **Monitor for leaks**
   ```bash
   # Use valgrind on Linux
   valgrind --leak-check=full cargo run

   # Use heaptrack
   heaptrack cargo run
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
   // Check if keys are properly generated
   let (private_key, public_key) = generate_ed25519_keypair();
   let peer_id = derive_peer_id_from_public_key(&public_key);
   println!("Generated peer ID: {:?}", peer_id);
   ```

2. **Check challenge-response timeout**
   ```rust
   let auth_config = AuthConfig {
       challenge_timeout: Duration::from_secs(60), // Increase timeout
       ..Default::default()
   };
   ```

3. **Verify time synchronization**
   ```rust
   // Authentication includes timestamps
   let now = SystemTime::now();
   println!("System time: {:?}", now);
   ```

### Problem: Certificate validation errors

**Symptoms:**
- "Certificate verification failed"
- "Unknown CA" errors
- TLS handshake failures

**Solutions:**

1. **Use raw public keys instead**
   ```rust
   // ant-quic supports RFC 7250 raw public keys
   // No certificate chain needed
   ```

2. **Check certificate expiry**
   ```rust
   // For custom certificates
   let cert = load_certificate()?;
   if cert.is_expired() {
       eprintln!("Certificate has expired!");
   }
   ```

## Bootstrap Node Issues

### Problem: Bootstrap node overwhelmed

**Symptoms:**
- Bootstrap node high CPU/memory
- Slow response times
- Connection timeouts to bootstrap

**Solutions:**

1. **Scale horizontally**
   ```rust
   // Run multiple bootstrap nodes
   // Load balance using DNS round-robin
   ```

2. **Adjust bootstrap configuration**
   ```rust
   // For bootstrap nodes
   let config = NatTraversalConfig {
       role: EndpointRole::Server { can_coordinate: true },
       max_connections: 1000, // Increase limit
       ..Default::default()
   };
   ```

3. **Implement rate limiting**
   ```rust
   // Per-IP rate limiting for bootstrap
   struct BootstrapRateLimiter {
       limits: HashMap<IpAddr, RateLimiter>,
   }
   ```

### Problem: Bootstrap coordination failures

**Symptoms:**
- "Coordinator unreachable" errors
- Hole punching never starts
- Peers can't find each other

**Solutions:**

1. **Verify coordinator role**
   ```rust
   // Ensure bootstrap can coordinate
   let config = NatTraversalConfig {
       role: EndpointRole::Server { can_coordinate: true },
       ..Default::default()
   };
   ```

2. **Check coordinator capacity**
   ```rust
   // Monitor active coordination sessions
   let stats = bootstrap_endpoint.coordination_stats();
   println!("Active sessions: {}", stats.active_sessions);
   println!("Session capacity: {}", stats.max_sessions);
   ```

## Debugging Tools

### Enable detailed logging

```bash
# Full debug logging
RUST_LOG=ant_quic=trace,quinn=debug cargo run

# Specific module logging
RUST_LOG=ant_quic::nat_traversal=debug cargo run
RUST_LOG=ant_quic::address_discovery=trace cargo run

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

### Connection state inspection

```rust
// Add connection state logging
endpoint.set_debug_callback(|state| {
    println!("Connection state: {:?}", state);
    println!("Active paths: {:?}", state.paths);
    println!("Discovered addresses: {:?}", state.discovered);
});
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
- **Fix**: Enable address discovery, add more bootstrap nodes

### "Coordination timeout reached"
- **Cause**: Hole punching coordination failed
- **Fix**: Increase timeout, check bootstrap connectivity

### "Rate limit exceeded for observations"
- **Cause**: Too many observation frames
- **Fix**: Normal behavior, adjust rate limit if needed

### "Authentication challenge expired"
- **Cause**: Response took too long
- **Fix**: Check network latency, increase timeout

### "Connection migration failed"
- **Cause**: Network change during connection
- **Fix**: Normal behavior, connection will retry

### "Bootstrap node connection refused"
- **Cause**: Bootstrap not running or firewall blocking
- **Fix**: Verify bootstrap status, check firewall

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

**Problem**: DNS resolution slow
```rust
// Use specific DNS resolver
std::env::set_var("TRUST_DNS_RESOLVER", "8.8.8.8");
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
let local_addr = "192.168.1.100:9000".parse()?;
config.bind_addr = Some(local_addr);
```

## FAQ

### Q: Why is address discovery important for NAT traversal?
**A**: Address discovery provides accurate external addresses without STUN servers, improving connection success rates by 27% and making connections 7x faster.

### Q: Can I disable address discovery for privacy?
**A**: Yes, set `endpoint_config.set_address_discovery_enabled(false)`. Note that this may reduce connection success rates.

### Q: How many bootstrap nodes should I use?
**A**: Use at least 3 bootstrap nodes in different geographic locations for redundancy.

### Q: What's the overhead of address discovery?
**A**: Minimal - approximately 15ns per frame processing and 100 bytes per path for tracking.

### Q: Can I use ant-quic without bootstrap nodes?
**A**: Yes, if peers have public IPs or are on the same local network. Bootstrap nodes are primarily for NAT traversal coordination.

### Q: How do I know what type of NAT I'm behind?
**A**: Check the discovered addresses - if the port changes between connections, you're likely behind a symmetric NAT.

### Q: Why do connections fail even with address discovery?
**A**: Some network configurations (CGNAT, strict firewalls) may still block direct connections. Consider using a relay as fallback.

### Q: How can I improve connection reliability?
**A**: Use multiple bootstrap nodes, enable address discovery, increase timeouts, and implement retry logic with exponential backoff.

## Getting Help

If you've tried the solutions above and still have issues:

1. **Enable debug logging** and collect logs
2. **Check GitHub issues** for similar problems
3. **File a bug report** with:
   - ant-quic version
   - Platform and OS version
   - Network configuration
   - Debug logs
   - Steps to reproduce

Report issues at: https://github.com/autonomi/ant-quic/issues
