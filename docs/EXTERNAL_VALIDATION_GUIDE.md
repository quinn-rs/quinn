# External QUIC Endpoint Validation Guide

## Overview

The external endpoint validation system tests ant-quic's ability to connect to real-world QUIC servers, verifying protocol compliance and interoperability. This automated system runs daily and provides continuous validation of our QUIC implementation.

## Components

### 1. Endpoint Database (`docs/public-quic-endpoints.yaml`)

A comprehensive database of public QUIC endpoints including:
- Major tech companies (Google, Meta, Cloudflare)
- CDN providers (Akamai, Fastly)
- Test servers (QUIC Interop Runner, LiteSpeed)
- Regional endpoints

Each endpoint includes:
- Connection details (host, port)
- Supported protocols (h3, h3-29, gQUIC)
- Features (0-RTT, connection migration, multipath)
- Reliability rating
- Category and notes

### 2. Test Binary (`test-public-endpoints`)

Enhanced testing tool with features:
- Parallel connection testing
- Comprehensive metrics collection
- Multiple output formats (JSON, Markdown)
- Analysis mode for historical data
- Configurable timeouts and retries

### 3. GitHub Actions Workflow (`.github/workflows/external-validation.yml`)

Automated workflow that:
- Runs daily at 2 AM UTC
- Tests all configured endpoints
- Generates performance reports
- Updates status badges
- Creates issues for failures
- Tracks historical trends

## Usage

### Manual Testing

```bash
# Test all endpoints
cargo run --bin test-public-endpoints

# Test specific endpoints
cargo run --bin test-public-endpoints -- --endpoints "Google,Cloudflare"

# Save results to JSON
cargo run --bin test-public-endpoints -- --output results.json

# Analyze previous results
cargo run --bin test-public-endpoints -- --analyze results.json --format markdown
```

### Configuration Options

```bash
# Custom configuration file
--config path/to/endpoints.yaml

# Connection timeout (seconds)
--timeout 15

# Parallel connections
--parallel 10

# Verbose logging
--verbose
```

## Metrics Collected

### Connection Metrics
- **Success Rate**: Percentage of successful connections
- **Handshake Time**: Time to complete QUIC handshake
- **RTT**: Round-trip time after connection
- **Protocol Support**: Which QUIC versions succeeded

### Aggregate Metrics
- **Average Handshake Time**: Across all successful connections
- **Regional Performance**: RTT by geographic region
- **Protocol Distribution**: Usage of different QUIC versions
- **Feature Availability**: Support for advanced features

## CI/CD Integration

### Scheduled Runs
The validation runs automatically every day, testing against all configured endpoints and updating the status report.

### Pull Request Testing
For PRs that modify QUIC protocol code:
```yaml
on:
  pull_request:
    paths:
      - 'src/**/*.rs'
      - 'Cargo.toml'
```

### Status Badges
![QUIC Compatibility](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/dirvine/ant-quic/main/.github/badges/quic-compatibility.json)
![Endpoints Tested](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/dirvine/ant-quic/main/.github/badges/endpoints-tested.json)

## Reports

### Daily Validation Report
Located at `docs/quic-endpoint-validation-report.md`, updated daily with:
- Detailed results for each endpoint
- Performance metrics
- Historical trends
- Failure analysis

### Performance Analysis
HTML report with visualizations:
- Success rate over time
- Handshake time by endpoint
- Protocol support distribution
- Regional performance comparison

## Adding New Endpoints

1. Edit `docs/public-quic-endpoints.yaml`:
```yaml
- name: New Endpoint
  host: example.com
  port: 443
  protocols:
    - h3
    - h3-29
  type: production
  category: test
  reliability: high
  features:
    - 0-RTT
  notes: Description of the endpoint
```

2. Test locally:
```bash
cargo run --bin test-public-endpoints -- --endpoints "New Endpoint"
```

3. Submit PR with the updated configuration

## Troubleshooting

### Common Issues

1. **DNS Resolution Failures**
   - Verify the hostname is correct
   - Check if the endpoint requires specific DNS settings

2. **Certificate Validation**
   - Ensure system certificates are up to date
   - Some test endpoints use self-signed certificates

3. **Protocol Mismatches**
   - Verify the endpoint supports the advertised protocols
   - Check ALPN negotiation in verbose logs

4. **Geographic Restrictions**
   - Some endpoints may be region-locked
   - Use regional CI runners if needed

### Debug Commands

```bash
# Enable debug logging
RUST_LOG=debug cargo run --bin test-public-endpoints -- --verbose

# Test single endpoint with detailed output
cargo run --bin test-public-endpoints -- \
  --endpoints "Google" \
  --verbose \
  --output debug.json
```

## Security Considerations

- The validation system only performs read operations
- No authentication credentials are used
- Connections are closed immediately after testing
- Rate limiting is respected (500ms between tests)

## Future Enhancements

- [ ] WebTransport endpoint testing
- [ ] QUIC v2 support validation
- [ ] Latency distribution analysis
- [ ] Packet loss simulation
- [ ] Multi-region testing from different locations