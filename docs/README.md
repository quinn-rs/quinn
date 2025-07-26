# ant-quic Documentation

Welcome to the ant-quic documentation! This directory contains comprehensive guides for testing, integrating, and troubleshooting ant-quic.

## 📚 Documentation Index

### For External Testers

1. **[Quick Start Guide](QUICK_START_TESTING.md)** - Get testing in under 5 minutes
   - Pre-built binaries
   - Docker images
   - Basic test commands

2. **[External Testing Guide](EXTERNAL_TESTING_GUIDE.md)** - Comprehensive testing instructions
   - Test scenarios
   - Interoperability matrix
   - Performance benchmarks

3. **[API Reference](API_REFERENCE.md)** - Complete API documentation
   - Client/Server APIs
   - NAT Traversal APIs
   - Transport parameters
   - Extension frames

4. **[Protocol Extensions](PROTOCOL_EXTENSIONS.md)** - QUIC protocol extensions
   - IETF draft implementations
   - Frame specifications
   - Security considerations

### CI/CD Documentation

5. **[CI/CD Guide](CI_CD_GUIDE.md)** - Comprehensive CI/CD documentation
   - Architecture overview
   - Workflow descriptions
   - Performance optimization

6. **[Workflow Reference](WORKFLOW_REFERENCE.md)** - Detailed workflow documentation
   - All workflows explained
   - Configuration options
   - Best practices

7. **[CI Troubleshooting](CI_TROUBLESHOOTING.md)** - Common CI/CD issues and solutions
   - Build failures
   - Test issues
   - Platform-specific problems

8. **[GitHub Secrets Setup](GITHUB_SECRETS_SETUP.md)** - Configure required secrets
   - Required secrets
   - Optional enhancements
   - Security best practices

9. **[CI Dashboard](ci-dashboard.html)** - Real-time CI status
   - Live workflow status
   - Build metrics
   - Coverage trends

### Testing Resources

10. **[Test Result Template](TEST_RESULT_TEMPLATE.md)** - Report your test results
    - Structured format
    - Required information
    - Submission process

11. **[Example Test Scripts](examples/)** - Ready-to-use test scripts
    - [`test_interop.py`](examples/test_interop.py) - Python interoperability tester

12. **[Troubleshooting Guide](TROUBLESHOOTING.md)** - Solve common issues
    - Connection problems
    - NAT traversal issues
    - Platform-specific fixes

13. **[Coverage Guide](COVERAGE_GUIDE.md)** - Code coverage configuration
    - Coverage tools
    - Report generation
    - CI integration

14. **[External Validation Guide](EXTERNAL_VALIDATION_GUIDE.md)** - Endpoint validation
    - Public endpoint testing
    - Validation workflow
    - Adding new endpoints

### Deployment

15. **[Public QUIC Endpoints](public-quic-endpoints.md)** - Known QUIC servers
    - Major providers
    - Test servers
    - Research implementations

16. **[QUIC Endpoint Testing Report](quic-endpoint-testing-report.md)** - Latest results
    - Validation status
    - Performance metrics
    - Compatibility matrix

## 🚀 Quick Links

### Test Now
```bash
# Download and test immediately
wget https://github.com/dirvine/ant-quic/releases/latest/download/ant-quic-linux-x86_64
chmod +x ant-quic-linux-x86_64
./ant-quic-linux-x86_64 --connect quic.saorsalabs.com:9000
```

### Docker Testing
```bash
docker run --rm ghcr.io/dirvine/ant-quic:latest \
    ant-quic --connect quic.saorsalabs.com:9000 --enable-nat-traversal
```

### Python Testing
```bash
wget https://raw.githubusercontent.com/dirvine/ant-quic/main/docs/examples/test_interop.py
python3 test_interop.py --all
```

## 📊 Test Endpoints

### Production Test Server
- **Host**: `quic.saorsalabs.com`
- **Port**: `9000` (UDP)
- **Dashboard**: https://quic.saorsalabs.com
- **Health**: https://quic.saorsalabs.com/health

### Features Supported
- ✅ QUIC v1 (RFC 9000)
- ✅ NAT Traversal (draft-seemann-quic-nat-traversal-02)
- ✅ Address Discovery (draft-ietf-quic-address-discovery-00)
- ✅ 0-RTT
- ✅ Connection Migration
- ✅ Raw Public Keys (RFC 7250)

## 🧪 Testing Matrix

| Your Implementation | Expected Result |
|-------------------|-----------------|
| quinn | ✅ Full compatibility |
| quiche | ✅ Full compatibility |
| mvfst | ✅ Full compatibility |
| picoquic | ✅ Full compatibility |
| ngtcp2 | ✅ Full compatibility |
| Custom | Test and report! |

## 📈 Performance Targets

- **Handshake**: < 1 RTT with 0-RTT
- **NAT Traversal**: > 85% success rate
- **Throughput**: > 1 Gbps (network permitting)
- **Latency**: < 10ms overhead

## 🔧 Development

### Building from Source
```bash
git clone https://github.com/dirvine/ant-quic.git
cd ant-quic
cargo build --release --bin ant-quic
```

### Running Tests
```bash
cargo test
cargo test nat_traversal -- --nocapture
cargo bench
```

## 📝 Reporting

### Submit Test Results
1. Use the [Test Result Template](TEST_RESULT_TEMPLATE.md)
2. File via:
   - GitHub Issue with `test-results` label
   - Email to quic-quic.saorsalabs.com
   - PR to `docs/test-results/`

### Report Issues
- **Bugs**: https://github.com/dirvine/ant-quic/issues
- **Security**: security@example.com
- **Questions**: Discord/Matrix community

## 🎯 Goals

ant-quic aims to achieve:
- 100% RFC 9000 compliance
- >90% NAT traversal success rate
- <100ms connection establishment
- Cross-implementation compatibility

## 📄 License

Documentation is licensed under CC BY 4.0. See [LICENSE](../LICENSE) for details.

---

**Version**: 0.4.4
**Last Updated**: 2025-07-26
**Maintainer**: David Irvine (@dirvine)
