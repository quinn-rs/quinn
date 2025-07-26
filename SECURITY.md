# Security Policy

## Supported Versions

We take security seriously and actively maintain the following versions of ant-quic:

| Version | Supported          |
| ------- | ------------------ |
| 0.4.x   | :white_check_mark: |
| 0.3.x   | :x:                |
| < 0.3   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability in ant-quic, please report it responsibly.

### How to Report

1. **DO NOT** create a public GitHub issue for security vulnerabilities
2. Email security reports to: security@maidsafe.net
3. Use our PGP key for sensitive information (key ID: [TBD])

### What to Include

Please provide as much information as possible:

- Type of vulnerability (e.g., buffer overflow, SQL injection, cross-site scripting)
- Affected component(s)
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response Timeline

- **Initial Response**: Within 48 hours
- **Triage**: Within 7 days
- **Fix Development**: Varies by severity
- **Public Disclosure**: Coordinated with reporter

## Security Measures

### Automated Security Scanning

We employ multiple automated security measures:

1. **Dependency Scanning**
   - Daily cargo-audit scans for known vulnerabilities
   - cargo-deny for license and security policy enforcement
   - Dependabot for automated updates

2. **Supply Chain Security**
   - cargo-vet for supply chain verification
   - SBOM generation for all releases
   - Signed commits and releases

3. **Code Security**
   - No unsafe code without thorough review
   - Memory safety enforced by Rust
   - Fuzz testing for protocol handlers

### Security Best Practices

When contributing to ant-quic:

1. **Dependencies**
   - Minimize external dependencies
   - Prefer well-maintained, audited crates
   - Pin dependency versions in Cargo.lock

2. **Cryptography**
   - Use established crypto libraries (rustls, ring)
   - Never implement custom crypto
   - Follow current best practices

3. **Network Security**
   - Validate all external input
   - Implement proper bounds checking
   - Use secure defaults

4. **Error Handling**
   - Never expose sensitive information in errors
   - Log security events appropriately
   - Fail securely

## Known Security Considerations

### NAT Traversal

The NAT traversal functionality introduces some security considerations:

- **Hole Punching**: Can potentially be abused for port scanning
- **Address Discovery**: Reveals network topology information
- **Relay Services**: Trust boundaries must be carefully managed

Mitigations are implemented but users should be aware of these aspects.

### Raw Public Keys

When using Raw Public Keys (RFC 7250):
- Proper key management is critical
- No certificate chain validation
- Application must verify key authenticity

## Security Audit History

| Date | Auditor | Scope | Report |
|------|---------|-------|--------|
| TBD  | TBD     | TBD   | TBD    |

## Bug Bounty Program

We currently do not have a bug bounty program but acknowledge security researchers in our releases.

## Security Updates

Security updates are released as:
- **Critical**: Immediate patch release
- **High**: Within 7 days
- **Medium**: Within 30 days
- **Low**: Next regular release

Subscribe to security announcements:
- GitHub Security Advisories
- RSS feed: [TBD]
- Mailing list: [TBD]

## Compliance

ant-quic follows security best practices from:
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [OWASP Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/)
- [Rust Security Guidelines](https://anssi-fr.github.io/rust-guide/)

## Contact

- Security Team: security@maidsafe.net
- Project Maintainers: @dirvine
- Security Advisory URL: https://github.com/dirvine/ant-quic/security/advisories