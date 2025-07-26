# Public QUIC Endpoints for Testing

This document provides a comprehensive list of publicly available QUIC endpoints that can be used for testing IETF compliance, interoperability, and protocol validation.

Last Updated: 2025-07-25

## Major Provider Endpoints

### Google
- **Primary endpoint**: `www.google.com:443`
- **Test endpoint**: `quic.rocks:4433`
- **Supported versions**: QUIC v1, gQUIC (various versions)
- **Notes**: Used by Chrome for >50% of connections to Google servers

### Cloudflare
- **Test site**: `cloudflare-quic.com:443`
- **Production**: All Cloudflare-enabled sites support HTTP/3
- **Supported versions**: IETF QUIC v1, draft versions
- **Notes**: Uses CUBIC for congestion control

### Facebook/Meta
- **Production endpoint**: `facebook.com:443`
- **CDN endpoints**: Various Facebook CDN URLs
- **Supported versions**: IETF QUIC v1
- **Notes**: Deployed in production since 2018

### LiteSpeed
- **Standard test**: `http3-test.litespeedtech.com:4433`
- **Retry test**: `http3-test.litespeedtech.com:4434` (sends stateless retry)
- **Speed test**: `http3-test.litespeedtech.com:4435` (optimized for downloads)
- **Multi-version**: `http3-test.litespeedtech.com:4437` (supports various QUIC versions)
- **PreferredAddress**: `http3-test.litespeedtech.com:4438`
- **Production**: `www.litespeedtech.com:443`
- **Supported versions**: QUIC v1, ID-34, ID-29, ID-27, gQUIC Q043/Q046/Q050

### Private Octopus (Picoquic)
- **Test server**: `test.privateoctopus.com:4433`
- **Retry test**: `test.privateoctopus.com:4434`
- **Supported versions**: Latest IETF drafts
- **Notes**: Server logs accessible at https://test.privateoctopus.com/

### PQUIC
- **Test endpoint**: `test.pquic.org:443`
- **Supported versions**: Pluginized QUIC implementation
- **Notes**: Research implementation with plugin support

### NGINX
- **Official endpoint**: `quic.nginx.org:443`
- **Supported versions**: QUIC v1 (since NGINX 1.25.0)
- **Notes**: Experimental support

## Specialized Testing Infrastructure

### QUIC Interop Runner
- **Dashboard**: https://interop.seemann.io/
- **Purpose**: Automated interoperability testing
- **Implementations**: 13+ different QUIC implementations
- **Test cases**: Version negotiation, handshake, retry, 0-RTT, migration

### HTTP/3 Check Service
- **URL**: https://http3check.net/
- **Purpose**: Verify HTTP/3 support for any domain
- **Usage**: Can test any public endpoint

## Testing by Provider Type

### CDN/Cloud Providers Supporting QUIC
1. **Cloudflare** - All zones can enable HTTP/3
2. **AWS CloudFront** - Supports connection migration
3. **Akamai** - QUIC support since 2016
4. **Hostinger** - Supports connection migration

### DNS-over-QUIC Endpoints
- **AdGuard**: `quic://dns.adguard.com`
- **NextDNS**: Check current documentation
- **Note**: Google and Cloudflare primarily use DNS-over-HTTPS

## Testing Recommendations

### Basic Connectivity Test
```bash
# Using quiche client
cargo run --bin quiche-client -- https://cloudflare-quic.com/

# Using curl with HTTP/3 support
curl --http3 https://quic.rocks:4433
```

### Browser Testing
1. Chrome: Visit `chrome://net-internals/#quic` to see QUIC sessions
2. Firefox: Enable HTTP/3 in about:config
3. Safari: HTTP/3 enabled by default in recent versions

### Automated Testing
Use the QUIC Interop Runner for comprehensive testing:
- Repository: https://github.com/quic-interop/quic-interop-runner
- Includes test cases for all major protocol features

## Important Notes

1. **Port Usage**: Most QUIC endpoints use UDP port 443
2. **Version Support**: Always verify supported QUIC versions before testing
3. **Availability**: Public endpoints may change; verify availability before automated testing
4. **Rate Limiting**: Be respectful of public endpoints; some may have rate limits
5. **Performance Variance**: Different implementations use different congestion control algorithms (e.g., Cloudflare uses CUBIC, Google uses BBR)

## Integration with ant-quic

To use these endpoints in the ant-quic compliance validator:

```rust
pub const PUBLIC_QUIC_ENDPOINTS: &[&str] = &[
    "quic.nginx.org:443",
    "cloudflare.com:443",
    "www.google.com:443",
    "facebook.com:443",
    "http3-test.litespeedtech.com:4433",
    "test.privateoctopus.com:4433",
    "www.litespeedtech.com:443",
    "cloudflare-quic.com:443",
    "quic.rocks:4433",
];
```

## References

1. QUIC Interop Runner: https://github.com/quic-interop/quic-interop-runner
2. IETF QUIC Working Group: https://quicwg.org/
3. HTTP/3 Specification: RFC 9114
4. QUIC Transport: RFC 9000