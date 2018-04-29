# quicr

quicr is an implementation of the [QUIC](https://en.wikipedia.org/wiki/QUIC) network protocol [undergoing
standardization by the IETF](https://quicwg.github.io/). It is currently suitable for experimental use. The
implementation is split up into the state macine crate `quicr-core` which performs no IO internally and can be tested
deterministically, and a high-level tokio-compatible API in `quicr`. See `quicr/examples/` for usage.

[![MIT licensed][mit-badge]][mit-url]

[mit-badge]: https://img.shields.io/badge/license-MIT-blue.svg
[mit-url]: LICENSE-MIT

## Features

- Simultaneous client/server operation
- Ordered and unordered reads for improved performance

## Status

- [x] QUIC draft 11 with TLS 1.3 draft 28
- [x] Cryptographic handshake
- [x] Stream data w/ flow control and congestion control
- [x] Connection close
- [x] Stateless retry
- [ ] 0-RTT data
- [ ] Session resumption

## Building

Because TLS1.3 is a new standard, OpenSSL 1.1.1-pre5 (or later) is required for quicr to build. For compatibility with
most other QUIC implementations as of this writing, it should be patched with `openssl-tls-28.patch` in this repository.
