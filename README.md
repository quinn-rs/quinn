# quicr

quicr is an implementation of the [QUIC](https://en.wikipedia.org/wiki/QUIC) network protocol [undergoing
standardization by the IETF](https://quicwg.github.io/). It is currently suitable for experimental use. The
implementation is split up into the state machine crate `quicr-core` which performs no IO internally and can be tested
deterministically, and a high-level tokio-compatible API in `quicr`. See `quicr/examples/` for usage.

[![Crates.io](https://img.shields.io/crates/v/quicr.svg)](https://crates.io/crates/quicr)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE-MIT)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE-APACHE)

[API Docs](https://ralith.github.io/quicr/quicr/)

## Features

- Simultaneous client/server operation
- Ordered and unordered reads for improved performance

## Status

- [x] QUIC draft 11 with TLS 1.3 draft 28
- [x] Cryptographic handshake
- [x] Stream data w/ flow control and congestion control
- [x] Connection close
- [x] Stateless retry
- [ ] Migration
- [x] 0-RTT data
- [x] Session resumption

## Building

Because TLS1.3 is a new standard, OpenSSL 1.1.1-pre6 (or later) is required for quicr to build. For compatibility with
most other QUIC implementations as of this writing, it should be patched with `openssl-tls-28.patch` in this repository.
