# Quinn

[![Build status](https://api.travis-ci.org/djc/quinn.svg?branch=master)](https://travis-ci.org/djc/quinn)
[![codecov](https://codecov.io/gh/djc/quinn/branch/master/graph/badge.svg)](https://codecov.io/gh/djc/quinn)
[![Chat](https://badges.gitter.im/gitterHQ/gitter.svg)](https://gitter.im/djc/quinn)
[![Crates.io](https://img.shields.io/crates/v/quinn.svg)](https://crates.io/crates/quinn)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE-MIT)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE-APACHE)

[API Docs](https://ralith.github.io/quicr/quicr/)

Quinn is an implementation of the [QUIC][quic] network protocol currently
undergoing standardization by the IETF. It is currently suitable for
experimental use. The implementation is split up into the state machine crate
`quicr-core` which performs no I/O internally and can be tested deterministically,
and a high-level tokio-compatible API in `quicr`. See `quicr/examples/` for usage.

Quinn is the subject of a [RustFest Paris (May 2018) presentation][talk]; you can
also get the [slides][slides] (and the [animation][animation] about head-of-line
blocking). Video of the talk is available [on YouTube][youtube]. Since this
presentation, Quinn has been merged with quicr, another Rust implementation.

All feedback welcome. Feel free to file bugs, requests for documentation and
any other feedback to the [issue tracker][issues].

Quinn was created and is maintained by by Dirkjan Ochtman and Benjamin Saunders.

## Features

* Currently targets QUIC draft 11, but with final TLS 1.3 per RFC 8446
* Simultaneous client/server operation
* Ordered and unordered reads for improved performance
* Uses [rustls][rustls] for all TLS operations
* Uses [*ring*][ring] for AEAD encryption/decryption

## Status

- [x] QUIC draft 11 with TLS 1.3 draft 28
- [x] Cryptographic handshake
- [x] Stream data w/ flow control and congestion control
- [x] Connection close
- [ ] Stateless retry
- [ ] Migration
- [ ] 0-RTT data
- [ ] Session resumption

[quic]: https://quicwg.github.io/
[issues]: https://github.com/djc/quinn/issues
[rustls]: https://github.com/ctz/rustls
[ring]: https://github.com/briansmith/ring
[talk]: https://paris.rustfest.eu/sessions/a-quic-future-in-rust
[slides]: https://dirkjan.ochtman.nl/files/quic-future-in-rust.pdf
[animation]: https://dirkjan.ochtman.nl/files/head-of-line-blocking.html
[youtube]: https://www.youtube.com/watch?v=EHgyY5DNdvI
[patreon]: https://www.patreon.com/dochtman
