<h1 align="center"><img width="440" src="docs/thumbnail.png" /></h1>

[![Documentation](https://docs.rs/quinn/badge.svg)](https://docs.rs/quinn/)
[![Crates.io](https://img.shields.io/crates/v/quinn.svg)](https://crates.io/crates/quinn)
[![Build status](https://github.com/djc/quinn/workflows/CI/badge.svg)](https://github.com/djc/quinn/actions?query=workflow%3ACI)
[![codecov](https://codecov.io/gh/djc/quinn/branch/master/graph/badge.svg)](https://codecov.io/gh/djc/quinn)
[![Chat](https://img.shields.io/badge/chat-%23quinn:matrix.org-%2346BC99?logo=matrix)](https://matrix.to/#/#quinn:matrix.org)
[![Chat](https://badges.gitter.im/gitterHQ/gitter.svg)](https://gitter.im/djc/quinn)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE-MIT)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE-APACHE)

# Pure-rust QUIC protocol implementation 
Quinn is a pure-rust implementation of the [QUIC][quic] transport protocol undergoing standardization by the IETF.
 It is suitable for experimental use. 

# Getting Started
<details>
<summary>
Click to show Cargo.toml.
</summary>

```toml
[dependencies]
quinn = "0.6"
```

</details>
<p></p>

**Links**
- Talk at [RustFest Paris (May 2018) presentation][talk]; [slides][slides]; [YouTube][youtube]
- Usage [Examples][examples]
- In progress [Documentation][documentation]

**Examples**

```sh
$ cargo run --example server ./
$ cargo run --example client https://localhost:4433/Cargo.toml
```

This launches an HTTP 0.9 server on the loopback address serving the current
working directory, with the client fetching `./Cargo.toml`. By default, the
server generates a self-signed certificate and stores it to disk, where the
client will automatically find and trust it.

## Overview
| name | description |
| :----- | :----- |
| `quinn` | high-level async API based on tokio, see for usage. This will be used by most developers. (Basic benchmarks are included.) |
| `quinn-proto` | deterministic state machine of the protocol which performs **no** I/O internally and is suitable for use with custom event loops (and potentially a C or C++ API). |
| `quinn-h3` | contains an implementation of HTTP-3 and QPACK. It is split internally in a deterministic state machine and a tokio-based high-level async API |
| `bench` | benchmarks without any framework. |
| `interop` | tooling that helps to run interoperability tests. |
| `fuzz` | fuzz tests |

## Features
- [x] QUIC draft 27 with TLS 1.3
- [x] Cryptographic handshake
- [x] Stream data w/ flow control and congestion control
- [x] Connection close
- [x] Stateless retry
- [x] Explicit congestion notification
- [x] Migration
- [x] 0-RTT data
- [x] Session resumption
- [x] Simultaneous client/server operation
- [x] Ordered and unordered stream reads for improved performance
- [x] Works on stable Rust, tested on Linux, macOS and Windows
- [x] Pluggable cryptography, with a standard implementation backed by
  [rustls][rustls] and [*ring*][ring]
- [x] Application-layer datagrams for small, unreliable messages
- [ ] HTTP over QUIC

## Contribution
- All feedback welcome. Feel free to file bugs, requests for documentation and
  any other feedback to the [issue tracker][issues].
- The quinn-proto test suite uses simulated IO for reproducibility and to avoid
long sleeps in certain timing-sensitive tests. If the `SSLKEYLOGFILE`
environment variable is set, the tests will emit UDP packets for inspection
using external protocol analyzers like Wireshark, and NSS-compatible key logs
for the client side of each connection will be written to the path specified in
the variable.

## Authors

* **Dirkjan Ochtman** - *Project Owner & creator*
* **Benjamin Saunders** - *Project Owner & creator*

## License

This project is licensed under [License-MIT][license-mit] and [LICENSE-APACHE][license-apache] - see the  file for details.

[quic]: https://quicwg.github.io/
[issues]: https://github.com/djc/quinn/issues
[rustls]: https://github.com/ctz/rustls
[ring]: https://github.com/briansmith/ring
[talk]: https://paris.rustfest.eu/sessions/a-quic-future-in-rust
[slides]: https://dirkjan.ochtman.nl/files/quic-future-in-rust.pdf
[animation]: https://dirkjan.ochtman.nl/files/head-of-line-blocking.html
[youtube]: https://www.youtube.com/watch?v=EHgyY5DNdvI
[letsencrypt]: https://letsencrypt.org/
[rcgen]: https://crates.io/crates/rcgen
[license-mit]: https://github.com/djc/quinn/blob/main/LICENSE-MIT
[license-apache]: https://github.com/djc/quinn/blob/main/LICENSE-APACHE
[examples]: https://github.com/djc/quinn/tree/master/quinn/examples
[documentation]: https://github.com/djc/quinn/issues/865

