# Quinn

[![Documentation](https://docs.rs/quinn/badge.svg)](https://docs.rs/quinn/)
[![Crates.io](https://img.shields.io/crates/v/quinn.svg)](https://crates.io/crates/quinn)
[![Build status](https://github.com/djc/quinn/workflows/CI/badge.svg)](https://github.com/djc/quinn/actions?query=workflow%3ACI)
[![codecov](https://codecov.io/gh/djc/quinn/branch/master/graph/badge.svg)](https://codecov.io/gh/djc/quinn)
[![Chat](https://img.shields.io/badge/chat-%23quinn:matrix.org-%2346BC99?logo=matrix)](https://matrix.to/#/#quinn:matrix.org)
[![Chat](https://badges.gitter.im/gitterHQ/gitter.svg)](https://gitter.im/djc/quinn)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE-MIT)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE-APACHE)

Quinn is an implementation of the [QUIC][quic] transport protocol undergoing
standardization by the IETF. It is suitable for experimental use. This repository
contains the following crates:

* `quinn` contains a high-level async API based on tokio, see
[quinn/examples/](https://github.com/djc/quinn/tree/master/quinn/examples) for
usage. This will be used by most Rust developers. (Basic benchmarks are included.)
* `quinn-proto` contains a deterministic state machine of the protocol which performs
no I/O internally and is suitable for use with custom event loops (and potentially
a C or C++ API).
* `quinn-h3` contains an implementation of HTTP 3 and QPACK. It is split internally
in a deterministatic state machine and a tokio-based high-level async API.
* `bench` contains some extra benchmarks without any framework.
* `interop` contains tooling that helps the Quinn team run interoperability tests.

Quinn is the subject of a [RustFest Paris (May 2018) presentation][talk]; you can
also get the [slides][slides] (and the [animation][animation] about head-of-line
blocking). Video of the talk is available [on YouTube][youtube]. Since this
presentation, Quinn has been merged with quicr, another Rust implementation.

All feedback welcome. Feel free to file bugs, requests for documentation and
any other feedback to the [issue tracker][issues].

Quinn was created and is maintained by Dirkjan Ochtman and Benjamin Saunders.

## Features

* Simultaneous client/server operation
* Ordered and unordered stream reads for improved performance
* Works on stable Rust, tested on Linux, macOS and Windows
* Pluggable cryptography, with a standard implementation backed by
  [rustls][rustls] and [*ring*][ring]
* Application-layer datagrams for small, unreliable messages

## Status

- [x] QUIC draft 27 with TLS 1.3
- [x] Cryptographic handshake
- [x] Stream data w/ flow control and congestion control
- [x] Connection close
- [x] Stateless retry
- [x] Explicit congestion notification
- [x] Migration
- [x] 0-RTT data
- [x] Session resumption
- [ ] HTTP over QUIC

## Usage Notes

### Buffers

A Quinn endpoint corresponds to a single UDP socket, no matter how many
connections are in use. Handling high aggregate data rates on a single endpoint
can require a larger UDP buffer than is configured by default in most
environments. If you observe erratic latency and/or throughput over a stable
network link, consider increasing the buffer sizes used. For example, you could
adjust the `SO_SNDBUF` and `SO_RCVBUF` options of the UDP socket to be used
before passing it in to Quinn. Note that some platforms (e.g. Linux) require
elevated privileges or modified system configuration for a process to increase
its UDP buffer sizes.

### Certificates

By default, Quinn clients validate the cryptographic identity of servers they
connect to. This prevents an active, on-path attacker from intercepting
messages, but requires trusting some certificate authority. For many purposes,
this can be accomplished by using certificates from [Let's Encrypt][letsencrypt]
for servers, and relying on the default configuration for clients.

For some cases, including peer-to-peer, trust-on-first-use, deliberately
insecure applications, or any case where servers are not identified by domain
name, this isn't practical. Arbitrary certificate validation logic can be
implemented by enabling the `dangerous_configuration` feature of `rustls` and
constructing a Quinn `ClientConfig` with an overridden certificate verifier by
hand.

When operating your own certificate authority doesn't make sense, [rcgen][rcgen]
can be used to generate self-signed certificates on demand. To support
trust-on-first-use, servers that automatically generate self-signed certificates
should write their generated certificate to persistent storage and reuse it on
future runs.

## Running the Examples

```sh
$ cargo run --example server ./
$ cargo run --example client https://localhost:4433/Cargo.toml
```

This launches a HTTP 0.9 server on the loopback address serving the current
working directory, with the client fetching `./Cargo.toml`. By default, the
server generates a self-signed certificate and stores it to disk, where the
client will automatically find and trust it.

## Development

The quinn-proto test suite uses simulated IO for reproducibility and to avoid
long sleeps in certain timing-sensitive tests. If the `SSLKEYLOGFILE`
environment variable is set, the tests will emit UDP packets for inspection
using external protocol analyzers like Wireshark, and NSS-compatible key logs
for the client side of each connection will be written to the path specified in
the variable.

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
