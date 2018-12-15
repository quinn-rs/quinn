# Quinn

[![Documentation](https://docs.rs/quinn/badge.svg)](https://docs.rs/quinn/)
[![Crates.io](https://img.shields.io/crates/v/quinn.svg)](https://crates.io/crates/quinn)
[![Build status](https://api.travis-ci.org/djc/quinn.svg?branch=master)](https://travis-ci.org/djc/quinn)
[![codecov](https://codecov.io/gh/djc/quinn/branch/master/graph/badge.svg)](https://codecov.io/gh/djc/quinn)
[![Chat](https://badges.gitter.im/gitterHQ/gitter.svg)](https://gitter.im/djc/quinn)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE-MIT)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE-APACHE)

Quinn is an implementation of the [QUIC][quic] network protocol currently
undergoing standardization by the IETF. It is currently suitable for
experimental use. The implementation is split up into the state machine crate
`quinn-proto` which performs no I/O internally and can be tested deterministically,
and a high-level tokio-compatible API in `quinn`. See `quinn/examples/` for usage.

Quinn is the subject of a [RustFest Paris (May 2018) presentation][talk]; you can
also get the [slides][slides] (and the [animation][animation] about head-of-line
blocking). Video of the talk is available [on YouTube][youtube]. Since this
presentation, Quinn has been merged with quicr, another Rust implementation.

All feedback welcome. Feel free to file bugs, requests for documentation and
any other feedback to the [issue tracker][issues].

Quinn was created and is maintained by Dirkjan Ochtman and Benjamin Saunders.

## Features

* Simultaneous client/server operation
* Ordered and unordered reads for improved performance
* Works on stable Rust
* Uses [rustls][rustls] for all TLS operations and [*ring*][ring] for cryptography

## Status

- [x] QUIC draft 11 with TLS 1.3
- [x] Cryptographic handshake
- [x] Stream data w/ flow control and congestion control
- [x] Connection close
- [x] Stateless retry
- [x] Explicit congestion notification
- [ ] Migration
- [ ] 0-RTT data
- [ ] Session resumption
- [ ] HTTP over QUIC

## How to start

The server [currently always requires][insecure] certificates to be supplied. 
Example certificates are included in the repository for test purposes.
The client must be configured to trust the test certificate authority unless the
client is built with the `dangerous_configuration` feature and passed
`--accept-insecure-certs`.

```sh
$ cargo run --example server -- --cert ./certs/server.chain --key ./certs/server.rsa ./
$ cargo run --example client -- --ca ./certs/ca.der https://localhost:4433/Cargo.toml
```

In the above example, the server will run on localhost and serve the "." folder to
the client. The client will request the "Cargo.toml" file.  

To run the example client/server across a network you need to update the 
`certs/openssl.cnf` file and change the `DNS.3` entry to suit the DNS name  of the 
server, and then regenerate the certificates using the `certs/generate.sh` script.  
For real-world use, a certificate signed by a legitimate CA is recommended when 
possible.

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
[insecure]: https://github.com/djc/quinn/issues/58
