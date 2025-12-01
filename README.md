# Quinn fork of iroh

Quinn is a pure-rust, async-compatible implementation of the IETF
[QUIC][quic] transport protocol.

- Simultaneous client/server operation
- Ordered and unordered stream reads for improved performance
- Works on stable Rust, tested on Linux, macOS and Windows
- Pluggable cryptography, with a standard implementation backed by
  [rustls][rustls] and [*ring*][ring]
- Application-layer datagrams for small, unreliable messages
- Future-based async API
- Minimum supported Rust version of 1.83.0

This is a fork incorporating some changes for use in iroh.  The aim is
to contribute back any generally useful changes into upstream Quinn,
so it is strongly discouraged to use this fork directly.


## Git branches

The upstream branches are kept unmodified and get occasionally synced
(e.g. our `main` branch tracks `upstream/main` with a small delay).
The iroh-specific branches are:

- `iroh-0.10.x` is the branch for quinn@0.10 series.
- `iroh-0.11.x` is the branch for quinn@0.11 series.

The default branch should be set the currently actively used branch by
iroh.

### Updating a branch

To update a branch to include the upstream changes, merge the upstream
branch.  E.g. when upstream is `main` and the current iroh branch is
`iroh-0.11.x`:

- Check which commits are new in main.

  Using *magit*: `magit-cherry` (Y), from `main` to `iroh-0.11.x`

- Find the commit to merge.

  You probably want to find the last released commit on the `main`
  branch, which might not be the last commit on main.  So you need to
  find the commit hash as you can't use "main" in this case.

- Merge this commit: `git merge abc123`

- You can check the log and cherries again to see if the right commits
  are left in main.

<<<<<<< HEAD
### Upstream versions
=======
For some cases, including peer-to-peer, trust-on-first-use, deliberately
insecure applications, or any case where servers are not identified by domain
name, this isn't practical. Arbitrary certificate validation logic can be
implemented by customizing the `rustls` configuration; see the
[insecure_connection.rs][insecure] example for details.
>>>>>>> upstream/main

Usually we only try to merge tagged upstream versions. Currently (as
of the 0.13 iroh-quinn release) we've released work that hasn't been
released upstream yet.

In the normal case, you'd be able to check the current matching
upstream version by running:

`git tag --merged`

<<<<<<< HEAD
This shows all the tags which are in the ancestors of HEAD.  Look for
the highest `quinn`, `quinn-proto` and `quinn-udp` tags which are
found in all the ancestor commits.
=======
All feedback welcome. Feel free to file bugs, requests for documentation and
any other feedback to the [issue tracker][issues].

The quinn-proto test suite uses simulated IO for reproducibility and to avoid
long sleeps in certain timing-sensitive tests. If the `SSLKEYLOGFILE`
environment variable is set, the tests will emit UDP packets for inspection
using external protocol analyzers like Wireshark, and NSS-compatible key logs
for the client side of each connection will be written to the path specified in
the variable.

The minimum supported Rust version for published releases of our
crates will always be at least 6 months old at the time of release.

[quic]: https://quicwg.github.io/
[issues]: https://github.com/djc/quinn/issues
[rustls]: https://github.com/ctz/rustls
[ring]: https://github.com/briansmith/ring
[talk]: https://paris.rustfest.eu/sessions/a-quic-future-in-rust
[slides]: https://github.com/djc/talks/blob/ff760845b51ba4836cce82e7f2c640ecb5fd59fa/2018-05-26%20A%20QUIC%20future%20in%20Rust/Quinn-Speaker.pdf
[animation]: https://dirkjan.ochtman.nl/files/head-of-line-blocking.html
[youtube]: https://www.youtube.com/watch?v=EHgyY5DNdvI
[letsencrypt]: https://letsencrypt.org/
[rcgen]: https://crates.io/crates/rcgen
[examples]: https://github.com/djc/quinn/tree/main/quinn/examples
[documentation]: https://quinn-rs.github.io/quinn/networking-introduction.html
[sans-io]: https://sans-io.readthedocs.io/how-to-sans-io.html
[insecure]: https://github.com/quinn-rs/quinn/blob/main/quinn/examples/insecure_connection.rs
>>>>>>> upstream/main
