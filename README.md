# Quinn fork of iroh

Quinn is a pure-rust, async-compatible implementation of the IETF
[QUIC][quic] transport protocol.

This is a fork incorporating some changes for use in iroh.  The aim is
to contribute back any generally useful changes into upstream Quinn,
so it is strongly discouraged to use this fork directly.


## Git branches

The upstream branches are kept unmodified and get occasionally synced.
The iroh-specific branches are:

- `iroh-0.10.x` is the branch for quinn@0.10 series.
- `iroh-0.11.x` is the branch for quinn@0.11 series.

The default branch should be set the currently actively used branch by
iroh.
