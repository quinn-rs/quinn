# Pull Request: Internal draft-21 MPQUIC support

## Summary

This PR adds internal Multipath QUIC support to Quinn for `draft-ietf-quic-multipath-21` while keeping the existing public API path-agnostic.

The implementation advertises MPQUIC by default for connections with nonzero connection IDs, but multipath behavior remains strictly negotiation-gated. A connection only uses MPQUIC when both peers advertise `initial_max_path_id`, active 1-RTT packet keys support draft-21 path nonces, and local runtime/socket capabilities can support the selected path behavior. Old or non-MPQUIC peers continue as ordinary single-path QUIC.

No public `PathId`, path handle, send-on-path API, stream binding API, datagram path API, or scheduler configuration is introduced in this PR.

## Why

Quinn's previous connection model was effectively single-path: one active recovery path, one Data packet number space, one CID queue, and ACK/recovery logic that assumed the acknowledged packets belonged to that one path.

Draft-21 MPQUIC changes those invariants:

- path ID, not the network 4-tuple, is the protocol identity of a path;
- path ID 0 remains the initial compatibility path;
- each path has its own 1-RTT packet number space;
- connection IDs are associated with specific path IDs;
- MPQUIC 1-RTT packets use PATH_ACK rather than ordinary ACK frames;
- nonzero paths use path-and-packet-number packet protection nonces;
- scheduling must respect the congestion, pacing, RTT, ECN, MTU, and validation state of the selected path.

This PR internalizes those protocol requirements while preserving the application-facing shape of Quinn.

## Compatibility Model

This is source-compatible for existing Quinn applications. Existing code still creates endpoints, accepts or opens connections, uses streams and datagrams, observes stats, and rebinds sockets through the same public APIs.

Wire compatibility is preserved through negotiation gating:

- new Quinn <-> new Quinn: both sides advertise MPQUIC by default and can negotiate internal multipath behavior;
- new Quinn <-> old Quinn: the old peer does not advertise `initial_max_path_id`, so the new side remains single-path;
- new Quinn <-> non-MPQUIC QUIC peer: unknown transport parameters are ignored and the connection remains single-path;
- zero-length connection IDs: `initial_max_path_id` is not serialized, so MPQUIC is disabled;
- unsupported custom crypto: MPQUIC is disabled unless the active 1-RTT packet keys explicitly opt into draft-21 path nonce support.

The default wire image does change for capable connections because Quinn now advertises `initial_max_path_id` when connection IDs are nonzero. That is intentional and negotiation-safe, but it is not a claim that the default wire output is byte-for-byte identical to previous Quinn releases.

## Protocol Support

### Transport Parameter

Adds draft-21 `initial_max_path_id` transport parameter support using ID `0x3e`.

Behavior:

- default `TransportConfig` advertises `initial_max_path_id = 1` when CIDs are nonzero;
- zero-length CIDs suppress MPQUIC advertisement;
- values larger than `2^32 - 1` are rejected;
- a peer that advertises MPQUIC with zero-length CIDs is rejected;
- the parameter is not remembered for resumption.

### Frames

Adds draft-21 MPQUIC frame parsing, encoding, validation, and fuzz coverage for:

- `PATH_ACK` / `PATH_ACK_ECN`
- `PATH_ABANDON`
- `PATH_STATUS_BACKUP`
- `PATH_STATUS_AVAILABLE`
- `PATH_NEW_CONNECTION_ID`
- `PATH_RETIRE_CONNECTION_ID`
- `MAX_PATH_ID`
- `PATHS_BLOCKED`
- `PATH_CIDS_BLOCKED`

MPQUIC frames received without MPQUIC negotiation are rejected. Frames for abandoned or unprocessable paths are ignored where draft-21 requires ignoring them.

### Packet Protection

Adds path-and-packet-number nonce support for MPQUIC 1-RTT packet protection.

The public crypto trait remains source-compatible through defaulted, doc-hidden nonce-aware methods. `PacketNonce` is doc-hidden and opaque, with private variants and checked constructors. Existing custom crypto providers continue compiling unchanged and default to no multipath support. A custom provider must explicitly opt into multipath nonce support before MPQUIC can be enabled with that provider.

The rustls provider opts in and uses draft-21 96-bit path nonce construction.

## Internal Architecture

### Path Identity And State

Adds an internal `PathId` and path table. Path ID 0 remains the compatibility path and continues to represent ordinary QUIC behavior when MPQUIC is not negotiated.

Per-path state now covers:

- remote address and local source IP metadata;
- path validation and lifecycle;
- path status preference;
- remote and local CID state;
- Data packet number space;
- packet number filtering;
- recovery, RTT, congestion, pacing, ECN, MTU, and anti-amplification state;
- path control queues.

### Packet Spaces And ACK Processing

Initial and Handshake packet spaces remain connection-global. Data packet state is path-specific under MPQUIC.

PATH_ACK processing updates the packet space for the acknowledged path ID rather than whichever path carried the ACK. Ordinary ACK frames continue to map to path ID 0 for compatibility.

### CID Routing

Connection IDs are tracked per path. Under MPQUIC, path 0 uses ordinary `NEW_CONNECTION_ID` and `RETIRE_CONNECTION_ID`; nonzero paths use `PATH_NEW_CONNECTION_ID` and `PATH_RETIRE_CONNECTION_ID`.

Endpoint routing resolves incoming packets to the connection and path implied by the destination CID.

### Path Lifecycle

Adds internal handling for opening, validating, activating, backing up, making available, and abandoning paths.

Abandoned nonzero paths retain enough state for 3 PTOs to avoid spurious stateless resets and continue processing required acknowledgments. `PATH_ABANDON` for path 0 closes the connection as a peer application close rather than attempting to remove the primary path.

### Scheduling

Adds an internal path scheduler that can aggregate application-data bandwidth across eligible paths without exposing path selection to applications.

Scheduling respects:

- path validation state;
- peer/local path availability status;
- congestion window;
- pacing;
- anti-amplification limits;
- MTU constraints;
- RTT quality for stream data.

One returned transmit remains path-homogeneous. GSO batches do not mix paths.

### Runtime I/O And Send Without Bind

Uses existing UDP metadata support for the ergonomic send-without-bind case:

- `RecvMeta::dst_ip` identifies the local destination IP where the platform reports it;
- `Transmit::src_ip` selects the outgoing source IP on wildcard-bound sockets.

Local runnable coverage now includes IPv4 and IPv6 wildcard receive destination-IP/source-IP reply tests. Broader OS/interface coverage still needs CI or manual platform matrix runs.

## Public API

No public multipath consumer API is added.

This PR intentionally keeps the following private/internal:

- path IDs;
- path handles;
- path lifecycle controls;
- scheduler controls;
- per-path send APIs;
- per-path stream/datagram binding;
- per-path public statistics.

Existing public stats retain path-0/aggregate semantics. A future public multipath API should be designed separately after the internal transport behavior is proven stable.

## Tests And Validation

Validated locally with:

- `cargo test -p quinn-proto --quiet`
- `cargo test -p quinn-proto multipath --quiet`
- `cargo clippy -p quinn-proto --tests --quiet`
- `cargo check -p quinn-proto --features qlog --quiet`
- `RUSTFLAGS="--cfg fuzzing" cargo check -p fuzz --bin mp_frames --quiet`
- `cargo check -p quinn --quiet`
- `cargo test -p quinn-udp wildcard_recv_dst_ip_and_src_ip_reply --quiet`
- `cargo fmt --check`
- `git diff --check`

Coverage added or updated for:

- default MPQUIC transport parameter generation and CID gating;
- mixed old/new peer compatibility staying single-path;
- default-on MPQUIC negotiation between capable Quinn peers;
- PATH_ACK parsing, encoding, and recovery routing;
- nonzero-path packet number spaces;
- path-aware packet protection;
- custom crypto providers requiring explicit multipath nonce opt-in;
- PATH_ABANDON including path 0 behavior;
- path status and path lifecycle frames;
- per-path CID issuance, retirement, and routing;
- same 4-tuple multiple path IDs;
- stream-aware and capacity-aware scheduling;
- source-IP send-without-bind metadata for IPv4 and IPv6;
- MPQUIC frame fuzzing.

## Remaining External Validation

External draft-21 interop is not proven by this PR alone because it requires a separate draft-21 MPQUIC peer implementation.

An ignored command-driven test hook exists and expects `QUINN_MPQUIC_DRAFT21_INTEROP_COMMAND` to point at an external interop harness. Once such a peer is available, that hook should be used to validate real cross-implementation behavior.

Broader local-IP behavior across OSes, interfaces, VPNs, and wildcard socket configurations should also be run in CI or a manual platform matrix. The local IPv4/IPv6 tests cover the core metadata path on this development platform.

## Risk Notes

- Default advertisement changes the default transport parameter set for nonzero-CID connections, even though old peers stay single-path.
- Packet protection is the highest-risk correctness area; MPQUIC is gated on explicit 1-RTT key support for draft-21 path nonces.
- Scheduler behavior can change bandwidth distribution when both peers negotiate MPQUIC.
- Public stats intentionally avoid exposing per-path semantics in this PR.
- External draft-version compatibility is limited to `draft-ietf-quic-multipath-21`.

## Reviewer Checklist

- Existing public APIs compile unchanged.
- Old or non-MPQUIC peers remain single-path.
- MPQUIC behavior only activates after both peers advertise `initial_max_path_id`.
- `initial_max_path_id` is suppressed for zero-length CIDs.
- Data packet number state is path-specific.
- PATH_ACK updates the acknowledged path, not merely the receive path.
- Connection IDs are path-specific under MPQUIC.
- Nonzero-path 1-RTT packet protection uses draft-21 path nonce construction.
- Custom crypto providers do not accidentally enable MPQUIC.
- One transmit/GSO batch is path-homogeneous.
- Source-IP send selection uses existing socket metadata rather than a new public bind API.
- PATH_ABANDON retains required nonzero-path state and closes cleanly for path 0.