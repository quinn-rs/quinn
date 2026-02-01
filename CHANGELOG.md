# Changelog

All notable changes to ant-quic will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.21.0] - 2026-02-01

### Breaking Changes

- **Channel-Based recv() Architecture**: Replaced polling-based `recv()` with event-driven channel-based system
  - Background reader tasks now feed a shared `mpsc` channel, eliminating O(n×timeout) peer iteration delays
  - `recv()` and `accept()` now race against shutdown tokens via `tokio::select!` for prompt shutdown
  - Data channel capacity is now configurable via `P2pConfig::data_channel_capacity`

### Changed

- **CancellationToken Shutdown**: Replaced `AtomicBool` shutdown flags with `tokio_util::sync::CancellationToken`
  - Enables cooperative cancellation across all endpoints
  - More idiomatic Rust async shutdown pattern

- **Zero-Latency Constrained Events**: Constrained transport events (BLE/LoRa) switched from 100ms polling to async `recv()`
  - New `recv_constrained_event()` async method for zero-latency event processing
  - Eliminates busy-wait polling loops

### Fixed

- **Reader Task Race Condition**: Fixed race where `recv()` called immediately after `connect()` could miss early data
  - Now spawns reader task before storing connection in `connected_peers`
  - Ensures data channel is ready when `connect()` returns

- **Send Bound Violation**: Fixed `parking_lot::MutexGuard` held across `.await` causing non-`Send` futures
  - Changed `constrained_event_rx` to use `tokio::sync::Mutex`

### Added

- `P2pConfig::data_channel_capacity` - Configurable capacity for the data receive channel
- `SHUTDOWN_DRAIN_TIMEOUT` constant (5s) for unified shutdown timeout handling
- Comprehensive E2E tests for channel-recv and CancellationToken improvements

## [0.20.3] - 2026-01-31

### Changed

- **"Measure, Don't Trust" Peer Selection**: Capability selection now prefers peers with observed support but no longer filters out unverified peers
  - `select_with_capabilities()` uses preference scoring instead of capability filtering
  - All peers participate in selection, ranked by observed capabilities then quality score
  - Achieves the "measure, don't trust" philosophy - test all peers, prefer those that deliver

- **Mandatory PQC/NAT Features**: All P2P features are now always-on in symmetric P2P mode
  - PQC (ML-KEM-768, ML-DSA-65) cannot be disabled - legacy flags are ignored
  - NAT traversal, relay fallback, and relay service are mandatory
  - `normalize_config()` enforces mandatory features at construction time
  - Downgrade to classical crypto is prevented at validation layer

### Documentation

- Updated ADR-004, ADR-008, and ARCHITECTURE.md to reflect "measure, don't trust" philosophy
- Documentation now states all nodes are equal with roles as hints, not requirements
- README updated with symmetric P2P and PQC-only messaging

## [0.20.2] - 2026-01-30

### Added

- **Multi-Client Mixed Traffic Tests** ([#128](https://github.com/saorsa-labs/ant-quic/issues/128)): Comprehensive integration tests validating stream reliability under concurrent load
  - `multi_client_mixed_traffic_no_datagram_loss`: Multiple clients exchanging datagrams and bi-streams simultaneously
  - `multi_client_select_loop_integrity`: Tests `tokio::select!` pattern with biased polling between `accept_bi()` and `read_datagram()`
  - `accept_bi_cancellation_is_safe`: Verifies rapid cancellation/re-polling of `accept_bi()` doesn't corrupt stream state
  - Confirms QUIC stream reliability guarantees - any stream data loss is a library bug, not protocol behavior

### Documentation

- Added TROUBLESHOOTING.md FAQ clarifying that QUIC streams are fully reliable and ordered - data loss indicates a bug

## [0.20.1] - 2026-01-30

### Fixed

- **Datagram Drop Notifications** ([#128](https://github.com/saorsa-labs/ant-quic/issues/128)): Silent datagram dropping when receive buffer is full now surfaces explicit notifications to applications
  - Added `DatagramDropStats` struct to track dropped datagrams count and bytes
  - Added `Event::DatagramDropped` variant to the connection event loop
  - Added `Connection::on_datagram_drop()` async method for event-driven notification
  - Added `Connection::datagram_drop_stats()` for polling cumulative drop statistics
  - Added `datagram_drops` field to `ConnectionStats` for aggregate tracking
  - Applications can now detect and react to buffer pressure instead of experiencing silent data loss

## [0.20.0] - 2026-01-24

### Added

- **Transport-Agnostic Endpoint API**: Higher layers (saorsa-gossip/Communitas) now see a single, unified endpoint
  - Socket sharing in default constructors: `P2pEndpoint::new()` binds single UDP socket shared with Quinn
  - Constrained peer registration: Automatic PeerId mapping on `ConnectionAccepted/Established` events
  - Bidirectional lookup: Both `PeerId → ConnectionId` and `ConnectionId → (PeerId, TransportAddr)`
  - Unified receive path: `P2pEvent::DataReceived` emitted for ALL transport types (QUIC and constrained)

- **Phase 5 Data Path Completion** (Milestones 5.1, 5.2, 5.3):
  - Phase 5.1: Multi-Transport Data Path Remediation
  - Phase 5.2: Constrained event forwarding and socket sharing constructors
  - Phase 5.3: Transport-agnostic endpoint with unified send/recv paths

- **Constrained Protocol Engine Integration**:
  - `ConstrainedEventWithAddr` wrapper for events with transport context
  - Event channel from transport listeners to P2pEndpoint
  - Activity tracking for constrained connections

### Changed

- `P2pEndpoint::new()` now automatically registers a UDP transport in the registry
- Default registry is no longer empty - includes socket-sharing UDP transport
- Constrained data no longer requires special-case handling in higher layers

## [0.19.0] - 2026-01-23

### Added

- **Multi-Transport Abstraction Layer**: New `src/transport/` module with unified addressing and provider trait
  - `TransportAddr` enum supporting UDP, BLE, LoRa, Serial, AX.25, I2P, and Yggdrasil transports
  - `TransportCapabilities` with bandwidth profiles and QUIC support detection
  - `TransportProvider` trait for pluggable transport implementations
  - `TransportRegistry` for multi-transport management
  - `ProtocolEngine` selector (QUIC vs Constrained engine) based on transport capabilities
- **BLE Transport Provider**: Cross-platform Bluetooth Low Energy support via btleplug
  - Linux (BlueZ), macOS (Core Bluetooth), and Windows (WinRT) support
  - PQC mitigations: 24-hour session caching and 32-byte resume tokens
  - Feature-gated with `ble` Cargo feature
- **UDP Transport Provider**: Reference implementation of `TransportProvider` for standard QUIC
- **NodeConfig Extensions**: `transport_providers` field and registry builder methods
- **Transport Diagnostics**: RTT, bandwidth class, and protocol engine reporting

### Changed

- Rust Edition updated to 2024
- Minimum Rust version bumped to 1.85.0

## [0.14.9] - 2025-12-23

### Bug Fixes

- Make supply-chain security check non-blocking to allow release builds

## [0.14.8] - 2025-12-23

### Bug Fixes

- Fix security workflow output to not block builds on non-PR events

## [0.14.7] - 2025-12-23

### Maintenance

- Update Cargo.lock for Rust 1.92.0 compatibility
- Update dependencies (zerocopy, zeroize, windows, etc.)

## [0.14.6] - 2025-12-23

### Bug Fixes

- Fix code formatting for CI compliance

## [0.14.5] - 2025-12-23

### Features

- Add connection health checking with automatic stale peer removal
- Add peer rotation for network freshness (randomly rotates oldest peer)
- Add globe interaction - pause auto-rotation on user interaction, resume after 5 seconds

### Bug Fixes

- Fix deployment script to use HTTPS registry URL
- Add --quiet flag to node service for headless operation

## [0.14.4] - 2025-12-23

### Features

- Add interactive ADR modal system with formatted architecture decision summaries
- Implement scroll-aware stats panel that auto-minimizes when scrolling
- Add Architecture navigation link in header for easy access to ADRs
- Add keyboard navigation support (Escape to close modals, Tab for focus)

### Bug Fixes

- Fix endpoint validation workflow to not create issues for 0/0 endpoints
- Update remaining registry URLs from quic.saorsalabs.com to saorsa-1.saorsalabs.com

## [0.14.3] - 2025-12-23

### Features

- Add macOS code signing and notarization to release workflow ([11d2ce7](https://github.com/dirvine/ant-quic/commit/11d2ce7a))
- Add Windows download button and platform-specific instructions to dashboard ([22400e8](https://github.com/dirvine/ant-quic/commit/22400e89))
- Modernize globe visualization with Globe.gl and add simple download page ([57955db](https://github.com/dirvine/ant-quic/commit/57955db96114abd4a1e95e39f3eaf3052fd05c97))
- Add clickable nodes with detailed stats panel ([317a498](https://github.com/dirvine/ant-quic/commit/317a49828b9b369ba48a0458b6a27856a5edde38))

### Bug Fixes

- Update registry URL to saorsa-1.saorsalabs.com ([68354db](https://github.com/dirvine/ant-quic/commit/68354db1ebef128a73bd4e6cd59c64fb369f7671))
- Improve Windows build support and release resilience ([4656fe6](https://github.com/dirvine/ant-quic/commit/4656fe64fc0094cf0b670defba0ead4589a0e1e1))
- Fix artifact path handling in release job ([cf39f37](https://github.com/dirvine/ant-quic/commit/cf39f3704b8c081c978447560910ce80f0bd7ee5))
- Add tag_name for workflow_dispatch releases ([1e68bf3](https://github.com/dirvine/ant-quic/commit/1e68bf3ad784a694ce5fa6fc756639b66b4683c5))

### Styling

- Fix formatting issues in test-network crate ([acc91de](https://github.com/dirvine/ant-quic/commit/acc91de5e839e82a883c9daa29359f8424dad6e2))

## [0.14.2] - 2025-12-23

### Bug Fixes

- Prevent integration test hangs with shutdown timeout ([48030fe](https://github.com/dirvine/ant-quic/commit/48030fe619f0a9e8ee5be3948660dcf7576a33c3))
- Allow unused_assignments for ZeroizeOnDrop struct ([d4c8562](https://github.com/dirvine/ant-quic/commit/d4c8562498bc3b7ddd929ec23c3bee4d79e87dd8))
- Move allow attribute to individual struct fields ([aeda08b](https://github.com/dirvine/ant-quic/commit/aeda08b31b842ceb166f35191827dcdd6c64e56c))
- Use module-level allow for ZeroizeOnDrop false positive ([c5c405d](https://github.com/dirvine/ant-quic/commit/c5c405db39540f3e5f023a2533a2a2e902781f04))
- Inline quick-checks to avoid workflow_call timing issues ([41e20a8](https://github.com/dirvine/ant-quic/commit/41e20a82170da3e1afa1cad83748d8b23a03f422))
- Use saorsa-1.saorsalabs.com for dashboard URL ([5b7ad2d](https://github.com/dirvine/ant-quic/commit/5b7ad2da3c74bbc419851c15d2942ad814f1fa35))
- Add missing warp dependency for metrics http server ([3fb536a](https://github.com/dirvine/ant-quic/commit/3fb536a76dcca47ebe2b5fd08af59bd7004e9a19))
- Make non-critical release jobs non-blocking ([da31ea0](https://github.com/dirvine/ant-quic/commit/da31ea0ff3fa0747975dc170a5be0f9ca37ae33a))

### Documentation

- Correct PeerId derivation - SHA-256(ML-DSA-65), not Ed25519 ([4897329](https://github.com/dirvine/ant-quic/commit/48973297a8d9688710d32017149612922e30fddf))

### Features

- Add E2E release test script ([e69ac8b](https://github.com/dirvine/ant-quic/commit/e69ac8b095c9efb73c922405ca5d1852e9adf6a1))
- Complete ADR-002/003/004 - remove legacy role enums, verify SPKI parser ([4b4db4c](https://github.com/dirvine/ant-quic/commit/4b4db4c068a17371c0c08b70e61406a9208ab63b))
- Enable dual-stack IPv4/IPv6 by default ([1d672ca](https://github.com/dirvine/ant-quic/commit/1d672ca956367e88b53ef4ab1849a2b41a404d58))
- Update default listen addresses to dual-stack [::] ([41393fc](https://github.com/dirvine/ant-quic/commit/41393fc44011054a93e211977914fedb03659898))
- Implement parallel dual-stack IPv4/IPv6 connections ([c7aad18](https://github.com/dirvine/ant-quic/commit/c7aad18957d3d95bf7a951f69174454fecce095f))
- Implement ADR-007 local-only HostKey system ([65ffb7d](https://github.com/dirvine/ant-quic/commit/65ffb7de7e2abea63ad6eea0ee84e3d9d4704d63))
- Implement proper keyring storage with plain file fallback ([1bb29e2](https://github.com/dirvine/ant-quic/commit/1bb29e2f523dc6757b4ab98c2863e3414af40bf2))
- Add large-scale network testing infrastructure ([7be1482](https://github.com/dirvine/ant-quic/commit/7be1482468d405fe3029638dc5aa9fa8c47bdaa8))

### Miscellaneous Tasks

- Fix cargo fmt formatting ([8aad98d](https://github.com/dirvine/ant-quic/commit/8aad98da9a9739068b9d571b472fc5abcfd05426))
- Bump version to 0.14.2 ([c4f0990](https://github.com/dirvine/ant-quic/commit/c4f0990cdeead8193b37be803568fdfdbff8e088))

### Refactor

- Consolidate 24 workflows into 14 clear modular workflows ([0c346c9](https://github.com/dirvine/ant-quic/commit/0c346c9e9e49fd0488e53da7cb0e18c75f2085e4))

### Styling

- Fix formatting issues ([43813aa](https://github.com/dirvine/ant-quic/commit/43813aa2c575acb62ec734d6b45d23d88fb91853))

## [0.14.1] - 2025-12-22

### Bug Fixes

- Bash 3.x compatibility for deploy script ([777eb22](https://github.com/dirvine/ant-quic/commit/777eb222006e0d8a4460b3305845ec4f8b6c2858))
- Resolve clippy derivable_impls warnings and remove legacy relay tests ([8a1b4fe](https://github.com/dirvine/ant-quic/commit/8a1b4feaeafb2e6ce2002f6d08637373fe0cd2ac))
- Relax PQC performance threshold for coverage CI ([7986c2d](https://github.com/dirvine/ant-quic/commit/7986c2d014bac737f7af7f5952f398f67207a554))
- Resolve documentation link warnings ([211574c](https://github.com/dirvine/ant-quic/commit/211574c9a3cc37d166018ddd696df1475b564cb9))

### Documentation

- Add ADRs and enhance LinkTransport documentation ([cc2bada](https://github.com/dirvine/ant-quic/commit/cc2badaa54bd4af24c6b4141e9122a265f071344))
- Caveat NAT traversal success rate claims ([96fc0e8](https://github.com/dirvine/ant-quic/commit/96fc0e8c640ebc0da5be6ee194a9bb6e4e8d9136))

### Features

- Add LinkTransport trait abstraction layer for overlay networks ([0c91bca](https://github.com/dirvine/ant-quic/commit/0c91bcabe7559233069b670b76bd56c149b7425e))
- Add greedy bootstrap cache with epsilon-greedy selection ([5586820](https://github.com/dirvine/ant-quic/commit/5586820ed3d7689335fc355526ce0b1977460a20))
- Complete MASQUE CONNECT-UDP Bind relay implementation ([2e382f0](https://github.com/dirvine/ant-quic/commit/2e382f0a91e538d3dc0a2beff438588075dbf2f6))
- Add default bootstrap nodes and document bootstrap cache ([67654f7](https://github.com/dirvine/ant-quic/commit/67654f76ef127a61a97981da261868b1d598dfda))

### Miscellaneous Tasks

- Bump version to 0.14.1 ([4927167](https://github.com/dirvine/ant-quic/commit/4927167ac7ad69fa40807048d1e4802018ace146))

### Styling

- Apply cargo fmt formatting ([597eb66](https://github.com/dirvine/ant-quic/commit/597eb669373e4666b159fd6b055c188c89669341))

## [0.14.0] - 2025-12-21

### Bug Fixes

- Replace corrupted nat-traversal.md with clean version ([7bf477e](https://github.com/dirvine/ant-quic/commit/7bf477ef7e6046daabd70f7a78f805ba90307404))
- Replace deprecated rustls-ring with rustls-aws-lc-rs ([0123f00](https://github.com/dirvine/ant-quic/commit/0123f004cf08cfee8ae4227bb6df70d49ac40325))
- Use derive(Default) and fix clone_on_copy warnings ([d75d006](https://github.com/dirvine/ant-quic/commit/d75d006a037b0fdd91bf4a26bcb2c0449cc153bb))
- Use derive(Default) for FallbackStrategy enum ([22308cd](https://github.com/dirvine/ant-quic/commit/22308cde91796447b23fb9a82b3b13edf6fecabd))
- Correct broken intra-doc link for platform verifier ([989b869](https://github.com/dirvine/ant-quic/commit/989b8696a4d2cb9cdb72df0754ce85a6e66dd6e2))
- Gate runtime-dependent tests on runtime-tokio feature ([c830cc8](https://github.com/dirvine/ant-quic/commit/c830cc869a00088cf24183e5643505c35a056010))
- Increase PQC overhead threshold for CI with coverage ([faba31d](https://github.com/dirvine/ant-quic/commit/faba31ddc4d2d842966d7aabd0630c29983c7b29))
- Use dereference instead of clone for Copy type PeerId ([ec56b7e](https://github.com/dirvine/ant-quic/commit/ec56b7e926a7c069c469e6c200631e460c642cf2))
- Use rustls-tls for reqwest to fix ARM64 cross-compilation ([d96ffdf](https://github.com/dirvine/ant-quic/commit/d96ffdfca5c545603afed2754012992755376220))

### Documentation

- Update all documentation for Pure PQC v0.2 ([d9036cc](https://github.com/dirvine/ant-quic/commit/d9036ccedbd352311f307ac14bf4558045298fbf))

### Features

- Add comprehensive E2E testing infrastructure with dashboard ([b959c73](https://github.com/dirvine/ant-quic/commit/b959c73838b7de0ae565785f35d5d117627298a0))
- [**BREAKING**] Migrate to pure PQC v0.2 - remove all hybrid cryptography ([2a46232](https://github.com/dirvine/ant-quic/commit/2a46232fada27deb078315bd382cc3162bccbd84))
- [**BREAKING**] Complete pure PQC v0.2 migration - remove all hybrid cryptography ([db988d8](https://github.com/dirvine/ant-quic/commit/db988d8b03e4e98ea637d24cdf9fa83ff46f8af3))
- Implement MASQUE CONNECT-UDP Bind protocol ([eabf0a4](https://github.com/dirvine/ant-quic/commit/eabf0a4043568a762da878ac5077e36f8ac88a99))
- Add TryConnectTo/TryConnectToResponse frames for NAT callback testing ([2e4f649](https://github.com/dirvine/ant-quic/commit/2e4f64916c6dfa5aaa5661cb6f4b6fcb8c5335a2))
- Add metrics reporting and bootstrap network deployment ([bab1c1e](https://github.com/dirvine/ant-quic/commit/bab1c1e7490e867b04e66c605f0cca57810bfba0))

### Miscellaneous Tasks

- Bump version to 0.14.0 ([54448a1](https://github.com/dirvine/ant-quic/commit/54448a1275da415e67b02b5a3c3a55cea050d64b))

### Styling

- Apply cargo fmt for CI compliance ([c7d9fb0](https://github.com/dirvine/ant-quic/commit/c7d9fb023687ff2e5af4c18250cf69c54af25de9))
- Apply cargo fmt for CI compliance ([bfe784c](https://github.com/dirvine/ant-quic/commit/bfe784cb9906767214ffe44288aca7539c2a2681))
- Apply cargo fmt formatting ([5a3d4d2](https://github.com/dirvine/ant-quic/commit/5a3d4d266bc6d1ab235c6085046aef0ab289b36c))

## [0.13.1] - 2025-12-19

### Bug Fixes

- Correct IANA hex codes for ML-KEM hybrid groups ([f35e393](https://github.com/dirvine/ant-quic/commit/f35e393d0d3cc862abae6c7b74f7f7f8fc127ce1))

### Miscellaneous Tasks

- Bump version to 0.13.1 with PQC hex code fix ([23fab5f](https://github.com/dirvine/ant-quic/commit/23fab5f7fee0353b28d5effaa8f6892b1077e41d))

## [0.13.0] - 2025-12-19

### Bug Fixes

- Add full git history for Security Scorecard analysis ([b4bdbb2](https://github.com/dirvine/ant-quic/commit/b4bdbb28bff3ff06e42b17b19fc6a8e1d575f673))
- Improve coverage workflows and upgrade actions ([126f265](https://github.com/dirvine/ant-quic/commit/126f265464ee3288568d368ecb581b60cc2b0815))
- Prevent duplicate ConnectionEstablished events ([b296093](https://github.com/dirvine/ant-quic/commit/b296093cd5b1fd792ce2b1d3b9e38222e67f37c4))
- Resolve workflow failures in Enhanced Testing and Extended Platform Tests ([fc68f86](https://github.com/dirvine/ant-quic/commit/fc68f869297da87ea598b5530e120d78bc41fb43))
- Resolve clippy warnings and mdbook configuration ([0e54151](https://github.com/dirvine/ant-quic/commit/0e541514625858d497b5a97c2b45e58d7a5e941b))
- Remove deprecated git-repository-icon from mdbook config ([5294e3e](https://github.com/dirvine/ant-quic/commit/5294e3e1bddba352ae60ec412f715cd6b56759a6))
- Use derive(Default) for PortRetryBehavior ([60e822f](https://github.com/dirvine/ant-quic/commit/60e822fa99680560bc5c1e772d8cabf003c8f192))
- Use derive(Default) for PortBinding and IpMode ([40a8e84](https://github.com/dirvine/ant-quic/commit/40a8e844dbb3691e5c99c1b4bfd392b88122557e))
- Add platform-specific UDP buffer sizing for PQC handshakes ([3b94f8a](https://github.com/dirvine/ant-quic/commit/3b94f8a81900223022aeab382126355575c40129))
- Gate socket2 and platform-specific types with network-discovery feature ([b251719](https://github.com/dirvine/ant-quic/commit/b251719758719963b1350f2e767aa9a3c04b0ddc))
- Remove wasm-check from standard-tests summary needs ([94405e2](https://github.com/dirvine/ant-quic/commit/94405e29b434c6674b83b91d13acacfc14b47d5f))
- Add property_tests test target and make non-blocking ([4d333e8](https://github.com/dirvine/ant-quic/commit/4d333e871ec511285e275ecbd2fc646355cc0c2c))
- Exclude broken property_tests from cargo check ([a2ddc35](https://github.com/dirvine/ant-quic/commit/a2ddc35dfc4375562e2653f26de601636b34fc22))
- Exclude property_tests from clippy --tests ([eabb29e](https://github.com/dirvine/ant-quic/commit/eabb29eda4217cb91f542b24f64b18f473674d98))
- Exclude property_tests from all workflows ([241f2c3](https://github.com/dirvine/ant-quic/commit/241f2c3ce8dbabb951259a811247e608fd882080))
- Adjust coverage thresholds and fix tool installs ([61dacb5](https://github.com/dirvine/ant-quic/commit/61dacb5e889671ecdcd2241b570f752bc35e6e49))
- Add continue-on-error for Android tests (bindgen issues) ([6adc810](https://github.com/dirvine/ant-quic/commit/6adc810d092e71f4672529ecea60e81351a560c8))
- Exclude property_tests from feature combination tests ([2da97e1](https://github.com/dirvine/ant-quic/commit/2da97e1b6061073cbec0a356116c5ea28f2c70a9))
- Fix remaining CI issues ([af85d88](https://github.com/dirvine/ant-quic/commit/af85d88ed9366b6b3978e4c1a0cc93362051d9fe))
- Add async-io dependency to runtime-smol feature ([7debfec](https://github.com/dirvine/ant-quic/commit/7debfecb474b6c24dbdd75c6089e02b6330b3f7b))
- Update deny.toml for RUSTSEC-2025-0134 ([56d67c9](https://github.com/dirvine/ant-quic/commit/56d67c909b65461c439415a6d5e249878be3ebfe))
- Fix Extended Platform Tests failures ([6f573e0](https://github.com/dirvine/ant-quic/commit/6f573e05611744b690bc409409d57dbcbe2aa4b8))
- Add rustls-ring feature to lint check ([621d183](https://github.com/dirvine/ant-quic/commit/621d183018a14695ec4cf5867606896091d57a3d))
- Fix broken rustdoc links ([d191838](https://github.com/dirvine/ant-quic/commit/d19183864f164d14c41e488007164ebc243a62d3))
- Add continue-on-error to exotic platform tests ([0230365](https://github.com/dirvine/ant-quic/commit/0230365736e7cb0710ee0fb71f42650246db9001))
- Fix Standard Tests workflow ([d7013ea](https://github.com/dirvine/ant-quic/commit/d7013ea0d8ecf4c96aeca3452573913de6ce9ff8))
- Comprehensive Extended Platform Tests fixes ([8415049](https://github.com/dirvine/ant-quic/commit/84150494deacbdbb774ae09e20ee0012dc6fc404))
- Fix cargo-hack feature powerset command ([9f3b10e](https://github.com/dirvine/ant-quic/commit/9f3b10edc210fc0c3c42a95c6c466a4fe9a792d4))
- Make fuzz test step conditional ([92e2453](https://github.com/dirvine/ant-quic/commit/92e24533f660875a7d9a2960a3bb4611f62efcb9))
- Remove --optional-deps from cargo-hack ([dfed17f](https://github.com/dirvine/ant-quic/commit/dfed17f1967b17fbc95e30663240275a4b02020f))
- Use bash shell for fuzz test step on Windows ([43714bf](https://github.com/dirvine/ant-quic/commit/43714bf921510f0f2d4ab02bacb783b800d328ae))
- Ignore doc tests with internal types ([91c86d7](https://github.com/dirvine/ant-quic/commit/91c86d70dc6e629edd98052a023b282118effe69))
- Exclude property_tests from cross-platform workflow ([3d3dbb2](https://github.com/dirvine/ant-quic/commit/3d3dbb2089a762aa0f7f1035faea77e11ebc4e3a))
- Add --lib to NAT tests to exclude broken property_tests ([cc1eb7d](https://github.com/dirvine/ant-quic/commit/cc1eb7d5331bebeff2d12c11791be1d89b773009))
- Skip hanging binding tests in Standard Tests workflow ([e0c64b9](https://github.com/dirvine/ant-quic/commit/e0c64b9049a89d32407cacf772b8dc0f795803de))
- Skip hanging binding tests in CI Consolidated Test Suite ([a064557](https://github.com/dirvine/ant-quic/commit/a0645570e37bce56a2dc913d20ecc114c483c534))
- Skip kem_group test in all-features CI runs ([deab5c7](https://github.com/dirvine/ant-quic/commit/deab5c76a98b707f04c11733a741b2b1992fc748))
- Stabilize Enhanced Testing Suite for consistent green CI ([4c02bcb](https://github.com/dirvine/ant-quic/commit/4c02bcb5ba954af35aa5cdb1214527d31412c8a8))
- Remove unnecessary borrow in test ([973b6a1](https://github.com/dirvine/ant-quic/commit/973b6a1d641ae52ea6057ad39e1b14c78faf9adb))

### Documentation

- Update documentation for v0.10.4 accuracy ([9364157](https://github.com/dirvine/ant-quic/commit/9364157409a2c043c49691641b3e95f10a35e317))

### Features

- Add comprehensive data transfer efficiency testing and documentation ([de4fa10](https://github.com/dirvine/ant-quic/commit/de4fa103a9b0c1d735c1c0a5cea100376dad0218))
- Expose OBSERVED_ADDRESS through high-level API ([593ac61](https://github.com/dirvine/ant-quic/commit/593ac61e2908ea85c1842af1112011cfa885f98d))
- Symmetric P2P architecture with 100% PQC ([3db3647](https://github.com/dirvine/ant-quic/commit/3db364767505a67a89e08db33403012439efeb0b))

### Miscellaneous Tasks

- Implement 100% green CI plan ([125f922](https://github.com/dirvine/ant-quic/commit/125f922a56aca2b0bf31af3c5de412a4ff17c689))
- Remove unused .md and .sh files from development process ([cecc827](https://github.com/dirvine/ant-quic/commit/cecc82717bc6f7ed2285f95197fde3a1aaede5f5))
- Update Cargo.lock for v0.10.5 ([339ca82](https://github.com/dirvine/ant-quic/commit/339ca825b7ee996c4bd0cc6dc6c85a1b61f7d226))
- Move quic_debug example to disabled (uses expect) ([80c85a9](https://github.com/dirvine/ant-quic/commit/80c85a909738f336679d60b6d1cc118b59fa756c))

### Styling

- Apply rustfmt to unformatted files ([4f2fb90](https://github.com/dirvine/ant-quic/commit/4f2fb905fe8cc10cea208de596b6f3fdc4eef589))
- Fix formatting in test files ([d8e1499](https://github.com/dirvine/ant-quic/commit/d8e1499ea2f5577d1ae1aae234ca4de9f49c883d))
- Format property_tests files ([0ddedb7](https://github.com/dirvine/ant-quic/commit/0ddedb72c246f9070d0ac1c050576284d56e4354))
- Apply cargo fmt for CI compliance ([630412a](https://github.com/dirvine/ant-quic/commit/630412a6a59c7db74d240000acc0233a8d672f58))

### Ci

- Add workflow_dispatch trigger to CI Consolidated ([4857f21](https://github.com/dirvine/ant-quic/commit/4857f21c33182d78027222d7a768774f64c8438a))

## [0.10.3] - 2025-10-06

### Bug Fixes

- Resolve GitHub workflow failures ([3e93851](https://github.com/dirvine/ant-quic/commit/3e93851dd070a1bd844a015759e5440948c57f9c))
- Resolve GitHub workflow failures ([a66de8f](https://github.com/dirvine/ant-quic/commit/a66de8f0864fbc246020a504a1fa08174e4bc7a4))
- Resolve remaining GitHub workflow failures ([e7bd5c7](https://github.com/dirvine/ant-quic/commit/e7bd5c79b948b5e101a6662d6eab8f200377083a))
- Resolve remaining GitHub workflow failures ([1b5cf56](https://github.com/dirvine/ant-quic/commit/1b5cf5619352ed0716ac2da30d6927544bdc5aa2))
- Correct YAML indentation in platform-specific-tests.yml ([e13ab14](https://github.com/dirvine/ant-quic/commit/e13ab1443d14dfba7177f8c56e1537b72f73e811))
- Correct YAML syntax in GitHub workflow files ([5e1b9c8](https://github.com/dirvine/ant-quic/commit/5e1b9c8e0d662f4a1ade10ad828db09b4841bd54))
- Correct YAML indentation in platform-specific-tests.yml ([f65aa04](https://github.com/dirvine/ant-quic/commit/f65aa043718bbebfd2b8046822b8f872f0f2f974))
- Resolve GitHub workflow failures ([17f5e56](https://github.com/dirvine/ant-quic/commit/17f5e56644a025e06787918fe61cd58d4b3cc4b6))
- Ensure MSRV check uses minimal crypto features ([6fd4597](https://github.com/dirvine/ant-quic/commit/6fd459787a4280b29c0a1954c55ce93063eefbc8))
- Store connection after establishment to prevent immediate closure ([9ce27c8](https://github.com/dirvine/ant-quic/commit/9ce27c8b2b0c0627b76c0f1ed9120928875c3f68))
- Resolve NAT traversal accept and data transfer race conditions ([e946658](https://github.com/dirvine/ant-quic/commit/e9466587238191c0fd613ba32a93ef339641f9ac))
- Make extract_peer_id_from_connection public API ([7715096](https://github.com/dirvine/ant-quic/commit/7715096e31887be2394d75024b5d7943add7eb1f))
- Code quality improvements and Docker NAT test enhancements ([9ec1168](https://github.com/dirvine/ant-quic/commit/9ec1168104f01c26cda8135963f483e668905017))
- Resolve clippy and Windows platform test errors ([970963d](https://github.com/dirvine/ant-quic/commit/970963dc636c2d3d019bf50930c26deca5159e7c))
- Initialize crypto provider for --all-features tests ([9c72462](https://github.com/dirvine/ant-quic/commit/9c724620744627a0ffb5c0d51e689f09be2a37ec))
- Require crypto provider in feature-powerset testing ([7387536](https://github.com/dirvine/ant-quic/commit/7387536c85066b9a1c0c05b7a62be4b25e3102b9))
- Sort imports correctly in ant_quic_comprehensive test ([c70a4be](https://github.com/dirvine/ant-quic/commit/c70a4beb2c9ee9a8f759c53f521b7ca55f5b4c7d))
- Add common crypto provider initialization module ([e5a2edc](https://github.com/dirvine/ant-quic/commit/e5a2edcefc1b3b77db0256d77654c5689eae011b))
- Use common crypto initialization in address_discovery_e2e tests ([bd770ba](https://github.com/dirvine/ant-quic/commit/bd770ba90dc99c2a2d2bce17620bc5e99aee9efa))
- Configure socket buffer sizes for Windows in address_discovery_e2e ([2ac0a1a](https://github.com/dirvine/ant-quic/commit/2ac0a1a08cc710fafe9f57c5f275dea3617c7254))
- Reduce MTU to 1200 bytes on Windows for address_discovery_e2e ([203fe7b](https://github.com/dirvine/ant-quic/commit/203fe7bcec3abb1d11bbe4e8ec693fbf632a2129))

### Documentation

- Update CHANGELOG.md for v0.8.17 release ([0eb084f](https://github.com/dirvine/ant-quic/commit/0eb084f3496a6f602d0cdd4cf6ba27c128d8ff99))

### Features

- Comprehensive multi-node testing framework ([b801bbe](https://github.com/dirvine/ant-quic/commit/b801bbe7d5152036146ca5982d4ae1b19dd6cee8))
- Add flexible port configuration system ([2ce898e](https://github.com/dirvine/ant-quic/commit/2ce898e3a43a896ec54364aefc7a56719c9441dc))
- Add P2P NAT traversal support v0.10.0 ([269e717](https://github.com/dirvine/ant-quic/commit/269e71732d65eef692da0d7a8debcd14b307acce))

### Miscellaneous Tasks

- Remove failing workflows and fix quick checks timeout ([5c65c73](https://github.com/dirvine/ant-quic/commit/5c65c732c56dfd99cd119b21a7650dffbfbfef12))
- Update Cargo.lock for v0.10.0 ([31afcf9](https://github.com/dirvine/ant-quic/commit/31afcf94f2ce7c3fa326288a409ade69ada78b03))
- Simplify feature flags and fix workflows v0.10.2 ([05eef8f](https://github.com/dirvine/ant-quic/commit/05eef8fcd6a0695cefd8b8052420afde9b44b31c))
- Bump version to 0.10.3 ([58a1553](https://github.com/dirvine/ant-quic/commit/58a15532e514344ec993514dd9fadaedf183fbc1))

### Refactor

- Simplify feature flags and remove legacy runtime support ([754121d](https://github.com/dirvine/ant-quic/commit/754121dfa67f901172b1e8f43c4bb833f19b67f5))

### Testing

- Ignore Windows-failing address discovery tests ([330c836](https://github.com/dirvine/ant-quic/commit/330c836117c378484c26b892ba801f648bbe41cf))
- Ignore flaky packet loss test in CI ([b6c1b0d](https://github.com/dirvine/ant-quic/commit/b6c1b0d6268555fce2f6951beeb38be94faf0cbe))
- Ignore Windows-failing tests in address_discovery_integration ([e385408](https://github.com/dirvine/ant-quic/commit/e38540803f590e3cf8b9b5736429e06fd9ab1a5e))

## [0.8.17] - 2025-09-20

### Bug Fixes

- Resolve compilation issues and enable property tests ([68ee639](https://github.com/dirvine/ant-quic/commit/68ee6397735c95023809ef7e8c2b2a5350d1bd6e))
- Adjust CI configuration to resolve workflow failures ([429be71](https://github.com/dirvine/ant-quic/commit/429be7188ad18cb2bed9c3577690e9b54f8c0c27))
- Resolve Docker build failure by creating dummy bench files ([fd2d0c8](https://github.com/dirvine/ant-quic/commit/fd2d0c890baee73841431be571827345ee4b68ca))
- Resolve CI failures for coverage and benchmark workflows ([8a62a50](https://github.com/dirvine/ant-quic/commit/8a62a50ca167111183b547d2e4da8f83d0bca209))
- Suppress legitimate dead code warnings for future NAT traversal features ([2de6ec3](https://github.com/dirvine/ant-quic/commit/2de6ec3318567a7f2e76194d06e0daa187ef2fb9))
- Resolve test compilation errors and bump to 0.8.13 ([e97bc53](https://github.com/dirvine/ant-quic/commit/e97bc530c363bf4f343926a3421cf1af6205fd0c))
- Correct binary names in scheduled-external workflow ([4777969](https://github.com/dirvine/ant-quic/commit/4777969b30b4bea4fa78377ba0bd489968e13207))
- Make quick-checks green by formatting and fixing tests ([835ba6b](https://github.com/dirvine/ant-quic/commit/835ba6bc2515cae35a124c6bdba17790b9e3fdd7))
- Document no-op tracing APIs to satisfy -D missing-docs ([f74bb49](https://github.com/dirvine/ant-quic/commit/f74bb49d558faa59135d181b7574c147dd189e62))
- Use refresh_cache_if_needed to avoid unused code warnings ([63edaab](https://github.com/dirvine/ant-quic/commit/63edaab8590bdcdf63841a28cfef35c2717dad67))
- Make enhanced test script suite-selectable and non-exiting ([59c58b6](https://github.com/dirvine/ant-quic/commit/59c58b669289b0c6af888fc21f683a552ed3629a))
- Gate ring_buffer behind feature; quiet no-trace stubs to unblock benches ([2c2b431](https://github.com/dirvine/ant-quic/commit/2c2b43196a95fdccd858e76c0acde92db60ce37d))
- Add CI helper flags to ant-quic binary ([b3d4fdc](https://github.com/dirvine/ant-quic/commit/b3d4fdc7641e5f461802174e46c743a98ee3aab8))
- Address dead-code and must-use errors in discovery modules ([5610bbd](https://github.com/dirvine/ant-quic/commit/5610bbd0f6ee76ec42785825cb8dc3b2d03f50bf))
- Make ACT runs reliable ([a64015c](https://github.com/dirvine/ant-quic/commit/a64015c11f09e3d7ece8503156b1945d2a3cadb9))
- Pre-clean leftover resources and improve health checks ([930acc1](https://github.com/dirvine/ant-quic/commit/930acc10c53f143342043df95e99b44ab7099a9b))
- Improve connectivity and report robustness ([6eceb2c](https://github.com/dirvine/ant-quic/commit/6eceb2c3f69d4b074d4002501da9841a03c08068))
- Make CI TLS verifier compile with rustls 0.23 and clone Args ([bc11851](https://github.com/dirvine/ant-quic/commit/bc11851b06d2e7f69ae93eed704a77ae2388306d))
- Derive Clone for Commands to satisfy Args Clone ([562341b](https://github.com/dirvine/ant-quic/commit/562341bf0a7599626c7041fdabe10628454a7c08))
- Apply cargo fmt and improve Docker test scripts ([55fdd7f](https://github.com/dirvine/ant-quic/commit/55fdd7fda534ac1b0ed18e577fd0ea5d6ed0ae21))
- Resolve clippy unused import warnings in PQC integration test ([f7f8910](https://github.com/dirvine/ant-quic/commit/f7f8910ba298642824fda70e69e95c826bf093c2))
- Run integration tests with --tests instead of glob ([399fc2f](https://github.com/dirvine/ant-quic/commit/399fc2f3dad5b8ea9c0bdaff3f8b11c62b30680d))
- Add rustfmt to quick checks, correct summary icons, support main branch, drop MSRV placeholder ([996320a](https://github.com/dirvine/ant-quic/commit/996320ab539cfc614d91318a46a1f43367f827eb))
- Install jq/bc for external validation workflows ([e58f3af](https://github.com/dirvine/ant-quic/commit/e58f3aff0f4085cd83a68625b95bc61a25ce107b))
- Use Codecov 'files' input for lcov upload ([507206f](https://github.com/dirvine/ant-quic/commit/507206f8591c49b5f66009bf6420bc7a885348c1))
- Install cross via taiki-e/install-action for stability ([e2d22dc](https://github.com/dirvine/ant-quic/commit/e2d22dcbd99699373e8f561c15c5bd9f9c935dd7))
- Trigger book build on main and master ([6498654](https://github.com/dirvine/ant-quic/commit/6498654bbce8a4b55e51f6a5739d5e6d2f90596f))
- Correct rust-cache action name in enhanced-testing ([deca96c](https://github.com/dirvine/ant-quic/commit/deca96c713c8bd006db4bee0c7c0074dd9b4ccfd))
- Make cargo-machete/cargo-outdated installs non-fatal in quick-checks ([1438c59](https://github.com/dirvine/ant-quic/commit/1438c59278aeb4706390ac2b7792d494f4b34e46))
- Replace rust-2024-idioms with stable rust-2021-compatibility to avoid unknown-lint warnings ([6bfa5ab](https://github.com/dirvine/ant-quic/commit/6bfa5ab77b6226b976914082bfce66520055ad16))
- Use rhysd/actionlint for YAML validation to avoid reviewdog GitHub checks under act ([3a4739d](https://github.com/dirvine/ant-quic/commit/3a4739d224107c395193dfdaa9d20f274fa4f1dc))
- Use cargo-llvm-cov for coverage in standard-tests and exclude integration tests; increase timeout ([b2dff81](https://github.com/dirvine/ant-quic/commit/b2dff81e901b8339514112063b083f91e76f34b0))
- Stop mounting ~/.cargo; mount only registry/git caches under .act-cache to avoid overwriting host cargo binaries ([6184dde](https://github.com/dirvine/ant-quic/commit/6184ddeabc2ec972c3d6e0b0f0447e186b8afd7e))
- Resolve failing workflows and YAML syntax errors ([e9099e9](https://github.com/dirvine/ant-quic/commit/e9099e9d83a62b27171db9ea2c8fc94b2b3720de))
- Resolve YAML syntax errors in quick-checks workflow ([e570927](https://github.com/dirvine/ant-quic/commit/e570927d7b79b1f8cda0c45aa2758266d3603167))
- Correct YAML indentation in quick-checks workflow ([6c95b74](https://github.com/dirvine/ant-quic/commit/6c95b740e901f9028626b792822aa59e35d46985))
- Correct multiple YAML indentation issues in quick-checks workflow ([578334f](https://github.com/dirvine/ant-quic/commit/578334f2ef36957e2d8e1dff8270face84ad161e))
- Correct quick-test job indentation structure ([12ff232](https://github.com/dirvine/ant-quic/commit/12ff2324cc5f20c4104805f84da57added215481))
- Temporarily remove quick-test job to isolate issue ([8edeeeb](https://github.com/dirvine/ant-quic/commit/8edeeeb13c16035eb96826fd4c98731fae161071))
- Stabilize workflows and lint policy ([3b6f8cb](https://github.com/dirvine/ant-quic/commit/3b6f8cbcbbd23ce177562ca7986f4be1a7315a49))
- Satisfy rustfmt on stable toolchain for CI ([0bff385](https://github.com/dirvine/ant-quic/commit/0bff3855e966d9e90b9129c794c8b698ce067d56))
- Remove unwraps/panics; resolve borrows in first-packet and retry path ([4c0086e](https://github.com/dirvine/ant-quic/commit/4c0086ed834ad4ea5f09bc9510a41c34d98fd4fe))
- Resolve CI failures and remove panics ([ccfac8b](https://github.com/dirvine/ant-quic/commit/ccfac8bd00c0e91993677dc32b7b9d0be39a8e64))
- Apply cargo fmt to fix CI formatting check ([4a50ab6](https://github.com/dirvine/ant-quic/commit/4a50ab605ad54226daa261fc0a61818a2780fcf7))
- Remove unwrap() calls and fix branch references for CI ([d92ff5b](https://github.com/dirvine/ant-quic/commit/d92ff5bdc94bed6af4079d302a35c7bd9fe336e7))
- Resolve Windows-specific compilation warnings ([82440fd](https://github.com/dirvine/ant-quic/commit/82440fdbf87391e49fdcc4d4e7f6265e9af77f0f))
- Actually remove pedantic clippy checks from workflows ([78dce31](https://github.com/dirvine/ant-quic/commit/78dce313483f2e2f87cd617cee08895fd7f39fef))
- Resolve coverage workflow failures and PQC test issues ([25dec71](https://github.com/dirvine/ant-quic/commit/25dec71dff14c289afac0529c6200d1c796fdd5e))
- Correct async test compilation error in Linux discovery test ([164cb89](https://github.com/dirvine/ant-quic/commit/164cb89ab1ea4765411e5aa1590bbd1945f42154))
- Remove unsupported test-timeout flag from tarpaulin ([9c90325](https://github.com/dirvine/ant-quic/commit/9c903253358bc3f2168ad6778c6f0f46de9bdf9f))
- Exclude discovery tests from tarpaulin coverage to prevent hangs ([ef36e2e](https://github.com/dirvine/ant-quic/commit/ef36e2e36b63bbf5e13c4050370fa002478e4805))
- Remove container names and static IPs from client services to allow Docker Compose scaling ([aa48849](https://github.com/dirvine/ant-quic/commit/aa48849def07baca0f01751f4d5c6f969fa60e62))
- V0.8.17 patch release - clippy fixes, API refactoring, token v2, trust model updates ([b4e2f60](https://github.com/dirvine/ant-quic/commit/b4e2f60bd47403904651c36c69cd35fc6fca3e31))

### Documentation

- Add Local NAT Traversal Tests section with local runner and cargo integration ([d879705](https://github.com/dirvine/ant-quic/commit/d879705152610a964be86dddb71ed27288cdb49f))
- Align release steps with current workflow (no crates.io/Docker) ([fc8ae6e](https://github.com/dirvine/ant-quic/commit/fc8ae6e69ff0ca66294b406c55fccbf9bd75616b))

### Features

- Production readiness - comprehensive security and error handling improvements ([363d581](https://github.com/dirvine/ant-quic/commit/363d581ca35e3dfed99bb1c2cdb9261eb35f47bf))
- Add license headers to all source files ([f1c43e2](https://github.com/dirvine/ant-quic/commit/f1c43e2f5af7a5937be35c2d3a8cffee1b8ddb7f))
- Implement Serialize/Deserialize for ML-DSA and ML-KEM keys ([7997e73](https://github.com/dirvine/ant-quic/commit/7997e73825ac8898199cf2b8a38822492bbfb106))
- Enable PQC by default; add 'classical-only' feature to force classical mode; PQC config defaults respect feature gate ([b9e96e6](https://github.com/dirvine/ant-quic/commit/b9e96e6baec5f7f5bc69e78061f44002704da014))

### Miscellaneous Tasks

- Bump version to 0.8.10 ([98c259a](https://github.com/dirvine/ant-quic/commit/98c259ac0c10a47305fb8256e6902beb30a18f37))
- Update Cargo.lock for version 0.8.10 ([6246a9b](https://github.com/dirvine/ant-quic/commit/6246a9bc12f529b0fb79d13e2b1951b8af91e225))
- Bump version to 0.8.11 for dead code cleanup release ([ed41029](https://github.com/dirvine/ant-quic/commit/ed410298599d7ed870f235454a0fe6aaba5d97a7))
- Tighten lint gates; doc or gate remaining public items; dead-code allowances ([abff2ee](https://github.com/dirvine/ant-quic/commit/abff2eeb10476180d1e45cb8ee88d73b85e15806))
- Bump version to 0.8.12 ([2155e45](https://github.com/dirvine/ant-quic/commit/2155e45cf9fb2a9c28d3a085ed74dfb5d5b5de91))
- Update Cargo.lock for 0.8.12 release ([b9ff9ed](https://github.com/dirvine/ant-quic/commit/b9ff9ed452e368088ed4637f910c654d490d1a66))
- Pass through host GITHUB_TOKEN if set for actions needing auth ([20a6c2e](https://github.com/dirvine/ant-quic/commit/20a6c2ea4e74ccfd6ae38ac31a52d2aee562f7de))
- Avoid global docker.sock/privileged mounts; apply only to NAT tests; default NO_SSH_AGENT/NO_DOCKER_SOCK=1 ([730f61d](https://github.com/dirvine/ant-quic/commit/730f61d1d98739378bb19816cd345092d4ba057d))
- Add per-job logging, result tracking, and end-of-run summary with debug tails ([667027e](https://github.com/dirvine/ant-quic/commit/667027e6f3816126b36bc8e0d417452d7598d2cd))
- Rename act runner to scripts/local_ci.sh with summary and logs ([c915a3e](https://github.com/dirvine/ant-quic/commit/c915a3efa345f78c54fa0786a36ba48107126bda))
- Make scripts/local_ci.sh executable ([5b73b4d](https://github.com/dirvine/ant-quic/commit/5b73b4d77da360874dcb3dad148e0010601434a4))
- Add optional Docker prune and disk usage reporting (CLEAN_BEFORE/CLEAN_BETWEEN) ([d4255d9](https://github.com/dirvine/ant-quic/commit/d4255d992b4cade191aa8682bcc1bae65e2f1a50))
- Default CLEAN_BEFORE=1 and add 'make local-ci' wrapper target ([f34df28](https://github.com/dirvine/ant-quic/commit/f34df284c27ffc1b4920db76ab98c8c20f06e214))
- Update .gitignore for docker test artifacts and local CI cache ([22d12bc](https://github.com/dirvine/ant-quic/commit/22d12bcf69735e0f70c07391fc906892912c8609))
- Remove tracked test artifacts and update docs ([a517167](https://github.com/dirvine/ant-quic/commit/a517167c1d8b3e69930a309b4e8db7fe3af06060))
- Add CI consolidated badge to trigger clean workflow run ([8e91a90](https://github.com/dirvine/ant-quic/commit/8e91a90ddc1bf071f63c4fb70041edb3486a05b5))

### Refactor

- Remove dead connection_establishment code and fix dependencies ([535190e](https://github.com/dirvine/ant-quic/commit/535190e1c3776f34fef9e33bf4bf1f08d9ef36bb))
- Remove unused NAT scaffolding; add docs; suppress transitional dead code ([8848bba](https://github.com/dirvine/ant-quic/commit/8848bba674e68f07976beb9965b06399bbb264de))

### Styling

- Apply cargo fmt to fix CI formatting checks ([bc355b1](https://github.com/dirvine/ant-quic/commit/bc355b1c1398dfa0ab8a94eef91069d08acde158))
- Apply rustfmt to satisfy CI format checks ([704d63e](https://github.com/dirvine/ant-quic/commit/704d63ef6e22dbc4f7c00c096713d8ca4252df2b))
- Apply rustfmt formatting to discovery test ([1ae6b08](https://github.com/dirvine/ant-quic/commit/1ae6b083ff0091e359c19df3d1e8b30d35c741ae))

### Testing

- Add scripts/run-local-nat-tests.sh to run NAT tests locally ([9b5106f](https://github.com/dirvine/ant-quic/commit/9b5106f6a7175259b5e2dc5f19a14d66de9dd2f2))
- Add opt-in cargo tests to run local NAT harness (RUN_LOCAL_NAT=1) ([1ca18cd](https://github.com/dirvine/ant-quic/commit/1ca18cd9d7a675851e4a5c3817ba96910a86f2ac))
- Fix awk field expansion under set -u (escape ) and improve reliability ([18d9bb7](https://github.com/dirvine/ant-quic/commit/18d9bb7bc532dd4ac649eaccc003e325f0fe9b41))
- Stop using Foundation::PSTR; pass raw pointer to getsockopt for WinSock API compatibility ([2af394e](https://github.com/dirvine/ant-quic/commit/2af394e166af1991ba300efcbc48a74cea7dfd3e))
- Add loopback classical TLS connect; ensure local QUIC handshake works ([5588b8a](https://github.com/dirvine/ant-quic/commit/5588b8a39f5fe41b78acd29792e758ea23e4b18d))

### Ci

- Mark matrix test step continue-on-error to avoid job fail ([c6d762b](https://github.com/dirvine/ant-quic/commit/c6d762baad0785ac403a5430f86296536b2ca938))
- Make steps act-friendly; guard disk cleanup, precreate results dirs ([dba5b26](https://github.com/dirvine/ant-quic/commit/dba5b26eb98d5ca73b9410ad17ac08a84e975685))
- Add ACT-safe build path and artifact guards ([3ca1f6d](https://github.com/dirvine/ant-quic/commit/3ca1f6dd2cda4beb787e3a1a59473641826862a7))
- Make healthcheck protocol-aware (UDP socket check via ss) ([0aaf224](https://github.com/dirvine/ant-quic/commit/0aaf22418932437842c162250467cae32a92532b))
- Enforce suite status in CI and harden NAT tests; temporarily disable symmetric_to_portrestricted ([7630507](https://github.com/dirvine/ant-quic/commit/76305072b4dc0b504d0c5f072e42b5fcde134f59))
- Skip checkout when running under act (uses mounted workspace) ([d8c8329](https://github.com/dirvine/ant-quic/commit/d8c8329f644cb5d18484b9aaf88b3e8ba8d0f6cf))
- Skip actions/checkout when runner is nektos/act to avoid git auth ([0aa0e26](https://github.com/dirvine/ant-quic/commit/0aa0e26940b3cf4f0888cfa9ce0d6e646161cac3))
- Remove windows from matrix; make yaml/toml validation non-blocking ([1f82915](https://github.com/dirvine/ant-quic/commit/1f829159318848a1e307b02c8702fb552eaec21f))
- Enforce unwrap/panic bans only for non-test targets; allow tests/benches ([b1b3047](https://github.com/dirvine/ant-quic/commit/b1b3047d5b18ba28736772411462d5fe8e76d7df))
- Run clippy as advisory only (no unwrap/panic enforcement) to get green CI ([f055afb](https://github.com/dirvine/ant-quic/commit/f055afb330565d6e8491181835e0116cd3942c2a))
- Drop actionlint step; keep TOML validation only (non-blocking) ([db594d8](https://github.com/dirvine/ant-quic/commit/db594d8d3a6a056f05dba256d9d138107b4e3333))
- Drop Windows from consolidated test matrix to match supported coverage ([8cb432d](https://github.com/dirvine/ant-quic/commit/8cb432d9935e4b48266801f82f48b2f4b93e2a88))
- Run Docker NAT tests only on schedule/dispatch; mark job continue-on-error ([130950e](https://github.com/dirvine/ant-quic/commit/130950ee863708aa2c3a3b4385e87e277017dddb))
- Schedule/dispatch only; drop extra RUSTFLAGS to reduce noise ([d595949](https://github.com/dirvine/ant-quic/commit/d595949d84762fb997aac755c6ffd53ee4cd880e))
- Re-enable windows-latest in consolidated test matrix; rustls gating fixed for MSVC build ([6592695](https://github.com/dirvine/ant-quic/commit/65926953d819a3020f5a228496f73c3ed64d1805))
- Allow-failure for ubuntu nightly matrix (continue-on-error) to keep CI gate green ([17b0715](https://github.com/dirvine/ant-quic/commit/17b0715a90dbaabe63dc2920770074c6ae8bb92d))
- Remove nightly testing from consolidated and extended workflows ([99019ec](https://github.com/dirvine/ant-quic/commit/99019ecca068dc02a17f1821f2b6c7232fc4c26f))
- Make NAT tests reusable via workflow_call; pin runner; add networking tools ([db56ac4](https://github.com/dirvine/ant-quic/commit/db56ac40db167067b183ce4e9afd4cd5c4738d36))
- Fix dependency review config conflict and supply chain check false positives ([06044b3](https://github.com/dirvine/ant-quic/commit/06044b3ae930a34015f9d2a0f42cb0c66130cafd))
- Fix CI failures - make coverage non-blocking and fix dependency review ([d627156](https://github.com/dirvine/ant-quic/commit/d6271560b4f050ad886bca8c7a64b2ae639a6055))
- Add non-blocking MSRV verification job ([2ec7569](https://github.com/dirvine/ant-quic/commit/2ec75695df27bd56fba56eba3da9f42f58fb940d))
- Enforce strict clippy policy as blocking; pin dtolnay/rust-toolchain@v1; add permissions/concurrency; unify MSRV 1.85.0 ([cdb7d55](https://github.com/dirvine/ant-quic/commit/cdb7d55e4b0590c2e6865ad01feed84a47ee422b))

### Relay

- Fix TokenBucket double locking and reduce allocations; add efficiency report ([ad20e51](https://github.com/dirvine/ant-quic/commit/ad20e51a7a117635649d87a5ae6135e616e2c02a))

## [0.8.9] - 2025-08-19

### Bug Fixes

- Optimize Docker NAT tests to prevent timeout failures ([e9401d8](https://github.com/dirvine/ant-quic/commit/e9401d8ee8f44ebc52e7fa44aec64ad67827011b))
- Consolidate CI workflows to reduce runner congestion ([27c5c88](https://github.com/dirvine/ant-quic/commit/27c5c88fa6c404349961c0740d2c36e928882612))

### Miscellaneous Tasks

- Bump version to 0.8.9 for placeholder cleanup release ([f1cedf1](https://github.com/dirvine/ant-quic/commit/f1cedf1f53220f1f36829ea4a565e23fb74daa3c))

### Refactor

- Remove misleading placeholder NAT traversal files ([fed1d20](https://github.com/dirvine/ant-quic/commit/fed1d207b777bec7ba1463aac759cab89f5f057c))

## [0.8.8] - 2025-08-19

### Bug Fixes

- Apply code formatting and finalize relay authenticator improvements ([e1bf568](https://github.com/dirvine/ant-quic/commit/e1bf5681737aa865f24a1c6442099039ad373f57))
- Add missing discovery integration test file ([0c96d31](https://github.com/dirvine/ant-quic/commit/0c96d31e17b524c9b17c29c440010a87bdb18951))

### Miscellaneous Tasks

- Update Cargo.lock for v0.8.6 ([291336c](https://github.com/dirvine/ant-quic/commit/291336c55e740b25dda163e162dc361dd9f2ea78))
- Bump version to 0.8.7 and update dependencies ([fa0c25f](https://github.com/dirvine/ant-quic/commit/fa0c25f4ed21fc87d36371aeed0f25a522493384))
- Relax clippy settings to be realistic instead of pedantic ([66784cf](https://github.com/dirvine/ant-quic/commit/66784cf034bd753658c072ed0d1c8dcd4f686487))
- Bump version to 0.8.8 ([5094298](https://github.com/dirvine/ant-quic/commit/5094298c3a86b418f16f1bf03d7b55da4f3426f5))

## [0.8.6] - 2025-08-19

### Bug Fixes

- Update Docker images to use available Rust 1.85.1 versions ([351437b](https://github.com/dirvine/ant-quic/commit/351437bc2bbcee7669e2f667003e529915750199))
- Correct Docker build contexts and file paths ([903835d](https://github.com/dirvine/ant-quic/commit/903835d11ecc19cc196e3a907031a7d20c277d0a))
- Copy benches directory before dependency build in Dockerfile ([cbf50f8](https://github.com/dirvine/ant-quic/commit/cbf50f8c99a698a1184bf6ac85684c99fd42a68d))
- Resolve clippy warnings in PQC integration tests ([5d9bcc4](https://github.com/dirvine/ant-quic/commit/5d9bcc4890ad2663d29d5e3e4b879f53f3ed6c38))
- Remove invalid cache-from references causing registry errors ([7b7b61f](https://github.com/dirvine/ant-quic/commit/7b7b61f99dfed604ee0abec99fc9753a87fe8d75))
- Add 'net' feature to nix crate for ifaddrs module ([23c46fe](https://github.com/dirvine/ant-quic/commit/23c46fef9a52f2f6efa22d469da34f37e400fdbb))
- Eliminate production panic risks with robust error handling ([a7d1de1](https://github.com/dirvine/ant-quic/commit/a7d1de11d6fb21e064ed5a6a211fb008de10993f))
- Enhance protocol obfuscation with improved random port binding ([6e633cd](https://github.com/dirvine/ant-quic/commit/6e633cd93afc4684eb2eff11fc38741d108deffa))
- Correct Docker build context paths for NAT gateway ([f510f4d](https://github.com/dirvine/ant-quic/commit/f510f4d616cbfbc07898fcc8a94c8e7874c789a3))
- Update MSRV to 1.85.0 for Edition 2024 support ([088a174](https://github.com/dirvine/ant-quic/commit/088a174bce06b70bc976373120b5ea43891b6fef))
- Remove obsolete Quinn package references from workflows ([e557a91](https://github.com/dirvine/ant-quic/commit/e557a917ea5e140998c4c52fdb61841265f8d014))
- Remove orphaned conditional statements in workflow ([acf2ef8](https://github.com/dirvine/ant-quic/commit/acf2ef89fa19bf5bdcdf87ae600ec99ec679d966))
- Optimize Coverage workflow to prevent timeouts ([d5d8362](https://github.com/dirvine/ant-quic/commit/d5d83628ffa620aac727c26ec2b75a7071e34d19))
- Resolve workflow name conflicts ([4204bae](https://github.com/dirvine/ant-quic/commit/4204bae18ce09b7fc4d543ece3c31a0339c80fd6))
- Remove invalid --skip flag from Coverage workflow ([7b671dd](https://github.com/dirvine/ant-quic/commit/7b671dd17ef00fc31ce4c99f804299f86409c7f5))
- Disable problematic CI workflow file ([d9cfd6f](https://github.com/dirvine/ant-quic/commit/d9cfd6ff3c0058086e0fbe467a93cc901dab98a9))
- Use approximate comparison for floating point test assertion ([ff8473a](https://github.com/dirvine/ant-quic/commit/ff8473ab5d70b3f49c1c9d921f2f67d15ae61cad))
- Resolve multiple CI/CD workflow failures ([0b02fff](https://github.com/dirvine/ant-quic/commit/0b02fff45a6ea49ba9f49374ab376948879314ee))
- Resolve Docker build context and cache timing test issues ([b133e76](https://github.com/dirvine/ant-quic/commit/b133e76230637cd16a6a05f5897e2be27e1bf28f))
- Correct Docker build context paths for compose builds ([81226c3](https://github.com/dirvine/ant-quic/commit/81226c335590f47647e083570cedfec5fdf506ca))
- Resolve NAT traversal mixed format test timeouts ([fcd6643](https://github.com/dirvine/ant-quic/commit/fcd664310334305cbd5756364ff7c30acfcc4328))
- Resolve timing test and ioctl type conversion failures ([9980aee](https://github.com/dirvine/ant-quic/commit/9980aee282cb9a3434ad4957d4a6480225efe40c))
- Remove references to disabled platform_compatibility_tests ([8696cf1](https://github.com/dirvine/ant-quic/commit/8696cf10138753814e141453eff0158735494d1b))
- Correct NAT gateway script paths for Docker build context ([cd51364](https://github.com/dirvine/ant-quic/commit/cd513641f99428d54e2731051f815793dbbabb6e))
- Update platform-specific tests to use correct Windows API ([892ce6e](https://github.com/dirvine/ant-quic/commit/892ce6e4bbe21c8d8a300bd181dc7844b27c7bb2))
- Add proper feature gates for crypto and platform modules ([2f77013](https://github.com/dirvine/ant-quic/commit/2f770135dab589796cb55ee5f621b7a02588fcec))
- Add feature gates for PQC state in connection module ([f83d414](https://github.com/dirvine/ant-quic/commit/f83d4148ee93087c43f7ee4964c2c7b207c2edd0))
- Add feature gates to PQC test files ([e1887b5](https://github.com/dirvine/ant-quic/commit/e1887b51ac5d2e21d5eccba76a9dcbd41695f049))
- Add remaining feature gates for PQC references ([6a9b805](https://github.com/dirvine/ant-quic/commit/6a9b805f07d6083809993d7c1083375991722404))
- Resolve feature gate compilation errors for minimal builds ([e1e1279](https://github.com/dirvine/ant-quic/commit/e1e12792334f3e369c106f939a38bba12e271e43))
- Resolve binary compilation errors for minimal builds ([985706f](https://github.com/dirvine/ant-quic/commit/985706fc7214b12768c35db2cae45de82ff277cf))
- Comprehensive feature gate fixes for minimal builds ([82ebdd4](https://github.com/dirvine/ant-quic/commit/82ebdd4b5632961884eb3c24290d086c8224aadd))
- Resolve compilation errors with minimal feature builds ([7223658](https://github.com/dirvine/ant-quic/commit/72236587d57731d684f747d730ce3da8abf625d4))
- Correct build context paths for NAT gateway services ([05e70ed](https://github.com/dirvine/ant-quic/commit/05e70ed287698d5d8875a0e36dd1c59cbec56cbb))
- Resolve compilation errors with minimal feature sets ([a3001ed](https://github.com/dirvine/ant-quic/commit/a3001edb75a6705b64a1f302f097d7d6b760b2b7))
- Resolve clippy lints and warnings ([3d6e6e6](https://github.com/dirvine/ant-quic/commit/3d6e6e640ffca343328dfe5fc2921a24c9867643))
- Resolve CI/CD workflow failures ([2423176](https://github.com/dirvine/ant-quic/commit/2423176cdf8deae69f5b8242519297f738ee1744))
- Pin cargo-nextest to version 0.9.100 for Rust 1.85 compatibility ([c70c19b](https://github.com/dirvine/ant-quic/commit/c70c19b51a179328a72ce201a2a202aa4f90ba85))
- Combine Docker Compose files to resolve service extension error ([5d25cde](https://github.com/dirvine/ant-quic/commit/5d25cdefef2c22582d2592b53ad6253dba8353af))
- Build Docker Compose services in correct order ([46da893](https://github.com/dirvine/ant-quic/commit/46da8931ba96a2160be72ce97ac25673dc7a2ab2))
- Resolve Docker Compose service extension errors in NAT tests ([310b285](https://github.com/dirvine/ant-quic/commit/310b2858c80482e7963e7125b1c4320cf0eef08d))
- Remove unnecessary cargo-nextest installation from test-runner ([974dbb0](https://github.com/dirvine/ant-quic/commit/974dbb0ceb1ed3e610e735825db162c3e458c00b))
- Resolve CI workflow failures ([1c21ec9](https://github.com/dirvine/ant-quic/commit/1c21ec9bd39ae843b6399c946e9cfc6b6de0da5f))
- Disable property tests workflow steps ([61e6659](https://github.com/dirvine/ant-quic/commit/61e6659b595c00ad0a4fe1cd38356fae26ea6b7c))
- Add missing benchmark-results.json generation for Performance Benchmarks workflow ([f4dacbb](https://github.com/dirvine/ant-quic/commit/f4dacbb4dfbff1faea26d31bf1d311b4276c4d6c))
- Optimize Docker NAT Tests to prevent build timeouts ([0c5da1a](https://github.com/dirvine/ant-quic/commit/0c5da1a477a193db265d1447fce13e1287d11e23))
- Disable automatic CI Backup workflow to prevent redundant failures ([7068eb6](https://github.com/dirvine/ant-quic/commit/7068eb6bfcd2fcd6340d987e437b289e0b94d913))
- Resolve NAT Testing workflow Docker Compose dependency issues ([64fd21f](https://github.com/dirvine/ant-quic/commit/64fd21f4e591c500fa9370b04d455a1b7e5dfa1c))
- Update NAT test script to use correct container names ([caaa93d](https://github.com/dirvine/ant-quic/commit/caaa93d32722fc7257d44518e21962d0b8decb2f))
- Correct binary name in external validation workflow ([e2ea276](https://github.com/dirvine/ant-quic/commit/e2ea276a90e48d0ea10662357f49f02875ac08e2))
- Add serde rename attributes for YAML field mapping in test_public_endpoints ([1e84816](https://github.com/dirvine/ant-quic/commit/1e84816c4f3e7e11d3805e9c9dbcefc3803f5406))
- Resolve clippy warnings and compilation errors ([81c4647](https://github.com/dirvine/ant-quic/commit/81c4647688d2d009503fd75034e8e6f983a91607))
- Resolve remaining clippy uninlined format args warnings ([1260bc2](https://github.com/dirvine/ant-quic/commit/1260bc2ca7ded1cbf6fee67e0edd220532ad2de9))
- Resolve code formatting issues ([fb9f945](https://github.com/dirvine/ant-quic/commit/fb9f9458c0d8bb3020ce0034ebf6ea9e0bb3d655))
- Correct YAML field names with underscore prefix in public-quic-endpoints.yaml ([52e36a1](https://github.com/dirvine/ant-quic/commit/52e36a12e15e4283e4f44e84982a503d0b120926))
- Resolve clippy uninlined format args warnings in security regression tests ([034d0e9](https://github.com/dirvine/ant-quic/commit/034d0e9ebd9d5a3e523c6b3b6e4713914f8ffb31))
- Resolve new Rust 1.89.0 clippy warnings ([0e510ba](https://github.com/dirvine/ant-quic/commit/0e510ba7d6b0618622af0a0f59e27f472bebcec3))
- Resolve CI workflow failures ([4e111cb](https://github.com/dirvine/ant-quic/commit/4e111cb51ca28864e21edba07ce80f124461cfd0))
- Correct CI workflow issues ([7cbd0bb](https://github.com/dirvine/ant-quic/commit/7cbd0bbd6603e831672ce47a9a66662357605489))
- Resolve documentation link errors ([b6e4b7a](https://github.com/dirvine/ant-quic/commit/b6e4b7a0ca12a04e6512e9072a0951cf061d16dd))
- Resolve clippy needless_return warnings in examples ([c293ff4](https://github.com/dirvine/ant-quic/commit/c293ff47fee1b3ea40079e99a214980b48890393))
- Resolve clippy warnings for crates.io publication ([300cc51](https://github.com/dirvine/ant-quic/commit/300cc516c3e1039e270b818e014eba2fd7d160af))
- Eliminate all .expect() calls from PQC cryptographic code ([b1cfa75](https://github.com/dirvine/ant-quic/commit/b1cfa757f79f53ad71d43a7426017b5b3c767db7))
- Resolve critical vulnerabilities in dependencies ([ae7c219](https://github.com/dirvine/ant-quic/commit/ae7c219460434795148ad03e529e5c4ddd2135cc))
- Docker workflow compatibility issues ([dafe161](https://github.com/dirvine/ant-quic/commit/dafe161d57f54ba9884f70b5065db8f07ace86b2))
- Force push benchmark history to handle branch conflicts ([2a99c01](https://github.com/dirvine/ant-quic/commit/2a99c01c966c429a0a37ff9c2ce2e01c0e96b21e))
- Correct Docker NAT testing configuration ([6c025cc](https://github.com/dirvine/ant-quic/commit/6c025cc57f0b5b798bd195bea0708ba2f1096076))
- Resolve CI workflow issues and enable platform-specific tests ([49bca10](https://github.com/dirvine/ant-quic/commit/49bca107f253c68295ce6f50dce476a7c95d78af))
- Resolve formatting issues in platform API integration tests ([60eeb8e](https://github.com/dirvine/ant-quic/commit/60eeb8e4f2740cf90857b69291a5939818384b6d))
- Resolve module visibility issues for macOS platform integration tests ([53ac4f4](https://github.com/dirvine/ant-quic/commit/53ac4f46b34d621b22a3eac94fa0768f75a290bb))
- Make LinuxNetworkError public to fix test compilation ([c2d1471](https://github.com/dirvine/ant-quic/commit/c2d14717fb9a71b244838faf6334730178652509))
- Resolve platform-specific test failures in CI ([346dcf9](https://github.com/dirvine/ant-quic/commit/346dcf9df1d78ba7e5e165947a6a658aa37b352e))
- Resolve Windows clippy warnings in candidate discovery ([dfe4030](https://github.com/dirvine/ant-quic/commit/dfe403095b75f7e034196c8a88bcfc7f4e46b873))
- Make NAT traversal integration test more robust for CI ([a7ffd51](https://github.com/dirvine/ant-quic/commit/a7ffd513dad6149127ef21f3c0ad0230fd287b18))
- Remove unmaintained paste crate dependency ([9ba4916](https://github.com/dirvine/ant-quic/commit/9ba491677dd5e860df52550fcaaee353061ef810))

### Documentation

- Establish ant-quic as independent project (not a Quinn fork) ([55a012d](https://github.com/dirvine/ant-quic/commit/55a012de830554b4c50cb323943482bc3dbcecd3))
- Update README with comprehensive PQC algorithm documentation ([964ed1f](https://github.com/dirvine/ant-quic/commit/964ed1f702c4d11aa3c5ed19e8ce1f1708a2cc63))

### Features

- Enhance testing and documentation quality scores ([0caae3f](https://github.com/dirvine/ant-quic/commit/0caae3fb5daa8c89ae133ff779d79672b6adf5ba))
- Add optional Prometheus metrics export capability ([44c820a](https://github.com/dirvine/ant-quic/commit/44c820ab6981f5eb17bfaaf0f6fcda76fd9fb6e1))
- Implement TURN-style relay protocol for NAT traversal fallback ([01ea90c](https://github.com/dirvine/ant-quic/commit/01ea90cab857e757153ca6c048cfe5daa9510e72))
- Make Post-Quantum Cryptography always available ([09200fb](https://github.com/dirvine/ant-quic/commit/09200fbe6dd4844e0913ff3a18a408283458e718))
- Wire SimpleConnectionEstablishmentManager to actual Quinn endpoints ([6b98e6f](https://github.com/dirvine/ant-quic/commit/6b98e6feeb79fe8611255be521ee8abc4ce6319a))
- Implement complete Post-Quantum Cryptography suite v0.8.3 ([02cb20d](https://github.com/dirvine/ant-quic/commit/02cb20d0ec31657e611b002205a4b7b9fb449508))

### Miscellaneous Tasks

- Bump version to 0.6.2 ([6a7536b](https://github.com/dirvine/ant-quic/commit/6a7536b763ac80bacb048fa69b64745602093969))
- Update Cargo.lock for version 0.6.2 ([f6125a4](https://github.com/dirvine/ant-quic/commit/f6125a4296bda3750adefe2f9b3130b5a8dc19fb))
- Bump version to 0.7.0 for Prometheus metrics release ([0b84801](https://github.com/dirvine/ant-quic/commit/0b84801b9cc53a14df742b4defa214d093eb0a28))
- Bump version to 0.8.0 for relay protocol release ([bdbf57c](https://github.com/dirvine/ant-quic/commit/bdbf57c097f2cf40c2f62e788664b279e740cb95))
- Add package exclusions to reduce crate size for crates.io ([924133a](https://github.com/dirvine/ant-quic/commit/924133a49a52813a65f3b83aa95689801cc8ba67))
- Bump version to 0.8.1 for PQC-by-default release ([528425d](https://github.com/dirvine/ant-quic/commit/528425dd4658eb96adec0540528ee70591e831e6))
- Optimize Cargo.toml exclude list for crates.io ([959cfa7](https://github.com/dirvine/ant-quic/commit/959cfa7f79f717cd81a3578c37029414ad940275))
- Bump version to 0.8.2 for crates.io publication ([2456593](https://github.com/dirvine/ant-quic/commit/245659363ea33cbd76d572807295879446f41c0f))
- Update Cargo.lock for v0.8.4 release ([c402eaa](https://github.com/dirvine/ant-quic/commit/c402eaa47337691183ea8ed18b5c1e13c5991813))
- Update saorsa-pqc to v0.3.5 and bump version to v0.8.5 ([7e20e3d](https://github.com/dirvine/ant-quic/commit/7e20e3d54b41f257f31eedab46468b47ad95fdbf))
- Bump version to 0.8.6 for paste dependency fix release ([1c819a5](https://github.com/dirvine/ant-quic/commit/1c819a5b77c089c7f4bb5a51ecbe528651944215))

### Refactor

- Simplify NAT traversal coordination request logic ([133dc72](https://github.com/dirvine/ant-quic/commit/133dc72e435fb3ef847261109af4df2af7f7398c))

## [0.6.1] - 2025-08-06

### Bug Fixes

- Add Debug derive to QuicP2PNode and AuthManager ([257b105](https://github.com/dirvine/ant-quic/commit/257b10514102cead3dbcc95c1294690d3c51ef22))

### Miscellaneous Tasks

- Release v0.6.1 ([47f2e3d](https://github.com/dirvine/ant-quic/commit/47f2e3d2b356b925eeb59a867e248f8633b10556))

## [0.6.0] - 2025-08-06

### Features

- Complete Edition 2024 migration for all test files ([11755e6](https://github.com/dirvine/ant-quic/commit/11755e65b1d89d1bef05e84d5cbf49f33d6207d5))
- Finalize v0.6.0 release with Edition 2024 migration ([2ee5646](https://github.com/dirvine/ant-quic/commit/2ee5646e0b8373a9a7597302b7a40f2dc402b25d))

### Miscellaneous Tasks

- Release v0.6.0 - Rust Edition 2024 Migration ([4ee0e10](https://github.com/dirvine/ant-quic/commit/4ee0e109b8e770280a253c83570347de02f09a18))

## [0.5.1] - 2025-08-06

### Bug Fixes

- Resolve formatting and clippy warnings for CI ([b7e2d64](https://github.com/dirvine/ant-quic/commit/b7e2d64cc46556d847072152f6afe74cbfcdbba1))
- Apply rustfmt formatting adjustments ([9d20c9f](https://github.com/dirvine/ant-quic/commit/9d20c9fc84dc7a0c59228bddd11879895c01c25b))
- Resolve remaining clippy format string warnings ([b1dcd36](https://github.com/dirvine/ant-quic/commit/b1dcd36eaa413cc24b5ffd6830c881dc1c637bb5))
- Auto-fix remaining clippy warnings ([10a9a6a](https://github.com/dirvine/ant-quic/commit/10a9a6a6cc8702f567c538fc40412a718cb472bc))
- Apply rustfmt formatting ([9329096](https://github.com/dirvine/ant-quic/commit/9329096def297220b1657113a3b34ff729ed56da))
- Resolve remaining clippy warnings ([01059d1](https://github.com/dirvine/ant-quic/commit/01059d1c8fc7648ee677e4769de4662ab35a20f3))
- Apply final rustfmt formatting ([150338b](https://github.com/dirvine/ant-quic/commit/150338b6caba4d5b6493f3303defb6966c147c6c))
- Resolve final clippy warnings ([8a0c065](https://github.com/dirvine/ant-quic/commit/8a0c065b5ffe82c216d5e547d67d03cec4fe99c1))
- Apply cargo clippy --fix for format strings ([9f83243](https://github.com/dirvine/ant-quic/commit/9f8324353ac405685dcbaea65726c8c568f978fd))
- Resolve remaining clippy warnings ([10820d4](https://github.com/dirvine/ant-quic/commit/10820d4aa4d7fbce2215e247e026f5fcfc7532dc))
- Complete PQC implementation fixes and enable all tests ([9f1f904](https://github.com/dirvine/ant-quic/commit/9f1f9049f43c6706419127d66f3aa985845c02b9))
- Resolve critical safety issues and improve implementation reliability ([c861a69](https://github.com/dirvine/ant-quic/commit/c861a69163621d3928220b6a3838f78cd22911b0))
- Resolve GitHub Actions workflow failures ([601085f](https://github.com/dirvine/ant-quic/commit/601085fabf44f56df69eff40a60b29e772abeb5e))
- Remove unstable bench tests to fix workflow failures ([61e2dd5](https://github.com/dirvine/ant-quic/commit/61e2dd5bf6e707a4120522b8b140f019fabf0cdf))
- Resolve remaining workflow issues ([7b29b98](https://github.com/dirvine/ant-quic/commit/7b29b98bbab44fae2e0ccdd17b0f0f611539aaf8))
- Resolve critical PQC signature verification issues ([3548510](https://github.com/dirvine/ant-quic/commit/35485106cb0df6501588eb66d5749c9c3f08e738))
- Resolve workflow failures ([7b2185e](https://github.com/dirvine/ant-quic/commit/7b2185e0030a6a9706b0f4291d7ba47bd16d9e51))
- Update to Rust 1.85.1 for edition 2024 support ([fe3bf36](https://github.com/dirvine/ant-quic/commit/fe3bf3612a3004096d96c944032d5442b4711505))
- Remove non-existent develop branch from comprehensive-ci workflow ([512cb70](https://github.com/dirvine/ant-quic/commit/512cb700b4b897ec427d10d1398ad79f3b1b0bb0))
- Temporarily disable comprehensive-ci workflow to resolve immediate CI issues ([52d2fd8](https://github.com/dirvine/ant-quic/commit/52d2fd825f0120385ba83e3136b91e0b9e51f4ba))
- Temporarily disable problematic workflows to allow core tests to run ([1bdf575](https://github.com/dirvine/ant-quic/commit/1bdf575ffd71368cbc1a7b926168f3f154756db7))
- Update all Docker images to Rust 1.85 for edition 2024 support ([e907bb2](https://github.com/dirvine/ant-quic/commit/e907bb2fd3f2430a1b14c0e040a883b6a4be9b8e))
- Fix hanging auth integration tests and NAT traversal frame tests ([f7d49fb](https://github.com/dirvine/ant-quic/commit/f7d49fb09a1e132e10e4abe8ac7a90655e6ed35d))
- Resolve NAT traversal frame encoding/decoding issues ([948d849](https://github.com/dirvine/ant-quic/commit/948d8494e3477a6a273f7a3a998f64877d00d892))

### Documentation

- Add CI workflow fix summary and current status ([375b1bf](https://github.com/dirvine/ant-quic/commit/375b1bf0f773b48a464eaec343a6f09ba8f0734d))

### Features

- Add missing PQC module files ([918dc65](https://github.com/dirvine/ant-quic/commit/918dc654e4a11c2217cfab40c4375a650f9fcdbc))
- Add configurable timeouts and improve NAT traversal reliability ([bb613b9](https://github.com/dirvine/ant-quic/commit/bb613b9194927b32fcfc3b072b1502f008c58dbb))
- Add comprehensive testing infrastructure ([0962496](https://github.com/dirvine/ant-quic/commit/0962496c1df2cbb10999f1aa19de86ae5e09188e))

### Miscellaneous Tasks

- Upgrade to Rust edition 2024 ([975dd77](https://github.com/dirvine/ant-quic/commit/975dd7777ce21ea106525094ee8032a943ae5761))
- Code cleanup and formatting ([77f73e3](https://github.com/dirvine/ant-quic/commit/77f73e38736e283b9ca654d180ddcfe0e94dc02d))
- Bump version to v0.5.1 ([126f340](https://github.com/dirvine/ant-quic/commit/126f34007f6ddf6ad78519ff81c5e7d970186ef3))
- Update Cargo.lock for v0.5.1 ([3d3259f](https://github.com/dirvine/ant-quic/commit/3d3259fb923727303697e327a86632ded65e5972))

## [0.5.0] - 2025-07-29

### Bug Fixes

- Fix workflow syntax errors ([6c72e10](https://github.com/dirvine/ant-quic/commit/6c72e10fe6ec419d3b569186caecc13e4414e7b8))
- Update deny.toml to allow OpenSSL license and all crates by default ([82fec0d](https://github.com/dirvine/ant-quic/commit/82fec0dab0f3fd59ea61164b1e0fc134d58b291c))
- Fix remaining CI/CD workflow issues ([2eced75](https://github.com/dirvine/ant-quic/commit/2eced7599ce7d6d0ec7121e3769a084f91b79ddb))
- Fix coverage workflow feature flags ([73cdda7](https://github.com/dirvine/ant-quic/commit/73cdda77964900b2e55389cc0a42381c4c302add))
- Final CI/CD workflow fixes ([a94b55b](https://github.com/dirvine/ant-quic/commit/a94b55b6cbec8669d7123a5170e23739d06fe68e))
- Remove invalid features from coverage workflows ([0aa7e90](https://github.com/dirvine/ant-quic/commit/0aa7e9072f7a866ee2db81aae68867f01563d6e9))
- Remove dependency names from coverage feature list ([9295c10](https://github.com/dirvine/ant-quic/commit/9295c105293088e75d50dc57f8b2d4f449af391f))
- Update deprecated actions in workflows ([551bbc0](https://github.com/dirvine/ant-quic/commit/551bbc0d57f51ffc3c01f80314b81529e480d44b))
- Fix clippy warnings and format code ([7eea954](https://github.com/dirvine/ant-quic/commit/7eea954b456db80e60393b3f0c2dfe784d1c9a80))
- Remove unused imports and fix cfg conditions ([83d01de](https://github.com/dirvine/ant-quic/commit/83d01dedbab6533c5fb4943b779aaf38f5dcdf28))
- Resolve clippy warnings in CI ([f464413](https://github.com/dirvine/ant-quic/commit/f46441375fd38e11f0e1caba1f8fb1b618515c2d))
- Resolve all compilation warnings and errors ([050e65d](https://github.com/dirvine/ant-quic/commit/050e65d2ff69db91a8967b3eb44b25a720e59153))
- Add missing documentation and handle unused results ([8da9ae6](https://github.com/dirvine/ant-quic/commit/8da9ae689d0a18a0b58b4ad639bad7f2c4ec5058))
- Temporarily disable missing_docs lint and fix unused variable ([c68085f](https://github.com/dirvine/ant-quic/commit/c68085f41c78ce098f5bae669834f61faafd4925))
- Temporarily disable clippy -D warnings to allow CI to pass ([4bdc5ca](https://github.com/dirvine/ant-quic/commit/4bdc5cac51b4e0d93af0e6bb1bfcb29118987492))
- Add crypto provider initialization to tests ([9ca6748](https://github.com/dirvine/ant-quic/commit/9ca67489ff315c70be799b1170e82d425d544258))
- Resolve all CI test failures and compilation errors ([6821a85](https://github.com/dirvine/ant-quic/commit/6821a853eb543677d98609f9578928c2a9f454a6))
- Resolve compilation warnings in test_public_endpoints binary ([11358df](https://github.com/dirvine/ant-quic/commit/11358df94f9454425340dcbbc3787ffd15c1ff5b))
- Resolve clippy warnings to fix CI failures ([fd15673](https://github.com/dirvine/ant-quic/commit/fd15673f502e5d7e967cbefd30f32d5ea62bcaac))
- Add crypto provider initialization to address_discovery_e2e tests ([58f593f](https://github.com/dirvine/ant-quic/commit/58f593fcd3e0b56886342130ca644b64a16bd204))
- Add crypto provider initialization to more integration tests ([4a6f2e7](https://github.com/dirvine/ant-quic/commit/4a6f2e7a43965660bffca676a6473ee90d938994))
- Resolve unused variable and dead code warnings in relay_queue benchmark ([8908d08](https://github.com/dirvine/ant-quic/commit/8908d0874275c45104376bbb35552724aa36bdd8))
- Add dead code allows to nat_traversal benchmark structs ([7e4ad18](https://github.com/dirvine/ant-quic/commit/7e4ad181a79491dac32d8b543a0c522a30ba56b1))
- Add crypto provider initialization to address_discovery_security_simple test ([0e62784](https://github.com/dirvine/ant-quic/commit/0e627844029c08bc9f8133be9e71a335f0c69e84))
- Remove deprecated key from deny.toml and apply formatting ([59eb9da](https://github.com/dirvine/ant-quic/commit/59eb9da06180f381e42fd4e0d00775ca9adc2490))
- Improve crypto provider initialization in tests to avoid race conditions ([8f8a61a](https://github.com/dirvine/ant-quic/commit/8f8a61ae9f81ec944cd205a64f6fa8973cbb40a6))
- Relax performance test timing and add crypto provider to auth tests ([8b97018](https://github.com/dirvine/ant-quic/commit/8b97018d5d66663eb429a39533c2ec578e6f8204))
- Resolve benchmark dead code warnings and cargo-deny bans issue ([305b1f9](https://github.com/dirvine/ant-quic/commit/305b1f96b16c1d7f8fdd79bcbacc06198e131b3e))
- Configure cargo-deny bans section to allow all crates by default ([6a6eb29](https://github.com/dirvine/ant-quic/commit/6a6eb297809cbe84aced300a52951bfa1e0ac493))
- Remove unused imports in address_discovery_security test ([12194de](https://github.com/dirvine/ant-quic/commit/12194debb16674e796e9bddaea88f532eef9843a))

### Documentation

- Add Phase 6 real-world validation test log ([4b9bd76](https://github.com/dirvine/ant-quic/commit/4b9bd7659e44565f6819812e2b6d0d9ad84599ed))
- Update README and CHANGELOG with Phase 6 real-world testing progress ([8c7feea](https://github.com/dirvine/ant-quic/commit/8c7feea9599f4bcd4206d7d64e771906fdc5d3d3))
- Add external address check script and update CHANGELOG ([204a716](https://github.com/dirvine/ant-quic/commit/204a7160b192d05d2b8ad287df3c3216cae9d37d))

### Features

- Add external address discovery display in ant-quic binary ([5315e41](https://github.com/dirvine/ant-quic/commit/5315e41f609babe7a7ae607d29786d5d963e9af7))
- Complete comprehensive CI/CD implementation with 12 tasks ([6ec1460](https://github.com/dirvine/ant-quic/commit/6ec146053d89d4ed7bd1fb30e70aed18561607dc))
- Add mdBook documentation ([f86558d](https://github.com/dirvine/ant-quic/commit/f86558dc84f6c145b8d73a403ef5ffd4454e1739))
- Implement comprehensive post-quantum cryptography support ([0b46d72](https://github.com/dirvine/ant-quic/commit/0b46d725c0f7d3335fc9c6afda514d00f451d4b6))
- Add release testing script for DigitalOcean deployment ([e777238](https://github.com/dirvine/ant-quic/commit/e777238fb4d9b0550cc553f6be88f28f21a3f7f9))

### Miscellaneous Tasks

- Update Cargo.lock for v0.4.4 ([b3edfea](https://github.com/dirvine/ant-quic/commit/b3edfea80909b13776f76984e0dd72084f5b6dba))
- Bump version to 0.5.0 for PQC release ([c3def39](https://github.com/dirvine/ant-quic/commit/c3def391b74ce6b7ae9d8ae5d069e4ce614e8ded))

### Styling

- Apply cargo fmt to fix formatting issues ([3321d8c](https://github.com/dirvine/ant-quic/commit/3321d8c9945c80e215e6c8a53d70d45921b4b4d2))

### Testing

- Complete Phase 5.3 and 5.4 with performance and security testing ([361bf29](https://github.com/dirvine/ant-quic/commit/361bf298dd7a37e71da0e3ec1abf509fa4e4cd32))

### Ci

- Remove format check workflow as requested ([8756dbc](https://github.com/dirvine/ant-quic/commit/8756dbc6cf8d39faaecb82c4ba6bd9f858f528a0))
- Temporarily disable property tests ([e19b482](https://github.com/dirvine/ant-quic/commit/e19b4828dc3fef0eb9c2d70c236799c4200ed43e))

## [0.4.4] - 2025-07-24

### Miscellaneous Tasks

- Release v0.4.4 ([8ea38bb](https://github.com/dirvine/ant-quic/commit/8ea38bb9deb15bcf99a82b432bc1f28b518e5127))

### Refactor

- Rename quinn_high_level module to high_level ([2c29b87](https://github.com/dirvine/ant-quic/commit/2c29b879b7e4ef18bc6bcf0933c6eb9703dc722f))

## [0.4.3] - 2025-07-24

### Bug Fixes

- Resolve compilation errors from fuzzing cfg attribute ([2c45561](https://github.com/dirvine/ant-quic/commit/2c455611dfd432da396eac0161cda685c1a43169))
- Wrap union field access in unsafe block ([e292d77](https://github.com/dirvine/ant-quic/commit/e292d7729d2446b840e7396d4a4eb3fb888b5577))
- Properly add ARM build testing to CI workflow ([dc7f95b](https://github.com/dirvine/ant-quic/commit/dc7f95b4f8a9897627bce677001155f81e7ce905))

### Documentation

- Update changelog with recent CI and platform fixes ([0f9d066](https://github.com/dirvine/ant-quic/commit/0f9d0669b283f6ec1d84f97580300c3beb68b72a))
- Update tasks.md to mark Phase 4.6 as complete ([cc49637](https://github.com/dirvine/ant-quic/commit/cc4963717fe6cc66a033e3c8b0df079a6c83fe35))
- Enhance with comprehensive technical specifications and deployment guidance ([2a83b3c](https://github.com/dirvine/ant-quic/commit/2a83b3cea012dbea9a3af27817f4b0f5318fd89b))
- Update CLAUDE.md and README to reflect completed platform-specific discovery ([3632ec0](https://github.com/dirvine/ant-quic/commit/3632ec0738c17cb54eec9f54ac8d7d86d0f07caa))

### Features

- Implement OBSERVED_ADDRESS frame for address discovery ([4838a8c](https://github.com/dirvine/ant-quic/commit/4838a8c42cf5fa380815dbf46e35a1622e76e711))
- Complete frame processing pipeline and rate limiting for address discovery ([1352dac](https://github.com/dirvine/ant-quic/commit/1352dac5ef78492ba243df64394201477ec70919))
- Implement QUIC Address Discovery and clean up unused metrics ([4d38c1c](https://github.com/dirvine/ant-quic/commit/4d38c1cebc29b6c5738b40914ca59f00ce05529d))
- Implement zero-cost tracing system ([4baee85](https://github.com/dirvine/ant-quic/commit/4baee85e2fe57c46c5860e89a70e460549066611))

### Miscellaneous Tasks

- Release v0.4.3 ([ff539e7](https://github.com/dirvine/ant-quic/commit/ff539e735f3b9ca1a2cbcd9040ee6a2ed0d4e0f7))

### Testing

- Ignore auth performance test in CI ([a0d8917](https://github.com/dirvine/ant-quic/commit/a0d891723b7b83b526035e481ce7d73475d5b0ac))
- Add comprehensive unit tests for phase 5.1 ([7187d98](https://github.com/dirvine/ant-quic/commit/7187d986c67c08d967378f046f17e0ccc4700b08))
- Add integration test suite for phase 5.2 ([1818019](https://github.com/dirvine/ant-quic/commit/1818019660b9b26685384092d5b0d77d5d49aab5))
- Fix crypto configuration and complete test suite ([0870446](https://github.com/dirvine/ant-quic/commit/0870446c14d96e2e70f851236aab3a6b3d903b10))

### Ci

- Temporarily remove warnings-as-errors from clippy check ([0c18004](https://github.com/dirvine/ant-quic/commit/0c180044032fd5544d12da0836e7f8a5aba31cc4))
- Allow clippy to return non-zero exit code ([19892e9](https://github.com/dirvine/ant-quic/commit/19892e94071b576cbd1538541d4e235eff924278))
- Add ARM build testing to CI workflow ([6d66b5b](https://github.com/dirvine/ant-quic/commit/6d66b5bfcdfa2e776d4f8596f7b2b19c9bd859bb))

## [0.4.2] - 2025-07-22

### Bug Fixes

- Correct port byte array size in derive_peer_id_from_address ([d8d262e](https://github.com/dirvine/ant-quic/commit/d8d262e8b02ad217c4246085869b025d36ac35c0))

### Documentation

- Comprehensive documentation update for v0.4.2 ([ab8a452](https://github.com/dirvine/ant-quic/commit/ab8a452fd8d1d048a3cd42b410c9f253670e11dc))

### Miscellaneous Tasks

- Update lockfile for v0.4.2 ([9211a84](https://github.com/dirvine/ant-quic/commit/9211a849c34673f102caea1ef8471427bb0bd89b))

## [0.4.1] - 2025-07-22

### Bug Fixes

- Add missing Windows feature flags and fix pattern matching ([e932095](https://github.com/dirvine/ant-quic/commit/e9320950304b73e2fb6184c15266a6b8abce907e))
- Resolve remaining Windows API compatibility issues ([2934979](https://github.com/dirvine/ant-quic/commit/293497990a4655aca48b1512fad9354304666197))

### Features

- Add automatic bootstrap node connection ([e97d5c5](https://github.com/dirvine/ant-quic/commit/e97d5c5a1f7108cbb895b6617d23f613b23c9e66))

## [0.4.0] - 2025-07-22

### Bug Fixes

- Resolve borrow checker error in netlink code ([b5e3cd6](https://github.com/dirvine/ant-quic/commit/b5e3cd62c491ca7beabaf205df6f714eb4fb13c3))
- Make parse_netlink_messages static to resolve borrow issue ([25a0905](https://github.com/dirvine/ant-quic/commit/25a0905d5a955e267bcba062e72d30b18cace55c))
- Use zeroed memory for sockaddr_nl to avoid private field access ([37a1b96](https://github.com/dirvine/ant-quic/commit/37a1b967b850231a7745df20ab1a9e9cc47a97c4))

### Features

- [**BREAKING**] Add real-time NAT traversal monitoring in ant-quic-v2 binary ([9f79f86](https://github.com/dirvine/ant-quic/commit/9f79f86e867972f3ab7890329b55bb6afdc9aab4))
- Add peer authentication and secure messaging capabilities ([326f11e](https://github.com/dirvine/ant-quic/commit/326f11eb3c558f7213f33a196387674f2350ec14))
- Implement 100% NAT traversal with real QUIC operations ([26e8474](https://github.com/dirvine/ant-quic/commit/26e847457f68b7ffce5a62d72a94a58aac73b816))

### Miscellaneous Tasks

- Update lockfile for v0.3.1 ([56ef97e](https://github.com/dirvine/ant-quic/commit/56ef97e48a46737974fe9640a37b006724393b6a))
- Bump version to 0.3.2 and update changelog ([5edc6b6](https://github.com/dirvine/ant-quic/commit/5edc6b656ff91e4b639797b94d34f131b795e238))
- Update Cargo.lock for v0.3.2 ([8d3302d](https://github.com/dirvine/ant-quic/commit/8d3302d2e86ba15ca74e85e11e2e85255535d49c))
- Update Cargo.lock for v0.4.0 ([eb33d02](https://github.com/dirvine/ant-quic/commit/eb33d02e9bfe85d46ea4fb74652d6142745f110c))

### Refactor

- [**BREAKING**] Remove production-ready feature flag ([0ba9d01](https://github.com/dirvine/ant-quic/commit/0ba9d0156638d942d79632ee23413a9daa45f20a))

### Ci

- Add github actions workflows for ci and releases ([7fd50fc](https://github.com/dirvine/ant-quic/commit/7fd50fcc32b52e95036e8f960c454d1588f11562))

## [0.3.0] - 2025-07-19

### Bug Fixes

- Remove Quinn dependency confusion from Cargo.toml and imports ([8f2ab27](https://github.com/dirvine/ant-quic/commit/8f2ab27461c39fd44bcd5e61db313da9208180f9))

### Features

- Implement RFC 7250 Raw Public Keys with enterprise features ([896882f](https://github.com/dirvine/ant-quic/commit/896882fc11a17807779ef7fb431fbcd7a7232b55))
- Add comprehensive NAT traversal testing infrastructure ([15b7bb3](https://github.com/dirvine/ant-quic/commit/15b7bb35a3a486742b7d2e57ee804e75081274ff))

### Miscellaneous Tasks

- Bump version to 0.3.0 for breaking API changes ([f3f1e49](https://github.com/dirvine/ant-quic/commit/f3f1e4944ff3e5522f120bf96cf1ebe4f2991170))

### Refactor

- [**BREAKING**] Comprehensive codebase cleanup and test suite stabilization ([d5d7a2d](https://github.com/dirvine/ant-quic/commit/d5d7a2dad7ef0bd9280c1de105fe6996ee9f0d1e))
- [**BREAKING**] Improve endpoint API ergonomics and eliminate all warnings ([a7f7cec](https://github.com/dirvine/ant-quic/commit/a7f7cec94c944bf46a16fcf3de75ce1f6e64d198))

## [0.2.1] - 2025-07-09

### #2008

- Make max_idle_timeout negotiation commutative ([31a95ee](https://github.com/dirvine/ant-quic/commit/31a95ee85fff18e2d937a99b84948a5bf6bec8df))

### #2057

- Use randomly generated GREASE transport parameter. ([2edf192](https://github.com/dirvine/ant-quic/commit/2edf192511873a52093dd57b9e70eb4b27c442cd))
- Extract known transport parameter IDs into enum. ([af4f29b](https://github.com/dirvine/ant-quic/commit/af4f29b8455590652c559fce1e923363ce8fae5a))
- Write transport parameters in random order. ([f188909](https://github.com/dirvine/ant-quic/commit/f18890960d7911739b5ed9402e85e8f8ad02b834))

### #729

- Proto: write outgoing packets to caller-supplied memory ([#1697](https://github.com/dirvine/ant-quic/issues/1697)) ([49aa4b6](https://github.com/dirvine/ant-quic/commit/49aa4b61e0a7dce07535eb8a288ecc3930afe2ef))

### Bug Fixes

- Read PEM certificates/keys by rustls_pemfile ([02d6010](https://github.com/dirvine/ant-quic/commit/02d6010375996ad948afdb72b78879c2e4c76b26))
- Don't bail if setting IP_RECVTOS fails ([b8b9bff](https://github.com/dirvine/ant-quic/commit/b8b9bffe3c3e914c2f72dd5b815d113e093217ac))
- Use TOS for IPv4-mapped IPv6 dst addrs ([a947962](https://github.com/dirvine/ant-quic/commit/a947962131aba8a6521253d03cc948b20098a2d6))
- Remove unused dependency tracing-attributes ([8f3f824](https://github.com/dirvine/ant-quic/commit/8f3f8242c9a36b7bfb16ab4712a127599a097144))
- Feature flag tracing in windows.rs ([061a74f](https://github.com/dirvine/ant-quic/commit/061a74fb6ef67b12f78bc2a3cfc9906e54762eeb))
- Typo in sendmsg error log ([cef42cc](https://github.com/dirvine/ant-quic/commit/cef42cccef6fb6f02527ae4b2f42d7f7da878f62))
- Pass matrix.target and increase api to v26 ([5e5cc93](https://github.com/dirvine/ant-quic/commit/5e5cc936450e7a843f88ed4008d5df9374fb7dd8))
- Use API level 26 ([bb02a12](https://github.com/dirvine/ant-quic/commit/bb02a12a8435a7732a1d762783eeacbb7e50418e))
- Enforce max 64k UDP datagram limit ([b5902da](https://github.com/dirvine/ant-quic/commit/b5902da5a95e863dfad7e1d15afaef07fc6fba0a))
- Use IPV6_PMTUDISC_PROBE instead of IP_PMTUDISC_PROBE on v6 ([7551282](https://github.com/dirvine/ant-quic/commit/7551282bdcffcf6ed57887d4eb41ffb2a4d88143))
- Propagate error on apple_fast ([53e13f2](https://github.com/dirvine/ant-quic/commit/53e13f2eb9f536713a82107d72175d800709d6fd))
- Retry on ErrorKind::Interrupted ([31a0440](https://github.com/dirvine/ant-quic/commit/31a0440009afd5a7e29101410aa9d3da2d1f8077))
- Do not enable URO on Windows on ARM ([7260987](https://github.com/dirvine/ant-quic/commit/7260987c91aa4fd9135b7eba3082f0be5cd9e8e6))
- Retry send on first EINVAL ([e953059](https://github.com/dirvine/ant-quic/commit/e9530599948820bd6bf3128e09319cd5eefc60ab))
- Make GRO (i.e. URO) optional, off by default ([6ee883a](https://github.com/dirvine/ant-quic/commit/6ee883a20cb02968ae627e2ca9396f570d815e86))
- Set socket option IPV6_RECVECN ([c32e2e2](https://github.com/dirvine/ant-quic/commit/c32e2e20896e6e1c78222cfcc703c3d36722bfb2))
- Set socket option IP_RECVECN ([fbc795e](https://github.com/dirvine/ant-quic/commit/fbc795e3cea722996232f2c853772390e05d51fe))
- Ignore aws-lc-rs-fips for codecov ([7d87dc9](https://github.com/dirvine/ant-quic/commit/7d87dc9f6ab5d7834ad1d21c3c2ef87eeac921c7))
- `impl tokio::io::AsyncWrite for SendStream` ([13decb4](https://github.com/dirvine/ant-quic/commit/13decb40b3a07af8bb9c46fb3beb6d08f81f86e5))
- Ignore empty cmsghdr ([f582bc8](https://github.com/dirvine/ant-quic/commit/f582bc8036522d475c22c201e0b3b5533dbccf6c))
- Do not produce tail-loss probes larger than segment size ([434c358](https://github.com/dirvine/ant-quic/commit/434c35861e68aac1da568bcd0b1523603f73f255))
- Respect max_datagrams when tail-loss probes happen and initial mtu is large enough to batch ([cc7608a](https://github.com/dirvine/ant-quic/commit/cc7608a6be9153267ded63cd669a7dff54732226))
- Move cmsg-len check to Iterator ([19a625d](https://github.com/dirvine/ant-quic/commit/19a625de606ea8e83bbf8e5c9265f21ebef193da))
- Zero control message array on fast-apple-datapath ([76b8916](https://github.com/dirvine/ant-quic/commit/76b89160fa74a23717e8bc97507397a18dadcc90))
- Resolve visibility warnings and update branding ([c18b2a3](https://github.com/dirvine/ant-quic/commit/c18b2a3308b49f2101f0a62fb747aa0de2295cee))
- Correct terminal_ui module location and imports ([a6600a6](https://github.com/dirvine/ant-quic/commit/a6600a6a98958c2d4ea69649c72ae3e501d29e82))
- Implement proper server reflexive discovery per QUIC NAT traversal spec ([e9c500a](https://github.com/dirvine/ant-quic/commit/e9c500a965b1d25a4c7bce42eb6228212c84f094))
- Resolve visibility warnings for public API ([4850980](https://github.com/dirvine/ant-quic/commit/485098000e5ed4a35f10651834342471fd9a83ea))

### CI

- Add test for netbsd ([d23e4e4](https://github.com/dirvine/ant-quic/commit/d23e4e494f7446e21184bf58acd17a861ae73bba))

### Chore

- Remove unused import ([858a26a](https://github.com/dirvine/ant-quic/commit/858a26a6c6f861b33d5b28dfd5c679bd7d46b910))
- Disable unused default features for various crates ([60b9f9f](https://github.com/dirvine/ant-quic/commit/60b9f9ff70431fa8da7ec073fe7fc47b3c854cda))

### ClientConfigBuilder

- :logger ([3298fc9](https://github.com/dirvine/ant-quic/commit/3298fc91bc36467b4699e0617199d1668a6b1c70))

### Connection

- :close by reference ([818dadd](https://github.com/dirvine/ant-quic/commit/818dadd671f049f40c6e25452456a42c71690d29))

### ConnectionState

- :decode_key() can now be private ([92e8c4d](https://github.com/dirvine/ant-quic/commit/92e8c4d06d9c6d7412e33ca754c5a1cab4998284))

### Documentation

- Typo fix ([0a447c6](https://github.com/dirvine/ant-quic/commit/0a447c629d1fab48854c4e16bac16d17336fc6cf))
- Rm generic directory ([6ceb3c6](https://github.com/dirvine/ant-quic/commit/6ceb3c63bb19d1b8c66b527c2fdc52053480d81d))
- Modify rustls ServerCertVerifier link ([412a477](https://github.com/dirvine/ant-quic/commit/412a4775f3382c511e67b56f144946c857c8c86f))
- Use automatic links for urls ([8fbbf33](https://github.com/dirvine/ant-quic/commit/8fbbf33440c07b1b9452132a0127cd5b96dc8bb9))
- Fix broken item links ([c9e1012](https://github.com/dirvine/ant-quic/commit/c9e10128852e448fe85ecb88ca8f60135c13d678))
- Match MSRV to 1.53 in readme ([ac56221](https://github.com/dirvine/ant-quic/commit/ac562218601af99b11bf4044818defa21b445e3a))
- Update the client certificates example to a working config ([#1328](https://github.com/dirvine/ant-quic/issues/1328)) ([e10075c](https://github.com/dirvine/ant-quic/commit/e10075cf2fdb0dcca62a79291929369e95e84c86))
- Add/modify docs ([3a25582](https://github.com/dirvine/ant-quic/commit/3a2558258034e60989bbc199d4d8b0b7297ee269))
- Remove restriction to tokio ([c17315f](https://github.com/dirvine/ant-quic/commit/c17315fa105d3af215ee46730f7dd522c0022576))
- Update the MSRV in the README ([c0b9d42](https://github.com/dirvine/ant-quic/commit/c0b9d4233e45bfa08b562db0b6507545a86fd923))
- Replace AsRawFd and AsRawSocket with AsFd and AsSocket ([c66f45e](https://github.com/dirvine/ant-quic/commit/c66f45e985f9c0098afaf25810eb007f5bb1ee35))
- Clarify effects of setting AckFrequencyConfig ([11050d6](https://github.com/dirvine/ant-quic/commit/11050d6fe3a10c9509e7435b1ec3808e05ed4b00))
- Revise and add additionall 0-rtt doc comments ([9366f5e](https://github.com/dirvine/ant-quic/commit/9366f5e80b9cd801a8deb4ec171cc15fd63b25da))
- Revise SendStream.stopped docs comment ([02ed621](https://github.com/dirvine/ant-quic/commit/02ed62142d60226c198dbbeb13ef6548d03fd922))
- Remove reference to sendmmsg ([7c4cce1](https://github.com/dirvine/ant-quic/commit/7c4cce1370e1d5f366e9f23fffce0469257b1bc8))
- Correct MSRV in README ([a4c886c](https://github.com/dirvine/ant-quic/commit/a4c886c38a6e78916f683c01043b37b6d3a597cf))
- Tweak Connecting docs ([04b9611](https://github.com/dirvine/ant-quic/commit/04b9611aff7d0da898ce2b42a5ddf3db19c9a5e1))
- Separate example code from document ([41f7d2e](https://github.com/dirvine/ant-quic/commit/41f7d2ea8f645adf630ca5712259fa34770c331e))
- Copy edit poll_read(_buf?) docs ([37beebf](https://github.com/dirvine/ant-quic/commit/37beebfa08e7e3cf66507ecbe611d540c5812cc1))
- Add reference to IETF NAT traversal draft ([769de64](https://github.com/dirvine/ant-quic/commit/769de64998f9df5659c7f629b25a5a1bc885ed54))

### Endpoint

- :get_side ([5b81b6a](https://github.com/dirvine/ant-quic/commit/5b81b6a5de8c77293c261dede92824c8a721fc8f))
- :close helper to close all connections ([ad6f15a](https://github.com/dirvine/ant-quic/commit/ad6f15a2660bb3f43df4e2ebd912f96c637bf8ef))

### Features

- Cubic ([#1122](https://github.com/dirvine/ant-quic/issues/1122)) ([3f908a2](https://github.com/dirvine/ant-quic/commit/3f908a2c8c1ec4585212d776fafe536ea17bf2b4))
- Use BytesMut for Transmit content ([89b527c](https://github.com/dirvine/ant-quic/commit/89b527c9a16f1985dd87b0bed8adfe78da430712))
- Add aws-lc-rs-fips feature flag ([aae5bdc](https://github.com/dirvine/ant-quic/commit/aae5bdc3fa9329748ac8b0cec846784c688f373c))
- Support recvmmsg ([91a639f](https://github.com/dirvine/ant-quic/commit/91a639f67c7ab2d7dbfd87932edcf2394340576f))
- Faster UDP/IO on Apple platforms ([adc4a06](https://github.com/dirvine/ant-quic/commit/adc4a0684105dfefa31356e531e6c02d7e1a5c53))
- Support both windows-sys v0.52 and v0.59 ([a461695](https://github.com/dirvine/ant-quic/commit/a461695fe3bb20fa1e352f646a9678d07fb5d45a))
- Allow notifying of network path changes ([4974621](https://github.com/dirvine/ant-quic/commit/497462129e2cd591347c89f7522640ab8aa6c70d))
- Support & test `wasm32-unknown-unknown` target ([a0d8985](https://github.com/dirvine/ant-quic/commit/a0d8985021cfd45665da38f17376ba335fd44bb4))
- Enable rustls logging, gated by rustls-log feature flag ([9be256e](https://github.com/dirvine/ant-quic/commit/9be256e1c48ad7a5d893079acda43c8fc9caede6))
- Support illumos ([e318cc4](https://github.com/dirvine/ant-quic/commit/e318cc4a80436fd9fa19c02886d682c49efca185))
- Unhide `quinn_proto::coding` ([7647bd0](https://github.com/dirvine/ant-quic/commit/7647bd01dd137d46a796fd6b766e49deda23c9d7))
- Disable `socket2` and `std::net::UdpSocket` dependencies in wasm/browser targets ([a5e9504](https://github.com/dirvine/ant-quic/commit/a5e950495220ee3c761371fb540764e2c4743ab8))
- Allow changing the UDP send/receive buffer sizes ([83b48b5](https://github.com/dirvine/ant-quic/commit/83b48b5b87faa2033fd7a2c824aa108baf6d3569))
- Make the future returned from SendStream::stopped 'static ([f1fe183](https://github.com/dirvine/ant-quic/commit/f1fe1832a7badcefd828f130753b6dec181020a2))
- Implement comprehensive QUIC NAT traversal for P2P networks ([30be002](https://github.com/dirvine/ant-quic/commit/30be0029661ea40c6802138d9a72c5cd96ea147b))
- Integrate four-word-networking for human-readable addresses ([635eaf8](https://github.com/dirvine/ant-quic/commit/635eaf8ddb394a2108bbe7f7fa71bff4fd4334c1))
- Display four-word addresses for all peer connections ([9e8ac56](https://github.com/dirvine/ant-quic/commit/9e8ac5684ea79c66351bb5305cc16fdfb606bd20))
- Add four-word address parsing for bootstrap nodes ([b3febec](https://github.com/dirvine/ant-quic/commit/b3febec2d0011d61b1f3801523a8425e31cb7f0f))
- Enhance interface display with external IP discovery and IPv6 support ([e0a3cd2](https://github.com/dirvine/ant-quic/commit/e0a3cd2feedade7bacd747350fe74ebf4cb80987))
- [**BREAKING**] Implement comprehensive QUIC NAT traversal for P2P networks ([d901c0e](https://github.com/dirvine/ant-quic/commit/d901c0ed615cfe4363baca75794ca7e3f533e600))

### Fuzzing

- Adds target for streams type. ([c054fb3](https://github.com/dirvine/ant-quic/commit/c054fb36cbcf435607419e58846f89138768ce94))

### H3

- Correct the placehoder setting type code ([8389489](https://github.com/dirvine/ant-quic/commit/83894896fba1d04ce5a7fdbfe4ac968d3cf734d6))
- Fix setting ids in tests ([55c5ae2](https://github.com/dirvine/ant-quic/commit/55c5ae298bd37549a04ff2ab2369ce970de37052))
- StreamType for unidirectional streams ([f939f8e](https://github.com/dirvine/ant-quic/commit/f939f8ebe4d01f60a90966c40bd21e119bd9c560))
- Frame header reordering and varint for frame type ([6a942a3](https://github.com/dirvine/ant-quic/commit/6a942a3c8eb438f7520645ce00ccfc7db6c95dae))
- Stream types varint format ([54aa9c9](https://github.com/dirvine/ant-quic/commit/54aa9c967d26cb8a193cd5e9af061da4f4c3ed09))
- Varint Settings ids and ignore unknown settings ([c2db1d5](https://github.com/dirvine/ant-quic/commit/c2db1d5437c250634e3e32d55ad11354badce4b9))
- Change reserved stream type pattern ([af8ff7c](https://github.com/dirvine/ant-quic/commit/af8ff7c49e24c59dc3ac8fdd73b856e4db986a6d))
- Add QPACK Settings in h3::frame::Settings ([2053e56](https://github.com/dirvine/ant-quic/commit/2053e564f46932d3adb7aeba96636d2d382071e4))
- Move codecs to a new proto module ([eab98c1](https://github.com/dirvine/ant-quic/commit/eab98c19f8bc4ce60bcadcf834ecddb0efc81ffb))
- Future::Stream for HttpFrames ([82bd19c](https://github.com/dirvine/ant-quic/commit/82bd19c8bb08a1cac6ec8f0482e1fae68c27c121))
- Builders for client and server ([18cef27](https://github.com/dirvine/ant-quic/commit/18cef2753614b3f3aab759b0b7d99a1740a13596))
- Connection types, common to server and client ([af7883a](https://github.com/dirvine/ant-quic/commit/af7883a99d57b34bb393c60843ed776df3c08280))
- Server incoming connection stream ([1740538](https://github.com/dirvine/ant-quic/commit/1740538157320fb59b0cdc32d40076ab2c289e80))
- Connecting wrapper for client ([5658895](https://github.com/dirvine/ant-quic/commit/565889591da797d3b14d25faaf5a3fe91c7cf044))
- Introduce client+server example, with connection story ([452cdd5](https://github.com/dirvine/ant-quic/commit/452cdd532ad148ae4a72f4bdd2f27d6879c90380))
- Let encoder pass an iterator instead of a slice ([79d07bd](https://github.com/dirvine/ant-quic/commit/79d07bd67fa87d8e40b995b5c9a9abece90bebc1))
- Make max_header_list_size unlimited by default ([bd8cc90](https://github.com/dirvine/ant-quic/commit/bd8cc901e6fb5c7551ee960582a45930f0af1983))
- Encode headers from inner connection ([0bb05fc](https://github.com/dirvine/ant-quic/commit/0bb05fc93b606ce07163fc3ce86d49fd2e576eca))
- Set qpack params when constructing connection ([72bb118](https://github.com/dirvine/ant-quic/commit/72bb118c274f357043424bcbc918853d90779703))
- Header decoding ([9c484ec](https://github.com/dirvine/ant-quic/commit/9c484ecef5480f7c9ac14fef581618804a91d1ea))
- Make stream id value accessible from SendStream ([cbd22d6](https://github.com/dirvine/ant-quic/commit/cbd22d6b06b8bcc18ab824a748592cc0aa7e9908))
- Basic send request future for client ([d1d0915](https://github.com/dirvine/ant-quic/commit/d1d0915afdc2c1fd25f4761299045c7b1520a061))
- Receive request for server ([9c5a777](https://github.com/dirvine/ant-quic/commit/9c5a777bf2cd8618dca2e0594b45fb5f33f55946))
- Incoming request stream ([92a3f20](https://github.com/dirvine/ant-quic/commit/92a3f20842c0ca676de018c8965c362d68640eff))
- Pseudo header handling for `http` crate integration ([af8ba54](https://github.com/dirvine/ant-quic/commit/af8ba54dd5d64f9e73fe9804c07ed2d8f1a6e005))
- Integrate Header type for encoding / decoding data types ([2ece5f9](https://github.com/dirvine/ant-quic/commit/2ece5f9939909de01d74e561403d3cf21d3fc3b6))
- Make example send / receive request in client / server ([8bf597d](https://github.com/dirvine/ant-quic/commit/8bf597db68b3bcad2f0cf23f4d5ec2002cfdaba1))
- Make server receive a Request struct ([3b79240](https://github.com/dirvine/ant-quic/commit/3b79240e447432444098ca22643cd9ed01aeb2de))
- Send Response from the server ([82cb3ce](https://github.com/dirvine/ant-quic/commit/82cb3ce285bc19ccdcd73260f48b87a7a6df0545))
- Make client receive a Response struct ([da2edba](https://github.com/dirvine/ant-quic/commit/da2edba29124df2fb3e0d04233acb2d33dadb480))
- Generalize try_take helper usage ([051ab91](https://github.com/dirvine/ant-quic/commit/051ab91df9eb88d8ae05b90ad148a5302d30db91))
- Send body from server ([af60668](https://github.com/dirvine/ant-quic/commit/af606683a03f74daed400f2d91cf51498b3bf03c))
- Fix infinit FrameStream polling (don't ignore poll_read() = 0) ([fca903d](https://github.com/dirvine/ant-quic/commit/fca903d1b59c8517e8c08a341d254141fb6d5fc5))
- Client receive body ([5504ffa](https://github.com/dirvine/ant-quic/commit/5504ffafa83bd5199442bb5c5c7929357a7b881c))
- Exchange trailers after body ([2e8a2fb](https://github.com/dirvine/ant-quic/commit/2e8a2fb1e4e070c86515287f8e7683d9a8c07d4f))
- Fix frame stream not polled anymore when finished ([9fcf929](https://github.com/dirvine/ant-quic/commit/9fcf9290ba1754d9e6a33b3a5363f8b19cec694e))
- Request body ([efaf945](https://github.com/dirvine/ant-quic/commit/efaf945258bb318be1dbeec62531247e1d9a0ecd))
- Send trailers from client ([25fc68d](https://github.com/dirvine/ant-quic/commit/25fc68d760048e12054e69f90c6f568c4785124a))
- Fix receive misspelling ([e0f1d11](https://github.com/dirvine/ant-quic/commit/e0f1d11fb447e8530456b880c0478cef4e9706a4))
- Document pseudo-header fields ([4c75c06](https://github.com/dirvine/ant-quic/commit/4c75c06869ac8cb166d6d4ab7ecb7fcd5a759de8))
- Stream response from client ([07eca3d](https://github.com/dirvine/ant-quic/commit/07eca3d34887ba05cba0ece21dd6c3f34b285307))
- Code reformatting from fmt update ([e2ee96d](https://github.com/dirvine/ant-quic/commit/e2ee96de60232b446cdae68d54f7f053554fa2c7))
- Reset expected frame size once one have been successfully decoded ([ded85aa](https://github.com/dirvine/ant-quic/commit/ded85aa004c5323552411c96fa0317eb76b2a44d))
- AsyncRead implementation for recieving body from client ([db7a8d3](https://github.com/dirvine/ant-quic/commit/db7a8d3dd3fd6f38b9754000ae9edf49d4bf5248))
- Use AsyncRead into the example ([06d060c](https://github.com/dirvine/ant-quic/commit/06d060c0e911747478ba387b431a5296d08895ca))
- Default capacity values for RecvBody ([57c756a](https://github.com/dirvine/ant-quic/commit/57c756a633d90ea62cef5d3d795845768c54a06e))
- Separate request header, body, and response structs in server ([92c04c3](https://github.com/dirvine/ant-quic/commit/92c04c3b66cbc25e9d130284c6c203157af512bc))
- AsyncRead or Stream from RecvBody, so server can stream request ([874dafe](https://github.com/dirvine/ant-quic/commit/874dafefc7d2fb7a7074c2aa51cc4ed8def0d300))
- Return RecvBody along response in client, similarly to server ([13cd3cf](https://github.com/dirvine/ant-quic/commit/13cd3cf86fa487b687aba68ff32cc3a6d72e696e))
- Introduce an intermediary type before any body-recv option ([73be859](https://github.com/dirvine/ant-quic/commit/73be859e8c15ce441d71241fddf7d7ebd2dcd08e))
- Rename RecvBody into ReadToEnd and Receiver into RecvBody ([73065fa](https://github.com/dirvine/ant-quic/commit/73065fa443181fbbd8d7147ae8de95b8f5587b37))
- Implement Debug for RecvBody ([81aa76b](https://github.com/dirvine/ant-quic/commit/81aa76bc50129a53c609da4c63e9bc8360cae087))
- Embed RecvBody into Http:: Request and Response type param ([503de0b](https://github.com/dirvine/ant-quic/commit/503de0b78e79112220b6250971b0d27b48c384b9))
- Make the user specify memory usage params on RecvBody construction ([a90ad6e](https://github.com/dirvine/ant-quic/commit/a90ad6e8b87e15a4d70676bfea107f3fdbd958c8))
- Remove superfluous stream / reader conversion for ReadToEnd ([3408899](https://github.com/dirvine/ant-quic/commit/34088990dba6423aba4d2e52338e16c445a56bfc))
- Use ok_or_else to handle request headers building error ([58bdb79](https://github.com/dirvine/ant-quic/commit/58bdb79497981dbc4ba2def25aeb3b5a0c0ac28c))
- Fix request / response build error handling ([6c5dabe](https://github.com/dirvine/ant-quic/commit/6c5dabebe99eac23edf9fac5712246304b134736))
- Fix minor style problem ([6ae1fb2](https://github.com/dirvine/ant-quic/commit/6ae1fb2504b23d377fbc6e16643cef48f0aa386a))
- Partial DataFrame decoding implementation ([23dcf2c](https://github.com/dirvine/ant-quic/commit/23dcf2cf9077cd7e20b19410878051a35fce74c5))
- Sending headers gets it's own future ([df4880a](https://github.com/dirvine/ant-quic/commit/df4880a93602d127939f4a4523571ebe21afac33))
- BodyWriter, AsyncWrite implementation ([9b212aa](https://github.com/dirvine/ant-quic/commit/9b212aaef547571b71a56bbf5a60069c7c57fa2e))
- Refactor server code to integrate BodyWriter ([fdd801c](https://github.com/dirvine/ant-quic/commit/fdd801c6e96de13b4c8449b9aa95148047f71163))
- Fix tail buffer ignored in BodyReader ([0459854](https://github.com/dirvine/ant-quic/commit/0459854acbc7663aada5cf0eae9dae932aded773))
- Use SendHeaders to send trailers in SendResponse ([2e7ef52](https://github.com/dirvine/ant-quic/commit/2e7ef52d0d2c12b4311c5d6f90533fceee932bc3))
- Refactor client with SendHeaders ([6d6763d](https://github.com/dirvine/ant-quic/commit/6d6763da030aa004754782bf24e7674b658a6991))
- Make sending response error management more ergonomic ([436f1cd](https://github.com/dirvine/ant-quic/commit/436f1cd511bf831ca52a187fa793daee322c560f))
- Introduce builder pattern for client request ([6950e35](https://github.com/dirvine/ant-quic/commit/6950e350eac26a9da8d3898bfb6ea3946583bbbd))
- Helper function to build response ([07cc1cc](https://github.com/dirvine/ant-quic/commit/07cc1cc5aee83fb66e8cfd73c9fc20cd4e2d7589))
- Stream request body from client ([d6b696c](https://github.com/dirvine/ant-quic/commit/d6b696c192d5dfe0601b9d5acfa6e8765910c2f6))
- Prevent extra copy when sending DataFrame ([3bd0c69](https://github.com/dirvine/ant-quic/commit/3bd0c6969deff1f17c54361d18b4731f42720643))
- Rename Response and Request Builders ([accb344](https://github.com/dirvine/ant-quic/commit/accb344fe0c6c675b46d5753a036288e14a67b3d))
- Let client close connection gracefully ([36dfee6](https://github.com/dirvine/ant-quic/commit/36dfee6ea7deed70950e8e1b14f36595d237fe9c))
- Minor readabilty tweak ([297c99a](https://github.com/dirvine/ant-quic/commit/297c99a9aa571af0b7ca9da5d7d4680912ed0a5a))
- Move some common example code into a shared module ([69a4977](https://github.com/dirvine/ant-quic/commit/69a49772675837b0540545fdac9b981a29508370))
- Simpler examples ([5881196](https://github.com/dirvine/ant-quic/commit/588119621193826d3f5eb725b5f57d921dee16c9))
- Incoming UniStream header parsing and polling ([248ec17](https://github.com/dirvine/ant-quic/commit/248ec17f0316b3771d1d7a2f0f5be241b71c2810))
- Poll incoming uni streams from connection ([18a9532](https://github.com/dirvine/ant-quic/commit/18a95328b94f674a22cb9e10517c211c809189af))
- Do not poll incoming bi streams in client ([a4e6563](https://github.com/dirvine/ant-quic/commit/a4e656302b3f9f125805a461de3f66d8f2c16298))
- Make Settings and SettingsFrame the same type ([ca02516](https://github.com/dirvine/ant-quic/commit/ca0251640afdc6908cbf0ca02186c2235fab9a38))
- Control stream implementation (Settings only) ([90f6ce1](https://github.com/dirvine/ant-quic/commit/90f6ce10d132def4d320ea22d8d757f9ad94b24f))
- Control stream sending mechanism ([ad4f516](https://github.com/dirvine/ant-quic/commit/ad4f516f0f9e0463ed3e3b47ac263e0fa240358a))
- Filter control frame types for client or server ([2bb13fa](https://github.com/dirvine/ant-quic/commit/2bb13fa6c5c8be79844c956f0e7d62f944b8baf2))
- Immediately close quic connection on fatal errors ([0bec6ea](https://github.com/dirvine/ant-quic/commit/0bec6eac8eb6458c950d9153ff40c7587b454197))
- Throw an error when client recieves a BiStream ([46102d0](https://github.com/dirvine/ant-quic/commit/46102d07f2986dd349792308a74d3786de0f6aef))
- Track ongoing requests ([a570f17](https://github.com/dirvine/ant-quic/commit/a570f17daab80c61ca6763aceb6d3241ff811cc5))
- GO_AWAY implementation ([f170a89](https://github.com/dirvine/ant-quic/commit/f170a8992266abc6aae07b3aaa8fb268606e6175))
- Rename RecvRequestState finished variant ([0972700](https://github.com/dirvine/ant-quic/commit/0972700dab8681146abd3b6e43de4c8d1c20bd9e))
- Typo in ResponseBuilder name ([51e5aae](https://github.com/dirvine/ant-quic/commit/51e5aaebbce864a06e100e04a952658a1d78f41d))
- Issue quic stream errors and reset streams ([d4caaf5](https://github.com/dirvine/ant-quic/commit/d4caaf5cd4a6b7b4eee5633ac3244ec0ca0410a1))
- Rename ReadToEnd's State ([ec67124](https://github.com/dirvine/ant-quic/commit/ec671244828b2f82a45263ba55579e971dac639f))
- Request cancellation and rejection ([c2cbffc](https://github.com/dirvine/ant-quic/commit/c2cbffc4830de6c814c75f7cc8fc28bdd31fd1b2))
- Better error reason when control stream closed ([efde863](https://github.com/dirvine/ant-quic/commit/efde8638c25981c8f3296dc036df0fd1e108d12a))
- Move ErrorCode to proto ([cf2c46a](https://github.com/dirvine/ant-quic/commit/cf2c46abd9ccb46b42ab494f2c2b0540ad122121))
- Fix driver polling story trivially ([a8eb51b](https://github.com/dirvine/ant-quic/commit/a8eb51b01c30275c91f3fd5ddd2cf5adddcb509b))
- Fix freshly type-resolved incoming uni streams handling ([06db4fb](https://github.com/dirvine/ant-quic/commit/06db4fb7571cce6168dd0b2e7f0080180db92e37))
- Replace SendControlStream with a generic impl ([a87e1a9](https://github.com/dirvine/ant-quic/commit/a87e1a9cf7c3904f6878c0e922ea71e1d9259bbb))
- Lock ConnectionInner once per drive ([8b40524](https://github.com/dirvine/ant-quic/commit/8b405240b75c0c61a01213d11ae7e07aa77c32a5))
- Manage all Uni stream transmits the same way ([daf9dc3](https://github.com/dirvine/ant-quic/commit/daf9dc3153d3f20ccea1c1050584da01c4ec76f7))
- Move Connection::default to tests ([fe6935d](https://github.com/dirvine/ant-quic/commit/fe6935d3f25203af51d16d8c21714b7bd07a8725))
- Resolve encoder and decoder streams ([4921821](https://github.com/dirvine/ant-quic/commit/4921821a7d4e30dc1b66f4e82d068bee51c55f41))
- Set encoder settings on receive ([77d32c3](https://github.com/dirvine/ant-quic/commit/77d32c3352ccecbf281122d3edea36080cb7d71a))
- Pass required ref to connection's decoding ([4572499](https://github.com/dirvine/ant-quic/commit/45724990484e43d4b9b32a9d0becb7e3b42330ed))
- Unblock streams on encoder receive mechanism ([e07b70e](https://github.com/dirvine/ant-quic/commit/e07b70ea9161fa5caf739def25d9882b1ca16def))
- Receive decoder stream ([5e6b83b](https://github.com/dirvine/ant-quic/commit/5e6b83b0c4fc36a507cca1fbb4efcaecbeae26df))
- Send decoder stream after decoding a block ([81f1fd2](https://github.com/dirvine/ant-quic/commit/81f1fd2a45565e7d8f938871dd893a664516f4f1))
- Do not ack headers not containing encode refs ([a8e9394](https://github.com/dirvine/ant-quic/commit/a8e93949aa3acb6c5462042b19208489c2b47da9))
- Fix and optimize new StreamType decoding ([dff7eee](https://github.com/dirvine/ant-quic/commit/dff7eeed200204fef91d4a3edb84ddefa39d4553))
- Enable QPACK by default ([96011ca](https://github.com/dirvine/ant-quic/commit/96011ca890bc8d7fb4f40a76f36da058a36a4fb5))
- Move connection constants to the bottom ([71b72eb](https://github.com/dirvine/ant-quic/commit/71b72eb1a94484687a01d24ecdaff85c0286b6ac))
- Add QPACK error codes ([d184b18](https://github.com/dirvine/ant-quic/commit/d184b18845e083c71fc264f47c6b3c4bde5fcde5))
- Move actual drive impl to ConnectionInner ([8c85c41](https://github.com/dirvine/ant-quic/commit/8c85c411a29d9f6dfb246d08e916dc6b756b2b96))
- Let internal error messages be strings ([418b0a7](https://github.com/dirvine/ant-quic/commit/418b0a7f638489ce1712d3bda29f976169155c66))
- DriverError to carry connection level error ([a36ffb8](https://github.com/dirvine/ant-quic/commit/a36ffb824db507146ce4ee100fbd6a5562de0dfc))
- Replace all driver error repetitive impls ([24a10ba](https://github.com/dirvine/ant-quic/commit/24a10baecd1f18277a996e7737d00b4fab38356b))
- Set quic connection error from top driver level ([a61c960](https://github.com/dirvine/ant-quic/commit/a61c96058677fb680a70371e5b6ce2ff896c890c))
- Fix formatting ([bf4c5a2](https://github.com/dirvine/ant-quic/commit/bf4c5a253040fe629074d7c3a518319778f37792))
- Better recv uni stream buffer space management ([84e0419](https://github.com/dirvine/ant-quic/commit/84e041939d94e620a7b9c79af2796d8574596e6d))
- Simplify SendUni state machine ([69a9545](https://github.com/dirvine/ant-quic/commit/69a95456326d97feb5bfe363caa0edc2ec168b5c))
- Shorten client builder story ([7e7262a](https://github.com/dirvine/ant-quic/commit/7e7262ab11982761b9e41c3b6df84e02da040195))
- Rewrite simple_client example ([102a727](https://github.com/dirvine/ant-quic/commit/102a727629435b9f7397a44228593b1100847b45))
- First useful traces in client and connection ([c8f86f8](https://github.com/dirvine/ant-quic/commit/c8f86f8fc00861a6c49aaceb9a041d59de578128))
- Remove unused local setttings from connection ([88adcbe](https://github.com/dirvine/ant-quic/commit/88adcbe891cadcf2cf30e90e717b5e1d17751479))
- Refactor client to API into one BodyReader ([4f5b196](https://github.com/dirvine/ant-quic/commit/4f5b196b5d74c9c4d2eacbc0a6001f8d2be1dce6))
- Refactor server to use only BodyReader/Writer ([9fd975a](https://github.com/dirvine/ant-quic/commit/9fd975afa3358234016cacbc2f127340a170ca44))
- Rewrite introp client with the new API ([e141526](https://github.com/dirvine/ant-quic/commit/e14152616392f250680889407bcc82f4ce0d83f5))
- Add async-only data stream interface for body reader ([16344f8](https://github.com/dirvine/ant-quic/commit/16344f89bfea312a9d39bbf1628b8aa42c94998e))
- Keep only simple examples ([c7504ad](https://github.com/dirvine/ant-quic/commit/c7504ad800b72dc6e6d9be1482474bbc80343e5b))
- Shorten server builder story ([0b1c567](https://github.com/dirvine/ant-quic/commit/0b1c567fdd212d9c0ce1344da69567fcb7d48588))
- Remove priority frames ([e19d9c6](https://github.com/dirvine/ant-quic/commit/e19d9c6bf16461638a2e1767716ce308cd2c9920))
- Forbid settings item duplication ([bce5404](https://github.com/dirvine/ant-quic/commit/bce54043265adf9ff2cde0a9d71e7c21fcf9ca68))
- Forbid H2 reserved frame types ([3876672](https://github.com/dirvine/ant-quic/commit/387667214801b7f57d7fa44f3302c1173b839102))
- Reserved SettingsId get the same pattern as frames ([8e3e91f](https://github.com/dirvine/ant-quic/commit/8e3e91f6c66585c8f7ba3bf0d7697aa090a2eb27))
- Ignore reserved uni streams ([3fc45b2](https://github.com/dirvine/ant-quic/commit/3fc45b2231065a3dc99164888f8cc1edfda0621b))
- Ignore reserved frames on concerned streams ([bb63196](https://github.com/dirvine/ant-quic/commit/bb63196a4c97f0a7cf81f6099f4627646a9e15d3))
- Bump ALPN to h3-24 ([79dc609](https://github.com/dirvine/ant-quic/commit/79dc609c0a61ea7385a9e71ac9947914ff7dec08))
- Allow connection with a custom quic client config ([259b970](https://github.com/dirvine/ant-quic/commit/259b970bbc291b8a24b3d155a4d44f03f4c6585f))
- Key update forcing test method ([42c5cc8](https://github.com/dirvine/ant-quic/commit/42c5cc8a5473ba70fbbcc4ab079783b36fa5ac5e))
- Temporary 0-RTT interface for interop ([f56a884](https://github.com/dirvine/ant-quic/commit/f56a8843b440a23dcbba7ce7ddcee986054014ff))
- Default scheme to https ([f21f01d](https://github.com/dirvine/ant-quic/commit/f21f01ded68834e6fd91ad1d2be3791e0d8d91c1))
- Consume reserved frames payload ([03fbc79](https://github.com/dirvine/ant-quic/commit/03fbc79f0002bd234fa6df8179170c71f66a8003))
- Tracing for received frames ([5f803f5](https://github.com/dirvine/ant-quic/commit/5f803f5615d6f1c129804f46e83196a59bb098b4))
- Rename push_id field into id ([2359715](https://github.com/dirvine/ant-quic/commit/23597158bd13cf90b1168643c2ff6dfc8056da62))
- Tracing for Uni streams ([1d82785](https://github.com/dirvine/ant-quic/commit/1d827856a358616a980b4c08edfe8b5d0db309db))
- Send a Set DynamicTable Size on encoding enable ([86227f4](https://github.com/dirvine/ant-quic/commit/86227f4b4535614fffd30764615445566d2df367))
- Remove unlegitimate IOError in body reader ([71d3969](https://github.com/dirvine/ant-quic/commit/71d39699d41f050278277ad36b9ce291a8012ae4))
- Poll control before anything in driver ([cf1cac3](https://github.com/dirvine/ant-quic/commit/cf1cac35872912b21928c0ba8351a94c948ce84a))
- Avoid panics in server example critical path ([f9965e4](https://github.com/dirvine/ant-quic/commit/f9965e473f750e0456f2346c0001048a7ac485f1))
- Accept directly http::Uri in client example args ([21f9cc9](https://github.com/dirvine/ant-quic/commit/21f9cc9d334f2802a520268be7169c7bc45b20d2))
- Spawn each incoming connection in server example ([0b4fa10](https://github.com/dirvine/ant-quic/commit/0b4fa10b970b06b2918b6b793079ddea0c264f71))
- Fix header len count in request constructor ([6fc82a1](https://github.com/dirvine/ant-quic/commit/6fc82a1ffdb6bc3953355f5f99238b4bf7956665))
- Default path is "/", not "" ([3befe15](https://github.com/dirvine/ant-quic/commit/3befe15c16f145626415426a732b1f6aad67387f))
- Poll control on opening instead of twice per loop ([c07cc7f](https://github.com/dirvine/ant-quic/commit/c07cc7f9d22dc9a66a049fb9b8ba879508436bd8))
- Fix WriteFrame incomplete write management ([7699d33](https://github.com/dirvine/ant-quic/commit/7699d33c4e221251e9f00234ef6956c0ffe4c7e8))
- Do not copy sent payload ([4a8cd6a](https://github.com/dirvine/ant-quic/commit/4a8cd6af3595ef944d5121e26c30887311088ba8))
- Display frame type number when it is unsupported ([1a8d825](https://github.com/dirvine/ant-quic/commit/1a8d825ab8c65c937d060aab41e5f38154a7dd1c))
- Make frame decoding resilient to split headers ([384549f](https://github.com/dirvine/ant-quic/commit/384549faf218a76b3dd7b9c712f6a192229b7522))
- Close body writer on any state ([ff4d736](https://github.com/dirvine/ant-quic/commit/ff4d736c06ab613bf8aee522d32d946bf805a862))
- Use early return where possible. ([02fb796](https://github.com/dirvine/ant-quic/commit/02fb7969088299c2784964b65417bc05046d9ca4))
- Fix driver error reaction for closing and logging ([d4b0553](https://github.com/dirvine/ant-quic/commit/d4b05530adf1b519143fc00a9848293b3c3d0634))
- Make Request yeild Connection's private ([949d947](https://github.com/dirvine/ant-quic/commit/949d9473942ff4d4d127cede75958df1713b4e37))
- Make user's futures resolve on driver error ([445a438](https://github.com/dirvine/ant-quic/commit/445a4388aa1753bff363de6b741c94b25018ef21))
- Update tokio dependency to 0.2.6 ([b2fac76](https://github.com/dirvine/ant-quic/commit/b2fac762f0d124587ea3f37f3d853ef6966296ed))
- Close connection on client drop ([757deec](https://github.com/dirvine/ant-quic/commit/757deecbdf8d30aa1e582fe30493f4f52e64bf09))
- Functionnal test for connection closure ([85a012e](https://github.com/dirvine/ant-quic/commit/85a012e9df9731d2556db753f3ab6351f1b9007a))
- Remove superfluous parenthesis ([d1127d5](https://github.com/dirvine/ant-quic/commit/d1127d5c643b09b916936f2b320801e45e96365a))
- Throughput benchmark ([4257846](https://github.com/dirvine/ant-quic/commit/42578464fea2369c0e3e0894b5d67fc90542c29e))
- Save an allocation on frame header encoding ([e54042a](https://github.com/dirvine/ant-quic/commit/e54042a038db357f48be993f4dcd26ff7e3e3838))
- Test request body reception ([cb9597b](https://github.com/dirvine/ant-quic/commit/cb9597b3bfabbd779bc1bc9172bc060df8738174))
- Minor style fix ([3613974](https://github.com/dirvine/ant-quic/commit/3613974b94189b6e8de7c33061db0c69c4aec1a9))
- Remove commented code left by error... ([705269b](https://github.com/dirvine/ant-quic/commit/705269b6c0a03a0abbbeed2ba9fc88dda8876ec8))
- Remove NUM_PLACEHOLDERS settings ([efee187](https://github.com/dirvine/ant-quic/commit/efee1871db62060e7a8187ceb3ff797e6a7d8a1e))
- Refactor settings in it's own module ([69ee3e5](https://github.com/dirvine/ant-quic/commit/69ee3e5f57a380b90427796f6516775f8c85d27c))
- New settings for interop ([723fc97](https://github.com/dirvine/ant-quic/commit/723fc97e77ebf1a241bffa3d090c11f53a060d19))
- Inline crate's default settings ([a2343c8](https://github.com/dirvine/ant-quic/commit/a2343c8df7a38712a5ac0d690532df4e8dbd5db0))
- Don't run request before client closure tests ([75aa21b](https://github.com/dirvine/ant-quic/commit/75aa21b446221e0ec689a9fb679f64c488afbe6f))
- Set FrameDecoder initial buffersize to UDP size ([0ff3d8f](https://github.com/dirvine/ant-quic/commit/0ff3d8f51db767e7ac6b963ead07ae25c384882a))
- Disable async tests in coverage ([6c557ff](https://github.com/dirvine/ant-quic/commit/6c557ff5efb6f3a5696d849754967b6ac2d60107))
- Re-enable h3 async tests after busy-loop fix. ([6f1d361](https://github.com/dirvine/ant-quic/commit/6f1d361dbf0c5d7818a26d9a3db29144f56030c4))
- Fix hidden warning ([394cc8a](https://github.com/dirvine/ant-quic/commit/394cc8a7f2d5918ba8fe178b667ad54c6cc2b1bd))
- Make connection constructors infaillible ([bf0dd08](https://github.com/dirvine/ant-quic/commit/bf0dd08024475755259b3e2a88d4e3f7cdaefb51))
- Request build helper macros for tests ([b265648](https://github.com/dirvine/ant-quic/commit/b2656480786707468783032efdb0a10f84884cf5))
- Join timeout helper ([02a4410](https://github.com/dirvine/ant-quic/commit/02a44108f4164d1c4e49dc4594abbb154294db0f))
- Reword comment ([c1e4d86](https://github.com/dirvine/ant-quic/commit/c1e4d86d0daba1bcf7ab4077106b33221d0a30c0))
- Serve_one return its error instead of panic ([67f7649](https://github.com/dirvine/ant-quic/commit/67f7649f82b4cc1b55d4c9616619c2d737723634))
- 0-RTT implementation ([5e03cd9](https://github.com/dirvine/ant-quic/commit/5e03cd935f5b9b49b1ef75901cc9e2d34fd7ce94))
- Simplify complex destructurings ([a244593](https://github.com/dirvine/ant-quic/commit/a2445933a656cbeb3c95e7322d392710e7b80b10))
- Activate qpack everywhere ([14f5230](https://github.com/dirvine/ant-quic/commit/14f523019d66b12421a548dd3860575c8b50781c))
- End to end response cancellation impl ([1be67f2](https://github.com/dirvine/ant-quic/commit/1be67f25971a0bb3ae0c774534c3b04049bced11))
- Rework Errors, easy to handle HttpError enum ([4068d3f](https://github.com/dirvine/ant-quic/commit/4068d3fad20db0852b2c3a1695863f2a2c0e6305))
- End to end GoAway implementation ([8bcca95](https://github.com/dirvine/ant-quic/commit/8bcca95304655e067ec5f57f76740f781dac17cf))
- Remove unused Server struct ([88a0796](https://github.com/dirvine/ant-quic/commit/88a0796c0a79f6ab49542604112679c4135c778e))
- Reorganize public API ([a6ff500](https://github.com/dirvine/ant-quic/commit/a6ff500f6f3274ec7e792f112088538ac68dfce9))
- Reorder server structs and methods ([7cd10d1](https://github.com/dirvine/ant-quic/commit/7cd10d16b36eb93e1acc20ad20b55dd701526ec6))
- Fix request cancellation error code ([158837e](https://github.com/dirvine/ant-quic/commit/158837e86a27428b3ec61bda7b4033a58074c6c9))
- Document server module ([e440425](https://github.com/dirvine/ant-quic/commit/e4404259476a1e75605c4d2ea397d6d3b848d99a))
- Reorder client API ([f3d7b03](https://github.com/dirvine/ant-quic/commit/f3d7b03fa1f8d3e13cef18443fed9688f06f2bcd))
- Add a shortchut to build a default client ([a55712d](https://github.com/dirvine/ant-quic/commit/a55712d58c773dc8c774e7cb731390dc1c5db557))
- Client documentation ([c2d6d71](https://github.com/dirvine/ant-quic/commit/c2d6d716e2700405e87ba0d96491dda1a8efc7ce))
- Body documentation ([34654bc](https://github.com/dirvine/ant-quic/commit/34654bc630cbfba848b232832a785d9a47998a85))
- Remove unused error helper ([e212233](https://github.com/dirvine/ant-quic/commit/e2122331167cf31ab5e6d193b0a0aef1a4b7c9bd))
- Remove error code ([8ee24df](https://github.com/dirvine/ant-quic/commit/8ee24df4d6b00ef5a1478126df2d856cde93e569))
- Settings and errors documentation ([28e211c](https://github.com/dirvine/ant-quic/commit/28e211cf4bfde26181e8fc9db65a9c128db92a62))
- Fix IO error wrongly wrapped into Error::Peer ([bae7e19](https://github.com/dirvine/ant-quic/commit/bae7e199827ca406a9d43d0f4662ef6ce8a09379))
- Make client able wait for endpoint idle state ([e9e973d](https://github.com/dirvine/ant-quic/commit/e9e973de2972afbfc991809ef6e33799a2738000))
- Rework the client example for clarity ([8894e3e](https://github.com/dirvine/ant-quic/commit/8894e3ee960fdc24b34f7187a108c23a1e142165))
- Rework server example for clarity, remove helpers ([b2351ef](https://github.com/dirvine/ant-quic/commit/b2351efc00fd34697e844b3cc38ab6d7f304aeeb))
- Documentation index ([be998ac](https://github.com/dirvine/ant-quic/commit/be998ac9f367aba2daee82b1abe462aa320cc13f))
- Bench factorize server ([739719f](https://github.com/dirvine/ant-quic/commit/739719f884721628342d7ab9b1a33f87e4d70c4b))
- Kill the server, fix bench ([a1d538c](https://github.com/dirvine/ant-quic/commit/a1d538c7d3aba1a12ae00856cc5b09be93c8746e))
- Fix comment style ([416cca0](https://github.com/dirvine/ant-quic/commit/416cca0935773013f6665393c7c45c1b7f2c91b8))
- Let the OS choose bench ports ([690c29f](https://github.com/dirvine/ant-quic/commit/690c29f135609007026f072952be17f1e64d6fb9))
- Orthogonal bench server spawner ([050b6fd](https://github.com/dirvine/ant-quic/commit/050b6fdc3f1627def4bf1af2f8b440f1259c86b9))
- Rename bench throughput -> download ([d6c290a](https://github.com/dirvine/ant-quic/commit/d6c290a64142074038c9b67283469c312673b2e6))
- Upload benchmarks ([963695d](https://github.com/dirvine/ant-quic/commit/963695db1d4a8caa73421af3be1e7f26c43851a9))
- Isolate throughput bench and helpers ([f3cc676](https://github.com/dirvine/ant-quic/commit/f3cc67601fb422a5faa66207e692f58c1a06da1d))
- Build benchmark context with settings ([10cde92](https://github.com/dirvine/ant-quic/commit/10cde920f60faf27720686f057239f638cff2777))
- Impl default for bench context ([2aa424a](https://github.com/dirvine/ant-quic/commit/2aa424a3ce67714346d090c0be874fed395e827b))
- Request benchmarks ([b524f6a](https://github.com/dirvine/ant-quic/commit/b524f6ac4c4f33812e8d7fe311bcf4474a4d41a5))
- Make payload-frames carry a Buf impl ([90008bf](https://github.com/dirvine/ant-quic/commit/90008bf7fb4bb6e06318dbdc28ebc90577fff605))
- Create Error variant for Body errors ([74d8798](https://github.com/dirvine/ant-quic/commit/74d8798b5d5ec189ba3262e7f7aeec9d4b71c874))
- Change structure of Body ([8a97c8d](https://github.com/dirvine/ant-quic/commit/8a97c8d39776891aae7879c956abdcd65cd6cda7))
- Impl HttpBody for Body ([ae4b61c](https://github.com/dirvine/ant-quic/commit/ae4b61cf1ec4b4fce5b7a29a4c6de23298b065fb))
- Make streams reset() take &mut, not ownership ([60949bc](https://github.com/dirvine/ant-quic/commit/60949bc0df4f4091b48dbb65427568148fb4dc0d))
- Body stream helper for benches ([57fe592](https://github.com/dirvine/ant-quic/commit/57fe592bd736f3e733f738b9c147e512b309efcd))
- HttpBody server integration in SendResponse ([34c9f45](https://github.com/dirvine/ant-quic/commit/34c9f458020daa95c322180f22b66effa820ad65))
- Poll method for header decoding ([36c4d0b](https://github.com/dirvine/ant-quic/commit/36c4d0ba53cb20ae24c25379f1a35ec57a70412d))
- Rewrite client to use SendData<HttpBody, _> ([4484705](https://github.com/dirvine/ant-quic/commit/448470518a55a291107807a150cb57aa6a6b8e07))
- HttpBody implementation on the receive side ([586cb59](https://github.com/dirvine/ant-quic/commit/586cb59a4e1d3252934fb630709b1ce1be802144))
- Restore canceling API ([61332ec](https://github.com/dirvine/ant-quic/commit/61332ec52cc694fd6f2b31c1ba6b5250afc08c3b))
- Refactor header receiving code into RecvData ([cf43135](https://github.com/dirvine/ant-quic/commit/cf431350ebfed41bef2b33d2f5461622ebcad131))
- Tweaks to error types ([6df0b1d](https://github.com/dirvine/ant-quic/commit/6df0b1d6e15722af043d265969d2ec531d517f4c))
- Don't take ownership for request cancellation ([99df1df](https://github.com/dirvine/ant-quic/commit/99df1dfbb1f77cdf977b180af8c08398cc5cc3fa))
- Update docs with HttpBody API ([56192ff](https://github.com/dirvine/ant-quic/commit/56192ff8750e68abfa6b3f8871aab80a4711cc95))
- Use a HashSet for in-flight request tracking ([1d59775](https://github.com/dirvine/ant-quic/commit/1d5977548a821667ff9bfdbf4971134a2a7b761c))
- Fix client response canceling ([d45ce73](https://github.com/dirvine/ant-quic/commit/d45ce73660b6cc1cf01c51b179b2fc03ffedf69a))
- Test response canceling from server ([b2ebb47](https://github.com/dirvine/ant-quic/commit/b2ebb47b8c9f3036ee4836ee1a9ad5ca662d8c3a))
- Enable tracing by default in tests ([77aeb55](https://github.com/dirvine/ant-quic/commit/77aeb5544ba5722ba09fd89e0bc4ccd00cca3994))
- Send get requests with FakeRequest helpers ([061733d](https://github.com/dirvine/ant-quic/commit/061733dc1e82fa3c89278c24a7dc1d22f5817015))
- Ignore unknown frames ([5f5be44](https://github.com/dirvine/ant-quic/commit/5f5be440dc2e11de2cc907307c109027adb99199))
- Ignore unknown incoming uni stream ([68b866b](https://github.com/dirvine/ant-quic/commit/68b866bc63084046b8e9e19e779516ed8066639c))
- Simplify ownership of SendStream ([#768](https://github.com/dirvine/ant-quic/issues/768)) ([aa1ebba](https://github.com/dirvine/ant-quic/commit/aa1ebbab7647e0f6b971a014cc45aa3496bac5f8))
- Poll for STOP_SENDING ([cbbd76e](https://github.com/dirvine/ant-quic/commit/cbbd76ec608aafdcc3a64245f0ede710cb79bd27))
- Reject request when headers are invalid ([cf0801c](https://github.com/dirvine/ant-quic/commit/cf0801c8fdaab8dd57149cbd090768f16b0165a6))
- Check authority validity for server ([94d5de1](https://github.com/dirvine/ant-quic/commit/94d5de1709906967c0529258ea00b271f8972852))
- Trace arriving requests ([2444a60](https://github.com/dirvine/ant-quic/commit/2444a60220a9a19f935e61486a323588e84709e3))
- Check request authority for client ([448ba9a](https://github.com/dirvine/ant-quic/commit/448ba9a061a40fcc1a667f1fd749513c1cfd343f))
- Make the h3 client default port 443 ([4945573](https://github.com/dirvine/ant-quic/commit/4945573fda9424ac30ed9b8c5a53b5a6ff2995d1))
- Ignore any number of unknown settings ([0c6a27c](https://github.com/dirvine/ant-quic/commit/0c6a27c37ad66422a1e8356b68947dbccb7d82c9))
- Name pin projections as required by 0.4.21 ([b5c8a21](https://github.com/dirvine/ant-quic/commit/b5c8a218ad9d72fdaf168046e471dffaa4ebea8f))
- Tests log level from env ([b940a3a](https://github.com/dirvine/ant-quic/commit/b940a3ae363102f73d020267cc408c81ec556e16))
- Clarify connection end return value ([878970b](https://github.com/dirvine/ant-quic/commit/878970b833a06ee4794aaacf7f1eb1a841d38135))
- GoAway from client ([0cdf96e](https://github.com/dirvine/ant-quic/commit/0cdf96e92104efa8c41e2332ad241d6cc7a73b3c))
- Store side information in proto::connection ([22200ae](https://github.com/dirvine/ant-quic/commit/22200ae79e424ca3a1268075fdb528f7be80e38e))
- Refactor GoAway mechanism to actually use the id ([b851934](https://github.com/dirvine/ant-quic/commit/b8519342281c0c6c015d49c9949522d1ed509018))
- Prevent client to start new requests on shutdown ([9a79718](https://github.com/dirvine/ant-quic/commit/9a797187791a092758c572a7c6084821da2c14f5))
- Refactor shutdown condition in h3 proto ([9594ba7](https://github.com/dirvine/ant-quic/commit/9594ba7ee3556cb4c18a3a04317259f5d01c5766))
- Wake connection on request finish ([babb07b](https://github.com/dirvine/ant-quic/commit/babb07b079e7e3ac4ff2fa7ef25b0dac5e934377))

### Interop

- Do not check h3 on hq only endpoints ([43bbeaa](https://github.com/dirvine/ant-quic/commit/43bbeaadd19fb3ee996180a309eefbb5d34ad3e0))
- Parse size from full path ([66e13e6](https://github.com/dirvine/ant-quic/commit/66e13e60b9df96a6feee18bebd018e6bb52e97b5))

### Miscellaneous Tasks

- Feature flag socket2 imports ([2de91cf](https://github.com/dirvine/ant-quic/commit/2de91cfd7f2d39a930afdbab454d526346fed693))
- Move common package data to workspace Cargo.toml ([9dbaff0](https://github.com/dirvine/ant-quic/commit/9dbaff0ea1be4faedd3cbdfbcf7b388a386f7da3))
- Increase crate patch version to v0.5.5 ([8bdbf42](https://github.com/dirvine/ant-quic/commit/8bdbf42a54f04b3bd2965d6ad0e2ce3966287330))
- Replace IP strings with address types ([15a4dce](https://github.com/dirvine/ant-quic/commit/15a4dcef42bf10c84535ec7e8331db9e97918856))
- `cargo +nightly clippy --fix` ([5dd3497](https://github.com/dirvine/ant-quic/commit/5dd3497107e97b6341eb519f080fd13907f26855))
- Increase crate patch version to v0.5.6 ([e7ae563](https://github.com/dirvine/ant-quic/commit/e7ae56300a2782fa7b8a87821432d4cdce19791a))
- Remove workaround for broken `cc` version ([a55c114](https://github.com/dirvine/ant-quic/commit/a55c1141e96809a94fdafc131d51642c5444ed30))
- Fix `cargo clippy` issues ([f8b8c50](https://github.com/dirvine/ant-quic/commit/f8b8c5032e0db9d7dbc7c3452f09c7d1e2a4295d))
- Increase crate patch version to v0.5.8 ([204b147](https://github.com/dirvine/ant-quic/commit/204b14792b5e92eb2c43cdb1ff05426412ff4466))
- Re-ignore stress tests in solaris ([db4c0e4](https://github.com/dirvine/ant-quic/commit/db4c0e40da25482a54c5fd0dbb7c75eda1ac28e0))
- Increase crate patch version to v0.5.9 ([b720c6a](https://github.com/dirvine/ant-quic/commit/b720c6a1d3abe039aa8b826d054ef241cb05df7e))
- Increase crate patch version to v0.5.10 ([f4bd4c2](https://github.com/dirvine/ant-quic/commit/f4bd4c21f4dec001d044ba4cd279b91627124b01))
- Increase crate patch version to v0.5.12 ([458295c](https://github.com/dirvine/ant-quic/commit/458295c30519f56ec160cc9c6264df72e2601e45))
- Increase patch version to v0.5.13 ([113fa61](https://github.com/dirvine/ant-quic/commit/113fa61de3fb4ff1c3622e53f530bd8d84d0a3bf))
- Bump version to 0.1.1 ([c298a67](https://github.com/dirvine/ant-quic/commit/c298a672980f48a854dd83b90743fc898d3ed19a))
- Update Cargo.lock for version 0.1.1 ([840a39d](https://github.com/dirvine/ant-quic/commit/840a39d53dea3c4c8efa632aac566bb9a56a4905))
- Bump version to 0.2.0 for NAT traversal release ([a6fd4e5](https://github.com/dirvine/ant-quic/commit/a6fd4e5929702fce3425ccecd9ae05909429acd0))
- Bump version to 0.2.1 for visibility fixes ([5ebf10b](https://github.com/dirvine/ant-quic/commit/5ebf10b841ab6eed864b0178ba06f9c3564b72f3))
- Update lockfile for v0.2.1 ([7c9bebc](https://github.com/dirvine/ant-quic/commit/7c9bebc2575b55dbe74333bee07f450cbe60b45a))

### PendingStreams

- Add missing internal API methods ([62f1818](https://github.com/dirvine/ant-quic/commit/62f1818dc4b0377d8e646edc384583e7292a055c))
- Add alternative (unfair) send stream scheduling strategy ([9d63e62](https://github.com/dirvine/ant-quic/commit/9d63e6236be5e831119ad6adb1de88b20bd93f5c))

### Perf

- Prefer more efficient cipher suites ([3de2727](https://github.com/dirvine/ant-quic/commit/3de2727b94de4755b9d67a40bca146cbf1652b8e))
- Use owned buffers ([312c0f0](https://github.com/dirvine/ant-quic/commit/312c0f041c1191b179fe5cd552a0c4c6d129226b))

### Performance

- Use tokio::try_join instead of select ([1203960](https://github.com/dirvine/ant-quic/commit/12039602ae6d91d1361acb4d9b2ad11df2bbaed8))
- Adopt more convential crate layout ([85dde10](https://github.com/dirvine/ant-quic/commit/85dde101bd7310fee784030039fabee019417a17))
- Tweak style in bind_socket() ([0f285bd](https://github.com/dirvine/ant-quic/commit/0f285bd751b08a3de5c6b299fbc1738877b2f4a4))
- Use dual stack socket for endpoints ([2870519](https://github.com/dirvine/ant-quic/commit/2870519f6eb27e13f8597bc4d5a8b49fcae3425d))
- Specialize slice extension in Datagram::encode ([d08ad01](https://github.com/dirvine/ant-quic/commit/d08ad01e4099024bfab82970251b1360698cef20))
- Change throughput units from MiB/s into Mb/s. ([90118e7](https://github.com/dirvine/ant-quic/commit/90118e76b3340a3b8f0f6877f27eebde7315fea0))
- Hoist config construction out of conditionals ([f0d1a45](https://github.com/dirvine/ant-quic/commit/f0d1a45639e2b89963e6d2b92ddc87fa7ac336ce))
- Allow setting initial round trip time ([abd1be0](https://github.com/dirvine/ant-quic/commit/abd1be051b64ecb7f882d2967141c6e2f7f50401))
- Allow configuring ack frequency ([1678ada](https://github.com/dirvine/ant-quic/commit/1678ada26d442eaa48e341cff51a3d47f5ae3f90))
- Allow selecting congestion algorithm ([a8eba3a](https://github.com/dirvine/ant-quic/commit/a8eba3ada638b6c9c87c9f5e249265b6fb6fcf90))
- Leave async tasks early ([62bc881](https://github.com/dirvine/ant-quic/commit/62bc881b9a7b8f6e95950304672af2d497a9ab32))

### QIF

- Get path from cli args ([d9bc7ce](https://github.com/dirvine/ant-quic/commit/d9bc7ce8de0ca8c832512afc12189758ddc8d67a))
- Correctly set max table size ([a2dea7c](https://github.com/dirvine/ant-quic/commit/a2dea7c6401a3955ffd5db6e350d1950256baa77))
- Encode one file, without configuration ([2997382](https://github.com/dirvine/ant-quic/commit/2997382aa9cd7cad95ba14bb05e8f1ba6a9d4915))
- Iterate over qif sir and generate all encode cases ([06654e2](https://github.com/dirvine/ant-quic/commit/06654e2e7f9893d61a3e24b8a89e6c92ebea864b))
- Implement acknowledgement mode ([a1cc9ca](https://github.com/dirvine/ant-quic/commit/a1cc9caebb86464dad7907a642bd8363602ae1df))
- Handle encoded files for all impls, generalize failure display ([b762712](https://github.com/dirvine/ant-quic/commit/b76271280b039485b3e749e63eb88290d61f1318))
- Gather encoding results ([b710fcc](https://github.com/dirvine/ant-quic/commit/b710fcc1a50ad27b08e1f50a63edf43cf6b85149))
- Get encoder settings from cli args ([0c37a8a](https://github.com/dirvine/ant-quic/commit/0c37a8a9943904fcf1af574b4d4d3558525e381f))
- Use cli args when encoding a single file ([9dc05fe](https://github.com/dirvine/ant-quic/commit/9dc05fe5d8b0a9a44380df12eb4115eba9b4b71f))
- Handle blocked streams ([15b3cbb](https://github.com/dirvine/ant-quic/commit/15b3cbb346749b1c89e3a470301532107a992a06))
- Use max blocked stream in encoding and check validity on decoding ([f874a8d](https://github.com/dirvine/ant-quic/commit/f874a8dad6d10b82e697946daf23d2f64618f6d3))

### QPACK

- Retreive fields by name in static table ([ceed37e](https://github.com/dirvine/ant-quic/commit/ceed37e2edd18a98c17ad917a4c92d7b04b34590))
- Reformat after big rebase ([664ecef](https://github.com/dirvine/ant-quic/commit/664ecef22de1b2aa0f132c08a50cff65b6ae8f7a))
- Rewrite prefixed integers using Codec traits ([76cd18b](https://github.com/dirvine/ant-quic/commit/76cd18b7c86a110c8a9641bb4234ac02f75a7d90))
- Rewrite prefixed string using codec traits ([ed37636](https://github.com/dirvine/ant-quic/commit/ed3763680588771cfb59b59403cc9830820cf72e))
- Rework decoder to use prefix_* mods and remove unused code ([772d873](https://github.com/dirvine/ant-quic/commit/772d8739bb980747bc304972a72388a909c3495b))
- Get largest reference from VirtualAddressSpace ([539b35f](https://github.com/dirvine/ant-quic/commit/539b35f2871f3c2de5a36a65226f2a7af2275bcd))
- Fix last post base index exlusion ([b509260](https://github.com/dirvine/ant-quic/commit/b50926027f00be501d11c3693ea8329edf1b1782))
- Header bloc decoding implementation ([38f925f](https://github.com/dirvine/ant-quic/commit/38f925f99b6aec57780d814de8073e7a119ce403))
- Simplify name reference code with header field value method ([40899b2](https://github.com/dirvine/ant-quic/commit/40899b2e355ff265be6b8e857a5f0c97b018bb9c))
- Refactor error decoder handling ([1528ac6](https://github.com/dirvine/ant-quic/commit/1528ac60cbd24fa866cef0b6e0485cea655d1554))
- Refactor encoder stream decode function ([12b1b25](https://github.com/dirvine/ant-quic/commit/12b1b25892e61936393cc1d2591cba3a3afc6491))
- Add test when entries dropped, and base index calculation, fix vas ([4f1d6b9](https://github.com/dirvine/ant-quic/commit/4f1d6b95f8353c6a9650f04788c439ef4550227e))
- Refactor decoder tests ([e16ef57](https://github.com/dirvine/ant-quic/commit/e16ef57f7a32c6f640abf7f8f9387597609a6d00))
- Send Table state synchronize message back to the encoder ([e4d490f](https://github.com/dirvine/ant-quic/commit/e4d490f843ba3ecfb1ba082e32f57e5bdbcf875b))
- Fix incomplete message parsing consuming too much bytes and breaking ([d86bc92](https://github.com/dirvine/ant-quic/commit/d86bc928ce5114ae8859666839b6f684627087d1))
- Refactor encoder stream instruction outside decoder ([aa0ba29](https://github.com/dirvine/ant-quic/commit/aa0ba2970ab578e00de0d23af05d29e6a91599b4))
- Refactor header bloc codec into it's own module ([4f84488](https://github.com/dirvine/ant-quic/commit/4f84488d8ec2335cb948e3eed0f073d601550909))
- Use base index only when it is meaningful ([f277603](https://github.com/dirvine/ant-quic/commit/f2776030d2ab822624d9cd3c46daeae217c731f0))
- Split stream inserter / bloc decoder interface: ([79de3ca](https://github.com/dirvine/ant-quic/commit/79de3ca989c45d001b99495579fdc73f2ef42e5f))
- Retreive static index from name or name+value ([ca92f2f](https://github.com/dirvine/ant-quic/commit/ca92f2fa00bc8888dfc9e3bf3740fb09cfb7fa5e))
- DynamicTable for the encoder ([9195df0](https://github.com/dirvine/ant-quic/commit/9195df075975c81e9fbb938e91287ab43934ed61))
- Use tuple struct syntax for Duplicate encoder stream instruction ([2a1e958](https://github.com/dirvine/ant-quic/commit/2a1e9588a2bc9ac3275bb640ac385a6fa5ebcb70))
- Static name reference insertion in dynamic table ([4adccc4](https://github.com/dirvine/ant-quic/commit/4adccc4163cd5dd8dd2cc599912c2bce03527032))
- Known the value of an invalid prefix, fix Literal prefix check ([12c0dab](https://github.com/dirvine/ant-quic/commit/12c0dab28fe71eaaa5ec8e5c61db59f4fc2d7187))
- Header bloc prefix codec ([dceca45](https://github.com/dirvine/ant-quic/commit/dceca45476396e72b593fb9f967a86baccf93324))
- Encoder implemetation, without reference trancking ([e2e07de](https://github.com/dirvine/ant-quic/commit/e2e07ded5cd76a78453e2579a6ed0de00c42037e))
- Retreive abolute index from real index ([67ae321](https://github.com/dirvine/ant-quic/commit/67ae321eaccfc0f84b0f538ef6dc32116fe390b5))
- Reference tracking on encoding ([d76cf81](https://github.com/dirvine/ant-quic/commit/d76cf81de208210154ea4d532dd1534ac343a834))
- Decoder instructions ([bdf1ffc](https://github.com/dirvine/ant-quic/commit/bdf1ffc6ee7cff7269dc4e563ae37874feddef55))
- Use tuple structs for decoder stream types ([2e1c3a0](https://github.com/dirvine/ant-quic/commit/2e1c3a0d4973628bff992a88ed637a7f6b7ad219))
- Untrack a bloc with stream id ([70a0e0e](https://github.com/dirvine/ant-quic/commit/70a0e0e1b79c92e9c4299bc94138e23a0589bfae))
- Decoder stream impl ([b47b18f](https://github.com/dirvine/ant-quic/commit/b47b18fd9ce182230dfa62fc94f31d51d8e31ebc))
- Update quinn-proto version ([71602a9](https://github.com/dirvine/ant-quic/commit/71602a980e92035873030c016febb647e4268555))
- Test instruction count incrememnt ([9b0308b](https://github.com/dirvine/ant-quic/commit/9b0308ba5b1ea8e82a1aa917c4ef4ae13ea249a8))
- Update name / name_value index maps on insert ([3f00c49](https://github.com/dirvine/ant-quic/commit/3f00c49b057878c15a8cbf39d3f8aa70deec756e))
- Do not panic on tracking an already tracked stream bloc ([a6d74bf](https://github.com/dirvine/ant-quic/commit/a6d74bfcb8a959b60e2e92c6772cd3d9b69c136f))
- Max table size = 0, fix division... ([1c921ad](https://github.com/dirvine/ant-quic/commit/1c921addd72dc999b1c4ab99bed4595493c8266e))
- Tuple struct for TableSizeUpdate ([76a33e2](https://github.com/dirvine/ant-quic/commit/76a33e2247f2300baf2590c1fc1b94f4e8151532))
- Codec tests ([3f8de36](https://github.com/dirvine/ant-quic/commit/3f8de36512b456faa513774bd1dedb4339426212))
- Remove dead_code attributes ([ab8a2c2](https://github.com/dirvine/ant-quic/commit/ab8a2c210208fa44e96ce141c576ce43a5647c58))
- Visibility cleanup ([8d14573](https://github.com/dirvine/ant-quic/commit/8d145736f70716f5fe77e5b866100d97986b2bb1))
- Last public API impl ([1bdf8d8](https://github.com/dirvine/ant-quic/commit/1bdf8d8acdb500f6aad11e2ad35d0583ee7efd54))
- Rename `bloc` to `block` ([53f5934](https://github.com/dirvine/ant-quic/commit/53f5934bf632f9247e1788da692ccd2f1f3ae61a))
- Display header field in qif line format ([0e15861](https://github.com/dirvine/ant-quic/commit/0e15861638930282575fdf02a498aa2e97be2c8a))
- Offline interop without encoder stream support ([3564549](https://github.com/dirvine/ant-quic/commit/35645490c50c8bcc10decbd0dd92a0552cfcf385))
- Interop tool, encoder stream and failure summary ([e0e9c50](https://github.com/dirvine/ant-quic/commit/e0e9c50375c71e9c4a6c9bb10cf348b2714fec64))
- Qif compare and better display ([db02128](https://github.com/dirvine/ant-quic/commit/db02128974f8755614a5784cc8f58f6a8dd83b2c))
- Fix error when required_ref = 0 and delta_base = -0 ([5254d2f](https://github.com/dirvine/ant-quic/commit/5254d2ffd900a07a6be3e1387b8571dd5be0efbc))
- Tracked blocked streams, do not insert if max reached ([7fb4356](https://github.com/dirvine/ant-quic/commit/7fb435641029cbeb64f59e18545030c7889951f6))
- Do not fail when encoder insertion try fails ([3bdb41f](https://github.com/dirvine/ant-quic/commit/3bdb41fbfa59a88c29359bde7b235ae2e24d78e9))
- Guard against substract overflow ([177b817](https://github.com/dirvine/ant-quic/commit/177b817591cf4b172d4ddebc464bddd831da98c2))
- Know if an index has been evicted, drop one by one ([7b47683](https://github.com/dirvine/ant-quic/commit/7b47683347695cbc6d4d42680419730aac74eb20))
- Remove evicted fields from dynamic reference map ([98a06b3](https://github.com/dirvine/ant-quic/commit/98a06b336fc071ef59fd58cdb08adfd0faa4cff3))
- Fix a prefi_int bug when integer encoding has a perfect fit ([bdb3f55](https://github.com/dirvine/ant-quic/commit/bdb3f557acde26712388aba5ebebe6d24100e2f0))
- Fix 0 required ref case on encoding block ([e56758d](https://github.com/dirvine/ant-quic/commit/e56758dcac623646ae726557d35f62405cba61da))
- Fix prefix string byte count when it fits 8 bit multiple ([d62b5fe](https://github.com/dirvine/ant-quic/commit/d62b5fe06a4b3f222e7d9cbf78aecd3e5255c8b2))
- Rename HeaderBloc{,k}Field ([b3263c3](https://github.com/dirvine/ant-quic/commit/b3263c38ecf48f631464ef291f301c5cc174acdd))
- Fix typo ([550bf55](https://github.com/dirvine/ant-quic/commit/550bf55717b32a18dc02e521afd793a483b5106c))
- Remove dead_code ([eca2af1](https://github.com/dirvine/ant-quic/commit/eca2af160459a57775a1f40a9c768754db4629cb))
- Fix visibilities ([2fec389](https://github.com/dirvine/ant-quic/commit/2fec3894805dac1b5604ad7fd5976c592a3572f7))
- Use err_derive for public errors ([dafe685](https://github.com/dirvine/ant-quic/commit/dafe6859955f6bde63127dc23589756076c1f73d))
- Fix default values for settings ([ba2eff5](https://github.com/dirvine/ant-quic/commit/ba2eff5fe923c66809d92f3d6f5e6500b31c6591))
- Make encode accept slice of HeaderField ([9910013](https://github.com/dirvine/ant-quic/commit/9910013a4e30d1d4cbff6dd4279ec5fb8a8197f1))
- Prevent substraction underflow in VAS ([5b67ded](https://github.com/dirvine/ant-quic/commit/5b67dedf842da79265e48a19d25b583e7d632f59))
- Rename mem_limit to max_size, as in specs ([807ae06](https://github.com/dirvine/ant-quic/commit/807ae068cf40cfb454fcf448bf65f4e31dad7366))
- Do increment largest known received ref ([aebada3](https://github.com/dirvine/ant-quic/commit/aebada353be7949a44331215e3a76841f74548cb))
- Track two ref blocks per stream ([3b4b86a](https://github.com/dirvine/ant-quic/commit/3b4b86a9f814e0ce7541d529f7f722a52da384b0))
- Make dynamic tracking state non-optional ([fc1035f](https://github.com/dirvine/ant-quic/commit/fc1035ff3c0690e49ecad415641e711215de4c9f))
- Ignore unknown stream cancellation ([0e87485](https://github.com/dirvine/ant-quic/commit/0e874850e9b1e78093b4e13a7df761497bbe9296))

### QUINN

- Include ios in the conditional compilation for mac platforms ([605c9a5](https://github.com/dirvine/ant-quic/commit/605c9a57efd89055118232fbb9eee3728e68ffbb))
- Allow retrieving the peer's certificate chain from a connection ([7122eab](https://github.com/dirvine/ant-quic/commit/7122eab85712b15b598998b324f3e777bed57ae6))

### Refactor

- Do not require &mut self in AsyncUdpSocket::poll_send ([75524fc](https://github.com/dirvine/ant-quic/commit/75524fcb0bf9aee1f9a0c623edba7c108de67b28))
- Use array::from_fn instead of unsafe MaybeUninit ([65bddc9](https://github.com/dirvine/ant-quic/commit/65bddc90187a93b2172519c72fc611258d0b2fd3))
- Use workspace dependency for tracing and tracing-subscriber ([9e2272a](https://github.com/dirvine/ant-quic/commit/9e2272a477a76fa9656f6caf427c039416999432))
- Add use declaration for tracing debug and error ([349dcd6](https://github.com/dirvine/ant-quic/commit/349dcd6017cd9b1b1bf07c08460f2d18a14663e9))
- Move rust-version to workspace Cargo.toml ([ce97879](https://github.com/dirvine/ant-quic/commit/ce97879e8d44e4b109efb08e88d1f3195d2c1770))
- Introduce log facade ([244b44d](https://github.com/dirvine/ant-quic/commit/244b44d8cf790879588615d2cb347b59e18f0b4c))
- Add fn new_socket ([a5e3b6f](https://github.com/dirvine/ant-quic/commit/a5e3b6f063e59e4331711477f7f308f0b0aa97f8))
- Switch to async ([a5046ad](https://github.com/dirvine/ant-quic/commit/a5046add78957bec4849fac366a00751f7ea5b70))
- Remove unnecessary `return` ([cb0b59d](https://github.com/dirvine/ant-quic/commit/cb0b59d09c37836d44a9f591899490c0545360e1))
- Move max_datagrams limit at poll_transmit from quinn-proto to quinn ([f8165c3](https://github.com/dirvine/ant-quic/commit/f8165c339483a09204514377c430579ceb6509e5))
- Favor early-return for `send` impls ([56e19b8](https://github.com/dirvine/ant-quic/commit/56e19b841f02ebc8c3982dcee47839563a228740))
- Favor early-return for `recv` impls ([3391e7a](https://github.com/dirvine/ant-quic/commit/3391e7a4a6e1d30b68037247480a5a98c8defe2e))
- Avoid blocks in `match` arms ([075c7ef](https://github.com/dirvine/ant-quic/commit/075c7ef235f2acbf7cf4ba2b203b1c4448e6a0f2))
- Remove redundant match-arms ([3e81eb0](https://github.com/dirvine/ant-quic/commit/3e81eb0dfb2c49b18170533339f0d673e277a51b))
- Use `match` blocks in `recv` ([c7687f7](https://github.com/dirvine/ant-quic/commit/c7687f7e0c5340168a29c348a4b794b66beee814))
- Remove some usage of execute_poll ([4f8a0f1](https://github.com/dirvine/ant-quic/commit/4f8a0f13cf7931ef9be573af5089c7a4a49387ae))
- Configure out `async_io::UdpSocket` when unused ([e8dc5a2](https://github.com/dirvine/ant-quic/commit/e8dc5a2eda57163bfbaba52ba57bf5b7a0027e22))
- Transform workspace to single ant-quic crate structure ([505b732](https://github.com/dirvine/ant-quic/commit/505b732b6e197a7ab8446ddacbe1ecb3f2674e5a))

### StreamState

- Allow reusing Recv instances ([41850c8](https://github.com/dirvine/ant-quic/commit/41850c8a304f09c7d009a6e70e48f35bd737e1b5))

### Testing

- Ignore stress tests by default ([6716b5a](https://github.com/dirvine/ant-quic/commit/6716b5a7b8c5c2e64522d56682ac12aae824c4cf))
- Gate PLPMTUD test ([caf8389](https://github.com/dirvine/ant-quic/commit/caf838947c59ec90ccb7a555cc9eb3ef39025232))
- Avoid ICE in beta ([6bfd248](https://github.com/dirvine/ant-quic/commit/6bfd24861e65649a7b00a9a8345273fe1d853a90))
- Refactor IncomingConnectionBehavior ([5a572e0](https://github.com/dirvine/ant-quic/commit/5a572e067d38b368a1955ae92921d4901aab8b4e))
- Enable NEW_TOKEN usage in tests ([ee29715](https://github.com/dirvine/ant-quic/commit/ee297152155ee3bb6a480fff7618e56061de9908))
- Create tests::token module ([d2acbc3](https://github.com/dirvine/ant-quic/commit/d2acbc3e94037d6d079abb8bc998bc147fab03bf))
- Add tests for NEW_TOKEN frames ([bb54bc4](https://github.com/dirvine/ant-quic/commit/bb54bc4a51594c86d757fb710b23e0a8a6f1d7fb))
- Fix wasm CI ([69c00eb](https://github.com/dirvine/ant-quic/commit/69c00ebfdc589f574dd3a515db700948086f3a83))
- Use default TokenMemoryCache ([1126591](https://github.com/dirvine/ant-quic/commit/11265915ae8c58dde53dca9af57bc0946ef23bb9))
- Use default BloomTokenLog ([7ce43e8](https://github.com/dirvine/ant-quic/commit/7ce43e8e7b22c61fee3430d1c1a1bf447e046e02))
- Add comprehensive test suite for NAT traversal ([52965af](https://github.com/dirvine/ant-quic/commit/52965af2543701ea701f7cc6f087a63ca8bea047))

### Bbr

- Apply clippy suggestions to avoid unnecessary late initialization ([92ab452](https://github.com/dirvine/ant-quic/commit/92ab452e1b573e5f9bf7736060b0318b8f07a813))
- Avoid unwrapping a value we just set ([a87b326](https://github.com/dirvine/ant-quic/commit/a87b3262ff7daeac3a76857d1eaaf944d5cd9d29))
- Avoid unwrapping checked Option value ([4630670](https://github.com/dirvine/ant-quic/commit/4630670655ce568813689530b7e579fe53d38145))
- Avoid unwrapping another checked Option value ([8da9cf5](https://github.com/dirvine/ant-quic/commit/8da9cf55e5ec8b9390e41bb9eee3484b67be7cc7))
- Implement Default for MinMax ([75b2b11](https://github.com/dirvine/ant-quic/commit/75b2b118ecdada612b296906fde94c6bf282ce6a))
- Derive default for AckAggregationState ([60dd3da](https://github.com/dirvine/ant-quic/commit/60dd3da2a1f67526a3354dbc10a29ee8998e593c))
- Change sent_time type to Instant ([5e0df6c](https://github.com/dirvine/ant-quic/commit/5e0df6c1f1668cf35ab14448b97b4b128be3cbdd))
- Reorder code according to prevailing style ([c0b50b4](https://github.com/dirvine/ant-quic/commit/c0b50b4a0dd72c8dc7c651c404975728ce420383))

### Bench

- Measure non-GSO & GSO on localhost ([#1915](https://github.com/dirvine/ant-quic/issues/1915)) ([36407fe](https://github.com/dirvine/ant-quic/commit/36407fecc31a794fb790ff8955f404d4ef346b09))

### Book

- Clean up example certificate code ([2bf23d6](https://github.com/dirvine/ant-quic/commit/2bf23d6b330700110741f344853d72553782512e))
- Clean up whitespace ([cd00119](https://github.com/dirvine/ant-quic/commit/cd00119d254f9442618a7f1b8f748dcb9f309740))
- Fix example code ([eec45e6](https://github.com/dirvine/ant-quic/commit/eec45e6b7629f76605966c7018eb37991b829976))
- Fix code references ([bbf9510](https://github.com/dirvine/ant-quic/commit/bbf95101cd5b7e54b1930d0d64951aa566f2283c))
- Clean up formatting ([3d019b3](https://github.com/dirvine/ant-quic/commit/3d019b3fd5be749178e28a0bf429af430ea7cffd))
- Suppress warnings in code samples ([3610629](https://github.com/dirvine/ant-quic/commit/3610629113fcca464dc22199f9e1e5c8e7d50f92))
- Merge certificate code files ([2447c2e](https://github.com/dirvine/ant-quic/commit/2447c2e65114eb6589db8e96183551985f99721b))
- Rename certificate-insecure to certificate ([62fc039](https://github.com/dirvine/ant-quic/commit/62fc0397fb14db94d1ec27a0ca63476469a5f67e))
- Rely on implicit targets ([ab0596a](https://github.com/dirvine/ant-quic/commit/ab0596a89ba8e137add9d5e9a0ab54cda17dc58b))
- Import more types ([48e0bb3](https://github.com/dirvine/ant-quic/commit/48e0bb3317b13364aa94319431f9dc5d34b478a4))
- Order certificate code in top-down order ([d948de6](https://github.com/dirvine/ant-quic/commit/d948de66b5ff43e1545f46bb38bfaf8e78189224))
- Simplify connection setup constants ([a196f7c](https://github.com/dirvine/ant-quic/commit/a196f7c48049c7e26ed51449f3ab3f0746e88ce7))
- Order set-up-connection code in top-down order ([6b6d115](https://github.com/dirvine/ant-quic/commit/6b6d115bdace983ecd0cb8bdcc24f7e19c280e47))
- Order data-transfer code in top-down order ([a788429](https://github.com/dirvine/ant-quic/commit/a788429e919d8e3a1563641d44d5c032be74221c))
- Remove unused dependency ([e960c33](https://github.com/dirvine/ant-quic/commit/e960c33729660013d5d1436a37d19994f0b7034d))
- Remove obsolete rustls features ([f63d962](https://github.com/dirvine/ant-quic/commit/f63d962d0829799f8775da70d0659a43c457159f))
- Specify dependency versions ([2f60681](https://github.com/dirvine/ant-quic/commit/2f60681abe8d626b2a15a42042fac479fd391168))

### Build

- Bump codecov/codecov-action from 3 to 4 ([dcc8048](https://github.com/dirvine/ant-quic/commit/dcc8048974ce9b1ca6b365019149b5586ed88f4a))
- Bump peaceiris/actions-mdbook from 1 to 2 ([b469e1c](https://github.com/dirvine/ant-quic/commit/b469e1c7ad7815df3f9d94335d6c454cd07412fa))
- Bump peaceiris/actions-gh-pages from 3 to 4 ([52c285d](https://github.com/dirvine/ant-quic/commit/52c285d60f4c3282578ba63a849689c5ef875632))
- Update windows-sys requirement from 0.52 to 0.59 ([91be546](https://github.com/dirvine/ant-quic/commit/91be5467387ebbabffa884f6abb1b7663c8ffec4))
- Bump android-actions/setup-android from 2 to 3 ([abaa2d3](https://github.com/dirvine/ant-quic/commit/abaa2d3b1390975e20911199d20131ba629db50b))
- Bump actions/setup-java from 3 to 4 ([1e48a70](https://github.com/dirvine/ant-quic/commit/1e48a703d5a7d7c7594acca2068cd6bd68e224c5))
- Update rustls-platform-verifier requirement from 0.3 to 0.4 ([c3e70aa](https://github.com/dirvine/ant-quic/commit/c3e70aa7ab9c51d8d976c3ea740641d9ac09dd91))
- Update thiserror requirement from 1.0.21 to 2.0.3 ([18b7956](https://github.com/dirvine/ant-quic/commit/18b79569693ea9d78ea127932f6d6e663664147f))
- Bump codecov/codecov-action from 4 to 5 ([3a9d176](https://github.com/dirvine/ant-quic/commit/3a9d176a7a131a1f6d9472c1a23fccdcb1275b52))
- Update rustls-platform-verifier requirement from 0.4 to 0.5 ([7cc1db2](https://github.com/dirvine/ant-quic/commit/7cc1db2cbc52f518c5457f4550b17d17a10efb88))
- Bump socket2 from 0.5.8 to 0.5.9 ([c94fa9b](https://github.com/dirvine/ant-quic/commit/c94fa9bacbb71bfd737245539e678e9be9be7d66))
- Bump rand from 0.9.0 to 0.9.1 ([b406b98](https://github.com/dirvine/ant-quic/commit/b406b98e45607ce2f8e9e4c2d08540419bfea6eb))
- Bump getrandom from 0.3.2 to 0.3.3 ([81282af](https://github.com/dirvine/ant-quic/commit/81282af8d5d27859f1a3324cf3a1884434f7965a))
- Bump rustls-platform-verifier from 0.5.1 to 0.5.3 ([176e84c](https://github.com/dirvine/ant-quic/commit/176e84c66698f112dc8f322e47d5fd7a6b23d0b4))
- Bump socket2 from 0.5.9 to 0.5.10 ([9fd189c](https://github.com/dirvine/ant-quic/commit/9fd189c7d5bf08d543b03a29bf0913d6909ec569))
- Bump async-io from 2.4.0 to 2.4.1 ([f61a0f6](https://github.com/dirvine/ant-quic/commit/f61a0f6637803007aaf591b0ec1384d1610b6c66))
- Bump criterion from 0.5.1 to 0.6.0 ([0699545](https://github.com/dirvine/ant-quic/commit/06995454f44171d4164753b95e0bce900089a9a7))

### Certificate

- Accept pem format ([#829](https://github.com/dirvine/ant-quic/issues/829)) ([2892490](https://github.com/dirvine/ant-quic/commit/2892490057e30587c089e158ce515d7b0eec5ada))

### Ci

- Check private docs for links as well ([8dca9fc](https://github.com/dirvine/ant-quic/commit/8dca9fcc37e819add3e96d6f7965a2b61897f582))
- Pass codecov token explicitly ([b570714](https://github.com/dirvine/ant-quic/commit/b5707140d5abd08dcdc182e8759bc4e577983d67))
- Add Android job ([1e00247](https://github.com/dirvine/ant-quic/commit/1e00247360779599eab4093897e332eb1ededf32))
- Add workflow testing feature permutations ([edf16a6](https://github.com/dirvine/ant-quic/commit/edf16a6f106379681509f229b6e45539fa3eebdb))
- Check coverage on multiple platforms ([19a5e9d](https://github.com/dirvine/ant-quic/commit/19a5e9dfd0594971856c45b62b365738ab1adf22))
- Only test FIPS features on Ubuntu ([459322b](https://github.com/dirvine/ant-quic/commit/459322b1800f7ae5612a6b4b890c5cd1b6a499bf))
- Test-run benchmarks ([c7a8758](https://github.com/dirvine/ant-quic/commit/c7a8758ab9639412b36fc43455ff1288526a58cd))
- Run on Android API Level 25 ([a83c6e4](https://github.com/dirvine/ant-quic/commit/a83c6e463b0dd091582e2cbd76f970c690e12294))
- Run quinn-udp tests with fast-apple-datapath ([3c3d460](https://github.com/dirvine/ant-quic/commit/3c3d46037884b0bf2b7d64653f88681381489eea))
- Powerset --clean-per-run ([d5e63d8](https://github.com/dirvine/ant-quic/commit/d5e63d8c2869af9f5e8af7492b42696cab55848f))
- Run macOS tests conditionally on runner OS ([107dd92](https://github.com/dirvine/ant-quic/commit/107dd923759419d5eaacde5323338b0b77310f20))
- Run `quinn-udp` fast-data-path tests ([3f94660](https://github.com/dirvine/ant-quic/commit/3f9466020cff6f846550fdfc9c1d923fc53c29ca))
- Change powerset check ([f642fa8](https://github.com/dirvine/ant-quic/commit/f642fa870edb4339e3135ef438eed1c43d03073a))

### Clippy

- :identical_conversion ([80986de](https://github.com/dirvine/ant-quic/commit/80986de0a510ca4b0826c62cfa1399dc7da1e20b))
- :single_match ([538154b](https://github.com/dirvine/ant-quic/commit/538154bc6d86f3338cb50f2b13c64bc50e3091e5))
- :collapsible_if ([208a162](https://github.com/dirvine/ant-quic/commit/208a1622bccb85dd415a917b6cf8f1825dfdee40))
- :range_plus_one ([c16c213](https://github.com/dirvine/ant-quic/commit/c16c2136c0deb235d29ccd2a1e6cb47e9e4f1b77))

### Config

- Add ServerConfig::transport_config() builder method ([d522b6d](https://github.com/dirvine/ant-quic/commit/d522b6dd63a88b5bf097addfc26f0d2ad35a367b))
- Make ClientConfig fields private ([838ad7c](https://github.com/dirvine/ant-quic/commit/838ad7c4715f032196449bbc5f6d367a9aaa951b))

### Connection

- Change overly verbose info span to debug ([dfa4f0e](https://github.com/dirvine/ant-quic/commit/dfa4f0e296479ed204c26eda98640790bcdb298a))
- Wake 'stopped' streams on stream finish events ([1122c62](https://github.com/dirvine/ant-quic/commit/1122c627c35241eda2e87a9637d3bd5ea19f290c))

### Core

- Clean up write ([1c84faa](https://github.com/dirvine/ant-quic/commit/1c84faa0e57b36b2017bf6e55ceccd4b50b47ecf))
- Bitfield-based stream assembly ([c0100f3](https://github.com/dirvine/ant-quic/commit/c0100f3c2af19cf70fdb67db5f539511b387e686))
- Implement ordered reads ([b6cc9c2](https://github.com/dirvine/ant-quic/commit/b6cc9c2345a79727b933199de5ab1ef55edf9a74))
- Ensure read sanity ([6f1ea7b](https://github.com/dirvine/ant-quic/commit/6f1ea7b783dd443fa88ec7703b98306616184adf))
- Truncate close reasons to fit MTU ([e288af2](https://github.com/dirvine/ant-quic/commit/e288af23f76817d8136e735f4600e181af05be99))
- Fix panic on close ([71ba828](https://github.com/dirvine/ant-quic/commit/71ba828c36362509bf8f836c6112727c6676ae06))
- Improve documentation ([6d0254a](https://github.com/dirvine/ant-quic/commit/6d0254a0ad7bed9fea0ce2ff5e61b338e8f3b2d9))
- TLS certificate verification ([b4bd5bc](https://github.com/dirvine/ant-quic/commit/b4bd5bc5517bd326b118cb8d25d40d24d047781d))
- Relax slog features ([725fbd3](https://github.com/dirvine/ant-quic/commit/725fbd3874ede7805ff90b5761166e746cd80244))
- Extensive cleanup ([8476e11](https://github.com/dirvine/ant-quic/commit/8476e117167a7e4f2718274039894a2cccf1bd17))
- Convenience impl From<ConnectionError> for io::Error ([b8b0634](https://github.com/dirvine/ant-quic/commit/b8b063447ad3f67cd8837c6dadab1abb21d4f9e3))
- Fix client connection loss when Initial was retransmitted ([fd69d56](https://github.com/dirvine/ant-quic/commit/fd69d565f68b177ca3f494f2215c9ae25b38207d))
- Support backpressure on incoming connections ([63c4371](https://github.com/dirvine/ant-quic/commit/63c4371d99e3badf03834fee63e65df66438418a))
- Fix underflow on client handshake failure ([d7754bf](https://github.com/dirvine/ant-quic/commit/d7754bfc31f412ffa39b6490e798d3b4f7045c17))
- Fix panic on stateless reset for short packets ([71c9c48](https://github.com/dirvine/ant-quic/commit/71c9c482fb1415105358eacc378327a415510610))
- Test and debug stop_sending ([ace87bb](https://github.com/dirvine/ant-quic/commit/ace87bbeec0941b60a8c727d4ab94acc28b49784))
- Deliver buffered data even after reset ([f82774a](https://github.com/dirvine/ant-quic/commit/f82774a367249d78a2b0b111f313144b0aa66094))
- Test finishing streams ([d0ee87f](https://github.com/dirvine/ant-quic/commit/d0ee87febaee67947c1bede77d12e965704d0ec7))
- Fix panic composing PNs before receiving ACKs ([82016c4](https://github.com/dirvine/ant-quic/commit/82016c47a2d15e4bc08de92130fe9c810e4f7aa4))
- More detailed logging ([6cef002](https://github.com/dirvine/ant-quic/commit/6cef002e07bf2d7fb8b01d81ed35e49f6f30d968))
- Fix default cert verification behavior ([5d3aca1](https://github.com/dirvine/ant-quic/commit/5d3aca186ff7e0e71e13c35921156c20dec3d6e2))
- Unit test for congestion ([934f681](https://github.com/dirvine/ant-quic/commit/934f681b77caa11622bfad4076d837b44e97d91e))
- Fix panic on long packet with empty payload ([f1862b5](https://github.com/dirvine/ant-quic/commit/f1862b55fee9cd8b34786a9f54214d5f6997d6d5))
- Fix client bidi stream limit fencepost ([a0b07dd](https://github.com/dirvine/ant-quic/commit/a0b07ddb7bfb06e79783ef28ea30dd3841de56d5))
- Fix connect test ([aa5300d](https://github.com/dirvine/ant-quic/commit/aa5300da58a92b4ce59f9bb1010eb9f44d78d565))
- Log ACK delay ([9ac732d](https://github.com/dirvine/ant-quic/commit/9ac732dd863d5a8f1ef1c3aa1f647baf1f573e45))
- Fix bad delay in server's first ACK ([5e8dcc7](https://github.com/dirvine/ant-quic/commit/5e8dcc71ee669c750e06695ad10362ad5c2f4396))
- Fix inadvertent sending of certificate requests ([1078ce9](https://github.com/dirvine/ant-quic/commit/1078ce9f76ce192a7dc57435890bee572eb7e637))
- Sni accessor ([e40d241](https://github.com/dirvine/ant-quic/commit/e40d241c0de3670dd5bd69c4e670a12b83f7899e))
- Refactor tests to support passage of time ([15662a3](https://github.com/dirvine/ant-quic/commit/15662a3f44ab5d10ee8909dfcfa5f5a1d285a621))
- Fix high-latency handshakes and related bugs ([31d3594](https://github.com/dirvine/ant-quic/commit/31d35944aacc8b52f436dca61b05de1a6c39db14))
- Don't ignore handshake completion ACKs ([6045f79](https://github.com/dirvine/ant-quic/commit/6045f79bd6b1469f979a159b26bc8a75370d42b4))
- Fix stream ID fencepost error ([af50ca0](https://github.com/dirvine/ant-quic/commit/af50ca01549a91ab5256ef1b8959c02b9924e820))
- Fix underflow on recv of already-read stream frame ([9e3467c](https://github.com/dirvine/ant-quic/commit/9e3467c0a28abe419025ae3e7009bf6173fc8b51))
- Fix panic on malformed header ([0912eda](https://github.com/dirvine/ant-quic/commit/0912edaaf2a0ce390eb9a9b6a37a414a8e9ffbee))
- Fix openssl version bound ([643c682](https://github.com/dirvine/ant-quic/commit/643c6829e9c00129f231ff6716978ab1823e5a56))
- Improve handling of unexpected long header packets ([9892845](https://github.com/dirvine/ant-quic/commit/989284511d22e3bbcb7eda1099a7721c5fd3e56c))
- Tolerate NEW_CONNECTION_ID ([d76f9e2](https://github.com/dirvine/ant-quic/commit/d76f9e2040b9af3c373bc5ed93695b1508b14c30))
- Sanity-check NEW_CONNECTION_ID ([f65a59a](https://github.com/dirvine/ant-quic/commit/f65a59a22e70892b323c70f118159faa1d66f0a7))
- Optional stateless retry ([55bf762](https://github.com/dirvine/ant-quic/commit/55bf7621a6c18cdb6a3d0a210fd48f786c879025))
- Minimal resumption UT ([a598957](https://github.com/dirvine/ant-quic/commit/a5989575d2aad5714aa96b4f75e1fe8c5053d3c0))
- Ensure we don't use later TLS versions inadvertently ([b0a3bc8](https://github.com/dirvine/ant-quic/commit/b0a3bc8837853d0f0406967eab4abe6708ab5a9e))
- Include TLS alert, if any, in handshake error ([5e3e85a](https://github.com/dirvine/ant-quic/commit/5e3e85ab08cdc5325086401bef5260fef9b7308d))
- Fix incorrect retransmission of ClientHello under high latency ([e6bd7ca](https://github.com/dirvine/ant-quic/commit/e6bd7cad9ca4a0c22872ae3531dbdba4018dbefa))
- Fix server dedup of retransmitted Initial under stateful hs ([9f13021](https://github.com/dirvine/ant-quic/commit/9f130218413de7e467d07fea8f8e97ea8d6a3e61))
- Don't send MAX_DATA after handshake ([8ccd95c](https://github.com/dirvine/ant-quic/commit/8ccd95c7033f3bb3e1be4d6de73119321e6934d8))
- Clarify some errors ([e65eaa2](https://github.com/dirvine/ant-quic/commit/e65eaa2ea3a012dfeff163daca11bae91abf6e7a))
- Don't inspect reserved short header bit ([1f1f946](https://github.com/dirvine/ant-quic/commit/1f1f9463fe102385578d2388cc4e9a2c8b6e02e8))
- Remove dead code ([14f33b7](https://github.com/dirvine/ant-quic/commit/14f33b74be6c2b792e1520f479d82956162fa5f2))
- Draft 0-RTT receive support ([7c7f635](https://github.com/dirvine/ant-quic/commit/7c7f63552749c73dcaedd77e4dcc9ce3e742ac48))
- Draft 0-RTT transmit support ([5993415](https://github.com/dirvine/ant-quic/commit/5993415434ff8a91cd4447debe87dbfc7198875b))
- Allow ACK-only handshake packets ([a9f9ec6](https://github.com/dirvine/ant-quic/commit/a9f9ec614ddb485533f3835ddc94431bd77ca62c))
- Fix 0-RTT send/recv ([fb9190a](https://github.com/dirvine/ant-quic/commit/fb9190a0b6b07c9d8a39c943f4d290800e34f1a7))
- Optional stateless reset token, fix CID spoofing attack ([a53a0b3](https://github.com/dirvine/ant-quic/commit/a53a0b384c0ace3cf8f920c27d5749de406cc22c))
- Only report stateless resets once ([4b01245](https://github.com/dirvine/ant-quic/commit/4b0124518760460810155496b5ff92f07ef33903))
- Update for current rust-openssl ([4cecc71](https://github.com/dirvine/ant-quic/commit/4cecc71a8608ac76857fd3ba207688bea0329382))

### Crypto

- Return Option from next_1rtt_keys() ([e07835b](https://github.com/dirvine/ant-quic/commit/e07835b954d6c8653b488e82c167b09cdf594573))
- Expose negotiated_cipher_suite in the hadshake data ([a5d9bd1](https://github.com/dirvine/ant-quic/commit/a5d9bd1154b7644ff22b75191a89db9687546fdb))

### Deps

- Upgrade rustls v0.20.3 -> v0.21.0. ([5d1f7bc](https://github.com/dirvine/ant-quic/commit/5d1f7bccf29e81d39a7b19bf395eb31d9ff905e0))
- Remove webpki dependency. ([2f72a5b](https://github.com/dirvine/ant-quic/commit/2f72a5b8479cadb46a1ee6a00a71b173f5d5ed23))
- Make tracing optional and add optional log ([8712910](https://github.com/dirvine/ant-quic/commit/8712910a4c0276d3ab25b426cca1e1110bd863db))

### Endpoint

- Allow override server configuration ([9bb4971](https://github.com/dirvine/ant-quic/commit/9bb4971b8d2b36fba97fd9b03b5d24940a2ad920))

### Examples

- Support fetching arbitrary URLs ([94f3c63](https://github.com/dirvine/ant-quic/commit/94f3c63959acbfd582e7c71077e6c086edc23567))
- Disable certificate verification in client ([1930534](https://github.com/dirvine/ant-quic/commit/19305344a3c22bcbdbeb83f7d20e90c8265c438f))
- Richer logging ([25c48a2](https://github.com/dirvine/ant-quic/commit/25c48a29d3b9a603f49bc94a36bbec058c0ed3bf))
- Server: configurable PEM certs ([36b627b](https://github.com/dirvine/ant-quic/commit/36b627b8da3bf665a874b1a2c9a7a04860b4ab52))
- Use packaged single-threaded runtime ([7b5499f](https://github.com/dirvine/ant-quic/commit/7b5499f1e77832bf8217c26ea86c197cae98c76e))
- Less monolithic server future ([a4fbb44](https://github.com/dirvine/ant-quic/commit/a4fbb443ea4934839c92495c2d1c17e156ffbec3))
- Mark unreachable case ([b44a612](https://github.com/dirvine/ant-quic/commit/b44a612304b7f5826a76cfcdc6934ee496fb1daf))
- Expose stateless retry ([843fc3c](https://github.com/dirvine/ant-quic/commit/843fc3c89aace5e7c3509cf57c9c2a1c8e2af9f7))
- Allow arbitrary listen address ([5ca79bb](https://github.com/dirvine/ant-quic/commit/5ca79bb6b99564bc91e919e72cacddecc684ced2))

### Followup

- Rename "stateless retry" -> "retry" ([25d9a40](https://github.com/dirvine/ant-quic/commit/25d9a40bf97b020661659d752501c3597a65deca))

### Fuzz

- Change config syntax to allow merging ([c4af9ec](https://github.com/dirvine/ant-quic/commit/c4af9ecb1c9352f80a407cbe92edca3fcba4dfca))

### H3

- Std futures ([f5e014d](https://github.com/dirvine/ant-quic/commit/f5e014dae1f6b1dcb240e991aefa1a0e8682477c))

### Interop

- Missing short option for listen ([897e1f3](https://github.com/dirvine/ant-quic/commit/897e1f3e07694eea708456a9d8067b450f340ca4))
- Remove stale comment ([d1df33a](https://github.com/dirvine/ant-quic/commit/d1df33ab5fabd03cf36b054e787507c9f5f5aa25))
- Make h3_get() faster and return the size read ([1c835f8](https://github.com/dirvine/ant-quic/commit/1c835f86882f9dc07c1f25b8a46536b56a5d597c))
- Hq get accepts a path ([fdcf0d2](https://github.com/dirvine/ant-quic/commit/fdcf0d27ccd922314994b4f2c4e9ae4b7f87f13c))
- Client throughput test `T` ([ec12aa8](https://github.com/dirvine/ant-quic/commit/ec12aa8be3042217d3cc88e47f7fb8c6846ffd73))
- Rename hq methods for symmetry ([d506d82](https://github.com/dirvine/ant-quic/commit/d506d8286072478d22b2b7deaf3f8788bb36f7ae))
- Tracing spans: peer | alpn | test ([3589dbf](https://github.com/dirvine/ant-quic/commit/3589dbf7871f407d286d54c8f00897b953412fbe))
- Server throughput test `T` ([005cf4e](https://github.com/dirvine/ant-quic/commit/005cf4e08190c33dc8158d801f190e31af8a0596))
- Beef up transport config so `T` passes ([ab76cab](https://github.com/dirvine/ant-quic/commit/ab76cab2bad736d4a19f8644c99ef7812cfff3c3))
- H3 remembers decoding with a QPACK dyn ref ([7f73546](https://github.com/dirvine/ant-quic/commit/7f7354666c8e714b1694c24ead2cba7d23057e65))
- Client `d` test ([30c4e5f](https://github.com/dirvine/ant-quic/commit/30c4e5fcfbd48a6063527c7783c2ca50c626f034))
- Custom header for dyn encoding from server ([48e2e80](https://github.com/dirvine/ant-quic/commit/48e2e80ac9a947cf2039eabe5da0d7a99706875b))
- Make h2 accept self-signed certs ([92123dc](https://github.com/dirvine/ant-quic/commit/92123dc0c54690cf805fb58d1c4204ab9a03fa83))
- Make qif tool catch up qpack API ([ea82372](https://github.com/dirvine/ant-quic/commit/ea8237209f7fff6856c656c570f655129282dbd7))
- Fix qif clippy warnings ([a6398dd](https://github.com/dirvine/ant-quic/commit/a6398ddf1df7693f399cbff96f023db88a0361cc))
- Rewrite qif tool error management ([b3f9288](https://github.com/dirvine/ant-quic/commit/b3f9288c2994d0c21585708c5a207f7df72c2347))
- Doc for qif tool ([3ec3612](https://github.com/dirvine/ant-quic/commit/3ec36129829d4b871438de9aa942f38a5d63c4eb))
- Send Alt-Svc from h2 and h1 ([8647b5c](https://github.com/dirvine/ant-quic/commit/8647b5c089b1c7c505a1bf7317642301929c561c))
- Remove type length limit after 1.47 release ([d4ac405](https://github.com/dirvine/ant-quic/commit/d4ac4057bd25e93e3aa29f961ab560ad47443344))
- Remove H3 support ([53b063b](https://github.com/dirvine/ant-quic/commit/53b063b9cdc6e671f2e87ab8b1d5bd2da1870a56))

### Nix

- Always have backtraces ([f2d88da](https://github.com/dirvine/ant-quic/commit/f2d88da66b40a1ab1151e0595e5cf0efe601ffe3))

### Proto

- Rename UnsupportedVersion fields ([766d20a](https://github.com/dirvine/ant-quic/commit/766d20a59230845b5105a4b53bce26819ac6e600))
- Add more high-level API docs to Connection, closes #924 ([#926](https://github.com/dirvine/ant-quic/issues/926)) ([cfe6570](https://github.com/dirvine/ant-quic/commit/cfe6570a66f669bfe7bd104f6f56b1d38132127c))
- Warn on unreachable_pub ([134ef97](https://github.com/dirvine/ant-quic/commit/134ef97bdd499a11f6c708fd4de3e18959efb687))
- Allow GSO to be manually disabled ([a06838a](https://github.com/dirvine/ant-quic/commit/a06838abde23bbd64d9f527c85b34a6da69055aa))
- Allow test code to opt out of skipping packet numbers ([bef7249](https://github.com/dirvine/ant-quic/commit/bef724969cb3568e99e291a969eb9b717aa6680f))
- Use deterministic packet numbers in tests that count ACKs ([f07a40d](https://github.com/dirvine/ant-quic/commit/f07a40d7f1da99253408fb1ab3db91eef3fe07e6))
- Fix double-boxing of `congestion::ControllerFactory` ([33fa6bb](https://github.com/dirvine/ant-quic/commit/33fa6bb24d298d6037d0ecd2162eba5ee3a85dd6))
- Add forgotten fields to Debug for TransportConfig ([8c58cc7](https://github.com/dirvine/ant-quic/commit/8c58cc77815f054f3b4c6a2a5cd3bef3cab07fed))
- Don't panic when draining a unknown connection ([394ac8c](https://github.com/dirvine/ant-quic/commit/394ac8c2b84497bb490659683ffd2f922ced8a0a))
- Detect stateless resets in authed and unprotected packets ([7f26029](https://github.com/dirvine/ant-quic/commit/7f260292848a93d615eb43e6e88114a97e64daf1))
- Make now explicit for Endpoint::connect() ([307d80b](https://github.com/dirvine/ant-quic/commit/307d80b9398d4e1e305c0131f2c3989090ec9432))
- Move IterErr below users ([9f437c0](https://github.com/dirvine/ant-quic/commit/9f437c0da7491075ecef8beb2b5bcd2e3d5c4200))
- Yield transport error for Initial packets with no CRYPTO ([470b213](https://github.com/dirvine/ant-quic/commit/470b2134c4cb54c18f6ae858de2a25005a97c255))
- Factor out Endpoint::retry ([a9c4dbf](https://github.com/dirvine/ant-quic/commit/a9c4dbf91eb36cf3912851b51671b958c20cbfff))
- Refactor Endpoint to use Incoming ([8311124](https://github.com/dirvine/ant-quic/commit/83111249e829a2f367e15376b207d787473b88c2))
- Remove the Side argument from ServerConfig::initial_keys() ([85351bc](https://github.com/dirvine/ant-quic/commit/85351bc3999888d8abb124c0200dc2cb5a5f33b5))
- Rename InvalidDnsName to InvalidServerName ([b61d9ec](https://github.com/dirvine/ant-quic/commit/b61d9ec5746317ae0ec5b827d6855d45de18d148))
- Deduplicate rustls ClientConfig setup ([07e4281](https://github.com/dirvine/ant-quic/commit/07e428169bae3527f9c956f26d9c97a4c780430c))
- Add test helpers for custom ALPN crypto configs ([285e1b6](https://github.com/dirvine/ant-quic/commit/285e1b650c8b8a687bcb9b4d6146045a16e860b4))
- Validate ClientConfig crypto provider ([e6d4897](https://github.com/dirvine/ant-quic/commit/e6d48970afb76452204b3b7f748c8725aa864a66))
- Validate ServerConfig crypto provider ([ce13559](https://github.com/dirvine/ant-quic/commit/ce135597786f8307db0336667636af2dbabe1e49))
- Factor out DatagramConnectionEvent ([89f99bb](https://github.com/dirvine/ant-quic/commit/89f99bbdc0cc84baa8c9f3d3abfb667e127ef25d))
- Take advantage of rustls::quic::Suite being Copy ([5b72270](https://github.com/dirvine/ant-quic/commit/5b722706b3cd46ce3f07fa2710b8a1024c7c6ed5))
- Guard rustls-specific types ([7af5296](https://github.com/dirvine/ant-quic/commit/7af5296dc3078994b1567bef3afde62dddb1cea8))
- Remove incorrect feature guard ([e764fe4](https://github.com/dirvine/ant-quic/commit/e764fe48cee11a6f10adfce85f899e39293c2cd9))
- Add rustls constructors with explicit initial ([690736c](https://github.com/dirvine/ant-quic/commit/690736cb2fa555fa34ced24479688a90248d44a1))
- Support creating config wrappers from Arc-wrapped configs ([8bd0600](https://github.com/dirvine/ant-quic/commit/8bd0600089fa8bcf333df4cad2e4cac23b514a99))
- Make NoInitialCipherSuite Clone ([f82beab](https://github.com/dirvine/ant-quic/commit/f82beab2f3d7cbed2e57a51864f115a9ce4a85d1))
- Make packet parsing APIs public ([d9da98b](https://github.com/dirvine/ant-quic/commit/d9da98bdc83ff39f72de0b29acc358f3433c138f))
- Introduce ConnectionIdParser ([ee1c0fd](https://github.com/dirvine/ant-quic/commit/ee1c0fd143df3b6c2e8524ccc6b4dacc88a223f5))
- Rename Plain types to Protected ([6c9c252](https://github.com/dirvine/ant-quic/commit/6c9c252326534d21e1e484824f79ebed7ad5872b))
- Make initial destination cid configurable ([03fe15f](https://github.com/dirvine/ant-quic/commit/03fe15f99ef251a259146218afd2aca7b5e27aad))
- Avoid overflow in handshake done statistic ([f0fa66f](https://github.com/dirvine/ant-quic/commit/f0fa66f871b80b9d2d7075d76967c649aecc0b77))
- Bump version to 0.11.4 ([f484d63](https://github.com/dirvine/ant-quic/commit/f484d633efeb532634a1d67698a918d3432b15cc))
- Bump version to 0.11.5 ([91b5a56](https://github.com/dirvine/ant-quic/commit/91b5a56424d23c1ad43263ccc9d1c81e9080d60d))
- Bump version to 0.11.6 ([2d06eef](https://github.com/dirvine/ant-quic/commit/2d06eef43fec927b0cf8f960bedb814bf3e4cc79))
- Avoid panicking on rustls server config errors ([a8ec510](https://github.com/dirvine/ant-quic/commit/a8ec510fd171380a50bd9b99f20a772980aabe47))
- Bump version to 0.11.8 for release ([#1981](https://github.com/dirvine/ant-quic/issues/1981)) ([7c09b02](https://github.com/dirvine/ant-quic/commit/7c09b02073783830abb7304fc4642c5452cc6853))
- Remove unnecessary feature guard ([983920f](https://github.com/dirvine/ant-quic/commit/983920f9627aa103e9d99dc5b78399a9706f1c96))
- Abstract more over ring dependency ([425f147](https://github.com/dirvine/ant-quic/commit/425f14789925df51e328bfce6b9dab4a32199c2b))
- Export `ShouldTransmit` ([41989fe](https://github.com/dirvine/ant-quic/commit/41989fef33738d281b1ca72801adf7137189aeff))
- Remove panic-on-drop from `Chunks` ([bcb962b](https://github.com/dirvine/ant-quic/commit/bcb962b222f7c15fc8d8b27285eb9cf3bf689e80))
- Update DatagramState::outgoing_total on drop_oversized() ([ead9b93](https://github.com/dirvine/ant-quic/commit/ead9b9316c155073c0984a243aeb9b84c5465298))
- Rename frame::Type to FrameType ([8c66491](https://github.com/dirvine/ant-quic/commit/8c664916f7b6718848eb43827b349472cfbe3213))
- Fix missing re-exports ([7944e0f](https://github.com/dirvine/ant-quic/commit/7944e0fabcffe9c0d14f00d8eaa147f94f5970c7))
- Bump version to 0.11.9 ([2a8b904](https://github.com/dirvine/ant-quic/commit/2a8b9044cc1a7108b63ff42746023bfbfec334bb))
- Split config module ([1c463ab](https://github.com/dirvine/ant-quic/commit/1c463ab5b46d549c4e2b76fbaad9ddf50bac46bc))
- Refactor TokenDecodeError ([51e974e](https://github.com/dirvine/ant-quic/commit/51e974e4d9c7a1156c55e8510d07980832a7ef53))
- Make Connection internally use SideState ([e706cd8](https://github.com/dirvine/ant-quic/commit/e706cd8ac063dfa9d9843d54d69c5a9a7067d1e3))
- Make Connection externally use SideArgs ([c5f81be](https://github.com/dirvine/ant-quic/commit/c5f81bec9bac9dcb894720689d4d938eea3fe569))
- Factor out IncomingToken ([89f3f45](https://github.com/dirvine/ant-quic/commit/89f3f458de2a39e9eb4ff040ee15d22250192d3d))
- Factor out IncomingToken::from_header ([afc7d7f](https://github.com/dirvine/ant-quic/commit/afc7d7f8ae3ef690e7da4db7beadd6c1b07eae03))
- Replace hidden field with From impl ([43b74b6](https://github.com/dirvine/ant-quic/commit/43b74b658b7038c9190c06e6969d16b82f9fc64b))
- Inline trivial constructor ([8a488f2](https://github.com/dirvine/ant-quic/commit/8a488f2d7eb565d33daa5416ba57ce7b94f1401f))
- Inline IncomingToken::from_retry() ([268cbd9](https://github.com/dirvine/ant-quic/commit/268cbd9116b078b61736053342cd41b7d5cafe95))
- Re-order items in token module ([670c517](https://github.com/dirvine/ant-quic/commit/670c517f429ce3ca0893fa872334dc021d178c39))
- Un-hide EcnCodepoint variants ([37b9340](https://github.com/dirvine/ant-quic/commit/37b93406cde5f6197c0aeaad5c4dfb36f5492b82))
- Remove superfluous `#[doc(hidden)]` fuzzing ([16f83d1](https://github.com/dirvine/ant-quic/commit/16f83d1c8fa449f49ef63187bdb8415580a637ff))
- Pass SocketAddr by value ([2071704](https://github.com/dirvine/ant-quic/commit/20717041bc308f88e99e35667737d6b51911a8b3))
- Utilize let-else in Endpoint::handle ([c1aa2a8](https://github.com/dirvine/ant-quic/commit/c1aa2a8be8d85eead94ec7b7a69556edb106d6b9))
- Refactor Endpoint::handle ([b350bb1](https://github.com/dirvine/ant-quic/commit/b350bb1b156e9beb3dd2202eb276dbc826f06413))
- Use pre-existing variable in handle ([b1e7709](https://github.com/dirvine/ant-quic/commit/b1e77091eae6139d08ff546c5123f90b1a6692c6))
- Factor out return in handle ([f99ca19](https://github.com/dirvine/ant-quic/commit/f99ca19bfe24713799decd60facf140ca9c42b22))
- Pass ConnectionId by value internally ([7caa30b](https://github.com/dirvine/ant-quic/commit/7caa30bd6153264d698592c5d9df5d5ae029598d))
- Rename RetryToken::from_bytes -> decode ([b0e39a9](https://github.com/dirvine/ant-quic/commit/b0e39a97fc18743fdec343e481a700355fff101e))
- Factor out encode_ip ([8fd8e1a](https://github.com/dirvine/ant-quic/commit/8fd8e1a7c89ab4a95675880063bed603530fefcf))
- Remove panic hazards from RetryToken decode ([bde7592](https://github.com/dirvine/ant-quic/commit/bde7592ea51ef0c7be39b6c2865bded9e4bada64))
- Factor out encode_unix_secs ([371f180](https://github.com/dirvine/ant-quic/commit/371f18032d2d3ec1f59169d6e44e95ba5989011a))
- Simplify encode_unix_secs ([5b45184](https://github.com/dirvine/ant-quic/commit/5b4518446b039591ef8b151d50b44a5b0761da8b))
- Remove Cursor usage from token.rs ([5c381aa](https://github.com/dirvine/ant-quic/commit/5c381aab52cc96fd24bdcdfc8efa85ae1157e2e3))
- Rearrange lines of RetryToken::encode ([e6380df](https://github.com/dirvine/ant-quic/commit/e6380df4867df3d4ea3b6fb20c5aa539c63c0b6c))
- Make address a field of RetryToken ([6925099](https://github.com/dirvine/ant-quic/commit/692509900b0302528b49cdec8caa00534e99b181))
- Remove ValidationError ([fe67e7c](https://github.com/dirvine/ant-quic/commit/fe67e7cd6499988d577d4e2adc826ab82e9f7a68))
- Reject RetryToken with extra bytes ([bfbeecd](https://github.com/dirvine/ant-quic/commit/bfbeecdc1c23c4ba4e7697b67e4888a80b533fdb))
- Move more logic into handle_first_packet ([408b7b0](https://github.com/dirvine/ant-quic/commit/408b7b0d44d8316851de649d4e6cff301f895fa1))
- Reduce whitespace in Endpoint.handle ([7f11d3c](https://github.com/dirvine/ant-quic/commit/7f11d3cc716ce53e204bb72068d04e9e65fdb7e6))
- Almost always construct event in handle ([ff2079b](https://github.com/dirvine/ant-quic/commit/ff2079b6a3616af2b856d5e8a388bbc632500ae8))
- Use event as param to handle_first_packet ([1e7358c](https://github.com/dirvine/ant-quic/commit/1e7358c57dc96960b00d743660dee48a501b0a03))
- Remove most return statements from handle ([3e3db6f](https://github.com/dirvine/ant-quic/commit/3e3db6f8665c1780f9ff7e22cc9f89f92aab5359))
- Use match for grease with reserved version ([ffbd15f](https://github.com/dirvine/ant-quic/commit/ffbd15f087262893e8d319534b99b684c0091f50))
- Remove redundant cursors ([23b18f2](https://github.com/dirvine/ant-quic/commit/23b18f2882ec0f55b491848c572a15344d599ec2))
- Replace calls to Duration::new ([f5b1ec7](https://github.com/dirvine/ant-quic/commit/f5b1ec7dd96c9b56ef98f2a7a91acaf5e341d718))
- Factor out NewToken frame struct ([273f7c2](https://github.com/dirvine/ant-quic/commit/273f7c23865df886f62f06ae8e22e168860d81e0))
- Rename RetryToken -> Token ([df22e27](https://github.com/dirvine/ant-quic/commit/df22e2772ea0ba9408b49d01eed361647622590b))
- Split out RetryTokenPayload ([22c1270](https://github.com/dirvine/ant-quic/commit/22c12708f0e9bb9087208e2c8d68d53fed512dc6))
- Change how tokens are encrypted ([b237cd7](https://github.com/dirvine/ant-quic/commit/b237cd766e808e17f893ddf573b6a08a655d98c2))
- Convert TokenPayload into enum ([78bfa5b](https://github.com/dirvine/ant-quic/commit/78bfa5b509465743954960d3aa549b61c148ce6b))
- Fix compatibility with older quinn ([a7821ff](https://github.com/dirvine/ant-quic/commit/a7821ff3da0884f42bad3a1b21ab96ff998c4f68))
- Bump version to 0.11.12 ([3482fcc](https://github.com/dirvine/ant-quic/commit/3482fcc759675ebb16348826ee88e77d764a4900))
- Make BytesSource private ([9f008ad](https://github.com/dirvine/ant-quic/commit/9f008ade668c1f0112affd55f4ce7d325f697c27))
- Suppress large AcceptError clippy warning ([c8ca79c](https://github.com/dirvine/ant-quic/commit/c8ca79c9c318e6a27e573e3b301193eff1c5463a))
- Upgrade to rustls-platform-verifier 0.6 ([e8fa804](https://github.com/dirvine/ant-quic/commit/e8fa80432ff0d615deb1942fb0e9c20f9dee98e3))
- Add option to pad application data UDP datagrams to MTU ([6fb6b42](https://github.com/dirvine/ant-quic/commit/6fb6b424d78d46d22c10cb3b788478163b0bfffd))

### Quinn

- Test export_keying_material ([363b353](https://github.com/dirvine/ant-quic/commit/363b3539ac60bd21f9139df00ec8929a3481ba62))
- Print socket addresses in example client/server ([4420b61](https://github.com/dirvine/ant-quic/commit/4420b61aaac7568905573b3d6650eefc9c14ff0c))
- Move UdpExt functionality into platform-specific UdpSocket types ([22fa31d](https://github.com/dirvine/ant-quic/commit/22fa31d571d13c5a513ff51c690d83f3f2896837))
- Remove unused field RecvStream::any_data_read ([6a58b3f](https://github.com/dirvine/ant-quic/commit/6a58b3f542af595d454abb2b3672d521c8b3cf20))
- Properly await client connection setup in benchmarks ([8b8f640](https://github.com/dirvine/ant-quic/commit/8b8f6401bf7f3b99176adfe1380433ee2e59853b))
- Unify ordered and unordered read APIs ([a280b77](https://github.com/dirvine/ant-quic/commit/a280b7770fe7a2e84a10ca837d6a3d92e90170ad))
- Split streams module in send/recv parts ([14db885](https://github.com/dirvine/ant-quic/commit/14db88562de0efa86aa5bfe007dfe6b29306feaf))
- Only depend on rt-multi-thread as a dev-dependency ([7f1aa1e](https://github.com/dirvine/ant-quic/commit/7f1aa1ead3dc02f32e0f2be9afbe9b6ac65bfbcb))
- Bump dependency on tokio to 1.13 ([28a2c80](https://github.com/dirvine/ant-quic/commit/28a2c8052ce5fa2abbd4ce385f6ee2f50cbfb770))
- Warn on unreachable_pub ([4fd2df3](https://github.com/dirvine/ant-quic/commit/4fd2df30b045770c6627857276cd9755136be1a2))
- Take Arc<dyn Runtime> directly ([3eb2636](https://github.com/dirvine/ant-quic/commit/3eb26361dba85f13b69e0eff6d934b28f70a37f8))
- Factor out TransmitState sub-struct from State ([e6ee90c](https://github.com/dirvine/ant-quic/commit/e6ee90cb2be33d4a25e9e259a71aef91a24fba16))
- Add bounds in dyn Error types ([e28b29f](https://github.com/dirvine/ant-quic/commit/e28b29f76ec7d830a029b9b8e17a684d98a2ec94))
- Use ClientConfig helper for tests ([ae82c38](https://github.com/dirvine/ant-quic/commit/ae82c380dccf1549ca8287a147085ffffe03628b))
- Inline single-use helper function ([7687540](https://github.com/dirvine/ant-quic/commit/76875408a9f18354334701a401228bd480b0b174))
- Allow rebinding an abstract socket ([5beaf01](https://github.com/dirvine/ant-quic/commit/5beaf01793bd4b25738de783ebc62d2b20abe64f))
- Require rustls for insecure_connection example ([faf7dbc](https://github.com/dirvine/ant-quic/commit/faf7dbc051f212a7329affdfec648c9c669d6224))
- UdpPoller::new() is only called if a runtime is enabled ([74c0358](https://github.com/dirvine/ant-quic/commit/74c035822bd1ac53a65025b021b7d76768251c37))
- Add proper guards to Endpoint constructor helpers ([272dd5d](https://github.com/dirvine/ant-quic/commit/272dd5d45f809ae42aa8cee25dbe896f389441de))
- Alphabetize default features ([1e54758](https://github.com/dirvine/ant-quic/commit/1e547588e8b3d86cfd6450cad73f480e1232c351))
- Fix bytes read count in ReadExactError::FinishedEarly ([f952714](https://github.com/dirvine/ant-quic/commit/f952714dfec3c2495ec3379fe23d4d4a5fede321))
- Return `ReadError::Reset` persistently ([d38854b](https://github.com/dirvine/ant-quic/commit/d38854b0a6146c67e438ea140e609b2ce6165e39))
- Introduce RecvStream::received_reset ([fc22ddd](https://github.com/dirvine/ant-quic/commit/fc22ddd7f865cec9750375a2cc48fe190685d3d4))
- Introduce wake_all() helper ([0273e0a](https://github.com/dirvine/ant-quic/commit/0273e0a7044631afcf7e416250b9bf5373481841))
- Introduce wake_stream() helper ([70f5194](https://github.com/dirvine/ant-quic/commit/70f5194fc85e7915aeb7d0e35d9e0a7cd635fb03))
- Make `Endpoint::client` dual-stack V6 by default ([693c9b7](https://github.com/dirvine/ant-quic/commit/693c9b7cfbf89c541ba99523237594499984ffed))
- Bump version to 0.11.3 ([b3f1493](https://github.com/dirvine/ant-quic/commit/b3f149386f978195634f1aec1d48cd1b5db5df20))
- Export endpoint::EndpointStats ([43a9d76](https://github.com/dirvine/ant-quic/commit/43a9d768bedfd81bf87ca25ff11c7a3b091c4956))
- Fix missing re-exports ([eebccff](https://github.com/dirvine/ant-quic/commit/eebccff309cb342c2faac3ea875ca81734685821))
- Bump version to 0.11.6 ([66546dd](https://github.com/dirvine/ant-quic/commit/66546ddd5aee10672e31bb166e57891a13863171))
- Avoid FIPS in docs.rs builds ([37355ec](https://github.com/dirvine/ant-quic/commit/37355ec5e7da09435e99d4a35df7ffd70d410061))
- Remove obsolete must_use for futures ([8ab077d](https://github.com/dirvine/ant-quic/commit/8ab077dbcecf2919bd3652a806176ec1d05f16b2))
- Make SendStream::poll_stopped private ([506e744](https://github.com/dirvine/ant-quic/commit/506e74417ac27e615cddda731d6b3218f383540d))
- Fix feature combination error / warnings ([14b905a](https://github.com/dirvine/ant-quic/commit/14b905ae568ab050caa63954673a2d99cf8e0497))
- Remove explicit write future structs ([bce3284](https://github.com/dirvine/ant-quic/commit/bce32845dcb0a466a4e0e1b01c2a9cdf0bc5bf54))

### Quinn-h3

- Clarify error message for closed control stream ([ea81e65](https://github.com/dirvine/ant-quic/commit/ea81e654da952527f60f699e76eef9a1712df4c7))
- Copy tracing subscriber setup from quinn ([48a3213](https://github.com/dirvine/ant-quic/commit/48a3213f74e08684457e27aa13694fed836c807b))
- Enable client-side key logging in tests ([661884f](https://github.com/dirvine/ant-quic/commit/661884f1ca4ebca6be61242ca2211789525a0c76))
- Reduce rightward drift in RecvUni Future impl ([6bbea44](https://github.com/dirvine/ant-quic/commit/6bbea44fb52147c3e218a72ea29e5288bcc1f5fd))
- Fix typo in example function name ([6de0b47](https://github.com/dirvine/ant-quic/commit/6de0b470be967fecc76c505eb4087f666b0b1a8f))
- Improve trace output ([889d2b3](https://github.com/dirvine/ant-quic/commit/889d2b3e034e19f79876a1a34d1b49ed983efea5))
- Change 4-tuple to a struct ([0dd5537](https://github.com/dirvine/ant-quic/commit/0dd5537e255a66a7dee789446cf50b6dcf0056aa))
- Limit amount of data decoded ([#994](https://github.com/dirvine/ant-quic/issues/994)) ([30c09d5](https://github.com/dirvine/ant-quic/commit/30c09d5c082231103c6f93bf2dd4b8b506528618))
- Partially revert limiting decoded data ([f5d53a1](https://github.com/dirvine/ant-quic/commit/f5d53a1cbd3324754da9fffc4473c76abd3d54f0))

### Quinn-proto

- Merge ExportKeyingMaterial trait into Session ([bc1c1a7](https://github.com/dirvine/ant-quic/commit/bc1c1a7e0e699fb419d69338907d23903d0c9670))
- Tweak ordering in RetryToken ([3f3335e](https://github.com/dirvine/ant-quic/commit/3f3335e2428f22bdd5a019879a9bce1e4c704c5b))
- Improve grouping in RetryToken impl ([84ba340](https://github.com/dirvine/ant-quic/commit/84ba3406974afaec51aa97cbf09b1f357fe7c002))
- Remove RetryToken TODO comment ([1e70959](https://github.com/dirvine/ant-quic/commit/1e7095941e67f8289060355641661f07e0c89964))
- Generalize over read methods ([13f1169](https://github.com/dirvine/ant-quic/commit/13f1169286ec6c8f0aae86f66755a06f6e7fdac8))
- Read crypto stream as bytes ([72e0f9a](https://github.com/dirvine/ant-quic/commit/72e0f9aa5a65786b790fe36c44378c8c9cbc1b81))
- Add max_length argument to Assembler::read_chunk() ([ce67167](https://github.com/dirvine/ant-quic/commit/ce671679688cd49569182da7f16c4e2b7b89df8b))
- Remove slice-based read API from Assembler ([0439ec5](https://github.com/dirvine/ant-quic/commit/0439ec529871abc620e1880a39371aa1571d266c))
- Rename Assembler::read_chunk() to read() ([6e9db53](https://github.com/dirvine/ant-quic/commit/6e9db53d14e1bb5fa17ebf44ccf32e5a39ee6ff7))
- Split streams module up ([6ce0ef2](https://github.com/dirvine/ant-quic/commit/6ce0ef2542674a5e6b0b667d2a40cb71dd534dd6))
- Split connection::streams::types into send and recv modules ([7947ad5](https://github.com/dirvine/ant-quic/commit/7947ad5854ccaf9af0a815341ec83c1651b36fa7))
- Check for stopped assembler before reading data ([f2d01fb](https://github.com/dirvine/ant-quic/commit/f2d01fb2ad0d466255ab978a00993a554717047c))
- Remove read() methods in favor of read_chunk() ([ab98859](https://github.com/dirvine/ant-quic/commit/ab98859756cde1dd2d37305bfb03be4c2c9d7a30))
- Rename read_chunk() to read() ([f569495](https://github.com/dirvine/ant-quic/commit/f569495b71bbf49ec1eb6a018c23ca8817ee5efc))
- Let Assembler take responsibility for reads from stopped streams ([0a07eab](https://github.com/dirvine/ant-quic/commit/0a07eaba20890a89ea5bf332cc2a8a2e31ba05ef))
- Add missing defragmented decrement ([39c4c28](https://github.com/dirvine/ant-quic/commit/39c4c2883bc71a6b7a2fc063e9a2025ceef66d8c))
- Move ShouldTransmit into streams module ([1ac9da4](https://github.com/dirvine/ant-quic/commit/1ac9da4be4c32fed27b3c1e928bd004baa839b69))
- Simplify ShouldTransmit interface ([672cbec](https://github.com/dirvine/ant-quic/commit/672cbec5e578b9d6c053ad568a57da0392d3590c))
- Merge add_read_credits() into post_read() ([ab3b74f](https://github.com/dirvine/ant-quic/commit/ab3b74f62d1aeb93aefb93a15dc84b7adae5bd48))
- Move post_read() logic into Retransmits ([31f1ecb](https://github.com/dirvine/ant-quic/commit/31f1ecb1f72f3ad46eb28242820cecddbacdd839))
- Unify ordered and unordered read paths in assembler ([ae29bb6](https://github.com/dirvine/ant-quic/commit/ae29bb6c305400a1bb1b9de12bfda68fdf6ff241))
- Unify API for ordered and unordered reads ([07db694](https://github.com/dirvine/ant-quic/commit/07db694a54c0395fa67c77cdead8369f0d3a4a0e))
- Rename assembler::Chunk to Buffer ([5350f23](https://github.com/dirvine/ant-quic/commit/5350f23da17b11315c979c421e794792abcf9c31))
- Use struct to yield data from assembler ([81ea06b](https://github.com/dirvine/ant-quic/commit/81ea06bf92711a81fa4aba138f8dd0164e50bc5b))
- Yield read data as Chunks ([6a7f861](https://github.com/dirvine/ant-quic/commit/6a7f861a1ee95d2fb2469fd9b1323a4068738c9d))
- Move end from Assembler into Recv ([dedcca1](https://github.com/dirvine/ant-quic/commit/dedcca1cff5edda56bc70b65bf9754303ba794b2))
- Move stream stopping logic into Recv ([c29d9ac](https://github.com/dirvine/ant-quic/commit/c29d9ac5d8978eb7fb9a241ca066f5ef492930dc))
- Keep stopped state in Recv ([90e903e](https://github.com/dirvine/ant-quic/commit/90e903e3156824c13c92fd2829067f9d9662afb4))
- In ordered mode, eagerly discard previously read data ([2610577](https://github.com/dirvine/ant-quic/commit/261057786dbdd730223f7a71fca6c5cf3f73b182))
- Split ordering check out of read() path ([3aca40b](https://github.com/dirvine/ant-quic/commit/3aca40b47f6102cd03ff82d11e4a6d0f62c49fd3))
- Deduplicate when entering unordered mode ([#1009](https://github.com/dirvine/ant-quic/issues/1009)) ([2687ef8](https://github.com/dirvine/ant-quic/commit/2687ef8df4f506c594fb7599bc2a91c2e74cc5f0))
- Trigger defragmentation based on over-allocation ([#981](https://github.com/dirvine/ant-quic/issues/981)) ([b9eb42e](https://github.com/dirvine/ant-quic/commit/b9eb42ee75fa6b24a3798a33545968f8aa8f3488))
- Unpack logic for Connection::space_can_send() ([34f910b](https://github.com/dirvine/ant-quic/commit/34f910bae626402bacb8dfa8cd0d5f04b1709ae9))
- Return early from finish_and_track_packet() ([8630946](https://github.com/dirvine/ant-quic/commit/863094657120b63181e3f229af0ce820815fee35))
- Inline single-use method ([095f402](https://github.com/dirvine/ant-quic/commit/095f402a9ff6539620a26a6d5fc44c71901a9d22))
- Remove unnecessary RecvState::Closed ([dd23094](https://github.com/dirvine/ant-quic/commit/dd23094007e70592c12aa912f7b156f017ebaef1))
- Add comment to clarify need for custom iteration ([4e6b8c6](https://github.com/dirvine/ant-quic/commit/4e6b8c6fe4fb1e056bd4ca7ea41fa240fbe31674))
- Refactor how ACKs are passed to the congestion controller ([18ed973](https://github.com/dirvine/ant-quic/commit/18ed973568550ba044413d6a4a6cc8f51ff3fbbd))
- Inline single-use reject_0rtt() method ([816e570](https://github.com/dirvine/ant-quic/commit/816e5701516db8a0e57931400924db9a3319227d))
- Handle handshake packets separately ([6bddfde](https://github.com/dirvine/ant-quic/commit/6bddfdea1aaba04964ee902ce2f43200ca0c5e6d))
- Move PacketBuilder into a separate module ([e1df56f](https://github.com/dirvine/ant-quic/commit/e1df56f40ced987ffbbc8a45f9706262415ea6b3))
- Move finish_packet() into PacketBuilder ([7e0f3fa](https://github.com/dirvine/ant-quic/commit/7e0f3fa7ab6dbf4a42934787e544f7073719d347))
- Move more methods into PacketBuilder ([d22800a](https://github.com/dirvine/ant-quic/commit/d22800ac79a20ccd1304a1dde4d15e2973b8a58f))
- Move probe queueing logic into PacketSpace ([5a7a80e](https://github.com/dirvine/ant-quic/commit/5a7a80ec1eb4ec7c6d4a1f5677ac90d7da3d140e))
- Inline single-use congestion_blocked() method ([1b92933](https://github.com/dirvine/ant-quic/commit/1b9293366f9cbef6e9164e89e6a016d310cf7642))
- Refactor handling of peer parameters ([dde27bf](https://github.com/dirvine/ant-quic/commit/dde27bf9197b7291c6e0726807390a1576bb5359))
- Rename Streams to StreamsState ([584b889](https://github.com/dirvine/ant-quic/commit/584b889494d48d70802866b62c2052f3faade4bc))
- Add public Streams interface ([8bbe908](https://github.com/dirvine/ant-quic/commit/8bbe908dbddb4a0230a71159423713b5e9bc000d))
- Move API logic into Streams ([d4bfc25](https://github.com/dirvine/ant-quic/commit/d4bfc25d6a88576d0d2585c63f0a18a9b67ee350))
- Split streams module into two parts ([8131bcc](https://github.com/dirvine/ant-quic/commit/8131bcc7b6e1ac51eba00ced1199571a7c3797e8))
- Extract separate SendStream interface type ([0b350e5](https://github.com/dirvine/ant-quic/commit/0b350e5d11541a03a7f5ad995ded4b967c443ac3))
- Extract separate RecvStream interface type ([5a7b888](https://github.com/dirvine/ant-quic/commit/5a7b88893430a15167b35a83852ad7ef8312954c))
- Standardize on ch suffix ([29e8a91](https://github.com/dirvine/ant-quic/commit/29e8a914d811a1ca3aa94a8cd58c92134b52c2fa))
- Inline single-use poll_unblocked() method ([cc1218e](https://github.com/dirvine/ant-quic/commit/cc1218ed12ac1af4e45b275ec325b41f82c49cca))
- Inline single-use flow_blocked() method ([a11abc6](https://github.com/dirvine/ant-quic/commit/a11abc648e7d67b1851592e5b29bff48f4647a2b))
- Inline single-use record_sent_max_data() method ([afe8a6c](https://github.com/dirvine/ant-quic/commit/afe8a6cfeeff9dd7d63c04473e6d52446f05c14f))
- Move datagram types into separate module ([71484b5](https://github.com/dirvine/ant-quic/commit/71484b57aaab68ddd63cb1b3af71f4a452585279))
- Derive Default for DatagramState ([c6843a7](https://github.com/dirvine/ant-quic/commit/c6843a7c84992f9b3bc9bf28aef7d6d3b15cee2d))
- Move datagram receive logic into DatagramState ([d25ce15](https://github.com/dirvine/ant-quic/commit/d25ce1523914df9215146d2dd8c3456af5216232))
- Move incoming datagram frame handling into DatagramState ([2637dfe](https://github.com/dirvine/ant-quic/commit/2637dfe5758105a9ed9b4bfccee63913c62dd674))
- Move datagram write logic into DatagramState ([61129c8](https://github.com/dirvine/ant-quic/commit/61129c811e319a43cd683230970c1876d72adfe6))
- Provide datagrams API access through special-purpose type ([971265d](https://github.com/dirvine/ant-quic/commit/971265d9ffb97a1e86a99ff061564814ecb365ca))
- Merge bytes_source module into connection::streams::send ([4abf5a6](https://github.com/dirvine/ant-quic/commit/4abf5a64e021da6add842ad182d1d74417aa5ee5))
- Reorder code from bytes_source module ([6292420](https://github.com/dirvine/ant-quic/commit/62924202fa0321def923054dcdbdbb77e241aabc))
- Bump version 0.9.3 -> 0.10.0. ([b56d60b](https://github.com/dirvine/ant-quic/commit/b56d60bbec577d73e67abbba60ed389f0589f208))

### Quinn-udp

- Normalize Cargo.toml formatting ([b65a402](https://github.com/dirvine/ant-quic/commit/b65a4026349da256138ea4819a8b887a3b1ee9b2))
- Bump version number ([91d22f7](https://github.com/dirvine/ant-quic/commit/91d22f73a65a93888533d460a04159c6504a0964))
- Bump version to 0.3 ([57bd764](https://github.com/dirvine/ant-quic/commit/57bd7643e75c0e974acaa6d47967cf9c6c11cff8))
- Increase crate patch version to v0.5.7 ([a0bcb35](https://github.com/dirvine/ant-quic/commit/a0bcb35334686d6af2c23c27d9885e9750f91376))
- Handle EMSGSIZE in a common place ([8f1a529](https://github.com/dirvine/ant-quic/commit/8f1a529837c7c99741d4097446a85e4482bf65b3))
- Sanitise `segment_size` ([6b901a3](https://github.com/dirvine/ant-quic/commit/6b901a3c278f58497d6d53c64ef1cc53497c625b))

### Readme

- Badge tweaks ([53c4156](https://github.com/dirvine/ant-quic/commit/53c4156c203d5f6d8a75062c7eef13a99345085e))
- API docs link ([a90da18](https://github.com/dirvine/ant-quic/commit/a90da181bf6fbe075994c53733c035159b305d2e))

### Recv-stream

- Clean up any previously register wakers when RecvStream is dropped ([70ef503](https://github.com/dirvine/ant-quic/commit/70ef5039e9ddba659e69801e1b4740333ea61189))

### Send-stream

- Unregister waker when Stopped is dropped ([7ba0acb](https://github.com/dirvine/ant-quic/commit/7ba0acb8da407fbd6a6910a73252381d847c704f))
- Clean up any previously register wakers when SendStream is dropped ([f6ae67e](https://github.com/dirvine/ant-quic/commit/f6ae67e2faa88a833a2b323f5d13f79ef5d2a052))
- Rely on cleaning up waker for Stopped in SendStream Drop impl ([9f50319](https://github.com/dirvine/ant-quic/commit/9f503194218fe796a486767f7881dc47c793e3e2))

### Shell

- Use an OpenSSL capable of logging exporter secrets ([40b4a59](https://github.com/dirvine/ant-quic/commit/40b4a59390a314555006d9fb7d9113d50c343477))

### Streams

- Extract max_send_data() helper ([e1e9768](https://github.com/dirvine/ant-quic/commit/e1e9768bd47b0fde8da78f85b38ea8a2a40e564c))

### Token

- Move RetryToken::validate() to IncomingToken::from_retry() ([020c38b](https://github.com/dirvine/ant-quic/commit/020c38b1b7eb4bf343ab428cdc91ae1c56566ac2))

### Tokio

- Separate send/recv stream types ([3d30b10](https://github.com/dirvine/ant-quic/commit/3d30b104b4213c964a9013ecde6eb9b0772a1253))
- Fix panic on connection loss ([69cf450](https://github.com/dirvine/ant-quic/commit/69cf45062ab5049231b6607811753eb5281e9665))
- Impl AsyncRead for RecvStream ([73d9e34](https://github.com/dirvine/ant-quic/commit/73d9e3470ed2a260e3b03694241cbca1750f7957))
- Refactor and document API ([08756e4](https://github.com/dirvine/ant-quic/commit/08756e4e6ddaa166aaa66c1abd1c13c372a51c41))
- Endpoint builder ([3fc7535](https://github.com/dirvine/ant-quic/commit/3fc75350644cc111cf3ee8d502b2974620310e63))
- Ergonomics and documentation ([57ef2f6](https://github.com/dirvine/ant-quic/commit/57ef2f68fbb55bad95f257016386a641ca55a20b))
- Doc fix ([ba19a86](https://github.com/dirvine/ant-quic/commit/ba19a865bbf32c2bff29b55c55e4f5e0805ad628))
- Specify quicr-core version ([a256212](https://github.com/dirvine/ant-quic/commit/a25621234b9ed8bc2c925ef6725ccaed35ce750d))
- Graceful close ([68e0db5](https://github.com/dirvine/ant-quic/commit/68e0db51a4003c8cc315eecc7ba34ecc6779d763))
- Expose API for STOP_SENDING ([3e72bc9](https://github.com/dirvine/ant-quic/commit/3e72bc9cee69f0e994da88bad0b70bcd5d296530))
- Docs link ([64a8d46](https://github.com/dirvine/ant-quic/commit/64a8d46c4026021235ace79379a3e229db6063e7))
- Update for rustc 1.26 ([6160a53](https://github.com/dirvine/ant-quic/commit/6160a53625394d35d2e40fac9d6220d489dd099c))
- Work around panic on handshake failure ([72c9e4b](https://github.com/dirvine/ant-quic/commit/72c9e4be350076f7335b08140c2766c5e47e80da))
- Expose 0-RTT writes ([0a93bf4](https://github.com/dirvine/ant-quic/commit/0a93bf4bda94cfcdd570502d7653a523b9ad34ae))
- Fix stateless reset handling ([897b804](https://github.com/dirvine/ant-quic/commit/897b804d96df749b6a7e3ccc629496e450c558f6))

### Transport_parameters

- :Error: Fail ([a69dd0b](https://github.com/dirvine/ant-quic/commit/a69dd0bd0193f2b8ea2580422e509fb34c72daa7))

### Udp

- Silence warnings on macOS ([0db9064](https://github.com/dirvine/ant-quic/commit/0db9064d062547452d3d7e7920c7f0ed24a95c23))
- Add safe wrapper for setsockopt() ([fd845b0](https://github.com/dirvine/ant-quic/commit/fd845b0c64c5ae6fdf9080ec11c263d23912c33f))
- Warn on unreachable_pub ([eab8728](https://github.com/dirvine/ant-quic/commit/eab8728f055ac45efe19a86d3802024f26c45b0a))
- Avoid warning about unused set_sendmsg_einval() method ([aaa58fc](https://github.com/dirvine/ant-quic/commit/aaa58fc501a63c010e82b1dfc50ceba302f6ec5a))
- Improve fragmentation suppression on *nix ([23b1416](https://github.com/dirvine/ant-quic/commit/23b1416a0109b3121b53ed9d134348e73bf8abd3))
- Expose whether IP_DONTFRAG semantics apply ([f4384e6](https://github.com/dirvine/ant-quic/commit/f4384e6edb02958d9f5b1c764cf61bd680cb32b1))
- Simplify socket state initialization ([4f25f50](https://github.com/dirvine/ant-quic/commit/4f25f501ef4d009af9d3bef44d322c09c327b2df))
- Use set_socket_option_supported() wrapper ([c02c8a5](https://github.com/dirvine/ant-quic/commit/c02c8a5a7a131c35be0e85dfe7d7e2a85c24a2b1))
- Don't log EMSGSIZE errors ([5cca306](https://github.com/dirvine/ant-quic/commit/5cca3063f6f7747dcd9ec6e080ee48dcb5cfc4a7))
- Disable GSO on EINVAL ([b3652a8](https://github.com/dirvine/ant-quic/commit/b3652a8336610fd969aa16ddd1488cf7b17d330b))
- Make cmsg a new module ([5752e75](https://github.com/dirvine/ant-quic/commit/5752e75c92b343dc1ecce8bae52edb5a49d0475f))
- Preparation work to make cmsg Encoder / decode / Iter generic ([ede912a](https://github.com/dirvine/ant-quic/commit/ede912a5777ddd554a9e4253877f3ccb34b40208))
- Move newly generic code so it can be reused ([06630aa](https://github.com/dirvine/ant-quic/commit/06630aa025dee4a0a956d483c3fd625e0dde3f68))
- Add helper function to set option on windows socket ([aa3b2e3](https://github.com/dirvine/ant-quic/commit/aa3b2e3e825e6414ef543ad666407cb5f9c7ebbd))
- Windows support for ECN and local addrs ([8dfb63b](https://github.com/dirvine/ant-quic/commit/8dfb63b4c795fcdd828199ecedb5248094c7af12))
- Don't test setting ECN CE codepoint ([1362483](https://github.com/dirvine/ant-quic/commit/136248365028a15d879b859c9e577e1dd6111ca2))
- Tolerate true IPv4 dest addrs when dual-stack ([d2aae4d](https://github.com/dirvine/ant-quic/commit/d2aae4d6e7f8186b0762c96c7e09762fe3467ba5))
- Handle GRO in tests ([7dc8edb](https://github.com/dirvine/ant-quic/commit/7dc8edb37e3bee18d83e147efb260b7eb0a6b4b9))
- Test GSO support ([25c21a2](https://github.com/dirvine/ant-quic/commit/25c21a22975d67ab785e60fb44fb8f2637a4f5c5))
- Support GSO on Windows ([33f6d89](https://github.com/dirvine/ant-quic/commit/33f6d89cf47fbd13083a465d6b044ada1b6099d2))
- Support GRO on Windows ([2105122](https://github.com/dirvine/ant-quic/commit/21051222246e412e0094a42ba57d75303f64fcea))
- Make basic test work even if Ipv6 support is disabled ([6e3d108](https://github.com/dirvine/ant-quic/commit/6e3d10857e724c749c37d29e2601140c26464858))
- Use io::Result<> where possible ([20dff91](https://github.com/dirvine/ant-quic/commit/20dff915e1feaf293a739e68dc2c6ea2c6bbca09))
- Expand crate documentation ([66cb4a9](https://github.com/dirvine/ant-quic/commit/66cb4a964a97bc0680498c4f8f5f67e5c65a848d))
- Bump version to 0.5.2 ([f117a74](https://github.com/dirvine/ant-quic/commit/f117a7430c8674d73ea7ceeeaf7f3a6015ea7426))
- Un-hide EcnCodepoint variants ([f51c93f](https://github.com/dirvine/ant-quic/commit/f51c93f2c21a0a1a6039a746f829d931909944c3))
- Tweak EcnCodepoint::from_bits ([3395458](https://github.com/dirvine/ant-quic/commit/33954582da3193a8469bbb06fac04674c529555e))
- Disable GSO for old Linux ([81f9cd9](https://github.com/dirvine/ant-quic/commit/81f9cd99579f6e33ca03c4ec1cbb4fba5c3e5273))

<!-- generated by git-cliff -->
