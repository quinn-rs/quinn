# Repository Guidelines

## Project Structure & Module Organization
- `src/`: Core library (QUIC, NAT traversal, crypto, metrics). CLI lives under `src/bin/` (`ant-quic`).
- `tests/`: Integration suites by duration: `quick/`, `standard/`, `long/`, plus `property_tests/`.
- `examples/`: Runnable demos (e.g., `simple_chat`, dashboard, PQC).
- `benches/`: Criterion benchmarks. `scripts/`: CI/coverage helpers. Also `.github/` workflows and `docs/`.

## Build, Test, and Development Commands
- Build optimized: `cargo build --release` or `make build` — builds binaries.
- Test all: `cargo test --all-features` or `make test` — full suite.
- Quick checks: `make quick-checks` — fmt, clippy, smoke tests for CI.
- Duration suites: `make test-quick`, `make test-standard`, `make test-long` — targeted runs.
- Run binary: `cargo run --bin ant-quic -- --listen 0.0.0.0:9000` (options: `--bootstrap host:port`, `--dashboard`).
- Run example: `cargo run --example simple_chat -- --listen 0.0.0.0:9000`.
- Coverage: `make coverage` (HTML: `make coverage-html`), quick: `make coverage-quick`.
- Lint/format: `make clippy` (treats warnings as errors) and `make fmt`.
 - Fast checks: `cargo check --all-targets`; verbose tests: `cargo test -- --nocapture`.

## Coding Style & Naming Conventions
- Language: Rust 2024; 4-space indentation; format with `cargo fmt --all`.
- Lints: `cargo clippy --all-targets -- -D warnings`. Global lint policy for library code: `cargo clippy --all-features -- -D clippy::panic -D clippy::unwrap_used -D clippy::expect_used` (optionally `-W clippy::pedantic`).
- Non-test code must not use `unwrap`, `expect`, or `panic!`; tests may use them.
- Naming: `snake_case` for functions/modules, `CamelCase` for types/traits, `SCREAMING_SNAKE_CASE` for consts. Keep modules small; place code under existing areas (e.g., `nat_traversal/`, `connection/`).
- Prefer precise errors via `thiserror` and structured logs via `tracing`.

## Testing Guidelines
- Use Rust unit tests and integration tests in `tests/`. Name clearly (e.g., `nat_traversal_api_tests.rs`, `test_observed_address_rate_limit`).
- Default to `--all-features` for CI parity; locally you may use default features for speed. Mark >5m or stress tests `#[ignore]`.
- Property tests live under `tests/property_tests/` gated by the `property_testing` feature.
- Aim for meaningful coverage; run `make coverage` before PRs that touch core logic.

## Commit & Pull Request Guidelines
- Conventional Commits required (see `cliff.toml`). Examples: `feat(nat): add punch scheduling`, `fix(frame): correct varint parse`, `test: add pqc regressions`.
- PRs must include description, rationale, linked issues, and note feature flags. Update `docs/` and `examples/` as relevant. Ensure CI is green via `make quick-checks`.

## Security & Configuration
- Run `make security` before release PRs (`cargo audit`, `cargo deny`).
- Crypto hygiene: use constant-time utils in `src/constant_time.rs`; avoid non-test `unwrap` unless invariant-proof.
- Config: see README and `src/config/` for PQC defaults and address discovery.

## Repository Independence
- ant-quic is an independent project (not a Quinn fork for contributions).
- Do not open PRs to `quinn-rs/quinn` or add it as an upstream remote.
- Contribute only to `github.com/dirvine/ant-quic` and keep API patterns consistent locally.
