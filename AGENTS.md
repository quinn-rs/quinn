# Repository Guidelines

## Project Structure & Module Organization
- `src/`: Core library (QUIC, NAT traversal, crypto, metrics) and `src/bin/` for the `ant-quic` CLI.
- `tests/`: Integration suites by duration: `quick/`, `standard/`, `long/`, plus `property_tests/`.
- `examples/`: Runnable demos (e.g., `simple_chat`, dashboard, PQC).
- `benches/`: Criterion benchmarks. `scripts/`: CI/coverage helpers. Also `.github/` workflows and `docs/`.

## Build, Test, and Development Commands
- Build (optimized): `cargo build --release` or `make build` — builds binaries.
- Test (all): `cargo test --all-features` or `make test` — full suite.
- Quick checks: `make quick-checks` — fmt, clippy, smoke tests for CI.
- Category tests: `make test-quick | test-standard | test-long` — targeted durations.
- Run example: `cargo run --example simple_chat -- --listen 0.0.0.0:9000`.
- Coverage: `make coverage` (HTML: `make coverage-html`), quick: `make coverage-quick`.
- Lint/format: `make clippy` and `make fmt` (`clippy` runs with `-D warnings`).

## Coding Style & Naming Conventions
- Language: Rust 2024; 4-space indentation; format with `cargo fmt` (see `rustfmt.toml`).
- Lints: `cargo clippy --all-targets -- -D warnings` (config in `clippy.toml`).
- Naming: `snake_case` for functions/modules, `CamelCase` for types/traits, `SCREAMING_SNAKE_CASE` for consts.
- Keep modules small; prefer existing areas (e.g., `nat_traversal/`, `connection/`).

## Testing Guidelines
- Framework: Rust unit tests + integration tests in `tests/`.
- Conventions: Descriptive names (e.g., `nat_traversal_api_tests.rs`, `test_observed_address_rate_limit`).
- Features: Prefer `--all-features` for CI parity; mark >5m with `#[ignore]` (covered by `test-long`).
- Property tests: Place under `tests/property_tests/` and gate with `property_testing`.
- Coverage: Aim for meaningful paths; run `make coverage` before PRs touching core logic.

## Commit & Pull Request Guidelines
- Commits: Conventional Commits required (see `cliff.toml`). Examples: `feat(nat): add punch scheduling`, `fix(frame): correct varint parse`, `test: add pqc regressions`.
- PRs: Provide description, rationale, and linked issues; note feature flags touched; update `docs/` and `examples/` when relevant; ensure CI is green (`make quick-checks`).

## Security & Configuration
- Security: Run `make security` before release PRs (`cargo audit`, `cargo deny`).
- Crypto hygiene: Prefer constant-time utils in `src/constant_time.rs`; avoid `unwrap` in non-test code unless invariant-proof.
- Config: See README and `src/config/` for PQC defaults and address discovery.

