# Repository Guidelines

## Project Structure & Modules
- `src/`: Core library (QUIC, NAT traversal, crypto, metrics) and `src/bin/` for the `ant-quic` CLI.
- `tests/`: Integration and categorized suites (`quick/`, `standard/`, `long/`, property tests).
- `examples/`: Runnable demos (chat, dashboard, PQC).
- `benches/`: Criterion benchmarks.
- `scripts/`: CI/coverage helpers; `.github/` for workflows; `docs/` for architecture and guides.

## Build, Test, Run
- Build: `cargo build --release` or `make build` — optimized binaries.
- Tests (all): `cargo test --all-features` or `make test` — full suite.
- Quick checks: `make quick-checks` — fmt, clippy, smoke tests for CI.
- Category tests: `make test-quick | test-standard | test-long` — targeted durations.
- Examples: `cargo run --example simple_chat -- --listen 0.0.0.0:9000`.
- Coverage: `make coverage` (HTML: `make coverage-html`), quick: `make coverage-quick`.
- Lint/format: `make clippy` and `make fmt` (clippy runs with `-D warnings`).

## Coding Style & Naming
- Language: Rust 2024 edition; format with `cargo fmt` (see `rustfmt.toml`).
- Lints: `cargo clippy --all-targets -- -D warnings` (config in `clippy.toml`).
- Indentation: 4 spaces; line length per rustfmt defaults.
- Naming: `snake_case` for functions/modules, `CamelCase` for types/traits, `SCREAMING_SNAKE_CASE` for consts.
- Keep modules small and focused; prefer `src/<area>/...` directories already present (e.g., `nat_traversal/`, `connection/`).

## Testing Guidelines
- Framework: Rust built-in tests + integration tests in `tests/`.
- Conventions: Name files and test fns descriptively (e.g., `nat_traversal_api_tests.rs`, `test_observed_address_rate_limit`).
- Features: Prefer `--all-features` for CI parity; add `#[ignore]` for >5m tests (covered by `test-long`).
- Property tests: Place under `tests/property_tests/` and gate with `property_testing` when appropriate.
- Aim for meaningful coverage; run `make coverage` locally before PRs touching core paths.

## Commit & PR Guidelines
- Commits: Conventional Commits required (see `cliff.toml`). Examples: `feat(nat): add punch scheduling`, `fix(frame): correct varint parse`, `test: add pqc regressions`.
- Scope: Small, logically grouped commits; keep noise low (fmt-only changes separate).
- PRs: Include clear description, rationale, and linked issues; note feature flags touched; add tests and docs changes (`docs/`, examples) where relevant; ensure CI green (`make quick-checks`).

## Security & Configuration
- Run `make security` before release PRs (`cargo audit`, `cargo deny`).
- Prefer constant-time utils in `constant_time.rs`; avoid `unwrap` in non-test code unless invariant-proof.
- Useful env/config: see README (PQC defaults, address discovery) and `src/config/`.

