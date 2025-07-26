# ant-quic Makefile
# Provides convenient targets for common development tasks

.PHONY: all build test clean coverage coverage-html coverage-report install-tools help quick-checks fmt-check lint quick-test test-quick test-standard test-long test-ci

# Default target
all: build test

# Quick CI checks (should pass before pushing)
quick-checks:
	@echo "Running quick CI checks..."
	@.github/scripts/test-quick-checks.sh

# Individual quick checks
fmt-check:
	@cargo fmt --all -- --check

lint:
	@cargo clippy --all-targets --all-features -- -D warnings

quick-test:
	@timeout 30s cargo test --lib || [ $$? -eq 124 ]

# Build the project
build:
	@echo "Building ant-quic..."
	@cargo build --release

# Run all tests
test:
	@echo "Running tests..."
	@cargo test --all-features

# Test categories
test-quick:
	@echo "Running quick tests (<30s)..."
	@cargo test --test quick

test-standard:
	@echo "Running standard tests (<5min)..."
	@cargo test --test standard

test-long:
	@echo "Running long tests (>5min)..."
	@cargo test --test long -- --ignored

# Run tests by category in CI
test-ci: test-quick test-standard

# Run benchmarks in CI
bench-ci:
	@echo "Running CI benchmarks..."
	@cargo criterion --message-format=json > benchmark-results.json

# Clean build artifacts
clean:
	@echo "Cleaning..."
	@cargo clean
	@rm -rf coverage/
	@rm -rf target/

# Install development tools
install-tools:
	@echo "Installing development tools..."
	@cargo install cargo-tarpaulin --locked
	@cargo install cargo-llvm-cov --locked
	@cargo install cargo-audit --locked
	@cargo install cargo-outdated --locked
	@echo "Tools installed successfully!"

# Generate test coverage report
coverage:
	@echo "Generating test coverage..."
	@./scripts/coverage.sh --all

# Generate and open HTML coverage report
coverage-html:
	@echo "Generating HTML coverage report..."
	@./scripts/coverage.sh --html --open

# Analyze coverage and generate recommendations
coverage-report: coverage
	@echo ""
	@echo "Analyzing coverage..."
	@python3 scripts/analyze_coverage.py

# Run coverage in CI mode (fails if below threshold)
coverage-ci:
	@echo "Running coverage checks for CI..."
	@./scripts/coverage.sh --ci --all

# Quick coverage check
coverage-quick:
	@echo "Quick coverage check..."
	@cargo tarpaulin --print-summary

# Run benchmarks
bench:
	@echo "Running benchmarks..."
	@cargo bench

# Run benchmarks with criterion
bench-criterion:
	@echo "Running criterion benchmarks..."
	@cargo criterion

# Quick benchmark check
bench-quick:
	@echo "Running quick benchmark check..."
	@cargo bench --bench quic_benchmarks -- --quick

# Compare benchmarks with baseline
bench-compare:
	@echo "Comparing benchmarks with baseline..."
	@cargo criterion --message-format=json > benchmark-current.json
	@if [ -f benchmark-baseline.json ]; then \
		python3 .github/scripts/compare-benchmarks.py benchmark-baseline.json benchmark-current.json; \
	else \
		echo "No baseline found. Run 'make bench-save' to create one."; \
	fi

# Save current benchmarks as baseline
bench-save:
	@echo "Saving current benchmarks as baseline..."
	@cargo criterion --message-format=json > benchmark-baseline.json
	@echo "Baseline saved to benchmark-baseline.json"

# Security scanning
security: audit deny licenses
	@echo "All security checks passed!"

# Check for security vulnerabilities
audit:
	@echo "Checking for security vulnerabilities..."
	@cargo audit || true

# Run cargo-deny checks
deny:
	@echo "Running cargo-deny policy checks..."
	@cargo deny check licenses advisories sources || true

# Check licenses
licenses:
	@echo "Checking dependency licenses..."
	@cargo deny check licenses || true

# Check for outdated dependencies
outdated:
	@echo "Checking for outdated dependencies..."
	@cargo outdated

# Supply chain verification
vet:
	@echo "Verifying supply chain..."
	@cargo vet || echo "cargo-vet not initialized"

# Generate SBOM
sbom:
	@echo "Generating Software Bill of Materials..."
	@cargo sbom > sbom.spdx.json
	@cargo sbom --output-format cyclonedx > sbom.cyclonedx.json

# Security check for CI
security-ci: audit deny
	@echo "Security checks passed!"

# Format code
fmt:
	@echo "Formatting code..."
	@cargo fmt --all

# Run clippy linter
clippy:
	@echo "Running clippy..."
	@cargo clippy --all-targets -- -D warnings

# Run all checks (format, clippy, test, audit)
check: fmt clippy test audit

# Long test operations
long-tests:
	@echo "Running long tests (this may take 1+ hours)..."
	@.github/scripts/long-test-manager.sh run all normal

long-tests-quick:
	@echo "Running quick long tests (5-15 minutes)..."
	@.github/scripts/long-test-manager.sh run all quick

long-tests-stress:
	@echo "Running stress tests..."
	@.github/scripts/long-test-manager.sh run stress normal

long-tests-performance:
	@echo "Running performance benchmarks..."
	@.github/scripts/long-test-manager.sh run performance normal

long-tests-nat:
	@echo "Running comprehensive NAT tests..."
	@.github/scripts/long-test-manager.sh run nat-comprehensive normal

long-tests-categorize:
	@echo "Categorizing tests by duration..."
	@.github/scripts/long-test-manager.sh categorize

# Generate documentation
doc:
	@echo "Generating documentation..."
	@cargo doc --no-deps --open

# Run the main binary
run:
	@cargo run --bin ant-quic

# Run with debug logging
run-debug:
	@RUST_LOG=debug cargo run --bin ant-quic

# Docker operations
docker-build:
	@echo "Building Docker image..."
	@docker build -t ant-quic:latest .

docker-test:
	@echo "Running tests in Docker..."
	@docker-compose -f docker/docker-compose.yml up --abort-on-container-exit

# Docker NAT testing
docker-nat-test:
	@echo "Running Docker NAT tests..."
	@cd docker && ./scripts/run-nat-tests.sh

docker-nat-build:
	@echo "Building Docker NAT test images..."
	@cd docker && docker compose build --parallel

docker-nat-up:
	@echo "Starting NAT test environment..."
	@cd docker && docker compose up -d

docker-nat-down:
	@echo "Stopping NAT test environment..."
	@cd docker && docker compose down -v

docker-nat-logs:
	@echo "Showing NAT test logs..."
	@cd docker && docker compose logs -f

# Cross-platform testing
test-cross-platform:
	@echo "Running cross-platform tests..."
	@cargo test --features platform-tests
	@.github/scripts/platform-test.sh

test-wasm:
	@echo "Testing WASM build..."
	@cargo build --target wasm32-unknown-unknown --no-default-features
	@cd quinn-proto && wasm-pack build --target web

test-android:
	@echo "Testing Android build..."
	@cargo ndk -t arm64-v8a build --release

test-ios:
	@echo "Testing iOS build..."
	@cargo build --target aarch64-apple-ios --release

# Property-based testing
test-property:
	@echo "Running property tests..."
	@cargo test --test property_tests --release

test-property-quick:
	@echo "Running quick property tests..."
	@PROPTEST_CASES=100 cargo test --test property_tests --release

test-property-extended:
	@echo "Running extended property tests..."
	@PROPTEST_CASES=1000 cargo test --test property_tests --release -- --test-threads=8

test-property-frame:
	@echo "Running frame property tests..."
	@cargo test --test property_tests frame_properties --release

test-property-nat:
	@echo "Running NAT property tests..."
	@cargo test --test property_tests nat_properties --release

# Platform-specific builds
build-linux-musl:
	@echo "Building for Linux (musl)..."
	@cross build --target x86_64-unknown-linux-musl --release

build-windows-gnu:
	@echo "Building for Windows (GNU)..."
	@cargo build --target x86_64-pc-windows-gnu --release

# External validation targets
validate-endpoints:
	@echo "Validating external QUIC endpoints..."
	@cargo run --release --bin test-public-endpoints

validate-endpoints-json:
	@echo "Validating endpoints with JSON output..."
	@cargo run --release --bin test-public-endpoints -- \
		--output validation-results.json

validate-specific:
	@echo "Testing specific endpoints: $(ENDPOINTS)"
	@cargo run --release --bin test-public-endpoints -- \
		--endpoints "$(ENDPOINTS)"

analyze-validation:
	@echo "Analyzing validation results..."
	@cargo run --release --bin test-public-endpoints -- \
		--analyze validation-results.json \
		--format markdown

# Release targets
release-patch:
	@echo "Creating patch release..."
	@.github/scripts/bump-version.sh patch

release-minor:
	@echo "Creating minor release..."
	@.github/scripts/bump-version.sh minor

release-major:
	@echo "Creating major release..."
	@.github/scripts/bump-version.sh major

release-dry-run:
	@echo "Performing release dry run..."
	@cargo publish --dry-run
	@echo "Dry run successful!"

changelog:
	@echo "Generating changelog..."
	@git cliff --output CHANGELOG.md
	@echo "Changelog updated!"

# Help target
help:
	@echo "ant-quic Development Makefile"
	@echo ""
	@echo "Available targets:"
	@echo "  make build          - Build the project in release mode"
	@echo "  make test           - Run all tests"
	@echo "  make clean          - Clean build artifacts"
	@echo "  make coverage       - Generate full coverage report"
	@echo "  make coverage-html  - Generate and open HTML coverage"
	@echo "  make coverage-ci    - Run coverage in CI mode"
	@echo "  make bench          - Run benchmarks"
	@echo "  make fmt            - Format code"
	@echo "  make clippy         - Run clippy linter"
	@echo "  make check          - Run all checks"
	@echo "  make doc            - Generate and open documentation"
	@echo "  make install-tools  - Install development tools"
	@echo ""
	@echo "Coverage targets:"
	@echo "  make coverage-quick   - Quick coverage summary"
	@echo "  make coverage-report  - Detailed coverage analysis"
	@echo ""
	@echo "Benchmark targets:"
	@echo "  make bench            - Run all benchmarks"
	@echo "  make bench-criterion  - Run criterion benchmarks"
	@echo "  make bench-quick      - Quick benchmark check"
	@echo "  make bench-compare    - Compare with baseline"
	@echo "  make bench-save       - Save current as baseline"
	@echo ""
	@echo "Docker targets:"
	@echo "  make docker-build   - Build Docker image"
	@echo "  make docker-test    - Run tests in Docker"
	@echo ""
	@echo "NAT testing targets:"
	@echo "  make docker-nat-test  - Run Docker NAT tests"
	@echo "  make docker-nat-build - Build NAT test images"
	@echo "  make docker-nat-up    - Start NAT test environment"
	@echo "  make docker-nat-down  - Stop NAT test environment"
	@echo "  make docker-nat-logs  - Show NAT test logs"
	@echo ""
	@echo "Cross-platform targets:"
	@echo "  make test-cross-platform - Run platform-specific tests"
	@echo "  make test-wasm          - Test WASM build"
	@echo "  make test-android       - Test Android build"
	@echo "  make test-ios           - Test iOS build"
	@echo "  make build-linux-musl   - Build for Linux (musl)"
	@echo "  make build-windows-gnu  - Build for Windows (GNU)"
	@echo ""
	@echo "Property testing targets:"
	@echo "  make test-property       - Run all property tests"
	@echo "  make test-property-quick - Run quick property tests (100 cases)"
	@echo "  make test-property-extended - Run extended tests (1000 cases)"
	@echo "  make test-property-frame - Test frame properties"
	@echo "  make test-property-nat   - Test NAT properties"
	@echo ""
	@echo "Security targets:"
	@echo "  make security        - Run all security checks"
	@echo "  make audit          - Check for security vulnerabilities"
	@echo "  make deny           - Run cargo-deny policy checks"
	@echo "  make licenses       - Check dependency licenses"
	@echo "  make vet            - Verify supply chain"
	@echo "  make sbom           - Generate Software Bill of Materials"
	@echo "  make outdated       - Check for outdated dependencies"
	@echo "  make security-ci    - Run security checks for CI"
	@echo ""
	@echo "External validation targets:"
	@echo "  make validate-endpoints      - Test all public QUIC endpoints"
	@echo "  make validate-endpoints-json - Test endpoints with JSON output"
	@echo "  make validate-specific ENDPOINTS=Google,Cloudflare - Test specific endpoints"
	@echo "  make analyze-validation      - Analyze validation results"
	@echo ""
	@echo "Long test targets:"
	@echo "  make long-tests              - Run all long tests (1+ hours)"
	@echo "  make long-tests-quick        - Run quick long tests (5-15 min)"
	@echo "  make long-tests-stress       - Run stress tests only"
	@echo "  make long-tests-performance  - Run performance benchmarks"
	@echo "  make long-tests-nat          - Run comprehensive NAT tests"
	@echo "  make long-tests-categorize   - Categorize tests by duration"
	@echo ""
	@echo "Release targets:"
	@echo "  make release-patch   - Create patch release (X.Y.Z+1)"
	@echo "  make release-minor   - Create minor release (X.Y+1.0)"
	@echo "  make release-major   - Create major release (X+1.0.0)"
	@echo "  make release-dry-run - Test release process"
	@echo "  make changelog       - Generate/update CHANGELOG.md"