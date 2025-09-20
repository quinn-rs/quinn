# GitHub Workflows Local Testing Guide

## Overview

This repository includes comprehensive GitHub workflows that can be tested locally using [act](https://github.com/nektos/act). Local testing allows you to validate workflows before pushing to GitHub, catch issues early, and ensure CI/CD reliability.

## Prerequisites

1. **Install act**: `brew install act` (macOS) or follow [installation instructions](https://github.com/nektos/act#installation)
2. **Docker Desktop**: Required for act to run workflows locally
3. **act configuration**: Create `~/.actrc` for optimal performance:

```bash
# ~/.actrc
--container-architecture linux/amd64
--platform macos-latest
```

## Available Workflows

### ✅ Fully Compatible with act

#### 1. Quick Checks (`quick-checks.yml`)
- **Purpose**: Fast validation of code quality, formatting, and basic compilation
- **Runtime**: ~2-3 minutes
- **Tests**: Format checking, clippy linting, cargo check, dependency validation
- **Local testing**: Fully supported

```bash
# Test quick-checks workflow
act -W .github/workflows/quick-checks.yml -j quick-checks
```

#### 2. CI Consolidated (`ci-consolidated.yml`)
- **Purpose**: Comprehensive testing including unit tests, security checks, and coverage
- **Runtime**: ~10-15 minutes
- **Tests**: Full test suite, security audit, coverage analysis
- **Local testing**: Fully supported (formatting and basic tests work)

```bash
# Test CI consolidated workflow
act -W .github/workflows/ci-consolidated.yml -j test
```

### ❌ Not Compatible with act (Docker-in-Docker Required)

#### 3. Docker NAT Tests (`docker-nat-tests.yml`)
- **Purpose**: NAT traversal testing using Docker containers
- **Runtime**: ~5-10 minutes
- **Tests**: Network connectivity and NAT traversal scenarios
- **Local testing**: ❌ **NOT COMPATIBLE** with act

**Important**: This workflow requires Docker-in-Docker (DinD) support and cannot run in act environments. It needs full Docker daemon access and is designed exclusively for GitHub Actions.

**Alternative**: Use the actual GitHub Actions environment or run NAT tests manually:
```bash
# Manual NAT testing (requires Docker)
./scripts/test_nat_traversal.sh
./scripts/test_nat_features.sh
```

## Testing Commands

### Quick Validation (Recommended for Development)
```bash
# Run quick checks - fastest validation
act -W .github/workflows/quick-checks.yml -j quick-checks

# Run CI consolidated tests
act -W .github/workflows/ci-consolidated.yml -j test
```

### Full Workflow Testing
```bash
# Test all workflows (requires Docker for NAT tests)
act --list  # List all available jobs
act -j quick-checks  # Run quick checks
act -j test  # Run CI consolidated tests
```

## Troubleshooting

### Common Issues

1. **Architecture Warnings**
   ```
   ⚠ You are using Apple M-series chip and you have not specified container architecture
   ```
   **Solution**: Add `--container-architecture linux/amd64` to your act commands or `~/.actrc`

2. **Docker Command Not Found**
   ```
   docker: command not found
   ```
   **Solution**: Ensure Docker Desktop is running and accessible

3. **Permission Issues**
   ```
   permission denied while trying to connect to the Docker daemon
   ```
   **Solution**: Ensure Docker daemon is running and you have proper permissions

4. **Network Issues**
   ```
   connect EHOSTUNREACH
   ```
   **Solution**: Check Docker daemon connectivity and network configuration

### Performance Tips

1. **Use caching**: act automatically caches Docker images and build artifacts
2. **Run specific jobs**: Use `-j job-name` to run only specific jobs
3. **Skip problematic workflows**: Focus on quick-checks and ci-consolidated for development
4. **Use `--reuse`**: Reuse containers between runs for faster execution

## Workflow Status

| Workflow | Local Testing | Status | Notes |
|----------|---------------|--------|-------|
| Quick Checks | ✅ Full | ✅ Working | Auto-formats code, validates quality |
| CI Consolidated | ✅ Full | ✅ Working | Comprehensive testing suite |
| Docker NAT Tests | ❌ None | ❌ Incompatible | Requires Docker-in-Docker support |

## Best Practices

1. **Development Workflow**: Always run `act -j quick-checks` before committing
2. **Pre-PR Validation**: Run both quick-checks and ci-consolidated before opening PRs
3. **Docker Testing**: Use GitHub Actions for full Docker NAT testing
4. **Caching**: Leverage act's caching for faster subsequent runs

## Integration with Development

The local testing setup integrates seamlessly with the development workflow:

```bash
# Typical development cycle
cargo fmt --all                    # Format code
cargo clippy -- -D warnings        # Check linting
cargo test                         # Run tests
act -j quick-checks               # Validate with GitHub workflow
git add . && git commit           # Commit changes
```

This ensures code quality standards are met before pushing to the repository.