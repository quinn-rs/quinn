# Contributing to ant-quic

Thank you for your interest in contributing to ant-quic! This guide will help you get started.

## Table of Contents
- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Process](#development-process)
- [Testing Requirements](#testing-requirements)
- [Code Style](#code-style)
- [Pull Request Process](#pull-request-process)
- [Documentation](#documentation)

## Code of Conduct

This project adheres to a code of conduct. By participating, you are expected to uphold this code. Please be respectful and constructive in all interactions.

## Getting Started

1. **Fork and Clone**
   ```bash
   git clone https://github.com/yourusername/ant-quic.git
   cd ant-quic
   ```

2. **Install Dependencies**
   - Rust 1.85.0 or later
   - Docker (for NAT testing)
   - Python 3.8+ (for scripts)

3. **Build the Project**
   ```bash
   cargo build --all-features
   ```

4. **Run Tests**
   ```bash
   cargo test --all-features
   ```

## Development Process

### 1. Create an Issue
Before starting work, create or find an issue describing the change you want to make.

### 2. Branch Naming
Create a feature branch:
```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/issue-number-description
```

### 3. Make Changes
- Write code following our style guidelines
- Add tests for new functionality
- Update documentation as needed

### 4. Test Your Changes
```bash
# Run all tests
cargo test --all-features

# Run clippy (policy)
cargo clippy --all-features --lib --bins --examples -- \
  -D clippy::panic -D clippy::unwrap_used -D clippy::expect_used -W clippy::pedantic

# Format code
cargo fmt --all

# Run specific test categories
cargo test nat_traversal
cargo test --test address_discovery
```

## Testing Requirements

### Unit Tests
- All new code must have unit tests
- Aim for >80% code coverage
- Use descriptive test names

### Integration Tests
- Test interactions between components
- Include both success and failure cases
- Document test scenarios

### Docker NAT Tests
For NAT traversal changes:
```bash
cd docker
./scripts/run-enhanced-nat-tests.sh
```

## Code Style

### Rust Guidelines
- Follow standard Rust naming conventions
- Use `rustfmt` for formatting
- Keep functions focused and small
- Document public APIs with doc comments

### Error Handling
- Use `Result<T, E>` for fallible operations
- Create descriptive error types
- Never use `unwrap()` in production code

### Example
```rust
/// Establishes a connection to the specified endpoint
///
/// # Arguments
/// * `endpoint` - The target endpoint address
///
/// # Returns
/// * `Ok(Connection)` - Successfully established connection
/// * `Err(ConnectionError)` - Connection failed
pub async fn connect(endpoint: SocketAddr) -> Result<Connection, ConnectionError> {
    // Implementation
}
```

## Pull Request Process

### 1. Pre-submission Checklist
- [ ] All tests pass
- [ ] Code is formatted (`cargo fmt`)
- [ ] No clippy warnings
- [ ] Documentation updated
- [ ] CHANGELOG.md updated

### 2. PR Description Template
```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Manual testing completed

## Checklist
- [ ] My code follows the project style
- [ ] I have added tests
- [ ] I have updated documentation
```

### 3. Review Process
- PRs require at least one review
- Address all feedback constructively
- Keep PRs focused and small when possible

## Documentation

### Code Documentation
- Document all public APIs
- Include examples in doc comments
- Explain complex algorithms

### Project Documentation
- Update relevant .md files in `/docs`
- Keep examples up to date
- Document breaking changes

### Commit Messages
Follow conventional commits:
```
feat: add new NAT traversal algorithm
fix: resolve connection timeout issue
docs: update API reference
test: add stress tests for symmetric NAT
chore: update dependencies
```

## Development Tips

### Running Benchmarks
```bash
cargo bench --all-features
```

### Debugging
```bash
RUST_LOG=ant_quic=debug cargo run --bin ant-quic
```

### Performance Profiling
```bash
cargo build --release --features profiling
perf record --call-graph=dwarf target/release/ant-quic
perf report
```

## Getting Help

- Check existing issues and discussions
- Join our community chat
- Read the documentation in `/docs`
- Ask questions in pull requests

## Recognition

Contributors are recognized in:
- CONTRIBUTORS.md
- Release notes
- Project documentation

Thank you for contributing to ant-quic!
